<#
.SYNOPSIS
  Builds (and, when configured, Authenticode-signs) the DranzoRMM agent MSI. Windows only.

.DESCRIPTION
  NOT RUN LOCALLY: written on macOS without PowerShell or WiX. First real execution is CI.

    pwsh installers/wix/build.ps1 -Arch x64 -AgentBinary dist\agent\dranzo-agent-windows-amd64.exe `
         -Version 1.4.0 -OutDir dist\windows

  Output: <OutDir>\DranzoAgent-<x64|arm64>.msi and SHA256SUMS.windows-<arch>

  Signing rule (docs/SPEC.md section 8, docs/RUNBOOK.md "Signing secrets"):
    * neither WINDOWS_CERT_PFX_BASE64 nor WINDOWS_CERT_PASSWORD set
        -> UNSIGNED build with a loud "UNSIGNED BUILD" notice.
    * both set -> dranzo-agent.exe is signed BEFORE it is packed, the MSI is signed after,
        both are verified with `signtool verify /pa`. Any failure fails the build.
    * only one set -> the build fails ("partially configured").
    WINDOWS_TIMESTAMP_URL  optional RFC 3161 timestamp server (default below).

  The certificate is imported into the CurrentUser\My store for the duration of the build
  and removed afterwards, so its password never appears on a command line.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Arch,
    [Parameter(Mandatory)][string]$AgentBinary,
    [Parameter(Mandatory)][string]$Version,
    [string]$OutDir = (Join-Path $PSScriptRoot 'dist'),
    # WiX v5 is pinned on purpose. WiX v6+ is published under the Open Source Maintenance
    # Fee model; moving to it is a licensing/cost decision for the product owner
    # (docs/RUNBOOK.md "Signing secrets and build tooling"). Verify the terms before bumping.
    [string]$WixVersion = '5.0.2'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Notice([string]$Level, [string]$Title, [string]$Message) {
    if ($env:GITHUB_ACTIONS) { Write-Host "::${Level} title=${Title}::${Message}" }
    Write-Host "[$Title] $Message"
}

function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}

# ($IsWindows only exists in PowerShell 6+; Windows PowerShell 5.1 is always Windows.)
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { throw 'build.ps1 must run on Windows.' }
if (-not (Test-Path -LiteralPath $AgentBinary -PathType Leaf)) { throw "Agent binary not found: $AgentBinary" }

# MSI ProductVersion is numeric X.Y.Z: drop any semver pre-release / build suffix.
$numeric = ($Version -split '[-+]')[0]
if ($numeric -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,5}$') { throw "Version '$Version' has no numeric X.Y.Z prefix usable as an MSI version." }
$parts = $numeric.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) { throw "MSI version parts out of range: $numeric" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("dranzo-msi-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$stagedExe = Join-Path $work 'dranzo-agent.exe'
Copy-Item -LiteralPath $AgentBinary -Destination $stagedExe
$msi = Join-Path $OutDir "DranzoAgent-$Arch.msi"

# ----- Signing mode -----
$pfxB64 = $env:WINDOWS_CERT_PFX_BASE64
$pfxPass = $env:WINDOWS_CERT_PASSWORD
$timestampUrl = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
$sign = $false
if ($pfxB64 -or $pfxPass) {
    if (-not ($pfxB64 -and $pfxPass)) {
        throw 'Windows signing is partially configured: WINDOWS_CERT_PFX_BASE64 and WINDOWS_CERT_PASSWORD must both be set. Refusing to produce an unsigned build.'
    }
    $sign = $true
} else {
    Write-Notice 'warning' 'UNSIGNED BUILD' "Windows agent and MSI ($Arch) are NOT Authenticode-signed (no WINDOWS_CERT_* secrets). SmartScreen will warn; do not distribute to client devices."
}

$thumbprint = $null
$signtool = $null
try {
    if ($sign) {
        $signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1 -ExpandProperty FullName
        if (-not $signtool) { throw 'Signing is configured but signtool.exe (Windows SDK) was not found.' }

        $pfxPath = Join-Path $work 'codesign.pfx'
        [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($pfxB64))
        try {
            $secure = ConvertTo-SecureString -String $pfxPass -AsPlainText -Force
            $cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $secure
        } finally {
            Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
        }
        $leaf = @($cert) | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
        if (-not $leaf) { throw 'The PFX contains no certificate with a private key.' }
        $thumbprint = $leaf.Thumbprint

        # Sign the executable first so the signed file is what the MSI contains.
        Invoke-Native $signtool @('sign', '/sha1', $thumbprint, '/fd', 'sha256', '/tr', $timestampUrl, '/td', 'sha256',
            '/d', 'DranzoRMM Agent', $stagedExe)
        Invoke-Native $signtool @('verify', '/pa', '/v', $stagedExe)
    }

    # ----- WiX -----
    $wixOk = $false
    if (Get-Command wix -ErrorAction SilentlyContinue) {
        $current = (& wix --version) -replace '\+.*$', ''
        $wixOk = ($current -eq $WixVersion)
    }
    if (-not $wixOk) {
        & dotnet tool update --global wix --version $WixVersion
        if ($LASTEXITCODE -ne 0) { throw "Could not install the wix dotnet tool $WixVersion" }
        $env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
    }

    if (Test-Path -LiteralPath $msi) { Remove-Item -LiteralPath $msi -Force }
    Push-Location $PSScriptRoot   # Package.wxs refers to README.txt relative to this directory
    try {
        Invoke-Native 'wix' @('build', 'Package.wxs', '-arch', $Arch,
            '-d', "ProductVersion=$numeric", '-d', "AgentBinary=$stagedExe",
            '-intermediateFolder', (Join-Path $work 'obj'), '-pdbtype', 'none',
            '-o', $msi)
    } finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath $msi)) { throw 'wix build reported success but produced no MSI.' }

    if ($sign) {
        Invoke-Native $signtool @('sign', '/sha1', $thumbprint, '/fd', 'sha256', '/tr', $timestampUrl, '/td', 'sha256',
            '/d', 'DranzoRMM Agent', $msi)
        Invoke-Native $signtool @('verify', '/pa', '/v', $msi)
        $status = (Get-AuthenticodeSignature -LiteralPath $msi).Status
        if ($status -ne 'Valid') { throw "MSI signature status is '$status', expected 'Valid'." }
    }

    $hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $(Split-Path -Leaf $msi)" | Set-Content -LiteralPath (Join-Path $OutDir "SHA256SUMS.windows-$Arch") -Encoding ascii
    Write-Host "signed=$($sign.ToString().ToLowerInvariant())"
    Write-Host "built: $msi"
} finally {
    if ($thumbprint) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
