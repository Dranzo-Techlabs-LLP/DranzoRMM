<#
.SYNOPSIS
    DranzoRMM Windows verification kit runner.

.DESCRIPTION
    Runs the DranzoRMM agent's compiled Go test binaries on this Windows
    machine and writes a results bundle (DranzoWindowsResults-<computer>-<time>.zip
    on the Desktop) that says exactly what passed and what failed.

    Order: system information -> unit tests -> live tests (as this
    administrator, then as SYSTEM with -AsSystem) -> optional live enrollment
    against a DranzoRMM server (waits for Enter) -> optional uninstall ->
    results zip -> optional Windows update installation (LAST; the zip is
    written again afterwards).

    Windows PowerShell 5.1 compatible; uses only in-box cmdlets. No telemetry.
    The runner itself makes no network connections except to -ServerUrl; some
    tests use Windows Update and winget, which talk to Microsoft (see README).

.PARAMETER Live
    Run the live tests (DRANZO_REAL_WINDOWS=1): read-only collectors, real
    scripts and terminals, temp-directory file tests.
.PARAMETER Service
    Also register / start / remove THROWAWAY test services
    (DranzoRMMAgentTest, DranzoRMMAgentUpdTest). Implies -Live.
.PARAMETER Ui
    Also run the on-screen tests (message boxes, session indicator). Someone
    must be signed in at the console and follow the instructions. Runs as
    SYSTEM (scheduled task). Implies -Live.
.PARAMETER PatchInstall
    At the very end, install ONE pending Windows update (a Defender
    definition update when available). May require a restart. Implies -Live.
.PARAMETER AsSystem
    Run the live tests a second time as LocalSystem (the agent service's
    account) through a temporary scheduled task.
.PARAMETER All
    = -Live -Service -Ui -PatchInstall -AsSystem.
.PARAMETER Only
    Regex on the package path (for example 'session|script').
.PARAMETER TimeoutMinutes
    Per-package go test timeout (default 30; 120 for the update installation).
.PARAMETER ServerUrl
    Live enrollment: https://<host>:8443 of a DranzoRMM server.
.PARAMETER Token
    Live enrollment token (dz_enroll_...). Prefer -TokenFile.
.PARAMETER TokenFile
    File that holds the enrollment token; deleted after a successful enrollment.
.PARAMETER CaFile
    ca.pem of the server (required for live enrollment).
.PARAMETER TrustFile
    trust.json of the server (required for live enrollment).
.PARAMETER UninstallAfter
    After the server-side checks: uninstall the agent and verify that the
    service and C:\ProgramData\DranzoRMM are gone.
.PARAMETER EnrollTimeoutSeconds
    How long to wait for "connected" after install (default 180).
.PARAMETER NoPause
    Do not wait for Enter after a live enrollment (automation).

.EXAMPLE
    .\Run-DranzoWindowsTests.ps1
.EXAMPLE
    .\Run-DranzoWindowsTests.ps1 -All -ServerUrl https://192.168.68.102:8443 -TokenFile .\token.txt -CaFile .\ca.pem -TrustFile .\trust.json
#>
[CmdletBinding()]
param(
    [switch]$Live,
    [switch]$Service,
    [switch]$Ui,
    [switch]$PatchInstall,
    [switch]$AsSystem,
    [switch]$All,
    [string]$Only = '',
    [int]$TimeoutMinutes = 30,
    [string]$ServerUrl = '',
    [string]$Token = '',
    [string]$TokenFile = '',
    [string]$CaFile = '',
    [string]$TrustFile = '',
    [switch]$UninstallAfter,
    [int]$EnrollTimeoutSeconds = 180,
    [switch]$NoPause
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- setup

if ($All) { $Live = $true; $Service = $true; $Ui = $true; $PatchInstall = $true; $AsSystem = $true }
if ($Service -or $Ui -or $PatchInstall) { $Live = $true }

$KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentExe = Join-Path $KitRoot 'bin\dranzo-agent.exe'
$TestsRoot = Join-Path $KitRoot 'tests'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ResultsDir = Join-Path $KitRoot ("results-" + $Stamp)
$Computer = $env:COMPUTERNAME
$Desktop = [Environment]::GetFolderPath('Desktop')
if (-not $Desktop -or -not (Test-Path -LiteralPath $Desktop)) { $Desktop = $KitRoot }
$ZipPath = Join-Path $Desktop ("DranzoWindowsResults-" + $Computer + "-" + $Stamp + ".zip")
$TaskPrefix = 'DranzoKitTest-'
$ProgramDir = Join-Path $env:ProgramFiles 'DranzoRMM'
$DataDir = Join-Path $env:ProgramData 'DranzoRMM'
$RealServiceName = 'DranzoRMMAgent'
$script:Secret = ''          # the enrollment token, scrubbed from every result file
$script:NativeExit = 0
$script:Phases = New-Object System.Collections.ArrayList
$script:Notes = New-Object System.Collections.ArrayList
$KnownEnv = @('DRANZO_REAL_WINDOWS', 'DRANZO_REAL_WINDOWS_SERVICE', 'DRANZO_REAL_WINDOWS_UI',
    'DRANZO_REAL_WINDOWS_PATCH_INSTALL', 'DRANZO_REAL_WINDOWS_PATCH_IDS', 'DRANZO_KIT_AGENT_EXE',
    'DRANZO_ENROLL_TOKEN', 'DRANZO_UPDATE_E2E')

function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host ('==== ' + $Text) -ForegroundColor Cyan
}

function Add-Note([string]$Text) {
    [void]$script:Notes.Add($Text)
    Write-Host ('NOTE: ' + $Text) -ForegroundColor Yellow
}

function Protect-Text([string]$Text) {
    if ($script:Secret -and $Text) { return $Text.Replace($script:Secret, '<redacted-token>') }
    return $Text
}

function Save-Text([string]$Name, [string]$Text) {
    $path = Join-Path $ResultsDir $Name
    [System.IO.File]::WriteAllText($path, (Protect-Text $Text), (New-Object System.Text.UTF8Encoding $false))
}

# Invoke-Native runs a console program and returns its stdout and stderr as
# text. Windows PowerShell 5.1 turns stderr lines of "& exe 2>&1" into
# terminating errors when $ErrorActionPreference is Stop, so it is relaxed here.
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = & $Exe @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ }
        }
        $script:NativeExit = $LASTEXITCODE
        return (Protect-Text (($lines | Out-String)))
    } catch {
        $script:NativeExit = -1
        return ('error: ' + $_.Exception.Message)
    } finally {
        $ErrorActionPreference = $old
    }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host ''
    Write-Host 'This kit must run from an ELEVATED PowerShell:' -ForegroundColor Red
    Write-Host '  Start menu > type "PowerShell" > right-click "Windows PowerShell" > "Run as administrator",' -ForegroundColor Red
    Write-Host ('  then: cd "' + $KitRoot + '"; .\Run-DranzoWindowsTests.ps1 ...') -ForegroundColor Red
    exit 2
}
if (-not (Test-Path -LiteralPath $AgentExe) -or -not (Test-Path -LiteralPath $TestsRoot)) {
    Write-Host ('Kit incomplete: ' + $AgentExe + ' or ' + $TestsRoot + ' is missing. Extract the whole zip first.') -ForegroundColor Red
    exit 2
}
if ($KitRoot.StartsWith('\\')) {
    Write-Host 'Run the kit from a local disk, not a network share (SYSTEM cannot read network shares).' -ForegroundColor Red
    exit 2
}

$enroll = [bool]$ServerUrl
if ($enroll) {
    if ($Token -and $TokenFile) { Write-Host 'Give either -Token or -TokenFile, not both.' -ForegroundColor Red; exit 2 }
    if ($TokenFile) {
        if (-not (Test-Path -LiteralPath $TokenFile)) { Write-Host ('Token file not found: ' + $TokenFile) -ForegroundColor Red; exit 2 }
        $TokenFile = (Resolve-Path -LiteralPath $TokenFile).Path
        $Token = ([System.IO.File]::ReadAllText($TokenFile)).Trim()
    }
    if ($Token -notmatch '^dz_enroll_[A-Za-z0-9._~-]{8,480}$') {
        Write-Host 'Live enrollment needs a token of the form dz_enroll_... (-Token or -TokenFile).' -ForegroundColor Red; exit 2
    }
    $script:Secret = $Token
    if ($ServerUrl -notmatch '^https://[^/\s]+(:\d+)?/?$') { Write-Host '-ServerUrl must look like https://host:8443' -ForegroundColor Red; exit 2 }
    if (-not $CaFile -or -not $TrustFile) { Write-Host 'Live enrollment needs -CaFile ca.pem and -TrustFile trust.json.' -ForegroundColor Red; exit 2 }
    foreach ($f in @($CaFile, $TrustFile)) {
        if (-not (Test-Path -LiteralPath $f)) { Write-Host ('File not found: ' + $f) -ForegroundColor Red; exit 2 }
    }
    $CaFile = (Resolve-Path -LiteralPath $CaFile).Path
    $TrustFile = (Resolve-Path -LiteralPath $TrustFile).Path
} elseif ($Token -or $TokenFile -or $UninstallAfter) {
    Write-Host '-Token / -TokenFile / -UninstallAfter need -ServerUrl.' -ForegroundColor Red; exit 2
}

New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
# Files extracted from a downloaded zip carry the "from the internet" mark.
Get-ChildItem -LiteralPath $KitRoot -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- system information

function Get-SafeValue([scriptblock]$Block) {
    try { return (& $Block) } catch { return ('error: ' + $_.Exception.Message) }
}

function Test-Cmd([string]$Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

Write-Step 'System information'
$os = Get-SafeValue { Get-CimInstance Win32_OperatingSystem }
$cs = Get-SafeValue { Get-CimInstance Win32_ComputerSystem }
$cv = Get-SafeValue { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' }
$nativeArch = Get-SafeValue { [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE }
$manifest = Get-SafeValue { Get-Content -Raw -LiteralPath (Join-Path $KitRoot 'manifest.json') | ConvertFrom-Json }
$kitArch = ''
if ($manifest -and ($manifest -isnot [string])) { $kitArch = [string]$manifest.goarch }
$wsc = Get-SafeValue { @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { [string]$_.displayName }) -join ', ' }
$wingetVersion = ''
$wingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($wingetCmd) { $wingetVersion = (Invoke-Native $wingetCmd.Source @('--version')).Trim() }
$agentVersion = (Invoke-Native $AgentExe @('version')).Trim()

$info = [ordered]@{
    computer            = $Computer
    user                = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    osCaption           = Get-SafeValue { [string]$os.Caption }
    osVersion           = Get-SafeValue { [string]$os.Version }
    osBuild             = Get-SafeValue { [string]$cv.CurrentBuildNumber + '.' + [string]$cv.UBR }
    displayVersion      = Get-SafeValue { [string]$cv.DisplayVersion }
    editionId           = Get-SafeValue { [string]$cv.EditionID }
    installationType    = Get-SafeValue { [string]$cv.InstallationType }
    osArchitecture      = Get-SafeValue { [string]$os.OSArchitecture }
    nativeArchitecture  = $nativeArch
    processorArch       = $env:PROCESSOR_ARCHITECTURE
    kitArchitecture     = $kitArch
    psVersion           = $PSVersionTable.PSVersion.ToString()
    psEdition           = Get-SafeValue { [string]$PSVersionTable.PSEdition }
    manufacturer        = Get-SafeValue { [string]$cs.Manufacturer }
    model               = Get-SafeValue { [string]$cs.Model }
    hypervisorPresent   = Get-SafeValue { [bool]$cs.HypervisorPresent }
    domainJoined        = Get-SafeValue { [bool]$cs.PartOfDomain }
    consoleUser         = Get-SafeValue { [string]$cs.UserName }
    defenderCmdlets     = Test-Cmd 'Get-MpComputerStatus'
    securityCenter      = $wsc
    bitlockerCmdlets    = Test-Cmd 'Get-BitLockerVolume'
    firewallCmdlets     = Test-Cmd 'Get-NetFirewallProfile'
    localAccountCmdlets = Test-Cmd 'Get-LocalGroupMember'
    scheduledTaskCmdlets = Test-Cmd 'Register-ScheduledTask'
    winget              = $wingetVersion
    python              = Get-SafeValue { $c = Get-Command python.exe -ErrorAction SilentlyContinue; if ($c) { $c.Source } else { '' } }
    agentVersion        = $agentVersion
    realAgentService    = [bool](Get-Service -Name $RealServiceName -ErrorAction SilentlyContinue)
    kitPath             = $KitRoot
    switches            = (@('Live', 'Service', 'Ui', 'PatchInstall', 'AsSystem') | Where-Object { Get-Variable -Name $_ -ValueOnly }) -join ','
    enrollment          = $enroll
    started             = (Get-Date).ToString('o')
}
$info.isVM = ($info.hypervisorPresent -eq $true) -or ([string]$info.model -match 'Virtual|VMware|QEMU|KVM|Parallels|VirtualBox|HVM')
$info.GetEnumerator() | ForEach-Object { Write-Host ('  {0,-22} {1}' -f $_.Key, $_.Value) }
Save-Text 'system-info.json' ($info | ConvertTo-Json -Depth 4)
Save-Text 'systeminfo.txt' (Invoke-Native (Join-Path $env:SystemRoot 'System32\systeminfo.exe') @())
Save-Text 'computerinfo.txt' (Get-SafeValue {
        Get-ComputerInfo -Property WindowsProductName, WindowsEditionId, WindowsVersion, WindowsBuildLabEx, OsArchitecture,
        OsLanguage, OsLocale, CsManufacturer, CsModel, CsSystemType, CsHypervisorPresent, CsDomainRole, BiosSeralNumber,
        OsLastBootUpTime, TimeZone, DeviceGuardSecurityServicesRunning | Format-List | Out-String })
Save-Text 'agent-version.txt' $agentVersion

if ($kitArch -eq 'arm64' -and $nativeArch -notmatch 'ARM64') {
    Write-Host 'This is the ARM64 kit but Windows is not ARM64: use DranzoWindowsKit-amd64.zip.' -ForegroundColor Red; exit 2
}
if ($kitArch -eq 'amd64' -and $nativeArch -match 'ARM64') {
    Add-Note 'x64 kit on ARM64 Windows: it runs under emulation. Use DranzoWindowsKit-arm64.zip to test the native ARM64 agent.'
}
if ($info.realAgentService -and $enroll) {
    Write-Host ('The real "' + $RealServiceName + '" service already exists. Run "dranzo-agent uninstall" (or remove it) before a live enrollment.') -ForegroundColor Red
    exit 2
}

# ---------------------------------------------------------------- test execution

$TestBinaries = @(Get-ChildItem -LiteralPath $TestsRoot -Recurse -Filter '*.test.exe' | Sort-Object FullName | ForEach-Object {
        $rel = $_.DirectoryName.Substring($TestsRoot.Length).TrimStart('\').Replace('\', '/')
        [pscustomobject]@{ Package = $rel; Exe = $_.FullName; Dir = $_.DirectoryName }
    })
if ($Only) { $TestBinaries = @($TestBinaries | Where-Object { $_.Package -match $Only }) }
Write-Host ('  test packages: ' + $TestBinaries.Count)
if ($TestBinaries.Count -eq 0) { Write-Host 'No test binaries selected.' -ForegroundColor Red; exit 2 }

function ConvertTo-CmdArg([string]$Value) { return '"' + $Value.Replace('"', '""') + '"' }

# New-Wrapper writes the .cmd that runs one test binary in its package
# directory with exactly the given DRANZO_* variables, and records the exit code.
function New-Wrapper([string]$Path, $Bin, [string[]]$TestArgs, [hashtable]$EnvMap, [string]$Log) {
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('@echo off')
    foreach ($k in $KnownEnv) { [void]$lines.Add('set "' + $k + '="') }
    foreach ($k in $EnvMap.Keys) { [void]$lines.Add('set "' + $k + '=' + $EnvMap[$k] + '"') }
    [void]$lines.Add('cd /d ' + (ConvertTo-CmdArg $Bin.Dir))
    $argText = ($TestArgs | ForEach-Object { ConvertTo-CmdArg $_ }) -join ' '
    [void]$lines.Add((ConvertTo-CmdArg $Bin.Exe) + ' ' + $argText + ' > ' + (ConvertTo-CmdArg $Log) + ' 2>&1')
    # Redirection first: "echo 1> file" would redirect stream 1 instead.
    [void]$lines.Add('set "DZ_KIT_EXIT=%ERRORLEVEL%"')
    [void]$lines.Add('> ' + (ConvertTo-CmdArg ($Log + '.exit')) + ' echo %DZ_KIT_EXIT%')
    # cmd.exe reads batch files in the OEM code page (paths may contain non-ASCII user names).
    $oem = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    [System.IO.File]::WriteAllText($Path, (($lines -join "`r`n") + "`r`n"), $oem)
}

# Show-LogTail prints what the test wrote since the last call.
function Show-LogTail([string]$Log, [ref]$Offset) {
    if (-not (Test-Path -LiteralPath $Log)) { return }
    try {
        $fs = [System.IO.File]::Open($Log, 'Open', 'Read', 'ReadWrite')
        try {
            if ($fs.Length -le $Offset.Value) { return }
            [void]$fs.Seek($Offset.Value, 'Begin')
            $buf = New-Object byte[] ($fs.Length - $Offset.Value)
            $n = $fs.Read($buf, 0, $buf.Length)
            $Offset.Value += $n
            $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
            foreach ($line in ($text -split "`r?`n")) {
                if ($line -match '^\s*--- FAIL|^FAIL|^panic:') { Write-Host $line -ForegroundColor Red }
                elseif ($line -match '>>>>> ACTION') { Write-Host $line -ForegroundColor Magenta }
                elseif ($line -match '^\s*--- PASS|^PASS|^ok') { Write-Host $line -ForegroundColor Green }
                elseif ($line -match '^\s*--- SKIP') { Write-Host $line -ForegroundColor DarkGray }
                elseif ($line -match '^=== RUN|^\s+\S+\.go:\d+:|RESULT') { Write-Host $line }
            }
        } finally { $fs.Close() }
    } catch { }
}

# Invoke-TestBinary runs one package's test binary (as this administrator, or
# as SYSTEM through a temporary scheduled task) and returns its parsed result.
function Invoke-TestBinary($Bin, [string]$Phase, [string[]]$TestArgs, [hashtable]$EnvMap, [bool]$System, [int]$Minutes) {
    $phaseDir = Join-Path $ResultsDir $Phase
    New-Item -ItemType Directory -Force -Path $phaseDir | Out-Null
    $safe = $Bin.Package.Replace('/', '_')
    $log = Join-Path $phaseDir ($safe + '.log')
    $wrapper = Join-Path $phaseDir ($safe + '.cmd')
    $allArgs = @('-test.v', '-test.count=1', ('-test.timeout=' + $Minutes + 'm')) + $TestArgs
    New-Wrapper $wrapper $Bin $allArgs $EnvMap $log
    $who = 'admin'
    if ($System) { $who = 'SYSTEM' }
    Write-Host ''
    Write-Host ('---- [' + $Phase + '] ' + $Bin.Package + ' (as ' + $who + ')') -ForegroundColor Cyan
    $start = Get-Date
    $deadline = $start.AddMinutes($Minutes + 5)
    $offset = [long]0
    $taskName = ''
    $proc = $null
    # /S: cmd strips exactly the outer quotes, so a kit path with spaces or
    # parentheses ("Kit (1)") still names the wrapper correctly.
    $cmdArgs = '/D /S /C "' + (ConvertTo-CmdArg $wrapper) + '"'
    if ($System) {
        $taskName = $TaskPrefix + $safe
        $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\cmd.exe') -Argument $cmdArgs
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes ($Minutes + 10))
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
    } else {
        $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList $cmdArgs -WindowStyle Hidden -PassThru
    }
    $timedOut = $false
    try {
        while (-not (Test-Path -LiteralPath ($log + '.exit'))) {
            Show-LogTail $log ([ref]$offset)
            if ((Get-Date) -gt $deadline) { $timedOut = $true; break }
            if ($proc -and $proc.HasExited -and -not (Test-Path -LiteralPath ($log + '.exit'))) { Start-Sleep -Milliseconds 500; break }
            Start-Sleep -Milliseconds 500
        }
        Show-LogTail $log ([ref]$offset)
    } finally {
        if ($timedOut) {
            Add-Note ($Bin.Package + ' [' + $Phase + ']: no result after ' + ($Minutes + 5) + ' minutes; killed')
            if ($proc) { [void](Invoke-Native (Join-Path $env:SystemRoot 'System32\taskkill.exe') @('/T', '/F', '/PID', [string]$proc.Id)) }
            Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Bin.Exe } | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        if ($taskName) {
            try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch { }
            try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
        }
    }
    $exit = -1
    if (Test-Path -LiteralPath ($log + '.exit')) {
        $raw = (Get-Content -Raw -LiteralPath ($log + '.exit')).Trim()
        if ($raw -match '^-?\d+$') { $exit = [int]$raw }
        Remove-Item -LiteralPath ($log + '.exit') -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
    $text = ''
    if (Test-Path -LiteralPath $log) {
        $text = [System.IO.File]::ReadAllText($log)
        if ($script:Secret -and $text.Contains($script:Secret)) { [System.IO.File]::WriteAllText($log, (Protect-Text $text)) }
    }
    $r = ConvertFrom-GoTestLog $text
    $r | Add-Member -NotePropertyName package -NotePropertyValue $Bin.Package
    $r | Add-Member -NotePropertyName phase -NotePropertyValue $Phase
    $r | Add-Member -NotePropertyName runAs -NotePropertyValue $who
    $r | Add-Member -NotePropertyName exitCode -NotePropertyValue $exit
    $r | Add-Member -NotePropertyName seconds -NotePropertyValue ([math]::Round(((Get-Date) - $start).TotalSeconds, 1))
    $r | Add-Member -NotePropertyName log -NotePropertyValue ($Phase + '\' + $safe + '.log')
    $status = 'PASS'
    if ($exit -ne 0 -or $r.failed -gt 0) { $status = 'FAIL' }
    if ($timedOut) { $status = 'TIMEOUT' }
    if ($status -eq 'PASS' -and $r.passed -eq 0 -and $r.skipped -gt 0) { $status = 'SKIP' }
    if ($exit -ne 0 -and $r.failed -eq 0) {
        # Panic, test timeout or a binary that did not start: keep the tail.
        $tail = @(($text -split "`r?`n") | Where-Object { $_ } | Select-Object -Last 25)
        $r.failures += , ([pscustomobject]@{ test = ('(package exit code ' + $exit + ')'); output = $tail })
    }
    $r | Add-Member -NotePropertyName status -NotePropertyValue $status
    $color = 'Green'
    if ($status -eq 'SKIP') { $color = 'DarkGray' } elseif ($status -ne 'PASS') { $color = 'Red' }
    Write-Host ('     => ' + $status + '  pass ' + $r.passed + ' / fail ' + $r.failed + ' / skip ' + $r.skipped + '  (' + $r.seconds + ' s)') -ForegroundColor $color
    return $r
}

# ConvertFrom-GoTestLog parses "go test -v" output: counts of PASS / FAIL /
# SKIP lines (tests and subtests) and, per failed test, its first log lines.
function ConvertFrom-GoTestLog([string]$Text) {
    $passed = 0; $failed = 0; $skipped = 0
    $failures = New-Object System.Collections.ArrayList
    $results = New-Object System.Collections.ArrayList
    $outputOf = @{}
    $current = ''
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^=== (RUN|CONT|PAUSE|NAME)\s+(\S+)') { $current = $Matches[2]; if (-not $outputOf.ContainsKey($current)) { $outputOf[$current] = New-Object System.Collections.ArrayList }; continue }
        if ($line -match '^\s*--- (PASS|FAIL|SKIP): (\S+) \(([\d.]+)s\)') {
            $kind = $Matches[1]; $name = $Matches[2]
            [void]$results.Add([pscustomobject]@{ test = $name; result = $kind; seconds = [double]$Matches[3] })
            switch ($kind) {
                'PASS' { $passed++ }
                'SKIP' { $skipped++ }
                'FAIL' {
                    $failed++
                    $out = @()
                    if ($outputOf.ContainsKey($name)) {
                        $out = @($outputOf[$name] | Where-Object { $_ -match '^\s+\S+\.go:\d+:' -or $_ -match '^\s{8}' } | Select-Object -First 12)
                        if ($out.Count -eq 0) { $out = @($outputOf[$name] | Select-Object -Last 12) }
                    }
                    [void]$failures.Add([pscustomobject]@{ test = $name; output = $out })
                }
            }
            continue
        }
        if ($current -and $outputOf.ContainsKey($current)) { [void]$outputOf[$current].Add($line) }
    }
    return [pscustomobject]@{ passed = $passed; failed = $failed; skipped = $skipped; failures = @($failures); tests = @($results) }
}

function Invoke-Phase([string]$Phase, [string[]]$TestArgs, [hashtable]$EnvMap, [bool]$System, $Binaries, [int]$Minutes) {
    Write-Step ('Phase: ' + $Phase)
    foreach ($b in $Binaries) {
        $r = Invoke-TestBinary $b $Phase $TestArgs $EnvMap $System $Minutes
        [void]$script:Phases.Add($r)
        Write-Summary
    }
}

function Write-Summary {
    $all = @($script:Phases)
    $summary = [ordered]@{
        computer = $Computer
        generated = (Get-Date).ToString('o')
        kit = $manifest
        system = $info
        notes = @($script:Notes)
        totals = [ordered]@{
            packages = $all.Count
            failedPackages = @($all | Where-Object { $_.status -ne 'PASS' -and $_.status -ne 'SKIP' }).Count
            passed = ($all | Measure-Object -Property passed -Sum).Sum
            failed = ($all | Measure-Object -Property failed -Sum).Sum
            skipped = ($all | Measure-Object -Property skipped -Sum).Sum
        }
        packages = $all
    }
    Save-Text 'summary.json' ($summary | ConvertTo-Json -Depth 8)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('DranzoRMM Windows verification kit - results')
    [void]$sb.AppendLine(('Computer: {0}   OS: {1} {2} ({3})   kit: {4}   agent: {5}' -f $Computer, $info.osCaption, $info.osBuild, $info.nativeArchitecture, $kitArch, $agentVersion))
    [void]$sb.AppendLine(('Switches: {0}   generated {1}' -f $info.switches, (Get-Date).ToString('u')))
    [void]$sb.AppendLine(('Totals: {0} package runs, {1} not passing; tests pass {2} / fail {3} / skip {4}' -f $summary.totals.packages, $summary.totals.failedPackages, $summary.totals.passed, $summary.totals.failed, $summary.totals.skipped))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('{0,-14} {1,-30} {2,-7} {3,-8} {4,5} {5,5} {6,5} {7,8}' -f 'phase', 'package', 'as', 'status', 'pass', 'fail', 'skip', 'seconds'))
    foreach ($r in $all) {
        [void]$sb.AppendLine(('{0,-14} {1,-30} {2,-7} {3,-8} {4,5} {5,5} {6,5} {7,8}' -f $r.phase, $r.package, $r.runAs, $r.status, $r.passed, $r.failed, $r.skipped, $r.seconds))
    }
    foreach ($r in $all) {
        if (@($r.failures).Count -eq 0) { continue }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(('FAILURES in {0} [{1}, as {2}] (log: {3})' -f $r.package, $r.phase, $r.runAs, $r.log))
        foreach ($f in $r.failures) {
            [void]$sb.AppendLine('  ' + $f.test)
            foreach ($l in @($f.output)) { [void]$sb.AppendLine('      ' + $l) }
        }
    }
    if ($script:Notes.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Notes:')
        foreach ($n in $script:Notes) { [void]$sb.AppendLine('  - ' + $n) }
    }
    Save-Text 'summary.txt' $sb.ToString()
}

function New-ResultsZip {
    Write-Summary
    if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
    # Last line of defence: no result file may contain the token.
    if ($script:Secret) {
        Get-ChildItem -LiteralPath $ResultsDir -Recurse -File | ForEach-Object {
            $t = [System.IO.File]::ReadAllText($_.FullName)
            if ($t.Contains($script:Secret)) { [System.IO.File]::WriteAllText($_.FullName, (Protect-Text $t)) }
        }
    }
    Compress-Archive -Path (Join-Path $ResultsDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal
    Write-Host ''
    Write-Host ('Results: ' + $ZipPath) -ForegroundColor Green
}

$Minutes = [math]::Max(5, $TimeoutMinutes)

# 1. Unit tests: every test binary, no live switches.
Invoke-Phase 'unit' @() @{} $false $TestBinaries $Minutes

# 2. Live tests (only the TestWindowsLive* tests of every package).
$liveEnv = @{ 'DRANZO_REAL_WINDOWS' = '1' }
if ($Service) { $liveEnv['DRANZO_REAL_WINDOWS_SERVICE'] = '1' }
if ($Live) {
    Invoke-Phase 'live-admin' @('-test.run=WindowsLive') $liveEnv $false $TestBinaries $Minutes
    if ($AsSystem -or $Ui) {
        if (-not (Test-Cmd 'Register-ScheduledTask')) {
            Add-Note 'Register-ScheduledTask is not available: the SYSTEM phase was skipped.'
        } else {
            $sysEnv = $liveEnv.Clone()
            $sysBins = $TestBinaries
            if ($Ui) {
                $sysEnv['DRANZO_REAL_WINDOWS_UI'] = '1'
                Write-Host ''
                Write-Host '*** The UI tests will show message boxes and a small window on the console of this VM. ***' -ForegroundColor Magenta
                Write-Host '*** Someone signed in at the console must follow the ">>>>> ACTION" lines printed below. ***' -ForegroundColor Magenta
            }
            if (-not $AsSystem) { $sysBins = @($TestBinaries | Where-Object { $_.Package -eq 'internal/userui' }) }
            Invoke-Phase 'live-system' @('-test.run=WindowsLive') $sysEnv $true $sysBins $Minutes
        }
    }
}

# 3. Live enrollment against the server.
function Get-AgentStatus {
    $exe = Join-Path $ProgramDir 'dranzo-agent.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return '' }
    return (Invoke-Native $exe @('status'))
}

if ($enroll) {
    Write-Step ('Live enrollment against ' + $ServerUrl)
    $log = New-Object System.Text.StringBuilder
    New-Item -ItemType Directory -Force -Path $ProgramDir | Out-Null
    $installed = Join-Path $ProgramDir 'dranzo-agent.exe'
    Copy-Item -LiteralPath $AgentExe -Destination $installed -Force
    [void]$log.AppendLine('copied agent to ' + $installed)
    $code = -1
    # The token travels in the environment of the install process only, never
    # on a command line.
    $env:DRANZO_ENROLL_TOKEN = $Token
    try {
        $out = Invoke-Native $installed @('install', '--server', $ServerUrl, '--ca-file', $CaFile, '--trust-file', $TrustFile)
        $code = $script:NativeExit
    } finally {
        Remove-Item Env:DRANZO_ENROLL_TOKEN -ErrorAction SilentlyContinue
    }
    [void]$log.AppendLine('install exit code ' + $code)
    [void]$log.AppendLine((Protect-Text $out))
    Write-Host (Protect-Text $out)
    $connected = $false
    if ($code -eq 0) {
        $deadline = (Get-Date).AddSeconds($EnrollTimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            $st = Get-AgentStatus
            if ($st -match 'Connection:\s+connected') { $connected = $true; break }
            Start-Sleep -Seconds 3
        }
    }
    $st = Get-AgentStatus
    [void]$log.AppendLine('--- status')
    [void]$log.AppendLine($st)
    Write-Host $st
    $svcInfo = Get-SafeValue { Get-Service -Name $RealServiceName | Select-Object Name, DisplayName, Status, StartType | Format-List | Out-String }
    [void]$log.AppendLine('--- Get-Service')
    [void]$log.AppendLine($svcInfo)
    $enrollResult = [pscustomobject]@{ package = 'live-enrollment'; phase = 'enroll'; runAs = 'service'; status = 'FAIL'; passed = 0; failed = 1; skipped = 0; exitCode = $code; seconds = 0; log = 'enroll.log'; failures = @(); tests = @() }
    if ($connected) {
        $enrollResult.status = 'PASS'; $enrollResult.passed = 1; $enrollResult.failed = 0
        if ($TokenFile -and (Test-Path -LiteralPath $TokenFile)) {
            Remove-Item -LiteralPath $TokenFile -Force
            [void]$log.AppendLine('token file deleted')
            Write-Host ('Token file deleted: ' + $TokenFile)
        }
        Write-Host ''
        Write-Host 'Agent enrolled and connected; the server-side test will now drive it - keep this window open' -ForegroundColor Green
        Save-Text 'enroll.log' $log.ToString()
        Write-Summary
        if (-not $NoPause) {
            [void](Read-Host 'Press Enter when the operator says the server-side checks are done')
        }
        [void]$log.AppendLine('--- status after the server-side checks')
        [void]$log.AppendLine((Get-AgentStatus))
    } else {
        $enrollResult.failures = @([pscustomobject]@{ test = 'enrollment'; output = @(($st -split "`r?`n") | Where-Object { $_ }) })
        Add-Note ('Live enrollment did not reach "connected" within ' + $EnrollTimeoutSeconds + ' s (install exit code ' + $code + ').')
    }
    $agentLog = Join-Path $DataDir 'agent.log'
    if (Test-Path -LiteralPath $agentLog) {
        Save-Text 'agent.log' ([System.IO.File]::ReadAllText($agentLog))
    }
    if ($UninstallAfter) {
        Write-Step 'Uninstall'
        $out = Invoke-Native $installed @('uninstall')
        [void]$log.AppendLine('--- uninstall exit code ' + $script:NativeExit)
        [void]$log.AppendLine($out)
        Write-Host $out
        Start-Sleep -Seconds 3
        $svcLeft = [bool](Get-Service -Name $RealServiceName -ErrorAction SilentlyContinue)
        $dataLeft = Test-Path -LiteralPath $DataDir
        [void]$log.AppendLine(('service left: {0}; {1} left: {2}' -f $svcLeft, $DataDir, $dataLeft))
        for ($i = 0; $i -lt 10 -and (Test-Path -LiteralPath $installed); $i++) {
            try { Remove-Item -LiteralPath $ProgramDir -Recurse -Force } catch { Start-Sleep -Seconds 2 }
        }
        if ($svcLeft -or $dataLeft) {
            $enrollResult.status = 'FAIL'; $enrollResult.failed++
            $enrollResult.failures = @($enrollResult.failures) + @([pscustomobject]@{ test = 'uninstall'; output = @(('service left: {0}; data directory left: {1}' -f $svcLeft, $dataLeft)) })
        } else {
            $enrollResult.passed++
            Write-Host 'Service and data directory are gone.' -ForegroundColor Green
        }
    } else {
        Add-Note ('The agent stays installed (service ' + $RealServiceName + '). Remove it with: "' + $installed + '" uninstall')
    }
    Save-Text 'enroll.log' $log.ToString()
    [void]$script:Phases.Add($enrollResult)
}

# 4. Results zip (before anything that could restart the machine).
New-ResultsZip

# 5. Windows update installation, LAST.
if ($PatchInstall) {
    $patchBin = @($TestBinaries | Where-Object { $_.Package -eq 'internal/patch' })
    if ($patchBin.Count -eq 0) {
        Add-Note 'internal/patch is not selected (-Only): the update installation was skipped.'
    } else {
        Write-Host ''
        Write-Host '*****************************************************************************' -ForegroundColor Yellow
        Write-Host '* WARNING: installing ONE pending Windows update now (a Defender definition  *' -ForegroundColor Yellow
        Write-Host '* update when one is pending). This can take a long time and the update may *' -ForegroundColor Yellow
        Write-Host '* need a restart. The results zip above is already complete; it is written  *' -ForegroundColor Yellow
        Write-Host '* again when the installation has finished.                                 *' -ForegroundColor Yellow
        Write-Host '*****************************************************************************' -ForegroundColor Yellow
        $patchEnv = $liveEnv.Clone()
        $patchEnv['DRANZO_REAL_WINDOWS_PATCH_INSTALL'] = '1'
        if ($env:DRANZO_REAL_WINDOWS_PATCH_IDS) { $patchEnv['DRANZO_REAL_WINDOWS_PATCH_IDS'] = $env:DRANZO_REAL_WINDOWS_PATCH_IDS }
        $asSys = [bool]$AsSystem -and (Test-Cmd 'Register-ScheduledTask')
        Invoke-Phase 'patch-install' @('-test.run=^TestWindowsLivePatchInstall$') $patchEnv $asSys $patchBin ([math]::Max($Minutes, 120))
        New-ResultsZip
    }
}

Write-Host ''
Get-Content -LiteralPath (Join-Path $ResultsDir 'summary.txt') | Select-Object -First 60 | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host ('Send this file back: ' + $ZipPath) -ForegroundColor Green
