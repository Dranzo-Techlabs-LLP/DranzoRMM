# DranzoRMM agent installer for one Windows PC (testing / manual enrollment).
#
# Put these files in one folder:
#   Install-DranzoAgent.ps1        (this script)
#   dranzo-agent-windows-amd64.exe (or -arm64.exe on ARM PCs)
#   ca.pem and trust.json          (from the dashboard: Devices > Add devices > Download ca.pem / trust.json)
# Then, in an Administrator PowerShell in that folder:
#   powershell -ExecutionPolicy Bypass -File .\Install-DranzoAgent.ps1 -ServerUrl https://<server>:8443
# The script asks for the enrollment token (dz_enroll_...). It prints every step and saves a copy to
# DranzoInstall.txt on the Desktop (the token is redacted there). Send that file back if anything fails.
param(
    [string]$ServerUrl = 'https://192.168.68.102:8443',
    [string]$Token = ''
)
$ErrorActionPreference = 'Continue'
$log = Join-Path ([Environment]::GetFolderPath('Desktop')) 'DranzoInstall.txt'
$dir = Join-Path $env:ProgramFiles 'DranzoRMM'
$exe = Join-Path $dir 'dranzo-agent.exe'

function Say {
    param($Message)
    $text = (($Message | ForEach-Object { "$_" }) -join "`r`n").TrimEnd() -replace 'dz_enroll_[A-Za-z0-9_-]+', 'dz_enroll_<redacted>'
    Write-Host $text
    Add-Content -Path $log -Value $text -Encoding UTF8
}
function Step { param($Title) Say ''; Say "=== $Title" }
function Fail {
    param($Message)
    Say ''
    Say "FAILED: $Message"
    Say "Details saved to $log - please send that file back."
    exit 1
}
function DefenderHits {
    try {
        Get-MpThreatDetection -ErrorAction Stop | Where-Object { ($_.Resources -join ' ') -match 'dranzo' } |
            ForEach-Object { "$($_.InitialDetectionTime)  ThreatID $($_.ThreatID)  $($_.Resources -join ', ')" }
    } catch { "(could not read Windows Security detections: $($_.Exception.Message))" }
}

Set-Content -Path $log -Value "DranzoRMM install log $(Get-Date -Format o)" -Encoding UTF8

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail 'Run this in an Administrator PowerShell (right-click PowerShell > Run as administrator).' }

Step 'Computer'
Say "Windows: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version), CPU: $env:PROCESSOR_ARCHITECTURE"
Say "Local time: $(Get-Date -Format o)"
Say "Server: $ServerUrl"

Step 'Files in this folder'
$here = $PSScriptRoot
$arm = $env:PROCESSOR_ARCHITECTURE -eq 'ARM64'
$candidates = @(Get-ChildItem -Path $here -Filter 'dranzo-agent*.exe' -File -ErrorAction SilentlyContinue)
$pick = $candidates | Where-Object { ($_.Name -match 'arm64') -eq $arm } | Select-Object -First 1
if (-not $pick -and $candidates.Count -eq 1) { $pick = $candidates[0] }
if (-not $pick) { Fail "No dranzo-agent-windows-$(if ($arm) {'arm64'} else {'amd64'}).exe next to this script in $here (Windows Security may have removed it - see below).`r`n$(DefenderHits)" }
$ca = Get-ChildItem -Path $here -Filter 'ca*.pem' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$trust = Get-ChildItem -Path $here -Filter 'trust*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $ca -or -not $trust) { Fail "ca.pem and trust.json must be in $here (download them from the dashboard: Devices > Add devices)." }
Say "Agent: $($pick.Name) ($($pick.Length) bytes)"
Say "CA:    $($ca.Name)"
Say "Trust: $($trust.Name)"

if (Get-Service -Name DranzoRMMAgent -ErrorAction SilentlyContinue) {
    Step 'Already installed'
    Say (Get-Service DranzoRMMAgent | Format-List Name, Status, StartType | Out-String)
    if (Test-Path $exe) { Say (& $exe status 2>&1) }
    Fail "The agent service already exists. To enroll again, first run: & '$exe' uninstall"
}

Step 'Network'
$hostName = ([Uri]$ServerUrl).Host
$port = ([Uri]$ServerUrl).Port
$tcp = Test-NetConnection -ComputerName $hostName -Port $port -WarningAction SilentlyContinue
Say "TCP $($hostName):$port reachable: $($tcp.TcpTestSucceeded)"
if (-not $tcp.TcpTestSucceeded) { Fail "Cannot reach $($hostName):$port. Check that this PC is on the same network and the server is running." }
Say ("Health check: " + ((& curl.exe -sk --max-time 10 "$ServerUrl/agent/v1/healthz" 2>&1) -join ' '))

if (-not $Token) { $Token = (Read-Host 'Paste the enrollment token (dz_enroll_...)').Trim() }
if ($Token -notmatch '^dz_enroll_[A-Za-z0-9_-]+$') { Fail 'That is not an enrollment token. It starts with dz_enroll_ (create one in the dashboard: Devices > Add devices).' }

Step "Copy agent to $dir"
New-Item -ItemType Directory -Path $dir -Force | Out-Null
try {
    Copy-Item -Path $pick.FullName -Destination $exe -Force -ErrorAction Stop
    Copy-Item -Path $ca.FullName -Destination (Join-Path $dir 'ca.pem') -Force -ErrorAction Stop
    Copy-Item -Path $trust.FullName -Destination (Join-Path $dir 'trust.json') -Force -ErrorAction Stop
} catch { Fail "Copy failed: $($_.Exception.Message)" }
Get-ChildItem $dir -File | Unblock-File
Start-Sleep -Seconds 3
if (-not (Test-Path $exe)) { Fail "The agent file disappeared right after copying: Windows Security probably removed it.`r`n$(DefenderHits)" }
Say "Version: $((& $exe version 2>&1) -join ' ')"
if ($LASTEXITCODE -ne 0) { Fail "The agent program does not start (exit code $LASTEXITCODE).`r`n$(DefenderHits)" }

Step 'Install and start the service'
$out = & $exe install --server $ServerUrl --token $Token --ca-file (Join-Path $dir 'ca.pem') --trust-file (Join-Path $dir 'trust.json') 2>&1
$code = $LASTEXITCODE
Say $out
Say "Exit code: $code"
if ($code -ne 0) { Fail 'The install command reported an error (see above).' }

Step 'Waiting for the device to enroll (up to 60 s)'
$enrolled = $false
for ($i = 0; $i -lt 12 -and -not $enrolled; $i++) {
    Start-Sleep -Seconds 5
    $status = (& $exe status 2>&1) -join "`n"
    if ($status -match 'Device ID:\s+[0-9a-fA-F-]{36}') { $enrolled = $true }
}
Say $status

Step 'Service'
Say (Get-Service DranzoRMMAgent -ErrorAction SilentlyContinue | Format-List Name, Status, StartType | Out-String)
Step 'Last 40 lines of agent.log'
Say (Get-Content (Join-Path $env:ProgramData 'DranzoRMM\agent.log') -Tail 40 -ErrorAction SilentlyContinue)
Step 'Service Control Manager events'
Say (Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue |
        Where-Object Message -match 'Dranzo' | Select-Object -First 5 TimeCreated, Message | Format-List | Out-String)
Step 'Windows Security detections'
Say (DefenderHits)

if ($enrolled) {
    Say ''
    Say 'SUCCESS: the device enrolled. It should now show as online in the dashboard.'
    Say "Log saved to $log"
} else {
    Fail 'The service is installed but the device has not enrolled yet.'
}
