package firewall

// PSApplyRules replaces every rule in the Windows Firewall group "DranzoRMM"
// with the rules in $env:DRANZO_FW_RULES (JSON from WindowsPayload). Values are
// read from the environment and never interpolated into the script.
const PSApplyRules = `$ErrorActionPreference = 'Stop'
$rules = @()
if ($env:DRANZO_FW_RULES) { $rules = @($env:DRANZO_FW_RULES | ConvertFrom-Json) }
Get-NetFirewallRule -Group 'DranzoRMM' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
foreach ($r in $rules) {
  $p = @{
    Name        = 'DranzoRMM-' + $r.id
    DisplayName = 'DranzoRMM: ' + $r.name
    Group       = 'DranzoRMM'
    Description = 'Managed by DranzoRMM policy. dranzo:' + $r.id
    Direction   = $r.direction
    Action      = $r.action
    Profile     = 'Any'
    Enabled     = 'True'
  }
  if ($r.protocol -ne 'Any') { $p.Protocol = $r.protocol }
  if (@($r.ports).Count -gt 0) {
    if ($r.direction -eq 'Inbound') { $p.LocalPort = [string[]]$r.ports } else { $p.RemotePort = [string[]]$r.ports }
  }
  if (@($r.remote).Count -gt 0) { $p.RemoteAddress = [string[]]$r.remote }
  if ($r.program) { $p.Program = $r.program }
  New-NetFirewallRule @p | Out-Null
}
'ok'`

// PSListRules prints the DranzoRMM rule names, one per line.
const PSListRules = `$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -Group 'DranzoRMM' -ErrorAction SilentlyContinue | ForEach-Object { 'dranzo:' + ($_.Name -replace '^DranzoRMM-', '') }`
