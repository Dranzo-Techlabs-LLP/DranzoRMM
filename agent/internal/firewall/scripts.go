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

// PSIsolate replaces the "DranzoRMM Isolation" rules with two block rules (in
// and out) for every address except the allowed ones. $env:DRANZO_ISO_V4 and
// $env:DRANZO_ISO_V6 hold comma-separated ranges from ComplementRanges.
const PSIsolate = `$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -Group 'DranzoRMM Isolation' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$ranges = @()
if ($env:DRANZO_ISO_V4) { $ranges += $env:DRANZO_ISO_V4.Split(',') }
if ($env:DRANZO_ISO_V6) { $ranges += $env:DRANZO_ISO_V6.Split(',') }
foreach ($dir in 'Inbound', 'Outbound') {
  New-NetFirewallRule -Name ('DranzoRMM-Isolation-' + $dir) -DisplayName ('DranzoRMM Isolation (' + $dir.ToLower() + ')') -Group 'DranzoRMM Isolation' -Description 'This computer is isolated from the network by DranzoRMM. Only DranzoRMM, DNS and DHCP are reachable. A local administrator can run: dranzo-agent release-isolation' -Direction $dir -Action Block -Profile Any -RemoteAddress ([string[]]$ranges) | Out-Null
}
'ok'`

// PSReleaseIsolation removes the isolation rules.
const PSReleaseIsolation = `$ErrorActionPreference = 'Stop'
Get-NetFirewallRule -Group 'DranzoRMM Isolation' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
'ok'`

// PSIsolationKeep prints the DNS servers and default gateways (kept reachable
// during isolation so DHCP and name resolution keep working).
const PSIsolationKeep = `$ErrorActionPreference = 'SilentlyContinue'
Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses }
Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object { $_.NextHop }
'255.255.255.255'`
