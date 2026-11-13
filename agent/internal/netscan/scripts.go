package netscan

// PSNeighbors prints the IPv4 neighbor table as JSON (Windows).
const PSNeighbors = `$ErrorActionPreference = 'Stop'
Get-NetNeighbor -AddressFamily IPv4 |
  Where-Object { $_.State -ne 'Unreachable' -and $_.State -ne 'Incomplete' -and $_.LinkLayerAddress } |
  Select-Object IPAddress, LinkLayerAddress, @{n='State';e={[string]$_.State}} |
  ConvertTo-Json -Compress`

// PSGateway prints the IPv4 default route next hops, lowest metric first (Windows).
const PSGateway = `$ErrorActionPreference = 'Stop'
Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  Sort-Object { $_.RouteMetric + $_.InterfaceMetric } |
  ForEach-Object { $_.NextHop }`
