// Virtual network: one subnet per concern, private DNS zones for the private endpoints.
@description('Azure region.')
param location string
@description('Name prefix for network resources.')
param namePrefix string
param tags object = {}
@description('Address space of the virtual network.')
param addressPrefix string = '10.40.0.0/16'
@description('Container Apps infrastructure subnet (workload profiles: /27 minimum; /23 leaves room to scale).')
param containerAppsSubnetPrefix string = '10.40.0.0/23'
@description('Delegated subnet for PostgreSQL Flexible Server.')
param postgresSubnetPrefix string = '10.40.2.0/27'
@description('Subnet for private endpoints (Key Vault, Storage).')
param privateEndpointSubnetPrefix string = '10.40.2.32/27'

var blobZoneName = 'privatelink.blob.${environment().suffixes.storage}'
// Key Vault private link zone for the public cloud; other clouds use a different zone name.
var vaultZoneName = 'privatelink.vaultcore.azure.net'
// Flexible Server with VNet integration needs a zone that ends in ".postgres.database.azure.com".
var postgresZoneName = '${namePrefix}.private.postgres.database.azure.com'

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
    subnets: [
      {
        name: 'snet-containerapps'
        properties: {
          addressPrefix: containerAppsSubnetPrefix
          delegations: [
            {
              name: 'containerapps'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'snet-postgres'
        properties: {
          addressPrefix: postgresSubnetPrefix
          delegations: [
            {
              name: 'postgres'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
      {
        name: 'snet-private-endpoints'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

resource zones 'Microsoft.Network/privateDnsZones@2024-06-01' = [
  for zone in [blobZoneName, vaultZoneName, postgresZoneName]: {
    name: zone
    location: 'global'
    tags: tags
  }
]

resource zoneLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [
  for (zone, i) in [blobZoneName, vaultZoneName, postgresZoneName]: {
    parent: zones[i]
    name: '${namePrefix}-link'
    location: 'global'
    tags: tags
    properties: {
      registrationEnabled: false
      virtualNetwork: {
        id: vnet.id
      }
    }
  }
]

output vnetId string = vnet.id
output containerAppsSubnetId string = '${vnet.id}/subnets/snet-containerapps'
output postgresSubnetId string = '${vnet.id}/subnets/snet-postgres'
output privateEndpointSubnetId string = '${vnet.id}/subnets/snet-private-endpoints'
output blobPrivateDnsZoneId string = zones[0].id
output vaultPrivateDnsZoneId string = zones[1].id
output postgresPrivateDnsZoneId string = zones[2].id
