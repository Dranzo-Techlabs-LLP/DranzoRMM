// Azure Database for PostgreSQL Flexible Server, private access only (VNet-integrated).
param location string
param name string
param tags object = {}
param delegatedSubnetId string
param privateDnsZoneId string
param databaseName string = 'dranzo'
param administratorLogin string
@secure()
param administratorPassword string
@description('Compute SKU, e.g. Standard_B2s (Burstable) for small fleets, Standard_D2ds_v5 (GeneralPurpose) for production.')
param skuName string = 'Standard_D2ds_v5'
@allowed(['Burstable', 'GeneralPurpose', 'MemoryOptimized'])
param skuTier string = 'GeneralPurpose'
param storageSizeGB int = 64
@description('Zone-redundant high availability (not available on the Burstable tier).')
param highAvailability bool = false
@minValue(7)
@maxValue(35)
param backupRetentionDays int = 14
param geoRedundantBackup bool = false

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: skuName
    tier: skuTier
  }
  properties: {
    version: '16'
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorPassword
    authConfig: {
      // The server uses a password connection string today (Npgsql). Moving to Entra ID
      // authentication with the managed identity is planned (docs/THREAT_MODEL.md, database).
      passwordAuth: 'Enabled'
      activeDirectoryAuth: 'Disabled'
    }
    storage: {
      storageSizeGB: storageSizeGB
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: backupRetentionDays
      geoRedundantBackup: geoRedundantBackup ? 'Enabled' : 'Disabled'
    }
    highAvailability: {
      mode: highAvailability ? 'ZoneRedundant' : 'Disabled'
    }
    network: {
      // Private access: no public endpoint exists at all.
      delegatedSubnetResourceId: delegatedSubnetId
      privateDnsZoneArmResourceId: privateDnsZoneId
      publicNetworkAccess: 'Disabled'
    }
  }
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: server
  name: databaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// TLS is mandatory (require_secure_transport is on by default); also refuse TLS < 1.2.
resource minTls 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: server
  name: 'ssl_min_protocol_version'
  properties: {
    value: 'TLSv1.2'
    source: 'user-override'
  }
  dependsOn: [
    database
  ]
}

output fqdn string = server.properties.fullyQualifiedDomainName
output databaseName string = database.name
