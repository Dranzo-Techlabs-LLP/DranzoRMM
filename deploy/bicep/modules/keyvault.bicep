// Key Vault with Azure RBAC, soft delete and purge protection. Optionally private-endpoint only.
param location string
@minLength(3)
@maxLength(24)
param name string
param tags object = {}
@description('Principal (the user-assigned managed identity) that reads secrets.')
param principalId string
@description('Role for that principal: "user" = Key Vault Secrets User (get), "officer" = Key Vault Secrets Officer (get, set, delete).')
@allowed(['user', 'officer'])
param principalRole string = 'user'
@description('When true the vault has no public network access and is reached through a private endpoint.')
param privateOnly bool = true
param privateEndpointSubnetId string = ''
param privateDnsZoneId string = ''
param logAnalyticsWorkspaceId string

// Built-in role definition IDs (identical in every tenant).
var roles = {
  user: '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
  officer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' // Key Vault Secrets Officer
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true // no access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true // cannot be turned off again; a deleted key stays recoverable for 90 days
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: privateOnly ? 'Disabled' : 'Enabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: privateOnly ? 'Deny' : 'Allow'
    }
  }
}

resource access 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, principalId, roles[principalRole])
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles[principalRole])
  }
}

resource endpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = if (privateOnly) {
  name: '${name}-pe'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: vault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource endpointDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = if (privateOnly) {
  parent: endpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

// Every secret read, write and delete is logged: this is the audit trail for key access.
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: vault
  name: 'audit'
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
  }
}

output name string = vault.name
output uri string = vault.properties.vaultUri
output id string = vault.id
