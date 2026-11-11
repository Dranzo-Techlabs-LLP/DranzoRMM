// Optional MeshCentral (remote desktop, Phase 6) with its own storage account and file share.
// LEAST VERIFIED PART of this deployment: MeshCentral's own configuration (config.json:
// TlsOffload, Cert name, trusted proxy, login token key) must be placed on the file share
// by the operator; see docs/RUNBOOK.md "MeshCentral".
param location string
param namePrefix string
param tags object = {}
param environmentName string
@description('MeshCentral container image, pinned by digest, e.g. ghcr.io/ylianst/meshcentral@sha256:<digest>.')
param image string
@minLength(3)
@maxLength(24)
param storageAccountName string

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: environmentName
}

// Azure Files mounts in Container Apps authenticate with the account key, so this account
// cannot disable shared-key access like the main blob account does. It holds MeshCentral
// data only and is separate for that reason.
resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: account
  name: 'default'
}

resource share 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: fileService
  name: 'meshcentral'
  properties: {
    shareQuota: 32
  }
}

resource envStorage 'Microsoft.App/managedEnvironments/storages@2024-03-01' = {
  parent: environment
  name: 'meshcentral'
  properties: {
    azureFile: {
      accountName: account.name
      accountKey: account.listKeys().keys[0].value
      shareName: share.name
      accessMode: 'ReadWrite'
    }
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-mesh'
  location: location
  tags: tags
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        transport: 'auto'
        targetPort: 80 // MeshCentral with "TlsOffload" listens on plain HTTP behind the platform's TLS
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'meshcentral'
          image: image
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          volumeMounts: [
            {
              volumeName: 'data'
              mountPath: '/opt/meshcentral/meshcentral-data'
              subPath: 'data'
            }
            {
              volumeName: 'data'
              mountPath: '/opt/meshcentral/meshcentral-files'
              subPath: 'files'
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'data'
          storageType: 'AzureFile'
          storageName: envStorage.name
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1 // MeshCentral keeps session state in process
      }
    }
  }
}

output fqdn string = app.properties.configuration.ingress.fqdn
