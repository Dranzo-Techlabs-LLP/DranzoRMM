// One Azure Container App running the DranzoRMM server image (or MeshCentral).
param location string
param name string
param tags object = {}
param environmentId string
param userAssignedIdentityId string
param image string
@description('Login server of the registry to pull from with the managed identity; empty for a public image.')
param registryServer string = ''
@description('Main ingress transport: "auto" (HTTP, TLS terminated by the platform) or "tcp" (raw TCP pass-through).')
@allowed(['auto', 'http', 'http2', 'tcp'])
param transport string = 'auto'
param targetPort int
@description('Exposed port for TCP main ingress (ignored for HTTP ingress, which is always 80/443).')
param exposedPort int = 0
@description('Extra TCP ports: [{ targetPort: int, exposedPort: int, external: bool }].')
param additionalPortMappings array = []
@description('Plain environment variables: [{ name, value }].')
param env array = []
@description('Key Vault backed secrets: [{ name: <secret ref>, keyVaultUrl: <secret URI> }].')
param keyVaultSecrets array = []
@description('Environment variables taken from secrets: [{ name, secretRef }].')
param secretEnv array = []
param cpu string = '1.0'
param memory string = '2Gi'
param minReplicas int = 1
param maxReplicas int = 1
@description('HTTP path for liveness/readiness probes; empty = TCP probe on targetPort.')
param healthPath string = ''

var isTcp = transport == 'tcp'

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentityId}': {}
    }
  }
  properties: {
    environmentId: environmentId
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        transport: transport
        targetPort: targetPort
        exposedPort: isTcp ? exposedPort : null
        allowInsecure: false
        additionalPortMappings: additionalPortMappings
      }
      registries: empty(registryServer)
        ? []
        : [
            {
              server: registryServer
              identity: userAssignedIdentityId
            }
          ]
      // Secrets are Key Vault references resolved with the managed identity; no secret
      // value is stored in the template, the deployment history or the app definition.
      secrets: [
        for s in keyVaultSecrets: {
          name: s.name
          keyVaultUrl: s.keyVaultUrl
          identity: userAssignedIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: name
          image: image
          resources: {
            cpu: json(cpu)
            memory: memory
          }
          env: concat(env, secretEnv)
          probes: empty(healthPath)
            ? [
                {
                  type: 'Liveness'
                  tcpSocket: {
                    port: targetPort
                  }
                  periodSeconds: 30
                }
              ]
            : [
                {
                  type: 'Liveness'
                  httpGet: {
                    path: healthPath
                    port: targetPort
                  }
                  periodSeconds: 30
                }
                {
                  type: 'Readiness'
                  httpGet: {
                    path: healthPath
                    port: targetPort
                  }
                  periodSeconds: 10
                }
              ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
    }
  }
}

output name string = app.name
output fqdn string = app.properties.configuration.ingress.fqdn
