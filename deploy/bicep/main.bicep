// DranzoRMM on Azure: docs/ARCHITECTURE.md section 10.
//
// STATUS: NOT DEPLOYED AND NOT COMPILED. Written without the Azure CLI / Bicep CLI and
// without an Azure subscription. Validate before use (see README.md):
//   az bicep build --file deploy/bicep/main.bicep
//   az deployment group what-if -g <rg> -f deploy/bicep/main.bicep -p deploy/bicep/main.bicepparam
//
// Resources: Log Analytics, user-assigned managed identity, VNet + private DNS, two Key
// Vaults (configuration secrets / key store), Storage account + private blob container,
// PostgreSQL Flexible Server (private access), optional ACR, Container Apps environment
// (VNet-integrated), the DranzoRMM server app(s), optional MeshCentral.
//
// Secrets: only @secure() parameters, written straight into Key Vault and consumed by the
// apps as Key Vault references through the managed identity. No secret is an output.

targetScope = 'resourceGroup'

// ----- General -----
@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Short lowercase prefix for resource names (letters and digits).')
@minLength(3)
@maxLength(10)
param namePrefix string

@description('Tags applied to every resource.')
param tags object = {
  application: 'dranzormm'
}

// ----- Images -----
@description('DranzoRMM server image. Pin by digest for production: <registry>/dranzo-server@sha256:<digest>.')
param serverImage string

@description('Create an Azure Container Registry (Premium is not required: pulls use the managed identity).')
param createRegistry bool = true

@description('Login server of an existing registry to pull from when createRegistry is false (the identity must already have AcrPull). Empty = public image.')
param existingRegistryServer string = ''

// ----- Public names -----
@description('Public URL of the dashboard, e.g. https://rmm.example.com. Empty = the generated Container Apps URL.')
param publicDashboardUrl string = ''

@description('DNS name agents connect to (goes into the gateway certificate), e.g. agents.example.com. Empty = the generated Container Apps host name.')
param agentsHostname string = ''

@description('''Public TCP port of the agent gateway.
443 is NOT available: in a Container Apps environment ports 80/443 belong to the built-in HTTP
ingress and an exposed TCP port must be unique in the environment. See README.md "Port 443".''')
@minValue(1024)
@maxValue(65535)
param agentsExposedPort int = 8443

@description('''false (default): ONE container app serves the dashboard (HTTP ingress) and the agent gateway
(additional TCP port). Required today: the agent connection registry and SignalR are in-process.
true: separate "agents" app with TCP ingress, as drawn in docs/ARCHITECTURE.md section 10. Only
valid once the server has a cross-instance backplane.''')
param splitAgentGateway bool = false

// ----- Database -----
param postgresAdminLogin string = 'dranzoadmin'

@description('PostgreSQL administrator password. Supply at deployment time; never commit it.')
@secure()
param postgresAdminPassword string

param postgresSkuName string = 'Standard_D2ds_v5'
@allowed(['Burstable', 'GeneralPurpose', 'MemoryOptimized'])
param postgresSkuTier string = 'GeneralPurpose'
param postgresHighAvailability bool = false

// ----- First administrator (optional, first deployment only) -----
param bootstrapPartnerName string = ''
param bootstrapAdminEmail string = ''

@description('Password of the first administrator. Leave empty after the first deployment.')
@secure()
param bootstrapAdminPassword string = ''

// ----- Key store -----
@description('''true: the server identity is Key Vault Secrets Officer on the key-store vault so the FIRST start can
create the CA key and the command-signing key. After that first start redeploy with false: the
identity is then Key Vault Secrets User (read only) and can no longer replace or delete keys.''')
param keyStoreInitialisation bool = true

// ----- MeshCentral (optional) -----
param deployMeshCentral bool = false
@description('MeshCentral image, pinned by digest.')
param meshCentralImage string = ''
@description('MeshCentral login token key (160 hex characters from `meshcentral --logintokenkey`).')
@secure()
param meshLoginTokenKey string = ''
param meshUrl string = ''
param meshId string = ''

// ----- Names -----
var unique = uniqueString(resourceGroup().id, namePrefix)
var names = {
  logs: '${namePrefix}-logs'
  identity: '${namePrefix}-server-id'
  configVault: take('${namePrefix}cfg${unique}', 24)
  keyVault: take('${namePrefix}key${unique}', 24)
  storage: take('${namePrefix}st${unique}', 24)
  meshStorage: take('${namePrefix}mesh${unique}', 24)
  postgres: '${namePrefix}-pg-${take(unique, 6)}'
  registry: take('${namePrefix}acr${unique}', 50)
  environment: '${namePrefix}-env'
  dashboard: '${namePrefix}-dashboard'
  agents: '${namePrefix}-agents'
}
var acrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

// ----- Observability -----
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: names.logs
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
  }
}

// ----- Identity: one user-assigned identity for the server; every grant below is to it -----
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: names.identity
  location: location
  tags: tags
}

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
  }
}

// ----- Key Vault 1: configuration secrets (connection string, bootstrap password, Mesh key) -----
// Read by the Container Apps platform to resolve secret references, so it keeps a public
// endpoint (RBAC-protected, read-only for the server identity).
module configVault 'modules/keyvault.bicep' = {
  name: 'config-vault'
  params: {
    location: location
    name: names.configVault
    tags: tags
    principalId: identity.properties.principalId
    principalRole: 'user'
    privateOnly: false
    logAnalyticsWorkspaceId: logs.id
  }
}

// ----- Key Vault 2: key store (device CA key + certificate, command-signing key) -----
// Private endpoint only; reached by the server from inside the VNet (KeyVaultKeyStore).
// Secret names used by the server: device-ca-key, device-ca-cert, command-signing-key.
module keyStoreVault 'modules/keyvault.bicep' = {
  name: 'keystore-vault'
  params: {
    location: location
    name: names.keyVault
    tags: tags
    principalId: identity.properties.principalId
    principalRole: keyStoreInitialisation ? 'officer' : 'user'
    privateOnly: true
    privateEndpointSubnetId: network.outputs.privateEndpointSubnetId
    privateDnsZoneId: network.outputs.vaultPrivateDnsZoneId
    logAnalyticsWorkspaceId: logs.id
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    name: names.storage
    tags: tags
    principalId: identity.properties.principalId
    privateEndpointSubnetId: network.outputs.privateEndpointSubnetId
    privateDnsZoneId: network.outputs.blobPrivateDnsZoneId
  }
}

module postgres 'modules/postgres.bicep' = {
  name: 'postgres'
  params: {
    location: location
    name: names.postgres
    tags: tags
    delegatedSubnetId: network.outputs.postgresSubnetId
    privateDnsZoneId: network.outputs.postgresPrivateDnsZoneId
    administratorLogin: postgresAdminLogin
    administratorPassword: postgresAdminPassword
    skuName: postgresSkuName
    skuTier: postgresSkuTier
    highAvailability: postgresHighAvailability
  }
}

// ----- Secrets (values go from @secure() parameters straight into Key Vault) -----
module dbConnectionSecret 'modules/keyvault-secret.bicep' = {
  name: 'secret-db-connection'
  params: {
    vaultName: configVault.outputs.name
    secretName: 'db-connection-string'
    value: 'Host=${postgres.outputs.fqdn};Port=5432;Database=${postgres.outputs.databaseName};Username=${postgresAdminLogin};Password=${postgresAdminPassword};SSL Mode=VerifyFull'
  }
}

module bootstrapSecret 'modules/keyvault-secret.bicep' = if (!empty(bootstrapAdminPassword)) {
  name: 'secret-bootstrap-admin'
  params: {
    vaultName: configVault.outputs.name
    secretName: 'bootstrap-admin-password'
    value: bootstrapAdminPassword
  }
}

module meshSecret 'modules/keyvault-secret.bicep' = if (!empty(meshLoginTokenKey)) {
  name: 'secret-mesh-login-token'
  params: {
    vaultName: configVault.outputs.name
    secretName: 'mesh-login-token-key'
    value: meshLoginTokenKey
  }
}

// ----- Container registry (optional) -----
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = if (createRegistry) {
  name: names.registry
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    adminUserEnabled: false // pulls use the managed identity
    anonymousPullEnabled: false
  }
}

resource registryPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createRegistry) {
  scope: registry
  name: guid(registry.id, identity.id, acrPull)
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPull)
  }
}

var registryServer = createRegistry ? '${names.registry}${environment().suffixes.acrLoginServer}' : existingRegistryServer

// ----- Container Apps environment (VNet-integrated: required for external TCP ingress) -----
resource environmentResource 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: names.environment
  location: location
  tags: tags
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: network.outputs.containerAppsSubnetId
      internal: false // agents and technicians connect from the internet
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

// ----- Server configuration -----
var generatedHost = '${names.dashboard}.${environmentResource.properties.defaultDomain}'
var generatedAgentsHost = splitAgentGateway
  ? '${names.agents}.${environmentResource.properties.defaultDomain}'
  : generatedHost
var effectiveAgentsHost = empty(agentsHostname) ? generatedAgentsHost : agentsHostname
var effectiveDashboardUrl = empty(publicDashboardUrl) ? 'https://${generatedHost}' : publicDashboardUrl

var serverEnv = concat(
  [
    { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
    // DefaultAzureCredential picks the user-assigned identity by client id.
    { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
    { name: 'Dranzo__DashboardPort', value: '8080' }
    { name: 'Dranzo__AgentPort', value: '8443' }
    { name: 'Dranzo__PublicDashboardUrl', value: effectiveDashboardUrl }
    { name: 'Dranzo__PublicAgentUrl', value: 'https://${effectiveAgentsHost}:${agentsExposedPort}' }
    { name: 'Dranzo__AgentHostnames__0', value: effectiveAgentsHost }
    // The dashboard listener is only reachable through the Container Apps ingress, which
    // overwrites X-Forwarded-Proto and appends the client address to X-Forwarded-For.
    { name: 'Dranzo__TrustForwardedHeaders', value: 'true' }
    { name: 'Dranzo__KeyStore__Type', value: 'keyvault' }
    { name: 'Dranzo__KeyStore__VaultUri', value: keyStoreVault.outputs.uri }
    { name: 'Dranzo__Storage__Type', value: 'azure' }
    { name: 'Dranzo__Storage__AzureAccountUri', value: storage.outputs.blobEndpoint }
    { name: 'Dranzo__Storage__Bucket', value: storage.outputs.containerName }
  ],
  empty(bootstrapAdminEmail)
    ? []
    : [
        { name: 'Dranzo__Bootstrap__PartnerName', value: bootstrapPartnerName }
        { name: 'Dranzo__Bootstrap__AdminEmail', value: bootstrapAdminEmail }
      ],
  empty(meshUrl)
    ? []
    : [
        { name: 'Dranzo__Mesh__Url', value: meshUrl }
        { name: 'Dranzo__Mesh__MeshId', value: meshId }
      ]
)

var serverSecrets = concat(
  [
    { name: 'db-connection-string', keyVaultUrl: dbConnectionSecret.outputs.secretUri }
  ],
  empty(bootstrapAdminPassword)
    ? []
    : [
        { name: 'bootstrap-admin-password', keyVaultUrl: '${configVault.outputs.uri}secrets/bootstrap-admin-password' }
      ],
  empty(meshLoginTokenKey)
    ? []
    : [
        { name: 'mesh-login-token-key', keyVaultUrl: '${configVault.outputs.uri}secrets/mesh-login-token-key' }
      ]
)

var serverSecretEnv = concat(
  [
    { name: 'ConnectionStrings__Default', secretRef: 'db-connection-string' }
  ],
  empty(bootstrapAdminPassword)
    ? []
    : [
        { name: 'Dranzo__Bootstrap__AdminPassword', secretRef: 'bootstrap-admin-password' }
      ],
  empty(meshLoginTokenKey)
    ? []
    : [
        { name: 'Dranzo__Mesh__LoginTokenKey', secretRef: 'mesh-login-token-key' }
      ]
)

// ----- Apps -----
// One replica: the agent registry, SignalR groups and the job dispatcher's "who holds this
// socket" lookup are in-process (docs/ARCHITECTURE.md section 9).
module dashboard 'modules/containerapp.bicep' = {
  name: 'app-dashboard'
  params: {
    location: location
    name: names.dashboard
    tags: tags
    environmentId: environmentResource.id
    userAssignedIdentityId: identity.id
    image: serverImage
    registryServer: registryServer
    transport: 'auto'
    targetPort: 8080
    // Agent gateway as an additional TCP port of the same process: TLS and mTLS are
    // terminated by Kestrel itself with the private-CA certificate, end to end.
    additionalPortMappings: splitAgentGateway
      ? []
      : [
          {
            external: true
            targetPort: 8443
            exposedPort: agentsExposedPort
          }
        ]
    env: serverEnv
    keyVaultSecrets: serverSecrets
    secretEnv: serverSecretEnv
    healthPath: '/healthz'
    minReplicas: 1
    maxReplicas: 1
  }
  dependsOn: [
    bootstrapSecret
    meshSecret
    registryPull
  ]
}

module agents 'modules/containerapp.bicep' = if (splitAgentGateway) {
  name: 'app-agents'
  params: {
    location: location
    name: names.agents
    tags: tags
    environmentId: environmentResource.id
    userAssignedIdentityId: identity.id
    image: serverImage
    registryServer: registryServer
    transport: 'tcp'
    targetPort: 8443
    exposedPort: agentsExposedPort
    env: serverEnv
    keyVaultSecrets: serverSecrets
    secretEnv: serverSecretEnv
    minReplicas: 1
    maxReplicas: 1
  }
  dependsOn: [
    bootstrapSecret
    meshSecret
    registryPull
  ]
}

module mesh 'modules/meshcentral.bicep' = if (deployMeshCentral) {
  name: 'meshcentral'
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
    environmentName: environmentResource.name
    image: meshCentralImage
    storageAccountName: names.meshStorage
  }
}

// ----- Outputs (no secrets) -----
output dashboardUrl string = effectiveDashboardUrl
output dashboardFqdn string = dashboard.outputs.fqdn
output agentUrl string = 'https://${effectiveAgentsHost}:${agentsExposedPort}'
output environmentStaticIp string = environmentResource.properties.staticIp
output keyStoreVaultName string = keyStoreVault.outputs.name
output configVaultName string = configVault.outputs.name
output storageAccountName string = storage.outputs.name
output postgresFqdn string = postgres.outputs.fqdn
output registryLoginServer string = registryServer
output serverIdentityClientId string = identity.properties.clientId
