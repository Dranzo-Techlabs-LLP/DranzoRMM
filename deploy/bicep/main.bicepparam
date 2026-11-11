// EXAMPLE parameters. Copy to main.local.bicepparam (git-ignored) and edit.
// Every value here is a placeholder; none is real.
using './main.bicep'

param namePrefix = 'dranzo'
param location = 'westeurope'

// Pin by digest once a real image exists.
param serverImage = 'EXAMPLE.azurecr.io/dranzo-server@sha256:0000000000000000000000000000000000000000000000000000000000000000'
param createRegistry = true

param publicDashboardUrl = 'https://rmm.example.invalid'
param agentsHostname = 'agents.example.invalid'
param agentsExposedPort = 8443
param splitAgentGateway = false

param postgresSkuName = 'Standard_D2ds_v5'
param postgresSkuTier = 'GeneralPurpose'
param postgresHighAvailability = false

// Secrets are NOT written in parameter files. Read them from the environment of the
// person or pipeline running the deployment:
//   export DRANZO_PG_ADMIN_PASSWORD="$(openssl rand -base64 32)"
param postgresAdminPassword = readEnvironmentVariable('DRANZO_PG_ADMIN_PASSWORD')

// First deployment only; afterwards unset DRANZO_BOOTSTRAP_ADMIN_PASSWORD (defaults to empty).
param bootstrapPartnerName = 'Example IT Services'
param bootstrapAdminEmail = 'admin@example.invalid'
param bootstrapAdminPassword = readEnvironmentVariable('DRANZO_BOOTSTRAP_ADMIN_PASSWORD', '')

// true for the very first deployment, then false (see README.md "Key store role").
param keyStoreInitialisation = true

param deployMeshCentral = false
