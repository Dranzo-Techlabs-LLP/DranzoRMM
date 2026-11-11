// Writes one secret into an existing Key Vault. The value arrives as a @secure() parameter
// and is never an output; only the secret's URI is returned (for Key Vault references).
param vaultName string
param secretName string
@secure()
param value string

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: vaultName
}

resource secret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: secretName
  properties: {
    contentType: 'text/plain'
    value: value
  }
}

// Version-less URI: the app picks up a rotated value on its next revision / restart.
output secretUri string = '${vault.properties.vaultUri}secrets/${secretName}'
