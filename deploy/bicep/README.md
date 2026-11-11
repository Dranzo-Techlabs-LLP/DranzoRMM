# Azure deployment (Bicep)

> **Not deployed and not compiled.** These templates were written without the Azure CLI, the
> Bicep CLI or an Azure subscription. They were reviewed by hand and passed only a structural
> check (balanced syntax, module parameters match). Expect `az bicep build` to report things to
> fix. Do not treat a successful `what-if` as proof that the application works on this topology.

## Validate first

```sh
az bicep build --file deploy/bicep/main.bicep                 # compile + linter
az bicep lint  --file deploy/bicep/main.bicep
cp deploy/bicep/main.bicepparam deploy/bicep/main.local.bicepparam   # git-ignored; edit it
export DRANZO_PG_ADMIN_PASSWORD="$(openssl rand -base64 32)"
export DRANZO_BOOTSTRAP_ADMIN_PASSWORD='<first admin password, 12+ characters>'
az group create -n rg-dranzo-prod -l westeurope
az deployment group validate -g rg-dranzo-prod -f deploy/bicep/main.bicep -p deploy/bicep/main.local.bicepparam
az deployment group what-if  -g rg-dranzo-prod -f deploy/bicep/main.bicep -p deploy/bicep/main.local.bicepparam
az deployment group create   -g rg-dranzo-prod -f deploy/bicep/main.bicep -p deploy/bicep/main.local.bicepparam
```

Deploying costs money (PostgreSQL Flexible Server, Container Apps, private endpoints, Log
Analytics, optional ACR). Get the owner's go-ahead first (`docs/SPEC.md` section 10, rule 3).

## What it creates

| Resource | Module | Notes |
|---|---|---|
| Log Analytics workspace | `main.bicep` | Container logs; Key Vault audit logs. 90 days. |
| User-assigned managed identity | `main.bicep` | The only identity the server uses. Every role assignment is to it. |
| VNet, 3 subnets, 3 private DNS zones | `modules/network.bicep` | Container Apps (delegated), PostgreSQL (delegated), private endpoints. |
| Key Vault "config" | `modules/keyvault.bicep` | Connection string, bootstrap password, Mesh key. RBAC, soft delete 90 d, purge protection. Identity: **Key Vault Secrets User**. Public endpoint (see below). |
| Key Vault "key store" | `modules/keyvault.bicep` | Device CA key + certificate, command-signing key (`device-ca-key`, `device-ca-cert`, `command-signing-key`). Private endpoint only. Identity: **Secrets Officer** for the first start, then **Secrets User**. |
| Storage account + container `dranzo` | `modules/storage.bicep` | No public access, no shared keys, TLS 1.2, private endpoint. Identity: **Storage Blob Data Contributor on the container only**. |
| PostgreSQL Flexible Server 16 | `modules/postgres.bicep` | Private access (delegated subnet), no public network, TLS 1.2 minimum, backups 14 days. |
| Container registry (optional) | `main.bicep` | Admin user off; identity has **AcrPull**. |
| Container Apps environment | `main.bicep` | VNet-integrated (needed for external TCP ingress), workload profiles. |
| `dashboard` container app | `modules/containerapp.bicep` | HTTP ingress → 8080. By default also the agent gateway as an additional TCP port → 8443. One replica. |
| `agents` container app (optional) | `modules/containerapp.bicep` | TCP ingress → 8443. Only with `splitAgentGateway=true`. |
| MeshCentral (optional) | `modules/meshcentral.bicep` | Own storage account + Azure Files share. Least verified part. |

Secrets enter only as `@secure()` parameters (read from environment variables by the parameter
file), are written to Key Vault by `modules/keyvault-secret.bicep` and reach the apps as Key
Vault references. No output contains a secret.

## Deviations from `docs/ARCHITECTURE.md` section 10, and why

### Port 443 for agents is not available on Container Apps

The architecture document and the brief want the agent gateway on **TCP 443**. In a Container
Apps environment an externally exposed TCP port must be unique across the environment
*including the 80/443 used by the built-in HTTP ingress*
([ingress overview](https://learn.microsoft.com/azure/container-apps/ingress-overview),
"Additional TCP ports"). `agentsExposedPort` therefore defaults to **8443** and the template
rejects values below 1024.

This matters: `docs/SPEC.md` section 1 promises outbound **443** so client firewalls need no
changes. Options, none implemented here:

1. Put a public Azure Load Balancer or Azure Firewall DNAT rule (443 → environment IP : 8443)
   in front. TLS stays end to end, so agent mTLS and CA pinning are unaffected.
2. Run the agent gateway somewhere that can bind 443 for raw TCP (a VM scale set, AKS with a
   LoadBalancer service).
3. Accept 8443 and document the firewall requirement for clients.

Decide before the first production enrolment: the port is part of the URL baked into every
installed agent's configuration.

### One app, not two

Section 10 draws a `dashboard` app and an `agents` app running the same image with
`DRANZO_ROLE=agents`. Two things prevent that today:

- The server has no `DRANZO_ROLE` switch; every process starts both listeners.
- The agent connection registry, the SignalR groups and the dispatcher's socket lookup are
  in-process (`docs/ARCHITECTURE.md` section 9). With two apps a job created through the
  dashboard process could not reach an agent connected to the other process, and live updates
  would not arrive.

Default (`splitAgentGateway=false`): one app, HTTP ingress for the dashboard plus an
**additional TCP port** for the agent gateway, one replica. `splitAgentGateway=true` deploys
the two-app layout for the day a backplane exists.

### Two Key Vaults

- The Container Apps platform resolves Key Vault secret references from outside the VNet, so
  the vault that holds them cannot be private-endpoint only. That is the "config" vault, where
  the server identity can only read.
- The key-store vault is read by the server itself over the private endpoint and has no public
  network access.

Separating them also means the identity's write permission (needed once, see next section)
never covers the connection string, and vice versa.

## Key store role (do this after the first start)

`KeyVaultKeyStore` creates the CA key and the command-signing key on first start
(`SetSecret`), which needs **Key Vault Secrets Officer**. Deploy first with
`keyStoreInitialisation = true`, start the server once, confirm the three secrets exist, then
redeploy with `keyStoreInitialisation = false`. The identity is then **Key Vault Secrets
User**: a compromised server process can still *read* the keys (they are loaded into memory
anyway) but can no longer overwrite or delete them. Check that the old Officer assignment is
gone (`az role assignment list --scope <key-store vault id>`); an incremental deployment does
not remove role assignments it no longer declares, so delete it by hand if it is still listed.

## After deployment

1. DNS: point the dashboard and agent names at the app FQDN (outputs `dashboardFqdn`,
   `environmentStaticIp`); bind the dashboard custom domain and a managed certificate.
2. Set `agentsHostname` **before** the first start: it is written into the gateway certificate
   and into every agent's configuration.
3. First sign-in with the bootstrap administrator, enrol MFA, then redeploy without
   `DRANZO_BOOTSTRAP_ADMIN_PASSWORD` and delete the `bootstrap-admin-password` secret.
4. Back up the key-store vault secrets offline (`docs/RUNBOOK.md` "Key management").

## Known gaps

- PostgreSQL uses password authentication with the administrator login; a dedicated
  least-privilege application role and Entra ID authentication are planned.
- No Azure Front Door / WAF in front of the dashboard, no DDoS plan, no IP restrictions on the
  dashboard ingress.
- No diagnostic settings on Storage or PostgreSQL, no alerts.
- The Key Vault private DNS zone name is the public-cloud one.
- `publicNetworkAccess: 'Disabled'` together with a delegated subnet on the PostgreSQL server,
  the `additionalPortMappings` shape and the `ssl_min_protocol_version` setting are written
  from memory of the resource schemas and are the most likely places for `az bicep build` or
  the deployment to complain.
- MeshCentral needs its `config.json` placed on the file share by hand and is not wired to the
  server's `Dranzo:Mesh:*` settings beyond passing `meshUrl`, `meshId` and the login token key.
