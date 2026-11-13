# DranzoRMM runbook

Operations guide for developers and operators. Written 2026-11-11.

**Honesty note.** Local development commands in sections 1 to 3 match the code. Production
(section 6), backup/restore (7) and the key-rotation and incident procedures (4, 5, 8) are
**outlines that have not been rehearsed**: there is no production deployment, the Bicep has
never been deployed, no code-signing has been performed and `trust.rotate` has no dashboard
workflow yet. Rehearse each procedure on a staging environment before relying on it.

## 1. Local development

### 1.1 Prerequisites

| Tool | Version | Used for |
|---|---|---|
| .NET SDK | 10.0 | server |
| Go | 1.27 (see `agent/go.mod`) | agent |
| Node.js | 26 (npm) | web |
| PostgreSQL | 16 | server and its tests (a container is fine) |
| Docker (Colima on macOS) | recent | compose stack, package tests |
| golangci-lint 2.x, nfpm 2.48, pre-commit | optional | lint, Linux packages, hooks |

```sh
pre-commit install            # once per clone: secret scan + basic hygiene on every commit
```

### 1.2 Run the pieces by hand

```sh
# PostgreSQL
docker run -d --name dranzo-pg -e POSTGRES_PASSWORD=<pick one> -p 5432:5432 postgres:16

# Server (development): keys and storage default to ~/.dranzormm-dev/ (outside the repository)
cd server
export ConnectionStrings__Default='Host=localhost;Database=dranzo;Username=postgres;Password=<the one you picked>'
export Dranzo__Bootstrap__PartnerName='Dev IT'
export Dranzo__Bootstrap__AdminEmail='admin@example.invalid'
export Dranzo__Bootstrap__AdminPassword='<12+ characters>'
ASPNETCORE_ENVIRONMENT=Development dotnet run --project src/Dranzo.Api
#   dashboard API  http://localhost:8080      agent gateway  https://localhost:8443 (private CA)

# Web
cd web && npm ci && npm run dev          # http://localhost:5173

# Agent against the real server, in the foreground, with a throwaway data directory
cd agent && make build
#   get ca.pem + trust.json from GET /api/v1/agent/install-info (dashboard: Enrollment),
#   put them in ./dev-data as ca.pem / trust.json, create a token in the dashboard, then:
printf '{"serverUrl":"https://localhost:8443","token":"<token>"}' > dev-data/bootstrap.json && chmod 600 dev-data/*
./dist/dranzo-agent run --foreground --data-dir ./dev-data
```

The agent can also be exercised without the server: `go run ./cmd/fakeserver ...` (see
`agent/README.md`).

### 1.3 Full stack

```sh
cp .env.example .env        # replace every CHANGE_ME value
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
#   dashboard  http://localhost:8081   (sign in as DRANZO_ADMIN_EMAIL; enroll an authenticator app)
#   API direct http://localhost:8080   agent gateway https://localhost:8443
scripts/e2e.sh              # sign-in, org/token, Linux agent container, script, files session, revoke
```

`scripts/e2e.py --help` lists more modes: `--agent native --agent-binary <path>` runs a locally built
agent against the stack, and `--update-binary <agent built with a newer version>` adds a signed
self-update round trip. The test keeps the administrator's dev-only TOTP seed in
`deploy/.e2e-state.json` (git-ignored); delete it together with `docker compose down -v`.

Object storage is **Azurite** (Microsoft's Azure Blob emulator), not MinIO: MinIO no longer
publishes container images. The server's S3 client is still available (`Dranzo__Storage__Type=s3`).

### 1.4 Tests and checks (the same commands CI runs)

```sh
cd server && dotnet restore --locked-mode && dotnet build -c Release \
  && dotnet format --verify-no-changes --no-restore \
  && DRANZO_TEST_PG='Host=localhost;Username=postgres;Password=<...>' dotnet test -c Release
cd agent  && make check                       # gofmt, vet for 6 targets, test -race, golangci-lint
cd web    && npm ci && npm run lint && npm run typecheck && npm test && npm run build
scripts/build-agent.sh                        # six targets (+ macOS universal) into dist/agent
```

The server tests create and drop throwaway databases on the server named by `DRANZO_TEST_PG`.

## 2. Configuration reference

Source of truth: `server/src/Dranzo.Api/DranzoOptions.cs`. Every setting can be given in
`appsettings.json` as `Dranzo:Section:Key` or as an environment variable with double
underscores: `Dranzo__Section__Key`. Array items use an index: `Dranzo__AgentHostnames__0`.

| Setting | Env var | Default | Meaning |
|---|---|---|---|
| `ConnectionStrings:Default` | `ConnectionStrings__Default` | `Host=localhost;Database=dranzo` | PostgreSQL (Npgsql) connection string. **Secret.** |
| `Dranzo:DashboardPort` | `Dranzo__DashboardPort` | `8080` | Plain-HTTP listener for API, SignalR and static web. TLS is terminated by the ingress. |
| `Dranzo:AgentPort` | `Dranzo__AgentPort` | `8443` | TLS/mTLS listener for agents (certificate from the private CA). |
| `Dranzo:AgentHostnames` | `Dranzo__AgentHostnames__0..n` | `localhost`, `127.0.0.1` | DNS names / IPs in the gateway certificate. Must contain the host agents connect to. |
| `Dranzo:PublicAgentUrl` | `Dranzo__PublicAgentUrl` | `https://localhost:8443` | URL shown in install commands. |
| `Dranzo:PublicDashboardUrl` | `Dranzo__PublicDashboardUrl` | `http://localhost:5173` | URL used in links. |
| `Dranzo:TrustForwardedHeaders` | `Dranzo__TrustForwardedHeaders` | `false` | Honour `X-Forwarded-For` / `X-Forwarded-Proto`. See 6.3. |
| `Dranzo:RunBackgroundServices` | `Dranzo__RunBackgroundServices` | `true` | Tests only. |
| `Dranzo:RunDispatcher` | `Dranzo__RunDispatcher` | `true` | Tests only. |
| **Key store** | | | |
| `Dranzo:KeyStore:Type` | `Dranzo__KeyStore__Type` | `file` | `file` or `keyvault`. |
| `Dranzo:KeyStore:Directory` | `Dranzo__KeyStore__Directory` | `~/.dranzormm-dev/keys` | File keystore directory (`0700`, files `0600`). Never inside the repository. |
| `Dranzo:KeyStore:VaultUri` | `Dranzo__KeyStore__VaultUri` | - | Key Vault URI when `Type=keyvault` (managed identity; set `AZURE_CLIENT_ID` for a user-assigned identity). |
| **Storage** | | | |
| `Dranzo:Storage:Type` | `Dranzo__Storage__Type` | `file` | `file`, `s3` (MinIO) or `azure`. |
| `Dranzo:Storage:Directory` | `Dranzo__Storage__Directory` | `~/.dranzormm-dev/storage` | `file` only. |
| `Dranzo:Storage:S3ServiceUrl`, `S3AccessKey`, `S3SecretKey` | `Dranzo__Storage__S3...` | - | `s3` only. `S3SecretKey` is a **secret**. |
| `Dranzo:Storage:Bucket` | `Dranzo__Storage__Bucket` | `dranzo` | Bucket / container name. |
| `Dranzo:Storage:AzureAccountUri` | `Dranzo__Storage__AzureAccountUri` | - | Blob endpoint; uses the managed identity (preferred). |
| `Dranzo:Storage:AzureConnectionString` | `Dranzo__Storage__AzureConnectionString` | - | Alternative to the above. **Secret**; avoid. |
| `Dranzo:Storage:MaxPackageBytes` | | 2 GiB | Upload cap for packages. |
| `Dranzo:Storage:MaxFileTransferBytes` | | 100 MiB | Cap for session file transfers. |
| **Auth** | | | |
| `Dranzo:Auth:SessionIdleMinutes` / `SessionAbsoluteHours` | | 30 / 12 | Session timeouts. |
| `Dranzo:Auth:StepUpMinutes` | | 5 | How long a step-up (TOTP re-entry) stays fresh. |
| `Dranzo:Auth:LockoutThreshold` / `LockoutMinutes` | | 5 / 15 | Failed attempts before lockout, and its length. |
| `Dranzo:Auth:PasswordMinLength` | | 12 | |
| `Dranzo:Auth:BulkStepUpThreshold` | | 10 | Device count above which a job needs step-up. |
| `Dranzo:Auth:Issuer` | | `DranzoRMM` | Name shown in authenticator apps. |
| **Agents** | | | |
| `Dranzo:Agents:HeartbeatSeconds` / `MissedHeartbeats` | | 60 / 3 | Offline after `HeartbeatSeconds × MissedHeartbeats`. |
| `Dranzo:Agents:CertValidityDays` | | 90 | Device certificate lifetime; agents renew in the last third. |
| `Dranzo:Agents:MaxMessageBytes`, `MessagesPerSecond`, `MessageBurst` | | 2 MiB, 50, 200 | Per-connection limits. |
| `Dranzo:Agents:InventoryIntervalSeconds`, `SoftwareIntervalSeconds`, `PostureIntervalSeconds`, `PatchScanIntervalSeconds` | | 6 h, 12 h, 1 h, 12 h | Report intervals sent in `hello.ack`. |
| `Dranzo:Agents:MaxConcurrentRunsPerDevice` | | 4 | |
| `Dranzo:Agents:PendingRunExpiryHours` | | 24 | Queued runs for offline devices expire after this. |
| `Dranzo:Agents:CommandValiditySeconds` | | 300 | Lifetime of a signed command (agents refuse more than 15 min). |
| **Bootstrap** | | | |
| `Dranzo:Bootstrap:PartnerName`, `AdminEmail`, `AdminPassword` | `Dranzo__Bootstrap__...` | - | First partner and administrator; used only while the database has no partner. `AdminPassword` is a **secret**. |
| **SMTP** | | | |
| `Dranzo:Smtp:Host`, `Port`, `Username`, `Password`, `From`, `UseStartTls` | `Dranzo__Smtp__...` | port 587, STARTTLS on | Notification e-mail. `Password` is a **secret**. |
| **MeshCentral** | | | |
| `Dranzo:Mesh:Url`, `MeshId`, `User`, `Domain` | `Dranzo__Mesh__...` | user `admin` | MeshCentral endpoint and identity. |
| `Dranzo:Mesh:LoginTokenKey` | `Dranzo__Mesh__LoginTokenKey` | - | From `meshcentral --logintokenkey`. **Secret**: equals MeshCentral access as `User`. |
| `Dranzo:Mesh:CertificateSha256` | `Dranzo__Mesh__CertificateSha256` | - | Hex SHA-256 of MeshCentral's HTTPS certificate when it is self-signed (`openssl x509 -in webserver-cert-public.crt -noout -fingerprint -sha256`). The server then trusts exactly that certificate for MeshAgent downloads. `MeshId` is the group id without the `mesh//` prefix. |
| `Dranzo:Mesh:AllowSharedUser` | | `false` | Only safe with a single organisation (a shared MeshCentral login sees every device). |
| `Dranzo:Mesh:LoginTokenMinutes` | | 2 | Lifetime of minted login tokens. |
| `Dranzo:Mesh:AgentIds` | | built in | MeshCentral agent ids per `os-arch`; check against your MeshCentral version. |
| **Feeds** | | | |
| `Dranzo:Feeds:Enabled`, `KevUrl`, `NvdUrl`, `NvdApiKey`, `SyncHours` | `Dranzo__Feeds__...` | disabled, 24 h | CISA KEV and NVD synchronisation. |
| **Rate limits** | | | |
| `Dranzo:RateLimits:AuthPerMinute`, `EnrollPerMinute`, `ApiPerMinute`, `ApiKeyPerMinute` | | 10, 30, 600, 120 | Per IP (per key for API keys), fixed one-minute window. |

Other variables: `ASPNETCORE_ENVIRONMENT` (`Development` enables console logs and the
non-`__Host-` cookie name), `DRANZO_TEST_PG` (tests), `DRANZO_DB` (`dotnet ef` design time only).

## 3. First administrator

1. Start the server with the three `Dranzo:Bootstrap:*` values set and an empty database. The
   log says `Created partner ... and first administrator ...`. The password must pass the
   password policy or the server refuses to start.
2. Sign in. MFA enrolment is forced: scan the QR code, enter a code, **store the ten recovery
   codes offline**. No account works without TOTP.
3. Remove `Dranzo:Bootstrap:AdminPassword` from the environment / Key Vault and restart. The
   values are ignored once a partner exists, but a secret that is no longer needed should not
   stay configured.
4. Create named accounts for every technician; do not share the bootstrap account. Give
   Technician roles at organisation or site scope, not partner scope, unless needed.

Lost second factor for the only administrator: there is no bypass by design. Restore access by
using a recovery code; if none are left, a database operator must clear `TotpEnabled` and
`TotpSecretProtected` for that user (which forces re-enrolment at next sign-in) and record the
intervention. Treat such a change as a security event.

## 4. Key management

| Key | Stored as (key store entry) | Loss means | Theft means |
|---|---|---|---|
| Device CA private key + certificate | `device-ca-key`, `device-ca-cert` | No renewals or enrolments; a new CA cannot be pinned remotely without a valid command key | Impersonation of server (channel) and devices |
| Command-signing key (Ed25519 seed) | `command-signing-key` | No commands; agents cannot be told to trust a new key | **Code execution on every agent that trusts it** |
| ASP.NET Data Protection key ring | database table `DataProtectionKeys` | All TOTP secrets unreadable: every user must re-enrol MFA | TOTP secrets decryptable |

### 4.1 Backup

- **Development (`file` key store):** copy the directory (`~/.dranzormm-dev/keys` by default)
  to encrypted offline storage. The files are base64 of the raw key material: handle the copy
  like the key.
- **Production (Key Vault):** soft delete (90 days) and purge protection guard against
  deletion, not against a lost subscription. After first start export the three secrets once
  to an **offline, encrypted** medium held by two people:

  ```sh
  az keyvault secret backup --vault-name <key-store-vault> --name command-signing-key --file command-signing-key.bak
  az keyvault secret backup --vault-name <key-store-vault> --name device-ca-key      --file device-ca-key.bak
  az keyvault secret backup --vault-name <key-store-vault> --name device-ca-cert     --file device-ca-cert.bak
  ```

  (`secret backup` blobs can only be restored into a vault in the same Azure geography and
  subscription family. Also keep a plain export in an HSM or an offline password manager if you
  need to survive losing the tenant. Reading the vault requires temporary network access and a
  privileged role; grant both just in time and remove them.)
- Test a restore into a scratch vault at least once.

### 4.2 Rotating the command-signing key (`trust.rotate`)

Agents accept a new key set only from a `trust.rotate` command signed by a key they already
trust (`docs/PROTOCOL.md` 6.7). Outline:

1. Generate the new Ed25519 key; store it under a new key-store entry.
2. Send `trust.rotate` (signed with the **old** key) to every device with `commandKeys` =
   [old, new]. Offline devices get it when they reconnect; track which devices report the new
   key id in `hello.trustKeyIds`.
3. Switch the server to sign with the new key.
4. When every active device trusts the new key, send `trust.rotate` (signed with the new key)
   with `commandKeys` = [new]. Devices that never came online keep trusting the old key until
   they do; revoke or reinstall the stragglers.
5. Destroy the old key. Rebuild installers with the new embedded key
   (`DRANZO_EMBED_COMMAND_KEYS`).

**Gap:** the server has no endpoint or UI for steps 2 to 4 today, and `Ed25519CommandSigner`
loads exactly one key. This procedure is the design, not a working feature. Until it exists,
the only rotation path is reinstalling agents with new trust files.

**Strong recommendation before production:** generate a second, **offline** command key now and
include its public half in every agent build. If the online key is stolen, the offline key can
still sign a `trust.rotate` that removes it.

### 4.3 Rotating the device CA

Same mechanism: `trust.rotate` with `caCertificates` = old + new, then issue the gateway
certificate and device certificates from the new CA (devices pick it up at renewal, within
`CertValidityDays`), then drop the old CA from trust stores. Not implemented in the server yet.
The CA certificate is valid for 10 years from first start; plan the rotation long before.

## 5. Certificates

- **Device certificates** are issued at enrolment, valid `CertValidityDays` (90). Agents renew
  automatically when under one third of the lifetime remains and check daily. The previous
  certificate stays valid until the first connection with the new one. Dashboard: device
  detail shows `CertNotAfter`.
- **A device that was offline past expiry** cannot renew (renewal needs a valid certificate).
  Re-enrol it: `dranzo-agent uninstall` then `dranzo-agent install --server ... --token ...`
  (it becomes a new device record).
- **Revocation:** Devices → device → Revoke (`POST /api/v1/devices/{id}/revoke`, needs
  `devices.revoke` and step-up). Effect is immediate: the thumbprints are cleared and the
  connection is closed; the agent gets `403` and backs off. There is no CRL or OCSP and none is
  needed: the gateway checks every request against the database.
- **Gateway server certificate** is issued in memory from the CA at start, valid 60 days,
  re-issued automatically 7 days before expiry. A restart also re-issues it. Agents pin the CA,
  not this certificate.

## 6. Production deployment (Azure): outline

Nothing here has been deployed. Read `deploy/bicep/README.md` first, in particular the two
deviations from `docs/ARCHITECTURE.md`: the agent gateway cannot use port 443 on Container
Apps, and one container app serves both listeners.

### 6.1 Order of work

1. Decide the agent host name and port. They are baked into every agent's configuration and
   into the gateway certificate.
2. Build and push the server image; pin it by digest in the parameter file.
3. `az deployment group what-if`, then `create` (owner approval: this costs money).
4. First start with `keyStoreInitialisation=true`: the server creates the CA and signing keys
   in the key-store vault. Back them up (4.1). Redeploy with `keyStoreInitialisation=false`.
5. Sign in as the bootstrap administrator (section 3). Remove the bootstrap secret.
6. Record the trust anchors from `GET /api/v1/agent/install-info`; set the repository variables
   `DRANZO_EMBED_COMMAND_KEYS` and `DRANZO_EMBED_CA_PEM_B64`; build signed installers (section 9).
7. Enrol one test device per OS before any client device.

### 6.2 Scaling

One replica only. The agent registry and SignalR state are in-process
(`docs/ARCHITECTURE.md` section 9). Scale up (CPU/memory), not out.

### 6.3 Reverse proxy and forwarded headers

The dashboard listener speaks plain HTTP and expects a TLS-terminating proxy in front.

- Set `Dranzo:TrustForwardedHeaders=true` **only** when the listener is reachable solely
  through that proxy. With it on, the server takes the client IP and scheme from
  `X-Forwarded-For` / `X-Forwarded-Proto` from *any* sender (the trusted-proxy lists are
  cleared in `DranzoApp.cs`). If the port is also reachable directly, a client can spoof its
  IP, defeating per-IP rate limits and putting false addresses in the audit log.
- With it off behind a proxy, every request appears to come from the proxy: all users share
  one rate-limit bucket and audit IPs are useless.
- The proxy must forward WebSockets (`/hubs/live`) and must not cache `/api`.
- **Never** put an HTTP proxy in front of the agent listener. It must be raw TCP end to end:
  the server performs mutual TLS itself and agents pin the private CA. A TLS-terminating proxy
  there breaks agent authentication by design.

## 7. Backup and restore

| What | How | Notes |
|---|---|---|
| PostgreSQL | Flexible Server automatic backups (14 days in the template), point-in-time restore to a **new** server; additionally a periodic `pg_dump` to separate storage if you need longer retention. | Contains the Data Protection key ring: a restore older than a key rotation still decrypts old TOTP secrets, but losing the table loses MFA enrolments. Backups are as sensitive as the database (`docs/THREAT_MODEL.md` 4.7). |
| Object storage | Blob versioning + 14-day soft delete (template). | Packages can be re-uploaded; agent builds can be rebuilt. |
| Key store | Section 4.1. | Without it a restored database is useless for managing existing agents. |
| Configuration | Bicep parameters in source control (no secrets), secrets in the config vault. | |

Restore order: key store → database → storage → server. After a database restore:

- Devices enrolled after the backup are unknown to the server: their certificates are refused
  (`403`). They must be re-enrolled.
- Devices revoked after the backup are active again: **re-revoke them**.
- Enrolment tokens revoked after the backup are valid again: re-revoke them.
- The audit chain ends at the backup point. Record the restore itself as an incident note; the
  gap is expected, not tampering.
- Run `GET /api/v1/audit/verify` for each partner.

## 8. Incident response

For every incident: start a timeline, preserve logs (Log Analytics, Key Vault audit logs,
`AuditEvents` export, GitHub audit log) **before** changing anything, and decide early who
informs affected clients. An RMM compromise is normally a notifiable event for the clients
whose devices were reachable.

### 8.1 Suspected server compromise

Assume the attacker has the command-signing key and the CA key (`docs/THREAT_MODEL.md`
section 5). Goal: stop commands reaching agents, then re-establish trust.

1. **Cut the gateway off from the internet** (disable the ingress / TCP port or block it at the
   network edge). Agents keep running locally and retry; without the gateway nobody can send
   them commands, including the attacker, unless they can also redirect agent traffic.
2. Snapshot the database, the container logs and the Key Vault audit log. Do not delete the
   compromised revision; keep its image digest.
3. Rotate everything the process could read: database password, storage access, SMTP password,
   MeshCentral login-token key, GitHub and registry credentials used for deployment. Revoke all
   dashboard sessions (`UPDATE "UserSessions" SET "RevokedAt" = now()`), revoke API keys,
   revoke all enrolment tokens.
4. Rebuild the server from a known-good commit on clean infrastructure.
5. **Keys.** The honest position today:
   - If an offline second command key is already trusted by the agents (recommended in 4.2):
     bring up the clean server, sign a `trust.rotate` with the offline key that removes the
     stolen key and pins a new CA. Agents are recovered remotely.
   - If not: the stolen key remains trusted by every agent. Remote recovery means sending a
     `trust.rotate` signed with a key the attacker also holds, over a channel authenticated by
     a CA the attacker also holds. That works only if you are sure the attacker can no longer
     reach the agents (DNS, network path) and you move fast. Otherwise **reinstall the agents
     with new trust files**, starting with the most sensitive clients.
6. Review `JobRuns`, `RemoteSessions` and the agents' local logs (`agent.log`) for the suspect
   window to determine what was executed where. Local agent logs are the more trustworthy
   record if the server's audit log may have been altered.
7. Treat every managed device that received a command in the window as potentially compromised
   and tell the client.

### 8.2 Stolen or lost managed device

1. Revoke the device (section 5). Its certificate stops working immediately.
2. If disk encryption was off (check the posture report), treat data on the device and the
   device private key as exposed. Revocation already neutralises the key.
3. The device's trust store contains only public material. Nothing to rotate server-side.
4. Remote wipe / lock is **not** a DranzoRMM capability without MDM (`docs/MDM_PLAN.md`).
5. If recovered, re-enrol with a new token after re-imaging.

### 8.3 Leaked enrolment token

1. Revoke it: Enrollment → token → Revoke (`DELETE /api/v1/enrollment-tokens/{id}`).
2. Audit log, action `device.enroll`, filter by the token id in the detail: list every device
   enrolled with it. Confirm each with the client; revoke and delete the ones nobody recognises.
3. Check whether jobs ran on unrecognised devices while they were enrolled: output of scripts
   may have been disclosed to them, and packages downloaded.
4. Issue a new token with a short lifetime and a low use count. Find how the token leaked
   (ticket, chat, shell history, a committed script: gitleaks has a `dz_enroll_` rule).

### 8.4 Compromised technician account

1. Disable the user and revoke their sessions (Users → user → Disable; disabling makes every
   existing session fail authentication on its next request). Revoke API keys they created.
2. Reset the password and force MFA re-enrolment before re-enabling. Invalidate recovery codes.
3. Audit log filtered by that actor for the suspect window: jobs created, scripts edited,
   sessions opened, roles and users changed, enrolment tokens created, packages uploaded.
4. For each device that ran a job or had a session: same assessment as 8.1 step 7, scoped to
   what was actually run. Cancel pending and scheduled jobs created by the account.
5. Check for persistence inside DranzoRMM: new users, new role assignments, modified scripts
   and policies with remediation scripts, schedules, notification webhooks.
6. If the account was a Partner Admin, also treat enrolment tokens and API keys as leaked.

### 8.5 Leaked secret in the repository

Rotate the secret first, then remove it. History rewriting does not un-leak anything; assume a
pushed secret is public. Do not add it to the gitleaks allowlist.

## 9. CI and signing secrets

Workflow: `.github/workflows/ci.yml` (never run yet). All names below are **placeholders**
chosen by this repository; create them in the GitHub **environment `release-signing`**, not as
repository secrets, restrict the environment to the `main` branch and `v*` tags, and add
required reviewers. Pull requests then never see them and produce unsigned artifacts.

Rule implemented by the build scripts: **secrets present ⇒ signing must succeed or the job
fails; no secrets ⇒ unsigned build with an `UNSIGNED BUILD` warning and an `-UNSIGNED`
artifact name; partially configured ⇒ failure.**

| Platform | Name | Kind | Content |
|---|---|---|---|
| Linux | `GPG_PRIVATE_KEY` | secret | ASCII-armoured private key used for deb and rpm signatures |
| Linux | `GPG_PASSPHRASE` | secret | Its passphrase (omit if none) |
| macOS | `APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64` | secret | base64 of the "Developer ID Application" certificate + key (.p12) |
| macOS | `APPLE_DEVELOPER_ID_INSTALLER_P12_BASE64` | secret | base64 of the "Developer ID Installer" certificate + key (.p12) |
| macOS | `APPLE_P12_PASSWORD` | secret | Password of both .p12 files |
| macOS | `APPLE_NOTARY_KEY_P8_BASE64` | secret | base64 of an App Store Connect API key (`AuthKey_XXXX.p8`) allowed to notarise |
| macOS | `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID` | secret | Key ID and issuer UUID of that API key |
| Windows | `WINDOWS_CERT_PFX_BASE64` | secret | base64 of the Authenticode certificate + key (.pfx) |
| Windows | `WINDOWS_CERT_PASSWORD` | secret | Its password |
| Windows | `WINDOWS_TIMESTAMP_URL` | variable | RFC 3161 timestamp server (default `http://timestamp.digicert.com`) |
| All | `DRANZO_EMBED_COMMAND_KEYS` | variable | `kid:base64pub[,…]` command-signing **public** keys to compile into agents |
| All | `DRANZO_EMBED_CA_PEM_B64` | variable | base64 of the CA certificate PEM to compile into agents |

Notes:

- The two `DRANZO_EMBED_*` variables are public values but **integrity-critical**: they decide
  which server an installed agent obeys. Restrict who can edit repository variables.
- Windows: publicly trusted code-signing keys must be on hardware. A PFX secret works for a
  test or internal certificate only. For production replace the `signtool` calls in
  `installers/wix/build.ps1` with a cloud signing service; keep the rule above.
- WiX is pinned to 5.0.2 in `build.ps1`. Later WiX versions use the Open Source Maintenance Fee
  model: upgrading is a cost decision for the owner.
- Apple notarisation needs a paid Apple Developer Program membership and the two Developer ID
  certificates; the owner provides these (`docs/SPEC.md` section 11).
- Linux package repository (signed apt/yum metadata) does not exist yet. Until it does,
  distribute the `.deb`/`.rpm` files with the public key
  (`dranzo-agent-signing-pubkey.asc`, produced by signed builds) and the `SHA256SUMS` files.

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| Agent shows "not enrolled" | `sudo dranzo-agent status`. No server URL: `install` was never run. `trust store is not initialised`: the binary has no embedded anchors, pass `--ca-file` and `--trust-file`. |
| Agent cannot connect: certificate error | The host in the server URL must be in `Dranzo:AgentHostnames`; the agent's `ca.pem` must be this server's CA (`GET /api/v1/agent/install-info`). A TLS-inspecting proxy on the client network breaks the pinned connection: it must be bypassed for the agent host. |
| Agent gets `403` and retries hourly | Device revoked or deleted, certificate expired while offline, or database restored from before its enrolment (section 7). Re-enrol. |
| Enrolment `401 invalid_token` | Token expired, revoked or used up. `429`: rate limit (`Dranzo:RateLimits:EnrollPerMinute` per IP; many devices behind one NAT enrolling at once). |
| `dranzo-agent install` fails: service already exists | The agent is already installed. `dranzo-agent uninstall` first; `install` always enrols as a **new** device. |
| Package removal refused on Linux / uninstall fails on macOS or Windows | An uninstall code is set. Linux: `sudo DRANZO_UNINSTALL_CODE=XXXX apt remove dranzo-agent`; macOS: `sudo /Library/DranzoRMM/uninstall.sh --code XXXX`; Windows: `msiexec /x DranzoAgent-x64.msi UNINSTALLCODE=XXXX`. |
| Agent logs | Linux `/var/lib/dranzormm/agent.log` and `journalctl -u dranzormm-agent`; macOS `/Library/Application Support/DranzoRMM/agent.log`; Windows `C:\ProgramData\DranzoRMM\agent.log`. Root/Administrator only. |
| Jobs stay Pending | Device offline, per-device concurrency limit reached, or the run is waiting for the dispatcher. Runs expire after `PendingRunExpiryHours`. |
| Agent refuses jobs: `expired` / `not_yet_valid` | Clock skew over 5 minutes on the device or server. Fix time sync. |
| Agent refuses jobs: `unknown_key` / `bad_signature` | The server's signing key is not in the device's `trust.json`: the server was started against a different or empty key store (it silently generates new keys), or the agent was built with other anchors. **Stop and investigate before enrolling anything else.** |
| Login works but every POST returns `403 csrf` | The proxy strips `X-CSRF-Token`, or the cookie is not sent (`__Host-` cookies need HTTPS and no `Domain`). |
| All users hit `429` together | Behind a proxy without `Dranzo:TrustForwardedHeaders` (section 6.3). |
| Server refuses to start: bootstrap password rejected | The bootstrap password fails the policy (12+ characters, not common, not containing the e-mail name). |
| `dotnet format --verify-no-changes` fails locally but not in CI (or the reverse) | The root `.editorconfig` must be present: it sets the two initializer-formatting options the code relies on. |
| macOS package build contains `._*` files | Build started from an application macOS tracks with `com.apple.provenance`; `build-pkg.sh` strips them and fails if any remain. |


## 11. Testing on your own machines

Start the stack (section 1.3) on a machine the test devices can reach, and set
`Dranzo__AgentHostnames__*` / `DRANZO_PUBLIC_AGENT_URL` to that machine's LAN name or IP **before the first
start** (the gateway certificate is issued for those names; to change them later delete the `keys` volume,
which also invalidates every enrolled device). Then in the dashboard: create an organization, site and
enrollment token (Enrollment page), and copy the CA certificate and trust file shown there.

| Device | Install | Notes |
|---|---|---|
| **Linux VM / container** (Ubuntu, Debian, RHEL family) | Build packages with `installers/linux/build-packages.sh` (or copy the `linux/<arch>` binary), install the `.deb`/`.rpm`, then `sudo dranzo-agent install --server https://<host>:8443 --token <token> --ca-file ca.pem --trust-file trust.json` | Verified in Debian 12 and Rocky 9 containers, including systemd. A container without systemd: use `deploy/agent-test` (foreground mode). |
| **Mac** (macOS 13+, Apple Silicon or Intel) | `installers/macos/build-pkg.sh` builds an **unsigned** pkg; install it, then `sudo /usr/local/bin/dranzo-agent install ...` as above | The pkg is unsigned until you provide Developer ID credentials (section 9), so Gatekeeper will warn. The launchd service path and root-only features (dialogs in the user's session, `installer -pkg`, `softwareupdate --install`) have **not** been run yet; please test them first. |
| **Windows 11 VM** (x64 or ARM64) | Build the MSI on Windows with `installers/wix/build.ps1`, or copy `dranzo-agent.exe` and run `dranzo-agent.exe install --server ... --token ... --ca-file ... --trust-file ...` in an elevated prompt | **No Windows code has ever run.** It compiles, vets and lints for both architectures. Expect first-run issues; collect `C:\ProgramData\DranzoRMM\agent.log`. |

Suggested acceptance walk-through per device, matching the brief: device shows online with inventory
(Phase 1) → run a script and watch live output (2) → install and remove 7-Zip / `tree` (3) → scan and
install updates (4) → turn the firewall or antivirus off and see the alert (5) → open a terminal and a
file session with consent mode "require", check the prompt and the on-screen indicator (6) → assign a
"firewall on + remediate" policy (7) → publish a release to a pilot group (8).

### 11.1 macOS privacy permissions (remote support)

macOS requires a person to approve some capabilities once per Mac (System Settings → Privacy &
Security). Without MDM there is no way around this, by design:

| Permission | Needed by | Without it |
|---|---|---|
| **Screen Recording** | MeshCentral agent (remote desktop) | The technician sees a black or wallpaper-only screen. |
| **Accessibility** | MeshCentral agent (remote keyboard/mouse) | View-only remote desktop. |
| **Full Disk Access** | `dranzo-agent` (file browser in protected folders, some posture checks) | Files under `~/Library`, Mail, Messages etc. return "permission denied"; the dashboard shows the error. |

Approve them on the Mac after the MeshAgent is installed (System Settings → Privacy & Security → the
relevant list → enable the agent). The DranzoRMM consent prompt and indicator are separate and always
apply. With MDM (Phase 9, `docs/MDM_PLAN.md`) Full Disk Access and Accessibility can be pre-approved by a
PPPC profile; Screen Recording can only be made approvable by a standard user, not granted silently.

## 12. Network isolation and firewall rules (Phase 10)

- **Isolate a device:** device page → Isolate (role Network Admin or Partner Admin, authenticator code, reason). The device keeps DranzoRMM, MeshCentral, DNS and DHCP only. It confirms within a minute; if it cannot reach the server after isolating, it releases itself and the job fails.
- **Release without the server** (server down, device moved): on the device, as administrator / root: `dranzo-agent release-isolation`. The dashboard still shows the device as isolated until you release it there too.
- **What the agent changes:** Windows Firewall groups `DranzoRMM` (policy rules) and `DranzoRMM Isolation`; nftables tables `inet dranzormm` and `inet dranzormm_isolation`; macOS pf anchors `com.apple/250.DranzoRMM` and `com.apple/200.DranzoRMMIsolation` (pf is switched on if it was off). Nothing else. Uninstalling the agent removes all of them.
- **Linux without nftables:** firewall rules and isolation report "not supported"; install the `nftables` package.

### 12.1 Connecting a UniFi controller

1. In UniFi Network (on the console): Settings → Control Plane → Integrations → create an API key. Or create a local admin account for DranzoRMM with the least role that can edit Wi-Fi.
2. DranzoRMM: Network → Wi-Fi & controllers → Add controller (partner admin, authenticator code). Address `https://<console-ip>` (UniFi OS) or `https://<host>:8443` (classic controller, untick "UniFi OS"). If the console uses its self-signed certificate, add its SHA-256 fingerprint: `openssl s_client -connect <ip>:443 </dev/null | openssl x509 -noout -fingerprint -sha256`.
3. Choose the Dranzo site whose discovered devices are linked to the controller's clients, then **Sync now**. Errors appear on the card.
4. **Guest & office Wi-Fi** creates both networks on their own VLANs and subnets; the guest network uses UniFi guest policies (internet only) and client isolation. Existing VLANs/SSIDs are reused, never changed.
5. Blocking a device on Network → Network devices then blocks it on the Wi-Fi (`block-sta`); approving unblocks it.

The integration uses UniFi Network's classic API (`/proxy/network/api/s/<site>/…`), written against UniFi Network 8/9 and tested against a simulated controller only. Check it on your console before relying on it.

### 12.2 802.1X office Wi-Fi (EAP-TLS)

1. Network → Wi-Fi & controllers → 802.1X: choose the organization, enter the access points' address range and the office Wi-Fi name, **Enable**.
2. **Download RADIUS server**, copy the folder to an always-on Linux/Docker machine on the office network, run `docker compose up -d` there. UDP 1812 must be reachable from the access points only. It refreshes the CRL from DranzoRMM every 5 minutes (outbound HTTPS to the dashboard address).
3. **Switch to 802.1X** with the controller and the RADIUS machine's IP: the office SSID becomes WPA2-Enterprise.
4. **Enroll all devices**. Windows and Linux devices get their certificate and Wi-Fi profile within a minute. Keep the old password network until every device shows as installed.
5. Revoking, deleting, uninstalling or blocking a device revokes its certificate.

Checked with real FreeRADIUS 3.2.7 and `eapol_test`. The FreeRADIUS image tag is amd64-only; on ARM machines Docker runs it under emulation.

