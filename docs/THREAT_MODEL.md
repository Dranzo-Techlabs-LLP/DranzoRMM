# DranzoRMM threat model

Status: living document, written 2026-11-11 against the code in the repository on that day.
Method: STRIDE per component (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege).

Rules for this document:

- **"Exists today"** means the control is in the code and a file is cited. Paths are relative
  to the repository root; `S/` abbreviates `server/src/`, `A/` abbreviates `agent/internal/`.
- **"Planned"** means not implemented. It is tied to a phase of `docs/SPEC.md` section 7 or
  marked *pre-production* (must be done before real client devices are enrolled).
- Where the code falls short of `docs/SPEC.md` or `docs/PROTOCOL.md`, it says so.

Update this file in the same change that adds a feature which runs code, opens a session or
handles a new secret (`docs/SPEC.md` section 8).

## 1. What we are protecting

DranzoRMM can run code as root / LocalSystem on every enrolled device of every client. A
compromise of the platform is a compromise of all of them. Everything else follows from that.

| # | Asset | Why it matters |
|---|---|---|
| A1 | **Command-signing private key** (Ed25519) | Whoever holds it can make any agent that trusts it run anything. The single most valuable secret. |
| A2 | **Device CA private key** (ECDSA P-256) | Mints device certificates and gateway server certificates: impersonate a device, or the server to agents. |
| A3 | Ability to create jobs / sessions (technician session, API key) | Legitimate path to code execution on devices within a tenant scope. |
| A4 | Device private keys and trust stores (on each device) | Identity of one device; integrity of what that device trusts. |
| A5 | Database contents | Tenant data, inventory, script bodies, job output (may contain secrets), password hashes, protected TOTP secrets, session and token hashes, the audit log. |
| A6 | Object storage | Software packages and agent builds that devices install; files transferred in sessions. |
| A7 | Enrollment tokens | Admit a new device into an organisation. |
| A8 | Audit log integrity | Evidence of who did what. |
| A9 | Code-signing identities and the build pipeline | What users and operating systems accept as "the DranzoRMM agent". |
| A10 | Availability of the gateway | Without it devices cannot be managed (they keep running). |

## 2. Trust boundaries

```
 [B1] Internet ─────────────── technician browser ──HTTPS──▶ ingress ──HTTP──▶ dashboard listener :8080
 [B1] Internet ─────────────── agent ───────TLS 1.2+/mTLS (end to end)──────▶ agent listener   :8443
 [B2] Listener separation      (one process, two Kestrel endpoints, routes bound to one of them)
 [B3] Tenant boundary          partner ▸ organisation ▸ site ▸ group (query filters + permissions)
 [B4] Server ▸ data stores     PostgreSQL, object storage, key store (Key Vault / file keystore)
 [B5] Server ▸ device          signed commands only; the device verifies, the server is not trusted blindly
 [B6] Device: agent (root) ▸ logged-in user ▸ other local users
 [B7] Build: developer laptop ▸ GitHub repository ▸ CI runners ▸ signing secrets ▸ published packages
 [B8] Third parties            MeshCentral, SMTP, webhooks, NVD/CISA feeds, package managers on devices
```

## 3. Attacker profiles

| ID | Attacker | Starting position |
|---|---|---|
| T1 | Internet attacker | Can reach both listeners; no credentials. |
| T2 | Malicious or compromised technician | Valid dashboard account (possibly phished, session hijacked, or an insider) with some role in some scope. |
| T3 | Compromised client device / agent | Root on one enrolled device: has its device key, certificate and trust store; can speak the protocol. Also: an unprivileged local user on a managed device. |
| T4 | Compromised server | Code execution in the server process or its host. |
| T5 | Malicious insider with database access | Read and/or write access to PostgreSQL (DBA, cloud operator, stolen backup, SQL injection). |
| T6 | Supply-chain attacker | Compromised dependency, GitHub Action, CI runner, build secret, or distribution channel. |

## 4. STRIDE per component

Columns: **Threat** (who, how) · **Mitigations that exist today** · **Residual risk** ·
**Planned**.

### 4.1 Agent (process on the device)

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| S | T3-local user plants an install parameter file so the next installation enrols the device with an attacker's server (which then runs code as root). | macOS `postinstall` honours `/tmp/dranzo-agent-install.json` only if it is a regular file owned by root and not group/world-writable (`installers/macos/scripts/postinstall`); Linux honours `/etc/dranzormm/install.env` only if root-owned `0600`/`0400` and parses it as data (`installers/linux/scripts/postinstall.sh`). Server URL must be `https`, no path/credentials (`A/config/config.go` `ValidateServerURL`). | A root-owned file written by a careless management script with attacker-influenced content. Windows: MSI properties are supplied by the installing administrator. | Phase 1: per-organisation installers with embedded, signed parameters. |
| T | T3-local user modifies the binary, config, trust store or device key. | Data directories root/SYSTEM only (`A/fsutil`, `A/config/paths*.go`); key and trust files are permission-checked before use on Unix (`A/fsutil/fsutil_unix.go` `CheckPrivate`); systemd re-asserts `0700` on both directories (`installers/linux/10-hardening.conf`); binary installed root-owned `0755`. | **Windows: `CheckPrivate` is a no-op** (`A/fsutil/fsutil_windows.go:70`): the agent does not verify ACLs on its key/trust files. A root/Administrator user can change anything (accepted: they own the device). | Pre-production: verify ACLs on Windows. Phase 5: "agent tampering" alert. |
| T | Trust store replaced by network input. | Trust anchors change only through installer files, compiled-in defaults, or a `trust.rotate` that passed signature verification (`A/trust/trust.go` header and `Replace`; `docs/PROTOCOL.md` 1.1, 6.7). | Compiled-in anchors are only as trustworthy as the build (see 4.14). | - |
| R | Agent actions on the device are not attributable. | Local JSON log with device and job ids (`A/logging/logging.go`); server-side audit of every dispatch and refusal (`S/Dranzo.Api/Jobs/JobProcessors.cs` `job.refused_by_agent`). | A local root user can edit the local log. | - |
| I | Secrets in agent logs or process lists. | `Redact` on errors and log lines (`A/logging/logging.go:34`); enrolment token accepted from `DRANZO_ENROLL_TOKEN` and passed that way by the Linux/macOS installers; token erased from `bootstrap.json` after enrolment (`A/config/config.go` `EraseToken`). | Windows MSI passes the token on the command line of a short-lived SYSTEM process (`installers/wix/Package.wxs`, hidden from MSI logs only). Script bodies and job output can contain secrets chosen by technicians. | Phase 2: document "no secrets in script parameters"; secret parameters. |
| D | A job or a flood of jobs exhausts the device. | Bounded concurrency and queue, per-job timeout and output cap (`A/jobs/manager.go`, `A/jobs/output.go`; `docs/PROTOCOL.md` 6.1). | A legitimate but heavy script still hurts the device; `KillMode=process` means children of a hard-killed agent survive (`installers/linux/10-hardening.conf`). | SPEC section 9 footprint measurement. |
| E | Agent runs as root/LocalSystem: any command-execution bug is full device compromise. | Only signature-verified commands are executed (`A/protocol/verify.go`); arguments passed as argv, never through a shell (`A/jobs/script/script.go`); `runAs: user` drops to the console user (`A/platform/run_unix.go`). | The design requires root; sandboxing would break the product (reasons listed in `10-hardening.conf`). Only the `script` job kind exists in the agent today. | Later phases add handlers; each needs its own input validation. |
| - | **Transparency (ethics, SPEC section 1)**: agent used covertly. | Visible service with truthful name and description (`A/svc/svc.go`); listed in dpkg/rpm, pkg receipts, Apps and features; README on the device; removable by an administrator; uninstall code is a deterrent only. No hiding, no AV/EDR interference anywhere in the code. | Session indicator and consent prompts are **not implemented in the agent yet** (no session handler; `A/agentcore/interfaces.go` only defines the interface). | Phase 6: indicator in every consent mode before any session feature ships. |

### 4.2 Agent ↔ server channel

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| S | T1 impersonates the server (DNS/BGP hijack, rogue CA in the OS store, TLS-inspecting proxy). | Agent trusts **only** the pinned DranzoRMM CA, never the OS store; hostname verification on; TLS 1.2 minimum (`A/transport/tls.go:21-35`). Even with a forged channel, commands need a valid Ed25519 signature (4.10). | Compromise of the CA key (A2). TLS-inspecting corporate proxies break the agent by design. | Pre-production: offline root + online issuing CA. |
| S | T1/T3 impersonates a device. | mTLS; client certificate must chain to the private CA only (`S/Dranzo.Infrastructure/Security/CertificateAuthority.cs` `ValidateClientCertificate`: custom root trust, chain length 2, clientAuth EKU); certificate thumbprint must be the device's current or still-valid previous one and the device `Active` (`S/Dranzo.Api/Agents/AgentGateway.cs` `AuthenticateDeviceAsync`). | A stolen device key works until the device is revoked. | Phase 5: alert on a device connecting from a new network while its previous connection is live. |
| T | Message tampering in transit. | TLS; server→agent commands are additionally signed over `type` + exact payload bytes (`S/.../Security/CommandSigner.cs`, `docs/PROTOCOL.md` 4.1). | Agent→server reports are protected by TLS only (acceptable: they cause bookkeeping, not actions). | - |
| R | Device denies having received/refused a command. | Job acks, results and agent refusals are stored and audited server-side (`S/Dranzo.Api/Jobs/JobProcessors.cs`). | The agent does not sign its results. | Not planned. |
| I | Eavesdropping. | TLS 1.2/1.3 only on the listener (`S/Dranzo.Api/DranzoApp.cs` `ConfigureKestrel`). | - | - |
| D | T3 floods the gateway from an enrolled device. | Per-connection token bucket (50 msg/s, burst 200), 2 MiB message cap, text frames only, one connection per device (`S/Dranzo.Api/Agents/AgentGateway.cs` `ReceiveLoopAsync`, `AgentRegistry.cs` `TryConsume`/`Register`). | The agent listener is exempt from the global HTTP rate limiter (`DranzoApp.cs`, `GetNoLimiter("agent")`); TLS-handshake floods from T1 are limited only by the platform. | Pre-production: connection-rate limits / DDoS protection at the network edge. |
| E | Agent certificate used against the dashboard API, or a browser session against the gateway. | Every route is bound to exactly one listener; a mismatch is `404` (`S/Dranzo.Api/Auth/Access.cs` `AccessMiddleware`, `AgentListenerMetadata`). | - | - |

### 4.3 Enrollment

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| S | T1 enrols a rogue device with a guessed or leaked token (A7). | Tokens are 32 random bytes, stored hashed, with expiry, max uses and revocation; uses are consumed atomically (`S/.../Security/KeyStore.cs` `Hashing.NewToken`; `AgentGateway.cs` `EnrollAsync`); enrol endpoint rate-limited per IP (`DranzoApp.cs` policy `enroll`); one generic error; every attempt with a known token is audited. | **A leaked valid token admits a device into that organisation** until it expires or is used up. The rogue device receives whatever jobs target its group. Tokens appear in install commands, tickets and shell history. | Phase 1: short default lifetime in the UI, optional approval queue for new devices. |
| S | Rogue device takes over an existing device's identity by claiming its `machineId`. | Every enrolment creates a **new** device; a matching `machineId` is only flagged (`AgentGateway.cs`, `PossibleDuplicateOfDeviceId`). | Duplicates must be reviewed by a human. | Phase 1 UI: duplicate banner. |
| T | Malicious CSR (wrong key type, attacker-chosen subject/extensions). | CSR self-signature verified; only the public key is used; must be ECDSA P-256; subject, SAN and EKU are set by the server; CSR size capped (`CertificateAuthority.cs` `IssueDeviceCertificate`, `RequireP256`). | - | - |
| I | Token disclosure. | Only the hash and a display prefix are stored (`S/Dranzo.Domain/Entities.cs` `EnrollmentToken`); the secret is returned once on creation; gitleaks rule for `dz_enroll_` (`.gitleaks.toml`). | See first row. | - |
| D | Token exhaustion or enrolment spam. | Rate limit; max uses. | A leaked multi-use token can be burned by an attacker (denial, plus rogue devices). | - |

### 4.4 Agent gateway (server side of the device protocol)

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| S | T3 reports results for another device's job run. | Runs are loaded with `r.DeviceId == conn.DeviceId` (`S/Dranzo.Api/Jobs/JobProcessors.cs:27,80`). | A new processor that forgets this check (convention in `CLAUDE.md`). | Test that enumerates processors. |
| T | T3 sends malformed or oversized reports to corrupt data or exploit parsers. | Bounded, type-checked JSON readers for all agent input (`S/Dranzo.Api/Agents/CoreProcessors.cs` class `J`); JSON depth 32; size caps; a processor failure does not drop the connection or the process (`AgentGateway.cs` `HandleMessageAsync`). | Inventory JSON is stored raw (`InventoryProcessor`, `DataJson`) and rendered by the dashboard: see 4.6. | - |
| I | T3 downloads blobs meant for other devices. | Blob must be granted to that device and unexpired (`S/Dranzo.Api/Agents/BlobEndpoints.cs:95-96`); uploads need a one-time ticket bound to device and run, size-capped. | - | - |
| I | T3 learns about other tenants. | The gateway runs with a system tenant context but every query is by this connection's device id; nothing tenant-wide is sent to agents. | - | - |
| D | Many devices reconnect at once (thundering herd after an outage). | Agent backoff with full jitter (`A/transport/backoff.go`); server marks all devices offline at start (`S/Dranzo.Api/Services/Bootstrap.cs`). | **Single process, in-process registry** (`AgentRegistry.cs`): one instance is a capacity ceiling and a single point of failure. | Backplane (ARCHITECTURE section 9), not scheduled. |
| E | Revoked device keeps acting. | Revocation sets status, clears thumbprints and closes the socket (`S/Dranzo.Api/Features/DeviceEndpoints.cs` revoke/delete, both `RequireStepUp`); every enrol/renew/WebSocket request re-checks (`AuthenticateDeviceAsync`). | PROTOCOL 2.3 says "on every TLS handshake": the handshake only validates the chain; the per-device check happens per request. Equivalent in effect for the three endpoints that exist. | - |

### 4.5 Dashboard API and sessions

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| S | T1 guesses or stuffs passwords. | Password policy (12+ characters, common/repetitive/email rejected), PBKDF2 hashing via ASP.NET Identity's hasher, lockout after 5 failures for 15 min, timing equalisation for unknown users, per-IP rate limit on auth routes (`S/Dranzo.Api/Auth/AuthService.cs`, `DranzoApp.cs` policy `auth`). | Lockout lets an attacker lock out a known user (DoS). | Phase 1: passkeys/WebAuthn. |
| S | T1 phishes a technician (password + TOTP in real time). | **TOTP mandatory, no exemptions**; a session is only issued after TOTP; used time-steps are burned (`AuthService.cs` `VerifyTotp`, `SessionAuthHandler` rejects users without TOTP). | **TOTP is phishable.** A real-time proxy gets a full session. Step-up asks for another TOTP code, which the same proxy can relay. | Phase 1: WebAuthn (phishing-resistant), recommended as mandatory for Partner Admins. |
| S | Session theft (malware on the technician's machine, XSS). | Opaque random token, only its hash stored; cookie `__Host-` prefixed outside development; idle 30 min and absolute 12 h timeouts; password change revokes other sessions (`Access.cs` `SessionAuthHandler`, `AuthService.cs`). | A stolen cookie is valid from any IP until timeout; no device binding. | Session list + revoke in the UI; alert on new-country sign-in. |
| T | CSRF. | `SameSite=Strict` cookie plus a per-session token required in `X-CSRF-Token` on every unsafe method, compared in constant time (`Access.cs` `AccessMiddleware`). | - | - |
| R | Technician denies an action. | Every state-changing endpoint writes an audit event with actor, IP, target and content hash (`S/Dranzo.Api/Common.cs` `Ctx.Audit`; hash chain in 4.13). | IP is taken from `X-Forwarded-For` when `Dranzo:TrustForwardedHeaders` is on: see 4.5-I. | - |
| I | Cross-tenant read (T2 of organisation A reads B). | One permission per endpoint, resolved into a scope that feeds EF Core **global query filters** on every tenant-owned entity; empty context matches nothing; out-of-scope ids are `404` (`Access.cs` `ScopeResolver`, `S/Dranzo.Infrastructure/Data/DranzoDbContext.cs`, `TenantContext.cs`); tests run every endpoint cross-tenant (`server/tests/Dranzo.Tests/TenantIsolationTests.cs`, `EndpointAccessTests.cs`). | `IgnoreQueryFilters()` in auth, gateway and background code must carry its own predicate; a mistake there bypasses isolation. Rows with `OrganizationId == null` in "shared" entities are visible partner-wide by design. | Lint/test that flags new `IgnoreQueryFilters` uses. |
| I | Spoofed client IP defeats rate limits, lockout attribution and audit IPs. | Forwarded headers are ignored unless `Dranzo:TrustForwardedHeaders=true` (`DranzoApp.cs:133`). | When enabled, **any** sender is trusted (`KnownIPNetworks`/`KnownProxies` are cleared): safe only if the dashboard listener is reachable exclusively through the proxy. | Pre-production: configurable trusted proxy ranges. |
| D | Request floods. | Global per-IP and per-API-key fixed-window limits; 10 MB request body cap; `Server` header removed (`DranzoApp.cs`). | Application-level only. | WAF / Front Door (`deploy/bicep/README.md` known gaps). |
| E | T2 escalates within the partner (grants self a role, creates admin, uses an API key for interactive actions). | User, role and assignment changes are step-up protected (`S/Dranzo.Api/Features/UserEndpoints.cs`, 7 `RequireStepUp` routes); API keys can never use interactive-only permissions or step-up routes (`Access.cs`, `S/Dranzo.Domain/Tenancy.cs` `Permissions.InteractiveOnly`); an endpoint without access metadata is denied and logged (`Access.cs`). | A Partner Admin is all-powerful inside the partner, by design. | Two-person approval for the highest-impact actions (not scheduled). |
| E | T2 runs code on many devices. | Step-up when a job targets more than `BulkStepUpThreshold` (10) devices, a whole organisation, or a non-explicit scheduled target (`S/Dranzo.Api/Features/JobEndpoints.cs:100,196`; same in `PatchEndpoints.cs:365`, script policies in `PolicyEndpoints.cs:214`). | **A technician with `scripts.run` can run arbitrary code as root on every device in their scope, ten at a time, without step-up.** That is the product. Mitigation is least-privilege scoping, audit and alerting, not prevention. | Phase 5: alert rule on unusual job volume. |

### 4.6 Web UI

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| T/E | Stored XSS through device-controlled data (hostname, software names, job output, inventory JSON) leading to actions as the technician. | React escapes by default; CSP `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` plus `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, COOP (`DranzoApp.cs:174` and the surrounding middleware); server truncates and strips NULs from agent strings (`CoreProcessors.cs` `J`). | `style-src 'unsafe-inline'` remains. Terminal output rendering (xterm.js, Phase 6) is a new sink. Any future `dangerouslySetInnerHTML` breaks the model. | ESLint rule forbidding raw HTML; remove `'unsafe-inline'` when the component library allows. |
| I | CSV/formula injection in exports opened in a spreadsheet. | Cells starting with `= + - @` are neutralised (`S/Dranzo.Api/Common.cs` `CsvCell`). | - | - |
| I | Sensitive API responses cached. | `Cache-Control: no-store` on `/api` (`DranzoApp.cs`). | - | - |
| S | Clickjacking / UI redress. | `frame-ancestors 'none'`, `X-Frame-Options: DENY`. | - | - |
| T | Compromised npm dependency ships malicious script to every technician. | `package-lock.json` + `npm ci --ignore-scripts`, `npm audit` gate, SBOM, Dependabot (`.github/workflows/ci.yml`); CSP blocks third-party script origins and exfiltration to other origins (`connect-src 'self'`). | A malicious dependency bundled into first-party JavaScript runs with the technician's session. | Dependency review on PRs; lock down who can merge dependency updates. |

### 4.7 Database (PostgreSQL)

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| T | SQL injection. | EF Core LINQ and interpolated-parameter SQL only (`S/Dranzo.Infrastructure/Audit/AuditLog.cs` uses `ExecuteSqlAsync` with an interpolated parameter). | Any future raw SQL string. | - |
| I | **T5 reads the database or a backup.** | Passwords PBKDF2-hashed; session tokens, API-key secrets and enrolment tokens stored as SHA-256 hashes of high-entropy values; TOTP secrets encrypted with ASP.NET Data Protection (`AuthService.cs`); the CA and signing keys are **not** in the database (`KeyStore.cs`). | (1) **The Data Protection key ring is stored in the same database, unencrypted** (`DranzoApp.cs:83` `PersistKeysToDbContext`, no `ProtectKeysWith...`): a reader can decrypt every TOTP secret and forge login-challenge tokens, reducing MFA to the password. (2) **Recovery codes are 80-bit values hashed with one unsalted SHA-256** (`AuthService.cs` `CompleteTotpEnrollmentAsync`): trivially brute-forced offline from a dump. (3) Script bodies, job output and inventory are plaintext. | **Pre-production: protect the key ring with a Key Vault key** (`ProtectKeysWithAzureKeyVault`) or keep it outside the database; longer recovery codes with a slow hash. |
| T | **T5 writes to the database.** | Signatures are created by the server at send time from the key store, so rows alone cannot make an agent execute anything. | A writer can still: insert a role assignment or session row for themselves, queue `JobRun`s that the dispatcher will then **sign and send** (`S/Dranzo.Api/Jobs/JobDispatcher.cs:162`), swap a blob's recorded hash, flip a device back to `Active`. **Database write access is equivalent to technician-level control of every tenant.** | Separate least-privilege DB role for the app; row-level integrity for jobs (sign the job at creation with the requester's session, verify at dispatch) is not scheduled. |
| R | T5 edits the audit log. | See 4.13. | See 4.13. | - |
| D | Storage exhaustion by output/inventory. | Output caps, snapshot pruning (`CoreProcessors.cs` `KeepSnapshots`). | No global quotas per tenant. | - |
| E | App connects as the PostgreSQL administrator. | - | The Bicep deployment uses the admin login in the connection string (`deploy/bicep/main.bicep`). The app can drop the audit trigger. | Pre-production: dedicated role without DDL; migrations run by a separate identity. |

### 4.8 Object storage

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| T | Package or agent build replaced in storage (T4, T5-storage, cloud operator). | The agent verifies size and SHA-256 **from the signed command** before executing anything (`A/transport/http.go` `Download`; `docs/PROTOCOL.md` 6.2, 6.4); the hash is computed at upload and audited (`S/Dranzo.Api/Features/SoftwareEndpoints.cs:176`). | The hash protects integrity from upload onward, not what the technician uploaded. A database writer can change the recorded hash (4.7). | Phase 3: optional publisher-signature check (Authenticode, pkg signature) on the device. |
| I | Public exposure of packages or transferred files. | Keys are server-generated and path-validated (`S/Dranzo.Infrastructure/Storage/ObjectStore.cs` `PathFor`); Azure: no public access, no shared keys, private endpoint, identity scoped to one container (`deploy/bicep/modules/storage.bicep`, not deployed). | MinIO in development uses static credentials. Files pulled from devices may be sensitive and are stored unencrypted at the application level. | Retention/auto-delete for session file transfers. |
| D | Upload floods. | 2 GiB package and 100 MiB transfer caps (`S/Dranzo.Api/DranzoOptions.cs` `StorageOptions`). | No per-tenant quota. | - |

### 4.9 Key store, PKI and signing keys

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| I/E | Theft of the command-signing key (A1). | Never in the repository or database; file keystore `0700`/`0600` outside the repo in development (`KeyStore.cs` `FileKeyStore`); Key Vault **secret** via managed identity in production (`KeyVaultKeyStore`); Key Vault audit logging, soft delete, purge protection, private endpoint (`deploy/bicep/modules/keyvault.bicep`, not deployed); keys never leave `ICommandSigner`. | **The private key is exportable and lives in server memory.** Azure Key Vault keys do not support Ed25519, so it cannot be a non-exportable HSM key (`docs/PLAN.md` open question 1). Anyone with code execution in the server, a memory dump, or Secrets-read on the vault has A1 permanently, until every agent's trust store is rotated. | Decision needed: ECDSA P-256 in Key Vault HSM (protocol change) **or** an external signing service. Until then: Secrets User (read-only) role after first start, alert on vault reads from unexpected identities. |
| I/E | Theft of the device CA key (A2). | Same storage as above. | **Single online CA, no offline root** (`CertificateAuthority.cs`: one self-signed CA, 10 years, issues both device and gateway certificates). A stolen CA key lets the attacker impersonate the server to agents (channel only; commands still need A1) and any device to the server. Rotation means re-pinning every agent via `trust.rotate`. | Pre-production: offline root, online issuing CA with name constraints, shorter CA lifetime. |
| T | Key store role allows overwrite/delete. | Bicep assigns Secrets Officer only for first start, then Secrets User (`deploy/bicep/README.md` "Key store role"). | First-start auto-generation means a server pointed at an empty/wrong vault silently creates **new** keys, orphaning all agents. | Refuse to generate keys in Production unless explicitly asked. |
| R | Unlogged key use. | Key Vault logs reads; the server audits what it signs indirectly through job/session audit events. | No per-signature log. | - |
| D | Key loss (deleted vault, lost dev keystore). | Soft delete + purge protection (Bicep). | No documented, tested backup until `docs/RUNBOOK.md` section 4 is exercised. Loss of A1 with no trusted second key means **every agent must be reinstalled**. | Enrol a second (offline) command key in every trust store from day one. |

### 4.10 Job pipeline (create → sign → dispatch → execute → result)

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| S | Forged command reaches an agent (T1 on path, T3 relaying, compromised proxy). | Ed25519 signature over `DRANZO-CMD-V1\n` + type + payload bytes; agent verifies key id, signature, `deviceId`, validity window (≤ 15 min, 5 min skew) and nonce, in that order, and refuses otherwise (`CommandSigner.cs`; `A/protocol/verify.go`, `nonce.go`; interop vectors `A/protocol/testdata/vectors.json`). | Depends entirely on A1. | - |
| T | Replay of a captured command, on the same or another device. | Per-command nonce persisted across restarts until expiry; `deviceId` bound into the signed payload; short expiry; signed at send time (`A/protocol/nonce.go`; `JobDispatcher.cs:162`). | Clock rollback on the device beyond the nonce retention window. | - |
| T | Command injection through job parameters. | Agent validates every spec field and passes arguments as argv; identifier pattern for package ids (`A/protocol/jobkinds.go`, `A/jobs/script/script.go`). | Script jobs are arbitrary code by definition. | - |
| R | "Who ran this?" | Job stores requester; audit event with content hash of the script; refusals audited. | Scheduled and policy-driven jobs run as "system" long after the human configured them. | Show the configuring user on system jobs. |
| I | Output leaks secrets across tenants. | Runs are tenant-filtered; live output only to subscribers whose scope includes the run (`S/Dranzo.Api/Live/LiveHub.cs` `SubscribeRun`). | A user removed from a role keeps already-joined SignalR groups until the socket closes (`LiveHub.cs`: scope checked at join time). | Re-evaluate group membership on role change. |
| D | Queue flooding; stuck runs. | Per-device concurrency limit, pending-run expiry (`DranzoOptions.cs` `AgentOptions`). | - | - |
| E | Low-privilege user reaches a higher-privilege job kind. | Each job kind is behind its own permission; step-up rules (4.5). | New job kinds must add their permission in the same change (`CLAUDE.md`). | - |

### 4.11 Remote sessions (terminal, files, desktop)

Server side exists (`S/Dranzo.Api/Features/RemoteSessions.cs`, `RemoteEndpoints.cs`). **The
agent has no session handler yet**, so nothing below is end-to-end today.

| STRIDE | Threat | Exists today | Residual risk | Planned (Phase 6) |
|---|---|---|---|---|
| S/E | T2 opens a session on a device outside their scope, or silently. | Session start requires `remote.*` permissions (interactive-only: API keys excluded) and step-up (`RemoteEndpoints.cs:86,89,98`); `session.start`/`session.end` are signed commands (`RemoteSessions.cs:123,183`); the organisation's consent mode is sent to the agent and recorded (`RemoteSessions.cs:102-115`). | Consent and the visible indicator are enforced **by the agent**, which does not implement them yet. A compromised server could send `consent: none` (the indicator is still mandatory per PROTOCOL 6.5). | Agent: indicator in all modes, default-deny prompt, local "End session". Must ship before any session capability is enabled. |
| T | Injected keystrokes. | `session.input` is signed per frame with a strictly increasing sequence (`RemoteSessions.cs:34`; agent `A/protocol/seq.go`). | - | - |
| R | Disputed session. | `RemoteSession` row and audit events for request, start, denial and end. | Terminal transcript is hashed, not stored. | Optional recording is a policy decision (privacy). |
| I | File browser reads anything root can. | File jobs require an active `files` session id (PROTOCOL 6.2). | By design, root-level read on the device within scope. | Per-organisation path allow-lists. |
| D | Sessions left open. | `SessionMonitor` hosted service; 12 h maximum (PROTOCOL). | - | - |

### 4.12 Update pipeline (agent self-update)

**Not implemented** on either side (no release endpoints in `S/Dranzo.Api`, no update handler
in the agent). Design from `docs/PROTOCOL.md` 6.4:

| STRIDE | Threat | Designed mitigation | Residual risk |
|---|---|---|---|
| T/E | Malicious agent binary pushed to every device: the worst case in this model. | `update.available` is a signed command carrying the SHA-256; agent verifies before staging; rollback if the new agent cannot connect; rollout rings. | **A holder of A1 (or of a Partner Admin session with `releases.manage` + step-up) can replace the agent everywhere.** The update signature and the command signature are the same key, so a server compromise is an update compromise. |
| - | Planned (Phase 8, strongly recommended) | A **separate offline release-signing key** whose public half ships in the agent; the agent requires both the server's command signature and the release signature. Then a compromised server cannot ship arbitrary agents. OS-level code signature check (Authenticode / Developer ID) before swapping binaries. | |

### 4.13 Audit log

| STRIDE | Threat | Exists today | Residual risk | Planned |
|---|---|---|---|---|
| T/R | T2 or a bug alters or deletes entries. | Append-only in code; PostgreSQL trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` (`S/Dranzo.Infrastructure/Data/Migrations/20261111162345_AuditImmutability.cs`); per-partner hash chain written under an advisory lock (`S/Dranzo.Infrastructure/Audit/AuditLog.cs`); `GET /api/v1/audit/verify` recomputes it (`S/Dranzo.Api/Features/AuditEndpoints.cs:79`). | - | - |
| T/R | **T5 or T4 rewrites history.** | Detection of naive edits by the chain. | The chain is an **unkeyed hash stored next to the data**: an attacker who can disable the trigger (table owner / superuser, which is what the app connects as today) can rewrite events and recompute every hash, or truncate the tail. Nothing outside the database anchors the head. | Pre-production: ship the chain head (sequence + hash) periodically to an external append-only sink (immutable blob storage, SIEM); app role without trigger/DDL rights. |
| R | Tampering goes unnoticed. | On-demand verification endpoint. | **No scheduled verifier exists**, although `docs/ARCHITECTURE.md` section 7 describes a nightly one (hosted services registered in `S/Dranzo.Api/FeatureRegistration.cs` do not include it). | Phase 5: nightly verify + alert. |
| I | Secrets in audit detail. | Convention: hash content, never store tokens or script bodies (`CLAUDE.md`; `ContentSha256`). | Convention only. | Test that scans audit detail for token patterns. |
| D | An audit write failure blocks or silently skips an action. | Writes are awaited in the request path. | Behaviour when the audit insert fails after the action committed is per call site. | Transactional outbox for audit. |

### 4.14 CI/CD and supply chain

| STRIDE | Threat | Exists today (in the repository; **the workflow has never run**) | Residual risk | Planned |
|---|---|---|---|---|
| T | Compromised GitHub Action or build tool. | Every action pinned to a full commit SHA; tools installed with `go install module@version` (checksum database); `permissions: {}` by default; no `pull_request_target`; Dependabot for actions (`.github/workflows/ci.yml`, `.github/dependabot.yml`). | A pinned SHA that is itself malicious; hosted runner image compromise; `dotnet tool` (WiX) and `apt` packages are not hash-pinned. | Reproducible agent builds verified from two builders. |
| T | Malicious dependency. | Lock files enforced (`--locked-mode`, `npm ci`, `go mod verify`); govulncheck, `dotnet list package --vulnerable`, `npm audit`, Trivy; CycloneDX SBOMs. | Scanners find known vulnerabilities, not fresh malicious code. | - |
| I/E | Signing secrets stolen through a pull request or a compromised workflow. | Signing secrets are meant to live in the GitHub **environment** `release-signing`, entered only on pushes to `main` and version tags; PR builds are unsigned by construction; macOS keychain and Windows certificate store entries are removed after the job (`ci.yml`, `installers/macos/ci-import-signing.sh`, `installers/wix/build.ps1`). | Anyone who can push to `main` or a `v*` tag can run code with the signing secrets. A PFX in a secret is exportable. | Required reviewers on the environment; branch/tag protection; HSM-backed signing (Trusted Signing / notarisation with scoped API key). |
| S | Unsigned or tampered installer distributed to clients. | Build fails if signing is configured but fails; unsigned builds are labelled (`-UNSIGNED` artifact name, warning annotation); checksums produced (`installers/*/build-*`). | **No signing has ever been performed**; no package repository with signed metadata exists; unsigned artifacts can still be downloaded from CI by anyone with repo access. | Phase 1/8: signed apt/yum repository, release process. |
| T | **Trust anchors embedded at build time are swapped** (`DRANZO_EMBED_COMMAND_KEYS`, `DRANZO_EMBED_CA_PEM_B64` repository variables → `scripts/build-agent.sh`). | Values are public, set by repository administrators. | Whoever can edit repository variables can make future agent builds trust an attacker's CA and command key. This is as sensitive as a signing key although it is "not a secret". | Commit the production anchors to the repo (reviewed) instead of variables, or sign them. |
| I | Secrets committed. | gitleaks pre-commit and CI over full history with project-specific token rules (`.pre-commit-config.yaml`, `.gitleaks.toml`); `.gitignore` for key material. | Pre-commit is opt-in per clone. | GitHub push protection. |

### 4.15 MeshCentral (remote desktop)

Integration code exists on the server (`S/Dranzo.Api/Features/MeshCentral.cs`); not deployed.

| STRIDE | Threat | Exists today | Residual risk | Planned (Phase 6) |
|---|---|---|---|---|
| E | MeshCentral is a **second, independent remote-control plane**: its agent runs as root/SYSTEM and obeys the MeshCentral server, not DranzoRMM's signed commands. A MeshCentral compromise is remote desktop on every device where its agent is installed, bypassing DranzoRMM consent, RBAC and audit. | Mesh agent installed only through a signed `mesh.install` job with hash verification (PROTOCOL 6.2); dashboard access through short-lived login tokens minted by the server (`MeshCentral.cs`, AES-256-GCM in MeshCentral's cookie format). | The login-token key grants access as the configured MeshCentral user (default `admin`, `S/Dranzo.Api/DranzoOptions.cs` `MeshOptions`); MeshCentral's own accounts, updates and consent settings are outside our control plane. | Install the Mesh agent **on demand per session and remove it afterwards**; MeshCentral reachable only through the server; per-session least-privilege Mesh user; enforce MeshCentral's own consent/notification features; patch cadence. |
| S | Forged login token. | Key from configuration/Key Vault. | Key leak = MeshCentral admin. | Rotate; store only in Key Vault. |
| R | Desktop session not in our audit log. | `RemoteSession` row created by our API before the Mesh session. | Sessions started directly in MeshCentral are invisible to DranzoRMM. | Block direct MeshCentral logins. |

## 5. What a full server compromise means

Assume T4: code execution inside `Dranzo.Api` in production.

**The attacker gets**

- A1 and A2 from process memory (4.9). They can sign `job.dispatch` for every device of every
  partner and run code as root/LocalSystem fleet-wide. **Nothing on the agent side can
  distinguish this from normal operation**: the agent's protection is against everyone
  *except* the holder of the signing key.
- The database (all tenant data, hashes, protected TOTP secrets and the key ring that decrypts
  them), object storage, MeshCentral login-token key, SMTP credentials.
- The ability to keep that power after being evicted, because A1 is exportable: until every
  agent's trust store is rotated, a copied key still works on any connection the attacker can
  establish to an agent (which also needs A2 or the gateway).

**What limits the blast radius today**

| Limit | Effect | Where |
|---|---|---|
| Agents connect outbound only and pin the CA | A stolen signing key alone cannot reach agents; the attacker also needs the gateway (or A2 plus network position). | `A/transport/tls.go` |
| Commands are per-device, short-lived, nonce-protected | No broadcast command; captured commands do not replay. | `A/protocol/verify.go`, `nonce.go` |
| Trust store changes only via signed `trust.rotate` or reinstall | Recovery is possible **if** a key the attacker does not hold is already trusted by the agents. | `A/trust/trust.go` |
| Keys are not in the database or backups | A database-only breach (T5-read) does not yield A1/A2. | `KeyStore.cs` |
| Key-store identity is read-only after first start; vault reads are logged | The attacker cannot destroy or replace keys in the vault; reads leave a trace. | `deploy/bicep` (not deployed) |
| Device-local transparency | Jobs appear in the local agent log; sessions will show an indicator (Phase 6). | `A/logging` |
| Audit chain | Naive log tampering is detectable. A T4 attacker can defeat it (4.13). | `AuditLog.cs` |

**What does not exist yet and would actually contain a server compromise**

1. *Pre-production:* a **second command key kept offline**, present in every agent's trust store
   from the first build, so that `trust.rotate` away from a stolen online key is possible
   without touching each device.
2. *Phase 8:* **separate offline release-signing key** for agent updates (4.12).
3. *Decision pending:* non-exportable signing (HSM-backed ECDSA or an isolated signing service
   that enforces policy: rate limits, allowed job kinds, per-tenant caps, human approval for
   fleet-wide commands). Today the signer signs whatever the process asks.
4. *Pre-production:* offline root CA; external anchoring of the audit chain; least-privilege
   database role; Data Protection key ring outside the database.
5. *Later:* agent-side policy that the server cannot override (per-organisation "require local
   consent for scripts", maintenance windows enforced on the device, kill switch).
6. *Architecture:* the agent gateway and the dashboard API in one process means an RCE in any
   dashboard endpoint is an RCE next to the signing key. Splitting the signer (or the gateway)
   into its own minimal process is the structural fix; the in-process registry currently
   prevents it (`docs/ARCHITECTURE.md` section 9).

Incident procedure: `docs/RUNBOOK.md` section 8.1.

## 6. Open risks, ranked

| # | Risk | Section | Needed before production? |
|---|---|---|---|
| 1 | Signing key exportable and in server memory; no offline recovery key in agent trust stores | 4.9, 5 | Yes |
| 2 | Technician accounts protected by phishable TOTP only | 4.5 | Yes for Partner Admins |
| 3 | Data Protection key ring in the database unencrypted; weak recovery-code hashing | 4.7 | Yes |
| 4 | Database write access equals fleet control (dispatcher signs queued runs) | 4.7 | Mitigate with a least-privilege role |
| 5 | Single online CA | 4.9 | Yes |
| 6 | Audit chain not anchored externally; no scheduled verification | 4.13 | Yes |
| 7 | No code signing performed yet; no signed package repository; embedded trust anchors come from mutable CI variables | 4.14 | Yes |
| 8 | Session consent/indicator and self-update not implemented in the agent | 4.11, 4.12 | Before those features are enabled |
| 9 | MeshCentral as an independent root-level control plane | 4.15 | Before Phase 6 ships |
| 10 | Single process / in-process registry: capacity and isolation limit | 4.4, 5 | Accept for pilot |
| 11 | Windows agent does not verify ACLs on its key files | 4.1 | Yes |
| 12 | Forwarded-header trust is all-or-nothing | 4.5 | Yes if any listener is directly reachable |


## Independent review, 2026-11-12

An independent security review of the server (read-only, with proof-of-concept tests against the real server
fixture) reported 8 confirmed and several suspected issues. All were fixed; each has a regression test in
`server/tests/Dranzo.Tests/SecurityRegressionTests.cs`, and every original proof of concept now fails.

| # | Severity | Issue | Fix |
|---|---|---|---|
| F7 | High | One agent could burn server CPU through vulnerability matching (23.6 s per message). | Per-type size/rate limits on heavy reports, unchanged-report skip, matching indexed by product with a hard work budget (1.0 s worst case measured). |
| F1 | High | Org-scoped technician could delete site/group policy assignments protecting another organization. | Assignment delete/list check the target site/group against the caller's scope. |
| F9 | High (MeshCentral) | Remote-desktop link signs in as a per-organization MeshCentral account, wider than a site/group technician's scope; shared-group fallback. | Link only for callers with organization-wide remote-desktop scope; no shared-group fallback unless `Mesh:AllowSharedUser`; step-up for MeshAgent install. **Residual:** the MeshCentral web session can outlive the DranzoRMM session and the MeshCentral account sees the whole organization. A per-session, per-node MeshCentral user via its API is the planned fix. |
| F2 | Medium | `users.manage` alone could reset a Partner Admin's password/MFA. | User management refuses targets holding permissions the caller lacks. |
| F3 | Medium | An agent in one organization defined patch severity/category used by another organization's auto-approval. | Patch catalog is per organization; at most 500 new entries per report. **Residual:** a compromised agent can still mislabel updates for its own organization. |
| F4 | Medium | The previous (possibly stolen) certificate could renew and evict the device. | Only the current certificate can renew; attempts raise an `agent.tamper` alert. |
| F5 | Medium | Alert/audit/notification flooding from one agent (64 invented disks per message). | One disk alert per device; per-type rate limits; smaller per-type size caps. |
| F6 | Medium | `SubscribeJob` streamed other organizations' run results. | Job group only receives `jobChanged`; clients re-read through the filtered API. |
| F8 | Low | Hub ignored idle timeout, disabled users and forced password change. | Hub calls re-check the full session rules and refresh activity. |
| F10 | Low/Medium | Consent mode / signed-PowerShell downgrades without step-up. | Step-up for downgrades. |
| F11 | Low | Schedules kept running with a removed creator's authority; forced-reboot windows with `patches.approve` only. | Schedules re-check the creator's current scope (disable + audit otherwise); re-enable needs step-up; patch policies need `patches.install`, forced reboot needs step-up. |
| F12 | Low | Audit attribution gaps (API keys, session ended by another user, uninstall revocation). | Correct actor recorded in each path. |
| — | Low | TOTP replay race, revocation race, forwarded headers on the agent listener, hub cross-origin upgrade, NAT64/6to4/Teredo/Azure wireserver SSRF ranges, URL/path package ids. | Atomic step burn; status re-check after registration; forwarded headers only on the dashboard listener; same-host Origin check; ranges blocked; ids rejected. |

## Phase 10: network and firewall features

| Area | Threat | Control |
|---|---|---|
| Firewall rule policies | A wrong or malicious policy cuts devices off DranzoRMM. | Rules that block all outgoing traffic are refused (server and agent). After applying, the agent opens a new connection to the server and restores the previous rules if that fails. The agent only touches its own rules (group/table/anchor "DranzoRMM"), visible in the OS firewall tools, and removes them on uninstall. `policies.manage` is needed. |
| Isolation | Abuse to cut a customer's computer off (denial of service), or isolation that strands the device. | `devices.isolate` (not in Technician), authenticator step-up, a reason in the audit log, user notification. The server, MeshCentral, DNS and DHCP stay reachable; the agent releases itself if the server is unreachable afterwards; a local administrator can run `dranzo-agent release-isolation`. **Residual:** DNS stays open during isolation (needed to reach the server by name), so DNS tunnelling is still possible from an isolated device. |
| Network scan | Abuse as an attack tool (port scanning other networks). | Only private IPv4 subnets the device itself is on, at most 2 and /22 each; only the neighbor table is reported (no port results); `network.manage` needed; audited. |
| Network controller (UniFi) | Server-side request forgery: the server makes HTTPS calls to an address an administrator enters, usually on a private network. | Only partner-wide `network.configure` with step-up may set the address. The client is pinned to that host and port (no redirects, no proxy), never connects to loopback, link-local (cloud metadata) or multicast addresses, and never echoes response bodies. Optional certificate pinning. **Residual:** a partner admin can make the server reach any other private host on the given port and learn whether it answers like a UniFi controller; acceptable because partner admins already control the deployment. |
| Controller credentials | Theft of the UniFi API key (full control of the customer's network). | Stored encrypted (`SecretProtector`, purpose `network-controller`), never returned or logged (audit holds a hash); Wi-Fi passwords are passed to the controller only. **Residual:** a server compromise exposes every stored controller key (see section 5). Use a dedicated UniFi admin with the least role that works. |

