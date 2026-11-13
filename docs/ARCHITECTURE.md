# DranzoRMM architecture

## 1. Components

```
 Technician browser ──HTTPS──▶  Dashboard listener (:8080 behind ingress TLS)
                                 ├─ REST API  /api/v1/*      (cookie session + CSRF, or API key)
                                 ├─ SignalR   /hubs/live     (live device/job/alert/terminal events)
                                 └─ Static web (production build of /web)

 Agent (Win/macOS/Linux) ─TLS+mTLS─▶ Agent listener (:8443 dev, agents.<domain>:443 prod)
                                 ├─ POST /agent/v1/enroll    (token + CSR → device certificate)
                                 ├─ POST /agent/v1/renew
                                 ├─ WS   /agent/v1/ws        (signed commands, reports, sessions)
                                 └─ GET/PUT /agent/v1/blobs|uploads

 Server (one ASP.NET Core process: Dranzo.Api)
   ├─ PostgreSQL (EF Core, migrations)
   ├─ Object storage (IObjectStore: filesystem | S3/MinIO | Azure Blob)
   ├─ Key store (IKeyStore: dev file keystore | Azure Key Vault)
   ├─ Hosted services: scheduler, job dispatcher, offline detector, alert evaluator,
   │                   notifier, vulnerability feed sync, update rollout, audit verifier
   └─ MeshCentral (separate container) for remote desktop
```

One server process hosts both listeners. They are separate Kestrel endpoints with separate TLS settings, and every route is bound to exactly one listener (`RequireHost`/port check), so an agent certificate can never reach the dashboard API and a browser session can never reach the agent gateway.

## 2. Repository layout

| Path | Contents |
|---|---|
| `/agent` | Go module. `cmd/dranzo-agent` (entry point), `internal/*` (one package per concern, per-OS files with build tags). |
| `/server` | `src/Dranzo.Domain` (entities, enums, permissions; no dependencies), `src/Dranzo.Infrastructure` (EF Core, PKI, signing, storage, notifications, feeds), `src/Dranzo.Api` (endpoints, auth, agent gateway, hosted services), `tests/Dranzo.Tests`. |
| `/web` | React + TypeScript + Vite dashboard. |
| `/installers` | `wix/`, `macos/`, `linux/` packaging. |
| `/deploy` | `docker-compose.yml`, `bicep/`. |
| `/docs` | Specification, plan, protocol, threat model, runbook. |

## 3. Tenancy and authorization

Hierarchy: **Partner → Organization → Site → DeviceGroup → Device**.

- Every tenant-owned row carries `PartnerId`; organisation-owned rows also carry `OrganizationId`; device-owned rows carry `DeviceId` plus a denormalised `OrganizationId`.
- A `RoleAssignment` binds a principal (user or API key) to a `Role` at one scope: partner, organization, site or device group.
- A `Role` is a set of permission strings (`devices.read`, `scripts.run`, ...). Built-in roles: Partner Admin, Technician, Read-only, Organization Viewer, Network Admin (network, firewall policies, isolation; no users or scripts). Custom roles are partner-defined.

### Central enforcement

1. Every API endpoint declares exactly one permission with `RequirePermission("x.y")` (or is explicitly marked `AllowAnonymous` / `AuthenticatedOnly`). A test enumerates all endpoints and fails if one has neither.
2. Before the endpoint runs, the permission filter loads the caller's role assignments, keeps only those whose role **contains that permission**, and writes the resulting scope into the request's `TenantContext` (partner id, all-orgs flag, org ids, site ids, group ids).
3. `DranzoDbContext` has **global query filters** on every tenant-owned entity that read the `TenantContext`. A query can only return rows inside the scope where the caller holds the endpoint's permission. With no permission filter the context is empty and every query returns nothing (fail closed).
4. Writes load the target row through the same filtered context, so an out-of-scope id is a `404`, never a `403` that leaks existence. Creating partner-level objects requires partner scope.
5. Background services and the agent gateway use an explicit *system* context (`TenantContext.System`) and always query by device id / organization id.

Cross-tenant tests (`TenantIsolationTests`) run every endpoint as a user of organization A against resources of organization B and expect `404`/empty.

## 4. Identity

- ASP.NET Core Identity (`AddIdentityCore`) for password hashing (PBKDF2), lockout and TOTP. Custom `User` entity; Identity's own roles are not used.
- Login is two-step: password → TOTP. A user without TOTP is forced through enrolment at first login and gets no session until it is verified. **No MFA exemptions.** Ten 80-bit recovery codes are issued once (regenerating them needs step-up).
- Secrets that must live in the database (TOTP seeds, notification channel settings) and the short-lived login challenge are encrypted with AES-256-GCM by `SecretProtector` under a key that exists only in the key store. A copy of the database alone cannot decrypt them.
- Session: opaque server-side session row + `HttpOnly`, `Secure`, `SameSite=Strict` cookie. Idle timeout 30 min, absolute 12 h (configurable). CSRF: double-submit header (`X-CSRF-Token`) checked on every unsafe method.
- **Step-up**: sensitive endpoints carry `RequireStepUp`; the caller must have re-entered a TOTP code within the last 5 minutes (`POST /api/v1/auth/step-up`), otherwise `401` with `{"error": "step_up_required"}`. Wide actions decided at run time (more than 10 devices, a whole organization, scheduled runs on dynamic targets, script policies) apply the same check inside the endpoint.
- A user with a temporary password (`MustChangePassword`) gets `403 password_change_required` on everything except the account endpoints until the password is changed. Enforced in `AccessMiddleware`, not only in the UI.
- API keys (Phase 8): `dz_api_<id>_<secret>`, stored hashed, own role assignments, rate limited, cannot perform step-up actions.

## 5. PKI and signing

| Key | Algorithm | Use | Dev | Production |
|---|---|---|---|---|
| Device CA | ECDSA P-256 | Issues device client certs and the agent-listener server cert | file keystore (`DRANZO_KEYSTORE_DIR`, outside the repo, 0600) | Key Vault |
| Command signing key | Ed25519 | Signs `job.dispatch`, `update.available`, sessions | file keystore | Key Vault (see note) |
| Device key | ECDSA P-256 | mTLS client auth | generated on the device, never leaves it | same |
| Data encryption key | AES-256-GCM | Encrypts TOTP seeds, channel secrets, login challenge | file keystore | Key Vault secret |

Missing keys are created only when `Dranzo:KeyStore:AllowCreate` allows it (default: yes for the file store, **no** for Key Vault). A wrong or empty production key store stops the server instead of silently minting new keys that would orphan every enrolled agent.

All key use goes through `IKeyStore` / `ICommandSigner` / `ICertificateAuthority`. Certificates are built with `System.Security.Cryptography.X509Certificates.CertificateRequest`; Ed25519 uses BouncyCastle. No hand-written cryptography.

> **Note (brief conflict, see PLAN.md "Open questions")**: Azure Key Vault *keys* do not support Ed25519. The production implementation stores the Ed25519 private key as a Key Vault **secret** (loaded into server memory at start). If a non-exportable HSM key is required, switch `ICommandSigner` to ECDSA P-256 backed by a Key Vault key; that is a protocol change (section 6 of the brief) and needs sign-off.

## 6. Jobs

`Job` (what, targets, schedule, requester) fans out to one `JobRun` per device. Runs are `Pending` until the device is online and under the concurrency limit, then signed and sent (`Dispatched`), then `Running` → terminal state. The dispatcher signs at send time, so a run that waited in the queue still gets a fresh nonce and 5-minute expiry. Output chunks are appended to the run (capped) and pushed to SignalR group `run:<id>`.

Everything that acts on a device (scripts, software, patches, policies, reboots, file operations, updates) is a job kind. That gives one place for authorization, step-up, auditing, signing, concurrency and history.

## 7. Audit log

`AuditEvent` rows are append-only (no update/delete in code; database trigger rejects `UPDATE`/`DELETE`). Each row stores `PrevHash` and `Hash = SHA-256(PrevHash ‖ canonical fields)`, forming one chain per partner. `GET /api/v1/audit/verify` and the daily `AuditVerifier` hosted service recompute the chain; a mismatch is logged at critical level, written to the audit log and published as the `audit.integrity_failed` webhook event.

## 8. Live updates

SignalR hub `/hubs/live`. Clients join groups (`org:<id>`, `device:<id>`, `run:<id>`, `session:<id>`); the hub checks the caller's scope before each join. The remote terminal uses hub methods `TerminalInput`/`TerminalResize`; the server signs each input frame before relaying it to the agent.

## 9. Scaling note

The agent connection registry is in-process. One server instance handles thousands of agents; to run several instances, pin agents with session affinity and add a backplane (Redis for SignalR; Postgres `LISTEN/NOTIFY` or Redis streams for cross-instance dispatch). The dispatcher already reads work from the database, so only the "which instance holds this socket" lookup needs the backplane.

## 10. Production topology (Azure)

- One Container App runs the server image with **two ingresses**: HTTP ingress (managed certificate) for the dashboard listener, and an additional **TCP port** for the agent listener so Kestrel terminates TLS itself with the private-CA certificate and performs mTLS end to end.
- **Agent port.** The brief asks for agents on 443. Azure Container Apps does not allow an extra TCP port to reuse 80/443 of the same environment, so the Bicep defaults to **8443** for agents. To give agents 443 use one of: a second environment/app dedicated to the agent gateway, Azure Application Gateway / Front Door in TCP mode in front, or App Service / AKS. This is an open decision (see `docs/PLAN.md`).
- Splitting dashboard and agent gateway into two apps needs a backplane first (section 9); the Bicep has a `splitAgentGateway` switch for later.
- Azure Database for PostgreSQL Flexible Server (private access), Blob Storage, Key Vault (managed identity), Log Analytics. MeshCentral: separate Container App with its own storage.
- Behind the ingress set `Dranzo:TrustForwardedHeaders=true`. Forwarded headers are accepted only from `Dranzo:TrustedProxyNetworks` (default: loopback and private ranges), one hop.

See `/deploy/bicep`. The Bicep has not been compiled or deployed from this repository (needs the Azure CLI and a subscription).
