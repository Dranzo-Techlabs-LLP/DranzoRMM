# DranzoRMM plan

Legend: `[x]` done and tested here · `[~]` implemented, **not fully verified in this environment** (reason given) · `[ ]` not done.

Verification environment: macOS (Apple Silicon) dev machine, local PostgreSQL 16, Docker via Colima (Linux arm64 containers). **No Windows machine, no Azure subscription, no signing certificates, no root on the Mac.** Anything that needs those is marked `[~]` and listed under "Needs your environment".

## Open questions for the owner

1. **Ed25519 in Key Vault.** The brief says the command-signing key is "an Ed25519 key held in Key Vault". Azure Key Vault *keys* support RSA and NIST EC curves only, not Ed25519. Implemented: Ed25519 as specified, private key stored as a Key Vault **secret** (loaded into server memory). Alternative: ECDSA P-256 with a non-exportable Key Vault key (changes brief §6; needs your sign-off).
2. **CA depth.** One private CA issues device and gateway certificates. An offline root + online issuing CA is recommended before production.
3. **Run-everything-phase instruction.** The brief says stop after each phase; you asked for all phases in one go. Phases were built in order with a commit each, without pausing.

## Phase 0: Foundation

- [ ] Repo scaffold (`agent/`, `server/`, `web/`, `installers/`, `deploy/`, `docs/`, `scripts/`)
- [ ] `docs/SPEC.md`, `ARCHITECTURE.md`, `PROTOCOL.md`, `THREAT_MODEL.md`, `PLAN.md`, `RUNBOOK.md`, `CLAUDE.md`
- [ ] Lint/format: Go (`gofmt`, `golangci-lint`), C# (analyzers, warnings as errors), TypeScript (ESLint, Prettier)
- [ ] Docker Compose dev environment (PostgreSQL, MinIO, server, web, MeshCentral, Linux test agent)
- [ ] CI workflows: build/test server, web, agent on 3 OS runners, 6 cross-compiled targets, packaging, SBOM, scans
- [ ] Secret scanning (gitleaks pre-commit), Dependabot, `.env.example`

## Phase 1: Identity, tenants, enrollment

- [ ] Data model + EF Core migrations, central tenant query filters
- [ ] Login: password policy, lockout, mandatory TOTP, recovery codes, sessions (idle/absolute timeout), CSRF, step-up
- [ ] Passkeys / WebAuthn as an optional second factor
- [ ] RBAC: built-in roles, custom roles, assignments scoped to partner / organization / site / group
- [ ] Organizations, sites, groups CRUD; users and roles admin
- [ ] Private CA, enrollment tokens, CSR enrollment, mTLS gateway, certificate renewal and revocation
- [ ] Agent: service install (3 OSes), enroll, mTLS, reconnect/backoff, heartbeat, inventory
- [ ] Hash-chained append-only audit log, export, verification
- [ ] Dashboard: login/MFA, tenants, devices list/detail (live status), enrollment, users/roles, audit
- [ ] Tests: auth, tenant isolation (every endpoint), gateway mTLS, audit chain
- [ ] Installers: MSI (WiX), pkg, deb/rpm with token parameter

## Phase 2: Remote scripts

- [ ] Script library with immutable versions, typed parameters
- [ ] Run on devices / group / site / organization / saved filter; cron schedules in the organization time zone
- [ ] Run as system or logged-in user; timeouts; cancellation; per-device and per-job concurrency limits
- [ ] Signed dispatch (Ed25519, nonce, expiry), agent-side verification and replay protection
- [ ] Live output streaming, history per device, output cap with truncation flag
- [ ] Step-up for >10 devices or a whole organization
- [ ] Windows signed-PowerShell-only mode
- [ ] Dashboard: script editor, run dialog, live output, job/run history, schedules

## Phase 3: Software inventory and deployment

- [ ] Agent collectors: Windows (registry, winget), macOS (apps, pkgutil, Homebrew), Linux (dpkg/rpm, snap, flatpak)
- [ ] Package-manager install/uninstall: winget, Homebrew (as console user), apt/dnf
- [ ] Custom package upload, SHA-256 verification on the agent, silent install args, detection rules
- [ ] Deployment jobs with per-device status and retries
- [ ] Dashboard: software inventory, deploy/uninstall, package library

## Phase 4: Patch management

- [ ] Agent: Windows Update (COM API), macOS `softwareupdate`, apt/dnf; third-party via winget/Homebrew
- [ ] Patch catalog, per-device state, approvals; policies (auto-approve, maintenance window, deferral)
- [ ] Reboot policy (notify, deferrals, deadline)
- [ ] Compliance view; documented limits

## Phase 5: Security posture, monitoring, alerts

- [ ] Agent posture collectors (AV, firewall, disk encryption, local admins, screen lock, ports)
- [ ] Vulnerability matching (NVD + CISA KEV)
- [ ] Alert rules and evaluation; notification channels (email, webhook, Teams, Slack)
- [ ] Dashboard: security posture, vulnerabilities, alerts, channels

## Phase 6: Remote support

- [ ] Sessions with consent modes and visible indicator; `RemoteSession` records and audit
- [ ] Remote terminal (xterm.js ↔ PTY/ConPTY), signed input frames
- [ ] File browser (list, upload, download, size limits)
- [ ] Remote desktop via MeshCentral (agent-managed MeshAgent, short-lived login token)
- [ ] macOS permission documentation

## Phase 7: Policies and compliance

- [ ] Built-in checks + script checks, remediation, assignments
- [ ] Compliance dashboard, drift alerts
- [ ] Tray / menu-bar helper (optional in the brief)

## Phase 8: Agent self-update, reports, API

- [ ] Signed releases, rollout rings, agent update with rollback
- [ ] Reports (CSV, PDF)
- [ ] Client portal (Organization Viewer)
- [ ] Public API keys with scopes and rate limits; outbound webhooks

## Phase 9: MDM (design only)

- [ ] `docs/MDM_PLAN.md`

## Needs your environment (cannot be verified here)

Filled in at the end of the build.
