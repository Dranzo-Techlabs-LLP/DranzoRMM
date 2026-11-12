# Changelog

All notable changes to DranzoRMM. Verification status of each item is tracked in `docs/PLAN.md`.

## Unreleased (0.1.0-dev)

### Phase 0: Foundation
- Repository layout (`agent/`, `server/`, `web/`, `installers/`, `deploy/`, `docs/`, `scripts/`).
- Design documents: `SPEC.md`, `ARCHITECTURE.md`, `PROTOCOL.md`, `THREAT_MODEL.md`, `RUNBOOK.md`, `PLAN.md`, `CLAUDE.md`.
- Docker Compose development stack (PostgreSQL, Azurite blob storage, server, web, optional Linux test agent and MeshCentral).
- GitHub Actions workflow: server, web, agent on three OS runners, six cross-compiled targets, packaging, SBOM, vulnerability and secret scanning. All third-party actions pinned to commit SHAs.
- Linting: `golangci-lint`, .NET analyzers with warnings as errors, ESLint + Prettier. Dependabot, gitleaks pre-commit hook, `.env.example`.

### Phase 1: Identity, tenants, enrollment
- Password + mandatory TOTP sign-in, recovery codes, lockout, idle and absolute session timeouts, CSRF protection, step-up re-authentication, forced change of temporary passwords.
- Partner → organization → site → group tenancy with central enforcement (EF Core global query filters scoped per permission). Built-in and custom roles, assignments at any scope level.
- Private CA, enrollment tokens, CSR-based enrollment, mutual TLS agent gateway on its own listener, certificate renewal and revocation.
- Go agent: service install on Windows/macOS/Linux, enrollment, pinned-CA mTLS, reconnect with backoff, heartbeat, inventory.
- Hash-chained, append-only audit log (database triggers refuse update/delete), CSV export, on-demand and daily verification.
- Dashboard: sign-in and MFA enrollment, organizations/sites/groups, devices with live status, enrollment tokens and install commands, users and roles, audit log.
- Installers: nfpm (deb/rpm), macOS pkg, WiX MSI sources.

### Phase 2: Remote scripts
- Script library with immutable versions and typed parameters.
- Jobs on devices, groups, sites, organizations or saved filters; cron schedules in the organization time zone; run as system or logged-in user; timeouts, cancellation, per-device and per-job concurrency.
- Ed25519-signed commands with device binding, nonce and expiry, signed at send time; agent refuses unsigned, tampered, expired, misdirected and replayed commands.
- Live output streaming, output cap with truncation flag, run history, step-up for wide runs, optional signed-PowerShell-only mode per organization.

### Phase 3: Software inventory and deployment
- Installed-software inventory per device and aggregated.
- Install/uninstall through winget, Homebrew (as the console user), apt and dnf.
- Custom package library: upload with server-side SHA-256, device-scoped download grants over mTLS, hash check on the agent before execution, detection rules, retries.

### Phase 4: Patch management
- Pending-update reporting, patch catalog, per-device state, approve/reject/defer.
- Patch policies: auto-approval by severity or category, deferral days, maintenance windows, reboot policy.
- Compliance view (patched / unpatched / unknown). Reboot job.

### Phase 5: Security posture, monitoring, alerts
- Posture reporting: antivirus, firewall, disk encryption, local administrators, screen lock, listening ports.
- Vulnerability matching against NVD and CISA KEV data (heuristic; application software only).
- Alert rules (offline, disk, antivirus, firewall, encryption, patch failure, new local admin, agent tampering, compliance drift, known-exploited vulnerability) with automatic resolution.
- Notification channels: email, signed webhooks, Microsoft Teams, Slack; delivery queue with retries; outbound requests protected against SSRF.

### Phase 6: Remote support
- Remote sessions with per-organization consent (none / notify / require), visible indicator, fail-closed on disconnect, full audit including a hash of the technician's terminal input.
- Remote terminal relayed through SignalR with server-signed input frames; file browser (list, download, upload) bound to an active session.
- Remote desktop through MeshCentral with short-lived, per-organization login tokens.

### Phase 7: Policies and compliance
- Desired-state policies with built-in checks and script checks, optional remediation, assignment at any scope.
- Scheduled evaluation, compliance dashboard data, drift alerts.

### Phase 8: Agent self-update, reports, API
- Signed agent releases with rollout rings (test → pilot → all), pause, per-device state, rollback handling.
- Reports as CSV and PDF: device inventory, patch compliance, security posture, software, audit log.
- Read-only client portal role, scoped API keys with rate limits, outbound webhook events.
- Agent uninstall code and remote agent uninstall.

### Phase 9: MDM (design only)
- `docs/MDM_PLAN.md`.

### Deviations from the brief
- **Object storage in development:** Azurite instead of MinIO (MinIO no longer publishes container images). The S3 client remains available.
- **PDF library:** PDFsharp/MigraDoc pinned to 6.2.4, the last MIT release (6.5+ is AGPL).
- **Ed25519 key in Key Vault:** stored as a Key Vault secret, because Key Vault keys do not support Ed25519.
- **Agent port in Azure:** Container Apps cannot expose a second listener on 443; the Bicep defaults to 8443 (options in `docs/ARCHITECTURE.md` §10).
- **macOS minimum:** Go 1.27 binaries require macOS 13; the brief says 12.
