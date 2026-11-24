# Changelog

All notable changes to DranzoRMM. Verification status of each item is tracked in `docs/PLAN.md`.

## Unreleased (0.1.0-dev)

### Phase 10: Network and firewall
- Permissions `network.read`, `network.manage`, `network.configure`, `devices.isolate` and the built-in role Network Admin.
- Security score per device (0-100, A-F) with the reason for every lost point; shown on the device, on the Security page (lowest first, average, low-score filter) and in the security-posture report.
- 802.1X (EAP-TLS) office Wi-Fi: per-organization network CA, a certificate per company device (key made on the device), Wi-Fi profiles installed by the agent (Windows, Linux), a ready-to-run FreeRADIUS server download, one click to switch the UniFi office Wi-Fi to WPA2-Enterprise; revoked, deleted and blocked devices are refused within 5 minutes (CRL).
- UniFi integration: Network > Wi-Fi & controllers. Connect a UniFi console (API key, stored encrypted), see access points, switches and gateways (restart), set up separate office and guest Wi-Fi on their own VLANs, alert when a company device joins guest Wi-Fi; blocking a discovered device blocks it on the Wi-Fi. Not yet verified on real UniFi hardware.
- Device isolation: Isolate / Release on the device page (needs `devices.isolate`, authenticator code and a reason). The device keeps only DranzoRMM, remote desktop, DNS and DHCP; it undoes the isolation itself if it cannot reach the server; the user is notified; a local administrator can run `dranzo-agent release-isolation`.
- Firewall rule policies: new policy check `firewall.rules` with a rule editor (allow/block, direction, protocol, ports, addresses, Windows program). DranzoRMM only manages its own rules, rolls back if the device can no longer reach the server, and removes its rules on uninstall.
- Network discovery: `network.scan` job lists every device a managed computer sees on its local network (IP, MAC, reverse-DNS name, gateway, private-MAC flag); Network > Network devices page with approve/block/forget and bulk actions; new-device alert. Inventory now reports the default gateway and the Wi-Fi connection.
- Access review: every user and API key with roles, scopes, effective permissions and findings (no MFA, inactive 90+ days, never-expiring keys, full admins). Page under Admin, CSV/PDF report, partner admins only, viewing is audited.

### Fixes from the 2026-11-19 end-to-end test (rmm.dranzo.com, Windows 11 + macOS 26 devices)
- Policies: a check the agent does not know ("unknown check", older agent) is stored as unsupported with "update the agent", no longer as non-compliant, so it raises no compliance-drift alert and does not lower the score.
- Isolation and network scan: the server refuses them with a clear 409 when the device's agent does not support them, instead of queuing a job that can never run; the Isolate button is disabled with an explanation for such devices, and the refused attempt is audited.
- Software deployment: "install" without a version leaves already-installed software unchanged ("already installed; not changed") instead of silently upgrading it (winget, apt). Updates stay in Patches. Held dpkg packages (`hi`) now count as installed.
- macOS consent prompt: announced in Notification Center with a sound before the dialog, so a dialog behind a full-screen app or on another Space is still noticed. Not yet verified on a Mac.
- Vulnerabilities: a macOS installer receipt (`com.apple.pkg.*`) no longer duplicates every finding of its app (same product and major.minor version only; an older separate install is still matched).
- Inventory (macOS): read-only APFS/HFS volumes under /Volumes (mounted disk images) are no longer listed as disks; read-only NTFS and locked USB drives still are.
- Agent self-update (Windows): staging failed with "sync ...dranzo-agent.new.exe: Access is denied" because the staged file was flushed through a read-only handle, which Windows refuses. Found when rolling out 0.1.1; fixed in 0.1.2. Agents older than 0.1.2 on Windows cannot update themselves and need a one-time manual (or scripted) replacement.
- Windows PowerShell scripts fed on stdin (`-Command -`): a statement spanning several lines only runs when a blank line follows, so the network scan, default gateway, firewall-rule and **isolation** scripts silently did nothing on Windows (scan found 0 devices, no gateway; isolation and firewall rules would not have been applied). Every such script now ends with a blank line (0.1.3). Verified on the field-test PC.
- Remote file sessions: uploads and downloads count in the session's bytes in/out.
- Device page: uptime counts from the boot time while the device is online (no longer frozen at inventory time); "Network" says "Not reported by the agent" instead of "Wired" when nothing was reported.

### Fixes after first LAN testing
- Windows: single-PC installer script (`scripts/windows-kit/Install-DranzoAgent.ps1` + double-click `.cmd`) that reports every step.
- MeshCentral: `Dranzo:Mesh:CertificateSha256` pins a self-signed MeshCentral certificate for MeshAgent downloads (normal validation otherwise).

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
