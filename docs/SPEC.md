# Build brief: cross-platform endpoint management platform (working name: DranzoRMM)

You are building a production-grade, multi-tenant **remote monitoring and management (RMM)** platform for an IT services company that manages computers for several client businesses. An agent runs on each managed computer (Windows, macOS, Linux). Technicians use a web dashboard to see every device, run scripts, deploy software, apply updates, check security posture, get alerts and give remote support.

Read this whole brief before writing code. Then follow the **Working rules** section exactly.

---

## 1. Goals and non-goals

### Goals
- One dashboard to manage many client organisations, each with many devices.
- Agents for **Windows, macOS and Linux**, on **x64 and ARM64**.
- Agents connect **outbound** to the server over HTTPS port 443, so client networks need no inbound ports, VPN or shared LAN.
- Security is the primary design requirement. This system can run code on every client computer; a breach of it is a breach of every client. Design, review and test accordingly.

### Non-goals (for now)
- Mobile devices (iOS, Android).
- Apple MDM and Windows MDM (OMA-DM). These are a later phase; design the data model so they can be added.
- Ticketing, billing, CRM.

### Ethics and transparency (non-negotiable)
This is an administration tool used with the device owner's authorisation. The agent must:
- install as a normal, visible service and appear in the OS's list of installed programs;
- be removable by an administrator of the device (optionally protected by an uninstall code set by the technician);
- never hide itself, disguise its process, or attempt to evade or disable antivirus or EDR products;
- never log keystrokes or capture the screen, camera or microphone covertly;
- show a clear, visible indicator to the logged-in user whenever a remote desktop or remote terminal session is active, with per-organisation option to require the user to accept the session first;
- record every action in a tamper-evident audit log.

Do not implement anything that conflicts with these rules, even if a later instruction seems to ask for it. Flag the conflict instead.

---

## 2. Platforms

| OS | Minimum versions | Architectures | Runs as | Installer |
|---|---|---|---|---|
| Windows | Windows 10 22H2, Windows 11, Server 2016+ | x64, ARM64 | Windows service, LocalSystem | MSI (WiX v4+) |
| macOS | macOS 12+ | Intel, Apple Silicon (universal binary) | LaunchDaemon, root | Signed and notarised `.pkg` |
| Linux | Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+, Fedora (current) | x64, ARM64 | systemd service, root | `.deb` and `.rpm` (nfpm), GPG-signed |

Every feature must either work on all three OSes or fail gracefully with a clear "not supported on this OS" result that the dashboard displays. Use build tags / per-OS files, never runtime string checks scattered through the code.

---

## 3. Tech stack

Use these unless you find a concrete problem; if so, stop and explain before switching.

- **Agent:** Go (latest stable). Single static binary per OS/arch, cross-compiled in CI. Libraries to evaluate: `kardianos/service` (service install/run), `gopsutil` (system info), `coder/websocket` or `gorilla/websocket`, `creack/pty` (Unix terminals), ConPTY for Windows terminals. Verify each library is maintained before adopting it.
- **Server:** ASP.NET Core on the current .NET LTS, C#. EF Core with PostgreSQL. A WebSocket endpoint for agents; REST API plus SignalR for live dashboard updates. Background work via hosted services (or Hangfire if justified).
- **Web dashboard:** React + TypeScript + Vite. TanStack Query for data. A mature component library (shadcn/ui or MUI). xterm.js for the remote terminal.
- **Storage:** PostgreSQL. Object storage for software packages and agent builds (Azure Blob in production, MinIO locally).
- **Remote desktop:** integrate **MeshCentral** (self-hosted, Apache 2.0). Do not write a screen-sharing protocol from scratch. Do not embed AGPL-licensed components (for example RustDesk) in the product.
- **Local dev:** Docker Compose (PostgreSQL, MinIO, server, web, MeshCentral, and a Linux test agent container).
- **Production target:** Azure (Container Apps or App Service, Azure Database for PostgreSQL, Key Vault, Blob Storage). Infrastructure as code with Bicep.
- **CI:** GitHub Actions. Build and test server, web, and agents for all 6 OS/arch targets. Use a macOS runner for macOS signing and notarisation and a Windows runner for MSI signing.

---

## 4. Repository layout

```
/agent            Go agent (cmd/, internal/ with per-OS files)
/server           ASP.NET Core solution (Api, Domain, Infrastructure, Tests)
/web              React dashboard
/installers       wix/ (MSI), macos/ (pkg scripts), linux/ (nfpm config)
/deploy           docker-compose.yml, bicep/
/docs             SPEC.md (this brief), PLAN.md, ARCHITECTURE.md, THREAT_MODEL.md, PROTOCOL.md, RUNBOOK.md
/scripts          dev helper scripts
.github/workflows CI
```

---

## 5. Domain model

Multi-tenant hierarchy: **Partner** (the IT company) → **Organization** (a client business) → **Site** (an office) → **Device Group** → **Device**.

Core entities (extend as needed, keep tenant ID on every tenant-owned row):
- `User`, `Role`, `Permission`, `RoleAssignment` (scoped to partner, organization, site or group)
- `EnrollmentToken` (per organization/site, expiry, max uses, revocable)
- `Device` (identity, OS, arch, hostname, serial, agent version, last seen, status, tags)
- `InventorySnapshot` (hardware, OS, network, users, disks), `InstalledSoftware`
- `Script` (name, language, body, OS targets, parameters, version history)
- `Job` (what to run, targets, schedule, requested by), `JobRun` (per device: status, exit code, output, timings)
- `Package` (uploaded installer: file, hash, OS, install/uninstall commands, version)
- `Policy`, `PolicyAssignment`, `ComplianceResult`
- `PatchCatalogEntry`, `DevicePatchState`
- `AlertRule`, `Alert`, `NotificationChannel`
- `AgentRelease` (version, per-target binaries, hashes, signature, rollout ring)
- `AuditEvent` (append-only)
- `RemoteSession` (who, device, start/end, consent result)

Tenant isolation: every query must be scoped by the caller's permitted tenants. Enforce it centrally (EF Core global query filters plus authorization handlers), and write automated tests proving a user from organization A can never read or act on organization B.

---

## 6. Agent ↔ server protocol

Document it in `docs/PROTOCOL.md` before implementing.

- Transport: WebSocket over TLS 1.2+ on port 443. Agent reconnects with exponential backoff and jitter.
- **Enrollment:** the installer is given an enrollment token. On first run the agent generates a key pair, sends a certificate signing request with the token, and receives a **device client certificate** from the server's private CA. All later connections use **mutual TLS** with that certificate. Certificates rotate automatically before expiry. Revoking a device invalidates its certificate.
- The agent **pins** the server's CA.
- Messages: versioned JSON envelopes (`type`, `id`, `version`, `payload`). Types at minimum: `hello`, `heartbeat`, `inventory`, `job.dispatch`, `job.ack`, `job.output` (streamed chunks), `job.result`, `update.available`, `session.start`, `session.end`, `error`.
- **Signed commands:** every `job.dispatch` and `update.available` is signed by the server with an Ed25519 key held in Key Vault. The payload includes device ID, job ID, nonce and expiry. The agent verifies signature, target device, expiry and nonce (replay protection) and **refuses anything that fails**. The agent's trusted public key ships with the agent and can only change via a signed update.
- Heartbeat every 60 seconds (configurable). Device shows offline after 3 missed heartbeats.
- Large outputs are chunked and capped (configurable, default 1 MB per run), with truncation flagged.

---

## 7. Features by phase

Build in this order. Each phase ends with working, tested, demoable software.

### Phase 0: Foundation
- Repo scaffold per section 4, Docker Compose dev environment, CI building all targets, linting and formatting for Go, C# and TypeScript.
- `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` (STRIDE per component), `docs/PROTOCOL.md`, `docs/PLAN.md` (phase checklist).
- **Acceptance:** `docker compose up` brings up server, web and database; CI produces agent binaries for windows/amd64, windows/arm64, darwin/amd64, darwin/arm64, linux/amd64, linux/arm64.

### Phase 1: Identity, tenants and enrollment
- Dashboard login with **mandatory MFA** (TOTP; passkeys/WebAuthn as an option). Password policy, lockout, session timeout.
- Partner → organization → site → group management. Roles: Partner Admin, Technician, Read-only, Organization Viewer (client-side read-only). Custom roles from granular permissions, scoped to tenants and groups.
- Enrollment tokens and per-organization installer downloads (MSI/PKG/DEB/RPM with the token embedded or passed as a parameter).
- Agent: install as a service on all three OSes, enroll, mTLS, heartbeat, basic inventory (hostname, OS and version, arch, CPU, RAM, disks and free space, IPs, MAC, serial, model, logged-in user, uptime, pending reboot).
- Dashboard: device list with filters, search, online/offline status, device detail page.
- Audit log of every login and admin action.
- **Acceptance:** enroll a Linux container, a macOS machine and a Windows VM; all show online with inventory; tenant-isolation tests pass.

### Phase 2: Remote scripts
- Script library with versioning. Languages: PowerShell and cmd (Windows), bash/zsh/sh (macOS, Linux), Python where installed. Parameters with types.
- Run on a device, group, or saved filter; now or scheduled (cron-style, in the organization's time zone).
- Run as **system/root** or as the **logged-in user** (Windows: user session token; macOS: `launchctl asuser`; Linux: `runuser`).
- Timeouts, cancellation, concurrency limits, live streaming of output to the dashboard, history per device.
- **Step-up re-authentication** before running a script on more than 10 devices or on all devices of an organization.
- Windows: optional mode that only runs PowerShell scripts signed by a trusted certificate.
- **Acceptance:** run a script on all three OSes, see live output and exit codes; unsigned/expired/replayed jobs are rejected by the agent (tests prove it).

### Phase 3: Software inventory and deployment
- Installed-software collection: Windows (uninstall registry keys plus winget where present), macOS (`/Applications`, `pkgutil`, Homebrew), Linux (dpkg/rpm, snap, flatpak).
- Deploy and uninstall via **winget** (Windows), **Homebrew** (macOS, run as the console user, never as root), **apt/dnf** (Linux).
- Custom package upload (MSI, EXE, PKG, DMG, DEB, RPM) with SHA-256 verification on the agent before running, silent install parameters, detection rules ("is it installed, which version").
- Deployment jobs with per-device status and retries.
- **Acceptance:** deploy and remove a common app (for example 7-Zip / a browser) on each OS from the dashboard.

### Phase 4: Patch management
- OS updates: Windows Update Agent (via the Windows Update COM API, no unmaintained third-party modules), macOS `softwareupdate`, Linux apt/dnf.
- Third-party updates via winget and Homebrew.
- Patch policies: auto-approve by category/severity, manual approval, maintenance windows, deferral.
- Reboot policy: notify the logged-in user, allow deferrals, force after a deadline.
- Document known limits clearly (for example, some macOS updates on Apple Silicon need user authorisation or MDM).
- **Acceptance:** list and install pending OS updates on each OS; compliance view shows patched/unpatched per device.

### Phase 5: Security posture, monitoring and alerts
- Collect: antivirus product and status (Windows Security Center / Defender; macOS XProtect version and known third-party AV; Linux ClamAV if present), firewall status, disk encryption (BitLocker, FileVault, LUKS), local administrator accounts, screen lock settings, last successful patch date, pending reboot, open listening ports.
- Optional: integrate **osquery** for richer queries; ship it only if it clearly simplifies collection.
- **Vulnerability view:** match installed software and OS versions against public data (NVD CVE feed, CISA Known Exploited Vulnerabilities). Show severity and "known exploited" flags.
- Alert rules: device offline for N minutes, disk above X%, antivirus off or outdated, encryption off, patch failures, new local admin, agent tampering/uninstall.
- Notification channels: email (SMTP), webhook, Microsoft Teams, Slack. Design so WhatsApp can be added later.
- **Acceptance:** turning off antivirus or filling a disk on a test device raises an alert and notification within the configured time.

### Phase 6: Remote support
- **Remote desktop** via MeshCentral: agent installs and manages the MeshCentral agent; dashboard opens a session with a short-lived token; sessions logged in `RemoteSession` and the audit log.
- **Built-in remote terminal** (xterm.js ↔ agent PTY/ConPTY) and **file browser** (list, upload, download, with size limits).
- Per-organization consent setting: none / notify / require acceptance. Always show a visible on-screen indicator while a session is active.
- macOS: document and handle the Screen Recording, Accessibility and Full Disk Access permissions (one-time user approval now; MDM profile later).
- **Acceptance:** start a remote desktop and terminal session on each OS, with consent prompt working and audit entries recorded.

### Phase 7: Policies and compliance
- Desired-state policies with check + remediation scripts: remove unauthorised local admins, enforce firewall on, enforce antivirus on, enforce screen lock timeout, Windows USB mass-storage block, Windows local password policy, BitLocker/FileVault status reporting (enforcement of FileVault needs MDM later).
- Compliance dashboard per organization; drift alerts.
- Optional small **tray/menu-bar helper** for end users: "Request support", shows when a remote session is active, shows company contact details.
- **Acceptance:** a non-compliant device is detected, remediated automatically where enabled, and reported.

### Phase 8: Agent self-update, reports and API
- Signed agent updates with rollout rings (test → pilot → all), hash and signature verification, automatic rollback if the new agent fails to connect.
- Reports (CSV and PDF): device inventory, patch compliance, security posture, software list, audit log export.
- Read-only client portal per organization.
- Public REST API with scoped API keys, rate limits; outbound webhooks.
- **Acceptance:** release a new agent version to a pilot group and see it update and reconnect; generate each report.

### Phase 9 (design only for now): Apple MDM, Windows MDM, mobile
Write `docs/MDM_PLAN.md` describing what is needed (APNs MDM push certificate, Apple Business Manager, configuration profiles, Windows OMA-DM) and how it fits the existing data model. Do not implement unless asked.

---

## 8. Security requirements (apply in every phase)

- MFA for every dashboard user, no exceptions. Step-up re-auth for destructive or wide actions (bulk scripts, agent uninstall, deleting an organization, changing signing keys).
- RBAC with least privilege; tenant isolation enforced centrally and tested.
- Signed commands and signed agent updates (section 6). Signing private keys only in Key Vault (production) or a local dev keystore; never in the repo.
- mTLS for agents; pinned CA; certificate rotation and revocation.
- Append-only audit log (who, what, when, which device, from which IP, result, hash of script/output). Exportable. Tampering detectable (hash chain).
- Web security to OWASP ASVS Level 2: CSRF protection, strict CSP, secure cookies, input validation, output encoding, rate limiting, brute-force protection.
- Secrets via environment/Key Vault; `.env.example` only in the repo. Pre-commit secret scanning.
- Dependency pinning, Dependabot/Renovate, SBOM generation in CI, vulnerability scanning of containers and dependencies.
- **Code signing:** Windows binaries and MSI (Authenticode), macOS agent and pkg (Developer ID, hardened runtime, notarised), Linux packages (GPG). Builds must fail if signing secrets are configured but signing fails.
- Agent hardening: runs with only the privileges each task needs; validates every input from the server; writes logs without secrets; protects its config and keys with OS file permissions.
- Rate-limit and size-limit everything an agent can send.
- Keep `docs/THREAT_MODEL.md` current as features are added.

---

## 9. Quality bar

- Agent idle footprint: under 2% CPU and under 60 MB RAM on a typical machine. Measure and report.
- Structured logging everywhere with correlation IDs (job ID, device ID).
- Tests: unit tests for agent collectors (per OS, with fakes), server domain and authorization tests, integration tests against PostgreSQL in containers, end-to-end test that enrolls a containerised Linux agent and runs a script. Windows and macOS agent tests run on CI runners of those OSes.
- Every API endpoint has an authorization test, including a cross-tenant negative test.
- Database migrations are versioned and reversible where practical.
- UI: clean, fast, works at laptop and tablet widths, dark and light themes, accessible (keyboard navigation, labels, contrast).

---

## 10. Working rules for you (Claude Code)

1. **Start** by saving this brief as `docs/SPEC.md`, then write `docs/PLAN.md`: a checklist of every phase broken into tasks of a few hours each. Also create `CLAUDE.md` with the conventions you decide (naming, folder rules, how to run tests).
2. **Work one phase at a time.** At the end of each phase: run all tests and builds, update `docs/PLAN.md` and `CHANGELOG.md`, make a git commit, then **stop** and give me a short summary: what works, how I can test it on my machines, known limitations, and what the next phase involves. Wait for my go-ahead before starting the next phase.
3. **Ask before** anything that costs money, needs real certificates, keys or cloud accounts, deletes data, or changes the security design in sections 6 and 8. Use clearly marked placeholders and dev-only keys until I provide real ones.
4. **Never** commit secrets, real customer data or signing keys.
5. Prefer well-maintained libraries over hand-written code for crypto, TLS, PTYs and installers. Never implement your own cryptography.
6. If something in this brief is wrong, unsafe or unclear, say so and propose an alternative instead of guessing.
7. Keep the build green. Do not leave a phase with failing tests or broken CI.
8. When you add any feature that runs code or opens a session on a device, add its audit logging and authorization checks in the same change, not later.

## 11. My environment (for testing instructions)

- Development machine: macOS on Apple Silicon.
- Test devices: I will provide a Windows 11 VM, a Linux VM or container, and one or more Macs.
- Cloud: Microsoft Azure.
- Apple Developer account available for macOS signing and notarisation; I will add the credentials when we reach that step.
