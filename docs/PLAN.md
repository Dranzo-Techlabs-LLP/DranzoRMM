# DranzoRMM plan

Legend: `[x]` done and tested here · `[~]` implemented, **not fully verified in this environment** (reason given) · `[ ]` not done.

Verification environment: macOS (Apple Silicon) dev machine, local PostgreSQL 16, Docker via Colima (Linux arm64 containers). **No Windows machine, no Azure subscription, no signing certificates, no root on the Mac.** Anything that needs those is marked `[~]` and listed under "Needs your environment".

## Open questions for the owner

1. **Ed25519 in Key Vault.** The brief says the command-signing key is "an Ed25519 key held in Key Vault". Azure Key Vault *keys* support RSA and NIST EC curves only, not Ed25519. Implemented: Ed25519 as specified, private key stored as a Key Vault **secret** (loaded into server memory). Alternative: ECDSA P-256 with a non-exportable Key Vault key (changes brief §6; needs your sign-off).
2. **CA depth.** One private CA issues device and gateway certificates. An offline root + online issuing CA is recommended before production.
3. **Agent port 443 on Azure.** Container Apps cannot expose a second listener on 443 (ARCHITECTURE §10). Pick: port 8443 for agents, a separate app/environment, or a TCP load balancer in front.
4. **MeshCentral isolation.** Remote desktop currently uses one MeshCentral account per organization. A per-session, per-device MeshCentral user (via its API) would close the residual risk in THREAT_MODEL; it needs a MeshCentral admin API key.
5. **macOS minimum.** Go 1.27 binaries need macOS 13; the brief says 12. Building the agent with an older Go would restore 12.
6. **Run-everything-phase instruction.** The brief says stop after each phase; you asked for all phases in one go. Phases were built in order with a commit each, without pausing.

## Phase 0: Foundation

- [x] Repo scaffold (`agent/`, `server/`, `web/`, `installers/`, `deploy/`, `docs/`, `scripts/`)
- [x] `docs/SPEC.md`, `ARCHITECTURE.md`, `PROTOCOL.md`, `THREAT_MODEL.md`, `PLAN.md`, `RUNBOOK.md`, `CLAUDE.md`
- [x] Lint/format: Go (`gofmt`, `golangci-lint`), C# (analyzers, warnings as errors), TypeScript (ESLint, Prettier)
- [x] Docker Compose dev environment (PostgreSQL, **Azurite** instead of MinIO, server, web, MeshCentral profile, Linux test agent profile). `scripts/e2e.py` passes against it with the Linux agent container.
- [~] CI workflow written (`.github/workflows/ci.yml`, SHA-pinned actions). **Never run**: no GitHub remote. All steps it calls were run locally except Windows/macOS runners, signing and actionlint.
- [~] gitleaks config + pre-commit, Dependabot, `.env.example` written; gitleaks itself not run locally.

## Phase 1: Identity, tenants, enrollment

- [x] Data model + EF Core migrations, central tenant query filters (test: every entity filtered or explicitly global)
- [x] Login: password policy, lockout, mandatory TOTP, recovery codes, sessions (idle/absolute timeout), CSRF, step-up, forced temporary-password change
- [ ] Passkeys / WebAuthn as an optional second factor — **not done** (brief marks it optional; TOTP is mandatory and implemented)
- [x] RBAC: built-in roles, custom roles, assignments scoped to partner / organization / site / group; scope resolved per permission
- [x] Organizations, sites, groups CRUD; users and roles admin (unlock, reset password, reset MFA)
- [x] Private CA, enrollment tokens, CSR enrollment, mTLS gateway, certificate renewal and revocation (real TLS in tests; verified with the real Go agent)
- [~] Agent: service install, enroll, mTLS, reconnect/backoff, heartbeat, inventory. **Run for real:** macOS (foreground, non-root) and Linux (Debian 12 / Rocky 9, incl. systemd install/uninstall) against the real server. **Windows: compiled only.** macOS launchd install not run (no root).
- [x] Hash-chained append-only audit log (DB triggers), export, on-demand + daily verification
- [x] Dashboard: login/MFA, tenants, devices list/detail (live status), enrollment, users/roles, audit (browser-verified against the real server)
- [x] Tests: auth, tenant isolation generated over every endpoint, gateway mTLS, audit chain
- [~] Installers: deb/rpm built and installed in containers (GPG signing tested with a throwaway key); macOS pkg built unsigned, not installed; **MSI sources not built** (needs Windows)

## Phase 2: Remote scripts

- [x] Script library with immutable versions, typed parameters
- [x] Run on devices / group / site / organization / saved filter; cron schedules in the organization time zone
- [~] Run as system or logged-in user; timeouts; cancellation; concurrency limits. Run-as-user verified on Linux (runuser + direct credentials); macOS `launchctl asuser` and Windows user token not run.
- [x] Signed dispatch (Ed25519, nonce, expiry), agent-side verification and replay protection; C#→Go interop vectors
- [x] Live output streaming, history per device, output cap with truncation flag (server enforces the cap too)
- [x] Step-up for >10 devices or a whole organization
- [~] Windows signed-PowerShell-only mode (`-ExecutionPolicy AllSigned`, per-organization switch): compiled only
- [x] Dashboard: script editor, run dialog, live output, job/run history, schedules (browser-verified with a real agent)

## Phase 3: Software inventory and deployment

- [~] Agent collectors: Linux dpkg/rpm and macOS apps/pkgutil/Homebrew run for real; snap/flatpak and all Windows collectors fixture-tested only
- [~] Package-manager install/uninstall: apt and dnf run for real (`tree`); Homebrew-as-console-user and winget compiled/fixture-tested only
- [~] Custom package upload, SHA-256 verification on the agent, detection rules: real `.deb`/`.rpm` installs in containers; msi/exe/pkg/dmg compiled and fake-tested only
- [x] Deployment jobs with per-device status and retries
- [x] Dashboard: software inventory, deploy/uninstall, package library (browser-verified; deploys not executed on the dev Mac)

## Phase 4: Patch management

- [~] Agent patching: apt and dnf scan + install run for real; macOS `softwareupdate --list` and `brew outdated` run for real; WUA COM (PowerShell, no third-party modules), winget and macOS installs compiled only
- [x] Patch catalog (per organization), per-device state, approvals; policies (auto-approve, maintenance window, deferral)
- [~] Reboot policy (notify, deferrals, deadline): logic tested with fake UI and fake rebooter; no real reboot performed
- [x] Compliance view; documented limits (Apple Silicon volume-owner authorisation, winget for SYSTEM)

## Phase 5: Security posture, monitoring, alerts

- [~] Agent posture collectors: Linux and macOS run for real (non-root on macOS); Windows (Security Center/Defender, BitLocker, NetFirewall) compiled and fixture-tested only
- [~] Vulnerability matching (NVD + CISA KEV): import and matching tested with sample feed data; live feed download not run (`Dranzo:Feeds:Enabled` off by default). Heuristic; application software only
- [~] Alert rules and evaluation; webhook, Teams and Slack payloads delivered to a local receiver in tests; email (SMTP) not sent (no SMTP server)
- [x] Dashboard: security posture, vulnerabilities, alerts, channels; remote terminal, files and desktop hand-off; policies and compliance; reports; releases; API keys; client portal (browser-verified against the real server and agent)

## Phase 6: Remote support

- [~] Sessions with consent modes and visible indicator; records and audit. Server and agent logic tested; the on-screen prompt/indicator was **not** seen on a real desktop (needs root on macOS, a Linux desktop, or Windows)
- [~] Remote terminal: real PTY on macOS and Linux with signed, sequence-checked input; ConPTY compiled only
- [x] File browser (list, upload, download, size limits), incl. end-to-end through the real server
- [~] Remote desktop via MeshCentral: login-token format and agent download ids verified against MeshCentral 1.1.44; MeshAgent install and a real desktop stream not run. **Residual risk** documented in THREAT_MODEL (per-organization MeshCentral account)
- [x] macOS permission documentation (RUNBOOK §11.1, MDM_PLAN)

## Phase 7: Policies and compliance

- [~] Built-in checks + script checks, remediation, assignments: Linux remediation run for real (sudo/wheel removal, ufw enable); macOS/Windows remediations fake-tested only
- [x] Compliance data and drift alerts (server); dashboard page: see below
- [ ] Tray / menu-bar helper — **not done** (optional). The session indicator uses OS dialogs instead.

## Phase 8: Agent self-update, reports, API

- [x] Signed releases, rollout rings, agent update with rollback: real update through the real server in a Linux container (`scripts/e2e.py --update-binary`), rollback verified under systemd. Windows/launchd restart paths compiled only
- [x] Reports (CSV, PDF)
- [x] Client portal role (server-enforced read-only, organization-scoped)
- [x] Public API keys with scopes and rate limits; outbound webhooks

## Phase 9: MDM (design only)

- [x] `docs/MDM_PLAN.md`

## Phase 10: Network and firewall

Requested after the first LAN tests: individual system security and firewall, separate guest and office Wi-Fi (UniFi), central device and network access management, central network administration. Approved plan: firewall rule policies, device isolation, security score, network discovery, approval list, Network Admin role, access review, UniFi integration, 802.1X/RADIUS.

- [x] 10a Permissions `network.read`, `network.manage`, `network.configure` (interactive only), `devices.isolate`; built-in role **Network Admin**; access review page and report (users, API keys, roles, scopes, effective permissions, findings)
- [x] 10b Security score 0-100 with grade and per-part reasons (antivirus 20, firewall 15, encryption 15, updates 20, policies 15, vulnerabilities 15; unknown parts left out). Device Security tab card, score column, low-score filter and average on Security, score in the security-posture report
- [x] 10c Network discovery (`network.scan`: neighbor table after a TCP wake-up sweep of the device's private /22-or-smaller subnets; live-tested on macOS, Windows/Linux fixture-tested) and device approval list (approve, block, forget, bulk; audited); managed devices matched by inventory MAC; inventory reports default gateway and Wi-Fi (SSID best effort); alert `network.unknown_device` (one summary on a site's first scan). Vendor names (IEEE OUI) not yet
- [x] 10d Firewall rule policies (`firewall.rules` check): rule editor, server + agent validation, Windows Firewall group / nftables table / pf anchor owned by DranzoRMM, reachability check with rollback, removal on uninstall. Live-tested: nftables in a Linux container. Windows and macOS pf: fixture-tested only (macOS needs root)
- [x] 10e Device isolation (`network.isolate` / `network.release`, `devices.isolate` + step-up, reason audited): only DranzoRMM, MeshCentral, DNS and DHCP stay reachable; reachability check with automatic release; state re-applied at agent start; on-screen notice; local `dranzo-agent release-isolation`; released on uninstall. Live-tested: nftables in a Linux container (allowed host reachable, others blocked, release restores). Windows Firewall and macOS pf: fixture-tested only
- [~] 10f UniFi integration: controllers (API key or local account, encrypted, optional certificate pin, connect-only-to-that-host client), overview of APs/switches/gateways with restart, separate office/guest Wi-Fi setup (VLAN, subnet, guest policies, client isolation), 5-minute client sync into discovered devices, `network.device_on_guest` alert, block/unblock on approval-list changes. **Tested against a simulated controller only; needs a real UniFi console**
- [~] 10g 802.1X / RADIUS (EAP-TLS): per-organization network CA (name-constrained to `*.dranzo-radius.invalid`, no IP addresses), device keys made on the device (Windows certreq machine store, Linux key file), certificates issued from CSRs, Wi-Fi profile install (Windows netsh EAP-TLS machine profile, Linux NetworkManager), public CRL, revocation on device revoke/delete/uninstall and network block, FreeRADIUS bundle (Docker) and UniFi switch to WPA2-Enterprise. **Verified:** real FreeRADIUS 3.2.7 + `eapol_test` (valid certificate accepted, revoked certificate refused, wrong secret refused, server name checked). **Not verified:** profile install on a real Windows/Linux Wi-Fi client and a real UniFi access point. macOS: not supported (needs a configuration profile)

## Security review

An independent review of the server found 8 confirmed issues (2 High, 4 Medium, 2 Low) plus several suspected ones. All are fixed with regression tests; details in `docs/THREAT_MODEL.md` (end).

## Field test 2026-11-19

A full end-to-end run against the production install (rmm.dranzo.com) with one Windows 11 and one macOS 26 device found issues that are now fixed (see CHANGELOG, "Fixes from the 2026-11-19 end-to-end test"): older agents marked non-compliant for checks they do not know, isolation/scan queued for agents that cannot run them, "install" silently upgrading installed software, duplicate macOS vulnerability findings, disk images listed as disks, file-session byte counts, frozen uptime and "Wired" shown without data. Rolling the fixes out found two more Windows bugs, also fixed: self-update failed with "Access is denied" (0.1.2), and multi-line PowerShell scripts fed on stdin never ran, so network scan, gateway, firewall rules and isolation did nothing on Windows (0.1.3). **Still open after that test:**
- `mesh.install` on macOS: MeshCentral serves the macOS MeshAgent binary without its settings (`.msh`), so the agent runs but never connects and no node id is reported. Worked around on the test Mac by writing `meshagent.msh` with a script and recording the node id by hand. Fix: fetch the group's `.msh` from MeshCentral (`/meshsettings`) and place it next to the binary before `-install`.
- The macOS consent prompt fix (notification before the dialog) is not yet verified with someone at the Mac.
- Isolation and firewall rules on Windows are now executed but not yet live-tested (isolation is disruptive).
- Email/chat alert channels were not configured; UniFi needs a controller.

## Needs your environment (cannot be verified here)

- **Windows:** every Windows code path (service, MSI, registry/WMI/WUA, winget, ConPTY, consent dialogs and indicator, BitLocker/Defender checks, signed-PowerShell mode). Build the MSI on Windows and run the walk-through in RUNBOOK §11.
- **macOS as root / under launchd:** service install, dialogs in the user's session, `installer -pkg`, dmg handling, `softwareupdate --install`, update restart via `launchctl kickstart`, TCC approvals for remote desktop.
- **Signing:** Authenticode, Developer ID + notarisation, production GPG key (secrets listed in RUNBOOK §9).
- **CI:** push to GitHub to run `.github/workflows/ci.yml` (never run).
- **Azure:** `az bicep build` / what-if and a real deployment (Bicep never compiled).
- **MeshCentral:** a real MeshAgent install and desktop session.
- **Email:** an SMTP server for email notifications.
- **UniFi:** a console and an API key to verify the integration (Phase 10f/10g).
- **Live feeds:** set `Dranzo:Feeds:Enabled=true` (and ideally an NVD API key) to download NVD/KEV.
