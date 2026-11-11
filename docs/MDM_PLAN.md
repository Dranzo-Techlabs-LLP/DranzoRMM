# MDM plan (Phase 9: design only)

Status: **design, nothing implemented.** `docs/SPEC.md` lists Apple MDM, Windows MDM and
mobile as non-goals for now and asks for this plan plus a data model that can absorb them.
Vendor requirements below are from the author's knowledge of Apple's and Microsoft's MDM
protocols as of 2026; **verify fees, programme terms and protocol details against current
vendor documentation before committing to dates or prices.**

## 1. Why MDM at all

The agent is a root service that the OS treats like any other program. Some things an RMM is
expected to do are reserved by the OS vendors for an MDM server:

| Need (from `docs/SPEC.md`) | Why the agent cannot do it | MDM mechanism |
|---|---|---|
| Grant the agent Screen Recording, Accessibility, Full Disk Access on macOS (Phase 6) | TCC permissions need the user's click, per Mac | PPPC configuration profile |
| Enforce FileVault and escrow the recovery key (Phase 7) | Enabling needs a user secure token and interaction | FileVault payload + escrow, bootstrap token |
| Install macOS updates on Apple Silicon without the user's password (Phase 4) | `softwareupdate` needs volume-owner authorisation | Declarative software-update management, bootstrap token |
| Zero-touch setup of a new Mac or PC | Someone has to run the installer | Automated Device Enrollment / Windows Autopilot |
| Remote lock and wipe (stolen device, `docs/RUNBOOK.md` 8.2) | Not safely doable from a user-space agent | `DeviceLock`, `EraseDevice`; RemoteWipe CSP |
| Suppress "Background Items Added" prompts, pre-approve system extensions | User-controlled | Service-management and system-extension payloads |
| Windows policy with tamper resistance (BitLocker, Defender, update rings, USB) | Registry/GPO edits by the agent are overwritable and unsupported | Policy CSP, BitLocker CSP, Defender CSP, Update CSP |
| iOS / Android | No agent model exists | MDM is the only management channel |

MDM **complements** the agent; it does not replace it. Scripts, software deployment, live
inventory, terminal and patch orchestration stay with the agent. MDM delivers the things only
the OS will do, and installs the agent itself.

## 2. Apple (macOS first, iOS/iPadOS later)

### 2.1 Accounts, certificates and what they cost

| Item | Who owns it | Purpose | Cost / renewal |
|---|---|---|---|
| **APNs MDM push certificate** | **Each client organisation** (created with a Managed Apple Account of that organisation at Apple's push certificates portal) | Lets our server wake that organisation's devices. The certificate's topic identifies the MDM relationship. | Free. **Expires yearly; must be renewed with the same Apple Account**, otherwise every device has to be re-enrolled. Operationally the biggest risk in Apple MDM. |
| **MDM vendor (CSR-signing) certificate** | DranzoRMM (the vendor) | Signs each customer's push-certificate request so Apple accepts it. | Requires an Apple Developer **Enterprise**-class entitlement for MDM vendors; Apple grants it on application. Alternative: use an existing vendor's signing service. **Needs the owner's decision and an application to Apple.** |
| **Apple Business Manager (ABM)** (or School Manager) | Each client organisation | Automated Device Enrollment (ADE), device assignment to our MDM server, Managed Apple Accounts, Apps and Books licences. | Free; the organisation must be verified by Apple (D-U-N-S number). Only devices bought through Apple or an authorised reseller appear automatically; others can be added with Apple Configurator. |
| ADE server token (`.p7m`) per organisation | Uploaded to us from ABM | Lets our server read the organisation's device list and assign enrollment profiles. | Free. **Expires yearly.** |
| Apps and Books (VPP) content token per organisation | Uploaded to us from ABM | Licence and install App Store apps without Apple IDs. | Free. Expires yearly. |
| Apple Developer Program | DranzoRMM | Developer ID signing and notarisation of the agent (already needed, Phase 0). | Annual fee. |
| TLS certificate for the MDM endpoints | DranzoRMM | Devices require a publicly trusted (or profile-trusted) HTTPS endpoint. | Standard. |

Consequence for tenancy: the Apple relationship is **per organisation**, not per partner. Each
client has its own push certificate, ABM tokens and renewal dates. The partner (IT company)
operates them on the client's behalf but must not hold them in the partner's own Apple account,
or a client could never leave with its devices.

### 2.2 Protocol pieces to build

1. **Enrollment**
   - *ADE (zero-touch):* device contacts Apple at Setup Assistant, is told our MDM URL, fetches
     the enrollment profile from us. Supervised, non-removable if we say so.
   - *Profile-based (existing Macs):* user or the DranzoRMM agent opens an enrollment profile;
     the user approves it in System Settings. On macOS this is "user-approved MDM"; some
     payloads (PPPC for Screen Recording) additionally need supervision or explicit user
     consent regardless.
   - *Account-driven enrollment* for BYOD (later).
   - Device identity certificate: issued via **SCEP or ACME** (with managed device attestation
     on supported hardware). We would run a **separate MDM device CA**, not the agent CA: a
     different trust domain with different rules, and the agent CA must stay minimal.
2. **Check-in and command channel**: `Authenticate`, `TokenUpdate`, `CheckOut`; APNs push to
   wake the device; the device polls `/mdm/command`, we return queued commands, it reports
   results. All over HTTPS with the device identity certificate (mTLS or signed messages).
3. **Declarative Device Management (DDM)**: required for current software-update management
   and status reporting on recent OS versions. Declarations (configurations, assets,
   activations) and a status channel. New work should target DDM first, classic commands where
   DDM has no equivalent.
4. **Configuration profiles** we need on day one:
   - **PPPC (Privacy Preferences Policy Control)** for the agent and the MeshCentral agent,
     identified by bundle ID / path and **code requirement** (so it only applies to our signed
     binary): Full Disk Access (`SystemPolicyAllFiles`) and Accessibility can be *allowed*;
     **Screen Recording (`ScreenCapture`) can only be set to "allow a standard user to
     approve"** on macOS: MDM cannot silently grant it. The transparency rule in
     `docs/SPEC.md` section 1 agrees with Apple here.
   - **Service management / login items**: mark our LaunchDaemon as managed so users cannot
     disable it in Login Items (optional per organisation; a transparency decision: it must
     remain visible, and removal stays possible for the organisation's administrators).
   - **FileVault**: enforce at next login, **escrow the personal recovery key** to us encrypted
     to a certificate we provide; rotate after use.
   - **Software update** declarations (deferrals, deadlines, forced install).
   - Passcode / screen lock, firewall, system extensions, certificate payloads.
5. **Bootstrap token**: the Mac escrows it to the MDM at enrollment; needed so MDM-initiated
   software updates and FileVault operations work on Apple Silicon without a user's password.
   Must be stored like a credential.
6. **Commands**: `InstallEnterpriseApplication` / `InstallApplication` (installs our signed
   `.pkg`: this is how the agent gets onto ADE Macs), `DeviceLock`, `EraseDevice`,
   `DeviceInformation`, `SecurityInfo`, `InstalledApplicationList`, `RestartDevice`,
   `RotateFileVaultKey`, `SetRecoveryLock`, Activation Lock bypass code retrieval.
7. **Mobile (iOS/iPadOS)**: same protocol, different payload set; supervision via ADE; Managed
   App configuration; Lost Mode. No agent. Android would be a separate integration (Android
   Management API through a Google-approved EMM registration: its own application process).

### 2.3 Build or integrate?

Writing an Apple MDM server is a multi-month effort with ongoing protocol churn every OS
release. Realistic options, to be decided by the owner:

| Option | Effort | Notes |
|---|---|---|
| Embed an open-source MDM core (for example NanoMDM / micromdm-family components, MIT/Apache) behind our API | Medium | Go services; we keep tenancy, RBAC, audit and UI. Licence check required, same rule as MeshCentral (`docs/SPEC.md` section 3: no AGPL). |
| Implement the protocol in the ASP.NET server | High | Full control, one process; most protocol risk. |
| Integrate with the client's existing MDM (Intune, Jamf, Kandji, ...) via their APIs | Low to medium per vendor | We only *consume* compliance and deliver the agent and PPPC profile through theirs. Fastest path to solving Phase 6's permission problem. |

Recommended sequence: (1) ship PPPC and agent-install **artifacts** (a signed
`.mobileconfig` and the notarised `.pkg`) that any existing MDM can deploy: no server work, and
it removes the Phase 6 blocker; (2) integrate read-only with Intune/Jamf for clients that have
them; (3) only then decide on our own Apple MDM server.

## 3. Windows

### 3.1 Protocol

Windows MDM is **OMA-DM (SyncML over HTTPS)** with a Microsoft enrollment protocol (MS-MDE2)
in front. Three services to host:

| Service | Role |
|---|---|
| **Discovery** (`/EnrollmentServer/Discovery.svc`, found via `enterpriseenrollment.<domain>` DNS or given explicitly) | Tells the device where to authenticate and enrol. |
| **Enrollment policy + enrollment (certificate) service** (MS-XCEP / WS-Trust) | Authenticates the user or device (federated/Entra token, on-premises credentials or a provisioning token), issues the **MDM device identity certificate** and returns the provisioning document (management server URL, polling schedule). |
| **Management service** (OMA-DM endpoint) | SyncML sessions: we send `Get/Add/Replace/Exec/Delete` against **Configuration Service Providers (CSPs)**, the device answers. Sessions start on schedule or when we send a push through **WNS**. |

### 3.2 CSPs we would use

| Goal | CSP |
|---|---|
| Baseline policy (password, lock, USB storage, Defender, firewall, update rings) | Policy CSP (incl. ADMX-backed policies), Firewall CSP, Defender CSP, Update CSP |
| Disk encryption with recovery-key escrow | BitLocker CSP (escrow to Entra ID by default; to us only on non-Entra devices with extra work) |
| Install the agent MSI | EnterpriseDesktopAppManagement CSP (per-device MSI, with our `SERVERURL`/`ENROLLTOKEN` properties in the command line) |
| Lock / wipe / reboot | RemoteLock (limited on desktop), RemoteWipe CSP, Reboot CSP |
| Certificates, Wi-Fi, VPN | ClientCertificateInstall, RootCATrustedCertificates, WiFi, VPNv2 CSPs |
| Inventory / health | DevDetail, DevInfo, DeviceStatus, HealthAttestation CSPs |
| Local admins | Policy CSP `LocalUsersAndGroups`, LAPS CSP |

### 3.3 Entra ID and coexistence: the real constraint

- A Windows device can be enrolled in **one MDM at a time**. Most clients with Microsoft 365
  Business Premium already have **Intune** and Entra join with automatic MDM enrollment.
  Displacing Intune is rarely acceptable and breaks Conditional Access, which only trusts the
  compliance state reported by the MDM registered with Entra ID.
- Becoming an Entra-integrated third-party MDM (so Entra-joined devices auto-enrol with us and
  Conditional Access accepts our compliance signal) requires registering as an MDM application
  in each tenant and implementing the compliance-partner integration: a Microsoft partner
  process, not just code.
- Without Entra integration we can only offer manual enrollment ("Access work or school →
  Enroll only in device management") or provisioning packages, with a user or bulk token.
- **Autopilot** zero-touch requires Intune (or another Autopilot-integrated MDM) and devices
  registered by hardware hash through the reseller or the client.
- Windows Home has no MDM enrollment; Windows Server is not manageable by MDM.

**Recommendation:** do not build a Windows MDM server first. For Windows, (1) integrate with
**Microsoft Graph / Intune** per client tenant (read compliance and BitLocker escrow state,
deploy our MSI as a line-of-business app, optionally push policies), using an app registration
per tenant with admin consent and least-privilege Graph scopes; (2) keep enforcing what the
agent can enforce (Phase 7 policies) on devices without Intune; (3) revisit a native OMA-DM
server only if a material share of clients has no Intune licence.

Costs: Intune licences are the client's (included in several Microsoft 365 plans); Graph API
use is free; WNS push needs a registered app (free); a native MDM needs a public TLS endpoint
and, for Entra integration, Microsoft partner onboarding.

## 4. Mapping onto the existing data model

Source: `server/src/Dranzo.Domain/Entities.cs`, `Tenancy.cs`. The tenant hierarchy and the
tenancy interfaces (`IPartnerOwned`, `IOrgOwned`, `IDeviceOwned`, ...) stay as they are; MDM
adds a second *management channel* to a device, not a second kind of device.

### 4.1 Reused as is

| Existing entity | Role with MDM |
|---|---|
| `Partner`, `Organization`, `Site`, `DeviceGroup` | Unchanged. MDM credentials hang off `Organization` (section 2.1). |
| `Device` | **One row per physical device regardless of channel.** `Serial` (already present) is the join key with ABM/Autopilot records; `Os` gains the values `ios`, `ipados`, `android` (it is a string). Agent-specific columns (`CertThumbprint`, `AgentVersion`, `Capabilities`, `IsOnline`) become meaningful only when the agent channel exists; an MDM-only device (a phone) has them empty. |
| `User`, `Role`, `RoleAssignment`, `ApiKey` | Unchanged; new permission strings only (4.3). |
| `Policy`, `PolicyAssignment`, `ComplianceResult` | Reused. `Policy.Check` gets new built-in ids (`mdm.profile`, `mdm.filevault`, `mdm.bitlocker`, ...) with `ParamsJson` naming the profile; assignment by scope and per-device compliance rows work unchanged, so the compliance dashboard covers both channels. |
| `Package`, `Blob`, `BlobGrant` | The agent `.pkg`/`.msi` and other installers are served to MDM-managed devices from the same store (with a manifest for `InstallEnterpriseApplication`). |
| `PatchCatalogEntry`, `DevicePatchState`, `PatchPolicy` | Reused; `Source` gains `ddm` (Apple declarative updates) and `wufb` (Windows Update for Business via CSP). |
| `PostureSnapshot` | MDM `SecurityInfo` / HealthAttestation results feed the same snapshot (FileVault/BitLocker state, firewall, SIP, secure boot). |
| `Alert`, `AlertRule`, `NotificationChannel` | Reused; new rule types (push certificate expiring, token expiring, device unenrolled from MDM). |
| `AuditEvent` | Every MDM command, profile change, escrow-key reveal and certificate renewal is audited with the same chain. |
| `Job` / `JobRun` | **Not reused for MDM commands** (see below), but an MDM action started from the dashboard still appears in the same activity view. |
| `EnrollmentToken` | Agent enrollment only. Stays separate from MDM enrollment (different protocol, different secret lifetime). The MDM can *deliver* an agent enrollment token inside the agent install command. |
| `RemoteSession` | Unchanged; MDM only removes the permission prompts. |

Why not `Job`/`JobRun` for MDM commands: jobs are **signed with the command-signing key and
verified by our agent**. MDM commands are authenticated by the MDM protocol and executed by
the OS. Putting both in one table would blur a security boundary (what was signed, what was
verified by whom) that `docs/THREAT_MODEL.md` depends on. They get their own queue.

### 4.2 New entities

| New entity | Tenancy interface | Key fields | Notes |
|---|---|---|---|
| `MdmTenantConfig` | `IOrgOwned` (one per organisation and platform) | `Platform` (`apple`/`windows`), `Enabled`, server URLs, `Mode` (`native` / `intune` / `jamf`), external tenant id | The per-organisation switch. |
| `ApplePushCertificate` | `IOrgOwned` | `Topic`, `NotAfter`, `AppleAccountHint`, certificate + **private key reference** | Private key lives in the key store (`IKeyStore`), **never in the database**; the row stores the key-store entry name. Alert 60/30/7 days before `NotAfter`. |
| `AppleServerToken` | `IOrgOwned` | `Kind` (`ade`/`vpp`), `NotAfter`, `OrgName`, token reference | Same storage rule. |
| `MdmEnrollment` | `IDeviceOwned` | `DeviceId`, `Platform`, `Udid`/`EnrollmentId`/`HardwareHash`, `Kind` (`ade`/`user_approved`/`account_driven`/`autopilot`/`manual`), `Supervised`, `IdentityCertThumbprint`, `IdentityCertNotAfter`, `PushToken`/`PushMagic`/`UnlockToken` references, `Status`, `EnrolledAt`, `LastCheckInAt`, `UnenrolledAt` | The MDM channel of a `Device`. One device can have an agent identity (`Device.CertThumbprint`) **and** an `MdmEnrollment`; either can exist alone. Push tokens and unlock tokens are secrets. |
| `MdmProfile` | `IOrgOptionalShared` | `Name`, `Platform`, `PayloadType`, `Content` (mobileconfig / DDM declaration / SyncML), `Version`, `Sha256` | Partner library item, shareable across organisations like `Script`. Signed with a profile-signing certificate when delivered. |
| `MdmProfileAssignment` | `IPartnerOwned` | `ProfileId`, `ScopeType`, `ScopeId` | Same shape as `PolicyAssignment` (reuses `ScopeType`). |
| `MdmProfileState` | `IDeviceOwned` | `ProfileId`, `Version`, `Status` (`pending`/`installed`/`failed`/`removed`), `Error`, `UpdatedAt` | Feeds `ComplianceResult`. |
| `MdmCommand` | `IDeviceOwned` | `CommandUuid`, `RequestType`, `PayloadJson`, `Status` (`queued`/`sent`/`acknowledged`/`error`/`not_now`/`expired`), `RequestedByUserId`, timestamps, `ResultJson` | The MDM command queue and history. |
| `EscrowedSecret` | `IDeviceOwned` | `Kind` (`filevault_prk`/`bitlocker_recovery`/`bootstrap_token`/`activation_lock_bypass`/`recovery_lock`), `CiphertextRef`, `RotatedAt`, `LastRevealedAt`, `LastRevealedByUserId` | Envelope-encrypted with a key-store key; plaintext never in the database. Revealing one is step-up protected, audited and triggers rotation. |
| `AdeDeviceRecord` | `IOrgOwned` | `Serial`, `Model`, `AssignedProfile`, `AssignedAt`, `DeviceId?` | Devices known from ABM (or Autopilot) before they ever enrol; lets us pre-assign site/group. Becomes linked to a `Device` at first check-in by serial. |
| `ExternalMdmLink` | `IDeviceOwned` | `Provider` (`intune`/`jamf`/...), `ExternalDeviceId`, `ComplianceState`, `LastSyncAt` | For the "integrate with the client's MDM" mode: we mirror state, we do not own the enrollment. |

All new entities implement an existing tenancy interface, so the global query filters in
`DranzoDbContext` and the cross-tenant tests cover them without new mechanisms
(`CLAUDE.md`: every entity must implement a tenancy interface or be listed as global).

### 4.3 Permissions and step-up

New permission strings following the existing pattern in `Tenancy.cs`:

| Permission | Covers | Step-up | API keys |
|---|---|---|---|
| `mdm.read` | Enrollment state, profiles, command history | no | allowed |
| `mdm.manage` | Create/assign profiles, queue non-destructive commands | no | allowed |
| `mdm.configure` | Upload push certificates and Apple tokens, enable MDM for an organisation | yes | interactive only |
| `mdm.lockwipe` | `DeviceLock`, `EraseDevice`, RemoteWipe | **always** | interactive only |
| `mdm.secrets.reveal` | Show a FileVault / BitLocker recovery key | **always**, plus audit and automatic rotation | interactive only |

Erase and lock are the most destructive actions the platform would have; they should require
step-up for a single device, not only in bulk, and are candidates for two-person approval.

### 4.4 Listener and trust separation

A third listener (or a separate small service) for MDM endpoints, following the existing rule
that every route belongs to exactly one listener (`docs/ARCHITECTURE.md` section 1):

- Public TLS certificate (devices do not pin our private CA).
- Authenticates devices with the **MDM identity certificate** from a dedicated MDM CA, never
  with the agent certificate; an agent certificate must not be usable on MDM endpoints and vice
  versa.
- No signed-command envelope: the MDM protocols define their own integrity. This is exactly
  why the MDM service must not be able to reach the command-signing key.

### 4.5 New secrets (threat-model impact)

Adding MDM adds high-value secrets per client organisation: APNs private keys, ADE/VPP tokens,
bootstrap tokens, unlock tokens, recovery keys, the MDM CA key and a profile-signing key.
A compromise of the MDM service means remote **wipe** of every enrolled device and access to
every escrowed disk-encryption key. `docs/THREAT_MODEL.md` needs a new component section
before any of this is built, and the escrow store needs its own key hierarchy and access log.

## 5. Suggested order, when Phase 9 is opened

| Step | Deliverable | Depends on |
|---|---|---|
| 0 | Signed PPPC `.mobileconfig` + deployment guide for Jamf / Intune / Kandji / Mosyle; MSI deployment guide for Intune | Developer ID signing working (Phase 0), final bundle identifiers and code requirement |
| 1 | `ExternalMdmLink`: read-only Intune (Graph) and Jamf integration; compliance mirrored into `ComplianceResult` | Per-tenant app registration and consent |
| 2 | Decision: native Apple MDM (embed an open-source core vs. build) and the MDM-vendor application to Apple | Owner sign-off, cost review |
| 3 | Apple MDM for macOS: enrollment (profile + ADE), PPPC, agent install, FileVault escrow, DDM software updates, lock/erase | Step 2, new threat-model section, escrow key hierarchy |
| 4 | iOS/iPadOS | Step 3 |
| 5 | Windows: Intune write operations (deploy apps/policies); native OMA-DM only if justified | Step 1 |
| 6 | Android (Android Management API) | Separate Google EMM registration |

## 6. Open questions for the owner

1. Do clients already have Intune / an Apple MDM? If most do, steps 0 and 1 may be all that is
   ever needed.
2. Is DranzoRMM willing to become an Apple MDM vendor (application to Apple, yearly
   certificate operations per client, on-call for expiring push certificates)?
3. Who holds each client's Apple Business Manager and push-certificate Apple Account: the
   client (recommended) or the partner?
4. Recovery-key escrow makes the platform a custodian of disk-encryption keys for every
   client. Is that liability acceptable, or should keys stay in Entra ID / the client's MDM?
5. BYOD: are personally owned devices in scope? That changes enrollment type, what may be
   collected, and the privacy notice.
