# DranzoRMM agent ↔ server protocol (v1)

Status: normative. The Go agent (`/agent`) and the server agent gateway (`/server/src/Dranzo.Api/Agents`) must both follow this document. Change the document first, then the code.

## 1. Transport and trust

| Item | Value |
|---|---|
| Listener | The server's **agent listener** (dev: `:8443`, production: `agents.<domain>:443`). Separate from the dashboard listener. |
| TLS | TLS 1.2 minimum, 1.3 preferred. The listener's server certificate is issued by the **DranzoRMM private CA**. |
| Server authentication | The agent trusts **only** the pinned DranzoRMM CA certificate(s) from its trust store. It never uses the OS trust store for the server. Hostname verification is on. |
| Agent authentication | Mutual TLS with the device client certificate (after enrollment). |
| Application protocol | HTTPS for enroll / renew / blob transfer; WebSocket (`/agent/v1/ws`, subprotocol `dranzo.agent.v1`) for everything else. |
| Encoding | UTF-8 JSON text frames. camelCase keys. Timestamps RFC 3339 UTC. IDs are lowercase UUID strings. Binary is standard base64. |

The agent only ever opens outbound connections, and only to the pinned server. Package and update binaries are fetched from the same listener (`/agent/v1/blobs/...`), so the agent needs no other trust anchors.

### 1.1 Agent trust store

Two trust anchors, both stored in the agent's protected data directory (root/SYSTEM only):

- `ca.pem`: the DranzoRMM CA certificate(s) used to verify the server.
- `trust.json`: `{"commandKeys":[{"kid":"<id>","alg":"ed25519","publicKey":"<base64 32 bytes>"}]}`: Ed25519 public keys that may sign commands.

They are compiled into the agent (`-ldflags -X`) and/or written by the installer at install time. At runtime they change **only** through a `trust.rotate` command signed by a currently trusted key, or by reinstalling the agent. Nothing received over an unsigned message may alter them.

### 1.2 Data directories

| OS | Directory | Protection |
|---|---|---|
| Windows | `C:\ProgramData\DranzoRMM\` | ACL: SYSTEM and Administrators full control, inheritance off |
| macOS | `/Library/Application Support/DranzoRMM/` | `root:wheel`, `0700`; key files `0600` |
| Linux | `/var/lib/dranzormm/` (state, keys), `/etc/dranzormm/` (bootstrap config) | `root:root`, `0700`; key files `0600` |

Files: `config.json` (server URL, device ID, intervals), `bootstrap.json` (server URL + enrollment token; the token is erased after enrollment), `device.key` (private key, PKCS#8 PEM), `device.crt`, `ca.pem`, `trust.json`, `nonces.json`, `agent.log` (rotated; never contains tokens, keys or script bodies).

## 2. Enrollment and certificates

### 2.1 Enroll: `POST /agent/v1/enroll` (no client certificate)

Request:

```json
{
  "token": "dz_enroll_...",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "hostname": "ACME-LT-042",
  "os": "windows",
  "arch": "amd64",
  "agentVersion": "0.1.0",
  "machineId": "stable OS machine id, max 128 chars"
}
```

- The agent generates an **ECDSA P-256** key pair locally. The private key never leaves the device.
- The CSR subject is ignored by the server. The server issues a certificate with `CN=<deviceId>`, SAN URI `urn:dranzo:device:<deviceId>`, EKU `clientAuth`, validity 90 days (configurable).
- `os` is one of `windows`, `macos`, `linux`; `arch` is `amd64` or `arm64`.

Response `200`:

```json
{
  "deviceId": "uuid",
  "certificate": "-----BEGIN CERTIFICATE-----...",
  "caCertificates": "-----BEGIN CERTIFICATE-----...",
  "notAfter": "2026-02-01T00:00:00Z"
}
```

Errors: `400` malformed, `401` token invalid/expired/revoked/used up (one generic message), `429` rate limited. The token is single-purpose; the agent deletes it from disk after success. Every enrollment always creates a new device record (an existing `machineId` is only flagged as a possible duplicate; it never takes over an existing identity).

### 2.2 Renew: `POST /agent/v1/renew` (mTLS)

Request `{"csr": "<PEM, new key pair>"}` → response same shape as enroll (same `deviceId`). The agent renews when less than one third of the lifetime remains, checks daily, and switches to the new certificate atomically (write new files, then rename). The server accepts the previous certificate until the first successful connection with the new one or until the old one expires.

### 2.3 Revocation

The gateway checks on every TLS handshake and every WebSocket upgrade that the presented certificate's SHA-256 thumbprint is the device's current (or still-valid previous) thumbprint and that the device is `Active`. Revoking a device clears both thumbprints and closes any open connection. A revoked agent receives HTTP `403` and stops reconnecting aggressively (backoff capped at 1 hour).

## 3. Connection lifecycle

1. Agent connects to `wss://<server>/agent/v1/ws` with its client certificate.
2. Agent sends `hello`. Server answers `hello.ack`. Anything else before `hello` closes the connection.
3. Agent sends `heartbeat` every `heartbeatSeconds` (default 60). Server answers `heartbeat.ack`. The server marks the device offline after 3 missed heartbeats (or immediately on socket close plus a 10 s grace).
4. On disconnect the agent reconnects with exponential backoff: base 1 s, factor 2, cap 5 min, full jitter. Backoff resets after a connection that lasted 60 s.
5. One connection per device. A new connection for the same device replaces (closes) the old one.

Limits enforced by the server (and mirrored by the agent):

| Limit | Default |
|---|---|
| Max WebSocket message from agent | 2 MiB |
| Max WebSocket message from server | 2 MiB |
| Agent messages per second | 50 (burst 200); excess closes the connection with code 1008 |
| `job.output` chunk | 16 KiB of text |
| Output per job run | 1 MiB (per-job configurable, hard max 16 MiB); then `truncated=true` |
| `software.inventory` items | 5,000 |

## 4. Envelope

Every message is one JSON object:

```json
{ "type": "heartbeat", "id": "uuid", "version": 1, "payload": { } }
```

- `type`: message type (section 6).
- `id`: unique per message. Replies that refer to a message put its id in `payload.refId` where stated.
- `version`: protocol version, currently `1`. A peer that receives a higher version than it supports replies `error` with code `unsupported_version` and closes.
- Unknown `type`: reply `error` (`unknown_type`), keep the connection.

### 4.1 Signed envelope (server → agent commands)

Command messages use a different shape. The payload is carried as bytes so that the signature never depends on JSON canonicalisation:

```json
{
  "type": "job.dispatch",
  "id": "uuid",
  "version": 1,
  "signedPayload": "<base64 of the UTF-8 JSON payload bytes>",
  "signature": "<base64 Ed25519 signature, 64 bytes>",
  "keyId": "<kid of the signing key>"
}
```

Signature input (bytes): `"DRANZO-CMD-V1\n"` + `type` + `"\n"` + decoded `signedPayload` bytes.

**Signed types** (the agent must reject these if they arrive unsigned): `job.dispatch`, `job.cancel`, `update.available`, `session.start`, `session.input`, `session.end`, `trust.rotate`.

Every signed payload contains these common fields:

```json
{ "deviceId": "uuid", "nonce": "<base64 16 random bytes>", "issuedAt": "...", "expiresAt": "..." }
```

Agent verification, in this order; any failure means the command is **refused** and nothing is executed:

1. `type` is a signed type and the envelope has `signedPayload`, `signature`, `keyId` (and no plain `payload`).
2. `keyId` is in `trust.json`; the Ed25519 signature verifies over the signature input.
3. Payload parses as JSON; `deviceId` equals this agent's device ID.
4. `issuedAt - 5 min ≤ now ≤ expiresAt`; `expiresAt - issuedAt ≤ 15 min`.
5. Replay: the `nonce` has not been seen. Accepted nonces are persisted to `nonces.json` until `expiresAt + 5 min` and survive restarts. (`session.input` instead uses `sessionId` + strictly increasing `seq`; see 6.6.)

On refusal the agent sends `error` with `code` one of `unsigned`, `unknown_key`, `bad_signature`, `wrong_device`, `expired`, `not_yet_valid`, `validity_too_long`, `replayed`, `malformed`, and `refId` = envelope id; for `job.dispatch` it additionally sends `job.ack` with `accepted=false` if `jobRunId` could be read from a payload whose signature verified. Refusals are logged locally and audited on the server.

The server signs at **send time** (not at job creation), so queued jobs for offline devices get a fresh nonce and a short expiry (default 5 min) when the device reconnects.

## 5. Agent → server message types

| Type | Payload |
|---|---|
| `hello` | `{agentVersion, protocolVersion, os, arch, hostname, capabilities: string[], trustKeyIds: string[]}` |
| `heartbeat` | `{seq, uptimeSeconds, cpuPercent, memUsedPercent, consoleUser?, pendingReboot, agentRssBytes}` |
| `inventory` | section 7.1 |
| `software.inventory` | section 7.2 |
| `posture` | section 7.3 |
| `patch.state` | section 7.4 |
| `job.ack` | `{jobRunId, accepted, reason?}` |
| `job.output` | `{jobRunId, seq, stream: "stdout"\|"stderr", data}` (`data` is UTF-8 text; invalid bytes replaced) |
| `job.result` | `{jobRunId, status, exitCode?, message?, truncated, outputBytes, outputSha256, startedAt, finishedAt, result?}` |
| `session.status` | `{sessionId, state: "pending_consent"\|"active"\|"denied"\|"ended"\|"failed", reason?}` |
| `session.output` | `{sessionId, seq, data}` (`data` base64 of terminal bytes) |
| `update.status` | `{version, state: "downloading"\|"verifying"\|"installed"\|"rolled_back"\|"failed", error?}` |
| `error` | `{code, message, refId?}` |

`job.result.status`: `succeeded` (exit code 0), `failed` (non-zero or error), `timeout`, `cancelled`, `rejected` (failed validation), `unsupported` (**"not supported on this OS"**; `message` says what).

`outputSha256` is the hex SHA-256 of the concatenated `data` of all delivered `job.output` chunks in `seq` order (UTF-8 bytes).

## 6. Server → agent message types

Unsigned (cannot cause any action beyond bookkeeping): `hello.ack`, `heartbeat.ack`, `error`.

| Type | Payload |
|---|---|
| `hello.ack` | `{serverTime, heartbeatSeconds, inventoryIntervalSeconds, softwareIntervalSeconds, postureIntervalSeconds, patchScanIntervalSeconds}`. The agent clamps each interval to a safe range (heartbeat 15–600 s; others 5 min–7 days). |
| `heartbeat.ack` | `{serverTime}` |

### 6.1 `job.dispatch` (signed)

```json
{
  "deviceId": "...", "nonce": "...", "issuedAt": "...", "expiresAt": "...",
  "jobRunId": "uuid",
  "kind": "script",
  "timeoutSeconds": 300,
  "maxOutputBytes": 1048576,
  "sessionId": null,
  "spec": { }
}
```

The agent replies `job.ack` at once, streams `job.output`, ends with exactly one `job.result`. The agent validates every `spec` field (types, lengths, enumerations, path and identifier patterns) before acting and never builds a shell command line from server-provided values: arguments are passed as an argv array.

Concurrency: the agent runs at most 4 jobs at a time (configurable); others are queued in memory (max 32; beyond that `job.ack accepted=false reason="busy"`).

### 6.2 Job kinds

| `kind` | `spec` | `result` (in `job.result.result`) |
|---|---|---|
| `script` | `{language: "powershell"\|"cmd"\|"bash"\|"zsh"\|"sh"\|"python", body, args: string[], env: {k:v}, runAs: "system"\|"user", requireSignedPowerShell: bool}` | none |
| `inventory.refresh` | `{}` → agent sends `inventory` | none |
| `software.scan` | `{}` → agent sends `software.inventory` | none |
| `software.install` / `software.uninstall` | `{manager: "winget"\|"brew"\|"apt"\|"dnf", packageId, version?}` | `{installed: bool, version?}` |
| `package.install` | `{blobId, sha256, sizeBytes, fileName, type: "msi"\|"exe"\|"pkg"\|"dmg"\|"deb"\|"rpm", installArgs: string[], detection?: Detection}` | `{installed: bool, version?}` |
| `package.uninstall` | `{type, uninstallCommand: string[], productCode?, detection?: Detection}` | `{installed: bool}` |
| `patch.scan` | `{}` → agent sends `patch.state` | none |
| `patch.install` | `{updateIds: string[] \| null (all approved), sources: string[], reboot: {mode: "never"\|"if_required"\|"force", notifyUser, deferrals, deadlineMinutes, message}}` | `{installed: [{id, ok, error?}], rebootRequired}` |
| `posture.scan` | `{}` → agent sends `posture` | none |
| `policy.evaluate` | `{checks: [{policyId, check: string, params: {}, remediate: bool}]}` | `{results: [{policyId, check, compliant, remediated, detail}]}` |
| `reboot` | `{delaySeconds, message, notifyUser}` | none |
| `file.list` | `{path}` (requires active `files` session: `sessionId`) | `{path, entries: [{name, isDir, sizeBytes, modifiedAt, mode}], truncated}` |
| `file.read` | `{path, uploadId, maxBytes}` → agent `PUT /agent/v1/uploads/{uploadId}` | `{sizeBytes, sha256}` |
| `file.write` | `{path, blobId, sha256, sizeBytes, overwrite}` | `{sizeBytes}` |
| `mesh.install` / `mesh.uninstall` | `{blobId, sha256, sizeBytes, fileName}` / `{}` | `{installed: bool, meshNodeId?}` |
| `agent.configure` | `{uninstallCode?: {salt: base64, iterations: int, hash: base64} \| null}` (PBKDF2-HMAC-SHA256 of the technician-set uninstall code; `null` clears it) | none |
| `agent.uninstall` | `{}` | none (agent acks, then removes itself) |
| `network.isolate` | `{allow: [{host, port}] (extra endpoints to keep, e.g. MeshCentral), message}` | `{allowed: string[] (resolved IPs)}` |
| `network.release` | `{message}` | none |
| `network.cert.request` | `{}` | `{csr}` (PEM PKCS#10; the key stays on the device) |
| `network.wifi.install` | `{ssid, caPem, certPem}` | `{installed: bool}` |
| `network.wifi.remove` | `{ssid}` | none |
| `network.scan` | `{resolveNames: bool}` | `{scannedAt, subnets: string[], gateway, neighbors: [{ip, mac, hostname?, gateway?, randomized?}], truncated}` |

`Detection`: `{type: "file"\|"registry"\|"pkgutil"\|"dpkg"\|"rpm"\|"winget"\|"brew"\|"app", key, valueName?, minVersion?}`.

Rules:

- `runAs: "user"` runs in the logged-in console user's session (Windows: user session token; macOS: `launchctl asuser`; Linux: `runuser`). If nobody is logged in: `failed`, `message: "no logged-in user"`.
- `brew` operations **always** run as the console user, never as root, whatever `runAs` says.
- `requireSignedPowerShell: true` (Windows): the script file is run with `-ExecutionPolicy AllSigned`; unsigned or untrusted scripts fail. On other OSes this flag yields `unsupported`.
- `package.install`: the agent downloads `GET /agent/v1/blobs/{blobId}` to a root-only temp directory, enforces `sizeBytes`, verifies `sha256` **before** executing anything, then installs silently by type. Hash mismatch ⇒ `rejected`.
- `packageId`, `version`, `updateIds` must match `^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,199}$`; anything else ⇒ `rejected`.
- `software.install` without `version` does not change software that is already installed: the agent first queries the package manager and, if the package is present, reports `succeeded` with `{installed: true, version}` and message `already installed; not changed` without running the install (winget and apt would otherwise upgrade it). Updates go through `patch.install`. If that query fails, the install runs as before and the output says so. With a `version` the install always runs.
- File jobs must carry the `sessionId` of an **active** `files` session, otherwise `rejected`.
- A kind the OS cannot do returns `unsupported` with a clear message.
- `network.isolate`: the agent cuts the device off the network except: loopback, DHCP, DNS (port 53), the DranzoRMM server (its host resolved now; IPs pinned for the isolation) and the `allow` endpoints. Windows: block rules in Windows Firewall group `DranzoRMM Isolation` whose remote addresses are every address except the allowed ones (block rules win over allow rules), plus the DNS servers and default gateway kept reachable for DHCP/DNS; Linux: nftables table `inet dranzormm_isolation` with `policy drop` chains; macOS: pf anchor `com.apple/251.DranzoRMMIsolation`. The agent then opens a new connection to the server; if that fails within 30 s it releases the isolation again and reports `failed`. The state is kept in the data directory and re-applied when the agent starts (nftables and pf rules do not survive a reboot). The person at the computer sees a notice. A local administrator can always run `dranzo-agent release-isolation`; uninstall also releases it.
- 802.1X (EAP-TLS, Phase 10g): `network.cert.request` creates a key on the device and returns a CSR (Windows: `certreq` in the machine store, ECDSA P-256, not exportable; Linux: P-256 key file, mode 0600, in the data directory). The server issues a client certificate from the organization's network CA (subject `CN=<deviceId>`, SAN `urn:dranzo:device:<id>`, clientAuth, 1 year) and sends `network.wifi.install`: Windows imports the CA into the machine root store (the CA is name-constrained to `*.dranzo-radius.invalid` and excludes every IP address, so it cannot vouch for websites), accepts the certificate and adds an EAP-TLS Wi-Fi profile that validates the RADIUS server `radius.dranzo-radius.invalid`; Linux adds a NetworkManager connection with its own CA file (no system trust change). macOS: `unsupported` (needs a configuration profile; see docs/MDM_PLAN.md). The CRL is public at `GET /pki/network/{organizationId}/crl.pem`.
- `network.scan`: the agent scans the IPv4 subnets of at most 2 active, non-loopback interfaces, each limited to the /22 (1024 addresses) around its own address. It wakes the neighbor cache with short TCP connects (ports 445, 80, 22; 300 ms timeout; at most 64 at a time; no raw sockets, no port scan report), then reads the OS neighbor table (Windows `Get-NetNeighbor`, macOS `arp -an`, Linux `/proc/net/arp`). Only entries inside the scanned subnets with a usable unicast MAC are reported, at most 1024 (`truncated` beyond). `randomized` marks a locally administered (private) MAC. Hostnames come from reverse DNS when `resolveNames` is true.

Built-in policy checks (`policy.evaluate.check`): `firewall.enabled`, `antivirus.enabled`, `screenlock.timeout` (`params.maxSeconds`), `localadmins.allowed` (`params.allowed: string[]`), `usb.storage.blocked` (Windows), `password.policy` (Windows; `params.minLength`, `maxAgeDays`, `complexity`), `diskencryption.enabled` (report only: `remediate` is ignored), `script` (`params.checkScript`, `params.remediationScript`, `params.language`: check is compliant on exit code 0).

A check the agent does not support on its OS answers with a `detail` starting `not supported on this OS`; an agent that does not know the check at all (older version) answers `detail: "unknown check"`. The server stores both as `supported: false` (not non-compliant, no drift alert), and shows "unknown check" as "not supported by this agent version (update the agent)".

Before queuing `network.isolate` or `network.scan` for one device, the server checks the capabilities the agent sent in `hello`; if `network.isolate` / `network.scan` is missing it answers `409` instead of queuing a job the agent cannot run (a refused isolation is audited as `device.isolate` with result `failure`). An agent that sent no capabilities at all is not refused.

`firewall.rules` (Phase 10): `params.rules: [{name, direction: "in"|"out", action: "allow"|"block", protocol: "tcp"|"udp"|"any", ports?: ["443", "8000-8100"], remoteAddresses?: [IP or CIDR], program?: "C:\\...\\app.exe" (Windows only)}]`, at most 100. The agent compares the rules it owns (Windows Firewall group `DranzoRMM`, rule names `DranzoRMM-<id>`; nftables table `inet dranzormm`, chains at priority -10, rule comments `dranzo:<id>`; pf anchor `com.apple/250.DranzoRMM`, labels `dranzo:<id>`) with the wanted set, where `<id>` is the first 16 hex digits of SHA-256 over the rule's normalized content. It never changes rules it does not own. Remediation replaces the owned set, then opens a new TCP connection to the server; if that fails within 30 s the previous rules are restored and the check reports failure. Rules that block all outgoing traffic are refused (use isolation). Program rules are skipped (and named in the detail) on macOS and Linux. Uninstall removes every owned rule.

### 6.3 `job.cancel` (signed)

`{deviceId, nonce, issuedAt, expiresAt, jobRunId}` → the agent kills the process tree and sends `job.result` with `cancelled`.

### 6.4 `update.available` (signed)

```json
{
  "deviceId": "...", "nonce": "...", "issuedAt": "...", "expiresAt": "...",
  "version": "0.2.0", "blobId": "uuid", "sha256": "hex", "sizeBytes": 12345678,
  "ring": "pilot", "force": false
}
```

The agent: ignores it unless `version` is newer (or `force`); downloads the blob; verifies size and SHA-256 (the hash is covered by the Ed25519 signature, so a valid hash proves the server signed this exact binary); stages the binary next to the current one; keeps the old binary as `.previous`; restarts the service. A watchdog (the new process itself plus the service manager) confirms a successful `hello.ack` within 5 minutes; otherwise the previous binary is restored and the service restarted (`update.status state="rolled_back"`). The failed version is remembered and not retried.

### 6.5 `session.start` / `session.end` (signed)

```json
{
  "deviceId": "...", "nonce": "...", "issuedAt": "...", "expiresAt": "...",
  "sessionId": "uuid",
  "kind": "terminal",
  "consent": "require",
  "consentTimeoutSeconds": 60,
  "requestedBy": "Jane Doe (Example IT)",
  "terminal": { "cols": 120, "rows": 30, "runAs": "system" }
}
```

`kind`: `terminal`, `files`, `desktop`. `consent`: `none`, `notify`, `require`.

Agent behaviour (transparency rules, not optional):

1. `require`: prompt the logged-in user (Allow / Deny, default Deny on timeout). Send `session.status pending_consent`, then `active` or `denied`. If nobody is logged in the session proceeds (nobody to ask) and this is reported in `reason: "no_user_logged_in"`.
2. `notify`: show a notification, then proceed.
3. In **all** modes, including `none`, a visible on-screen indicator ("Remote session active: <requestedBy>") is shown to the logged-in user for the whole session, with a way to end the session locally.
4. The session ends on `session.end`, local "End session", loss of the control connection (fail closed), terminal exit, or 12 h maximum.
5. `desktop`: the agent performs consent + indicator; the screen stream itself is carried by the MeshCentral agent, which the agent installs/starts via `mesh.install`.

`session.end`: `{deviceId, nonce, issuedAt, expiresAt, sessionId, reason}`.

### 6.6 `session.input` (signed)

`{deviceId, sessionId, seq, kind: "data"|"resize", data?: base64, cols?, rows?, issuedAt, expiresAt}`. No nonce: replay protection is `seq`, which must be exactly `last + 1` for that session (first is 1). The session must be `active` and of kind `terminal`.

### 6.7 `trust.rotate` (signed)

`{deviceId, nonce, issuedAt, expiresAt, commandKeys: [{kid, alg, publicKey}], caCertificates?: PEM}`. Must be signed by a key in the **current** `trust.json`. Replaces the trust store atomically. At least one key must be present.

## 7. Report payloads

All sub-collectors report what they can. A sub-section the OS cannot provide is `null` and its name is added to `unsupported: string[]`.

### 7.1 `inventory`

```json
{
  "collectedAt": "...", "hostname": "", "machineId": "",
  "os": {"family": "windows|macos|linux", "name": "", "version": "", "build": "", "kernel": ""},
  "arch": "amd64|arm64",
  "cpu": {"model": "", "cores": 0, "logicalCores": 0},
  "memoryBytes": 0,
  "disks": [{"device": "", "mountPoint": "", "fsType": "", "totalBytes": 0, "freeBytes": 0}],
  "network": [{"name": "", "mac": "", "ipv4": [], "ipv6": []}],
  "defaultGateway": "192.168.1.1",
  "wifi": {"interface": "", "ssid": "", "bssid": ""},
  "serial": "", "manufacturer": "", "model": "",
  "consoleUser": "", "loggedInUsers": [],
  "bootTime": "...", "uptimeSeconds": 0, "pendingReboot": false, "timezone": "",
  "agent": {"version": "", "cpuPercent": 0.0, "rssBytes": 0},
  "unsupported": []
}
```

`defaultGateway` (IPv4, optional) and `wifi` (null when not on Wi-Fi or not readable) were added in Phase 10. The SSID is best effort: Windows 11 24H2+ and macOS 14+ hide it from services without location permission; a hidden SSID is reported as `""`.

### 7.2 `software.inventory`

`{collectedAt, items: [{name, version, publisher?, source, id?, installDate?}], truncated, unsupported: []}`; `source` ∈ `registry`, `winget`, `app`, `pkgutil`, `brew`, `dpkg`, `rpm`, `snap`, `flatpak`.

### 7.3 `posture`

```json
{
  "collectedAt": "...",
  "antivirus": [{"name": "", "enabled": true, "upToDate": true, "signatureVersion": "", "source": "wsc|defender|xprotect|clamav|known_av"}],
  "firewall": {"enabled": true, "detail": ""},
  "diskEncryption": [{"volume": "", "method": "bitlocker|filevault|luks|none", "status": "encrypted|decrypted|in_progress|unknown"}],
  "localAdmins": [""],
  "screenLock": {"enabled": true, "timeoutSeconds": 300},
  "lastPatchDate": "...",
  "pendingReboot": false,
  "listeningPorts": [{"protocol": "tcp|udp", "address": "", "port": 0, "process": ""}],
  "unsupported": []
}
```

### 7.4 `patch.state`

`{collectedAt, pending: [{id, title, kb?, category, severity, source: "wua"|"softwareupdate"|"apt"|"dnf"|"winget"|"brew", currentVersion?, newVersion?, sizeBytes?, requiresReboot?}], rebootRequired, lastInstallAt?, scanError?, unsupported: []}`

## 8. HTTP side endpoints (agent listener, mTLS)

| Endpoint | Purpose |
|---|---|
| `GET /agent/v1/blobs/{blobId}` | Download a package / agent build / file for `file.write`. The server authorises the blob for this device (it must be referenced by a job run or release dispatched to it within the last hour). The agent always verifies the SHA-256 from the signed command. |
| `PUT /agent/v1/uploads/{uploadId}` | Upload for `file.read`. One-time ticket bound to the device and job run; size-capped. |

## 9. Versioning

- `version` in the envelope is the protocol major version. Additive changes (new optional fields, new types, new job kinds) do not bump it; agents answer unknown job kinds with `unsupported`.
- `hello.capabilities` lists the job kinds and session kinds this agent build supports so the server can avoid dispatching the rest.
