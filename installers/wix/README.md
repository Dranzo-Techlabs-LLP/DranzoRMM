# Windows installer (`DranzoAgent-x64.msi`, `DranzoAgent-arm64.msi`)

> **Not built locally.** WiX runs only on Windows; these sources were written on macOS from
> knowledge of the WiX v4/v5 schema. `Package.wxs` was checked for XML well-formedness only and
> `build.ps1` has never executed. Expect to fix details on the first CI run, and test install,
> upgrade and uninstall on a Windows VM before shipping.

| File | Purpose |
|---|---|
| `Package.wxs` | Per-machine MSI: `C:\Program Files\DranzoRMM\dranzo-agent.exe`, enrolment and removal through the agent, MajorUpgrade. |
| `build.ps1` | Installs the pinned `wix` dotnet tool, signs the exe and the MSI when secrets are present, builds for `x64` or `arm64`. Used by CI. |
| `README.txt` | Installed next to the agent (what it is, how to remove it). |

## Build (Windows)

```powershell
pwsh installers/wix/build.ps1 -Arch x64   -AgentBinary dist\agent\dranzo-agent-windows-amd64.exe -Version 1.4.0 -OutDir dist\windows
pwsh installers/wix/build.ps1 -Arch arm64 -AgentBinary dist\agent\dranzo-agent-windows-arm64.exe -Version 1.4.0 -OutDir dist\windows
```

WiX is pinned to **5.0.2**. WiX 6 and later are distributed under the Open Source Maintenance
Fee model; upgrading is a cost/licensing decision for the product owner, not a routine
dependency bump. Check the current terms before changing `-WixVersion`.

### Signing rule

| `WINDOWS_CERT_PFX_BASE64` / `WINDOWS_CERT_PASSWORD` | Result |
|---|---|
| neither | **Unsigned** exe and MSI, `UNSIGNED BUILD` notice. |
| both | `signtool sign /fd sha256 /tr <timestamp> /td sha256` on the exe (before packing) and on the MSI, then `signtool verify /pa`. Any failure fails the build. |
| one of them | Build fails: "partially configured". |

Publicly trusted code-signing keys must now live on hardware (token/HSM), so a PFX in a secret
is realistic only for an internal or test certificate. For production use a cloud signing
service (Azure Trusted Signing, or a Key Vault HSM key with a compatible signing tool) and
replace the two `signtool sign` calls; the rule above (configured ⇒ must succeed) stays.

## Install

```bat
msiexec /i DranzoAgent-x64.msi /qn SERVERURL="https://agents.example.com" ENROLLTOKEN="dz_enroll_..."
```

| Property | Meaning |
|---|---|
| `SERVERURL` | `https://host[:port]` of the agent listener. Must be given together with `ENROLLTOKEN`. |
| `ENROLLTOKEN` | Enrolment token. `Hidden`: replaced by `********` in MSI logs. |
| `CAFILE`, `TRUSTFILE` | Optional trust anchors (both or neither) when the binary has none embedded. |
| `UNINSTALLCODE` | Uninstall code for removal, when the technician set one. Hidden. |
| `REMOVEDATA` | `1` deletes `C:\ProgramData\DranzoRMM` on uninstall. Default: data is kept. |

Without `SERVERURL`/`ENROLLTOKEN` the MSI only installs the files; enrol later with
`"C:\Program Files\DranzoRMM\dranzo-agent.exe" install --server ... --token ...` (elevated).

## Service ownership

The agent registers the Windows service itself (`DranzoRMMAgent`, display name "DranzoRMM
Agent", LocalSystem, automatic start, restart 5 s after failure) and refuses to run `install`
when the service already exists. The MSI therefore contains **no `ServiceInstall`**:

- `EnrollAgent` (deferred, SYSTEM): `dranzo-agent.exe install --server ... --token ...` on first
  install only. A non-zero exit fails the installation and rolls it back. `install` does not
  contact the server; it fails only for local reasons (malformed URL or token, missing trust
  anchors, service already present).
- `ServiceControl Stop="both"` stops the service before the exe is replaced or removed.
- `StartAgentService`: `sc.exe start` after an upgrade or repair.
- `UnregisterAgent`: `dranzo-agent.exe uninstall [--keep-data] [--code ...]` on uninstall, only
  when the service is registered. If the agent refuses (wrong or missing uninstall code) the
  uninstall fails and is rolled back.
- `RemoveAgentData`: `rd /s /q "%ProgramData%\DranzoRMM"` when `REMOVEDATA=1`.

## Known limits and open points

- The enrolment token is on the command line of the short-lived `dranzo-agent.exe install`
  process (visible to administrators of that machine while it runs). MSI cannot pass an
  environment variable to a custom action; `HideTarget` keeps it out of the MSI log.
- Plain EXE custom actions do not capture output: a failed enrolment shows only the exit code
  in the MSI log. Run the same command by hand to see the message.
- A console window may flash during interactive installs (the agent is a console program).
- The `agent.uninstall` command removes the service and data but leaves the MSI registered
  (files in Program Files, entry in Apps and features) until the MSI is uninstalled.
- A Phase 8 self-update replaces `dranzo-agent.exe` outside Windows Installer. MSI repair
  normally leaves a newer unversioned file alone, but this must be tested with the real updater.
- Not verified at all: launch conditions, the `RegistrySearch` results on arm64, the custom
  action sequencing, major upgrade behaviour, rollback, Authenticode signing.
