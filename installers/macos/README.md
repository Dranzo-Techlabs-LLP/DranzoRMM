# macOS installer package (`DranzoAgent.pkg`)

A flat distribution package built with `pkgbuild` + `productbuild` from the universal
(x86_64 + arm64) agent binary.

| File | Purpose |
|---|---|
| `build-pkg.sh` | Builds the package; signs, notarises and staples when signing settings are present. Used by CI. |
| `ci-import-signing.sh` | CI only: imports the signing secrets into a throwaway keychain and exports the settings `build-pkg.sh` reads. |
| `distribution.xml.in` | productbuild distribution template (minimum macOS and architectures are filled in from the binary). |
| `scripts/preinstall` | Refuses to install on a macOS older than the binary supports. |
| `scripts/postinstall` | Upgrade: restarts the daemon. First install: enrols if a trusted parameter file exists, otherwise leaves the agent un-enrolled. |
| `uninstall.sh` | Installed as `/Library/DranzoRMM/uninstall.sh`. |
| `com.dranzormm.agent.plist` | Reference LaunchDaemon definition (see "Daemon ownership"). |
| `resources/` | Installer welcome text and the README installed on the device. |

## Payload

```
/usr/local/bin/dranzo-agent                          universal binary, root:wheel 0755
/Library/DranzoRMM/uninstall.sh                      root:wheel 0755
/Library/DranzoRMM/README.txt
/Library/DranzoRMM/com.dranzormm.agent.plist         reference copy, not loaded
```

Package identifier `com.dranzormm.agent.pkg`. Agent data lives in
`/Library/Application Support/DranzoRMM/` (created by the agent, `root:wheel 0700`).

## Build

```sh
scripts/build-agent.sh darwin/universal
installers/macos/build-pkg.sh --binary dist/agent/dranzo-agent-darwin-universal \
    --version 1.4.0 --out dist/macos
pkgutil --payload-files dist/macos/DranzoAgent.pkg
```

### Signing rule

| Settings | Result |
|---|---|
| none of the `APPLE_*` settings | **Unsigned** package, `UNSIGNED BUILD` notice. Gatekeeper blocks it on other Macs. |
| all of them | Binary: `codesign --options runtime --timestamp` (Developer ID Application). Package: `productsign` (Developer ID Installer), `notarytool submit --wait`, `stapler staple`, then `spctl --assess --type install`. Any failure fails the build; a notarisation status other than `Accepted` is a failure. |
| some but not all | Build fails: "partially configured". |

Settings are listed at the top of `build-pkg.sh`; the CI secret names are in
`ci-import-signing.sh` and `docs/RUNBOOK.md`.

## Daemon ownership

The agent registers its own LaunchDaemon through `kardianos/service` with the label
**`com.dranzormm.agent`** (`agent/internal/svc/svc_darwin.go`): `dranzo-agent install` writes
`/Library/LaunchDaemons/com.dranzormm.agent.plist` (`KeepAlive`, `RunAtLoad`, root,
`dranzo-agent run`) and **fails with "Init already exists" if that file is already there**.
`dranzo-agent uninstall` and the signed `agent.uninstall` command remove the same file.

So the package does **not** place a plist in `/Library/LaunchDaemons`. If it did, the documented
flow `sudo installer -pkg DranzoAgent.pkg -target / && sudo dranzo-agent install --server ...`
would fail at the second step. `com.dranzormm.agent.plist` in this directory is the reference
definition of the same job; it is linted at build time and installed, unloaded, under
`/Library/DranzoRMM/`.

> The task brief asked for a package-owned `com.dranzo.agent.plist`. Both the label and the
> ownership conflict with the agent code as it exists today; the agent's behaviour wins. To make
> the package own the daemon instead, `svc.Install` must first learn to accept an existing
> definition (start it instead of failing).

## Install and enrol

Interactive:

```sh
sudo installer -pkg DranzoAgent.pkg -target /
sudo /usr/local/bin/dranzo-agent install --server https://agents.example.com --token dz_enroll_...
```

Unattended (MDM, management script running as root): create the parameter file first.

```sh
sudo install -m 0600 -o root -g wheel /dev/null /tmp/dranzo-agent-install.json
sudo tee /tmp/dranzo-agent-install.json >/dev/null <<'JSON'
{ "serverUrl": "https://agents.example.com", "token": "dz_enroll_..." }
JSON
sudo installer -pkg DranzoAgent.pkg -target /
```

Optional keys `caFile` and `trustFile` (paths) supply trust anchors when the binary has none
embedded. The file is deleted after use.

**The parameter file is only honoured when it is a regular file owned by root and not writable
by group or others.** `/tmp` is world-writable; without that check any local user could plant
the file and have the next installation enrol the Mac with a server of their choosing, which
would then be able to run commands as root. A file that fails the check is ignored and reported
in `/var/log/install.log`.

A failed enrolment is logged but does not fail the installation.

## Remove

```sh
sudo /Library/DranzoRMM/uninstall.sh                 # removes daemon, binary, data, receipt
sudo /Library/DranzoRMM/uninstall.sh --keep-data     # keeps the device identity
sudo /Library/DranzoRMM/uninstall.sh --code XXXX     # when an uninstall code is set
```

## Known limits

- **Minimum macOS is 13, not 12.** The agent is built with Go 1.27 (`agent/go.mod`), whose
  darwin binaries carry `minos 13.0`. `build-pkg.sh` reads that value from the binary and the
  installer refuses older systems. `docs/SPEC.md` section 2 says macOS 12+: either the
  specification or the toolchain has to change (Go 1.26 is the last release that targets 12).
- Screen Recording, Accessibility and Full Disk Access cannot be granted by a package. They need
  one-time user approval or an MDM PPPC profile (`docs/MDM_PLAN.md`).
- macOS shows a "Background Items Added" notification when the daemon is registered. That is
  expected and desirable for a transparent agent.

## What was verified locally (2026-11-11, macOS 26.6.2 arm64)

- `build-pkg.sh` built an **unsigned** `DranzoAgent.pkg` from a locally built universal binary
  under `/bin/bash` 3.2. `pkgutil --payload-files`:
  `./usr/local/bin/dranzo-agent`, `./Library/DranzoRMM/uninstall.sh`,
  `./Library/DranzoRMM/com.dranzormm.agent.plist`, `./Library/DranzoRMM/README.txt`
  (plus their directories); payload ownership `root:wheel`; `installer -pkginfo` and
  `-volinfo` accept it; `pkgutil --check-signature` reports "no signature".
- The AppleDouble stripping path ran (this machine stamps `com.apple.provenance` on created
  files) and the resulting payload and Bom are clean.
- Partial signing settings fail the build; complete settings with a non-existent identity fail
  at `codesign` and produce no package.
- `postinstall` logic in a harness with redirected paths: a parameter file not owned by root is
  ignored; JSON extraction and the call to `dranzo-agent install` work.

Not verified: the package was **not installed** (needs sudo); `preinstall`/`postinstall` and
`uninstall.sh` have not run as root; signing, notarisation and stapling have never run (no
Developer ID certificates here); `ci-import-signing.sh` was only exercised for its "no secrets"
and "partial secrets" branches.
