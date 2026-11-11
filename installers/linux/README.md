# Linux packages (`.deb`, `.rpm`)

Built with [nfpm](https://nfpm.goreleaser.com) from a statically linked agent binary.
Targets: Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+, current Fedora; amd64 and arm64.

| File | Purpose |
|---|---|
| `nfpm.yaml` | Package definition (templated by `NFPM_ARCH`, `DRANZO_VERSION`, `NFPM_SIGNING_KEY_FILE`). |
| `build-packages.sh` | Stages files, runs nfpm for deb + rpm, signs and verifies when a key is configured. Used by CI. |
| `dranzormm-agent.service` | Packaged systemd unit (`/usr/lib/systemd/system/`). |
| `10-hardening.conf` | Drop-in with restart behaviour and hardening; every choice is explained in the file. |
| `scripts/postinstall.sh`, `preremove.sh`, `postremove.sh` | Maintainer scripts shared by deb and rpm. |
| `README.package` | Installed as `/usr/share/doc/dranzo-agent/README` (what the agent is, how to remove it). |

## Build

```sh
scripts/build-agent.sh linux/arm64                       # -> dist/agent/dranzo-agent-linux-arm64
installers/linux/build-packages.sh --arch arm64 \
    --binary dist/agent/dranzo-agent-linux-arm64 --version 1.4.0 --out dist/linux
```

Output: `dranzo-agent_<version>_<arch>.deb`, `dranzo-agent-<version>-1.<x86_64|aarch64>.rpm`,
`SHA256SUMS.linux-<arch>`.

### Signing rule

| `GPG_PRIVATE_KEY` | Result |
|---|---|
| not set | Packages are built **unsigned**; the script prints `UNSIGNED BUILD` (a GitHub warning annotation in CI). |
| set | Packages **must** be signed with it (`GPG_PASSPHRASE` if the key has one). The script then verifies the deb `_gpgorigin` signature with `gpg` and the rpm signature with `rpmkeys`. Any failure, including a missing `rpmkeys`, fails the build. |

## Service ownership (read this before changing the unit)

The agent registers its own service through `kardianos/service` under the name
**`dranzormm-agent`** (`agent/internal/svc/svc_linux.go`). `dranzo-agent install` writes
`/etc/systemd/system/dranzormm-agent.service` and refuses to run if that file already exists.
The package therefore:

- ships its unit in `/usr/lib/systemd/system/` **with the same name**. A unit in `/etc` shadows
  one in `/usr/lib`, so there is always exactly one service;
- puts restart behaviour and hardening in a **drop-in**, which systemd applies to whichever
  definition is active;
- never writes to `/etc/systemd/system/` itself.

> The original task brief named the unit `dranzo-agent.service`. That name would create a second
> service next to the one the agent registers, and `dranzo-agent status` / `uninstall` / the
> signed `agent.uninstall` command would not find it. The agent's name wins.

## Install and enrol

```sh
sudo dpkg -i dranzo-agent_1.4.0_amd64.deb        # or: sudo rpm -i dranzo-agent-1.4.0-1.x86_64.rpm
sudo dranzo-agent install --server https://agents.example.com --token dz_enroll_...
```

Unattended (configuration management, images): provide the parameters to the package manager
and the post-install script enrols the device.

```sh
sudo DRANZO_SERVER_URL=https://agents.example.com DRANZO_ENROLL_TOKEN=dz_enroll_... \
     dpkg -i dranzo-agent_1.4.0_amd64.deb
# or drop /etc/dranzormm/install.env (root, 0600) with DRANZO_SERVER_URL= and DRANZO_ENROLL_TOKEN=
# lines before installing; the file is deleted after use.
```

Optional `DRANZO_CA_FILE` + `DRANZO_TRUST_FILE` supply the trust anchors when the binary was
built without embedded ones. A failed enrolment prints a warning but does **not** fail the
package installation (a bad token must not leave dpkg/rpm half-configured); check with
`sudo dranzo-agent status`.

## Remove

| Command | Service | Agent data (`/var/lib/dranzormm`, `/etc/dranzormm`) |
|---|---|---|
| `apt remove dranzo-agent` | stopped, disabled, removed | kept (same device identity on re-install) |
| `apt purge dranzo-agent` | removed | deleted |
| `dnf remove dranzo-agent` | removed | deleted (`DRANZO_KEEP_DATA=1` in the environment keeps it) |

If the technician set an **uninstall code**, `preremove.sh` fails (and the package stays
installed) unless the code is supplied: `sudo DRANZO_UNINSTALL_CODE=XXXX apt remove dranzo-agent`,
or run `sudo dranzo-agent uninstall --code XXXX` first. This is a deterrent against casual
removal, not a lock: root can always stop the unit and delete the files by hand, and the
package README on the device says so.

## What was verified locally (2026-11-11, macOS arm64 host, Docker via Colima)

- `nfpm` 2.48.0 built unsigned deb + rpm for arm64 and amd64 from locally cross-compiled binaries.
- `debian:12` and `rockylinux:9` containers (arm64): install, file modes (`/etc/dranzormm` and
  `/var/lib/dranzormm` are `0700 root:root`), package listed in `dpkg -l` / `rpm -q`,
  `dranzo-agent version` runs, remove / purge / erase behave as in the table above.
- `debian:12` with systemd as PID 1 (privileged throwaway container): `systemd-analyze verify`
  passes; un-enrolled unit stays inactive; `dranzo-agent install` creates one enabled, running
  service whose `FragmentPath` is the `/etc` unit and whose `DropInPaths` is the packaged drop-in
  (`Restart=always`, `RestartUSec=10s`, `KillMode=process`, `NoNewPrivileges=no`,
  `StartLimitIntervalUSec=0`, state directories `0700`); package upgrade restarts it; removal
  without the uninstall code is refused; removal with the code leaves no unit, no process.
- Signed build with a throwaway GPG key inside a container: deb and rpm signatures verify;
  wrong passphrase and a non-key secret both fail the build.

Not verified: amd64 packages were built but only the arm64 ones were installed (the Docker VM is
arm64); Ubuntu, Fedora, RHEL 8 and Alma were not exercised; no real enrolment against a server
(the test used an unreachable server URL and throwaway trust anchors); the CI job has never run.
