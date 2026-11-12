# DranzoRMM Windows verification kit

The kit runs the DranzoRMM agent's own test programs on a Windows 11 machine
(x64 or ARM64) and produces one results file to send back. It needs no
internet download, no PowerShell module and no developer tools: everything is
inside the zip.

## 1. Build the kit (developer, macOS or Linux)

```sh
scripts/windows-kit/build-kit.sh            # both architectures
scripts/windows-kit/build-kit.sh arm64      # only one
```

Output: `dist/windows-kit/DranzoWindowsKit-amd64.zip` and
`dist/windows-kit/DranzoWindowsKit-arm64.zip`. Each holds
`bin\dranzo-agent.exe` (version `0.1.0-wintest`, no compiled-in keys),
`tests\<package>\<name>.test.exe` (one per Go package, with its `testdata\`),
`Run-DranzoWindowsTests.ps1`, this README as `README.txt`, and
`manifest.json` (commit, build time, SHA-256 of every binary).

## 2. On the Windows VM (owner)

1. **Pick the zip for the VM's processor.** Settings > System > About >
   "System type": `x64-based` -> `DranzoWindowsKit-amd64.zip`;
   `ARM-based` -> `DranzoWindowsKit-arm64.zip`. (The x64 kit also runs on
   ARM64 under emulation, but then the native ARM64 agent is not tested.)
2. **Copy the zip to the VM's local disk**, e.g. `C:\DranzoKit\`. Not a
   network share or a mapped drive: part of the tests run as SYSTEM, which
   cannot read them.
3. **Unblock and extract**: right-click the zip > Properties > tick
   "Unblock" > OK; then right-click > "Extract All...". (The runner also
   unblocks the extracted files itself.)
4. **Open an elevated PowerShell**: Start > type `PowerShell` > right-click
   "Windows PowerShell" > "Run as administrator".
5. Go to the kit folder and run it (`-ExecutionPolicy Bypass` applies to
   this one process only and changes no setting):

   ```powershell
   cd C:\DranzoKit\DranzoWindowsKit-arm64
   powershell -ExecutionPolicy Bypass -File .\Run-DranzoWindowsTests.ps1 -All
   ```

   With a live server-side test (the operator gives you `token.txt`,
   `ca.pem` and `trust.json`; put them in the kit folder):

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Run-DranzoWindowsTests.ps1 -All `
       -ServerUrl https://<server>:8443 -TokenFile .\token.txt -CaFile .\ca.pem -TrustFile .\trust.json `
       -UninstallAfter
   ```

6. **Stay at the VM** when `-Ui` or `-All` is used: the window prints lines
   starting with `>>>>> ACTION` ("click Yes now", "click End session") that
   a person must follow on the VM's screen within 3 minutes each.
7. When it finishes it prints the path of
   `DranzoWindowsResults-<computer>-<time>.zip` **on your Desktop**. Send
   that file back (it contains logs and system information, never the
   enrollment token).

A run with `-All` takes roughly 20-60 minutes, most of it Windows Update.

## 3. Switches: what each one does on the VM and how it is undone

| Switch | What it does | Undo |
|---|---|---|
| (none) | Unit tests of every package. Temporary files only, in `%TEMP%`. | Removed by the tests. |
| `-Live` | Live tests (`DRANZO_REAL_WINDOWS=1`): reads inventory, installed software, security posture (Defender, firewall, BitLocker, administrators, ports), searches Windows Update (read-only), runs PowerShell/cmd test scripts and terminals that only print text and ping 127.0.0.1, file tests in a temp folder (incl. a junction), a read-only password/USB policy read (`net accounts`, `secedit /export` to a temp file). | Nothing to undo; temp files are removed. |
| `-Service` | Registers, starts, crashes (to test restart-on-failure), stops and removes two THROWAWAY services, `DranzoRMMAgentTest` (also its event-log source) and `DranzoRMMAgentUpdTest` (never started). The real `DranzoRMMAgent` service is not touched. Implies `-Live`. | The tests remove both services, also on failure. Check: `Get-Service DranzoRMM*`. Manual: `sc.exe delete DranzoRMMAgentTest`. |
| `-Ui` | Message boxes and the "remote session active" indicator window on the console. Needs someone signed in at the console. Runs as SYSTEM via a temporary scheduled task. Implies `-Live`. | Windows close by themselves; the task is deleted. |
| `-AsSystem` | Runs the live tests a second time as LocalSystem (the account the agent service uses) through temporary scheduled tasks `DranzoKitTest-*`. | Tasks are deleted after each package. Check: `Get-ScheduledTask DranzoKitTest-*`. |
| `-PatchInstall` | **Last**, after the results zip is written: installs ONE pending Windows update (a Defender definition update if one is pending, else the smallest non-driver, non-feature update). A warning is printed first. The update may need a restart. Implies `-Live`. | Updates are not rolled back (Settings > Windows Update > Update history > Uninstall updates, if needed). The results zip is written again afterwards. |
| `-All` | `-Live -Service -Ui -PatchInstall -AsSystem`. | As above. |
| `-ServerUrl ... -TokenFile ... -CaFile ... -TrustFile ...` | Live enrollment: copies the agent to `C:\Program Files\DranzoRMM\`, runs `dranzo-agent.exe install` (token passed in the `DRANZO_ENROLL_TOKEN` environment variable of that one process, never on a command line and never in a log), waits until `dranzo-agent.exe status` says connected, deletes `token.txt`, prints *"Agent enrolled and connected; the server-side test will now drive it - keep this window open"* and waits for **Enter** ("Press Enter when the operator says the server-side checks are done"). The agent keeps running as the visible service "DranzoRMM Agent". Refused if a `DranzoRMMAgent` service already exists. | `-UninstallAfter` runs `dranzo-agent.exe uninstall`, checks that the service and `C:\ProgramData\DranzoRMM` are gone and removes `C:\Program Files\DranzoRMM`. Without it: `"C:\Program Files\DranzoRMM\dranzo-agent.exe" uninstall`. |
| `-Token dz_enroll_...` | Same as `-TokenFile` (prefer the file: a command line ends up in the PowerShell history). | Clear-History; delete `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` lines. |
| `-Only <regex>` | Only the packages whose path matches, e.g. `-Only 'session|script'`. | - |
| `-TimeoutMinutes <n>` | Per-package test timeout (default 30; the update installation uses at least 120). | - |
| `-NoPause` | Do not wait for Enter after the enrollment. | - |

Order of a run: system information -> unit tests -> live tests (admin, then
SYSTEM) -> live enrollment and the Enter prompt -> optional uninstall ->
results zip -> Windows update installation -> results zip again.

**Network:** the runner itself only connects to `-ServerUrl`. Some tests use
Windows components that talk to Microsoft: the Windows Update search and
installation, and `winget list` / `winget upgrade` (may refresh winget's
package index). No telemetry is sent by the kit.

## 4. What is in the results zip

- `summary.txt`: one line per package and phase (`unit`, `live-admin`,
  `live-system`, `enroll`, `patch-install`) with pass / fail / skip counts,
  duration, and for each failing test its first output lines.
- `summary.json`: the same, machine-readable, plus the system information.
- `<phase>\<package>.log`: the complete `go test -v` output of each package.
- `system-info.json`, `systeminfo.txt`, `computerinfo.txt`,
  `agent-version.txt`; with an enrollment `enroll.log` and the agent's
  `agent.log`.

Results also stay in the kit folder under `results-<time>\`.

## 5. Troubleshooting

- "must run from an ELEVATED PowerShell": see step 4.
- "running scripts is disabled on this system": use the
  `powershell -ExecutionPolicy Bypass -File ...` form from step 5.
- A package shows `TIMEOUT`: it was killed after `-TimeoutMinutes` + 5;
  its log shows where it hung.
- Leftovers after an aborted run (Ctrl+C): `Get-Service DranzoRMM*`,
  `Get-ScheduledTask DranzoKitTest-*`; remove with `sc.exe delete <name>`
  and `Unregister-ScheduledTask <name>`.

## Installing the agent on one PC (without the test kit)

`Install-DranzoAgent.ps1` installs and enrolls a single Windows PC and reports
each step: network reach, copy to `C:\Program Files\DranzoRMM`, Windows Security
removing the binary, the `install` output, enrollment within 60 s, service
state, the last lines of `agent.log`. Put it in one folder with
`dranzo-agent-windows-<arch>.exe`, `ca.pem` and `trust.json`, then run in an
Administrator PowerShell (or double-click `Install-DranzoAgent.cmd`, which asks for elevation and runs it):

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-DranzoAgent.ps1 -ServerUrl https://<server>:8443
```

It asks for the enrollment token and writes `DranzoInstall.txt` (token
redacted) to the Desktop.
