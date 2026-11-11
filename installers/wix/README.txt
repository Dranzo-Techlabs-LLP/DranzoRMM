DranzoRMM Agent
===============

This computer has the DranzoRMM endpoint management agent installed. It lets
your IT provider monitor, maintain and support the computer: hardware and
software inventory, software and security updates, scripts and remote support.

What it does and does not do
  * It runs as the ordinary, visible Windows service "DranzoRMM Agent"
    (service name DranzoRMMAgent, account LocalSystem).
  * It only makes outbound connections to its management server and only
    executes commands signed by that server.
  * It does not hide itself, does not interfere with antivirus or EDR
    software, and shows a visible indicator whenever a remote session is active.

Useful commands (elevated command prompt)
  Status   "C:\Program Files\DranzoRMM\dranzo-agent.exe" status
           sc query DranzoRMMAgent
  Enrol    "C:\Program Files\DranzoRMM\dranzo-agent.exe" install --server https://AGENT-SERVER --token dz_enroll_...
  Log      C:\ProgramData\DranzoRMM\agent.log   (administrators only)

Removing the agent (any administrator of this computer can do this)
  Settings > Apps > Installed apps > DranzoRMM Agent > Uninstall
  or:      msiexec /x DranzoAgent-x64.msi
  If your IT provider protects the agent with an uninstall code:
           msiexec /x DranzoAgent-x64.msi UNINSTALLCODE=XXXX
  Add REMOVEDATA=1 to also delete C:\ProgramData\DranzoRMM (device identity).
