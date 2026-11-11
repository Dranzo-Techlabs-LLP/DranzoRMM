DranzoRMM agent
===============

This Mac has the DranzoRMM endpoint management agent installed. It lets your
IT provider monitor, maintain and support the computer: hardware and software
inventory, software and security updates, scripts and remote support.

What it does and does not do
  * It runs as the ordinary, visible LaunchDaemon "com.dranzormm.agent" (as root).
  * It only makes outbound connections to its management server and only
    executes commands signed by that server.
  * It does not hide itself, does not interfere with security software, and
    shows a visible indicator whenever a remote session is active.

Useful commands
  Status      sudo /usr/local/bin/dranzo-agent status
              sudo launchctl print system/com.dranzormm.agent
  Enrol       sudo /usr/local/bin/dranzo-agent install --server https://AGENT-SERVER --token dz_enroll_...
  Log         /Library/Application Support/DranzoRMM/agent.log   (root only)

Removing the agent (any administrator of this Mac can do this)
              sudo /Library/DranzoRMM/uninstall.sh
              sudo /Library/DranzoRMM/uninstall.sh --code XXXX     (if an uninstall code is set)

Files
  /usr/local/bin/dranzo-agent                          the agent
  /Library/LaunchDaemons/com.dranzormm.agent.plist     written by "dranzo-agent install"
  /Library/Application Support/DranzoRMM/              device key, certificate, state, log (root only)
  /Library/DranzoRMM/                                  this file, uninstall.sh, reference daemon definition
