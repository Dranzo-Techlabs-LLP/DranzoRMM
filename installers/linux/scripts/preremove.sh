#!/bin/sh
# DranzoRMM agent - package pre-remove script (deb prerm / rpm %preun).
#
# Arguments:  deb: "remove" | "upgrade" <new-version> | "deconfigure" | "failed-upgrade"
#             rpm: 0 = erase, 1+ = upgrade
#
# On a real removal it stops and disables the service and calls the agent's own
# uninstall path (`dranzo-agent uninstall --keep-data`), which removes the service
# definition the agent registered. Agent data is handled by postremove.sh.
#
# Uninstall code: if the IT provider set an uninstall code for this device, the
# agent's uninstall command requires it (docs/SPEC.md section 1). Supply it with
#     sudo DRANZO_UNINSTALL_CODE=XXXX apt remove dranzo-agent
# or run `sudo dranzo-agent uninstall --code XXXX` first and then remove the package.
set -eu

UNIT=dranzormm-agent.service
AGENT=/usr/bin/dranzo-agent
AGENT_UNIT_FILE=/etc/systemd/system/$UNIT     # written by `dranzo-agent install`

have_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

case "${1:-}" in
  remove|0) ;;                      # real removal: continue below
  *) exit 0 ;;                      # upgrade / deconfigure: keep the service as it is
esac

if [ -e "$AGENT_UNIT_FILE" ] && [ -x "$AGENT" ]; then
  # The agent registered the service itself: let it deregister (stop, disable,
  # delete /etc/systemd/system/dranzormm-agent.service). --keep-data because data
  # removal is the package manager's decision (purge vs remove), see postremove.sh.
  set -- uninstall --keep-data
  if [ -n "${DRANZO_UNINSTALL_CODE:-}" ]; then
    set -- "$@" --code "$DRANZO_UNINSTALL_CODE"
  fi
  if ! "$AGENT" "$@"; then
    cat >&2 <<'MSG'
dranzo-agent: the agent refused to uninstall, so the package was NOT removed.
If your IT provider protects this agent with an uninstall code, run:
    sudo dranzo-agent uninstall --code XXXX
and then remove the package again.
MSG
    exit 1
  fi
fi

# Packaged unit (or anything left): make sure nothing keeps running.
if have_systemd; then
  systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
fi
exit 0
