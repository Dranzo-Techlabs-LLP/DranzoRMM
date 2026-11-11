#!/bin/sh
# DranzoRMM agent - macOS uninstaller. Installed as /Library/DranzoRMM/uninstall.sh.
#
#   sudo /Library/DranzoRMM/uninstall.sh [--code XXXX] [--keep-data]
#
#   --code XXXX   uninstall code, if your IT provider protects the agent with one
#   --keep-data   keep "/Library/Application Support/DranzoRMM" (device identity,
#                 configuration, log) so a later re-install is the same device
#
# Removes: the LaunchDaemon com.dranzormm.agent, /usr/local/bin/dranzo-agent,
# /Library/DranzoRMM, the agent data directory (unless --keep-data), the launchd
# log files and the package receipt. Nothing else is touched.
set -eu

LABEL="com.dranzormm.agent"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
AGENT="/usr/local/bin/dranzo-agent"
DATA_DIR="/Library/Application Support/DranzoRMM"
SUPPORT_DIR="/Library/DranzoRMM"
PKG_ID="com.dranzormm.agent.pkg"

code=""
keep_data=no
while [ $# -gt 0 ]; do
  case "$1" in
    --code) code="${2:-}"; shift 2 ;;
    --keep-data) keep_data=yes; shift ;;
    -h|--help) /usr/bin/sed -n '2,13p' "$0" | /usr/bin/sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  echo "This uninstaller must be run as root: sudo $0" >&2
  exit 1
fi

if [ -f "$PLIST" ] && [ -x "$AGENT" ]; then
  # The agent registered the daemon, so the agent removes it (and checks the
  # uninstall code). --keep-data here; the data directory is handled below.
  set -- uninstall --keep-data
  [ -n "$code" ] && set -- "$@" --code "$code"
  if ! "$AGENT" "$@"; then
    echo "The agent refused to uninstall. If an uninstall code is required, run:" >&2
    echo "    sudo $0 --code XXXX" >&2
    exit 1
  fi
fi

# Belt and braces: make sure the job is gone even if the definition was edited by hand.
/bin/launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true
/bin/rm -f "$PLIST"

/bin/rm -f "$AGENT" "${AGENT}.previous"
/bin/rm -f "/var/log/${LABEL}.out.log" "/var/log/${LABEL}.err.log"
if [ "$keep_data" = no ]; then
  /bin/rm -rf "$DATA_DIR"
fi
/bin/rm -rf "$SUPPORT_DIR"
/usr/sbin/pkgutil --forget "$PKG_ID" >/dev/null 2>&1 || true

echo "DranzoRMM agent removed."
[ "$keep_data" = yes ] && echo "Agent data kept in: $DATA_DIR"
exit 0
