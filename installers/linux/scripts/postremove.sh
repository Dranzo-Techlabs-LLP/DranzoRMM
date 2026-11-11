#!/bin/sh
# DranzoRMM agent - package post-remove script (deb postrm / rpm %postun).
#
# Arguments:  deb: "remove" | "purge" | "upgrade" | "failed-upgrade" | "abort-install" | ...
#             rpm: 0 = erase, 1+ = upgrade
#
# Data policy (device private key, certificate, trust anchors, configuration, log):
#   deb  `apt remove`  keeps  /var/lib/dranzormm and /etc/dranzormm (Debian convention)
#        `apt purge`   deletes them
#   rpm  `dnf remove`  deletes them (rpm has no purge); set DRANZO_KEEP_DATA=1 in the
#                      environment of the rpm/dnf command to keep them.
# A kept identity lets a re-installed agent come back as the same device.
set -eu

UNIT=dranzormm-agent.service
STATE_DIR=/var/lib/dranzormm
CONFIG_DIR=/etc/dranzormm

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

purge=no
case "${1:-}" in
  purge) purge=yes ;;
  0) [ "${DRANZO_KEEP_DATA:-0}" = "1" ] || purge=yes ;;
  *) ;;
esac

if [ "$purge" = yes ]; then
  # Fixed, literal paths only.
  rm -rf -- "$STATE_DIR" "$CONFIG_DIR"
  rm -f -- "/var/log/dranzormm-agent.out" "/var/log/dranzormm-agent.err"
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
  fi
fi
exit 0
