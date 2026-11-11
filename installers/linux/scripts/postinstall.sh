#!/bin/sh
# DranzoRMM agent - package post-install script (deb postinst / rpm %post).
#
# Arguments:  deb: "configure" [previous-version]      rpm: 1 = first install, 2+ = upgrade
#
# What it does
#   * upgrade        : reload systemd and restart the agent if it was running.
#   * first install  : enrol only when the administrator supplied the parameters
#                      (environment or /etc/dranzormm/install.env); otherwise leave
#                      the agent installed but NOT enrolled and say how to enrol.
#
# Nothing here hides the agent or makes it hard to remove; `apt remove dranzo-agent`
# / `dnf remove dranzo-agent` undo everything this script does.
set -eu

UNIT=dranzormm-agent.service
AGENT=/usr/bin/dranzo-agent
CONFIG_DIR=/etc/dranzormm
STATE_DIR=/var/lib/dranzormm
AGENT_UNIT_FILE=/etc/systemd/system/$UNIT     # written by `dranzo-agent install`
INSTALL_ENV=$CONFIG_DIR/install.env

have_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

is_upgrade() {
  case "${1:-}" in
    configure) [ -n "${2:-}" ] ;;      # deb: a previous version was configured
    1) return 1 ;;                     # rpm: first install
    [2-9]|[1-9][0-9]*) return 0 ;;     # rpm: upgrade
    *) return 1 ;;
  esac
}

# Secrets live here: keep both directories root-only whatever the umask was.
install -d -m 0700 -o root -g root "$CONFIG_DIR" "$STATE_DIR"

if have_systemd; then
  systemctl daemon-reload || true
fi

resume_hint() {
  echo "dranzo-agent: existing agent data found in $STATE_DIR but the service is not enabled."
  echo "dranzo-agent: resume as the same device:  sudo systemctl enable --now $UNIT"
  echo "dranzo-agent: or enrol again:             sudo dranzo-agent install --server URL --token TOKEN"
}

has_data() {
  [ -e "$STATE_DIR/config.json" ] || [ -e "$CONFIG_DIR/bootstrap.json" ]
}

if is_upgrade "$@"; then
  if have_systemd; then
    # try-restart = restart only if it is running; never starts a stopped agent.
    systemctl try-restart "$UNIT" || true
    # deb also reports "configure <old-version>" when a removed-but-not-purged
    # package is installed again; the service is then disabled.
    if has_data && ! systemctl is-enabled --quiet "$UNIT" 2>/dev/null; then
      resume_hint
    fi
  fi
  exit 0
fi

# ----- First install ---------------------------------------------------------
# Optional unattended enrolment. Parameters come from the environment of the
# package manager, or from a root-only file dropped before installing:
#   /etc/dranzormm/install.env   (mode 0600), lines of KEY=value, keys:
#     DRANZO_SERVER_URL    https://agents.example.com
#     DRANZO_ENROLL_TOKEN  dz_enroll_...
#     DRANZO_CA_FILE       optional path to the pinned CA bundle (PEM)
#     DRANZO_TRUST_FILE    optional path to trust.json (command signing keys)
# The file is parsed as data (never sourced) and deleted afterwards because it
# holds the enrolment token.
if [ -f "$INSTALL_ENV" ]; then
  mode=$(stat -c '%a' "$INSTALL_ENV" 2>/dev/null || echo unknown)
  owner=$(stat -c '%u' "$INSTALL_ENV" 2>/dev/null || echo unknown)
  if [ "$owner" != "0" ] || { [ "$mode" != "600" ] && [ "$mode" != "400" ]; }; then
    echo "dranzo-agent: ignoring $INSTALL_ENV (must be owned by root with mode 0600)" >&2
  else
    while IFS='=' read -r key value; do
      case "$key" in
        DRANZO_SERVER_URL)   : "${DRANZO_SERVER_URL:=$value}" ;;
        DRANZO_ENROLL_TOKEN) : "${DRANZO_ENROLL_TOKEN:=$value}" ;;
        DRANZO_CA_FILE)      : "${DRANZO_CA_FILE:=$value}" ;;
        DRANZO_TRUST_FILE)   : "${DRANZO_TRUST_FILE:=$value}" ;;
        *) ;;
      esac
    done <"$INSTALL_ENV"
  fi
  rm -f "$INSTALL_ENV"
fi

if [ -n "${DRANZO_SERVER_URL:-}" ] && [ -n "${DRANZO_ENROLL_TOKEN:-}" ]; then
  if [ -e "$AGENT_UNIT_FILE" ]; then
    echo "dranzo-agent: a service definition already exists ($AGENT_UNIT_FILE); not enrolling again." >&2
  else
    # The token is passed in the environment (the agent reads DRANZO_ENROLL_TOKEN),
    # not on the command line, so it does not show up in the process list.
    export DRANZO_ENROLL_TOKEN
    set -- install --server "$DRANZO_SERVER_URL"
    if [ -n "${DRANZO_CA_FILE:-}" ] && [ -n "${DRANZO_TRUST_FILE:-}" ]; then
      set -- "$@" --ca-file "$DRANZO_CA_FILE" --trust-file "$DRANZO_TRUST_FILE"
    fi
    if "$AGENT" "$@"; then
      echo "dranzo-agent: enrolled with $DRANZO_SERVER_URL and started."
    else
      # Do not fail the package installation: a bad or expired token must not
      # leave dpkg/rpm half-configured. The administrator can simply retry.
      echo "dranzo-agent: WARNING: enrolment failed. The package is installed but the agent is NOT enrolled." >&2
      echo "dranzo-agent: retry with: sudo dranzo-agent install --server URL --token TOKEN" >&2
    fi
    unset DRANZO_ENROLL_TOKEN
  fi
  exit 0
fi

if has_data; then
  # Fresh package install over existing agent data (e.g. rpm erased with DRANZO_KEEP_DATA=1).
  if have_systemd && systemctl is-enabled --quiet "$UNIT" 2>/dev/null; then
    systemctl restart "$UNIT" || true
  else
    resume_hint
  fi
  exit 0
fi

cat <<'MSG'
DranzoRMM agent installed. It is NOT enrolled yet and is not running.

  Enrol this computer (values from your IT provider's dashboard):
    sudo dranzo-agent install --server https://AGENT-SERVER --token dz_enroll_...

  Check:    sudo dranzo-agent status
  Remove:   sudo apt remove dranzo-agent    or    sudo dnf remove dranzo-agent
MSG
exit 0
