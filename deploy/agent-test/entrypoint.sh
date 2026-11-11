#!/bin/sh
# Enrolls on first start (token from DRANZO_ENROLL_TOKEN, trust anchors from the shared /trust volume),
# then runs the agent in the foreground.
set -eu
DATA=/var/lib/dranzormm
mkdir -p "$DATA"
chmod 0700 "$DATA"
if [ ! -f "$DATA/device.crt" ]; then
    : "${DRANZO_SERVER_URL:?set DRANZO_SERVER_URL}"
    : "${DRANZO_ENROLL_TOKEN:?set DRANZO_ENROLL_TOKEN (create one in the dashboard: Enrollment)}"
    for i in $(seq 1 60); do
        [ -s /trust/ca.pem ] && [ -s /trust/trust.json ] && break
        echo "waiting for the server to publish its trust anchors..." >&2
        sleep 1
    done
    cp /trust/ca.pem "$DATA/ca.pem"
    cp /trust/trust.json "$DATA/trust.json"
    umask 077
    printf '{"serverUrl":"%s","token":"%s"}\n' "$DRANZO_SERVER_URL" "$DRANZO_ENROLL_TOKEN" > "$DATA/bootstrap.json"
    chmod 0600 "$DATA"/*
fi
unset DRANZO_ENROLL_TOKEN
exec /usr/local/bin/dranzo-agent run --foreground --data-dir "$DATA"
