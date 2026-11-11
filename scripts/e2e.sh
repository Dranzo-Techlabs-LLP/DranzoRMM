#!/usr/bin/env bash
# Brings up the compose stack and runs the end-to-end test against it. Used by CI and locally.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DRANZO_ADMIN_EMAIL="${DRANZO_ADMIN_EMAIL:-admin@example.test}"
export DRANZO_ADMIN_PASSWORD="${DRANZO_ADMIN_PASSWORD:?set DRANZO_ADMIN_PASSWORD}"
export DRANZO_HEARTBEAT_SECONDS="${DRANZO_HEARTBEAT_SECONDS:-15}"
docker compose -f "$ROOT/deploy/docker-compose.yml" up -d --build postgres minio server web
exec python3 "$ROOT/scripts/e2e.py" --dashboard "${DRANZO_DASHBOARD_URL:-http://localhost:8081}" --agent compose "$@"
