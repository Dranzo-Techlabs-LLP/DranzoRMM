#!/usr/bin/env bash
# Starts a development server reachable from other machines on the LAN (for testing agents on VMs).
# Development only: dashboard on http://<ip>:8080 (sign-in still needs password + TOTP), agent gateway on
# https://<ip>:8443 with a certificate issued for <ip>. Keys and storage live in a throwaway directory.
#
#   DRANZO_ADMIN_PASSWORD='...' scripts/lan-test-server.sh [ip] [state-dir]
set -euo pipefail
IP="${1:-$(ipconfig getifaddr en0 2>/dev/null || hostname -I | awk '{print $1}')}"
STATE="${2:-$HOME/.dranzormm-lan-test}"
DB="${DRANZO_LAN_DB:-dranzo_lan_test}"
: "${DRANZO_ADMIN_PASSWORD:?set DRANZO_ADMIN_PASSWORD (12+ characters)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$STATE" && chmod 700 "$STATE"
createdb "$DB" 2>/dev/null || true
cd "$ROOT/server"
dotnet build src/Dranzo.Api -v q >/dev/null
# Serve the dashboard from the same address (build it first: cd web && npm run build).
if [ -f "$ROOT/web/dist/index.html" ]; then
    rm -rf src/Dranzo.Api/bin/Debug/net10.0/wwwroot && cp -R "$ROOT/web/dist" src/Dranzo.Api/bin/Debug/net10.0/wwwroot
fi
export ASPNETCORE_ENVIRONMENT=Development
export ConnectionStrings__Default="Host=localhost;Database=$DB"
export Dranzo__Bootstrap__AdminEmail="${DRANZO_ADMIN_EMAIL:-admin@example.test}"
export Dranzo__Bootstrap__AdminPassword="$DRANZO_ADMIN_PASSWORD"
export Dranzo__AgentHostnames__0="$IP" Dranzo__AgentHostnames__1=localhost Dranzo__AgentHostnames__2=127.0.0.1
export Dranzo__PublicAgentUrl="https://$IP:8443"
export Dranzo__KeyStore__Directory="$STATE/keys" Dranzo__Storage__Directory="$STATE/storage"
# Logs every request, so connection attempts from test machines are visible in server.log.
(cd src/Dranzo.Api/bin/Debug/net10.0 && exec nohup env "Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics=Information" dotnet Dranzo.Api.dll > "$STATE/server.log" 2>&1) &
echo $! > "$STATE/server.pid"
for _ in $(seq 1 60); do
    curl -fsS "http://localhost:8080/healthz" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsSk "https://$IP:8443/agent/v1/healthz" >/dev/null
echo "Server running (pid $(cat "$STATE/server.pid")): dashboard http://$IP:8080, agents https://$IP:8443, log $STATE/server.log"
echo "Stop: kill \$(cat $STATE/server.pid)"
