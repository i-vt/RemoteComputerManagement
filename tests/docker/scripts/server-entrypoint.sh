#!/bin/bash
# tests/docker/scripts/server-entrypoint.sh
#
# Entrypoint for the C2 server container. Starts the server, creates
# test operators, copies pre-built agents to the shared volume, and
# writes credentials for the test runner.

set -euo pipefail

echo "[server] Starting RCM team server..."

# Export Cargo.lock so it can be committed to the repo
cp /opt/rcm/Cargo.lock /shared/Cargo.lock 2>/dev/null || true

# Copy pre-built agent binaries to shared volume (compiled during Docker build)
cp /opt/rcm/agent-tls  /shared/agent-tls  2>/dev/null && chmod +x /shared/agent-tls  && echo "[server] TLS agent ready on shared volume"  || echo "[server] WARN: no pre-built TLS agent"
cp /opt/rcm/agent-http /shared/agent-http 2>/dev/null && chmod +x /shared/agent-http && echo "[server] HTTP agent ready on shared volume" || echo "[server] WARN: no pre-built HTTP agent"
cp /opt/rcm/agent-tls.exe  /shared/agent-tls.exe  2>/dev/null && echo "[server] Windows TLS agent ready on shared volume"  || echo "[server] WARN: no pre-built Windows TLS agent"
cp /opt/rcm/agent-http.exe /shared/agent-http.exe 2>/dev/null && echo "[server] Windows HTTP agent ready on shared volume" || echo "[server] WARN: no pre-built Windows HTTP agent"

# Copy pivot agents if they were built
if [ -d /opt/rcm/pivot-agents ] && ls /opt/rcm/pivot-agents/c0h* 1>/dev/null 2>&1; then
    cp /opt/rcm/pivot-agents/* /shared/ 2>/dev/null || true
    chmod +x /shared/c*h* 2>/dev/null || true
    echo "[server] Pivot agents ready on shared volume ($(ls /opt/rcm/pivot-agents/ | grep -v '\.empty' | wc -l) binaries)"
fi

# ── Start the server in the background and capture first-run output ─────
./server 2>&1 | tee /tmp/server.log &
SERVER_PID=$!

# Wait for the API to become ready
echo "[server] Waiting for API on :8080..."
for i in $(seq 1 60); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/api/auth/login \
        -X POST -H "Content-Type: application/json" \
        -d '{"username":"probe","password":"probe"}' 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
        echo "[server] API is ready (HTTP $STATUS)."
        break
    fi
    sleep 1
done

# ── Extract bootstrap credentials from server output ────────────────
ADMIN_PASS=$(grep "Password:" /tmp/server.log | head -1 | awk '{print $NF}')

if [ -z "$ADMIN_PASS" ]; then
    echo "[server] FATAL: Could not extract admin password from server output."
    echo "[server] Last 20 lines of server log:"
    tail -20 /tmp/server.log
    exit 1
fi

# Log in to get a fresh raw API key
LOGIN_RESP=$(curl -sf http://127.0.0.1:8080/api/auth/login \
    -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null || echo '{}')

ADMIN_KEY=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
if [ -z "$ADMIN_KEY" ]; then
    echo "[server] FATAL: Login failed — could not get API key."
    exit 1
fi

echo "[server] Admin password: ${ADMIN_PASS}"
echo "[server] Admin API key:  ${ADMIN_KEY}"

# ── Create test operators with different roles ──────────────────────────
echo "[server] Creating test operators..."

curl -sf http://127.0.0.1:8080/api/operators \
    -X POST -H "Content-Type: application/json" \
    -H "X-API-KEY: ${ADMIN_KEY}" \
    -d '{"username":"testop","password":"TestOp123!","role":"operator"}' \
    -o /dev/null 2>/dev/null || true

curl -sf http://127.0.0.1:8080/api/operators \
    -X POST -H "Content-Type: application/json" \
    -H "X-API-KEY: ${ADMIN_KEY}" \
    -d '{"username":"testview","password":"TestView123!","role":"viewer"}' \
    -o /dev/null 2>/dev/null || true

# ── Create an HTTP listener for the HTTP-transport agent ────────────────
echo "[server] Creating HTTP listener on port 4480..."
curl -sf http://127.0.0.1:8080/api/listeners \
    -X POST -H "Content-Type: application/json" \
    -H "X-API-KEY: ${ADMIN_KEY}" \
    -d '{"name":"http-test","port":4480,"transport":"http"}' \
    -o /dev/null 2>/dev/null || true

# ── Write credentials to shared volume ──────────────────────────────────
cat > /shared/admin_creds.json <<EOF
{
  "admin_password": "${ADMIN_PASS}",
  "admin_api_key": "${ADMIN_KEY}",
  "operator_password": "TestOp123!",
  "viewer_password": "TestView123!",
  "c2_url": "http://c2-server:8080"
}
EOF

echo "[server] Credentials written to /shared/admin_creds.json"
echo "[server] Ready. Waiting for connections..."

# ── Keep the server running ─────────────────────────────────────────────
wait $SERVER_PID
