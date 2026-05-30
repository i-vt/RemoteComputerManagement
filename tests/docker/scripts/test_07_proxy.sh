#!/usr/bin/env bash
# tests/docker/scripts/test_07_proxy.sh — SOCKS proxy & reverse port forwarding
source "$(dirname "$0")/lib.sh"

# These tests require live agents
RESP=$(api_get "/api/hosts")
HOST_COUNT=$(echo "$RESP" | jq 'length')

if [ "$HOST_COUNT" -eq 0 ]; then
    suite "Proxy tests (no agents)"
    skip "No agents connected — skipping proxy/rportfwd tests"
    return 0 2>/dev/null || exit 0
fi

SESSION_ID=$(echo "$RESP" | jq -r '.[0].id')

# ── SOCKS Proxy ─────────────────────────────────────────────────────────

suite "Start SOCKS proxy"
PROXY_RESP=$(api_post "/api/hosts/${SESSION_ID}/proxy")
assert_http "proxy start returns 200" "200"
SOCKS_PORT=$(echo "$PROXY_RESP" | jq -r '.socks_port // empty')
echo "  (socks_port=$SOCKS_PORT)"

suite "List proxies"
api_get "/api/proxies"
assert_http "proxy list returns 200" "200"
PROXY_COUNT=$(echo "$(api_get "/api/proxies")" | jq 'length')
assert_ne "proxy list not empty" "0" "$PROXY_COUNT"

suite "Stop SOCKS proxy"
api_delete "/api/hosts/${SESSION_ID}/proxy"
assert_http "proxy stop returns 200" "200"

# ── Reverse Port Forwarding ─────────────────────────────────────────────

suite "Start reverse port forward"
RPORTFWD_RESP=$(api_post "/api/hosts/${SESSION_ID}/rportfwd" "$ADMIN_KEY" \
    '{"bind_port":18080,"target_host":"mock-service","target_port":80}')
assert_http "rportfwd start returns 200" "200"

suite "List reverse port forwards"
RLIST=$(api_get "/api/rportfwds")
assert_http "rportfwd list returns 200" "200"
RFWD_COUNT=$(echo "$RLIST" | jq 'length')
assert_ne "rportfwd list not empty" "0" "$RFWD_COUNT"

suite "Rportfwd tunnels traffic to mock service"
# Give the tunnel a moment to establish
sleep 3
# Try to reach the mock service through the rportfwd
MOCK_RESP=$(curl -sf --max-time 5 http://c2-server:18080/ 2>/dev/null || echo "CONNECT_FAILED")
if echo "$MOCK_RESP" | grep -qF "MOCK_SERVICE_OK"; then
    echo "  ✓ rportfwd delivers mock-service content through tunnel"
    PASS_COUNT=$((PASS_COUNT + 1))
elif echo "$MOCK_RESP" | grep -qF "CONNECT_FAILED"; then
    echo "  ✗ rportfwd connection failed (tunnel may not be established)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  ✗ rportfwd returned unexpected content: $(echo "$MOCK_RESP" | head -1)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

suite "Stop reverse port forward"
api_delete "/api/hosts/${SESSION_ID}/rportfwd" "$ADMIN_KEY" '{"bind_port":18080}'
assert_http "rportfwd stop returns 200" "200"

# ── RBAC on proxy endpoints ─────────────────────────────────────────────

suite "Viewer cannot start proxy"
VW_KEY=$(login_as "testview" "$VIEWER_PASS")
if [ -n "$VW_KEY" ]; then
    api_post "/api/hosts/${SESSION_ID}/proxy" "$VW_KEY"
    assert_http "viewer blocked from starting proxy" "403"
else
    skip "viewer login failed"
fi
