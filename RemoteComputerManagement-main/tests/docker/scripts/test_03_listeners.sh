#!/usr/bin/env bash
# tests/docker/scripts/test_03_listeners.sh — Listener management
source "$(dirname "$0")/lib.sh"

suite "List listeners"
RESP=$(api_get "/api/listeners")
assert_http "list returns 200" "200"
COUNT=$(echo "$RESP" | jq 'length')
echo "  (found $COUNT listeners)"

suite "Create a TCP listener"
RESP=$(api_post "/api/listeners" "$ADMIN_KEY" '{"name":"test-tcp","port":15000,"transport":"tcp_plain"}')
assert_http "create returns 201" "201"
NEW_ID=$(echo "$RESP" | jq -r '.id // empty')
echo "  (created listener id=$NEW_ID)"

suite "Reject privileged port"
api_post "/api/listeners" "$ADMIN_KEY" '{"name":"priv","port":443,"transport":"tls"}'
assert_http "port 443 rejected with 400" "400"

suite "Reject port 0"
api_post "/api/listeners" "$ADMIN_KEY" '{"name":"zero","port":0,"transport":"tls"}'
assert_http "port 0 rejected with 400" "400"

suite "Reject API port"
api_post "/api/listeners" "$ADMIN_KEY" '{"name":"api","port":8080,"transport":"tcp_plain"}'
assert_http "port 8080 rejected with 400" "400"

suite "Reject duplicate port"
api_post "/api/listeners" "$ADMIN_KEY" '{"name":"dup","port":15000,"transport":"tcp_plain"}'
assert_http "duplicate port rejected with 409" "409"

suite "Stop a listener"
if [ -n "$NEW_ID" ]; then
    api_post "/api/listeners/${NEW_ID}/stop" "$ADMIN_KEY"
    assert_http "stop returns 200" "200"
else
    skip "no listener ID to stop"
fi

suite "Delete a listener"
if [ -n "$NEW_ID" ]; then
    api_delete "/api/listeners/${NEW_ID}" "$ADMIN_KEY"
    assert_http "delete returns 200" "200"
else
    skip "no listener ID to delete"
fi
