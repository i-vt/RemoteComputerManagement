#!/usr/bin/env bash
# tests/docker/scripts/test_06_audit.sh — Audit log & auto-recon config
source "$(dirname "$0")/lib.sh"

suite "Audit log is populated"
RESP=$(api_get "/api/audit")
assert_http "audit returns 200" "200"
COUNT=$(echo "$RESP" | jq 'length')
assert_ne "audit log is not empty" "0" "$COUNT"
echo "  ($COUNT audit entries)"

suite "Audit log contains login events"
HAS_LOGIN=$(echo "$RESP" | jq '[.[] | select(.action == "login")] | length')
assert_ne "at least one login event" "0" "$HAS_LOGIN"

suite "Auto-recon: add a command"
ADD_RESP=$(api_post "/api/config/recon" "$ADMIN_KEY" '{"command":"shell hostname"}')
assert_http "add recon returns 201" "201"
RECON_ID=$(echo "$ADD_RESP" | jq -r '.id // empty')

suite "Auto-recon: list commands"
LIST_RESP=$(api_get "/api/config/recon")
assert_http "list recon returns 200" "200"
assert_contains "our command is listed" "hostname" "$LIST_RESP"

suite "Auto-recon: delete a command"
if [ -n "$RECON_ID" ]; then
    api_delete "/api/config/recon/${RECON_ID}"
    assert_http "delete recon returns 200" "200"
else
    skip "no recon ID to delete"
fi

suite "Viewer cannot add auto-recon"
VW_KEY=$(login_as "testview" "$VIEWER_PASS")
if [ -n "$VW_KEY" ]; then
    api_post "/api/config/recon" "$VW_KEY" '{"command":"shell id"}'
    assert_http "viewer blocked from recon config" "403"
else
    skip "viewer login failed"
fi
