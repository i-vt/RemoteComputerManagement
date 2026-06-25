#!/usr/bin/env bash
# tests/docker/scripts/test_02_rbac.sh — Role-based access control
source "$(dirname "$0")/lib.sh"

# Get keys for each role
ADMIN_K="$ADMIN_KEY"
OP_KEY=$(login_as "testop" "$OPERATOR_PASS")
VW_KEY=$(login_as "testview" "$VIEWER_PASS")

# ── Viewer restrictions ─────────────────────────────────────────────────

suite "Viewer cannot list operators (admin-only)"
api_get "/api/operators" "$VW_KEY"
assert_http "viewer gets 403 on operator list" "403"

suite "Viewer cannot create operators"
api_post "/api/operators" "$VW_KEY" '{"username":"hack","password":"hack","role":"admin"}'
assert_http "viewer gets 403 on create operator" "403"

suite "Viewer cannot broadcast commands"
api_post "/api/broadcast" "$VW_KEY" '{"command":"whoami"}'
assert_http "viewer gets 403 on broadcast" "403"

suite "Viewer cannot broadcast modules"
api_post "/api/broadcast/module" "$VW_KEY" '{"module_name":"test"}'
# Should be 403 (forbidden) not 404 (module not found)
VIEWER_MOD_CODE="$HTTP_CODE"
if [ "$VIEWER_MOD_CODE" = "403" ]; then
    echo "  ✓ viewer gets 403 on broadcast module"
    PASS_COUNT=$((PASS_COUNT + 1))
elif [ "$VIEWER_MOD_CODE" = "404" ]; then
    echo "  ✗ viewer gets 404 (module check runs before auth check)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  ✗ viewer gets $VIEWER_MOD_CODE (expected 403)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

suite "Viewer can read host list (read-only is allowed)"
api_get "/api/hosts" "$VW_KEY"
assert_http "viewer can list hosts" "200"

suite "Viewer can read audit log"
api_get "/api/audit" "$VW_KEY"
assert_http "viewer can read audit" "200"

# ── Operator permissions ────────────────────────────────────────────────

suite "Operator cannot create other operators (admin-only)"
api_post "/api/operators" "$OP_KEY" '{"username":"hack2","password":"hack","role":"operator"}'
assert_http "operator gets 403 on create operator" "403"

suite "Operator can broadcast commands"
api_post "/api/broadcast" "$OP_KEY" '{"command":"echo test"}'
# Should succeed (200) — operators can execute
assert_http "operator can broadcast" "200"

suite "Operator can list listeners"
api_get "/api/listeners" "$OP_KEY"
assert_http "operator can list listeners" "200"

# ── Admin permissions ───────────────────────────────────────────────────

suite "Admin can list operators"
RESP=$(api_get "/api/operators" "$ADMIN_K")
assert_http "admin can list operators" "200"
OP_COUNT=$(echo "$RESP" | jq 'length')
assert_ne "operator list is not empty" "0" "$OP_COUNT"

suite "Admin can create and delete operators"
CREATE_RESP=$(api_post "/api/operators" "$ADMIN_K" '{"username":"temp_user","password":"Temp123!","role":"viewer"}')
assert_http "admin can create operator" "201"
TEMP_ID=$(echo "$CREATE_RESP" | jq -r '.id // empty')
if [ -n "$TEMP_ID" ]; then
    api_delete "/api/operators/${TEMP_ID}" "$ADMIN_K"
    assert_http "admin can delete operator" "200"
else
    skip "could not get temp operator ID for deletion test"
fi

suite "Admin can manage listeners"
api_post "/api/listeners" "$ADMIN_K" '{"name":"rbac-test","port":19999,"transport":"tcp_plain"}'
assert_http "admin can create listener" "201"

suite "Operator cannot create listeners (admin-only)"
api_post "/api/listeners" "$OP_KEY" '{"name":"rbac-hack","port":19998,"transport":"tcp_plain"}'
assert_http "operator gets 403 on create listener" "403"
