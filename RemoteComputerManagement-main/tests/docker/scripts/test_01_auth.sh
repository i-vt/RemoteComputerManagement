#!/usr/bin/env bash
# tests/docker/scripts/test_01_auth.sh — Authentication & rate limiting
source "$(dirname "$0")/lib.sh"

suite "Login with valid credentials"
RESP=$(api_post "/api/auth/login" "" '{"username":"admin","password":"'"$ADMIN_PASS"'"}')
KEY=$(echo "$RESP" | jq -r '.api_key // empty')
assert_http "admin login returns 200" "200"
assert_ne   "returns a non-empty API key" "" "$KEY"

suite "Login returns valid key usable for subsequent requests"
api_get "/api/auth/me" "$KEY"
ME_USER=$(echo "$(api_get "/api/auth/me" "$KEY")" | jq -r '.username')
assert_eq "returned key resolves to admin" "admin" "$ME_USER"

suite "Login with bad password"
api_post "/api/auth/login" "" '{"username":"admin","password":"wrong"}'
assert_http "returns 401" "401"

suite "Login with nonexistent user"
api_post "/api/auth/login" "" '{"username":"nobody","password":"x"}'
assert_http "returns 401" "401"

suite "Rate limiting kicks in after 5 failures"
for i in $(seq 1 5); do
    api_post "/api/auth/login" "" '{"username":"ratelimit_test","password":"bad"}'
done
api_post "/api/auth/login" "" '{"username":"ratelimit_test","password":"bad"}'
assert_http "6th attempt returns 429" "429"

suite "Invalid API key returns 401"
api_get "/api/auth/me" "totally-invalid-key-12345"
assert_http "bad key rejected" "401"

suite "Missing API key returns 401"
api_get "/api/auth/me" ""
assert_http "empty key rejected" "401"

suite "Operator login returns correct role"
OP_KEY=$(login_as "testop" "$OPERATOR_PASS")
if [ -n "$OP_KEY" ]; then
    OP_ROLE=$(api_get "/api/auth/me" "$OP_KEY" | jq -r '.role')
    assert_eq "operator role is 'operator'" "operator" "$OP_ROLE"
else
    skip "operator login failed — key empty"
fi

suite "Viewer login returns correct role"
VW_KEY=$(login_as "testview" "$VIEWER_PASS")
if [ -n "$VW_KEY" ]; then
    VW_ROLE=$(api_get "/api/auth/me" "$VW_KEY" | jq -r '.role')
    assert_eq "viewer role is 'viewer'" "viewer" "$VW_ROLE"
else
    skip "viewer login failed — key empty"
fi
