#!/usr/bin/env bash
# tests/docker/scripts/test_05_webhook.sh — Webhook configuration & SSRF
source "$(dirname "$0")/lib.sh"

suite "Set a valid webhook URL"
WEBHOOK_URL="${WEBHOOK_URL:-http://webhook-sink:9999/hook}"
api_post "/api/config/webhook" "$ADMIN_KEY" "{\"url\":\"${WEBHOOK_URL}\"}"
assert_http "setting webhook returns 200" "200"

suite "Get webhook URL"
RESP=$(api_get "/api/config/webhook")
assert_http "get webhook returns 200" "200"
GOT_URL=$(echo "$RESP" | jq -r '.webhook_url')
assert_eq "stored URL matches" "$WEBHOOK_URL" "$GOT_URL"

suite "Clear webhook"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":""}'
assert_http "clearing webhook returns 200" "200"

# ── SSRF prevention ─────────────────────────────────────────────────────

suite "Reject localhost webhook"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"http://localhost:1234/hook"}'
assert_http "localhost rejected" "400"

suite "Reject 127.0.0.1 webhook"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"http://127.0.0.1:1234/hook"}'
assert_http "loopback IP rejected" "400"

suite "Reject metadata endpoint"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"http://metadata.google.internal/computeMetadata/v1/"}'
assert_http "cloud metadata rejected" "400"

suite "Reject .internal domain"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"http://evil.internal:8080/hook"}'
assert_http ".internal domain rejected" "400"

suite "Reject .local domain"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"http://myserver.local/hook"}'
assert_http ".local domain rejected" "400"

suite "Reject .corp domain"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"http://intranet.corp/hook"}'
assert_http ".corp domain rejected" "400"

suite "Reject non-HTTP scheme"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"ftp://files.example.com/hook"}'
assert_http "ftp scheme rejected" "400"

suite "Reject URL without host"
api_post "/api/config/webhook" "$ADMIN_KEY" '{"url":"http://"}'
assert_http "empty host rejected" "400"

suite "Non-admin cannot set webhook"
OP_KEY=$(login_as "testop" "$OPERATOR_PASS")
if [ -n "$OP_KEY" ]; then
    api_post "/api/config/webhook" "$OP_KEY" '{"url":"http://example.com/hook"}'
    assert_http "operator cannot set webhook" "403"
else
    skip "operator login failed"
fi
