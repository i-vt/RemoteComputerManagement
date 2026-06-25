#!/usr/bin/env bash
# tests/docker/scripts/lib.sh — Shared test helpers
#
# Source this from every test_*.sh file:
#   source "$(dirname "$0")/lib.sh"

set -euo pipefail

# ── Globals ─────────────────────────────────────────────────────────────
C2_URL="${C2_URL:-http://c2-server:8080}"
CREDS_FILE="/shared/admin_creds.json"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CURRENT_SUITE=""
HTTP_CODE=""

# ── Load credentials ────────────────────────────────────────────────────
load_creds() {
    if [ ! -f "$CREDS_FILE" ]; then
        echo "FATAL: $CREDS_FILE not found" >&2
        exit 1
    fi
    ADMIN_KEY=$(jq -r '.admin_api_key' "$CREDS_FILE")
    ADMIN_PASS=$(jq -r '.admin_password' "$CREDS_FILE")
    OPERATOR_PASS=$(jq -r '.operator_password' "$CREDS_FILE")
    VIEWER_PASS=$(jq -r '.viewer_password' "$CREDS_FILE")
    export ADMIN_KEY ADMIN_PASS OPERATOR_PASS VIEWER_PASS
}

# ── API helpers ─────────────────────────────────────────────────────────

# Generic API call. Returns body on stdout; sets $HTTP_CODE.
api() {
    local method="$1" path="$2" key="${3:-$ADMIN_KEY}"
    shift 2; [ $# -gt 0 ] && shift  # consume key if provided
    local body="${1:-}"

    local args=(-s -w '\n%{http_code}' -X "$method" -H "X-API-KEY: $key")
    [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")

    local raw
    raw=$(curl "${args[@]}" "${C2_URL}${path}" 2>/dev/null) || true
    HTTP_CODE=$(echo "$raw" | tail -1)
    # Persist HTTP_CODE so it survives when api() runs inside $() subshells
    echo "$HTTP_CODE" > /tmp/.last_http_code
    echo "$raw" | sed '$d'
}

# Shorthand wrappers
api_get()    { api GET  "$1" "${2:-$ADMIN_KEY}"; }
api_post()   { api POST "$1" "${2:-$ADMIN_KEY}" "${3:-}"; }
api_delete() { api DELETE "$1" "${2:-$ADMIN_KEY}" "${3:-}"; }

# Login and return the API key
login_as() {
    local user="$1" pass="$2"
    local resp
    resp=$(curl -s -X POST "${C2_URL}/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}")
    echo "$resp" | jq -r '.api_key // empty'
}

# ── Readiness helpers ───────────────────────────────────────────────────

# Poll the /api/hosts endpoint until at least $expected agents are connected.
# Usage: wait_agents <expected_count> [timeout_secs]
# Returns 0 on success, 1 on timeout.
wait_agents() {
    local expected="${1:-1}" timeout="${2:-60}"
    echo "  Waiting for $expected agent(s) (timeout ${timeout}s)..."
    for i in $(seq 1 "$timeout"); do
        local count
        count=$(curl -sf -H "X-API-KEY: $ADMIN_KEY" "${C2_URL}/api/hosts" 2>/dev/null \
            | jq 'length' 2>/dev/null || echo "0")
        if [ "$count" -ge "$expected" ]; then
            echo "  $count agent(s) connected after ${i}s."
            return 0
        fi
        sleep 1
    done
    local final
    final=$(curl -sf -H "X-API-KEY: $ADMIN_KEY" "${C2_URL}/api/hosts" 2>/dev/null \
        | jq 'length' 2>/dev/null || echo "0")
    echo "  Timeout: only $final/$expected agent(s) after ${timeout}s."
    return 1
}

# ── Assertions ──────────────────────────────────────────────────────────

suite() {
    CURRENT_SUITE="$1"
    echo ""
    echo "━━━ $1 ━━━"
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  ✓ $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ $desc"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_ne() {
    local desc="$1" unexpected="$2" actual="$3"
    if [ "$unexpected" != "$actual" ]; then
        echo "  ✓ $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ $desc  (got '$actual', expected anything else)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        echo "  ✓ $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ $desc"
        echo "    expected to contain: $needle"
        echo "    got: $(echo "$haystack" | head -3)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_http() {
    local desc="$1" expected_code="$2"
    local code
    code=$(cat /tmp/.last_http_code 2>/dev/null || echo "${HTTP_CODE:-000}")
    if [ "$code" = "$expected_code" ]; then
        echo "  ✓ $desc (HTTP $code)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ $desc (expected HTTP $expected_code, got $code)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

skip() {
    echo "  ⊘ $1 (skipped)"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# ── Summary ─────────────────────────────────────────────────────────────
print_summary() {
    local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  Results: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped ($total total)"
    echo "═══════════════════════════════════════════"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        return 1
    fi
    return 0
}

# Auto-load credentials when sourced
load_creds
# The stored API key may have been rotated by a previous test's login call
# (every successful login regenerates the key). Get a fresh one.
_fresh_key=$(login_as "admin" "$ADMIN_PASS" 2>/dev/null)
if [ -n "$_fresh_key" ]; then
    ADMIN_KEY="$_fresh_key"
    export ADMIN_KEY
fi
