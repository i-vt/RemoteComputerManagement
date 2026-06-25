#!/usr/bin/env bash
# tests/docker/scripts/test_10_builder_features.sh
#
# Integration tests for the three new builder feature flags:
#   --sni <hostname>        TLS ClientHello SNI override
#   --alpn <protocols>      ALPN protocol list
#   --hibernation           Build in hibernation mode
#   --batch-size <n>        Tasks per hibernation check-in
#
# These tests submit build jobs via /api/builder/build and verify:
#   1. The new fields are accepted (not rejected with 400)
#   2. Build jobs complete without errors
#   3. Agents built with --hibernation actually operate differently
#      (verified in test_12_hibernation.sh after a built agent connects)
#
# Depends on: c2-server healthy, admin credentials in /shared/admin_creds.json
#
# NOTE: Build jobs are async. Each test starts a job, polls status, and
# allows up to $BUILD_TIMEOUT seconds for completion.

set -uo pipefail
source "$(dirname "$0")/lib.sh"

BUILD_TIMEOUT="${BUILD_TIMEOUT:-180}"  # seconds to wait for each build

# ── Helper: start a build and return the job ID ────────────────────────────
start_build() {
    local payload="$1"
    local resp
    resp=$(curl -s -w '\n%{http_code}' \
        -X POST "${C2_URL}/api/builder/build" \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)
    local code
    code=$(echo "$resp" | tail -1)
    echo "$code" > /tmp/.last_http_code
    echo "$resp" | sed '$d'
}

# ── Helper: poll job status until done or timeout ──────────────────────────
wait_for_build() {
    local job_id="$1"
    local deadline=$(($(date +%s) + BUILD_TIMEOUT))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        local status_resp
        status_resp=$(curl -sf \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/builder/jobs/${job_id}/status" 2>/dev/null || echo '{}')
        local state
        state=$(echo "$status_resp" | jq -r '.status // "unknown"')

        case "$state" in
            completed|done|success)
                echo "completed"
                return 0
                ;;
            failed|error)
                echo "failed"
                return 1
                ;;
        esac
        sleep 3
    done
    echo "timeout"
    return 1
}

# ══════════════════════════════════════════════════════
suite "Builder accepts SNI override flag"
# ══════════════════════════════════════════════════════

RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "linux",
    "transport": "tls",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true,
    "sni_override": "cdn.cloudflare.com"
}')
assert_http "SNI build request accepted" "202"

JOB_SNI=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for SNI build" "" "$JOB_SNI"

if [ -n "$JOB_SNI" ]; then
    SNI_RESULT=$(wait_for_build "$JOB_SNI")
    assert_eq "SNI build completes successfully" "completed" "$SNI_RESULT"
fi

# ══════════════════════════════════════════════════════
suite "Builder accepts ALPN protocols flag"
# ══════════════════════════════════════════════════════

RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "linux",
    "transport": "tls",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true,
    "alpn_protocols": ["http/1.1"]
}')
assert_http "ALPN build request accepted" "202"

JOB_ALPN=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for ALPN build" "" "$JOB_ALPN"

if [ -n "$JOB_ALPN" ]; then
    ALPN_RESULT=$(wait_for_build "$JOB_ALPN")
    assert_eq "ALPN build completes successfully" "completed" "$ALPN_RESULT"
fi

# ══════════════════════════════════════════════════════
suite "Builder accepts SNI + ALPN together"
# ══════════════════════════════════════════════════════

RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "linux",
    "transport": "tls",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true,
    "sni_override": "s3.amazonaws.com",
    "alpn_protocols": ["h2", "http/1.1"]
}')
assert_http "combined SNI+ALPN build accepted" "202"

JOB_COMBO=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for combined build" "" "$JOB_COMBO"

if [ -n "$JOB_COMBO" ]; then
    COMBO_RESULT=$(wait_for_build "$JOB_COMBO")
    assert_eq "combined SNI+ALPN build completes" "completed" "$COMBO_RESULT"
fi

# ══════════════════════════════════════════════════════
suite "Builder accepts hibernation mode flag"
# ══════════════════════════════════════════════════════

RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "linux",
    "transport": "tls",
    "sleep": 10,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true,
    "hibernation_mode": true,
    "task_batch_size": 5
}')
assert_http "hibernation build request accepted" "202"

JOB_HIB=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for hibernation build" "" "$JOB_HIB"

if [ -n "$JOB_HIB" ]; then
    HIB_RESULT=$(wait_for_build "$JOB_HIB")
    assert_eq "hibernation build completes successfully" "completed" "$HIB_RESULT"

    # Persist the job ID so test_12_hibernation.sh can download and run the agent.
    echo "$JOB_HIB" > /shared/hibernation_agent_job_id
fi

# ══════════════════════════════════════════════════════
suite "Empty SNI override is treated as no-override"
# ══════════════════════════════════════════════════════
# An empty sni_override should be accepted and treated as using c2_host.
RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "linux",
    "transport": "tls",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true,
    "sni_override": ""
}')
assert_http "empty SNI override accepted" "202"

# ══════════════════════════════════════════════════════
suite "Builder validates batch_size > 0"
# ══════════════════════════════════════════════════════
# batch_size = 0 should either be rejected or clamped to 1.
RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "linux",
    "transport": "tls",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": true,
    "hibernation_mode": true,
    "task_batch_size": 0
}')
# Either 400 (validation) or 202 (clamped to 1) are acceptable.
HTTP_GOT=$(cat /tmp/.last_http_code 2>/dev/null || echo "000")
if [ "$HTTP_GOT" = "400" ] || [ "$HTTP_GOT" = "202" ]; then
    echo "  ✓ batch_size=0 handled correctly (HTTP $HTTP_GOT)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ batch_size=0 returned unexpected HTTP $HTTP_GOT"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ══════════════════════════════════════════════════════
suite "Build job list includes new jobs"
# ══════════════════════════════════════════════════════
JOBS_RESP=$(api_get "/api/builder/jobs")
assert_http "jobs list returns 200" "200"
JOB_COUNT=$(echo "$JOBS_RESP" | jq 'length // 0')
echo "  (found $JOB_COUNT build jobs)"
# We submitted at least 5 jobs above; list should be non-empty
if [ "$JOB_COUNT" -gt 0 ]; then
    echo "  ✓ build job list is non-empty"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ build job list is empty (expected >= 1)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

print_summary
