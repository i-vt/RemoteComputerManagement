#!/usr/bin/env bash
# tests/docker/scripts/test_11_builder_evasion_guardrails.sh
#
# Integration tests for the evasion technique selection and execution
# guardrail builder fields:
#
#   Evasion:
#     sleep_mask        "none" | "ekko" | "foliage"
#     indirect_syscalls bool
#     stack_spoof       bool
#     patch_amsi_etw    bool
#     heap_encrypt      bool
#
#   Execution guardrails:
#     guard_domain      glob string
#     guard_hostname    glob string
#     guard_hour_start  0-23
#     guard_hour_end    0-23
#     guard_no_system   bool
#
# Tests cover:
#   1. API accepts valid payloads for every new field combination
#   2. API rejects invalid values with 400
#   3. Omitting new fields preserves the existing default behaviour
#   4. Built artifacts exist when builds succeed
#   5. Job list and status endpoints reflect new builds
#
# Depends on: c2-server healthy, admin credentials in environment
# Uses: BUILD_TIMEOUT (default 180 s)

set -uo pipefail
source "$(dirname "$0")/lib.sh"

BUILD_TIMEOUT="${BUILD_TIMEOUT:-300}"

# ── Local helpers (mirrors test_10 conventions) ───────────────────────

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

wait_for_build() {
    local job_id="$1"
    local deadline=$(( $(date +%s) + BUILD_TIMEOUT ))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        local status_resp state
        status_resp=$(curl -sf \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/builder/jobs/${job_id}/status" 2>/dev/null || echo '{}')
        state=$(echo "$status_resp" | jq -r '.status // "unknown"')

        case "$state" in
            completed|done|success) echo "completed"; return 0 ;;
            failed|error)
                echo "--- builder log for $job_id ---" >&2
                echo "$status_resp" | jq -r '.log[] // empty' >&2
                echo "--- end builder log ---" >&2
                echo "failed"; return 1 ;;
        esac
        sleep 3
    done
    echo "timeout"; return 1
}

# Minimal valid payload — used by rejection tests that only change one field.
BASE_JSON='{"host":"c2-server","port":"4443","platform":"linux","transport":"tls","sleep":5,"jitter_min":0,"jitter_max":0,"debug":true}'

# ══════════════════════════════════════════════════════════════════════
suite "Evasion — all techniques explicitly enabled"
# ══════════════════════════════════════════════════════════════════════

RESP=$(start_build '{
    "host":"c2-server","port":"4443","platform":"linux","transport":"tls",
    "sleep":5,"jitter_min":0,"jitter_max":0,"debug":true,
    "sleep_mask":"ekko",
    "indirect_syscalls":true,
    "stack_spoof":true,
    "patch_amsi_etw":true,
    "heap_encrypt":true
}')
assert_http "all-evasion build accepted" "202"
JOB_ALL_ON=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned" "" "$JOB_ALL_ON"

if [ -n "$JOB_ALL_ON" ]; then
    assert_eq "all-evasion build completes" "completed" "$(wait_for_build "$JOB_ALL_ON")"
fi

# ══════════════════════════════════════════════════════════════════════
suite "Evasion — all techniques explicitly disabled"
# ══════════════════════════════════════════════════════════════════════

RESP=$(start_build '{
    "host":"c2-server","port":"4443","platform":"linux","transport":"tls",
    "sleep":5,"jitter_min":0,"jitter_max":0,"debug":true,
    "sleep_mask":"none",
    "indirect_syscalls":false,
    "stack_spoof":false,
    "patch_amsi_etw":false,
    "heap_encrypt":false
}')
assert_http "no-evasion build accepted" "202"
JOB_ALL_OFF=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned" "" "$JOB_ALL_OFF"

if [ -n "$JOB_ALL_OFF" ]; then
    assert_eq "no-evasion build completes" "completed" "$(wait_for_build "$JOB_ALL_OFF")"
fi

# ══════════════════════════════════════════════════════════════════════
suite "Evasion — sleep mask variants"
# ══════════════════════════════════════════════════════════════════════

for MASK in ekko foliage none; do
    RESP=$(start_build "$(echo "$BASE_JSON" | jq --arg m "$MASK" '. + {sleep_mask:$m}')")
    assert_http "sleep_mask=$MASK accepted" "202"
    JID=$(echo "$RESP" | jq -r '.job_id // empty')
    assert_ne "job_id returned for sleep_mask=$MASK" "" "$JID"
    if [ -n "$JID" ]; then
        assert_eq "sleep_mask=$MASK build completes" "completed" "$(wait_for_build "$JID")"
    fi
done

# ══════════════════════════════════════════════════════════════════════
suite "Evasion — invalid sleep_mask rejected"
# ══════════════════════════════════════════════════════════════════════

start_build "$(echo "$BASE_JSON" | jq '. + {sleep_mask:"custom"}')" > /dev/null
assert_http "sleep_mask=custom returns 400" "400"

start_build "$(echo "$BASE_JSON" | jq '. + {sleep_mask:""}')" > /dev/null
assert_http "sleep_mask empty string returns 400" "400"

start_build "$(echo "$BASE_JSON" | jq '. + {sleep_mask:"EKKO"}')" > /dev/null
assert_http "sleep_mask wrong case returns 400" "400"

# ══════════════════════════════════════════════════════════════════════
suite "Evasion — legacy payload without new fields still works"
# ══════════════════════════════════════════════════════════════════════
# Omitting the new fields must not break existing callers.

RESP=$(start_build "$BASE_JSON")
assert_http "payload without evasion fields accepted" "202"
JOB_LEGACY=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for legacy payload" "" "$JOB_LEGACY"

if [ -n "$JOB_LEGACY" ]; then
    assert_eq "legacy payload build completes" "completed" "$(wait_for_build "$JOB_LEGACY")"
fi

# ══════════════════════════════════════════════════════════════════════
suite "Guardrails — domain and hostname filters"
# ══════════════════════════════════════════════════════════════════════

RESP=$(start_build '{
    "host":"c2-server","port":"4443","platform":"linux","transport":"tls",
    "sleep":5,"jitter_min":0,"jitter_max":0,"debug":true,
    "guard_domain":"CORP*",
    "guard_hostname":"DESKTOP-*"
}')
assert_http "domain+hostname guardrail build accepted" "202"
JOB_NAMES=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned" "" "$JOB_NAMES"

if [ -n "$JOB_NAMES" ]; then
    assert_eq "domain+hostname build completes" "completed" "$(wait_for_build "$JOB_NAMES")"
fi

# ══════════════════════════════════════════════════════════════════════
suite "Guardrails — time window"
# ══════════════════════════════════════════════════════════════════════

RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:8,guard_hour_end:18}')")
assert_http "guard_hours 8-18 accepted" "202"
JOB_HOURS=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned" "" "$JOB_HOURS"

if [ -n "$JOB_HOURS" ]; then
    assert_eq "time-window build completes" "completed" "$(wait_for_build "$JOB_HOURS")"
fi

# Only start set — end defaults to 0
RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:9}')")
assert_http "guard_hour_start only accepted" "202"

# Only end set — start defaults to 0
RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_end:17}')")
assert_http "guard_hour_end only accepted" "202"

# Both zero — treated as all-day (no restriction), should accept
RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:0,guard_hour_end:0}')")
assert_http "guard_hours 0-0 (all-day) accepted" "202"

# ══════════════════════════════════════════════════════════════════════
suite "Guardrails — hour bounds validation"
# ══════════════════════════════════════════════════════════════════════

start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:24}')" > /dev/null
assert_http "guard_hour_start=24 returns 400" "400"

start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_end:24}')" > /dev/null
assert_http "guard_hour_end=24 returns 400" "400"

start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:255}')" > /dev/null
assert_http "guard_hour_start=255 returns 400" "400"

# Boundary values must pass
start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:23,guard_hour_end:23}')" > /dev/null
assert_http "guard_hours at boundary 23-23 accepted" "202"

start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:0,guard_hour_end:23}')" > /dev/null
assert_http "guard_hours full-day range 0-23 accepted" "202"

# ══════════════════════════════════════════════════════════════════════
suite "Guardrails — guard_no_system flag"
# ══════════════════════════════════════════════════════════════════════

RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_no_system:true}')")
assert_http "guard_no_system=true accepted" "202"
JOB_SYS=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned" "" "$JOB_SYS"

if [ -n "$JOB_SYS" ]; then
    assert_eq "guard_no_system build completes" "completed" "$(wait_for_build "$JOB_SYS")"
fi

start_build "$(echo "$BASE_JSON" | jq '. + {guard_no_system:false}')" > /dev/null
assert_http "guard_no_system=false accepted" "202"

# ══════════════════════════════════════════════════════════════════════
suite "Combined — full evasion + all guardrails"
# ══════════════════════════════════════════════════════════════════════

RESP=$(start_build '{
    "host":"c2-server","port":"4443","platform":"linux","transport":"tls",
    "sleep":5,"jitter_min":0,"jitter_max":0,"debug":true,
    "sleep_mask":"foliage",
    "indirect_syscalls":true,
    "stack_spoof":true,
    "patch_amsi_etw":true,
    "heap_encrypt":true,
    "guard_domain":"CORP*",
    "guard_hostname":"DESKTOP-*",
    "guard_hour_start":8,
    "guard_hour_end":18,
    "guard_no_system":true
}')
assert_http "full evasion+guardrails build accepted" "202"
JOB_FULL=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for full config" "" "$JOB_FULL"

if [ -n "$JOB_FULL" ]; then
    RESULT=$(wait_for_build "$JOB_FULL")
    assert_eq "full-config build completes" "completed" "$RESULT"
fi

# ══════════════════════════════════════════════════════════════════════
suite "Job status — completed build has artifact"
# ══════════════════════════════════════════════════════════════════════

if [ -n "${JOB_FULL:-}" ]; then
    STATUS=$(curl -sf \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        "${C2_URL}/api/builder/jobs/${JOB_FULL}/status" 2>/dev/null || echo '{}')
    assert_eq "status field is success" \
        "success" "$(echo "$STATUS" | jq -r '.status // empty')"
    assert_ne "artifact_name is present" \
        "" "$(echo "$STATUS" | jq -r '.artifact_name // empty')"
    assert_ne "started_at is present" \
        "" "$(echo "$STATUS" | jq -r '.started_at // empty')"
    assert_ne "finished_at is present" \
        "" "$(echo "$STATUS" | jq -r '.finished_at // empty')"
fi

# ══════════════════════════════════════════════════════════════════════
suite "Job status — unknown job returns 404"
# ══════════════════════════════════════════════════════════════════════

curl -s -w '\n%{http_code}' \
    -H "X-API-KEY: ${ADMIN_KEY}" \
    "${C2_URL}/api/builder/jobs/00000000-0000-0000-0000-000000000000/status" \
    > /tmp/.last_resp 2>/dev/null
code=$(tail -1 /tmp/.last_resp)
echo "$code" > /tmp/.last_http_code
assert_http "unknown job_id returns 404" "404"

# ══════════════════════════════════════════════════════════════════════
suite "Job list — includes builds from this run"
# ══════════════════════════════════════════════════════════════════════

JOBS=$(api_get "/api/builder/jobs")
assert_http "jobs list returns 200" "200"
COUNT=$(echo "$JOBS" | jq 'length // 0')
if [ "${COUNT:-0}" -gt 0 ]; then
    assert_eq "job list is non-empty" "true" "true"
else
    assert_eq "job list is non-empty" "true" "false"
fi

# Every entry must have the mandatory fields
MISSING=$(echo "$JOBS" | jq '[.[] | select(.job_id == null or .status == null or .started_at == null)] | length')
assert_eq "all job entries have required fields" "0" "$MISSING"

print_summary
