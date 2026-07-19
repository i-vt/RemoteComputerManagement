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
# Test design (rewritten for decisiveness — see notes at bottom):
#
#   Phase 0  Pre-flight: wait until no builds are RUNNING (leftovers from
#            earlier suites would otherwise starve the awaited build).
#   Phase 1  Exactly ONE end-to-end build is awaited (full evasion +
#            guardrails). This is the only assertion that depends on the
#            compiler, and it runs before this script spawns any other
#            build, so its duration is deterministic.
#   Phase 2  Validation matrix: every 400/202 case is asserted WITHOUT
#            waiting for compilation. Validation is synchronous in the
#            API (validate_request runs before the job is spawned), so
#            these checks are instant and deterministic.
#   Phase 3  Job list invariants.
#   Phase 4  Drain: wait for the fire-and-forget builds spawned in
#            Phase 2 to leave the running state, so this suite does not
#            leak cargo builds into test_12+. Their outcomes are not
#            asserted (they duplicate Phase 1 coverage); a drain timeout
#            is reported as a skip, not a failure.
#
# Depends on: c2-server healthy, admin credentials in environment
# Uses: BUILD_TIMEOUT (default 300 s — budget for the single awaited build)
#       DRAIN_TIMEOUT (default 600 s — budget for phases 0 and 4)

set -uo pipefail
source "$(dirname "$0")/lib.sh"

BUILD_TIMEOUT="${BUILD_TIMEOUT:-300}"
DRAIN_TIMEOUT="${DRAIN_TIMEOUT:-600}"
POLL_INTERVAL=2

# ── Local helpers ───────────────────────────────────────────────────────

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

# Decisive build waiter.
#
#   - ALWAYS returns 0, so `RESULT=$(wait_for_build ...)` can never trip
#     the `set -e` inherited from lib.sh and silently abort the suite.
#   - Echoes exactly one token on stdout: success | failed | timeout
#   - Matches the server's actual status vocabulary (BuildStatus enum:
#     running | success | failed). Accepting "completed"/"done" only
#     masked API drift; an unknown status now fails immediately with a
#     clear message instead of polling until timeout.
#   - 'failed' is terminal: fail fast and print the log tail instead of
#     burning the whole BUILD_TIMEOUT.
wait_for_build() {
    local job_id="$1"
    local deadline=$(( $(date +%s) + BUILD_TIMEOUT ))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        local status_resp state
        status_resp=$(curl -sf \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/builder/jobs/${job_id}/status" 2>/dev/null || echo '{}')
        state=$(echo "$status_resp" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")

        case "$state" in
            success)
                echo "success"; return 0 ;;
            running)
                ;; # expected while compiling — keep polling
            failed)
                echo "--- builder log for $job_id (last 40 lines) ---" >&2
                echo "$status_resp" | jq -r '.log[-40:][]? // empty' 2>/dev/null >&2
                echo "--- end builder log ---" >&2
                echo "failed"; return 0 ;;
            *)
                echo "job $job_id returned unexpected status '$state' — API contract drift" >&2
                echo "failed"; return 0 ;;
        esac
        sleep "$POLL_INTERVAL"
    done
    echo "timeout"; return 0
}

# Wait until no build job is in the running state.
# Echoes "idle" or "busy"; always returns 0.
wait_for_quiescence() {
    local timeout="$1"
    local deadline=$(( $(date +%s) + timeout ))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        local running
        running=$(curl -sf \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/builder/jobs" 2>/dev/null \
            | jq '[.[] | select(.status == "running")] | length' 2>/dev/null || echo "0")
        if [ "${running:-0}" = "0" ]; then
            echo "idle"; return 0
        fi
        sleep "$POLL_INTERVAL"
    done
    echo "busy"; return 0
}

# Minimal valid payload — used by rejection tests that only change one field.
BASE_JSON='{"host":"c2-server","port":"4443","platform":"linux","transport":"tls","sleep":5,"jitter_min":0,"jitter_max":0,"debug":true}'

# Full combined payload — the single end-to-end build that is awaited.
FULL_JSON='{
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
}'

# ══════════════════════════════════════════════════════════════════════
suite "Phase 0 — pre-flight: build queue is idle"
# ══════════════════════════════════════════════════════════════════════
# Earlier suites (e.g. test_10) fire builds without waiting for all of
# them. Awaiting our build while leftovers hold the cargo target-dir
# lock is what made this suite pass or fail depending on machine speed.

assert_eq "no leftover builds running" "idle" "$(wait_for_quiescence "$DRAIN_TIMEOUT")"

# ══════════════════════════════════════════════════════════════════════
suite "Phase 1 — end-to-end: full evasion + all guardrails"
# ══════════════════════════════════════════════════════════════════════
# The ONE awaited build. Runs before this script spawns any other build.

RESP=$(start_build "$FULL_JSON")
assert_http "full evasion+guardrails build accepted" "202"
JOB_FULL=$(echo "$RESP" | jq -r '.job_id // empty' 2>/dev/null || true)
assert_ne "job_id returned for full config" "" "$JOB_FULL"

if [ -n "$JOB_FULL" ]; then
    RESULT="$(wait_for_build "$JOB_FULL")"
    assert_eq "full-config build succeeds" "success" "$RESULT"
fi

# ── Completed build exposes a well-formed status record ───────────────
if [ -n "$JOB_FULL" ] && [ "${RESULT:-}" = "success" ]; then
    STATUS=$(curl -sf \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        "${C2_URL}/api/builder/jobs/${JOB_FULL}/status" 2>/dev/null || echo '{}')
    assert_eq "status field is exactly 'success'" \
        "success" "$(echo "$STATUS" | jq -r '.status // empty' 2>/dev/null || true)"
    assert_ne "artifact_name is present" \
        "" "$(echo "$STATUS" | jq -r '.artifact_name // empty' 2>/dev/null || true)"
    assert_ne "started_at is present" \
        "" "$(echo "$STATUS" | jq -r '.started_at // empty' 2>/dev/null || true)"
    assert_ne "finished_at is present" \
        "" "$(echo "$STATUS" | jq -r '.finished_at // empty' 2>/dev/null || true)"

    # Artifact is downloadable
    curl -s -o /tmp/.dl_artifact -w '%{http_code}' \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        "${C2_URL}/api/builder/jobs/${JOB_FULL}/download" > /tmp/.last_http_code 2>/dev/null
    assert_http "artifact downloads with 200" "200"
    if [ -s /tmp/.dl_artifact ]; then
        assert_eq "downloaded artifact is non-empty" "true" "true"
    else
        assert_eq "downloaded artifact is non-empty" "true" "false"
    fi
    rm -f /tmp/.dl_artifact
fi

# ══════════════════════════════════════════════════════════════════════
suite "Phase 2 — validation: invalid sleep_mask rejected"
# ══════════════════════════════════════════════════════════════════════
# From here on NOTHING is awaited: validation happens synchronously in
# the API before any compilation starts, so these checks are instant.

start_build "$(echo "$BASE_JSON" | jq '. + {sleep_mask:"custom"}')" > /dev/null
assert_http "sleep_mask=custom returns 400" "400"

start_build "$(echo "$BASE_JSON" | jq '. + {sleep_mask:""}')" > /dev/null
assert_http "sleep_mask empty string returns 400" "400"

start_build "$(echo "$BASE_JSON" | jq '. + {sleep_mask:"EKKO"}')" > /dev/null
assert_http "sleep_mask wrong case returns 400" "400"

# ══════════════════════════════════════════════════════════════════════
suite "Phase 2 — validation: sleep mask variants accepted"
# ══════════════════════════════════════════════════════════════════════

for MASK in ekko foliage none; do
    RESP=$(start_build "$(echo "$BASE_JSON" | jq --arg m "$MASK" '. + {sleep_mask:$m}')")
    assert_http "sleep_mask=$MASK accepted" "202"
    JID=$(echo "$RESP" | jq -r '.job_id // empty' 2>/dev/null || true)
    assert_ne "job_id returned for sleep_mask=$MASK" "" "$JID"
done

# ══════════════════════════════════════════════════════════════════════
suite "Phase 2 — validation: evasion flag combinations accepted"
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
assert_ne "job_id returned" "" "$(echo "$RESP" | jq -r '.job_id // empty' 2>/dev/null || true)"

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
assert_ne "job_id returned" "" "$(echo "$RESP" | jq -r '.job_id // empty' 2>/dev/null || true)"

# ══════════════════════════════════════════════════════════════════════
suite "Phase 2 — validation: legacy payload without new fields"
# ══════════════════════════════════════════════════════════════════════
# Omitting the new fields must not break existing callers.

RESP=$(start_build "$BASE_JSON")
assert_http "payload without evasion fields accepted" "202"
assert_ne "job_id returned for legacy payload" "" "$(echo "$RESP" | jq -r '.job_id // empty' 2>/dev/null || true)"

# ══════════════════════════════════════════════════════════════════════
suite "Phase 2 — validation: guardrail fields accepted"
# ══════════════════════════════════════════════════════════════════════

RESP=$(start_build '{
    "host":"c2-server","port":"4443","platform":"linux","transport":"tls",
    "sleep":5,"jitter_min":0,"jitter_max":0,"debug":true,
    "guard_domain":"CORP*",
    "guard_hostname":"DESKTOP-*"
}')
assert_http "domain+hostname guardrail build accepted" "202"
assert_ne "job_id returned" "" "$(echo "$RESP" | jq -r '.job_id // empty' 2>/dev/null || true)"

RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:8,guard_hour_end:18}')")
assert_http "guard_hours 8-18 accepted" "202"

# Only start set — end defaults to 0
RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:9}')")
assert_http "guard_hour_start only accepted" "202"

# Only end set — start defaults to 0
RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_end:17}')")
assert_http "guard_hour_end only accepted" "202"

# Both zero — treated as all-day (no restriction), should accept
RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_hour_start:0,guard_hour_end:0}')")
assert_http "guard_hours 0-0 (all-day) accepted" "202"

RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_no_system:true}')")
assert_http "guard_no_system=true accepted" "202"

RESP=$(start_build "$(echo "$BASE_JSON" | jq '. + {guard_no_system:false}')")
assert_http "guard_no_system=false accepted" "202"

# ══════════════════════════════════════════════════════════════════════
suite "Phase 2 — validation: hour bounds"
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
suite "Phase 2 — validation: unknown job returns 404"
# ══════════════════════════════════════════════════════════════════════

curl -s -w '\n%{http_code}' \
    -H "X-API-KEY: ${ADMIN_KEY}" \
    "${C2_URL}/api/builder/jobs/00000000-0000-0000-0000-000000000000/status" \
    > /tmp/.last_resp 2>/dev/null
code=$(tail -1 /tmp/.last_resp)
echo "$code" > /tmp/.last_http_code
assert_http "unknown job_id returns 404" "404"

# ══════════════════════════════════════════════════════════════════════
suite "Phase 3 — job list invariants"
# ══════════════════════════════════════════════════════════════════════

JOBS=$(api_get "/api/builder/jobs")
assert_http "jobs list returns 200" "200"
COUNT=$(echo "$JOBS" | jq 'length // 0' 2>/dev/null || echo "0")
if [ "${COUNT:-0}" -gt 0 ]; then
    assert_eq "job list is non-empty" "true" "true"
else
    assert_eq "job list is non-empty" "true" "false"
fi

# Every entry must have the mandatory fields
MISSING=$(echo "$JOBS" | jq '[.[] | select(.job_id == null or .status == null or .started_at == null)] | length' 2>/dev/null || echo "1")
assert_eq "all job entries have required fields" "0" "$MISSING"

# ══════════════════════════════════════════════════════════════════════
suite "Phase 4 — drain fire-and-forget builds"
# ══════════════════════════════════════════════════════════════════════
# Phase 2 spawned builds that we deliberately did not await (their
# configs duplicate Phase 1 coverage). Drain them so the cargo load
# does not bleed into test_12+. A drain timeout is environmental, not
# a contract violation — report it as a skip.

if [ "$(wait_for_quiescence "$DRAIN_TIMEOUT")" = "idle" ]; then
    assert_eq "background builds drained" "true" "true"
else
    skip "background builds still running after ${DRAIN_TIMEOUT}s (environmental)"
fi

print_summary

# ── Why this rewrite is decisive ──────────────────────────────────────
#
# The old version had three independent defects that together produced
# "sometimes accepts, sometimes rejects, always slow":
#
# 1. Six fire-and-forget 202 builds (hour variants, boundary checks,
#    no_system=false) spawned REAL cargo release builds that competed
#    with the nine awaited builds for the shared target/ directory
#    lock. Whether an awaited build finished within BUILD_TIMEOUT
#    depended on how many builds happened to queue ahead of it —
#    machine-speed-dependent, i.e. flaky. Now exactly one build is
#    awaited, and it runs while the queue is provably idle.
#
# 2. `RESULT=$(wait_for_build "$JOB_FULL")` inherited wait_for_build's
#    non-zero exit code under the `set -e` that lib.sh enables, so a
#    failed/timed-out build in the combined suite aborted the whole
#    script with no summary — a different failure mode than the same
#    condition produced in other suites. wait_for_build now always
#    returns 0 and communicates via its stdout token.
#
# 3. wait_for_build accepted completed|done|success while the server
#    only ever emits success (BuildStatus::{Running,Success,Failed}),
#    and a later assertion required exactly "success" — an
#    inconsistency that could pass one check and fail another for the
#    same job. The waiter now matches the server's exact vocabulary
#    and treats anything else as immediate failure (API drift), not
#    as a timeout.
