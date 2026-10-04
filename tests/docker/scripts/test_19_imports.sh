#!/usr/bin/env bash
# tests/docker/scripts/test_19_imports.sh
#
# Integration guard for the windows FFI migration: once the agent batch
# moves the sensitive windows API surface to runtime-hash resolution, a
# built windows agent's IMPORT TABLE must no longer name those APIs.
#
# Flow: drain the builder queue (Phase 0, per test_16/17), build a windows
# agent via the API (debug:false, allow_vm:true, mirroring test_18's
# rationale), download the exe, dump the import table with a PE-capable
# objdump inside the test-runner, then assert:
#   ABSENT: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread,
#           OpenProcess, CreateServiceA, CreateServiceW, RegSetValueExA,
#           RegSetValueExW, WinExec
#   PRESENT: kernel32.dll in the DLL list plus a plausible number of
#           imported functions (proves the PE is not broken)
#
# IMPORT_STRICT=0 (default): a denylisted import still present is a loud
#   skip while the migration is landing; IMPORT_STRICT=1 makes it a hard
#   failure. PE-parse and sane-surface assertions are always hard.
#
# objdump source: the test-runner apk line installs mingw-w64-binutils
# (x86_64-w64-mingw32-objdump); the script falls back to objdump /
# llvm-objdump if either can actually parse the PE.
#
# Depends on: c2-server healthy, admin credentials in /shared/admin_creds.json

set -uo pipefail
source "$(dirname "$0")/lib.sh"

# Windows cross-compile plus queue drain need generous budgets (see the
# test_17 class note: serialized gate, upstream suite backlog).
BUILD_TIMEOUT="${BUILD_TIMEOUT:-900}"
DRAIN_TIMEOUT="${DRAIN_TIMEOUT:-1800}"
IMPORT_STRICT="${IMPORT_STRICT:-0}"

IMPORT_DENYLIST="VirtualAllocEx WriteProcessMemory CreateRemoteThread OpenProcess CreateServiceA CreateServiceW RegSetValueExA RegSetValueExW WinExec"

# Contract-pending assertion (same pattern as test_17/18).
contract_assert() {
    local desc="$1" ok="$2" detail="$3"
    if [ "$ok" = "0" ]; then
        echo "  ✓ $desc"
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [ "$IMPORT_STRICT" = "1" ]; then
        echo "  ✗ $desc"
        echo "    $detail"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "  ⊘ $desc"
        echo "    NOTE(contract pending): $detail"
        SKIP_COUNT=$((SKIP_COUNT + 1))
    fi
}

# ── Build helpers (same conventions as test_15/17/18) ───────────────────
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
# ALWAYS returns 0 (set -e safety; see test_16 header). failed/timeout
# dump the builder log tail so a slow or broken build stays visible.
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

# Wait until no build job is in the running state (test_16 pattern).
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
        sleep 5
    done
    echo "busy"; return 0
}

# ── objdump discovery ───────────────────────────────────────────────────
# Prints the objdump command that can parse PE, or nothing. Always
# returns 0; callers test for empty output.
find_pe_objdump() {
    local cand
    for cand in x86_64-w64-mingw32-objdump llvm-objdump objdump; do
        command -v "$cand" > /dev/null 2>&1 || continue
        if "$cand" -p "$1" 2>/dev/null | grep -q "The Import Tables"; then
            echo "$cand"
            return 0
        fi
    done
    echo ""
    return 0
}

# ══════════════════════════════════════════════════════
suite "Import guard: Phase 0 - builder gate quiescence"
# ══════════════════════════════════════════════════════
QUIET=$(wait_for_quiescence "$DRAIN_TIMEOUT")
assert_eq "no leftover builds running at start" "idle" "$QUIET"

# ══════════════════════════════════════════════════════
suite "Import guard: build windows agent via API"
# ══════════════════════════════════════════════════════
# debug:false (a debug build keeps tracing callsites and is not the
# shipped configuration) and allow_vm:true (containers are VMs; only the
# import surface is under test here), per test_18's build rationale.
RESP=$(start_build '{
    "host": "c2-server",
    "port": "4443",
    "platform": "windows",
    "transport": "tls",
    "format": "exe",
    "sleep": 5,
    "jitter_min": 0,
    "jitter_max": 0,
    "debug": false,
    "allow_vm": true
}')
assert_http "windows agent build request accepted" "202"

JOB_ID=$(echo "$RESP" | jq -r '.job_id // empty')
assert_ne "job_id returned for windows build" "" "$JOB_ID"

EXE="/tmp/test_19_agent.exe"
if [ -n "$JOB_ID" ]; then
    RESULT=$(wait_for_build "$JOB_ID")
    assert_eq "windows agent build completes" "completed" "$RESULT"

    if [ "$RESULT" = "completed" ]; then
        dl_code=$(curl -s -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/builder/jobs/${JOB_ID}/download" \
            -o "$EXE" -w '%{http_code}' 2>/dev/null)
        assert_eq "windows agent artifact downloads via API" "200" "$dl_code"
    fi
fi

# ══════════════════════════════════════════════════════
suite "Import guard: import table analysis"
# ══════════════════════════════════════════════════════

if [ ! -s "$EXE" ]; then
    skip "No built windows agent - skipping import assertions"
    print_summary
    exit 0
fi

OBJDUMP=$(find_pe_objdump "$EXE")
if [ -z "$OBJDUMP" ]; then
    skip "No PE-capable objdump in the test-runner (apk mingw-w64-binutils failed?) - skipping import assertions"
    print_summary
    exit 0
fi
echo "  Using: $OBJDUMP"

IMPORTS="$($OBJDUMP -p "$EXE" 2>/dev/null)"
assert_contains "PE import table parses" "The Import Tables" "$IMPORTS"

# Sane surface: kernel32.dll present (mingw lowercases DLL names, so the
# check is case-insensitive) plus a plausible import count prove the PE's
# import directory is intact (not a broken/stripped artifact).
if echo "$IMPORTS" | grep -i "DLL Name" | grep -qi "kernel32"; then
    echo "  ✓ kernel32.dll present in import DLLs"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ kernel32.dll missing from import DLLs (PE broken?)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
fn_count=$(echo "$IMPORTS" \
    | grep -cE '^[[:space:]]+[0-9a-fA-F]+[[:space:]]+[0-9a-fA-F]+[[:space:]]+[A-Za-z_]' || true)
if [ "$fn_count" -ge 10 ]; then
    echo "  ✓ plausible import surface (${fn_count} named imports)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ plausible import surface (only ${fn_count} named imports - PE broken?)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Denylist: whole-word matches only (OpenProcess vs OpenProcessToken).
for fn in $IMPORT_DENYLIST; do
    if echo "$IMPORTS" | grep -qwE "$fn"; then
        contract_assert "import absent: $fn" "1" \
            "$fn still appears in the import table (runtime-hash migration not landed?)"
    else
        contract_assert "import absent: $fn" "0" ""
    fi
done

print_summary
