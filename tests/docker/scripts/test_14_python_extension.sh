#!/usr/bin/env bash
# tests/docker/scripts/test_14_python_extension.sh
#
# Integration tests for the Python scripting bridge.
#
# Sends RHAI scripts to a connected agent via the C2 API and asserts
# on the output.  Tests cover:
#   • Python discovery and version detection
#   • Basic code execution (arithmetic, JSON, stdlib)
#   • VENV creation, existence check, deletion
#   • pip install / list / freeze / has_package
#   • Execute code inside a venv
#   • python_call JSON I/O round-trip
#   • Persistent session lifecycle and state persistence
#   • Error handling (bad code, missing venv, unknown session)
#   • internal_python_ensure (installs Python if absent)
#   • internal_python_bootstrap (one-shot setup)
#   • offensive library check
#
# Prerequisites: c2-server healthy, at least one agent connected.
#
# Usage:
#   PYTHON_VENV_BASE=/tmp/rcm_test_py bash test_14_python_extension.sh

set -uo pipefail
source "$(dirname "$0")/lib.sh"

AGENT_TIMEOUT="${AGENT_TIMEOUT:-120}"
CMD_TIMEOUT="${CMD_TIMEOUT:-60}"
VENV_BASE="${PYTHON_VENV_BASE:-/tmp/rcm_test_py_$$}"

# ── Agent helpers ─────────────────────────────────────────────────────────────

# Resolve the first connected agent session ID.
get_session() {
    curl -sf -H "X-API-KEY: ${ADMIN_KEY}" "${C2_URL}/api/hosts" 2>/dev/null \
        | jq -r '.[0].session_id // empty'
}

# Send a RHAI script to the agent and return its output (blocking poll).
run_script() {
    local session_id="$1"
    local script="$2"
    local timeout="${3:-${CMD_TIMEOUT}}"

    local resp job_id
    resp=$(curl -sf \
        -X POST "${C2_URL}/api/sessions/${session_id}/command" \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"type\":\"script\",\"content\":$(echo "$script" | jq -Rs .)}" \
        2>/dev/null) || { echo "Error: API call failed"; return; }

    job_id=$(echo "$resp" | jq -r '.job_id // empty')
    if [ -z "$job_id" ]; then
        echo "Error: no job_id in response: $resp"
        return
    fi

    local deadline=$(($(date +%s) + timeout))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local result
        result=$(curl -sf \
            -H "X-API-KEY: ${ADMIN_KEY}" \
            "${C2_URL}/api/jobs/${job_id}" 2>/dev/null || echo '{}')
        local status
        status=$(echo "$result" | jq -r '.status // "pending"')
        case "$status" in
            completed|done|success)
                echo "$result" | jq -r '.output // .result // ""'
                return ;;
            failed|error)
                echo "Error: $(echo "$result" | jq -r '.error // .output // "unknown"')"
                return ;;
        esac
        sleep 1
    done
    echo "Error: job ${job_id} timed out after ${timeout}s"
}

# ── Setup ─────────────────────────────────────────────────────────────────────

echo "Waiting for agent (up to ${AGENT_TIMEOUT}s)..."
if ! wait_agents 1 "${AGENT_TIMEOUT}"; then
    echo "FATAL: No agent connected after ${AGENT_TIMEOUT}s" >&2
    exit 1
fi

SESSION=$(get_session)
if [ -z "$SESSION" ]; then
    echo "FATAL: Could not resolve session ID" >&2
    exit 1
fi
echo "Using session: ${SESSION}"
echo "VENV base:     ${VENV_BASE}"
echo ""

# ── Suite 1: Python discovery ─────────────────────────────────────────────────

suite "Python discovery"

# Check if Python is available on the agent; if not, try to install it.
PY_PATH=$(run_script "$SESSION" "internal_python_ensure(\"${VENV_BASE}/runtime\")")

if echo "$PY_PATH" | grep -q "^Error"; then
    skip "Python not available and could not be installed: ${PY_PATH}"
    PYTHON_AVAILABLE=false
else
    PYTHON_AVAILABLE=true
    assert_contains "python_find returns a path" "python" "$PY_PATH"
fi

if [ "$PYTHON_AVAILABLE" = "true" ]; then
    VERSION=$(run_script "$SESSION" "internal_python_version(\"\")")
    assert_contains "python_version contains 'Python'" "Python" "$VERSION"

    PBS_URL=$(run_script "$SESSION" "internal_python_pbs_url()")
    if echo "$PBS_URL" | grep -qF "Error"; then
        skip "GitHub API unavailable for pbs_url test"
    else
        assert_contains "pbs_url starts with https" "https" "$PBS_URL"
        assert_contains "pbs_url references python-build-standalone" "python-build-standalone" "$PBS_URL"
        assert_contains "pbs_url ends with .tar.gz" ".tar.gz" "$PBS_URL"
    fi
fi

# ── Suite 2: Basic execution ──────────────────────────────────────────────────

suite "Basic execution"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available — skipping execution tests"
else
    OUT=$(run_script "$SESSION" 'internal_python_exec("print(6 * 7)")')
    assert_contains "exec arithmetic gives 42" "42" "$OUT"

    OUT=$(run_script "$SESSION" 'internal_python_exec("
x = list(range(10))
print(sum(x))
")')
    assert_contains "exec multiline gives 45" "45" "$OUT"

    OUT=$(run_script "$SESSION" 'internal_python_exec_json("
import json, sys
print(json.dumps({\"py_major\": sys.version_info.major}))
")')
    assert_contains "exec_json output is JSON with py_major" "py_major" "$OUT"
    PY_MAJOR=$(echo "$OUT" | jq -r '.py_major // 0' 2>/dev/null || echo 0)
    assert_eq "py_major is 3" "3" "$PY_MAJOR"

    # Syntax error should produce non-empty output (error message from Python).
    ERR_OUT=$(run_script "$SESSION" 'internal_python_exec("this is not valid python !!!")')
    assert_ne "syntax error produces non-empty output" "" "$ERR_OUT"
fi

# ── Suite 3: VENV lifecycle ───────────────────────────────────────────────────

suite "VENV lifecycle"

VENV_PATH="${VENV_BASE}/test_venv"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available — skipping venv tests"
else
    OUT=$(run_script "$SESSION" "internal_venv_exists(\"${VENV_PATH}\")")
    assert_eq "venv does not exist before creation" "false" "$(echo "$OUT" | tr -d '[:space:]')"

    OUT=$(run_script "$SESSION" "internal_venv_create(\"${VENV_PATH}\")")
    assert_contains "venv_create reports success" "Created" "$OUT"

    OUT=$(run_script "$SESSION" "internal_venv_exists(\"${VENV_PATH}\")")
    assert_eq "venv exists after creation" "true" "$(echo "$OUT" | tr -d '[:space:]')"

    PY_BIN=$(run_script "$SESSION" "internal_venv_python_path(\"${VENV_PATH}\")")
    assert_contains "venv_python_path contains 'python'" "python" "$PY_BIN"

    # Idempotency: creating again should not fail.
    OUT=$(run_script "$SESSION" "internal_venv_create(\"${VENV_PATH}\")")
    assert_ne "re-creating existing venv does not produce an Error: prefix" "Error" \
        "$(echo "$OUT" | head -c5)"

    # sys.prefix inside the venv should reference the venv dir.
    OUT=$(run_script "$SESSION" \
        "internal_python_in_venv(\"${VENV_PATH}\", \"import sys; print(sys.prefix)\")")
    assert_contains "sys.prefix inside venv references venv dir" "test_venv" "$OUT"

    # Delete.
    OUT=$(run_script "$SESSION" "internal_venv_delete(\"${VENV_PATH}\")")
    assert_contains "venv_delete reports Deleted" "Deleted" "$OUT"

    OUT=$(run_script "$SESSION" "internal_venv_exists(\"${VENV_PATH}\")")
    assert_eq "venv gone after deletion" "false" "$(echo "$OUT" | tr -d '[:space:]')"

    # Delete non-existent → error.
    OUT=$(run_script "$SESSION" "internal_venv_delete(\"${VENV_PATH}\")")
    assert_contains "deleting non-existent venv returns Error" "Error" "$OUT"
fi

# ── Suite 4: Pip operations ───────────────────────────────────────────────────

suite "Pip operations"

PIP_VENV="${VENV_BASE}/pip_venv"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available — skipping pip tests"
else
    run_script "$SESSION" "internal_venv_create(\"${PIP_VENV}\")" > /dev/null

    # pip list returns a JSON array.
    OUT=$(run_script "$SESSION" "internal_pip_list(\"${PIP_VENV}\")")
    PARSED=$(echo "$OUT" | jq -e 'type == "array"' 2>/dev/null && echo "array" || echo "not-array")
    assert_eq "pip_list returns JSON array" "array" "$PARSED"

    # pip itself should always be listed.
    assert_contains "pip appears in pip_list" "pip" "$OUT"

    # pip_freeze: requirements.txt format.
    OUT=$(run_script "$SESSION" "internal_pip_freeze(\"${PIP_VENV}\")")
    # An empty venv might have no output from freeze — just verify no Error.
    assert_ne "pip_freeze does not return Error" "Error" \
        "$(echo "$OUT" | head -c5)"

    # pip_has_package: stdlib always present.
    for MOD in os sys json hashlib; do
        HAS=$(run_script "$SESSION" \
            "internal_pip_has_package(\"${PIP_VENV}\", \"${MOD}\")")
        assert_eq "stdlib module '${MOD}' is available" "true" \
            "$(echo "$HAS" | tr -d '[:space:]')"
    done

    # pip_has_package: definitely-absent package.
    ABSENT=$(run_script "$SESSION" \
        "internal_pip_has_package(\"${PIP_VENV}\", \"this_pkg_does_not_exist_xyz123\")")
    assert_eq "missing package returns false" "false" \
        "$(echo "$ABSENT" | tr -d '[:space:]')"

    # Install six (smallest real package with no deps).
    OUT=$(run_script "$SESSION" \
        "internal_pip_install(\"${PIP_VENV}\", \"[\\\"six\\\"]\")" "${CMD_TIMEOUT}")
    assert_contains "pip_install six succeeds" "Installed" "$OUT"

    HAS_SIX=$(run_script "$SESSION" \
        "internal_pip_has_package(\"${PIP_VENV}\", \"six\")")
    assert_eq "six is importable after install" "true" \
        "$(echo "$HAS_SIX" | tr -d '[:space:]')"

    # pip_freeze should now contain six.
    FREEZE=$(run_script "$SESSION" "internal_pip_freeze(\"${PIP_VENV}\")")
    assert_contains "freeze contains six after install" "six" "$FREEZE"
    assert_contains "freeze contains version pin ==" "==" "$FREEZE"

    # requirements string install.
    UNINSTALL_VENV="${VENV_BASE}/req_venv"
    run_script "$SESSION" "internal_venv_create(\"${UNINSTALL_VENV}\")" > /dev/null
    OUT=$(run_script "$SESSION" \
        "internal_pip_install_requirements(\"${UNINSTALL_VENV}\", \"six\n\")" "${CMD_TIMEOUT}")
    assert_contains "pip_install_requirements succeeds" "Installed" "$OUT"

    # Uninstall.
    OUT=$(run_script "$SESSION" \
        "internal_pip_uninstall(\"${PIP_VENV}\", \"[\\\"six\\\"]\")")
    assert_contains "pip_uninstall succeeds" "Uninstalled" "$OUT"

    HAS_SIX_AFTER=$(run_script "$SESSION" \
        "internal_pip_has_package(\"${PIP_VENV}\", \"six\")")
    assert_eq "six gone after uninstall" "false" \
        "$(echo "$HAS_SIX_AFTER" | tr -d '[:space:]')"
fi

# ── Suite 5: python_call JSON I/O ─────────────────────────────────────────────

suite "python_call JSON I/O"

CALL_VENV="${VENV_BASE}/call_venv"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available"
else
    run_script "$SESSION" "internal_venv_create(\"${CALL_VENV}\")" > /dev/null

    OUT=$(run_script "$SESSION" "
let code = \"import json; print(json.dumps({'total': sum(rcm_input['numbers'])}))\";
internal_python_call(\"${CALL_VENV}\", \"{\\\"numbers\\\": [10, 20, 30]}\", code)
")
    TOTAL=$(echo "$OUT" | jq -r '.total // empty' 2>/dev/null)
    assert_eq "python_call JSON round-trip gives 60" "60" "$TOTAL"
fi

# ── Suite 6: Persistent session ───────────────────────────────────────────────

suite "Persistent session"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available"
else
    # Start session.
    SID=$(run_script "$SESSION" 'internal_python_session_start("")')
    assert_ne "session_start returns non-error ID" "Error" "$(echo "$SID" | head -c5)"

    # Basic exec.
    OUT=$(run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"print(7 * 6)\")")
    assert_contains "session exec gives 42" "42" "$OUT"

    # State persistence: accumulate across multiple execs.
    run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"total = 0\")" > /dev/null
    run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"total += 10\")" > /dev/null
    run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"total += 20\")" > /dev/null
    run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"total += 30\")" > /dev/null
    TOTAL=$(run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"print(total)\")")
    assert_contains "cross-exec state: total == 60" "60" "$TOTAL"

    # session_list shows the active session.
    LIST=$(run_script "$SESSION" 'internal_python_session_list()')
    assert_contains "session_list contains active session ID" "$SID" "$LIST"

    # Error in session: Python exception should be reported, not crash the session.
    ERR=$(run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"raise ValueError('test error')\")")
    assert_contains "session captures Python exception" "ValueError" "$ERR"

    # Session still alive after exception.
    AFTER=$(run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"print('still_alive')\")")
    assert_contains "session survives an exception" "still_alive" "$AFTER"

    # Stop.
    STOP=$(run_script "$SESSION" "internal_python_session_stop(\"${SID}\")")
    assert_contains "session_stop confirms stopped" "stopped" "$STOP"

    # Exec on stopped session → error.
    DEAD=$(run_script "$SESSION" \
        "internal_python_session_exec(\"${SID}\", \"print('dead')\")")
    assert_contains "exec on stopped session returns Error" "Error" "$DEAD"
fi

# ── Suite 7: Error handling ───────────────────────────────────────────────────

suite "Error handling"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available"
else
    # exec in non-existent venv.
    OUT=$(run_script "$SESSION" \
        'internal_python_in_venv("/no/such/venv/12345", "print(1)")')
    assert_contains "exec in nonexistent venv returns Error" "Error" "$OUT"

    # pip_list in non-existent venv.
    OUT=$(run_script "$SESSION" 'internal_pip_list("/no/such/venv/12345")')
    assert_contains "pip_list in nonexistent venv returns Error" "Error" "$OUT"

    # Session exec with unknown ID.
    OUT=$(run_script "$SESSION" \
        'internal_python_session_exec("00000000-dead-beef-0000-000000000000", "print(1)")')
    assert_contains "session_exec with unknown ID returns Error" "Error" "$OUT"

    # Delete non-existent venv.
    OUT=$(run_script "$SESSION" 'internal_venv_delete("/no/such/venv/12345")')
    assert_contains "venv_delete nonexistent returns Error" "Error" "$OUT"
fi

# ── Suite 8: bootstrap ────────────────────────────────────────────────────────

suite "Bootstrap (ensure + venv + packages)"

BS_VENV="${VENV_BASE}/bootstrap_venv"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available"
else
    PY_BIN=$(run_script "$SESSION" \
        "internal_python_bootstrap(\"${VENV_BASE}/runtime\", \"${BS_VENV}\", \"[\\\"six\\\"]\")" \
        "${CMD_TIMEOUT}")

    assert_ne "bootstrap returns non-error" "Error" "$(echo "$PY_BIN" | head -c5)"
    assert_contains "bootstrap returns a path with 'python'" "python" "$PY_BIN"

    EXISTS=$(run_script "$SESSION" "internal_venv_exists(\"${BS_VENV}\")")
    assert_eq "venv exists after bootstrap" "true" "$(echo "$EXISTS" | tr -d '[:space:]')"

    HAS=$(run_script "$SESSION" \
        "internal_pip_has_package(\"${BS_VENV}\", \"six\")")
    assert_eq "requested package installed by bootstrap" "true" \
        "$(echo "$HAS" | tr -d '[:space:]')"
fi

# ── Suite 9: Offensive check ──────────────────────────────────────────────────

suite "Offensive library check"

if [ "$PYTHON_AVAILABLE" != "true" ]; then
    skip "Python not available"
else
    OUT=$(run_script "$SESSION" 'internal_python_offensive_check("")')
    assert_ne "offensive_check returns non-Error" "Error" "$(echo "$OUT" | head -c5)"

    IS_OBJ=$(echo "$OUT" | jq -e 'type == "object"' 2>/dev/null && echo "yes" || echo "no")
    assert_eq "offensive_check returns JSON object" "yes" "$IS_OBJ"

    # json, os, sys are always available so at least some keys should be true.
    assert_contains "offensive_check includes requests key" "requests" "$OUT"
fi

# ── Suite 10: Cleanup ────────────────────────────────────────────────────────

suite "Cleanup"

if [ "$PYTHON_AVAILABLE" = "true" ]; then
    # Remove the whole VENV_BASE tree.
    OUT=$(run_script "$SESSION" "
let exists = internal_exists(\"${VENV_BASE}\");
if exists {
    internal_delete(\"${VENV_BASE}\")
} else {
    \"already gone\"
}
")
    assert_ne "cleanup returns non-Error" "Error" "$(echo "$OUT" | head -c5)"
fi

# ── Final summary ─────────────────────────────────────────────────────────────

print_summary
