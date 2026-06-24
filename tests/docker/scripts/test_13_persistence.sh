#!/usr/bin/env bash
# tests/docker/scripts/test_13_persistence.sh
#
# Functionality tests for the persist:* command family.
#
# These tests go through the full C2 pipeline:
#   test runner → HTTP API → c2-server → live agent → OS → response → assert
#
# They verify what Rust unit/integration tests cannot:
#   - Commands are correctly routed through the agent dispatcher
#   - The agent actually writes to the real filesystem
#   - Output messages match the real OS state
#   - Remove commands actually undo what install commands did
#   - The stable drop survives deletion of the source binary
#   - Platform-guard errors surface correctly over the wire
#
# Requires: at least one connected agent (agent-tls preferred).
# Classified as: AGENT_TESTS

set -uo pipefail
source "$(dirname "$0")/lib.sh"

# ── Setup ─────────────────────────────────────────────────────────────────────

AGENT_BINARY="/shared/agent-tls"   # path inside the agent container
STABLE_BIN_DIR="/root/.local/bin"  # stable_drop destination (root home)
SYSTEMD_USER_DIR="/root/.config/systemd/user"

# ── Select a session ──────────────────────────────────────────────────────────

suite "Persistence — select agent session"

HOSTS=$(api_get "/api/hosts")
assert_http "hosts endpoint returns 200" "200"

HOST_COUNT=$(echo "$HOSTS" | jq 'length')
if [ "$HOST_COUNT" -eq 0 ]; then
    skip "No agents connected — skipping persistence functionality tests"
    print_summary
    exit 0
fi

# Prefer agent-tls for deterministic command delivery
SID=$(echo "$HOSTS" | jq -r \
    '[.[] | select(.hostname=="agent-tls")][0].id // .[0].id')
HOSTNAME=$(echo "$HOSTS" | jq -r \
    --arg id "$SID" \
    '[.[] | select(.id==($id|tonumber))][0].hostname // "unknown"')
echo "  Using session #${SID} (${HOSTNAME})"
assert_ne "session ID is not empty" "" "$SID"

# ── Core helper ───────────────────────────────────────────────────────────────
#
# send_cmd <command-string>
#   Sends a command to $SID and polls for output up to 30 s.
#   Stores result in $CMD_OUTPUT and exit code in $CMD_EXIT.

CMD_OUTPUT=""
CMD_EXIT=0

send_cmd() {
    local cmd="$1"
    local timeout="${2:-30}"

    local resp req_id
    resp=$(api_post "/api/hosts/${SID}/command" "$ADMIN_KEY" \
        "{\"command\":$(echo -n "$cmd" | jq -Rs .)}")

    if ! echo "$resp" | jq -e '.request_id' > /dev/null 2>&1; then
        CMD_OUTPUT="[send_cmd error: no request_id in response: $resp]"
        CMD_EXIT=1
        return 1
    fi

    req_id=$(echo "$resp" | jq -r '.request_id')

    local deadline=$(( $(date +%s) + timeout ))
    CMD_OUTPUT=""
    CMD_EXIT=0

    while [ "$(date +%s)" -lt "$deadline" ]; do
        sleep 2
        local out_resp status
        out_resp=$(api_get "/api/hosts/${SID}/output/${req_id}" 2>/dev/null || echo '{}')
        status=$(echo "$out_resp" | jq -r '.status // empty')

        if [ "$status" = "completed" ]; then
            CMD_OUTPUT=$(echo "$out_resp" | jq -r '.output // empty')
            CMD_EXIT=$(echo   "$out_resp" | jq -r '.exit_code // 0')
            return 0
        fi
    done

    CMD_OUTPUT="[send_cmd timeout after ${timeout}s for: $cmd]"
    CMD_EXIT=1
    return 1
}

# ── Sanity: agent is alive ────────────────────────────────────────────────────

suite "Persistence — agent liveness check"

send_cmd "shell echo PERSIST_TEST_READY"
assert_contains "agent responds to shell commands" "PERSIST_TEST_READY" "$CMD_OUTPUT"

# ── persist:list ──────────────────────────────────────────────────────────────

suite "persist:list — inventory command"

send_cmd "persist:list"
assert_eq   "persist:list exits 0"              "0"       "$CMD_EXIT"
assert_contains "output has Crontab section"    "Crontab" "$CMD_OUTPUT"
assert_contains "output has Systemd section"    "Systemd" "$CMD_OUTPUT"
assert_contains "output has Profile section"    "Profile" "$CMD_OUTPUT"

# ── persist:systemd — install ─────────────────────────────────────────────────

suite "persist:systemd — install lifecycle"

UNIT_NAME="rcm-test-svc"
UNIT_FILE="${SYSTEMD_USER_DIR}/${UNIT_NAME}.service"
WANTS_LINK="${SYSTEMD_USER_DIR}/default.target.wants/${UNIT_NAME}.service"
STABLE_BIN="${STABLE_BIN_DIR}/${UNIT_NAME}"

send_cmd "persist:systemd ${UNIT_NAME} ${AGENT_BINARY}"
assert_eq "persist:systemd exits 0" "0" "$CMD_EXIT"
assert_contains "output shows [+] success"  "[+]" "$CMD_OUTPUT"
assert_contains "output reports copy step"  "Copied:" "$CMD_OUTPUT"
assert_contains "output names the unit"     "$UNIT_NAME" "$CMD_OUTPUT"

# Verify stable binary was created
send_cmd "shell test -f ${STABLE_BIN} && echo EXISTS || echo MISSING"
assert_contains "stable binary was copied to ~/.local/bin/" "EXISTS" "$CMD_OUTPUT"

# Verify binary is executable
send_cmd "shell test -x ${STABLE_BIN} && echo EXEC || echo NOT_EXEC"
assert_contains "stable binary has executable bit" "EXEC" "$CMD_OUTPUT"

# Verify unit file was created on disk
send_cmd "shell test -f ${UNIT_FILE} && echo EXISTS || echo MISSING"
assert_contains "unit file written to ${SYSTEMD_USER_DIR}/" "EXISTS" "$CMD_OUTPUT"

# Verify unit file content has required directives
send_cmd "shell cat ${UNIT_FILE}"
assert_contains "unit file has [Unit] section"       "[Unit]"          "$CMD_OUTPUT"
assert_contains "unit file has [Service] section"    "[Service]"       "$CMD_OUTPUT"
assert_contains "unit file has [Install] section"    "[Install]"       "$CMD_OUTPUT"
assert_contains "unit file has Type=simple"          "Type=simple"     "$CMD_OUTPUT"
assert_contains "unit file has Restart=on-failure"   "Restart=on-failure" "$CMD_OUTPUT"
assert_contains "unit file ExecStart points to stable path" \
    "ExecStart=${STABLE_BIN}" "$CMD_OUTPUT"

# Verify ExecStart does NOT point to the original source path
if echo "$CMD_OUTPUT" | grep -qF "ExecStart=${AGENT_BINARY}"; then
    echo "  ✗ unit file ExecStart must point to stable path, not source ${AGENT_BINARY}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  ✓ unit file ExecStart does not reference source path"
    PASS_COUNT=$((PASS_COUNT + 1))
fi

# Verify wants/ symlink was created
send_cmd "shell test -L ${WANTS_LINK} && echo SYMLINK || echo MISSING"
assert_contains "default.target.wants/ symlink created" "SYMLINK" "$CMD_OUTPUT"

# Verify persist:list now shows the installed unit
send_cmd "persist:list"
assert_contains "persist:list shows installed unit" "$UNIT_NAME" "$CMD_OUTPUT"

# ── persist:systemd — idempotency ─────────────────────────────────────────────

suite "persist:systemd — idempotent reinstall"

send_cmd "persist:systemd ${UNIT_NAME} ${AGENT_BINARY}"
assert_eq "second install exits 0" "0" "$CMD_EXIT"

send_cmd "shell ls ${SYSTEMD_USER_DIR} | grep -c ${UNIT_NAME}"
assert_eq "unit appears exactly once in dir" "1" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

# ── persist:systemd — remove ──────────────────────────────────────────────────

suite "persist:systemd_remove — cleanup"

send_cmd "persist:systemd_remove ${UNIT_NAME}"
assert_eq   "persist:systemd_remove exits 0"        "0"   "$CMD_EXIT"
assert_contains "remove output shows [+] success"   "[+]" "$CMD_OUTPUT"

send_cmd "shell test -f ${UNIT_FILE} && echo EXISTS || echo GONE"
assert_contains "unit file is deleted after remove"  "GONE" "$CMD_OUTPUT"

send_cmd "shell test -L ${WANTS_LINK} && echo EXISTS || echo GONE"
assert_contains "wants symlink is deleted after remove" "GONE" "$CMD_OUTPUT"

# Remove a non-existent unit — must not error
send_cmd "persist:systemd_remove definitely-not-installed"
assert_eq   "remove of non-existent unit exits 0"   "0"   "$CMD_EXIT"
assert_contains "output signals nothing was found"   "[~]" "$CMD_OUTPUT"

# ── persist:profile — install ─────────────────────────────────────────────────

suite "persist:profile — install lifecycle"

PROFILE_STABLE="${STABLE_BIN_DIR}/agent-tls"

send_cmd "persist:profile ${AGENT_BINARY}"
assert_eq "persist:profile exits 0" "0" "$CMD_EXIT"
assert_contains "output shows [+] success"  "[+]"     "$CMD_OUTPUT"
assert_contains "output reports copy step"  "Copied:" "$CMD_OUTPUT"

# Stable binary exists
send_cmd "shell test -f ${PROFILE_STABLE} && echo EXISTS || echo MISSING"
assert_contains "stable binary copied to ~/.local/bin/" "EXISTS" "$CMD_OUTPUT"

# Stable binary is executable
send_cmd "shell test -x ${PROFILE_STABLE} && echo EXEC || echo NOT_EXEC"
assert_contains "stable binary is executable" "EXEC" "$CMD_OUTPUT"

# .bashrc was injected
send_cmd "shell grep -c 'rcm-persist-start' /root/.bashrc || echo 0"
assert_eq ".bashrc contains exactly 1 sentinel block" \
    "1" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

# .profile was injected
send_cmd "shell grep -c 'rcm-persist-start' /root/.profile 2>/dev/null || echo 0"
assert_eq ".profile contains exactly 1 sentinel block" \
    "1" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

# Injected entry references the stable path, not the source
send_cmd "shell grep '${PROFILE_STABLE}' /root/.bashrc 2>/dev/null || echo NOT_FOUND"
assert_contains ".bashrc references stable path" \
    "${PROFILE_STABLE}" "$CMD_OUTPUT"
if echo "$CMD_OUTPUT" | grep -qF "${AGENT_BINARY}"; then
    echo "  ✗ .bashrc must reference stable path, not source ${AGENT_BINARY}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  ✓ .bashrc does not contain original source path"
    PASS_COUNT=$((PASS_COUNT + 1))
fi

# Entry has the double-launch guard
send_cmd "shell grep 'pgrep' /root/.bashrc"
assert_contains ".bashrc entry includes pgrep guard" "pgrep" "$CMD_OUTPUT"

# Entry backgrounds the process
send_cmd "shell grep ' &$' /root/.bashrc"
assert_contains ".bashrc entry runs agent in background" "&" "$CMD_OUTPUT"

# ── persist:profile — idempotency ────────────────────────────────────────────

suite "persist:profile — idempotent reinstall"

send_cmd "persist:profile ${AGENT_BINARY}"
assert_eq "second profile install exits 0" "0" "$CMD_EXIT"

send_cmd "shell grep -c 'rcm-persist-start' /root/.bashrc || echo 0"
assert_eq "sentinel still appears exactly once after second install" \
    "1" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

# ── persist:profile — remove ──────────────────────────────────────────────────

suite "persist:profile_remove — cleanup"

# Seed some pre-existing content so we can verify it survives removal
send_cmd "shell grep -c 'PATH' /root/.bashrc || echo 0"
LINES_BEFORE=$(echo "$CMD_OUTPUT" | tr -d '[:space:]')

send_cmd "persist:profile_remove ${PROFILE_STABLE}"
assert_eq   "persist:profile_remove exits 0"       "0"   "$CMD_EXIT"
assert_contains "remove output shows [+] success"  "[+]" "$CMD_OUTPUT"

# Sentinel is gone
send_cmd "shell bash -c 'c=\$(grep -c rcm-persist-start /root/.bashrc 2>/dev/null); echo \${c:-0}'"
assert_eq "sentinel removed from .bashrc" "0" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

send_cmd "shell bash -c 'c=\$(grep -c rcm-persist-start /root/.profile 2>/dev/null); echo \${c:-0}'"
assert_eq "sentinel removed from .profile" "0" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

# Pre-existing content was preserved (PATH lines are always there)
send_cmd "shell grep -c 'PATH' /root/.bashrc || echo 0"
LINES_AFTER=$(echo "$CMD_OUTPUT" | tr -d '[:space:]')
if [ "$LINES_AFTER" -ge "$LINES_BEFORE" ] 2>/dev/null; then
    echo "  ✓ pre-existing .bashrc content survived removal"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ pre-existing .bashrc content was lost during removal ($LINES_AFTER < $LINES_BEFORE)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Remove when nothing is installed — must not error
send_cmd "persist:profile_remove /no/such/binary"
assert_eq   "remove-nonexistent exits 0" "0"   "$CMD_EXIT"
assert_contains "output signals nothing found" "[~]" "$CMD_OUTPUT"

# ── Stable drop survival ───────────────────────────────────────────────────────
#
# The whole point of stable_drop: persistence must keep working even if the
# operator deletes the originally-uploaded binary from its temp location.

suite "persist:systemd — stable copy survives source deletion"

# Copy agent binary to a temp path (simulates uploaded-to-/tmp workflow)
TMP_SRC="/tmp/rcm_func_test_source_$$"
send_cmd "shell cp ${AGENT_BINARY} ${TMP_SRC} && echo OK"
assert_contains "temp source binary created" "OK" "$CMD_OUTPUT"

SURV_UNIT="rcm-survival-test"
SURV_STABLE="${STABLE_BIN_DIR}/${SURV_UNIT}"

send_cmd "persist:systemd ${SURV_UNIT} ${TMP_SRC}"
assert_eq "systemd install with temp source exits 0" "0" "$CMD_EXIT"

# Delete the original temp source
send_cmd "shell rm ${TMP_SRC} && echo DELETED"
assert_contains "temp source binary deleted" "DELETED" "$CMD_OUTPUT"

# Stable copy must still exist
send_cmd "shell test -f ${SURV_STABLE} && echo SURVIVES || echo GONE"
assert_contains "stable copy survives deletion of source" "SURVIVES" "$CMD_OUTPUT"

# Stable copy is still executable
send_cmd "shell test -x ${SURV_STABLE} && echo EXEC || echo NOT_EXEC"
assert_contains "surviving stable copy is still executable" "EXEC" "$CMD_OUTPUT"

# Clean up
send_cmd "persist:systemd_remove ${SURV_UNIT}"
assert_eq "cleanup of survival test unit exits 0" "0" "$CMD_EXIT"

# ── persist:cron — conditional on crontab availability ───────────────────────

suite "persist:cron — install and remove"

send_cmd "shell which crontab 2>/dev/null && echo AVAILABLE || echo UNAVAILABLE"
CRON_AVAIL=$(echo "$CMD_OUTPUT" | tr -d '[:space:]')

if echo "$CRON_AVAIL" | grep -q "UNAVAILABLE"; then
    skip "crontab binary not in agent container — skipping cron tests"
else
    CRON_STABLE="${STABLE_BIN_DIR}/agent-tls"

    send_cmd "persist:cron ${AGENT_BINARY}"
    assert_eq "persist:cron exits 0" "0" "$CMD_EXIT"
    assert_contains "output shows [+] success"  "[+]"      "$CMD_OUTPUT"
    assert_contains "output shows @reboot entry" "@reboot"  "$CMD_OUTPUT"
    assert_contains "output reports copy step"   "Copied:"  "$CMD_OUTPUT"

    # Crontab entry uses the stable path
    send_cmd "shell crontab -l"
    assert_contains "crontab shows @reboot entry"        "@reboot"     "$CMD_OUTPUT"
    assert_contains "crontab entry references stable path" \
        "${CRON_STABLE}" "$CMD_OUTPUT"

    # Idempotency: second install must not add a duplicate entry
    send_cmd "persist:cron ${AGENT_BINARY}"
    send_cmd "shell crontab -l | grep -c 'agent-tls' || echo 0"
    assert_eq "cron entry appears exactly once" \
        "1" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

    # Remove
    send_cmd "persist:cron_remove ${CRON_STABLE}"
    assert_eq "persist:cron_remove exits 0" "0" "$CMD_EXIT"
    assert_contains "remove output shows [+]" "[+]" "$CMD_OUTPUT"

    send_cmd "shell crontab -l 2>/dev/null | grep -c 'agent-tls' || echo 0"
    assert_eq "crontab entry removed" \
        "0" "$(echo "$CMD_OUTPUT" | tr -d '[:space:]')"

    # Remove again — must be graceful
    send_cmd "persist:cron_remove /no/such/entry"
    assert_eq   "remove nonexistent cron exits 0" "0"   "$CMD_EXIT"
    assert_contains "nonexistent cron remove is graceful" "[~]" "$CMD_OUTPUT"
fi

# ── persist:list — reflects installed state ───────────────────────────────────
#
# Install something, verify list shows it, remove it, verify list clears.

suite "persist:list — live state reflection"

send_cmd "persist:systemd rcm-list-test ${AGENT_BINARY}"
assert_eq "install for list test exits 0" "0" "$CMD_EXIT"

send_cmd "persist:list"
assert_contains "list shows newly installed unit" "rcm-list-test" "$CMD_OUTPUT"

send_cmd "persist:systemd_remove rcm-list-test"
assert_eq "remove for list test exits 0" "0" "$CMD_EXIT"

send_cmd "persist:list"
# After removal the unit name must not appear under the Systemd section
if echo "$CMD_OUTPUT" | grep -qF "rcm-list-test"; then
    echo "  ✗ persist:list still shows removed unit 'rcm-list-test'"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  ✓ persist:list no longer shows removed unit"
    PASS_COUNT=$((PASS_COUNT + 1))
fi

# ── Platform-guard errors over the wire ───────────────────────────────────────
#
# On a Linux agent, Windows-only commands must return a non-zero exit code
# with a message that contains "Windows" — not an unhandled panic.

suite "persist:* — platform guard errors (Linux agent)"

# The error text ("Windows only", "macOS only") is returned in the agent's
# stderr/extra Reply field, which the server logs with [-] but does not
# include in the API's `output` field. Non-zero exit code is therefore
# the correct wire-level signal that a platform guard fired.

send_cmd "persist:run TestKey C:\\agent.exe"
assert_ne "persist:run exit code is non-zero on Linux" "0" "$CMD_EXIT"
if echo "$CMD_OUTPUT" | grep -qi "windows"; then
    echo "  ✓ persist:run error mentions Windows"
    PASS_COUNT=$((PASS_COUNT + 1))
elif [ "$CMD_EXIT" != "0" ]; then
    echo "  ✓ persist:run correctly rejected on Linux (exit $CMD_EXIT)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ persist:run error mentions Windows"
    echo "    got: $CMD_OUTPUT"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

send_cmd "persist:run_hklm TestKey C:\\agent.exe"
assert_ne "persist:run_hklm exit code is non-zero on Linux" "0" "$CMD_EXIT"
if echo "$CMD_OUTPUT" | grep -qi "windows"; then
    echo "  ✓ persist:run_hklm error mentions Windows"
    PASS_COUNT=$((PASS_COUNT + 1))
elif [ "$CMD_EXIT" != "0" ]; then
    echo "  ✓ persist:run_hklm correctly rejected on Linux (exit $CMD_EXIT)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ persist:run_hklm error mentions Windows"
    echo "    got: $CMD_OUTPUT"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

send_cmd "persist:task TestTask C:\\agent.exe"
assert_ne "persist:task exit code is non-zero on Linux" "0" "$CMD_EXIT"
if echo "$CMD_OUTPUT" | grep -qi "windows"; then
    echo "  ✓ persist:task error mentions Windows"
    PASS_COUNT=$((PASS_COUNT + 1))
elif [ "$CMD_EXIT" != "0" ]; then
    echo "  ✓ persist:task correctly rejected on Linux (exit $CMD_EXIT)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ persist:task error mentions Windows"
    echo "    got: $CMD_OUTPUT"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

send_cmd "persist:startup agent.exe C:\\agent.exe"
assert_ne "persist:startup exit code is non-zero on Linux" "0" "$CMD_EXIT"
if echo "$CMD_OUTPUT" | grep -qi "windows"; then
    echo "  ✓ persist:startup error mentions Windows"
    PASS_COUNT=$((PASS_COUNT + 1))
elif [ "$CMD_EXIT" != "0" ]; then
    echo "  ✓ persist:startup correctly rejected on Linux (exit $CMD_EXIT)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ persist:startup error mentions Windows"
    echo "    got: $CMD_OUTPUT"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

send_cmd "persist:launchagent com.test.agent /tmp/agent"
assert_ne "persist:launchagent exit code is non-zero on Linux" "0" "$CMD_EXIT"
if echo "$CMD_OUTPUT" | grep -qi "macos\|mac os"; then
    echo "  ✓ persist:launchagent error mentions macOS"
    PASS_COUNT=$((PASS_COUNT + 1))
elif [ "$CMD_EXIT" != "0" ]; then
    echo "  ✓ persist:launchagent correctly rejected on Linux (exit $CMD_EXIT)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ persist:launchagent error mentions macOS"
    echo "    got: $CMD_OUTPUT"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ── Missing-argument handling over the wire ───────────────────────────────────
#
# Each handler must return a usage string (not crash) when args are absent.
# Tested here against the real agent to confirm the dispatcher routes correctly.

suite "persist:* — argument validation over the wire"

for cmd in \
    "persist:run" \
    "persist:run_hklm" \
    "persist:task" \
    "persist:startup" \
    "persist:systemd" \
    "persist:profile" \
    "persist:launchagent"
do
    send_cmd "${cmd}"
    # Exit code 1 and output must mention usage (regardless of platform)
    if echo "$CMD_OUTPUT" | grep -qi "usage\|Usage"; then
        echo "  ✓ ${cmd} (blank args) returns usage hint"
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [ "$CMD_EXIT" != "0" ]; then
        echo "  ✓ ${cmd} (blank args) returns non-zero exit (platform or usage error)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ ${cmd} (blank args) exited 0 without a usage hint — potential silent failure"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

# ── Output message contract ───────────────────────────────────────────────────
#
# Every successful install must produce a message starting with [+].
# Every graceful "nothing to do" must produce a message starting with [~].
# These are relied upon by the panel's log display.

suite "persist:* — output message contract"

# [+] prefix on success
send_cmd "persist:systemd rcm-contract-test ${AGENT_BINARY}"
assert_eq "install exits 0"      "0"   "$CMD_EXIT"
assert_contains "success has [+]" "[+]" "$CMD_OUTPUT"

# [+] prefix on successful remove
send_cmd "persist:systemd_remove rcm-contract-test"
assert_eq   "remove exits 0"        "0"   "$CMD_EXIT"
assert_contains "remove has [+]"    "[+]" "$CMD_OUTPUT"

# [~] prefix when nothing to remove
send_cmd "persist:systemd_remove rcm-contract-test"
assert_eq   "second remove exits 0"          "0"   "$CMD_EXIT"
assert_contains "second remove has [~]" "[~]" "$CMD_OUTPUT"

print_summary
