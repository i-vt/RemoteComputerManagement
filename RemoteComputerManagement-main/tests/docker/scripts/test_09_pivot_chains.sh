#!/usr/bin/env bash
# tests/docker/scripts/test_09_pivot_chains.sh — Pivot chain & stress tests
#
# Orchestrates multi-hop pivot chains, then tests EVERY hop individually:
#   - Command execution at each depth
#   - SOCKS forward proxy on each hop (start/verify/stop)
#   - Reverse port forward on each hop (start/curl/stop)
#   - All while the pivot chain remains active
#
# Profiles:
#   PIVOT_TEST=1                    → Chain 0 (Linux-only, 4-hop)
#   PIVOT_TEST=1 + WINDOWS_AGENT=1 → All 4 chains (mixed platforms)
source "$(dirname "$0")/lib.sh"

if [ "${PIVOT_TEST:-0}" != "1" ]; then
    skip "Pivot tests not enabled (set PIVOT_TEST=1 via docker-compose.pivot.yml)"
    print_summary
    exit 0
fi

# ── Helpers ─────────────────────────────────────────────────────────────

find_session() {
    local hostname="$1"
    api_get "/api/hosts" | jq -r --arg h "$hostname" '[.[] | select(.hostname==$h)][0].id // empty'
}

wait_session() {
    local hostname="$1" timeout="${2:-60}"
    for i in $(seq 1 "$timeout"); do
        local sid
        sid=$(find_session "$hostname")
        if [ -n "$sid" ]; then echo "$sid"; return 0; fi
        sleep 1
    done
    echo ""; return 1
}

send_cmd() {
    local session_id="$1" cmd="$2" timeout="${3:-15}"
    local resp rid
    resp=$(api_post "/api/hosts/${session_id}/command" "$ADMIN_KEY" "{\"command\":\"${cmd}\"}")
    rid=$(echo "$resp" | jq -r '.request_id // empty')
    [ -z "$rid" ] && { echo ""; return 1; }
    for i in $(seq 1 $((timeout * 2))); do
        local out val
        out=$(api_get "/api/hosts/${session_id}/output/${rid}")
        val=$(echo "$out" | jq -r '.output // empty')
        [ -n "$val" ] && { echo "$val"; return 0; }
        sleep 0.5
    done
    echo ""; return 1
}

start_pivot() {
    local session_id="$1" port="$2" label="$3"
    local result
    result=$(send_cmd "$session_id" "pivot:listener_tcp ${port}" 10)
    if [ -n "$result" ]; then
        echo "  ✓ ${label}: pivot listener on port ${port} (session #${session_id})"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ ${label}: failed to start pivot on port ${port}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# ── setup_chain: orchestrate a 4-hop chain, return session IDs ──────────

setup_chain() {
    local chain="$1" h1="$2" h2="$3" h3="$4" h4="$5"
    local p1="$6" p2="$7" p3="$8"

    suite "Chain ${chain}: hop1 (${h1}) connects to C2"
    local s1; s1=$(wait_session "$h1" 30)
    if [ -z "$s1" ]; then
        echo "  ✗ ${h1} never checked in"; FAIL_COUNT=$((FAIL_COUNT + 1)); return 1
    fi
    echo "  ✓ ${h1} → session #${s1}"; PASS_COUNT=$((PASS_COUNT + 1))

    suite "Chain ${chain}: start pivot on hop1 (port ${p1})"
    start_pivot "$s1" "$p1" "hop1"

    suite "Chain ${chain}: hop2 (${h2}) through pivot"
    local s2; s2=$(wait_session "$h2" 45)
    if [ -z "$s2" ]; then
        echo "  ✗ ${h2} never checked in"; FAIL_COUNT=$((FAIL_COUNT + 1)); return 1
    fi
    echo "  ✓ ${h2} → session #${s2}"; PASS_COUNT=$((PASS_COUNT + 1))

    suite "Chain ${chain}: start pivot on hop2 (port ${p2})"
    start_pivot "$s2" "$p2" "hop2"

    suite "Chain ${chain}: hop3 (${h3}) through pivot"
    local s3; s3=$(wait_session "$h3" 45)
    if [ -z "$s3" ]; then
        echo "  ✗ ${h3} never checked in"; FAIL_COUNT=$((FAIL_COUNT + 1)); return 1
    fi
    echo "  ✓ ${h3} → session #${s3}"; PASS_COUNT=$((PASS_COUNT + 1))

    suite "Chain ${chain}: start pivot on hop3 (port ${p3})"
    start_pivot "$s3" "$p3" "hop3"

    suite "Chain ${chain}: hop4 (${h4}) through pivot (deepest)"
    local s4; s4=$(wait_session "$h4" 45)
    if [ -z "$s4" ]; then
        echo "  ✗ ${h4} never checked in"; FAIL_COUNT=$((FAIL_COUNT + 1)); return 1
    fi
    echo "  ✓ ${h4} → session #${s4} (leaf)"; PASS_COUNT=$((PASS_COUNT + 1))

    echo "${s1}:${s2}:${s3}:${s4}"
}

# ── test_hop_commands: run a command on each hop in the chain ───────────

test_hop_commands() {
    local chain="$1" s1="$2" s2="$3" s3="$4" s4="$5"

    suite "Chain ${chain}: execute command on hop1 (direct)"
    local o1; o1=$(send_cmd "$s1" "shell echo C${chain}_HOP1_OK" 15)
    assert_contains "hop1 command OK" "C${chain}_HOP1_OK" "$o1"

    suite "Chain ${chain}: execute command on hop2 (1 pivot)"
    local o2; o2=$(send_cmd "$s2" "shell echo C${chain}_HOP2_OK" 15)
    assert_contains "hop2 command OK" "C${chain}_HOP2_OK" "$o2"

    suite "Chain ${chain}: execute command on hop3 (2 pivots)"
    local o3; o3=$(send_cmd "$s3" "shell echo C${chain}_HOP3_OK" 20)
    assert_contains "hop3 command OK" "C${chain}_HOP3_OK" "$o3"

    suite "Chain ${chain}: execute command on hop4 (3 pivots)"
    local o4; o4=$(send_cmd "$s4" "shell echo C${chain}_HOP4_OK" 20)
    assert_contains "hop4 command OK" "C${chain}_HOP4_OK" "$o4"

    suite "Chain ${chain}: file roundtrip on hop4"
    local b64; b64=$(echo -n "PIVOT_C${chain}_PAYLOAD" | base64)
    local wr; wr=$(send_cmd "$s4" "file:write|/tmp/pivot_c${chain}.txt|${b64}" 20)
    assert_contains "hop4 file write" "File written" "$wr"
    local rd; rd=$(send_cmd "$s4" "file:read|/tmp/pivot_c${chain}.txt" 20)
    assert_contains "hop4 file read" "file:data" "$rd"
}

# ── test_hop_socks: SOCKS proxy start/verify/stop on each hop ──────────

test_hop_socks() {
    local chain="$1" s1="$2" s2="$3" s3="$4" s4="$5"
    local sids=("$s1" "$s2" "$s3" "$s4")
    local hop_names=("hop1(direct)" "hop2(1-pivot)" "hop3(2-pivot)" "hop4(3-pivot)")

    for idx in 0 1 2 3; do
        local sid="${sids[$idx]}"
        local label="${hop_names[$idx]}"

        suite "Chain ${chain}: SOCKS proxy on ${label}"

        # Start
        local presp; presp=$(api_post "/api/hosts/${sid}/proxy")
        assert_http "start proxy on ${label}" "200"
        local sport; sport=$(echo "$presp" | jq -r '.socks_port // empty')
        assert_ne "socks port assigned on ${label}" "" "$sport"

        # Verify in list
        local plist; plist=$(api_get "/api/proxies")
        local found; found=$(echo "$plist" | jq --argjson s "$sid" '[.[] | select(.session_id==$s)] | length')
        assert_ne "proxy listed for ${label}" "0" "$found"

        # Stop
        api_delete "/api/hosts/${sid}/proxy"
        assert_http "stop proxy on ${label}" "200"

        # Verify removed
        local plist2; plist2=$(api_get "/api/proxies")
        local gone; gone=$(echo "$plist2" | jq --argjson s "$sid" '[.[] | select(.session_id==$s)] | length')
        assert_eq "proxy cleaned up for ${label}" "0" "$gone"
    done
}

# ── test_hop_rportfwd: reverse port forward on each hop ─────────────────

test_hop_rportfwd() {
    local chain="$1" s1="$2" s2="$3" s3="$4" s4="$5" port_base="$6"
    local sids=("$s1" "$s2" "$s3" "$s4")
    local hop_names=("hop1(direct)" "hop2(1-pivot)" "hop3(2-pivot)" "hop4(3-pivot)")

    for idx in 0 1 2 3; do
        local sid="${sids[$idx]}"
        local label="${hop_names[$idx]}"
        local bind_port=$((port_base + idx + 1))   # e.g. 19001..19004

        suite "Chain ${chain}: rportfwd on ${label} (bind:${bind_port})"

        # Start
        api_post "/api/hosts/${sid}/rportfwd" "$ADMIN_KEY" \
            "{\"bind_port\":${bind_port},\"target_host\":\"mock-service\",\"target_port\":80}"
        assert_http "start rportfwd on ${label}" "200"

        # Verify in list
        local rlist; rlist=$(api_get "/api/rportfwds")
        local rfound; rfound=$(echo "$rlist" | jq --argjson s "$sid" '[.[] | select(.session_id==$s)] | length')
        assert_ne "rportfwd listed for ${label}" "0" "$rfound"

        # Curl through the tunnel
        sleep 3
        local mock; mock=$(curl -sf --max-time 8 "http://c2-server:${bind_port}/" 2>/dev/null || echo "FAIL")
        if echo "$mock" | grep -qF "MOCK_SERVICE_OK"; then
            echo "  ✓ rportfwd on ${label} delivers content (port ${bind_port})"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo "  ✗ rportfwd on ${label} failed (port ${bind_port}): $(echo "$mock" | head -1)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi

        # Stop
        api_delete "/api/hosts/${sid}/rportfwd" "$ADMIN_KEY" "{\"bind_port\":${bind_port}}"
        assert_http "stop rportfwd on ${label}" "200"
    done
}

# ════════════════════════════════════════════════════════════════════════
# §1  Chain 0: C2 → Linux → Linux → Linux → Linux
# ════════════════════════════════════════════════════════════════════════

suite "Chain 0 setup (Linux-only: L→L→L→L)"
C0_RAW=$(setup_chain "0" "c0-hop1" "c0-hop2" "c0-hop3" "c0-hop4" 5001 5002 5003)
C0_IDS=$(echo "$C0_RAW" | tail -1)

if echo "$C0_IDS" | grep -q ":"; then
    C0_S1=$(echo "$C0_IDS" | cut -d: -f1)
    C0_S2=$(echo "$C0_IDS" | cut -d: -f2)
    C0_S3=$(echo "$C0_IDS" | cut -d: -f3)
    C0_S4=$(echo "$C0_IDS" | cut -d: -f4)

    test_hop_commands "0" "$C0_S1" "$C0_S2" "$C0_S3" "$C0_S4"
    test_hop_socks    "0" "$C0_S1" "$C0_S2" "$C0_S3" "$C0_S4"
    test_hop_rportfwd "0" "$C0_S1" "$C0_S2" "$C0_S3" "$C0_S4" 19000
else
    echo "  ✗ Chain 0 setup failed — skipping per-hop tests"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ════════════════════════════════════════════════════════════════════════
# §2  Chain 1: C2 → Linux → Windows → Windows → Linux
# ════════════════════════════════════════════════════════════════════════

if [ "${WINDOWS_AGENT:-0}" = "1" ]; then

suite "Chain 1 setup (L→W→W→L)"
C1_RAW=$(setup_chain "1" "c1-hop1" "c1-hop2" "c1-hop3" "c1-hop4" 5101 5102 5103)
C1_IDS=$(echo "$C1_RAW" | tail -1)

if echo "$C1_IDS" | grep -q ":"; then
    C1_S1=$(echo "$C1_IDS" | cut -d: -f1)
    C1_S2=$(echo "$C1_IDS" | cut -d: -f2)
    C1_S3=$(echo "$C1_IDS" | cut -d: -f3)
    C1_S4=$(echo "$C1_IDS" | cut -d: -f4)

    test_hop_commands "1" "$C1_S1" "$C1_S2" "$C1_S3" "$C1_S4"
    test_hop_socks    "1" "$C1_S1" "$C1_S2" "$C1_S3" "$C1_S4"
    test_hop_rportfwd "1" "$C1_S1" "$C1_S2" "$C1_S3" "$C1_S4" 19100
fi

# ════════════════════════════════════════════════════════════════════════
# §3  Chain 2: C2 → Windows → Windows → Linux → Linux
# ════════════════════════════════════════════════════════════════════════

suite "Chain 2 setup (W→W→L→L)"
C2P_RAW=$(setup_chain "2" "c2-hop1" "c2-hop2" "c2-hop3" "c2-hop4" 5201 5202 5203)
C2P_IDS=$(echo "$C2P_RAW" | tail -1)

if echo "$C2P_IDS" | grep -q ":"; then
    C2P_S1=$(echo "$C2P_IDS" | cut -d: -f1)
    C2P_S2=$(echo "$C2P_IDS" | cut -d: -f2)
    C2P_S3=$(echo "$C2P_IDS" | cut -d: -f3)
    C2P_S4=$(echo "$C2P_IDS" | cut -d: -f4)

    test_hop_commands "2" "$C2P_S1" "$C2P_S2" "$C2P_S3" "$C2P_S4"
    test_hop_socks    "2" "$C2P_S1" "$C2P_S2" "$C2P_S3" "$C2P_S4"
    test_hop_rportfwd "2" "$C2P_S1" "$C2P_S2" "$C2P_S3" "$C2P_S4" 19200
fi

# ════════════════════════════════════════════════════════════════════════
# §4  Chain 3: C2 → Windows → Linux → Windows → Linux
# ════════════════════════════════════════════════════════════════════════

suite "Chain 3 setup (W→L→W→L)"
C3_RAW=$(setup_chain "3" "c3-hop1" "c3-hop2" "c3-hop3" "c3-hop4" 5301 5302 5303)
C3_IDS=$(echo "$C3_RAW" | tail -1)

if echo "$C3_IDS" | grep -q ":"; then
    C3_S1=$(echo "$C3_IDS" | cut -d: -f1)
    C3_S2=$(echo "$C3_IDS" | cut -d: -f2)
    C3_S3=$(echo "$C3_IDS" | cut -d: -f3)
    C3_S4=$(echo "$C3_IDS" | cut -d: -f4)

    test_hop_commands "3" "$C3_S1" "$C3_S2" "$C3_S3" "$C3_S4"
    test_hop_socks    "3" "$C3_S1" "$C3_S2" "$C3_S3" "$C3_S4"
    test_hop_rportfwd "3" "$C3_S1" "$C3_S2" "$C3_S3" "$C3_S4" 19300
fi

fi  # end WINDOWS_AGENT check

# ════════════════════════════════════════════════════════════════════════
# §5  Session Topology Verification
# ════════════════════════════════════════════════════════════════════════

suite "Session topology: pivot relationships visible"
ALL_HOSTS=$(api_get "/api/hosts")
assert_http "hosts list returns 200" "200"
TOTAL=$(echo "$ALL_HOSTS" | jq 'length')
PIVOTED=$(echo "$ALL_HOSTS" | jq '[.[] | select(.parent_id != null)] | length')
echo "  Total sessions: $TOTAL, Pivoted: $PIVOTED"
assert_ne "pivoted sessions exist" "0" "$PIVOTED"

# ════════════════════════════════════════════════════════════════════════
# §6  Stress Test: Burst Through Deepest Hops
# ════════════════════════════════════════════════════════════════════════

if [ -n "${C0_S4:-}" ]; then

suite "Stress: 20 sequential commands through 4-hop chain"
STRESS_OK=0
STRESS_FAIL=0
T_START=$(date +%s)
for i in $(seq 1 20); do
    OUT=$(send_cmd "$C0_S4" "shell echo STRESS_${i}" 15)
    if echo "$OUT" | grep -qF "STRESS_${i}"; then
        STRESS_OK=$((STRESS_OK + 1))
    else
        STRESS_FAIL=$((STRESS_FAIL + 1))
    fi
done
T_END=$(date +%s)
echo "  ${STRESS_OK}/20 in $((T_END - T_START))s (${STRESS_FAIL} failures)"
assert_eq "all sequential stress commands OK" "0" "$STRESS_FAIL"

suite "Stress: 10 rapid-fire commands (no inter-send wait)"
RAPID_RIDS=()
for i in $(seq 1 10); do
    resp=$(api_post "/api/hosts/${C0_S4}/command" "$ADMIN_KEY" "{\"command\":\"shell echo RAPID_${i}\"}")
    rid=$(echo "$resp" | jq -r '.request_id // empty')
    [ -n "$rid" ] && RAPID_RIDS+=("$rid")
done
echo "  Dispatched ${#RAPID_RIDS[@]} commands"
sleep 10
RAPID_OK=0
for rid in "${RAPID_RIDS[@]}"; do
    out=$(api_get "/api/hosts/${C0_S4}/output/${rid}")
    val=$(echo "$out" | jq -r '.output // empty')
    [ -n "$val" ] && RAPID_OK=$((RAPID_OK + 1))
done
echo "  Received ${RAPID_OK}/${#RAPID_RIDS[@]} responses"
assert_eq "all rapid-fire responses received" "${#RAPID_RIDS[@]}" "$RAPID_OK"

suite "Stress: 64KB file through 4-hop pivot"
LARGE_B64=$(dd if=/dev/urandom bs=1024 count=64 2>/dev/null | base64 | tr -d '\n')
WR=$(send_cmd "$C0_S4" "file:write|/tmp/stress_large.bin|${LARGE_B64}" 30)
assert_contains "64KB written" "File written" "$WR"
RD=$(send_cmd "$C0_S4" "file:read|/tmp/stress_large.bin" 30)
assert_contains "64KB read back" "file:data" "$RD"

fi  # end stress tests

# ════════════════════════════════════════════════════════════════════════
# §7  Simultaneous Proxy + Rportfwd on ALL Hops
# ════════════════════════════════════════════════════════════════════════

if [ -n "${C0_S4:-}" ]; then

suite "All-hops-active: start SOCKS proxy on every chain-0 hop simultaneously"
for sid in $C0_S1 $C0_S2 $C0_S3 $C0_S4; do
    api_post "/api/hosts/${sid}/proxy" > /dev/null
done
PLIST=$(api_get "/api/proxies")
ACTIVE_PROXIES=$(echo "$PLIST" | jq 'length')
assert_eq "4 proxies running simultaneously" "4" "$ACTIVE_PROXIES"

suite "All-hops-active: commands still work on every hop with proxies running"
for hop_i in 1 2 3 4; do
    sid_var="C0_S${hop_i}"
    sid="${!sid_var}"
    OUT=$(send_cmd "$sid" "shell echo PROXY_ACTIVE_HOP${hop_i}" 15)
    assert_contains "hop${hop_i} responds with proxies active" "PROXY_ACTIVE_HOP${hop_i}" "$OUT"
done

suite "All-hops-active: start rportfwd on every hop with proxies still running"
for hop_i in 1 2 3 4; do
    sid_var="C0_S${hop_i}"
    sid="${!sid_var}"
    bp=$((19050 + hop_i))
    api_post "/api/hosts/${sid}/rportfwd" "$ADMIN_KEY" \
        "{\"bind_port\":${bp},\"target_host\":\"mock-service\",\"target_port\":80}" > /dev/null
done
sleep 3
RLIST=$(api_get "/api/rportfwds")
ACTIVE_RFWD=$(echo "$RLIST" | jq 'length')
assert_eq "4 rportfwds running simultaneously" "4" "$ACTIVE_RFWD"

suite "All-hops-active: curl through each rportfwd"
for hop_i in 1 2 3 4; do
    bp=$((19050 + hop_i))
    mock=$(curl -sf --max-time 8 "http://c2-server:${bp}/" 2>/dev/null || echo "FAIL")
    if echo "$mock" | grep -qF "MOCK_SERVICE_OK"; then
        echo "  ✓ rportfwd port ${bp} (hop${hop_i}) delivers content"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ rportfwd port ${bp} (hop${hop_i}) failed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

suite "All-hops-active: commands still work on deepest hop under full load"
OUT=$(send_cmd "$C0_S4" "shell echo FULL_LOAD_OK" 20)
assert_contains "hop4 responds under full proxy+rportfwd load" "FULL_LOAD_OK" "$OUT"

suite "All-hops-active: cleanup all proxies and rportfwds"
for hop_i in 1 2 3 4; do
    sid_var="C0_S${hop_i}"
    sid="${!sid_var}"
    bp=$((19050 + hop_i))
    api_delete "/api/hosts/${sid}/proxy" > /dev/null
    api_delete "/api/hosts/${sid}/rportfwd" "$ADMIN_KEY" "{\"bind_port\":${bp}}" > /dev/null
done
sleep 1
PLIST_FINAL=$(api_get "/api/proxies")
RLIST_FINAL=$(api_get "/api/rportfwds")
P_REMAIN=$(echo "$PLIST_FINAL" | jq 'length')
R_REMAIN=$(echo "$RLIST_FINAL" | jq 'length')
assert_eq "all proxies cleaned up" "0" "$P_REMAIN"
assert_eq "all rportfwds cleaned up" "0" "$R_REMAIN"

fi

print_summary
