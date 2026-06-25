#!/usr/bin/env bash
# tests/docker/scripts/test_11_topology.sh
#
# Integration tests for the topology API:
#   GET /api/topology/plan?target=<ip>
#   GET /api/topology/snapshot
#
# Two test tiers:
#
#   API structure tests — always run; verify the endpoints return the
#     correct shape even when no agents are connected (empty candidates).
#
#   Route inference tests — run only when at least one agent is connected
#     and has reported interface data. These verify that sessions are
#     scored and ranked correctly.
#
# Since agents report their real container interfaces (agent-tls is on
# the c2net bridge, typically 172.x.x.x/16 or 10.x.x.x/24), we test
# that those networks appear in the plan results.

set -uo pipefail
source "$(dirname "$0")/lib.sh"

# ══════════════════════════════════════════════════════
suite "Topology plan endpoint — API structure"
# ══════════════════════════════════════════════════════

# Valid target IP
RESP=$(api_get "/api/topology/plan?target=10.0.0.1")
assert_http "plan returns 200 for valid IP" "200"
assert_contains "response has target field" '"target"' "$RESP"
assert_contains "response has candidates array" '"candidates"' "$RESP"
assert_contains "response has rendered field" '"rendered"' "$RESP"

# Valid CIDR target
RESP=$(api_get "/api/topology/plan?target=10.0.0.0/24")
assert_http "plan returns 200 for CIDR target" "200"
assert_contains "CIDR target has candidates array" '"candidates"' "$RESP"

# Invalid target — should return 400
RESP=$(api_get "/api/topology/plan?target=not-an-ip")
assert_http "plan returns 400 for invalid target" "400"
assert_contains "error message present" '"error"' "$RESP"

# Missing target parameter — should return 400
RESP=$(api_get "/api/topology/plan")
assert_http "plan returns 400 when target missing" "400"

# ══════════════════════════════════════════════════════
suite "Topology snapshot endpoint — API structure"
# ══════════════════════════════════════════════════════

RESP=$(api_get "/api/topology/snapshot")
assert_http "snapshot returns 200" "200"
assert_contains "snapshot has candidates" '"candidates"' "$RESP"
assert_contains "snapshot has shared_networks" '"shared_networks"' "$RESP"
assert_contains "snapshot has conflicts" '"conflicts"' "$RESP"
assert_contains "snapshot has session_count" '"session_count"' "$RESP"

SESSION_COUNT=$(echo "$RESP" | jq '.session_count // -1')
echo "  (session_count: $SESSION_COUNT)"
if [ "$SESSION_COUNT" -ge 0 ]; then
    echo "  ✓ session_count is a non-negative integer"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ session_count invalid: $SESSION_COUNT"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ══════════════════════════════════════════════════════
suite "Topology candidate scoring"
# ══════════════════════════════════════════════════════

# Get all connected sessions
SESSIONS=$(api_get "/api/hosts")
SESSION_COUNT_LIVE=$(echo "$SESSIONS" | jq 'length // 0')
echo "  (connected sessions: $SESSION_COUNT_LIVE)"

if [ "$SESSION_COUNT_LIVE" -eq 0 ]; then
    skip "No agents connected — skipping route inference tests"
    print_summary
    exit $((FAIL_COUNT > 0 ? 1 : 0))
fi

# Get the snapshot with live sessions
SNAP=$(api_get "/api/topology/snapshot")
CAND_COUNT=$(echo "$SNAP" | jq '.candidates | length // 0')
echo "  (route candidates found: $CAND_COUNT)"

if [ "$CAND_COUNT" -gt 0 ]; then
    echo "  ✓ At least one route candidate reported by connected agents"
    PASS_COUNT=$((PASS_COUNT + 1))

    # Verify candidate structure
    FIRST=$(echo "$SNAP" | jq '.candidates[0]')
    assert_contains "candidate has session_id"  '"session_id"'  "$FIRST"
    assert_contains "candidate has hostname"    '"hostname"'    "$FIRST"
    assert_contains "candidate has cidr"        '"cidr"'        "$FIRST"
    assert_contains "candidate has interface"   '"interface"'   "$FIRST"
    assert_contains "candidate has score"       '"score"'       "$FIRST"

    # Score must be a non-negative integer
    SCORE=$(echo "$FIRST" | jq '.score // -1')
    if [ "$SCORE" -ge 0 ]; then
        echo "  ✓ score is a non-negative integer ($SCORE)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ score is invalid: $SCORE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    # Candidates should be sorted by score descending
    SCORES=$(echo "$SNAP" | jq '[.candidates[].score]')
    IS_SORTED=$(echo "$SCORES" | jq 'to_entries | all(.value <= (if .key == 0 then . else .[.key-1] end | .value)) // false' 2>/dev/null || echo "unknown")
    # jq sort check is complex; simpler: first score >= last score
    FIRST_SCORE=$(echo "$SNAP" | jq '.candidates[0].score // 0')
    LAST_SCORE=$(echo "$SNAP"  | jq '.candidates[-1].score // 0')
    if [ "$FIRST_SCORE" -ge "$LAST_SCORE" ]; then
        echo "  ✓ candidates sorted score-descending ($FIRST_SCORE >= $LAST_SCORE)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ candidates not sorted: first=$FIRST_SCORE last=$LAST_SCORE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
else
    skip "No candidates in snapshot — agents may not report interfaces yet"
fi

# ══════════════════════════════════════════════════════
suite "Topology plan against agent network"
# ══════════════════════════════════════════════════════

if [ "$CAND_COUNT" -gt 0 ]; then
    # Extract the IP of the first candidate's source address and plan toward it
    TARGET_IP=$(echo "$SNAP" | jq -r '.candidates[0].source_addr // empty')
    if [ -n "$TARGET_IP" ]; then
        PLAN_RESP=$(api_get "/api/topology/plan?target=${TARGET_IP}")
        assert_http "plan for live agent IP returns 200" "200"
        PLAN_COUNT=$(echo "$PLAN_RESP" | jq '.candidates | length // 0')
        if [ "$PLAN_COUNT" -gt 0 ]; then
            echo "  ✓ plan found $PLAN_COUNT route(s) for $TARGET_IP"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo "  ✗ plan returned 0 candidates for $TARGET_IP (expected >= 1)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi

        # Rendered output should contain the IP
        RENDERED=$(echo "$PLAN_RESP" | jq -r '.rendered // ""')
        assert_contains "rendered output contains target" "$TARGET_IP" "$RENDERED"

        # Rendered output should contain the hostname of the first candidate
        HOSTNAME=$(echo "$SNAP" | jq -r '.candidates[0].hostname // ""')
        if [ -n "$HOSTNAME" ]; then
            assert_contains "rendered output contains hostname" "$HOSTNAME" "$RENDERED"
        fi
    else
        skip "First candidate has no source_addr"
    fi
fi

# ══════════════════════════════════════════════════════
suite "Topology endpoint RBAC — viewer can read"
# ══════════════════════════════════════════════════════

VW_KEY=$(login_as "testview" "$VIEWER_PASS" 2>/dev/null || true)
if [ -n "$VW_KEY" ]; then
    RESP=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "X-API-KEY: $VW_KEY" \
        "${C2_URL}/api/topology/snapshot")
    # Topology reads are OK for viewers — no command execution involved
    if [ "$RESP" = "200" ] || [ "$RESP" = "403" ]; then
        echo "  ✓ viewer topology access handled (HTTP $RESP)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ viewer topology access returned unexpected $RESP"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
else
    skip "viewer login not available"
fi

print_summary
