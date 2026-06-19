#!/usr/bin/env bash
# tests/docker/scripts/test_12_hibernation.sh
#
# Integration tests for the hibernation task queue:
#   POST /api/hosts/:id/queue        — enqueue a command
#   GET  /api/hosts/:id/tasks        — list all tasks
#   GET  /api/hosts/:id/tasks/:id    — fetch one task by UUID
#   DELETE /api/hosts/:id/tasks/:id  — cancel a pending task
#
# Two test tiers:
#
#   API contract tests — always run; verify endpoint shapes and error codes
#     against any connected session (persistent or hibernating).
#
#   End-to-end task completion — only runs when a hibernating agent from
#     test_10 is connected. Queues a command, waits for the agent to
#     check in, verifies the task reaches 'completed' status.
#
# Note: test_10_builder_features.sh writes the hibernation agent job ID
# to /shared/hibernation_agent_job_id. This test reads it and downloads
# the binary to /shared/agent-hib, then runs it.

set -uo pipefail
source "$(dirname "$0")/lib.sh"

TASK_COMPLETE_TIMEOUT="${TASK_COMPLETE_TIMEOUT:-120}"

# ── Pick a session for API contract tests ─────────────────────────────────
SESSIONS=$(api_get "/api/hosts")
SESSION_ID=$(echo "$SESSIONS" | jq -r '.[0].id // empty')

# ══════════════════════════════════════════════════════
suite "Task queue API — endpoint exists"
# ══════════════════════════════════════════════════════

if [ -z "$SESSION_ID" ]; then
    # Even without a session, hitting a non-existent ID should return 404 or 200.
    # The queue endpoint should NOT 500.
    RESP=$(curl -s -w '\n%{http_code}' \
        -X POST "${C2_URL}/api/hosts/9999/queue" \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"command":"shell id"}' 2>/dev/null)
    HTTP_CODE=$(echo "$RESP" | tail -1)
    if [ "$HTTP_CODE" != "500" ] && [ "$HTTP_CODE" != "000" ]; then
        echo "  ✓ queue endpoint is reachable (HTTP $HTTP_CODE)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ✗ queue endpoint returned unexpected $HTTP_CODE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    skip "No sessions connected — skipping session-specific tests"
    print_summary
    exit $((FAIL_COUNT > 0 ? 1 : 0))
fi

echo "  Using session #${SESSION_ID}"

# ══════════════════════════════════════════════════════
suite "Task queue — enqueue a command"
# ══════════════════════════════════════════════════════

QUEUE_RESP=$(api_post "/api/hosts/${SESSION_ID}/queue" "$ADMIN_KEY" '{"command":"shell echo HIBTEST_MARKER"}')
assert_http "task queued returns 201" "201"
assert_contains "response has task_id"     '"task_id"'    "$QUEUE_RESP"
assert_contains "response has command"     '"command"'    "$QUEUE_RESP"
assert_contains "response has status"      '"status"'     "$QUEUE_RESP"
TASK_ID=$(echo "$QUEUE_RESP" | jq -r '.task_id // empty')
assert_ne "task_id is non-empty UUID" "" "$TASK_ID"

STATUS_INITIAL=$(echo "$QUEUE_RESP" | jq -r '.status // "unknown"')
assert_eq "initial status is pending" "pending" "$STATUS_INITIAL"

# ══════════════════════════════════════════════════════
suite "Task queue — empty command rejected"
# ══════════════════════════════════════════════════════

BAD_RESP=$(api_post "/api/hosts/${SESSION_ID}/queue" "$ADMIN_KEY" '{"command":""}')
assert_http "empty command returns 400" "400"
assert_contains "error message present" '"error"' "$BAD_RESP"

# ══════════════════════════════════════════════════════
suite "Task queue — list tasks"
# ══════════════════════════════════════════════════════

LIST_RESP=$(api_get "/api/hosts/${SESSION_ID}/tasks")
assert_http "tasks list returns 200" "200"
assert_contains "response has tasks array" '"tasks"' "$LIST_RESP"
assert_contains "response has total" '"total"' "$LIST_RESP"

TASK_COUNT=$(echo "$LIST_RESP" | jq '.total // 0')
if [ "$TASK_COUNT" -ge 1 ]; then
    echo "  ✓ tasks list contains $TASK_COUNT task(s)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ tasks list is empty (expected >= 1)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Verify our specific task is in the list
if echo "$LIST_RESP" | jq '.tasks[].task_id' | grep -q "$TASK_ID"; then
    echo "  ✓ our queued task appears in the list"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ✗ our task_id not found in list"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ══════════════════════════════════════════════════════
suite "Task queue — get single task"
# ══════════════════════════════════════════════════════

if [ -n "$TASK_ID" ]; then
    TASK_RESP=$(api_get "/api/hosts/${SESSION_ID}/tasks/${TASK_ID}")
    assert_http "get single task returns 200" "200"
    assert_contains "task has task_id field"   '"task_id"'   "$TASK_RESP"
    assert_contains "task has command field"   '"command"'   "$TASK_RESP"
    assert_contains "task has status field"    '"status"'    "$TASK_RESP"
    RETRIEVED_CMD=$(echo "$TASK_RESP" | jq -r '.command // ""')
    assert_contains "command matches what we queued" "HIBTEST_MARKER" "$RETRIEVED_CMD"

    # Non-existent task should 404
    MISSING=$(api_get "/api/hosts/${SESSION_ID}/tasks/non-existent-uuid-12345")
    assert_http "non-existent task returns 404" "404"
fi

# ══════════════════════════════════════════════════════
suite "Task queue — RBAC (viewer cannot queue)"
# ══════════════════════════════════════════════════════

VW_KEY=$(login_as "testview" "$VIEWER_PASS" 2>/dev/null || echo "")
if [ -n "$VW_KEY" ]; then
    api_post "/api/hosts/${SESSION_ID}/queue" "$VW_KEY" '{"command":"shell id"}' > /dev/null
    assert_http "viewer blocked from queuing" "403"
else
    skip "viewer account not available"
fi

# ══════════════════════════════════════════════════════
suite "Task queue — cancel a pending task"
# ══════════════════════════════════════════════════════

# Queue a second task specifically for cancellation
CANCEL_RESP=$(api_post "/api/hosts/${SESSION_ID}/queue" "$ADMIN_KEY" '{"command":"shell sleep 999"}')
CANCEL_TASK_ID=$(echo "$CANCEL_RESP" | jq -r '.task_id // empty')
assert_ne "cancel-target task_id non-empty" "" "$CANCEL_TASK_ID"

if [ -n "$CANCEL_TASK_ID" ]; then
    DEL_RESP=$(curl -s -w '\n%{http_code}' \
        -X DELETE \
        -H "X-API-KEY: ${ADMIN_KEY}" \
        "${C2_URL}/api/hosts/${SESSION_ID}/tasks/${CANCEL_TASK_ID}" 2>/dev/null)
    DEL_CODE=$(echo "$DEL_RESP" | tail -1)
    if [ "$DEL_CODE" = "204" ]; then
        echo "  ✓ cancel pending task returns 204"
        PASS_COUNT=$((PASS_COUNT + 1))
        # Verify it's now cancelled
        AFTER=$(api_get "/api/hosts/${SESSION_ID}/tasks/${CANCEL_TASK_ID}")
        AFTER_STATUS=$(echo "$AFTER" | jq -r '.status // ""')
        assert_eq "cancelled task status = cancelled" "cancelled" "$AFTER_STATUS"
    else
        echo "  ✗ cancel task returned $DEL_CODE (expected 204)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
fi

# ══════════════════════════════════════════════════════
suite "End-to-end: hibernation agent completes a queued task"
# ══════════════════════════════════════════════════════
#
# This suite only runs if:
#   (a) test_10 built a hibernating agent and saved the job ID
#   (b) that agent is now connected (has a session)
#
# The hibernating agent runs with --sleep 10 so it checks in every 10s
# during tests. We wait up to TASK_COMPLETE_TIMEOUT seconds for completion.

HIB_SESSION=""

# Check if any connected session is in hibernation mode
HIB_SESSION=$(echo "$SESSIONS" | \
    jq -r '[.[] | select(.hibernation_mode == true)][0].id // empty' 2>/dev/null || echo "")

if [ -z "$HIB_SESSION" ]; then
    skip "No hibernating session connected — start the agent from test_10's build first"
    print_summary
    exit $((FAIL_COUNT > 0 ? 1 : 0))
fi

echo "  Found hibernating session #${HIB_SESSION}"

# Queue our test task
E2E_QUEUE=$(api_post "/api/hosts/${HIB_SESSION}/queue" "$ADMIN_KEY" '{"command":"shell echo HIB_E2E_COMPLETE"}')
assert_http "e2e task queued" "201"
E2E_TASK_ID=$(echo "$E2E_QUEUE" | jq -r '.task_id // empty')

if [ -z "$E2E_TASK_ID" ]; then
    skip "Failed to queue e2e task"
    print_summary
    exit $((FAIL_COUNT > 0 ? 1 : 0))
fi

echo "  Queued task $E2E_TASK_ID, waiting up to ${TASK_COMPLETE_TIMEOUT}s..."

# Poll for completion
COMPLETED=0
DEADLINE=$(($(date +%s) + TASK_COMPLETE_TIMEOUT))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    TASK_STATE=$(api_get "/api/hosts/${HIB_SESSION}/tasks/${E2E_TASK_ID}")
    STATUS=$(echo "$TASK_STATE" | jq -r '.status // "pending"')
    case "$STATUS" in
        completed)
            COMPLETED=1
            break
            ;;
        failed)
            echo "  ✗ task failed: $(echo "$TASK_STATE" | jq -r '.error // "unknown"')"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            break
            ;;
    esac
    sleep 3
done

if [ "$COMPLETED" -eq 1 ]; then
    echo "  ✓ task reached 'completed' status"
    PASS_COUNT=$((PASS_COUNT + 1))

    RESULT=$(api_get "/api/hosts/${HIB_SESSION}/tasks/${E2E_TASK_ID}" | jq -r '.result // ""')
    assert_contains "task result contains expected output" "HIB_E2E_COMPLETE" "$RESULT"
else
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "  ✗ task did not complete within ${TASK_COMPLETE_TIMEOUT}s (still: $STATUS)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
fi

print_summary
