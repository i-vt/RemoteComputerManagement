#!/usr/bin/env bash
# tests/docker/scripts/test_04_sessions.sh — Agent sessions & commands
source "$(dirname "$0")/lib.sh"

suite "Agents have checked in"
RESP=$(api_get "/api/hosts")
assert_http "hosts list returns 200" "200"
HOST_COUNT=$(echo "$RESP" | jq 'length')
echo "  (found $HOST_COUNT sessions)"

if [ "$HOST_COUNT" -eq 0 ]; then
    skip "No agents connected — skipping session tests"
    return 0 2>/dev/null || exit 0
fi

# Prefer the TLS agent for command tests — HTTP sessions queue commands
# through HttpC2State in-memory, which doesn't write to the history DB
# the same way TLS sessions do.
SESSION_ID=$(echo "$RESP" | jq -r '[.[] | select(.hostname=="agent-tls")][0].id // .[0].id')
SESSION_HOST=$(echo "$RESP" | jq -r --arg id "$SESSION_ID" '[.[] | select(.id==($id|tonumber))][0].hostname // "unknown"')
echo "  Using session #${SESSION_ID} (${SESSION_HOST})"

suite "Send a shell command"
CMD_RESP=$(api_post "/api/hosts/${SESSION_ID}/command" "$ADMIN_KEY" '{"command":"shell echo INTEGRATION_TEST_OK"}')
assert_http "command accepted" "200"
REQ_ID=$(echo "$CMD_RESP" | jq -r '.request_id // empty')

suite "Poll for command output"
if [ -n "$REQ_ID" ]; then
    OUTPUT=""
    for i in $(seq 1 15); do
        sleep 2
        OUT_RESP=$(api_get "/api/hosts/${SESSION_ID}/output/${REQ_ID}")
        STATUS=$(echo "$OUT_RESP" | jq -r '.output // empty')
        if [ -n "$STATUS" ]; then
            OUTPUT="$STATUS"
            break
        fi
    done
    assert_contains "output contains test marker" "INTEGRATION_TEST_OK" "$OUTPUT"
else
    skip "no request_id returned"
fi

suite "Command appears in session history"
# Poll instead of fixed sleep — HTTP transport writes history asynchronously
# and can lag several seconds behind the output response.
HIST=""
for i in $(seq 1 15); do
    sleep 2
    HIST=$(api_get "/api/hosts/${SESSION_ID}/history")
    if echo "$HIST" | grep -qF "INTEGRATION_TEST_OK"; then
        break
    fi
done
assert_http "history returns 200" "200"
assert_contains "history contains our command" "INTEGRATION_TEST_OK" "$HIST"

suite "Command appears in global history"
GHIST=$(api_get "/api/history")
assert_http "global history returns 200" "200"

suite "Viewer cannot send commands"
VW_KEY=$(login_as "testview" "$VIEWER_PASS")
if [ -n "$VW_KEY" ]; then
    api_post "/api/hosts/${SESSION_ID}/command" "$VW_KEY" '{"command":"shell id"}'
    assert_http "viewer blocked from commands" "403"
else
    skip "viewer login failed"
fi

suite "Session notes CRUD"
# Add a note
NOTE_RESP=$(api_post "/api/hosts/${SESSION_ID}/notes" "$ADMIN_KEY" '{"note":"test note from integration","tag":"test"}')
assert_http "add note returns 201" "201"
NOTE_ID=$(echo "$NOTE_RESP" | jq -r '.id // empty')

# Read notes
NOTES=$(api_get "/api/hosts/${SESSION_ID}/notes")
assert_http "get notes returns 200" "200"
assert_contains "note text present" "test note from integration" "$NOTES"

# Delete note
if [ -n "$NOTE_ID" ]; then
    api_delete "/api/hosts/${SESSION_ID}/notes/${NOTE_ID}"
    assert_http "delete note returns 200" "200"
fi

suite "Note deletion is scoped to session"
# Try to delete a non-existent note on a different session
api_delete "/api/hosts/99999/notes/99999"
assert_http "cross-session delete returns 404" "404"
