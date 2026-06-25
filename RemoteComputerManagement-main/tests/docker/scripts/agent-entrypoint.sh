#!/bin/sh
# tests/docker/scripts/agent-entrypoint.sh
#
# Waits for the server to compile the agent binary and place it on
# the shared volume, then runs it.

set -eu

TRANSPORT="${AGENT_TRANSPORT:-tls}"
BINARY="/shared/agent-${TRANSPORT}"

echo "[agent:${AGENT_NAME:-unknown}] Waiting for agent binary at ${BINARY}..."

for i in $(seq 1 120); do
    if [ -f "$BINARY" ] && [ -x "$BINARY" ]; then
        echo "[agent:${AGENT_NAME:-unknown}] Binary found, starting..."
        exec "$BINARY"
    fi
    sleep 1
done

echo "[agent:${AGENT_NAME:-unknown}] FATAL: agent binary never appeared after 120s"
exit 1
