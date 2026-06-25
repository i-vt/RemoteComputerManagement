#!/bin/sh
# tests/docker/scripts/pivot-entrypoint.sh
#
# Generic entrypoint for pivot chain agents. Picks up a specific binary
# from the shared volume based on the PIVOT_BINARY environment variable.
# Retries for up to 180s to account for parent pivot listener startup.

set -eu

BINARY="/shared/${PIVOT_BINARY:-agent-tls}"
NAME="${AGENT_NAME:-pivot-unknown}"

echo "[pivot:${NAME}] Waiting for binary ${BINARY}..."

for i in $(seq 1 180); do
    if [ -f "$BINARY" ] && [ -x "$BINARY" ]; then
        echo "[pivot:${NAME}] Binary found. Waiting ${PIVOT_DELAY:-0}s for parent pivot listener..."
        sleep "${PIVOT_DELAY:-0}"
        echo "[pivot:${NAME}] Starting..."
        exec "$BINARY"
    fi
    sleep 1
done

echo "[pivot:${NAME}] FATAL: binary never appeared after 180s"
exit 1
