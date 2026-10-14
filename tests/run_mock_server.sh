#!/usr/bin/env bash
# tests/run_mock_server.sh
#
# Raise the RCM mock C2 server (tests/mock_server.py) for panel UX/UI testing.
# The mock serves the real panel from ./panel plus faux REST APIs, so the
# whole interface can be driven without building or running the Rust server.
#
# Usage:
#   ./tests/run_mock_server.sh                 # http://127.0.0.1:18080
#   ./tests/run_mock_server.sh -p 9000         # custom port
#   ./tests/run_mock_server.sh -v              # log every HTTP request
#   RCM_MOCK_PORT=9000 ./tests/run_mock_server.sh
#
# Then open the printed URL and sign in with one of the demo logins:
#   admin / admin   ·   operator / operator   ·   viewer / viewer
#
# State is in-memory only; Ctrl+C stops the server and resets everything.
#
# Why port 18080 and not the real server's 8080: service workers are bound
# to an origin (host:port), and one registered by ANY app that previously
# ran on 127.0.0.1:8080 keeps intercepting requests - serving stale panel
# files or reload-looping the tab. A fresh port is a fresh origin and
# sidesteps all of that. If the panel ever looks stale or reload-loops,
# just restart on a port you have never used before.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

HOST="${RCM_MOCK_HOST:-127.0.0.1}"
PORT="${RCM_MOCK_PORT:-18080}"
VERBOSE="${RCM_MOCK_VERBOSE:-0}"

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port) PORT="${2:?missing port value}"; shift 2 ;;
        -h|--host) HOST="${2:?missing host value}"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        --help)
            # Print the header comment block (skip shebang, stop at first code line).
            awk 'NR==1 && /^#!/ {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
            exit 0 ;;
        *) echo "[-] Unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] python3 is required but was not found in PATH." >&2
    exit 1
fi

if [ ! -f "$REPO_ROOT/panel/index.html" ]; then
    echo "[-] panel/index.html not found under $REPO_ROOT -" >&2
    echo "    run this script from the RCM repository tree." >&2
    exit 1
fi

# Friendly pre-flight: fail fast if the port is already taken.
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    exec 3>&- 3<&-
    echo "[-] Port $PORT is already in use. Pick another: $0 -p <port>" >&2
    exit 1
fi

echo "[+] Raising mock C2 server for panel UX/UI testing"
echo "[+] Repo root: $REPO_ROOT"
echo "[+] Panel URL: http://$HOST:$PORT/"
echo

cd "$REPO_ROOT"
if [ "$VERBOSE" = "1" ]; then
    exec python3 -u tests/mock_server.py --host "$HOST" --port "$PORT" --verbose
else
    exec python3 -u tests/mock_server.py --host "$HOST" --port "$PORT"
fi
