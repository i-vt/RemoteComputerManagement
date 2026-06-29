#!/usr/bin/env bash
# gen_certs.sh — Generate a self-signed CA + server/client certificate bundle.
# Auto-detects all local and public IPs and includes them in the SAN.
set -euo pipefail

# ── Error trap — never fail silently ─────────────────────────────────────────
trap 'echo ""; echo "[!] FAILED at line ${LINENO}: ${BASH_COMMAND}"; echo "[!] Exit code: $?"; exit 1' ERR

CERTS_DIR="${1:-./certs}"
mkdir -p "$CERTS_DIR"

echo "[*] Generating TLS certificates in $CERTS_DIR ..."

# ── Collect IPs ───────────────────────────────────────────────────────────────

SAN_IPS=("127.0.0.1")

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'; read -ra o <<< "$1"
    for octet in "${o[@]}"; do (( octet <= 255 )) || return 1; done
}

add_ip() {
    local ip="$1"
    is_ipv4 "$ip" || return 0
    [[ "$ip" == "127."* ]] && return 0
    for existing in "${SAN_IPS[@]}"; do
        [[ "$existing" == "$ip" ]] && return 0
    done
    SAN_IPS+=("$ip")
}

LOCAL_IPS=$(ip -4 addr show 2>/dev/null \
    | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)

if [[ -z "$LOCAL_IPS" ]]; then
    echo "[!] 'ip addr' returned nothing — falling back to hostname -I"
    LOCAL_IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' || true)
fi

while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    add_ip "$ip"
done <<< "$LOCAL_IPS"

PUBLIC_IP=""
for provider in \
    "https://api.ipify.org" \
    "https://icanhazip.com" \
    "https://ifconfig.me/ip" \
    "https://checkip.amazonaws.com"; do
    candidate=$(curl -s --max-time 5 "$provider" 2>/dev/null | tr -d '[:space:]') || true
    if is_ipv4 "$candidate"; then
        PUBLIC_IP="$candidate"
        break
    fi
done

if [[ -n "$PUBLIC_IP" ]]; then
    add_ip "$PUBLIC_IP"
    echo "[*] Public IP:  $PUBLIC_IP"
else
    echo "[!] Could not detect public IP — skipping."
fi

if (( ${#SAN_IPS[@]} == 1 )); then
    echo "[!] WARNING: Only 127.0.0.1 detected. Agents on other hosts will fail to connect."
fi

echo "[*] All IPs:    ${SAN_IPS[*]}"

# ── Build SAN string ──────────────────────────────────────────────────────────

SAN_STRING=""
for ip in "${SAN_IPS[@]}"; do
    SAN_STRING+="IP:${ip},"
done
SAN_STRING="${SAN_STRING%,}"
echo "[*] SAN:        $SAN_STRING"

# ── Write extension configs to temp files ─────────────────────────────────────
# Explicit temp files — process substitution reads /etc/ssl/openssl.cnf on
# some distros, which injects the machine hostname into the SAN.

EXT_SERVER=$(mktemp /tmp/rcm_ext_server_XXXXXX)
EXT_CLIENT=$(mktemp /tmp/rcm_ext_client_XXXXXX)
trap 'echo ""; echo "[!] FAILED at line ${LINENO}: ${BASH_COMMAND}"; echo "[!] Exit code: $?"; rm -f "$EXT_SERVER" "$EXT_CLIENT"; exit 1' ERR
trap 'rm -f "$EXT_SERVER" "$EXT_CLIENT"' EXIT

printf 'basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = %s\n' \
    "$SAN_STRING" > "$EXT_SERVER"

printf 'basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = clientAuth\n' \
    > "$EXT_CLIENT"

# ── CA ────────────────────────────────────────────────────────────────────────
echo "[*] Generating CA key..."
openssl genrsa -out "$CERTS_DIR/ca.key" 4096 2>/dev/null
echo "[*] Signing CA certificate..."
openssl req -x509 -new -nodes \
    -key  "$CERTS_DIR/ca.key" \
    -sha256 -days 3650 \
    -subj "/CN=RCM-CA/O=RCM/C=US" \
    -out  "$CERTS_DIR/ca.crt"

# ── Server cert ───────────────────────────────────────────────────────────────
# NOTE: CN=rcm-server is intentionally different from CA CN=RCM-CA.
# Having identical subject and issuer CN breaks rustls chain verification
# and produces BadSignature. rustls uses SANs for IP/hostname checks,
# not CN, so the CN value here does not affect agent connectivity.
echo "[*] Generating server key..."
openssl genrsa -out "$CERTS_DIR/server.key" 4096 2>/dev/null
echo "[*] Creating server CSR..."
openssl req -new -nodes \
    -key  "$CERTS_DIR/server.key" \
    -subj "/CN=rcm-server/O=RCM/C=US" \
    -out  "$CERTS_DIR/server.csr"
echo "[*] Signing server certificate..."
openssl x509 -req \
    -in       "$CERTS_DIR/server.csr" \
    -CA       "$CERTS_DIR/ca.crt" \
    -CAkey    "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out      "$CERTS_DIR/server.crt" \
    -days 3650 -sha256 \
    -extfile  "$EXT_SERVER"
openssl pkcs8 -topk8 -nocrypt \
    -in     "$CERTS_DIR/server.key" \
    -out    "$CERTS_DIR/server.key.der" \
    -outform DER

# ── Client cert ───────────────────────────────────────────────────────────────
echo "[*] Generating client key..."
openssl genrsa -out "$CERTS_DIR/client.key" 4096 2>/dev/null
echo "[*] Creating client CSR..."
openssl req -new -nodes \
    -key  "$CERTS_DIR/client.key" \
    -subj "/CN=rcm-agent/O=RCM/C=US" \
    -out  "$CERTS_DIR/client.csr"
echo "[*] Signing client certificate..."
openssl x509 -req \
    -in       "$CERTS_DIR/client.csr" \
    -CA       "$CERTS_DIR/ca.crt" \
    -CAkey    "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out      "$CERTS_DIR/client.crt" \
    -days 3650 -sha256 \
    -extfile  "$EXT_CLIENT"
openssl pkcs8 -topk8 -nocrypt \
    -in     "$CERTS_DIR/client.key" \
    -out    "$CERTS_DIR/client.key.der" \
    -outform DER

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "[+] Verifying certificate chain..."
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/server.crt"
openssl verify -CAfile "$CERTS_DIR/ca.crt" "$CERTS_DIR/client.crt"

echo ""
echo "[+] SAN in server certificate:"
openssl x509 -in "$CERTS_DIR/server.crt" -noout -text \
    | grep -A1 "Subject Alternative Name"

echo ""
echo "[+] Certificates written to $CERTS_DIR"
echo "[!] Rebuild agents after regenerating — CA changes invalidate old builds."
