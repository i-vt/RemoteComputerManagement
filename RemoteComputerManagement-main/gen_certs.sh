#!/usr/bin/env bash
# gen_certs.sh — Generate a self-signed CA + server/client certificate bundle
# Run this once before `docker compose up`, or mount your own certs.
set -euo pipefail

CERTS_DIR="${1:-./certs}"
mkdir -p "$CERTS_DIR"

echo "[*] Generating TLS certificates in $CERTS_DIR ..."

# ── CA ────────────────────────────────────────────────────
openssl genrsa -out "$CERTS_DIR/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes \
    -key "$CERTS_DIR/ca.key" \
    -sha256 -days 3650 \
    -subj "/CN=RCM-CA/O=RCM/C=US" \
    -out "$CERTS_DIR/ca.crt"

# ── Server cert (signed by CA) ────────────────────────────
openssl genrsa -out "$CERTS_DIR/server.key" 4096 2>/dev/null
openssl req -new -nodes \
    -key "$CERTS_DIR/server.key" \
    -subj "/CN=rcm-server/O=RCM/C=US" \
    -out "$CERTS_DIR/server.csr"
# -extfile is required for X.509v3 — rustls rejects v1/v2 certs outright.
openssl x509 -req \
    -in  "$CERTS_DIR/server.csr" \
    -CA  "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/server.crt" \
    -days 3650 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:c2-server,DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
# Convert server private key to DER format (what the Rust code loads)
openssl pkcs8 -topk8 -nocrypt \
    -in  "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.key.der" \
    -outform DER

# ── Client cert (signed by CA) ────────────────────────────
openssl genrsa -out "$CERTS_DIR/client.key" 4096 2>/dev/null
openssl req -new -nodes \
    -key "$CERTS_DIR/client.key" \
    -subj "/CN=rcm-agent/O=RCM/C=US" \
    -out "$CERTS_DIR/client.csr"
openssl x509 -req \
    -in  "$CERTS_DIR/client.csr" \
    -CA  "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/client.crt" \
    -days 3650 -sha256 \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n')
# Convert client private key to DER format
openssl pkcs8 -topk8 -nocrypt \
    -in  "$CERTS_DIR/client.key" \
    -out "$CERTS_DIR/client.key.der" \
    -outform DER

echo "[+] Certificates written to $CERTS_DIR"
echo "    ca.crt         — CA certificate (embedded in agents + server)"
echo "    server.crt     — Server TLS certificate"
echo "    server.key.der — Server private key (DER)"
echo "    client.crt     — Client/agent TLS certificate"
echo "    client.key.der — Client/agent private key (DER)"
