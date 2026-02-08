#!/bin/bash
set -e 

# [SAFETY FIX] Do not wipe the whole directory, or you lose signing.key!
mkdir -p certs
# Only remove old TLS specific files
rm -f certs/*.crt certs/*.key certs/*.csr certs/*.der certs/*.pem certs/*.srl certs/openssl.cnf

cd certs

echo "[*] Generating Configuration for X.509 v3..."

# ... (Keep the rest of your robust logic exactly as is) ...
cat > openssl.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = localhost

[v3_ca]
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[v3_server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[v3_client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

# 2. Generate CA
echo "[*] Generating CA..."
openssl req -new -x509 -days 365 -nodes -subj "/CN=SecureC2_Root_CA" \
    -keyout ca.key -out ca.crt -config openssl.cnf -extensions v3_ca

# 3. Generate Server Cert
echo "[*] Generating Server Cert..."
openssl req -new -nodes -keyout server.key.pem -out server.csr -config openssl.cnf
# FORCE v3_server extensions
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 \
    -extfile openssl.cnf -extensions v3_server

openssl pkcs8 -topk8 -inform PEM -outform DER -in server.key.pem -out server.key.der -nocrypt

# 4. Generate Client Cert
echo "[*] Generating Client Cert..."
openssl req -new -nodes -keyout client.key.pem -out client.csr -subj "/CN=client_user"
# FORCE v3_client extensions
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 \
    -extfile openssl.cnf -extensions v3_client

openssl pkcs8 -topk8 -inform PEM -outform DER -in client.key.pem -out client.key.der -nocrypt

# Verification
echo "[*] Verifying Certificate Versions..."
openssl x509 -in client.crt -text -noout | grep "Version: 3" && echo "[+] Client Cert is Version 3 (OK)"
openssl x509 -in server.crt -text -noout | grep "Version: 3" && echo "[+] Server Cert is Version 3 (OK)"

# Cleanup
rm *.csr *.pem *.srl openssl.cnf
echo "[+] Done. Certificates generated in ./certs/"
