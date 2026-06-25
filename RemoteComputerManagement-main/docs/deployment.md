# Deployment

## Prerequisites
- Rust toolchain (stable)
- OpenSSL (for certificate generation)
- Cross-compilation targets if building for Windows from Linux:
  ```
  rustup target add x86_64-pc-windows-gnu
  apt install mingw-w64
  ```

## Certificates

Generate the mTLS certificate chain:

```bash
./gen_certs.sh
```

This creates `certs/ca.crt`, `certs/server.crt`, `certs/server.key.der`, `certs/client.crt`, `certs/client.key.der`.

## First Run

```bash
cargo build --release --bin server
./target/release/server
```

On first run the server:
1. Initializes `c2_audit.db` (SQLite)
2. Imports certificates into the database
3. Creates a default `admin` operator and prints credentials
4. Creates a default TLS listener on port 4443
5. Starts the API server on `127.0.0.1:8080`

**Save the printed admin password and API key.** You'll need them to log into the panel.

## Panel

The panel is a static HTML/JS app in `panel/`. Serve it from any web server or open `panel/index.html` directly. Point it at `http://127.0.0.1:8080` and log in with the admin credentials.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `C2_TRANSPORT` | `tls` | Default transport for the built-in listener |

## Database

All state lives in `c2_audit.db`:
- Sessions, command history, client outputs
- Operator accounts and API keys
- Listener configurations
- Build keys and malleable profiles
- Auto-recon commands
- Session notes and tags
- Audit log
- Webhook URL
