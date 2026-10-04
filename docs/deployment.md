# Deployment

## Prerequisites
- Rust toolchain: **nightly, pinned by `rust-toolchain.toml`** (currently
  `nightly-2026-08-22`, with the `rust-src` component - rustup installs it
  automatically on first cargo invocation). Nightly is not optional for agent
  builds: the OPSEC panic-path stripping flags (`-Zlocation-detail=none`,
  `-Ztrim-paths`, `-Zbuild-std` with immediate-abort panics) are unstable, and
  the builder refuses to build agents on stable unless `--allow-stable-leak`
  is passed (dev builds only). The server alone does compile on stable.
- OpenSSL (for certificate generation)
- Cross-compilation targets if building for Windows from Linux:
  ```
  rustup target add x86_64-pc-windows-gnu
  apt install mingw-w64
  ```

## Docker

`start_docker.sh` is the recommended path. The root `Dockerfile` is a
five-stage build:

1. **build** - `rustlang/rust:nightly-2026-08-22` base with `rust-src`, the
   windows-gnu and linux-musl targets, mingw, and osslsigncode; also compiles
   the vendored donut generator at a pinned commit
2. **test** - runs the Rust test suite as a build gate; a failing test fails
   the image build
3. **agents** - builds the agent binaries used by the integration stack
4. **audit** - runs `tools/string_audit.sh` over the built agent; any leaked
   path or Rust fingerprint string fails the image build here, in-image
5. **runtime** - `debian:trixie-slim` with only the finished binaries copied
   from the audit stage

A `.dockerignore` at the repo root keeps `target/`, `dist/`, `logs/`,
`certs/`, databases, and `.git` out of the build context, so private CA key
material never lands in image layers. `docker-compose.yml` uses host
networking and mounts `config.docker.toml` as `/app/config.toml`.

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

The panel is a static HTML/JS app in `panel/`, served by the API server itself
at `http://127.0.0.1:8080/` (`GET /` serves `panel/index.html`, and
`/panel/*` serves its assets). Do not open `panel/index.html` as a `file://`
document: the app issues relative fetches that only resolve when served by the
server. Log in with the admin credentials from the first run.

The API/panel binds `127.0.0.1:8080` by default (`server.api_bind_addr`,
`server.api_port` in `config.toml`). Only rebind to `0.0.0.0` behind a
firewall rule - the panel and REST API share that port and are protected only
by the API key.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RCM_CONFIG` | *(unset)* | Path to the TOML config overlay. When unset, `./config.toml` in the working directory is used if present; otherwise embedded defaults apply. An empty value is treated as unset. |

All other operational values (ports, limits, transfer sizes, logging) are keys
in the config tree - see `config.example.toml` and
[Configuration and String Encryption](config-and-encryption.md).

## Database

All state lives in `c2_audit.db`:
- Sessions, command history, client outputs
- Operator accounts (`operators`) and per-login API keys (`operator_sessions`)
- Listener configurations
- Build keys and malleable profiles
- Auto-recon commands
- Session notes and tags
- IOC records (`iocs`)
- Hibernation task queue (`queued_tasks`)
- Audit log
- Webhook URL (`server_config`)