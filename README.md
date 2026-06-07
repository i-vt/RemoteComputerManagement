# RCM — Remote Computer Management

A modular command-and-control framework written in Rust.
<img width="1333" height="773" alt="image" src="https://github.com/user-attachments/assets/e01b1c59-93c3-4ca4-8d19-50737a98c8fc" />

## Features

- **Multi-transport**: Raw TLS, TCP, named pipes, HTTP(S) with proxy support
- **Malleable profiles**: Traffic shaping to mimic legitimate services (Slack, Google Drive, CDN)
- **Fallback resilience**: 4 strategies (priority, round-robin, random, failover) with per-endpoint profiles
- **Multi-operator**: Role-based access (admin/operator/viewer), per-operator audit trail
- **Dynamic listeners**: Create, start, stop listeners from the panel without server restart
- **Job system**: Background task execution with streamed output
- **In-memory execution**: PE loader, BOF runner, .NET CLR hosting
- **Process migration**: Spawn or inject into another process
- **Evasion**: AMSI/ETW patching, ntdll unhooking, direct/indirect syscalls, heap encryption, fiber-based stack spoofing
- **Artifact management**: Timestomping, secure deletion, NTFS alternate data streams
- **Pivoting**: TCP and SMB named pipe pivot listeners with multi-hop chains
- **Auto-recon**: Commands that fire automatically on every new session
- **Web panel**: 10 pages, keyboard shortcuts, dark/light theme, toast notifications, webhook alerts

## Quick Start

```bash
# Build server
cargo build --release --bin server

# Run (creates admin account on first run)
./target/release/server

# Build an agent
cargo run --bin builder -- \
  --host <C2_IP> --port 4443 --transport tls --platform linux

# Open panel/index.html in a browser, login with printed credentials
```

## Documentation

See [`docs/`](docs/README.md) for the full documentation:

- [Architecture](docs/architecture.md) — system design and data flow
- [Deployment](docs/deployment.md) — server setup and first run
- [Builder Guide](docs/builder.md) — compiling agents
- [Operator Guide](docs/operator-guide.md) — workflows and OPSEC
- [Command Reference](docs/commands.md) — all 38 agent commands
- [API Reference](docs/api.md) — 28 REST endpoints
- [Extensions](docs/extensions.md) — writing Rhai scripts (32 native bindings)
- [Fallback Profiles](docs/fallback.md) — 7 pre-built resilience templates
- [Evasion](docs/evasion.md) — defense bypass techniques
- [Panel Guide](docs/panel.md) — UI walkthrough and shortcuts
- [Testing](docs/testing.md) — 67 tests across 7 test locations

## Project Structure

```
src/
├── bin/            # server, client, client_dll, client_service, stager, builder
├── agent/          # config, handlers, jobs, fallback, evasion, syscalls,
│                   # inmem, migrate, artifacts, pivot, injection, keylogger,
│                   # scripting, http_transport
├── server/         # mod, session, listeners, http_listener, logging
├── api/            # mod, state, middleware, models, routes/
├── common.rs       # shared types, transport protocol, C2 config
├── transport.rs    # TCP/TLS/pipe stream abstraction
├── traffic.rs      # malleable profile transforms
├── database.rs     # SQLite schema + CRUD
├── file_transfer.rs
├── socks.rs        # SOCKS5 proxy
├── pki.rs          # TLS certificate handling
└── utils.rs        # shell exec, process list, self-destruct
panel/              # static HTML/JS web interface
tests/              # integration tests
fallback_profiles/  # 7 pre-built fallback JSON templates
traffic_profiles/   # malleable C2 traffic profiles
modules/            # Rhai recon/crypto modules
extensions/         # Rhai extension scripts
```

## Disclaimer

This software is provided for authorized security testing only. Unauthorized access to computer systems is illegal. See the full disclaimer at the bottom of this file.

Users are solely responsible for ensuring their use complies with all applicable laws.

