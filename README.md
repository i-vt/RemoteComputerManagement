# RCM — Remote Computer Management

A modular command-and-control framework written in Rust.
<img width="1333" height="773" alt="image" src="https://github.com/user-attachments/assets/e01b1c59-93c3-4ca4-8d19-50737a98c8fc" />

## Features

- **Multi-transport**: Raw TLS, TCP, named pipes, HTTP(S) with proxy support
- **Malleable profiles**: Traffic shaping to mimic legitimate services (Slack, Google Drive, CDN)
- **SNI/ALPN overrides**: Control TLS ClientHello fields independently of the C2 host — fronting-ready
- **Fallback resilience**: 4 strategies (priority, round-robin, random, failover) with per-endpoint profiles
- **Domain generation**: Seed-based DGA injects algorithmically-derived fallback domains per time window
- **Hibernation mode**: Dweller model — agent connects, claims a task batch, executes, disconnects, sleeps; no persistent socket
- **Multi-operator**: Role-based access (admin/operator/viewer), per-operator audit trail
- **Dynamic listeners**: Create, start, stop listeners from the panel without server restart
- **Job system**: Background task execution with streamed output
- **Topology planner**: Passive network-interface analysis to rank pivot candidates toward a target IP/CIDR
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

# Build a standard persistent agent
cargo run --bin builder -- \
  --host <C2_IP> --port 4443 --transport tls --platform linux

# Build a hibernation agent (no persistent socket)
cargo run --bin builder -- \
  --host <C2_IP> --port 4443 --transport tls --platform linux \
  --hibernation --batch-size 5

# Build an agent with CDN fronting
cargo run --bin builder -- \
  --host <CDN_IP> --port 443 --transport tls --platform windows \
  --sni legitimate-site.com --alpn h2,http/1.1

# Open panel/index.html in a browser, login with printed credentials
```

## Documentation

See [`docs/`](docs/README.md) for the full documentation:

- [Architecture](docs/architecture.md) — system design and data flow
- [Deployment](docs/deployment.md) — server setup and first run
- [Builder Guide](docs/builder.md) — compiling agents
- [Operator Guide](docs/operator-guide.md) — workflows and OPSEC
- [Command Reference](docs/commands.md) — all 39 agent commands
- [API Reference](docs/api.md) — 34 REST endpoints
- [Extensions](docs/extensions.md) — writing Rhai scripts (32 native bindings)
- [Fallback & DGA](docs/fallback.md) — multi-host resilience templates and domain generation
- [Evasion](docs/evasion.md) — defense bypass techniques
- [Panel Guide](docs/panel.md) — UI walkthrough and shortcuts
- [Testing](docs/testing.md) — 229+ tests across 10 test locations

## Project Structure

```
src/
├── bin/            # server, client, client_dll, client_service, stager, builder
├── agent/          # config, handlers, jobs, fallback, dga, hibernation, evasion,
│                   # syscalls, inmem, migrate, artifacts, pivot, injection,
│                   # keylogger, scripting, http_transport
├── server/         # mod, session, listeners, http_listener, logging
├── api/            # mod, state, middleware, models, routes/
├── common.rs       # shared types, transport protocol, C2Config, DgaConfig
├── transport.rs    # TCP/TLS/pipe stream abstraction, SNI/ALPN configuration
├── topology.rs     # passive network-interface topology inference
├── traffic.rs      # malleable profile transforms
├── database.rs     # SQLite schema + CRUD, queued_tasks table
├── file_transfer.rs
├── socks.rs        # SOCKS5 proxy
├── pki.rs          # TLS certificate handling
└── utils.rs        # shell exec, process list, network interfaces, self-destruct
panel/              # static HTML/JS web interface
tests/              # integration tests
fallback_profiles/  # 7 pre-built fallback JSON templates
traffic_profiles/   # malleable C2 traffic profiles
modules/            # Rhai recon/crypto modules
extensions/         # Rhai extension scripts
```

## Contributors

* Mad respect to my homie [Emp](https://github.com/Emp5r0R) — he a chill guy. Some features were yoinked from his project [labyrinth](https://github.com/Emp5r0R/labyrinth).
* Props to [Vovanus](https://github.com/LimerBoy) for doing QA on the web ui. Homie is a big expert on deving offensive tooling (with love n care)
* & special thank you to Sofazavr 

## Disclaimer

This software is provided for authorized security testing only. Unauthorized access to computer systems is illegal. See the full disclaimer at the bottom of this file.

Users are solely responsible for ensuring their use complies with all applicable laws.

