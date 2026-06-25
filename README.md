# RCM — Remote Computer Management

A modular command-and-control framework written in Rust, built for authorized red team operations.

![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![Tests](https://img.shields.io/badge/tests-317%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

<img width="1333" height="773" alt="RCM panel screenshot" src="https://github.com/user-attachments/assets/e01b1c59-93c3-4ca4-8d19-50737a98c8fc" />

## Features

- **Multi-transport** — Raw TLS, TCP, named pipes, HTTP(S) with proxy support
- **Malleable profiles** — Traffic shaping to mimic legitimate services (Slack, Google Drive, CDN); 5 pre-built traffic profiles
- **SNI/ALPN overrides** — Control TLS ClientHello fields independently of the C2 host; domain-fronting ready
- **Fallback resilience** — 4 strategies (priority, round-robin, random, failover) with per-endpoint malleable profiles; 7 pre-built templates
- **Domain generation** — Seed-based DGA injects algorithmically-derived fallback domains per time window
- **Hibernation mode** — Dweller model: agent connects, claims a task batch, executes, disconnects, sleeps; no persistent socket
- **Chunked file transfer** — SHA-256-verified chunked upload and download; handles files over 1 GB with constant RAM usage
- **Loot browser** — Panel-side file browser with streaming ZIP download of entire folders (no memory buffering)
- **Extensions** — Agent-side Rhai scripts pushed via `ext:load`; 44 built-in extensions including `auto_persist`, injection chains, recon, and crypters
- **Modules** — Server-side Rhai scripts with 34 native bindings; executed on session events or on demand
- **Script manager** — Create, edit, and delete extensions and modules live from the panel; no filesystem access required
- **Multi-operator** — Role-based access (admin/operator/viewer), per-operator audit trail
- **Dynamic listeners** — Create, start, and stop listeners from the panel without server restart
- **Job system** — Background task execution with streamed partial output
- **Topology planner** — Passive network-interface analysis to rank pivot candidates toward a target IP/CIDR
- **In-memory execution** — PE loader, BOF runner, .NET CLR hosting
- **Process migration** — Spawn or inject into another process
- **Evasion** — AMSI/ETW patching, ntdll unhooking, direct/indirect syscalls, heap encryption (AES-256-GCM), fiber-based stack spoofing
- **Artifact management** — Timestomping, secure deletion, NTFS alternate data streams read/write
- **Pivoting** — TCP and SMB named pipe pivot listeners with multi-hop chains
- **Keylogger** — Background key capture with job-streamed output
- **Auto-recon** — Commands, modules, or extensions that fire automatically on every new session
- **Web panel** — 15 pages, keyboard shortcuts, dark/light theme, toast notifications, webhook alerts

## Quick Start

### Docker (recommended)

```bash
# Install Docker
# https://docs.docker.com/engine/install/debian/

# Clone the repository
git clone https://github.com/i-vt/RemoteComputerManagement.git
cd RemoteComputerManagement

# Generate TLS certificates and start
./gen_certs.sh
./start_docker.sh

# Credentials are printed on first start — save them before closing the terminal
```

Restrict access after the server is running:

```bash
# Allow only your team's IPs on the C2 and panel ports
ufw allow from <YOUR_IP> to any port 4443
ufw allow from <YOUR_IP> to any port 8443
ufw enable
```

### Bare Metal

```bash
# Build the server
cargo build --release --bin server

# Generate certificates and start (creates admin account on first run)
./gen_certs.sh
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

# Open panel/index.html in a browser and log in
```

## Documentation

See [`docs/`](docs/README.md):

- [Architecture](docs/architecture.md) — system design and data flow
- [Deployment](docs/deployment.md) — server setup and first run
- [Builder Guide](docs/builder.md) — compiling agents for each platform
- [Operator Guide](docs/operator-guide.md) — workflows and OPSEC notes
- [Command Reference](docs/commands.md) — all 45 agent commands
- [API Reference](docs/api.md) — 54 REST endpoints
- [Extensions](docs/extensions.md) — writing Rhai scripts (34 native bindings)
- [Persistence](docs/persistence.md) — auto_persist extension: Windows and Linux techniques
- [Fallback & DGA](docs/fallback.md) — multi-host resilience templates and domain generation
- [Evasion](docs/evasion.md) — defense bypass techniques
- [Panel Guide](docs/panel.md) — UI walkthrough and keyboard shortcuts
- [Testing](docs/testing.md) — 317+ tests across 19 test locations

## Project Structure

```
src/
├── bin/              # server, client, client_dll, client_service, stager, builder
├── agent/            # config, handlers, jobs, fallback, dga, hibernation, evasion,
│                     # syscalls, inmem, migrate, artifacts, pivot, injection,
│                     # keylogger, scripting, http_transport
├── server/           # mod, session, listeners, http_listener, logging
├── api/              # mod, state, middleware, models, routes/
│   └── routes/       # hosts, modules, extensions, listeners, builder,
│                     # downloads, history, operators, proxies, tasks, topology
├── common.rs         # shared types, transport protocol, C2Config, DgaConfig
├── transport.rs      # TCP/TLS/pipe stream abstraction, SNI/ALPN configuration
├── topology.rs       # passive network-interface topology inference
├── traffic.rs        # malleable profile transforms
├── database.rs       # SQLite schema + CRUD, queued_tasks table
├── file_transfer.rs  # chunked download/upload with SHA-256 verification
├── streaming_zip.rs  # streaming ZIP writer (ZIP64, data descriptors, O(1) RAM)
├── socks.rs          # SOCKS5 proxy
├── pki.rs            # TLS certificate handling
└── utils.rs          # shell exec, process list, network interfaces, self-destruct
panel/
├── index.html        # single-page app (15 pages)
└── js/               # per-page modules, router, extensions manager, loot browser
extensions/           # 44 built-in Rhai agent-side scripts
modules/              # server-side Rhai modules
fallback_profiles/    # 7 pre-built fallback JSON templates
traffic_profiles/     # 5 malleable C2 traffic profiles
tests/                # 13 integration test files
docs/                 # full documentation
```

## Testing

```bash
# All unit tests (fast, no server needed)
./run_tests.sh

# One module only
./run_tests.sh --module extension

# Full integration suite
./run_tests.sh --integration

# Unit + integration + pivot chains
./run_tests.sh --all --pivot
```

317 tests passing across 19 test locations (13 integration test files + 6 inline `#[test]` modules).

## Contributors

- [Emp](https://github.com/Emp5r0R) — several features were adapted from his project [labyrinth](https://github.com/Emp5r0R/labyrinth).
- [Vovanus](https://github.com/LimerBoy) — QA on the web UI.
- Special thanks to Sofazavr.

## Disclaimer

This software is provided for authorized security testing and research only. You are solely responsible for ensuring your use complies with all applicable laws and that you have explicit written authorization before testing any system you do not own. The authors accept no liability for misuse or damage caused by this software. Unauthorized access to computer systems is a criminal offence in most jurisdictions.
