# RCM - Remote Computer Management

A modular command-and-control framework written in Rust, built for authorized red team operations.

![Rust](https://img.shields.io/badge/rust-nightly--2026--08--22-orange)
![Tests](https://img.shields.io/badge/tests-1370%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

<img width="2882" height="1910" alt="image" src="https://github.com/user-attachments/assets/9e9f5f1e-b5ea-4d75-b637-9367c78cc8c3" />


## Features

- **Multi-transport** - Raw TLS, TCP, named pipes, HTTP(S) with proxy support
- **Malleable profiles** - Traffic shaping to mimic legitimate services (Slack, Google Drive, CDN); 5 pre-built traffic profiles
- **SNI/ALPN overrides** - Control TLS ClientHello fields independently of the C2 host; domain-fronting ready
- **Fallback resilience** - 4 strategies (priority, round-robin, random, failover) with per-endpoint malleable profiles; 8 pre-built templates
- **Domain generation** - Seed-based DGA injects algorithmically-derived fallback domains per time window
- **Hibernation mode** - Dweller model: agent connects, claims a task batch, executes, disconnects, sleeps; no persistent socket
- **Chunked file transfer** - SHA-256-verified chunked upload and download; handles files over 1 GB with constant RAM usage
- **RCM data collection** - Exfiltrated files, screenshots, and keylogs are packaged per target per the RCM Data Collection & Packaging spec (v2.1): reconstructed target paths under `downloads/`, XML metadata sidecars in `downloads.metadata/`, machine fingerprints, hash-chained chain-of-custody log, and SHA-256 package manifests with seal/verify API (`POST /api/rcm/seal`, `POST /api/rcm/verify`)
- **Loot browser** - Panel-side file browser over the RCM packages with streaming ZIP download of entire folders (no memory buffering)
- **Extensions** - Agent-side Rhai scripts pushed via `ext:load`; 31 built-in extensions including `auto_persist`, a credential pack (browsers, DPAPI, cloud/SSH secrets), injection chains, recon, and crypters. The agent-side engine exposes 187 native functions
- **Modules** - Server-side Rhai scripts with 3 native bindings (`send_c2_command`, `send_c2_extension`, `random_hex_key`); run per session via the API, on session events, or broadcast to all sessions
- **Python bridge** - Portable CPython bootstrap, venvs, offensive-package installs, and persistent Python sessions from inside Rhai extensions
- **Script manager** - Create, edit, and delete extensions and modules live from the panel; no filesystem access required
- **Multi-operator** - Role-based access (admin/operator/viewer), per-operator audit trail
- **Dynamic listeners** - Create, start, and stop listeners from the panel without server restart
- **Job system** - Background task execution with streamed partial output
- **Topology planner** - Passive network-interface analysis to rank pivot candidates toward a target IP/CIDR
- **In-memory execution** - PE loader, BOF runner, .NET CLR hosting
- **Shellcode output** - sRDI-style reflective conversion of the agent DLL to position-independent `.bin` (`--format shellcode`); raw, base64, C-array, or hex encodings. Also donut, OEP sRDI (`pe_to_shellcode`), PIC from C source (`pic_c`), and composable `--pipeline` stage chains
- **Stager** - Minimal (~50 KB) downloader that fetches the full agent over HTTP(S) from `/stage/<build_id>` with per-build HMAC authentication
- **Execution guardrails** - Build-time target lock-in: domain/hostname glob matching, active-hours window, no-SYSTEM exit, parent-process allow-list (`--valid-parents`), VM/sandbox artifact check (`--allow-vm` to opt out)
- **Egress proxy** - Per-build explicit proxy (`--proxy-url/--proxy-user/--proxy-pass`) or per-endpoint overrides in fallback files
- **Process migration** - Spawn or inject into another process
- **Evasion** - AMSI/ETW patching, ntdll unhooking, direct/indirect syscalls, heap encryption (AES-256-GCM), fiber-based stack spoofing
- **Artifact management** - Timestomping, secure deletion, NTFS alternate data streams read/write
- **Pivoting** - TCP and SMB named pipe pivot listeners with multi-hop chains
- **Keylogger** - Background key capture with job-streamed output
- **Auto-recon** - Commands, modules, or extensions that fire automatically on every new session
- **Web panel** - 16 pages (Users is admin-only), keyboard shortcuts, dark/light theme, toast notifications, webhook alerts

## Quick Start

### New Installation

```bash
wget -qO- https://raw.githubusercontent.com/i-vt/InterestingSnippets/refs/heads/main/Linux/QuickSetup.sh | bash && sudo apt purge -y apache2 && wget -qO- https://raw.githubusercontent.com/i-vt/InterestingSnippets/refs/heads/main/Linux/Docker/Install.sh | bash && git clone https://github.com/i-vt/RemoteComputerManagement.git && cd RemoteComputerManagement && chmod +x *.sh && ./gen_certs.sh && ./start_docker.sh && echo "Save the credentials above before continuing."
```

### Upgrade Version

Change directory (cd) into the RCM folder, then run this:

```bash
cp c2_audit.db c2_audit.db.bak_$(date +%Y%m%d_%H%M%S) && docker compose down && git stash && git pull && { git stash pop 2>/dev/null; true; } && ./start_docker.sh
```


## Detailed Installation

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

# Credentials are printed on first start - save them before closing the terminal
```

Restrict access after the server is running:

```bash
# Allow only your team's IPs on the C2 listener and panel/API ports.
# (The panel binds 127.0.0.1:8080 by default; the 8080 rule matters if you
# set server.api_bind_addr to 0.0.0.0 in config.toml.)
ufw allow from <YOUR_IP> to any port 4443
ufw allow from <YOUR_IP> to any port 8080
ufw enable
```

### Bare Metal

`rust-toolchain.toml` pins `nightly-2026-08-22` (with the `rust-src`
component); rustup picks it up automatically. Nightly is required for agent
builds: the OPSEC panic-path stripping flags (`-Zlocation-detail=none`,
`-Ztrim-paths`, `-Zbuild-std`) are unstable, and the builder refuses to
produce agents on stable unless you pass `--allow-stable-leak` (dev builds
only). The server itself compiles on stable, but the pinned toolchain keeps
everything on one channel.

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

# The API server also serves the panel - browse to http://127.0.0.1:8080/
# and log in. (Do not open panel/index.html as a file: its relative fetches
# only resolve when served by the server.)
```

## Documentation

See [`docs/`](docs/README.md):

- [Architecture](docs/architecture.md) - system design and data flow
- [Deployment](docs/deployment.md) - server setup and first run
- [Builder Guide](docs/builder.md) - compiling agents for each platform
- [Operator Guide](docs/operator-guide.md) - workflows and OPSEC notes
- [Command Reference](docs/commands.md) - all 68 agent commands
- [API Reference](docs/api.md) - 60 REST endpoints
- [Extensions](docs/extensions.md) - writing Rhai scripts (187 native functions agent-side, 3 module bindings)
- [Persistence](docs/persistence.md) - auto_persist extension: Windows and Linux techniques
- [Fallback & DGA](docs/fallback.md) - multi-host resilience templates and domain generation
- [Evasion](docs/evasion.md) - defense bypass techniques
- [Panel Guide](docs/panel.md) - UI walkthrough and keyboard shortcuts
- [Testing](docs/testing.md) - 1300+ Rust tests plus 18 Docker end-to-end scripts

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
├── common.rs # shared types, transport protocol, C2Config, DgaConfig
├── transport.rs # TCP/TLS/pipe stream abstraction, SNI/ALPN configuration
├── topology.rs # passive network-interface topology inference
├── traffic.rs # malleable profile transforms
├── database.rs # SQLite schema + CRUD, queued_tasks table
├── file_transfer.rs # chunked download/upload with SHA-256 verification
├── streaming_zip.rs # streaming ZIP writer (ZIP64, data descriptors, O(1) RAM)
├── socks.rs # SOCKS5 proxy
├── pki.rs # TLS certificate handling
└── utils.rs # shell exec, process list, network interfaces, self-destruct
panel/
├── index.html # single-page app (16 pages)
└── js/               # per-page modules, router, extensions manager, loot browser
extensions/           # 31 built-in Rhai agent-side scripts
modules/              # 13 server-side Rhai modules
fallback_profiles/    # 8 pre-built fallback JSON templates
traffic_profiles/     # 5 malleable C2 traffic profiles
tests/                # 43 Rust test files (integration + spec/regression)
│   └── docker/       # 18 end-to-end scripts against a live stack
tools/                # string_audit.sh, dga_precompute.py, PE stub helpers
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

Last recorded full run (`tests/results/last.json`): 1108 unit tests passed, 262 integration checks passed, 0 failed. That covers 767 inline `#[cfg(test)]` tests across `src/`, 636 tests in the 43 files under `tests/`, and the 18 Docker end-to-end scripts (`test_01`-`test_18`). Platform-gated tests (Windows-only paths) account for the difference between the attribute count and the recorded pass count.

## Contributors

- [Emp](https://github.com/Emp5r0R) - several features were adapted from his project [labyrinth](https://github.com/Emp5r0R/labyrinth).
- [Vovanus](https://github.com/LimerBoy) - QA on the web UI.
- Special thanks to Sofazavr.
- [kazusss](https://open.spotify.com/artist/0VntdiB8bfvjW0S1WLiWRV) - banger track, made with love <3

## Disclaimer

This software is provided for authorized security testing and research only. You are solely responsible for ensuring your use complies with all applicable laws and that you have explicit written authorization before testing any system you do not own. The authors accept no liability for misuse or damage caused by this software. Unauthorized access to computer systems is a criminal offence in most jurisdictions.