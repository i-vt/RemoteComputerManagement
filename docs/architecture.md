# Architecture

## Overview

RCM is a client-server C2 framework with three compiled binaries and a static-file web panel.

```
┌──────────────┐     ┌─────────────────────────────────┐
│  Operator │────▶│  Team Server │
│  (Panel UI) │ API │  ┌───────────┐ ┌─────────────┐  │
│              │◀────│  │ API (8080)│ │ Listeners │  │
└──────────────┘     │  └───────────┘ │ (TCP/HTTP) │  │
                     │  ┌───────────┐ └──────┬──────┘  │
                     │  │ SQLite DB │        │         │
                     │  └───────────┘        │         │
                     └───────────────────────┼─────────┘
                                             │
                          ┌──────────────────┼──────────────┐
                          │                  │              │
                     ┌────▼────┐       ┌─────▼────┐  ┌─────▼────┐
                     │ Agent 1 │       │ Agent 2 │  │ Agent 3 │
                     │ (TLS) │──────▶│ (Pivot) │  │ (Hiber.) │
                     └─────────┘       └──────────┘  └──────────┘
```

## Binaries

| Binary | Purpose |
|--------|---------|
| `server` | Team server: listeners, API, session management, database |
| `client` | Agent: connects to server, executes commands, reports back |
| `builder` | Compiles configured agents with embedded crypto keys and C2 config |

Additional bin targets: `client_dll` (DLL entry), `client_service` (Windows service), `stager` (minimal downloader).

## Data Flow

### TCP/TLS Transport (Persistent)
1. Agent opens persistent connection to listener
2. Handshake: agent sends `ClientHello` (hostname, OS, build ID, network interfaces, hibernation flag)
3. Server authenticates via build key, registers session
4. Bidirectional: server pushes signed `SecuredCommand`, agent returns `CommandResponse`
5. All traffic optionally shaped by malleable profiles
6. TLS ClientHello SNI and ALPN fields are independently configurable at build time

### HTTP(S) Transport
1. Agent POSTs `ClientHello` to `/register`
2. Server returns session token
3. Agent polls via GET with token in `X-Request-ID` header
4. Server returns queued commands (or empty 200) with the active malleable profile's `http_get` transform applied, matching the TCP path
5. Agent POSTs `CommandResponse` back under the profile's `http_post` transform
6. Repeat on sleep interval
7. Downstream pivot frames are mixed into the poll body and ride home in the result POST; the agent splits each poll body into commands and pivot frames (`PollBatch` in `agent/http_transport.rs`)
8. Staging: `GET /stage/<build_id>` serves `dist/staged_<build_id>.payload` behind per-build HMAC auth (`X-Stage-Timestamp` / `X-Stage-HMAC` headers) with per-IP rate limiting

### Hibernation Transport
1. Operator enqueues commands ahead of the next check-in (`POST /api/hosts/:id/queue`); rows land in the `queued_tasks` table as `pending`
2. Agent connects and sends `ClientHello` with `hibernation_mode: true`
3. Server registers the session and claims up to `task_batch_size` pending tasks server-side (`poll_and_claim_tasks`)
4. Server pushes each task as a signed `SecuredCommand` on the same connection; the agent executes it and returns the `CommandResponse` on that connection
5. Server marks each task completed or failed (`complete_task` / `fail_task`); a delivery failure returns the task to pending (`requeue_task`)
6. Server closes its end after the batch; the agent disconnects and sleeps for the jitter-bounded interval
7. Between check-ins the host row stays listed as inactive; direct sends against it are converted into queued tasks for the next check-in

## Key Components

### Transport Layer (`transport.rs`, `traffic.rs`)
- `C2Stream` enum unifies TCP, TLS, named pipe, and virtual (pivot) streams
- `ClientTransport` stores per-build SNI override and ALPN protocol list; both are injected into the TLS `rustls` config at connection time
- `DataMolder` handles malleable profile transforms (base64, hex, XOR mask, prepend/append)
- Direction-aware: `http_get` block for polling, `http_post` for data exfil

### Session Management (`server/session.rs`)
- Per-session signing key (Ed25519) for command authentication
- Atomic session IDs persisted in SQLite across restarts
- Last-seen heartbeat tracking via `AtomicI64`
- Auto-recon commands dispatched on registration
- `interfaces: Vec<NetworkInterface>` stored per-session for topology inference
- `hibernation_mode: bool` stored to route commands through queue vs live dispatch

### Topology Planner (`topology.rs`, `api/routes/topology.rs`)
- Passive analysis of agent-reported `NetworkInterface` data (CIDR addresses, UP/RUNNING flags)
- Scores each session as a pivot candidate toward a target IP or CIDR using:
  - Prefix specificity (more specific = higher score)
  - Interface type (physical ethernet > wireless > Docker/bridge > loopback)
  - Operational flags (UP + RUNNING required)
  - RFC-1918 vs public addressing
- Returns ranked candidates with rendered text plan
- Zero network traffic: entirely based on registration data already on the server

### Fallback & DGA (`agent/fallback.rs`, `agent/dga.rs`)
- `FallbackManager` implements four strategies: priority, round-robin, random (weighted), failover
- Per-endpoint failure tracking with dead-time rotation
- `DgaConfig` (seed, window_secs, count, tlds) embedded at build time
- At startup, `inject_dga_endpoints()` generates the current window's domain list and appends them to the fallback list with `priority ≥ 100`
- DGA uses FNV-1a mixing of `(seed, window, index)` -> syllable-based hostname generation

### Hibernation Agent (`agent/hibernation.rs`)
- Separate agent loop: connect -> hello -> receive claimed task batch -> execute -> return results -> disconnect -> sleep
- `queued_tasks` SQLite table stores pending commands with status (pending/running/completed/failed/cancelled)
- Tasks are atomically claimed in batches to prevent double-execution across concurrent check-ins
- Execution output stored back into the task record; operators poll via `GET /api/hosts/:id/tasks/:task_id`

### Job System (`agent/jobs.rs`)
- Background task execution via tokio
- Output streaming (`JOB_STREAM` chunks sent in real-time)
- Kill by ID, list, purge lifecycle

### Evasion (`agent/evasion/`, `agent/syscalls.rs`)
- Module directory: `detection.rs` (VM/sandbox checks, decoy exit, parent validation), `patching.rs` (AMSI/ETW patching, ntdll unhooking), `heap.rs` (heap protection), `sleep.rs` (sleep obfuscation)
- Direct and indirect syscalls
- Fiber-based stack spoofing and Ekko-style sleep mask during sleep
- On-demand heap encryption: AES-256-GCM over the live process heap with other threads suspended, triggered by the `evasion:encrypt_heap_aes` / `evasion:decrypt_heap_aes` commands (handlers in `agent/handlers/evasion.rs`)

### Multi-Operator (`api/middleware.rs`, `api/routes/operators.rs`)
- Operator accounts with roles (admin/operator/viewer)
- Per-request auth via API key -> operator resolution
- Two-tier keys: every login mints a per-session key row in `operator_sessions`, so concurrent sessions of the same operator coexist; the legacy `operators.api_key` primary key still resolves
- Audit log for every action

### Builder API (`api/routes/builder.rs`)
- Panel/API-driven agent builds: `POST /api/builder/build` spawns the `builder` binary as an async job with streamed status (`/api/builder/jobs/:id/status`) and artifact download (`/api/builder/jobs/:id/download`)
- Accepts fallback files in the `fallback_profiles/*.json` format
- Built artifacts land in `dist/` and are served by the staging endpoint

### IOC Tracker (`api/routes/iocs.rs`)
- Per-session artifact records: what the agent dropped, where, and when
- CRUD over HTTP with idempotent `cleaned_at` stamping for remediation tracking

### Loot & RCM Packages (`api/routes/downloads.rs`, `api/routes/rcm.rs`)
- Exfiltrated material lands per-target under `downloads/` as RCM packages: reconstructed paths, XML metadata sidecars, machine fingerprints, and a hash-chained chain-of-custody log
- Loot browser routes with streaming ZIP download of a session's folder
- Package seal/verify actions over the custody chain (`POST /api/rcm/seal`, `POST /api/rcm/verify`)

### Scripting Engine (`agent/scripting/`)
- Rhai engine with 187 registered native functions across fs, system, network, crypto, media, process, memory, DPAPI, browser, injection, pipes, and more
- Resource limits: max operations, max call depth, max string size, and a per-script wall-clock deadline enforced via the progress handler

### Fallback Profiles (`fallback_profiles/`)
- Eight pre-built fallback templates: simple failover, weighted random, multi-cloud round-robin, redirector and pivot chains, corporate proxy, mixed transport, staged infrastructure
- Same JSON format the builder's `--fallback-file` flag consumes

### Build Pipeline (`tests/docker/Dockerfile`, `rust-toolchain.toml`)
- Toolchain pinned to `nightly-2026-08-22` with `rust-src`, required for the `-Zbuild-std` / panic-path stripping flags the builder injects
- The string-audit OPSEC gate runs as an in-image `audit` stage: `tools/string_audit.sh` runs against the built agent binaries and a denylist hit fails the image build
- Runtime image is `debian:trixie-slim`