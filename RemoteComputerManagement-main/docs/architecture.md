# Architecture

## Overview

RCM is a client-server C2 framework with three compiled binaries and a static-file web panel.

```
┌──────────────┐     ┌─────────────────────────────────┐
│  Operator    │────▶│  Team Server                    │
│  (Panel UI)  │ API │  ┌───────────┐ ┌─────────────┐  │
│              │◀────│  │ API (8080)│ │ Listeners   │  │
└──────────────┘     │  └───────────┘ │ (TCP/HTTP)  │  │
                     │  ┌───────────┐ └──────┬──────┘  │
                     │  │ SQLite DB │        │         │
                     │  └───────────┘        │         │
                     └───────────────────────┼─────────┘
                                             │
                          ┌──────────────────┼──────────────┐
                          │                  │              │
                     ┌────▼────┐       ┌─────▼────┐  ┌─────▼────┐
                     │ Agent 1 │       │ Agent 2  │  │ Agent 3  │
                     │ (TLS)   │──────▶│ (Pivot)  │  │ (Hiber.) │
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
4. Server returns queued commands (or empty 200)
5. Agent POSTs `CommandResponse` back
6. Repeat on sleep interval

### Hibernation Transport
1. Agent connects and sends `ClientHello` with `hibernation_mode: true`
2. Server registers session and marks it as hibernating
3. Agent claims up to `batch_size` pending tasks from the queue (`/api/hosts/:id/queue`)
4. Agent executes each task and reports results
5. Agent disconnects and sleeps for `sleep_interval` seconds
6. Repeat — no persistent socket is held between check-ins

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
- DGA uses FNV-1a mixing of `(seed, window, index)` → syllable-based hostname generation

### Hibernation Agent (`agent/hibernation.rs`)
- Separate agent loop: connect → hello → claim task batch → execute → disconnect → sleep
- `queued_tasks` SQLite table stores pending commands with status (pending/claimed/completed/failed/cancelled)
- Tasks are atomically claimed in batches to prevent double-execution across concurrent check-ins
- Execution output stored back into the task record; operators poll via `GET /api/hosts/:id/tasks/:task_id`

### Job System (`agent/jobs.rs`)
- Background task execution via tokio
- Output streaming (`JOB_STREAM` chunks sent in real-time)
- Kill by ID, list, purge lifecycle

### Evasion (`agent/evasion.rs`, `agent/syscalls.rs`)
- AMSI/ETW patching, ntdll unhooking
- Direct and indirect syscalls
- Fiber-based stack spoofing during sleep
- Heap encryption (XOR walk) during sleep

### Multi-Operator (`api/middleware.rs`)
- Operator accounts with roles (admin/operator/viewer)
- Per-request auth via API key → operator resolution
- Audit log for every action
