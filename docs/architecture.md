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
                     │ (TCP)   │──────▶│ (Pivot)  │  │ (HTTPS)  │
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

### TCP/TLS Transport
1. Agent opens persistent connection to listener
2. Handshake: agent sends `ClientHello` (hostname, OS, build ID)
3. Server authenticates via build key, registers session
4. Bidirectional: server pushes signed `SecuredCommand`, agent returns `CommandResponse`
5. All traffic optionally shaped by malleable profiles

### HTTP(S) Transport
1. Agent POSTs `ClientHello` to `/register`
2. Server returns session token
3. Agent polls via GET with token in `X-Request-ID` header
4. Server returns queued commands (or empty 200)
5. Agent POSTs `CommandResponse` back
6. Repeat on sleep interval

## Key Components

### Transport Layer (`transport.rs`, `traffic.rs`)
- `C2Stream` enum unifies TCP, TLS, named pipe, and virtual (pivot) streams
- `DataMolder` handles malleable profile transforms (base64, hex, XOR mask, prepend/append)
- Direction-aware: `http_get` block for polling, `http_post` for data exfil

### Session Management (`server/session.rs`)
- Per-session signing key (Ed25519) for command authentication
- Atomic session IDs persisted in SQLite across restarts
- Last-seen heartbeat tracking via `AtomicI64`
- Auto-recon commands dispatched on registration

### Job System (`agent/jobs.rs`)
- Background task execution via tokio
- Output streaming (`JOB_STREAM` chunks sent in real-time)
- Kill by ID, list, purge lifecycle

### Fallback (`agent/fallback.rs`)
- Four strategies: priority, round-robin, random (weighted), failover
- Per-endpoint failure tracking with dead-time rotation
- Per-endpoint profile/proxy overrides

### Evasion (`agent/evasion.rs`, `agent/syscalls.rs`)
- AMSI/ETW patching, ntdll unhooking
- Direct and indirect syscalls
- Fiber-based stack spoofing during sleep
- Heap encryption (XOR walk) during sleep

### Multi-Operator (`api/middleware.rs`)
- Operator accounts with roles (admin/operator/viewer)
- Per-request auth via API key → operator resolution
- Audit log for every action
