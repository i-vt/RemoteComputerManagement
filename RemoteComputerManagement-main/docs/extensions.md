# Rhai Extensions

Extensions are scripts written in [Rhai](https://rhai.rs/) that run inside the agent process. They have access to registered native functions for file I/O, process listing, injection, crypto, clipboard, screenshots, and artifact management.

## Deploying

From the panel terminal:
```
ext:load <base64_encoded_script> [arg1] [arg2] ...
```

Extensions run as background jobs automatically. Output streams back in real-time.

## Available Functions

### File System
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_read(path)` | String | Read file to string |
| `internal_write(path, data)` | String | Write string to file |
| `internal_ls(path)` | String | List directory (JSON) |

### System
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_env(var)` | String | Read environment variable |
| `internal_sysinfo()` | String | Hostname and OS info |
| `internal_procs()` | String | Process list (`PID\|Name` format) |
| `exec_os(cmd)` | String | Execute shell command |

### Network
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_http_get(url)` | String | HTTP GET request |

### Crypto
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_keygen()` | String | Generate 256-bit key (hex) |
| `internal_encrypt_file(path, key_hex)` | String | AES-GCM encrypt file in-place |
| `internal_decrypt_file(path, key_hex)` | String | AES-GCM decrypt file in-place |
| `internal_encrypt_recursive(path, key)` | String | Encrypt all files under path |
| `internal_decrypt_recursive(path, key)` | String | Decrypt all files under path |

### Media
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_screenshot()` | String | Capture all monitors (JSON array of base64 PNGs) |
| `internal_clipboard_get()` | String | Read clipboard text |
| `internal_clipboard_set(text)` | String | Set clipboard text |
| `internal_clipboard_clear()` | String | Clear clipboard |

### Injection
| Function | Returns | Description |
|----------|---------|-------------|
| `native_inject_self(b64_shellcode)` | String | Self-inject shellcode |
| `native_inject_remote_apc(pid, b64)` | String | Remote APC injection |
| `native_inject_remote_hijack(pid, b64)` | String | Thread hijack injection |
| `native_inject_remote_create_thread(pid, b64)` | String | CreateRemoteThread |
| `native_inject_spawn_early_bird(binary, b64)` | String | Early bird (spawn + inject) |
| `native_inject_spawn_advanced(binary, ppid, b64)` | String | PPID-spoofed spawn |
| `native_inject_module_stomping(pid, dll, b64)` | String | Module stomping |
| `native_inject_module_stomping_auto(pid, b64)` | String | Auto-target module stomping |

### Artifacts
| Function | Returns | Description |
|----------|---------|-------------|
| `timestomp(target, reference)` | String | Copy timestamps |
| `timestomp_epoch(path, epoch)` | String | Set timestamps to epoch |
| `secure_delete(path)` | String | Secure file deletion |
| `ads_write(path, stream, data)` | String | Write to ADS |
| `ads_read(path, stream)` | String | Read from ADS |
| `ads_list(path)` | String | List ADS |

### Utility
| Function | Returns | Description |
|----------|---------|-------------|
| `print_log(msg)` | — | Print to agent's stderr |

## Example Script

```rhai
// recon.rhai — Basic host enumeration
let hostname = exec_os("hostname");
let whoami = exec_os("whoami");
let ips = exec_os("ip addr show");
let procs = internal_procs();

let result = "=== RECON ===\n";
result += "Host: " + hostname + "\n";
result += "User: " + whoami + "\n";
result += "IPs:\n" + ips + "\n";
result += "Processes:\n" + procs;
result
```

Scripts receive arguments via the `args` array variable:
```rhai
let target = args[0];
let output = exec_os("ping -c 1 " + target);
output
```
