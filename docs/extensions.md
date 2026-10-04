# Rhai Extensions and Modules

RCM scripts come in two flavors that are easy to confuse:

- **Extensions** (`extensions/`) run **inside the agent process**. They are
  pushed to a session with `ext:load` and execute against a rich native API:
  the agent's Rhai engine registers **187 functions** (listed below) covering
  file I/O, process introspection, injection, crypto, browser credentials,
  the registry, services, screenshots, clipboard, and a Python bridge.
- **Modules** (`modules/`) run **on the server**, once per target session.
  A module declares `fn run(session_id)` (or `run(session_id, args)`) and
  orchestrates sessions through three bindings: `send_c2_command`,
  `send_c2_extension`, and `random_hex_key`, plus `print` for output the API
  returns to the caller. Broadcasting a module
  (`POST /api/broadcast/module`) also runs it server-side, looped over every
  active session - module source is never pushed into agents.

## Deploying Extensions

From the panel terminal:
```
ext:load <base64_encoded_script> [arg1] [arg2] ...
```

or pick one from the **Scripts** page (Deploy button), which calls
`POST /api/hosts/:id/extensions/:filename`. Extensions run as background jobs
automatically; output streams back in real time. Arguments arrive in the
script as the `args` array.

The Scripts page and the API (`GET/PUT/DELETE /api/extensions/:name`,
`/api/modules/:name`) can create, edit, and delete both kinds of script live
on the server.

## Built-in Extensions

31 scripts ship in `extensions/` (the 3 files in `examples/` are dev scripts,
not deployable extensions):

| Group | Scripts |
|-------|---------|
| Persistence | `auto_persist` (see [Persistence](persistence.md)); `persistence_windows`, `persistence_linux` are **deprecated**, superseded by `auto_persist` and the native `persist:*` commands |
| Credentials | `cred_dump` (full sweep: SSH keys, AWS/Vault/Kube/Docker/Git/NPM secrets, browser stores), `cred_chrome` (Chrome cookies: DPAPI on Windows, keyring AES on Linux; raw ciphertext on macOS), `cred_firefox` (logins.json; NSS ciphertext for offline decryption) |
| Helpers | `klog` (keylogger start/stop/dump/status), `mem` (process memory read/write/search), `reg` (registry read/write), `svc` (service control) |
| Recon / audit | `env_audit`, `hunter` (Windows file hunt), `localhost_audit` (common local web ports), `scanner` (internal network scan), `ps`, `sysinfo` |
| Injection | `inject_classic`, `inject_self`, `inject_remote_apc`, `inject_remote_thread_hijack`, `inject_earlybird`, `inject_spawn_early_bird`, `inject_spawn_advanced` (PPID spoof), `inject_module_stomping`, `inject_auto_stomp`, `inject_hunter` |
| Media | `screenshot`, `clipboard_thief`, `clipboard_poison` |
| File crypto | `recursive_lock`, `recursive_unlock` (recursive AES-GCM encrypt/decrypt with a hex key - see the OPSEC note below) |

OPSEC note: the shipped `crypt_*` **modules** use a hardcoded demo key
committed in the repo - generate a per-run key with `internal_keygen()`
instead of reusing it on a real target.

## Platform Caveats

- Injection helpers, `reg`, `svc`, DPAPI decryption, token theft, event log
  access, and the keylogger API are **Windows-only**; scripts that use them
  get a loud error elsewhere.
- `internal_screenshot` and the clipboard functions have **no X11 capture in
  fully-static musl builds** (`--platform linux-musl`) - they return an error
  string there. Use glibc Linux or Windows builds when you need screen
  capture.
- `internal_mic_record` shells out to `arecord` (Linux), `ffmpeg` (Windows),
  or `sox`/`ffmpeg` (macOS); it fails on targets without one of those
  installed, and it writes a predictable `rcm_mic.wav` temp file while
  recording.
- Browser decryption coverage is asymmetric: Chrome cookies decrypt on
  Windows (DPAPI; Chrome 127+ app-bound v20 blobs fail honestly) and Linux
  (keyring AES), but not macOS; Firefox logins are reported as NSS
  ciphertext for offline decryption on all platforms.

## Native Function Reference (agent-side, 187 functions)

### File System
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_read(path)` | String | Read file to string |
| `internal_read_bytes(path)` | String | Read file as base64 |
| `internal_write(path, data)` | String | Write string to file |
| `internal_write_bytes(path, b64)` | String | Write raw bytes |
| `internal_ls(path)` | String | List directory (JSON) |
| `internal_stat(path)` | String | File metadata (JSON) |
| `internal_file_size(path)` | String | File size in bytes |
| `internal_exists(path)` | bool | Path exists |
| `internal_delete(path)` | String | Delete file |
| `internal_copy(src, dst)` | String | Copy file |
| `internal_move(src, dst)` | String | Move/rename file |
| `internal_mkdir(path)` | String | Create directory recursively |
| `internal_find_files(root, pattern)` | String | Recursive glob search |

### Shell Execution
| Function | Returns | Description |
|----------|---------|-------------|
| `exec_os(cmd)` | String | Execute shell command |
| `exec_os_timeout(cmd, secs)` | String | Execute with a timeout |
| `internal_exec_detach(cmd)` | String | Fire-and-forget, detached |
| `internal_exec_script(script)` | String | Run a script text through the OS shell |
| `internal_spawn_hidden(binary, args_json)` | String | Spawn hidden process (Windows) |

### System and Process Info
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_env(var)` | String | Read environment variable |
| `internal_sysinfo()` | String | Hostname and OS info |
| `internal_sysinfo_json()` | String | Full survey as JSON |
| `internal_hostname()` / `internal_username()` | String | Host / user name |
| `internal_uptime()` | String | System uptime |
| `internal_is_elevated()` | bool | Admin/root check |
| `internal_self_path()` | String | Path of the running executable |
| `internal_procs()` | String | Process list (`PID\|Name`) |
| `internal_proc_path(pid)` / `internal_proc_cmdline(pid)` / `internal_proc_env(pid)` / `internal_proc_user(pid)` / `internal_proc_parent(pid)` / `internal_proc_modules(pid)` | String | Per-process introspection |
| `internal_proc_kill(pid)` | String | Terminate a process |
| `internal_network_interfaces()` | String | Interface list (JSON) |
| `internal_disk_info()` | String | Mounted disks (JSON) |

### Network
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_http_get(url)` | String | HTTP GET |
| `internal_http_get_headers(url, headers)` | String | GET with custom headers |
| `internal_http_post(url, body)` | String | HTTP POST |
| `internal_http_post_file(url, path)` | String | POST a file |
| `internal_http_put(url, body)` | String | HTTP PUT |
| `internal_http_upload_chunks(url, data_hex, chunk_size, headers_json)` | String | Chunked upload |
| `internal_tcp_connect(host, port, timeout_ms)` | String | Raw TCP probe |
| `internal_udp_send(host, port, data)` / `internal_udp_recv(port, timeout)` | String | Raw UDP |
| `internal_dns_resolve(name)` / `internal_dns_resolve_all(name)` / `internal_dns_reverse(ip)` / `internal_dns_txt(name)` | String | DNS lookups |
| `internal_named_pipe_listen(name)` / `internal_named_pipe_write(name, data)` | String | Named pipe IPC (Windows) |

### Crypto and Encoding
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_keygen()` | String | Generate 256-bit key (hex) |
| `internal_encrypt_file(path, key_hex)` | String | AES-GCM encrypt file in-place |
| `internal_decrypt_file(path, key_hex)` | String | AES-GCM decrypt file in-place |
| `internal_encrypt_recursive(path, key)` | String | Encrypt all files under path |
| `internal_decrypt_recursive(path, key)` | String | Decrypt all files under path |
| `internal_encrypt_bytes(b64, key)` / `internal_decrypt_bytes(b64, key)` | String | In-memory AES-GCM |
| `internal_aes256_cbc_decrypt(...)` / `internal_aes128_cbc_decrypt(...)` | String | CBC variants (browser cookies etc.) |
| `internal_xor(data, key)` | String | XOR transform |
| `internal_base64_encode/decode`, `internal_base64_encode_hex`, `internal_hex_encode/decode` | String | Encodings |
| `internal_md5`, `internal_sha256`, `internal_sha256_bytes`, `internal_crc32`, `internal_fnv1a` | String | Hashes |
| `internal_hmac(key, data)` / `internal_pbkdf2(...)` | String | Keyed hashes / KDF |

### Compression and Archives
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_gzip(data)` / `internal_gunzip(data)` | String | gzip |
| `internal_zip_create(dir, zip)` / `internal_zip_extract(zip, dir)` / `internal_zip_list(zip)` | String | ZIP archives |

### Media
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_screenshot()` | String | Capture all monitors (JSON array of base64 PNGs). Errors on musl builds |
| `internal_clipboard_get()` | String | Read clipboard text |
| `internal_clipboard_set(text)` | String | Set clipboard text |
| `internal_clipboard_clear()` | String | Clear clipboard |
| `internal_mic_record(seconds)` | String | Record microphone via an installed CLI recorder (see Platform Caveats) |

### Credentials
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_credential_sweep()` | String | All sources below in one pass |
| `internal_ssh_keys(home)` | String | SSH private keys under a home dir |
| `internal_aws_credentials()` / `internal_vault_token()` / `internal_kube_config()` / `internal_docker_config()` / `internal_git_credentials()` / `internal_npm_token()` | String | Cloud/CLI secret files |
| `internal_chrome_cookies(profile?)` | String | Chrome Cookies DB (read-only) |
| `internal_chrome_decrypt_linux(blob)` | String | Chrome keyring AES decrypt (Linux) |
| `internal_firefox_logins(profile?)` | String | Firefox logins.json (NSS ciphertext) |
| `internal_dpapi_decrypt(blob)` | String | CryptUnprotectData (Windows) |
| `internal_token_steal(pid)` | String | Impersonate a process token (Windows) |

### Registry, Services, Event Log (Windows)
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_reg_read(hive, key, value)` | String | Read registry value |
| `internal_reg_write(hive, key, value, data)` | String | Write registry value |
| `internal_reg_delete_value(hive, key, value)` / `internal_reg_delete_key(hive, parent, subkey)` | String | Deletes |
| `internal_reg_enum_keys(hive, key)` / `internal_reg_enum_values(hive, key)` | String | Enumeration |
| `internal_service_enum()` | String | List services |
| `internal_service_start(name)` / `internal_service_stop(name)` | String | Control |
| `internal_service_create(name, display, binpath, auto)` / `internal_service_delete(name)` | String | Install/remove |
| `internal_eventlog_query(log, xpath, max)` | String | Query events |
| `internal_eventlog_clear(log)` | String | Clear a log |

### Memory and Detection
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_mem_read(pid, addr, len)` | String | Read process memory |
| `internal_mem_write(pid, addr, b64)` | String | Write process memory |
| `internal_mem_regions(pid)` | String | Memory map |
| `internal_mem_scan(pid, pattern)` | String | Search memory |
| `internal_vm_detect()` / `internal_debugger_detect()` / `internal_timing_check()` | bool | Sandbox/VM/debugger checks |
| `internal_av_detect()` | String | Installed AV/EDR products |
| `internal_parent_check(valid_parents)` | bool | Parent-process allow-list check |
| `internal_enable_privilege(name)` | String | Enable a token privilege (Windows) |

### Injection (Windows)
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
| `ads_write(path, stream, data)` | String | Write to ADS (Windows) |
| `ads_read(path, stream)` | String | Read from ADS (Windows) |
| `ads_list(path)` | String | List ADS (Windows) |

### Keylogger (Windows)
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_keylog_start()` / `internal_keylog_stop()` / `internal_keylog_dump()` | String | Keylogger control |

### Script State and Loading
| Function | Returns | Description |
|----------|---------|-------------|
| `internal_state_set(k, v)` / `internal_state_get(k)` / `internal_state_delete(k)` / `internal_state_keys()` / `internal_state_clear()` | - | Shared KV store visible to all extensions on the agent |
| `internal_load_script(b64)` / `internal_load_script_args(b64, args)` | String | Load and run another extension from a script |
| `internal_mutex_create(name)` / `internal_mutex_exists(name)` / `internal_mutex_release(name)` | - | Cross-run mutexes |
| `internal_sleep(ms)` | - | Sleep inside a script |
| `internal_uuid()` | String | Random UUID |

### Utility
| Function | Returns | Description |
|----------|---------|-------------|
| `print_log(msg)` | - | Print to agent's stderr |
| `internal_json_get(json, key)` | String | Extract a field from JSON |
| `internal_grep(text, pattern)` / `internal_regex_match` / `internal_regex_findall` | String | Text search |

## Python Bridge

The agent can bootstrap and drive a real CPython on the target, entirely from
extensions (35 bindings, `src/agent/scripting/python.rs`):

- **Install**: `internal_python_find()`, `internal_python_version()`,
  `internal_python_install_portable()` (python-build-standalone fetch;
  `internal_python_pbs_url()` exposes the URL logic),
  `internal_python_install_system()`, `internal_python_install_offensive()`
  (interpreter + common offensive packages in one shot),
  `internal_python_offensive_check()`, and the combined
  `internal_python_bootstrap()` / `internal_python_ensure()`.
- **Run**: `internal_python_exec(code)`, `internal_python_exec_file(path)`,
  `internal_python_exec_json(code)` (JSON result), and the `_timeout`
  variants.
- **Sessions**: `internal_python_session_start(venv_path)` returns a session id for a
  persistent interpreter; `internal_python_session_exec(id, code)`,
  `internal_python_session_list()`, `internal_python_session_stop(id)`.
- **Venvs**: `internal_venv_create(path)`, `internal_venv_create_with(interpreter,
  path)`, `internal_venv_exists`, `internal_venv_python_path`,
  `internal_venv_delete`, and `internal_python_in_venv` /
  `internal_python_in_venv_json` / `internal_python_in_venv_timeout` /
  `internal_python_file_in_venv` / `internal_python_ensure_venv` to run code
  inside one.
- **Packages**: `internal_pip_install(pkg)`, `internal_pip_uninstall`,
  `internal_pip_list`, `internal_pip_freeze`, `internal_pip_has_package(pkg)`,
  `internal_pip_install_requirements(file)`.
- `print_python_log(msg)` mirrors `print_log` from Python-facing flows.

The bridge is exercised end-to-end by `tests/docker/scripts/test_14_python_extension.sh`.

## Example Script

```rhai
// recon.rhai - Basic host enumeration
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
