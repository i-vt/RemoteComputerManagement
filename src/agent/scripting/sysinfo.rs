// src/agent/scripting/sysinfo.rs
use rhai::Engine;
use serde_json::json;

pub fn register(engine: &mut Engine) {

    engine.register_fn("internal_hostname", || -> String {
        sys_info::hostname().unwrap_or_else(|_| "unknown".into())
    });

    engine.register_fn("internal_username", || -> String {
        #[cfg(target_os = "windows")]
        {
            std::env::var("USERNAME").unwrap_or_else(|_| whoami_native())
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| whoami_native())
        }
    });

    // Exposes utils::get_network_interfaces() — already cross-platform.
    // Returns JSON: [{name, mac, ipv4, ipv6, flags}]
    engine.register_fn("internal_network_interfaces", || -> String {
        let ifaces = crate::utils::get_network_interfaces();
        serde_json::to_string(&ifaces).unwrap_or("[]".into())
    });

    engine.register_fn("internal_uptime", || -> String {
        #[cfg(not(target_os = "windows"))]
        {
            sys_info::boottime()
                .map(|t| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    ((now - t.tv_sec as u64) as i64).to_string()
                })
                .unwrap_or("-1".into())
        }
        #[cfg(target_os = "windows")]
        {
            extern "system" { fn GetTickCount64() -> u64; }
            ((unsafe { GetTickCount64() } / 1000) as i64).to_string()
        }
    });

    engine.register_fn("internal_disk_info", || -> String {
        match sys_info::disk_info() {
            Ok(di) => json!({
                "total_kb": di.total,
                "free_kb":  di.free,
            }).to_string(),
            Err(e) => format!("Error: {}", e),
        }
    });

    // Convenience: returns the full sysinfo blob as JSON.
    engine.register_fn("internal_sysinfo_json", || -> String {
        json!({
            "hostname": sys_info::hostname().unwrap_or_default(),
            "os_type":  sys_info::os_type().unwrap_or_default(),
            "os_release": sys_info::os_release().unwrap_or_default(),
            "cpu_num":  sys_info::cpu_num().unwrap_or(0),
            "mem_total_kb": sys_info::mem_info().map(|m| m.total).unwrap_or(0),
            "mem_free_kb":  sys_info::mem_info().map(|m| m.free).unwrap_or(0),
        }).to_string()
    });
}

fn whoami_native() -> String {
    #[cfg(target_os = "windows")]
    unsafe {
        extern "system" { fn GetUserNameA(buf: *mut i8, sz: *mut u32) -> i32; }
        let mut buf = vec![0i8; 256];
        let mut sz  = 256u32;
        if GetUserNameA(buf.as_mut_ptr(), &mut sz) != 0 {
            return String::from_utf8_lossy(
                &buf[..sz.saturating_sub(1) as usize]
                    .iter().map(|&b| b as u8).collect::<Vec<_>>()
            ).to_string();
        }
        "unknown".into()
    }
    #[cfg(not(target_os = "windows"))]
    {
        unsafe {
            let uid = libc::getuid();
            let pw  = libc::getpwuid(uid);
            if !pw.is_null() {
                let cstr = std::ffi::CStr::from_ptr((*pw).pw_name);
                return cstr.to_string_lossy().to_string();
            }
        }
        "unknown".into()
    }
}
