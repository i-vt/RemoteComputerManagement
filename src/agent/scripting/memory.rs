// src/agent/scripting/memory.rs
use rhai::Engine;
use std::fs;
use std::io::{Read, Seek};
use serde_json::json;

pub fn register(engine: &mut Engine) {

    // Read N bytes from a process's virtual address space.
    // Windows: ReadProcessMemory  |  Linux: /proc/{pid}/mem  |  Others: error.
    engine.register_fn("internal_mem_read", |pid_str: &str, addr_hex: &str, size: i64| -> String {
        let pid  = match pid_str.parse::<u32>() {
            Ok(p)  => p,
            Err(_) => return "Error: invalid PID".into(),
        };
        let addr = match u64::from_str_radix(addr_hex.trim_start_matches("0x"), 16) {
            Ok(a)  => a,
            Err(_) => return "Error: invalid address".into(),
        };
        let n = size.max(1).min(64 * 1024 * 1024) as usize;

        #[cfg(target_os = "windows")]
        unsafe {
            use super::win_ffi::win_ext::*;
            let h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if h.is_null() { return format!("Error: OpenProcess failed ({})", GetLastError()); }
            let mut buf  = vec![0u8; n];
            let mut read = 0usize;
            let ok = ReadProcessMemory(h, addr as *const std::ffi::c_void, buf.as_mut_ptr() as _, n, &mut read);
            CloseHandle(h);
            if ok != 0 { hex::encode(&buf[..read]) }
            else { format!("Error: ReadProcessMemory failed ({})", GetLastError()) }
        }
        #[cfg(target_os = "linux")]
        {
            let mem_path = format!("/proc/{}/mem", pid);
            match fs::OpenOptions::new().read(true).open(&mem_path) {
                Ok(mut f) => {
                    if f.seek(std::io::SeekFrom::Start(addr)).is_err() {
                        return "Error: seek failed".into();
                    }
                    let mut buf = vec![0u8; n];
                    match f.read(&mut buf) {
                        Ok(r) => hex::encode(&buf[..r]),
                        Err(e) => format!("Error: {}", e),
                    }
                }
                Err(e) => format!("Error: {}", e),
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        format!("Error: mem_read not supported on this platform (pid {}, addr {})", pid, addr_hex)
    });

    // Write hex-encoded bytes into a process's address space.
    // Windows: WriteProcessMemory  |  Others: error.
    engine.register_fn("internal_mem_write", |pid_str: &str, addr_hex: &str, data_hex: &str| -> String {
        let pid  = match pid_str.parse::<u32>() {
            Ok(p)  => p,
            Err(_) => return "Error: invalid PID".into(),
        };
        let addr = match u64::from_str_radix(addr_hex.trim_start_matches("0x"), 16) {
            Ok(a)  => a,
            Err(_) => return "Error: invalid address".into(),
        };
        let data = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(e) => return format!("Error: {}", e),
        };

        #[cfg(target_os = "windows")]
        unsafe {
            use super::win_ffi::win_ext::*;
            let h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if h.is_null() { return format!("Error: OpenProcess failed ({})", GetLastError()); }
            let mut written = 0usize;
            let ok = WriteProcessMemory(
                h, addr as *mut std::ffi::c_void, data.as_ptr() as _, data.len(), &mut written,
            );
            CloseHandle(h);
            if ok != 0 { format!("Wrote {} bytes", written) }
            else { format!("Error: WriteProcessMemory failed ({})", GetLastError()) }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: mem_write not supported on this platform (pid {}, addr {})", pid, addr_hex)
    });

    // List committed virtual memory regions.
    // Windows: VirtualQueryEx loop  |  Linux: /proc/maps  |  Others: error.
    engine.register_fn("internal_mem_regions", |pid_str: &str| -> String {
        let pid = match pid_str.parse::<u32>() {
            Ok(p)  => p,
            Err(_) => return "Error: invalid PID".into(),
        };

        #[cfg(target_os = "windows")]
        unsafe {
            use super::win_ffi::win_ext::*;
            let h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if h.is_null() { return format!("Error: OpenProcess failed ({})", GetLastError()); }
            let mut regions = Vec::new();
            let mut addr: u64 = 0;
            loop {
                let mut mbi = MemoryBasicInformation {
                    base_address: std::ptr::null_mut(), allocation_base: std::ptr::null_mut(),
                    allocation_protect: 0, region_size: 0, state: 0, protect: 0, mem_type: 0,
                };
                let ret = VirtualQueryEx(h, addr as *const std::ffi::c_void, &mut mbi,
                    std::mem::size_of::<MemoryBasicInformation>());
                if ret == 0 { break; }
                if mbi.state == MEM_COMMIT {
                    regions.push(json!({
                        "base":    format!("0x{:x}", mbi.base_address as u64),
                        "size":    mbi.region_size,
                        "protect": mbi.protect,
                        "type":    mbi.mem_type,
                    }));
                }
                addr = mbi.base_address as u64 + mbi.region_size as u64;
                if addr == 0 { break; }
            }
            CloseHandle(h);
            serde_json::to_string(&regions).unwrap_or("[]".into())
        }
        #[cfg(target_os = "linux")]
        {
            let maps_path = format!("/proc/{}/maps", pid);
            match fs::read_to_string(&maps_path) {
                Ok(content) => {
                    let regions: Vec<serde_json::Value> =
                        content.lines().map(|line| json!({ "raw": line })).collect();
                    serde_json::to_string(&regions).unwrap_or("[]".into())
                }
                Err(e) => format!("Error: {}", e),
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        format!("Error: mem_regions not supported on this platform (pid {})", pid_str)
    });

    // Scan all readable committed regions for a byte pattern.
    // Returns a JSON array of hex addresses (capped at 10k hits).
    engine.register_fn("internal_mem_scan", |pid_str: &str, pattern_hex: &str| -> String {
        let pid     = match pid_str.parse::<u32>() {
            Ok(p)  => p,
            Err(_) => return "Error: invalid PID".into(),
        };
        let pattern = match hex::decode(pattern_hex) {
            Ok(p)  => p,
            Err(e) => return format!("Error: {}", e),
        };
        if pattern.is_empty() { return "Error: empty pattern".into(); }

        let mut hits = Vec::<String>::new();

        #[cfg(target_os = "linux")]
        {
            let maps = match fs::read_to_string(format!("/proc/{}/maps", pid)) {
                Ok(m)  => m,
                Err(e) => return format!("Error: {}", e),
            };
            let mem_path = format!("/proc/{}/mem", pid);
            let mut mem_file = match fs::OpenOptions::new().read(true).open(&mem_path) {
                Ok(f)  => f,
                Err(e) => return format!("Error: {}", e),
            };
            for line in maps.lines() {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() < 2 || !parts[1].starts_with('r') { continue; }
                let range: Vec<&str> = parts[0].split('-').collect();
                if range.len() != 2 { continue; }
                let start = u64::from_str_radix(range[0], 16).unwrap_or(0);
                let end   = u64::from_str_radix(range[1], 16).unwrap_or(0);
                if end <= start || end - start > 128 * 1024 * 1024 { continue; }
                let _ = mem_file.seek(std::io::SeekFrom::Start(start));
                let mut buf = vec![0u8; (end - start) as usize];
                let n = mem_file.read(&mut buf).unwrap_or(0);
                for (i, window) in buf[..n].windows(pattern.len()).enumerate() {
                    if window == pattern.as_slice() {
                        hits.push(format!("0x{:x}", start + i as u64));
                    }
                }
                if hits.len() >= 10_000 { break; }
            }
        }
        #[cfg(target_os = "windows")]
        unsafe {
            use super::win_ffi::win_ext::*;
            let h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if h.is_null() { return format!("Error: OpenProcess failed ({})", GetLastError()); }
            let mut addr: u64 = 0;
            loop {
                let mut mbi = MemoryBasicInformation {
                    base_address: std::ptr::null_mut(), allocation_base: std::ptr::null_mut(),
                    allocation_protect: 0, region_size: 0, state: 0, protect: 0, mem_type: 0,
                };
                let ret = VirtualQueryEx(h, addr as *const std::ffi::c_void, &mut mbi,
                    std::mem::size_of::<MemoryBasicInformation>());
                if ret == 0 { break; }
                let next = mbi.base_address as u64 + mbi.region_size as u64;
                if mbi.state == MEM_COMMIT
                    && (mbi.protect & 0xFF) != PAGE_NOACCESS
                    && mbi.region_size <= 128 * 1024 * 1024
                {
                    let mut buf  = vec![0u8; mbi.region_size];
                    let mut read = 0usize;
                    if ReadProcessMemory(
                        h, mbi.base_address as *const std::ffi::c_void,
                        buf.as_mut_ptr() as _, mbi.region_size, &mut read,
                    ) != 0 {
                        for (i, window) in buf[..read].windows(pattern.len()).enumerate() {
                            if window == pattern.as_slice() {
                                hits.push(format!("0x{:x}", mbi.base_address as u64 + i as u64));
                            }
                        }
                    }
                }
                addr = next;
                if addr == 0 || hits.len() >= 10_000 { break; }
            }
            CloseHandle(h);
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        { return "Error: mem_scan only supported on Linux and Windows".into(); }

        serde_json::to_string(&hits).unwrap_or("[]".into())
    });
}
