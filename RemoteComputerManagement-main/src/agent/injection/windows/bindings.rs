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

#[link(name = "kernel32")]
extern "system" {
    pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
    pub fn VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID; 
    pub fn VirtualAllocEx(h: HANDLE, lp: LPVOID, dw: SIZE_T, fl: DWORD, flP: DWORD) -> LPVOID;
    pub fn WriteProcessMemory(h: HANDLE, lp: LPVOID, b: *const c_void, n: SIZE_T, w: *mut SIZE_T) -> BOOL;
    pub fn ReadProcessMemory(h: HANDLE, lp: LPVOID, b: *mut c_void, n: SIZE_T, w: *mut SIZE_T) -> BOOL; 
    pub fn VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: LPDWORD) -> BOOL;
    pub fn VirtualProtectEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: LPDWORD) -> BOOL;
    pub fn QueueUserAPC(pfnAPC: *const c_void, hThread: HANDLE, dwData: usize) -> DWORD;
    pub fn ResumeThread(hThread: HANDLE) -> DWORD;
    pub fn SuspendThread(hThread: HANDLE) -> DWORD;
    pub fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT) -> BOOL;
    pub fn SetThreadContext(hThread: HANDLE, lpContext: *const CONTEXT) -> BOOL;
    pub fn CloseHandle(h: HANDLE) -> BOOL;
    pub fn CreateProcessA(lpAppName: LPSTR, lpCmdLine: LPSTR, lpProcAttr: *mut c_void, lpThreadAttr: *mut c_void, bInherit: BOOL, dwFlags: DWORD, lpEnv: *mut c_void, lpDir: LPSTR, lpStartup: *mut STARTUPINFOA, lpProcInfo: *mut PROCESS_INFORMATION) -> BOOL;
    pub fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
    pub fn Thread32First(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn Thread32Next(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) -> HANDLE;
    pub fn GetLastError() -> DWORD;
    pub fn CreateThread(lpThreadAttributes: *mut c_void, dwStackSize: SIZE_T, lpStartAddress: LPVOID, lpParameter: LPVOID, dwCreationFlags: DWORD, lpThreadId: LPDWORD) -> HANDLE;
    pub fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: *mut c_void, dwStackSize: SIZE_T, lpStartAddress: LPVOID, lpParameter: LPVOID, dwCreationFlags: DWORD, lpThreadId: LPDWORD) -> HANDLE;
    pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;

    // Advanced / Spoofing APIs
    pub fn InitializeProcThreadAttributeList(lpAttributeList: *mut c_void, dwAttributeCount: DWORD, dwFlags: DWORD, lpSize: *mut SIZE_T) -> BOOL;
    pub fn UpdateProcThreadAttribute(lpAttributeList: *mut c_void, dwFlags: DWORD, Attribute: usize, lpValue: *const c_void, cbSize: SIZE_T, lpPreviousValue: *mut c_void, lpReturnSize: *mut SIZE_T) -> BOOL;
    pub fn DeleteProcThreadAttributeList(lpAttributeList: *mut c_void);
    pub fn GetModuleHandleA(lpModuleName: LPSTR) -> HANDLE;
    
    // [NEW] Added for AMSI patching
    pub fn LoadLibraryA(lpLibFileName: LPCSTR) -> HMODULE;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> LPVOID;
}

// PSAPI Imports
#[link(name = "psapi")]
extern "system" {
    pub fn EnumProcessModulesEx(hProcess: HANDLE, lphModule: *mut HMODULE, cb: DWORD, lpcbNeeded: *mut DWORD, dwFilterFlag: DWORD) -> BOOL;
    pub fn GetModuleBaseNameA(hProcess: HANDLE, hModule: HMODULE, lpBaseName: LPSTR, nSize: DWORD) -> DWORD;
    pub fn GetModuleInformation(hProcess: HANDLE, hModule: HMODULE, lpmodinfo: *mut MODULEINFO, cb: DWORD) -> BOOL;
}
