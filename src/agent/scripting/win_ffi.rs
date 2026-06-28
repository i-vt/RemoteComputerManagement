// src/agent/scripting/win_ffi.rs
//
// Windows FFI types, constants, and extern linkage declarations used across
// the scripting sub-modules.  Import with:
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
        pub privileges: [LuidAndAttribs; 1],
    }

    // ── kernel32 ─────────────────────────────────────────────────────────────

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn GetCurrentProcessId() -> DWORD;
        pub fn TerminateProcess(h: HANDLE, code: DWORD) -> BOOL;
        pub fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE;
        pub fn CloseHandle(h: HANDLE) -> BOOL;
        pub fn GetLastError() -> DWORD;

        pub fn ReadProcessMemory(
            h: HANDLE, base: *const c_void,
            buf: *mut c_void, n: usize, read: *mut usize,
        ) -> BOOL;
        pub fn WriteProcessMemory(
            h: HANDLE, base: *mut c_void,
            buf: *const c_void, n: usize, written: *mut usize,
        ) -> BOOL;
        pub fn VirtualQueryEx(
            h: HANDLE, addr: *const c_void,
            info: *mut MemoryBasicInformation, len: usize,
        ) -> usize;

        pub fn CreateNamedPipeA(
            name: *const i8, open_mode: DWORD, pipe_mode: DWORD,
            max_instances: DWORD, out_buf: DWORD, in_buf: DWORD,
            timeout: DWORD, sa: *mut c_void,
        ) -> HANDLE;
        pub fn ConnectNamedPipe(h: HANDLE, overlapped: *mut c_void) -> BOOL;
        pub fn DisconnectNamedPipe(h: HANDLE) -> BOOL;
        pub fn ReadFile(
            h: HANDLE, buf: *mut c_void, to_read: DWORD,
            read: *mut DWORD, overlapped: *mut c_void,
        ) -> BOOL;
        pub fn WriteFile(
            h: HANDLE, buf: *const c_void, to_write: DWORD,
            written: *mut DWORD, overlapped: *mut c_void,
        ) -> BOOL;
        pub fn CreateFileA(
            name: *const i8, access: DWORD, share: DWORD,
            sa: *mut c_void, creation: DWORD, flags: DWORD, tmpl: HANDLE,
        ) -> HANDLE;
    }

    // ── advapi32 ─────────────────────────────────────────────────────────────

    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(
            h: HANDLE, access: DWORD, token: *mut HANDLE,
        ) -> BOOL;
        pub fn DuplicateTokenEx(
            existing: HANDLE, access: DWORD, attrs: *mut c_void,
            impersonation: u32, tok_type: u32, new_tok: *mut HANDLE,
        ) -> BOOL;
        pub fn ImpersonateLoggedOnUser(token: HANDLE) -> BOOL;
        pub fn LookupPrivilegeValueA(
            sys: *const i8, name: *const i8, luid: *mut Luid,
        ) -> BOOL;
        pub fn AdjustTokenPrivileges(
            tok: HANDLE, disable_all: BOOL,
            new_state: *const TokenPrivileges,
            buf_len: DWORD,
            prev: *mut TokenPrivileges,
            ret_len: *mut DWORD,
        ) -> BOOL;
        pub fn IsUserAnAdmin() -> BOOL;
    }

    // ── crypt32 ───────────────────────────────────────────────────────────────

    #[link(name = "crypt32")]
    extern "system" {
        pub fn CryptUnprotectData(
            data_in:  *const DataBlob,
            desc:     *mut *mut u16,
            entropy:  *const DataBlob,
            reserved: *mut c_void,
            prompt:   *mut c_void,
            flags:    DWORD,
            data_out: *mut DataBlob,
        ) -> BOOL;
    }

    // ── kernel32 (LocalFree — needed after CryptUnprotectData) ───────────────

    extern "system" {
        pub fn LocalFree(mem: *mut c_void) -> *mut c_void;
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

    #[link(name = "advapi32")]
    extern "system" {
        pub fn RegOpenKeyExA(hKey: HKEY, lpSubKey: *const i8, ulOptions: DWORD, samDesired: DWORD, phkResult: *mut HKEY) -> DWORD;
        pub fn RegCreateKeyExA(hKey: HKEY, lpSubKey: *const i8, Reserved: DWORD, lpClass: *mut i8, dwOptions: DWORD, samDesired: DWORD, lpSA: *mut c_void, phkResult: *mut HKEY, lpdwDisposition: *mut DWORD) -> DWORD;
        pub fn RegQueryValueExA(hKey: HKEY, lpValueName: *const i8, lpReserved: *mut DWORD, lpType: *mut DWORD, lpData: *mut u8, lpcbData: *mut DWORD) -> DWORD;
        pub fn RegSetValueExA(hKey: HKEY, lpValueName: *const i8, Reserved: DWORD, dwType: DWORD, lpData: *const u8, cbData: DWORD) -> DWORD;
        pub fn RegDeleteValueA(hKey: HKEY, lpValueName: *const i8) -> DWORD;
        pub fn RegDeleteKeyA(hKey: HKEY, lpSubKey: *const i8) -> DWORD;
        pub fn RegEnumKeyExA(hKey: HKEY, dwIndex: DWORD, lpName: *mut i8, lpcchName: *mut DWORD, lpReserved: *mut DWORD, lpClass: *mut i8, lpcchClass: *mut DWORD, lpftLastWriteTime: *mut u64) -> DWORD;
        pub fn RegEnumValueA(hKey: HKEY, dwIndex: DWORD, lpValueName: *mut i8, lpcchValueName: *mut DWORD, lpReserved: *mut DWORD, lpType: *mut DWORD, lpData: *mut u8, lpcbData: *mut DWORD) -> DWORD;
        pub fn RegCloseKey(hKey: HKEY) -> DWORD;
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

    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenSCManagerA(lpMachineName: *const i8, lpDatabaseName: *const i8, dwDesiredAccess: DWORD) -> HANDLE;
        pub fn CloseServiceHandle(hSCObject: HANDLE) -> BOOL;
        pub fn EnumServicesStatusExA(hSCManager: HANDLE, InfoLevel: u32, dwServiceType: DWORD, dwServiceState: DWORD, lpServices: *mut u8, cbBufSize: DWORD, pcbBytesNeeded: *mut DWORD, lpServicesReturned: *mut DWORD, lpResumeHandle: *mut DWORD, pszGroupName: *const i8) -> BOOL;
        pub fn OpenServiceA(hSCManager: HANDLE, lpServiceName: *const i8, dwDesiredAccess: DWORD) -> HANDLE;
        pub fn CreateServiceA(hSCManager: HANDLE, lpServiceName: *const i8, lpDisplayName: *const i8, dwDesiredAccess: DWORD, dwServiceType: DWORD, dwStartType: DWORD, dwErrorControl: DWORD, lpBinaryPathName: *const i8, lpLoadOrderGroup: *const i8, lpdwTagId: *mut DWORD, lpDependencies: *const i8, lpServiceStartName: *const i8, lpPassword: *const i8) -> HANDLE;
        pub fn StartServiceA(hService: HANDLE, dwNumServiceArgs: DWORD, lpServiceArgVectors: *const *const i8) -> BOOL;
        pub fn ControlService(hService: HANDLE, dwControl: DWORD, lpServiceStatus: *mut ServiceStatus) -> BOOL;
        pub fn DeleteService(hService: HANDLE) -> BOOL;
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

    #[link(name = "wevtapi")]
    extern "system" {
        pub fn EvtQuery(Session: EVT_HANDLE, Path: *const u16, Query: *const u16, Flags: DWORD) -> EVT_HANDLE;
        pub fn EvtNext(ResultSet: EVT_HANDLE, EventArraySize: DWORD, EventArray: *mut EVT_HANDLE, Timeout: DWORD, Flags: DWORD, Returned: *mut DWORD) -> BOOL;
        pub fn EvtRender(Context: EVT_HANDLE, Fragment: EVT_HANDLE, Flags: DWORD, BufferSize: DWORD, Buffer: *mut c_void, BufferUsed: *mut DWORD, PropertyCount: *mut DWORD) -> BOOL;
        pub fn EvtClearLog(Session: EVT_HANDLE, ChannelPath: *const u16, TargetFilePath: *const u16, Flags: DWORD) -> BOOL;
        pub fn EvtClose(Object: EVT_HANDLE) -> BOOL;
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

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateMutexA(lpMutexAttributes: *mut c_void, bInitialOwner: BOOL, lpName: *const i8) -> HANDLE;
        pub fn OpenMutexA(dwDesiredAccess: DWORD, bInheritHandle: BOOL, lpName: *const i8) -> HANDLE;
        pub fn ReleaseMutex(hMutex: HANDLE) -> BOOL;
        pub fn QueryFullProcessImageNameW(hProcess: HANDLE, dwFlags: DWORD, lpExeName: *mut u16, lpdwSize: *mut DWORD) -> BOOL;
        pub fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
        pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut ProcessEntry32W) -> BOOL;
        pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut ProcessEntry32W) -> BOOL;
        pub fn GetModuleFileNameExW(hProcess: HANDLE, hModule: HANDLE, lpFilename: *mut u16, nSize: DWORD) -> DWORD;
        pub fn IsDebuggerPresent() -> BOOL;
    }

    pub fn wstr_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}
