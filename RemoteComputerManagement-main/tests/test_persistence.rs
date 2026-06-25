// tests/test_persistence.rs — Persistence module integration tests.
//
// Tests the public `rcm::agent::persistence::*` API end-to-end.
// Each test that touches the filesystem gets a private HOME directory
// so it doesn't interfere with the real user's dotfiles or systemd units.
//
// Structure:
//   - Isolation helpers
//   - Platform-guard tests (run everywhere — verify wrong-platform commands fail cleanly)
//   - Linux-only tests (systemd, profile, list)
//   - Handler argument-parsing tests (run everywhere)

use rcm::agent::persistence as persist;
use std::fs;
use std::path::Path;

// ── Isolation ─────────────────────────────────────────────────────────────────
//
// Setting HOME is not thread-safe; HOME_MTX serialises all tests that need it.

static HOME_MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct TempHome {
    pub path: String,
    old_home: String,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl TempHome {
    fn new(tag: &str) -> Self {
        let guard = HOME_MTX.lock().unwrap_or_else(|p| p.into_inner());
        let path = format!(
            "/tmp/rcm_persist_integ_{}_{tag}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        fs::create_dir_all(&path).unwrap();
        let old_home = std::env::var("HOME").unwrap_or_default();
        std::env::set_var("HOME", &path);
        TempHome { path, old_home, _guard: guard }
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        std::env::set_var("HOME", &self.old_home);
        fs::remove_dir_all(&self.path).ok();
    }
}

/// Write a minimal fake executable. Does not need to be a real binary —
/// only needs to exist on disk so `install_*` calls can `fs::copy` it.
fn fake_bin(dir: &str, name: &str) -> String {
    let path = format!("{dir}/{name}");
    fs::write(&path, b"\x7fELF fake binary for testing").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

// ── Platform-guard tests ──────────────────────────────────────────────────────
//
// These run on all platforms. On non-Windows hosts they verify that Windows-only
// commands return a clean error (not a panic or garbage output). Mirrors the
// pattern in handlers/persistence.rs inline tests.

#[test]
#[cfg(not(target_os = "windows"))]
fn run_key_on_non_windows_returns_os_error() {
    let result = persist::install_run("TestKey", "C:\\agent.exe");
    assert!(result.is_err(), "install_run should fail on non-Windows");
    assert!(
        result.unwrap_err().to_lowercase().contains("windows"),
        "Error message must mention the platform"
    );
}

#[test]
#[cfg(not(target_os = "windows"))]
fn run_hklm_on_non_windows_returns_os_error() {
    let result = persist::install_run_hklm("TestKey", "C:\\agent.exe");
    assert!(result.is_err());
}

#[test]
#[cfg(not(target_os = "windows"))]
fn scheduled_task_on_non_windows_returns_os_error() {
    let result = persist::install_task("TestTask", "C:\\agent.exe");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_lowercase().contains("windows"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn startup_folder_on_non_windows_returns_os_error() {
    let result = persist::install_startup("agent.exe", "C:\\agent.exe");
    assert!(result.is_err());
}

#[test]
#[cfg(not(target_os = "macos"))]
fn launchagent_on_non_macos_returns_os_error() {
    let result = persist::install_launchagent("com.test.agent", "/tmp/agent");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_lowercase().contains("macos"),
        "Error must mention platform");
}

#[test]
#[cfg(not(target_os = "linux"))]
fn systemd_on_non_linux_returns_os_error() {
    let result = persist::install_systemd("myservice", "/tmp/agent");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_lowercase().contains("linux"));
}

#[test]
#[cfg(not(target_os = "linux"))]
fn profile_on_non_linux_returns_os_error() {
    let result = persist::install_profile("/tmp/agent");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_lowercase().contains("linux"));
}

// ── Linux integration tests ───────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rcm::agent::persistence as persist;

    // ── systemd ──────────────────────────────────────────────────────────────

    #[test]
    fn systemd_install_creates_unit_file_on_disk() {
        let h = TempHome::new("sys_creates");
        let src = fake_bin(&h.path, "agent");

        let result = persist::install_systemd("creates-svc", &src);
        assert!(result.is_ok(), "install_systemd failed: {:?}", result.err());

        let unit = format!("{}/.config/systemd/user/creates-svc.service", h.path);
        assert!(Path::new(&unit).exists(), "Unit file must exist at {unit}");
    }

    #[test]
    fn systemd_install_unit_contains_required_directives() {
        let h = TempHome::new("sys_content");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("content-svc", &src).unwrap();

        let unit = format!("{}/.config/systemd/user/content-svc.service", h.path);
        let content = fs::read_to_string(&unit).unwrap();

        for directive in &["[Unit]", "[Service]", "[Install]",
                            "Type=simple", "Restart=on-failure",
                            "WantedBy=default.target", "ExecStart="] {
            assert!(content.contains(directive),
                "Unit file missing directive '{directive}':\n{content}");
        }
    }

    #[test]
    fn systemd_install_unit_exec_start_is_stable_path() {
        let h = TempHome::new("sys_stable_path");
        let src = fake_bin(&h.path, "src_agent");
        persist::install_systemd("stable-svc", &src).unwrap();

        let unit = format!("{}/.config/systemd/user/stable-svc.service", h.path);
        let content = fs::read_to_string(&unit).unwrap();

        let stable = format!("{}/.local/bin/stable-svc", h.path);
        assert!(
            content.contains(&format!("ExecStart={stable}")),
            "ExecStart must point to stable path {stable}, not original.\nUnit:\n{content}"
        );
    }

    #[test]
    fn systemd_install_stable_binary_is_executable() {
        let h = TempHome::new("sys_exec_bit");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("exec-svc", &src).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let stable = format!("{}/.local/bin/exec-svc", h.path);
        let mode = fs::metadata(&stable).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0,
            "Stable binary must be executable (mode: {:o})", mode);
    }

    #[test]
    fn systemd_install_creates_wants_symlink() {
        let h = TempHome::new("sys_wants");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("wants-svc", &src).unwrap();

        let link = format!(
            "{}/.config/systemd/user/default.target.wants/wants-svc.service",
            h.path
        );
        let meta = fs::symlink_metadata(&link)
            .expect("wants symlink must exist");
        assert!(meta.file_type().is_symlink(), "Must be a symlink, not a regular file");
    }

    #[test]
    fn systemd_install_success_message_mentions_stable_path() {
        let h = TempHome::new("sys_msg");
        let src = fake_bin(&h.path, "agent");
        let msg = persist::install_systemd("msg-svc", &src).unwrap();

        let stable = format!("{}/.local/bin/msg-svc", h.path);
        assert!(msg.contains(&stable), "Output must mention stable path:\n{msg}");
        assert!(msg.contains("[+]"), "Success message must start with [+]");
    }

    #[test]
    fn systemd_install_reports_copy_source_to_destination() {
        let h = TempHome::new("sys_copy_msg");
        let src = fake_bin(&h.path, "copyme");
        let msg = persist::install_systemd("copy-svc", &src).unwrap();

        // Message should show: "Copied: <src> → <dst>"
        assert!(msg.contains("Copied:") || msg.contains("→"),
            "Output must show the copy operation:\n{msg}");
    }

    #[test]
    fn systemd_install_idempotent() {
        let h = TempHome::new("sys_idem");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("idem-svc", &src).unwrap();
        // Second install must not error — overwrites existing unit
        let result = persist::install_systemd("idem-svc", &src);
        assert!(result.is_ok(), "Second install must not fail");
    }

    #[test]
    fn systemd_remove_deletes_unit_file() {
        let h = TempHome::new("sys_rm_unit");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("rm-unit-svc", &src).unwrap();

        let unit = format!("{}/.config/systemd/user/rm-unit-svc.service", h.path);
        assert!(Path::new(&unit).exists(), "Setup: unit must exist");

        persist::remove_systemd("rm-unit-svc").unwrap();
        assert!(!Path::new(&unit).exists(), "Unit file must be deleted after remove");
    }

    #[test]
    fn systemd_remove_deletes_wants_symlink() {
        let h = TempHome::new("sys_rm_link");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("rm-link-svc", &src).unwrap();

        let link = format!(
            "{}/.config/systemd/user/default.target.wants/rm-link-svc.service",
            h.path
        );
        persist::remove_systemd("rm-link-svc").unwrap();
        assert!(fs::symlink_metadata(&link).is_err(), "Symlink must be deleted");
    }

    #[test]
    fn systemd_remove_nonexistent_unit_returns_ok_with_tilde() {
        let h = TempHome::new("sys_rm_none");
        let result = persist::remove_systemd("not-installed-at-all");
        assert!(result.is_ok(), "Must not error for missing unit");
        assert!(result.unwrap().starts_with("[~]"),
            "Message must start with [~] to indicate nothing was removed");
    }

    #[test]
    fn systemd_remove_returns_ok_message() {
        let h = TempHome::new("sys_rm_ok");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("good-remove", &src).unwrap();
        let msg = persist::remove_systemd("good-remove").unwrap();
        assert!(msg.contains("[+]"), "Success message must contain [+]");
    }

    // ── profile ───────────────────────────────────────────────────────────────

    #[test]
    fn profile_install_creates_bashrc_with_sentinel() {
        let h = TempHome::new("prof_bash");
        let src = fake_bin(&h.path, "agent");
        persist::install_profile(&src).unwrap();

        let bashrc = format!("{}/.bashrc", h.path);
        let content = fs::read_to_string(&bashrc).unwrap();
        assert!(content.contains("# --- rcm-persist-start ---"), ".bashrc missing start sentinel");
        assert!(content.contains("# --- rcm-persist-end ---"),   ".bashrc missing end sentinel");
    }

    #[test]
    fn profile_install_creates_profile_with_sentinel() {
        let h = TempHome::new("prof_prof");
        let src = fake_bin(&h.path, "agent");
        persist::install_profile(&src).unwrap();

        let profile = format!("{}/.profile", h.path);
        let content = fs::read_to_string(&profile).unwrap();
        assert!(content.contains("# --- rcm-persist-start ---"), ".profile missing sentinel");
    }

    #[test]
    fn profile_install_injects_stable_path_not_source() {
        let h = TempHome::new("prof_stable");
        let src = fake_bin(&h.path, "testbin");
        persist::install_profile(&src).unwrap();

        let bashrc  = format!("{}/.bashrc", h.path);
        let content = fs::read_to_string(&bashrc).unwrap();
        let stable  = format!("{}/.local/bin/testbin", h.path);

        assert!(content.contains(&stable),
            "Injected entry must reference stable path {stable}.\n.bashrc:\n{content}");
    }

    #[test]
    fn profile_install_stable_binary_is_executable() {
        let h = TempHome::new("prof_exec");
        let src = fake_bin(&h.path, "execbin");
        persist::install_profile(&src).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let stable = format!("{}/.local/bin/execbin", h.path);
        let mode = fs::metadata(&stable).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0,
            "Stable binary must be executable (mode {:o})", mode);
    }

    #[test]
    fn profile_install_is_idempotent() {
        let h = TempHome::new("prof_idem");
        let src = fake_bin(&h.path, "idem_agent");
        persist::install_profile(&src).unwrap();
        persist::install_profile(&src).unwrap(); // second call

        let bashrc  = format!("{}/.bashrc", h.path);
        let content = fs::read_to_string(&bashrc).unwrap();
        let count   = content.matches("# --- rcm-persist-start ---").count();
        assert_eq!(count, 1, "Sentinel must appear exactly once after two installs (got {count})");
    }

    #[test]
    fn profile_install_preserves_content_before_sentinel() {
        let h = TempHome::new("prof_pre");
        let bashrc = format!("{}/.bashrc", h.path);
        let pre = "export PATH=\"$HOME/.local/bin:$PATH\"\nalias ll='ls -la'\n";
        fs::write(&bashrc, pre).unwrap();

        let src = fake_bin(&h.path, "preserve_agent");
        persist::install_profile(&src).unwrap();

        let content = fs::read_to_string(&bashrc).unwrap();
        assert!(content.contains("alias ll='ls -la'"),
            "Pre-existing content must be preserved");
        assert!(content.contains("# --- rcm-persist-start ---"),
            "Sentinel must still be appended");
    }

    #[test]
    fn profile_remove_strips_only_the_sentinel_block() {
        let h = TempHome::new("prof_rm");
        let bashrc = format!("{}/.bashrc", h.path);
        fs::write(&bashrc, "# pre-existing content\n").unwrap();

        let src = fake_bin(&h.path, "rm_agent");
        persist::install_profile(&src).unwrap();

        // Confirm sentinel is present
        assert!(fs::read_to_string(&bashrc).unwrap().contains("rcm-persist-start"),
            "Setup: sentinel must be present");

        // remove_profile removes by sentinel, not by path — pass the stable path
        let stable = format!("{}/.local/bin/rm_agent", h.path);
        persist::remove_profile(&stable).unwrap();

        let after = fs::read_to_string(&bashrc).unwrap();
        assert!(!after.contains("rcm-persist-start"),  "Sentinel must be removed");
        assert!(after.contains("# pre-existing content"), "Pre-existing content must survive");
    }

    #[test]
    fn profile_remove_preserves_content_after_sentinel() {
        let h = TempHome::new("prof_post");
        let bashrc = format!("{}/.bashrc", h.path);
        fs::write(&bashrc, "# before\n").unwrap();

        let src = fake_bin(&h.path, "post_agent");
        persist::install_profile(&src).unwrap();

        // Append a line after the injected block
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&bashrc).unwrap();
        writeln!(f, "# after").unwrap();
        drop(f);

        let stable = format!("{}/.local/bin/post_agent", h.path);
        persist::remove_profile(&stable).unwrap();

        let after = fs::read_to_string(&bashrc).unwrap();
        assert!(after.contains("# before"), "Content before sentinel must survive");
        assert!(after.contains("# after"),  "Content after sentinel must survive");
    }

    #[test]
    fn profile_remove_nonexistent_returns_graceful_ok() {
        let h = TempHome::new("prof_rm_none");
        let result = persist::remove_profile("/tmp/not_installed_anywhere");
        assert!(result.is_ok(), "Must not error when nothing to remove");
        let msg = result.unwrap();
        assert!(msg.starts_with("[~]"), "Must signal nothing was found: {msg}");
    }

    #[test]
    fn profile_install_success_message_has_plus_prefix() {
        let h = TempHome::new("prof_msg");
        let src = fake_bin(&h.path, "msg_agent");
        let msg = persist::install_profile(&src).unwrap();
        assert!(msg.contains("[+]"), "Success message must contain [+]:\n{msg}");
    }

    // ── list ──────────────────────────────────────────────────────────────────

    #[test]
    fn list_output_has_crontab_section() {
        let h = TempHome::new("list_cron");
        let out = persist::list();
        assert!(out.contains("Crontab"), "list() must include a Crontab section:\n{out}");
    }

    #[test]
    fn list_output_has_systemd_section() {
        let h = TempHome::new("list_sys");
        let out = persist::list();
        assert!(out.contains("Systemd"), "list() must include a Systemd section:\n{out}");
    }

    #[test]
    fn list_output_has_profile_section() {
        let h = TempHome::new("list_prof");
        let out = persist::list();
        assert!(out.contains("Profile") || out.contains("Shell"),
            "list() must include a profile/shell section:\n{out}");
    }

    #[test]
    fn list_shows_installed_systemd_unit() {
        let h = TempHome::new("list_sys_shows");
        let src = fake_bin(&h.path, "agent");
        persist::install_systemd("visible-svc", &src).unwrap();

        let out = persist::list();
        assert!(out.contains("visible-svc"), "list() must show installed unit:\n{out}");
    }

    #[test]
    fn list_shows_injected_profile_files() {
        let h = TempHome::new("list_prof_shows");
        let src = fake_bin(&h.path, "agent");
        persist::install_profile(&src).unwrap();

        let out = persist::list();
        assert!(out.contains(".bashrc") || out.contains("injected"),
            "list() must report injected profile files:\n{out}");
    }

    // ── stable drop via public API ────────────────────────────────────────────

    #[test]
    fn systemd_copies_source_binary_to_local_bin() {
        let h = TempHome::new("pub_sd_sys");
        let src = fake_bin(&h.path, "orig");
        persist::install_systemd("copy-test-svc", &src).unwrap();

        let stable = format!("{}/.local/bin/copy-test-svc", h.path);
        assert!(Path::new(&stable).exists(),
            "Source binary must be copied to stable location {stable}");
    }

    #[test]
    fn profile_copies_source_binary_to_local_bin() {
        let h = TempHome::new("pub_sd_prof");
        let src = fake_bin(&h.path, "profagent");
        persist::install_profile(&src).unwrap();

        let stable = format!("{}/.local/bin/profagent", h.path);
        assert!(Path::new(&stable).exists(),
            "Source binary must be copied to {stable}");
    }

    #[test]
    fn stable_binary_survives_deletion_of_source() {
        let h = TempHome::new("pub_sd_survive");
        let src = fake_bin(&h.path, "survivebin");
        persist::install_systemd("survive-svc", &src).unwrap();

        // Delete the original source
        fs::remove_file(&src).unwrap();

        // Stable copy must still exist
        let stable = format!("{}/.local/bin/survive-svc", h.path);
        assert!(Path::new(&stable).exists(),
            "Stable copy must survive deletion of original source");
    }
}

// ── Handler argument-parsing tests ───────────────────────────────────────────
//
// These live in src/agent/handlers/persistence.rs as inline #[cfg(test)]
// tests because DispatchResult is pub(crate) and not accessible from here.
// See the `mod tests` block at the bottom of that file.
