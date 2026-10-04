// tests/test_w2_menu.rs - Unit tests for the wave-2 menu command builders.
//
// Covers the pivot listener lifecycle wire format agreed with the agent
// batch: the agent router matches `pivot:list` exactly and strips the
// `pivot:stop ` prefix, parsing the remainder as the listener id.

use rcm::menu::handlers::{build_pivot_list_command, build_pivot_stop_command};

#[test]
fn pivot_list_command_matches_agent_router() {
    assert_eq!(build_pivot_list_command(), "pivot:list");
}

#[test]
fn pivot_stop_command_uses_exact_wire_format() {
    // Contract with the agent batch: the string must be `pivot:stop <id>`.
    assert_eq!(build_pivot_stop_command("3").unwrap(), "pivot:stop 3");
}

#[test]
fn pivot_stop_command_strips_prefix_as_agent_would() {
    // Agent side: cmd.strip_prefix("pivot:stop ") then parse the id.
    let cmd = build_pivot_stop_command("42").unwrap();
    let id = cmd.strip_prefix("pivot:stop ").unwrap();
    assert_eq!(id.parse::<u32>().unwrap(), 42);
}

#[test]
fn pivot_stop_command_normalizes_whitespace_and_leading_zeros() {
    assert_eq!(build_pivot_stop_command("  7  ").unwrap(), "pivot:stop 7");
    assert_eq!(build_pivot_stop_command("007").unwrap(), "pivot:stop 7");
}

#[test]
fn pivot_stop_command_rejects_missing_and_bad_ids() {
    assert!(build_pivot_stop_command("").is_err());
    assert!(build_pivot_stop_command("   ").is_err());
    assert!(build_pivot_stop_command("abc").is_err());
    assert!(build_pivot_stop_command("-1").is_err());
    assert!(build_pivot_stop_command("1 2").is_err());
    assert!(build_pivot_stop_command("99999999999").is_err());
}
