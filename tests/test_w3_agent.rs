// tests/test_w3_agent.rs - Wave 3 agent tests (integration-visible items)
//
// guardrail matchers are unit-tested in-file in
// src/agent/evasion/detection.rs; the tests here exercise the same fns
// through the pub re-export path (rcm::agent::evasion) to prove the
// surface the run() gate consumes. Media recorder selection is tested
// in-file in scripting/media.rs (module is crate-private), dotnet b64
// staging in-file in handlers/execution.rs.

use rcm::agent::evasion;

#[test]
fn wildcard_match_via_pub_reexport() {
    assert!(evasion::wildcard_match("CORP*", "corp-example"));
    assert!(evasion::wildcard_match("*.example.com", "wks01.example.com"));
    assert!(!evasion::wildcard_match("CORP*", "CONTOSO"));
    assert!(!evasion::wildcard_match("WKS?", "WKS01"));
}

#[test]
fn hour_window_wraparound_via_pub_reexport() {
    assert!(evasion::hour_in_window(23, 22, 6));
    assert!(!evasion::hour_in_window(12, 22, 6));
    assert!(evasion::hour_in_window(9, 9, 17));
    assert!(!evasion::hour_in_window(17, 9, 17));
}

#[test]
fn root_or_system_check_runs() {
 // Privilege-dependent; the gate just must not panic or wedge.
    let _ = evasion::is_root_or_system();
}
