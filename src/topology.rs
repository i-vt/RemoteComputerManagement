//! Passive network topology inference from session interface data.
//!
//! All analysis runs over data agents already reported at registration — no
//! probes are sent and no new network traffic is ever generated.
//!
//! # Usage
//!
//! 1. Collect [`SessionSnapshot`]s from `SharedSessions` (each snapshot holds
//!    the session id, hostname, and reported network interfaces).
//! 2. Call [`TopologyManager::plan`] with a target IP or CIDR to get ranked
//!    [`RouteCandidate`]s — which sessions can reach the target, and how good
//!    each route is.
//! 3. Call [`TopologyManager::build_snapshot`] for the full cross-session view
//!    including shared networks and overlapping-CIDR conflicts.
//! 4. Call [`TopologyManager::render_plan`] to get a printable string for the
//!    server console.
//!
//! # Adding to the server command loop
//!
//! In `src/server/session.rs`, when `handle_connection` builds the `Session`
//! it now stores `interfaces: hello.interfaces.clone()`.  In
//! `src/server/mod.rs` add a `"plan"` command arm that:
//! ```ignore
//! let snaps: Vec<SessionSnapshot> = sessions.iter()
//!     .map(|e| SessionSnapshot {
//!         session_id: *e.key(),
//!         hostname: e.value().hostname.clone(),
//!         interfaces: e.value().interfaces.clone(),
//!     })
//!     .collect();
//! let candidates = TopologyManager::plan(&snaps, target);
//! println!("{}", TopologyManager::render_plan(target, &candidates));
//! ```

use crate::common::NetworkInterface;
use std::collections::HashMap;
use std::net::Ipv4Addr;

// ── Public data types ──────────────────────────────────────────────────────

/// Lightweight per-session snapshot carrying only the fields topology needs.
/// Decoupled from `Session` so all topology functions are pure — no channels,
/// no atomics, no locks needed in tests.
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub session_id: u32,
    pub hostname: String,
    pub interfaces: Vec<NetworkInterface>,
}

/// One reachable CIDR exposed by a specific session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub session_id: u32,
    pub hostname: String,
    /// Network address in CIDR notation, e.g. "10.20.0.0/24".
    pub cidr: String,
    pub interface: String,
    /// The specific IP address reported by the agent for this interface.
    pub source_addr: String,
    /// Confidence score — higher is better. Driven by prefix length,
    /// RFC-1918 membership, interface name heuristics, and UP flag.
    pub score: u16,
}

/// A CIDR reachable via more than one session (redundant or load-balanced).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedNetwork {
    pub cidr: String,
    pub sessions: Vec<u32>,
}

/// Two sessions advertising overlapping-but-not-identical CIDRs.
/// The operator should choose which session to route through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConflict {
    pub cidr_a: String,
    pub cidr_b: String,
    pub session_a: u32,
    pub session_b: u32,
}

/// Full cross-session view computed on demand.
#[derive(Debug, Clone, Default)]
pub struct TopologySnapshot {
    /// All non-loopback, non-link-local IPv4 routes across all sessions,
    /// sorted by score descending.
    pub candidates: Vec<RouteCandidate>,
    /// CIDRs covered by more than one session.
    pub shared_networks: Vec<SharedNetwork>,
    /// Overlapping-but-different CIDRs from different sessions.
    pub conflicts: Vec<RouteConflict>,
}

// ── TopologyManager ────────────────────────────────────────────────────────

pub struct TopologyManager;

impl TopologyManager {
    // ── Public API ──────────────────────────────────────────────────────────

    /// Build a full topology snapshot from a set of session snapshots.
    pub fn build_snapshot(sessions: &[SessionSnapshot]) -> TopologySnapshot {
        let mut candidates: Vec<RouteCandidate> = sessions
            .iter()
            .flat_map(Self::candidates_for_session)
            .collect();

        // Highest score first; break ties by CIDR then session_id for stability.
        candidates.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.cidr.cmp(&b.cidr))
                .then_with(|| a.session_id.cmp(&b.session_id))
        });

        let shared_networks = Self::find_shared_networks(&candidates);
        let conflicts = Self::find_conflicts(&candidates);

        TopologySnapshot {
            candidates,
            shared_networks,
            conflicts,
        }
    }

    /// Return ranked route candidates that can reach `target` (IP or CIDR).
    /// Returns an empty vec when no session has a matching route.
    /// No network traffic is generated.
    pub fn plan(sessions: &[SessionSnapshot], target: &str) -> Vec<RouteCandidate> {
        let target_ip = match Self::parse_target_ip(target) {
            Some(ip) => ip,
            None => return vec![],
        };

        let snap = Self::build_snapshot(sessions);
        snap.candidates
            .into_iter()
            .filter(|c| Self::cidr_contains(&c.cidr, target_ip))
            .collect()
        // Already sorted by score from build_snapshot.
    }

    /// Render plan results as a human-readable string for the server console.
    pub fn render_plan(target: &str, candidates: &[RouteCandidate]) -> String {
        let mut out = format!("\n[plan] Target: {}\n{}\n", target, "─".repeat(52));

        if candidates.is_empty() {
            out.push_str("  ✗  No route candidates found across active sessions.\n");
            out.push_str("     Check that agents are registered with interface data.\n");
        } else {
            for (i, c) in candidates.iter().enumerate() {
                let marker = if i == 0 { "✓" } else { "·" };
                out.push_str(&format!(
                    "  {}  Session #{} ({}) via {} [{}] — score {}\n",
                    marker, c.session_id, c.hostname, c.interface, c.cidr, c.score
                ));
            }
        }
        out
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    fn candidates_for_session(session: &SessionSnapshot) -> Vec<RouteCandidate> {
        let mut out: Vec<RouteCandidate> = session
            .interfaces
            .iter()
            .flat_map(|iface| {
                iface.addresses.iter().filter_map(|addr| {
                    let (cidr, source) = Self::normalize_ipv4_cidr(addr, iface)?;
                    if !Self::is_route_candidate(&cidr, iface) {
                        return None;
                    }
                    let score = Self::score(&cidr, iface);
                    Some(RouteCandidate {
                        session_id: session.session_id,
                        hostname: session.hostname.clone(),
                        cidr,
                        interface: iface.name.clone(),
                        source_addr: source,
                        score,
                    })
                })
            })
            .collect();

        // Deduplicate same CIDR on the same interface (multiple host IPs in range).
        out.sort_by(|a, b| a.cidr.cmp(&b.cidr).then(b.score.cmp(&a.score)));
        out.dedup_by(|a, b| a.cidr == b.cidr && a.interface == b.interface);
        out
    }

    /// Normalise "10.0.1.5/24" → ("10.0.0.0/24", "10.0.1.5").
    /// Returns `None` for IPv6, unparseable addresses, or prefix > 32.
    fn normalize_ipv4_cidr(addr: &str, _iface: &NetworkInterface) -> Option<(String, String)> {
        let (ip_str, prefix_str) = addr.split_once('/')?;
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = Self::prefix_to_mask(prefix);
        let network = Ipv4Addr::from(u32::from(ip) & mask);
        Some((format!("{}/{}", network, prefix), ip_str.to_string()))
    }

    fn prefix_to_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            !((1u32 << (32 - prefix)) - 1)
        }
    }

    /// Returns `false` for loopback, default-route, link-local, and multicast.
    fn is_route_candidate(cidr: &str, iface: &NetworkInterface) -> bool {
        let (ip_str, _) = match cidr.split_once('/') {
            Some(p) => p,
            None => return false,
        };
        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        if ip.is_loopback() || ip == Ipv4Addr::UNSPECIFIED {
            return false;
        }
        // 169.254.x.x link-local
        if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
            return false;
        }
        if ip.is_multicast() {
            return false;
        }
        if iface.flags.iter().any(|f| f == "LOOPBACK") {
            return false;
        }
        true
    }

    /// Produce a confidence score for a route candidate.
    ///
    /// Rules (additive):
    /// - Prefix length contributes 0–32 points (more specific = better).
    /// - RFC-1918 address: +20.
    /// - Physical interface names (eth, en, em): +10. Wireless (wl): +8.
    ///   Container / virtual (docker, veth, br-): −10.
    /// - Interface has the UP flag: +10.
    fn score(cidr: &str, iface: &NetworkInterface) -> u16 {
        let (ip_str, prefix_str) = match cidr.split_once('/') {
            Some(p) => p,
            None => return 0,
        };
        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return 0,
        };
        let prefix: u8 = prefix_str.parse().unwrap_or(0);

        let mut s = prefix as u16;

        if ip.is_private() {
            s += 20;
        }

        let name = iface.name.to_lowercase();
        if name.starts_with("eth") || name.starts_with("en") || name.starts_with("em") {
            s += 10;
        } else if name.starts_with("wl") {
            s += 8;
        } else if name.starts_with("docker")
            || name.starts_with("veth")
            || name.starts_with("br-")
        {
            s = s.saturating_sub(10);
        }

        if iface.flags.iter().any(|f| f == "UP") {
            s += 10;
        }

        s
    }

    fn find_shared_networks(candidates: &[RouteCandidate]) -> Vec<SharedNetwork> {
        let mut by_cidr: HashMap<&str, Vec<u32>> = HashMap::new();
        for c in candidates {
            by_cidr.entry(&c.cidr).or_default().push(c.session_id);
        }

        let mut out: Vec<SharedNetwork> = by_cidr
            .into_iter()
            .filter_map(|(cidr, mut sessions)| {
                sessions.sort_unstable();
                sessions.dedup();
                if sessions.len() > 1 {
                    Some(SharedNetwork {
                        cidr: cidr.to_string(),
                        sessions,
                    })
                } else {
                    None
                }
            })
            .collect();

        out.sort_by(|a, b| a.cidr.cmp(&b.cidr));
        out
    }

    /// A conflict is two candidates from *different* sessions where one CIDR is
    /// a supernet of the other — the operator must choose which route to prefer.
    fn find_conflicts(candidates: &[RouteCandidate]) -> Vec<RouteConflict> {
        let mut conflicts = Vec::new();
        for (i, a) in candidates.iter().enumerate() {
            for b in candidates.iter().skip(i + 1) {
                if a.session_id == b.session_id || a.cidr == b.cidr {
                    continue;
                }
                if Self::cidrs_overlap(&a.cidr, &b.cidr) {
                    conflicts.push(RouteConflict {
                        cidr_a: a.cidr.clone(),
                        cidr_b: b.cidr.clone(),
                        session_a: a.session_id,
                        session_b: b.session_id,
                    });
                }
            }
        }
        conflicts
    }

    fn cidrs_overlap(a: &str, b: &str) -> bool {
        let (a_ip, a_p) = match Self::parse_cidr(a) {
            Some(v) => v,
            None => return false,
        };
        let (b_ip, b_p) = match Self::parse_cidr(b) {
            Some(v) => v,
            None => return false,
        };
        Self::cidr_contains_ip(a_ip, a_p, b_ip) || Self::cidr_contains_ip(b_ip, b_p, a_ip)
    }

    fn cidr_contains(cidr: &str, target: Ipv4Addr) -> bool {
        match Self::parse_cidr(cidr) {
            Some((net, prefix)) => Self::cidr_contains_ip(net, prefix, target),
            None => false,
        }
    }

    fn cidr_contains_ip(network: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
        let mask = Self::prefix_to_mask(prefix);
        (u32::from(network) & mask) == (u32::from(ip) & mask)
    }

    fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
        let (ip_str, prefix_str) = cidr.split_once('/')?;
        Some((ip_str.parse().ok()?, prefix_str.parse().ok()?))
    }

    /// Parse a target string as a single IPv4 address, accepting either
    /// "10.0.0.5" or "10.0.0.0/24" (uses the network/host address).
    fn parse_target_ip(target: &str) -> Option<Ipv4Addr> {
        if let Some((ip_str, _)) = target.split_once('/') {
            ip_str.parse().ok()
        } else {
            target.parse().ok()
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::NetworkInterface;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn iface(name: &str, addrs: &[&str], flags: &[&str]) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            addresses: addrs.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn snap(id: u32, hostname: &str, ifaces: Vec<NetworkInterface>) -> SessionSnapshot {
        SessionSnapshot {
            session_id: id,
            hostname: hostname.to_string(),
            interfaces: ifaces,
        }
    }

    // ── normalize_ipv4_cidr ───────────────────────────────────────────────

    #[test]
    fn normalize_masks_host_bits() {
        let i = iface("eth0", &[], &[]);
        let (cidr, src) =
            TopologyManager::normalize_ipv4_cidr("192.168.1.50/24", &i).unwrap();
        assert_eq!(cidr, "192.168.1.0/24");
        assert_eq!(src, "192.168.1.50");
    }

    #[test]
    fn normalize_slash16_network() {
        let i = iface("eth0", &[], &[]);
        let (cidr, _) =
            TopologyManager::normalize_ipv4_cidr("172.16.5.1/16", &i).unwrap();
        assert_eq!(cidr, "172.16.0.0/16");
    }

    #[test]
    fn normalize_slash32_unchanged() {
        let i = iface("eth0", &[], &[]);
        let (cidr, _) =
            TopologyManager::normalize_ipv4_cidr("10.0.0.1/32", &i).unwrap();
        assert_eq!(cidr, "10.0.0.1/32");
    }

    #[test]
    fn normalize_rejects_ipv6() {
        let i = iface("eth0", &[], &[]);
        assert!(TopologyManager::normalize_ipv4_cidr("fe80::1/64", &i).is_none());
    }

    #[test]
    fn normalize_rejects_bad_prefix() {
        let i = iface("eth0", &[], &[]);
        assert!(TopologyManager::normalize_ipv4_cidr("10.0.0.1/99", &i).is_none());
    }

    #[test]
    fn normalize_rejects_no_prefix() {
        let i = iface("eth0", &[], &[]);
        assert!(TopologyManager::normalize_ipv4_cidr("10.0.0.1", &i).is_none());
    }

    // ── prefix_to_mask ────────────────────────────────────────────────────

    #[test]
    fn mask_slash24() {
        let mask = TopologyManager::prefix_to_mask(24);
        assert_eq!(mask, 0xFFFF_FF00);
    }

    #[test]
    fn mask_slash0_is_zero() {
        assert_eq!(TopologyManager::prefix_to_mask(0), 0);
    }

    #[test]
    fn mask_slash32_all_ones() {
        assert_eq!(TopologyManager::prefix_to_mask(32), 0xFFFF_FFFF);
    }

    // ── is_route_candidate ────────────────────────────────────────────────

    #[test]
    fn loopback_flag_excluded() {
        let i = iface("lo", &[], &["LOOPBACK", "UP"]);
        assert!(!TopologyManager::is_route_candidate("127.0.0.0/8", &i));
    }

    #[test]
    fn loopback_ip_excluded() {
        let i = iface("eth0", &[], &["UP"]);
        assert!(!TopologyManager::is_route_candidate("127.0.0.1/8", &i));
    }

    #[test]
    fn link_local_169_excluded() {
        let i = iface("eth0", &[], &["UP"]);
        assert!(!TopologyManager::is_route_candidate("169.254.1.0/16", &i));
    }

    #[test]
    fn unspecified_0_0_0_0_excluded() {
        let i = iface("eth0", &[], &["UP"]);
        assert!(!TopologyManager::is_route_candidate("0.0.0.0/0", &i));
    }

    #[test]
    fn rfc1918_10_included() {
        let i = iface("eth0", &[], &["UP"]);
        assert!(TopologyManager::is_route_candidate("10.0.0.0/8", &i));
    }

    #[test]
    fn rfc1918_192_168_included() {
        let i = iface("eth0", &[], &["UP"]);
        assert!(TopologyManager::is_route_candidate("192.168.0.0/24", &i));
    }

    #[test]
    fn public_ip_included() {
        let i = iface("eth0", &[], &["UP"]);
        assert!(TopologyManager::is_route_candidate("8.8.0.0/24", &i));
    }

    // ── score ─────────────────────────────────────────────────────────────

    #[test]
    fn eth_scores_higher_than_docker() {
        let eth = iface("eth0", &[], &["UP"]);
        let docker = iface("docker0", &[], &["UP"]);
        assert!(
            TopologyManager::score("10.0.0.0/24", &eth)
                > TopologyManager::score("10.0.0.0/24", &docker)
        );
    }

    #[test]
    fn more_specific_prefix_scores_higher() {
        let i = iface("eth0", &[], &["UP"]);
        assert!(
            TopologyManager::score("10.0.0.0/24", &i)
                > TopologyManager::score("10.0.0.0/16", &i)
        );
    }

    #[test]
    fn private_scores_higher_than_public_same_prefix() {
        let i = iface("eth0", &[], &["UP"]);
        let private = TopologyManager::score("192.168.0.0/24", &i);
        let public = TopologyManager::score("8.8.0.0/24", &i);
        assert!(private > public, "private={} public={}", private, public);
    }

    #[test]
    fn up_flag_adds_score() {
        let up = iface("eth0", &[], &["UP"]);
        let down = iface("eth0", &[], &[]);
        assert!(
            TopologyManager::score("10.0.0.0/24", &up)
                > TopologyManager::score("10.0.0.0/24", &down)
        );
    }

    #[test]
    fn wireless_scores_between_eth_and_docker() {
        let eth = iface("eth0", &[], &["UP"]);
        let wl = iface("wlan0", &[], &["UP"]);
        let docker = iface("docker0", &[], &["UP"]);
        let eth_s = TopologyManager::score("10.0.0.0/24", &eth);
        let wl_s = TopologyManager::score("10.0.0.0/24", &wl);
        let dk_s = TopologyManager::score("10.0.0.0/24", &docker);
        assert!(eth_s > wl_s, "eth={} wl={}", eth_s, wl_s);
        assert!(wl_s > dk_s, "wl={} docker={}", wl_s, dk_s);
    }

    // ── build_snapshot ────────────────────────────────────────────────────

    #[test]
    fn empty_sessions_empty_snapshot() {
        let snap = TopologyManager::build_snapshot(&[]);
        assert!(snap.candidates.is_empty());
        assert!(snap.shared_networks.is_empty());
        assert!(snap.conflicts.is_empty());
    }

    #[test]
    fn single_session_produces_candidate() {
        let sessions = vec![snap(
            1,
            "host-a",
            vec![iface("eth0", &["10.20.0.5/24"], &["UP"])],
        )];
        let s = TopologyManager::build_snapshot(&sessions);
        assert_eq!(s.candidates.len(), 1);
        assert_eq!(s.candidates[0].cidr, "10.20.0.0/24");
        assert_eq!(s.candidates[0].session_id, 1);
    }

    #[test]
    fn loopback_never_in_candidates() {
        let sessions = vec![snap(
            1,
            "host-a",
            vec![
                iface("lo", &["127.0.0.1/8"], &["UP", "LOOPBACK"]),
                iface("eth0", &["10.0.0.2/24"], &["UP"]),
            ],
        )];
        let s = TopologyManager::build_snapshot(&sessions);
        assert!(
            s.candidates.iter().all(|c| c.interface != "lo"),
            "loopback should never appear; candidates: {:?}",
            s.candidates
        );
    }

    #[test]
    fn candidates_sorted_score_desc() {
        let sessions = vec![
            snap(1, "a", vec![iface("docker0", &["10.0.0.2/24"], &["UP"])]),
            snap(2, "b", vec![iface("eth0", &["10.0.1.5/24"], &["UP"])]),
        ];
        let s = TopologyManager::build_snapshot(&sessions);
        // eth0 should appear first (higher score)
        assert_eq!(s.candidates[0].interface, "eth0");
    }

    // ── shared_networks ───────────────────────────────────────────────────

    #[test]
    fn two_sessions_same_cidr_is_shared() {
        let sessions = vec![
            snap(1, "a", vec![iface("eth0", &["10.20.0.5/24"], &["UP"])]),
            snap(2, "b", vec![iface("eth0", &["10.20.0.9/24"], &["UP"])]),
        ];
        let s = TopologyManager::build_snapshot(&sessions);
        assert!(
            s.shared_networks.iter().any(|n| n.cidr == "10.20.0.0/24"),
            "expected shared 10.20.0.0/24; got {:?}",
            s.shared_networks
        );
    }

    #[test]
    fn single_session_never_shared() {
        let sessions = vec![snap(
            1,
            "a",
            vec![iface("eth0", &["10.20.0.5/24"], &["UP"])],
        )];
        let s = TopologyManager::build_snapshot(&sessions);
        assert!(s.shared_networks.is_empty());
    }

    // ── conflicts ─────────────────────────────────────────────────────────

    #[test]
    fn supernet_subset_across_sessions_is_conflict() {
        // /24 is a subset of /16 — they overlap
        let sessions = vec![
            snap(1, "a", vec![iface("eth0", &["10.0.0.5/24"], &["UP"])]),
            snap(2, "b", vec![iface("eth0", &["10.0.1.5/16"], &["UP"])]),
        ];
        let s = TopologyManager::build_snapshot(&sessions);
        assert!(
            !s.conflicts.is_empty(),
            "/24 inside /16 should be a conflict; candidates={:?}",
            s.candidates
        );
    }

    #[test]
    fn non_overlapping_cidrs_no_conflict() {
        let sessions = vec![
            snap(1, "a", vec![iface("eth0", &["10.0.0.5/24"], &["UP"])]),
            snap(2, "b", vec![iface("eth0", &["192.168.1.5/24"], &["UP"])]),
        ];
        let s = TopologyManager::build_snapshot(&sessions);
        assert!(s.conflicts.is_empty());
    }

    #[test]
    fn identical_cidr_from_two_sessions_is_shared_not_conflict() {
        let sessions = vec![
            snap(1, "a", vec![iface("eth0", &["10.0.0.2/24"], &["UP"])]),
            snap(2, "b", vec![iface("eth0", &["10.0.0.9/24"], &["UP"])]),
        ];
        let s = TopologyManager::build_snapshot(&sessions);
        // Same CIDR → shared network, not a conflict
        assert!(
            s.shared_networks.iter().any(|n| n.cidr == "10.0.0.0/24"),
            "should be shared"
        );
        // Conflicts should be empty because the CIDRs are identical
        assert!(s.conflicts.is_empty(), "identical CIDR should not be a conflict");
    }

    // ── plan ──────────────────────────────────────────────────────────────

    #[test]
    fn plan_finds_matching_session_by_ip() {
        let sessions = vec![
            snap(1, "a", vec![iface("eth0", &["10.10.0.5/24"], &["UP"])]),
            snap(2, "b", vec![iface("eth0", &["192.168.1.10/24"], &["UP"])]),
        ];
        let cs = TopologyManager::plan(&sessions, "10.10.0.100");
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].session_id, 1);
    }

    #[test]
    fn plan_accepts_cidr_target() {
        let sessions = vec![snap(
            1,
            "a",
            vec![iface("eth0", &["10.10.0.5/24"], &["UP"])],
        )];
        let cs = TopologyManager::plan(&sessions, "10.10.0.0/24");
        assert!(!cs.is_empty());
        assert_eq!(cs[0].session_id, 1);
    }

    #[test]
    fn plan_empty_when_no_matching_route() {
        let sessions = vec![snap(
            1,
            "a",
            vec![iface("eth0", &["10.10.0.5/24"], &["UP"])],
        )];
        assert!(TopologyManager::plan(&sessions, "172.99.0.1").is_empty());
    }

    #[test]
    fn plan_ranks_eth_before_docker_for_same_subnet() {
        let sessions = vec![
            snap(1, "a", vec![iface("docker0", &["10.10.0.2/24"], &["UP"])]),
            snap(2, "b", vec![iface("eth0", &["10.10.0.6/24"], &["UP"])]),
        ];
        let cs = TopologyManager::plan(&sessions, "10.10.0.100");
        assert!(cs.len() >= 2);
        assert_eq!(cs[0].session_id, 2, "eth0 session should rank first");
    }

    #[test]
    fn plan_rejects_invalid_target() {
        let sessions = vec![snap(
            1,
            "a",
            vec![iface("eth0", &["10.10.0.5/24"], &["UP"])],
        )];
        assert!(TopologyManager::plan(&sessions, "not-an-ip").is_empty());
    }

    // ── render_plan ───────────────────────────────────────────────────────

    #[test]
    fn render_contains_target_and_session_info() {
        let sessions = vec![snap(
            1,
            "host-a",
            vec![iface("eth0", &["10.10.0.5/24"], &["UP"])],
        )];
        let cs = TopologyManager::plan(&sessions, "10.10.0.100");
        let r = TopologyManager::render_plan("10.10.0.100", &cs);
        assert!(r.contains("10.10.0.100"));
        assert!(r.contains("#1"));
        assert!(r.contains("host-a"));
        assert!(r.contains("eth0"));
    }

    #[test]
    fn render_no_candidates_message() {
        let r = TopologyManager::render_plan("172.99.0.1", &[]);
        assert!(r.contains("No route candidates"));
    }

    #[test]
    fn render_first_candidate_has_checkmark() {
        let sessions = vec![snap(
            1,
            "a",
            vec![iface("eth0", &["10.10.0.5/24"], &["UP"])],
        )];
        let cs = TopologyManager::plan(&sessions, "10.10.0.100");
        let r = TopologyManager::render_plan("10.10.0.100", &cs);
        assert!(r.contains('✓'));
    }
}
