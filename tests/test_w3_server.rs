use rcm::server::http_listener::{
    apply_profile_body_transform, check_stage_rate_limit, drain_poll_items,
    find_stage_challenge_key, http_tls_acceptor, parse_http_outbound,
    reverse_profile_body_transform, stage_artifact_path, stage_request_authorized,
    verify_stage_api_key, verify_stage_auth,
    HttpC2State, HttpOutboundItem,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rcm::common::{PivotFrame, SecuredCommand, TransformStep};
use rcm::api::routes::listeners::{collect_c2_hints, parse_ipv4_sans_from_openssl_text};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

fn stage_db() -> rcm::database::DbPool {
    let path = format!("/tmp/rcm_w3_stage_{}.db", uuid::Uuid::new_v4());
    let manager = r2d2_sqlite::SqliteConnectionManager::file(path);
    let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();
    pool.get().unwrap().execute_batch(
        "CREATE TABLE build_keys (
            build_id TEXT PRIMARY KEY,
            private_key BLOB,
            profile TEXT DEFAULT 'default',
            profile_data TEXT,
            challenge_key BLOB
         );"
    ).unwrap();
    pool
}

fn stage_hmac(key: &[u8], build_id: &str, timestamp: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(build_id.as_bytes());
    mac.update(b":");
    mac.update(timestamp.as_bytes());
    BASE64.encode(mac.finalize().into_bytes())
}

#[test]
fn stage_artifact_path_is_single_private_payload_per_canonical_build_id() {
    let id = "550e8400-e29b-41d4-a716-446655440000";
    let path = stage_artifact_path(id).unwrap();
    assert_eq!(path.file_name().unwrap(), "staged_550e8400-e29b-41d4-a716-446655440000.payload");
    assert_eq!(path.parent().unwrap().file_name().unwrap(), "dist");

    assert!(stage_artifact_path("../stage/payload").is_none());
    assert!(stage_artifact_path("550E8400-E29B-41D4-A716-446655440000").is_none());
    assert!(stage_artifact_path("550e8400e29b41d4a716446655440000").is_none());
}

#[test]
fn stage_build_lookup_uses_exact_build_id_and_returns_its_challenge_key() {
    let pool = stage_db();
    let conn = pool.get().unwrap();
    let first = "550e8400-e29b-41d4-a716-446655440000";
    let second = "550e8400-e29b-41d4-a716-446655440001";
    conn.execute(
        "INSERT INTO build_keys (build_id, private_key, challenge_key) VALUES (?1, ?2, ?3)",
        rusqlite::params![first, vec![1u8; 32], vec![7u8; 32]],
    ).unwrap();
    conn.execute(
        "INSERT INTO build_keys (build_id, private_key, challenge_key) VALUES (?1, ?2, ?3)",
        rusqlite::params![second, vec![2u8; 32], vec![8u8; 32]],
    ).unwrap();

    assert_eq!(find_stage_challenge_key(&conn, first), Some(vec![7u8; 32]));
    assert_eq!(find_stage_challenge_key(&conn, second), Some(vec![8u8; 32]));
    assert_eq!(find_stage_challenge_key(&conn, "550e8400-e29b-41d4-a716-446655440002"), None);
}

#[test]
fn stage_auth_accepts_only_fresh_matching_build_hmac() {
    let key = [9u8; 32];
    let id = "550e8400-e29b-41d4-a716-446655440000";
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let valid = stage_hmac(&key, id, &timestamp);

    assert!(verify_stage_auth(&key, id, &timestamp, &valid));
    let mut tampered = valid.clone();
    let replacement = if tampered.starts_with('A') { 'B' } else { 'A' };
    tampered.replace_range(0..1, &replacement.to_string());
    assert!(!verify_stage_auth(&key, id, &timestamp, &tampered));
    assert!(!verify_stage_auth(&key, id, &(chrono::Utc::now().timestamp() - 301).to_string(), &valid));

    let other_id = "550e8400-e29b-41d4-a716-446655440001";
    let other_hmac = stage_hmac(&key, other_id, &timestamp);
    assert!(!verify_stage_auth(&key, id, &timestamp, &other_hmac));

    let pool = stage_db();
    let conn = pool.get().unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-stage-timestamp", timestamp.parse().unwrap());
    headers.insert("x-stage-hmac", valid.parse().unwrap());
    assert!(stage_request_authorized(&conn, &key, id, &headers));
}

#[test]
fn stage_api_key_auth_accepts_session_or_primary_operator_key_only() {
    let pool = stage_db();
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "CREATE TABLE operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
         );
         CREATE TABLE operator_sessions (
            operator_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
         );"
    ).unwrap();

    let primary_key = "stage-primary-key";
    let operator_id = rcm::database::create_operator(
        &conn, "operator", "hash", "operator", primary_key,
    ).unwrap();
    let session_key = rcm::database::create_operator_session(&conn, operator_id).unwrap();

    assert!(verify_stage_api_key(&conn, primary_key));
    assert!(verify_stage_api_key(&conn, &session_key));
    assert!(!verify_stage_api_key(&conn, "not-an-operator-key"));
    assert!(!verify_stage_api_key(&conn, ""));

    let build_id = "550e8400-e29b-41d4-a716-446655440000";
    let challenge_key = [7u8; 32];
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-api-key", primary_key.parse().unwrap());
    assert!(stage_request_authorized(&conn, &challenge_key, build_id, &headers));

    headers.insert("x-api-key", "not-an-operator-key".parse().unwrap());
    assert!(!stage_request_authorized(&conn, &challenge_key, build_id, &headers));
}

#[test]
fn stage_rate_limit_allows_burst_then_rejects_same_ip() {
    let sessions = Arc::new(DashMap::new());
    let state = HttpC2State::new(
        sessions,
        stage_db(),
        Arc::new(Mutex::new(HashMap::new())),
    );
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    for _ in 0..10 {
        assert!(check_stage_rate_limit(&state, ip));
    }
    assert!(!check_stage_rate_limit(&state, ip));

    let other_ip: IpAddr = "127.0.0.2".parse().unwrap();
    assert!(check_stage_rate_limit(&state, other_ip));
}

#[test]
fn https_listener_rejects_invalid_certificate_material_eagerly() {
    assert!(http_tls_acceptor(b"not a certificate", b"not a key").is_err());
    assert!(http_tls_acceptor(b"", b"").is_err());
}

#[test]
fn http_profile_body_transform_round_trips_in_configured_order() {
    let steps = vec![
        TransformStep::Prepend("pre:".into()),
        TransformStep::Base64,
        TransformStep::Append(":post".into()),
    ];
    let plaintext = b"payload body";
    let transformed = apply_profile_body_transform(plaintext, &steps);
    assert_eq!(reverse_profile_body_transform(&transformed, &steps).unwrap(), plaintext);
    assert!(reverse_profile_body_transform(b"wrong:post", &steps).is_err());
}

#[test]
fn http_post_classification_tries_pivot_frame_before_command_response() {
    let frame = PivotFrame {
        stream_id: 7,
        destination: 0,
        source: 42,
        data: b"upstream".to_vec(),
        metadata: String::new(),
    };
    let body = serde_json::to_vec(&frame).unwrap();
    match parse_http_outbound(&body).unwrap() {
        HttpOutboundItem::Pivot(parsed) => assert_eq!(parsed.source, 42),
        HttpOutboundItem::Result(_) => panic!("pivot frame classified as command response"),
    }
}

#[test]
fn http_poll_drain_mixes_commands_and_downstream_pivot_frames_in_wire_shape() {
    let sessions = Arc::new(DashMap::new());
    let state = HttpC2State::new(sessions, stage_db(), Arc::new(Mutex::new(HashMap::new())));
    let command = SecuredCommand {
        session_id: "sess".into(),
        counter: 9,
        nonce: 1,
        timestamp: chrono::Utc::now(),
        command: "whoami".into(),
        signature: "sig".into(),
    };
    let frame = PivotFrame {
        stream_id: 0,
        destination: 42,
        source: 0,
        data: b"downstream".to_vec(),
        metadata: String::new(),
    };
    {
        let mut inner = state.inner.lock().unwrap();
        inner.cmd_queues.entry(5).or_default().push_back(command);
        inner.pivot_queues.entry(5).or_default().push_back(frame);
    }

    let items = drain_poll_items(&state, 5);
    assert_eq!(items.len(), 2);
    assert!(items[0][0].is_string(), "SecuredCommand seq starts with session_id string");
    assert!(items[1][0].is_number(), "PivotFrame seq starts with stream_id number");
    assert_eq!(items[1][1], serde_json::json!(42));
    assert!(state.inner.lock().unwrap().cmd_queues.get(&5).unwrap().is_empty());
    assert!(state.inner.lock().unwrap().pivot_queues.get(&5).unwrap().is_empty());
}

#[test]
fn c2_hints_parse_dedup_sort_and_skip_unusable_sources() {
    let openssl_text = r#"
X509v3 Subject Alternative Name:
    DNS:c2.example, IP Address:203.0.113.10, IP Address:198.51.100.2
X509v3 Extended Key Usage:
    TLS Web Server Authentication
"#;
    assert_eq!(
        parse_ipv4_sans_from_openssl_text(openssl_text),
        vec!["203.0.113.10".parse::<std::net::Ipv4Addr>().unwrap(), "198.51.100.2".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    let interfaces = vec![
        "127.0.0.1/8".to_string(),
        "10.0.0.5/24".to_string(),
        "203.0.113.10/24".to_string(),
        "fe80::1/64".to_string(),
    ];
    assert_eq!(
        collect_c2_hints(openssl_text, &interfaces, "192.0.2.20"),
        vec!["10.0.0.5", "192.0.2.20", "198.51.100.2", "203.0.113.10"]
    );
    assert_eq!(
        collect_c2_hints("", &interfaces, "0.0.0.0"),
        vec!["10.0.0.5", "203.0.113.10"]
    );
}
