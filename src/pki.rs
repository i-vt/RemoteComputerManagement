use tokio_rustls::rustls;
use std::io::BufReader;
use std::sync::Arc;

pub fn create_client_config(
    ca_bytes: &[u8], 
    client_cert_bytes: &[u8], 
    client_key_bytes: &[u8]
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    
    let mut root_store = rustls::RootCertStore::empty();
    let mut ca_reader = BufReader::new(ca_bytes);
    for cert in rustls_pemfile::certs(&mut ca_reader)? {
        root_store.add(&rustls::Certificate(cert))?;
    }

    let mut cert_reader = BufReader::new(client_cert_bytes);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter().map(rustls::Certificate).collect();
    
    let key = rustls::PrivateKey(client_key_bytes.to_vec());

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    Ok(config)
}

pub fn create_server_config(
    server_cert: &[u8],
    server_key: &[u8],
    ca_cert: &[u8]
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(server_cert))?
        .into_iter().map(rustls::Certificate).collect();
    let key = rustls::PrivateKey(server_key.to_vec());
    
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(ca_cert))? { 
        roots.add(&rustls::Certificate(cert))?; 
    }
    
    let verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(certs, key)?;

    Ok(config)
}
