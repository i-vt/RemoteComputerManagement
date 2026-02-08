use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::net::Ipv4Addr;

pub async fn handle_socks5_stream<T>(mut stream: T) -> Result<(), Box<dyn std::error::Error>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // 1. Handshake
    let mut header = [0u8; 2];
    if stream.read_exact(&mut header).await.is_err() { return Err("Read error".into()); }
    
    if header[0] != 0x05 { return Err("Not SOCKS5".into()); }

    let n_methods = header[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    // Respond: OK (No Auth)
    stream.write_all(&[0x05, 0x00]).await?;

    // 2. Request
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;

    let cmd = req_header[1];
    let atyp = req_header[3];

    if cmd != 0x01 { // 0x01 = CONNECT
        return Err("Unsupported SOCKS command".into());
    }

    let addr_str = match atyp {
        0x01 => { // IPv4
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::from(buf);
            ip.to_string()
        }
        0x03 => { // Domain Name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            String::from_utf8_lossy(&buf).to_string()
        }
        _ => return Err("Unsupported Address Type".into()),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    let target_addr = format!("{}:{}", addr_str, port);
    
    // [DEBUG LOG] - Prints to Client Console
    eprintln!("[SOCKS] Attempting connection to: {}", target_addr);

    // 3. Connect to Target
    match TcpStream::connect(&target_addr).await {
        // [FIXED] Removed 'mut' here
        Ok(target_socket) => {
            eprintln!("[SOCKS] Connected to {}", target_addr);
            // Send Success (0x00)
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

            // 4. Pipe Data
            let (mut ri, mut wi) = tokio::io::split(stream);
            let (mut ro, mut wo) = tokio::io::split(target_socket);

            let _ = tokio::try_join!(
                tokio::io::copy(&mut ri, &mut wo),
                tokio::io::copy(&mut ro, &mut wi)
            );
        }
        Err(e) => {
            eprintln!("[SOCKS] Connection Failed to {}: {}", target_addr, e);
            // Send Host Unreachable (0x04)
            let _ = stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(Box::new(e));
        }
    }

    Ok(())
}
