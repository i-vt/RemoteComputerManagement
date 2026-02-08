// src/traffic.rs
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::common::{MalleableProfile, TransformStep, HttpBlock};
use std::io;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::seq::SliceRandom;

pub struct DataMolder;

impl DataMolder {
    /// Applies transformations defined in the profile (Outbound)
    fn apply_transform(data: &[u8], steps: &[TransformStep]) -> Vec<u8> {
        let mut buffer = data.to_vec();
        for step in steps {
            match step {
                TransformStep::Base64 => {
                    let b64 = BASE64.encode(&buffer);
                    buffer = b64.into_bytes();
                },
                TransformStep::Hex => {
                    let hex = hex::encode(&buffer);
                    buffer = hex.into_bytes();
                },
                TransformStep::Mask => {
                    // Simple XOR for obfuscation (not security)
                    // In a real malleable C2, the key is usually random and prepended.
                    // For simplicity, we use a static mask or 0x55
                    for byte in &mut buffer { *byte ^= 0x55; }
                },
                TransformStep::Prepend(s) => {
                    let mut new_buf = s.as_bytes().to_vec();
                    new_buf.extend_from_slice(&buffer);
                    buffer = new_buf;
                },
                TransformStep::Append(s) => {
                    buffer.extend_from_slice(s.as_bytes());
                }
            }
        }
        buffer
    }

    /// Reverses transformations (Inbound)
    fn reverse_transform(data: &[u8], steps: &[TransformStep]) -> io::Result<Vec<u8>> {
        let mut buffer = data.to_vec();
        // Reverse order of operations
        for step in steps.iter().rev() {
            match step {
                TransformStep::Base64 => {
                    // Strip whitespace/newlines usually found in HTTP bodies before decoding
                    let clean: Vec<u8> = buffer.into_iter().filter(|b| !b.is_ascii_whitespace()).collect();
                    buffer = BASE64.decode(&clean).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                },
                TransformStep::Hex => {
                    buffer = hex::decode(&buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                },
                TransformStep::Mask => {
                    for byte in &mut buffer { *byte ^= 0x55; }
                },
                TransformStep::Prepend(s) => {
                    let p_bytes = s.as_bytes();
                    if buffer.starts_with(p_bytes) {
                        buffer = buffer[p_bytes.len()..].to_vec();
                    } else {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Prepend Mismatch"));
                    }
                },
                TransformStep::Append(s) => {
                    let a_bytes = s.as_bytes();
                    if buffer.ends_with(a_bytes) {
                        buffer = buffer[..buffer.len() - a_bytes.len()].to_vec();
                    } else {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Append Mismatch"));
                    }
                }
            }
        }
        Ok(buffer)
    }

    /// Construct HTTP Request Wrapper
    fn build_http_frame(method: &str, block: &HttpBlock, user_agent: &str, body_data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let uri = block.uris.choose(&mut rng).unwrap_or(&block.uris[0]); // Randomize URI
        
        let mut headers = String::new();
        headers.push_str(&format!("{} {} HTTP/1.1\r\n", method, uri));
        headers.push_str(&format!("User-Agent: {}\r\n", user_agent));
        
        // Add custom headers from profile
        for (k, v) in &block.headers {
            headers.push_str(&format!("{}: {}\r\n", k, v));
        }

        // Auto-calc content length if not sending empty
        if !body_data.is_empty() {
            headers.push_str(&format!("Content-Length: {}\r\n", body_data.len()));
        }
        
        headers.push_str("\r\n"); // End of headers

        let mut frame = headers.into_bytes();
        frame.extend_from_slice(body_data);
        frame
    }

    // --- PUBLIC API ---

    pub async fn send<W>(writer: &mut W, data: &[u8], profile: &MalleableProfile) -> io::Result<()>
    where W: AsyncWrite + Unpin {
        if !profile.format_http {
            // Default RAW Mode (Length Prefixed)
            writer.write_u32(data.len() as u32).await?;
            writer.write_all(data).await?;
            writer.flush().await?;
            return Ok(());
        }

        // Malleable Mode (HTTP POST usually for data sending)
        let transformed = Self::apply_transform(data, &profile.http_post.data_transform);
        let frame = Self::build_http_frame("POST", &profile.http_post, &profile.user_agent, &transformed);
        
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(())
    }

    pub async fn recv<R>(reader: &mut R, profile: &MalleableProfile) -> io::Result<Vec<u8>>
    where R: AsyncRead + Unpin {
        if !profile.format_http {
            // Default RAW Mode
            let len = reader.read_u32().await? as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            return Ok(buf);
        }

        // Malleable Mode
        // 1. Read Headers (Naive implementation: read until \r\n\r\n)
        let mut header_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte).await?;
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") { break; }
            if header_buf.len() > 8192 { return Err(io::Error::new(io::ErrorKind::InvalidData, "Header Too Large")); }
        }

        let header_str = String::from_utf8_lossy(&header_buf);
        
        // 2. Determine Content-Length
        let content_len = header_str.lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);

        if content_len == 0 { return Ok(vec![]); }

        // 3. Read Body
        let mut body = vec![0u8; content_len];
        reader.read_exact(&mut body).await?;

        // 4. Reverse Transformation
        // Note: For 'recv', we assume the incoming data matches the 'http_post' config 
        // if we act as server, or 'http_get' output if we act as client. 
        // For simplicity in this unidirectional example, we use http_post logic.
        Self::reverse_transform(&body, &profile.http_post.data_transform)
    }

    // Used for initial handshake detection
    pub async fn detect_and_recv<R>(reader: &mut R) -> io::Result<(Vec<u8>, MalleableProfile)>
    where R: AsyncRead + Unpin {
        // In Malleable C2, "detection" is harder because traffic looks legit.
        // We usually rely on the Build ID or a specific header value.
        // For MVP, we fall back to assuming Default Profile for the handshake
        // or trying to parse standard raw length.
        
        let mut prefix = [0u8; 4];
        reader.read_exact(&mut prefix).await?;

        // Simple heuristic: If it looks like HTTP, buffer it.
        if &prefix == b"POST" || &prefix == b"GET " || &prefix == b"HTTP" {
             return Err(io::Error::new(io::ErrorKind::Other, "Dynamic Profile Detection Not Implemented in Handshake - Use compiled profile"));
        }

        // Assume Raw
        let len = u32::from_be_bytes(prefix) as usize;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        Ok((buf, MalleableProfile::default())) 
    }
}
