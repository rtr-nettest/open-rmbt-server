use std::io::{self, BufReader, Read, Write};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha1::{Sha1, Digest};
use tungstenite::WebSocket;
use log::debug;

use super::{Stream, Transport};

// HTTP 101 response for plain RMBT-over-HTTP upgrade (no WebSocket framing).
const RMBT_UPGRADE_RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: RMBT\r\n\r\n";

// RFC 6455 §1.3 magic suffix appended to Sec-WebSocket-Key before SHA-1.
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Detect the HTTP upgrade type, complete the handshake, and return a `Stream`.
///
/// Called for every new connection when the server operates in HTTP/WebSocket
/// mode (always, matching the C reference's `-w` behaviour which is now the
/// default).
pub fn detect_and_upgrade(mut transport: Transport) -> io::Result<Stream> {
    // Read until the blank line that ends the HTTP request headers.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1];
    loop {
        transport.read_exact(&mut tmp)?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP request too large"));
        }
    }

    let req = String::from_utf8_lossy(&buf);

    if !req.starts_with("GET ") {
        debug!("unexpected HTTP method; request:\n{}", req.trim_end());
        let _ = transport.write_all(
            b"HTTP/1.1 405 Method Not Allowed\r\n\
              Connection: close\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );
        let _ = transport.flush();
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected HTTP GET"));
    }

    let req_lower = req.to_ascii_lowercase();

    if req_lower.contains("upgrade: websocket") {
        websocket_handshake(transport, &req)
    } else if req_lower.contains("upgrade: rmbt") {
        // Plain RMBT: acknowledge the upgrade and continue without WS framing.
        transport.write_all(RMBT_UPGRADE_RESPONSE)?;
        Ok(Stream::Raw(BufReader::new(transport)))
    } else {
        debug!("no recognized Upgrade header; request:\n{}", req.trim_end());
        // Browser or health-check request with no Upgrade header.
        // Send 426 so the client gets a clean HTTP response instead of a
        // dangling TLS connection, then close.
        let version = crate::config::constants::GREETING.trim(); // "RMBTv1.3.5"
        let body    = format!("RMBT measurement server - {version}");
        let resp    = format!(
            "HTTP/1.1 426 Upgrade Required\r\n\
             Connection: close\r\n\
             Upgrade: RMBT, websocket\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            body.len(),
            body,
        );
        let _ = transport.write_all(resp.as_bytes());
        let _ = transport.flush();
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no recognized Upgrade header (need 'websocket' or 'rmbt')",
        ))
    }
}

/// Complete the RFC 6455 WebSocket opening handshake.
///
/// We implement the handshake directly (parse Sec-WebSocket-Key, compute
/// Sec-WebSocket-Accept via SHA-1, send the HTTP 101 response) rather than
/// using tungstenite's `accept()` so that we control when we read vs. write
/// and can reuse the transport we already hold.
fn websocket_handshake(mut transport: Transport, request: &str) -> io::Result<Stream> {
    // Extract the Sec-WebSocket-Key header value (case-insensitive search).
    let key = request
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("sec-websocket-key:") {
                Some(line[lower.find(':').unwrap() + 1..].trim().to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Sec-WebSocket-Key"))?;

    // Compute Sec-WebSocket-Accept = base64(SHA1(key + WS_GUID)).
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID);
    let accept = B64.encode(hasher.finalize());

    // Send the HTTP 101 Switching Protocols response.
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         \r\n"
    );
    transport.write_all(response.as_bytes())?;
    transport.flush()?;

    // Promote the transport to a WebSocket stream using tungstenite for framing.
    // Role::Server means tungstenite expects masked frames from clients and sends
    // unmasked frames to clients (RFC 6455 §5.1).
    let ws = WebSocket::from_raw_socket(transport, tungstenite::protocol::Role::Server, None);
    Ok(Stream::WebSocket(ws))
}
