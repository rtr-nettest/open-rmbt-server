/// Transport-level I/O: plain TCP or TLS-wrapped TCP.
///
/// Both variants implement `Read + Write` so they can be passed directly to
/// `tungstenite::WebSocket` for WebSocket framing, or used as-is for raw RMBT.
mod transport;
mod websocket_upgrade;

pub use transport::Transport;
pub use websocket_upgrade::detect_and_upgrade;

use std::io::{self, BufRead, BufReader, Read, Write};
use tungstenite::{Message, WebSocket};

// ─── Stream ──────────────────────────────────────────────────────────────────

/// A connection as seen by protocol handlers.
///
/// After the HTTP-upgrade phase the raw TCP/TLS transport is optionally
/// promoted to a WebSocket.  Protocol logic only calls the methods below and
/// never touches the transport directly.
pub enum Stream {
    /// Plain TCP or TLS — RMBT lines sent as raw bytes.
    Raw(BufReader<Transport>),
    /// WebSocket over TCP or TLS — RMBT lines sent as text/binary frames.
    WebSocket(WebSocket<Transport>),
}

impl Stream {
    /// Read one newline-terminated protocol line (newline is stripped).
    /// Returns an error on EOF or if the line exceeds `MAX_LINE_LENGTH`.
    pub fn read_line(&mut self) -> io::Result<String> {
        use crate::config::constants::MAX_LINE_LENGTH;
        match self {
            Stream::Raw(br) => {
                let mut line = String::new();
                let n = br.read_line(&mut line)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
                }
                if line.len() > MAX_LINE_LENGTH {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                // strip trailing \n and \r\n
                if line.ends_with('\n') { line.pop(); }
                if line.ends_with('\r') { line.pop(); }
                Ok(line)
            }
            Stream::WebSocket(ws) => {
                // WebSocket frames arrive complete; keep reading until we get a
                // text or binary frame (skip control frames like Ping/Pong).
                loop {
                    match ws.read() {
                        Ok(Message::Text(t))   => return Ok(t.trim_end_matches('\n').trim_end_matches('\r').to_string()),
                        Ok(Message::Binary(b)) => {
                            let mut s = String::from_utf8_lossy(&b).into_owned();
                            if s.ends_with('\n') { s.pop(); }
                            if s.ends_with('\r') { s.pop(); }
                            return Ok(s);
                        }
                        Ok(Message::Close(_))  => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "ws close")),
                        Ok(_)                  => continue, // ping/pong/continuation
                        Err(tungstenite::Error::Io(e)) => return Err(e),
                        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
                    }
                }
            }
        }
    }

    /// Write all bytes; for WebSocket, uses Binary framing for chunk data and
    /// Text framing for short protocol lines — matching the C reference's logic
    /// (Binary if len < 2 or len > CHUNK_SIZE-3, else Text).
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        use crate::config::constants::CHUNK_SIZE;
        match self {
            Stream::Raw(br) => br.get_mut().write_all(data),
            Stream::WebSocket(ws) => {
                let msg = if data.len() < 2 || data.len() > CHUNK_SIZE - 3 {
                    Message::Binary(data.to_vec().into())
                } else {
                    Message::Text(String::from_utf8_lossy(data).to_string().into())
                };
                ws.send(msg).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                ws.flush().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            }
        }
    }

    /// Write a UTF-8 string (protocol line).
    #[inline]
    pub fn write_line(&mut self, s: &str) -> io::Result<()> {
        self.write_all(s.as_bytes())
    }

    /// Read exactly `buf.len()` bytes from the underlying transport.
    /// For WebSocket this reassembles frames until the buffer is full.
    pub fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Stream::Raw(br) => br.read_exact(buf),
            Stream::WebSocket(ws) => {
                let mut filled = 0;
                while filled < buf.len() {
                    match ws.read() {
                        Ok(Message::Binary(b)) => {
                            let n = b.len().min(buf.len() - filled);
                            buf[filled..filled + n].copy_from_slice(&b[..n]);
                            filled += n;
                        }
                        Ok(Message::Text(t)) => {
                            let b = t.as_bytes();
                            let n = b.len().min(buf.len() - filled);
                            buf[filled..filled + n].copy_from_slice(&b[..n]);
                            filled += n;
                        }
                        Ok(Message::Close(_)) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "ws close")),
                        Ok(_) => continue,
                        Err(tungstenite::Error::Io(e)) => return Err(e),
                        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
                    }
                }
                Ok(())
            }
        }
    }

    /// Non-exact read — returns however many bytes arrived.
    /// Used for upload (PUT/PUTNORESULT) where the caller accumulates.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Raw(br) => br.read(buf),
            Stream::WebSocket(ws) => {
                loop {
                    match ws.read() {
                        Ok(Message::Binary(b)) => {
                            let n = b.len().min(buf.len());
                            buf[..n].copy_from_slice(&b[..n]);
                            return Ok(n);
                        }
                        Ok(Message::Text(t)) => {
                            let bytes = t.as_bytes();
                            let n = bytes.len().min(buf.len());
                            buf[..n].copy_from_slice(&bytes[..n]);
                            return Ok(n);
                        }
                        Ok(Message::Close(_)) => return Ok(0),
                        Ok(_) => continue,
                        Err(tungstenite::Error::Io(e)) => return Err(e),
                        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
                    }
                }
            }
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Stream::Raw(_)       => "raw",
            Stream::WebSocket(_) => "websocket",
        }
    }

    /// Peer address, if available.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        let transport = match self {
            Stream::Raw(br)       => br.get_ref(),
            Stream::WebSocket(ws) => ws.get_ref(),
        };
        transport.peer_addr()
    }
}
