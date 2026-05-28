use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use rustls::ServerConnection;

/// Unified transport layer: either a plain TCP socket or a TLS-wrapped socket.
///
/// Both variants implement `Read + Write` so that `tungstenite::WebSocket<Transport>`
/// works for WebSocket-over-TCP and WebSocket-over-TLS with no extra boxing.
pub enum Transport {
    Plain(TcpStream),
    Tls(rustls::StreamOwned<ServerConnection, TcpStream>),
}

impl Transport {
    /// Wrap a plain TCP stream.
    pub fn plain(stream: TcpStream) -> Self {
        Transport::Plain(stream)
    }

    /// Perform a TLS server handshake and return a TLS transport.
    pub fn tls(stream: TcpStream, tls_cfg: Arc<rustls::ServerConfig>) -> io::Result<Self> {
        let conn = ServerConnection::new(tls_cfg)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Transport::Tls(rustls::StreamOwned::new(conn, stream)))
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Transport::Plain(s) => s.peer_addr().ok(),
            Transport::Tls(s)   => s.get_ref().peer_addr().ok(),
        }
    }

    /// Set the read/write timeout on the underlying TCP socket.
    pub fn set_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        let tcp = match self {
            Transport::Plain(s) => s,
            Transport::Tls(s)   => s.get_ref(),
        };
        tcp.set_read_timeout(dur)?;
        tcp.set_write_timeout(dur)?;
        Ok(())
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s)   => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s)   => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s)   => s.flush(),
        }
    }
}
