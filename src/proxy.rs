use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{anyhow, bail};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::pki_types::ServerName;

use crate::config::constants::SOCKET_TIMEOUT_SECS;
use crate::stream::{Transport, read_http_head};

/// Upper bound for establishing the TCP connection to the upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Request headers that are not forwarded verbatim: hop-by-hop headers and
/// headers the proxy sets itself.  `X-Real-IP` in particular must never be
/// taken from the client, the control server trusts it as the client address.
const DROPPED_REQUEST_HEADERS: &[&str] = &[
    "host", "connection", "proxy-connection", "keep-alive", "te", "upgrade",
    "expect", "x-real-ip", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
];

/// Response headers replaced by the proxy: it always closes the connection,
/// and HSTS policy for this host is governed by `--hsts`, not by the upstream
/// (whose header may carry e.g. `includeSubDomains` for its own domain).
const DROPPED_RESPONSE_HEADERS: &[&str] = &[
    "connection", "proxy-connection", "keep-alive", "strict-transport-security",
];

/// Reverse proxy for all requests whose path starts with a configured prefix
/// (e.g. `/RMBTControlServer`), forwarding them to an HTTP or HTTPS upstream.
///
/// Each proxied connection carries exactly one request: the upstream request
/// is sent with `Connection: close` and the client connection is closed after
/// the response, so no keep-alive bookkeeping is needed.
pub struct Proxy {
    /// Path prefix with a leading slash and no trailing slash.
    prefix:    String,
    host:      String,
    port:      u16,
    /// Authority as given in the destination URL, sent as `Host` header.
    authority: String,
    /// Optional path of the destination URL, prepended to the request target.
    base_path: String,
    tls:       Option<(Arc<ClientConfig>, ServerName<'static>)>,
}

/// Parsed client request head.
struct Request<'a> {
    method:          &'a str,
    target:          &'a str,
    headers:         String,
    content_length:  u64,
    chunked:         bool,
    expect_continue: bool,
    host:            Option<&'a str>,
}

impl Proxy {
    /// Build a proxy from `path` (e.g. `RMBTControlServer`) and `destination`
    /// (e.g. `https://c01.netztest.at`).  A destination without a scheme is
    /// treated as `https://`.
    pub fn new(path: &str, destination: &str) -> anyhow::Result<Self> {
        let prefix = format!("/{}", path.trim().trim_matches('/'));
        if prefix == "/" {
            bail!("proxy path must not be empty");
        }

        let dest = destination.trim();
        let (is_tls, rest) = if let Some(r) = dest.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = dest.strip_prefix("http://") {
            (false, r)
        } else if dest.contains("://") {
            bail!("unsupported scheme in proxy destination '{dest}'");
        } else {
            (true, dest)
        };

        let (authority, base_path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None    => (rest, ""),
        };
        let (host, port) = split_host_port(authority, if is_tls { 443 } else { 80 })?;

        let tls = if is_tls {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = ServerName::try_from(host.clone())
                .map_err(|e| anyhow!("invalid TLS server name '{host}': {e}"))?;
            Some((Arc::new(cfg), name))
        } else {
            None
        };

        Ok(Self {
            prefix,
            host,
            port,
            authority: authority.to_string(),
            base_path: base_path.to_string(),
            tls,
        })
    }

    /// Human-readable mapping for startup logs.
    pub fn describe(&self) -> String {
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        format!("{}/* -> {scheme}://{}{}", self.prefix, self.authority, self.base_path)
    }

    /// True if the request target falls under the proxied path prefix.
    pub fn matches(&self, target: &str) -> bool {
        target
            .strip_prefix(self.prefix.as_str())
            .is_some_and(|r| r.is_empty() || r.starts_with('/') || r.starts_with('?'))
    }

    /// Forward one request, whose header block `head` has already been read
    /// from `client`, and relay the upstream response.  Returns a short
    /// summary (`METHOD target -> status`) for logging.
    ///
    /// Upstream failures before any response byte was sent are answered with
    /// `502 Bad Gateway`; later failures just abort the connection.
    ///
    /// `hsts` is the HSTS header line to add to responses (empty when disabled);
    /// any HSTS header from the upstream is dropped.
    pub fn handle(&self, client: &mut Transport, head: &str, hsts: &str) -> io::Result<String> {
        let req = parse_request(head)?;

        if req.chunked {
            // RMBT clients always send Content-Length; supporting chunked
            // uploads would require de-chunking the body on the fly.
            send_status(client, "411 Length Required", hsts)?;
            return Ok(format!("{} {} -> 411 (chunked request body)", req.method, req.target));
        }

        let mut started = false;
        let result = self.connect().and_then(|tcp| match &self.tls {
            Some((cfg, name)) => {
                let conn = ClientConnection::new(cfg.clone(), name.clone())
                    .map_err(io::Error::other)?;
                self.exchange(client, StreamOwned::new(conn, tcp), &req, hsts, &mut started)
            }
            None => self.exchange(client, tcp, &req, hsts, &mut started),
        });

        match result {
            Ok(status) => Ok(format!("{} {} -> {status}", req.method, req.target)),
            Err(e) if !started => {
                send_status(client, "502 Bad Gateway", hsts)?;
                Ok(format!("{} {} -> 502 ({e})", req.method, req.target))
            }
            Err(e) => Err(e),
        }
    }

    /// Open a TCP connection to the upstream, trying every resolved address.
    fn connect(&self) -> io::Result<TcpStream> {
        let mut last_err = None;
        for addr in (self.host.as_str(), self.port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(tcp) => {
                    let timeout = Some(Duration::from_secs(SOCKET_TIMEOUT_SECS));
                    tcp.set_read_timeout(timeout)?;
                    tcp.set_write_timeout(timeout)?;
                    let _ = tcp.set_nodelay(true);
                    return Ok(tcp);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::new(
            io::ErrorKind::NotFound,
            format!("no address found for '{}'", self.host),
        )))
    }

    /// Send the request to `upstream` and relay the response to `client`.
    /// Returns the upstream status code.  `started` is set once the first
    /// response byte was written to the client.
    fn exchange<U: Read + Write>(
        &self,
        client: &mut Transport,
        mut upstream: U,
        req: &Request,
        hsts: &str,
        started: &mut bool,
    ) -> io::Result<u16> {
        // ── Request head ──────────────────────────────────────────────────────
        let mut out = format!(
            "{} {}{} HTTP/1.1\r\nHost: {}\r\n{}",
            req.method, self.base_path, req.target, self.authority, req.headers,
        );
        if let Some(ip) = client.peer_addr().map(|a| a.ip()) {
            out.push_str(&format!("X-Real-IP: {ip}\r\nX-Forwarded-For: {ip}\r\n"));
        }
        let proto = if matches!(client, Transport::Tls(_)) { "https" } else { "http" };
        out.push_str(&format!("X-Forwarded-Proto: {proto}\r\n"));
        if let Some(host) = req.host {
            out.push_str(&format!("X-Forwarded-Host: {host}\r\n"));
        }
        out.push_str("Connection: close\r\n\r\n");
        upstream.write_all(out.as_bytes())?;

        // ── Request body ──────────────────────────────────────────────────────
        if req.content_length > 0 {
            if req.expect_continue {
                client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                client.flush()?;
            }
            let copied = io::copy(&mut Read::take(&mut *client, req.content_length), &mut upstream)?;
            if copied != req.content_length {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body truncated"));
            }
        }
        upstream.flush()?;

        // ── Response head ─────────────────────────────────────────────────────
        let head = read_http_head(&mut upstream)?;
        let head = String::from_utf8_lossy(&head);
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let status: u16 = status_line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad upstream status line"))?;

        let mut resp = format!("{status_line}\r\n");
        let mut content_length = None;
        let mut chunked = false;
        for line in lines.filter(|l| !l.is_empty()) {
            let Some((name, value)) = line.split_once(':') else { continue };
            let name = name.trim().to_ascii_lowercase();
            match name.as_str() {
                "content-length"    => content_length = value.trim().parse::<u64>().ok(),
                "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
                _ => {}
            }
            if !DROPPED_RESPONSE_HEADERS.contains(&name.as_str()) {
                resp.push_str(line);
                resp.push_str("\r\n");
            }
        }
        resp.push_str(hsts);
        resp.push_str("Connection: close\r\n\r\n");

        // ── Response body ─────────────────────────────────────────────────────
        let no_body = req.method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&status) || status == 204 || status == 304;
        let body_len = if no_body { Some(0) } else if chunked { None } else { content_length };

        *started = true;
        client.write_all(resp.as_bytes())?;
        match body_len {
            Some(n) => { io::copy(&mut upstream.take(n), client)?; }
            // Close-delimited or chunked body: relay until upstream EOF.
            // rustls reports a missing close_notify as UnexpectedEof, which
            // many servers omit, so treat it as a regular end of stream.
            None => match io::copy(&mut upstream, client) {
                Err(e) if e.kind() != io::ErrorKind::UnexpectedEof => return Err(e),
                _ => {}
            },
        }
        client.flush()?;
        Ok(status)
    }
}

fn parse_request(head: &str) -> io::Result<Request<'_>> {
    let invalid = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_string());

    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let method = parts.next().filter(|m| !m.is_empty()).ok_or_else(|| invalid("missing method"))?;
    let target = parts.next().filter(|t| t.starts_with('/')).ok_or_else(|| invalid("bad request target"))?;

    let mut req = Request {
        method,
        target,
        headers:         String::new(),
        content_length:  0,
        chunked:         false,
        expect_continue: false,
        host:            None,
    };

    for line in lines.filter(|l| !l.is_empty()) {
        let Some((name, value)) = line.split_once(':') else { continue };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length"    => req.content_length = value.parse().map_err(|_| invalid("bad Content-Length"))?,
            "transfer-encoding" => req.chunked = value.to_ascii_lowercase().contains("chunked"),
            "expect"            => req.expect_continue = value.eq_ignore_ascii_case("100-continue"),
            "host"              => req.host = Some(value),
            _ => {}
        }
        if !DROPPED_REQUEST_HEADERS.contains(&name.as_str()) {
            req.headers.push_str(line);
            req.headers.push_str("\r\n");
        }
    }
    Ok(req)
}

/// Send an empty-bodied response with the given status (e.g. `502 Bad Gateway`).
fn send_status(client: &mut Transport, status: &str, hsts: &str) -> io::Result<()> {
    client.write_all(format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\n{hsts}Content-Length: 0\r\n\r\n"
    ).as_bytes())?;
    client.flush()
}

/// Split `host[:port]` or `[ipv6][:port]` into host and port.
fn split_host_port(authority: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    let bad_port = || anyhow!("invalid port in proxy destination '{authority}'");
    if authority.is_empty() {
        bail!("missing host in proxy destination");
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid IPv6 host in proxy destination '{authority}'"))?;
        let port = match after.strip_prefix(':') {
            Some(p)                 => p.parse().map_err(|_| bad_port())?,
            None if after.is_empty() => default_port,
            None                    => return Err(bad_port()),
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, p)) => Ok((host.to_string(), p.parse().map_err(|_| bad_port())?)),
        None            => Ok((authority.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_destination() {
        let p = Proxy::new("RMBTControlServer", "https://c01.netztest.at").unwrap();
        assert_eq!((p.host.as_str(), p.port, p.base_path.as_str()), ("c01.netztest.at", 443, ""));
        assert!(p.tls.is_some());

        let p = Proxy::new("/x/", "http://[::1]:8080/base/").unwrap();
        assert_eq!((p.host.as_str(), p.port, p.base_path.as_str()), ("::1", 8080, "/base"));
        assert_eq!(p.authority, "[::1]:8080");
        assert!(p.tls.is_none());

        let p = Proxy::new("x", "c01.netztest.at:8443").unwrap();
        assert_eq!((p.port, p.tls.is_some()), (8443, true));

        assert!(Proxy::new("", "http://a").is_err());
        assert!(Proxy::new("x", "ftp://a").is_err());
        assert!(Proxy::new("x", "http://a:port").is_err());
    }

    #[test]
    fn matches_prefix() {
        let p = Proxy::new("RMBTControlServer", "http://127.0.0.1").unwrap();
        assert!(p.matches("/RMBTControlServer"));
        assert!(p.matches("/RMBTControlServer/settings"));
        assert!(p.matches("/RMBTControlServer?x=1"));
        assert!(!p.matches("/RMBTControlServerX"));
        assert!(!p.matches("/rmbt"));
    }

    #[test]
    fn filters_request_headers() {
        let head = "POST /RMBTControlServer/settings HTTP/1.1\r\nHost: m.example\r\n\
                    Content-Type: application/json\r\nContent-Length: 12\r\n\
                    X-Real-IP: 6.6.6.6\r\nConnection: keep-alive\r\n\r\n";
        let req = parse_request(head).unwrap();
        assert_eq!((req.method, req.target, req.content_length), ("POST", "/RMBTControlServer/settings", 12));
        assert_eq!(req.host, Some("m.example"));
        assert_eq!(req.headers, "Content-Type: application/json\r\nContent-Length: 12\r\n");
    }
}
