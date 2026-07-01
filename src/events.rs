//! Structured per-connection event logging to a remote collector over UDP syslog
//! (RFC 5424), for ingestion into ELK.
//!
//! When `syslog` is configured (config file `syslog = IP[:port]` or `--syslog`), the
//! server emits one UDP datagram per connection event with RFC 5424 framing and a JSON
//! message body, e.g.:
//!
//! ```text
//! <134>1 2026-06-21T12:34:56.789Z host rmbtd 4242 close - {"event":"close","conn":1,...}
//! ```
//!
//! Logstash parses the syslog envelope and the `json` filter turns the body into typed,
//! queryable fields. Sending is fire-and-forget (UDP, errors ignored) so logging never
//! blocks connection handling. Unlike the UDP-ping server, every connection is logged
//! (connections are comparatively low-frequency), so there is no rate limiting.
//!
//! Events per connection:
//! * `connect` — a connection was accepted (anonymised client, TLS or plain);
//! * `auth` — token validity: accepted / rejected / not-checked, with uuid, token type
//!   (v1/v2) and the matched secret label;
//! * `close` — the outcome: duration plus server-measured download/upload throughput and
//!   ping, and how the connection ended.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const APP_NAME: &str = "rmbtd";
/// Syslog facility `local0`.
const FACILITY: u32 = 16;

// RFC 5424 severities.
const SEV_ERR: u8 = 3;
const SEV_NOTICE: u8 = 5;
const SEV_INFO: u8 = 6;

/// Server-measured accounting for one connection, populated by the command handlers
/// and reported in the `close` event. The RMBT server does not compute the client's
/// final "quality" result — only what it can observe: bytes/time and ping RTT.
#[derive(Debug)]
pub struct ConnStats {
    pub download_bytes: u64,
    pub download_ns: u128,
    pub upload_bytes: u64,
    pub upload_ns: u128,
    pub ping_count: u32,
    pub ping_min_ns: u128,
    pub ping_max_ns: u128,
    /// Number of test commands (GETTIME/GETCHUNKS/PUT/PUTNORESULT/PING) processed.
    pub commands: u32,
}

impl ConnStats {
    pub fn new() -> Self {
        Self {
            download_bytes: 0,
            download_ns: 0,
            upload_bytes: 0,
            upload_ns: 0,
            ping_count: 0,
            ping_min_ns: u128::MAX,
            ping_max_ns: 0,
            commands: 0,
        }
    }

    pub fn add_download(&mut self, bytes: u64, ns: u128) {
        self.download_bytes += bytes;
        self.download_ns += ns;
    }

    pub fn add_upload(&mut self, bytes: u64, ns: u128) {
        self.upload_bytes += bytes;
        self.upload_ns += ns;
    }

    pub fn add_ping(&mut self, ns: u128) {
        self.ping_count += 1;
        if ns < self.ping_min_ns {
            self.ping_min_ns = ns;
        }
        if ns > self.ping_max_ns {
            self.ping_max_ns = ns;
        }
    }
}

impl Default for ConnStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Sends structured events to a syslog collector over UDP.
pub struct EventSink {
    socket: UdpSocket,
    hostname: String,
    procid: u32,
}

impl EventSink {
    /// Connects a UDP socket to `target` so events can be sent with `send`.
    /// The local socket family matches the target (IPv4 or IPv6).
    pub fn new(target: SocketAddr) -> io::Result<Self> {
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(target)?;
        Ok(Self {
            socket,
            hostname: hostname(),
            procid: std::process::id(),
        })
    }

    /// One-time startup event describing the running server.
    pub fn startup(&self, workers: usize, tcp_listeners: usize, tls_listeners: usize) {
        self.emit(
            SEV_INFO,
            "lifecycle",
            Json::new()
                .str("event", "startup")
                .str("version", env!("CARGO_PKG_VERSION"))
                .int("workers", workers as i64)
                .int("tcp_listeners", tcp_listeners as i64)
                .int("tls_listeners", tls_listeners as i64)
                .done(),
        );
    }

    /// A connection was accepted. `client` is the anonymised source address.
    pub fn connect(&self, conn_id: usize, client: &str, tls: bool) {
        self.emit(
            SEV_INFO,
            "connect",
            Json::new()
                .str("event", "connect")
                .int("conn", conn_id as i64)
                .str("client", client)
                .bool("tls", tls)
                .done(),
        );
    }

    /// Token validation result. `result` is `accepted` | `rejected` | `not_checked`;
    /// `label` is the matched secret (on accept) and `reason` the rejection cause.
    #[allow(clippy::too_many_arguments)]
    pub fn auth(
        &self,
        conn_id: usize,
        client: &str,
        uuid: &str,
        token_type: &str,
        result: &str,
        label: Option<&str>,
        reason: Option<&str>,
    ) {
        let sev = if result == "rejected" { SEV_NOTICE } else { SEV_INFO };
        let mut j = Json::new()
            .str("event", "auth")
            .int("conn", conn_id as i64)
            .str("client", client)
            .str("uuid", uuid)
            .str("token", token_type)
            .str("result", result);
        if let Some(l) = label {
            j = j.str("secret", l);
        }
        if let Some(r) = reason {
            j = j.str("reason", r);
        }
        self.emit(sev, "auth", j.done());
    }

    /// End-of-connection outcome. `end` describes how it terminated
    /// (`quit` | `disconnect` | `error` | `auth_failed` | `tls_failed` | `upgrade_failed` | ...).
    #[allow(clippy::too_many_arguments)]
    pub fn close(
        &self,
        conn_id: usize,
        uuid: &str,
        token_type: &str,
        secret: &str,
        tls: bool,
        duration: Duration,
        stats: &ConnStats,
        end: &str,
    ) {
        let mut j = Json::new()
            .str("event", "close")
            .int("conn", conn_id as i64)
            .str("uuid", uuid)
            .str("token", token_type)
            .str("secret", secret)
            .bool("tls", tls)
            .str("end", end)
            .float("duration_ms", duration.as_secs_f64() * 1000.0)
            .int("commands", stats.commands as i64);

        if stats.download_bytes > 0 {
            j = j
                .int("dl_bytes", stats.download_bytes as i64)
                .float("dl_ms", ns_to_ms(stats.download_ns))
                .float("dl_mbps", mbps(stats.download_bytes, stats.download_ns));
        }
        if stats.upload_bytes > 0 {
            j = j
                .int("ul_bytes", stats.upload_bytes as i64)
                .float("ul_ms", ns_to_ms(stats.upload_ns))
                .float("ul_mbps", mbps(stats.upload_bytes, stats.upload_ns));
        }
        if stats.ping_count > 0 {
            j = j
                .int("ping_count", stats.ping_count as i64)
                .float("ping_min_ms", ns_to_ms(stats.ping_min_ns))
                .float("ping_max_ms", ns_to_ms(stats.ping_max_ns));
        }
        self.emit(SEV_INFO, "close", j.done());
    }

    /// An operational error (rare). `context` is a short location tag.
    pub fn error(&self, context: &str, message: &str) {
        self.emit(
            SEV_ERR,
            "error",
            Json::new()
                .str("event", "error")
                .str("context", context)
                .str("message", message)
                .done(),
        );
    }

    /// Builds the RFC 5424 frame and sends it. Fire-and-forget: errors are ignored.
    fn emit(&self, severity: u8, msgid: &str, body: String) {
        let pri = FACILITY * 8 + severity as u32;
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let frame = format!(
            "<{pri}>1 {ts} {} {APP_NAME} {} {msgid} - {body}",
            self.hostname, self.procid,
        );
        let _ = self.socket.send(frame.as_bytes());
    }
}

/// Best-effort hostname from the environment; `-` (RFC 5424 NILVALUE) when unknown.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

fn ns_to_ms(ns: u128) -> f64 {
    ns as f64 / 1_000_000.0
}

/// Throughput in megabits per second from a byte count and a nanosecond duration.
fn mbps(bytes: u64, ns: u128) -> f64 {
    if ns == 0 {
        return 0.0;
    }
    (bytes as f64 * 8.0) / (ns as f64 / 1_000_000_000.0) / 1_000_000.0
}

/// Appends `s` to `out` with JSON string escaping.
fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// A minimal JSON object builder for the small, server-controlled event payloads.
struct Json(String);

impl Json {
    fn new() -> Self {
        Self(String::from("{"))
    }

    fn sep(&mut self) {
        if !self.0.ends_with('{') {
            self.0.push(',');
        }
    }

    fn key(&mut self, k: &str) {
        self.0.push('"');
        json_escape(k, &mut self.0);
        self.0.push_str("\":");
    }

    fn str(mut self, k: &str, v: &str) -> Self {
        self.sep();
        self.key(k);
        self.0.push('"');
        json_escape(v, &mut self.0);
        self.0.push('"');
        self
    }

    fn int(mut self, k: &str, v: i64) -> Self {
        self.sep();
        self.key(k);
        self.0.push_str(&v.to_string());
        self
    }

    fn bool(mut self, k: &str, v: bool) -> Self {
        self.sep();
        self.key(k);
        self.0.push_str(if v { "true" } else { "false" });
        self
    }

    fn float(mut self, k: &str, v: f64) -> Self {
        self.sep();
        self.key(k);
        self.0.push_str(&format!("{v:.3}"));
        self
    }

    fn done(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_quotes_and_controls() {
        let mut s = String::new();
        json_escape("a\"b\\c\n", &mut s);
        assert_eq!(s, "a\\\"b\\\\c\\n");
    }

    #[test]
    fn json_builder_emits_object() {
        let body = Json::new()
            .str("event", "x")
            .int("conn", 3)
            .bool("tls", true)
            .float("v", 1.5)
            .done();
        assert_eq!(body, r#"{"event":"x","conn":3,"tls":true,"v":1.500}"#);
    }

    #[test]
    fn mbps_computes_throughput() {
        // 1_000_000 bytes in 1 s = 8 Mbit/s.
        assert!((mbps(1_000_000, 1_000_000_000) - 8.0).abs() < 1e-9);
        assert_eq!(mbps(100, 0), 0.0);
    }

    #[test]
    fn stats_track_min_ping_and_totals() {
        let mut s = ConnStats::new();
        s.add_download(1000, 500);
        s.add_download(2000, 1500);
        s.add_ping(900);
        s.add_ping(300);
        assert_eq!(s.download_bytes, 3000);
        assert_eq!(s.download_ns, 2000);
        assert_eq!(s.ping_count, 2);
        assert_eq!(s.ping_min_ns, 300);
        assert_eq!(s.ping_max_ns, 900);
    }
}
