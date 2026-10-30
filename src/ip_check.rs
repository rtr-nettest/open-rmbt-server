use std::io::{self, Read, Write};
use std::net::IpAddr;
use serde_json::Value;

use crate::stream::Transport;

/// Upper bound for the request body; real requests are a few hundred bytes.
const MAX_BODY: u64 = 8192;

/// How much of an oversized body is read and discarded before answering 413.
const MAX_DRAIN: u64 = 64 * 1024;

/// True if the request target addresses the IP check (`/ip`, optionally with
/// a query string).
pub fn matches(target: &str) -> bool {
    target == "/ip" || target.starts_with("/ip?")
}

/// Answer one request to `/ip`, mirroring `POST /RMBTControlServer/ip` of the
/// control server: the client's address as seen by this server, its IP
/// version and the NAT type derived from the optional `client_ip_local`.
///
/// `head` is the already-read request header block; `hsts` the HSTS header
/// line to add (empty when disabled).  Returns a short summary for logging.
///
/// The control server additionally stores the NAT type for a running test
/// (`test_uuid`) and detects VPN/proxy usage; neither is available here, so
/// `test_uuid` is ignored and `is_proxy` is always false.
pub fn handle(client: &mut Transport, head: &str, hsts: &str) -> io::Result<String> {
    let mut lines = head.split("\r\n");
    let method = lines.next().unwrap_or("").split(' ').next().unwrap_or("");

    let mut content_length: u64 = 0;
    let mut content_type = "";
    let mut chunked = false;
    let mut origin = false;
    let mut request_headers = "";
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = value.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad Content-Length")
                })?;
            }
            "content-type"      => content_type = value,
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            "origin"            => origin = true,
            "access-control-request-headers" => request_headers = value,
            _ => {}
        }
    }
    // Browsers (e.g. the web client) call /ip cross-origin.
    let cors = if origin { "Access-Control-Allow-Origin: *\r\n" } else { "" };

    let (status, extra, body) = match method {
        "OPTIONS" => {
            let extra = format!(
                "Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                 Access-Control-Allow-Headers: {request_headers}\r\n\
                 Access-Control-Max-Age: 1800\r\n"
            );
            ("200 OK", extra, String::new())
        }
        "POST" if chunked => ("411 Length Required", String::new(), error_body("Content-Length required")),
        "POST" if content_length > MAX_BODY => {
            // Discard (a bounded amount of) the unread body: closing a socket
            // with pending input makes the OS send an RST, which can destroy
            // the response before the client reads it.
            io::copy(&mut Read::take(&mut *client, content_length.min(MAX_DRAIN)), &mut io::sink())?;
            ("413 Content Too Large", String::new(), error_body("request body too large"))
        }
        "POST" => {
            let mut buf = Vec::with_capacity(content_length as usize);
            Read::take(&mut *client, content_length).read_to_end(&mut buf)?;
            if (buf.len() as u64) < content_length {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body truncated"));
            }
            let public = client.peer_addr()
                .ok_or_else(|| io::Error::other("peer address unavailable"))?
                .ip();
            if !is_json(content_type) {
                ("415 Unsupported Media Type", "Accept: application/json\r\n".into(),
                 error_body("Content-Type must be application/json"))
            } else {
                match ip_response(&buf, public) {
                    Ok(json) => ("200 OK", String::new(), json),
                    Err(msg) => ("400 Bad Request", String::new(), error_body(&msg)),
                }
            }
        }
        _ => ("405 Method Not Allowed", "Allow: POST, OPTIONS\r\n".into(), String::new()),
    };

    let content_type = if body.is_empty() { "" } else { "Content-Type: application/json\r\n" };
    let resp = format!(
        "HTTP/1.1 {status}\r\n\
         Connection: close\r\n\
         {hsts}{cors}{extra}{content_type}\
         Cache-Control: no-cache, no-store, max-age=0, must-revalidate\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len(),
    );
    client.write_all(resp.as_bytes())?;
    client.flush()?;

    let code = &status[..3];
    Ok(match body.split("\"nat_type\":\"").nth(1).and_then(|r| r.split('"').next()) {
        Some(nat) => format!("{method} /ip -> {code} ({nat})"),
        None      => format!("{method} /ip -> {code}"),
    })
}

/// True for `application/json`, with or without parameters such as charset.
fn is_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

fn error_body(msg: &str) -> String {
    serde_json::json!({ "error": [msg] }).to_string()
}

/// Build the JSON response for request `body` from a client at `public`, or an
/// error message for a 400 response.
fn ip_response(body: &[u8], public: IpAddr) -> Result<String, String> {
    if body.is_empty() {
        return Err("Required request body is missing".into());
    }
    let req: Value = serde_json::from_slice(body)
        .map_err(|e| format!("Invalid request format: {e}"))?;
    let obj = req.as_object().ok_or("Invalid request format: expected a JSON object")?;

    // Like the control server (Jackson): null/missing/blank means "unknown",
    // scalars are coerced to strings, anything else is rejected.
    let local = match obj.get("client_ip_local") {
        None | Some(Value::Null)                     => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s))                       => Some(s.clone()),
        Some(v @ (Value::Number(_) | Value::Bool(_))) => Some(v.to_string()),
        Some(_) => return Err("Invalid request format: client_ip_local must be a string".into()),
    };
    // IPv4-mapped IPv6 addresses (as seen on dual-stack listeners) count as IPv4.
    let local = local
        .map(|s| s.parse::<IpAddr>().map(|ip| ip.to_canonical()))
        .transpose()
        .map_err(|_| "client_ip_local must be valid IP address".to_string())?;
    let public = public.to_canonical();

    let v = if public.is_ipv4() { "4" } else { "6" };
    Ok(format!(
        r#"{{"v":"{v}","ip":"{public}","nat_type":"{}","is_proxy":false}}"#,
        nat_type(local, public),
    ))
}

/// NAT classification, identical to the control server's
/// `HelperFunctions.getNatType`.
fn nat_type(local: Option<IpAddr>, public: IpAddr) -> String {
    let version = |ip: &IpAddr| if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    let scope   = |ip: &IpAddr| if is_ip_local(ip) { "local" } else { "public" };

    let Some(local) = local else {
        return format!("is_{}", version(&public));
    };
    if local == public {
        format!("no_nat_{}", version(&public))
    } else if local.is_ipv4() == public.is_ipv4() {
        format!("nat_{}_to_{}_{}", scope(&local), scope(&public), version(&public))
    } else {
        format!("nat_{}_to_{}_{}", version(&local), scope(&public), version(&public))
    }
}

/// Java's link-local || loopback || site-local, as used by the control server.
/// Note: site-local is the deprecated `fec0::/10` for IPv6, not ULA `fc00::/7`.
fn is_ip_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_private(),
        IpAddr::V6(v6) => {
            let prefix = v6.segments()[0] & 0xffc0;
            v6.is_loopback() || prefix == 0xfe80 || prefix == 0xfec0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(body: &str, public: &str) -> Result<String, String> {
        ip_response(body.as_bytes(), public.parse().unwrap())
    }

    #[test]
    fn matches_path() {
        assert!(matches("/ip"));
        assert!(matches("/ip?x=1"));
        assert!(!matches("/ip/"));
        assert!(!matches("/ipx"));
        assert!(!matches("/RMBTControlServer/ip"));
    }

    #[test]
    fn nat_types_match_control_server() {
        // Expected values taken from c01.netztest.at for the same inputs.
        let p = "213.47.60.109";
        let nat = |body: &str| resp(body, p).unwrap();
        assert_eq!(nat("{}"), r#"{"v":"4","ip":"213.47.60.109","nat_type":"is_ipv4","is_proxy":false}"#);
        assert!(nat(r#"{"client_ip_local":"192.168.1.5"}"#).contains(r#""nat_type":"nat_local_to_public_ipv4""#));
        assert!(nat(r#"{"client_ip_local":"213.47.60.109"}"#).contains(r#""nat_type":"no_nat_ipv4""#));
        assert!(nat(r#"{"client_ip_local":"::ffff:213.47.60.109"}"#).contains(r#""nat_type":"no_nat_ipv4""#));
        assert!(nat(r#"{"client_ip_local":"fe80::1"}"#).contains(r#""nat_type":"nat_ipv6_to_public_ipv4""#));
        assert!(nat(r#"{"client_ip_local":null,"client_uuid":"x"}"#).contains(r#""nat_type":"is_ipv4""#));
        assert!(nat(r#"{"client_ip_local":"  "}"#).contains(r#""nat_type":"is_ipv4""#));
    }

    #[test]
    fn ipv6_and_mapped_clients() {
        let r = resp(r#"{"client_ip_local":"2001:db8::1"}"#, "2001:db8::1").unwrap();
        assert_eq!(r, r#"{"v":"6","ip":"2001:db8::1","nat_type":"no_nat_ipv6","is_proxy":false}"#);
        // Dual-stack listener: IPv4 client shows up as ::ffff:a.b.c.d.
        let r = resp("{}", "::ffff:198.51.100.7").unwrap();
        assert_eq!(r, r#"{"v":"4","ip":"198.51.100.7","nat_type":"is_ipv4","is_proxy":false}"#);
        assert!(resp(r#"{"client_ip_local":"10.0.0.2"}"#, "10.0.0.1").unwrap()
            .contains(r#""nat_type":"nat_local_to_local_ipv4""#));
    }

    #[test]
    fn rejects_bad_requests() {
        let p = "203.0.113.1";
        assert!(resp("", p).is_err());
        assert!(resp("{x", p).is_err());
        assert!(resp("[]", p).is_err());
        assert!(resp(r#"{"client_ip_local":"nope"}"#, p).is_err());
        assert!(resp(r#"{"client_ip_local":5}"#, p).is_err());
        assert!(resp(r#"{"client_ip_local":{}}"#, p).is_err());
    }

    #[test]
    fn content_type() {
        assert!(is_json("application/json"));
        assert!(is_json("Application/JSON; charset=utf-8"));
        assert!(!is_json("text/plain"));
        assert!(!is_json(""));
    }
}
