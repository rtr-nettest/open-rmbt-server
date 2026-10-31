use std::io::{self, Read, Write};
use std::net::IpAddr;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::config::SecretKey;
use crate::protocol::token::{check_ip_token, TokenResult};
use crate::stream::Transport;

type HmacSha256 = Hmac<Sha256>;

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
/// The request may carry the speed-test `token`.  Its v1 part must then be
/// valid for one of `keys`, and that key signs the answer, so that the control
/// server which issued the token can verify the address; see
/// `ip-signature.md`.  `--no-token-check` does not apply here.  Unknown request fields (e.g. `test_uuid`) are ignored.
///
/// `head` is the already-read request header block; `hsts` the HSTS header
/// line to add (empty when disabled).  Returns a short summary for logging.
pub fn handle(
    client: &mut Transport,
    head: &str,
    hsts: &str,
    keys: &[SecretKey],
    conn_id: usize,
) -> io::Result<String> {
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

    // Detail for the log line, e.g. "is_ipv4, key 'x', matching_ip=true, signed".
    let mut note = None;
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
                match ip_response(&buf, public, keys, conn_id) {
                    Ok(answer) => {
                        note = Some(answer.note);
                        ("200 OK", String::new(), answer.json)
                    }
                    Err((status, msg)) => (status, String::new(), error_body(&msg)),
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
    Ok(match note {
        Some(note) => format!("{method} /ip -> {code} ({note})"),
        None       => format!("{method} /ip -> {code}"),
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

/// A successful `/ip` answer.
struct IpAnswer {
    json: String,
    /// Detail for the log line.
    note: String,
}

/// Status line and message of an error answer.
type IpError = (&'static str, String);

fn bad_request(msg: impl Into<String>) -> IpError {
    ("400 Bad Request", msg.into())
}

/// Build the answer for request `body` from a client at `public`.
///
/// The request may carry the speed-test `token` (`<v1>_#v2#<v2>` or plain
/// v1).  Without a token the answer is unsigned.  With a token, the v1 part
/// must be valid (HMAC and time window), otherwise the request is refused with
/// 403.  The key that validated it signs the answer, and `matching_ip` tells
/// whether the v2 part is valid for `public`, i.e. whether the control server
/// issued the token for the address this server sees.
fn ip_response(
    body: &[u8],
    public: IpAddr,
    keys: &[SecretKey],
    conn_id: usize,
) -> Result<IpAnswer, IpError> {
    if body.is_empty() {
        return Err(bad_request("Required request body is missing"));
    }
    let req: Value = serde_json::from_slice(body)
        .map_err(|e| bad_request(format!("Invalid request format: {e}")))?;
    let obj = req.as_object()
        .ok_or_else(|| bad_request("Invalid request format: expected a JSON object"))?;

    // Like the control server (Jackson): null/missing/blank means "unknown",
    // scalars are coerced to strings, anything else is rejected.
    let local = match obj.get("client_ip_local") {
        None | Some(Value::Null)                     => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s))                       => Some(s.clone()),
        Some(v @ (Value::Number(_) | Value::Bool(_))) => Some(v.to_string()),
        Some(_) => return Err(bad_request("Invalid request format: client_ip_local must be a string")),
    };
    // IPv4-mapped IPv6 addresses (as seen on dual-stack listeners) count as IPv4.
    let local = local
        .map(|s| s.parse::<IpAddr>().map(|ip| ip.to_canonical()))
        .transpose()
        .map_err(|_| bad_request("client_ip_local must be valid IP address"))?;

    let token = match obj.get("token") {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.as_str()),
        None | Some(Value::Null | Value::String(_))   => None,
        Some(_) => return Err(bad_request("Invalid request format: token must be a string")),
    };

    let public = public.to_canonical();
    let nat_type = nat_type(local, public);
    let v = if public.is_ipv4() { "4" } else { "6" };
    let mut json = format!(r#"{{"v":"{v}","ip":"{public}","nat_type":"{nat_type}""#);
    let mut note = nat_type;

    match token {
        None => note.push_str(", no token, unsigned"),
        Some(token) => {
            let checked = check_ip_token(token, keys, conn_id, public)
                .map_err(|rejected| ("403 Forbidden", token_error(&rejected)))?;
            // The v1 token starts with the open test UUID (without the "O" prefix).
            let uuid = parse_uuid(&checked.open_test_uuid)
                .ok_or_else(|| ("403 Forbidden", "invalid token: malformed open test UUID".to_string()))?;
            let signature = ip_signature(checked.key.key.as_bytes(), public, &uuid);
            json.push_str(&format!(
                r#","matching_ip":{},"signature":"{}""#,
                checked.matching_ip,
                B64.encode(signature),
            ));
            note.push_str(&format!(", key '{}', matching_ip={}, signed", checked.key.label, checked.matching_ip));
        }
    }
    json.push('}');

    Ok(IpAnswer { json, note })
}

/// Message for a token the `/ip` check refuses.
fn token_error(rejected: &TokenResult) -> String {
    match rejected {
        TokenResult::TooEarly { reason } | TokenResult::TooLate { reason } => format!("invalid token: {reason}"),
        TokenResult::ParseError => "invalid token: malformed".into(),
        _ => "invalid token".into(),
    }
}

/// `HMAC-SHA256(key, ip16 ‖ uuid16)`, where `ip16` is the address as
/// IPv6 (IPv4 as IPv4-mapped `::ffff:a.b.c.d`, as in the v2 token) and
/// `uuid16` the 16 bytes of the open test UUID from the token.  No salt is
/// needed: the open test UUID is random and unique per test.
fn ip_signature(key: &[u8], ip: IpAddr, open_test_uuid: &[u8; 16]) -> [u8; 32] {
    let ip16 = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&ip16);
    mac.update(open_test_uuid);
    mac.finalize().into_bytes().into()
}

/// Parse a UUID in canonical form (`8-4-4-4-12` hex digits) into its 16 bytes.
fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
        return None;
    }
    let hex: Vec<u8> = b.iter().copied().filter(|&c| c != b'-').collect();
    if hex.len() != 32 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
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
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::protocol::token::make_test_token;

    const KEY: &[u8] = b"testkey12345";
    const UUID: &str = "f71d53f4-c67c-4b99-b319-979f714cd408";

    fn now() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    /// Two control servers, each with its own key for this measurement server.
    fn keys() -> Vec<SecretKey> {
        vec![
            SecretKey { key: "control-a-secret".into(), label: "control-a".into() },
            SecretKey { key: "control-b-secret".into(), label: "control-b".into() },
        ]
    }

    /// Token issued by control server B for `issued_for`.
    fn token_b(issued_for: &str) -> String {
        make_test_token("control-b-secret", UUID, now(), issued_for.parse().unwrap())
    }

    /// Request `fields` (a JSON object body without braces) plus a valid token
    /// issued for `public`, answered for a client at `public`.
    fn answer(fields: &str, public: &str) -> Result<IpAnswer, IpError> {
        let sep = if fields.is_empty() { "" } else { "," };
        let body = format!(r#"{{"token":"{}"{sep}{fields}}}"#, token_b(public));
        ip_response(body.as_bytes(), public.parse().unwrap(), &keys(), 1)
    }

    fn json(fields: &str, public: &str) -> String {
        answer(fields, public).ok().unwrap().json
    }

    fn status(body: &str) -> &'static str {
        match ip_response(body.as_bytes(), "203.0.113.1".parse().unwrap(), &keys(), 1) {
            Ok(_) => "200",
            Err((status, _)) => &status[..3],
        }
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
        let nat = |fields: &str| json(fields, p);
        assert!(nat("").starts_with(r#"{"v":"4","ip":"213.47.60.109","nat_type":"is_ipv4","#));
        assert!(nat(r#""client_ip_local":"192.168.1.5""#).contains(r#""nat_type":"nat_local_to_public_ipv4""#));
        assert!(nat(r#""client_ip_local":"213.47.60.109""#).contains(r#""nat_type":"no_nat_ipv4""#));
        assert!(nat(r#""client_ip_local":"::ffff:213.47.60.109""#).contains(r#""nat_type":"no_nat_ipv4""#));
        assert!(nat(r#""client_ip_local":"fe80::1""#).contains(r#""nat_type":"nat_ipv6_to_public_ipv4""#));
        assert!(nat(r#""client_ip_local":null,"client_uuid":"x""#).contains(r#""nat_type":"is_ipv4""#));
        assert!(nat(r#""client_ip_local":"  ""#).contains(r#""nat_type":"is_ipv4""#));
    }

    #[test]
    fn ipv6_and_mapped_clients() {
        let r = json(r#""client_ip_local":"2001:db8::1""#, "2001:db8::1");
        assert!(r.starts_with(r#"{"v":"6","ip":"2001:db8::1","nat_type":"no_nat_ipv6","#));
        // Dual-stack listener: IPv4 client shows up as ::ffff:a.b.c.d.
        let r = json("", "::ffff:198.51.100.7");
        assert!(r.starts_with(r#"{"v":"4","ip":"198.51.100.7","nat_type":"is_ipv4","matching_ip":true,"#));
        assert!(json(r#""client_ip_local":"10.0.0.2""#, "10.0.0.1").contains(r#""nat_type":"nat_local_to_local_ipv4""#));
    }

    #[test]
    fn rejects_bad_requests() {
        let tok = token_b("203.0.113.1");
        assert_eq!(status(""), "400");
        assert_eq!(status("{x"), "400");
        assert_eq!(status("[]"), "400");
        assert_eq!(status(&format!(r#"{{"token":"{tok}","client_ip_local":"nope"}}"#)), "400");
        assert_eq!(status(&format!(r#"{{"token":"{tok}","client_ip_local":5}}"#)), "400");
        assert_eq!(status(&format!(r#"{{"token":"{tok}","client_ip_local":{{}}}}"#)), "400");
        assert_eq!(status(r#"{"token":5}"#), "400");
    }

    #[test]
    fn without_token_the_answer_is_unsigned() {
        let ip = "203.0.113.1".parse().unwrap();
        for body in ["{}", r#"{"token":null}"#, r#"{"token":"  "}"#, r#"{"client_ip_local":"192.168.1.5"}"#] {
            let a = ip_response(body.as_bytes(), ip, &keys(), 1).ok().unwrap();
            assert!(!a.json.contains("matching_ip") && !a.json.contains("signature"), "{}", a.json);
            assert!(a.note.contains("unsigned"), "{}", a.note);
        }
        let a = ip_response(br#"{"client_ip_local":"192.168.1.5"}"#, ip, &keys(), 1).ok().unwrap();
        assert_eq!(a.json, r#"{"v":"4","ip":"203.0.113.1","nat_type":"nat_local_to_public_ipv4"}"#);
    }

    #[test]
    fn a_given_token_must_be_valid() {
        assert_eq!(status(r#"{"token":"garbage"}"#), "403");
        let unknown = make_test_token("unknown-secret", UUID, now(), "203.0.113.1".parse().unwrap());
        assert_eq!(status(&format!(r#"{{"token":"{unknown}"}}"#)), "403");
        let expired = make_test_token("control-a-secret", UUID, now() - 3600, "203.0.113.1".parse().unwrap());
        assert_eq!(status(&format!(r#"{{"token":"{expired}"}}"#)), "403");
    }

    #[test]
    fn signs_with_the_key_that_issued_the_token() {
        let a = answer(r#""test_uuid":"ignored""#, "203.0.113.1").ok().unwrap();
        assert!(a.note.contains("key 'control-b'"), "{}", a.note);
        assert!(!a.json.contains("is_proxy"));
        assert!(!a.json.contains("salt"));

        let uuid = parse_uuid(UUID).unwrap();
        let ip = "203.0.113.1".parse().unwrap();
        let sig_b = B64.encode(ip_signature(b"control-b-secret", ip, &uuid));
        let sig_a = B64.encode(ip_signature(b"control-a-secret", ip, &uuid));
        assert!(a.json.contains(&format!(r#""signature":"{sig_b}""#)));
        assert!(!a.json.contains(&sig_a));
    }

    #[test]
    fn matching_ip_reports_whether_the_token_was_issued_for_this_address() {
        let same = answer("", "203.0.113.1").ok().unwrap();
        assert!(same.json.contains(r#""matching_ip":true"#));

        // Control server saw IPv4, this server sees IPv6: still signed, matching_ip false.
        let body = format!(r#"{{"token":"{}"}}"#, token_b("203.0.113.1"));
        let other = ip_response(body.as_bytes(), "2001:db8::7".parse().unwrap(), &keys(), 1).ok().unwrap();
        assert!(other.json.contains(r#""ip":"2001:db8::7""#));
        assert!(other.json.contains(r#""matching_ip":false"#));
        assert!(other.json.contains(r#""signature":"#));
    }

    #[test]
    fn without_keys_a_token_is_refused() {
        // No secret key file (possible with --no-token-check): no token can be verified.
        let ip = "203.0.113.1".parse().unwrap();
        let body = format!(r#"{{"token":"{}"}}"#, token_b("203.0.113.1"));
        assert!(ip_response(body.as_bytes(), ip, &[], 1).is_err());
        assert_eq!(ip_response(b"{}", ip, &[], 1).ok().unwrap().json,
                   r#"{"v":"4","ip":"203.0.113.1","nat_type":"is_ipv4"}"#);
    }

    #[test]
    fn content_type() {
        assert!(is_json("application/json"));
        assert!(is_json("Application/JSON; charset=utf-8"));
        assert!(!is_json("text/plain"));
        assert!(!is_json(""));
    }

    #[test]
    fn parses_uuid() {
        let bytes = parse_uuid(UUID).unwrap();
        assert_eq!(bytes[..4], [0xf7, 0x1d, 0x53, 0xf4]);
        assert_eq!(bytes[15], 0x08);
        assert_eq!(parse_uuid(&UUID.to_uppercase()), Some(bytes));
        assert!(parse_uuid(&format!("O{UUID}")).is_none());
        assert!(parse_uuid("f71d53f4c67c4b99b319979f714cd408").is_none());
        assert!(parse_uuid("+71d53f4-c67c-4b99-b319-979f714cd408").is_none());
    }

    #[test]
    fn signature_binds_ip_and_uuid() {
        let uuid = parse_uuid(UUID).unwrap();
        let v4: IpAddr = "203.0.113.1".parse().unwrap();
        let sig = ip_signature(KEY, v4, &uuid);
        // Reference value, cross-checked with the Java verifier in ip-signature.md.
        assert_eq!(B64.encode(sig), "HVDXiyb2awlRvPhVIx5y/ERz113y0rnCMCHyU2ktAcA=");
        // IPv4 and its mapped form sign identically.
        assert_eq!(sig, ip_signature(KEY, "::ffff:203.0.113.1".parse().unwrap(), &uuid));
        // Any change of IP, UUID or key changes the signature.
        assert_ne!(sig, ip_signature(KEY, "203.0.113.2".parse().unwrap(), &uuid));
        let mut other = uuid;
        other[0] ^= 1;
        assert_ne!(sig, ip_signature(KEY, v4, &other));
        assert_ne!(sig, ip_signature(b"otherkey", v4, &uuid));
    }
}
