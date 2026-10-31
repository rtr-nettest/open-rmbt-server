use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac, KeyInit};
use sha1::Sha1;
use sha2::Sha256;
use log::{debug, error, info};

use crate::config::{constants::{MAX_ACCEPT_EARLY, MAX_ACCEPT_LATE}, SecretKey};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Result of token validation.
#[derive(Debug)]
pub enum TokenResult {
    /// Token accepted; if `sleep_secs > 0` the caller should sleep that long
    /// before continuing (client connected slightly early).
    Accepted { sleep_secs: u64, label: String },
    /// HMAC signature did not match any loaded key (v1, or v2 time HMAC).
    InvalidHmac,
    /// v2 only: the time HMAC matched a key, but the connecting source IP does not
    /// match the token's IP HMAC (or the source IP was unavailable).
    InvalidIp,
    /// HMAC matched but the token is not valid yet — the client connected more than
    /// MAX_ACCEPT_EARLY seconds before the token's start time.
    TooEarly { reason: String },
    /// HMAC matched but the token has expired — the client connected more than
    /// MAX_ACCEPT_LATE seconds after the token's start time.
    TooLate { reason: String },
    /// Token string did not parse.
    ParseError,
    /// A legacy v1 token was presented but the server is configured for v2 only.
    V2Required,
}

/// Validate an RMBT authentication token, auto-detecting the version.
///
/// The control server emits a combined token `<v1>_#v2#<base64-v2>`, where:
///
/// **v1** (legacy): `<UUID>_<UNIX_TIMESTAMP>_<BASE64_HMAC_SHA1>` — the HMAC-SHA1 is
/// computed over `UUID_TIMESTAMP`. A pure v1 token has no `#v2#` marker.
///
/// **v2** (`open-rmbt-udp-ping` schema): the part after the `#v2#` marker is base64 of 16 bytes
/// `time(4 BE) ‖ HMAC-SHA256(key, time)[0..8] ‖ HMAC-SHA256(key, time ‖ ip16)[0..4]`,
/// where `time` is the low 32 bits of the Unix start time and `ip16` is the client
/// source address as IPv4-mapped IPv6. Both the **time** and the **source IP** are checked.
///
/// If the `#v2#` marker is present the v2 part is validated (the v1 prefix is ignored);
/// otherwise the token is validated as v1. `source_ip` is the address the connection
/// actually came from (required for v2). When `v2_only` is set, a token without a v2
/// part is rejected.
///
/// Multiple keys are tried in order to support key rotation.
pub fn validate_token(
    raw_token: &str,
    keys: &[SecretKey],
    conn_id: usize,
    source_ip: Option<IpAddr>,
    v2_only: bool,
) -> TokenResult {
    match extract_v2(raw_token) {
        Some(v2_b64) => validate_v2(v2_b64, keys, conn_id, source_ip),
        None if v2_only => {
            error!("[conn {}] token rejected: no v2 part (#v2# marker) and server is in v2-only mode", conn_id);
            TokenResult::V2Required
        }
        None => validate_v1(raw_token, keys, conn_id),
    }
}

/// The combined token is `<v1>_#v2#<base64 v2 token>`. Return the base64 v2 part if the
/// `#v2#` marker is present (everything after it; `#` is not in the base64 alphabet).
fn extract_v2(raw: &str) -> Option<&str> {
    raw.split_once("#v2#").map(|(_, v2)| v2)
}

// ── v1: UUID_TIMESTAMP_HMAC-SHA1 ────────────────────────────────────────────────

fn validate_v1(raw_token: &str, keys: &[SecretKey], conn_id: usize) -> TokenResult {
    match match_v1(raw_token, keys, conn_id) {
        Ok((_, start_time, key)) => {
            info!("[conn {}] v1 token HMAC accepted by key '{}'", conn_id, key.label);
            time_window(start_time, conn_id, key.label.clone())
        }
        Err(rejected) => rejected,
    }
}

/// Parse a v1 token `UUID_TIMESTAMP_HMAC` and find the key whose HMAC-SHA1 over
/// `UUID_TIMESTAMP` matches. Returns the UUID, the start time and that key.
fn match_v1<'t, 'k>(
    raw_token: &'t str,
    keys: &'k [SecretKey],
    conn_id: usize,
) -> Result<(&'t str, i64, &'k SecretKey), TokenResult> {
    // Token is exactly three underscore-separated fields; the UUID uses hyphens not
    // underscores, so the first split field is the whole UUID.
    let parts: Vec<&str> = raw_token.splitn(3, '_').collect();
    if parts.len() != 3 {
        debug!("[conn {}] token parse error: expected 3 parts, got {}", conn_id, parts.len());
        return Err(TokenResult::ParseError);
    }
    let (uuid, ts_str, hmac_b64) = (parts[0], parts[1], parts[2]);

    if uuid.len() != 36 || ts_str.is_empty() || ts_str.len() > 12 {
        debug!("[conn {}] token parse error: malformed uuid or timestamp", conn_id);
        return Err(TokenResult::ParseError);
    }

    let start_time: i64 = match ts_str.parse() {
        Ok(v) => v,
        Err(_) => { debug!("[conn {}] token parse error: invalid timestamp", conn_id); return Err(TokenResult::ParseError); }
    };

    // The signed message is exactly "UUID_TIMESTAMP".
    let message = format!("{uuid}_{ts_str}");

    match keys.iter().find(|k| hmac_sha1_b64(k.key.as_bytes(), message.as_bytes()) == hmac_b64) {
        Some(key) => Ok((uuid, start_time, key)),
        None => {
            error!("[conn {}] token rejected: HMAC mismatch for uuid={}", conn_id, uuid);
            Err(TokenResult::InvalidHmac)
        }
    }
}

// ── v2: open-rmbt-udp-ping schema (SHA256, time + IP) ────────────────────────────

fn validate_v2(raw: &str, keys: &[SecretKey], conn_id: usize, source_ip: Option<IpAddr>) -> TokenResult {
    let bytes = match B64.decode(raw.as_bytes()) {
        Ok(b) if b.len() == 16 => b,
        Ok(b) => {
            debug!("[conn {}] v2 token parse error: {} bytes (expected 16)", conn_id, b.len());
            return TokenResult::ParseError;
        }
        Err(_) => {
            debug!("[conn {}] v2 token parse error: not valid base64", conn_id);
            return TokenResult::ParseError;
        }
    };

    debug!(
        "[conn {}] v2 token: time={} packet_hash={} ip_hash={}",
        conn_id, hex(&bytes[0..4]), hex(&bytes[4..12]), hex(&bytes[12..16])
    );

    // v2 binds the source IP, so we must know where the connection came from.
    let ip = match source_ip {
        Some(ip) => ip,
        None => {
            error!("[conn {}] v2 token rejected: source IP unavailable", conn_id);
            return TokenResult::InvalidIp;
        }
    };
    let ip16 = mapped_ipv6(ip);
    debug!("[conn {}] v2 source ip {} (mapped {})", conn_id, ip, hex(&ip16));

    // The time HMAC identifies the key (keyed, so no cross-key collisions in practice);
    // the IP HMAC then binds the connecting address.
    let mut matched_label: Option<String> = None;
    let mut ip_mismatch = false;
    for key in keys {
        match match_v2(&bytes, key, &ip16, conn_id) {
            V2Match::TimeMismatch => continue,
            V2Match::IpMismatch   => ip_mismatch = true,
            V2Match::Ok           => matched_label = Some(key.label.clone()),
        }
        break;
    }

    let label = match matched_label {
        Some(l) => l,
        None => {
            if ip_mismatch {
                error!("[conn {}] v2 token rejected: source IP {} does not match token", conn_id, ip);
                return TokenResult::InvalidIp;
            }
            error!("[conn {}] v2 token rejected: HMAC mismatch", conn_id);
            return TokenResult::InvalidHmac;
        }
    };

    info!("[conn {}] v2 token HMAC+IP accepted by key '{}'", conn_id, label);

    // The 32-bit time field has a periodicity of 2^32 s; reconstruct the absolute
    // start time as the value nearest to "now".
    let time_u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let now = now_secs();
    let start_time = reconstruct_time(time_u32, now);
    debug!(
        "[conn {}] v2 token time: u32={} reconstructed={} now={} (early {}s)",
        conn_id, time_u32, start_time, now, start_time - now
    );
    time_window(start_time, conn_id, label)
}

/// Outcome of checking a decoded 16-byte v2 token against one key.
enum V2Match {
    /// The time HMAC does not match: the token was not issued with this key.
    TimeMismatch,
    /// Issued with this key, but for a different source IP.
    IpMismatch,
    Ok,
}

fn match_v2(bytes: &[u8], key: &SecretKey, ip16: &[u8; 16], conn_id: usize) -> V2Match {
    let (time_bytes, packet_hash, ip_hash) = (&bytes[0..4], &bytes[4..12], &bytes[12..16]);
    let kb = key.key.as_bytes();
    let own_packet = hmac_sha256(kb, &[time_bytes]);
    if own_packet[..8] != *packet_hash {
        debug!(
            "[conn {}] v2 key '{}': time HMAC no match (own {})",
            conn_id, key.label, hex(&own_packet[..8])
        );
        return V2Match::TimeMismatch;
    }
    debug!("[conn {}] v2 key '{}': time HMAC matches", conn_id, key.label);

    let own_ip = hmac_sha256(kb, &[time_bytes, ip16]);
    if own_ip[..4] == *ip_hash {
        debug!(
            "[conn {}] v2 key '{}': ip HMAC matches (own {})",
            conn_id, key.label, hex(&own_ip[..4])
        );
        V2Match::Ok
    } else {
        debug!(
            "[conn {}] v2 key '{}': ip HMAC MISMATCH (own {} token {})",
            conn_id, key.label, hex(&own_ip[..4]), hex(ip_hash)
        );
        V2Match::IpMismatch
    }
}

// ── /ip check: v1 identifies the key, v2 tells whether the IP matches ──────────

/// Result of checking the token sent to `/ip`.
pub struct IpToken<'k> {
    /// The key that validated the v1 token; it signs the `/ip` answer.
    pub key: &'k SecretKey,
    /// The open test UUID at the start of the v1 token (canonical text, no "O").
    pub open_test_uuid: String,
    /// True if the v2 token, checked with the same key, is valid for `source_ip`:
    /// the control server issued it for the address this server sees.
    pub matching_ip: bool,
}

/// Check a token sent to `/ip`, as the speed test would: the v1 part must be
/// valid (HMAC and time window); it identifies the key, which also signs the
/// answer.  The v2 part, if any, is checked with that same key and only
/// reported via [`IpToken::matching_ip`]; it never causes a rejection.
pub fn check_ip_token<'k>(
    raw_token: &str,
    keys: &'k [SecretKey],
    conn_id: usize,
    source_ip: IpAddr,
) -> Result<IpToken<'k>, TokenResult> {
    let (v1, v2) = match raw_token.split_once("_#v2#") {
        Some((v1, v2)) => (v1, Some(v2)),
        None           => (raw_token, None),
    };
    let (uuid, start_time, key) = match_v1(v1, keys, conn_id)?;
    // No sleeping: an early /ip call is answered right away.
    window_check(start_time, conn_id)?;

    let matching_ip = v2.is_some_and(|b64| match B64.decode(b64.as_bytes()) {
        Ok(bytes) if bytes.len() == 16 => {
            matches!(match_v2(&bytes, key, &mapped_ipv6(source_ip), conn_id), V2Match::Ok)
        }
        _ => false,
    });
    info!("[conn {}] ip check token accepted by key '{}'; matching_ip={}", conn_id, key.label, matching_ip);
    Ok(IpToken { key, open_test_uuid: uuid.to_string(), matching_ip })
}

// ── Shared helpers ──────────────────────────────────────────────────────────────

/// Apply the early/late accept window (identical for v1 and v2).
fn time_window(start_time: i64, conn_id: usize, label: String) -> TokenResult {
    let seconds_early = match window_check(start_time, conn_id) {
        Ok(s)  => s,
        Err(rejected) => return rejected,
    };
    let sleep_secs = if seconds_early > 0 {
        debug!("[conn {}] client is {seconds_early}s early; will sleep", conn_id);
        seconds_early as u64
    } else {
        0
    };
    TokenResult::Accepted { sleep_secs, label }
}

/// Check the early/late accept window.  Returns how many seconds early the
/// client is (zero or negative when on time or late).
fn window_check(start_time: i64, conn_id: usize) -> Result<i64, TokenResult> {
    let now = now_secs();
    let seconds_early = start_time - now; // positive → client is early
    let seconds_late = now - start_time;  // positive → client is late

    if seconds_early > MAX_ACCEPT_EARLY {
        let reason = format!("token not valid yet: client is {seconds_early}s early (max {MAX_ACCEPT_EARLY})");
        error!("[conn {}] token rejected: {}", conn_id, reason);
        return Err(TokenResult::TooEarly { reason });
    }
    if seconds_late > MAX_ACCEPT_LATE {
        let reason = format!("token expired: client is {seconds_late}s late (max {MAX_ACCEPT_LATE})");
        error!("[conn {}] token rejected: {}", conn_id, reason);
        return Err(TokenResult::TooLate { reason });
    }
    Ok(seconds_early)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Map the 32-bit token time back to an absolute Unix time near `now`, handling
/// the 2^32-second wrap.
fn reconstruct_time(time_u32: u32, now: i64) -> i64 {
    const PERIOD: i64 = 1i64 << 32;
    let mut t = (now & !0xFFFF_FFFFi64) | (time_u32 as i64);
    if t - now > PERIOD / 2 {
        t -= PERIOD;
    } else if now - t > PERIOD / 2 {
        t += PERIOD;
    }
    t
}

/// Client source address as IPv4-mapped IPv6 (`::ffff:a.b.c.d` for IPv4), 16 bytes —
/// matching `makeToken.py` and the control server's `RmbtUdpTokenFactory`.
fn mapped_ipv6(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(a) => a.octets(),
        IpAddr::V4(a) => {
            let o = a.octets();
            let mut m = [0u8; 16];
            m[10] = 0xff;
            m[11] = 0xff;
            m[12..16].copy_from_slice(&o);
            m
        }
    }
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn hmac_sha1_b64(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    B64.encode(mac.finalize().into_bytes())
}

/// Lower-case hex of a byte slice, for debug logging.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build a combined `<v1>_#v2#<v2>` token as the control server issues it
/// (`TestSettingsFacade`): v1 over `open_test_uuid_start`, v2 bound to `ip`.
#[cfg(test)]
pub(crate) fn make_test_token(key: &str, open_test_uuid: &str, start: i64, ip: IpAddr) -> String {
    let data = format!("{open_test_uuid}_{start}");
    let v1 = format!("{data}_{}", hmac_sha1_b64(key.as_bytes(), data.as_bytes()));
    let tb = (start as u32).to_be_bytes();
    let mut v2 = Vec::with_capacity(16);
    v2.extend_from_slice(&tb);
    v2.extend_from_slice(&hmac_sha256(key.as_bytes(), &[&tb])[..8]);
    v2.extend_from_slice(&hmac_sha256(key.as_bytes(), &[&tb, &mapped_ipv6(ip)])[..4]);
    format!("{v1}_#v2#{}", B64.encode(v2))
}

// ── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn two_keys() -> Vec<SecretKey> {
        vec![
            SecretKey { key: "control-a-secret".into(), label: "control-a".into() },
            SecretKey { key: "control-b-secret".into(), label: "control-b".into() },
        ]
    }

    #[test]
    fn ip_token_selects_the_issuing_key_not_the_first() {
        let ip: IpAddr = "62.1.2.3".parse().unwrap();
        let tok = make_test_token("control-b-secret", UUID, now_secs(), ip);
        let keys = two_keys();
        let t = check_ip_token(&tok, &keys, 1, ip).ok().unwrap();
        assert_eq!(t.key.label, "control-b");
        assert_eq!(t.open_test_uuid, UUID);
        assert!(t.matching_ip);
    }

    #[test]
    fn ip_token_matching_ip_false_for_other_address() {
        let issued_for: IpAddr = "62.1.2.3".parse().unwrap();
        let tok = make_test_token("control-a-secret", UUID, now_secs(), issued_for);
        let keys = two_keys();
        let t = check_ip_token(&tok, &keys, 1, "2001:db8::1".parse().unwrap()).ok().unwrap();
        assert_eq!(t.key.label, "control-a");
        assert!(!t.matching_ip);
    }

    #[test]
    fn ip_token_v1_only_or_broken_v2_is_not_matching_ip() {
        let ip: IpAddr = "62.1.2.3".parse().unwrap();
        let v1 = make_v1("control-a-secret", UUID, now_secs());
        assert!(!check_ip_token(&v1, &two_keys(), 1, ip).ok().unwrap().matching_ip);
        let broken = format!("{v1}_#v2#notbase64!");
        assert!(!check_ip_token(&broken, &two_keys(), 1, ip).ok().unwrap().matching_ip);
        // v2 issued with a different key than v1 does not count.
        let other = make_test_token("control-b-secret", UUID, now_secs(), ip);
        let mixed = format!("{v1}_#v2#{}", other.split_once("_#v2#").unwrap().1);
        assert!(!check_ip_token(&mixed, &two_keys(), 1, ip).ok().unwrap().matching_ip);
    }

    #[test]
    fn ip_token_rejects_invalid_v1() {
        let ip: IpAddr = "62.1.2.3".parse().unwrap();
        let unknown = make_test_token("unknown-secret", UUID, now_secs(), ip);
        assert!(matches!(check_ip_token(&unknown, &two_keys(), 1, ip), Err(TokenResult::InvalidHmac)));
        let late = make_test_token("control-a-secret", UUID, now_secs() - MAX_ACCEPT_LATE - 5, ip);
        assert!(matches!(check_ip_token(&late, &two_keys(), 1, ip), Err(TokenResult::TooLate { .. })));
        let early = make_test_token("control-a-secret", UUID, now_secs() + MAX_ACCEPT_EARLY + 5, ip);
        assert!(matches!(check_ip_token(&early, &two_keys(), 1, ip), Err(TokenResult::TooEarly { .. })));
        assert!(matches!(check_ip_token("garbage", &two_keys(), 1, ip), Err(TokenResult::ParseError)));
        // A valid v2 part cannot stand in for a broken v1 part.
        let tok = make_test_token("control-a-secret", UUID, now_secs(), ip);
        let v2 = tok.split_once("_#v2#").unwrap().1;
        let forged = format!("{UUID}_{}_bogus_#v2#{v2}", now_secs());
        assert!(matches!(check_ip_token(&forged, &two_keys(), 1, ip), Err(TokenResult::InvalidHmac)));
    }

    const SEED: &str = "topsecret";

    fn keys(k: &str) -> Vec<SecretKey> {
        vec![SecretKey { key: k.to_string(), label: "test".to_string() }]
    }

    /// Build the bare v2 token (base64) exactly like makeToken.py / RmbtUdpTokenFactory.
    fn v2_bare(seed: &str, ip: IpAddr, time: u32) -> String {
        let tb = time.to_be_bytes();
        let ph = hmac_sha256(seed.as_bytes(), &[&tb]);
        let ih = hmac_sha256(seed.as_bytes(), &[&tb, &mapped_ipv6(ip)]);
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&tb);
        buf.extend_from_slice(&ph[..8]);
        buf.extend_from_slice(&ih[..4]);
        B64.encode(buf)
    }

    /// Wrap a bare v2 token in the control server's combined form: `<v1>_#v2#<bare>`.
    /// The v1 prefix (underscores and all) is ignored by v2 validation.
    fn wrap_v2(bare: &str) -> String {
        format!("8723358c-2037-4029-a70c-91e5d9d35cf3_1700000000_v1hmac_#v2#{bare}")
    }

    /// The full combined token the control server issues for a v2-capable session.
    fn make_v2(seed: &str, ip: IpAddr, time: u32) -> String {
        wrap_v2(&v2_bare(seed, ip, time))
    }

    fn make_v1(seed: &str, uuid: &str, ts: i64) -> String {
        let hmac = hmac_sha1_b64(seed.as_bytes(), format!("{uuid}_{ts}").as_bytes());
        format!("{uuid}_{ts}_{hmac}")
    }

    const UUID: &str = "8723358c-2037-4029-a70c-91e5d9d35cf3";

    #[test]
    fn v2_correct_ipv4_accepted() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let tok = make_v2(SEED, ip, now_secs() as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(ip), false),
            TokenResult::Accepted { .. }
        ));
    }

    #[test]
    fn v2_correct_ipv6_accepted() {
        let ip = "2001:db8::1".parse::<IpAddr>().unwrap();
        let tok = make_v2(SEED, ip, now_secs() as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(ip), false),
            TokenResult::Accepted { .. }
        ));
    }

    #[test]
    fn v2_wrong_ipv4_rejected() {
        let issued_for = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let connecting = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let tok = make_v2(SEED, issued_for, now_secs() as u32);
        // time HMAC matches the key, but the connecting IP does not → InvalidIp (not InvalidHmac)
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(connecting), false),
            TokenResult::InvalidIp
        ));
    }

    #[test]
    fn v2_wrong_ipv6_rejected() {
        let issued_for = "2001:db8::1".parse::<IpAddr>().unwrap();
        let connecting = "2001:db8::2".parse::<IpAddr>().unwrap();
        let tok = make_v2(SEED, issued_for, now_secs() as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(connecting), false),
            TokenResult::InvalidIp
        ));
    }

    #[test]
    fn v2_ipv4_token_from_ipv6_rejected() {
        // issued for an IPv4 address but the client connects from a (non-mapped) IPv6 → InvalidIp
        let issued_for = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let connecting = "2001:db8::1".parse::<IpAddr>().unwrap();
        let tok = make_v2(SEED, issued_for, now_secs() as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(connecting), false),
            TokenResult::InvalidIp
        ));
    }

    #[test]
    fn v2_wrong_key_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let tok = make_v2(SEED, ip, now_secs() as u32);
        assert!(matches!(
            validate_token(&tok, &keys("othersecret"), 0, Some(ip), false),
            TokenResult::InvalidHmac
        ));
    }

    #[test]
    fn v2_too_late_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let tok = make_v2(SEED, ip, (now_secs() - 1000) as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(ip), false),
            TokenResult::TooLate { .. }
        ));
    }

    #[test]
    fn v2_too_early_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let tok = make_v2(SEED, ip, (now_secs() + 1000) as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(ip), false),
            TokenResult::TooEarly { .. }
        ));
    }

    #[test]
    fn v2_missing_source_ip_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let tok = make_v2(SEED, ip, now_secs() as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, None, false),
            TokenResult::InvalidIp
        ));
    }

    #[test]
    fn v1_still_accepted_by_default() {
        let tok = make_v1(SEED, UUID, now_secs());
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, None, false),
            TokenResult::Accepted { .. }
        ));
    }

    #[test]
    fn v1_rejected_in_v2_only_mode() {
        let tok = make_v1(SEED, UUID, now_secs());
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, None, true),
            TokenResult::V2Required
        ));
    }

    #[test]
    fn v2_accepted_in_v2_only_mode() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let tok = make_v2(SEED, ip, now_secs() as u32);
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(ip), true),
            TokenResult::Accepted { .. }
        ));
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_v4() {
        // An IPv4 client seen as ::ffff:a.b.c.d (V6) hashes the same as the V4 form.
        let v4 = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let mapped = "::ffff:62.1.2.3".parse::<IpAddr>().unwrap();
        assert_eq!(mapped_ipv6(v4), mapped_ipv6(mapped));
    }

    // ── Golden interop vectors ──────────────────────────────────────────────────
    // Produced by the Python reference (makeToken.py) / control-server
    // RmbtUdpTokenFactory for seed="topsecret", time=1700000000, ip=62.1.2.3.
    // They pin the on-the-wire format across implementations. The timestamp is in
    // the past, so the full validation ends in TooLate — which also proves the HMAC
    // (v2: HMAC + IP) was accepted, since those are checked before the window.

    const V2_GOLDEN: &str = "ZVPxAEzErM6+VBk3HmTzPw==";
    const V1_GOLDEN: &str =
        "8723358c-2037-4029-a70c-91e5d9d35cf3_1700000000_Q+55pZ/JOQgjMe49FlelxsfCxqA=";

    #[test]
    fn v2_golden_vector_is_byte_compatible_with_reference() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        assert_eq!(v2_bare(SEED, ip, 1_700_000_000), V2_GOLDEN);
    }

    #[test]
    fn v2_golden_token_crypto_valid_but_old() {
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        assert!(matches!(
            validate_token(&wrap_v2(V2_GOLDEN), &keys(SEED), 0, Some(ip), false),
            TokenResult::TooLate { .. }
        ));
    }

    #[test]
    fn combined_token_ignores_v1_prefix_and_uses_v2() {
        // a bogus v1 prefix is fine as long as the #v2# part is valid
        let ip = IpAddr::V4(Ipv4Addr::new(62, 1, 2, 3));
        let tok = format!("garbage_not_a_real_v1_token_#v2#{}", v2_bare(SEED, ip, now_secs() as u32));
        assert!(matches!(
            validate_token(&tok, &keys(SEED), 0, Some(ip), false),
            TokenResult::Accepted { .. }
        ));
    }

    #[test]
    fn v1_golden_token_crypto_valid_but_old() {
        assert!(matches!(
            validate_token(V1_GOLDEN, &keys(SEED), 0, None, false),
            TokenResult::TooLate { .. }
        ));
    }
}
