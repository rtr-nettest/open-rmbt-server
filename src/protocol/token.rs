use std::time::{SystemTime, UNIX_EPOCH};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac, KeyInit};
use sha1::Sha1;
use log::{debug, error, info};

use crate::config::{constants::{MAX_ACCEPT_EARLY, MAX_ACCEPT_LATE}, SecretKey};

type HmacSha1 = Hmac<Sha1>;

/// Result of token validation.
#[derive(Debug)]
pub enum TokenResult {
    /// Token accepted; if `sleep_secs > 0` the caller should sleep that long
    /// before continuing (client connected slightly early).
    Accepted { sleep_secs: u64, label: String },
    /// HMAC signature did not match any loaded key.
    InvalidHmac,
    /// HMAC matched but the timestamp is outside the allowed window.
    OutsideWindow { reason: String },
    /// Token string did not parse as UUID_TIMESTAMP_HMAC.
    ParseError,
}

/// Validate an RMBT authentication token against one or more secret keys.
///
/// Token format:  `<UUID>_<UNIX_TIMESTAMP>_<BASE64_HMAC_SHA1>`
///
/// The HMAC is computed over the string `UUID_TIMESTAMP` using the shared
/// secret.  Multiple keys are tried in order to support key rotation.
///
/// Time window (mirrors config.h):
///   * Too early  → accepted only if within MAX_ACCEPT_EARLY seconds; server sleeps.
///   * On time    → accepted immediately.
///   * Too late   → accepted only if within MAX_ACCEPT_LATE seconds.
pub fn validate_token(raw_token: &str, keys: &[SecretKey], conn_id: usize) -> TokenResult {
    // ── Parse ──────────────────────────────────────────────────────────────────
    // Token is exactly three underscore-separated fields, but UUIDs contain
    // hyphens not underscores, so split on the last two underscores from the right.
    let parts: Vec<&str> = raw_token.splitn(3, '_').collect();
    // Actually UUID contains hyphens so the first field might contain hyphens.
    // The C code uses sscanf with specific field widths (36, 12, 50 chars).
    // We replicate: UUID (36), TIMESTAMP (up to 12 digits), HMAC (rest).
    if parts.len() != 3 {
        debug!("[conn {}] token parse error: expected 3 parts, got {}", conn_id, parts.len());
        return TokenResult::ParseError;
    }
    let (uuid, ts_str, hmac_b64) = (parts[0], parts[1], parts[2]);

    if uuid.len() != 36 || ts_str.is_empty() || ts_str.len() > 12 {
        debug!("[conn {}] token parse error: malformed uuid or timestamp", conn_id);
        return TokenResult::ParseError;
    }

    let start_time: i64 = match ts_str.parse() {
        Ok(v) => v,
        Err(_) => { debug!("[conn {}] token parse error: invalid timestamp", conn_id); return TokenResult::ParseError; }
    };

    // ── HMAC validation ────────────────────────────────────────────────────────
    // The message to sign is exactly "UUID_TIMESTAMP" (same as the first two
    // fields joined with underscore), matching the C reference:
    //   snprintf(msg, sizeof(msg), "%s_%s", uuid, start_time_str);
    let message = format!("{uuid}_{ts_str}");

    let mut matched_label = None;
    for key in keys {
        let mut mac = match HmacSha1::new_from_slice(key.key.as_bytes()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        mac.update(message.as_bytes());
        let result = mac.finalize().into_bytes();
        let expected = B64.encode(result);

        // The C code compares using strncmp with base64_buf_size bytes.
        // We compare the full base64 string.
        if expected == hmac_b64 {
            matched_label = Some(key.label.clone());
            break;
        }
    }

    let label = match matched_label {
        Some(l) => l,
        None => {
            error!("[conn {}] token rejected: HMAC mismatch for uuid={}", conn_id, uuid);
            return TokenResult::InvalidHmac;
        }
    };

    info!("[conn {}] token HMAC accepted by key '{}'", conn_id, label);

    // ── Time window check ─────────────────────────────────────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64;

    let seconds_early = start_time - now;   // positive → client is early
    let seconds_late  = now - start_time;   // positive → client is late

    if seconds_early > MAX_ACCEPT_EARLY {
        let reason = format!("client is {seconds_early}s early (max {MAX_ACCEPT_EARLY})");
        error!("[conn {}] token rejected: {}", conn_id, reason);
        return TokenResult::OutsideWindow { reason };
    }

    if seconds_late > MAX_ACCEPT_LATE {
        let reason = format!("client is {seconds_late}s late (max {MAX_ACCEPT_LATE})");
        error!("[conn {}] token rejected: {}", conn_id, reason);
        return TokenResult::OutsideWindow { reason };
    }

    // Client is slightly early but within window — let caller sleep.
    let sleep_secs = if seconds_early > 0 {
        debug!("[conn {}] client is {seconds_early}s early; will sleep", conn_id);
        seconds_early as u64
    } else {
        0
    };

    TokenResult::Accepted { sleep_secs, label }
}
