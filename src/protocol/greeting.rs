use std::io;
use std::thread;
use std::time::Duration;
use log::{info, error};

use crate::config::{Config, SecretKey, constants::{GREETING, CHUNK_SIZE, MIN_CHUNK_SIZE}};
use crate::events::EventSink;
use crate::stream::Stream;
use crate::protocol::token::{validate_token, TokenResult};

/// Outcome of a successful greeting, carried through to the connection's close event.
pub struct Greeting {
    /// Client UUID, taken from the (v1) token prefix — present for both v1 and v2 tokens.
    pub uuid: String,
    /// Token version that was presented: `"v1"` or `"v2"`.
    pub token_type: &'static str,
    /// Label of the secret key that validated the token (empty when token checking is off).
    pub label: String,
}

/// Run the RMBT greeting/authentication phase.
///
/// Mirrors the C reference's `handle_connection()` up to and including the
/// CHUNKSIZE line:
///
/// ```text
/// S → C:  RMBTv1.3.5\n
/// S → C:  ACCEPT TOKEN QUIT\n
/// C → S:  TOKEN <uuid>_<ts>_<hmac>\n
/// S → C:  OK\n                           (on success)
/// S → C:  CHUNKSIZE 4096 4096 4194304\n
/// ```
///
/// Returns a [`Greeting`] (uuid, token type, secret label) on success, or an `io::Error`
/// if authentication fails or the connection drops. When `sink` is set, an `auth` event
/// describing the token validity is emitted here (both on accept and on rejection).
pub fn run_greeting(
    stream: &mut Stream,
    conn_id: usize,
    config: &Config,
    keys: &[SecretKey],
    sink: Option<&EventSink>,
    client: &str,
) -> io::Result<Greeting> {
    // ── Send version string and token prompt ──────────────────────────────────
    stream.write_line(GREETING)?;
    stream.write_line("ACCEPT TOKEN QUIT\n")?;

    // ── Read TOKEN line ───────────────────────────────────────────────────────
    // Some clients send a blank line between the HTTP upgrade and TOKEN; skip it.
    let line = loop {
        let l = stream.read_line()?;
        if !l.trim().is_empty() { break l; }
    };

    // Parse "TOKEN <value>" — disconnect on any syntax error.
    let token_value = if let Some(rest) = line.strip_prefix("TOKEN ") {
        rest.trim()
    } else if line.trim_start().starts_with("QUIT") {
        stream.write_line("BYE\n")?;
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "client sent QUIT before TOKEN"));
    } else {
        error!("[conn {}] expected TOKEN, got: {:?}", conn_id, line);
        stream.write_line("ERR\n")?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "expected TOKEN line"));
    };

    // Split off the UUID for logging. The combined token starts with the v1
    // `<uuid>_...` prefix, so this yields the uuid for v2 tokens as well.
    let uuid = token_value.split('_').next().unwrap_or("?").to_string();
    // The `#v2#` marker selects v2 validation; otherwise the token is v1.
    let token_type = if token_value.contains("#v2#") { "v2" } else { "v1" };

    // ── Validate HMAC + time window ───────────────────────────────────────────
    let label = if config.check_token {
        // The v2 token binds the client source address, so pass it through.
        let source_ip = stream.peer_addr().map(|sa| sa.ip());
        match validate_token(token_value, keys, conn_id, source_ip, config.v2_only) {
            TokenResult::Accepted { sleep_secs, label } => {
                info!("[conn {}] valid token; uuid={} key='{}'", conn_id, uuid, label);
                if let Some(s) = sink {
                    s.auth(conn_id, client, &uuid, token_type, "accepted", Some(&label), None);
                }
                // Sleep if the client connected slightly before the allowed start time.
                if sleep_secs > 0 {
                    thread::sleep(Duration::from_secs(sleep_secs));
                }
                label
            }
            rejected => {
                let reason = reject_reason(&rejected);
                if let Some(s) = sink {
                    s.auth(conn_id, client, &uuid, token_type, "rejected", None, Some(reason));
                }
                stream.write_line("ERR\n")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "token rejected"));
            }
        }
    } else {
        info!("[conn {}] token NOT CHECKED; uuid={}", conn_id, uuid);
        if let Some(s) = sink {
            s.auth(conn_id, client, &uuid, token_type, "not_checked", None, None);
        }
        String::new()
    };

    // ── Acknowledge and advertise chunk size range ────────────────────────────
    stream.write_line("OK\n")?;

    let max_cs = config.max_chunk_size.unwrap_or(crate::config::constants::MAX_CHUNK_SIZE);
    let chunksize_line = format!("CHUNKSIZE {CHUNK_SIZE} {MIN_CHUNK_SIZE} {max_cs}\n");
    stream.write_line(&chunksize_line)?;

    Ok(Greeting { uuid, token_type, label })
}

/// Map a rejecting [`TokenResult`] to a short machine-readable reason code for logging.
fn reject_reason(result: &TokenResult) -> &'static str {
    match result {
        TokenResult::InvalidHmac    => "invalid_hmac",
        TokenResult::InvalidIp      => "invalid_ip",
        TokenResult::TooEarly { .. } => "too_early",
        TokenResult::TooLate { .. }  => "too_late",
        TokenResult::ParseError     => "parse_error",
        TokenResult::V2Required     => "v2_required",
        TokenResult::Accepted { .. } => "accepted",
    }
}
