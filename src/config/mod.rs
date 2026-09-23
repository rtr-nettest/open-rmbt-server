use std::net::SocketAddr;
use log::LevelFilter;

pub mod constants;
pub mod parser;

/// A single HMAC secret key loaded from the `secret.key` file.
/// The C reference supports multiple keys (for key rotation) each with a label
/// that is printed in logs when that key successfully validates a token.
#[derive(Clone, Debug)]
pub struct SecretKey {
    /// The raw key bytes used for HMAC-SHA1 computation.
    pub key: String,
    /// Human-readable label printed in logs on successful validation.
    pub label: String,
}

/// Runtime configuration, built entirely from command-line arguments.
#[derive(Debug, Clone)]
pub struct Config {
    // ── TLS certificate paths ─────────────────────────────────────────────────
    pub cert_path: Option<String>,
    pub key_path:  Option<String>,

    // ── Worker threads ────────────────────────────────────────────────────────
    /// Number of worker threads in the connection handler pool.
    pub num_workers: usize,

    // ── Token authentication ──────────────────────────────────────────────────
    /// Path to the secret.key file (multi-key, one per line).
    pub secret_key_path: String,
    /// When false, incoming tokens are accepted without HMAC verification.
    /// Useful for testing. Mirrors C's `CHECK_TOKEN` constant.
    pub check_token: bool,
    /// When true, only v2 tokens (SHA256, open-rmbt-udp-ping schema, bound to source
    /// IP + time) are accepted; legacy v1 tokens are rejected.
    pub v2_only: bool,

    // ── Logging ───────────────────────────────────────────────────────────────
    pub log_level: LevelFilter,
    /// Collector address for UDP syslog event logging (per-connection events for ELK).
    /// `None` disables remote event logging.
    pub syslog_target: Option<SocketAddr>,
    /// Log the full client IP instead of the anonymised form (last octet for IPv4,
    /// everything past /48 for IPv6 dropped).
    /// Off by default to avoid storing personal data; affects both local logs and events.
    pub log_full_ip: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cert_path:       None,
            key_path:        None,
            num_workers:     200,
            secret_key_path: "secret.key".to_string(),
            check_token:     true,
            v2_only:         false,
            log_level:       LevelFilter::Off,
            syslog_target:   None,
            log_full_ip:     false,
        }
    }
}
