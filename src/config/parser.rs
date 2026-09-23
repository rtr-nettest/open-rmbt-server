use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::{Config, SecretKey};
use crate::config::constants::DEFAULT_TLS_PORT;

// ─── Secret key file ─────────────────────────────────────────────────────────

/// Load HMAC secret keys from a file.
///
/// File format (one key per line, optional label after a space):
/// ```text
/// mysecretkey1 production
/// oldsecretkey staging
/// ```
/// Lines shorter than 5 characters or starting with `#` are skipped.
/// Multiple keys allow key rotation: the server tries all keys and accepts
/// whichever matches.
pub fn read_secret_keys(path: &str) -> anyhow::Result<Vec<SecretKey>> {
    use std::fs;
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot open secret key file '{}': {}", path, e))?;

    let mut keys = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.len() < 5 || line.starts_with('#') {
            continue;
        }
        if let Some((key, label)) = line.split_once(' ') {
            keys.push(SecretKey { key: key.to_string(), label: label.trim().to_string() });
        } else {
            keys.push(SecretKey { key: line.to_string(), label: String::new() });
        }
    }
    if keys.is_empty() {
        return Err(anyhow::anyhow!("no valid keys found in '{}'", path));
    }
    Ok(keys)
}

// ─── CLI argument parser ──────────────────────────────────────────────────────

/// Fully-resolved configuration parsed from the command line: the runtime
/// [`Config`] plus the listen addresses (which are not part of `Config`).
pub struct Cli {
    pub config:    Config,
    pub tcp_addrs: Vec<SocketAddr>,
    pub tls_addrs: Vec<SocketAddr>,
}

/// Parse the command-line arguments into the final configuration.
/// Returns `None` if the process should exit after printing (--help/--version).
pub fn parse_cli(args: &[String]) -> anyhow::Result<Option<Cli>> {
    // All settings start from the built-in defaults and are overridden by flags.
    let mut config = Config::default();
    let mut tcp_addrs: Vec<SocketAddr> = Vec::new();
    let mut tls_addrs: Vec<SocketAddr> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-l" => { i += 1; if i < args.len() { tcp_addrs.push(parse_addr(&args[i])?); } }
            "-L" => { i += 1; if i < args.len() { tls_addrs.push(parse_addr(&args[i])?); } }
            "-c" => { i += 1; if i < args.len() { config.cert_path       = Some(args[i].clone()); } }
            "-k" => { i += 1; if i < args.len() { config.key_path        = Some(args[i].clone()); } }
            "--tls13-only" => { config.tls13_only = true; }
            "-S" => { i += 1; if i < args.len() { config.secret_key_path = args[i].clone(); } }
            "-t" => { i += 1; if i < args.len() { config.num_workers = args[i].parse()?; } }
            "-log" => { i += 1; if i < args.len() { config.log_level = args[i].parse()?; } }
            "-s" => {} // legacy: "start as server" — no-op, always server mode
            "--no-token-check" => { config.check_token = false; }
            "--v2-only" => { config.v2_only = true; }
            "--syslog" => {
                i += 1;
                if i < args.len() { config.syslog_target = Some(parse_syslog_target(&args[i])?); }
            }
            "--log-full-ip" => { config.log_full_ip = true; }
            "--help" | "-h" => { print_help(); return Ok(None); }
            "-v" | "--version" => {
                println!("rmbtd {}", env!("RMBTD_VERSION"));
                return Ok(None);
            }
            unknown => {
                eprintln!("unknown option '{}'\n", unknown);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // TCP has no default — plain TCP must be explicitly requested with -l.
    // TLS defaults to both IPv6 (::) and IPv4 (0.0.0.0) on the default TLS port.
    if tls_addrs.is_empty() {
        tls_addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_TLS_PORT));
        tls_addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_TLS_PORT));
    }

    Ok(Some(Cli { config, tcp_addrs, tls_addrs }))
}

/// Parse a listen address: bare port, IPv4:port, [IPv6]:port.
pub fn parse_addr(s: &str) -> anyhow::Result<SocketAddr> {
    let s = s.trim();
    if let Ok(sa) = s.parse::<SocketAddr>() { return Ok(sa); }
    // [IPv6]:port
    if s.starts_with('[') {
        if let Some(end) = s.rfind(']') {
            if let Some(port_str) = s[end + 1..].strip_prefix(':') {
                if let (Ok(ip), Ok(port)) =
                    (s[1..end].parse::<Ipv6Addr>(), port_str.parse::<u16>())
                {
                    return Ok(SocketAddr::new(IpAddr::V6(ip), port));
                }
            }
        }
    }
    // IPv4:port
    if let Some((ip_s, port_s)) = s.split_once(':') {
        if let (Ok(ip), Ok(port)) = (ip_s.parse::<Ipv4Addr>(), port_s.parse::<u16>()) {
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    // bare port → 0.0.0.0:port
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    Err(anyhow::anyhow!("invalid address: '{}'", s))
}

/// Parse a syslog target of the form `IP` or `IP:port` (port defaults to 514).
/// IPv6 addresses must be bracketed when a port is given (`[::1]:514`).
pub fn parse_syslog_target(s: &str) -> anyhow::Result<SocketAddr> {
    let s = s.trim();
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 514));
    }
    Err(anyhow::anyhow!("invalid syslog target: '{}' (expected IP or IP:port)", s))
}

fn print_help() {
    println!(
        "rmbtd — RMBT network measurement server\n\
         \n\
         USAGE:\n\
         \trmbtd [OPTIONS]\n\
         \n\
         OPTIONS:\n\
         \t-l ADDRESS   TCP listen address  (no default; TCP disabled unless specified)\n\
         \t-L ADDRESS   TLS listen address  (default: [::]:443 and 0.0.0.0:443)\n\
         \t-c PATH      TLS certificate file (PEM)\n\
         \t-k PATH      TLS private key file (PEM)\n\
         \t--tls13-only Restrict TLS to version 1.3 (reject TLS 1.2)\n\
         \t-S PATH      Secret key file (default: secret.key)\n\
         \t-t N         Worker thread count  (default: 200)\n\
         \t--no-token-check  Accept all tokens without HMAC verification (testing/debugging only)\n\
         \t--v2-only    Accept only v2 tokens (SHA256, IP+time bound); reject legacy v1 tokens\n\
         \t-log LEVEL   Log level: info | debug | trace\n\
         \t--syslog ADDRESS  Send structured per-connection events as UDP RFC 5424 to ADDRESS (IP or IP:port; port default 514)\n\
         \t--log-full-ip  Log the full client IP (default: anonymised, last octet dropped for IPv4, past /48 for IPv6)\n\
         \t-h, --help   Show this help\n\
         \t-v, --version Print version\n\
         \n\
         ADDRESS examples: \"443\", \"0.0.0.0:443\", \"[::]:443\"\n"
    );
}
