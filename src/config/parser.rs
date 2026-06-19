use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use log::LevelFilter;

use crate::config::{Config, SecretKey};

// ─── Config file ─────────────────────────────────────────────────────────────

/// Read `rmbtd.conf` from the platform-specific path.
/// If the file does not exist the built-in defaults are written to disk.
pub fn read_config_file() -> anyhow::Result<Config> {
    use std::{fs, path::PathBuf};

    let path: PathBuf = if cfg!(windows) {
        "rmbtd.conf".into()
    } else if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{home}/.config/rmbtd.conf").into()
    } else {
        "/etc/rmbtd.conf".into()
    };

    if !path.exists() {
        return Ok(Config::default());
    }

    let content = fs::read_to_string(&path)?;
    parse_config_content(&content)
}

fn parse_config_content(content: &str) -> anyhow::Result<Config> {
    let mut cfg = Config::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else { continue };
        let key = key.trim();
        let val = val.trim().trim_matches('"');

        match key {
            "server_tcp_port"  => { if let Ok(p) = val.parse::<u16>() { cfg.tcp_port = p; } }
            "server_tls_port"  => { if let Ok(p) = val.parse::<u16>() { cfg.tls_port = p; } }
            "cert_path"        => { cfg.cert_path = Some(val.to_string()); }
            "key_path"         => { cfg.key_path  = Some(val.to_string()); }
            "server_workers"   => { if let Ok(n) = val.parse::<usize>() { cfg.num_workers = n; } }
            "secret_key_path"  => { cfg.secret_key_path = val.to_string(); }
            "check_token"      => { cfg.check_token = val != "false" && val != "0"; }
            "v2_only"          => { cfg.v2_only = val == "true" || val == "1"; }
            "max_chunk_size"   => { if let Ok(s) = val.parse::<u32>() { cfg.max_chunk_size = Some(s); } }
            "logger" => {
                cfg.log_level = match val {
                    "trace" => LevelFilter::Trace,
                    "debug" => LevelFilter::Debug,
                    "info"  => LevelFilter::Info,
                    other   => return Err(anyhow::anyhow!("unknown log level: {}", other)),
                };
            }
            _ => {} // silently ignore unknown keys
        }
    }
    Ok(cfg)
}

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

pub struct CliArgs {
    pub tcp_addrs:       Vec<SocketAddr>,
    pub tls_addrs:       Vec<SocketAddr>,
    pub cert_path:       Option<String>,
    pub key_path:        Option<String>,
    pub secret_key_path: Option<String>,
    pub num_workers:     Option<usize>,
    pub log_level:       Option<LevelFilter>,
    pub v2_only:         bool,
}

/// Parse the command-line arguments and return overrides to apply on top of the
/// file-based config.  Returns `None` if the process should exit (--help/-v).
pub fn parse_cli(args: &[String], cfg: &Config) -> anyhow::Result<Option<CliArgs>> {
    let mut out = CliArgs {
        tcp_addrs:       Vec::new(),
        tls_addrs:       Vec::new(),
        cert_path:       cfg.cert_path.clone(),
        key_path:        cfg.key_path.clone(),
        secret_key_path: None,
        num_workers:     None,
        log_level:       None,
        v2_only:         cfg.v2_only,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-l" => {
                i += 1;
                if i < args.len() {
                    out.tcp_addrs.push(parse_addr(&args[i])?);
                }
            }
            "-L" => {
                i += 1;
                if i < args.len() {
                    out.tls_addrs.push(parse_addr(&args[i])?);
                }
            }
            "-c" => { i += 1; if i < args.len() { out.cert_path       = Some(args[i].clone()); } }
            "-k" => { i += 1; if i < args.len() { out.key_path        = Some(args[i].clone()); } }
            "-S" => { i += 1; if i < args.len() { out.secret_key_path = Some(args[i].clone()); } }
            "-t" => {
                i += 1;
                if i < args.len() { out.num_workers = Some(args[i].parse()?); }
            }
            "-log" => {
                i += 1;
                if i < args.len() { out.log_level = Some(args[i].parse()?); }
            }
            "-s" => {} // legacy: "start as server" — no-op, always server mode
            "--v2-only" => { out.v2_only = true; }
            "--help" | "-h" => { print_help(); return Ok(None); }
            "-v" | "--version" => {
                println!("rmbtd {}", env!("CARGO_PKG_VERSION"));
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
    // TLS defaults to both IPv6 (::) and IPv4 (0.0.0.0) on the configured port.
    if out.tls_addrs.is_empty() {
        out.tls_addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), cfg.tls_port));
        out.tls_addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.tls_port));
    }

    Ok(Some(out))
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
         \t-S PATH      Secret key file (default: secret.key)\n\
         \t-t N         Worker thread count  (default: 200)\n\
         \t--v2-only    Accept only v2 tokens (SHA256, IP+time bound); reject legacy v1 tokens\n\
         \t-log LEVEL   Log level: info | debug | trace\n\
         \t-h, --help   Show this help\n\
         \t-v, --version Print version\n\
         \n\
         ADDRESS examples: \"443\", \"0.0.0.0:443\", \"[::]:443\"\n"
    );
}
