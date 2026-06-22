use std::sync::Arc;
use std::sync::atomic::Ordering;
use log::{info, error};

use rmbtd::config::parser::{read_config_file, parse_cli};
use rmbtd::events::EventSink;
use rmbtd::logger;
use rmbtd::server::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Load the config file first so CLI flags can override it.
    let mut config = read_config_file()?;

    // Parse CLI arguments.  Returns None if --help or --version was printed.
    let cli = match parse_cli(&args, &config)? {
        Some(c) => c,
        None    => return Ok(()),
    };

    // Apply CLI overrides on top of the file config.
    if let Some(n) = cli.num_workers     { config.num_workers     = n; }
    if let Some(l) = cli.log_level       { config.log_level       = l; }
    if let Some(c) = cli.cert_path       { config.cert_path       = Some(c); }
    if let Some(k) = cli.key_path        { config.key_path        = Some(k); }
    if let Some(s) = cli.secret_key_path { config.secret_key_path = s; }
    // --v2-only is additive on top of the config file (CLI can only tighten, not relax).
    config.v2_only = cli.v2_only;
    if let Some(t) = cli.syslog_target { config.syslog_target = Some(t); }
    config.log_full_ip = cli.log_full_ip;

    // Initialise logging before anything else so all startup messages appear.
    if config.log_level != log::LevelFilter::Off {
        logger::init(config.log_level)?;
    }

    info!("starting rmbtd v{}", env!("CARGO_PKG_VERSION"));
    info!("version string: {}", rmbtd::config::constants::GREETING.trim());

    // Set up the optional UDP syslog event sink for structured per-connection logging.
    let sink = match config.syslog_target {
        Some(target) => match EventSink::new(target) {
            Ok(s)  => { info!("syslog event logging to {target}"); Some(Arc::new(s)) }
            Err(e) => { error!("syslog target {target} unusable: {e}"); std::process::exit(1); }
        },
        None => None,
    };

    let num_workers = config.num_workers;

    // Build the server (binds listeners, loads keys, starts workers).
    let (server, tcp_listeners, tls_listeners) =
        Server::new(config, cli.tcp_addrs, cli.tls_addrs, sink.clone())?;

    if let Some(s) = &sink {
        s.startup(num_workers, tcp_listeners.len(), tls_listeners.len());
    }

    // Set up a Ctrl+C / SIGTERM handler that sets the shutdown flag.
    let shutdown = server.shutdown_signal();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
        info!("shutdown signal received");
        shutdown.store(true, Ordering::Relaxed);
    });

    // Block on the accept loop until shutdown.
    server.run(tcp_listeners, tls_listeners)?;

    info!("server stopped");
    Ok(())
}
