use std::sync::Arc;
use std::sync::atomic::Ordering;
use log::{info, error};

use rmbtd::config::parser::{read_config_file, parse_cli};
use rmbtd::events::EventSink;
use rmbtd::logger;
use rmbtd::server::Server;

fn main() {
    // Build the async runtime explicitly rather than via `#[tokio::main]`.
    // `run` reports every failure at the point it occurs with a dedicated,
    // human-readable message (a CLI/config message on stderr, or a logged
    // `error!` for startup failures). On failure we just exit with a non-zero
    // code — we deliberately do NOT re-print the error or dump a stack trace,
    // which is what returning `anyhow::Result` from `main` would do.
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    if runtime.block_on(run()).is_err() {
        std::process::exit(1);
    }
}

/// Startup and run the server. Returns `Err(())` if the process should exit with
/// a failure code; the underlying error has already been reported to the user.
async fn run() -> Result<(), ()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Load the config file first so CLI flags can override it.
    // (Logging is not yet initialised here, so report on stderr.)
    let mut config = read_config_file().map_err(|e| eprintln!("error: {e}"))?;

    // Parse CLI arguments.  Returns None if --help or --version was printed.
    let cli = match parse_cli(&args, &config).map_err(|e| eprintln!("error: {e}"))? {
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
    // (Still on stderr for reporting, since the logger is what just failed.)
    if config.log_level != log::LevelFilter::Off {
        logger::init(config.log_level).map_err(|e| eprintln!("error: {e}"))?;
    }

    info!("starting rmbtd v{}", env!("RMBTD_VERSION"));
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
    // Server::new already logs a dedicated `error!` for each failure path, so we
    // just propagate the exit code here without reporting the error a second time.
    let (server, tcp_listeners, tls_listeners) =
        Server::new(config, cli.tcp_addrs, cli.tls_addrs, sink.clone()).map_err(|_| ())?;

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
    if let Err(e) = server.run(tcp_listeners, tls_listeners) {
        error!("server error: {e}");
        return Err(());
    }

    info!("server stopped");
    Ok(())
}
