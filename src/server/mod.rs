use std::io;
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc};
use std::thread;
use std::time::Duration;
use log::{info, error, debug};
use mio::{Events, Interest, Poll, Token};
use mio::net::TcpListener as MioListener;

use crate::config::{Config, SecretKey};
use crate::config::parser::read_secret_keys;
use crate::config::constants::SOCKET_TIMEOUT_SECS;
use crate::stream::{Transport, detect_and_upgrade};
use crate::protocol::{greeting::run_greeting, commands::run_commands};
use crate::tls::build_tls_config;

/// Message sent from the accept loop to a worker thread.
enum Job {
    Connection { stream: TcpStream, addr: SocketAddr, is_tls: bool },
    Shutdown,
}

/// Shared state cloned into every worker thread.
#[derive(Clone)]
struct WorkerCtx {
    config:  Arc<Config>,
    keys:    Arc<Vec<SecretKey>>,
    tls_cfg: Option<Arc<rustls::ServerConfig>>,
}

/// The top-level server object.
pub struct Server {
    shutdown: Arc<AtomicBool>,
    senders:  Vec<mpsc::SyncSender<Job>>,
}

impl Server {
    /// Bind listeners, load secret keys, and start worker threads.
    pub fn new(
        config: Config,
        tcp_addrs: Vec<SocketAddr>,
        tls_addrs: Vec<SocketAddr>,
    ) -> anyhow::Result<(Self, Vec<TcpListener>, Vec<TcpListener>)> {
        // ── Load secret keys ──────────────────────────────────────────────────
        let keys = if config.check_token {
            read_secret_keys(&config.secret_key_path)
                .map_err(|e| { error!("failed to load secret keys: {e}"); e })?
        } else {
            info!("token checking disabled — no secret keys loaded");
            Vec::new()
        };
        info!("loaded {} secret key(s) from '{}'", keys.len(), config.secret_key_path);

        // ── Build TLS config ──────────────────────────────────────────────────
        let tls_cfg = if config.cert_path.is_some() && config.key_path.is_some() {
            let cert = config.cert_path.as_deref().unwrap();
            let key  = config.key_path.as_deref().unwrap();
            match build_tls_config(cert, key) {
                Ok(c) => { info!("TLS configured (cert={cert}, key={key})"); Some(Arc::new(c)) }
                Err(e) => { error!("TLS config failed: {e} — TLS disabled"); None }
            }
        } else {
            info!("no cert/key configured — TLS disabled");
            None
        };

        // ── Bind TCP listeners ────────────────────────────────────────────────
        let mut tcp_listeners = Vec::new();
        for addr in &tcp_addrs {
            match bind_listener(*addr) {
                Ok(l)  => { info!("TCP listening on {addr}"); tcp_listeners.push(l); }
                Err(e) => {
                    error!("TCP bind on {addr} failed: {e}");
                    anyhow::bail!("TCP bind on {addr} failed: {e}");
                }
            }
        }

        let mut tls_listeners = Vec::new();
        if tls_cfg.is_some() {
            for addr in &tls_addrs {
                match bind_listener(*addr) {
                    Ok(l)  => { info!("TLS listening on {addr}"); tls_listeners.push(l); }
                    Err(e) => {
                        error!("TLS bind on {addr} failed: {e}");
                        anyhow::bail!("TLS bind on {addr} failed: {e}");
                    }
                }
            }
        }

        // ── Spawn worker thread pool ──────────────────────────────────────────
        let ctx = WorkerCtx {
            config:  Arc::new(config),
            keys:    Arc::new(keys),
            tls_cfg,
        };

        let num_workers = ctx.config.num_workers;
        let mut senders = Vec::with_capacity(num_workers);
        let shutdown    = Arc::new(AtomicBool::new(false));

        for id in 0..num_workers {
            // Bounded channel: capacity of 8 lets a worker queue several
            // connections before back-pressure kicks in, preventing drops when
            // round-robin lands on a temporarily-busy worker.
            let (tx, rx) = mpsc::sync_channel::<Job>(8);
            senders.push(tx);

            let ctx2      = ctx.clone();
            let shutdown2 = shutdown.clone();

            thread::Builder::new()
                .name(format!("rmbt-worker-{id}"))
                .stack_size(2 * 1024 * 1024)
                .spawn(move || worker_loop(id, rx, ctx2, shutdown2))
                .expect("failed to spawn worker thread");
        }

        Ok((Self { shutdown, senders }, tcp_listeners, tls_listeners))
    }

    /// Run the accept loop (blocking).  Dispatches connections round-robin to
    /// workers.  Returns when the shutdown signal is set.
    pub fn run(
        &self,
        tcp_listeners: Vec<TcpListener>,
        tls_listeners: Vec<TcpListener>,
    ) -> io::Result<()> {
        // Collect and tag all listeners before converting to mio.
        let all_std: Vec<(TcpListener, bool)> =
            tcp_listeners.into_iter().map(|l| (l, false))
            .chain(tls_listeners.into_iter().map(|l| (l, true)))
            .collect();

        if all_std.is_empty() {
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "no listeners bound"));
        }

        // Convert to mio listeners.  mio requires non-blocking mode.
        let mut mio_listeners: Vec<(MioListener, bool)> = all_std.into_iter()
            .map(|(l, is_tls)| {
                l.set_nonblocking(true)?;
                Ok((MioListener::from_std(l), is_tls))
            })
            .collect::<io::Result<_>>()?;

        // Register all listeners with a mio Poll instance.
        // The thread will block in poll() until a connection arrives or the
        // 100 ms timeout expires (used to check the shutdown flag).
        let mut poll = Poll::new()?;
        for (i, (listener, _)) in mio_listeners.iter_mut().enumerate() {
            poll.registry().register(listener, Token(i), Interest::READABLE)?;
        }
        let mut events = Events::with_capacity(16);

        info!("ready for connections ({} listener(s))", mio_listeners.len());

        let mut next_worker = 0usize;

        loop {
            // Block until a connection arrives or the shutdown-check timeout fires.
            poll.poll(&mut events, Some(Duration::from_millis(100)))?;

            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            for event in events.iter() {
                let (listener, is_tls) = &mio_listeners[event.token().0];

                // Drain all pending connections on this listener before sleeping again.
                loop {
                    match listener.accept() {
                        Ok((mio_stream, addr)) => {
                            let stream: TcpStream = std::net::TcpStream::from(mio_stream);
                            let _ = stream.set_nodelay(true);
                            // Accepted sockets are non-blocking (inherited from mio);
                            // worker threads use blocking I/O so we must reset it here.
                            if let Err(e) = stream.set_nonblocking(false) {
                                error!("set_nonblocking(false) failed for {addr}: {e}");
                                continue;
                            }
                            debug!("accepted {} connection from {}",
                                   if *is_tls { "TLS" } else { "TCP" }, addr);

                            // Round-robin dispatch.
                            let sender = &self.senders[next_worker % self.senders.len()];
                            next_worker += 1;

                            let job = Job::Connection { stream, addr, is_tls: *is_tls };
                            if sender.try_send(job).is_err() {
                                debug!("all workers busy — dropping connection from {}", addr);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => { error!("accept error: {e}"); break; }
                    }
                }
            }
        }

        // Signal all workers to stop.
        for tx in &self.senders {
            let _ = tx.try_send(Job::Shutdown);
        }

        Ok(())
    }

    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

// ─── Worker thread ────────────────────────────────────────────────────────────

fn worker_loop(
    id: usize,
    rx: mpsc::Receiver<Job>,
    ctx: WorkerCtx,
    shutdown: Arc<AtomicBool>,
) {
    debug!("worker {id} started");
    // Connection counter — incrementing per worker, used for log correlation.
    let mut conn_seq: usize = 0;

    loop {
        if shutdown.load(Ordering::Relaxed) { break; }

        let job = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(j)  => j,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        match job {
            Job::Shutdown => break,
            Job::Connection { stream, addr, is_tls } => {
                conn_seq += 1;
                let conn_id = id * 100_000 + conn_seq;
                handle_connection(conn_id, stream, addr, is_tls, &ctx);
            }
        }
    }

    debug!("worker {id} stopped");
}

fn handle_connection(
    conn_id: usize,
    tcp: TcpStream,
    addr: SocketAddr,
    is_tls: bool,
    ctx: &WorkerCtx,
) {
    // Anonymise IP: strip last octet/group (matches C's log anonymisation).
    let anon_addr = anonymise_addr(&addr);
    info!("[conn {}] connection from {}", conn_id, anon_addr);

    // Apply socket-level I/O timeout (mirrors C's SO_RCVTIMEO/SO_SNDTIMEO).
    let timeout = Some(Duration::from_secs(SOCKET_TIMEOUT_SECS));
    if let Err(e) = tcp.set_read_timeout(timeout).and(tcp.set_write_timeout(timeout)) {
        error!("[conn {}] failed to set socket timeout: {e}", conn_id);
        return;
    }

    // Build transport (plain or TLS).
    let transport = if is_tls {
        match ctx.tls_cfg.as_ref() {
            Some(tls_cfg) => match Transport::tls(tcp, tls_cfg.clone()) {
                Ok(t)  => t,
                Err(e) => { error!("[conn {}] TLS handshake failed: {e}", conn_id); return; }
            },
            None => { error!("[conn {}] TLS connection on non-TLS worker", conn_id); return; }
        }
    } else {
        Transport::plain(tcp)
    };

    // Perform HTTP upgrade (WebSocket or plain RMBT).
    let mut stream = match detect_and_upgrade(transport) {
        Ok(s)  => s,
        Err(e) => { info!("[conn {}] upgrade failed: {e}", conn_id); return; }
    };
    debug!("[conn {}] upgraded to {}", conn_id, stream.kind_name());

    // Greeting + token validation.
    let uuid = match run_greeting(&mut stream, conn_id, &ctx.config, &ctx.keys) {
        Ok(u)  => u,
        Err(e) => { info!("[conn {}] greeting failed: {e}", conn_id); return; }
    };

    // Main command loop.
    if let Err(e) = run_commands(&mut stream, conn_id, &uuid) {
        if e.kind() != io::ErrorKind::ConnectionAborted && e.kind() != io::ErrorKind::ConnectionReset {
            debug!("[conn {}] command loop ended: {e}", conn_id);
        }
    }

    info!("[conn {}] closing connection; uuid={}", conn_id, uuid);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Bind a TCP listener on the given address.
fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(false)?;
    Ok(listener)
}

/// Remove the last octet (IPv4) or group (IPv6) from an address to avoid
/// storing personal data in logs — identical to the C reference's behaviour.
fn anonymise_addr(addr: &SocketAddr) -> String {
    let ip = addr.ip().to_string();
    if let Some(pos) = ip.rfind('.') {
        format!("{}.*", &ip[..pos])
    } else if let Some(pos) = ip.rfind(':') {
        format!("{}:*", &ip[..pos])
    } else {
        ip
    }
}
