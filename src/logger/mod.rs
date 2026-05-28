use std::io::Write;
use log::LevelFilter;

/// Initialise the global logger with the given level filter.
///
/// Each log line is prefixed with an ISO-8601 timestamp so that log files
/// remain interpretable without an external timestamp source.
pub fn init(level: LevelFilter) -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_level(level)
        .format(|buf, record| {
            let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f");
            writeln!(
                buf,
                "{} [{:<5}] {}",
                ts,
                record.level(),
                record.args()
            )
        })
        .try_init()
        .map_err(|e| anyhow::anyhow!("logger init failed: {e}"))
}
