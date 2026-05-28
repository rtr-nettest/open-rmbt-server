// Protocol constants matching the RMBT specification and the C reference (config.h).

/// Version string sent to clients in the greeting line.
pub const GREETING: &str = "RMBTv1.3.5\n";

/// Default chunk size for download/upload tests (4 KiB).
pub const CHUNK_SIZE: usize = 4096;

/// Minimum chunk size a client may request.
pub const MIN_CHUNK_SIZE: u32 = 4096;

/// Maximum chunk size a client may request (4 MiB).
pub const MAX_CHUNK_SIZE: u32 = 4_194_304;

/// Maximum number of chunks for a GETCHUNKS command (~1.2 GiB at 4 KiB).
pub const MAX_CHUNKS: u32 = 300_000;

/// Maximum duration in seconds for a GETTIME command.
pub const MAX_SECONDS: u32 = 30;

/// Maximum length of a single protocol text line (bytes).
pub const MAX_LINE_LENGTH: usize = 1024;

/// Per-socket I/O timeout (seconds) — mirrors C's SO_RCVTIMEO/SO_SNDTIMEO.
pub const SOCKET_TIMEOUT_SECS: u64 = 30;

/// Token time window: how many seconds early a client may connect.
/// The server will sleep until the token's start_time is reached.
pub const MAX_ACCEPT_EARLY: i64 = 20;

/// Token time window: how many seconds late a client may still connect.
pub const MAX_ACCEPT_LATE: i64 = 90;

// ─── Pre-allocated random chunk buffers ──────────────────────────────────────
//
// Download tests send random-filled byte slices. We pre-allocate one buffer at
// MAX_CHUNK_SIZE filled with pseudo-random bytes and serve slices from it so
// that handler code never allocates on the hot path.
//
// RMBT last-byte convention:
//   0x00 → non-terminal chunk (more data follows)
//   0xFF → terminal chunk     (end of this transfer)

use lazy_static::lazy_static;

lazy_static! {
    /// A MAX_CHUNK_SIZE buffer of pseudo-random bytes used for all downloads.
    /// The last byte is always overwritten per-chunk to 0x00 or 0xFF.
    pub static ref RANDOM_CHUNK: Vec<u8> = {
        let mut buf = vec![0u8; MAX_CHUNK_SIZE as usize];
        fastrand::fill(&mut buf);
        buf
    };
}

