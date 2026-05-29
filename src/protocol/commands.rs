use std::io;
use std::time::Instant;
use log::{debug, info, error};

use crate::config::constants::{
    CHUNK_SIZE, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE, MAX_CHUNKS, MAX_SECONDS, RANDOM_CHUNK,
};
use crate::stream::Stream;

const ACCEPT_LINE: &str = "ACCEPT GETCHUNKS GETTIME PUT PUTNORESULT PING QUIT\n";

/// Main command dispatch loop — runs after the greeting/auth phase succeeds.
///
/// Mirrors the infinite `for(;;)` loop in the C reference's `handle_connection()`.
/// Each iteration sends the ACCEPT line and waits for one command.
pub fn run_commands(stream: &mut Stream, conn_id: usize, uuid: &str) -> io::Result<()> {
    // The current chunk size negotiated with this client.
    let mut chunk_size: usize = CHUNK_SIZE;
    let max_chunk_size = MAX_CHUNK_SIZE as usize;

    loop {
        stream.write_line(ACCEPT_LINE)?;

        let line = stream.read_line()?;
        let line = line.trim();

        debug!("[conn {}] command: {:?}", conn_id, line);

        // Split into at most 3 fields: command, arg1, arg2
        let mut parts = line.splitn(3, ' ');
        let cmd  = parts.next().unwrap_or("");
        let arg1 = parts.next().unwrap_or("").trim();
        let arg2 = parts.next().unwrap_or("").trim();

        match cmd {
            "GETTIME"     => handle_gettime(stream, conn_id, arg1, arg2, &mut chunk_size, max_chunk_size)?,
            "GETCHUNKS"   => handle_getchunks(stream, conn_id, arg1, arg2, &mut chunk_size, max_chunk_size)?,
            "PUT"         => handle_put(stream, conn_id, arg1, &mut chunk_size, max_chunk_size, true)?,
            "PUTNORESULT" => handle_put(stream, conn_id, arg1, &mut chunk_size, max_chunk_size, false)?,
            "PING"        => handle_ping(stream, conn_id)?,
            "QUIT"        => {
                stream.write_line("BYE\n")?;
                info!("[conn {}] QUIT received; uuid={}", conn_id, uuid);
                return Ok(());
            }
            other => {
                error!("[conn {}] unknown command: {:?}", conn_id, other);
                stream.write_line("ERR\n")?;
            }
        }
    }
}

// ─── GETTIME ─────────────────────────────────────────────────────────────────

/// `GETTIME <seconds> [chunksize]`
///
/// Send random chunks continuously until `seconds` have elapsed on the server.
/// Mark the final chunk with termination byte 0xFF.
/// Wait for client's "OK", then send `TIME <nanoseconds>`.
fn handle_gettime(
    stream: &mut Stream,
    _conn_id: usize,
    arg_secs: &str,
    arg_chunk: &str,
    chunk_size: &mut usize,
    max_chunk_size: usize,
) -> io::Result<()> {
    // Optional chunk-size override
    if !arg_chunk.is_empty() {
        if let Some(cs) = parse_chunk_size(arg_chunk, max_chunk_size) {
            *chunk_size = cs;
        } else {
            stream.write_line("ERR\n")?;
            return Ok(());
        }
    }

    let seconds: u32 = match arg_secs.parse() {
        Ok(s) if s > 0 && s <= MAX_SECONDS => s,
        _ => { stream.write_line("ERR\n")?; return Ok(()); }
    };

    let max_ns = seconds as u128 * 1_000_000_000;
    let start  = Instant::now();

    // Pre-allocate once from the shared random buffer; mutate the terminal
    // byte in-place on each iteration instead of re-allocating a new Vec.
    let mut buf = RANDOM_CHUNK[..*chunk_size].to_vec();

    loop {
        let elapsed_ns = start.elapsed().as_nanos();
        let terminal   = elapsed_ns >= max_ns;
        *buf.last_mut().unwrap() = if terminal { 0xFF } else { 0x00 };
        stream.write_all(&buf)?;
        if terminal { break; }
    }

    // Wait for client acknowledgement.
    let ack = stream.read_line()?;
    if ack.trim() != "OK" {
        stream.write_line("ERR\n")?;
        return Ok(());
    }

    // Report the total elapsed time.
    let total_ns = start.elapsed().as_nanos();
    stream.write_line(&format!("TIME {total_ns}\n"))?;
    Ok(())
}

// ─── GETCHUNKS ───────────────────────────────────────────────────────────────

/// `GETCHUNKS <count> [chunksize]`
///
/// Send exactly `count` chunks.  Last chunk is marked with 0xFF.
/// Wait for "OK", reply with `TIME <ns>`.
fn handle_getchunks(
    stream: &mut Stream,
    _conn_id: usize,
    arg_count: &str,
    arg_chunk: &str,
    chunk_size: &mut usize,
    max_chunk_size: usize,
) -> io::Result<()> {
    if !arg_chunk.is_empty() {
        if let Some(cs) = parse_chunk_size(arg_chunk, max_chunk_size) {
            *chunk_size = cs;
        } else {
            stream.write_line("ERR\n")?;
            return Ok(());
        }
    }

    let count: u32 = match arg_count.parse() {
        Ok(n) if n > 0 && n <= MAX_CHUNKS => n,
        _ => { stream.write_line("ERR\n")?; return Ok(()); }
    };

    let start = Instant::now();
    let mut buf = RANDOM_CHUNK[..*chunk_size].to_vec();

    for i in 1..=count {
        let terminal = i == count;
        *buf.last_mut().unwrap() = if terminal { 0xFF } else { 0x00 };
        stream.write_all(&buf)?;
    }

    let ack = stream.read_line()?;
    if ack.trim() != "OK" {
        stream.write_line("ERR\n")?;
        return Ok(());
    }

    let total_ns = start.elapsed().as_nanos();
    stream.write_line(&format!("TIME {total_ns}\n"))?;
    Ok(())
}

// ─── PUT / PUTNORESULT ───────────────────────────────────────────────────────

/// `PUT [chunksize]` / `PUTNORESULT [chunksize]`
///
/// Receive upload data from client until the chunk with last-byte 0xFF.
/// For PUT: send `TIME <t> BYTES <b>` after each chunk, but at most every 1 ms.
/// For PUTNORESULT: no intermediate feedback.
/// Both: send final `TIME <ns>` after receiving the terminal chunk.
fn handle_put(
    stream: &mut Stream,
    _conn_id: usize,
    arg_chunk: &str,
    chunk_size: &mut usize,
    max_chunk_size: usize,
    send_intermediate: bool,
) -> io::Result<()> {
    if !arg_chunk.is_empty() {
        if let Some(cs) = parse_chunk_size(arg_chunk, max_chunk_size) {
            *chunk_size = cs;
        } else {
            stream.write_line("ERR\n")?;
            return Ok(());
        }
    }

    stream.write_line("OK\n")?;

    let start              = Instant::now();
    let mut total_bytes    = 0u64;
    let mut buf            = vec![0u8; *chunk_size];
    let mut last_report_ns = i128::MIN; // -1 equivalent (never reported yet)

    loop {
        stream.read_exact(&mut buf)?;
        total_bytes += *chunk_size as u64;
        let last_byte = buf[*chunk_size - 1];

        if send_intermediate {
            let elapsed_ns = start.elapsed().as_nanos() as i128;
            if last_report_ns < 0 || (elapsed_ns - last_report_ns) >= 1_000_000 {
                last_report_ns = elapsed_ns;
                let line = format!("TIME {elapsed_ns} BYTES {total_bytes}\n");
                stream.write_line(&line)?;
            }
        }

        if last_byte == 0xFF {
            break;
        }
    }

    let total_ns = start.elapsed().as_nanos();
    stream.write_line(&format!("TIME {total_ns}\n"))?;
    Ok(())
}

// ─── PING ────────────────────────────────────────────────────────────────────

/// `PING`
///
/// Immediately reply `PONG`, wait for "OK", then send `TIME <ns>`.
/// The measured time is from PONG-sent to OK-received, matching the C code.
fn handle_ping(stream: &mut Stream, _conn_id: usize) -> io::Result<()> {
    let start = Instant::now();

    stream.write_line("PONG\n")?;

    let ack = stream.read_line()?;
    if ack.trim() != "OK" {
        stream.write_line("ERR\n")?;
        return Ok(());
    }

    let ns = start.elapsed().as_nanos();
    stream.write_line(&format!("TIME {ns}\n"))?;
    Ok(())
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Parse and validate a chunk size argument.
/// Returns `None` if the value is out of range or not a valid number.
fn parse_chunk_size(s: &str, max: usize) -> Option<usize> {
    let n: usize = s.parse().ok()?;
    if n < MIN_CHUNK_SIZE as usize || n > max {
        return None;
    }
    Some(n)
}
