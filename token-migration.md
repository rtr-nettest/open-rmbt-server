# RMBT token migration — v1 (SHA1) → v2 (SHA256, IP + time bound)

The control server issues a **combined** token that carries both versions:

```
<v1 token>_#v2#<base64 v2 token>
```

The v1 prefix is unchanged, so old measurement servers keep parsing it and ignore the trailing
field; new servers detect the `#v2#` marker and validate the v2 part. A command-line switch can
restrict this server to **v2 only**. The whole combined string travels in the existing `test_token`,
so the client sends one token to every server — no client change needed.

## Token formats

### v1 part (legacy) — `<UUID>_<UNIX_TIMESTAMP>_<BASE64( HMAC-SHA1(key, "UUID_TIMESTAMP") )>`
- HMAC-SHA1 over the ASCII string `UUID_TIMESTAMP`.
- Only the timestamp is checked against the accept window; the source IP is **not** bound.
- A token with **no** `#v2#` marker is validated as pure v1.

### v2 part (new) — the `open-rmbt-udp-ping` schema, after the `#v2#` marker
```
BASE64( time(4, big-endian)
      ‖ HMAC-SHA256(key, time)[0..8]
      ‖ HMAC-SHA256(key, time ‖ ip16)[0..4] )
```
A 16-byte token → 24 base64 chars (e.g. `ZVPxAEzErM6+VBk3HmTzPw==`); `#` is not in the base64
alphabet, so the marker is unambiguous.
- `time` = low 32 bits of the Unix start time (periodicity 2³² s).
- `ip16` = the client source address as **IPv4-mapped IPv6** (`::ffff:a.b.c.d` for IPv4), 16 bytes.
- `key` = the shared secret (same `secret.key` entries as v1).
- The server checks **both** the time HMAC **and** the source-IP HMAC, plus the accept window.
- When `#v2#` is present, **only the v2 part is validated** (the v1 prefix is ignored).

Example combined token:
```
8723358c-2037-4029-a70c-91e5d9d35cf3_1700000000_oFAdP8+Cw9TqvJOgNc5ABOQRxss=_#v2#ZVPxAEzErM6+VBk3HmTzPw==
```

The v2 part is the same token produced by the control server (`RmbtUdpTokenFactory`) and the
`open-rmbt-udp-ping` reference `makeToken.py`, so it also authenticates the UDP-ping server.

## Usage

By default the server accepts v1 **and** v2 tokens (no action needed; fully backward compatible).

Restrict to v2 only (v1 tokens are rejected):

```bash
# CLI flag
rmbtd -L 0.0.0.0:443 --v2-only

# or in rmbtd.conf
v2_only = true
```

`--v2-only` on the CLI forces v2-only on top of the config file (CLI can only tighten). The token
HMAC check itself is still governed by `check_token` (set it `false` only for testing).

## Interface

`src/protocol/token.rs`:

```rust
pub fn validate_token(
    raw_token: &str,
    keys: &[SecretKey],
    conn_id: usize,
    source_ip: Option<IpAddr>,   // the address the connection actually came from
    v2_only: bool,
) -> TokenResult;

pub enum TokenResult {
    Accepted { sleep_secs: u64, label: String }, // sleep_secs > 0 → client slightly early
    InvalidHmac,                                  // v1, or v2 time-HMAC mismatch
    InvalidIp,                                    // v2: time HMAC ok but source IP doesn't match
    TooEarly { reason: String },                  // HMAC ok but token not valid yet
    TooLate  { reason: String },                  // HMAC ok but token expired
    ParseError,                                   // unparseable token
    V2Required,                                   // a v1 token arrived while --v2-only is set
}
```

The greeting handler (`src/protocol/greeting.rs`) supplies `source_ip` from
`stream.peer_addr()` and `v2_only` from the config; every non-`Accepted` result is answered with
`ERR` and the connection is dropped.

## Implementation notes

- **Version detection** (`extract_v2`): `split_once("#v2#")` — if the marker is present, everything
  after it is the base64 v2 token (the v1 prefix is ignored); otherwise the token is validated as v1.
  A malformed v2 base64 / wrong length → `ParseError`.
- **v2 validation** (`validate_v2`): base64-decode to 16 bytes; for each key, compare
  `HMAC-SHA256(key, time)[0..8]` to the packet hash (this identifies the key), then compare
  `HMAC-SHA256(key, time ‖ ip16)[0..4]` to the IP hash. A time match with an IP mismatch yields
  `InvalidIp` (distinct from `InvalidHmac`). Multiple keys are tried in order (key rotation).
- **IP mapping** (`mapped_ipv6`): IPv4 → `::ffff:a.b.c.d`; IPv6 → as-is. An IPv4 client that the OS
  reports as `::ffff:…` hashes identically to its V4 form.
- **Time window**: the 32-bit time is reconstructed to an absolute Unix time nearest to "now"
  (handles the 2³² wrap), then the existing `MAX_ACCEPT_EARLY` / `MAX_ACCEPT_LATE` window applies —
  shared by v1 and v2.
- **Dependencies**: added `sha2` (HMAC-SHA256) alongside the existing `sha1`/`hmac`/`base64`.

## Debugging

Run with `-log debug` (or `logger = debug` in `rmbtd.conf`) to trace v2 verification. Each step is
logged with the relevant bytes in hex so a mismatch is easy to localise:

```
[conn 7] v2 token: time=67ac5975 packet_hash=c44138a21867e72c ip_hash=07f4136c
[conn 7] v2 source ip 62.1.2.3 (mapped 00000000000000000000ffff3e010203)
[conn 7] v2 key 'production': time HMAC matches
[conn 7] v2 key 'production': ip HMAC matches (own 07f4136c)
[conn 7] v2 token time: u32=1739347829 reconstructed=1739347829 now=1739347831 (early -2s)
[conn 7] v2 token HMAC+IP accepted by key 'production'
```

An IP mismatch prints both the computed and the token value, e.g.
`ip HMAC MISMATCH (own 1a2b3c4d token 07f4136c)` — the usual cause is NAT/proxy between the client
and this server (see Caveats).

## Tests

`cargo test` (module `protocol::token::tests`, 17 tests):
- correct **IPv4** and **IPv6** accepted;
- wrong **IPv4**, wrong **IPv6**, IPv4-token-from-IPv6, and missing source IP → `InvalidIp`;
- wrong key → `InvalidHmac`; future time → `TooEarly`; past time → `TooLate`;
- a combined token with a bogus v1 prefix still validates via its `#v2#` part;
- pure v1 accepted by default; pure v1 rejected under `--v2-only`; a `#v2#` token accepted under `--v2-only`;
- **golden vectors** for v1 and v2 (produced by the Python `makeToken.py` reference) pin the
  on-the-wire byte format across implementations.

## Caveats

- **Source-IP authority:** the v2 IP check only passes if the address this server sees as the peer
  equals the address the control server hashed into the token. NAT/proxy/load-balancer between the
  client→control and client→measurement paths will break the IP binding — verify against the real
  topology before enabling `--v2-only`.
- **Clocks:** v2 still relies on the accept window, so server and client clocks must be roughly in
  sync (within `MAX_ACCEPT_EARLY`/`LATE`).
- `--v2-only` only tightens; there is no CLI switch to force v1-only.
