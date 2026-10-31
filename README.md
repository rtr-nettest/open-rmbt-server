RMBT Test Server in Rust
========================

This project contains the Rust implementation of the RMBT Test Server for conducting measurements based on
the RMBT protocol. Clients can communicate either directly via TCP sockets or based on
the WebSocket protocol.


Requirements
------------

- Rust 1.70+ (uses the 2021 edition)
- Cargo (included with Rust)

Install Rust via [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build
-----

```sh
cargo build --release
```

The binary is written to `target/release/rmbtd`.

For a debug build (faster compile, slower runtime):

```sh
cargo build
# binary at target/debug/rmbtd
```

Usage
-----
```
        rmbtd [OPTIONS]

OPTIONS:
        -l ADDRESS   TCP listen address  (no default; TCP disabled unless specified)
        -L ADDRESS   TLS listen address  (default: [::]:443 and 0.0.0.0:443)
        -c PATH      TLS certificate file (PEM)
        -k PATH      TLS private key file (PEM)
        --tls13-only Restrict TLS to version 1.3 (reject TLS 1.2)
        --hsts       Send an HSTS header (Strict-Transport-Security: max-age=31536000) on TLS responses
        -S PATH      Secret key file (default: secret.key)
        -t N         Worker thread count  (default: 200)
        --no-token-check  Accept all tokens without HMAC verification (testing/debugging only)
        --v2-only    Accept only v2 tokens (SHA256, IP+time bound); reject legacy v1 tokens
        -log LEVEL   Log level: info | debug | trace
        --syslog ADDRESS  Send structured per-connection events as UDP RFC 5424 to ADDRESS (IP or IP:port; port default 514)
        --log-full-ip  Log the full client IP (default: anonymised, last octet/group dropped)
        -h, --help   Show this help
        -v, --version Print version

ADDRESS examples: "443", "0.0.0.0:443", "[::]:443"
```

IP check
--------

`POST /ip` reports the client's address as seen by this server, modelled on
`POST /RMBTControlServer/ip` of the control server:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{"token":"<test_token from /testRequest>","client_ip_local":"192.168.1.5"}' https://<host>/ip
{"v":"4","ip":"203.0.113.7","nat_type":"nat_local_to_public_ipv4","matching_ip":true,"salt":"Na6v…OYg==","signature":"SA3o…5bM="}
```

The reported `ip` is always the address of the TCP connection; it cannot be set by the
client. `client_ip_local` is optional and only used to derive `nat_type`. Other request
fields (e.g. `test_uuid`) are ignored. There is no `is_proxy` field: this server does no
VPN/proxy detection.

`token` is mandatory: the same test token (`<v1>_#v2#<v2>`) the client uses for the speed
test. Its v1 part must be valid for one of the keys in the secret key file, within the same
time window as for the speed test (20 s early to 90 s late); otherwise the request is
refused with 403. The matching key, i.e. the one of the control server that issued the
token, signs the answer:
`signature = HMAC-SHA256(key, salt ‖ ip16 ‖ uuid16)`, base64, with a random 16-byte `salt`
and the open test UUID from the token. `matching_ip` is `true` if the v2 part is valid for the
connecting address, i.e. the control server issued the token for the same IP this server
sees. With `--no-token-check` (no keys loaded) the token is required but not checked, and
the answer has neither `matching_ip` nor a signature. See [ip-signature.md](ip-signature.md) for
the format and control-server verification.

CORS preflight (`OPTIONS`) is answered, so browsers can call it cross-origin.

Remote event logging (ELK)
--------------------------

`--syslog <IP[:port]>` (off by default, port
defaults to 514) ships one structured event per client activity to a collector as UDP
**RFC 5424** datagrams with a JSON message body. This ingests directly into ELK (Logstash
syslog input + `json` filter). Sending is fire-and-forget and never blocks connection
handling; every connection is logged (no sampling).

Events (each carries a `conn` id for correlation):

* `connect` — a connection was accepted (anonymised `client`, `tls`).
* `auth` — token validity: `result` is `accepted` / `rejected` / `not_checked`, with the
  client `uuid` (present for **v2** tokens too), the `token` type (`v1`/`v2`), the matched
  `secret` label (on accept), and a `reason` code (on reject).
* `close` — the outcome at end of connection: `duration_ms`, server-measured download
  (`dl_bytes`/`dl_mbps`), upload (`ul_bytes`/`ul_mbps`) and ping (`ping_count`/`ping_min_ms`/`ping_max_ms`),
  the command count, and `end` (`quit` / `disconnect` / `error` / `auth_failed` /
  `upgrade_failed` / `ip_check` / …). The `uuid`, `token` type and `secret` label are repeated for
  correlation.

By default the source IP is anonymised (last octet/group dropped), matching the local-log
behaviour; pass `--log-full-ip` to log the full
client IP in both local logs and events. Example `close` datagram:

```text
<134>1 2026-06-21T15:58:10.097Z host rmbtd 28936 close - {"event":"close","conn":1,"uuid":"8723358c-2037-4029-a70c-91e5d9d35cf3","token":"v2","secret":"testlabel","tls":false,"end":"quit","duration_ms":18.482,"commands":3,"dl_bytes":16384,"dl_mbps":7.765,"ul_bytes":12288,"ul_mbps":915.307,"ping_count":1,"ping_min_ms":0.102,"ping_max_ms":0.102}
```

Get in Touch
------------

* [RTR-Netztest](https://www.netztest.at) on the web

License
-------

This source code is licensed under the Apache license found in
the [LICENSE.txt](https://github.com/rtr-nettest/rmbtws/blob/master/LICENSE.txt) file.
The documentation to the project is licensed under the [CC BY-AT 3.0](https://creativecommons.org/licenses/by/3.0/at/deed.de_AT)
license.
