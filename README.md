RMBT Test Server in Rust
========================

This project contains the Rust implementation of the RMBT Test Server for conducting measurements based on
the RMBT protocol. Clients can communicate either directly via TCP sockets or based on
the WebSocket protocol.


Usage
-----
```
        rmbtd [OPTIONS]

OPTIONS:
        -l ADDRESS   TCP listen address  (no default; TCP disabled unless specified)
        -L ADDRESS   TLS listen address  (default: [::]:443 and 0.0.0.0:443)
        -c PATH      TLS certificate file (PEM)
        -k PATH      TLS private key file (PEM)
        -S PATH      Secret key file (default: secret.key)
        -t N         Worker thread count  (default: 200)
        --v2-only    Accept only v2 tokens (SHA256, IP+time bound); reject legacy v1 tokens
        -log LEVEL   Log level: info | debug | trace
        --syslog ADDRESS  Send structured per-connection events as UDP RFC 5424 to ADDRESS (IP or IP:port; port default 514)
        --log-full-ip  Log the full client IP (default: anonymised, last octet/group dropped)
        -h, --help   Show this help
        -v, --version Print version

ADDRESS examples: "443", "0.0.0.0:443", "[::]:443"
```

Remote event logging (ELK)
--------------------------

`--syslog <IP[:port]>` (or `syslog = <IP[:port]>` in `rmbtd.conf`; off by default, port
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
  (`dl_bytes`/`dl_mbps`), upload (`ul_bytes`/`ul_mbps`) and ping (`ping_count`/`ping_min_ms`),
  the command count, and `end` (`quit` / `disconnect` / `error` / `auth_failed` /
  `upgrade_failed` / …). The `uuid`, `token` type and `secret` label are repeated for
  correlation.

By default the source IP is anonymised (last octet/group dropped), matching the local-log
behaviour; pass `--log-full-ip` (or `log_full_ip = true` in `rmbtd.conf`) to log the full
client IP in both local logs and events. Example `close` datagram:

```text
<134>1 2026-06-21T15:58:10.097Z host rmbtd 28936 close - {"event":"close","conn":1,"uuid":"8723358c-2037-4029-a70c-91e5d9d35cf3","token":"v2","secret":"testlabel","tls":false,"end":"quit","duration_ms":18.482,"commands":3,"dl_bytes":16384,"dl_mbps":7.765,"ul_bytes":12288,"ul_mbps":915.307,"ping_count":1,"ping_min_ms":0.102}
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
