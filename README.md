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
        -t N         Worker thread count  (default: 200)
        -log LEVEL   Log level: info | debug | trace
        -h, --help   Show this help
        -v, --version Print version

ADDRESS examples: "443", "0.0.0.0:443", "[::]:443"
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
