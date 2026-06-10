<div align="center">
<h1>websockit</h1>
</div>
<div align="center">

Batteries-included, runtime-agnostic **WebSocket** for Rust — a Sans-I/O
protocol core with pluggable async drivers.

</div>

## Status

Under construction. Cycle 1 builds [`websocket-proto`](websocket-proto), the
Sans-I/O protocol core (RFC 6455 client & server, RFC 7692 permessage-deflate,
and the RFC 8441 / RFC 9220 handshake surfaces for WebSocket over HTTP/2 and
HTTP/3). Drivers follow.

## The family

The crates split protocol logic from I/O, mirroring the `quinn` layering:

| Crate | Role |
|-------|------|
| [`websocket-proto`](websocket-proto) | Sans-I/O protocol state machines (`no_std`-capable, panic-free) |
| `wren` *(planned)* | batteries-included facade (core + default driver) |
| `wren-reactor` *(planned)* | runtime-agnostic async h1 driver (`tokio` & `smol`) |
| `wren-compio` *(planned)* | `compio` (thread-per-core) async h1 driver |
| `wren-h2` *(planned)* | RFC 8441 driver over the `h2` crate |
| `wren-h3` *(planned)* | RFC 9220 driver over `quinn` |
| `wren-trace` *(planned)* | observability shim |

## License

`websockit` is under the terms of both the MIT license and the Apache License
(Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.
