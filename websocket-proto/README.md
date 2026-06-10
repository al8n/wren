<div align="center">
<h1>websocket-proto</h1>
</div>
<div align="center">

Sans-I/O WebSocket protocol state machines — RFC 6455 (client & server),
RFC 7692 (permessage-deflate), and the handshake/negotiation surfaces for
RFC 8441 / RFC 9220 (WebSocket over HTTP/2 and HTTP/3).

`no_std` capable (with or without `alloc`), zero-copy, panic-free.

</div>

## Status

Under construction — cycle 1 of the websockit family. The crate compiles and
its utility substrate is tested, but the protocol surface is not yet complete.

## Design

All protocol behavior lives here as pure state machines: no sockets, no
threads, no clocks, no async. Callers feed bytes, time, and randomness in,
and shuttle the produced bytes out. RFC 8441/9220 change only the opening
handshake, so one transport-blind framing core serves HTTP/1.1-upgraded TCP,
HTTP/2 streams, and HTTP/3 streams alike; drivers compose this crate with
their transport stack (e.g. `quinn-proto` + an HTTP/3 layer).

## Feature flags

- `std` *(default)* — implies `alloc`; `Instant` impl for `std::time::Instant`.
- `alloc` — owned `Message` assembly and `SmolStr`-backed negotiated strings.
- `heapless` — bounded storage for the `no_std` + no-alloc tier.
- `deflate` — RFC 7692 permessage-deflate (requires `alloc`).
- `rand` — std-tier convenience constructors with a default RNG.

## License

`websocket-proto` is under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.
