<div align="center">
<h1>websocket-proto</h1>
</div>
<div align="center">

Sans-I/O WebSocket protocol state machines — RFC 6455 (client & server),
RFC 7692 (permessage-deflate), and the handshake/negotiation surfaces for
RFC 8441 / RFC 9220 (WebSocket over HTTP/2 and HTTP/3).

`no_std` capable (with or without `alloc`), zero-copy on the hot path,
panic-free.

</div>

## Status

**Cycle-1 core complete.** The full RFC 6455 client and server framing and
close handshake, the RFC 7692 permessage-deflate transform (inflate on receive,
opt-in compress on send, context takeover, window-bits, inflated-size caps), the
HTTP/1.1 opening handshake for both roles, and the RFC 8441 / RFC 9220
negotiation surfaces are implemented and tested. Conformance is checked against
the [Autobahn TestSuite](#conformance) (sections 1–9 and the §12/§13
permessage-deflate cases pass; see below). Async drivers live in sibling crates
and are not part of this core.

The state machines carry their own validation, fragmentation, and close
sequencing; what remains for later cycles is ergonomics and the driver layer,
not protocol coverage.

## Design

All protocol behavior lives here as pure state machines: no sockets, no
threads, no clocks, no async. Callers feed bytes, time, and randomness in, and
shuttle the produced bytes out. RFC 8441/9220 change only the opening
handshake, so one transport-blind framing core serves HTTP/1.1-upgraded TCP,
HTTP/2 streams, and HTTP/3 streams alike; drivers compose this crate with their
transport stack (e.g. `quinn` + an HTTP/3 layer).

Receive is a **lending iterator**: feed transport bytes to
[`Connection::handle`] and walk the returned [`Events`] cursor. Uncompressed
payloads are unmasked in place and the chunks borrow the input directly (no
copy); each event is valid only until the next `next()` call. Send encoders
write straight into your buffer (clients mask on the copy with a fresh key per
frame); only protocol-generated frames (pong echoes, the close echo, keepalive
pings) are queued internally and drained via [`Connection::poll_transmit`].

## Feature flags

| Feature | Default | Enables |
|---------|:-------:|---------|
| `std` | ✅ | `alloc`; an [`Instant`] impl for `std::time::Instant`; `rand` std conveniences when `rand` is also on |
| `alloc` | | owned [`Message`] assembly ([`MessageAssembler`]) with cheap-clone `bytes::Bytes` / `smol_str::SmolStr` payloads, `SmolStr`-backed negotiated strings; multi-pong queuing |
| `no-atomic` | | the heap tier for cores **without** native atomic CAS (Cortex-M0+ / thumbv6m / RP2040): same [`Message`] / [`Negotiated`] storage as `alloc`, but the refcounted text / binary buffers use `portable_atomic_util::Arc` (clone via a `critical-section` impl the final binary provides) instead of `smol_str` + `bytes`. Pick one heap tier; `deflate` is **not** available here (the combination is a compile error) |
| `deflate` | | RFC 7692 permessage-deflate (implies `alloc`; pulls in `miniz_oxide`) |
| `rand` | | a default `RngCore` for client mask keys (std-tier convenience; opt in explicitly) |

The bare `no_std`, no-`alloc` tier compiles with `--no-default-features`.

## Quick start

### Server: accept and echo

After the HTTP/1.1 upgrade completes, build a [`Connection`] from the
[`Negotiated`] result and run a `handle` → assemble → echo → drain loop. A
[`MessageAssembler`] folds the lending events into owned [`Message`]s
(`alloc`); drivers that prefer streaming can consume the events directly.

```rust,no_run
# // Doctests compile with whatever features the test run enables; this one
# // needs `std` + `alloc`, so it is gated (a no-op under `--no-default-features`).
# #[cfg(feature = "std")]
# fn main() {}
# #[cfg(not(feature = "std"))]
# fn main() {}
# #[cfg(feature = "std")]
use std::time::Instant;
# #[cfg(feature = "std")]
use websocket_proto::{
    Message, MessageAssembler,
    connection::{Connection, Event, role::Server},
};

# #[cfg(feature = "std")]
fn echo_step(
    conn: &mut Connection<Instant, Server>,
    asm: &mut MessageAssembler,
    inbound: &mut [u8],
    out: &mut [u8],
) {
    // Drain inbound bytes into events, folding messages with the assembler.
    let mut completed: Vec<Message> = Vec::new();
    {
        let mut events = conn.handle(Instant::now(), inbound).expect("not terminal");
        while let Some(event) = events.next() {
            match &event {
                Event::Closed(_) => return,           // drain poll_transmit then drop
                Event::Ping(_) | Event::Pong(_) => {} // pong echo is auto-queued
                _ => {}
            }
            if let Some(msg) = asm.push(&event).expect("in sequence") {
                completed.push(msg);
            }
        }
    }
    // Echo each completed message (text as text, binary as binary).
    for msg in completed {
        let _n = match msg {
            Message::Text(s) => conn.encode_text(&s, out),
            Message::Binary(b) => conn.encode_binary(&b, out),
        }
        .expect("buffer large enough");
        // ... write out[..n] to the socket ...
    }
    // Flush protocol-generated frames (pong/close echoes, keepalive pings).
    while let Some(_n) = conn.poll_transmit(Instant::now(), out).expect("encode") {
        // ... write out[.._n] to the socket ...
    }
}
```

### Client: connect

The client mirror: draw a nonce from an RNG, write the upgrade request, feed
the accumulating response to [`ClientHandshake::handle`], then build the
[`Connection`] with the [`Client`] role.

```rust,no_run
# // Needs `std`; gated so `--no-default-features` doctest runs is a no-op.
# #[cfg(feature = "std")]
# fn main() {}
# #[cfg(not(feature = "std"))]
# fn main() {}
# #[cfg(feature = "std")]
use std::time::Instant;
# #[cfg(feature = "std")]
use websocket_proto::{
    connection::{Connection, ConnectionConfig, role::Client},
    handshake::h1::{ClientHandshake, ClientOptions, ClientProgress},
};

# #[cfg(feature = "std")]
fn connect<R: rand_core::Rng>(mut rng: R, response: &[u8], request_out: &mut [u8]) {
    let options = ClientOptions::new("example.com", "/chat");
    let handshake = ClientHandshake::new(options, &mut rng).expect("valid options");

    // 1. Send the upgrade request.
    let n = handshake.encode_request(request_out).expect("buffer fits");
    // ... write request_out[..n]; read the response into `response` ...
    let _ = n;

    // 2. Feed the accumulated response until the handshake completes.
    if let ClientProgress::Complete(done) = handshake.handle(response).expect("valid") {
        let negotiated = done.into_negotiated();
        let _conn: Connection<Instant, _> = Connection::new(
            &negotiated,
            ConnectionConfig::new(),
            Client::new(rng),
            Instant::now(),
        );
        // ... drive the same handle → encode → poll_transmit loop as the server ...
    }
}
```

Working end-to-end harnesses (handshake + echo over blocking TCP, with
permessage-deflate) live in [`examples/autobahn-server.rs`] and
[`examples/autobahn-client.rs`].

## The family

`websocket-proto` is the Sans-I/O core; drivers and the batteries-included
facade are separate crates, mirroring the `quinn` layering:

| Crate | Role |
|-------|------|
| `websocket-proto` | Sans-I/O protocol state machines (this crate) |
| `wren` *(planned)* | batteries-included facade (core + default driver) |
| `wren-reactor` *(planned)* | runtime-agnostic async h1 driver (`tokio` & `smol`) |
| `wren-compio` *(planned)* | `compio` (thread-per-core) async h1 driver |
| `wren-h2` *(planned)* | RFC 8441 driver over the `h2` crate |
| `wren-h3` *(planned)* | RFC 9220 driver over `quinn` |
| `wren-trace` *(planned)* | observability shim |

## Conformance

A [`no-panic`] link-time test (`tests/no_panic.rs`) proves the core codec leaf
paths (frame decode/encode, masking, UTF-8 validation, base64) compile to
panic-free code, complementing the crate-wide clippy panic-freedom lint wall.

The [Autobahn TestSuite](https://github.com/crossbario/autobahn-testsuite) is
run by the opt-in `autobahn` CI workflow (manual + weekly): the dockerized
fuzzing client drives the server example and the fuzzing server drives the
client example, across all cases including the §12/§13 permessage-deflate
suites. The gate fails on any case whose Autobahn verdict is `FAILED`
(`OK`/`NON-STRICT`/`INFORMATIONAL`/`UNIMPLEMENTED` pass). Reports are uploaded
as a build artifact.

## MSRV

Rust 1.91.0. The MSRV may be raised in a minor release.

## License

`websocket-proto` is under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[`Connection`]: https://docs.rs/websocket-proto/latest/websocket_proto/connection/struct.Connection.html
[`Connection::handle`]: https://docs.rs/websocket-proto/latest/websocket_proto/connection/struct.Connection.html#method.handle
[`Connection::poll_transmit`]: https://docs.rs/websocket-proto/latest/websocket_proto/connection/struct.Connection.html#method.poll_transmit
[`Events`]: https://docs.rs/websocket-proto/latest/websocket_proto/connection/struct.Events.html
[`Instant`]: https://docs.rs/websocket-proto/latest/websocket_proto/time/trait.Instant.html
[`Message`]: https://docs.rs/websocket-proto/latest/websocket_proto/message/enum.Message.html
[`MessageAssembler`]: https://docs.rs/websocket-proto/latest/websocket_proto/message/struct.MessageAssembler.html
[`Negotiated`]: https://docs.rs/websocket-proto/latest/websocket_proto/negotiation/struct.Negotiated.html
[`ClientHandshake::handle`]: https://docs.rs/websocket-proto/latest/websocket_proto/handshake/h1/struct.ClientHandshake.html#method.handle
[`Client`]: https://docs.rs/websocket-proto/latest/websocket_proto/connection/role/struct.Client.html
[`no-panic`]: https://docs.rs/no-panic
[`examples/autobahn-server.rs`]: https://github.com/al8n/websockit/blob/main/websocket-proto/examples/autobahn-server.rs
[`examples/autobahn-client.rs`]: https://github.com/al8n/websockit/blob/main/websocket-proto/examples/autobahn-client.rs
