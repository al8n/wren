<div align="center">
<h1>websocket-proto</h1>
</div>
<div align="center">

Sans-I/O WebSocket protocol state machines — RFC 6455 (client & server),
RFC 7692 (permessage-deflate), and the handshake/negotiation surfaces for
RFC 8441 / RFC 9220 (WebSocket over HTTP/2 and HTTP/3).

`no_std` capable (with or without `alloc`), zero-copy on the hot path,
panic-free.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/wren-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Fwebsocket-proto&style=for-the-badge" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/wren/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/wren?style=for-the-badge&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-websocket--proto-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/websocket-proto?style=for-the-badge&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDE5LjAuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPg0KPHN2ZyB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB4PSIwcHgiIHk9IjBweCINCgkgdmlld0JveD0iMCAwIDUxMiA1MTIiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0yNTYsMEwzMS41MjgsMTEyLjIzNnYyODcuNTI4TDI1Niw1MTJsMjI0LjQ3Mi0xMTIuMjM2VjExMi4yMzZMMjU2LDB6IE0yMzQuMjc3LDQ1Mi41NjRMNzQuOTc0LDM3Mi45MTNWMTYwLjgxDQoJCQlsMTU5LjMwMyw3OS42NTFWNDUyLjU2NHogTTEwMS44MjYsMTI1LjY2MkwyNTYsNDguNTc2bDE1NC4xNzQsNzcuMDg3TDI1NiwyMDIuNzQ5TDEwMS44MjYsMTI1LjY2MnogTTQzNy4wMjYsMzcyLjkxMw0KCQkJbC0xNTkuMzAzLDc5LjY1MVYyNDAuNDYxbDE1OS4zMDMtNzkuNjUxVjM3Mi45MTN6IiBmaWxsPSIjRkZGIi8+DQoJPC9nPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPGc+DQo8L2c+DQo8Zz4NCjwvZz4NCjxnPg0KPC9nPg0KPC9zdmc+DQo=" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/websocket-proto?color=critical&logo=data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/PjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+PHN2ZyB0PSIxNjQ1MTE3MzMyOTU5IiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjM0MjEiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkzIiB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj48ZGVmcz48c3R5bGUgdHlwZT0idGV4dC9jc3MiPjwvc3R5bGU+PC9kZWZzPjxwYXRoIGQ9Ik00NjkuMzEyIDU3MC4yNHYtMjU2aDg1LjM3NnYyNTZoMTI4TDUxMiA3NTYuMjg4IDM0MS4zMTIgNTcwLjI0aDEyOHpNMTAyNCA2NDAuMTI4QzEwMjQgNzgyLjkxMiA5MTkuODcyIDg5NiA3ODcuNjQ4IDg5NmgtNTEyQzEyMy45MDQgODk2IDAgNzYxLjYgMCA1OTcuNTA0IDAgNDUxLjk2OCA5NC42NTYgMzMxLjUyIDIyNi40MzIgMzAyLjk3NiAyODQuMTYgMTk1LjQ1NiAzOTEuODA4IDEyOCA1MTIgMTI4YzE1Mi4zMiAwIDI4Mi4xMTIgMTA4LjQxNiAzMjMuMzkyIDI2MS4xMkM5NDEuODg4IDQxMy40NCAxMDI0IDUxOS4wNCAxMDI0IDY0MC4xOTJ6IG0tMjU5LjItMjA1LjMxMmMtMjQuNDQ4LTEyOS4wMjQtMTI4Ljg5Ni0yMjIuNzItMjUyLjgtMjIyLjcyLTk3LjI4IDAtMTgzLjA0IDU3LjM0NC0yMjQuNjQgMTQ3LjQ1NmwtOS4yOCAyMC4yMjQtMjAuOTI4IDIuOTQ0Yy0xMDMuMzYgMTQuNC0xNzguMzY4IDEwNC4zMi0xNzguMzY4IDIxNC43MiAwIDExNy45NTIgODguODMyIDIxNC40IDE5Ni45MjggMjE0LjRoNTEyYzg4LjMyIDAgMTU3LjUwNC03NS4xMzYgMTU3LjUwNC0xNzEuNzEyIDAtODguMDY0LTY1LjkyLTE2NC45MjgtMTQ0Ljk2LTE3MS43NzZsLTI5LjUwNC0yLjU2LTUuODg4LTMwLjk3NnoiIGZpbGw9IiNmZmZmZmYiIHAtaWQ9IjM0MjIiIGRhdGEtc3BtLWFuY2hvci1pZD0iYTMxM3guNzc4MTA2OS4wLmkwIiBjbGFzcz0iIj48L3BhdGg+PC9zdmc+&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076&logo=data:image/svg+xml;base64,PCFET0NUWVBFIHN2ZyBQVUJMSUMgIi0vL1czQy8vRFREIFNWRyAxLjEvL0VOIiAiaHR0cDovL3d3dy53My5vcmcvR3JhcGhpY3MvU1ZHLzEuMS9EVEQvc3ZnMTEuZHRkIj4KDTwhLS0gVXBsb2FkZWQgdG86IFNWRyBSZXBvLCB3d3cuc3ZncmVwby5jb20sIFRyYW5zZm9ybWVkIGJ5OiBTVkcgUmVwbyBNaXhlciBUb29scyAtLT4KPHN2ZyBmaWxsPSIjZmZmZmZmIiBoZWlnaHQ9IjgwMHB4IiB3aWR0aD0iODAwcHgiIHZlcnNpb249IjEuMSIgaWQ9IkNhcGFfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgdmlld0JveD0iMCAwIDI3Ni43MTUgMjc2LjcxNSIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSIgc3Ryb2tlPSIjZmZmZmZmIj4KDTxnIGlkPSJTVkdSZXBvX2JnQ2FycmllciIgc3Ryb2tlLXdpZHRoPSIwIi8+Cg08ZyBpZD0iU1ZHUmVwb190cmFjZXJDYXJyaWVyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KDTxnIGlkPSJTVkdSZXBvX2ljb25DYXJyaWVyIj4gPGc+IDxwYXRoIGQ9Ik0xMzguMzU3LDBDNjIuMDY2LDAsMCw2Mi4wNjYsMCwxMzguMzU3czYyLjA2NiwxMzguMzU3LDEzOC4zNTcsMTM4LjM1N3MxMzguMzU3LTYyLjA2NiwxMzguMzU3LTEzOC4zNTcgUzIxNC42NDgsMCwxMzguMzU3LDB6IE0xMzguMzU3LDI1OC43MTVDNzEuOTkyLDI1OC43MTUsMTgsMjA0LjcyMywxOCwxMzguMzU3UzcxLjk5MiwxOCwxMzguMzU3LDE4IHMxMjAuMzU3LDUzLjk5MiwxMjAuMzU3LDEyMC4zNTdTMjA0LjcyMywyNTguNzE1LDEzOC4zNTcsMjU4LjcxNXoiLz4gPHBhdGggZD0iTTE5NC43OTgsMTYwLjkwM2MtNC4xODgtMi42NzctOS43NTMtMS40NTQtMTIuNDMyLDIuNzMyYy04LjY5NCwxMy41OTMtMjMuNTAzLDIxLjcwOC0zOS42MTQsMjEuNzA4IGMtMjUuOTA4LDAtNDYuOTg1LTIxLjA3OC00Ni45ODUtNDYuOTg2czIxLjA3Ny00Ni45ODYsNDYuOTg1LTQ2Ljk4NmMxNS42MzMsMCwzMC4yLDcuNzQ3LDM4Ljk2OCwyMC43MjMgYzIuNzgyLDQuMTE3LDguMzc1LDUuMjAxLDEyLjQ5NiwyLjQxOGM0LjExOC0yLjc4Miw1LjIwMS04LjM3NywyLjQxOC0xMi40OTZjLTEyLjExOC0xNy45MzctMzIuMjYyLTI4LjY0NS01My44ODItMjguNjQ1IGMtMzUuODMzLDAtNjQuOTg1LDI5LjE1Mi02NC45ODUsNjQuOTg2czI5LjE1Miw2NC45ODYsNjQuOTg1LDY0Ljk4NmMyMi4yODEsMCw0Mi43NTktMTEuMjE4LDU0Ljc3OC0zMC4wMDkgQzIwMC4yMDgsMTY5LjE0NywxOTguOTg1LDE2My41ODIsMTk0Ljc5OCwxNjAuOTAzeiIvPiA8L2c+IDwvZz4KDTwvc3ZnPg==" height="22">
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
(`alloc`); the allocator-free [`SliceAssembler`] folds them into a
caller-provided buffer and yields a borrowed [`MessageRef`] on every tier
(including the bare `no_std` build); drivers that prefer streaming can consume
the events directly.

```rust,ignore
use std::time::Instant;
use websocket_proto::{
    Message, MessageAssembler,
    connection::{Connection, Event, role::Server},
};

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

```rust,ignore
use std::time::Instant;
use websocket_proto::{
    connection::{Connection, ConnectionConfig, role::Client},
    handshake::h1::{ClientHandshake, ClientOptions, ClientProgress},
};

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
[`SliceAssembler`]: https://docs.rs/websocket-proto/latest/websocket_proto/message/struct.SliceAssembler.html
[`MessageRef`]: https://docs.rs/websocket-proto/latest/websocket_proto/message/enum.MessageRef.html
[`Negotiated`]: https://docs.rs/websocket-proto/latest/websocket_proto/negotiation/struct.Negotiated.html
[`ClientHandshake::handle`]: https://docs.rs/websocket-proto/latest/websocket_proto/handshake/h1/struct.ClientHandshake.html#method.handle
[`Client`]: https://docs.rs/websocket-proto/latest/websocket_proto/connection/role/struct.Client.html
[`no-panic`]: https://docs.rs/no-panic
[`examples/autobahn-server.rs`]: https://github.com/al8n/wren/blob/main/websocket-proto/examples/autobahn-server.rs
[`examples/autobahn-client.rs`]: https://github.com/al8n/wren/blob/main/websocket-proto/examples/autobahn-client.rs
[Github-url]: https://github.com/al8n/wren/
[CI-url]: https://github.com/al8n/wren/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/wren/
[doc-url]: https://docs.rs/websocket-proto
[crates-url]: https://crates.io/crates/websocket-proto
