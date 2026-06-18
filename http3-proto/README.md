<div align="center">
<h1>http3-proto</h1>
</div>
<div align="center">

Sans-I/O HTTP/3 Extended-CONNECT tunnel state machine — the RFC 9114 / 9204 /
9220 subset needed to carry a tunneled byte stream (e.g. WebSocket) over QUIC.

`no_std` + no-alloc capable, static-table-only QPACK, panic-free codec leaves.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/websockit-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/websockit/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-http3--proto-66c2a5?style=for-the-badge&labelColor=555555&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMiA0MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMiAzOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMiA0MS40di0uNmwxMDIgMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/http3-proto?style=for-the-badge&logo=rust" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

</div>

## What it is

`http3-proto` is the Sans-I/O core for an HTTP/3 Extended-CONNECT tunnel
(RFC 9114 / RFC 9204 / RFC 9220). It owns no sockets, no threads, no async
runtime. Callers feed inbound QUIC stream bytes in, and shuttle the produced
bytes out to their QUIC implementation (e.g. `quinn`).

The scope is the WS-over-HTTP/3 handshake + DATA tunnel subset:

- QUIC variable-length integer codec (RFC 9000 §16).
- HTTP/3 frame header codec — type + length varints (RFC 9114 §7.1).
- Static-table-only QPACK field-section encode/decode (RFC 9204); the dynamic
  table is permanently disabled, matching the WebSocket tunnel use-case.
- HTTP/3 SETTINGS frame encode/decode (RFC 9114 §7.2.4, RFC 9204 §5, RFC 9220 §3).
- `Connection<Client>` / `Connection<Server>` state machine: control stream
  (SETTINGS exchange), idle QPACK streams, and a bidirectional request stream
  carrying the CONNECT HEADERS + DATA tunnel.

The core stays HTTP-status-agnostic: it reports the peer's HEADERS as
`Frame::Request` / `Frame::Response` and lets the driver validate `:status` /
`:protocol`. "Established" means the CONNECT HEADERS exchange completed.

## Feature flags

| Feature | Default | Enables |
|---------|:-------:|---------|
| `std` | ✅ | `thiserror/std`; the owned `decode_field_section` (Vec-backed Huffman scratch) |
| `alloc` | | the owned `decode_field_section` without `std` |

The bare `no_std`, no-`alloc` tier compiles with `--no-default-features`. The
only external dependency on that tier is `thiserror` (with `std` off) and
`derive_more`.

## Storage model

The default request/connection storage is feature-configured through
`DefaultReqBuf<'a>`, `DefaultCtrlBuf<'a>`, `DefaultTxBuf<'a>`, and
`DefaultEventBuf<'a>` / `DefaultUniBuf<'a>`.

With `std` or `alloc`, `Connection::<Role>::new()` allocates the
request/control/transmit byte buffers, event-slot buffer, and inbound-uni
tracking buffer, and stores only their handles in the connection value.
In the bare `no_std`, no-`alloc` tier, the default buffer aliases are borrowed
`&mut [u8]`, `&mut [Option<Event>]`, and `&mut [UniSlot]` slices. Each
connection storage class has its own lifetime, so request, control, transmit,
event, and uni-tracking storage can come from different owners/scopes. The
connection still stores only handles and is constructed with
`RequestStream::with_buffer(...)` / `Connection::with_buffers(...)` /
`BorrowedConnection`.

For production code that wants explicit placement, use `BorrowedConnection` /
`Connection::with_buffers(...)` and keep those buffers in caller-owned
storage instead:

```rust,ignore
use http3_proto::{BorrowedConnection, Client, UniSlot};
use http3_proto::connection::{CTRL_CAP, EVENT_QUEUE_CAP, TX_BYTES_CAP, UNI_TRACKING_CAP};
use http3_proto::stream::HDR_CAP;

let mut request_headers = [0u8; HDR_CAP];
let mut control_payload = [0u8; CTRL_CAP];
let mut tx_bytes = [0u8; TX_BYTES_CAP];
let mut event_slots = [None; EVENT_QUEUE_CAP];
let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];

let mut conn = BorrowedConnection::<Client>::with_buffers(
    &mut request_headers,
    &mut control_payload,
    &mut tx_bytes,
    &mut event_slots,
    &mut uni_slots,
);
```

Borrowed storage does not require `alloc`; it just moves the backing buffers out
of the connection value. Smaller buffers are allowed. A shorter HEADERS,
SETTINGS, event, or inbound-uni buffer lowers that memory bound, and transmit
storage is used in complete slot-sized chunks up to the default queue depth.

## Driver contract

A client MUST NOT send its `:protocol` CONNECT request before it has received the
peer's `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` (RFC 8441 §3 / RFC 9220). The client
flow is therefore two-phase: `start()` sends the control + QPACK setup streams,
and `open_with(...)` sends the CONNECT request **only after** the peer's SETTINGS
have arrived — at which point the opt-in and the peer's `MAX_FIELD_SECTION_SIZE`
are checked synchronously. The driver learns the peer's SETTINGS arrived by
polling `conn.peer_settings().is_some()` after `handle_stream` (there is no
separate event).

The driver loop — simplified, `std` tier:

```rust,ignore
use http3_proto::{Connection, Client, Error, event::{StreamId, StreamRole}};

let mut conn = Connection::<Client>::new();

// 1. start(): enqueue the control stream + the two idle QPACK streams.
conn.start()?;

// 2. Pump poll_transmit — the driver opens each new stream and writes bytes.
while let Some(tx) = conn.poll_transmit() {
    // tx.kind() says Open{Uni,Request} or Existing(id).
    // tx.bytes() is the wire data; tx.fin() says whether to FIN.
    // ... open/write on the QUIC connection ...
    // Report the assigned stream id back:
    // conn.provide_stream(role, StreamId::new(quinn_stream_id));
}

// 3. On each inbound QUIC stream data event:
//    `scratch` is transient Huffman-decode space only: an in-progress HEADERS
//    field section is buffered inside the connection, so this buffer need NOT be
//    preserved across calls — a fresh (even stack-local) buffer per event is
//    fine. It must hold the longest single decoded field line's name+value.
let mut scratch = [0u8; 4096]; // Huffman decode scratch (bare tier: stack)
// Drain `frames` to receive all tunnel DATA in this call. Every supplied
// request-stream byte is validated regardless — dropping the iterator early still
// checks the rest for protocol errors (a forbidden frame makes the connection
// terminal) — but unread tunnel DATA in a call you stop draining is discarded.
let mut frames = conn.handle_stream(stream_id, bytes, &mut scratch)?;
while let Some(frame) = frames.next()? {
    match frame {
        http3_proto::Frame::Response { headers, .. } => {
            // Check headers for :status 200 — tunnel established.
        }
        http3_proto::Frame::Data(chunk) => {
            // Forward chunk to the WebSocket layer.
        }
        _ => {}
    }
}

// 4. Once the peer's SETTINGS have arrived, send the CONNECT request. Call this
//    after each inbound pump until it no longer returns WouldBlock.
if conn.peer_settings().is_some() {
    match conn.open_with(&[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":path", "/"),
        (":authority", "example.com"),
    ]) {
        Ok(()) => { /* request enqueued — pump poll_transmit again */ }
        Err(Error::WouldBlock) => { /* peer SETTINGS not decoded yet; pump + retry */ }
        Err(Error::ExtendedConnectUnsupported) => { /* peer opted out; fall back */ }
        Err(Error::FieldSectionTooLarge) => { /* trim headers under the peer's limit */ }
        Err(Error::Closed) => { /* a prior close()/reset made the connection terminal */ }
        Err(e) => return Err(e),
    }
}

// 5. Drain events.
while let Some(event) = conn.poll_event() { /* ... */ }

// 6. Send tunnel payload.
conn.send_data(b"hello websocket")?;
conn.close();
```

The server is symmetric: `start()` to send setup, then `accept_with(response)`
**only after the peer's `Frame::Request` has been yielded by `handle_stream`**.
Registering the request stream id (`provide_stream`) is not enough — that happens
when the QUIC stream opens, before any HEADERS — so `accept_with` returns
`Error::WouldBlock` until the CONNECT request has actually been decoded. QUIC
streams are also unordered, so the request can arrive before the client's
control-stream SETTINGS; until those SETTINGS are decoded `accept_with` likewise
returns `Error::WouldBlock` (the peer's `MAX_FIELD_SECTION_SIZE` is not yet known),
so the driver pumps more inbound bytes and retries — the same peer-SETTINGS gate
the client's `open_with` applies. The response is sent exactly once: a repeat
`accept_with` after a successful one is a no-op `Ok(())`.

Both send paths are terminal once the connection is closing: after `close()` or a
peer reset (`handle_stream_reset`), `open_with` / `accept_with` return
`Error::Closed` rather than sending. `start()` is likewise idempotent (a second
call is a no-op `Ok(())`, never a duplicate control stream) and terminal once
closing.

### Lifecycle

Internally the connection is a single explicit state machine, moving through the
phases `Created → Handshaking → Open`, plus the terminal `Closing` (graceful local
`close()` / clean peer reset) and `Failed` (a fatal protocol error, surfaced as an
`Event::ConnError`). Every operation's preconditions derive from the current
phase, so the driver-visible contract reduces to:

- **Created**: only `start()` is meaningful; the send paths return `Error::Closed`
  (setup must precede any request / response / DATA).
- **Handshaking**: the SETTINGS exchange and the CONNECT request/response run here.
  `open_with` / `accept_with` are gated as above (`WouldBlock` until ready); the
  tunnel is not yet open, so `send_data` returns `Error::Closed`.
- **Open**: the CONNECT exchange completed (`is_established()` is `true`);
  `send_data` flows, and a repeat `open_with` / `accept_with` is a no-op `Ok(())`.
- **Closing / Failed**: terminal — every send path returns `Error::Closed`. A
  clean peer request-stream FIN at a frame boundary *after* the CONNECT HEADERS is
  a *half-close* (`Event::PeerClosed`) and does **not** make the connection
  terminal, so local sends may continue. A request-stream FIN *before* the
  mandatory CONNECT HEADERS is an incomplete request (`H3_REQUEST_INCOMPLETE`), and
  one mid-frame is `H3_FRAME_ERROR` — both are connection-fatal (`Event::ConnError`,
  terminal), like every connection-fatal inbound error.

### Field-section size

The peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` bounds the *decoded* field-section
size of outbound HEADERS: the sum over every field of its name length + value
length + 32 bytes of per-field overhead (RFC 9114 §4.2.2). The core enforces it
synchronously at send time — `open_with` (client) and `accept_with` (server)
return `Error::FieldSectionTooLarge` when the request/response exceeds the peer's
advertised limit. Our own peers never advertise the setting, so it reads back as
`None` (unlimited) and the check never fires against our own stack.

This is separate from the internal HEADERS accumulator bound (`HDR_CAP` by
default, or the caller-provided request buffer length for `BorrowedConnection`),
which caps the *encoded* inbound HEADERS buffer and fails oversize input
gracefully with `H3_FRAME_ERROR`.

### Control-stream frame handling

After the mandatory SETTINGS frame, the peer's control stream is parsed with a
role-aware policy (RFC 9114 §7.2):

- `DATA` / `HEADERS` / `PUSH_PROMISE` / HTTP/2-reserved types / a second
  `SETTINGS` → `H3_FRAME_UNEXPECTED`.
- `CANCEL_PUSH` → `H3_ID_ERROR`: this crate never enables server push (it never
  sends `MAX_PUSH_ID`), so no push id is ever valid.
- `MAX_PUSH_ID` → `H3_FRAME_UNEXPECTED` for a client (it is client→server only);
  accepted-and-skipped for a server (valid; we simply never push).
- `GOAWAY` → **accepted and ignored** (v1 limitation): graceful connection
  shutdown is not modeled by this tunnel core. The frame is parsed and its
  payload skipped; the driver is not notified.
- GREASE / unknown extension frames → skipped (RFC 9114 §9).

The peer's SETTINGS payload is buffered into a no-alloc bound (`CTRL_CAP` = 1024
bytes by default, or the caller-provided control buffer length for
`BorrowedConnection`) before decoding. The default is generous enough to hold many
settings plus unknown/GREASE extension settings (RFC 9114 §7.2.4.1), so a
conforming peer is never rejected for carrying GREASE. A SETTINGS payload that
exceeds the configured bound is rejected with `H3_EXCESSIVE_LOAD` (an
excessive-load policy — "this SETTINGS frame is too big"), never `H3_FRAME_ERROR`
("malformed") and never a panic.

## Tiers

| Cargo features | Heap | Target example |
|---|---|---|
| `default` (`std`) | yes | any std platform |
| `alloc` | yes (no `std`) | WASM, embedded with allocator |
| _(none)_ | **no** | `thumbv6m-none-eabi`, `thumbv7em-none-eabihf` |

## Conformance

A [`no-panic`] link-time test (`tests/no_panic.rs`) proves that varint decode
and frame header decode compile to panic-free code in release — they are
`#[inline]`, so they fully inline into their shims where `no-panic` can verify
the whole body at link time. QPACK field-section decode is covered by the
crate-wide clippy panic-freedom lint wall (`unwrap_used` / `indexing_slicing` /
`arithmetic_side_effects` / …) and fuzzing rather than the link-time check,
because its call-tree depth prevents full inlining into a single shim across
the crate boundary.

Four fuzz targets under `fuzz/fuzz_targets/` cover the same paths plus the
full `Connection` receive machine with arbitrary byte streams.

## MSRV

Rust 1.91.0. The MSRV may be raised in a minor release.

## License

`http3-proto` is under the terms of both the MIT license and the Apache
License (Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[`no-panic`]: https://docs.rs/no-panic
[Github-url]: https://github.com/al8n/websockit/
[CI-url]: https://github.com/al8n/websockit/actions/workflows/ci.yml
[doc-url]: https://docs.rs/http3-proto
[crates-url]: https://crates.io/crates/http3-proto
