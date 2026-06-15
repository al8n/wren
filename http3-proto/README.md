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

## Driver contract

The driver loop — simplified, `std` tier:

```rust,ignore
use http3_proto::{Connection, Client, event::{StreamId, StreamRole}};

let mut conn = Connection::<Client>::new();

// 1. Open the tunnel: enqueues control stream, QPACK streams, HEADERS.
conn.open_with(&[
    (":method", "CONNECT"),
    (":protocol", "websocket"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "example.com"),
])?;

// 2. Pump poll_transmit — the driver opens each new stream and writes bytes.
while let Some(tx) = conn.poll_transmit() {
    // tx.kind() says Open{Uni,Request} or Existing(id).
    // tx.bytes() is the wire data; tx.fin() says whether to FIN.
    // ... open/write on the QUIC connection ...
    // Report the assigned stream id back:
    // conn.provide_stream(role, StreamId::new(quinn_stream_id));
}

// 3. On each inbound QUIC stream data event:
let mut scratch = [0u8; 4096]; // Huffman decode scratch (bare tier: stack)
let mut frames = conn.handle_stream(stream_id, bytes, &mut scratch)?;
while let Some(frame) = frames.next()? {
    match frame {
        http3_proto::Frame::Response(hs) => {
            // Check hs for :status 200 — tunnel established.
        }
        http3_proto::Frame::Data(chunk) => {
            // Forward chunk to the WebSocket layer.
        }
        _ => {}
    }
}

// 4. Drain events.
while let Some(event) = conn.poll_event() { /* ... */ }

// 5. Send tunnel payload.
conn.send_data(b"hello websocket")?;
conn.close();
```

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
