# UNRELEASED

## `http1-proto` — cycle 5 (Sans-I/O HTTP/1.1 core)

A hand-rolled Sans-I/O HTTP/1.1 message and connection core — no_std +
no-alloc capable, with no buffer, clock, or allocator of its own. PR1 of the
cycle: the standalone crate. PR2 re-bases `websocket-proto`'s h1 handshake onto
it.

### What it is

- **Scope**: RFC 9110 / RFC 9112 as a complete message and connection layer —
  grammar, both start lines, a resumable bounded head scanner, the §6.3 body
  framing decision list, counted / chunked / read-to-close bodies, validated
  encoders, and a connection state machine for both roles. Not a router, a URI
  resolver, a cache, or a content codec: it reports what the message says and
  refuses what the RFCs make unframable.

### Codec leaves (panic-free)

- **Grammar** (RFC 9110 §5.6): `token` / `field-value` over raw bytes
  (`field-vchar = VCHAR / obs-text`, interior SP/HTAB, OWS-trimmed, CTLs
  rejected), the RFC 3986 target validators, and the §5.6.1 list splitter.
- **Start lines** (RFC 9112 §3, §4): all four §3.2 request-target forms with
  method pairing; single-SP separators only; case-sensitive `HTTP-version`,
  higher 1.x minor processed as 1.1 (RFC 9110 §6.2), other majors → 505.
- **Head scanner** (RFC 9112 §2.1, §5): **resumable** — it carries a watermark
  rather than restarting, so a head arriving one byte at a time is O(N) not
  O(N²). `MAX_HEAD_BYTES = 16384`, `MAX_HEADERS = 64`, and at most 4 leading
  empty lines server-side; an over-long request-line is 414, an over-large
  field section 431.
- **Lazy head view**: fields walked out of the borrowed block on demand — no
  table, no copies — with case-insensitive lookup and repeated-line iteration.
- **Chunked** (RFC 9112 §7.1): overflow-guarded `1*HEXDIG` size, no whitespace
  after it, `1*("0")` last-chunk, grammar-checked `chunk-ext` under a 256-byte
  per-line cap, trailer section surfaced separately and never merged.
- **Encoders**: heads and chunk framing written into a caller slice with exact
  sizing, no partial writes, and refusal of anything a parser would reject.

### Connection state machine

- `Connection<Client | Server, General | Tunnel>`: the mode is a **compile-time
  type-state**, not a runtime flag — a General connection cannot be asked to
  switch protocols, and a Tunnel connection cannot be asked to stream
  exchanges.
- **General**: `handle(input) -> Items` lends borrowed
  `Item::{Head, BodyChunk, Trailer, ExchangeComplete, ExpectContinue}` naming
  their `ExchangeId`; the core holds no buffer, so `Items::consumed()` is the
  driver's cursor into its own append-only accumulation. Keep-alive re-arm,
  pipelining tolerance (RFC 9112 §9.3.2), 1xx interim, `Expect: 100-continue`,
  HTTP/1.0 fallback, close-delimited responses, §9.6 draining.
- **Readiness split**: `wants_read()` / `is_awaiting_send()` — the two disjoint
  answers to why the items ran out, which `Ok(None)` alone cannot give.
- **Send side**: `open_request`, `send_response`, `send_interim`, `send_body`,
  `finish_body`, and the single RFC-mandated `send_error_response` owed after a
  violation (injects `close`, refuses a contradicting caller field). RFC 9112
  §3.2's `Host` is enforced outbound as well as inbound: every request path
  (CONNECT included) refuses a section that states none, and writes nothing.
- **Tunnel**: one switch — RFC 9110 §7.8 `Upgrade` or §9.3.6 `CONNECT`, at
  either end — reporting the **leftover** that belongs to the new protocol, and
  enforcing a 100 before a 101 when both were asked for.
- **Errors**: a byte offset on every violation and a `SuggestedStatus`
  (400 / 414 / 431 / 501 / 505) wherever a server would answer.

### Tiers

| Cargo features | Heap | Target |
|---|---|---|
| `default` (`std`) | yes | any std platform |
| `alloc` | yes | WASM, embedded with allocator |
| `no-atomic` | yes (no atomic CAS) | `thumbv6m-none-eabi` |
| _(none)_ | **no** | `thumbv6m-none-eabi`, `thumbv7em-none-eabihf` |

### Tooling

- **no-panic link test** (`tests/no_panic.rs`): shims over `find_head_end`,
  `parse_status_line` and `parse_chunk_size`, plus four release smokes.
  Requires `--release` **and fat LTO** — the shims call across the crate
  boundary, so the default thin-local LTO false-positives on all of them; CI
  sets `CARGO_PROFILE_RELEASE_LTO=fat` on that step.
- **httparse differential oracle** (`tests/differential.rs`): never more
  permissive than `httparse`; every divergence adjudicated in-file and the
  allowlists checked for stale entries.
- **Request-smuggling corpus** (`tests/smuggling.rs`): each named vector, accept
  and reject side.
- **Split-robustness property** (`tests/split_robustness.rs`): where the
  transport cut the stream cannot change what the connection says about it, over
  one shot / byte-at-a-time / every single cut / proptest multi-cut vectors.
- **254 tests** at `--all-features`, green on every tier and under
  `cargo hack test --each-feature`.

## `http3-proto` — cycle 4 (Sans-I/O HTTP/3 tunnel core)

A novel hand-rolled Sans-I/O HTTP/3 Extended-CONNECT tunnel core for Rust —
no_std + no-alloc capable, zero external runtime dependencies on the bare tier.

### What it is

- **Scope**: the RFC 9114 / 9204 / 9220 subset needed to carry a tunneled byte
  stream (WebSocket or arbitrary protocol) over QUIC — not a general HTTP/3
  implementation. The core stays HTTP-status-agnostic and WebSocket-agnostic: it
  reports the peer's HEADERS as `Frame::Request` / `Frame::Response` and leaves
  validation of `:status` / `:protocol` to the driver.

### Codec leaves (panic-free, fuzzed)

- **QUIC varint** (RFC 9000 §16): 1/2/4/8-byte encode/decode with zero
  arithmetic side-effects.
- **HTTP/3 frame header** (RFC 9114 §7.1): type + length varint pairs;
  `decode_header` / `encode_header`.
- **Static-table-only QPACK** (RFC 9204): field-section encode/decode with the
  dynamic table permanently disabled (matching the WS-tunnel scope). `decode_field_section_into` (no-alloc, caller scratch) and `decode_field_section`
  (std/alloc, owned scratch). A lending iterator yields `Pair { name, value }`
  per call with raw/static borrows or Huffman decoding into the scratch.
- **SETTINGS codec** (RFC 9114 §7.2.4, RFC 9204 §5, RFC 9220 §3): encode/decode
  the small SETTINGS payload carried on the control stream preamble.

### Connection state machine

- `Connection<Client>` / `Connection<Server>`: Sans-I/O state machine generic
  over the role marker. No I/O, no clocks, no async.
- **Setup**: `open_with` (client) / `start` (server) enqueue the control stream
  (type byte + SETTINGS frame), two idle QPACK uni-streams (encoder + decoder),
  and (client only) the bidirectional request stream with the CONNECT HEADERS
  frame. The driver pumps `poll_transmit` and opens the streams, reporting each
  assigned id via `provide_stream`.
- **Receive**: `handle_stream(id, bytes, scratch)` routes inbound bytes by
  stream id — control stream (accumulate + parse SETTINGS), QPACK streams (idle
  after type byte), unknown uni-streams (classify by leading type varint,
  buffered across calls), or request stream (HEADERS decode + DATA relay). The
  request stream yields a lending `Frames` iterator; all other streams yield
  nothing.
- **Events**: `poll_event` drains `Event::{Established, PeerClosed, Reset,
  ConnError}` from a fixed-capacity bounded queue (no heap).
- **Transmit ring**: a fixed-capacity, no-alloc ring buffer carries outbound
  transmit slots. `poll_transmit` lends `Transmit { kind, bytes, fin }` one
  at a time; `StreamKind::{OpenUni, OpenRequest, Existing}` tells the driver
  which quinn call to make.
- **Tunnel data + close**: `send_data(payload)` encodes a DATA frame; `close`
  enqueues a FIN on the request stream.

### Tiers

| Cargo features | Heap | Target |
|---|---|---|
| `default` (`std`) | yes | any std platform |
| `alloc` | yes | WASM, embedded with allocator |
| _(none)_ | **no** | `thumbv6m-none-eabi`, `thumbv7em-none-eabihf` |

### Tooling

- **no-panic link test** (`tests/no_panic.rs`): wraps `varint::decode` and
  `frame::decode_header` in `#[no_panic]` shims and verifies panic-freedom at
  link time in release (they are `#[inline]`, so they inline fully into the
  shim where `no-panic` can see them). `qpack::decode_field_section_into`
  panic-freedom is enforced by the crate-wide clippy lint wall
  (`unwrap_used` / `indexing_slicing` / `arithmetic_side_effects` / …) +
  fuzzing — its call-tree depth prevents full inlining into a single shim.
  Enabled via `--features test-no-panic`.
- **Fuzz harnesses** (`fuzz/fuzz_targets/`): four targets —
  `varint_decode`, `frame_decode`, `qpack_decode`, `connection_handle` —
  covering all codec leaf paths and the full connection receive machine with
  arbitrary byte streams.
- **Bare-tier smoke test** (`tests/tiers.rs`): four tests run under
  `--no-default-features` proving the bare tier needs no allocator:
  `open_with` + drain, varint round-trip, frame decode, QPACK decode-into.
- **100 unit + integration tests** across all features (from prior cycles).

## `wren-reactor` — cycle 3 (runtime-agnostic full-duplex driver)

- **`wren-reactor`**: readiness-based WebSocket driver over `websocket-proto`,
  runtime-agnostic across **tokio and smol** (feature-selected) via
  `agnostic-net` / `agnostic-lite`. Client (`connect` over `ws://` / `wss://`,
  or `client` over any `futures::io` stream) and server (`accept`, plus the
  two-step `accept_pending` → inspect → `accept` / `reject` for pre-upgrade
  authorization). **Caller-driven, no background tasks** (tungstenite / soketto
  parity): `WebSocket<R, Ro, S>` owns the proto state machine and the transport
  and implements `futures::Stream` / `Sink` plus convenience methods
  (`send_text`, `send_binary`, `ping`, `close`, the `*_compressed` sends);
  polling `next()` / the `Sink` *is* the pump — it drives pong echoes and the
  close handshake. `split()` yields independently-owned read and write halves
  sharing the connection through a mutex held only across brief, non-blocking
  poll steps and never across a pending I/O, so a stalled write releases the lock
  and reads never head-of-line-block behind it (the limitation `wren-compio`'s
  single pump documented). A single ordered write buffer carries data, pongs, and
  the Close in FIFO order, so a close never overtakes queued data. Sends are
  cancellation-safe (a dropped send never leaves a partial frame and still
  backpressures the next). The write buffer applies *inter-message* backpressure
  (a send waits for it to fall below a soft cap before encoding the next frame, and
  the read pump stops reading while a stalled flush has it over the cap, so neither a
  flooding nor a slow peer grows it without bound); a single message still allocates
  its whole frame, so bound an individual outbound payload caller-side if needed.
  **Liveness, write deadlines, and the close handshake
  are the caller's** — the library is a state machine, not a supervisor, with no
  autonomous timers: bound them with `timeout(next())`, `timeout(send())`,
  `timeout(close())`, a ping loop, or OS TCP keepalive. A send not yet flushed
  when `close` is issued is not guaranteed delivered; await it (or flush) before
  closing. A recorded transport write error poisons the connection and surfaces
  as the real `Io` error on every send path; a peer protocol violation fails the
  connection fast and surfaces as `Error::Protocol(CloseCode)` carrying the code,
  distinct from a transport reset. Features: `tokio` (default), `smol`,
  `tls` (futures-rustls + rustls/ring, webpki roots by default, full
  `TlsConnector` override), `deflate`, `tracing`.

## `wren-compio` + `wren-trace` — cycle 2 (first async driver)

- **`wren-compio`**: compio-native (io_uring / IOCP / kqueue, thread-per-core)
  WebSocket driver over `websocket-proto`. Client (`connect` over `ws://` /
  `wss://`, or `client` over any `IntoDuplex` transport) and server
  (`accept`, plus the two-step `accept_pending` → inspect → `accept` /
  `reject` for pre-upgrade authorization by Origin, Host, path, or auth).
  One direct connection object — no background task: `next()` pumps reads,
  keepalive/close timers, pong echoes, and queued writes. `split()` yields
  read/write halves for ANY stream type (no `Clone` bound) via a
  doorbell-flushed outbound queue; a split writer's sends progress while
  the read half is polled. `next()` and the senders are cancellation-safe:
  the driver runs on a poll-based duplex (completion streams adapt through
  `compio_io::compat::AsyncStream`), so dropping a pump or send future
  mid-await — a caller `timeout` or lost `select!` arm — neither loses
  inbound bytes nor strands the transport, and partial write progress
  resumes on the next call. The close handshake is fully bounded by the
  close timeout (flush, echo wait counted from the flush, and transport
  shutdown each get the budget), protocol replies flush before buffered
  messages are delivered, a peer close only reads as clean once our echo
  is on the wire, and the first write failure poisons the connection
  instead of splicing frames after a partial one. Features: `tls`
  (compio-tls + rustls/ring, webpki roots by default, full `TlsConnector`
  override), `deflate` (transparent inflate on receive,
  `send_*_compressed` senders), `tracing`.
- **`wren-trace`**: the family's zero-cost tracing shim — `tracing`-or-noop
  diagnostic and span macros whose disabled form type-checks but never
  evaluates its arguments.

## `websocket-proto` — cycle 1 (Sans-I/O core)

The first functional cycle of the Sans-I/O WebSocket protocol core. Highlights:

### Framing & connection (RFC 6455)

- Lossless §5.2 frame codec: incremental header decode/encode with canonical
  length enforcement, and in-place payload masking (§5.3).
- Transport-blind `Connection` state machine for both roles (`Client`/`Server`),
  generic over a monotonic `Instant` clock. Receive is a **lending iterator**
  (`handle` → `Events::next`): uncompressed payload chunks borrow the input with
  no copy; protocol-generated frames (pong/close echoes, keepalive pings) are
  queued internally and drained via `poll_transmit`.
- Incremental UTF-8 validation across `handle` calls (§8.1), fragmentation
  sequencing, the close handshake with code/reason validation and a close-timeout
  state, and keepalive pings. Protocol violations fail the connection with the
  prescribed close code rather than returning errors.

### permessage-deflate (RFC 7692)

- Inflate inbound compressed messages inside `Connection`; compressed messages
  surface as ordinary decoded text/binary chunks (text re-validated as UTF-8
  post-inflation). Context takeover, negotiated window bits, and an inflated-size
  cap (1009) are honoured; malformed DEFLATE fails 1007.
- Opt-in `encode_text_compressed` / `encode_binary_compressed` with RSV1, the
  §7.2.1 sync-flush tail stripped, per-message reset under `no_context_takeover`,
  and a graceful `CompressionUnavailable` fallback when deflate is not negotiated
  or the outbound window is below 15 bits.

### Handshakes & negotiation

- HTTP/1.1 opening handshake for both roles (RFC 6455 §4): stateless re-parsing
  request/response validators, subprotocol selection, and permessage-deflate
  offer/accept. Caller-supplied extra headers are passed as an `ExtraHeaders`
  newtype (`ClientOptions` / `Accept` / `Rejection`), with shared token + CR/LF
  validation; the client additionally rejects names that collide with the
  headers it manages.
- RFC 8441 / RFC 9220 negotiation surfaces (the header-data form of the same
  negotiation for WebSocket over HTTP/2 and HTTP/3).

### Tiers, assembly & tooling

- `alloc`-tier `MessageAssembler` folding events into owned `Message::{Text,
  Binary}`, carrying cheap-clone (`O(1)`) payloads — `smol_str::SmolStr` text and
  `bytes::Bytes` binary, exposed as the public `TextBuf` / `BinaryBuf` aliases;
  bare `no_std` (no-alloc) tier supported — the inline subprotocol storage retains negotiation results without any allocator.
- Allocator-free `SliceAssembler` on **every** tier (including bare `no_std`):
  folds events into a caller-provided buffer and yields a borrowed `MessageRef`
  (`Text` / `Binary`); the buffer length is the message-size cap.
- `no-atomic` heap tier for cores without native atomic CAS (Cortex-M0+ /
  thumbv6m / RP2040): the same `Message` / `Negotiated` storage as `alloc`, but
  the refcounted text / binary buffers and negotiated subprotocol use
  `portable_atomic_util::Arc` (clone via a `critical-section` impl the final
  binary provides) instead of `smol_str` + `bytes`. Pick one heap tier; `deflate`
  is not available on this tier (it requires `alloc`). Checked on
  `thumbv6m-none-eabi` in CI.
- Autobahn TestSuite harnesses (`examples/autobahn-server`,
  `examples/autobahn-client`) and an opt-in `autobahn` CI workflow; sections 1–9
  and the §12/§13 permessage-deflate cases pass.
- `no-panic` link-time verification of the core codec leaf paths (frame
  decode/encode, masking, UTF-8, base64), alongside the crate-wide clippy
  panic-freedom lint wall.

### Fixes landed this cycle

- permessage-deflate compressed sends of large/incompressible payloads were
  silently truncated (and corrupted the context-takeover stream for every
  following message) because the compressor's buffered output and sync-flush were
  drained into a fixed, too-small window. The compressor now drains to
  completion; verified against an independent reference decoder and Autobahn
  §12/§13.
- Multiple pings arriving in one `handle` batch now each receive a pong where a
  heap is available (Autobahn 2.10); the bare tier still coalesces to the most
  recent ping (RFC 6455 §5.5.3).
