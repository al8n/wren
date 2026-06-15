# UNRELEASED

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
