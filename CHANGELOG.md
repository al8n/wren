# UNRELEASED

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
  offer/accept.
- RFC 8441 / RFC 9220 negotiation surfaces (the header-data form of the same
  negotiation for WebSocket over HTTP/2 and HTTP/3).

### Tiers, assembly & tooling

- `alloc`-tier `MessageAssembler` folding events into owned `Message::{Text,
  Binary}`, carrying cheap-clone (`O(1)`) payloads — `smol_str::SmolStr` text and
  `bytes::Bytes` binary, exposed as the public `TextBuf` / `BinaryBuf` aliases;
  bare `no_std` (no-alloc) and `heapless` tiers supported.
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
