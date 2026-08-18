# Changelog

## 0.1.0 (unreleased)

First release: a Sans-I/O HTTP/1.1 message and connection core (RFC 9110 /
RFC 9112), `no_std` + no-alloc capable, with no buffer, clock, or allocator of
its own.

### Codec leaves

- **Grammar** (`grammar`): RFC 9110 §5.6 `token` and `field-value` over raw
  bytes — `field-vchar = VCHAR / obs-text` with interior SP/HTAB, OWS-trimmed,
  CTLs rejected — plus the RFC 3986 request-target validators and the §5.6.1
  list-element splitter.
- **Parameterised lists** (`grammar::parameterised_list`): a borrowing walk of a
  §5.6.6 parameterised `#`-list across ALL of a field's lines, which §5.2 makes
  one comma-joined value. Splits only on the commas and semicolons OUTSIDE a
  §5.6.4 quoted-string, skips §5.6.1.2's empty elements, and crosses the join
  through the same `scan_quoted_after_join` the `Expect` parser uses — so a
  string opened on one field line continues into the next instead of being
  called unterminated. The one value such a walk cannot hand over is a
  quoted-string that spans the join, since its content is not one slice: the
  member's boundaries stay correct across it, and reading THAT value reports
  `ListError::ValueSpansFieldLines` rather than mis-slicing it.
- **Start lines** (`head::request_line`, `head::status_line`): RFC 9112 §3
  `request-line` with all four §3.2 target forms (origin / absolute / authority /
  asterisk) and §4 `status-line`. Single-SP separators only; the lenient
  whitespace-boundary parse is a named smuggling vector and is not taken.
  `HTTP-version` is case-sensitive (RFC 9112 §2.3), a higher 1.x minor is
  processed as 1.1 (RFC 9110 §6.2), and any other major is `505` rather than
  malformed.
- **Head scanner** (`head::scan`): a **resumable** bounded scan — it carries a
  watermark instead of restarting, so a head arriving one byte at a time costs
  O(N) rather than O(N²). Caps: `MAX_HEAD_BYTES = 16384`, `MAX_HEADERS = 64`,
  `MAX_LEADING_EMPTY_LINES = 4`. A cap breach distinguishes an over-long
  request-line (`414`) from an over-large field section (`431`). The empty-line
  cap binds BOTH roles: a server's leading empty lines (RFC 9112 §2.2) are never
  consumed, so one scan of the growing region sees them all; an idle client's
  discarded ones (§9.2) ARE consumed, so the connection carries a cumulative
  tally instead — cleared by `open_request`, since the allowance is per idle
  period.
- **Lazy head view** (`head::view`): `HeadView` walks field lines out of the
  borrowed block on demand — no table, no copies — with case-insensitive
  lookup, repeated-line iteration, and the field count the scan recorded.
  `request_line()` reads the §3 request-line back out of the same block, so a
  consumer that needs the method, the request-target or the version gets what the
  ONE §3 codec in this crate produced rather than a second reading of the same
  bytes. It is `None` on a response head, whose start line is the §4 status-line.
- **Encoders** (`head::encode`, `body::encode`): validated request/status heads
  and chunk framing written into a caller-supplied slice, with exact sizing,
  no partial writes on a short buffer, and refusal of any field a parser would
  reject (CRLF injection is impossible by construction).

### Semantics

- **`validate`**: the RFC 9112 §3.2 `Host` rule (exactly one, valid
  `uri-host[:port]`, required on 1.1 requests, an empty value accepted),
  `Content-Length` and `Transfer-Encoding` validation, method/target pairing,
  and the connection directives a head carries.
- **RFC 9112 §6.3 body framing** implemented branch-for-branch **in its stated
  order**: bodiless statuses and HEAD responses and CONNECT 2xx resolve before
  any CL/TE inspection; then chunked, then `Content-Length`, then
  read-to-close for a response, then zero-length for a request.
- Every framing ambiguity is a hard error rather than a guess: TE beside CL,
  differing `Content-Length` values, `chunked` non-final in a request. An
  identical comma-repeated `Content-Length` is processed as that single value
  (the exception §6.3 item 5 carves out).
- The **sender** rules bind at every status, item 1's bodiless responses
  included: §6.2's "a sender MUST NOT send a Content-Length header field in any
  message that contains a Transfer-Encoding header field" is unconditional, and
  §8.6's `1*DIGIT` is what a length has to be. Item 1 tells a RECIPIENT to
  ignore those fields; it is not a licence for this end to write a pair of them
  or an unreadable one. A single well-formed `Content-Length` on a HEAD response
  or a 304 stays legal — that is item 1's own case.
- §3.2's `Host` is enforced **in both directions**. Every outbound request path
  — `open_request`, and Tunnel's `open_upgrade` / `open_connect`, CONNECT
  included, since §3.2.3's authority-form target is an addressing rule and not
  an exemption — refuses a field section that states no `Host`, and writes
  nothing. Presence is the whole check: an empty value is the field §3.2
  requires when the target authority is undefined, and naming the right
  authority stays the caller's.

### Bodies

- **`body`**: counted, read-to-close, and none, plus a strict **chunked**
  decoder (RFC 9112 §7.1) — `1*HEXDIG` chunk-size with an overflow guard, no
  whitespace after the size, `1*("0")` last-chunk, grammar-checked `chunk-ext`
  under a 256-byte per-line cap, and a trailer section surfaced as its own items
  and never merged into the header section.

### Connection

- **Compile-time type-state**: `Connection<Client | Server, General | Tunnel>`.
  The mode is a type parameter, not a runtime flag, so asking a General
  connection to switch protocols (or a Tunnel connection to stream exchanges)
  does not compile.
- **General mode**: `handle(input) -> Items` yields borrowed
  `Item::{Head, BodyChunk, Trailer, ExchangeComplete, ExpectContinue}`, each
  naming its `ExchangeId`; `Items::consumed()` is the driver's cursor. Keep-alive
  re-arm, inbound pipelining tolerance (RFC 9112 §9.3.2 holds the next request
  unconsumed until the response is written), 1xx interim responses,
  `Expect: 100-continue`, HTTP/1.0 fallback, close-delimited responses, and
  RFC 9112 §9.6 draining.
- **Readiness split**: `wants_read()` and `is_awaiting_send()` are disjoint
  answers to "why did the items run out?" — `Ok(None)` alone cannot say whether
  to read the socket or to write to it.
- **Send side**: `open_request`, `send_response`, `send_interim`, `send_body`,
  `finish_body`, and `send_error_response` — the single RFC-mandated
  400-then-close answer owed after a violation, which injects the `close`
  connection option, refuses a caller `Connection` field that would contradict
  it, and refuses the whole 1xx and 2xx classes: a phase whose meaning is "a
  rejection is owed" has no success to state (Tunnel's `reject` applies the same
  rule while a rejection is owed). A 3xx is legal — a redirect refuses the
  request as it was put.
- `finish_body` refuses four field names in a trailer section —
  `Content-Length`, `Transfer-Encoding`, `Host`, `Trailer` — per RFC 9110
  §6.5.1's sender MUST NOT. A narrow list on purpose: which other definitions
  permit a trailer is a registry question for the layer that knows the message.
- An inbound **close-delimited** response (§6.3 item 8) signals the end of
  keep-alive at its HEAD, not at the EOF: §9.3 makes a connection carrying a
  message with no self-defined length non-persistent, so `Event::CloseSignaled`
  reaches the driver before it plans a second request.
- **Tunnel mode**: one protocol switch, RFC 9110 §7.8 `Upgrade` or §9.3.6
  `CONNECT`, at either end. Every outcome that CONSUMED a head reports the
  **leftover** — the suffix of the offer belonging to the new protocol, or to the
  head that follows an interim — and carries the start line this core parsed;
  `Refused` is terminal and reports none. A 100 is enforced before a 101 when
  both were asked for, and `owes_continue()` reports that obligation so a caller
  discharges it through `send_interim` instead of re-deriving it from `Expect`.
  A handshake head may carry `Content-Length: 0`: it announces no octets (RFC
  9110 §8.6), so both directions of this crate write and classify it.
- **Mode edges**: `Connection::<Server, General>::into_tunnel` answers an upgrade
  request the General pump has ALREADY read. RFC 9110 §7.8 makes the switch an
  answer and permits it only once the client "has completely sent the request
  message", so the edge runs after the read rather than instead of it — which is
  also why an upgrade request carrying CONTENT is switchable here and is not on
  the native path: General has drained the body by then. It lands the connection
  where `handle_request` leaves one, so `accept` writes the 101.
- `Connection::<Client, General>::into_tunnel` is the other edge: it spends an
  IDLE pooled connection on a handshake — a decision this end takes rather than
  an answer it owes, so what it gates on is that nothing is outstanding. Both
  edges are consuming, since the General state has no meaning past the switch,
  and both hand the connection back beside a refusal
  (`Err((Self, TransitionRefused))`): a switch that cannot be taken is a reason
  to answer differently, not a reason to lose the ability to answer at all.
- `TransitionRefused` names ONE gate rather than reporting a set. The gates are
  checked in a FIXED order, several of them fail together on the same connection
  — a peer that stated `close` moved the lifecycle and queued a notice in the
  same step — and a caller told a different reason on different runs could act on
  none of them. Branch by comparing against the named constants; `reason()` and
  `Display` write the same string for a log line.
- **Head binding**: `Connection::<Server, Tunnel>::head_binding` answers whether
  a head the caller is holding is the head that armed this connection's
  handshake — the identity no signature can state, since `into_tunnel` CONSUMES
  the connection a lifetime brand would be tied to while the head outlives it,
  and the transition resets the exchange counter so `ExchangeId` cannot say it
  either. `HeadBinding` has three answers rather than two: `Matches`; `Mismatch`
  for a live handshake this head did not arm, RFC 9110 §9.3.6's CONNECT among
  them, since it made no §7.8 offer for any head to be; and `NoHandshake` for a
  connection holding no handshake at all, which is what keeps a throwaway
  `Connection::new()` usable for validating a head BEFORE spending the one-way
  transition. `Matches` is FNV-1a digest equality over the whole head block,
  computed only for a request that offered a switch, so an ordinary request pays
  nothing for it. It refuses an accidental mispairing and is NOT a security
  boundary: head content is peer-controlled and a colliding pair is
  constructible offline.
- **Public enums**: `Item`, `StartLine`, `Event`, `ClientTunnelOutcome` and
  `ServerTunnelRequest` are `#[non_exhaustive]` — they are what this core chooses
  to surface, and that can grow. `Target`, `BodyPlan` and `BodyFraming` are NOT:
  the RFCs close those sets, so a consumer may match them exhaustively. Nor is
  `HeadBinding`, whose three answers are closed by the question rather than by a
  spec: a head either armed this connection's handshake, did not, or has no
  handshake to have armed.
- **Errors**: every protocol violation carries a byte offset
  (`MalformedDetail { at, what }`) and, where a server would answer, a
  `SuggestedStatus` (400 / 414 / 431 / 501 / 505).

### Tiers

| Cargo features | Heap | Target |
|---|---|---|
| `default` (`std`) | yes | any std platform |
| `alloc` | yes (no `std`) | WASM, embedded with allocator |
| `no-atomic` | yes (no `std`, no atomic CAS) | `thumbv6m-none-eabi` |
| _(none)_ | **no** | `thumbv6m-none-eabi`, `thumbv7em-none-eabihf` |

`Connection<Role, Mode>` is const-asserted at ≤ 256 bytes and `HeadView` at
≤ 128, unconditionally — so the bound is checked on every target, including the
32-bit `usize` ones.

### Tooling

- **no-panic link test** (`tests/no_panic.rs`): `#[no_panic]` shims prove
  `find_head_end`, `parse_status_line`, `parse_chunk_size` and
  `parameterised_list` compile to panic-free code at link time, plus four
  release smokes over the deeper paths.
  Requires `--release` **and fat LTO** (`CARGO_PROFILE_RELEASE_LTO=fat`) — the
  shims call across the crate boundary, so without it every one false-positives.
  Every argument goes through `core::hint::black_box`: a shim called with
  compile-time constants is folded away before the guard can act, and proves
  nothing. The internal `test-no-panic-lie` feature adds a shim with a reachable
  panic whose build CI asserts must FAIL, which is what keeps that honest.
- **httparse differential oracle** (`tests/differential.rs`): we are never more
  permissive than `httparse`; every stricter refusal and every looser acceptance
  is adjudicated in-file with its RFC citation, and the allowlists are checked
  for stale entries. A second, independent comparison over the same corpus checks
  where each parser says a head ENDS — `Status::Complete(n)` against
  `Items::consumed` — since two recipients that accept the same head but cut it
  in different places have already disagreed about where the body begins.
- **Request-smuggling corpus**, both directions. `tests/smuggling.rs` drives
  each named inbound vector end to end with both its accept and its reject side,
  pinning the EXACT refusal — the `H1Error` variant and its payload — rather than
  the error class. `tests/smuggling_outbound.rs` is the mirror: for every send
  entry point, the head/plan combinations that must be refused, each asserting
  the exact refusal and that the call left the buffer and the connection
  untouched. RFC 9112 §11.1/§11.2 are about two recipients disagreeing, and
  nothing in that says the disagreement has to be the peer's fault.
- **Split-robustness property** (`tests/split_robustness.rs`): where the
  transport cut the stream cannot change what the connection says about it —
  one shot, byte-at-a-time, every single cut, and proptest multi-cut vectors,
  over a corpus covering every inbound shape, each entry carrying an absolute
  golden pin as well as the equality (an entry mis-read identically in every feed
  shape satisfies an equality). Includes the linearity probe that pins the head
  scan as resuming rather than restarting — asserted on CI too, at a looser
  margin, since a lost watermark makes the two halves EQUAL and no margin above
  1 tolerates that.
- **The suite** is one default-profile `cargo test -p http1-proto` run: the lib
  unit tests, all five integration targets (`differential`, `no_panic`,
  `smuggling`, `smuggling_outbound`, `split_robustness`), and the doc-tests,
  including the compile-fail ones. Green on every tier and on `cargo hack test
  --each-feature`. The bare `no_std` tier runs the same set minus the `no_panic`
  shims, which need `std`, and minus the heap-gated lib tests.
  No total is quoted, deliberately. A count is invalidated by every commit that
  adds a test, nothing in CI checks it, and the figures this entry used to carry
  went stale TWICE inside one PR — the second time because a doc-test was added
  to `README.md`, which is not even a file a reader would think to re-measure
  after. Naming the targets is the part that stays true; for the number as of any
  given commit, run `cargo test -p http1-proto --all-features` (or
  `--no-default-features` for the bare tier) at it.
