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
  included: §6.2's "MUST NOT send a Content-Length header field in any message
  that contains a Transfer-Encoding header field" is unconditional, and
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

- **The inbound body is BOUNDED**, per message and in payload octets, and a
  breach is a POLICY REFUSAL rather than a protocol failure. It was the only
  unbounded quantity this core handled: a consumer that needed a whole body
  accumulated the chunks itself and nothing bounded that accumulation, so the
  crate handed its consumers a denial-of-service surface. No RFC supplies a
  number — RFC 9110 §8.6: "there is no predefined limit to the length of
  content" — and §17.5 sanctions the rejection while declining the value, so the
  ceiling is configurable and its defaults are named `DEFAULT_`.
  - **`Limits`**, seeded from the connection type being built:
    `Connection::<Ro, Mo>::default_limits()`, narrowed with
    `with_max_body_bytes` / `with_max_chunk_framing_bytes`, read back with
    `max_body_bytes()` / `max_chunk_framing_bytes()`, and applied with
    `Connection::with_limits`. `Connection::new()` is
    `with_limits(default_limits())`. The ceiling is written once, at
    construction: there is no setter and no `&mut` path, and it reaches the
    receive pump by value.
  - **Role-dependent defaults** on the sealed `Role` trait.
    `Server::DEFAULT_MAX_BODY_BYTES` is 1 MiB — nginx's own
    `client_max_body_size 1m`, and exactly `MAX_HEAD_BYTES × MAX_HEADERS`.
    `Client::DEFAULT_MAX_BODY_BYTES` is 64 MiB, because RFC 9112 §6.3 item 8's
    undeclared close-delimited framing is response-only and is where a real
    ceiling has to exist; it matches `websocket-proto`'s `max_message_size`
    default. `DEFAULT_MAX_CHUNK_FRAMING_BYTES` is a sixteenth of each (64 KiB,
    4 MiB) and acts as the FLOOR under a budget resolved from the payload
    ceiling in force — so raising the payload ceiling carries the framing budget
    with it rather than leaving a ceiling that ordinary chunked traffic cannot
    reach.
  - **`Error::Refused(Refusal::BodyTooLarge { exchange, limit })`**: not an
    `H1Error`, because nothing on the wire broke a rule. The connection does NOT
    fail, `transport()` reads `Transport::Ending`, `wants_read`
    goes false, and a server's `is_awaiting_send` stays true until it has
    written its one answer. `SuggestedStatus::ContentTooLarge` (413, RFC 9110
    §15.5.14) is what it advises. The payload names the LIMIT, not the observed
    size, which the peer chooses and may never end.
  - **`SuggestedStatus::reason()`**: the RFC 9110 §15 reason phrase, so a driver
    maps a suggested status as `(s.code(), s.reason())` and no variant added
    later silently degrades to a 400.
  - **Two new refusals on the send side**, both keyed on a refused body so
    nothing that works today breaks. A final response to a refused body must
    state the `close` connection option — RFC 9112 §9.3 makes reading the whole
    body or closing a MUST and this core has taken the close branch, which RFC
    9110 §10.1.1 makes a SHOULD to state — and `send_interim` is refused
    entirely, since a refused exchange owes exactly one final answer.
  - **An oversized `Content-Length` never invites content**: the head that
    declares it does not surface `Item::ExpectContinue`, which discharges RFC
    9110 §10.1.1's first MUST-alternative with no special case.
  - **Where a breach is found.** A `Content-Length` past the ceiling is refused
    in the same call that yields `Item::Head`, before an octet is read; a
    chunked or close-delimited body is refused by a cumulative charge on the one
    line every payload item leaves through, so the whole offer is refused rather
    than a legal prefix delivered first. A syntactically malformed element still
    LATCHES: only a message that parsed can be refused by policy.
  - **The chunk FRAMING is bounded too, and separately**, because a payload
    ceiling cannot see it: RFC 9112 §7.1's `chunk-size = 1*HEXDIG` admits
    unlimited leading zeros, so a 272-octet size line can announce one payload
    octet and cost 277 octets of wire. The whole size LINE — digits, `chunk-ext`
    and the CRLF — is charged cumulatively per body against
    `Limits::max_chunk_framing_bytes()`, the last chunk's `0\r\n` included. An
    extension-only budget, which is what RFC 9112 §7.1.1 names, is walked around
    by the padding attack with zero extension octets.
  - **`Error::Refused(Refusal::ChunkFramingTooLarge { exchange, limit })`**: the
    same refusal disposition as its sibling — not a protocol failure, one close
    notice, one answer still owed and stating `close` — but advising
    `SuggestedStatus::BadRequest`. RFC 9112 §7.1.1 asks for "an appropriate 4xx
    (Client Error) response if that amount is exceeded"; 413's name is about
    content, which such a message may be well inside.
  - **Granularity, and it is role-independent** because the budget scales with
    the payload ceiling: 65 octets is the smallest chunk a whole body can be
    sent in at either role. 1 MiB in exactly-64-octet chunks spends the server's
    65,536 to the byte and is refused at the terminating `0\r\n`, every payload
    octet already delivered.
  - **A chunked body over the PAYLOAD ceiling is refused at the size line** that
    announces the octets — §7.1 declares one chunk at a time, so the
    announcement is measured against what is left — one chunk ahead of the data
    and with the same `BodyTooLarge` limit. A line breaching both budgets is
    refused as framing.
  - **Per-message wire exposure**: `payload + (5/3) × framing_budget`, plus the
    trailer section's own caps and one unterminated line. `Items::limit_body`
    narrows payload only, so a route's exposure is
    `route_payload + (5/3) × connection_framing`.
  - **BREAKING at the next publish (0.2.0).** A `Connection::new()` that used to
    accept any body now refuses one past its role's default.
  - **The ceiling NARROWS per exchange**, through `Items::limit_body(max)`.
    `min` only, so it is idempotent, order-free and safe to forget — forgetting
    it leaves the operator's ceiling in force, and no routing bug can lift one.
    A route asking for more than the connection allows is capped silently, so
    the ceiling a connection is CONSTRUCTED with has to be the maximum over
    every route it may serve. An unsatisfiable narrowing refuses through the
    same path a wire-side breach takes, and the `limit` it reports is the
    ROUTE's `max`: the narrowing is committed before satisfiability is checked.
    A message with no body answers `Ok` — RFC 9112 §6.3 items 1 and 7 make it a
    body of no octets — so a driver that narrows after every head is not
    punished for a conformant GET, HEAD response or 304; `Error::InvalidState`
    is reserved for a connection that cannot act on the call at all.
  - **`BodyProgress` and `Connection::body_progress()`**: the exchange, the
    octets delivered, the ceiling in force, and what the framing has COMMITTED
    to and not yet handed over. Read right after the head, the last one
    separates the three RFC 9112 §6.3 framings — `Some(total)` is counted,
    `None` is chunked or close-delimited — and inside a chunk it is the
    remainder of THAT CHUNK, since §7.1 never declares a body total.
  - **A counted body can be taken as ONE borrowed chunk**, with no copy path:
    wait until the driver's buffer holds `announced` more octets and the next
    `handle` yields the whole body at once. Stop pulling at `Item::Head` and
    DROP the iterator first — one more `next()` may hand back a partial chunk,
    and `body_progress` is unreachable while `Items` borrows the connection —
    and answer any pending expectation BEFORE waiting, because
    `Item::ExpectContinue` comes out of the body pump and a client that RFC
    9110 §10.1.1 provides for — one that waits for its `100 (Continue)` before
    sending content — will otherwise wait as long as the server does. The wait is bounded in MAGNITUDE by the
    ceiling and unbounded in TIME: a peer declaring exactly the ceiling and then
    dribbling pins up to `limit` of driver buffer for the whole dribble — about
    10 GB at ten thousand connections on the server default, 640 GB on the
    client's. Liveness is the DRIVER's; this core owns no clock.
    `body_progress().received` is the quantity to sample and the socket read
    deadline is the real control.
- **`body`**: counted, read-to-close, and none, plus a strict **chunked**
  decoder (RFC 9112 §7.1) — `1*HEXDIG` chunk-size with an overflow guard, no
  whitespace after the size, `1*("0")` last-chunk, grammar-checked `chunk-ext`
  under a 256-byte per-line cap, and a trailer section surfaced as its own items
  and never merged into the header section.

### Connection

- **Compile-time type-state**: `Connection<Client | Server, General | Tunnel>`.
  The mode is a type parameter, not a runtime flag, so asking a Tunnel
  connection to stream exchanges does not compile. BUILDING a handshake is
  Tunnel's alone; a General client may CARRY one that came back on an ordinary
  exchange, when its operator permitted the RFC 9110 §7.8 offer that invited it
  (`Limits::allow_opportunistic_upgrade`).
- **General mode**: `handle(input) -> Items` yields borrowed
  `Item::{Head, BodyChunk, Trailer, ExchangeComplete, ExpectContinue, Switched}`,
  all but `Switched` naming their `ExchangeId` — the switch ends HTTP framing on
  the connection rather than reporting anything about an exchange;
  `Items::consumed()` is the driver's cursor. Keep-alive
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
  message with no self-defined length non-persistent, so `transport()` reads
  `Transport::Ending` before the driver plans a second request.
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
  `find_head_end`, `parse_status_line` and `parse_chunk_size` compile to
  panic-free code at link time, plus four release smokes over the deeper paths.
  The RFC 9110 §5.6.6 parameterised-list walk, the §12.4.2 `qvalue` reader and
  the §12.5.1 weight selection are link-checked too, in `http-semantics`, which
  is where that code lives and where its shims now sit.
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
