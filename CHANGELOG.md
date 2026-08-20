# UNRELEASED

## `http1-proto` — cycle 6 (media types and the `Accept` ranking)

Issue #42. `Content-Type` and `Accept` were the two fields this core scanned but
would not read: a consumer holding their values had to re-implement RFC 9110
§5.6.6's parameter grammar to get at a charset, and §12.5.1's precedence to pick
a representation — the second of which is a ranking the RFC settles and a
hand-rolled one gets wrong. Both are now parsed here, to the last parameter. The
PICK stays the caller's: §12.1 says a user agent "cannot rely on proactive
negotiation preferences being consistently honored", so this crate answers what
weight applies and nothing about what to serve.

### Added

- **`media_type`, `MediaType`**: reads ONE `Content-Type` value into §8.3.1's
  `type "/" subtype parameters`, borrowing the value rather than copying it.
  `ty()` and `subtype()` hand back the tokens as written, since §8.3.1 makes them
  case-insensitive and the comparison is the caller's; `params()` yields every
  parameter in wire order. It takes a single VALUE rather than a field's lines
  because §8.3 makes `Content-Type` a singleton, and a comma outside a
  quoted-string is refused rather than recovered from: §8.3 records that
  recipients which take "the last syntactically valid member of the list" cause
  "potential interoperability and security issues", and refusal is the one
  behaviour that cannot diverge between two recipients.
- **`accept`, `MediaRange`**: walks an `Accept` field's §12.5.1 media ranges.
  Takes the field's LINES, not one value, for the reason `parameterised_list`
  does — §5.2 makes a repeated field one comma-joined value and a quoted-string
  may span the join. `ty()`/`subtype()` report `None` for exactly the two
  wildcard SHAPES §12.5.1 names, so a literal asterisk reached through the
  `type "/" subtype` alternative (`*/json`) stays an ordinary token and matches
  nothing real. `params()` never yields `q`, wherever it appeared: §12.5.1 says
  recipients "SHOULD process any parameter named "q" as weight, regardless of
  parameter ordering", so none of them is a range parameter.
- **`weight_for`**: the §12.5.1 selection — the weight an `Accept` field gives
  one candidate. Precedence is a lexicographic key over the ranges that matched
  (shape, then matched parameter instances, then field order) which GENERATES
  §12.5.1's printed four-item list rather than transcribing it, which is what
  ranks a parameterised wildcard above its bare form — a pair that list does not
  contain. Three parts of it are readings rather than answers §12.5.1 gives and
  ship as implementation-defined determinism; they are named in the function's
  own doc. `Weight::ZERO` both for a matching range that says `q=0` and for a
  candidate nothing matched (§12.4.3). A range's parameter matches a
  candidate's when the NAMES agree ASCII-case-insensitively (§5.6.6) and the
  values agree byte-exact after unescaping — except `charset`, which folds ASCII
  case because §8.3.2 says "In both cases, charset names are matched
  case-insensitively". That exception is load-bearing rather than cosmetic:
  without it `text/plain;charset=UTF-8;q=0` would not match a candidate spelling
  its charset `utf-8`, and the field's own refusal would be answered with the
  weight of whatever coarser range sat behind it.
- **`Weight`**: a §12.4.2 `qvalue` in thousandths, `0..=1000`. Fixed point rather
  than a float, because the grammar is already fixed point and this core compares
  weights exactly, on tiers with no FPU and under a link-time no-panic proof.
  `Ord` is PREFERENCE ("0.001 is the least preferred and 1 is the most
  preferred"), not §12.5.1's separate question of which range applies.
- **`MediaError`**: why a media-type or `Accept` walk stopped.
  `ValueSpansFieldLines` and `TooManyParameters` are their own variants rather
  than `Parameters` details, because one condition gets one representation: the
  first is well-formed input that is simply not one contiguous slice, and the
  second names a limit of a no-alloc match rather than a fault the sender
  committed.
- **`MAX_TRACKED_PARAMS`**: the most parameter instances a candidate may carry
  while a range's parameters are matched against it. §12.5.1's match is per
  INSTANCE — a range naming `a` twice matches only a candidate offering two, so
  repeating a parameter cannot buy precedence — which means remembering which of
  the candidate's instances are already spent, and a no-alloc core cannot grow
  that memory. Exceeding it is `Err`, never a weight read off the parameters the
  walk could see. A parse-constant like `MAX_HEADERS`, not a `Limits` knob: the
  storage is in the binary, so a caller cannot raise it. A range carrying no
  parameters spends no slot and keeps matching a candidate with any number.
- **`validate::parse_content_length`**: the §8.6 `1*DIGIT` reader, made `pub`.
  It was already the crate's one spelling of that parse and a consumer had no
  way to reach it. One element only; a caller holding a comma-bearing value
  composes it with the existing `grammar::list_elements` and `grammar::trim_ows`.
  An overflow is a framing error rather than a wrapped length.
- **`ParamValue::unescaped`, `unescape_into` and `eq_unescaped_ignore_ascii_case`**:
  new methods, not new consumers of an old one — none of the three existed
  before this branch. `unescaped` is the no-alloc iterator the other two are
  built on and the one a no-alloc caller reaches for first: `same_value` (the
  range-vs-candidate parameter match behind `weight_for`) compares two values
  with it directly. `unescape_into` writes it into a caller-supplied slice;
  `range_from` uses it to unescape a `q` parameter's digits before
  `parse_qvalue` reads them. `eq_unescaped_ignore_ascii_case` has no internal
  caller yet — it answers the common question ("is this charset utf-8?")
  without a buffer, for whoever asks it next. Neither `unescaped` nor
  `unescape_into` folds case, and the folding one says so in its name: §8.3.1
  says parameter values "might or might not be case-sensitive, depending on the
  semantics of the parameter name", so which of them fold belongs to the field
  asking rather than to these three. `same_value` is where the media surface
  answers it, and RFC 9110 answers it for exactly one parameter — see
  `weight_for` above. Parameter NAMES compare ASCII-case-insensitively
  regardless (§5.6.6).
- **`ListMember` now derives `Eq` and `PartialEq`**, comparing a member's bytes
  as written; `MediaType` and `MediaRange` reuse it through their own derives.

### Internals

- **The §12.4.2 `qvalue` reader and the §12.5.1 weight selection join the
  link-time `no-panic` proof**, bringing it to eleven link-checked leaves. The
  `qvalue` reader carries the feature's only checked accumulation; the weight
  shim is driven over a field's LINES rather than one value, so §5.2's join
  branches stay live rather than being pruned as visibly dead before the guard
  can act on them.

## `http1-proto` — cycle 6 (the General ↔ Tunnel mode edges)

PR1 of the cycle. A server could not answer WebSocket upgrades and ordinary HTTP
on one port, because `Connection`'s mode is a compile-time type-state and had to
be chosen before the request that decides it had been read. The type-state is
unchanged; what is new is an EDGE between the two modes, taken AFTER the read
rather than instead of it.

### Added

- **`Connection::<Server, General>::into_tunnel`**: answers an upgrade request
  the General pump has ALREADY read. RFC 9110 §7.8 makes the switch an answer and
  permits it only once the client "has completely sent the request message", so
  the edge runs after the read — which is also why an upgrade request carrying
  CONTENT is switchable here and is not on the native path: General has drained
  the body by then. It lands the connection where `handle_request` leaves one, so
  `accept` writes the 101.
- **`Connection::<Client, General>::into_tunnel`**: spends an IDLE pooled
  connection on a handshake — a decision this end takes rather than an answer it
  owes, so what it gates on is that nothing is outstanding. Both edges are
  consuming, since the General state has no meaning past the switch.
- **`TransitionRefused`**: a refused transition hands the connection back beside
  it (`Err((Self, TransitionRefused))`), because a switch that cannot be taken is
  a reason to answer differently, not a reason to lose the ability to answer at
  all. It names ONE gate rather than reporting a set: the gates are checked in a
  FIXED order, several of them fail together on the same connection — a peer that
  stated `close` moved the lifecycle and queued a notice in the same step — and a
  caller told a different reason on different runs could act on none of them.
  Branch by comparing against the named constants; `reason()` and `Display` write
  the same string for a log line.
- **`HeadBinding` and `Connection::<Server, Tunnel>::head_binding`**: whether a
  head the caller is holding is the head that armed this connection's handshake.
  A layer that answers RFC 9110 §7.8 upgrades on a connection it did not read the
  request on holds two values per exchange, and nothing in either one's type says
  they belong together: `into_tunnel` CONSUMES the connection a lifetime brand
  would be tied to while the head outlives it, and `ExchangeId` cannot say it
  either, since the transition resets the counter. Three answers rather than a
  `bool`, because neither `bool` can be written correctly — `Matches`; `Mismatch`
  for a live handshake this head did not arm, RFC 9110 §9.3.6's CONNECT included,
  which made no §7.8 offer for any head to be; and `NoHandshake` for a connection
  holding no handshake at all, which is the answer a throwaway
  `Connection::new()` gives and the reason it stays usable for validating a head
  BEFORE spending the one-way transition. `Matches` is FNV-1a digest equality
  over the whole head block, computed only for a request that offered a switch,
  so an ordinary request pays nothing for it. Against an accidental mispairing
  the miss probability is 2⁻⁶⁴ per event; it is NOT a security boundary, since
  head content is peer-controlled and a colliding pair is constructible offline.
- **`HeadView::request_line`**: the RFC 9112 §3 request-line read back out of the
  block the view already borrows, so a consumer that needs the method, the
  request-target or the version reads what the ONE §3 codec in this crate
  produced instead of re-implementing it. `None` on a response head, whose start
  line is the §4 status-line.

### Internals

- **An `Exchange` carries four facts durably** — `expect_unanswered`, `version`,
  `upgrade_offered` and `head_digest`, which are exactly the four `into_tunnel`
  reads off it — because a transition is where a transient copy is lost.
  `expect_unanswered` is RFC 9110 §7.8's outstanding `100 (Continue)`: the
  transient copy lives in `RecvState::Body` and is gone by the time an answer is
  written, so both sends that discharge the ask clear the durable copy alongside
  it and `into_tunnel` reads the obligation off that. `version` is the version
  the REQUEST stated, which RFC 9112 §6.1 and RFC 9110 §15.2 both turn on and
  which no response can be read for. `upgrade_offered` is §7.8's two-halved offer
  as the receive side decided it, which cannot be re-derived once the head is
  gone. `head_digest` is WHICH request made that offer, and it is the fact
  `head_binding` answers from on the far side of the edge. Without the four, a
  Tunnel handed back across it would owe an interim it cannot know about, would
  answer under a version it can no longer see, could not tell that a switch was
  offered at all, and could not tell the request it is holding from any other.

## `http1-proto` — cycle 6 (the inbound body gets a ceiling)

PR2 of the cycle. The message body was the only unbounded quantity this core
handled: it streamed borrowed chunks and never accumulated, but a consumer that
needed a whole body accumulated them itself and nothing bounded that, so the
crate handed its consumers a denial-of-service surface. A body now has a
per-message ceiling, and exceeding it is a POLICY REFUSAL that leaves the
connection answerable rather than failed — which is the whole point, since a 413
carrying an explanation has to stay representable.

### Breaking (0.2.0 at the next publish; the crate is unpublished today)

- `Connection::new()` applies its role's default ceiling. A driver that
  previously accepted any body now refuses one past 1 MiB at a server, 64 MiB at
  a client, with `Error::Refused` rather than an item stream that never ends.
  `Connection::with_limits` is how a driver states its own.
- `Error` gains a `Refused` variant and `SuggestedStatus` a `ContentTooLarge`
  one; both enums are already `#[non_exhaustive]`, so a `_` arm keeps compiling
  and a driver that wants the 413 matches for it.

### Added

- **`Limits`**, and the constructors that read it —
  `Connection::<Ro, Mo>::default_limits()`, `with_max_body_bytes`,
  `with_max_chunk_framing_bytes`, `max_body_bytes`, `max_chunk_framing_bytes`,
  and `Connection::with_limits`. The seed hangs off the CONNECTION type rather
  than off `Limits`, so the wrong role's seed has no shorter spelling than the
  right one. Read once, at construction: a live connection has no path back to
  it, so the ceiling has one writer and the only direction a route can move it
  is down.
- **Role-dependent defaults** on the sealed `Role` trait — a server's 1 MiB is
  nginx's `client_max_body_size 1m` and exactly `MAX_HEAD_BYTES × MAX_HEADERS`;
  a client's 64 MiB is where RFC 9112 §6.3 item 8's undeclared, close-delimited
  framing lives and matches `websocket-proto`'s own `max_message_size`.
- **A chunk-framing budget resolved from the payload ceiling in force** — a
  sixteenth of it, with the role default as a floor. Derived from the ceiling
  rather than fixed because a fixed one reproduces, one knob up, the failure it
  exists to prevent: 100 MiB at the commonest 4 KiB chunk granularity spends
  153,600 octets of RFC 9112 §7.1 size lines, so a budget frozen at 64 KiB would
  refuse ordinary traffic about 42.7 MiB into a body the payload ceiling allows.
  `u64::MAX >> 4` is 2⁶⁰, so "unbounded" stays one knob.
- **`Error::Refused(Refusal::BodyTooLarge { exchange, limit })`** — deliberately
  not an `H1Error`. RFC 9110 §15.5.14 names this as a double MAY ("The server
  MAY terminate the request, if the protocol version in use allows it;
  otherwise, the server MAY close the connection") and HTTP/1.1 has no way to
  end one request without the connection, so this core takes the second branch:
  keep-alive ends, `Event::CloseSignaled` is queued once, and a server's one
  response is still owed and still sendable.
- **`SuggestedStatus::ContentTooLarge`** (413) and **`SuggestedStatus::reason()`**,
  which retires a defect class rather than adding a convenience: both wren
  drivers mapped a suggested status through `match code { Some(414) => …, _ =>
  (400, …) }`, so every variant added later degraded silently at two
  byte-identical sites. Both now map `(s.code(), s.reason())`.

### Changed

- **A refused body constrains what may still be written.** The final response
  must state the `close` connection option — RFC 9112 §9.3 makes reading the
  whole body or closing a MUST, this core has taken the close branch on the
  driver's behalf, and RFC 9110 §10.1.1 makes stating it a SHOULD — and
  `send_interim` is refused outright, because a refused exchange owes exactly
  one final answer. Both gates are keyed on a refused body, so nothing that
  works today changes.
- **An oversized `Content-Length` never yields `Item::ExpectContinue`.** The
  expectation asks "shall I send the content?" and this end has already answered
  no, so the ask is not surfaced and no `100 (Continue)` can be written for it.
- **Closing after a 413 is a STAGED close, and a driver must do it that way.**
  The peer is mid-transmission of the refused body by construction, so RFC 9112
  §9.6's reset case is guaranteed rather than incidental and an immediate full
  close can erase the very response this path exists to deliver. Half-close the
  write side, keep draining the socket at the transport level until the peer
  closes or a deadline expires, then close. `wants_read() == false` means the
  CORE needs no more octets, not that the socket should stop being drained;
  nothing discarded that way is parsed, so §9.6's "MUST NOT process any further
  requests" is untouched.
- **What the ceiling does NOT bound: time.** A peer declaring exactly the
  ceiling and then dribbling one octet per read is not refused, and pins a
  connection for as long as the driver lets it. The core is Sans-I/O and has no
  clock; the socket read deadline is the driver's, and it is the real control.

## `http1-proto` — cycle 6 (the ceiling narrows per exchange, and reports)

PR3 of the cycle. The ceiling PR2 gave the inbound body is the connection's, and
a connection serves many routes: the one that accepts uploads and the one that
takes a 4 KiB JSON document had to share a number chosen for the larger. A route
can now tighten that ceiling once its own head has been read, a driver can ask
where the body it is receiving stands, and a counted body can be taken as one
borrowed chunk with no copy path anywhere in this core.

### Added

- **`Items::limit_body(max)`** — narrows the ceiling on the body in flight to
  `max` payload octets. NARROWING ONLY: the effective ceiling is
  `min(current, max)`, and `min` is idempotent and commutative, so it may be
  called any number of times, in any order, right after `Item::Head` or
  mid-body, and the answer is the same. There is no "exactly once, before X"
  rule to get wrong, which is why the call is safe to FORGET — forgetting it
  leaves the operator's ceiling in force. A routing bug cannot LIFT that ceiling
  because the operation has no increasing direction to be pointed in, not
  because a check refuses one.

  On `Items` rather than on `Connection`, and only there: `Item<'a>` borrows the
  INPUT rather than the iterator, so a driver narrows while still holding the
  head it just pulled — before the pump has decoded one octet of that body, even
  when head and body arrived in the same offer. A `Connection`-level twin could
  not promise that, and two surfaces with one signature and different timing
  guarantees is a trap dressed as symmetry.

  **The connection ceiling must be the maximum over all route limits.** A route
  asking for more than the connection allows is capped silently, since narrowing
  is `min`: `limit_body(8 << 20)` under a 1 MiB ceiling answers `Ok` and grants
  1 MiB. A ceiling taken from any one route's limit caps every route above it
  and reports nothing.

  It refuses — `Err(Error::Refused(Refusal::BodyTooLarge { .. }))`, with the
  connection moved to the same refused disposition a wire-side breach produces —
  when `max` cannot be satisfied: more octets have already been delivered than it
  allows, or the framing has already DECLARED more than fits (a `Content-Length`
  remainder, RFC 9112 §6.3 item 6, or the remainder of the chunk in flight,
  §7.1). The `limit` such a refusal carries is the ROUTE's `max` and not the
  ceiling it replaced, because the narrowing is committed before satisfiability
  is checked; a driver logging one otherwise reads back a number that never
  refused anything.

  It answers `Ok(())` on a message with no body. RFC 9112 §6.3 items 1 and 7
  frame a bodiless message as a body of no octets, so nothing has been
  delivered, no ceiling can be exceeded at any value, and a uniform
  narrow-after-every-head driver — the natural shape — is never told that a
  conformant GET, HEAD response or 304 was an error. A body already THROUGH is a
  different case and is measured like any other: its octets are out, so the
  window between `Item::BodyChunk` and `Item::ExchangeComplete` — in which the
  iterator is still usable and a route may still narrow — answers about what the
  body delivered rather than about how far the item stream has been pumped. `Error::InvalidState` is reserved for a connection that cannot act on
  the call at all: no message being received, or a failed or drained connection.
  That reservation is deliberate, because `InvalidState` carries a `&'static str`
  a caller cannot branch on — folding "this message has no body" into it would
  make it indistinguishable from "this connection is dead".

- **`BodyProgress` and `Connection::body_progress()`** — where the body being
  received stands: its exchange, the payload octets already delivered, the
  ceiling now in force, and what the framing has COMMITTED to and not yet handed
  over. That last one separates the three RFC 9112 §6.3 framings cleanly when
  read right after the head: `Some(total)` is a counted body, `None` is chunked
  or close-delimited. Inside a chunk it is the remainder of THAT CHUNK — §7.1
  never declares a body total, and it must not be read as one.

  On the CONNECTION rather than on `Items`, which is the opposite side from
  `limit_body` and for the same reason: the iterator borrows the connection for
  as long as it lives, so this is read once it has been dropped — which is
  exactly where the recipe below wants it.

- **The zero-copy contiguous handover**, which needs no new API beyond the
  above and adds no copy path. Wait until the driver's own buffer holds
  `announced` more octets and the next `handle` yields the whole body as ONE
  borrowed `Item::BodyChunk`, because the counted framing claims
  `min(remaining, input.len())` in one go. Two steps of that are not
  discoverable from the signatures and both are required:

  1. **Stop pulling at `Item::Head` and DROP the iterator.** One more `next()`
     may hand back a partial chunk of whatever happened to be buffered, and
     `body_progress` is unreachable while `Items` borrows the connection.
  2. **Answer any pending expectation BEFORE waiting.** `Item::ExpectContinue`
     is yielded by the BODY pump, so a driver that stopped at the head has never
     seen it and must re-derive the ask from the head's own `Expect` field. RFC
     9110 §10.1.1 provides for a client that waits for its `100 (Continue)`
     before sending content, so against one that does both ends wait — the server
     for octets, the client for permission to send them.

  **The wait is bounded in MAGNITUDE and unbounded in TIME, and that is not a
  footnote.** A declaration above the ceiling was already refused, so the wait
  can never ask for more than `limit` octets of driver buffer — but it can ask
  for them for as long as the peer likes, and a peer that declares exactly the
  ceiling and then dribbles pins that buffer for the whole dribble. That is the
  consumer-side accumulation the ceiling exists to close, reintroduced at
  `limit`. Per process: a streaming driver costs about 200 core bytes per
  connection, a contiguous-handover driver up to `limit` — roughly 10 GB at ten
  thousand connections on the server default, and **640 GB on the client's 64
  MiB default**. **Liveness is the DRIVER's**, and this core cannot take it: it
  owns no clock. `body_progress().received` is the quantity to sample against
  the driver's own clock, and the socket read deadline is the real control.

## `http1-proto` — cycle 6 (the chunk framing gets a budget of its own)

PR4 of the cycle, and the last of it. A payload ceiling bounds content, and RFC
9112 §7.1's chunk-size lines are not content: `chunk-size = 1*HEXDIG` admits
unlimited leading zeros, so 271 of them and a `1` is a 272-octet line that
parses cleanly, announces ONE payload octet and costs 277 octets of wire. A body
comfortably inside its ceiling could therefore make this end parse about 277
wire octets per payload octet, for as long as it liked, because nothing counted
them. The framing a chunked body may spend is now bounded per message, at the
one place it is parsed.

### Added

- **A cumulative chunk-framing budget**, charged over the whole chunk-size LINE
  — digits, `chunk-ext` and the CRLF that ends it — and reset per body. The
  budget is `Limits::max_chunk_framing_bytes()`, which PR2 already resolved from
  the payload ceiling in force (a sixteenth of it, floored at the role default);
  this is the PR that makes it bind. The last chunk's `0\r\n` is charged like
  every other line, since it comes through the same parse and exempting it would
  be a second rule.

  **The LINE and not the extension**, which is the whole of why it catches
  anything: RFC 9112 §7.1.1 asks a server to "limit the total length of chunk
  extensions received in a request to an amount reasonable for the services
  provided", and the zero-padding attack above spends 274 framing octets with no
  extension in it at all. An extension-only budget never sees it.

- **`Refusal::ChunkFramingTooLarge { exchange, limit }`**, whose `limit` is the
  budget in framing octets. Its advised status is `SuggestedStatus::BadRequest`
  and not the 413 its sibling advises: RFC 9112 §7.1.1 asks for "an appropriate
  4xx (Client Error) response if that amount is exceeded", and 413's name — RFC
  9110 §15.5.14, "Content Too Large" — is about content this message may be well
  inside. `Refusal` is `#[non_exhaustive]`, so a `_` arm keeps compiling and a
  driver mapping `(s.code(), s.reason())` answers `400 Bad Request` without
  changing. Everything else is the refusal disposition PR2 built: not a protocol
  failure, `Event::CloseSignaled` once, and a server still owing exactly one
  answer that has to state `close`.

- **The granularity the budget implies, and it does not move with the role.** At
  a full payload ceiling the smallest chunk size a whole body can be sent in is
  **65 octets** at either role, because the budget scales with the ceiling: 1 MiB
  in exactly-64-octet chunks writes 16,384 `40\r\n` lines, spends 65,536 to the
  byte, and is refused at the terminating `0\r\n` with every payload octet
  already delivered. 128-octet chunks have 2× margin, and 1 MiB in 4 KiB chunks
  — the commonest reverse-proxy granularity — writes 256 six-octet size lines
  and spends 1,539 octets of the 65,536.

### Changed

- **A chunked body over the payload ceiling is now refused at the size LINE**
  that announces the octets, one chunk ahead of the data, rather than by the
  cumulative charge as the octets arrive. RFC 9112 §7.1 declares one chunk at a
  time, so the announcement is measured against what is left of the allowance:
  the same `Refusal::BodyTooLarge` with the same `limit`, reached sooner, with
  every octet the ceiling allowed still delivered first.
- **Syntax still runs before policy**, on both budgets. A line that is not
  `1*HEXDIG`, or whose extensions break the §7.1.1 grammar, is diagnosed as
  malformed however far past a budget it also was — only a message that PARSED
  can be refused by policy — and a line breaching both budgets is refused as
  framing, deterministically.

### The exposure numbers this changes

- **Per message**: `payload + (5/3) × framing_budget`, plus a trailer section
  (already capped at 16,384 octets by `MAX_HEAD_BYTES`, with `MAX_HEADERS` over
  its line count) and one unterminated line. Each chunk spends at least three
  charged octets, so the budget admits at most `F/3` chunks and the `2F/3`
  octets of chunk-data CRLF that go with them. At the server defaults that is
  1 MiB of content plus **109,227 octets** — 106.7 KiB — of framing and
  chunk-data CRLF.
- **Per narrowed route**: `Items::limit_body` narrows the PAYLOAD ceiling only —
  the framing budget belongs to the connection — so a route narrowed to 4 KiB on
  a connection with a 64 KiB framing budget still admits `4096 + (5/3) × 65,536`
  ≈ **113,300 octets** (110.7 KiB) of wire. Construct the connection's budget
  accordingly; there is deliberately no per-route knob for it.
- **The instantaneous 277:1 ratio is unchanged.** What this bounds is the
  absolute amount, not the ratio: an attacker still gets 277 wire octets per
  payload octet, and now runs out.

## `websocket-proto` — cycle 6 (handshakes on a connection the caller holds)

PR1 of the cycle. Both h1 handshakes can now be driven on a connection the caller
transitioned out of `http1-proto`'s General mode, so one port can serve WebSocket
upgrades and ordinary HTTP, and a client handshake can ride a connection kept
warm by ordinary keep-alive exchanges. The handshake that opens its own
connection is unchanged; what is added is a second way in.

### Breaking

- **`classify` DERIVES the request-line rather than taking one beside the head.**
  The signature is `classify(&head, leftover)`; what was a `RequestLine` argument
  is now `HeadView::request_line` read out of the block this call was handed. A
  caller-supplied line is exactly the class of mistake this call exists to
  refuse: RFC 9112 §3.2.2 makes an absolute-form target override `Host`, so a
  foreign line grants the right request's key against a different request's
  resource name and authority, and the head digest says nothing about it. A head
  that begins with no §3 request-line answers `NotARequestHead`, which is a
  refusal the old signature had no way to express.

### Added

- **`ServerHandshake::adopt`**: takes the `Connection<Server, Tunnel>` the caller
  transitioned, where `new` creates one. It pairs with `classify`, and the pair
  is also how a caller pre-validates WITHOUT spending a connection: because
  `Connection::into_tunnel` is one-way, a request that is a valid RFC 9110 §7.8
  upgrade but an invalid RFC 6455 §4.2.1 handshake leaves a caller that
  transitioned FIRST holding a tunnel it must reject and no keep-alive HTTP
  connection left to serve. `adopt(Connection::new())` plus `classify` runs every
  §4.2.1 check against the head the General pump produced, touching neither that
  pump's connection nor the throwaway one — `classify` advances nothing — so a
  rejection costs a discarded handshake and an acceptance is the go-ahead to
  transition for real. Discarding it is REQUIRED rather than tidy: a refused head
  spends the one request that handshake is offered.
- **`ServerHandshake::classify`**: validates the request head the CALLER read,
  where `handle` reads one itself. Nothing binds a borrowed head to a connection
  at compile time, so the binding is stated at RUNTIME:
  `Connection::head_binding` is asked ahead of every §4.2.1 check, and a
  `Mismatch` — a head that armed some OTHER connection, or a connection armed by
  RFC 9110 §9.3.6's CONNECT — is refused with `HeadMismatch`. `NoHandshake`
  PROCEEDS rather than refusing, which is what keeps the pre-validation recipe
  above working, and `accept` refuses a 101 on such a connection anyway. Three
  content checks stand behind the binding, and on the throwaway path, where no
  identity check runs, the first two are the WHOLE of the protection. Two restore
  §4.2.1 items the native path proves as it reads the head — item 1's HTTP/1.1
  floor, which RFC 9110 §7.8 makes a MUST by making an HTTP/1.0 `Upgrade` field a
  MUST-ignore, and item 4's `Connection` naming `upgrade`. The third is §7.8's
  outstanding `100 (Continue)`, and it is ONE-DIRECTIONAL: a connection owing one
  against a head that states no such expectation is a mismatched pair, while the
  converse is a conforming sequence — an interim sent on the General connection
  before the transition discharges the obligation and leaves the answer owed.
- **`ClientHandshake::with_connection`**: opens the handshake on a connection the
  caller transitioned. It and `new` are two callers of one private validation
  path, so neither entry point can grow a gate the other lacks. It checks the
  connection itself not at all: `TunnelPhase` is crate-private to `http1-proto`,
  so this crate cannot read whether a handshake is already outstanding on the
  connection it was handed — and none is needed, since `open_upgrade` refuses
  such a connection when `encode_request` reaches it, which is where the bytes
  would have been written and where the caller can act on it.
- **`pub use http1_proto`**: the h1 handshake surface NAMES that crate's types —
  `adopt` takes a `Connection<Server, Tunnel>`, `classify` a `HeadView`,
  `with_connection` a `Connection<Client, Tunnel>` — and a type a caller cannot
  name is one it cannot build an argument out of. Reaching them through here is
  also what makes them the SAME types: a downstream that depends
  on `http1-proto` directly agrees with this crate only while the two version
  requirements resolve to one crate, and the day they do not, the two
  `Connection`s are distinct types printed with the same name. A doctest builds
  `adopt`'s argument entirely through this path, so a version split stops
  compiling instead.
- **Five `ServerHandshakeError` variants**: `UnsupportedHttpVersion`, the head
  is not HTTP/1.1 — distinct from `UnsupportedVersion`, which is §4.2.1 item 6's
  `Sec-WebSocket-Version` and is answered with a 426, since there is no HTTP
  version to advertise back; `ExpectationMismatch`, the connection owes a
  `100 (Continue)` while the head states no such expectation, so the two describe
  different requests; `HeadMismatch`, the head is not the one the adopted
  connection read — either a head that armed some other connection, or a
  connection armed by RFC 9110 §9.3.6's CONNECT, which made no §7.8 offer for any
  head to be; `NotARequestHead`, the head begins with no RFC 9112 §3
  request-line, of which a view of a RESPONSE head is the reachable case, kept
  distinct from `HeadMismatch` because a status-line head handed to a connection
  holding nothing raises no binding question at all; and `AlreadyClassified`,
  below.

### Changed

- **A handshake is offered its one request exactly once** — whichever entry point
  offers it, and WHATEVER the outcome. `handle` and `classify` read one latch,
  and both spend it on the ATTEMPT rather than on success: the connection was
  armed with its one request before the handshake existed, so a head that fails a
  check is definitively not that request, and the next head has no better claim
  to being it. A second request offered to either now answers
  `AlreadyClassified`, which is a NEW answer on paths that previously gave a
  lower-layer error or none at all — a second `handle`, which fell through to
  `http1-proto`'s own narrower guard against a connection that is no longer idle;
  `handle` after `classify` and `classify` after `handle`, which cross entry
  points and were caught by neither; and a request this layer REFUSED, a generic
  upgrade or RFC 9110 §9.3.6's CONNECT, which left the offer open on a connection
  `http1-proto` had already armed. Answering a second head would pair a
  `Sec-WebSocket-Accept` with a request the client did not make, which §7.8
  forbids, and would set it beside whatever RFC 6455 §4.2.2 grants an earlier
  head had settled. A `NeedMore` and a `Closed` consumed no request, so neither
  spends the offer. On error the handshake survives and stays reject-only, so
  §4.2.1's "return an HTTP response with an appropriate error code" is still
  writable — but a corrected pairing needs a fresh handshake.

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
  rejected), the RFC 3986 target validators, the §5.6.1 list splitter, and
  `parameterised_list` — the §5.6.6 `#`-list walk that crosses a §5.2 field-line
  join without materialising it. That walk has **no consumer in this workspace**:
  it was added for `websocket-proto`'s `Sec-WebSocket-Extensions`, which turned
  out to need RFC 6455 §9.1's own grammar instead (see that crate's *Fixed*
  below). It stays because it is the right reading of the fields §5.6.6 actually
  governs — `Accept`, `Content-Type`, `Forwarded`, a `Transfer-Encoding` with
  parameters — which is what an HTTP core is for, and because it is the one place
  the join-crossing rule is implemented.
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
- Green on every tier and under `cargo hack test --each-feature`; the suite is
  enumerated in `http1-proto/CHANGELOG.md`. No total is quoted here: the figure
  this line used to carry (254) was 133 short of the measured suite, because a
  count is invalidated by every commit that adds a test and nothing checks it.

## `websocket-proto` 0.2.0 — cycle 5 (h1 handshake re-based onto `http1-proto`)

PR2 of the cycle. websocket-proto's private HTTP/1.1 layer is deleted and both
h1 handshakes are rebuilt on `http1-proto`'s Tunnel API, so the split between
the two crates is the split between the two specifications: `http1-proto` owns
HTTP — head grammar and caps, RFC 9112 §3.2's `Host` and request-target rules,
RFC 9110 §7.8's upgrade offer and the 101 that answers it, and the leftover
handoff — and this crate keeps only what RFC 6455 adds on top: the
`Sec-WebSocket-Key`/`-Accept` SHA-1, the version check, subprotocol and
extension negotiation, and the §4.2.1.1 resource-name policy. `RequestView`'s
inline 64-entry header table (~2 KB) is replaced by the borrowed `HeadView`.

### Breaking

- **The handshakes are stateful, one instance per handshake.** Every method that
  drives the connection — `handle`, `encode_request`, `encode_response`,
  `encode_rejection` — takes `&mut self` and ADVANCES it, so `handle` is no
  longer replayable and a driver that used to re-parse the head must carry the
  handshake instead. `ServerHandshake` is no longer `Copy`/`Clone`/`Default` and
  `ClientHandshake` is no longer `Clone` (`http1_proto::Connection` is not
  `Clone`).
- **Answering a request splits in two, and the answer never leaves the
  handshake.** The head's borrow ends before the driver decides, so RFC 6455
  §4.2.2's request-bound checks — the chosen subprotocol was offered, the
  deflate grant is one this request legalizes — run in the new
  `PendingUpgrade::validate_accept(&accept)` while the view is alive. It returns
  `Result<(), ServerHandshakeError>` and stores what it settled INSIDE the
  handshake; `ServerHandshake::encode_response(&extras, out)` takes no answer
  argument and returns `(usize, Negotiated)`, writing the subprotocol and the
  extension grant out of that stored answer. A handshake that validated nothing
  answers with the new `ServerHandshakeError::AnswerNotValidated`, so there is no
  unvalidated path to a 101.
- **`AcceptDecision` is gone, and so is the request argument.** Both halves of
  the pairing used to be values a caller held: an owned decision between the two
  calls, and the classified `RequestView` handed to `validate_accept`. Both were
  policed by COMPARING the request's `Sec-WebSocket-Key`, which is data the PEER
  chooses — a client may send one key on two concurrent requests (§4.1 asks for a
  randomly selected value, which binds a conforming client and not a hostile
  one), and the comparison then passes: A's subprotocol and A's extension grant
  written into the 101 answering B, whose client offered neither, with every call
  returning `Ok`. Deleting the pairable objects deletes the pairing rather than
  policing it. The answer lives in the handshake that validated it, and
  `ServerHandshake::handle` now yields a `PendingUpgrade` that holds its
  handshake by mutable borrow next to the view — `validate_accept` is a method on
  it and takes no request. No function in the crate accepts a `RequestView`, so
  answering one exchange out of another's offers does not compile
  (`PendingUpgrade`'s `compile_fail` proofs), and one handshake cannot hold two
  pending upgrades at once. `ServerHandshakeError::MismatchedRequest` is gone
  with the comparison it named.
- **Extra response headers move off `Accept` and onto `encode_response`.**
  `Accept::with_extra_headers` is gone; `Accept` now carries only the
  request-bound half of an answer (the subprotocol and the grant). Nothing
  about an extra header depends on the request — the checks are token names,
  field-value bytes, and no collision with a managed field — so they are
  supplied and validated where the answer is written. Pass
  `&ExtraHeaders::new()` when there are none. This is what keeps the decision
  free of borrows; the rejection path is unchanged
  (`Rejection::with_extra_headers` stays).
- `handshake::h1` now re-exports `InvalidOptionsDetail`. It was a `pub` type
  reachable only through an error variant, so no downstream crate could name it
  and rustdoc had nothing to link.
- `ServerProgress::Request(view)` is now `Upgrade(PendingUpgrade)`, whose
  `request()` hands out a `Copy` of the view and whose `leftover()` is whatever
  the client pipelined behind the head. `ServerProgress` carries the handshake's
  borrow as a second lifetime, `ServerProgress<'h, 'a>`. The new
  `ServerProgress::Closed` is "the peer closed WITHOUT sending a request";
  closing part-way through one stays an error.
- `RequestView::{origin, header}` return `&[u8]` rather than `&str` — RFC 9110
  §5.5 admits `obs-text` in a field value, so bytes are what the head layer can
  honestly hand over — and `extensions` yields the raw `Sec-WebSocket-Extensions`
  field lines rather than parsed `&str` entries, and is no longer `deflate`-gated.
  `consumed()` is gone (the offset is `PendingUpgrade::leftover`);
  `method()`, `target()` and `head()` are new. `method`, `target`, `path`,
  `query`, `host` and `subprotocols` stay `&str`: each is validated ASCII by
  construction.
- `ClientHandshakeError::UnexpectedStatus(u16)` is gone, and a refusal is not an
  error at all: `ClientProgress` gains `Refused { status, consumed }`. A server
  that will not switch is the peer ANSWERING, and RFC 6455 §4.1 sends the caller
  to "HTTP procedures" for it — "the client might perform authentication if it
  receives a 401 status code; the server might redirect the client using a 3xx
  status code" — which read `WWW-Authenticate` and `Location`. A status code
  alone cannot even locate those fields, so the outcome carries the offset its
  head ended at and the caller hands `data[..consumed]` to whatever HTTP client
  it already has.
- `ClientProgress` also gains `Interim { status, consumed }` (see *Fixed*).
- The `Head(HeadError)` variant on both error enums is now
  `Http(http1_proto::Error)`, and `handshake::{HeadError, MalformedDetail}` are
  no longer re-exported — name `http1_proto`'s directly.
  `ServerHandshakeError::NotHttp11` is gone with them: an HTTP/1.0 upgrade
  request is still refused (RFC 9110 §7.8's `Upgrade` is not honoured below
  1.1), but the verdict is `http1-proto`'s and arrives as `Http(_)`.
- `derive_more::TryUnwrap` is gone from `ServerProgress` and `ClientProgress`;
  match instead. The derive cannot generate one for a struct variant, and on
  `ClientProgress` it was actively dangerous: `try_unwrap_complete()` routes
  `Interim` into the "not yet" arm, so a driver using it re-reads the same head
  forever. `IsVariant` stays on both, and both error enums keep `TryUnwrap`.
- `negotiation::{accept_deflate_offer, parse_deflate_response}` take `&[u8]`
  values rather than `&str`: RFC 6455 §9.1 lets an extension parameter value be
  a quoted-string and RFC 9110 §5.5 admits `obs-text`, so `&str` at this seam
  was either lossy or fallible at the wrong layer. Subprotocols are tokens
  (§4.2.1.8) and stay `&str`.
- `negotiation::select_subprotocol` returns the matching element of `supported`
  rather than of the client's offers, so the selection outlives the request
  head. Its lifetime follows the ENTRIES rather than the slice holding them, so
  a caller that collects its supported names into a temporary keeps a selection
  that outlives the collection. Selection ORDER is unchanged — the offers are
  walked in client preference order.
- The head cap is `http1-proto`'s 16 KiB rather than this crate's 8 KiB.

### Added

- `ServerHandshake::handle_eof` and `ClientHandshake::handle_eof`: the
  transport's read side ended. Idempotent, and they decide nothing on their own
  — the next `handle` resolves the offer that ran out.
- `h1::MAX_SUBPROTOCOL_OFFER_BYTES` (512): how much the client's offers may
  measure once comma-joined into the one `Sec-WebSocket-Protocol` field value.
  Seven offers at `negotiation::MAX_SUBPROTOCOL_LEN`, twenty-five at the lengths
  RFC 6455 §11.5's registered names run to, a hundred and seventy-one at the
  one-byte floor. See *Fixed*.
- `negotiation::MAX_SUBPROTOCOL_OFFERS` (64) and
  `negotiation::MAX_SUBPROTOCOL_LIST_BYTES` (16384): how many offers, and how
  many bytes of them, either server will READ — and, mirrored at both emitters,
  how many either client will write. The first cannot be lower than the sixty
  `sixty_subprotocol_offers_round_trip_through_our_own_server` pins and is
  `http1_proto::MAX_HEADERS`; the second is `http1_proto::MAX_HEAD_BYTES`, so on
  h1 it refuses nothing the head cap did not already. See *Fixed*.
- `connect::ConnectRequestView::origin` and
  `connect::ConnectRequestError::DuplicateOrigin`. See *Fixed*.
- `negotiation::MAX_EXTENSION_VALUE_BYTES` (160): how large a buffer holds any
  `Sec-WebSocket-Extensions` value this crate RENDERS, which is what
  `DeflateOffer::write` and `DeflateResponse::write` want to be called with —
  128 bytes at the widest, pinned by
  `the_widest_rendered_extension_value_fits`. It was four separate numbers (both
  h1 scratches, both extended-CONNECT views' inline buffers, and the re-render
  behind the server-side grant check), three named apart and the fourth an
  anonymous literal; naming it once is why there is no fifth to drift. It does
  NOT bound a value a PEER sends — that one is bounded by the transport's own
  head cap and read in place.

### Documented

- **The head limits an extra header is read under are the RECEIVING peer's**,
  and they are now stated where a caller sets one:
  `h1::ClientOptions::with_extra_headers`,
  `h1::ServerHandshake::encode_response` and `h1::Rejection::with_extra_headers`
  each name `http1_proto::MAX_HEADERS` (64 field lines) and
  `http1_proto::MAX_HEAD_BYTES` (16 KiB), and how many lines the managed
  handshake fields already spend. Neither emitter bounds its own head, and that
  is deliberate — a large head violates nothing, and refusing to write one a
  lenient peer would accept is a rule no RFC has — but sixty extra request
  headers is sixty-five field lines against a sixty-four-line cap, and a caller
  met that as an error from the far end with nothing in the documentation to
  explain it.

### Fixed

- **Interim 1xx responses are parsed instead of failing the handshake.** The old
  client mapped a `100 Continue` prefix to `UnexpectedStatus(100)`, which RFC
  9110 §15.2.1 forbids: "a client MUST be able to parse one or more 1xx
  responses received prior to a final response". `ClientProgress::Interim`
  reports which one arrived AND how far the buffer advanced past it — a driver
  told only that an interim arrived cannot advance, so it re-offers the same
  head and reads it forever.
- **An extension offer can no longer be fabricated out of a quoted string.**
  `Sec-WebSocket-Extensions` is walked with a quoted-string-aware parser that
  splits only on the commas and semicolons OUTSIDE a quoted-string. The previous
  `str::split` splitter cut inside quoted strings and read their CONTENT as list
  members, so a peer that never offered permessage-deflate could have it
  negotiated — and then be sent RSV1-compressed frames it never agreed to.
  Demonstrated against the old code with
  `x-note; v="a,permessage-deflate;client_max_window_bits=8,b"`, and pinned by
  `an_offer_cannot_be_fabricated_from_inside_a_quoted_string`.
- **A malformed `Sec-WebSocket-Extensions` field fails the handshake.** RFC 6455
  §9.1: "If a value is received by either the client or the server during
  negotiation that does not conform to the ABNF below, the recipient of such
  malformed data MUST immediately _Fail the WebSocket Connection_." Both h1
  handshakes and both extended-CONNECT gates used to read the field only to
  negotiate with, so an unreadable offer yielded no grant and a 101 all the
  same — the freedom §9.1 gives a recipient to DECLINE an extension is about one
  it does not want, not about data it cannot read. The new
  `negotiation::extension_list_conforms` is the gate, and it runs on every
  handshake carrying the field, on both sides, whatever extensions the build
  supports: `ServerHandshakeError::MalformedExtensions`,
  `ClientHandshakeError::MalformedExtensions`,
  `ConnectRequestError::MalformedExtensions`,
  `ConnectResponseError::MalformedExtensions`. The server's refusal is
  reject-only, so §4.2.1's "HTTP response with an appropriate error code" still
  goes out. Two consequences of the ABNF: a quoted value whose unescaped form is
  not a `token` is malformed, and so is a value that spans an RFC 9110 §5.2
  field-line join — the join's comma lands inside it and a comma is not a
  `tchar`. And a semicolon with nothing behind it — `permessage-deflate;`,
  `permessage-deflate;;client_max_window_bits` — is malformed too: what `[ … ]`
  makes optional in `extension-param = token [ "=" (token | quoted-string) ]` is
  the value, not the parameter, RFC 2616 §2.1's implied *LWS rule puts whitespace
  between productions rather than removing one, and the null elements §2.1's
  `#rule` does permit are list elements rather than parameters. Pinned from both
  ends by `a_malformed_extension_list_fails_the_handshake`.
- **`Sec-WebSocket-Extensions` has ONE parser, and it is RFC 6455 §9.1's.** The
  gate above and the negotiation behind it briefly read two grammars — the gate
  §9.1's, the readers `http1_proto::grammar::parameterised_list`'s RFC 9110
  §5.6.6 — on the argument that a divergence could only decline an extension,
  never grant one. That is true of the OFFER path and false of the RESPONSE
  path: RFC 7692 §8.1 makes an extension response the client will not accept
  FAIL the connection, so "declined" there means "handshake refused". §9.1 states
  its ABNF "including the 'implied *LWS rule'", so a conforming server may write
  `permessage-deflate ; server_max_window_bits = 11` — the gate passed it and
  `parse_deflate_response` then rejected it, on the h1 client and on the
  extended-CONNECT client alike. The gate's §9.1 walk now YIELDS the members and
  parameters it was already traversing, and `extension_list_conforms`,
  `accept_deflate_offer`, `parse_deflate_response` and the server-side grant bind
  all consume it; websocket-proto no longer uses `parameterised_list` at all (see
  the http1-proto note above for why the walker stays). The walk is line-local,
  which for this grammar is the same question as the joined value: a member spans
  §5.2's join only inside a quoted-string, and such a string is malformed either
  way. Pinned by
  `a_response_written_with_implied_lws_completes_the_handshake` (h1) and by
  `connect_gates_enforce_the_extension_grammar` (extended CONNECT).
- **RFC 9110 §7.8's ordering MUST is honoured.** When the upgrade request
  carried `Expect: 100-continue`, `encode_response` writes the `100 (Continue)`
  ahead of the 101 into the same buffer; a short buffer leaves the obligation
  outstanding rather than discharging it against bytes the caller must not send
  (`a_hundred_continue_precedes_the_switch`,
  `a_short_buffer_does_not_lose_the_hundred_continue`).
- **An extended CONNECT refuses an ambiguous `Origin`, and the client cannot
  write one.** RFC 8441 §5 carries `Origin` onto the h2/h3 transports in as many
  words — "The Origin [RFC6454], Sec-WebSocket-Version, Sec-WebSocket-Protocol,
  and Sec-WebSocket-Extensions header fields are used in the CONNECT request and
  response-header fields as defined in [RFC6455]" — and RFC 6454 §7 gives it one
  SP-separated `origin-list-or-null`, so RFC 9110 §5.3 forbids repeating it. The
  gate now refuses a repeat as `DuplicateOrigin` (reject-only, so the caller
  still answers), `ConnectRequestView::origin` resolves it, and `origin` is out
  of the first-occurrence escape hatch on BOTH transports: `header("origin")`
  routes back through the accessor, so the two cannot answer differently even
  below a gate. The outbound half is the same defect from the other side — the h1
  client could put two `Origin` extras in a request its own server then refused —
  and `ExtraHeaders::validate` now refuses a repeated extra header for the names
  this crate itself resolves as singletons: `Origin`, plus `Host`,
  `Sec-WebSocket-Key` and `Sec-WebSocket-Accept`, which the managed-collision
  check already refuses outright. Every other name may still repeat, because RFC
  9110 §5.3's exception covers every field "definition \[that\] allows multiple
  field line values to be recombined as a comma-separated list" — an open set
  that includes `Cache-Control` and `Via`, so refusing by default would break
  conforming layouts. `Sec-WebSocket-Version` is deliberately absent for the same
  reason: the only extras that may carry it are a rejection's, and RFC 6455
  §11.3.5 makes it one that "MAY appear multiple times in an HTTP response"
  (`a_repeated_origin_is_refused_on_extended_connect`,
  `the_two_transports_agree_on_the_origin_rule`,
  `the_escape_hatch_does_not_answer_a_resolved_field`,
  `an_extra_header_may_not_repeat_a_singleton_field_name`,
  `a_rejection_may_advertise_several_versions_but_not_two_origins`,
  `what_the_client_emits_our_own_server_accepts`).
- **The offer-uniqueness scan is no longer quadratic in a peer's input.** The
  offers "MUST all be unique" (RFC 6455 §4.1 item 10) and this crate allocates
  nothing, so uniqueness is proved by re-walking the value once per offer —
  Θ(offers × bytes) over input an unauthenticated peer chooses. A 16 KiB head of
  one-byte offers cost **22.8 ms and was ACCEPTED**; extended CONNECT passed the
  same function a header slice with no length of its own at all. Both halves are
  now bounded inside the one function both gates call, and mirrored at both
  emitters so nothing this crate writes is something it refuses to read. The
  worst input either server now accepts costs **371 µs**, and the 16 KiB dense
  head is refused in 13.8 µs. RFC 9110 §5.6.1.2 asks for the bound in as many
  words — a recipient parses empty list elements "but not so much that they could
  be used as a denial-of-service mechanism" — and §5.4 makes the refusal a 4xx,
  which is what a reject-only handshake writes (`the_offer_list_is_bounded`,
  `the_offer_count_is_bounded_by_what_our_own_server_reads`,
  `the_offer_count_bound_is_the_same_in_both_directions`,
  `the_offer_count_bound_is_symmetric_on_both_transports`).
- **The client's subprotocol offers are one field line again.** The re-base
  emitted one `Sec-WebSocket-Protocol` field LINE per offer, so sixty one-byte
  offers made a sixty-five-line head — and `http1-proto`'s own server, the one
  behind `ServerHandshake` and behind both drivers, refuses a head past
  `MAX_HEADERS = 64`. Configurations that round-tripped before the re-base failed
  after it, on every path. RFC 6455 §4.1 item 10 spells the offer as "one or more
  comma-separated subprotocol", and that is what goes out: `ClientHandshake::new`
  joins the offers ONCE, in the pass that already validated them, into an inline
  buffer the `Headers` walk only reads — which is what keeps the section
  walk-stable without a line per offer. The accidental field-count cliff at the
  peer becomes the documented byte limit `h1::MAX_SUBPROTOCOL_OFFER_BYTES` (512),
  and a longer list is refused by `ClientHandshake::new` with the limit named
  (`subprotocol_offers_travel_as_one_bounded_field_line`,
  `sixty_subprotocol_offers_round_trip_through_our_own_server`, and one test per
  driver).

### Changed

- An HTTP/1.0 status line is accepted rather than refused outright, and a higher
  1.x minor is processed as 1.1 (RFC 9110 §6.2).
- Up to four leading empty lines before a request are tolerated (RFC 9112 §2.2).
- A `Sec-WebSocket-Extensions` member the walk cannot resolve ENDS the walk —
  past a value §9.1's grammar does not admit, nothing behind it is what the peer
  wrote — where the old splitter skipped that element and kept looking. An offer
  behind a malformed member is therefore not granted
  (`an_offer_behind_an_unresolvable_member_is_not_granted`). This fails closed:
  declining an extension is always available to a server (RFC 7692 §7.1.1), so
  the handshake still completes, just without compression.

### Tooling

- **Handshake differential harness** (`handshake-corpus`, driven by
  `cargo run -p xtask -- handshake-diff <base> [head]`): 1967 cases over the five
  handshake surfaces — the h1 server and client, the extended-CONNECT gate on
  both sides, and the two EMITTERS read back by this crate's own gate — each
  reporting the verdict a build reaches for it. `xtask` builds the corpus (one
  file, always the working tree's, public API only) against two revisions of
  `websocket-proto` and diffs the records, so a verdict that moved is the
  revision range's doing and nothing else's. It reports them grouped by
  `(role, field, reason)`.
- 165 of the cases' groups are **equivalence groups**: one logical field value
  written several ways (RFC 9110 §5.2/§5.3, RFC 6455 §9.1's "MAY be split or
  combined across multiple lines", RFC 2616 §2.1's null elements), which must all
  reach one verdict. A group that disagrees is a reader making a distinction the
  grammar does not — the defect found three times in this cycle, always between a
  gate and a reader that resolved one field separately — and one on the head side
  fails the command. The claim is withheld exactly where the ROLES make the
  distinction: the response `Sec-WebSocket-Protocol` is §4.2.2's single
  selection, and `Origin` is RFC 6454 §7's SP-separated `origin-list-or-null`,
  so neither has a split spelling.
- Measured over this branch: `3b13c5d..HEAD` moves 204 verdicts and takes the
  equivalence violations from 8 to 0; `90d1d1e..HEAD` — the last two commits —
  moves 117 and holds them at 0. Earlier revisions are out of reach: the corpus
  is written against the public API, and `ServerProgress::Upgrade` was a struct
  variant before `3b13c5d`.

## `wren-compio` + `wren-reactor` — cycle 5 (re-based handshake drivers)

Both drivers follow `websocket-proto` 0.2.0's two-phase accept: the pending
accept carries an advanced `ServerHandshake`, which holds the validated answer
itself, so the application's accept-or-reject choice happens between
classification and the answer, and either answer is written through the
connection that read the request — with nothing beside it that could be paired
with a different one.

### Fixed

- **A handshake the server stops processing is answered, not dropped.** RFC 6455
  §4.2.1: "the server MUST stop processing the client's handshake and return an
  HTTP response with an appropriate error code (such as 400 Bad Request)".
  `accept`/`accept_pending` used to propagate the fault and drop the transport
  with nothing on the wire, leaving the client unable to tell a rejected
  handshake from a dead server. A version the server does not speak now gets RFC
  6455 §4.2.2's 426 carrying `Sec-WebSocket-Version: 13`; anything else gets 400,
  or the code `http1_proto::Error::suggested_status` names for an HTTP-level
  fault. Best-effort by construction: the error returned is always the one that
  failed the handshake, never one from writing the refusal — the caller needs to
  know why the handshake failed, not that the apology could not be delivered. A
  `validate_accept` failure is deliberately NOT answered this way: the answer was
  built from this request's own offers, so a fault there is the server refusing
  its own answer rather than the client's handshake being invalid.
- **Interim responses no longer grow the client's buffer without bound.** The
  client loop advanced a cursor past each consumed 1xx head and never dropped
  what it had passed, while later reads kept appending — and RFC 9110 §15.2 puts
  no limit on how many interim responses may precede the final one, so a hostile
  server could stream 1xx heads until the client exhausted memory. The consumed
  prefix is now dropped after each interim (the suffix glued behind it, when one
  read carried both, is preserved), which bounds the buffer at one head plus one
  read chunk.
- **…and the reading stops.** Compacting bounds the memory that stream costs,
  not the work: a server can still send interim responses forever, and a client
  that obeys §15.2 literally never returns — a connect hung with nothing to
  report, and neither driver applies a handshake deadline. Both now abandon the
  attempt after 32 interim responses with the new
  `ConnectError::TooManyInterimResponses { limit }`. 32 is set against what a
  conforming server sends (RFC 9110 §10.1.1 allows one `100 (Continue)` per
  request; RFC 8297's `103 (Early Hints)` arrives once or a small handful of
  times), so it bounds a hostile peer's work at 32 heads without touching any
  real pattern. It is a driver policy, not a protocol rule: `websocket-proto`
  classifies one head per call and has no loop to bound.

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
