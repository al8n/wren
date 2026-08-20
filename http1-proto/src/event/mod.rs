//! The driver vocabulary: what a connection hands back, and what names the
//! message each piece belongs to.
//!
//! Three shapes, split by ownership, because they answer different questions.
//!
//! `Item` is BORROWED. A head, a body chunk, a trailer field — each points into
//! the very slice the driver fed in, so a megabyte of upload crosses this core
//! without being copied and without the core holding a buffer to copy it into.
//! That is what a no-alloc Sans-I/O core is for, and it is why `Items`, the
//! iterator that yields them, has the lifetime structure documented on the type:
//! an item's bytes belong to the DRIVER's buffer, not to the connection, and the
//! type system is what says so.
//!
//! `Event` is OWNED and tiny. "The peer ended keep-alive" is a fact about the
//! connection rather than about any byte of the input, so there is nothing to
//! borrow: it is a small `Copy` value the driver drains after the items, on its
//! own schedule.
//!
//! `ExchangeId` ties the two together. RFC 9112 §9.3 lets one connection carry
//! many messages in sequence, so "a body chunk arrived" is not a complete
//! statement — the driver has to know WHICH message it belongs to, all the more
//! so when it pipelined several. The core mints that number; it never comes from
//! the driver.
//!
//! The borrow architecture the whole inbound path is built on is documented on
//! `Items`. Read it before writing anything that produces items.

use crate::{
  body::Budget,
  connection::{Borrows, Exchange, Lifecycle, RecvState, SendState, inbound, writable},
  error::Error,
  head::{HeadView, RequestLine, StatusLine},
};

/// No message body is being received, so there is no ceiling to narrow.
///
/// The RECEIVE side's, and named apart from `outbound::NO_BODY_IN_FLIGHT` — the
/// send side's answer to "write these body octets" — because the two describe
/// opposite directions and nothing but the name would say so at a call site.
///
/// Distinct from the lifecycle's own answers by its TEXT alone, which is why the
/// benign case — a message RFC 9112 §6.3 items 1 and 7 frame with no content at
/// all — is deliberately NOT reported here: a caller cannot branch on a
/// `&'static str`, so folding "this message has no body" in would make it
/// indistinguishable from "this connection is dead".
pub(crate) const NO_BODY_BEING_RECEIVED: &str = "no message body is being received";

/// The number that names one request/response exchange on a connection.
///
/// Minted by the CORE, never by the driver, and monotone by construction: the
/// connection owns a single counter and takes its value each time an exchange
/// begins, so ids are issued in the order the exchanges start. That ordering is
/// what makes the id useful on a pipelined connection — RFC 9112 §9.3 requires
/// responses to come back in request order — and it is why this is `Ord`:
/// comparing two ids answers which exchange came first.
///
/// Ids are per-connection. Two connections each start from their own first
/// number, and nothing here is a globally unique handle.
///
/// An interim (1xx) response does NOT mint a new one. The exchange continues
/// through any number of them until its final head arrives (RFC 9110 §15.2), so
/// every interim head carries the id of the exchange it belongs to.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ExchangeId(u64);

impl ExchangeId {
  /// Wraps a number the connection's counter produced.
  ///
  /// Deliberately no more than a wrapper: this cannot make ids monotone,
  /// because it does not own the counter. Monotonicity is the CONNECTION's
  /// invariant — the connection is the only caller, it calls this once per
  /// exchange it opens, with its counter's current value. Keeping the
  /// constructor crate-private is what makes that invariant hold for every id
  /// in existence: no driver can fabricate an id for an exchange the core never
  /// opened, or re-use one it already closed.
  #[inline(always)]
  pub(crate) const fn new(number: u64) -> Self {
    Self(number)
  }

  /// The underlying number — a map key or a log field on the driver side.
  ///
  /// The core attaches no meaning to the value beyond its order, so a driver may
  /// treat it as opaque; it may not construct one.
  #[inline(always)]
  pub const fn get(self) -> u64 {
    self.0
  }
}

/// The parsed start line of a head, borrowed from the block it was read out of.
///
/// RFC 9112 §2.1 puts a start-line above every message's field lines, and which
/// one it is is the RECIPIENT's context rather than anything in the bytes: a
/// server reads §3's `request-line`, a client §4's `status-line`. This enum is
/// that context made explicit, so a driver handed an [`Item::Head`] can read the
/// method it must route on, the target it must resolve, or the status it must
/// act on — without re-parsing a line the core has already parsed once.
///
/// Both payloads borrow the same block [`HeadView`] does and are `Copy`, so
/// carrying one costs the width of a couple of slices and no allocation.
///
/// `#[non_exhaustive]`, unlike the [`Target`](crate::Target) inside a
/// [`RequestLine`]: RFC 9112 §3.2 closes the target forms at four, but which
/// start lines this core hands a driver is a fact about the API surface rather
/// than about the grammar — a mode that reports something other than a request-
/// or status-line would add a variant here. A consumer matches with a `_` arm.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum StartLine<'a> {
  /// A request's RFC 9112 §3 `request-line`: method, request-target, version.
  Request(RequestLine<'a>),
  /// A response's RFC 9112 §4 `status-line`: version, status-code, reason.
  Status(StatusLine<'a>),
}

/// One parsed inbound unit, borrowed from the slice the driver fed in.
///
/// The variants are the parts RFC 9112 §2.1 builds a message out of — a head,
/// then a body — plus the trailer section §7.1.2 allows a chunked body to end
/// with, plus the two signals a driver has to act on rather than merely forward.
/// Every one of them names its exchange, because a keep-alive connection carries
/// many (§9.3).
///
/// Borrowed, never owned: `data` and `value` ARE the fed bytes, and `view` reads
/// its fields straight out of the head block. An item is valid for as long as
/// the input slice is — see the borrow rules on [`Items`], which is what
/// guarantees an item outlives the iterator that produced it.
///
/// No `PartialEq`: [`HeadView`] does not implement it (comparing two heads is a
/// question about fields, not about bytes, and the answer depends on which
/// fields the caller means), so an item is matched on rather than compared.
///
/// `#[non_exhaustive]`, unlike [`Target`](crate::Target) or
/// [`BodyPlan`](crate::BodyPlan): those enumerate sets the RFCs closed — RFC 9112
/// §3.2's four target forms, §6.3's four framings — and a fifth would mean the
/// protocol changed, so a consumer is entitled to match them exhaustively. This
/// is the opposite kind of enum: it is what this core chooses to SURFACE out of
/// a message, and a future item (a parsed `Expect` other than `100-continue`,
/// say) is an addition to that vocabulary rather than a change to HTTP. A
/// consumer therefore matches with a `_` arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum Item<'a> {
  /// A complete head: the request on a server, a response on a client.
  Head {
    /// The exchange this head belongs to. A server head OPENS the exchange (the
    /// id is freshly minted); a client head continues the one whose request it
    /// answers.
    exchange: ExchangeId,
    /// The head itself, read lazily out of the borrowed block.
    view: HeadView<'a>,
    /// The parsed start line above those fields.
    ///
    /// The core parsed it to decide the message's framing, so it is handed over
    /// rather than thrown away: [`view`](HeadView) answers "what fields did this
    /// head carry?", and this answers "what message is it?" — the RFC 9112 §3
    /// method and request-target a server routes on, or the §4 status-code a
    /// client acts on. Always [`StartLine::Request`] on a server connection and
    /// [`StartLine::Status`] on a client one, matching the role.
    line: StartLine<'a>,
    /// Whether this is an interim (1xx) response rather than the final head.
    ///
    /// RFC 9110 §15.2 lets any number of them precede the final response and
    /// requires a client to parse them, so an interim head does NOT end the
    /// exchange and does NOT begin a body: the final head is still to come, on
    /// this same [`ExchangeId`]. Always `false` on a request.
    interim: bool,
  },
  /// Payload octets in arrival order, borrowed from the fed slice.
  ///
  /// A body is delivered as it arrives, in whatever pieces the transport
  /// happened to deliver, so one body yields as many of these as it takes; the
  /// chunked coding's framing is already stripped (RFC 9112 §7.1).
  BodyChunk {
    /// The exchange whose body these octets belong to.
    exchange: ExchangeId,
    /// The octets themselves, pointing into the driver's buffer.
    data: &'a [u8],
  },
  /// One field of the trailer section that closed a chunked body (RFC 9112
  /// §7.1.2), yielded per field line in arrival order.
  Trailer {
    /// The exchange whose trailer section this field came from.
    exchange: ExchangeId,
    /// The field name. A validated field name is a `token` (RFC 9110 §5.6.2)
    /// and therefore ASCII, so it surfaces as `&str`.
    name: &'a str,
    /// The field value, OWS-trimmed. Bytes, not text: `obs-text` (RFC 9110
    /// §5.5) is legal field content and need not be UTF-8.
    value: &'a [u8],
  },
  /// The exchange's inbound side is complete: head, body, and trailers are all
  /// through, and the next bytes belong to the next message.
  ExchangeComplete {
    /// The exchange that just completed.
    exchange: ExchangeId,
  },
  /// Server-side: the request carried `Expect: 100-continue` (RFC 9110 §10.1.1),
  /// so the client is waiting for the head to be approved before it sends the
  /// body.
  ///
  /// Surfaced right after the head it belongs to. The core states the ask and
  /// nothing more — answering `100 Continue`, answering a final status, or
  /// waiting is the driver's policy.
  ExpectContinue {
    /// The exchange whose request carried the expectation.
    exchange: ExchangeId,
  },
}

/// The borrowed iterator a connection returns from `handle`. Drive it with
/// [`next`](Self::next) until it yields `Ok(None)`.
///
/// # Lifetime and borrow architecture
///
/// This shape is load-bearing rather than incidental: it is what lets the pump
/// mutate connection state while handing out items that borrow the driver's
/// input, and a pump written against any other shape does not compile. It needs
/// nothing beyond stable NLL — no polonius.
///
/// THREE of the four techniques below are `http3-proto`'s, and are worth reading
/// there: the disjoint field borrows (`RequestFrames`, in
/// `http3-proto/src/connection/mod.rs`), the borrow-free `Advanced { start, end }`
/// step and the `input` accessor (both on `stream::Items`, in
/// `http3-proto/src/stream/mod.rs`).
///
/// The fourth — a non-lending `next` — is a deliberate DIVERGENCE, and reading h3
/// for it would mislead: h3's iterators LEND. `Frames::next` yields `Frame<'_>`
/// and `stream::Items::next` yields `StreamItem<'_>`, both tied to `&mut self`.
/// The cause is QPACK: a decoded field section is materialized into storage the
/// iterator reaches (the FSM's field accumulator plus the caller's Huffman
/// scratch), so a headers item cannot borrow the input the way h3's DATA chunks
/// do — and one such variant is enough to make the whole enum lend. HTTP/1.1 has
/// no header compression. A field name and value are literal substrings of the
/// bytes on the wire, as are a body chunk and a trailer, so no variant has
/// scratch to borrow and this iterator does not lend at all.
///
/// **`'a` is the driver's input; `'c` is the connection.** Two parameters
/// because the two borrows end at different times. The input slice is the
/// driver's accumulation buffer and outlives the iterator; the connection borrow
/// lasts exactly as long as the iterator does. Collapsing them would tie every
/// item's bytes to the connection's borrow and make the whole design pointless.
///
/// **The connection is DESTRUCTURED, never borrowed whole.** This type does not
/// hold `&'c mut Connection`. It holds a separate `&'c mut` borrow of each
/// connection FIELD the pump touches, taken at construction time by
/// destructuring `self` (through `connection::Borrows`, which is only the
/// vehicle — the borrows land as one field each). Those fields are disjoint, so
/// the borrow checker allows all of them at once — while a single whole-struct
/// borrow would make every step re-borrow everything, so that advancing the
/// receive FSM and, in the same expression, minting an id / pushing an event /
/// bumping the consumed counter would conflict. The set is the consumed counter,
/// the head-scan watermark, the receive FSM, the exchange in flight, the counter
/// that mints the next [`ExchangeId`], the send-side state the keep-alive re-arm
/// is gated on, the lifecycle latch, the event slot, the pending-CR flag, and the
/// idle-client CRLF tally. The
/// rule for adding any more: each must be its OWN `Connection` field. If two pieces of state the pump
/// mutates independently ever share one field, split that field — do not reach
/// for `&mut Connection`.
///
/// **[`next`](Self::next) returns `Item<'a>`, not `Item<'_>` — the divergence
/// from h3.** An item is tied to the INPUT lifetime and borrows nothing from the
/// iterator, so it stays valid across later `next()` calls and outlives the
/// iterator itself. Available only because nothing here is decompressed (see
/// above), and REQUIRED rather than merely available: a pump holds a `view`
/// while pulling the next item, which a lending `Item<'_>` cannot support.
/// The cost is a rule the pump has to keep — an item's payload may never be
/// re-derived from `&self`, no matter how convenient a scratch buffer would be
/// for some future variant, because one lending variant would take the whole
/// enum with it exactly as QPACK does in h3. It is
/// re-sliced from the crate-internal `input` accessor, which takes `&self` but
/// returns `&'a [u8]` and therefore hands back a slice whose lifetime is
/// independent of the `&mut self` the pump is holding.
///
/// **The FSM steps return OFFSETS, not borrows.** An internal step reports what
/// it advanced past as borrow-free indices into the input (`http3-proto` spells
/// this `Advanced { start, end }`), and the caller re-slices them through
/// `input` afterwards. The reason is the loop: the pump has to iterate —
/// skipping a zero-length chunk, running a state transition that produces
/// nothing — and a step that returned a borrow of `*self` would keep that borrow
/// live across the loop's back-edge, which stable NLL rejects. Offsets cross the
/// back-edge freely, and the borrow is re-derived exactly once at the point of
/// yield.
///
/// **The consumed counter LIVES IN the connection.** It is not a tally this
/// iterator keeps; [`consumed`](Self::consumed) reads the connection's own
/// counter through one of the disjoint borrows, and the pump advances it as each
/// item is emitted. That is what makes dropping the iterator mid-iteration safe:
/// what was consumed stays consumed, so when the driver re-offers its buffer
/// from the reported point nothing re-emits and nothing is re-parsed. A counter
/// living here would be lost on drop, and the driver would either replay bytes
/// or skip them — the recipient disagreement RFC 9112 §11.2 is about.
///
/// Nothing else has to happen on drop, and that is a real difference from
/// `http3-proto`, which drains its iterator on drop to catch a violation the
/// driver never pulled. Here the bytes past the counter are simply left
/// unconsumed, so the driver's next offer re-presents them and whatever is wrong
/// with them is diagnosed then. A drop-drain would re-parse the same bytes twice
/// for no gain — provided the pump keeps the invariant that makes it true:
/// input bytes are counted as consumed only once the item they produced has been
/// YIELDED, never merely because a step looked at them.
///
/// The FSM behind all of this lives in `connection::inbound`, which is where the
/// two documented exemptions to that invariant — the head-scan watermark and the
/// chunked coding's own framing lines, neither of which any item ever carries —
/// are spelled out.
pub struct Items<'a, 'c> {
  /// The driver's input slice. Every item's payload is re-sliced out of this,
  /// and it is `Copy`, so handing a piece of it out never borrows the iterator.
  pub(crate) input: &'a [u8],
  /// Whether the connection is a client, off the type-state: the pump is one
  /// non-generic function, so the role reaches it as a value.
  pub(crate) is_client: bool,
  /// The operator's ceiling on the payload octets one inbound body may deliver.
  ///
  /// BY VALUE, and that is the property rather than an economy: the pump is
  /// handed a copy of the connection's field, so no step of it can raise the
  /// ceiling even by accident. It is read once, where a head's framing decision
  /// builds the decoder that will enforce it.
  pub(crate) max_body: u64,
  /// The budget for the RFC 9112 §7.1 chunk-size lines one inbound body may
  /// spend.
  ///
  /// BY VALUE for the same reason, and read at the same one site: framing and
  /// payload are two ceilings on one body, so they reach its decoder together.
  pub(crate) max_chunk_framing: u64,
  /// A disjoint borrow of the connection's consumed counter. It stays a
  /// connection field rather than a tally kept here, because drop-safety depends
  /// on it: see the paragraph above.
  pub(crate) consumed: &'c mut usize,
  /// How far into an unterminated head the scan has already looked.
  pub(crate) watermark: &'c mut usize,
  /// The number the next exchange to begin will take.
  pub(crate) next_exchange: &'c mut u64,
  /// Where the inbound side of the connection stands.
  pub(crate) recv: &'c mut RecvState,
  /// The exchange in flight, whose id every item names.
  pub(crate) exchange: &'c mut Option<Exchange>,
  /// Where the local send side stands — the keep-alive re-arm gate.
  pub(crate) send: &'c mut SendState,
  /// Where the connection stands in its life, including the failure latch.
  ///
  /// POLICY only. Whether the transport can still produce bytes is
  /// [`read_closed`](Self::read_closed), a separate fact — see `Lifecycle`.
  pub(crate) lifecycle: &'c mut Lifecycle,
  /// The queued connection-scoped notice.
  pub(crate) event: &'c mut Option<Event>,
  /// Whether the PEER's write side has ended, so no further byte can arrive.
  ///
  /// A fact about the TRANSPORT, borrowed beside the lifecycle rather than
  /// folded into it: the pump needs it to tell "these bytes are exhausted, ask
  /// again after a read" from "these bytes are all there will ever be".
  pub(crate) read_closed: &'c mut bool,
  /// Whether the PEER has stated RFC 9112 §9.6's `close` option — provenance the
  /// lifecycle cannot carry, since both ends can close a connection but only the
  /// peer's decision releases this end from sending.
  pub(crate) peer_close: &'c mut bool,
  /// Whether a completed CLIENT exchange left bytes behind in the offer that
  /// completed it, which no request may be opened over (RFC 9112 §9.2).
  pub(crate) tail_unresolved: &'c mut bool,
  /// The exchange that ended without its final response, if one just did.
  pub(crate) aborted: &'c mut Option<ExchangeId>,
  /// Whether a lone `\r` is pending at a client's idle cursor (RFC 9112 §2.2:
  /// undecided until its next byte arrives).
  pub(crate) pending_cr: &'c mut bool,
  /// How many stray empty lines an idle client has discarded since its last
  /// request (RFC 9112 §9.2), which is bounded cumulatively because those bytes
  /// ARE consumed.
  pub(crate) idle_crlfs: &'c mut u8,
}

impl<'a, 'c> Items<'a, 'c> {
  /// Builds the iterator over `input` from the connection's destructured
  /// borrows.
  ///
  /// Crate-private: an `Items` is only ever produced by the connection that owns
  /// the state it borrows, which is what keeps the borrows disjoint by
  /// construction.
  #[inline]
  pub(crate) fn new(input: &'a [u8], borrows: Borrows<'c>) -> Self {
    let Borrows {
      is_client,
      max_body,
      max_chunk_framing,
      consumed,
      watermark,
      next_exchange,
      recv,
      exchange,
      send,
      lifecycle,
      event,
      read_closed,
      peer_close,
      tail_unresolved,
      aborted,
      pending_cr,
      idle_crlfs,
    } = borrows;
    Self {
      input,
      is_client,
      max_body,
      max_chunk_framing,
      consumed,
      watermark,
      next_exchange,
      recv,
      exchange,
      send,
      lifecycle,
      event,
      read_closed,
      peer_close,
      tail_unresolved,
      aborted,
      pending_cr,
      idle_crlfs,
    }
  }

  /// The next inbound item, or `Ok(None)` when the fed bytes yield no more.
  ///
  /// `Ok(None)` is "these bytes are exhausted", NOT "this connection is done":
  /// the remainder may be a partial head the driver has to keep accumulating, or
  /// a complete message the connection is holding back until its own send side
  /// catches up. The connection's readiness accessors are what tell those apart,
  /// and [`consumed`](Self::consumed) is what says how much of the input to drop
  /// before offering the rest.
  ///
  /// `Err` is TWO different answers, and a driver that treats them alike loses
  /// the response it is still allowed to send:
  ///
  /// - [`Error::Protocol`] is a wire violation, and it is terminal for the
  ///   connection rather than for this call: the connection latches into its
  ///   failed state and no further item can surface after it.
  /// - [`Error::Refused`] is this end's own POLICY refusing a message the peer
  ///   framed correctly. The connection has NOT failed. `poll_event` has queued
  ///   [`Event::CloseSignaled`], [`wants_read`] is false, and a server's
  ///   [`is_awaiting_send`] is TRUE until it has written its one answer — which
  ///   must state the `close` connection option (RFC 9112 §9.3). Treating this
  ///   as terminal drops a `413` the peer is entitled to.
  ///
  /// [`Error::Protocol`]: crate::Error::Protocol
  /// [`Error::Refused`]: crate::Error::Refused
  /// [`wants_read`]: crate::Connection::wants_read
  /// [`is_awaiting_send`]: crate::Connection::is_awaiting_send
  // Not `Iterator`: that trait's `next` cannot be fallible, and `Ok(None)` here
  // means "feed me more", which is not iterator exhaustion either — collapsing
  // the two would let a `for` loop silently treat a partial head as the end of
  // the stream. `http3-proto`'s `Frames::next` carries the same allow but for an
  // additional reason that does NOT apply here: its items lend (see the type doc).
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Result<Option<Item<'a>>, Error> {
    inbound::pump(self)
  }

  /// Bytes of the input consumed so far — the driver's cue for how far to
  /// advance its buffer before re-offering the rest.
  ///
  /// Reads the CONNECTION's counter, which the pump advances as each item is
  /// emitted; see the drop-safety paragraph on the type. Zero is a legitimate
  /// answer: a partial head consumes nothing until the whole head is present, so
  /// the driver simply keeps accumulating.
  #[inline]
  pub fn consumed(&self) -> usize {
    *self.consumed
  }

  /// Narrows the ceiling on the body in flight to `max` payload octets.
  ///
  /// NARROWING ONLY: the effective ceiling becomes `min(current, max)`. `min` is
  /// idempotent and commutative, so this may be called any number of times, in
  /// any order, right after [`Item::Head`] or mid-body, and the answer is the
  /// same. There is no "exactly once, before X" rule to get wrong, which is the
  /// whole reason the call is safe to FORGET: forgetting it leaves the
  /// operator's ceiling in force. A routing bug cannot LIFT that ceiling,
  /// because this operation has no increasing direction to be pointed in — not
  /// because a check refuses one.
  ///
  /// # The connection ceiling must be the maximum over all routes
  ///
  /// A route limit ABOVE the connection's ceiling is silently capped, since
  /// narrowing is `min`: `limit_body(8 << 20)` on a connection built with a
  /// 1 MiB ceiling answers `Ok` and grants 1 MiB. Construct the ceiling
  /// ([`Connection::with_limits`]) as the maximum over every route this
  /// connection may serve; a ceiling taken from one route's limit caps every
  /// route above it and reports nothing.
  ///
  /// It narrows the PAYLOAD ceiling and nothing else. The connection's
  /// chunk-framing budget ([`Connection::max_chunk_framing_bytes`]) belongs to
  /// the connection, so a route narrowed to a few kilobytes still carries the
  /// whole of it. A narrowed route's true exposure is therefore
  /// `route_payload + (5/3) × connection_framing` octets of wire, plus a
  /// trailer section and one unterminated line: every RFC 9112 §7.1 chunk
  /// spends at least three charged octets, so the budget admits at most `F/3`
  /// chunks and the `2F/3` octets of chunk-data CRLF that go with them.
  /// Narrowing a route to 4 KiB on a connection whose framing budget is 64 KiB
  /// therefore still admits `4096 + (5/3) × 65_536` ≈ **113,300 octets** —
  /// 110.7 KiB — of wire for a message whose content is capped at 4 KiB. Construct
  /// the connection's framing budget accordingly
  /// ([`Limits::with_max_chunk_framing_bytes`]); there is deliberately no
  /// per-route knob for it.
  ///
  /// # What it refuses, and when
  ///
  /// The bound is on the message's TOTAL, not on what is left: `limit_body(4096)`
  /// after 6000 octets have already been handed over refuses immediately.
  ///
  /// `Err(Error::Refused(Refusal::BodyTooLarge { .. }))`, with the connection
  /// moved to the refused disposition (see [`Refusal`]), when `max` cannot be
  /// satisfied — either more than `max` octets have already been delivered, or
  /// the framing has already DECLARED more than fits: a `Content-Length`
  /// remainder (RFC 9112 §6.3 item 6), or the remainder of the chunk in flight
  /// (§7.1). That is the case the call exists for. The `limit` the refusal
  /// carries is the ROUTE's `max`, not the ceiling it replaced: the narrowing is
  /// committed before satisfiability is checked.
  ///
  /// `Ok(())` on a message with no body — RFC 9112 §6.3 items 1 and 7 make a
  /// bodiless message a body of no octets, so nothing has been delivered, no
  /// ceiling can be exceeded, and a driver that narrows after every head is not
  /// punished for a conformant GET, HEAD response or 304 — and on a body already
  /// refused, since a refusal is not undone.
  ///
  /// A body already THROUGH is not in that list. Its octets are out, so a
  /// ceiling below what it delivered refuses like any other: the window between
  /// [`Item::BodyChunk`] and [`Item::ExchangeComplete`] is still a window in
  /// which this call can be made, and the answer there is about what the body
  /// delivered rather than about how far the item stream has been pumped.
  ///
  /// `Err(Error::InvalidState(_))` is reserved for a connection that cannot act
  /// on the call at all: no message is being received, or the connection has
  /// failed or drained. The distinction matters because
  /// [`Error::InvalidState`] carries a `&'static str` a caller cannot branch on
  /// — folding "this message has no body" into it would make it
  /// indistinguishable from "this connection is dead".
  ///
  /// # On `Items` rather than on `Connection`, and only there
  ///
  /// [`Item`] borrows the INPUT rather than the iterator, so a driver narrows
  /// while still holding the [`Item::Head`] it just pulled — before the pump has
  /// decoded one octet of that body, even when head and body arrived in the same
  /// offer. A `Connection`-level twin could not promise that, and two surfaces
  /// with one signature and different timing guarantees is a trap dressed as
  /// symmetry. Observing goes the other way: [`Connection::body_progress`] is
  /// read once this iterator has been dropped.
  ///
  /// [`Refusal`]: crate::Refusal
  /// [`Error::InvalidState`]: crate::Error::InvalidState
  /// [`Connection::with_limits`]: crate::Connection::with_limits
  /// [`Connection::max_chunk_framing_bytes`]: crate::Connection::max_chunk_framing_bytes
  /// [`Limits::with_max_chunk_framing_bytes`]: crate::Limits::with_max_chunk_framing_bytes
  /// [`Connection::body_progress`]: crate::Connection::body_progress
  pub fn limit_body(&mut self, max: u64) -> Result<(), Error> {
    // The lifecycle gate, which is `Connection::sendable`'s own — one statement
    // of it, two callers, so the receive side cannot come to answer a failed or
    // drained connection differently from the send side.
    writable(*self.lifecycle)?;
    // Read BEFORE the decoder is touched: a refusal names the exchange it
    // refused, and a narrowing that could not name one must change nothing. A
    // receive state holding a decoder was written beside a minted exchange, so
    // this is defensive rather than reachable.
    let Some(exchange) = *self.exchange else {
      return Err(Error::InvalidState(NO_BODY_BEING_RECEIVED));
    };
    // Exhaustive over the receive states, so a state added later has to say
    // whether a body can be narrowed in it.
    let satisfiable = match &mut *self.recv {
      RecvState::Body { decoder, .. } => decoder.narrow(max),
      RecvState::Idle | RecvState::AwaitingRearm => {
        return Err(Error::InvalidState(NO_BODY_BEING_RECEIVED));
      }
    };
    if satisfiable {
      return Ok(());
    }
    // The decoder is refused, and this resolves it in the same call: the
    // refusal's two storage windows stay contiguous, so no send gate can see a
    // connection that is neither refusable nor refused.
    // PAYLOAD: `narrow` writes the payload ceiling and reads only payload
    // counts, so the budget that refused is the one it narrowed.
    Err(Error::Refused(inbound::refused(
      self,
      exchange.id,
      Budget::Payload,
    )))
  }

  /// The fed input slice, at the INPUT lifetime.
  ///
  /// This is the accessor that decouples a payload from `&mut self`: it takes
  /// `&self` but returns `&'a [u8]`, so the pump can re-slice a chunk from the
  /// offsets a borrow-free FSM step reported and yield it as `Item<'a>` while
  /// still holding `&mut self`. Re-deriving a payload any other way ties it to
  /// the iterator and breaks the lending-free contract.
  #[inline]
  pub(crate) fn input(&self) -> &'a [u8] {
    self.input
  }
}

/// A connection-scoped notice, drained through `poll_event`.
///
/// Owned and small, because none of it describes the input: an event is a fact
/// about the connection's lifecycle that the driver acts on after it has drained
/// the items. ONE variant today, and that is the whole of what this core has to
/// say outside the item stream — everything about a MESSAGE reaches the driver
/// as an [`Item`], and everything a call could not do reaches it as the
/// [`Error`] that call returned.
///
/// [`Error`]: crate::Error
///
/// `#[non_exhaustive]` because that boundary can move: a lifecycle fact that
/// belongs to no message and to no call would land here, and adding it must not
/// be a breaking release. A consumer therefore matches with a `_` arm.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event {
  /// Keep-alive is over: the peer signalled close, or the local driver asked for
  /// one. Finish draining what is already parsed, then close the transport
  /// (RFC 9112 §9.6). No further exchange begins on this connection.
  CloseSignaled,
  /// This exchange ended WITHOUT its final response, and no
  /// [`Item::ExchangeComplete`] will follow for it.
  ///
  /// Exchange-scoped on purpose: [`CloseSignaled`](Self::CloseSignaled) says the
  /// connection is over and names nothing, so a consumer tracking exchanges
  /// cannot learn from it that a particular request went unanswered. It would
  /// wait, or fail to retry.
  ///
  /// # Exactly one producer
  ///
  /// A received 1xx that carries RFC 9112 §9.6's `close` connection option, on a
  /// General connection with an exchange in flight.
  ///
  /// §9.6 makes the peer close after the response CARRYING the option, and RFC
  /// 9110 §15.2 makes a 1xx informational — explicitly not the final response. So
  /// that head both ends the exchange and is not an answer to it, which is the
  /// only shape in this core that can do both. The head itself is still yielded
  /// as an ordinary interim [`Item::Head`]; this follows it.
  ///
  /// Every OTHER way an exchange ends produces something else, and the contrast
  /// is deliberate:
  ///
  /// - A complete message — including RFC 9112 §6.3 item 8's close-delimited one,
  ///   where the close IS the delimiter and the message is therefore COMPLETE —
  ///   yields [`Item::ExchangeComplete`]. (An earlier version of this variant
  ///   named that case as its reason. It was wrong, and the variant was deleted
  ///   for having no producer at all.)
  /// - A truncation, a framing fault, or an EOF before any response is a protocol
  ///   ERROR: the connection latches and the `Err` is the signal.
  /// - A [`Tunnel`](crate::Tunnel) handshake has no exchange to name; its
  ///   outcome is returned directly.
  ExchangeAborted {
    /// The exchange that ended unanswered.
    exchange: ExchangeId,
  },
}

#[cfg(test)]
mod tests;
