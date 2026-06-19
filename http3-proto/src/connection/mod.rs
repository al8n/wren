//! The top-level connection state machine: the Sans-I/O core a driver wraps to
//! run one HTTP/3 Extended-CONNECT tunnel (RFC 9114/9204/9220).
//!
//! The connection owns no I/O. It produces [`Transmit`]s (bytes the driver
//! writes on QUIC streams) and [`Event`]s (lifecycle signals), and it consumes
//! inbound stream bytes via [`handle_stream`](Connection::handle_stream). The
//! driver opens the QUIC streams the core asks for and reports their ids back
//! via [`provide_stream`](Connection::provide_stream); the core never mints
//! stream ids.
//!
//! # Role
//!
//! Both roles begin with [`start`](Connection::start), which enqueues the control
//! stream (carrying our SETTINGS) and the pair of idle QPACK streams (the dynamic
//! table is disabled). The client then sends its CONNECT request with
//! [`open_with`](Connection::open_with) — but only *after* the peer's SETTINGS
//! have arrived, so the RFC 8441 opt-in and the peer's
//! `MAX_FIELD_SECTION_SIZE` can be checked synchronously at send time. The server
//! accepts the request with [`accept_with`](Connection::accept_with). The
//! bidirectional request stream then carries the CONNECT HEADERS exchange
//! followed by the DATA tunnel.
//!
//! # Client flow
//!
//! 1. [`start`](Connection::start), then pump [`poll_transmit`](Connection::poll_transmit)
//!    to open the control + QPACK streams.
//! 2. Feed inbound bytes via [`handle_stream`](Connection::handle_stream) until
//!    [`peer_settings`](Connection::peer_settings) is `Some` (the peer's
//!    control-stream SETTINGS were decoded — there is no separate event for this).
//! 3. [`open_with`](Connection::open_with) the CONNECT request. It returns
//!    [`Error::WouldBlock`] if the peer's SETTINGS have not arrived yet (pump more
//!    and retry), [`Error::ExtendedConnectUnsupported`] if the peer did not opt in
//!    to Extended CONNECT, or [`Error::FieldSectionTooLarge`] if the request
//!    exceeds the peer's advertised `MAX_FIELD_SECTION_SIZE`; otherwise it enqueues
//!    the request HEADERS.
//!
//! # Scope
//!
//! The core stays HTTP-status- and WebSocket-agnostic: it reports the peer's
//! HEADERS as a [`Frame::Request`] / [`Frame::Response`] and lets the driver
//! validate the `:status` / `:protocol`. "Established" here means the CONNECT
//! HEADERS exchange completed, not that any particular status was seen.

mod queue;

use core::marker::PhantomData;

use derive_more::IsVariant;
use queue::{BoundedQueue, PendingResets, TX_CAP, TxError, TxRing};

use crate::{
  Error, HeaderSet,
  error::H3Error,
  event::{Event, ROLE_COUNT, StreamId, StreamKind, StreamRole, Transmit},
  frame::{self, FrameType},
  headers::Headers,
  qpack,
  settings::Settings,
  stream::{Advanced, HeadersKind, ReqBufAlloc, Stream},
  stream_store::StreamStore,
  validate::{self, MessageKind},
  varint,
};

#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
use crate::stream_store::{ArraySlot, ArrayStore};

pub use crate::stream::DefaultReqBuf;
pub use queue::{DefaultEventBuf, DefaultTxBuf};

mod sealed {
  pub trait Sealed {}
}

/// Marker for the connection role (client or server). Sealed: only [`Client`]
/// and [`Server`] implement it.
pub trait Role: sealed::Sealed {
  /// True for the client role.
  const IS_CLIENT: bool;
}

/// Client role marker.
pub struct Client;

/// Server role marker.
pub struct Server;

impl sealed::Sealed for Client {}
impl sealed::Sealed for Server {}
impl Role for Client {
  const IS_CLIENT: bool = true;
}
impl Role for Server {
  const IS_CLIENT: bool = false;
}

/// The uni-stream type byte for the HTTP/3 control stream (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;
/// The uni-stream type byte for an HTTP/3 push stream (RFC 9114 §6.2.2). We never
/// enable server push, so receiving one is `H3_ID_ERROR`.
const STREAM_TYPE_PUSH: u64 = 0x01;
/// The uni-stream type byte for the QPACK encoder stream (RFC 9204 §4.2).
const STREAM_TYPE_QPACK_ENC: u64 = 0x02;
/// The uni-stream type byte for the QPACK decoder stream (RFC 9204 §4.2).
const STREAM_TYPE_QPACK_DEC: u64 = 0x03;

/// Capacity for accumulating the peer control stream's SETTINGS frame *payload*.
///
/// Generous on purpose: a conforming peer may carry many settings plus
/// unknown/GREASE extension settings (RFC 9114 §7.2.4.1 / §9), so a tighter bound
/// would reject legal payloads and break interop. A SETTINGS payload that *still*
/// exceeds this bound is treated as implausibly large and rejected with
/// [`H3Error::ExcessiveLoad`] (an excessive-load policy — "this SETTINGS frame is
/// too big"), never [`H3Error::FrameError`] (which would mean "malformed") and
/// never a panic. Decoding still uses [`Settings::decode_payload`] over the
/// buffered payload.
pub const CTRL_CAP: usize = 1024;

/// Bytes available to one queued transmit.
///
/// The public alias of the internal `queue::TX_CAP`.
pub const TX_SLOT_CAP: usize = queue::TX_CAP;

/// Total byte storage needed by the default transmit ring.
pub const TX_BYTES_CAP: usize = queue::TX_BYTES_CAP;

/// Lifecycle-event queue slots needed by the default connection.
///
/// The public alias of the internal `queue::EVENT_CAP`.
pub const EVENT_QUEUE_CAP: usize = queue::EVENT_CAP;

/// Default control-stream SETTINGS payload storage.
///
/// With `std` or `alloc`, the default connection stores this in a heap-backed
/// `Vec<u8>` so the default owned `Connection` stays small.
#[cfg(any(feature = "std", feature = "alloc"))]
pub type DefaultCtrlBuf<'a> = std::vec::Vec<u8>;

/// Default control-stream SETTINGS payload storage.
///
/// With no allocator available, the default is borrowed caller-owned storage so
/// borrowed connections stay small. Construct it with
/// [`Connection::with_buffers`].
#[cfg(not(any(feature = "std", feature = "alloc")))]
pub type DefaultCtrlBuf<'a> = &'a mut [u8];

#[cfg(any(feature = "std", feature = "alloc"))]
fn default_ctrl_buf() -> DefaultCtrlBuf<'static> {
  std::vec![0u8; CTRL_CAP]
}

/// The largest a frame header (type varint + length varint) can be: two 8-byte
/// QUIC varints. Mirrors the request FSM's bound.
const CTRL_HDR_CAP: usize = 16;

/// A decoded frame yielded by [`Frames`]: the peer's request/response HEADERS, a
/// trailing HEADERS section (trailers), or a chunk of DATA. Borrows the
/// `handle_stream` scratch/input and is invalidated by the next [`Frames::next`].
//
// `Unwrap`/`TryUnwrap` are NOT derived: `derive_more` cannot generate them for a
// struct variant (`Response { .. }`) — it panics at derive time (exactly what bit
// `StreamItem`). `IsVariant` (unit-of-work predicates) handles every variant; the
// driver `match`es to bind the payload.
#[derive(IsVariant)]
#[non_exhaustive]
pub enum Frame<'a> {
  /// The peer's request HEADERS (server side): the leading field section.
  Request(HeaderSet<'a>),
  /// The peer's response HEADERS (client side): a leading field section.
  Response {
    /// Whether this is an interim (1xx informational) response, decided by the
    /// `:status` pseudo-header. `true` means more responses follow (one or more
    /// interim 1xx then exactly one final); `false` is the final response.
    interim: bool,
    /// The decoded response field section.
    headers: HeaderSet<'a>,
  },
  /// A trailing HEADERS section (trailers) after the body, in either direction.
  Trailers(HeaderSet<'a>),
  /// A chunk of DATA-frame payload (body / tunnel bytes). Yielded ONLY once the
  /// stream is established (the final response sent/seen; the CONNECT exchange
  /// completed). EVERY DATA-frame occurrence —
  /// including a zero-length one — passes the establishment gate, on BOTH the yield
  /// path ([`Frames::next`]) and the drop-drain (a dropped [`Frames`] cannot smuggle
  /// premature DATA past the gate): premature DATA — on the server before
  /// [`accept_with`](Connection::accept_with) sent the 2xx, or on any
  /// request stream whose tunnel was never established — is a malformed message
  /// ([`H3Error::MessageError`], RFC 9114 §4.4 / §4.1.2), terminal, and fails the
  /// connection instead of surfacing here or being silently discarded. An ESTABLISHED
  /// zero-length DATA frame is a real occurrence that is consumed but NOT surfaced as
  /// an empty `Frame::Data` (it carries no tunnel bytes). A post-`Open` half-close
  /// still delivers peer DATA.
  Data(&'a [u8]),
}

/// The per-stream LOCAL send half-FSM: the single source of truth for what the
/// local endpoint may legally enqueue NEXT on a stream, so no public-call sequence
/// can put protocol-invalid frame ordering on the wire (RFC 9114 §4.1 / §4.1.2).
/// It replaces the former ad-hoc `final_response_sent` / `local_send_closed`
/// booleans; every send guard validates against it and every successful send
/// transitions it. It is orthogonal to the inbound recv FSM and to the PEER's
/// half-close (`peer_closed`).
///
/// The legal sequence is role-shaped (the role is `Ro::IS_CLIENT`, so one enum
/// covers both; a server entry never holds [`RequestSent`](Self::RequestSent) and a
/// client entry never holds [`Idle`](Self::Idle) / [`FinalSent`](Self::FinalSent)):
///
/// - **Server response side:** [`Idle`](Self::Idle) (no leading section yet, or only
///   interim 1xx leading sections — both reject body / trailers / FIN) → a FINAL
///   response (a 2xx–5xx [`send_response`](Connection::send_response), or the tunnel
///   [`accept_with`](Connection::accept_with) 2xx) moves to
///   [`FinalSent`](Self::FinalSent), after which body / trailers may flow; interim 1xx
///   responses are allowed only while [`Idle`](Self::Idle) (none after the final).
/// - **Client request side:** [`RequestSent`](Self::RequestSent) (set at registration —
///   the request HEADERS are already enqueued) allows request body BEFORE any response,
///   with NO server-style final-response gate.
/// - **Both roles:** a trailing section ([`send_trailers`](Connection::send_trailers))
///   moves to [`TrailersSent`](Self::TrailersSent), which rejects any further body /
///   trailers (RFC 9114: at most one trailing section, nothing after it but the FIN);
///   [`finish`](Connection::finish) moves to [`Closed`](Self::Closed), after which
///   nothing may follow the FIN.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SendState {
  /// SERVER, no FINAL response sent yet (the start state, and the state across zero or
  /// more interim 1xx responses). Body / trailers / FIN are rejected here (premature
  /// DATA / a FIN before the response — RFC 9114 §4.1); only another
  /// [`send_response`](Connection::send_response) (interim or the one final) /
  /// [`accept_with`](Connection::accept_with) is legal. Never held by a client entry.
  Idle,
  /// CLIENT, request HEADERS enqueued (set at stream registration). Request body /
  /// trailers / FIN are all legal here, BEFORE any response — the client has no
  /// final-response gate. Never held by a server entry.
  RequestSent,
  /// SERVER, the FINAL response leading section has been sent (a 2xx–5xx
  /// [`send_response`](Connection::send_response) or the tunnel
  /// [`accept_with`](Connection::accept_with) 2xx). Body / trailers / FIN may now flow;
  /// a further [`send_response`](Connection::send_response) (interim OR final) is
  /// rejected (at most one final, none after it). Never held by a client entry.
  FinalSent,
  /// A trailing HEADERS section has been sent (either role). Only
  /// [`finish`](Connection::finish) is legal now — further body / trailers are rejected
  /// (at most one trailing section, and nothing follows it but the FIN).
  TrailersSent,
  /// [`finish`](Connection::finish) enqueued the terminating FIN (either role). The
  /// terminal state: every further local send is rejected (nothing follows the FIN).
  Closed,
}

impl SendState {
  /// Whether body / trailers may be enqueued in this state: the CLIENT request body
  /// window ([`RequestSent`](Self::RequestSent)) or the SERVER post-final-response
  /// window ([`FinalSent`](Self::FinalSent)). [`Idle`](Self::Idle) (server pre-final),
  /// [`TrailersSent`](Self::TrailersSent), and [`Closed`](Self::Closed) reject them.
  const fn can_send_body(self) -> bool {
    matches!(self, Self::RequestSent | Self::FinalSent)
  }
}

/// Which general per-stream send a [`guard_send_on`](Connection::guard_send_on) call is
/// validating against the [`SendState`], so the one guard can apply the right transition
/// rule: a DATA body, a trailing HEADERS section, or the terminating FIN.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SendOp {
  /// A DATA-frame body chunk ([`send_data_on`](Connection::send_data_on)).
  Body,
  /// A trailing HEADERS section ([`send_trailers`](Connection::send_trailers)).
  Trailers,
  /// The terminating empty FIN ([`finish`](Connection::finish)).
  Finish,
}

/// Per-stream connection-side state: the inbound recv FSM, the local send half-FSM
/// (`SendState`), plus the lifecycle markers that used to be singular
/// [`Connection`] fields (now one set PER stream, held in the [`StreamStore`]). The
/// CONNECT tunnel uses exactly one entry, keyed by the tunnel's `request_id`.
///
/// Its fields are private connection bookkeeping; the type is `pub` only so the
/// bare-tier caller can name `StreamSlot` when allocating
/// [`with_buffers`](Connection::with_buffers) storage (the same way [`UniSlot`]
/// is a public opaque handle around private parser state).
pub struct StreamEntry<'req, ReqBuf> {
  /// The inbound recv FSM for this stream (the read side of the request/response
  /// exchange). Was the singular `Connection::request`.
  fsm: Stream<'req, ReqBuf>,
  /// The first HEADERS was OBSERVED (yielded to the driver via [`Frames::next`]),
  /// not merely decoded. Server: gates [`accept_with`](Connection::accept_with).
  /// (Was the singular `request_received`.)
  observed: bool,
  /// The message exchange reached "established"/open for this stream (CONNECT 2xx
  /// seen/sent). Gates yielding [`Frame::Data`]; stays `true` across a later
  /// `Closing`. (Was the singular `tunnel_established`.)
  established: bool,
  /// Client-only PLACEMENT state: a FINAL (non-interim) response leading section was
  /// accepted on this stream. Distinct from `established` (the readiness / DATA-gate
  /// transition, set only on the LIVE yield): this is set inside the SHARED
  /// [`accept_headers_section`](RequestFrames::accept_headers_section) on BOTH the live
  /// and drop-drain paths, so a later `Initial` HEADERS after the final response is
  /// rejected identically on both ([`Frames::next`] / drain parity — RFC 9114 §4.1.2:
  /// at most one final response). Interim (1xx) leading sections do NOT set it (several
  /// are allowed before the final response). Unused on the server (a request has exactly
  /// one leading section, gated by `first_headers_seen`).
  final_response_seen: bool,
  /// The peer FIN'd its send half on this stream and the clean half-close already
  /// surfaced [`Event::PeerClosed`] (de-dups a second clean FIN). (Was the
  /// singular `peer_closed`.)
  peer_closed: bool,
  /// A clean pre-establishment peer FIN, deferred until establish so
  /// [`Event::PeerClosed`] never precedes [`Event::Established`]. (Was the
  /// singular `peer_fin_pending`.)
  peer_fin_pending: bool,
  /// The stream was abandoned: its first HEADERS was decoded by the drop-drain
  /// UNOBSERVED, so the stream is permanently inert to the driver (validated, but
  /// never surfaces tunnel data / grants readiness). (Was the singular
  /// `request_abandoned`.)
  abandoned: bool,
  /// The per-stream LOCAL send half-FSM: the single source of truth for what may be
  /// enqueued NEXT on this stream's send half, replacing the former
  /// `final_response_sent` / `local_send_closed` booleans. Every send guard validates
  /// against it and every successful send transitions it, so no public-call sequence can
  /// produce protocol-invalid frame ordering (RFC 9114 §4.1 / §4.1.2). See [`SendState`]
  /// for the full role-shaped transition table; it is orthogonal to the inbound recv FSM
  /// and to `peer_closed` (the PEER's half-close).
  send: SendState,
  /// Whether this stream is the CONNECT tunnel (vs a general request/response
  /// stream). It drives BOTH the establish split (connection-scoped for the tunnel,
  /// per-stream otherwise) and the error-scope split (a protocol violation /
  /// `RESET_STREAM` is connection-fatal on the tunnel, stream-scoped otherwise —
  /// RFC 9114 §4.1.2):
  ///
  /// - `true` — the tunnel: the client establishes on the final response via the
  ///   shared `Handshaking → Open` transition ([`Phase::establish_into`]: phase →
  ///   `Open`, [`Event::Established`] enqueued, `established` set), and the server via
  ///   [`accept_with`](Connection::accept_with). A stream error on it fails the WHOLE
  ///   connection. Set on:
  ///   - the client tunnel path (`open_with` →
  ///     [`provide_stream`](Connection::provide_stream)); and
  ///   - an inbound server request stream registered while the connection is in
  ///     [`Mode::Tunnel`] (the default) — the server cannot tell tunnel from general
  ///     before any HEADERS, so the strict-CONNECT default keeps a pre-response protocol
  ///     violation connection-fatal. In [`Mode::General`] the registration is `false`
  ///     instead (a general server: a pre-response request error resets per-stream).
  ///     Either way [`send_response`](Connection::send_response) (the general response
  ///     path) makes/keeps it `false`; `accept_with` makes/keeps it `true` (the
  ///     established tunnel). See [`Mode`].
  /// - `false` — a general stream (opened with
  ///   [`open_request`](Connection::open_request) on the client, or responded to with
  ///   [`send_response`](Connection::send_response) on the server): establishment is
  ///   purely per-stream — the final response sets `established` (gating
  ///   [`Frame::Data`]) and NOTHING else (no connection [`Event::Established`], no
  ///   `Phase::Open` transition), because [`Event`]s are connection-scoped and a
  ///   general request stream is not. A stream error on it resets ONLY that stream.
  is_tunnel: bool,
}

impl<'req, ReqBuf> StreamEntry<'req, ReqBuf> {
  /// A fresh entry wrapping the recv FSM `fsm`, with every recv-side lifecycle marker
  /// clear and the send half-FSM seeded to `send`. `is_tunnel` marks whether this is
  /// the CONNECT tunnel slot (set only on the tunnel path) — it drives the
  /// connection-scoped vs per-stream establish split. `send` is the role-shaped start
  /// state: [`SendState::RequestSent`] for a CLIENT-opened stream (its request HEADERS
  /// are already enqueued, so request body may follow) or [`SendState::Idle`] for an
  /// inbound SERVER request stream (no response sent yet).
  fn new(fsm: Stream<'req, ReqBuf>, is_tunnel: bool, send: SendState) -> Self {
    Self {
      fsm,
      observed: false,
      established: false,
      final_response_seen: false,
      peer_closed: false,
      peer_fin_pending: false,
      abandoned: false,
      send,
      is_tunnel,
    }
  }
}

/// The default per-tier [`StreamStore`] the [`Connection`] holds.
///
/// On the heap tiers (`std` / `alloc` / `no-atomic`) it is the dynamically
/// growing [`SlabStore`](crate::stream_store::SlabStore); [`Connection::new`]
/// builds it internally.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
pub type DefaultStreamStore<'req, ReqBuf> =
  crate::stream_store::SlabStore<StreamEntry<'req, ReqBuf>>;

/// The default per-tier [`StreamStore`] the [`Connection`] holds.
///
/// On the bare `no_std` tier it is a zero-allocation [`ArrayStore`] over
/// caller-provided slots (pass them to
/// [`with_buffers`](Connection::with_buffers) as `stream_slots`). The slot
/// storage shares the `'req` lifetime of the per-stream recv FSMs it holds, so
/// the connection keeps the same five storage lifetimes on every tier.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
pub type DefaultStreamStore<'req, ReqBuf> = ArrayStore<'req, StreamEntry<'req, ReqBuf>, 0>;

/// One caller-provided storage slot for a bare-tier [`Connection`]'s stream
/// table — a [`StreamStore`] entry slot. Initialize borrowed storage with
/// [`ArraySlot::EMPTY`] and pass `&mut [StreamSlot<'_, _>]` to
/// [`with_buffers`](Connection::with_buffers) as `stream_slots`.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
pub type StreamSlot<'req, ReqBuf> = ArraySlot<StreamEntry<'req, ReqBuf>>;

/// A lending iterator over the [`Frame`]s a single
/// [`handle_stream`](Connection::handle_stream) call produced.
///
/// Only the request stream yields frames; for all other streams this is empty.
/// Each [`Frame`] borrows the call's input/scratch and is invalidated by the
/// next [`next`](Frames::next).
///
/// The iterator is inert once the connection is `Failed`: if a `next()` hits a lazy
/// fatal request-FSM error (a second HEADERS, premature DATA, malformed QPACK, …) it
/// routes that through the centralized fail transition and returns the `Err`, after
/// which EVERY further `next()` returns `Ok(None)` — no `Frame::Data` / `Frame::Request`
/// / `Frame::Response` can surface past the terminal error (terminal-priority; the
/// [`Event::ConnError`] is delivered by [`poll_event`](Connection::poll_event)). This
/// is the yield-path twin of the drop path's `drain_for_errors` `is_failed()` top guard
/// (next/drain parity).
pub struct Frames<
  'a,
  'req,
  'event,
  ReqBuf = DefaultReqBuf<'req>,
  EventBuf = DefaultEventBuf<'event>,
> {
  inner: Option<RequestFrames<'a, 'req, 'event, ReqBuf, EventBuf>>,
}

/// The request-stream branch of [`Frames`]: wraps the inbound [`Stream`]
/// item iterator and tags each item as a request or response per our role.
///
/// It carries disjoint borrows of the connection's `phase`, event queue,
/// `close_pending` flag, and `conn_error` slot (all separate fields from the
/// request FSM the iterator drives) so that the connection-level side effects of
/// the FSM's progress can run from inside the lending iterator, where `&mut self`
/// is unavailable:
///
/// - the handshake-readiness transition the moment [`Frames::next`] YIELDS the
///   first HEADERS to the driver — the client's `Handshaking → Open` establish
///   ([`Phase::establish_into`]) / the server's `request_received` — via
///   [`on_headers_decoded`] (gated on OBSERVATION, not decoding), and
/// - the `{anything but Failed} → Failed` fail on ANY fatal request-FSM error
///   ([`Phase::fail_into`], recording the terminal error in the non-droppable
///   `conn_error` slot), so a lazily-surfaced protocol violation (a second
///   HEADERS, DATA before HEADERS, malformed QPACK, …) makes the connection
///   terminal — exactly as the eager `handle_stream` errors do.
///
/// Those same borrows back the drain-on-drop ([`Drop`]): a driver that pulls only
/// the FIRST yielded frame and stops (or none at all) would otherwise leave any
/// forbidden frame later in the SAME `handle_stream` input (a second HEADERS,
/// PUSH_PROMISE, DATA before HEADERS, …) unvalidated, so the connection would stay
/// non-terminal and `send_data` / `accept_with` would keep working. To keep the
/// fatal-path invariant true for ALL supplied bytes — not just fully-drained
/// iterators — `Drop` drives the request FSM over any remaining unconsumed input
/// purely to detect such an error, discarding the items, and routes the first error
/// through the same [`Phase::fail_into`]. The drop path validates (structurally
/// decodes the first HEADERS, so a malformed section is still fatal) but grants NO
/// readiness, and is a no-op when the connection is already terminal so a post-error
/// FSM is never re-driven. See the observation-gating section on [`Connection`] for
/// the full validation-vs-observation invariant.
///
/// [`on_headers_decoded`]: RequestFrames::on_headers_decoded
struct RequestFrames<'a, 'req, 'event, ReqBuf, EventBuf> {
  drain_on_drop: fn(&mut RequestFrames<'a, 'req, 'event, ReqBuf, EventBuf>),
  items: crate::stream::Items<'a, 'req, ReqBuf>,
  /// The id of the request stream this carrier drives. Names the stream to free +
  /// `RESET_STREAM` when a NON-tunnel stream error is recorded into `pending_reset`
  /// (see [`fail_or_reset`](Self::fail_or_reset)); on the tunnel it is unused (a
  /// tunnel error fails the connection instead).
  id: StreamId,
  /// A disjoint borrow of the connection's lifecycle phase (see the struct docs).
  phase: &'a mut Phase,
  /// A disjoint borrow of the connection's event queue (see the struct docs).
  events: &'a mut BoundedQueue<'event, Event, EventBuf>,
  /// A disjoint borrow of the connection's `close_pending` flag. The fail
  /// transition clears it so a `Failed` connection never flushes a deferred
  /// graceful FIN — the same invariant that [`Connection::fail`] maintains on
  /// the eager path. `phase`, `events`, and `close_pending` are all distinct
  /// `Connection` fields, so holding `&mut` to all three is a disjoint borrow.
  close_pending: &'a mut bool,
  /// A disjoint borrow of the connection's dedicated terminal-error slot. A lazy
  /// request-FSM error routes through [`Phase::fail_into`], which records the
  /// fatal code here (not the bounded event queue), so it reaches the SAME
  /// non-droppable slot the eager fail paths use. Another distinct `Connection`
  /// field, so the borrow stays disjoint from `phase` / `events` / `close_pending`.
  conn_error: &'a mut Option<H3Error>,
  /// A disjoint borrow of the connection's `pending_resets` channel — the stream-scoped
  /// twin of `conn_error`. On a NON-tunnel stream a request-FSM / validator error is
  /// a STREAM error (RFC 9114 §4.1.2): it resets only this stream, leaving the
  /// connection live. The carrier holds per-entry borrows, not `streams` / `tx`, so it
  /// cannot do the reset's slot bookkeeping / DATA purge in place; it only RECORDS the
  /// abort `(id, code)` here, and the next `&mut self` API entry reconciles it (frees the
  /// slot, purges the stream's DATA) while `poll_transmit` emits the `RESET_STREAM`
  /// directly from the channel. Yet another distinct `Connection` field, so the borrow
  /// stays disjoint from `phase` / `events` / `close_pending` / `conn_error` /
  /// `request_abandoned`. See [`fail_or_reset`](Self::fail_or_reset).
  pending_resets: &'a mut PendingResets,
  /// A disjoint borrow of the connection's `request_abandoned` flag. The drop-drain
  /// ([`drain_for_errors`](Self::drain_for_errors)) sets it when it decodes the first
  /// HEADERS UNOBSERVED (the driver dropped [`Frames`] before any `next()` yielded
  /// it): that decode advanced the inbound FSM into its tunnel phase as a side effect,
  /// but the consumed HEADERS bytes are gone, so the stream can never be observed and
  /// is permanently inert. Yet another distinct `Connection` field, so the borrow
  /// stays disjoint from `phase` / `events` / `close_pending` / `conn_error`. Backs
  /// the drop glue exactly like `conn_error`.
  request_abandoned: &'a mut bool,
  is_client: bool,
  /// Client-only: arm the establish on the FIRST FINAL (non-interim) response the
  /// moment [`Frames::next`] YIELDS it to the driver (the observation point — NOT
  /// merely when the FSM decodes it, so a dropped-unobserved iterator does not
  /// establish). Armed for EVERY client request stream INDEPENDENT of the connection
  /// phase (per-stream establishment is decoupled from connection-level establishment);
  /// cleared by the consuming `take` after it fires. Always `false` on the server (it
  /// establishes in `accept_with` / `send_response`).
  ///
  /// The establish split rides [`is_tunnel`](Self::is_tunnel): consuming this on the
  /// final response runs the connection-scoped [`Phase::establish_into`] (phase →
  /// `Open` + [`Event::Established`] + `established`) for the tunnel — gated INTERNALLY on
  /// `Handshaking`, so a response yielded after a close / failure does not re-establish —
  /// or sets the per-stream `established` ONLY (in ANY phase) for a general stream. The
  /// per-stream flag is therefore set on every client final response regardless of phase,
  /// so a general stream opened AFTER a CONNECT tunnel reached `Open` still establishes
  /// per-stream (gating `Frame::Data`). An interim 1xx response establishes NEITHER — it
  /// leaves this armed and yields `Frame::Response { interim: true, .. }` — so the consume
  /// happens in [`Frames::next`]'s yield tail AFTER the `:status` interim classification,
  /// not in [`on_headers_decoded`](Self::on_headers_decoded) (which would fire on a
  /// leading interim, before `interim` is known).
  establish_on_response: bool,
  /// Whether the stream this carrier drives is the CONNECT tunnel (copied from the
  /// [`StreamEntry`]'s [`is_tunnel`](StreamEntry::is_tunnel)). Read in
  /// [`Frames::next`]'s client final-response yield tail to pick the establish:
  /// connection-scoped ([`Phase::establish_into`]) for the tunnel, per-stream
  /// (`established` only) for a general stream.
  is_tunnel: bool,
  /// Server-only: a disjoint borrow of `request_received`, flipped to `true`
  /// exactly when [`Frames::next`] YIELDS the first request HEADERS to the driver
  /// (the [`Frame::Request`] yield is itself the signal — there is no event; a
  /// dropped-unobserved iterator does NOT flip it). This gates
  /// [`accept_with`](Connection::accept_with): the server must not respond before it
  /// has SURFACED the peer's CONNECT request to the driver, even though the request
  /// stream id is registered (via [`provide_stream`](Connection::provide_stream)) the
  /// moment the QUIC stream opens — before any HEADERS arrive. `None` on the client
  /// and once flipped.
  on_first_request: Option<&'a mut bool>,
  /// A disjoint borrow of the connection's `tunnel_established` flag. Read by
  /// [`Frames::next`] to gate yielding [`Frame::Data`] (tunnel DATA is delivered
  /// only once the tunnel reached `Open`, RFC 9114 §4.4), and written by the
  /// client's establish carrier ([`on_headers_decoded`](Self::on_headers_decoded) →
  /// [`Phase::establish_into`]) when the response is observed. Yet another distinct
  /// `Connection` field, so the borrow stays disjoint from `phase` / `events` /
  /// `close_pending` / `conn_error` / `request_abandoned` / `request_received`.
  tunnel_established: &'a mut bool,
  /// A disjoint borrow of the [`StreamEntry`]'s `final_response_seen` PLACEMENT flag
  /// (client only). Read by [`accept_headers_section`](Self::accept_headers_section) to
  /// reject a later `Initial` HEADERS after the final response, and SET there (on BOTH
  /// the live and drop paths) when a non-interim response is classified — so the
  /// second-`Initial`-after-final reject fires identically on next and drain (parity).
  /// Distinct from `tunnel_established` (the readiness transition, set only on the live
  /// yield): placement state must be path-shared, establishment must stay live-only.
  /// Yet another distinct entry-field borrow, disjoint from the rest.
  final_response_seen: &'a mut bool,
  /// Whether a HEADERS section already completed on this stream (initialized from
  /// the recv FSM's [`headers_seen`](crate::stream::Stream::headers_seen) at build
  /// time, then set `true` the moment this carrier first observes / abandons a
  /// HEADERS). On the SERVER a HEADERS that arrives once this is set is a second
  /// request leading section — a frame-placement violation
  /// ([`H3Error::FrameUnexpected`]). The CLIENT instead gates its
  /// second-`Initial`-after-final reject on `final_response_seen` (several interim
  /// leading sections are legal before the final response, so "any second Initial" is
  /// too strict there). The general recv FSM allows repeated leading (interim 1xx)
  /// HEADERS and a trailing section, so this placement guard lives here in the
  /// connection, not in the FSM.
  first_headers_seen: bool,
}

impl<ReqBuf, EventBuf> Frames<'_, '_, '_, ReqBuf, EventBuf> {
  /// An empty frame iterator (non-request streams produce no frames).
  const fn empty() -> Self {
    Self { inner: None }
  }
}

impl<ReqBuf, EventBuf> Frames<'_, '_, '_, ReqBuf, EventBuf>
where
  ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
  EventBuf: AsMut<[Option<Event>]>,
{
  /// The next decoded frame, or `Ok(None)` when the fed bytes are exhausted.
  ///
  /// The returned [`Frame`] borrows the `handle_stream` input (`Data`) or its
  /// scratch (`Request` / `Response`) and is invalidated by the next call.
  ///
  /// Fused after a fatal error: once the connection is `Failed` this returns
  /// `Ok(None)` without driving the FSM. A lazy fatal request-FSM error makes the
  /// FIRST `next()` route through the centralized fail transition and return its `Err`;
  /// every subsequent `next()` then yields `Ok(None)`, so no `Frame` can surface after
  /// the terminal error (terminal-priority, parity with the drop path's
  /// `drain_for_errors`).
  // A lending iterator (each `Frame` borrows `self`), so `Iterator` cannot be
  // implemented; mirrors `qpack::FieldLines` and `stream::Items`.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Result<Option<Frame<'_>>, H3Error> {
    let Some(rf) = self.inner.as_mut() else {
      return Ok(None);
    };
    // Terminal-priority: once the connection is Failed (e.g. a prior poll of THIS
    // iterator hit a lazy fatal request-FSM error and routed through fail_into), the
    // iterator is inert — yield nothing more, so no Frame::Data/Headers can surface
    // after the terminal ConnError. poll_event delivers the ConnError from its
    // dedicated slot. Mirrors drain_for_errors' is_failed() top guard (next/drain parity).
    if rf.phase.is_failed() {
      return Ok(None);
    }
    // Stream-scoped twin of the `is_failed()` fuse above: once THIS carrier recorded a
    // stream reset for its (non-tunnel) stream, it is inert — yield nothing more, so no
    // `Frame` surfaces on a stream that has been aborted. The connection stays live; the
    // reset materializes (slot freed + `RESET_STREAM` enqueued) at the next `&mut self`
    // API entry. Mirrors `drain_for_errors`' top guard (next/drain parity).
    if rf.stream_reset_recorded() {
      return Ok(None);
    }
    // Drive the request FSM via the borrow-free `advance` (it reports each item as
    // owned offsets / a section length, not a borrow), looping ONLY to skip an
    // established-but-empty DATA frame; for a yieldable item the borrow is re-derived
    // by a SINGLE-shot tail call after the loop. EVERY DATA frame passes the
    // establishment gate here — including a zero-length one (the FSM yields it as one
    // empty occurrence). Looping over `advance` (owned offsets) rather than the
    // borrowing `Items::next` is what lets the skip compile on stable NLL: no returned
    // borrow crosses the loop back-edge.
    let headers = loop {
      // A lazily-surfaced request-FSM error (a second HEADERS, DATA before HEADERS,
      // malformed QPACK, PUSH_PROMISE → IdError, malformed framing, …) is routed by
      // SCOPE via `fail_or_reset` BEFORE returning it: connection-fatal on the CONNECT
      // tunnel (phase → `Failed`, one `ConnError`, so a later `send_data` reports
      // `Closed`), or a stream-scoped reset on a general request stream (RFC 9114
      // §4.1.2 — the connection stays live; only this stream is aborted). Still returns
      // the `Err` so the driver learns the code.
      let advanced = match rf.items.advance() {
        Ok(advanced) => advanced,
        Err(e) => {
          rf.fail_or_reset(e);
          return Err(e);
        }
      };
      match advanced {
        None => return Ok(None),
        // A HEADERS section. The FSM classified it by placement ([`HeadersKind`]: an
        // `Initial` leading section — request / interim / final response — or a `Trailers`
        // section, after the body OR a bodyless leading message). The role-based placement
        // policy, validation, and `interim` classification all live in the shared
        // `accept_headers_section` routine the drop-drain runs too (next/drain parity);
        // break out so it (and the readiness side effect + the borrowing yield) run once,
        // outside the skip loop.
        Some(Advanced::Headers { acc_end, kind }) => break (acc_end, kind),
        Some(Advanced::Data { start, end }) => {
          // Tunnel DATA is delivered ONLY once the tunnel reached `Open`
          // (`tunnel_established`, set on the single establish transition). RFC 9114
          // §4.4: a peer must not send DATA ahead of the 2xx response. On the server a
          // peer can coalesce the request HEADERS and a DATA frame in one
          // `handle_stream` read while the phase is still `Handshaking` (the 2xx is
          // sent by `accept_with`, which cannot run while this borrow is held), so
          // observing the HEADERS only sets `request_received` — the DATA here is
          // premature. `tunnel_established` (not `is_open()`) is the gate so a
          // post-`Open` half-close (`Closing`, flag still true) still delivers peer
          // DATA, while a `close()` during `Handshaking` (→ `Closing`, never
          // established) does not re-leak it. Premature DATA — empty or not — is a
          // malformed message (RFC 9114 §4.1.2): the shared `fail_if_premature_data`
          // routes it by scope (connection-fatal on the tunnel, a stream reset on a
          // general stream), then we return the code so the driver learns it.
          if rf.fail_if_premature_data() {
            return Err(H3Error::MessageError);
          }
          // Established. An empty DATA frame is a real (consumed, gate-passed)
          // occurrence but is NOT surfaced to the driver — handing back an empty
          // `Frame::Data` would be noise — so skip it and pull the next item; a
          // non-empty chunk is re-sliced from the input (lifetime `'a`, independent of
          // `&mut items`) and yielded.
          if start == end {
            continue;
          }
          let chunk = rf
            .items
            .input()
            .get(start..end)
            .ok_or(H3Error::FrameError)?;
          return Ok(Some(Frame::Data(chunk)));
        }
      }
    };
    let (acc_end, kind) = headers;
    // Validate + classify the accepted section through the ONE routine the drop-drain
    // runs too (next/drain parity): placement reject, role-aware semantic validation,
    // and `:status` interim classification, with EVERY decode / validate error routed
    // by scope through `fail_or_reset` BEFORE it is returned. Only after it returns Ok
    // do the observation side effects + the borrowing yield run — so a section that
    // fails validation never marks the request observed nor establishes.
    let outcome = rf.accept_headers_section(kind, acc_end)?;
    // A trailing section is just `Frame::Trailers` (either role): it carries no handshake
    // readiness (the leading section already granted it). Re-decode the now-validated
    // buffered section and yield it.
    if let HeadersAccept::Trailers = outcome {
      let hs = rf.items.decode_buffered_headers(acc_end)?;
      return Ok(Some(Frame::Trailers(hs)));
    }
    // A leading (`Initial`) section that PASSED validation is current. We are about to
    // YIELD it to the driver — the observation point. The SERVER's readiness side effect
    // (flip `observed`) runs here over the disjoint field borrows, at most once (consumed
    // by `take`), and ONLY now that the section is valid: a malformed request is never
    // marked observed, so a condemned (pending-reset) general stream can never be picked
    // up by `guard_send_response`. This is also the ONLY place readiness fires: the
    // drop-drain (`drain_for_errors`) validates the same section but does NOT run this, so
    // an iterator dropped before any `next()` never advances the handshake on a request
    // the driver never observed.
    RequestFrames::<ReqBuf, EventBuf>::on_headers_decoded(&mut rf.on_first_request);
    if let HeadersAccept::Response { interim } = outcome {
      // Establish on the FIRST FINAL response (the observation point). An interim 1xx
      // establishes NOTHING — it leaves the carrier armed so a later final response still
      // establishes. Armed for EVERY client request stream (see `establish_on_response`);
      // consumed exactly once via `take`. The split keeps per-stream establishment SEPARATE
      // from connection-level establishment (events are connection-scoped only,
      // RFC 9114 §2):
      //
      // - the CONNECT TUNNEL establishes connection-wide via `Phase::establish_into` (phase
      //   → `Open`, one `Event::Established`, `established` set), gated INTERNALLY on
      //   `Handshaking` (a no-op in any other phase). This connection-level transition fires
      //   ONLY for the tunnel (`is_tunnel`) AND only from `Handshaking`.
      // - a GENERAL stream sets ONLY its per-stream `established` (gating `Frame::Data`) — in
      //   ANY connection phase — and emits NO connection `Event::Established` and NO
      //   `Phase::Open` transition. This is what lets a general stream opened via
      //   `open_request` AFTER a CONNECT tunnel reached `Open` still establish per-stream;
      //   without it the next valid response DATA would be (wrongly) premature and reset it.
      //
      // `*rf.tunnel_established` (the entry's `established`) thus becomes true on the
      // final response on BOTH paths, so the second-`Initial`-after-final reject in
      // `accept_headers_section` fires identically for tunnel and general clients.
      if !interim && core::mem::take(&mut rf.establish_on_response) {
        if rf.is_tunnel {
          Phase::establish_into(rf.phase, rf.events, rf.tunnel_established);
        } else {
          *rf.tunnel_established = true;
        }
      }
      let hs = rf.items.decode_buffered_headers(acc_end)?;
      Ok(Some(Frame::Response {
        interim,
        headers: hs,
      }))
    } else {
      // A server request leading section (the only remaining `HeadersAccept`).
      let hs = rf.items.decode_buffered_headers(acc_end)?;
      Ok(Some(Frame::Request(hs)))
    }
  }
}

/// The role-aware classification of an accepted leading / trailing HEADERS section,
/// returned by [`RequestFrames::accept_headers_section`] so the live yield path
/// ([`Frames::next`]) can build the matching [`Frame`] AFTER the shared validation +
/// error routing has run. The drop-drain ([`RequestFrames::drain_for_errors`])
/// discards it — it only needs the shared routine to have validated and routed any
/// error by scope.
enum HeadersAccept {
  /// A server request leading section (validated as [`MessageKind::Request`]).
  Request,
  /// A client response leading section, with its `:status`-decided `interim` flag
  /// (validated as [`MessageKind::Interim`] or [`MessageKind::Response`]).
  Response {
    /// Whether `:status` is a 1xx informational (interim) response.
    interim: bool,
  },
  /// A trailing section, either direction (validated as [`MessageKind::Trailers`]).
  Trailers,
}

/// The outcome of [`provide_request_stream`](Connection::provide_request_stream):
/// whether the request stream's [`StreamEntry`] is now tracked or was rejected at
/// store capacity. A caller that also enqueues request HEADERS
/// ([`open_request`](Connection::open_request)) keys on this so it never writes on a
/// rejected (untracked, already-reset) id.
#[derive(Clone, Copy, Eq, PartialEq)]
enum RequestRegister {
  /// The entry is tracked: freshly inserted, or already present (an idempotent
  /// re-provide). The caller may enqueue HEADERS on `id`.
  Inserted,
  /// The store was at capacity: the overflow stream was reset with
  /// [`H3Error::RequestRejected`] and is NOT tracked. The caller must NOT enqueue
  /// HEADERS on `id`.
  Rejected,
}

impl<ReqBuf, EventBuf> RequestFrames<'_, '_, '_, ReqBuf, EventBuf> {
  /// Routes a request-FSM / validator / placement error by SCOPE — the single
  /// decision point shared by [`Frames::next`] and
  /// [`drain_for_errors`](Self::drain_for_errors) so the two paths cannot drift:
  ///
  /// - the CONNECT **tunnel** stream ([`is_tunnel`](Self::is_tunnel)): the error is
  ///   connection-fatal (one tunnel = one connection), routed through
  ///   [`Phase::fail_into`] — phase → `Failed`, `close_pending` cleared, the stale
  ///   event queue cleared, exactly one terminal `ConnError` recorded — exactly as
  ///   before this scoping existed, keeping every tunnel assertion green.
  /// - a **general** (non-tunnel) request stream: the error is a STREAM error
  ///   (RFC 9114 §4.1.2 — a malformed message / validator violation / premature DATA
  ///   / frame-placement on one request stream). It resets ONLY that stream, leaving
  ///   the connection and every other stream live. The carrier holds per-entry
  ///   borrows, not `streams` / `tx`, so it records `(id, code)` into `pending_reset`
  ///   (the stream-scoped twin of `conn_error`); the next `&mut self` API entry
  ///   materializes the real [`reset_stream`](Connection::reset_stream). The
  ///   connection `phase` is UNCHANGED.
  ///
  /// The caller still returns the `Err(error)` so the driver learns the code; only
  /// the connection-level effect differs by scope. Operates on `&mut self` (no `items`
  /// borrow is live at any call site).
  fn fail_or_reset(&mut self, error: H3Error)
  where
    EventBuf: AsMut<[Option<Event>]>,
  {
    if self.is_tunnel {
      Phase::fail_into(
        self.phase,
        self.close_pending,
        self.events,
        self.conn_error,
        error,
      );
    } else {
      // Record the abort into the dedicated reset channel (deduped by id, FIRST code
      // wins — a later error on the same already-condemned stream neither overwrites
      // the code nor adds a duplicate). The carrier holds only per-entry borrows, not
      // `streams` / `tx`, so it cannot free the slot or purge the stream's queued DATA
      // here; the next `&mut self` API entry reconciles that (see
      // `Connection::reconcile_pending_resets`), and `poll_transmit` emits the abort
      // directly from this channel — never byte-ring-gated. The carrier also stops
      // yielding once this is set (see `Frames::next` / `drain_for_errors`). A full
      // channel is pathological (`RESET_CAP` distinct undrained resets); fail the
      // connection closed rather than silently drop the reset.
      if !self.pending_resets.record(self.id, error.code()) {
        Phase::fail_into(
          self.phase,
          self.close_pending,
          self.events,
          self.conn_error,
          H3Error::ExcessiveLoad,
        );
      }
    }
  }

  /// Whether this carrier already recorded a stream-scoped reset for its
  /// (non-tunnel) stream. Once set, the carrier stops yielding / scanning — the
  /// stream-scoped twin of the `phase.is_failed()` fuse the tunnel path uses, keeping
  /// [`Frames::next`] and [`drain_for_errors`](Self::drain_for_errors) at parity.
  fn stream_reset_recorded(&self) -> bool {
    self.pending_resets.contains(self.id)
  }

  /// Runs the semantic validator over the just-completed HEADERS section (a fresh,
  /// dedicated decode pass over the buffered bytes), routing a violation by SCOPE via
  /// [`fail_or_reset`](Self::fail_or_reset) — connection-fatal on the tunnel, a
  /// stream-scoped reset on a general request stream (RFC 9114 §4.1.2) — before
  /// returning it. The decode pass is independent of the yield decode the caller
  /// performs next (each
  /// [`decode_buffered_headers`](crate::stream::Items::decode_buffered_headers) is a
  /// fresh, idempotent decode over the same owned bytes).
  ///
  /// The QPACK DECODE itself is routed too: the recv FSM eager-validates only the
  /// FIRST section (see [`Items::advance`](crate::stream::Items::advance)), so for a
  /// NON-first accepted section (an interim 1xx or a trailing HEADERS) this is where a
  /// malformed QPACK section first surfaces. Funnelling the decode error through
  /// [`fail_or_reset`](Self::fail_or_reset) (not a bare `?`) is what makes a malformed
  /// interim/trailers section a ConnError on a tunnel stream and a RESET_STREAM on a
  /// general one, instead of a silent `Err` that leaves the stream live.
  fn validate_section(&mut self, kind: MessageKind, acc_end: usize) -> Result<(), H3Error>
  where
    ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    let mut hs = match self.items.decode_buffered_headers(acc_end) {
      Ok(hs) => hs,
      Err(e) => {
        self.fail_or_reset(e);
        return Err(e);
      }
    };
    if let Err(e) = validate::validate(kind, &mut hs) {
      self.fail_or_reset(e);
      return Err(e);
    }
    Ok(())
  }

  /// Validates and classifies ONE accepted HEADERS section, the single routine
  /// [`Frames::next`] and [`drain_for_errors`](Self::drain_for_errors) BOTH run so the
  /// two paths cannot drift (the historically worst bug class in this crate). It owns
  /// the full "accept this section" decision:
  ///
  /// 1. **Placement** — a second `Initial` is a frame-placement violation routed
  ///    through [`fail_or_reset`](Self::fail_or_reset) (`FrameUnexpected`), gated on
  ///    placement state BOTH paths maintain identically: the server's
  ///    `first_headers_seen` (any second request leading section) and the client's
  ///    `final_response_seen` (a leading section after the FINAL response — interim 1xx
  ///    leadings are legal and do not arm it). This is the next/drain parity invariant:
  ///    every accept/reject decision here depends only on path-shared state, never on
  ///    the establish flag set in [`Frames::next`]'s yield tail.
  /// 2. **Validation** — the role-aware semantic validator runs under the
  ///    [`MessageKind`] the section's role + (for a client leading section) `:status`
  ///    class selects: `Request` (server), `Interim`/`Response` (client), `Trailers`
  ///    (either). EVERY decode / [`response_is_interim`](validate::response_is_interim)
  ///    / validate error is funnelled through [`fail_or_reset`](Self::fail_or_reset)
  ///    BEFORE it is returned (no bare `?` that would leave a condemned stream live).
  /// 3. **Bookkeeping** — `first_headers_seen` is set for an accepted `Initial`, and
  ///    `final_response_seen` (client) when that `Initial` is the final response (a
  ///    `Trailers` section re-arms neither). Both are committed BEFORE the semantic
  ///    validate, so placement is identical on both paths even if validation then fails.
  /// 4. **Leading-complete signal** — when the accepted `Initial` is the SERVER's request
  ///    or the CLIENT's FINAL (non-interim) response, the recv FSM is signalled via
  ///    `Items::complete_leading` (NOT for an interim 1xx), so its next HEADERS section is
  ///    classified as the trailing section even with NO intervening DATA (bodyless
  ///    trailers, RFC 9114 §4.1). Because the FSM cannot decode `:status`, this connection
  ///    signal is the only thing that distinguishes "the final response, then trailers"
  ///    from "another interim leading section". It runs here in the shared routine, so the
  ///    FSM transitions identically on the live and drop paths (next/drain parity).
  ///
  /// Returns the [`HeadersAccept`] classification so each caller can run its OWN tail
  /// (the live path yields the matching [`Frame`] after re-deciding the same `interim`;
  /// the drain marks abandonment and keeps scanning) — but the validation + error
  /// routing live HERE, once, for both. Operates on `&mut self` (no `items` borrow is
  /// live at any call site).
  fn accept_headers_section(
    &mut self,
    kind: HeadersKind,
    acc_end: usize,
  ) -> Result<HeadersAccept, H3Error>
  where
    ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    // A trailing section is never a placement violation (the FSM enforces
    // at-most-one / nothing-after) and never re-arms `first_headers_seen`.
    if kind.is_trailers() {
      self.validate_section(MessageKind::Trailers, acc_end)?;
      return Ok(HeadersAccept::Trailers);
    }
    // A leading (`Initial`) section. The role-based placement reject both paths apply,
    // gated on PLACEMENT state both paths maintain identically (next / drain parity):
    //
    // - SERVER: a second request leading section is illegal (`first_headers_seen`, set
    //   in this shared routine on the first accepted `Initial`).
    // - CLIENT: an `Initial` after the FINAL response is illegal (`final_response_seen`,
    //   set in this shared routine when a non-interim response is classified below).
    //   Interim (1xx) leading sections are legal and do NOT arm it, so this is NOT
    //   `first_headers_seen` (too strict) — and it is NOT `tunnel_established` (the
    //   readiness flag, set only on the LIVE yield), which on the drop path stays clear
    //   and would let a second leading section slip through unvalidated. THIS is the
    //   parity fix.
    let second_initial_illegal = if self.is_client {
      *self.final_response_seen
    } else {
      self.first_headers_seen
    };
    if second_initial_illegal {
      self.fail_or_reset(H3Error::FrameUnexpected);
      return Err(H3Error::FrameUnexpected);
    }
    // An accepted leading section: record it (gates the next second-`Initial` reject,
    // across `handle_stream` calls too) before validating, so the placement state is
    // committed identically on both paths even if validation then fails.
    self.first_headers_seen = true;
    if self.is_client {
      // A response: decide interim vs final by `:status` (a dedicated decode pass),
      // routing the decode AND the missing-`:status` malformed-message error through
      // the scope splitter, then validate under the kind the `:status` class selects.
      let interim = match self.classify_response(acc_end)? {
        Some(interim) => interim,
        None => {
          self.fail_or_reset(H3Error::MessageError);
          return Err(H3Error::MessageError);
        }
      };
      let kind = if interim {
        MessageKind::Interim
      } else {
        // The FINAL response: arm the placement flag (BOTH paths) so a later `Initial`
        // on this stream is rejected identically on next and drain. Set BEFORE the
        // semantic validate so placement is committed even if validation then fails
        // (mirrors `first_headers_seen`). Establishment (the DATA gate / `Established`
        // event) is SEPARATE and stays live-only in `Frames::next`'s yield tail.
        *self.final_response_seen = true;
        MessageKind::Response
      };
      self.validate_section(kind, acc_end)?;
      if !interim {
        // The leading message is complete on the FINAL (non-interim) response: signal the
        // recv FSM so the NEXT HEADERS section is classified as the trailing section even
        // with NO intervening DATA (bodyless trailers, RFC 9114 §4.1). An interim 1xx does
        // NOT complete the leading message — leaving the FSM in its leading phase keeps a
        // subsequent interim / the final classified `Initial`. This runs on BOTH the live
        // (`Frames::next`) and drop-drain paths because it lives in this shared routine
        // (next/drain parity): the FSM transitions to its post-leading phase identically,
        // so bodyless trailers are recognised whether or not the driver pulled the
        // response. (After the final response `final_response_seen` is set, so a later
        // `Initial` is impossible — every subsequent HEADERS is now trailers, validated
        // under `MessageKind::Trailers`; a pseudo-header-bearing section is rejected there.)
        self.items.complete_leading();
      }
      Ok(HeadersAccept::Response { interim })
    } else {
      // A request: validate under `Request` (pseudo-header presence/ordering, CONNECT
      // / Extended-CONNECT shape, field rules).
      self.validate_section(MessageKind::Request, acc_end)?;
      // The server's single request IS the whole leading message: signal the recv FSM so
      // the next HEADERS section is trailers even with no DATA in between (bodyless
      // trailers). Shared routine ⇒ runs on the live and drop paths identically.
      self.items.complete_leading();
      Ok(HeadersAccept::Request)
    }
  }

  /// The `:status`-class scan a client leading section needs to tag itself interim
  /// (`Some(true)`) / final (`Some(false)`) / `None` (no `:status` — a malformed
  /// message). A dedicated decode pass whose decode error is routed through
  /// [`fail_or_reset`](Self::fail_or_reset) before being returned, so a malformed
  /// QPACK interim section (the FSM defers its validation) is not a silent `Err`.
  fn classify_response(&mut self, acc_end: usize) -> Result<Option<bool>, H3Error>
  where
    ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    let mut hs = match self.items.decode_buffered_headers(acc_end) {
      Ok(hs) => hs,
      Err(e) => {
        self.fail_or_reset(e);
        return Err(e);
      }
    };
    match validate::response_is_interim(&mut hs) {
      Ok(interim) => Ok(interim),
      Err(e) => {
        self.fail_or_reset(e);
        Err(e)
      }
    }
  }

  /// The SERVER's handshake-READINESS side effect of the driver OBSERVING the first
  /// request HEADERS, run the moment [`Frames::next`] YIELDS the first
  /// [`Frame::Request`] to the driver — and ONLY then. This is deliberately NOT run
  /// from the drop-drain ([`drain_for_errors`](Self::drain_for_errors)): it is the SOLE
  /// place this readiness is granted, so this method is what makes it gate on
  /// observation, not decoding. See the observation-gating section on [`Connection`].
  ///
  /// Flips `request_received` (the gate [`accept_with`](Connection::accept_with) /
  /// [`send_response`](Connection::send_response) wait on — the [`Frame::Request`] yield
  /// is itself the signal, there is no event), exactly once: the carrier `take`s
  /// `on_first_request`, so a later HEADERS (itself a protocol error the FSM rejects)
  /// cannot re-trigger it. `None` on the client.
  ///
  /// The CLIENT's establish is intentionally NOT here: it must fire only on the FINAL
  /// (non-interim) response, which is known only after the `:status` classification, so
  /// [`Frames::next`] runs it in its yield tail (see
  /// [`establish_on_response`](Self::establish_on_response)). Operates on a disjoint
  /// field borrow rather than `&mut self` so [`Frames::next`] can call it while the
  /// yielded `HeaderSet` still borrows `items`.
  fn on_headers_decoded(on_first_request: &mut Option<&mut bool>) {
    // The server records the request as received at the first *yielded* request
    // HEADERS (this runs only from the `Frames::next` yield — not when the stream id
    // is registered, and not from the drop-drain), so a split / partial request cannot
    // let `accept_with` respond a round early and a dropped-unobserved request is never
    // accepted.
    if let Some(flag) = on_first_request.take() {
      *flag = true;
    }
  }

  /// The premature-DATA decision, shared by [`Frames::next`] and
  /// [`drain_for_errors`](Self::drain_for_errors) so the two DATA gates cannot drift:
  /// the yield path, the drop-drain, and a zero-length DATA frame all resolve through
  /// this single check. A DATA frame — empty or not — observed while the tunnel is
  /// NOT established is premature: the peer sent DATA before the
  /// 2xx response (server before [`accept_with`](Connection::accept_with), or any
  /// request stream whose tunnel was never established), which is a malformed message
  /// (RFC 9114 §4.4 / §4.1.2). Routes through [`fail_or_reset`](Self::fail_or_reset) —
  /// connection-fatal `MessageError` on the tunnel, a stream-scoped reset on a general
  /// request stream — and returns whether the DATA was premature (so the caller can
  /// `Err`/`return`):
  ///
  /// - `true`  → premature: the tunnel was `fail`ed, or the general stream's reset was
  ///   recorded, both with `MessageError`;
  /// - `false` → established: the caller handles the (possibly empty) DATA chunk.
  ///
  /// Called on `&mut self` at a point where no `items` borrow is live (the DATA chunk
  /// is re-sliced only after this returns `false`).
  fn fail_if_premature_data(&mut self) -> bool
  where
    EventBuf: AsMut<[Option<Event>]>,
  {
    if *self.tunnel_established {
      return false;
    }
    self.fail_or_reset(H3Error::MessageError);
    true
  }
}

impl<ReqBuf, EventBuf> RequestFrames<'_, '_, '_, ReqBuf, EventBuf>
where
  ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
  EventBuf: AsMut<[Option<Event>]>,
{
  /// Drives the request FSM over any input the driver did not consume, purely to
  /// detect a protocol violation, and routes the first one through the centralized
  /// fail transition. The yielded items are discarded (the driver chose not to read
  /// them, so any unread ESTABLISHED tunnel DATA in this call is abandoned); only an
  /// error matters. A DATA frame still passes the SAME establishment gate as
  /// [`Frames::next`] (the shared [`fail_if_premature_data`](Self::fail_if_premature_data)),
  /// so PREMATURE DATA — a peer §4.4 violation — is fatal on the drop path too, not
  /// silently discarded. A no-op once the connection is terminal — a drained-to-error
  /// FSM (its error already `fail`ed the connection) or one closed/reset out of band
  /// must not be re-driven.
  ///
  /// This path does the STRUCTURAL half of consuming the stream and nothing more, but it
  /// runs the FULL acceptance check on EVERY HEADERS section via the shared
  /// [`accept_headers_section`](Self::accept_headers_section) the live path uses
  /// (next/drain parity): placement, role-aware SEMANTIC validation, and the QPACK decode
  /// of a non-first section, with any error routed by scope through
  /// [`fail_or_reset`](Self::fail_or_reset). So a driver that DROPS [`Frames`] before
  /// consuming an invalid section still has it classified identically to the `next` path
  /// (a Tunnel violation fails the connection, a General one resets the stream), and a
  /// trailing forbidden/fatal frame is still caught — the whole reason the drop drain
  /// exists. It does NOT run the handshake-READINESS side effects
  /// ([`on_headers_decoded`](Self::on_headers_decoded)): validating bytes is not observing
  /// them, so a dropped-before-pull iterator grants no readiness. See the
  /// observation-gating section on [`Connection`].
  ///
  /// This is sync + infallible from the caller's view: it swallows the items and
  /// stops at the first error after calling [`Phase::fail_into`] (idempotent). It is
  /// the body [`Drop`] calls so the drain logic owns the `&mut` borrows directly
  /// rather than fighting the borrow checker across the drop glue.
  ///
  /// [`Items::next`]: crate::stream::Items::next
  fn drain_for_errors(&mut self) {
    // Already in the truly-terminal Failed state: the FSM error already routed
    // through `fail_into` (either eagerly by `Frames::next` or by an earlier drain),
    // so re-driving a post-error FSM would be wrong. Do not re-drive.
    //
    // Closing is NOT skipped here: a fatal request-stream frame received while
    // gracefully closing must still supersede the close — exactly the
    // `fail_supersedes_closing` semantics. Driving the FSM from Closing (or Open /
    // Handshaking) and finding NO error is a no-op (the state stays Closing); finding
    // an error calls `fail_into`, which transitions Closing → Failed, clears
    // `close_pending`, and records exactly one terminal ConnError.
    if self.phase.is_failed() {
      return;
    }
    // Stream-scoped twin of the `is_failed()` guard (next/drain parity): this carrier
    // already recorded a stream reset for its (non-tunnel) stream, so the stream is
    // being aborted — stop scanning. The connection stays live.
    if self.stream_reset_recorded() {
      return;
    }
    loop {
      match self.items.advance() {
        // No protocol error in the remaining bytes: every supplied byte is now
        // validated. Discarding the items is intentional (the driver abandoned them).
        Ok(None) => return,
        // A HEADERS section. It runs through the SAME `accept_headers_section` routine the
        // live path (`Frames::next`) uses (next/drain parity), so the role-based placement
        // reject, the role-aware SEMANTIC validation, and the QPACK DECODE of a non-first
        // section all happen identically here — and any error is routed by scope through
        // `fail_or_reset` (connection-fatal on the tunnel, a stream reset on a general
        // stream) before it returns. The routine also sets `first_headers_seen`; the drop
        // path adds only the UNOBSERVED-first-HEADERS abandonment bookkeeping below.
        Ok(Some(Advanced::Headers { acc_end, kind })) => {
          // On an accepted (valid) section we keep scanning; on an error the routine
          // already `fail_or_reset`-ed, so stop. Readiness is NOT granted on the drop path
          // (`on_headers_decoded` runs only from the live yield), so an unobserved LEADING
          // message COMPLETION marks the stream `request_abandoned` — every later observable
          // path then treats it as inert (no `Frame::Data` from a tunnel the driver never
          // established, no `PeerClosed` on a clean FIN) WITHOUT failing the connection (a
          // lazy drop is not a protocol violation).
          //
          // Only a COMPLETED leading message abandons: an unobserved SERVER `Request` or an
          // unobserved CLIENT FINAL (non-interim) response. An unobserved INTERIM 1xx is
          // validated-and-IGNORED — interims are optional and do NOT complete the leading
          // message, so abandoning on one would make the stream validation-only forever and
          // SWALLOW a later final response (the stream could never establish). A `Trailers`
          // section never abandons either. KEEP scanning the rest of THIS input regardless —
          // a trailing forbidden frame routes through `fail_into`, and a coalesced DATA frame
          // hits the establishment gate in the DATA arm (an unobserved request never
          // established the tunnel, so that DATA is premature, RFC 9114 §4.4); both SUPERSEDE
          // mere abandonment.
          match self.accept_headers_section(kind, acc_end) {
            Ok(HeadersAccept::Request | HeadersAccept::Response { interim: false }) => {
              *self.request_abandoned = true;
            }
            Ok(HeadersAccept::Response { interim: true } | HeadersAccept::Trailers) => {}
            Err(_) => return,
          }
        }
        // A DATA frame on the drop path passes the SAME establishment gate as
        // `Frames::next` (via the shared `fail_if_premature_data`), so premature DATA
        // is fatal on EVERY path — not just a drained iterator. A peer that coalesces
        // request HEADERS + DATA in one read and whose iterator the driver drops
        // (pulling only `Frame::Request`, or nothing) would otherwise have the
        // premature DATA silently discarded here while `request_received` stayed set,
        // letting a later `accept_with` establish on a stream that already smuggled
        // pre-accept bytes (RFC 9114 §4.4). This supersedes mere abandonment: a §4.4
        // violation by the peer fails the connection exactly as a trailing forbidden
        // frame already does, even after an UNOBSERVED first HEADERS set
        // `request_abandoned` above. Both empty and non-empty DATA items reach this
        // gate (the FSM yields empty occurrences too). Established DATA is discarded
        // (the driver abandoned it) and the scan continues.
        Ok(Some(Advanced::Data { .. })) => {
          if self.fail_if_premature_data() {
            return;
          }
        }
        Err(e) => {
          // The same scope split the live path uses (`fail_or_reset`): connection-fatal
          // on the tunnel (phase → `Failed`, `close_pending` cleared, the stale event
          // queue cleared, one terminal ConnError), a stream reset on a general stream.
          // Stop.
          self.fail_or_reset(e);
          return;
        }
      }
    }
  }
}

impl<ReqBuf, EventBuf> Drop for RequestFrames<'_, '_, '_, ReqBuf, EventBuf> {
  /// Validates every byte handed to [`handle_stream`](Connection::handle_stream)
  /// for the request stream even when the returned iterator is not fully drained:
  /// an early-stopping driver still gets the remaining input checked for protocol
  /// errors (which become terminal via [`Phase::fail_into`]). Infallible — it never
  /// panics; the drain just discards items and `fail`s on the first error. A normal
  /// full drain leaves nothing here, so this is a no-op on the common path.
  fn drop(&mut self) {
    (self.drain_on_drop)(self);
  }
}

/// The role of an inbound (peer-opened) unidirectional stream, as classified by
/// its leading type varint (RFC 9114 §6.2 / RFC 9204 §4.2).
#[derive(Clone, Copy, Eq, PartialEq)]
enum UniRole {
  /// The peer's control stream (type 0x00): carries its SETTINGS.
  ControlIn,
  /// The peer's QPACK encoder stream (type 0x02): idle (dynamic table disabled).
  QpackEncIn,
  /// The peer's QPACK decoder stream (type 0x03): idle.
  QpackDecIn,
  /// A GREASE / unknown stream type: its bytes are discarded (RFC 9114 §9).
  Ignored,
}

impl UniRole {
  /// The peer-side [`StreamRole`] for a *critical* uni role, or `None` for
  /// [`Ignored`](Self::Ignored). Used to register critical inbound streams and
  /// to route their bytes.
  const fn stream_role(self) -> Option<StreamRole> {
    Some(match self {
      Self::ControlIn => StreamRole::ControlIn,
      Self::QpackEncIn => StreamRole::QpackEncIn,
      Self::QpackDecIn => StreamRole::QpackDecIn,
      Self::Ignored => return None,
    })
  }
}

/// The state of one tracked inbound uni stream: either its leading type varint is
/// still mid-parse, or it has been classified into a [`UniRole`].
#[derive(Clone, Copy)]
enum UniState {
  /// The leading type varint has not yet completed; `buf[..len]` holds the
  /// partial varint bytes seen so far (a QUIC varint is at most 8 bytes).
  Pending { buf: [u8; 8], len: usize },
  /// The type varint completed and selected this role.
  Classified(UniRole),
}

/// One tracked inbound uni stream: its id and its current [`UniState`]. A
/// not-yet-classified stream occupies a slot too (as [`UniState::Pending`]), so
/// the same bounded table covers both phases.
#[derive(Clone, Copy)]
struct UniEntry {
  id: StreamId,
  state: UniState,
}

/// The capacity of the inbound-uni tracking table. Every inbound uni stream the
/// peer opens (its control + 2 QPACK streams, plus any GREASE / unknown streams)
/// occupies one slot — from the moment its first byte arrives (while its type
/// varint is still mid-parse) through classification. Exceeding this when
/// reserving a slot for a NEW id is [`H3Error::ExcessiveLoad`] rather than a
/// silent drop, so a flood of partial / GREASE streams cannot hide a later
/// critical stream.
const UNI_CAP: usize = 16;

/// Slots needed by the default inbound unidirectional-stream tracking table.
pub const UNI_TRACKING_CAP: usize = UNI_CAP;

/// One caller-provided storage slot for inbound unidirectional-stream tracking.
///
/// The contents are intentionally opaque: the connection stores private parser
/// state here while classifying peer-opened unidirectional streams. Use
/// [`UniSlot::EMPTY`] to initialize borrowed storage for
/// [`Connection::with_buffers`].
#[derive(Clone, Copy)]
pub struct UniSlot {
  entry: Option<UniEntry>,
}

impl UniSlot {
  /// An empty inbound-uni tracking slot.
  pub const EMPTY: Self = Self { entry: None };
}

/// Default inbound-uni tracking storage.
///
/// With `std` or `alloc`, the default connection stores this in a heap-backed
/// `Vec` so the default owned `Connection` stays small.
#[cfg(any(feature = "std", feature = "alloc"))]
pub type DefaultUniBuf<'a> = std::vec::Vec<UniSlot>;

/// Default inbound-uni tracking storage.
///
/// With no allocator available, the default is borrowed caller-owned storage so
/// borrowed connections stay small. Construct it with
/// [`Connection::with_buffers`].
#[cfg(not(any(feature = "std", feature = "alloc")))]
pub type DefaultUniBuf<'a> = &'a mut [UniSlot];

#[cfg(any(feature = "std", feature = "alloc"))]
fn default_uni_buf() -> DefaultUniBuf<'static> {
  std::vec![UniSlot::EMPTY; UNI_CAP]
}

/// The frame currently being consumed on the peer control stream (after its
/// header has been parsed).
enum CtrlCur {
  /// At a frame boundary; the next bytes begin a frame header.
  None,
  /// Accumulating the first SETTINGS frame's payload into `payload[..acc]`.
  Settings { remaining: u64, acc: usize },
  /// Discarding a skipped payload: GOAWAY, a server-side MAX_PUSH_ID, or a
  /// GREASE / unknown frame. (CANCEL_PUSH and a client-side MAX_PUSH_ID are
  /// rejected, not skipped — see [`ControlState::begin_frame`].)
  Skip { remaining: u64 },
}

/// The peer control stream's continuous frame parser (RFC 9114 §6.2.1 / §7.2).
///
/// The first frame MUST be SETTINGS (else [`H3Error::MissingSettings`]). After
/// it, the placement policy is role-aware (RFC 9114 §7.2):
///
/// - DATA / HEADERS / PUSH_PROMISE / an HTTP/2-reserved type / a second SETTINGS
///   → [`H3Error::FrameUnexpected`].
/// - CANCEL_PUSH → [`H3Error::IdError`] (push is never enabled, so no push id is
///   ever valid).
/// - MAX_PUSH_ID → [`H3Error::FrameUnexpected`] for a client (it is client→server
///   only); skipped for a server (valid; we just never push).
/// - GOAWAY → skipped (graceful shutdown is a v1 limitation: accepted-and-ignored).
/// - GREASE / unknown frames → skipped.
///
/// Bounded and no-alloc: a frame header buffers in `hdr_buf` and the SETTINGS
/// payload in `payload`. An oversize frame header is a graceful
/// [`H3Error::FrameError`]; a SETTINGS payload over the configured buffer
/// capacity is [`H3Error::ExcessiveLoad`] (an excessive-load policy). Neither
/// panics. The default payload storage follows [`DefaultCtrlBuf`].
struct ControlState<'a, B = DefaultCtrlBuf<'a>> {
  settings_seen: bool,
  cur: CtrlCur,
  hdr_buf: [u8; CTRL_HDR_CAP],
  hdr_len: usize,
  payload: B,
  _storage: PhantomData<&'a mut ()>,
}

impl<B> ControlState<'_, B> {
  /// A fresh parser backed by caller-provided SETTINGS payload storage.
  fn with_buffer(payload: B) -> Self {
    Self {
      settings_seen: false,
      cur: CtrlCur::None,
      hdr_buf: [0u8; CTRL_HDR_CAP],
      hdr_len: 0,
      payload,
      _storage: PhantomData,
    }
  }

  /// Feeds inbound control-stream `bytes`, advancing the frame loop. Returns
  /// `Ok(Some(settings))` exactly once — when the first (SETTINGS) frame's
  /// payload completes — and `Ok(None)` otherwise. A protocol violation takes
  /// precedence over any settings completed earlier in the same call.
  ///
  /// `is_client` selects the role-dependent frame-placement policy (RFC 9114
  /// §7.2): a client rejects `MAX_PUSH_ID` (it is client→server only), a server
  /// accepts-and-skips it.
  fn feed(&mut self, is_client: bool, bytes: &[u8]) -> Result<Option<Settings>, H3Error>
  where
    B: AsMut<[u8]>,
  {
    let mut pos = 0usize;
    let mut decoded = None;
    loop {
      match self.cur {
        CtrlCur::None => match self.read_header(bytes, &mut pos)? {
          None => return Ok(decoded), // header not yet complete
          Some(hdr) => self.begin_frame(is_client, hdr)?,
        },
        CtrlCur::Settings { remaining, acc } => {
          match Self::take_into(self.payload.as_mut(), acc, remaining, bytes, &mut pos)? {
            FramePart::More { remaining, acc } => {
              self.cur = CtrlCur::Settings { remaining, acc };
              return Ok(decoded);
            }
            FramePart::Done { acc } => {
              let payload = self.payload.as_mut().get(..acc).unwrap_or(&[]);
              let settings =
                Settings::decode_payload(payload).map_err(|_| H3Error::SettingsError)?;
              decoded = Some(settings);
              self.cur = CtrlCur::None;
            }
          }
        }
        CtrlCur::Skip { remaining } => match Self::skip(remaining, bytes, &mut pos) {
          Some(remaining) => {
            self.cur = CtrlCur::Skip { remaining };
            return Ok(decoded);
          }
          None => self.cur = CtrlCur::None,
        },
      }
    }
  }

  /// Reassembles a frame header byte-by-byte from `bytes[*pos..]`. Returns the
  /// decoded header (advancing `pos`), or `None` if more bytes are needed.
  fn read_header(
    &mut self,
    bytes: &[u8],
    pos: &mut usize,
  ) -> Result<Option<frame::FrameHeader>, H3Error> {
    loop {
      let Some(&b) = bytes.get(*pos) else {
        return Ok(None);
      };
      *pos = pos.saturating_add(1);
      let slot = self
        .hdr_buf
        .get_mut(self.hdr_len)
        .ok_or(H3Error::FrameError)?;
      *slot = b;
      self.hdr_len = self.hdr_len.saturating_add(1);
      match frame::decode_header(self.hdr_buf.get(..self.hdr_len).unwrap_or(&[])) {
        Err(frame::FrameError::Truncated(_)) => {
          if self.hdr_len >= CTRL_HDR_CAP {
            return Err(H3Error::FrameError);
          }
        }
        Err(_) => return Err(H3Error::FrameError),
        Ok((_, hdr)) => {
          self.hdr_len = 0;
          return Ok(Some(hdr));
        }
      }
    }
  }

  /// Applies the control-stream frame-placement policy to a freshly decoded
  /// header and arms `cur` to consume its payload. `is_client` selects the
  /// role-dependent rules for the push-related frames (RFC 9114 §7.2).
  fn begin_frame(&mut self, is_client: bool, hdr: frame::FrameHeader) -> Result<(), H3Error>
  where
    B: AsMut<[u8]>,
  {
    match hdr.kind() {
      frame::FrameKind::Settings => {
        if self.settings_seen {
          // A second SETTINGS frame on the control stream (RFC 9114 §7.2.4).
          return Err(H3Error::FrameUnexpected);
        }
        self.settings_seen = true;
        let remaining = hdr.length();
        let cap = self.payload.as_mut().len().min(CTRL_CAP);
        if usize::try_from(remaining).map_err(|_| H3Error::ExcessiveLoad)? > cap {
          // The SETTINGS payload exceeded the configured memory bound: an
          // excessive-load policy, not a malformed-frame error.
          return Err(H3Error::ExcessiveLoad);
        }
        self.cur = CtrlCur::Settings { remaining, acc: 0 };
        Ok(())
      }
      // The first control-stream frame MUST be SETTINGS (RFC 9114 §6.2.1).
      _ if !self.settings_seen => Err(H3Error::MissingSettings),
      // CANCEL_PUSH (RFC 9114 §7.2.3): we never enable server push (we never send
      // MAX_PUSH_ID), so no push id can ever be valid — receiving CANCEL_PUSH is
      // H3_ID_ERROR. No need to parse the push id: none is in range.
      frame::FrameKind::CancelPush => Err(H3Error::IdError),
      // MAX_PUSH_ID (RFC 9114 §7.2.7) is client→server only. A client receiving
      // it from the server is H3_FRAME_UNEXPECTED; a server receiving it from the
      // client is valid — skip the payload (we simply never push).
      frame::FrameKind::MaxPushId => {
        if is_client {
          return Err(H3Error::FrameUnexpected);
        }
        self.cur = CtrlCur::Skip {
          remaining: hdr.length(),
        };
        Ok(())
      }
      // GOAWAY (RFC 9114 §7.2.6): graceful shutdown is not modeled by this tunnel
      // core (a v1 limitation), so it is accepted and its payload skipped.
      frame::FrameKind::GoAway => {
        self.cur = CtrlCur::Skip {
          remaining: hdr.length(),
        };
        Ok(())
      }
      // GREASE / unknown extension frames are ignored (RFC 9114 §9).
      frame::FrameKind::Unknown => {
        self.cur = CtrlCur::Skip {
          remaining: hdr.length(),
        };
        Ok(())
      }
      // Forbidden on the control stream (RFC 9114 §7.2): DATA / HEADERS are
      // request-stream frames; PUSH_PROMISE is a push frame (never enabled); and
      // the HTTP/2-reserved types (§7.2.8). A second SETTINGS is rejected by the
      // first match arm above.
      frame::FrameKind::Data
      | frame::FrameKind::Headers
      | frame::FrameKind::PushPromise
      | frame::FrameKind::Reserved => Err(H3Error::FrameUnexpected),
    }
  }

  /// Copies up to `remaining` payload bytes from `bytes[*pos..]` into
  /// `dst[acc..]`, advancing `pos`. `Done` once the whole payload is buffered;
  /// `More` when the input ran out first.
  fn take_into(
    dst: &mut [u8],
    acc: usize,
    remaining: u64,
    bytes: &[u8],
    pos: &mut usize,
  ) -> Result<FramePart, H3Error> {
    let avail = bytes.len().saturating_sub(*pos);
    let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
    let end = pos.checked_add(take).ok_or(H3Error::FrameError)?;
    let src = bytes.get(*pos..end).ok_or(H3Error::FrameError)?;
    let acc_end = acc.checked_add(take).ok_or(H3Error::FrameError)?;
    let slot = dst.get_mut(acc..acc_end).ok_or(H3Error::FrameError)?;
    slot.copy_from_slice(src);
    *pos = end;
    let taken = u64::try_from(take).unwrap_or(u64::MAX);
    let remaining = remaining.saturating_sub(taken);
    if remaining == 0 {
      Ok(FramePart::Done { acc: acc_end })
    } else {
      Ok(FramePart::More {
        remaining,
        acc: acc_end,
      })
    }
  }

  /// Discards up to `remaining` payload bytes from `bytes[*pos..]`, advancing
  /// `pos`. Returns the leftover `remaining` if the input ran out, else `None`.
  fn skip(remaining: u64, bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let avail = bytes.len().saturating_sub(*pos);
    let take = usize::try_from(remaining).unwrap_or(usize::MAX).min(avail);
    *pos = pos.saturating_add(take);
    let taken = u64::try_from(take).unwrap_or(u64::MAX);
    let left = remaining.saturating_sub(taken);
    if left == 0 { None } else { Some(left) }
  }
}

/// The outcome of buffering part of a frame payload (see [`ControlState::take_into`]).
enum FramePart {
  /// The payload is fully buffered; `acc` bytes are ready to decode.
  Done { acc: usize },
  /// More payload bytes are needed: `remaining` still to come, `acc` buffered.
  More { remaining: u64, acc: usize },
}

/// One of the connection's mutually exclusive lifecycle phases.
///
/// The phase is the single source of truth for *where in the lifecycle* the
/// connection is; it changes ONLY through the centralized transition methods
/// ([`start`](Connection::start), [`establish`](Connection::establish),
/// [`begin_close`](Connection::begin_close), [`fail`](Connection::fail)), and
/// every public operation's preconditions are derived from it (see the
/// phase × operation table on [`Connection`]). The orthogonal data/role markers
/// (`settings_peer`, `request_sent`, `request_received`, `request_id`, the stream
/// bookkeeping) are NOT phases — they record *what has been exchanged*, and are
/// read alongside the phase by the guards.
#[derive(Clone, Copy, Eq, PartialEq, derive_more::IsVariant)]
enum Phase {
  /// Constructed; setup not yet queued. [`start`](Connection::start) moves to
  /// [`Handshaking`](Self::Handshaking).
  Created,
  /// Setup queued (control+SETTINGS and the two idle QPACK streams). The SETTINGS
  /// exchange and the CONNECT request/response exchange are in progress.
  Handshaking,
  /// The CONNECT exchange completed (client received the response; server sent
  /// it). The tunnel is open for DATA.
  Open,
  /// Graceful close initiated (local [`close`](Connection::close) or a clean peer
  /// reset); winding down (a deferred FIN may still be flushing).
  Closing,
  /// A fatal connection-level error; terminal.
  Failed,
}

/// How inbound request-stream errors are SCOPED for the whole connection
/// (RFC 9114 §4.1.2 per-stream error vs a connection-level error).
///
/// The mode is connection-level, set on the SERVER before [`start`](Connection::start)
/// / [`provide_stream`](Connection::provide_stream), and it governs how a newly
/// registered inbound request stream is classified (its private `is_tunnel` error
/// scope): a request error before the server has committed to a response is connection-fatal
/// in [`Tunnel`](Self::Tunnel) mode and stream-scoped in [`General`](Self::General)
/// mode. It does not affect the CLIENT (which always knows whether it opened a
/// CONNECT tunnel via [`open_with`](Connection::open_with) or a general request via
/// [`open_request`](Connection::open_request)) nor an already-established server
/// CONNECT tunnel (an [`accept_with`](Connection::accept_with) stream stays a tunnel).
///
/// The default is [`Tunnel`](Self::Tunnel) for backward compatibility with the
/// shipped CONNECT-tunnel behavior; a general HTTP/3 server should select
/// [`General`](Self::General) via [`set_mode`](Connection::set_mode).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, IsVariant, derive_more::Display)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum Mode {
  /// One tunnel = one connection: an error on an inbound request stream is
  /// CONNECTION-fatal. This is the strict CONNECT-tunnel scoping — a protocol
  /// violation on the (single) tunnel stream fails the whole connection rather
  /// than resetting just that stream. The default, preserving the behavior of a
  /// connection dedicated to one CONNECT tunnel.
  #[default]
  Tunnel,
  /// A general HTTP/3 server: an error on an inbound request stream is
  /// STREAM-scoped — it resets just that stream (RFC 9114 §4.1.2,
  /// `RESET_STREAM`) and the connection survives, so other concurrent request
  /// streams are unaffected. Select this on a general server (it governs the
  /// pre-response window before [`send_response`](Connection::send_response)).
  General,
}

impl Mode {
  /// A stable, lower-case name for the mode (logging / diagnostics).
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Tunnel => "tunnel",
      Self::General => "general",
    }
  }
}

impl Phase {
  /// The `Handshaking → Open` establish transition body, operating on disjoint
  /// borrows of the phase, the event queue, and the `tunnel_established` flag so it
  /// can run BOTH from [`Connection::establish`] (`&mut self`) and from inside the
  /// lending [`Frames`] iterator (which already borrows the request FSM, so
  /// `&mut self` is unavailable). The single definition of "establish":
  /// `Handshaking → Open` plus [`Event::Established`] AND `tunnel_established`
  /// exactly once; a no-op in any other phase.
  ///
  /// `tunnel_established` is set HERE — on the one real transition — rather than
  /// derived from the phase, so it survives a later `Closing` (a post-`Open`
  /// half-close): the phase moves on but the tunnel was, in fact, established. It
  /// gates [`Frames::next`] yielding [`Frame::Data`] (DATA only after the CONNECT
  /// exchange completes, RFC 9114 §4.4).
  fn establish_into<EventBuf>(
    phase: &mut Self,
    events: &mut BoundedQueue<'_, Event, EventBuf>,
    tunnel_established: &mut bool,
  ) where
    EventBuf: AsMut<[Option<Event>]>,
  {
    if phase.is_handshaking() {
      *phase = Self::Open;
      *tunnel_established = true;
      let _ = events.push(Event::Established);
    }
  }

  /// The `{anything but Failed} → Failed` fail transition body, operating on
  /// disjoint borrows of the phase, the `close_pending` flag, the event queue, and
  /// the dedicated terminal-error slot so it can run BOTH from
  /// [`Connection::fail`] (`&mut self`) and from inside the lending [`Frames`]
  /// iterator on a lazy request-FSM error (which already borrows the request FSM, so
  /// `&mut self` is unavailable). The single definition of "fail":
  ///
  /// - phase → `Failed`;
  /// - `close_pending` cleared (so a `Failed` connection never flushes a deferred
  ///   graceful FIN);
  /// - the pending event queue cleared (so stale nonfatal lifecycle events queued
  ///   before the failure — an `Established` / `PeerClosed` / `Reset` — are
  ///   discarded; once `Failed` the connection is terminal-priority, so a prior
  ///   graceful event is moot and must not be delivered ahead of the terminal
  ///   `ConnError`);
  /// - the terminal [`H3Error`] recorded in the dedicated `conn_error` slot — NOT
  ///   the bounded event queue — so a saturated queue can never swallow the fatal
  ///   code. [`poll_event`](Connection::poll_event) surfaces it as the terminal
  ///   [`Event::ConnError`] FIRST and exactly once; with the queue cleared here and
  ///   the inbound guards keeping a `Failed` connection inert, it is the connection's
  ///   ONLY remaining observable event.
  ///
  /// Idempotent and exactly-once: a no-op when already `Failed`, and the FIRST fatal
  /// error wins the slot (a second fatal condition neither overwrites it nor
  /// re-records a duplicate).
  fn fail_into<EventBuf>(
    phase: &mut Self,
    close_pending: &mut bool,
    events: &mut BoundedQueue<'_, Event, EventBuf>,
    conn_error: &mut Option<H3Error>,
    error: H3Error,
  ) where
    EventBuf: AsMut<[Option<Event>]>,
  {
    if phase.is_failed() {
      return;
    }
    *phase = Self::Failed;
    // A `Failed` connection must not flush a deferred graceful FIN; clear it here
    // as the primary guard (belt-and-suspenders: `try_send_fin` also requires
    // `Phase::Closing`, but clearing here is the definitive invariant).
    *close_pending = false;
    // Discard any stale nonfatal lifecycle events queued before this failure. Once
    // `Failed` the connection is terminal-priority: the terminal `ConnError` is the
    // only signal the driver should observe, so a previously-queued graceful event
    // (an `Established` pulled just before a trailing fatal frame, a `PeerClosed`, a
    // `Reset`) must not be delivered ahead of it. The inbound guards keep a `Failed`
    // connection inert, so nothing re-enqueues after this point.
    events.clear();
    // Record the terminal error in its dedicated, non-droppable slot rather than
    // the bounded event queue, which a flood of benign events could have filled —
    // a fatal path (especially a no-return one like `provide_stream`'s duplicate
    // role or `handle_stream_fin`'s critical-stream close) must always be able to
    // surface its `ConnError`. First fatal wins (this branch runs only when not yet
    // `Failed`, so the slot is empty).
    *conn_error = Some(error);
  }
}

/// The outcome of a HEADERS-send guard ([`open_with`](Connection::open_with) /
/// [`accept_with`](Connection::accept_with)): either the operation is an
/// already-done idempotent no-op, or the preconditions hold and it carries the
/// resolved data (the peer's field-size limit, plus the target stream for the
/// server) needed to encode and send. Every error case is reported as the guard's
/// `Err`, so the public method has exactly one decision point.
enum SendGuard<T> {
  /// The send already happened (request sent / response sent); the call is a no-op
  /// `Ok(())`.
  AlreadyDone,
  /// Preconditions hold; proceed to encode + send with this resolved data.
  Proceed(T),
}

/// The HTTP/3 Extended-CONNECT tunnel connection state machine.
///
/// Parameterized by the [`Role`] ([`Client`] or [`Server`]). See the
/// [module docs](self) for the lifecycle.
///
/// # Lifecycle `Phase`
///
/// The connection's lifecycle is a single internal `Phase` enum — the mutually
/// exclusive states `Created → Handshaking → Open`, plus the terminal/winding-down
/// `Closing` and `Failed`. The phase changes ONLY through four centralized
/// transition methods, and each public operation checks its preconditions through
/// one guard derived from the phase, so the guards are correct by construction
/// rather than scattered across the methods.
///
/// Orthogonal to the phase are the data/role markers, which record *what has been
/// exchanged* (not *where in the lifecycle* we are): `settings_peer` (presence =
/// the peer's SETTINGS were decoded), `request_sent` (client: the CONNECT request
/// was queued, exactly once), `request_received` (server: the request HEADERS were
/// OBSERVED — yielded to the driver via [`Frames::next`], not merely decoded),
/// `tunnel_established` (the tunnel reached `Open` — gates yielding [`Frame::Data`],
/// and stays `true` across a later `Closing`), `request_id` / `roles` / `uni` /
/// `close_pending`.
///
/// ## Transitions (the only places the phase changes)
///
/// - [`start`](Self::start): `Created → Handshaking`, transactionally enqueuing
///   the three setup transmits (all-or-nothing). Idempotent no-op past `Created`;
///   `Err(Closed)` when `Closing`/`Failed`.
/// - `establish`: `Handshaking → Open`, enqueuing [`Event::Established`] exactly
///   once. No-op when not `Handshaking`.
/// - `begin_close`: `{Created, Handshaking, Open} → Closing` (the phase change
///   only). Idempotent; no-op when `Closing`/`Failed`. A local [`close`](Self::close)
///   additionally arms the deferred FIN; a peer reset does not.
/// - `fail`: `{anything but Failed} → Failed`, enqueuing [`Event::ConnError`]
///   exactly once. Idempotent.
///
/// A clean peer request-stream FIN is a *half-close* ([`Event::PeerClosed`]): it
/// does NOT force `Closing`/`Failed`, so local sends may continue.
///
/// ## Phase × operation
///
/// Each public operation routes through one guard. `WouldBlock` is retriable
/// (pump / drain and retry); `Closed` and the terminal `ConnError` events are not.
///
/// | operation | `Created` | `Handshaking` | `Open` | `Closing` / `Failed` |
/// |---|---|---|---|---|
/// | [`start`](Self::start) | enqueue setup → `Handshaking` (ring full → `WouldBlock`) | no-op `Ok` | no-op `Ok` | `Err(Closed)` |
/// | [`open_with`](Self::open_with) (client) | `Err(Closed)` | no peer SETTINGS → `WouldBlock`; not opted in → `ExtendedConnectUnsupported`; else send (field-size; `request_sent` ⇒ no-op `Ok`) | `request_sent` ⇒ no-op `Ok` | `Err(Closed)` |
/// | [`accept_with`](Self::accept_with) (server) | `Err(Closed)` | no `request_received` / no peer SETTINGS → `WouldBlock`; else send + establish (field-size) | no-op `Ok` (response already sent) | `Err(Closed)` |
/// | [`send_data`](Self::send_data) | `Err(Closed)` | `Err(Closed)` | send (no request stream → `Closed`; oversize → `FrameError`; full ring → `WouldBlock`) | `Err(Closed)` |
/// | [`close`](Self::close) | → `Closing` (+ deferred FIN) | → `Closing` (+ FIN) | → `Closing` (+ FIN) | no-op |
/// | [`handle_stream_reset`](Self::handle_stream_reset) | → `Closing` + `Reset` (request id only; no FIN) | → `Closing` + `Reset` | → `Closing` + `Reset` | no-op |
///
/// The `Created` terminal guard on the send paths enforces setup-before-traffic:
/// the control stream's SETTINGS must reach the wire before any request / response
/// / DATA frame (RFC 8441 §3 / RFC 9114 §6.2.1). In practice the peer's SETTINGS
/// cannot arrive before our own [`start`](Self::start), so it only fires on misuse.
///
/// ## The observation-gating invariant (readiness on OBSERVATION, not on bytes)
///
/// This section is the single canonical statement of the observation-gating
/// invariant; the `Frames` / `handle_stream` / drain APIs each restate only their
/// local specifics and cross-reference back here.
///
/// The CONNECT-HEADERS readiness the table gates on — the server's `request_received`
/// (which unblocks [`accept_with`](Self::accept_with)) and the client's
/// `Handshaking → Open` establish — is granted ONLY when [`Frames::next`] actually
/// yields the first [`Frame::Request`] / [`Frame::Response`] to the driver (the
/// observation point). Merely feeding the HEADERS bytes to
/// [`handle_stream`](Self::handle_stream) is not enough: a [`Frames`] iterator
/// dropped before any `next()` has its bytes validated (a malformed HEADERS section
/// or a trailing forbidden frame is still fatal) but advances NO readiness — the
/// server cannot then `accept_with` a CONNECT the driver never observed, and the
/// client does not become `Established` on a response it never validated. The driver
/// must observe and validate the request / response (pull it via `next()`) before
/// accepting or using the tunnel.
///
/// ## Tunnel DATA is yielded only once established (`tunnel_established`)
///
/// [`Frames::next`] yields [`Frame::Data`] ONLY after the tunnel has reached `Open`
/// — tracked by `tunnel_established`, set on the single `Handshaking → Open`
/// transition (reached by server [`accept_with`](Self::accept_with) or the client
/// observing the response). EVERY DATA-frame occurrence passes this establishment
/// gate, on BOTH paths — the yield path ([`Frames::next`]) AND the drop-drain (so
/// dropping the iterator cannot smuggle premature DATA past the gate) — and for EVERY
/// DATA frame, including a zero-length
/// one (the request FSM yields a length-0 DATA header as one empty occurrence rather
/// than silently consuming it, so it reaches the gate too). A peer that coalesces
/// request HEADERS and a DATA frame in one
/// [`handle_stream`](Self::handle_stream) read sends that DATA before the 2xx
/// response (RFC 9114 §4.4 forbids it); on the server, observing the HEADERS only
/// sets `request_received`, so the DATA is premature. Such premature DATA — server
/// before `accept_with`, or any never-established phase — is a malformed message
/// ([`H3Error::MessageError`], RFC 9114 §4.1.2): it routes through the centralized
/// fail transition (the connection becomes `Failed` with one terminal `ConnError`)
/// instead of being yielded to the driver OR silently discarded by the drain. Because
/// the gate is `tunnel_established` (not the phase), a post-`Open` half-close (phase
/// `Closing`, flag still `true`) STILL delivers peer DATA, whereas a `close()` while
/// still `Handshaking` (→ `Closing`, never established) does not re-leak pre-accept
/// DATA. An ESTABLISHED zero-length DATA frame is consumed but NOT surfaced as an
/// empty [`Frame::Data`] (it passes the gate, then `Frames::next` skips it — the
/// driver is never handed empty chunks). The client observes [`Frame::Response`]
/// (which establishes) before any [`Frame::Data`] in the same drain, and the stream
/// FSM requires HEADERS before DATA, so legitimate tunnel DATA always flows.
///
/// ### Dropped-unobserved: the request stream goes inert (`request_abandoned`)
///
/// Decoding the first HEADERS advances the inbound [`Stream`] FSM into its
/// tunnel phase as a side effect, and the drop-drain decodes that HEADERS too. So a
/// [`Frames`] dropped before any `next()` over a valid first HEADERS leaves the FSM
/// in `Tunnel` even though the driver never observed the CONNECT request / response —
/// and the consumed HEADERS bytes are gone with the per-call input, so the stream can
/// NEVER be observed afterwards. Rather than let that orphaned tunnel phase surface
/// later activity, the drop-drain marks the connection `request_abandoned`. The
/// request stream is then permanently inert to the DRIVER — it never surfaces tunnel
/// data and never grants readiness — but it is NOT terminal, so its later input is
/// still VALIDATED (only a `Failed` connection bypasses the FSM/gate entirely, see
/// below). An abandoned stream's bytes / FIN are driven through the same validation-only
/// path — the premature-DATA establishment gate and the FSM error checks — surfacing
/// nothing but failing the connection on the peer's protocol violations:
///
/// | inbound method | dropped-unobserved (`request_abandoned`) |
/// |---|---|
/// | [`handle_stream`](Self::handle_stream) (request stream) | validation-only: drives the FSM/gate, NO `Frame::Data` surfaced (the driver never established the tunnel); a clean read stays non-terminal, premature DATA → terminal `MessageError`, a forbidden frame → its FSM error |
/// | [`handle_stream_fin`](Self::handle_stream_fin) (request stream) | validation-only: a clean FIN surfaces NO `Event::PeerClosed` (the tunnel was never observed / established) and stays non-terminal; a malformed / mid-frame FIN → terminal (`FrameError` / `RequestIncomplete`) |
///
/// Abandonment ITSELF is not a connection failure: a lazy driver dropping an iterator
/// is not a protocol violation, so readiness simply stays ungranted (server
/// [`accept_with`](Self::accept_with) keeps returning [`Error::WouldBlock`], the client
/// never becomes `Established`) — the correct consequence of not observing. But the
/// PEER's protocol violations on that stream (premature DATA, a forbidden frame, a
/// malformed FIN) are still its own faults and still fail the connection. Non-request
/// streams (control / QPACK) are unaffected, and a FIN on a critical stream still fails
/// the connection as usual.
///
/// ## Terminal-state guards (`Failed` is fully terminal-priority)
///
/// Once a connection-fatal error has occurred, the terminal [`Event::ConnError`] is
/// the connection's last observable signal — on BOTH directions. The driver-facing
/// *inbound* methods (those the driver calls to feed peer activity into the core)
/// all honor the `Failed` phase, so no later inbound activity is processed or
/// surfaces an event ahead of it; and the *output* methods are inert too:
/// [`poll_transmit`](Self::poll_transmit) emits nothing, and the fail transition
/// clears the pending event queue so [`poll_event`](Self::poll_event) yields EXACTLY
/// the terminal `ConnError` (no stale queued `Established` / `PeerClosed` / `Reset`,
/// no stale outbound DATA / `OpenRequest`), then `None`. `Closing` is treated
/// differently — a gracefully-closing connection has only half-closed locally, so
/// the peer's half stays live (inbound DATA keeps flowing until the peer FINs) and
/// the output side still flushes queued bytes and the deferred close FIN.
///
/// `Failed` is the ONLY state in which request-stream input bypasses the FSM/gate
/// entirely — there it is moot, the connection is already terminal. Every other state
/// (including `Closing`, and an abandoned-but-non-terminal request stream — see above)
/// STILL drives inbound request-stream bytes / FINs through validation, so a peer's
/// protocol violation (premature DATA, a forbidden frame, a malformed FIN) is caught
/// and fails the connection on the first occurrence.
///
/// | inbound method | `Failed` | `Closing` |
/// |---|---|---|
/// | [`handle_stream`](Self::handle_stream) | no-op: empty [`Frames`], bytes ignored on EVERY stream | processes (peer half still open; a forbidden frame still supersedes the close) |
/// | [`Frames::next`] (a live request iterator) | fused: `Ok(None)` (a lazy fatal error inside THIS iterator already routed through the fail transition; no `Frame` surfaces past the terminal `ConnError`) — parity with the drop path's `drain_for_errors` | yields normally (the close is not terminal) |
/// | [`handle_stream_fin`](Self::handle_stream_fin) | no-op (no `PeerClosed`, no second `ConnError`) | processes; a clean request FIN is `PeerClosed` (idempotent — at most once) |
/// | [`handle_stream_reset`](Self::handle_stream_reset) | no-op (no `Reset` after the fatal `ConnError`) | no-op (already terminal; `Reset` enqueued at most once) |
/// | [`provide_stream`](Self::provide_stream) | no-op (binds no id) | binds (a deferred close FIN may target a late request stream) |
/// | [`poll_transmit`](Self::poll_transmit) | no-op: emits nothing (no stale queued bytes, no graceful FIN) | drains; retries the deferred close FIN |
/// | [`poll_event`](Self::poll_event) | yields EXACTLY the terminal `ConnError` (first, once), then `None` | delivers queued events |
///
/// The remaining methods take no readiness guards and never panic when called out
/// of order, but several drive the transitions on a fatal/graceful condition:
/// [`provide_stream`](Self::provide_stream) records an id (usable even while
/// closing, so a deferred close FIN can target a late request stream), but
/// rebinding an already-bound role to a *different* id is a duplicate
/// critical/request stream — it `fail`s the connection without
/// rebinding; [`handle_stream_fin`](Self::handle_stream_fin) (each id matches at
/// most one case; an unknown id is ignored) `fail`s on a
/// connection-fatal FIN (a request stream ending mid-frame, or a critical stream
/// closing). A clean request-stream FIN is a *half-close*: it enqueues
/// [`Event::PeerClosed`] (at most once) WITHOUT changing the phase, so local sends
/// may continue. The purely read-only methods are
/// [`handle_stream`](Self::handle_stream) (parses inbound bytes — a
/// connection-fatal violation is an [`H3Error`], never a panic; a no-op once
/// `Failed`),
/// [`poll_transmit`](Self::poll_transmit) (also retries a deferred close FIN),
/// [`poll_event`](Self::poll_event), [`peer_settings`](Self::peer_settings), and
/// [`is_established`](Self::is_established).
pub struct Connection<
  'req,
  'ctrl,
  'tx,
  'event,
  'uni,
  Ro,
  ReqBuf = DefaultReqBuf<'req>,
  CtrlBuf = DefaultCtrlBuf<'ctrl>,
  TxBuf = DefaultTxBuf<'tx>,
  EventBuf = DefaultEventBuf<'event>,
  UniBuf = DefaultUniBuf<'uni>,
  St = DefaultStreamStore<'req, ReqBuf>,
> {
  settings_local: Settings,
  settings_peer: Option<Settings>,
  /// Per-stream state ([`StreamEntry`]) keyed by [`StreamId`]. The CONNECT tunnel
  /// uses exactly one entry, named by `request_id`; the singular `request` FSM and
  /// per-tunnel markers moved onto that entry. See [`StreamStore`].
  streams: St,
  /// The single CONNECT-tunnel stream slot's id (the one entry in `streams`). Kept
  /// as the tunnel-specialization pointer so [`send_data`](Self::send_data) /
  /// [`close`](Self::close) / [`accept_with`](Self::accept_with) find their stream.
  request_id: Option<StreamId>,
  /// The caller-provided (or default) HEADERS accumulator buffer, held until the
  /// FIRST request stream is registered. The CONNECT tunnel preallocates exactly
  /// one recv FSM, so its buffer is seeded here at construction and moved into the
  /// tunnel's [`StreamEntry`] on the first
  /// [`provide_stream`](Self::provide_stream)`(Request, …)`. (Additional request
  /// ids — the relaxed multi-stream path — mint a fresh `ReqBuf::default()` buffer;
  /// the general per-stream buffering is wired in a later task.)
  req_seed: Option<ReqBuf>,
  /// Role → stream id for the streams *we* open (outbound uni streams) and the
  /// bidirectional request stream; index by [`StreamRole::index`]. Inbound uni
  /// streams the peer opens are tracked in `uni` instead.
  roles: [Option<StreamId>; ROLE_COUNT],
  /// The peer control stream's continuous frame parser (SETTINGS first, then a
  /// role-aware policy for the push frames; GOAWAY / GREASE skipped; DATA /
  /// HEADERS / PUSH_PROMISE / reserved / duplicate SETTINGS rejected). See
  /// [`ControlState`].
  ctrl: ControlState<'ctrl, CtrlBuf>,
  /// Every inbound (peer-opened) uni stream we are tracking, by id → state.
  /// Bounded at [`UNI_CAP`]; a stream occupies a slot from its first byte
  /// (`Pending`, while its type varint is mid-parse) through classification: a
  /// critical role routes its bytes to its handler, an `Ignored` entry discards
  /// them by lookup (so a GREASE payload is never reinterpreted as a stream-type
  /// varint), and reserving a slot for a new id when the table is full is
  /// [`H3Error::ExcessiveLoad`] rather than a silent drop — so a flood of partial
  /// or GREASE streams cannot saturate the table and then hide the peer's real
  /// control stream.
  uni: UniBuf,
  events: BoundedQueue<'event, Event, EventBuf>,
  tx: TxRing<'tx, TxBuf>,
  /// The single lifecycle state (see [`Phase`]). Every public operation's
  /// preconditions are derived from this, and it changes ONLY through the
  /// centralized transitions ([`start`](Self::start) / [`establish`](Self::establish)
  /// / [`begin_close`](Self::begin_close) / [`fail`](Self::fail)).
  phase: Phase,
  /// Client-only: set once [`open_with`](Self::open_with) has enqueued the CONNECT
  /// request HEADERS, so a second `open_with` is a no-op `Ok` (the request is sent
  /// exactly once). A data marker, not a phase. Never set on the server.
  ///
  /// This stays a connection field (not on the per-stream [`StreamEntry`]) because
  /// the client enqueues the request as an `OpenRequest` transmit BEFORE the driver
  /// reports the stream id via [`provide_stream`](Self::provide_stream) — i.e. before
  /// the tunnel's `StreamEntry` exists. The general per-stream send marker is wired
  /// with the per-stream send API in a later task.
  request_sent: bool,
  /// Set by [`close`](Self::close) when the empty FIN transmit could not be
  /// enqueued immediately (the transmit ring was full) or the request stream did
  /// not exist yet. [`poll_transmit`](Self::poll_transmit) retries the enqueue
  /// once the ring drains and the request id is known, so a close is never lost
  /// under backpressure. Cleared the moment the FIN is enqueued (exactly once).
  close_pending: bool,
  /// The terminal connection error, recorded by [`fail`](Self::fail) /
  /// [`Phase::fail_into`] when the `Failed` transition happens (the FIRST fatal
  /// error wins). This dedicated slot — NOT the bounded `events` queue — is what
  /// makes the terminal [`Event::ConnError`] non-droppable: a fatal path can land
  /// in `Failed` even when `events` is saturated (e.g. a no-return path like a
  /// duplicate-role [`provide_stream`](Self::provide_stream) or a critical-stream
  /// [`handle_stream_fin`](Self::handle_stream_fin)), and the error must still
  /// surface. [`poll_event`](Self::poll_event) delivers it FIRST and takes it, so it
  /// is delivered exactly once; the fail transition also clears the pending event
  /// queue, so no stale graceful event precedes the terminal `ConnError`.
  conn_error: Option<H3Error>,
  /// The dedicated reset control-signal channel: a small bounded, id-keyed queue of
  /// stream-scoped `RESET_STREAM` aborts, the SOLE source of `RESET_STREAM`. A reset is
  /// modeled as a per-stream SIGNAL, not bytes: it is recorded here and emitted directly
  /// by [`poll_transmit`](Self::poll_transmit) (FIRST, one per call, never gated by byte
  /// [`TxRing`] slot capacity), so an abort can never be ring-gated, dropped, or stranded
  /// behind a held front transmit. Two sources feed it:
  ///
  /// - the lending [`Frames`] carrier (its [`RequestFrames`]) on a non-tunnel stream
  ///   error — a malformed message / validator violation / premature DATA — that resets
  ///   only that stream rather than failing the connection. The carrier holds disjoint
  ///   borrows of the per-stream entry's fields and cannot reach `streams` / `tx`, so it
  ///   only RECORDS the abort here; and
  /// - the capacity backstop ([`provide_request_stream`](Self::provide_request_stream)):
  ///   an at-capacity request stream is rejected and its `RESET_STREAM(RequestRejected)`
  ///   recorded here (RFC 9114 §4.1 — `H3_REQUEST_REJECTED` lets the peer safely retry).
  ///
  /// Recording is DEDUPED by stream id (FIRST code wins — exactly-once per RFC 9114
  /// §4.1.2). The slot bookkeeping (free the entry, clear `request_id`) and DATA purge a
  /// recorded reset still needs run in [`reconcile_pending_resets`](Self::reconcile_pending_resets),
  /// at the head of every `&mut self` entry that can observe the effect
  /// ([`handle_stream`](Self::handle_stream) / [`poll_transmit`](Self::poll_transmit) /
  /// the send guards), DECOUPLED from the abort emission — the abort lives in this channel
  /// regardless of whether the DATA tombstones have drained. A full channel is
  /// pathological (`RESET_CAP` distinct undrained resets), so it fails the connection
  /// closed rather than silently dropping an abort.
  ///
  /// This is the stream-scoped twin of `conn_error` (the connection-fatal slot): a
  /// distinct `Connection` field so the carrier's borrow of it stays disjoint from
  /// `phase` / `events` / `close_pending` / `conn_error`.
  pending_resets: PendingResets,
  /// How inbound request-stream errors are scoped for this connection (see [`Mode`]).
  /// Read by the SERVER's [`provide_request_stream`](Self::provide_request_stream) to
  /// classify a newly registered request stream's
  /// [`is_tunnel`](StreamEntry::is_tunnel) marker, so it must be set (via
  /// [`set_mode`](Self::set_mode)) before the first inbound request stream is provided.
  /// Defaults to [`Mode::Tunnel`] (strict CONNECT-tunnel scoping); the CLIENT paths and
  /// `accept_with` ignore it (they know their stream's scope directly).
  mode: Mode,
  _ro: PhantomData<fn() -> Ro>,
  _storage: PhantomData<(
    &'req mut (),
    &'ctrl mut (),
    &'tx mut (),
    &'event mut (),
    &'uni mut (),
  )>,
}

/// A connection backed by borrowed byte buffers.
///
/// This is the no-alloc, small-value form: callers own the request HEADERS
/// accumulator, control-stream payload buffer, transmit-ring byte storage,
/// event slots, and inbound-uni tracking slots. Each storage class has its own
/// lifetime parameter so the buffers do not have to come from the same owner.
pub type BorrowedConnection<'req, 'ctrl, 'tx, 'event, 'uni, Ro> = Connection<
  'req,
  'ctrl,
  'tx,
  'event,
  'uni,
  Ro,
  &'req mut [u8],
  &'ctrl mut [u8],
  &'tx mut [u8],
  &'event mut [Option<Event>],
  &'uni mut [UniSlot],
>;

#[cfg(any(feature = "std", feature = "alloc"))]
impl<Ro: Role> Connection<'static, 'static, 'static, 'static, 'static, Ro> {
  /// A fresh connection in the role `Ro`, with our local settings selected and
  /// all queues empty. Nothing is sent until [`start`](Self::start) (both roles);
  /// the client then sends its CONNECT request with
  /// [`open_with`](Connection::open_with) once the peer's SETTINGS arrive.
  ///
  /// No `Default` is implemented: in the bare no-alloc tier the default storage
  /// is borrowed slices, so there is no honest feature-independent default
  /// connection value.
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self::with_buffers(
      crate::stream::default_req_buf(),
      default_ctrl_buf(),
      queue::default_tx_buf(),
      queue::default_event_buf(),
      default_uni_buf(),
    )
  }
}

impl<'req, Ro, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf>
  Connection<
    'req,
    '_,
    '_,
    '_,
    '_,
    Ro,
    ReqBuf,
    CtrlBuf,
    TxBuf,
    EventBuf,
    UniBuf,
    DefaultStreamStore<'req, ReqBuf>,
  >
where
  Ro: Role,
{
  /// A fresh connection backed by caller-provided storage buffers (heap tiers).
  ///
  /// This constructor is the no-alloc-`Connection`-value alternative to
  /// [`new`](Connection::new): put the buffers wherever your application wants
  /// (arena, static storage, stack, or an allocator outside this crate) and the
  /// connection value itself stores only the buffer handles. On the heap tiers
  /// the [`StreamStore`] grows dynamically, so it is constructed internally — no
  /// caller-provided slots are needed.
  #[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
  pub fn with_buffers(
    request_headers: ReqBuf,
    control_payload: CtrlBuf,
    tx_bytes: TxBuf,
    event_slots: EventBuf,
    uni_slots: UniBuf,
  ) -> Self {
    Self::from_parts(
      request_headers,
      control_payload,
      tx_bytes,
      event_slots,
      uni_slots,
      crate::stream_store::SlabStore::new(),
    )
  }

  /// A fresh connection backed by caller-provided storage buffers (bare tier).
  ///
  /// Identical to the heap-tier [`with_buffers`](Self::with_buffers), but the bare
  /// `no_std` [`StreamStore`] is a fixed-capacity [`ArrayStore`] over
  /// caller-provided `stream_slots` (mirroring how the inbound-uni table takes
  /// `uni_slots`): initialize a `[StreamSlot::EMPTY; N]` (or
  /// `[ArraySlot::EMPTY; N]`) and pass `&mut slots[..]`. The slice length bounds
  /// concurrent streams (the CONNECT tunnel needs one).
  #[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
  pub fn with_buffers(
    request_headers: ReqBuf,
    control_payload: CtrlBuf,
    tx_bytes: TxBuf,
    event_slots: EventBuf,
    uni_slots: UniBuf,
    stream_slots: &'req mut [ArraySlot<StreamEntry<'req, ReqBuf>>],
  ) -> Self {
    Self::from_parts(
      request_headers,
      control_payload,
      tx_bytes,
      event_slots,
      uni_slots,
      ArrayStore::with_slots(stream_slots),
    )
  }

  /// The construction body shared by both tiers' [`with_buffers`](Self::with_buffers):
  /// seeds the single tunnel HEADERS buffer (moved into the tunnel
  /// [`StreamEntry`] at the first [`provide_stream`](Self::provide_stream)) and
  /// stores the already-built [`StreamStore`].
  fn from_parts(
    request_headers: ReqBuf,
    control_payload: CtrlBuf,
    tx_bytes: TxBuf,
    event_slots: EventBuf,
    uni_slots: UniBuf,
    streams: DefaultStreamStore<'req, ReqBuf>,
  ) -> Self {
    let settings_local = if Ro::IS_CLIENT {
      Settings::for_client()
    } else {
      Settings::for_server()
    };
    Self {
      settings_local,
      settings_peer: None,
      streams,
      request_id: None,
      req_seed: Some(request_headers),
      roles: [None; ROLE_COUNT],
      ctrl: ControlState::with_buffer(control_payload),
      uni: uni_slots,
      events: BoundedQueue::with_buffer(event_slots),
      tx: TxRing::with_buffer(tx_bytes),
      phase: Phase::Created,
      request_sent: false,
      close_pending: false,
      conn_error: None,
      pending_resets: PendingResets::new(),
      mode: Mode::Tunnel,
      _ro: PhantomData,
      _storage: PhantomData,
    }
  }
}

impl<Ro, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
  Connection<'_, '_, '_, '_, '_, Ro, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
where
  Ro: Role,
{
  /// The peer's settings, once its control-stream SETTINGS frame has been
  /// received and validated (`None` until then).
  ///
  /// The client polls this after [`handle_stream`](Self::handle_stream) to learn
  /// the peer's SETTINGS have arrived (there is no separate event): once it is
  /// `Some`, call [`open_with`](Connection::open_with) to send the CONNECT
  /// request.
  ///
  /// # Field-section size
  ///
  /// The peer's `MAX_FIELD_SECTION_SIZE`
  /// ([`Settings::max_field_section_size`]) bounds the *decoded* field-section
  /// size of outbound HEADERS: the sum over every field of its name length + value
  /// length + 32 bytes of per-field overhead (RFC 9114 §4.2.2). The core enforces
  /// it synchronously at send time — [`open_with`](Connection::open_with) (client)
  /// and [`accept_with`](Connection::accept_with) (server) return
  /// [`Error::FieldSectionTooLarge`] when the request/response exceeds the limit.
  /// (Our own peers never advertise it, so it reads back as `None` = unlimited.)
  ///
  /// This is distinct from the internal `HDR_CAP` bound, which limits the
  /// *encoded* inbound HEADERS buffer (a memory bound that fails oversize input
  /// gracefully with [`H3Error::FrameError`]).
  pub const fn peer_settings(&self) -> Option<Settings> {
    self.settings_peer
  }

  /// Whether the CONNECT HEADERS exchange has completed (the tunnel is open).
  pub const fn is_established(&self) -> bool {
    self.phase.is_open()
  }

  /// This connection's request-error scoping [`Mode`] (default [`Mode::Tunnel`]).
  #[inline(always)]
  pub const fn mode(&self) -> Mode {
    self.mode
  }

  /// Selects how inbound request-stream errors are scoped (see [`Mode`]), returning
  /// `&mut Self` so it chains with other configuration.
  ///
  /// This must be set BEFORE [`start`](Self::start) /
  /// [`provide_stream`](Self::provide_stream): it governs how the SERVER registers a
  /// newly inbound request stream (it derives the new entry's private `is_tunnel` error
  /// scope from the mode), so changing it after a request stream is already registered
  /// does not reclassify that stream. The default is
  /// [`Mode::Tunnel`] (strict CONNECT-tunnel scoping); a general HTTP/3 server should
  /// call `set_mode(`[`Mode::General`]`)`. The CLIENT paths and
  /// [`accept_with`](Self::accept_with) ignore the mode (they know their stream's
  /// scope directly).
  #[inline(always)]
  pub const fn set_mode(&mut self, mode: Mode) -> &mut Self {
    self.mode = mode;
    self
  }

  /// Whether the connection is winding down or terminal (phase `Closing` or
  /// `Failed`): a local [`close`](Self::close), a clean peer reset, or a fatal
  /// error have all made it so. The send paths are terminal (`Err(Closed)`) here.
  /// This is the `Phase`-derived successor to the old `closing` flag.
  pub(crate) const fn is_terminal(&self) -> bool {
    matches!(self.phase, Phase::Closing | Phase::Failed)
  }

  /// Whether [`start`](Self::start) has queued the setup (phase past `Created`).
  /// The `Phase`-derived successor to the old `started` flag, used by the
  /// lifecycle tests to assert the setup-before-traffic ordering. Gated to the
  /// same cfg as the test module that consumes it (the bare tier omits both).
  #[cfg(all(test, any(feature = "std", feature = "alloc")))]
  pub(crate) const fn is_started(&self) -> bool {
    !self.phase.is_created()
  }

  /// Whether a deferred graceful FIN is still pending (set by [`close`](Self::close)
  /// when the transmit ring was full; cleared once the FIN is enqueued or once the
  /// connection `fail`s). Used by regression tests to assert that every fatal path
  /// cancels the deferred FIN — the invariant "a `Failed` connection never flushes a
  /// graceful FIN" must hold on ALL fail paths, not only `Connection::fail`.
  #[cfg(all(test, any(feature = "std", feature = "alloc")))]
  pub(crate) const fn is_close_pending(&self) -> bool {
    self.close_pending
  }
}

impl<'req, 'event, Ro, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
  Connection<'req, '_, '_, 'event, '_, Ro, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
where
  Ro: Role,
  St: StreamStore<StreamEntry<'req, ReqBuf>>,
{
  // ── Centralized transitions: the ONLY places `self.phase` changes ────────────

  /// `Created → Handshaking`, transactionally enqueuing the three setup transmits
  /// (control+SETTINGS and the two idle QPACK streams). All-or-nothing on a full
  /// ring (see [`enqueue_setup`](Self::enqueue_setup)); on an empty ring it always
  /// fits. Idempotent no-op once past `Created`; `Err(Closed)` when terminal.
  fn start_handshake(&mut self) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    match self.phase {
      // The setup is enqueued exactly once; a repeat (in any non-terminal post-
      // setup phase) is a no-op so it never opens a duplicate control stream.
      Phase::Handshaking | Phase::Open => Ok(()),
      Phase::Closing | Phase::Failed => Err(Error::Closed),
      Phase::Created => {
        // Enqueue the setup BEFORE flipping the phase, so a full-ring `WouldBlock`
        // leaves the phase `Created` (nothing enqueued) and a retry is single.
        self.enqueue_setup()?;
        self.phase = Phase::Handshaking;
        Ok(())
      }
    }
  }

  /// `Handshaking → Open`, enqueuing [`Event::Established`] exactly once. A no-op
  /// in any other phase (so a stray trigger cannot re-establish or revive a
  /// closed/failed connection). Delegates to [`Phase::establish_into`], the shared
  /// transition body (the client's response-HEADERS carrier runs the same body
  /// from inside the lending iterator).
  ///
  /// Then flushes a DEFERRED clean peer FIN: if a pre-establishment clean request
  /// FIN set `peer_fin_pending` (a half-close that arrived while still
  /// `Handshaking`, see [`handle_stream_fin`](Self::handle_stream_fin)), surface its
  /// [`Event::PeerClosed`] now — AFTER `establish_into` enqueued `Established`, so a
  /// tunnel-lifecycle `PeerClosed` never precedes `Established`. Exactly once, via the
  /// `peer_closed` flag. This is the SERVER's establish point (`accept_with` → here);
  /// the client cannot have a pending pre-establishment FIN (it establishes on
  /// observing the response HEADERS via its own carrier, which is not this method), so
  /// localizing the deferred emit here is correct and complete. A no-op flush when
  /// `establish_into` was itself a no-op (not `Handshaking`): `tunnel_established`
  /// stays `false`, so `peer_fin_pending` could not have been set on this path, and
  /// even a stray flag is harmless because nothing established.
  fn establish(&mut self)
  where
    EventBuf: AsMut<[Option<Event>]>,
  {
    // The tunnel's per-stream `established` / `peer_*` markers live on its
    // `StreamEntry` now; look it up by the tunnel-slot pointer (`request_id`) and
    // borrow `phase` / `events` separately (disjoint fields from `self.streams`).
    let Some(id) = self.request_id else {
      // No tunnel stream yet: still run the phase-only establish so a degenerate
      // order behaves as before (no per-stream marker to flip).
      Phase::establish_into(&mut self.phase, &mut self.events, &mut false);
      return;
    };
    let Some(entry) = self.streams.get_mut(id) else {
      Phase::establish_into(&mut self.phase, &mut self.events, &mut false);
      return;
    };
    Phase::establish_into(&mut self.phase, &mut self.events, &mut entry.established);
    if entry.peer_fin_pending && !entry.peer_closed {
      entry.peer_closed = true;
      entry.peer_fin_pending = false;
      let _ = self.events.push(Event::PeerClosed);
    }
  }

  /// Whether the CONNECT tunnel's request HEADERS have been OBSERVED (the tunnel
  /// entry's `observed`, the gate [`accept_with`](Self::accept_with) waits on, was
  /// the singular `request_received`). Test-only accessor: the marker now lives on
  /// the per-stream [`StreamEntry`], so the tunnel suite reads it through here rather
  /// than a bare field. Gated to the same cfg as the test module that consumes it.
  #[cfg(all(test, any(feature = "std", feature = "alloc")))]
  pub(crate) fn request_received(&self) -> bool {
    self
      .request_id
      .and_then(|id| self.streams.get(id))
      .is_some_and(|e| e.observed)
  }

  /// Whether the connection is in the terminal `Failed` phase (a fatal,
  /// connection-scoped error occurred). Test-only probe used to assert that a
  /// per-stream event (e.g. a future non-tunnel reset) does NOT fail the whole
  /// connection. Gated to the same cfg as the test module that consumes it.
  #[cfg(all(test, any(feature = "std", feature = "alloc")))]
  pub(crate) const fn is_failed(&self) -> bool {
    self.phase.is_failed()
  }

  /// Whether `id` no longer names a tracked request stream (its [`StreamEntry`] was
  /// removed from the [`StreamStore`]). Test-only probe: drives the per-stream-reset
  /// isolation assertions (a reset stream is freed).
  #[cfg(all(test, any(feature = "std", feature = "alloc")))]
  pub(crate) fn stream_is_gone(&self, id: StreamId) -> bool {
    self.streams.get(id).is_none()
  }

  /// The graceful-close phase transition `{Created, Handshaking, Open} → Closing`.
  /// Idempotent; a no-op when already `Closing`/`Failed`. Returns whether it
  /// actually transitioned (so the caller runs its first-transition side effect
  /// exactly once).
  ///
  /// This is the phase change ONLY: it does NOT arm the deferred FIN. A local
  /// [`close`](Self::close) arms the FIN on top of this (the local half-close sends
  /// an empty FIN), whereas a peer reset ([`handle_stream_reset`](Self::handle_stream_reset))
  /// routes through here WITHOUT a FIN — the peer already reset the request stream,
  /// so FINing it would be spurious. Closing from `Created` is legal (a degenerate
  /// but valid order, e.g. `close()` before `start()`).
  fn begin_close(&mut self) -> bool {
    if self.is_terminal() {
      return false;
    }
    self.phase = Phase::Closing;
    true
  }

  /// `{anything but Failed} → Failed`, recording the terminal [`Event::ConnError`]
  /// in the dedicated, non-droppable `conn_error` slot exactly once. Idempotent — a
  /// second fatal condition neither overwrites the slot nor records a duplicate (the
  /// FIRST fatal error wins). `Failed` supersedes `Closing` (a fatal error during a
  /// graceful close still surfaces the error), but never overwrites an existing
  /// `Failed`. Delegates to [`Phase::fail_into`], the shared transition body (a lazy
  /// request-FSM error routes through the same body — into the same slot — from
  /// inside the lending iterator over a disjoint borrow).
  ///
  /// The terminal error goes to `conn_error`, not the bounded `events` queue, so a
  /// fatal path can surface its code even when the queue is saturated (a no-return
  /// path like a duplicate-role [`provide_stream`](Self::provide_stream) or a
  /// critical-stream [`handle_stream_fin`](Self::handle_stream_fin) would otherwise
  /// become `Failed` with no observable `ConnError`).
  /// [`poll_event`](Self::poll_event) delivers it FIRST — the fail transition also
  /// clears the pending event queue, so the terminal `ConnError` is the connection's
  /// only remaining observable event (stale graceful events are discarded).
  ///
  /// A failing connection also cancels any deferred graceful FIN: a `Failed`
  /// connection must not flush a clean close FIN. `close_pending` is cleared
  /// inside [`Phase::fail_into`] (the single definition of this invariant on ALL
  /// fatal paths); [`try_send_fin`](Self::try_send_fin) additionally requires
  /// `Phase::Closing` as belt-and-suspenders. This matters when a local
  /// [`close`](Self::close) deferred its FIN under a full ring and a fatal error
  /// then arrives before the FIN flushed.
  fn fail(&mut self, error: H3Error)
  where
    EventBuf: AsMut<[Option<Event>]>,
  {
    Phase::fail_into(
      &mut self.phase,
      &mut self.close_pending,
      &mut self.events,
      &mut self.conn_error,
      error,
    );
  }

  /// Records a driver-assigned `id` for `role`. The driver calls this for every
  /// stream it opens (after acting on an `OpenUni` / `OpenRequest` transmit) and
  /// for the inbound request stream the peer opens (server side).
  ///
  /// For [`StreamRole::Request`] this inserts a fresh per-stream [`StreamEntry`]
  /// (its recv FSM + lifecycle markers) into the [`StreamStore`] under `id`. Unlike
  /// the critical streams, a request stream is **not** write-once-singular: each new
  /// request `id` gets its own store entry (the multi-stream core). Re-providing the
  /// SAME request `id` re-binds in place (idempotent). At store capacity the insert
  /// is dropped and the overflow stream reset with [`H3Error::RequestRejected`] (a
  /// `RESET_STREAM` transmit) — NOT connection-fatal: the peer learns the request was
  /// rejected while the connection stays live. The FIRST request id also records
  /// `request_id`, the CONNECT tunnel-slot pointer the tunnel send paths use.
  ///
  /// Binding a *critical* (control / QPACK) role stays write-once: each maps to
  /// exactly one stream id for the connection's lifetime. Re-providing the SAME
  /// `(role, id)` is an idempotent no-op; rebinding a critical role to a DIFFERENT
  /// id is a duplicate critical stream (RFC 9114 §6.1 / §6.2.1) — the connection is
  /// `fail`ed (phase → `Failed`) with a terminal
  /// [`Event::ConnError`]`(`[`H3Error::StreamCreation`]`)`, the stored id left
  /// UNCHANGED. (`provide_stream` keeps its `()` signature; the failure is signalled
  /// terminally via the phase and the event.)
  ///
  /// A [`close`](Self::close) before the request stream is bound leaves
  /// `request_id` unbound, so the later FIRST `provide_stream(Request, id)` still
  /// records it — the deferred close FIN then has its target id. By contrast, a
  /// `Failed` connection is terminal, so `provide_stream` is a no-op there: it does
  /// not bind a new id (nothing usable could come of it after the terminal
  /// `ConnError`).
  #[allow(private_bounds)]
  pub fn provide_stream(&mut self, role: StreamRole, id: StreamId)
  where
    EventBuf: AsMut<[Option<Event>]>,
    ReqBuf: ReqBufAlloc,
    TxBuf: AsMut<[u8]>,
  {
    // A `Failed` connection is terminal: registering a new stream id on it serves
    // no purpose and must not happen — the driver should not be opening streams
    // for a connection-fatal core. No-op so a late registration cannot resurrect
    // bookkeeping after the terminal `ConnError`. (`Closing` still binds: a
    // deferred close FIN may target a request stream the driver opens late — see
    // the method docs.)
    if self.phase.is_failed() {
      return;
    }
    // Reconcile any deferred stream-scoped reset FIRST, so a request stream a prior
    // `Frames` carrier condemned is freed before the membership check in
    // `provide_request_stream` below. Otherwise a condemned `id` would read as an
    // idempotent re-provide (kept as-is) while its abort is still queued; reconciling
    // first lets a same-id re-provide register a clean fresh stream instead.
    self.reconcile_pending_resets();
    if role.is_request() {
      // Classify the new request entry's `is_tunnel` (its error scope: RFC 9114
      // §4.1.2 per-stream vs a connection error) by SIDE and connection [`Mode`]:
      //
      // - The CLIENT reaches `provide_stream(Request, …)` only via the CONNECT tunnel
      //   path (`open_with` → `OpenRequest` → the driver registers the minted id here),
      //   so a client stream provided this way IS the tunnel. The general client opens
      //   streams through `open_request` instead, which registers them
      //   `is_tunnel = false` directly. So the client always passes `true` here, and
      //   `self.mode` (a server-side knob, default `Tunnel`) leaves that unchanged.
      // - The SERVER cannot tell tunnel from general from the id alone (it is bound
      //   before any HEADERS), so it uses the connection-level [`Mode`]:
      //   [`Mode::Tunnel`] (the default) ⇒ `is_tunnel = true`, so a protocol violation
      //   before it commits to a response is connection-fatal (strict CONNECT-tunnel
      //   scoping: one tunnel = one connection); [`Mode::General`] ⇒ `is_tunnel = false`,
      //   so a pre-response malformed request resets just that stream and the connection
      //   survives. Either way the general server response path
      //   [`send_response`](Self::send_response) keeps the entry `is_tunnel = false`,
      //   and [`accept_with`](Self::accept_with) keeps it `true` (the established tunnel).
      //
      // This is the connection-level tunnel-mode that resolves the former Phase-0
      // limitation (a general server's PRE-response window mis-scoped the error): a
      // `General`-mode connection now resets a pre-response request error per-stream
      // instead of failing the whole connection. The default stays `Tunnel`, so every
      // CONNECT-tunnel test keeps the connection-fatal behavior unchanged; a general
      // HTTP/3 server opts in via [`set_mode`](Self::set_mode)`(`[`Mode::General`]`)`.
      //
      // The driver provides an INBOUND stream; the core enqueues no HEADERS of its own
      // here (the server responds later via `accept_with` / `send_response`), so a
      // capacity rejection (the overflow stream already reset inside) needs no further
      // action — discard the outcome.
      let _ = self.provide_request_stream(id, self.mode.is_tunnel());
      return;
    }
    // Critical (control / QPACK) streams stay write-once-singular in `roles`.
    if let Some(Some(existing)) = self.roles.get(role.index()) {
      if *existing == id {
        return; // Idempotent: the same (role, id) re-registered is a no-op.
      }
      // The role is already bound to a different id: a duplicate critical stream.
      // Do NOT rebind; fail the connection terminally (exactly once).
      self.fail(H3Error::StreamCreation);
      return;
    }
    if let Some(slot) = self.roles.get_mut(role.index()) {
      *slot = Some(id);
    }
  }

  /// Registers an inbound request stream `id`: inserts a fresh [`StreamEntry`] into
  /// the [`StreamStore`] (seeding the FIRST entry's recv-FSM buffer from the
  /// construction-time `req_seed`, additional entries from `ReqBuf::default()`), and
  /// records the CONNECT tunnel-slot pointer `request_id` the first time. A
  /// re-provided id re-binds in place; an at-capacity insert is dropped and the overflow
  /// stream reset with [`H3Error::RequestRejected`] via
  /// [`enqueue_stream_reset`](Self::enqueue_stream_reset) (not connection-fatal). See
  /// [`provide_stream`](Self::provide_stream).
  ///
  /// Returns the [`RequestRegister`] outcome so a caller that also enqueues request
  /// HEADERS ([`open_request`](Self::open_request)) can tell an accepted/idempotent
  /// registration from a capacity rejection: it MUST NOT enqueue HEADERS on a rejected
  /// (untracked) id (the stream was reset, not opened).
  ///
  /// `is_tunnel` marks the new entry's
  /// [`StreamEntry::is_tunnel`](StreamEntry::is_tunnel): `true` on the CONNECT tunnel
  /// path (the client tunnel, or a server inbound stream while in [`Mode::Tunnel`] —
  /// the client's establish split then picks connection-scoped establishment, and a
  /// protocol error is connection-fatal), `false` for a general client `open_request`
  /// stream or a server inbound stream in [`Mode::General`] (per-stream establishment,
  /// a stream-scoped error reset — RFC 9114 §4.1.2). The caller derives it from the
  /// side and connection [`Mode`] (see [`provide_stream`](Self::provide_stream)). A
  /// re-provide does not change an existing entry's marker.
  #[allow(private_bounds)]
  fn provide_request_stream(&mut self, id: StreamId, is_tunnel: bool) -> RequestRegister
  where
    ReqBuf: ReqBufAlloc,
    TxBuf: AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    // Idempotent re-provide of an already-registered request id: the entry (and its
    // in-flight recv FSM) is kept as-is.
    if self.streams.get(id).is_some() {
      return RequestRegister::Inserted;
    }
    // The CONNECT tunnel preallocates exactly one recv FSM, seeded at construction; the
    // first request id takes that buffer. Additional concurrent streams mint a fresh,
    // CORRECTLY-SIZED accumulator via `ReqBufAlloc::fresh` — NOT `ReqBuf::default()`,
    // whose `Vec` value is empty (zero capacity) and would reject the second stream's
    // first HEADERS with `FrameError`. (A borrowed-buffer connection's `fresh` is an
    // empty slice, so it supports only the seeded tunnel stream — bare multi-stream
    // buffering is a later task.)
    let buf = self.req_seed.take().unwrap_or_else(ReqBuf::fresh);
    // Seed the send half-FSM by role: a CLIENT registers a stream only when it has
    // already enqueued the request HEADERS (`open_request` / `open_with`), so it starts
    // in `RequestSent` (request body may follow); an inbound SERVER request stream has
    // sent no response yet, so it starts in `Idle` (body gated until the final response).
    let send = if Ro::IS_CLIENT {
      SendState::RequestSent
    } else {
      SendState::Idle
    };
    let entry = StreamEntry::new(Stream::with_buffer(buf), is_tunnel, send);
    if self.streams.insert(id, entry).is_err() {
      // At store capacity: drop the overflow stream and reset it with
      // `H3_REQUEST_REJECTED` so the peer learns the request was not accepted (and may
      // retry it). The entry was never inserted, so `reset_stream`'s `streams.remove`
      // would no-op — record the abort directly via `enqueue_stream_reset`, which puts it
      // in the dedicated reset channel (purge is a no-op: an uninserted id has no queued
      // DATA). `poll_transmit` emits it FIRST and unconditionally — never byte-ring-gated,
      // so it is delivered even under a full ring (RFC 9114 §4.1 — `H3_REQUEST_REJECTED`
      // lets the peer safely retry). NOT connection-fatal; the driver also bounds
      // concurrency via QUIC `MAX_STREAMS`.
      self.enqueue_stream_reset(id, H3Error::RequestRejected.code());
      return RequestRegister::Rejected;
    }
    // The first registered request id names the single CONNECT tunnel slot.
    if self.request_id.is_none() {
      self.request_id = Some(id);
    }
    RequestRegister::Inserted
  }

  /// Resets request stream `id` with application error `code`: records the abort in the
  /// dedicated reset channel (the SOLE source of `RESET_STREAM` — a QUIC `RESET_STREAM`
  /// carrying no bytes, the driver issues `reset_stream(id, code)` on QUIC), purges the
  /// stream's already-queued DATA/FIN from the transmit ring, frees the stream's
  /// [`StreamStore`] slot, and leaves the connection and every OTHER stream live. This
  /// is the stream-scoped counterpart to the connection-fatal `fail` transition: the
  /// connection `phase` is unchanged (it stays `Open` / `Handshaking` / `Closing`) and
  /// no [`Event::ConnError`] is enqueued.
  ///
  /// Used for stream-scoped errors on a GENERAL (non-tunnel) request stream — a
  /// malformed message / validator violation / premature DATA (RFC 9114 §4.1.2) — and
  /// as the driver-requested per-stream cancel. A fatal on the CONNECT **tunnel** stream
  /// is connection-fatal instead (one tunnel = one connection), failing the whole
  /// connection rather than resetting here.
  ///
  /// A no-op if `id` is not a tracked request stream or the connection is already
  /// `Failed` (a reset is moot then, and a stale `RESET_STREAM` must not follow the
  /// terminal `ConnError`). If `id` was the tunnel-slot pointer (`request_id`) it is
  /// cleared.
  ///
  /// EXACTLY-ONCE (RFC 9114 §4.1.2 — at most one `RESET_STREAM` per stream): a
  /// carrier-recorded reset for `id` is reconciled FIRST (its slot freed + DATA purged),
  /// so a stream a `Frames` carrier already condemned is gone from `streams` before the
  /// membership check below. As a second guard, an `id` already in the reset channel is
  /// left to that recorded abort — the FIRST code wins; this call does not record a
  /// second with a possibly-different `code`.
  #[allow(private_bounds)]
  pub fn reset_stream(&mut self, id: StreamId, code: u64)
  where
    TxBuf: AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    if self.phase.is_failed() {
      return;
    }
    // Reconcile any deferred reset for `id` (and every other condemned stream) before
    // touching `streams`: a carrier reset's slot bookkeeping runs here (entry removed,
    // DATA purged) while its abort stays recorded in the channel, so the `remove` below
    // sees `id` as already gone.
    self.reconcile_pending_resets();
    // A reset for `id` already recorded already owns this stream's single abort — do not
    // record a duplicate with a different code (first code wins).
    if self.pending_resets.contains(id) {
      return;
    }
    if self.streams.remove(id).is_some() {
      if self.request_id == Some(id) {
        self.request_id = None;
      }
      self.enqueue_stream_reset(id, code);
    }
  }

  /// Records `id`'s abort into the dedicated reset channel and purges the stream's
  /// already-queued ordinary transmits ([`Existing(id)`](StreamKind::Existing) DATA/FIN,
  /// freeing held bodies) from the byte [`TxRing`], so no stale same-stream transmit is
  /// ever yielded once the stream is reset (RFC 9114 §4.1.2). The abort itself is emitted
  /// LATER, directly from the channel by [`poll_transmit`](Self::poll_transmit) — never
  /// from the byte ring — so it can never be ring-slot-gated, dropped, or stranded behind
  /// a held front transmit. The purge is therefore DECOUPLED from the abort: it only
  /// drops stale DATA and neither gates nor is gated by emission.
  ///
  /// Requires NO existing [`StreamStore`] entry — the capacity backstop's at-capacity
  /// stream was never inserted, yet must still be reset on the wire (RFC 9114 §4.1 —
  /// `H3_REQUEST_REJECTED` lets the peer retry); its purge is a harmless no-op (an
  /// uninserted id queued no DATA). Callers do their own slot bookkeeping first (free the
  /// entry, clear `request_id`). A no-op when already `Failed` (a reset is moot — a stale
  /// `RESET_STREAM` must not follow the terminal `ConnError`). Recording is deduped by id
  /// (FIRST code wins); a full channel is pathological (`RESET_CAP` distinct undrained
  /// resets), so the connection fails closed ([`H3Error::ExcessiveLoad`]) rather than
  /// silently dropping the abort.
  fn enqueue_stream_reset(&mut self, id: StreamId, code: u64)
  where
    TxBuf: AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    if self.phase.is_failed() {
      return;
    }
    // Purge the stream's queued DATA/FIN so `poll` never yields stale same-stream bytes;
    // decoupled from the abort, which emits from the channel below.
    self.tx.purge_stream(id);
    if !self.pending_resets.record(id, code) {
      self.fail(H3Error::ExcessiveLoad);
    }
  }

  /// Reconciles the dedicated reset channel against `streams` / the transmit ring,
  /// idempotently, WITHOUT emitting (or removing) any abort. For every recorded reset it
  /// frees the [`StreamStore`] slot (clearing the tunnel-slot pointer `request_id` if it
  /// matched) and purges the stream's already-queued DATA/FIN from the ring. The recorded
  /// aborts stay in the channel; [`poll_transmit`](Self::poll_transmit) emits them.
  ///
  /// Run at the head of every `&mut self` entry that can observe the effect —
  /// [`handle_stream`](Self::handle_stream), [`poll_transmit`](Self::poll_transmit), the
  /// send guards — so a stream the lending [`Frames`] carrier condemned (it holds only
  /// disjoint per-entry borrows, not `streams` / `tx`, so it could only record the abort)
  /// reads as GONE before the driver looks: `send_data_on` / `send_response` on it are
  /// rejected, and no stale same-stream DATA precedes the abort. Idempotent — `remove`
  /// no-ops on an already-freed slot and re-purging already-tombstoned slots is harmless —
  /// so running it on every entry is safe. (`poll_event` does not call it: a stream reset
  /// produces no `Event`.)
  fn reconcile_pending_resets(&mut self)
  where
    TxBuf: AsMut<[u8]>,
  {
    // Snapshot the ids first so the per-id `&mut self` store / ring calls below do not
    // hold a borrow of `pending_resets`. At most `RESET_CAP` ids; the aborts stay
    // recorded for `poll_transmit` to emit.
    for id in self.pending_resets.ids().into_iter().flatten() {
      // Free the slot (idempotent) so a condemned stream's id reads as gone at the send
      // guards, and clear the tunnel-slot pointer if this was it. The carrier could not
      // do this in place; the capacity backstop already did (its stream was never
      // inserted), so this no-ops there.
      if self.streams.remove(id).is_some() && self.request_id == Some(id) {
        self.request_id = None;
      }
      // Drop the stream's queued DATA/FIN so `poll` never yields stale same-stream bytes
      // ahead of (or after) the abort. Decoupled from emission — purging here does not
      // gate the abort, which `poll_transmit` emits from the channel regardless.
      self.tx.purge_stream(id);
    }
  }

  /// Routes an eager request-stream error by SCOPE — the `&mut self` twin of the
  /// lending carrier's [`RequestFrames::fail_or_reset`], shared by the request-stream
  /// FIN branches of [`handle_stream_fin`](Self::handle_stream_fin):
  ///
  /// - the CONNECT **tunnel** (`is_tunnel`): connection-fatal via [`fail`](Self::fail)
  ///   (one tunnel = one connection);
  /// - a **general** request stream: a stream-scoped [`reset_stream`](Self::reset_stream)
  ///   with the error's [`code`](H3Error::code) (free the slot + enqueue `RESET_STREAM`,
  ///   RFC 9114 §4.1.2), leaving the connection live.
  fn fail_or_reset_stream(&mut self, id: StreamId, is_tunnel: bool, error: H3Error)
  where
    EventBuf: AsMut<[Option<Event>]>,
    TxBuf: AsMut<[u8]>,
  {
    if is_tunnel {
      self.fail(error);
    } else {
      self.reset_stream(id, error.code());
    }
  }

  /// The control-and-SETTINGS transmit plus the two idle QPACK uni streams.
  /// Shared by [`start`](Self::start) on both roles.
  ///
  /// All-or-nothing: the three setup transmits go in together or not at all. The
  /// ring is preflighted for three free slots BEFORE the first enqueue, so a ring
  /// without room returns [`Error::WouldBlock`] having enqueued NOTHING. This is
  /// what keeps the `Created → Handshaking` transition transactional — without it,
  /// enqueueing 1–2 transmits and then hitting a full ring would leave the phase
  /// `Created`, and a retry would emit a SECOND (partial) setup sequence, opening
  /// duplicate critical streams the peer rejects with `H3_STREAM_CREATION_ERROR`.
  /// The three enqueues below therefore cannot individually fail on a full ring.
  fn enqueue_setup(&mut self) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    const SETUP_TRANSMITS: usize = 3;
    if !self.tx.has_capacity_mut(SETUP_TRANSMITS) {
      return Err(Error::WouldBlock);
    }
    let settings = self.settings_local;
    // Control stream: type byte 0x00, then a SETTINGS frame.
    self
      .tx
      .enqueue(StreamKind::OpenUni(StreamRole::ControlOut), false, |out| {
        write_control_settings(out, &settings)
      })
      .map_err(map_tx)?;
    // QPACK encoder stream: just the type byte (then idle).
    self
      .tx
      .enqueue(StreamKind::OpenUni(StreamRole::QpackEncOut), false, |out| {
        write_type_byte(out, STREAM_TYPE_QPACK_ENC)
      })
      .map_err(map_tx)?;
    // QPACK decoder stream: just the type byte (then idle).
    self
      .tx
      .enqueue(StreamKind::OpenUni(StreamRole::QpackDecOut), false, |out| {
        write_type_byte(out, STREAM_TYPE_QPACK_DEC)
      })
      .map_err(map_tx)?;
    Ok(())
  }

  /// Feeds the peer's control-stream bytes through the continuous frame parser
  /// (RFC 9114 §6.2.1 / §7.2). The first frame must be SETTINGS; afterwards the
  /// placement policy is role-aware (see [`ControlState`]): DATA / HEADERS /
  /// PUSH_PROMISE / an HTTP/2-reserved type / a second SETTINGS are protocol
  /// violations, CANCEL_PUSH is [`H3Error::IdError`], a client rejects MAX_PUSH_ID
  /// (a server skips it), and GOAWAY / GREASE / unknown frames are skipped. When
  /// the first SETTINGS frame completes its payload is decoded and stored; the
  /// client then observes [`peer_settings`](Self::peer_settings) becoming `Some`
  /// and calls [`open_with`](Self::open_with) to send its CONNECT request.
  fn handle_control(&mut self, bytes: &[u8]) -> Result<(), H3Error>
  where
    CtrlBuf: AsMut<[u8]>,
  {
    if let Some(settings) = self.ctrl.feed(Ro::IS_CLIENT, bytes)? {
      self.settings_peer = Some(settings);
    }
    Ok(())
  }

  /// Drives the inbound request stream FSM with `bytes`, returning a lending
  /// frame iterator. The client tunnel is established (phase `Handshaking → Open`,
  /// with [`Event::Established`] enqueued) when the iterator actually yields its
  /// first response HEADERS — not on entry — so a split or partial response cannot
  /// flip it a round early; see [`RequestFrames::establish_on_response`]. A lazy
  /// fatal error surfaced while draining the iterator routes through
  /// [`Phase::fail_into`] (see [`Frames::next`]).
  fn handle_request<'a>(
    &'a mut self,
    id: StreamId,
    bytes: &'a [u8],
    scratch: &'a mut [u8],
  ) -> Result<Frames<'a, 'req, 'event, ReqBuf, EventBuf>, H3Error>
  where
    ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    let is_client = Ro::IS_CLIENT;
    // Decide the role-specific first-HEADERS readiness side effects before the request FSM
    // is borrowed: the client arms the establish on its first FINAL response; the server
    // flips the tunnel entry's `observed` (the `Frame::Request` yield is itself the gate
    // `accept_with` waits on). Each role arms exactly one. Both fire ONLY when
    // `Frames::next` yields the first HEADERS (the observation point), never from the
    // drop-drain.
    //
    // The client arms it for EVERY request stream, INDEPENDENT of the connection phase —
    // per-stream establishment is decoupled from connection-level establishment. The split
    // in `Frames::next` keeps them apart: the CONNECT TUNNEL'S final response runs the
    // connection-scoped `Phase::establish_into` (gated INTERNALLY on `Handshaking`, so a
    // response after a close / failure does not re-establish) AND sets the per-stream flag;
    // a GENERAL stream's final response sets ONLY its per-stream `established` flag, in ANY
    // phase. So a general client stream opened via `open_request` AFTER a CONNECT tunnel
    // moved the connection to `Open` still establishes per-stream (gating `Frame::Data`),
    // even though the connection is no longer `Handshaking`. (Evaluated here because the
    // transition fires from inside the lending iterator over a disjoint borrow.)
    let establish_on_response = is_client;
    let observed = self.streams.get(id).is_some_and(|e| e.observed);
    let needs_request = !is_client && !observed;
    Ok(Frames {
      inner: self.build_request_frames(id, bytes, scratch, establish_on_response, needs_request),
    })
  }

  /// Builds the [`RequestFrames`] carrier for the tunnel stream `id`, shared by the
  /// live drain ([`handle_request`](Self::handle_request)) and the abandoned
  /// validation-only drain ([`drain_request_abandoned`](Self::drain_request_abandoned)).
  /// Returns `None` if `id` has no [`StreamEntry`] (the caller then hands the driver
  /// an empty [`Frames`]).
  ///
  /// The per-stream subset of the carrier's disjoint borrows now lives in ONE
  /// `StreamEntry`: the recv FSM the iterator drives plus its `abandoned` /
  /// `established` / `observed` markers. We destructure `self` into disjoint field
  /// borrows, look the entry up in `streams` (one field), and split the entry — so the
  /// FSM borrow and the entry-marker borrows are distinct from the connection-shared
  /// `phase` / `events` / `close_pending` / `conn_error` borrows. The server's
  /// `on_first_request` is the conditional `&mut entry.observed` borrow, which an
  /// `Option<&mut bool>` PARAMETER could not express (the caller would have to borrow
  /// that field while also passing `&mut self`); passing `needs_request` /
  /// `establish_on_response` as plain `bool`s keeps every field borrow inside this split.
  ///
  /// `establish_on_response` arms the client's `Handshaking → Open` establish on the
  /// first OBSERVED response (`false` on the server / abandoned path); `needs_request`
  /// arms the server's `observed` flip on the first OBSERVED request (the abandoned path
  /// passes `false` so neither carrier is armed). Both fire only from a real
  /// [`Frames::next`] yield — never from the drop-drain.
  fn build_request_frames<'a>(
    &'a mut self,
    id: StreamId,
    bytes: &'a [u8],
    scratch: &'a mut [u8],
    establish_on_response: bool,
    needs_request: bool,
  ) -> Option<RequestFrames<'a, 'req, 'event, ReqBuf, EventBuf>>
  where
    ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    let is_client = Ro::IS_CLIENT;
    // Destructure `self` into disjoint field borrows: the per-stream FSM + markers come
    // from the looked-up entry in `streams` (one field), the rest are distinct
    // connection-shared fields, so all the carrier's borrows are disjoint.
    let Self {
      streams,
      phase,
      events,
      close_pending,
      conn_error,
      pending_resets,
      ..
    } = self;
    let entry = streams.get_mut(id)?;
    // Read whether a HEADERS section already completed BEFORE the FSM is moved into the
    // carrier (an immutable read that ends before the `&mut entry.fsm` split below), so
    // the second-HEADERS guard works across `handle_stream` calls too.
    let first_headers_seen = entry.fsm.headers_seen();
    // Copy the tunnel marker out before the FSM borrow splits the entry: the client's
    // establish split in `Frames::next` reads it to pick connection-scoped (tunnel) vs
    // per-stream (general) establishment.
    let is_tunnel = entry.is_tunnel;
    let request_abandoned = &mut entry.abandoned;
    let tunnel_established = &mut entry.established;
    let final_response_seen = &mut entry.final_response_seen;
    let observed = &mut entry.observed;
    let on_first_request = needs_request.then_some(observed);
    let items = entry.fsm.handle(bytes, scratch);
    Some(RequestFrames {
      drain_on_drop: RequestFrames::<ReqBuf, EventBuf>::drain_for_errors,
      items,
      id,
      phase,
      events,
      close_pending,
      conn_error,
      pending_resets,
      request_abandoned,
      is_client,
      establish_on_response,
      is_tunnel,
      on_first_request,
      tunnel_established,
      final_response_seen,
      first_headers_seen,
    })
  }

  /// Drives later request-stream `bytes` through the VALIDATION-ONLY path on an
  /// already-abandoned (dropped-unobserved) request stream, surfacing nothing. An
  /// abandoned stream is inert to the driver but not terminal, so it may not bypass the
  /// FSM/gate (see the observation-gating section on [`Connection`]).
  ///
  /// The peer can still commit protocol violations on it, and every one must still fail
  /// the connection: this builds the same [`RequestFrames`] over
  /// `fsm.handle(bytes, scratch)` as the normal path (the same disjoint borrows) and
  /// runs [`drain_for_errors`](RequestFrames::drain_for_errors), which applies the
  /// premature-DATA establishment gate (the tunnel was never established, so any DATA is
  /// `H3Error::MessageError`, RFC 9114 §4.4), fails on an FSM `Err` (a forbidden /
  /// second-HEADERS frame, malformed framing), and grants NO readiness and yields NO
  /// items. The built iterator is then dropped, so the caller hands the driver an
  /// empty [`Frames`]. The gate logic is reused, never duplicated.
  fn drain_request_abandoned(&mut self, id: StreamId, bytes: &[u8], scratch: &mut [u8])
  where
    ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    // An abandoned stream grants no readiness on validation, so neither carrier is
    // armed: `establish_on_response = false` and `needs_request = false` (so
    // `on_first_request` is `None`). The drain ignores them regardless (it never runs
    // `on_headers_decoded`), but keeping them inert documents that this path advances
    // nothing the driver observes. The carrier is then driven for errors and dropped.
    if let Some(mut rf) = self.build_request_frames(id, bytes, scratch, false, false) {
      rf.drain_for_errors();
    }
  }

  /// Handles bytes on a QPACK encoder/decoder stream: the type byte is consumed at
  /// registration, so any further bytes are encoder/decoder instructions. We
  /// advertise `QPACK_MAX_TABLE_CAPACITY=0` (the dynamic table is disabled, RFC
  /// 9204 §4.2), so almost every instruction is a protocol error with a
  /// stream-specific code (RFC 9204 §6): encoder-stream instructions are
  /// [`H3Error::QpackEncoderStreamError`] (`0x0201`), decoder-stream instructions
  /// [`H3Error::QpackDecoderStreamError`] (`0x0202`) — both distinct from the
  /// field-section-decode `QPACK_DECOMPRESSION_FAILED`.
  ///
  /// The sole exception, on the peer's ENCODER stream, is "Set Dynamic Table
  /// Capacity" with value 0: it sets the capacity to 0, which is legal even when
  /// our advertised maximum is 0 (a no-op within the maximum). That instruction is
  /// the single byte `0x20` (pattern `001` + a 5-bit prefixed integer whose value
  /// 0 fits the prefix, so there is no continuation), so it needs no further
  /// parsing: a `0x20` byte is skipped, and any other encoder-stream byte — Set
  /// Capacity with value > 0, Insert With Name Reference (`1xxxxxxx`), Insert With
  /// Literal Name (`01xxxxxx`), or Duplicate (`000xxxxx`) — requires the dynamic
  /// table and is rejected.
  ///
  /// The DECODER stream has no such exception: a static-only encoder never
  /// references the dynamic table, so the peer's decoder stream is idle and even
  /// Insert Count Increment(0) is itself illegal — any byte is an error.
  fn handle_qpack(role: StreamRole, bytes: &[u8]) -> Result<(), H3Error> {
    match role {
      StreamRole::QpackEncIn | StreamRole::QpackEncOut => {
        // Set Dynamic Table Capacity(0) == the single byte 0x20 is the only legal
        // static-mode instruction; accept (skip) it, reject everything else.
        if bytes.iter().all(|&b| b == 0x20) {
          Ok(())
        } else {
          Err(H3Error::QpackEncoderStreamError)
        }
      }
      _ => {
        if bytes.is_empty() {
          Ok(())
        } else {
          Err(H3Error::QpackDecoderStreamError)
        }
      }
    }
  }

  /// Classifies an inbound uni stream by its leading type varint, buffering the
  /// partial varint across calls (in its slot) if it is split. Returns the
  /// classified [`UniRole`] and the offset of the bytes following the type varint
  /// once known, or `None` if more bytes are needed (the partial is retained in
  /// the slot against `id`).
  ///
  /// `id`'s slot in the bounded `uni` table is reserved on first sight as
  /// [`UniState::Pending`] (so an unclassified stream is accounted in the SAME
  /// table); reserving it for a new id when the table is full is
  /// [`H3Error::ExcessiveLoad`]. On completion the slot transitions to
  /// [`UniState::Classified`] (a critical role is also checked for duplication).
  fn classify_uni(
    &mut self,
    id: StreamId,
    bytes: &[u8],
  ) -> Result<Option<(UniRole, usize)>, H3Error>
  where
    UniBuf: AsMut<[UniSlot]>,
  {
    let slot_idx = self.uni_slot(id)?;
    let mut consumed = 0usize;
    loop {
      let (buf, len) = self.pending_buf(slot_idx)?;
      match varint::decode(buf.get(..len).unwrap_or(&[])) {
        Ok((_, ty)) => {
          let role = self.classify_pending(slot_idx, id, ty)?;
          return Ok(Some((role, consumed)));
        }
        Err(varint::VarintError::Truncated(_)) => {}
        Err(_) => return Err(H3Error::FrameError),
      }
      let Some(&b) = bytes.get(consumed) else {
        // Ran out of input mid-varint; keep the partial for the next call.
        return Ok(None);
      };
      consumed = consumed.saturating_add(1);
      self.push_pending_byte(slot_idx, b)?;
    }
  }

  /// The index of `id`'s slot in the `uni` table, reserving a free slot as a
  /// fresh [`UniState::Pending`] on first sight. A full table when a NEW id must
  /// be reserved is [`H3Error::ExcessiveLoad`] (consistent with the
  /// classified-overflow behavior), so a flood of partial / GREASE streams cannot
  /// hide a later critical stream.
  fn uni_slot(&mut self, id: StreamId) -> Result<usize, H3Error>
  where
    UniBuf: AsMut<[UniSlot]>,
  {
    let slots = self.uni.as_mut();
    if let Some(i) = slots
      .iter()
      .position(|s| matches!(s.entry, Some(e) if e.id == id))
    {
      return Ok(i);
    }
    let i = slots
      .iter()
      .position(|s| s.entry.is_none())
      .ok_or(H3Error::ExcessiveLoad)?;
    if let Some(slot) = slots.get_mut(i) {
      slot.entry = Some(UniEntry {
        id,
        state: UniState::Pending {
          buf: [0u8; 8],
          len: 0,
        },
      });
    }
    Ok(i)
  }

  /// The partial type-varint bytes buffered in slot `slot_idx`. The slot must be
  /// [`UniState::Pending`]; reaching a classified (or empty) slot here is an
  /// internal inconsistency surfaced as `H3_STREAM_CREATION_ERROR` rather than a
  /// panic.
  fn pending_buf(&mut self, slot_idx: usize) -> Result<([u8; 8], usize), H3Error>
  where
    UniBuf: AsMut<[UniSlot]>,
  {
    match self
      .uni
      .as_mut()
      .get_mut(slot_idx)
      .and_then(|s| s.entry.as_ref())
    {
      Some(UniEntry {
        state: UniState::Pending { buf, len },
        ..
      }) => Ok((*buf, *len)),
      _ => Err(H3Error::StreamCreation),
    }
  }

  /// Appends one byte to the partial type-varint buffer in slot `slot_idx`. A
  /// varint exceeding 8 bytes is malformed ([`H3Error::FrameError`]).
  fn push_pending_byte(&mut self, slot_idx: usize, b: u8) -> Result<(), H3Error>
  where
    UniBuf: AsMut<[UniSlot]>,
  {
    match self
      .uni
      .as_mut()
      .get_mut(slot_idx)
      .and_then(|s| s.entry.as_mut())
    {
      Some(UniEntry {
        state: UniState::Pending { buf, len },
        ..
      }) => {
        let dst = buf.get_mut(*len).ok_or(H3Error::FrameError)?;
        *dst = b;
        *len = len.saturating_add(1);
        Ok(())
      }
      _ => Err(H3Error::StreamCreation),
    }
  }

  /// Transitions slot `slot_idx` from [`UniState::Pending`] to
  /// [`UniState::Classified`], returning the role.
  ///
  /// A second control/QPACK stream of a kind already classified under a
  /// *different* id is `H3_STREAM_CREATION_ERROR` (RFC 9114 §6.2.1 / RFC 9204
  /// §4.2). The slot was already reserved while pending, so no capacity check is
  /// needed here.
  fn classify_pending(&mut self, slot_idx: usize, id: StreamId, ty: u64) -> Result<UniRole, H3Error>
  where
    UniBuf: AsMut<[UniSlot]>,
  {
    let role = classify_stream_type(ty)?;
    let slots = self.uni.as_mut();
    // A duplicate critical stream (same role, classified under a different id) is
    // a creation error. Pending slots carry no role yet, so they never match.
    if role != UniRole::Ignored
      && slots
        .iter()
        .filter_map(|s| s.entry.as_ref())
        .any(|e| e.id != id && matches!(e.state, UniState::Classified(r) if r == role))
    {
      return Err(H3Error::StreamCreation);
    }
    if let Some(slot) = slots.get_mut(slot_idx) {
      slot.entry = Some(UniEntry {
        id,
        state: UniState::Classified(role),
      });
    }
    Ok(role)
  }

  /// The classified [`UniRole`] of inbound uni stream `id`, if it is tracked AND
  /// already classified. A still-`Pending` stream returns `None` (its bytes flow
  /// back into [`classify_uni`] to continue the type varint), so its continuation
  /// is never routed to a handler before its type is known.
  fn uni_role_of(&self, id: StreamId) -> Option<UniRole>
  where
    UniBuf: AsRef<[UniSlot]>,
  {
    self
      .uni
      .as_ref()
      .iter()
      .filter_map(|s| s.entry.as_ref())
      .find(|e| e.id == id)
      .and_then(|e| match e.state {
        UniState::Classified(role) => Some(role),
        UniState::Pending { .. } => None,
      })
  }

  /// The role a registered (outbound or request) `id` currently plays, if any.
  /// Inbound uni streams are tracked in `uni`, not here; see [`uni_role_of`].
  ///
  /// [`uni_role_of`]: Self::uni_role_of
  fn role_of(&self, id: StreamId) -> Option<StreamRole> {
    self
      .roles
      .iter()
      .position(|s| matches!(s, Some(rid) if *rid == id))
      .and_then(role_from_index)
  }

  /// Routes inbound `bytes` on stream `id` to the right handler.
  ///
  /// - The request stream yields decoded [`Frame`]s. Drain the returned [`Frames`]
  ///   to receive all tunnel DATA in this call; ALL supplied request-stream bytes
  ///   are validated regardless (see the terminal-error note below), but unread
  ///   tunnel DATA in a call whose iterator is dropped early is discarded.
  /// - The peer control stream's SETTINGS frame is parsed and stored.
  /// - QPACK streams must stay idle past their type byte.
  /// - An unknown id is treated as a new inbound uni stream: its leading type
  ///   varint is parsed (buffered across calls if split) and classified into the
  ///   bounded `uni` table. A GREASE / unknown type is recorded as `Ignored` and
  ///   its bytes discarded; a push stream (type 0x01) is [`H3Error::IdError`]
  ///   (server push is never enabled); a full table is
  ///   [`H3Error::ExcessiveLoad`].
  ///
  /// `scratch` is transient Huffman-decode space for the request stream's HEADERS
  /// decode (see [`Stream::handle`]): an in-progress field section is
  /// buffered inside the request FSM, so `scratch` need NOT be preserved across
  /// calls — it may be a fresh buffer each call. It must outlive the returned
  /// [`Frames`] (and so shares its lifetime) and be large enough for the longest
  /// single decoded field line's name+value.
  ///
  /// Returns an [`H3Error`] on a connection-fatal protocol violation; the driver
  /// closes the QUIC connection with [`H3Error::code`]. Every connection-fatal
  /// inbound error ALSO drives the connection's centralized fail transition before
  /// it is returned — the eager non-request and no-FSM errors here, and the lazy
  /// request-FSM errors inside [`Frames::next`] — so the connection becomes
  /// terminal (a subsequent [`send_data`](Self::send_data) /
  /// [`open_with`](Connection::open_with) / [`accept_with`](Connection::accept_with)
  /// reports [`Error::Closed`]) and exactly one [`Event::ConnError`] is enqueued.
  /// The driver still learns the error code from the returned `Err`.
  ///
  /// Once the connection is `Failed` (terminal), this is a no-op for EVERY stream:
  /// it returns an empty [`Frames`] without processing the bytes. The terminal
  /// [`Event::ConnError`] is the connection's last observable signal, so no inbound
  /// frame — application DATA, a peer HEADERS, a control-stream frame — may be
  /// processed or yielded after a connection-fatal error and ahead of that
  /// `ConnError`. `Closing` is NOT short-circuited: a gracefully-closing connection
  /// keeps processing inbound DATA (the peer's half stays open until it FINs).
  ///
  /// EVERY byte supplied here for the request stream is validated even if the
  /// returned [`Frames`] is not fully drained: dropping it after pulling only some
  /// frames (or none) drives the request FSM over the remaining input purely to
  /// detect a protocol error (discarding any unread tunnel DATA in that call), and
  /// routes any such error through the same fail transition. So a peer cannot smuggle
  /// a forbidden frame (a second HEADERS, PUSH_PROMISE, DATA before HEADERS, …) past
  /// an early-stopping driver and leave the connection non-terminal — but a driver
  /// that wants the tunnel DATA must drain.
  ///
  /// Validation is NOT observation: dropping [`Frames`] checks the bytes but advances
  /// no readiness, so the driver must pull the request / response via [`Frames::next`]
  /// before accepting or using the tunnel. See the observation-gating section on
  /// [`Connection`].
  pub fn handle_stream<'a>(
    &'a mut self,
    id: StreamId,
    bytes: &'a [u8],
    scratch: &'a mut [u8],
  ) -> Result<Frames<'a, 'req, 'event, ReqBuf, EventBuf>, H3Error>
  where
    ReqBuf: AsRef<[u8]> + AsMut<[u8]>,
    CtrlBuf: AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
    TxBuf: AsMut<[u8]>,
    UniBuf: AsRef<[UniSlot]> + AsMut<[UniSlot]>,
  {
    // Materialize a stream-scoped reset a prior `Frames` carrier deferred (free the
    // slot + enqueue the `RESET_STREAM`) before routing these bytes, so a reset stream
    // is already gone — new bytes on it then read as a fresh/unknown id, never the
    // half-reset entry.
    self.reconcile_pending_resets();
    // A `Failed` connection is terminal: it must neither process nor yield any
    // inbound bytes, on ANY stream (request, control, QPACK, uni). The terminal
    // `ConnError` is the last observable signal — surfacing application DATA (or
    // any other frame) after a connection-fatal error, and before that `ConnError`
    // is polled, would break the terminal ordering. So short-circuit to an empty,
    // no-op iterator. This is NOT done for `Closing`: after a local graceful
    // `close()` the peer may still legitimately send on its half until it FINs, so
    // `Closing` keeps processing inbound DATA (and a forbidden frame received while
    // `Closing` still supersedes the close — see `drain_for_errors`).
    if self.phase.is_failed() {
      return Ok(Frames::empty());
    }
    // Non-request streams (any id NOT in the stream store) are fully processed here
    // (mutating connection state) and yield no frames; their eager errors carry no
    // escaping borrow, so route them through `fail` and return empty/`Err` here. A
    // request stream is keyed in `streams`, so store membership — not a single
    // `request_id` — selects the request path (the multi-stream router).
    if self.streams.get(id).is_none() {
      return match self.handle_non_request(id, bytes) {
        Ok(()) => Ok(Frames::empty()),
        Err(e) => {
          self.fail(e);
          Err(e)
        }
      };
    }
    // The request stream was abandoned: a prior `handle_stream` decoded its first
    // HEADERS on the drop-drain WITHOUT the driver ever observing it, which advanced
    // the inbound FSM into its tunnel phase as a side effect. The HEADERS bytes are
    // gone, so the stream can never be OBSERVED again and is permanently inert — the
    // driver will never establish this tunnel (it never saw the CONNECT request /
    // response). But abandonment is NOT terminal: only a `Failed` connection (handled
    // above) may bypass the FSM/gate entirely. A non-terminal abandoned stream must
    // STILL drive the new bytes through validation to catch the peer's protocol
    // violations — premature DATA (the tunnel was never established) is `MessageError`,
    // a forbidden / second-HEADERS frame is its FSM error, malformed framing fails too.
    // So run the VALIDATION-ONLY path (`drain_for_errors`, the same DATA gate as
    // `Frames::next` but granting no readiness and surfacing no items), then return an
    // empty/inert iterator: the abandoned stream never surfaces tunnel data, yet the
    // peer can no longer smuggle a §4.4 violation past the gate. A clean (violation-
    // free) read leaves the connection non-terminal (abandonment itself is not a fault).
    if self.streams.get(id).is_some_and(|e| e.abandoned) {
      self.drain_request_abandoned(id, bytes, scratch);
      return Ok(Frames::empty());
    }
    // The request stream. Lazy FSM errors route through `fail` from `Frames::next`.
    self.handle_request(id, bytes, scratch)
  }

  /// Processes inbound `bytes` on a NON-request stream `id` (the caller has already
  /// established `id != request_id`), mutating connection state and producing no
  /// frames. A connection-fatal violation is returned as an [`H3Error`]; the
  /// caller ([`handle_stream`](Self::handle_stream)) routes it through
  /// [`fail`](Self::fail). Split out so the eager error path holds no escaping
  /// borrow.
  fn handle_non_request(&mut self, id: StreamId, bytes: &[u8]) -> Result<(), H3Error>
  where
    CtrlBuf: AsMut<[u8]>,
    UniBuf: AsRef<[UniSlot]> + AsMut<[UniSlot]>,
  {
    // An already-tracked inbound uni stream: route by its recorded role. A
    // critical role goes to its handler; an `Ignored` id is discarded *by lookup*
    // (its `stream_role()` is `None`), so its payload is never reparsed as a
    // stream type. This covers continuation bytes for every kind.
    if let Some(role) = self.uni_role_of(id) {
      if let Some(sr) = role.stream_role() {
        self.dispatch_registered(sr, bytes)?;
      }
      return Ok(());
    }
    // A stream *we* opened (outbound uni / request) that the driver delivers bytes
    // on. The request id is handled by the caller; outbound uni streams are
    // write-only, so this is defensive.
    if let Some(role) = self.role_of(id) {
      self.dispatch_registered(role, bytes)?;
      return Ok(());
    }
    // A brand-new inbound uni stream: classify its leading type varint (buffered
    // across calls if split) and record it in the bounded table.
    match self.classify_uni(id, bytes)? {
      None => Ok(()), // varint not yet complete
      Some((UniRole::Ignored, _)) => Ok(()),
      Some((role, offset)) => {
        let rest = bytes.get(offset..).unwrap_or(&[]);
        if let Some(sr) = role.stream_role() {
          self.dispatch_registered(sr, rest)?;
        }
        Ok(())
      }
    }
  }

  /// Routes a registered non-request stream by role. Produces no frames.
  fn dispatch_registered(&mut self, role: StreamRole, bytes: &[u8]) -> Result<(), H3Error>
  where
    CtrlBuf: AsMut<[u8]>,
  {
    match role {
      StreamRole::ControlIn | StreamRole::ControlOut => self.handle_control(bytes),
      StreamRole::QpackEncIn
      | StreamRole::QpackDecIn
      | StreamRole::QpackEncOut
      | StreamRole::QpackDecOut => Self::handle_qpack(role, bytes),
      // A registered request id is handled before role lookup; reaching here for
      // Request means the role table and request id diverged, which is a protocol
      // error from the caller's stream registration sequence.
      StreamRole::Request => Err(H3Error::FrameUnexpected),
    }
  }

  /// Sends a chunk of tunnel payload as an HTTP/3 DATA frame on the CONNECT tunnel's
  /// request stream — the CONNECT **specialization** of the general
  /// [`send_data_on`](Self::send_data_on): a thin wrapper that forwards to
  /// `send_data_on(request_id, …)`, so the DATA frame travels the exact same per-id
  /// path as a general request/response body. The specialization is only the
  /// signature and the implicit id: it keeps the tunnel's `send_data(&[u8])` arity
  /// (copying the borrowed slice into a [`DataBuf`](crate::backend::DataBuf) on the
  /// heap tiers, since the caller hands no owned buffer) and targets the single
  /// tunnel-slot pointer (`request_id`) instead of an explicit id. As with every
  /// tunnel method, a framing/transport error here is CONNECTION-fatal (one tunnel =
  /// one connection), where a general stream resets per-stream.
  ///
  /// Returns:
  /// - [`Err`]`(`[`Error::Closed`]`)` before the tunnel is established or after
  ///   it has been closed;
  /// - [`Err`]`(`[`Error::WouldBlock`]`)` when the transmit queue is full — drain
  ///   it with [`poll_transmit`](Self::poll_transmit) and retry;
  /// - [`Err`]`(`[`Error::Protocol`]`(`[`H3Error::FrameError`]`))` when the framed
  ///   payload does not fit a single transmit slot (the v1 no-alloc bound).
  pub fn send_data(&mut self, payload: &[u8]) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    // The tunnel precondition: DATA flows only while the tunnel is `Open`. This one
    // phase check subsumes the old `!started || !established || closing` triple —
    // `Created` / `Handshaking` (not yet open) and `Closing` / `Failed` (no longer
    // open) all report `Closed`. It also pins setup-before-traffic: the control
    // stream's SETTINGS reach the wire (in `Handshaking`) before any DATA frame
    // (RFC 8441 / RFC 9114 ordering). This stays the TUNNEL gate; the general
    // `send_data_on` enqueue is shared underneath.
    if !self.phase.is_open() {
      return Err(Error::Closed);
    }
    let id = self.request_id.ok_or(Error::Closed)?;
    // The tunnel keeps its `send_data(&[u8])` arity. On heap tiers the general
    // entry point takes an owned `DataBuf`, so the borrowed slice is copied into
    // one here (the caller did not hand us a buffer to hold zero-copy); on bare it
    // forwards the slice to the copy-into-ring path.
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    {
      self.send_data_on(id, crate::backend::copy_from_slice(payload))
    }
    #[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
    {
      self.send_data_on(id, payload)
    }
  }

  /// Sends a chunk of DATA-frame payload (request/response body, or tunnel bytes) on
  /// the request stream `id` — the GENERAL per-stream DATA entry point.
  ///
  /// On the heap tiers (`alloc` / `std` / `no-atomic`) `body` is anything that
  /// converts into the refcounted [`DataBuf`](crate::backend::DataBuf) (e.g.
  /// `bytes::Bytes` / `portable_atomic_util::Arc<[u8]>`); it is held **zero-copy**
  /// as the DATA frame's body segment (a cheap clone, not a memcpy into the ring),
  /// so only the small frame header is bounded by the per-slot capacity — a large
  /// body no longer has to fit one transmit slot. The driver writes the resulting
  /// two-segment [`Transmit`] (header + body) with a vectored `writev`.
  ///
  /// Distinct in name from the tunnel [`send_data`](Self::send_data) because Rust
  /// cannot overload by arity and the tunnel keeps its `send_data(&[u8])` (a thin
  /// wrapper over this). `id` must name a known request stream; the connection must
  /// be non-terminal and past setup.
  ///
  /// Returns:
  /// - [`Err`]`(`[`Error::Closed`]`)` when the connection is closing/failed, setup
  ///   has not run, or `id` is not a known request stream;
  /// - [`Err`]`(`[`Error::WouldBlock`]`)` when the transmit ring is momentarily full
  ///   — drain it with [`poll_transmit`](Self::poll_transmit) and retry;
  /// - [`Err`]`(`[`Error::Protocol`]`(`[`H3Error::FrameError`]`))` when the DATA
  ///   frame header does not fit a transmit slot (only the header is so bounded).
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  pub fn send_data_on<B>(&mut self, id: StreamId, body: B) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
    B: Into<crate::backend::DataBuf>,
  {
    use core::ops::Deref;
    self.guard_send_on(id, SendOp::Body)?;
    let body = body.into();
    let body_len = body.deref().len();
    self
      .tx
      .enqueue_data(StreamKind::Existing(id), false, body, |out| {
        write_data_header(out, body_len)
      })
      .map_err(map_tx)
  }

  /// Sends a chunk of DATA-frame payload on the request stream `id` — the GENERAL
  /// per-stream DATA entry point (bare `no_std` tier).
  ///
  /// With no refcounted buffer type available, `payload` is copied into the
  /// caller-provided transmit storage as a single framed DATA segment (the v1
  /// no-alloc bound: the framed payload must fit one transmit slot). See the heap
  /// tiers' [`send_data_on`](Self::send_data_on) for the zero-copy variant.
  ///
  /// Returns:
  /// - [`Err`]`(`[`Error::Closed`]`)` when the connection is closing/failed, setup
  ///   has not run, or `id` is not a known request stream;
  /// - [`Err`]`(`[`Error::WouldBlock`]`)` when the transmit ring is momentarily full
  ///   — drain it with [`poll_transmit`](Self::poll_transmit) and retry;
  /// - [`Err`]`(`[`Error::Protocol`]`(`[`H3Error::FrameError`]`))` when the framed
  ///   payload does not fit a single transmit slot (the v1 no-alloc bound).
  #[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
  pub fn send_data_on(&mut self, id: StreamId, payload: &[u8]) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    self.guard_send_on(id, SendOp::Body)?;
    self
      .tx
      .enqueue(StreamKind::Existing(id), false, |out| {
        write_data_frame(out, payload)
      })
      .map_err(map_tx)
  }

  /// Reports that the driver wrote `n` bytes of the transmit last returned by
  /// [`poll_transmit`](Self::poll_transmit) — a partial QUIC `writev`. The next
  /// `poll_transmit` re-yields that transmit's remaining segments (re-sliced past
  /// the `n` already-written bytes); the transmit is only dropped once every byte
  /// is written. A `poll_transmit` with no intervening `consume_transmit`
  /// acknowledges the previous transmit as fully written (the "driver re-polls"
  /// model). Calling this with no transmit in flight is a no-op.
  pub fn consume_transmit(&mut self, n: usize) {
    self.tx.consume(n);
  }

  /// Sends a trailing HEADERS section (trailers) on the request stream `id`, in
  /// either direction (request trailers from a client, response trailers from a
  /// server). EXACTLY ONE trailing section is allowed, after the body: on a successful
  /// enqueue the stream's `SendState` moves to `SendState::TrailersSent`, so a
  /// following [`send_data_on`](Self::send_data_on) (DATA after trailers) or a second
  /// `send_trailers` (two trailing sections) is rejected with
  /// [`Error::Protocol`]`(`[`H3Error::FrameUnexpected`]`)` — only [`finish`](Self::finish)
  /// (the FIN) may follow (RFC 9114 §4.1). The driver owns trailer validity; the core
  /// stays semantics-agnostic (the full validator is a later task).
  ///
  /// Returns the same `Err` set as [`send_data_on`](Self::send_data_on), plus
  /// [`Error::FieldSectionTooLarge`] when the trailers' decoded field-section size
  /// exceeds the peer's advertised `MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2).
  pub fn send_trailers<H: Headers + ?Sized>(
    &mut self,
    id: StreamId,
    headers: &H,
  ) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    self.guard_send_on(id, SendOp::Trailers)?;
    // The peer's SETTINGS bound the trailers' field-section size, as for any HEADERS
    // frame. When they have not arrived the size is unbounded locally; matching the
    // request/response paths, block until they do.
    let limit = self
      .settings_peer
      .ok_or(Error::WouldBlock)?
      .max_field_section_size();
    self
      .tx
      .enqueue(StreamKind::Existing(id), false, |out| {
        write_headers_frame(out, headers, limit)
      })
      .map_err(map_tx)?;
    // The trailing section is queued: move the send half to `TrailersSent` so nothing but
    // the FIN may follow (no DATA-after-trailers, no second trailing section). Only reached
    // on success, so a `WouldBlock` retry does not advance the state.
    if let Some(entry) = self.streams.get_mut(id) {
      entry.send = SendState::TrailersSent;
    }
    Ok(())
  }

  /// Half-closes the request stream `id` by enqueuing an empty FIN transmit on it —
  /// the GENERAL per-stream finish (end of the locally-sent message: after the
  /// request body / trailers on a client, or the response body / trailers on a
  /// server). Unlike the connection-level [`close`](Self::close) it does NOT change
  /// the connection phase; it is a per-stream send-half close.
  ///
  /// Returns the same `Err` set as [`send_data_on`](Self::send_data_on) (a full ring
  /// is [`Error::WouldBlock`] — retry after [`poll_transmit`](Self::poll_transmit)).
  ///
  /// Closes the stream's LOCAL send half exactly once: on a successful enqueue the entry's
  /// `SendState` moves to `SendState::Closed`, after which every further local send on
  /// `id` (body / trailers / a second `finish` / a response) is rejected with
  /// [`Error::Protocol`]`(`[`H3Error::FrameUnexpected`]`)`. A [`Error::WouldBlock`] (full
  /// ring) does NOT advance the state — the caller retries the same `finish` — so the FIN
  /// is enqueued, and the half closed, exactly once.
  pub fn finish(&mut self, id: StreamId) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    self.guard_send_on(id, SendOp::Finish)?;
    // An empty FIN: zero bytes, fin = true. The fill closure writes nothing, so its
    // error type is the uninhabited-in-practice `()`; a full ring is the only failure
    // and maps to `WouldBlock` (retry after `poll_transmit`).
    self
      .tx
      .enqueue(StreamKind::Existing(id), true, |_out| Ok::<usize, ()>(0))
      .map_err(|e| match e {
        TxError::Full => Error::WouldBlock,
        TxError::Fill(()) => too_large(),
      })?;
    // The FIN is queued: close the local send half so nothing follows it on the wire.
    // Only reached on success, so a backpressure retry does not double-close.
    if let Some(entry) = self.streams.get_mut(id) {
      entry.send = SendState::Closed;
    }
    Ok(())
  }

  /// Shared precondition for the general per-stream send paths
  /// ([`send_data_on`](Self::send_data_on) / [`send_trailers`](Self::send_trailers) /
  /// [`finish`](Self::finish)): the connection must be non-terminal and past setup, `id`
  /// must name a known request stream, and the stream's [`SendState`] must permit `op`.
  /// A terminal/`Created` connection or an unknown `id` is [`Error::Closed`].
  ///
  /// Materializes a deferred stream-scoped reset FIRST (`reconcile_pending_resets`), so a
  /// stream condemned by a `Frames` carrier (e.g. a malformed General-mode request that
  /// recorded a `pending_reset`) is already removed from `streams` before the membership
  /// check — its `id` then reads as unknown (`Error::Closed`), so a condemned stream can
  /// never be sent on by any of these paths.
  ///
  /// The send-state gate is the [`SendState`] transition table for `op` (a local refusal
  /// — [`Error::Protocol`]`(`[`H3Error::FrameUnexpected`]`)`, the connection stays live):
  ///
  /// - **Body / trailers** ([`SendOp::Body`] / [`SendOp::Trailers`]) require a body-open
  ///   state ([`SendState::can_send_body`]): the CLIENT request-body window
  ///   ([`SendState::RequestSent`]) or the SERVER post-final-response window
  ///   ([`SendState::FinalSent`]). They are rejected before the SERVER's final response
  ///   ([`SendState::Idle`] — premature DATA / malformed ordering, RFC 9114 §4.1), after a
  ///   trailing section ([`SendState::TrailersSent`] — at most one trailing section,
  ///   nothing after it), and after the FIN ([`SendState::Closed`]).
  /// - **FIN** ([`SendOp::Finish`]) is legal from any state that can still terminate the
  ///   send half — the body-open states OR [`SendState::TrailersSent`] (a clean FIN after
  ///   the trailers) — and rejected only from [`SendState::Idle`] (a SERVER FIN before any
  ///   response leaves the response with no HEADERS) and [`SendState::Closed`] (a second
  ///   FIN). The CLIENT never holds [`SendState::Idle`], so its request body / trailers /
  ///   FIN before any response stay legal (no over-restriction).
  fn guard_send_on(&mut self, id: StreamId, op: SendOp) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    self.reconcile_pending_resets();
    match self.phase {
      Phase::Closing | Phase::Failed | Phase::Created => return Err(Error::Closed),
      Phase::Handshaking | Phase::Open => {}
    }
    let Some(entry) = self.streams.get(id) else {
      return Err(Error::Closed);
    };
    let allowed = match op {
      // A FIN may terminate the send half from a body-open state or after the trailing
      // section; a body / trailers require the body-open window (and never re-open after
      // trailers / FIN). `Idle` (server pre-final) and `Closed` reject everything here.
      SendOp::Finish => entry.send.can_send_body() || entry.send == SendState::TrailersSent,
      SendOp::Body | SendOp::Trailers => entry.send.can_send_body(),
    };
    if !allowed {
      return Err(Error::Protocol(H3Error::FrameUnexpected));
    }
    Ok(())
  }

  /// Closes the tunnel: moves to phase `Closing` (from any non-terminal phase) and
  /// enqueues an empty FIN transmit on the request stream.
  ///
  /// Unlike the other tunnel methods this has no general per-id counterpart in
  /// Phase 0: it is connection-level (the tunnel-slot pointer `request_id` IS the
  /// connection's one stream), so it half-closes the connection rather than a single
  /// general stream. A per-id graceful half-close for general streams is future work.
  ///
  /// If the transmit ring is momentarily full (or the request stream has not been
  /// opened yet), the FIN cannot be enqueued now; it is marked pending and
  /// [`poll_transmit`](Self::poll_transmit) retries it once the ring drains, so a
  /// close under backpressure is never silently dropped. The FIN is emitted
  /// exactly once: a second `close` while one is already pending is a no-op, and
  /// once enqueued `close_pending` is cleared. A `close` on an already-terminal
  /// connection (`Closing`/`Failed`) is a no-op.
  pub fn close(&mut self)
  where
    TxBuf: AsMut<[u8]>,
  {
    // Enter `Closing` (a no-op if already terminal), and on the FIRST transition
    // arm the deferred FIN — the local half-close sends an empty FIN on the request
    // stream (deferred via `close_pending` if the ring is full / the stream is not
    // yet bound). Arming only on a real transition keeps the FIN exactly-once.
    if self.begin_close() {
      self.close_pending = true;
      self.try_send_fin();
    }
  }

  /// Attempts to enqueue the pending empty FIN transmit on the request stream.
  /// A no-op unless a close is pending and the request stream exists; on a
  /// successful enqueue it clears `close_pending` so the FIN is sent exactly once.
  /// Leaves `close_pending` set if the ring is full (retried from
  /// [`poll_transmit`](Self::poll_transmit)).
  ///
  /// The graceful FIN is emitted ONLY in `Phase::Closing`: a `Failed` connection
  /// does not flush a clean close FIN. `fail` already clears `close_pending` (the
  /// primary guard), so this phase check is belt-and-suspenders against a deferred
  /// FIN surviving a later failure.
  fn try_send_fin(&mut self)
  where
    TxBuf: AsMut<[u8]>,
  {
    if !self.close_pending || !self.phase.is_closing() {
      return;
    }
    let Some(id) = self.request_id else {
      return; // No request stream yet; retry once it is provided.
    };
    // An empty FIN: zero bytes, fin = true. The fill closure writes nothing.
    if self
      .tx
      .enqueue(StreamKind::Existing(id), true, |_out| Ok::<usize, ()>(0))
      .is_ok()
    {
      self.close_pending = false;
    }
  }

  /// Signal a QUIC `RESET_STREAM` for `id` with application error `code`. A no-op
  /// once the connection is `Failed` (terminal): a reset is moot then, and a `Reset`
  /// event must not land ahead of the terminal `ConnError`. Otherwise the full
  /// matrix — intentionally parallel to [`handle_stream_fin`](Self::handle_stream_fin),
  /// differing ONLY in the request-stream action (the non-request branches share the
  /// same `resolve_non_request_close` body) — with each `id` matching at most one
  /// case:
  ///
  /// - **Request stream**, scoped by whether it is the CONNECT tunnel (the entry's
  ///   private `is_tunnel` marker):
  ///   - a **general** (non-tunnel) request stream is stream-scoped: free its store
  ///     slot and leave the connection (and every OTHER stream) live — NO
  ///     [`Event::Reset`], NO phase change. A `RESET_STREAM` carries no frame bytes,
  ///     and we do not echo a reset back (the peer already aborted its side).
  ///   - the **CONNECT tunnel** is connection-scoped (one tunnel = one connection): a
  ///     reset of the established tunnel is a teardown. On the abandoned
  ///     (lazily-dropped, never-observed) tunnel stream it is a no-op (there is no
  ///     framing to validate and the stream is already inert). Otherwise, while not
  ///     already terminal, enqueue [`Event::Reset`] exactly once and transition to
  ///     `Closing` via the phase-only `begin_close`; a reset arriving while already
  ///     `Closing` is a no-op (a redundant `Reset`). Unlike [`close`](Self::close)
  ///     this does NOT arm a local FIN: the peer already reset the stream, so FINing it
  ///     would be spurious. This is the phase transition (and the `Reset` signal) only.
  /// - **An outbound critical stream** we opened (control or QPACK encoder/decoder,
  ///   tracked in `roles`): resetting it is
  ///   [`Event::ConnError`]`(`[`H3Error::ClosedCriticalStream`]`)` (RFC 9114 §6.2.1),
  ///   and supersedes a graceful `Closing` (it fires even when already terminal-but-
  ///   not-`Failed`).
  /// - **An inbound uni stream** (tracked in the `uni` table), by its state:
  ///   - a classified *critical* role (control / QPACK enc / QPACK dec) →
  ///     [`H3Error::ClosedCriticalStream`]; the slot is also freed.
  ///   - a classified `Ignored` (GREASE / extension) stream → **free the slot** so a
  ///     peer cannot reset `UNI_CAP` GREASE streams to wedge the table and starve a
  ///     real critical stream into [`H3Error::ExcessiveLoad`].
  ///   - still `Pending` (reset before its type varint completed) → **free the slot**
  ///     for the same reason.
  /// - **Any other (unknown / untracked) id** is ignored (no panic).
  pub fn handle_stream_reset(&mut self, id: StreamId, code: u64)
  where
    EventBuf: AsMut<[Option<Event>]>,
    TxBuf: AsMut<[u8]>,
    UniBuf: AsMut<[UniSlot]>,
  {
    // A `Failed` connection is terminal: a reset is moot. Do nothing — no `Reset`
    // (it would be delivered, FIFO, BEFORE the terminal `ConnError` from the
    // dedicated slot, breaking terminal ordering) and no second `ConnError`.
    if self.phase.is_failed() {
      return;
    }
    // Reconcile any deferred stream-scoped reset FIRST (free the slot + queue the
    // `RESET_STREAM` with its ORIGINAL code), so a stream a `Frames` carrier already
    // condemned is gone from `streams` before the lookup below. Otherwise this would act
    // on the still-present condemned entry — re-resetting it or pushing a spurious
    // `Reset` — while its original reset is still queued (a duplicate / wrong-code abort
    // on the wire). A stream reset does not fail the connection, so this runs live.
    self.reconcile_pending_resets();
    if let Some(entry) = self.streams.get(id) {
      let is_tunnel = entry.is_tunnel;
      let abandoned = entry.abandoned;
      if !is_tunnel {
        // A GENERAL request stream the peer reset is stream-scoped: free its slot and
        // leave the connection (and every other stream) live — NO `Event::Reset`, NO
        // phase change. A `RESET_STREAM` carries no frame bytes (nothing to validate),
        // and we do not echo a reset back (the peer already aborted its side). If it was
        // the tunnel-slot pointer it is cleared. (The tunnel branch below keeps the
        // connection-scoped teardown.)
        self.streams.remove(id);
        if self.request_id == Some(id) {
          self.request_id = None;
        }
        return;
      }
      // An abandoned tunnel request stream is inert and a `RESET_STREAM` carries no
      // frame bytes, so — unlike a FIN (which `handle_stream_fin` still validates for
      // mid-frame truncation) — there is nothing to validate here: no `Reset` event
      // (the tunnel was never observed), no failure (a lazy drop is not a violation).
      if abandoned {
        return;
      }
      // The CONNECT tunnel (one tunnel = one connection): a reset is a teardown. Push
      // `Reset` exactly once — only while NOT already terminal (`Failed` is handled
      // above; this guards the redundant reset-while-`Closing` case) — then enter
      // `Closing` via the phase-only transition. No deferred FIN is armed: the peer
      // already reset the request stream, so FINing it would be spurious.
      if !self.is_terminal() {
        let _ = self.events.push(Event::Reset(code));
        let _ = self.begin_close();
      }
      return;
    }
    // The non-request branches resolve identically to FIN (outbound critical / inbound
    // uni / unknown), so the two matrices share one body and cannot drift.
    self.resolve_non_request_close(id);
  }

  /// Signal the QUIC stream FIN for `id`. A no-op once the connection is `Failed`
  /// (terminal): a FIN is moot then, and surfacing anything — a `PeerClosed` or a
  /// second `ConnError` — would land ahead of the terminal `ConnError` and break
  /// terminal ordering. Otherwise the full matrix (each `id` matches at most one
  /// case):
  ///
  /// - **Request stream** (routed through [`Stream::fin`]):
  ///   - a clean end at a frame boundary once the leading message completed (the
  ///     CONNECT request / final response, and the tunnel is established) enqueues
  ///     [`Event::PeerClosed`] — a graceful half-close that does NOT make the
  ///     connection terminal. Idempotent: a second clean FIN on the (already
  ///     half-closed) request stream enqueues no duplicate `PeerClosed` (the peer FINs
  ///     its send side at most once);
  ///   - a malformed FIN — at a frame boundary while the leading message is still
  ///     incomplete (no HEADERS, or only interim 1xx leading sections —
  ///     [`H3Error::RequestIncomplete`], RFC 9114 §8.1) or mid-frame
  ///     ([`H3Error::FrameError`], RFC 9114 §7.1) — is scoped by whether the stream is
  ///     the CONNECT tunnel (the entry's private `is_tunnel` marker): on the tunnel it
  ///     is connection-fatal ([`Event::ConnError`], terminal); on a **general** request
  ///     stream it is a stream-scoped reset (free the slot + a `RESET_STREAM` transmit,
  ///     RFC 9114 §4.1.2) that leaves the connection live.
  /// - **An outbound critical stream** (control or QPACK encoder/decoder we
  ///   opened, tracked in `roles`): closing it is
  ///   [`Event::ConnError`]`(`[`H3Error::ClosedCriticalStream`]`)` (RFC 9114
  ///   §6.2.1).
  /// - **An inbound uni stream** (tracked in the `uni` table), by its state:
  ///   - a classified *critical* role (control / QPACK enc / QPACK dec) →
  ///     [`H3Error::ClosedCriticalStream`]; the slot is also freed (the
  ///     connection is failing, so retaining it serves no purpose).
  ///   - a classified `Ignored` (GREASE / extension) stream → **free the slot**: a
  ///     closed extension stream releases its tracking capacity, so a peer cannot
  ///     open+FIN `UNI_CAP` GREASE streams to wedge the table and then have a real
  ///     control stream rejected with [`H3Error::ExcessiveLoad`].
  ///   - still `Pending` (closed before its type varint completed) → **free the
  ///     slot** for the same reason.
  /// - **Any other (unknown / untracked) id** is ignored (no panic).
  pub fn handle_stream_fin(&mut self, id: StreamId)
  where
    EventBuf: AsMut<[Option<Event>]>,
    TxBuf: AsMut<[u8]>,
    UniBuf: AsMut<[UniSlot]>,
  {
    // A `Failed` connection is terminal: a FIN on any stream is moot. Do nothing —
    // no `PeerClosed` (it would be delivered, FIFO, BEFORE the terminal `ConnError`
    // that `poll_event` surfaces from the dedicated slot, breaking terminal
    // ordering) and no second `ConnError` (`fail` is idempotent, but the FIN is
    // simply irrelevant once a fatal error already occurred).
    if self.phase.is_failed() {
      return;
    }
    // Reconcile any deferred stream-scoped reset FIRST (free the slot + queue the
    // `RESET_STREAM` with its ORIGINAL code), so a stream a `Frames` carrier already
    // condemned is gone from `streams` before the lookup below. Otherwise a clean FIN
    // would push `PeerClosed` on a condemned stream (or a malformed FIN would re-reset
    // it with a different code) while its original reset is still queued — a duplicate
    // abort / spurious event. A stream reset does not fail the connection, so this runs
    // live; the condemned `id` then reads as unknown here (handled by the non-request
    // fallthrough, which ignores it).
    self.reconcile_pending_resets();
    if let Some(entry) = self.streams.get(id) {
      // Read the per-stream FIN outcome + markers into locals so the `entry` (and thus
      // `self.streams`) borrow ends before any `self.fail` / `self.events` mutation
      // below (those borrow disjoint connection fields, but `self.fail` reborrows all
      // of `self`).
      let fin = entry.fsm.fin();
      let abandoned = entry.abandoned;
      let is_tunnel = entry.is_tunnel;
      // An abandoned request stream: a prior `handle_stream` decoded its first HEADERS
      // on the drop-drain without the driver observing it, advancing the FSM into its
      // tunnel phase. It is permanently inert to the DRIVER (the tunnel was never
      // observed / established), but — exactly as for inbound bytes above — abandonment
      // is NOT terminal, so the FIN must still be VALIDATED rather than blindly ignored.
      // A malformed FIN (mid-frame / pre-HEADERS) is a real framing violation: on the
      // tunnel it `fail`s the connection; on a general stream it resets only that stream
      // (RFC 9114 §4.1.2). A CLEAN FIN is validated but SUPPRESSED — no `PeerClosed`,
      // because the tunnel was never observed/established (a clean FIN on an abandoned
      // stream is therefore inert but not a fault, so the connection stays non-terminal).
      // Only a `Failed` connection (above) skips this validation entirely. Scoped to the
      // request stream so a FIN on a critical stream below still fails; sits alongside
      // the `Failed` (above) and `peer_closed` guards.
      if abandoned {
        if let Err(e) = fin {
          self.fail_or_reset_stream(id, is_tunnel, e);
        }
        return;
      }
      match fin {
        // A clean end at a frame boundary once the LEADING MESSAGE completed (the FSM
        // left `Phase::Headers`): the peer half-closed its send side. A graceful
        // tunnel-end signal, NOT a connection-fatal error, so the connection is not
        // forced terminal here — a half-closed tunnel may still send locally (the
        // request FSM models only the peer's direction). But `fin() == Ok(())` proves
        // only that the leading message completed (the CONNECT request / final
        // response, NOT merely an interim 1xx), NOT that the tunnel is established (open
        // for DATA): on the SERVER the phase can still be `Handshaking` here, with the
        // request HEADERS observed (`request_received`) but `accept_with` not yet called
        // (it sends the 2xx and establishes). A tunnel-lifecycle `PeerClosed` must never
        // precede `Established`, so gate on `tunnel_established` exactly like inbound
        // tunnel DATA:
        //
        // - established → surface `PeerClosed` now. Idempotent: `RequestStream::fin()`
        //   is a pure read that keeps returning `Ok(())` at a post-leading frame
        //   boundary, so a second clean FIN would re-push `PeerClosed`; the
        //   `peer_closed` flag emits it exactly once (the peer FINs its send side at
        //   most once).
        // - not yet established → DEFER it: record `peer_fin_pending` and emit nothing
        //   now. This is a real half-close that must still surface, but only after the
        //   tunnel opens — `establish` (which `accept_with` calls) emits the deferred
        //   `PeerClosed` immediately after pushing `Established`, so `Established`
        //   strictly precedes it. `peer_closed` stays `false` so that deferred emit
        //   can still fire exactly once.
        Ok(()) => {
          // The per-stream markers live on the entry; borrow it and `self.events`
          // (disjoint fields) to surface / defer the half-close exactly once.
          let Self {
            streams, events, ..
          } = self;
          if let Some(entry) = streams.get_mut(id) {
            if entry.established {
              if !entry.peer_closed {
                entry.peer_closed = true;
                let _ = events.push(Event::PeerClosed);
              }
            } else {
              entry.peer_fin_pending = true;
            }
          }
        }
        // A FIN with no completed leading message — before any HEADERS or after ONLY
        // interim 1xx leading sections (`RequestIncomplete`) — or mid-frame
        // (`FrameError`), scoped by `is_tunnel`: connection-fatal on the tunnel (make it
        // terminal so a later send is rejected, signalled once), a stream-scoped reset
        // on a general stream (RFC 9114 §4.1.2 — free + `RESET_STREAM`, connection live).
        Err(e) => self.fail_or_reset_stream(id, is_tunnel, e),
      }
      return;
    }
    // Every non-request stream close (FIN or RESET_STREAM) resolves identically;
    // the shared body keeps the FIN and reset matrices from drifting.
    self.resolve_non_request_close(id);
  }

  /// The shared non-request branch of both [`handle_stream_fin`](Self::handle_stream_fin)
  /// and [`handle_stream_reset`](Self::handle_stream_reset): a close (FIN or
  /// `RESET_STREAM`) of a stream that is NOT the request stream resolves the same way
  /// whichever signal arrived, so the two matrices share one body and cannot drift.
  /// The caller has already handled the `Failed` terminal-priority guard and the
  /// request-stream case.
  ///
  /// - An **outbound critical stream** we opened (control or QPACK encoder/decoder,
  ///   tracked in `roles`, not `uni`): closing it is a closed-critical-stream
  ///   connection error (terminal), which supersedes a graceful `Closing`.
  /// - An **inbound (peer-opened) uni stream** tracked in the `uni` table: the slot is
  ///   freed for every case (a critical close fails the connection, so the slot is
  ///   moot; a closed Ignored / Pending stream must release its capacity so it cannot
  ///   wedge the table). A classified *critical* role is
  ///   [`H3Error::ClosedCriticalStream`]; `Pending` and `Classified(Ignored)` are
  ///   non-fatal (no event).
  /// - **Any other (unknown / untracked) id** is ignored (no panic).
  fn resolve_non_request_close(&mut self, id: StreamId)
  where
    EventBuf: AsMut<[Option<Event>]>,
    UniBuf: AsMut<[UniSlot]>,
  {
    // An outbound critical stream we opened (tracked in `roles`, not `uni`):
    // closing it is a closed-critical-stream connection error (terminal).
    if self.role_of(id).is_some_and(is_critical_role) {
      self.fail(H3Error::ClosedCriticalStream);
      return;
    }
    // An inbound (peer-opened) uni stream tracked in the `uni` table. Resolve the
    // outcome from its state, then free its slot for every case here: a critical
    // close fails the connection (so the slot is moot), and a closed Ignored /
    // Pending stream must release its capacity so it cannot wedge the table.
    if let Some(state) = self.take_uni_state(id) {
      let critical = matches!(
        state,
        UniState::Classified(UniRole::ControlIn | UniRole::QpackEncIn | UniRole::QpackDecIn)
      );
      if critical {
        self.fail(H3Error::ClosedCriticalStream);
      }
      // `Pending` and `Classified(Ignored)` are non-fatal: the slot is freed (by
      // `take_uni_state`) with no event, so the released capacity is reusable.
    }
    // Otherwise `id` is unknown / untracked: ignore it (no panic).
  }

  /// Removes `id`'s entry from the `uni` table, returning its [`UniState`] if it
  /// was tracked. Used on FIN to both inspect the closed inbound uni stream's role
  /// and release its tracking slot in one step — so a closed GREASE / extension or
  /// still-`Pending` stream frees its capacity (it can no longer send bytes, so it
  /// need not be retained), and a closed critical stream's now-moot slot is
  /// reclaimed while the connection fails.
  fn take_uni_state(&mut self, id: StreamId) -> Option<UniState>
  where
    UniBuf: AsMut<[UniSlot]>,
  {
    let slot = self
      .uni
      .as_mut()
      .iter_mut()
      .find(|s| matches!(s.entry, Some(e) if e.id == id))?;
    slot.entry.take().map(|e| e.state)
  }

  /// The next queued transmit (bytes the driver must write on a QUIC stream),
  /// or `None` if the queue is empty.
  ///
  /// Inert once `Failed`: a terminal connection emits NO transmit. The terminal
  /// [`Event::ConnError`] from [`poll_event`](Self::poll_event) is the connection's
  /// last observable output, so stale outbound bytes queued before a no-return fatal
  /// path (DATA / an `OpenRequest` enqueued while `Open`) must not still be written
  /// after the failure. This mirrors the inbound `Failed` no-op in
  /// [`handle_stream`](Self::handle_stream): once `Failed` the connection is fully
  /// terminal-priority on BOTH directions. `Closing` is NOT short-circuited — a
  /// graceful close still flushes queued bytes and the deferred close FIN.
  ///
  /// Lending: the returned [`Transmit`] borrows the connection's transmit ring
  /// and is valid until the next `poll_transmit`.
  ///
  /// Reset ordering & LIVENESS: a stream reset is a per-stream control SIGNAL, not
  /// bytes. Pending `RESET_STREAM` aborts come from the dedicated reset channel and are
  /// emitted FIRST — one per call, BEFORE the byte ring — and unconditionally: an abort
  /// is never gated by ring slot capacity, so `poll_transmit` can ALWAYS emit a recorded
  /// abort and can NEVER return `None` while one is pending. This dissolves the whole
  /// reset-stranding class (a full ring, tombstone ordering, a held front transmit) by
  /// construction. The stream's stale queued DATA was already purged from the ring when
  /// the reset was recorded (and re-asserted by the reconcile below), so the abort
  /// supersedes — never trails — it.
  pub fn poll_transmit(&mut self) -> Option<Transmit<'_>>
  where
    TxBuf: AsRef<[u8]> + AsMut<[u8]>,
  {
    // Reconcile any deferred stream-scoped reset (free the slot + purge the stream's
    // queued DATA) BEFORE the `Failed` guard, so a condemned stream reads as gone and no
    // stale same-stream DATA is yielded. A stream reset does not fail the connection, so
    // this runs on a live (non-`Failed`) connection.
    self.reconcile_pending_resets();
    if self.phase.is_failed() {
      return None;
    }
    // Emit one pending abort FIRST, directly from the dedicated reset channel — never the
    // byte ring, so it is never slot-gated and never stranded. A `RESET_STREAM` carries
    // no bytes (`fin = false`); the driver issues the QUIC `reset_stream(id, code)`. The
    // stream's DATA was purged when the reset was recorded / by the reconcile above, so
    // no `Existing(id)` transmit precedes the abort.
    if let Some(reset) = self.pending_resets.pop_front() {
      return Some(Transmit::new(
        StreamKind::ResetStream {
          id: reset.id,
          code: reset.code,
        },
        &[],
        false,
      ));
    }
    // Retry a close FIN that could not be enqueued under backpressure, so it is
    // delivered once the ring drains (never lost).
    self.try_send_fin();
    self.tx.poll()
  }

  /// Enqueues the control + QPACK setup streams: the control stream's type byte
  /// (`0x00`) followed by our SETTINGS frame, the QPACK encoder stream (`0x02`),
  /// and the QPACK decoder stream (`0x03`). Available for both roles.
  ///
  /// The client sends its CONNECT request separately with
  /// [`open_with`](Self::open_with), *after* the peer's SETTINGS arrive; the
  /// server accepts the peer's request with
  /// [`accept_with`](Self::accept_with). Drive the enqueued setup with
  /// [`poll_transmit`](Self::poll_transmit), opening each requested stream and
  /// reporting its id via [`provide_stream`](Self::provide_stream).
  ///
  /// Drives the `Created → Handshaking` transition. The setup is enqueued exactly
  /// once: a second `start` (already `Handshaking`/`Open`) is a no-op `Ok(())` (it
  /// must not open a duplicate control stream, which the peer would reject with
  /// `H3_STREAM_CREATION_ERROR`). Returns [`Error::Closed`] if the connection is
  /// already terminal (`Closing`/`Failed`).
  ///
  /// `start` is transactional: the three setup transmits go in together or not at
  /// all. If the transmit ring lacks three free slots it returns
  /// [`Error::WouldBlock`] having enqueued NOTHING and left the phase `Created`, so
  /// a retry sends exactly one setup sequence — never a partial-then-duplicate one
  /// (which would open duplicate critical streams). Normally `start` is the first
  /// call on an empty ring, so this never blocks; the guard just rules out the
  /// partial path. Drain the ring with [`poll_transmit`](Self::poll_transmit) and
  /// retry.
  pub fn start(&mut self) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    self.start_handshake()
  }

  /// The next queued connection event, or `None` if the queue is empty.
  ///
  /// The terminal [`Event::ConnError`] is delivered FIRST and supersedes everything
  /// else. It comes from the dedicated, non-droppable `conn_error` slot (set by the
  /// fail transition) rather than the bounded event queue, so it surfaces even if
  /// the queue was saturated when the connection failed. It is `take`n on return,
  /// so it is yielded exactly once.
  ///
  /// Once the connection is `Failed` it is terminal-priority: the fail transition
  /// already cleared the pending event queue (discarding stale nonfatal lifecycle
  /// events) and the inbound guards keep a `Failed` connection inert, so after the
  /// terminal `ConnError` the queue is empty and every further `poll_event` is
  /// `None`. The driver therefore observes EXACTLY the terminal error — no stale
  /// `Established` / `PeerClosed` / `Reset` ahead of it.
  ///
  /// Before any failure (the `conn_error` slot empty) this drains the normal
  /// lifecycle queue in FIFO order.
  pub fn poll_event(&mut self) -> Option<Event>
  where
    EventBuf: AsMut<[Option<Event>]>,
  {
    if let Some(error) = self.conn_error.take() {
      return Some(Event::ConnError(error));
    }
    self.events.pop()
  }
}

impl<'req, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
  Connection<'req, '_, '_, '_, '_, Client, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
where
  St: StreamStore<StreamEntry<'req, ReqBuf>>,
{
  /// Sends the CONNECT request HEADERS — call this AFTER the peer's SETTINGS have
  /// been received (i.e. [`peer_settings`](Connection::peer_settings) is `Some`).
  ///
  /// This is the CONNECT **specialization** of the general
  /// [`open_request`](Connection::open_request): it opens a request stream with the
  /// same `write_headers_frame` encode+size-check, adding exactly one extra
  /// precondition — the Extended-CONNECT opt-in (`SETTINGS_ENABLE_CONNECT_PROTOCOL`,
  /// checked in `guard_open` where `open_request`'s `guard_open_request` does not) —
  /// and registering the resulting stream `is_tunnel = true`. That marker makes the
  /// tunnel connection-scoped: it establishes the whole connection
  /// ([`Event::Established`], `Phase::Open`) and a stream error on it is
  /// CONNECTION-fatal (one tunnel = one connection), where a general `open_request`
  /// stream establishes per-stream and resets per-stream (RFC 9114 §4.1.2). It also
  /// goes through the id-minting `OpenRequest` round-trip rather than taking a
  /// driver-supplied id.
  ///
  /// A client MUST NOT send a request carrying the `:protocol` pseudo-header
  /// before it has received `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` (RFC 8441 §3 /
  /// RFC 9220), so the opt-in and the peer's `MAX_FIELD_SECTION_SIZE` are checked
  /// synchronously here at send time:
  ///
  /// - [`Error::Closed`] — the connection is already closing (a prior
  ///   [`close`](Connection::close), or a peer reset via
  ///   [`handle_stream_reset`](Connection::handle_stream_reset)), so the request
  ///   must not be sent. Terminal, mirroring [`accept_with`](Connection::accept_with).
  /// - [`Error::WouldBlock`] — the peer's SETTINGS have not arrived yet. Pump more
  ///   inbound bytes through [`handle_stream`](Connection::handle_stream) (so the
  ///   peer's control-stream SETTINGS are decoded) and retry.
  /// - [`Error::ExtendedConnectUnsupported`] — the peer did not advertise Extended
  ///   CONNECT. A valid refusal, not a connection error: the HTTP/3 connection
  ///   stays healthy and the driver reports tunnel-setup failure or falls back.
  /// - [`Error::FieldSectionTooLarge`] — the request's decoded field-section size
  ///   (the sum over every field of name length + value length + 32 bytes of
  ///   overhead, RFC 9114 §4.2.2) exceeds the peer's advertised
  ///   `MAX_FIELD_SECTION_SIZE`.
  ///
  /// On success the request HEADERS frame is enqueued as an `OpenRequest`
  /// transmit; the driver pumps [`poll_transmit`](Connection::poll_transmit) to
  /// open the request stream and report its id via
  /// [`provide_stream`](Connection::provide_stream). Calling `open_with` again
  /// after the request was already sent is a no-op `Ok(())` (the request is sent
  /// exactly once).
  pub fn open_with<H: Headers + ?Sized>(&mut self, request: &H) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    let limit = match self.guard_open()? {
      SendGuard::AlreadyDone => return Ok(()),
      SendGuard::Proceed(limit) => limit,
    };
    // Encode and size-check the request HEADERS in a SINGLE traversal: the field
    // section is written into the transmit slot and its decoded size measured in
    // the one pass, then validated against the peer's MAX_FIELD_SECTION_SIZE. On
    // a too-large section `write_headers_frame` errors, so the slot is discarded
    // (never committed) and `request_sent` below is NOT reached — the bytes we
    // validated are exactly the bytes we would have sent.
    self
      .tx
      .enqueue(StreamKind::OpenRequest, false, |out| {
        write_headers_frame(out, request, limit)
      })
      .map_err(map_tx)?;
    self.request_sent = true;
    Ok(())
  }

  /// Opens a new request stream on the driver-minted QUIC bidi id `id`, registering
  /// its [`StreamEntry`] slot and enqueuing the request HEADERS as an `Existing(id)`
  /// transmit so the bytes flush on `id` via
  /// [`poll_transmit`](Connection::poll_transmit).
  ///
  /// This is the GENERAL request entry point (any HTTP request), distinct from the
  /// CONNECT-tunnel [`open_with`](Connection::open_with) in two ways:
  ///
  /// - **Id-explicit, no round-trip.** It mirrors
  ///   [`provide_stream`](Connection::provide_stream) ("ids are the driver's"): the
  ///   driver opens the QUIC stream first, then calls this with that id. There is no
  ///   `OpenRequest`/`provide_stream` round-trip and no single-outstanding-request
  ///   limit — call it repeatedly with DISTINCT ids for genuinely concurrent request
  ///   streams, each its own slot.
  /// - **No Extended-CONNECT opt-in.** A normal request does not require
  ///   `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so (unlike `open_with`) this does not
  ///   check it. It still requires a non-terminal post-setup phase and the peer's
  ///   SETTINGS for the `MAX_FIELD_SECTION_SIZE` size check.
  ///
  /// Transactional: it registers the stream entry AND enqueues its leading HEADERS
  /// together, or registers nothing. The transmit slot is preflighted before the entry
  /// is inserted, so a momentarily full ring returns [`Error::WouldBlock`] having
  /// touched no state (the retry starts fresh); an entry therefore never lingers without
  /// its leading HEADERS queued, so a later [`send_data_on`](Connection::send_data_on) /
  /// [`send_trailers`](Connection::send_trailers) / [`finish`](Connection::finish)
  /// cannot put a body on the wire ahead of the HEADERS.
  ///
  /// Returns:
  /// - [`Error::Closed`] — the connection is closing/failed, or setup has not run
  ///   (`Created`), so the request must not be sent (mirrors `open_with`).
  /// - [`Error::WouldBlock`] — the peer's SETTINGS have not arrived yet (pump more
  ///   inbound bytes and retry), or the transmit ring is momentarily full (drain it
  ///   with [`poll_transmit`](Connection::poll_transmit) and retry). On a full ring
  ///   nothing is registered, so the retry is a clean re-open.
  /// - [`Error::Protocol`]`(`[`H3Error::RequestRejected`]`)` — the stream store is at
  ///   capacity, so the stream cannot be tracked. The overflow id is reset with
  ///   `H3_REQUEST_REJECTED` (RFC 9114 §4.1; the request may be safely retried on a new
  ///   id) and NO HEADERS are enqueued for it — the open failed. NOT connection-fatal.
  /// - [`Error::FieldSectionTooLarge`] — the request's decoded field-section size
  ///   exceeds the peer's advertised `MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2). A
  ///   just-inserted entry is rolled back (no lingering entry without HEADERS).
  #[allow(private_bounds)]
  pub fn open_request<H: Headers + ?Sized>(
    &mut self,
    id: StreamId,
    headers: &H,
  ) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
    ReqBuf: ReqBufAlloc,
    EventBuf: AsMut<[Option<Event>]>,
  {
    // Same phase + peer-SETTINGS preconditions as `open_with`, minus the
    // Extended-CONNECT opt-in (a normal request has no `:protocol`). Resolved before
    // any slot is registered so a not-ready call mutates no state.
    let limit = self.guard_open_request()?;
    // Reconcile any deferred stream-scoped reset FIRST, so a stream a prior `Frames`
    // carrier condemned (e.g. a malformed response on this client `id`) is freed before
    // the `preexisting` / `provide_request_stream` membership checks below. Otherwise a
    // condemned `id` would read as already-registered (`preexisting = true`) and this
    // call would write its HEADERS onto an entry whose abort is still queued. After
    // reconciling, the condemned entry is gone — re-opening `id` is then a clean fresh
    // stream (a legitimate id reuse after the reset).
    self.reconcile_pending_resets();
    // Preflight the one transmit slot the request HEADERS need BEFORE registering the
    // stream, so a full ring registers NOTHING (no entry lingers without its leading
    // HEADERS, and the construction-time seed buffer is not consumed) and the caller
    // simply retries once the ring drains. This keeps `open_request` transactional —
    // either the entry AND its HEADERS are committed, or neither — mirroring
    // `enqueue_setup`'s all-or-nothing preflight.
    if !self.tx.has_capacity_mut(1) {
      return Err(Error::WouldBlock);
    }
    // Whether `id` was already tracked (an idempotent re-provide): only an entry THIS
    // call freshly inserts is rolled back below.
    let preexisting = self.streams.get(id).is_some();
    // Register the per-stream slot (recv FSM + lifecycle markers) keyed by the
    // driver-minted `id`, mirroring an inbound `provide_stream(Request, id)`, but marked
    // NON-tunnel: a general request establishes per-stream (final response → the entry's
    // `established`), never connection-wide (no `Event::Established`, no `Phase::Open`).
    // The first registered id still names the `request_id` tunnel-slot pointer (the
    // CONNECT specialization's "one stream"); later ids are independent concurrent
    // streams. An at-capacity STORE rejects the overflow stream (already reset with
    // `H3_REQUEST_REJECTED` inside): the id is NOT tracked, so we must NOT enqueue HEADERS
    // on it (the driver was told the request was rejected, not opened). Return the
    // rejection error rather than both resetting and writing on the same untracked id.
    if self.provide_request_stream(id, false) == RequestRegister::Rejected {
      return Err(Error::Protocol(H3Error::RequestRejected));
    }
    // Enqueue the request HEADERS on `id` (size-checked in the single encode pass, as in
    // `open_with`). The ring slot was preflighted, so a failure here is a `Fill` error
    // (the field section exceeds the peer's `MAX_FIELD_SECTION_SIZE`), not a full ring.
    // Roll back a JUST-inserted entry on failure so it never lingers without its leading
    // HEADERS — every later send path (`send_data_on` / `send_trailers` / `finish`) then
    // reads `id` as unknown, so body-before-HEADERS is impossible. We do NOT enqueue a
    // `RESET_STREAM`: the HEADERS never reached the wire, so there is nothing for the peer
    // to reset (do not both reset and write).
    if let Err(e) = self.tx.enqueue(StreamKind::Existing(id), false, |out| {
      write_headers_frame(out, headers, limit)
    }) {
      if !preexisting {
        self.streams.remove(id);
        if self.request_id == Some(id) {
          self.request_id = None;
        }
      }
      return Err(map_tx(e));
    }
    Ok(())
  }

  /// The preconditions for [`open_request`](Self::open_request): identical to
  /// [`guard_open`](Self::guard_open) MINUS the Extended-CONNECT opt-in check (a
  /// general request carries no `:protocol`) and MINUS the exactly-once
  /// `request_sent` short-circuit (each `open_request` call opens a distinct id).
  /// Returns the resolved `MAX_FIELD_SECTION_SIZE` limit, or the appropriate `Err`.
  fn guard_open_request(&self) -> Result<Option<u64>, Error> {
    match self.phase {
      // Terminal, or setup not yet run: the request must not be sent (mirrors
      // `guard_open`'s `Closing`/`Failed`/`Created` arms).
      Phase::Closing | Phase::Failed | Phase::Created => Err(Error::Closed),
      // The peer's SETTINGS gate the request for its `MAX_FIELD_SECTION_SIZE`; until
      // they arrive, block and retry. No `enable_connect_protocol` check.
      Phase::Handshaking | Phase::Open => {
        let settings = self.settings_peer.ok_or(Error::WouldBlock)?;
        Ok(settings.max_field_section_size())
      }
    }
  }

  /// The single source of truth for `open_with`'s preconditions. Returns the
  /// resolved field-size limit to proceed, [`SendGuard::AlreadyDone`] for the
  /// idempotent already-sent case, or the appropriate `Err`. The phase decides
  /// the terminal / not-started cases; the data markers decide readiness.
  fn guard_open(&self) -> Result<SendGuard<Option<u64>>, Error> {
    match self.phase {
      // Terminal: a prior `close()` / reset / fatal error. Checked before the
      // readiness gate so a closed-and-not-yet-ready connection reports `Closed`,
      // not `WouldBlock`. Mirrors `accept_with`.
      Phase::Closing | Phase::Failed => Err(Error::Closed),
      // Setup (control + SETTINGS) must precede the CONNECT request: a request
      // ahead of `start` would put the CONNECT HEADERS on the wire before our
      // SETTINGS (RFC 8441 / RFC 9114 ordering). In practice the peer's SETTINGS
      // cannot arrive before our own `start`, so this only fires on misuse.
      Phase::Created => Err(Error::Closed),
      // The request is sent exactly once; a repeat is a no-op (only reachable in a
      // non-terminal post-setup phase, so it never resends after a teardown).
      Phase::Handshaking | Phase::Open if self.request_sent => Ok(SendGuard::AlreadyDone),
      Phase::Handshaking | Phase::Open => {
        // The peer's SETTINGS gate the request: the RFC 8441 opt-in and the peer's
        // MAX_FIELD_SECTION_SIZE are both checked synchronously here at send time.
        let settings = self.settings_peer.ok_or(Error::WouldBlock)?;
        if !settings.enable_connect_protocol() {
          return Err(Error::ExtendedConnectUnsupported);
        }
        Ok(SendGuard::Proceed(settings.max_field_section_size()))
      }
    }
  }
}

impl<'req, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
  Connection<'req, '_, '_, '_, '_, Server, ReqBuf, CtrlBuf, TxBuf, EventBuf, UniBuf, St>
where
  St: StreamStore<StreamEntry<'req, ReqBuf>>,
{
  /// Accepts the peer's request, enqueuing the response HEADERS frame on the
  /// (already-registered) request stream, marking the tunnel established, and
  /// enqueuing [`Event::Established`].
  ///
  /// This is the CONNECT **specialization** of the general
  /// [`send_response`](Connection::send_response): it is `send_response(id, response,
  /// last = true)` (the same `write_headers_frame` encode+size-check + final-response
  /// enqueue) PLUS the tunnel establish path — keep the entry `is_tunnel = true`, run
  /// the connection-scoped `establish` (phase → `Open`, push [`Event::Established`],
  /// flush any deferred `peer_fin_pending` as [`Event::PeerClosed`]). `send_response`
  /// instead flips the entry to
  /// `is_tunnel = false` and pushes NO connection event. The error scope rides that
  /// marker: a stream error on the established tunnel is CONNECTION-fatal (one tunnel
  /// = one connection), where a general response stream resets per-stream (RFC 9114
  /// §4.1.2).
  ///
  /// A CONNECT tunnel is established only by a valid `2xx` final response (RFC 9114
  /// §4.4), so — unlike the status-agnostic general `send_response` —`accept_with`
  /// ENFORCES that `response`'s committed `:status` is a `2xx`. The `2xx` check rides
  /// the SAME single-pass `StatusObserver` encode that `send_response` uses to classify
  /// finality: a missing, malformed (not three ASCII digits in `100..=599`), interim
  /// (`1xx`), or non-`2xx` final (`3xx`–`5xx`) `:status` is rejected with
  /// [`Error::Protocol`]`(`[`H3Error::MessageError`]`)` (a local caller bug) BEFORE the
  /// response is committed — the transmit slot is discarded, the tunnel is NOT marked
  /// established, and NO [`Event::Established`] is pushed. To send a non-`2xx` (the
  /// CONNECT request was refused) use [`send_response`](Connection::send_response).
  ///
  /// The preconditions mirror the client's [`open_with`](Connection::open_with)
  /// (QUIC streams are unordered, so the request stream — and this call — can
  /// arrive before the peer's control-stream SETTINGS):
  ///
  /// - [`Error::WouldBlock`] — the server is not ready to respond yet, for either
  ///   of two reasons (pump more inbound bytes through
  ///   [`handle_stream`](Connection::handle_stream) and retry):
  ///   - the peer's CONNECT request HEADERS have not been decoded yet. The request
  ///     stream id is registered (via [`provide_stream`](Connection::provide_stream))
  ///     when the QUIC stream opens, *before* any HEADERS arrive, so registration
  ///     alone is not enough: the server must first see the request as a
  ///     [`Frame::Request`] from `handle_stream`.
  ///   - the peer's SETTINGS have not arrived yet, so the peer's
  ///     `MAX_FIELD_SECTION_SIZE` is not yet known and the response must not be
  ///     sent. This matches `open_with`'s peer-SETTINGS gate; the server has no
  ///     `enable_connect_protocol` opt-in to check (that is client-only).
  /// - [`Error::Closed`] after the tunnel has begun closing (a prior
  ///   [`close`](Connection::close) or a peer reset via
  ///   [`handle_stream_reset`](Connection::handle_stream_reset)).
  /// - [`Error::FieldSectionTooLarge`] if the response's decoded field-section
  ///   size exceeds the peer's advertised `MAX_FIELD_SECTION_SIZE` (RFC 9114
  ///   §4.2.2 / §7.2.4.1), enforced in the single encode+measure pass exactly as
  ///   `open_with` enforces it for the request. Our own client advertises no
  ///   limit, so this never fires against our peers, but it is enforced against
  ///   real ones.
  /// - [`Error::Protocol`]`(`[`H3Error::MessageError`]`)` if the committed `:status`
  ///   is not a valid `2xx` (missing / malformed / interim / non-`2xx` final — see
  ///   above): a CONNECT acceptance must be a `2xx`. Nothing is committed.
  ///
  /// On success the response HEADERS frame is enqueued, the tunnel is marked
  /// established, and [`Event::Established`] is pushed — only on success, so an
  /// over-limit, unsendable, or non-`2xx` response commits nothing. The response is
  /// sent exactly once: a repeat `accept_with` after a successful one is a no-op
  /// `Ok(())` (no second HEADERS, no second `Established`), mirroring the client's
  /// exactly-once `request_sent` guard. A single CONNECT phase carries exactly one
  /// response HEADERS, so re-sending it would be a protocol violation.
  pub fn accept_with<H: Headers + ?Sized>(&mut self, response: &H) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    // Reconcile any deferred stream-scoped reset FIRST (as the general send guards do).
    // `request_id` is NOT provably un-condemned: in `Mode::General` the first inbound
    // request still becomes `request_id` yet is registered NON-tunnel (`is_tunnel =
    // false`), so a stream-scoped error on it (e.g. premature DATA in a dropped `Frames`)
    // records a pending reset for `request_id`. Reconciling frees that condemned entry and
    // clears `request_id`, so `guard_accept` below then reads it as not-yet-observed and
    // returns `WouldBlock` — `accept_with` cannot report `Established` for a stream that
    // `poll_transmit` will reset. (A tunnel-mode `request_id` is `is_tunnel = true`, whose
    // errors fail the connection instead of recording a reset, so this no-ops there.)
    self.reconcile_pending_resets();
    let (id, limit) = match self.guard_accept()? {
      SendGuard::AlreadyDone => return Ok(()),
      SendGuard::Proceed(resolved) => resolved,
    };
    // The committed `:status` is the source of truth for whether this is a CONNECT
    // acceptance, NOT the caller's word: a CONNECT tunnel is established only by a valid
    // `2xx` final response (RFC 9114 §4.4). The `StatusObserver` records the first
    // `:status`'s class DURING the single encode pass that produces the bytes — so the
    // bytes committed and the acceptance decision come from ONE pass, exactly as
    // `send_response` derives interim-vs-final. A missing / malformed / interim (`1xx`)
    // / non-`2xx` final (`3xx`–`5xx`) `:status` makes the fill closure return `Err`, so
    // the transmit slot is discarded BEFORE commit: nothing reaches the wire, and the
    // `is_tunnel` / `FinalSent` / `establish()` transitions below are NOT reached (no
    // `Event::Established`).
    let observer = StatusObserver::new(response);
    self
      .tx
      .enqueue(StreamKind::Existing(id), false, |out| {
        // Encode + size-check in ONE traversal (see `open_with`): a too-large section
        // errors here and discards the slot.
        let frame_len = write_headers_frame(out, &observer, limit)?;
        // The recorded class now reflects the EXACT encoded section. Reject anything but
        // a valid `2xx` — discarding this slot.
        observer.require_2xx()?;
        Ok(frame_len)
      })
      .map_err(map_tx)?;
    // The slot is committed (the closure returned `Ok` only after `require_2xx`
    // succeeded), so this re-read cannot diverge from the committed bytes.
    observer.require_2xx()?;
    // Confirm the tunnel slot's entry as the CONNECT tunnel: `accept_with` is the
    // tunnel-establishing path, so its entry is `is_tunnel = true` regardless of the
    // connection [`Mode`] that classified it at `provide_stream` time (`Tunnel` ⇒ `true`
    // already; `General` ⇒ `false`, re-asserted to `true` here — accepting a CONNECT
    // makes this stream the tunnel). The marker keeps the entry's establishment
    // connection-scoped (matching the `Event::Established` this enqueues) and feeds the
    // per-stream-vs-connection reset split (a tunnel error is connection-fatal). The
    // general `send_response` path instead clears it.
    if let Some(entry) = self.streams.get_mut(id) {
      entry.is_tunnel = true;
      // The CONNECT 2xx IS this stream's FINAL response: move the send half to `FinalSent`
      // so tunnel DATA / FIN may now flow (`send_data` / `finish`). Without this the
      // tunnel's own body would be rejected as premature by `guard_send_on`.
      entry.send = SendState::FinalSent;
    }
    // The single `Handshaking → Open` transition: flips the phase and enqueues
    // `Event::Established` exactly once — only after the response is committed.
    self.establish();
    Ok(())
  }

  /// Sends a response HEADERS frame on the request stream `id`, the GENERAL
  /// (non-CONNECT) server response entry point.
  ///
  /// `id` must name a known request stream the server has OBSERVED as a
  /// [`Frame::Request`] (registered via [`provide_stream`](Connection::provide_stream)
  /// and seen via [`handle_stream`](Connection::handle_stream)). The `:status` is the
  /// driver's to choose; the core stays status-agnostic.
  ///
  /// Interim vs final is derived from the response's `:status`, NOT from `last`: the
  /// SAME classifier the connection applies to a CLIENT's RECEIVED response
  /// ([`validate::status_class_is_interim`]) decides it here — `1xx` ⇒ interim, `2xx`–`5xx`
  /// ⇒ final. `last` is kept in the signature but treated as a CHECKED ASSERTION the
  /// caller makes about that class: it must equal the derived finality (`last == true` for
  /// a final `:status`, `last == false` for an interim), or the call is a caller bug and
  /// is rejected with [`Error::Protocol`]`(`[`H3Error::MessageError`]`)` — so a
  /// `send_response(:status 200, last = false)` or `(:status 103, last = true)` can never
  /// put a misclassified response on the wire. A response with no `:status`, or a
  /// non-numeric / out-of-range one, is likewise [`H3Error::MessageError`] (it cannot be
  /// classified).
  ///
  /// - **Interim** (`1xx`): more responses follow, the stream is NOT marked established,
  ///   and no body may flow yet (`SendState::Idle` is unchanged).
  /// - **Final** (`2xx`–`5xx`): the per-stream entry is marked `established` (gating
  ///   yielding [`Frame::Data`] on this stream) and its `SendState` moves to
  ///   `SendState::FinalSent` (response body / trailers / FIN may now follow).
  ///
  /// The legal server response sequence is enforced (RFC 9114 §4.1.2): zero or more
  /// interim responses (`SendState::Idle`), then exactly ONE final response. A second
  /// `send_response` of EITHER kind after the final (`SendState::FinalSent` /
  /// `SendState::TrailersSent`), or any `send_response` after [`finish`](Connection::finish)
  /// closed the local send half (`SendState::Closed`), is rejected with
  /// [`Error::Protocol`]`(`[`H3Error::FrameUnexpected`]`)` (a local refusal — the
  /// connection stays live).
  ///
  /// **No connection event.** Unlike the CONNECT-tunnel
  /// [`accept_with`](Connection::accept_with), `send_response` pushes NO
  /// [`Event::Established`]: [`Event`]s are connection-scoped, and a general request
  /// stream is not connection-scoped. Per-stream lifecycle is surfaced through
  /// [`Frames`] and these return values; `Event::Established` stays the
  /// CONNECT-tunnel-only signal. `send_response` also does NOT change the connection
  /// phase (it stays whatever the connection-level lifecycle set it to).
  ///
  /// Returns:
  /// - [`Error::WouldBlock`] — the request on `id` has not been observed yet, the
  ///   peer's SETTINGS have not arrived (its `MAX_FIELD_SECTION_SIZE` is unknown), or
  ///   the transmit ring is momentarily full (drain it with
  ///   [`poll_transmit`](Connection::poll_transmit) and retry).
  /// - [`Error::Closed`] — the connection is closing/failed, or setup has not run.
  /// - [`Error::Protocol`]`(`[`H3Error::FrameUnexpected`]`)` — an out-of-sequence
  ///   response: a second response after the final one, or any response after
  ///   [`finish`](Connection::finish) (see the sequence rule above).
  /// - [`Error::Protocol`]`(`[`H3Error::MessageError`]`)` — the response cannot be
  ///   classified or `last` contradicts the `:status` class (see the derivation above).
  /// - [`Error::FieldSectionTooLarge`] — the response's decoded field-section size
  ///   exceeds the peer's advertised `MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2),
  ///   enforced in the single encode+measure pass exactly as `accept_with` does.
  pub fn send_response<H: Headers + ?Sized>(
    &mut self,
    id: StreamId,
    headers: &H,
    last: bool,
  ) -> Result<(), Error>
  where
    TxBuf: AsMut<[u8]>,
    EventBuf: AsMut<[Option<Event>]>,
  {
    // The guard materializes any deferred stream-scoped reset first, so a stream
    // condemned for reset (e.g. a malformed General-mode request) is gone before the
    // response can be enqueued — see `guard_send_response`. It also rejects a response
    // out of sequence (after the final, or after `finish`).
    let limit = self.guard_send_response(id)?;
    // Finality is DERIVED from the `:status` of the field section ACTUALLY ENCODED,
    // NOT taken from `last` and NOT from a separate traversal: the `StatusObserver`
    // records the first `:status`'s class DURING the single encode pass that produces
    // the bytes, so the bytes committed and the finality decision come from one pass.
    // `last` is asserted to match that recorded class. A misclassified / unclassifiable
    // response, or a `last` that contradicts the encoded class, makes the fill closure
    // return `Err` so the transmit slot is discarded BEFORE commit — nothing reaches
    // the wire and the `established` / `SendState` transition below is NOT reached.
    let observer = StatusObserver::new(headers);
    self
      .tx
      .enqueue(StreamKind::Existing(id), false, |out| {
        // Encode + size-check in ONE traversal (see `accept_with` / `open_with`);
        // a too-large section errors here and discards the slot.
        let frame_len = write_headers_frame(out, &observer, limit)?;
        // The class now reflects the EXACT encoded section. Reject an unclassifiable
        // `:status` or a `last` that contradicts it — both discard this slot.
        let interim = observer.finality()?;
        if last == interim {
          // `last` contradicts the `:status` class: a final status with `last = false`,
          // or an interim status with `last = true`. A caller bug — refuse without
          // sending (returning `Err` from `fill` discards the reserved slot).
          return Err(Error::Protocol(H3Error::MessageError));
        }
        Ok(frame_len)
      })
      .map_err(map_tx)?;
    // The slot is committed: re-read the class the encode pass recorded to drive the
    // state transition. It is `Some(Some(_))` (the closure returned `Ok` only after
    // `finality()` succeeded), so this cannot diverge from the committed bytes.
    let interim = observer.finality()?;
    // Responding via the GENERAL path marks the entry NON-tunnel (`is_tunnel = false`):
    // committing to a general response is what makes the stream general — a later stream
    // error then resets just this stream rather than failing the connection (RFC 9114
    // §4.1.2). This is also what made the entry general in `Mode::Tunnel` (the default,
    // where `provide_stream` registered it `true`); in `Mode::General` it was already
    // `false`, so this is a no-op re-assert. `accept_with` is the tunnel path and keeps it
    // `true`. The FINAL response also marks the entry established (gating `Frame::Data`)
    // but pushes NO connection `Event` — general streams are not connection-scoped (see
    // the doc above); an interim response leaves it unestablished. A missing entry was
    // already rejected by the guard.
    if let Some(entry) = self.streams.get_mut(id) {
      entry.is_tunnel = false;
      if !interim {
        entry.established = true;
        // The FINAL response leading section is now SENT: move the send half to `FinalSent`
        // so response body / trailers / FIN may follow (`send_data_on` / `send_trailers` /
        // `finish`). An interim response leaves it `Idle` — a body before the FINAL response
        // would be premature DATA (RFC 9114 §4.1).
        entry.send = SendState::FinalSent;
      }
    }
    Ok(())
  }

  /// The preconditions for [`send_response`](Self::send_response). Returns the
  /// resolved `MAX_FIELD_SECTION_SIZE` limit, or the appropriate `Err`. Like
  /// [`guard_accept`](Self::guard_accept) it gates on a non-terminal post-setup
  /// phase, the request being OBSERVED on `id`, and the peer's SETTINGS — but it is
  /// per-`id` (not the single tunnel slot) and has no exactly-once short-circuit
  /// (interim 1xx then final responses are several `send_response` calls).
  ///
  /// Materializes a deferred stream-scoped reset FIRST (`apply_pending_reset`), so a
  /// stream condemned by a `Frames` carrier is removed from `streams` before the
  /// `observed` read — its `id` then reads as not-yet-observed (`Error::WouldBlock`), so
  /// a condemned stream is never responded on. A malformed request is also never marked
  /// `observed` (the flip runs only AFTER validation), so the two defenses compose.
  ///
  /// Enforces the SERVER leading-HEADERS sequence (RFC 9114 §4.1.2: zero or more interim
  /// 1xx, then exactly one final response) via the stream's [`SendState`]: a response is
  /// legal only from [`SendState::Idle`] (no final response yet — the start state and the
  /// state across interim responses). Once the FINAL response has been sent
  /// ([`SendState::FinalSent`]), or trailers / FIN have followed it
  /// ([`SendState::TrailersSent`] / [`SendState::Closed`]), a further `send_response` —
  /// interim OR final — is a placement violation
  /// [`Error::Protocol`]`(`[`H3Error::FrameUnexpected`]`)` (no second leading section after
  /// the final, none after the FIN). A DEFINITIVE refusal (the connection stays live),
  /// distinct from the retriable `WouldBlock` readiness gates. Several interim responses
  /// before the first final stay allowed (each leaves the state [`SendState::Idle`]).
  fn guard_send_response(&mut self, id: StreamId) -> Result<Option<u64>, Error>
  where
    TxBuf: AsMut<[u8]>,
  {
    self.reconcile_pending_resets();
    match self.phase {
      // Terminal, or setup not yet run: the response must not be sent.
      Phase::Closing | Phase::Failed | Phase::Created => Err(Error::Closed),
      Phase::Handshaking | Phase::Open => {
        // The request on `id` must be observed first (registration alone is not
        // enough); a missing entry reads as not-yet-observed.
        let Some(entry) = self.streams.get(id) else {
          return Err(Error::WouldBlock);
        };
        if !entry.observed {
          return Err(Error::WouldBlock);
        }
        // A response is the FIRST/interim leading section: legal only from `Idle`. Any
        // later send-state (the final sent, trailers/FIN after it) rejects a further
        // response — no second leading section after the final, none after the FIN.
        if entry.send != SendState::Idle {
          return Err(Error::Protocol(H3Error::FrameUnexpected));
        }
        // The peer's SETTINGS gate the response for its `MAX_FIELD_SECTION_SIZE`.
        let settings = self.settings_peer.ok_or(Error::WouldBlock)?;
        Ok(settings.max_field_section_size())
      }
    }
  }

  /// The single source of truth for `accept_with`'s preconditions. Returns the
  /// resolved `(request stream id, field-size limit)` to proceed,
  /// [`SendGuard::AlreadyDone`] for the idempotent already-responded case, or the
  /// appropriate `Err`. Mirrors [`guard_open`](Self::guard_open): the phase decides
  /// the terminal / not-started / already-done cases; the data markers decide
  /// readiness.
  fn guard_accept(&self) -> Result<SendGuard<(StreamId, Option<u64>)>, Error> {
    match self.phase {
      // The response is sent exactly once: an established server responded already,
      // so a repeat is a no-op `Ok` (no second HEADERS, no second `Established`).
      Phase::Open => Ok(SendGuard::AlreadyDone),
      // Terminal: a prior `close()` / reset / fatal error takes precedence over the
      // readiness gates, so a closing server reports `Closed`, not `WouldBlock`.
      Phase::Closing | Phase::Failed => Err(Error::Closed),
      // Setup (control + SETTINGS) must precede the response: a response ahead of
      // `start` would precede our own SETTINGS on the wire (RFC 8441 / RFC 9114).
      Phase::Created => Err(Error::Closed),
      Phase::Handshaking => {
        // The request HEADERS must be decoded before the server responds. The
        // request stream id is registered (via `provide_stream`) the moment the
        // QUIC stream opens — before any HEADERS — so registration alone is not
        // enough; block until `handle_stream` has yielded `Frame::Request` (which
        // sets the tunnel entry's `observed`). Enforces "accept after the request
        // arrives". A missing tunnel slot / entry reads as not-yet-observed.
        let id = self.request_id.ok_or(Error::WouldBlock)?;
        let Some(entry) = self.streams.get(id) else {
          return Err(Error::WouldBlock);
        };
        if !entry.observed {
          return Err(Error::WouldBlock);
        }
        // The CONNECT 2xx is a FINAL leading section: legal only from `Idle`. A non-`Idle`
        // send-state means a final response was already sent on this stream by the general
        // `send_response`, or trailers / a FIN already followed it — a second leading section
        // (here the CONNECT 2xx) is out of sequence. The all-`Open` idempotent repeat is
        // handled above; this catches the mixed general-then-tunnel misuse on the same
        // stream while still in `Handshaking`.
        if entry.send != SendState::Idle {
          return Err(Error::Protocol(H3Error::FrameUnexpected));
        }
        // The peer's SETTINGS gate the response, exactly as in `open_with`: its
        // MAX_FIELD_SECTION_SIZE is checked synchronously at send time. Until it
        // arrives, an unlimited limit could send an over-limit response and commit
        // the tunnel — so block and retry instead.
        let settings = self.settings_peer.ok_or(Error::WouldBlock)?;
        Ok(SendGuard::Proceed((id, settings.max_field_section_size())))
      }
    }
  }
}

/// Writes a single uni-stream type byte (`ty` fits one byte for our types).
fn write_type_byte(out: &mut [u8], ty: u64) -> Result<usize, Error> {
  varint::encode(ty, out).map_err(|_| Error::Protocol(H3Error::FrameError))
}

/// Writes the control stream's preamble: the type byte then a SETTINGS frame.
fn write_control_settings(out: &mut [u8], settings: &Settings) -> Result<usize, Error> {
  // Encode the SETTINGS payload into a small scratch to learn its length.
  let mut payload = [0u8; 32];
  let plen = settings
    .encode_payload(&mut payload)
    .map_err(|_| Error::Protocol(H3Error::SettingsError))?;
  let payload = payload.get(..plen).unwrap_or(&[]);
  // [type byte][SETTINGS frame header][payload].
  let mut at = write_type_byte(out, STREAM_TYPE_CONTROL)?;
  at = write_frame_header(out, at, FrameType::Settings, plen)?;
  copy_into(out, at, payload)
}

/// Bytes reserved at the front of a [`TX_CAP`] workspace for a prepended HEADERS
/// frame header (type + length varints). A QUIC frame header is at most two 8-byte
/// varints (16 bytes); since the field section is encoded into the remaining
/// `TX_CAP - HEADERS_HDR_RESERVE` bytes, its length varint is far smaller than
/// this, so header + field section is guaranteed to fit one transmit slot.
const HEADERS_HDR_RESERVE: usize = CTRL_HDR_CAP;

/// A [`Headers`] adapter that records the FIRST `:status`'s interim/final class
/// (via [`validate::status_class_is_interim`]) as it forwards the supplier's
/// `for_each` to the encoder — so the recorded class comes from the EXACT SAME
/// single traversal that produced the encoded bytes.
///
/// This closes the classify-then-encode gap: a non-replayable / interior-mutable
/// supplier (which the crate already treats as adversarial for outbound HEADERS)
/// could yield one `:status` to a separate classifying traversal and a different
/// one to the encoder. By classifying DURING the encode pass, `send_response`
/// drives its finality decision from the `:status` of the field section it
/// actually commits, never from a stale earlier reading.
///
/// `status` distinguishes "no `:status` seen" (`None`) from "a `:status` seen,
/// classified" (`Some(Option<bool>)`): `Some(Some(interim))` is a valid
/// interim/final, `Some(None)` an unclassifiable value. The first `:status` wins
/// (a duplicate is the validator's concern, not this).
struct StatusObserver<'a, H: Headers + ?Sized> {
  inner: &'a H,
  /// The first `:status`'s interim classification, recorded during the single encode
  /// pass: outer `None` = no `:status` seen; `Some(None)` = a `:status` that is not a
  /// valid `1xx`–`5xx`; `Some(Some(interim))` = a valid code's interim flag.
  status: core::cell::Cell<Option<Option<bool>>>,
  /// Whether that first `:status` is a valid `2xx`, recorded in the SAME pass so the
  /// CONNECT-acceptance check (`is_2xx`) and the interim check (`finality`) both come
  /// from the bytes actually encoded. `false` until a `2xx` `:status` is seen.
  is_2xx: core::cell::Cell<bool>,
}

impl<'a, H: Headers + ?Sized> StatusObserver<'a, H> {
  const fn new(inner: &'a H) -> Self {
    Self {
      inner,
      status: core::cell::Cell::new(None),
      is_2xx: core::cell::Cell::new(false),
    }
  }

  /// The recorded finality of the encoded section: `Ok(true)` interim (`1xx`),
  /// `Ok(false)` final (`2xx`–`5xx`). A section with no `:status`, or a `:status`
  /// that is not exactly three ASCII digits in `100..=599`, is unclassifiable and
  /// rejected as [`Error::Protocol`]`(`[`H3Error::MessageError`]`)` (a malformed
  /// response — a local caller bug). Read only AFTER the encode pass has run.
  fn finality(&self) -> Result<bool, Error> {
    match self.status.get() {
      Some(Some(interim)) => Ok(interim),
      Some(None) | None => Err(Error::Protocol(H3Error::MessageError)),
    }
  }

  /// Whether the encoded section's first `:status` is a valid `2xx` — the CONNECT
  /// acceptance check (RFC 9114 §4.4): a tunnel is established only by a `2xx` final
  /// response. A missing / malformed / interim (`1xx`) / non-`2xx` final (`3xx`–`5xx`)
  /// `:status` is NOT a CONNECT acceptance and is rejected as
  /// [`Error::Protocol`]`(`[`H3Error::MessageError`]`)`. Read only AFTER the encode
  /// pass has run. The recorded `2xx` bit is meaningful only once a `:status` was seen,
  /// so this also requires the outer `status` to be set (a no-`:status` response leaves
  /// `is_2xx` at its `false` default and so is rejected here too).
  fn require_2xx(&self) -> Result<(), Error> {
    if self.status.get().is_some() && self.is_2xx.get() {
      Ok(())
    } else {
      Err(Error::Protocol(H3Error::MessageError))
    }
  }
}

impl<H: Headers + ?Sized> Headers for StatusObserver<'_, H> {
  fn for_each(&self, f: &mut dyn FnMut(&str, &str)) -> Result<(), Error> {
    self.inner.for_each(&mut |name, value| {
      if name == ":status" && self.status.get().is_none() {
        self
          .status
          .set(Some(validate::status_class_is_interim(value)));
        self.is_2xx.set(validate::status_is_2xx(value));
      }
      f(name, value);
    })
  }
}

/// Writes a HEADERS frame (`[header][QPACK field section]`) for `headers` into
/// `out`, enforcing the peer's `MAX_FIELD_SECTION_SIZE` (`limit`, when advertised)
/// in the SAME traversal that encodes the bytes.
///
/// The field section is encoded once via [`qpack::encode_field_section_from`] into
/// a workspace sized to the transmit slot ([`TX_CAP`], less a small reserve for
/// the prepended frame header), which BOTH writes the bytes AND bounds the RFC
/// 9114 §4.2.2 decoded size against `limit` in a single [`Headers::for_each`]
/// pass. The size check happens inside that pass, *before* and independent of any
/// output-buffer exhaustion, so:
///
/// - a section whose decoded size exceeds the peer's `limit`
///   ([`qpack::EncodeError::TooLarge`]), AND
/// - a section that overflows the local encode workspace
///   ([`qpack::EncodeError::BufferExhausted`] — too large for us to send)
///
/// BOTH map to the LOCAL [`Error::FieldSectionTooLarge`] refusal — never to a peer
/// protocol error such as `QPACK_DECOMPRESSION_FAILED`. On either, this returns
/// WITHOUT writing the frame header, so the caller's transmit slot is discarded
/// (never committed) and `request_sent` / `established` stay false. Only a genuine
/// encoder fault ([`qpack::EncodeError::Qpack`]) or a supplier error surfaces as a
/// protocol/driver error. A non-replayable / interior-mutable [`Headers`] supplier
/// therefore cannot be measured in one pass and encoded differently in another.
fn write_headers_frame<H: Headers + ?Sized>(
  out: &mut [u8],
  headers: &H,
  limit: Option<u64>,
) -> Result<usize, Error> {
  // Encode the field section directly into the transmit slot after a worst-case
  // frame-header gap. Once the real header length is known, the field section is
  // moved down in-place. This keeps the single encode+measure pass but avoids a
  // separate TX_CAP stack scratch and a scratch-to-slot copy.
  let max_decoded = limit.map(|l| usize::try_from(l).unwrap_or(usize::MAX));
  let (fs_len, _decoded_size) = {
    let workspace = out.get_mut(HEADERS_HDR_RESERVE..).ok_or(too_large())?;
    match qpack::encode_field_section_from(headers, workspace, max_decoded) {
      Ok(out) => out,
      // Both "over the peer's limit" and "too large for the local workspace" are a
      // LOCAL refusal, not a peer protocol error.
      Err(qpack::EncodeError::TooLarge | qpack::EncodeError::BufferExhausted) => {
        return Err(Error::FieldSectionTooLarge);
      }
      Err(qpack::EncodeError::Qpack(e)) => return Err(Error::Protocol(e.to_h3())),
      Err(qpack::EncodeError::Supplier(e)) => return Err(e),
    }
  };
  let at = write_frame_header(out, 0, FrameType::Headers, fs_len)?;
  if at > HEADERS_HDR_RESERVE {
    return Err(too_large());
  }
  let src_end = HEADERS_HDR_RESERVE.checked_add(fs_len).ok_or(too_large())?;
  let frame_len = at.checked_add(fs_len).ok_or(too_large())?;
  out.get(..src_end).ok_or(too_large())?;
  out.get(..frame_len).ok_or(too_large())?;
  if at < HEADERS_HDR_RESERVE && fs_len != 0 {
    out.copy_within(HEADERS_HDR_RESERVE..src_end, at);
  }
  Ok(frame_len)
}

/// Writes a DATA frame (`[header][payload]`) for `payload` — the bare-tier path
/// that copies the whole framed DATA into one transmit slot (no refcounted body).
#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
fn write_data_frame(out: &mut [u8], payload: &[u8]) -> Result<usize, Error> {
  let at = write_frame_header(out, 0, FrameType::Data, payload.len())?;
  copy_into(out, at, payload)
}

/// Writes ONLY a DATA frame header (type + length varints) for a body of
/// `body_len` bytes — the heap-tier vectored path, whose body segment is the held
/// [`DataBuf`](crate::backend::DataBuf) and so is never copied into the ring.
#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
fn write_data_header(out: &mut [u8], body_len: usize) -> Result<usize, Error> {
  write_frame_header(out, 0, FrameType::Data, body_len)
}

/// Writes a frame header of `(ty, length)` at `out[at..]`, returning the new
/// offset.
fn write_frame_header(
  out: &mut [u8],
  at: usize,
  ty: FrameType,
  length: usize,
) -> Result<usize, Error> {
  let dst = out.get_mut(at..).ok_or(too_large())?;
  let len64 = u64::try_from(length).map_err(|_| too_large())?;
  let n = frame::encode_header(ty, len64, dst).map_err(|_| too_large())?;
  at.checked_add(n).ok_or(too_large())
}

/// Copies `src` into `out[at..]`, returning the index just past it. A `src` that
/// does not fit is a too-large (capacity-exceeded) error.
fn copy_into(out: &mut [u8], at: usize, src: &[u8]) -> Result<usize, Error> {
  let end = at.checked_add(src.len()).ok_or(too_large())?;
  let dst = out.get_mut(at..end).ok_or(too_large())?;
  dst.copy_from_slice(src);
  Ok(end)
}

/// The error for a transmit whose framed bytes exceed [`TX_CAP`].
fn too_large() -> Error {
  Error::Protocol(H3Error::FrameError)
}

/// Maps a transmit-ring enqueue error to a connection [`Error`]. A full ring is
/// retriable ([`Error::WouldBlock`] — drain with `poll_transmit` and retry); an
/// oversized frame (a single frame exceeding [`TX_CAP`]) surfaces from `fill` as
/// the too-large protocol error.
fn map_tx(e: TxError<Error>) -> Error {
  match e {
    TxError::Full => Error::WouldBlock,
    TxError::Fill(inner) => inner,
  }
}

/// Whether `role` is a critical stream (a control or QPACK encoder/decoder
/// stream, either direction): closing one is `H3_CLOSED_CRITICAL_STREAM` and a
/// duplicate is `H3_STREAM_CREATION_ERROR` (RFC 9114 §6.2.1). The request stream
/// is not critical in this sense (its FIN ends the tunnel).
const fn is_critical_role(role: StreamRole) -> bool {
  matches!(
    role,
    StreamRole::ControlIn
      | StreamRole::ControlOut
      | StreamRole::QpackEncIn
      | StreamRole::QpackEncOut
      | StreamRole::QpackDecIn
      | StreamRole::QpackDecOut
  )
}

/// Classifies an inbound uni-stream type code into the [`UniRole`] we track, or
/// [`UniRole::Ignored`] for a GREASE / unknown stream type.
///
/// The push stream type (0x01) is a KNOWN type, not GREASE: since we never enable
/// server push (we never send `MAX_PUSH_ID`, so the max push id stays 0),
/// receiving one is [`H3Error::IdError`] (RFC 9114 §6.2.2 / §7.2.7), not an
/// ignored stream.
const fn classify_stream_type(ty: u64) -> Result<UniRole, H3Error> {
  Ok(match ty {
    STREAM_TYPE_CONTROL => UniRole::ControlIn,
    STREAM_TYPE_PUSH => return Err(H3Error::IdError),
    STREAM_TYPE_QPACK_ENC => UniRole::QpackEncIn,
    STREAM_TYPE_QPACK_DEC => UniRole::QpackDecIn,
    _ => UniRole::Ignored,
  })
}

/// The inverse of [`StreamRole::index`].
const fn role_from_index(i: usize) -> Option<StreamRole> {
  Some(match i {
    0 => StreamRole::ControlOut,
    1 => StreamRole::ControlIn,
    2 => StreamRole::QpackEncOut,
    3 => StreamRole::QpackEncIn,
    4 => StreamRole::QpackDecOut,
    5 => StreamRole::QpackDecIn,
    6 => StreamRole::Request,
    _ => return None,
  })
}

const _: () = assert!(TX_CAP > 16, "a transmit slot must hold a frame header");

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod tests;
