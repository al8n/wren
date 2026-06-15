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
//! A [`Connection<Client>`] opens the tunnel ([`open_with`](Connection::open_with));
//! a [`Connection<Server>`] starts its endpoint ([`start`](Connection::start))
//! and accepts the request ([`accept_with`](Connection::accept_with)). Both
//! exchange a control stream (carrying SETTINGS) and a pair of idle QPACK
//! streams (the dynamic table is disabled), then the bidirectional request
//! stream carries the CONNECT HEADERS exchange followed by the DATA tunnel.
//!
//! # Scope
//!
//! The core stays HTTP-status- and WebSocket-agnostic: it reports the peer's
//! HEADERS as a [`Frame::Request`] / [`Frame::Response`] and lets the driver
//! validate the `:status` / `:protocol`. "Established" here means the CONNECT
//! HEADERS exchange completed, not that any particular status was seen.

mod queue;

use core::marker::PhantomData;

use queue::{BoundedQueue, TX_CAP, TxError, TxRing};

use crate::{
  Error, HeaderSet,
  error::H3Error,
  event::{Event, ROLE_COUNT, StreamId, StreamKind, StreamRole, Transmit},
  frame::{self, FrameType},
  headers::Headers,
  qpack,
  settings::Settings,
  stream::{RequestStream, StreamItem},
  varint,
};

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
/// The uni-stream type byte for the QPACK encoder stream (RFC 9204 §4.2).
const STREAM_TYPE_QPACK_ENC: u64 = 0x02;
/// The uni-stream type byte for the QPACK decoder stream (RFC 9204 §4.2).
const STREAM_TYPE_QPACK_DEC: u64 = 0x03;

/// Capacity for accumulating the peer control stream's SETTINGS frame (the
/// stream-type byte plus a small SETTINGS frame). Bounded; an oversized
/// SETTINGS frame is rejected.
const CTRL_CAP: usize = 64;

/// The number of inbound uni streams whose leading type varint may be mid-parse
/// at once (peer control + 2 QPACK = 3; a little headroom for GREASE).
const UNI_PENDING_N: usize = 4;

/// A decoded frame yielded by [`Frames`]: the peer's CONNECT HEADERS or a chunk
/// of tunnel DATA. Borrows the `handle_stream` scratch/input and is invalidated
/// by the next [`Frames::next`].
#[derive(derive_more::IsVariant)]
#[non_exhaustive]
pub enum Frame<'a> {
  /// The peer's request HEADERS (server side): the CONNECT field section.
  Request(HeaderSet<'a>),
  /// The peer's response HEADERS (client side): the CONNECT response field section.
  Response(HeaderSet<'a>),
  /// A chunk of DATA-frame payload (tunnel bytes).
  Data(&'a [u8]),
}

/// A lending iterator over the [`Frame`]s a single
/// [`handle_stream`](Connection::handle_stream) call produced.
///
/// Only the request stream yields frames; for all other streams this is empty.
/// Each [`Frame`] borrows the call's input/scratch and is invalidated by the
/// next [`next`](Frames::next).
pub struct Frames<'a> {
  inner: Option<RequestFrames<'a>>,
}

/// The request-stream branch of [`Frames`]: wraps the inbound [`RequestStream`]
/// item iterator and tags each item as a request or response per our role.
struct RequestFrames<'a> {
  items: crate::stream::Items<'a>,
  is_client: bool,
  /// Client-only: the side effect to run exactly once when the first response
  /// HEADERS is actually decoded — flip `established` and enqueue
  /// [`Event::Established`]. `None` on the server (it flips in `accept_with`) and
  /// once the flip has happened. Holds disjoint borrows of the connection's
  /// `established` flag and event queue (separate fields from the request FSM).
  on_first_response: Option<EstablishOnResponse<'a>>,
}

/// The disjoint-field borrows needed to mark a client tunnel established the
/// moment its first response HEADERS is decoded (see [`RequestFrames`]).
struct EstablishOnResponse<'a> {
  established: &'a mut bool,
  events: &'a mut BoundedQueue<Event, 8>,
}

impl Frames<'_> {
  /// An empty frame iterator (non-request streams produce no frames).
  const fn empty() -> Self {
    Self { inner: None }
  }

  /// The next decoded frame, or `Ok(None)` when the fed bytes are exhausted.
  ///
  /// The returned [`Frame`] borrows the `handle_stream` input (`Data`) or its
  /// scratch (`Request` / `Response`) and is invalidated by the next call.
  // A lending iterator (each `Frame` borrows `self`), so `Iterator` cannot be
  // implemented; mirrors `qpack::FieldLines` and `stream::Items`.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Result<Option<Frame<'_>>, H3Error> {
    let Some(rf) = self.inner.as_mut() else {
      return Ok(None);
    };
    match rf.items.next()? {
      None => Ok(None),
      Some(StreamItem::Headers(hs)) => {
        if rf.is_client {
          // The client tunnel is established at the first *decoded* response
          // HEADERS (not on entry), so a split or partial response cannot flip
          // it early. Exactly once: `take` clears the carrier.
          if let Some(eff) = rf.on_first_response.take() {
            *eff.established = true;
            let _ = eff.events.push(Event::Established);
          }
          Ok(Some(Frame::Response(hs)))
        } else {
          Ok(Some(Frame::Request(hs)))
        }
      }
      Some(StreamItem::Data(chunk)) => Ok(Some(Frame::Data(chunk))),
    }
  }
}

/// One inbound uni stream whose leading type varint has not yet completed.
#[derive(Clone, Copy)]
struct UniPending {
  id: StreamId,
  buf: [u8; 8],
  len: usize,
}

/// The number of GREASE / unknown inbound uni streams we remember in order to
/// keep discarding their bytes (RFC 9114 §6.2 / §9: ignore unknown stream types).
const IGNORED_N: usize = 4;

/// The result of classifying a new inbound uni stream's leading type varint.
enum UniClass {
  /// A known stream type, registered under this role.
  Role(StreamRole),
  /// A GREASE / unknown stream type; its bytes are discarded.
  Ignored,
}

/// The HTTP/3 Extended-CONNECT tunnel connection state machine.
///
/// Parameterized by the [`Role`] ([`Client`] or [`Server`]). See the
/// [module docs](self) for the lifecycle.
pub struct Connection<Ro> {
  settings_local: Settings,
  settings_peer: Option<Settings>,
  request: Option<RequestStream>,
  request_id: Option<StreamId>,
  /// Role → stream id (the registered streams; index by [`StreamRole::index`]).
  roles: [Option<StreamId>; ROLE_COUNT],
  /// Accumulated bytes of the peer control stream's leading SETTINGS frame.
  ctrl_buf: [u8; CTRL_CAP],
  ctrl_len: usize,
  /// Whether the peer's SETTINGS frame has been parsed (only the first counts).
  settings_done: bool,
  /// Inbound uni streams whose type varint is mid-parse.
  uni_pending: [Option<UniPending>; UNI_PENDING_N],
  /// GREASE / unknown inbound uni streams whose bytes we discard.
  ignored: [Option<StreamId>; IGNORED_N],
  events: BoundedQueue<Event, 8>,
  tx: TxRing,
  established: bool,
  closing: bool,
  _ro: PhantomData<fn() -> Ro>,
}

impl<Ro: Role> Default for Connection<Ro> {
  fn default() -> Self {
    Self::new()
  }
}

impl<Ro: Role> Connection<Ro> {
  /// A fresh connection in the role `Ro`, with our local settings selected and
  /// all queues empty. Nothing is sent until [`open_with`](Self::open_with)
  /// (client) or [`start`](Self::start) (server).
  pub fn new() -> Self {
    let settings_local = if Ro::IS_CLIENT {
      Settings::for_client()
    } else {
      Settings::for_server()
    };
    Self {
      settings_local,
      settings_peer: None,
      request: None,
      request_id: None,
      roles: [None; ROLE_COUNT],
      ctrl_buf: [0u8; CTRL_CAP],
      ctrl_len: 0,
      settings_done: false,
      uni_pending: [None; UNI_PENDING_N],
      ignored: [None; IGNORED_N],
      events: BoundedQueue::new(),
      tx: TxRing::new(),
      established: false,
      closing: false,
      _ro: PhantomData,
    }
  }

  /// The peer's settings, once its control-stream SETTINGS frame has been
  /// received and validated.
  pub const fn peer_settings(&self) -> Option<Settings> {
    self.settings_peer
  }

  /// Whether the CONNECT HEADERS exchange has completed (the tunnel is open).
  pub const fn is_established(&self) -> bool {
    self.established
  }

  /// Records a driver-assigned `id` for `role`. The driver calls this for every
  /// stream it opens (after acting on an `OpenUni` / `OpenRequest` transmit) and
  /// for the inbound request stream the peer opens (server side).
  ///
  /// For [`StreamRole::Request`] this also creates the inbound request FSM.
  pub fn provide_stream(&mut self, role: StreamRole, id: StreamId) {
    if let Some(slot) = self.roles.get_mut(role.index()) {
      *slot = Some(id);
    }
    if role.is_request() {
      self.request_id = Some(id);
      if self.request.is_none() {
        self.request = Some(RequestStream::new());
      }
    }
  }

  /// The control-and-SETTINGS transmit, the two idle QPACK uni streams. Shared
  /// by the client `open_with` and the server `start`.
  fn enqueue_setup(&mut self) -> Result<(), Error> {
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

  /// Feeds the peer's control-stream bytes: accumulate, then parse the leading
  /// SETTINGS frame once complete and store the peer settings.
  fn handle_control(&mut self, bytes: &[u8]) -> Result<(), H3Error> {
    if self.settings_done {
      // Control-stream frames after SETTINGS (e.g. GOAWAY) are not modeled by
      // this tunnel core; ignore their bytes rather than misparse them.
      return Ok(());
    }
    let end = self
      .ctrl_len
      .checked_add(bytes.len())
      .ok_or(H3Error::FrameError)?;
    let dst = self
      .ctrl_buf
      .get_mut(self.ctrl_len..end)
      .ok_or(H3Error::FrameError)?;
    dst.copy_from_slice(bytes);
    self.ctrl_len = end;
    self.try_parse_settings()
  }

  /// Attempts to parse a complete SETTINGS frame from the front of `ctrl_buf`.
  /// Leaves the buffer untouched (returns `Ok`) if more bytes are needed.
  fn try_parse_settings(&mut self) -> Result<(), H3Error> {
    let buf = self.ctrl_buf.get(..self.ctrl_len).unwrap_or(&[]);
    let (consumed, hdr) = match frame::decode_header(buf) {
      Ok(v) => v,
      // Header not yet complete: wait for more bytes.
      Err(frame::FrameError::Truncated(_)) => return Ok(()),
      Err(_) => return Err(H3Error::FrameError),
    };
    // The first frame on the control stream MUST be SETTINGS (RFC 9114 §6.2.1).
    if !matches!(hdr.kind(), frame::FrameKind::Settings) {
      return Err(H3Error::MissingSettings);
    }
    let len = usize::try_from(hdr.length()).map_err(|_| H3Error::FrameError)?;
    let payload_end = consumed.checked_add(len).ok_or(H3Error::FrameError)?;
    let payload = match buf.get(consumed..payload_end) {
      Some(p) => p,
      // Payload not fully buffered yet.
      None => return Ok(()),
    };
    let settings = Settings::decode_payload(payload).map_err(|_| H3Error::SettingsError)?;
    self.settings_peer = Some(settings);
    self.settings_done = true;
    Ok(())
  }

  /// Drives the inbound request stream FSM with `bytes`, returning a lending
  /// frame iterator. The client tunnel is marked established (and
  /// [`Event::Established`] enqueued) when the iterator actually yields its first
  /// response HEADERS — not on entry — so a split or partial response cannot flip
  /// it a round early; see [`RequestFrames::on_first_response`].
  fn handle_request<'a>(
    &'a mut self,
    bytes: &'a [u8],
    scratch: &'a mut [u8],
  ) -> Result<Frames<'a>, H3Error> {
    let is_client = Ro::IS_CLIENT;
    // Split-borrow the disjoint fields the first-response side effect needs (the
    // `established` flag and event queue) before the request FSM is borrowed.
    let needs_flip = is_client && !self.established;
    let established = &mut self.established;
    let events = &mut self.events;
    let Some(fsm) = self.request.as_mut() else {
      return Err(H3Error::FrameUnexpected);
    };
    let on_first_response = needs_flip.then_some(EstablishOnResponse {
      established,
      events,
    });
    let items = fsm.handle(bytes, scratch);
    Ok(Frames {
      inner: Some(RequestFrames {
        items,
        is_client,
        on_first_response,
      }),
    })
  }

  /// Handles bytes on a QPACK stream: the type byte is consumed at registration,
  /// so any further bytes are field-section/instruction data, which is a
  /// protocol error because the dynamic table is disabled (RFC 9204 §4.2).
  fn handle_qpack(bytes: &[u8]) -> Result<(), H3Error> {
    if bytes.is_empty() {
      Ok(())
    } else {
      Err(H3Error::QpackDecompressionFailed)
    }
  }

  /// Classifies a new inbound uni stream by its leading type varint, buffering
  /// across calls if it is split. Returns the classification and the offset of
  /// the bytes following the type varint once known, or `None` if more bytes are
  /// needed (the partial varint is retained against `id`).
  ///
  /// A known type is registered in `roles`; a GREASE / unknown type is recorded
  /// in `ignored` so its subsequent bytes are discarded.
  fn classify_uni(
    &mut self,
    id: StreamId,
    bytes: &[u8],
  ) -> Result<Option<(UniClass, usize)>, H3Error> {
    let slot_idx = self.uni_pending_slot(id)?;
    let mut consumed = 0usize;
    loop {
      let pend = self
        .uni_pending
        .get(slot_idx)
        .and_then(Option::as_ref)
        .ok_or(H3Error::StreamCreation)?;
      match varint::decode(pend.buf.get(..pend.len).unwrap_or(&[])) {
        Ok((_, ty)) => {
          let class = self.register_uni(slot_idx, id, ty);
          return Ok(Some((class, consumed)));
        }
        Err(varint::VarintError::Truncated(_)) => {}
        Err(_) => return Err(H3Error::FrameError),
      }
      let Some(&b) = bytes.get(consumed) else {
        // Ran out of input mid-varint; keep the partial for the next call.
        return Ok(None);
      };
      consumed = consumed.saturating_add(1);
      let pend = self
        .uni_pending
        .get_mut(slot_idx)
        .and_then(Option::as_mut)
        .ok_or(H3Error::StreamCreation)?;
      let dst = pend.buf.get_mut(pend.len).ok_or(H3Error::FrameError)?;
      *dst = b;
      pend.len = pend.len.saturating_add(1);
    }
  }

  /// The index of `id`'s pending-uni slot, allocating a free one on first sight.
  fn uni_pending_slot(&mut self, id: StreamId) -> Result<usize, H3Error> {
    if let Some(i) = self
      .uni_pending
      .iter()
      .position(|s| matches!(s, Some(p) if p.id == id))
    {
      return Ok(i);
    }
    let i = self
      .uni_pending
      .iter()
      .position(Option::is_none)
      .ok_or(H3Error::StreamCreation)?;
    if let Some(slot) = self.uni_pending.get_mut(i) {
      *slot = Some(UniPending {
        id,
        buf: [0u8; 8],
        len: 0,
      });
    }
    Ok(i)
  }

  /// Frees the pending slot and registers `id` for its type code, returning the
  /// classification. A known type takes a role slot; an unknown one is ignored.
  fn register_uni(&mut self, slot_idx: usize, id: StreamId, ty: u64) -> UniClass {
    if let Some(slot) = self.uni_pending.get_mut(slot_idx) {
      *slot = None;
    }
    match classify_stream_type(ty) {
      Some(role) => {
        if let Some(r) = self.roles.get_mut(role.index()) {
          *r = Some(id);
        }
        UniClass::Role(role)
      }
      None => {
        if let Some(slot) = self.ignored.iter_mut().find(|s| s.is_none()) {
          *slot = Some(id);
        }
        UniClass::Ignored
      }
    }
  }

  /// Whether `id` is a GREASE / unknown uni stream we are discarding.
  fn is_ignored(&self, id: StreamId) -> bool {
    self.ignored.contains(&Some(id))
  }

  /// The role a registered `id` currently plays, if any.
  fn role_of(&self, id: StreamId) -> Option<StreamRole> {
    self
      .roles
      .iter()
      .position(|s| matches!(s, Some(rid) if *rid == id))
      .and_then(role_from_index)
  }

  /// Routes inbound `bytes` on stream `id` to the right handler.
  ///
  /// - The request stream yields decoded [`Frame`]s (drain the returned
  ///   [`Frames`]).
  /// - The peer control stream's SETTINGS frame is parsed and stored.
  /// - QPACK streams must stay idle past their type byte.
  /// - An unknown id is treated as a new inbound uni stream: its leading type
  ///   varint is parsed (buffered across calls if split) and classified.
  ///
  /// `scratch` backs the request stream's HEADERS decode (see
  /// [`RequestStream::handle`]); it must outlive the returned [`Frames`] and so
  /// shares its lifetime.
  ///
  /// Returns an [`H3Error`] on a connection-fatal protocol violation; the driver
  /// closes the QUIC connection with [`H3Error::code`].
  pub fn handle_stream<'a>(
    &'a mut self,
    id: StreamId,
    bytes: &'a [u8],
    scratch: &'a mut [u8],
  ) -> Result<Frames<'a>, H3Error> {
    // Non-request streams are fully processed here (mutating connection state)
    // and yield no frames; only the request stream's borrow escapes in `Frames`.
    if self.request_id != Some(id) {
      if self.is_ignored(id) {
        return Ok(Frames::empty());
      }
      if let Some(role) = self.role_of(id) {
        self.dispatch_registered(role, bytes)?;
        return Ok(Frames::empty());
      }
      // Unknown id: a new inbound uni stream. Classify its leading type varint.
      match self.classify_uni(id, bytes)? {
        None => return Ok(Frames::empty()), // varint not yet complete
        Some((UniClass::Ignored, _)) => return Ok(Frames::empty()),
        Some((UniClass::Role(role), offset)) => {
          let rest = bytes.get(offset..).unwrap_or(&[]);
          self.dispatch_registered(role, rest)?;
          return Ok(Frames::empty());
        }
      }
    }
    self.handle_request(bytes, scratch)
  }

  /// Routes a registered non-request stream by role. Produces no frames.
  fn dispatch_registered(&mut self, role: StreamRole, bytes: &[u8]) -> Result<(), H3Error> {
    match role {
      StreamRole::ControlIn | StreamRole::ControlOut => self.handle_control(bytes),
      StreamRole::QpackEncIn
      | StreamRole::QpackDecIn
      | StreamRole::QpackEncOut
      | StreamRole::QpackDecOut => Self::handle_qpack(bytes),
      // A registered request id is handled before role lookup; reaching here for
      // Request means no request FSM exists, which is a protocol error.
      StreamRole::Request => Err(H3Error::FrameUnexpected),
    }
  }

  /// Sends a chunk of tunnel payload as an HTTP/3 DATA frame on the request
  /// stream.
  ///
  /// Returns:
  /// - [`Err`]`(`[`Error::Closed`]`)` before the tunnel is established or after
  ///   it has been closed;
  /// - [`Err`]`(`[`Error::WouldBlock`]`)` when the transmit queue is full — drain
  ///   it with [`poll_transmit`](Self::poll_transmit) and retry;
  /// - [`Err`]`(`[`Error::Protocol`]`(`[`H3Error::FrameError`]`))` when the framed
  ///   payload does not fit a single transmit slot (the v1 no-alloc bound).
  pub fn send_data(&mut self, payload: &[u8]) -> Result<(), Error> {
    if !self.established || self.closing {
      return Err(Error::Closed);
    }
    let id = self.request_id.ok_or(Error::Closed)?;
    self
      .tx
      .enqueue(StreamKind::Existing(id), false, |out| {
        write_data_frame(out, payload)
      })
      .map_err(map_tx)
  }

  /// Closes the tunnel: marks it closing and enqueues an empty FIN transmit on
  /// the request stream. Idempotent in effect (a second call simply enqueues
  /// another FIN, which the driver may coalesce).
  pub fn close(&mut self) {
    self.closing = true;
    if let Some(id) = self.request_id {
      // An empty FIN: zero bytes, fin = true. The fill closure writes nothing.
      let _ = self
        .tx
        .enqueue(StreamKind::Existing(id), true, |_out| Ok::<usize, ()>(0));
    }
  }

  /// Records that the peer reset the request stream with application error
  /// `code`: enqueues [`Event::Reset`] and marks the tunnel closing.
  pub fn handle_stream_reset(&mut self, id: StreamId, code: u64) {
    if self.request_id == Some(id) {
      self.closing = true;
      let _ = self.events.push(Event::Reset(code));
    }
  }

  /// Signal the QUIC stream FIN for `id`. For the request stream, a clean end (at
  /// a frame boundary) enqueues [`Event::PeerClosed`]; an end mid-frame enqueues
  /// [`Event::ConnError`]`(`[`H3Error::FrameError`]`)` (RFC 9114 §7.1). FIN on any
  /// other stream is ignored.
  pub fn handle_stream_fin(&mut self, id: StreamId) {
    if Some(id) == self.request_id
      && let Some(req) = self.request.as_ref()
    {
      let ev = match req.fin() {
        Ok(()) => Event::PeerClosed,
        Err(e) => Event::ConnError(e),
      };
      let _ = self.events.push(ev);
    }
  }

  /// The next queued transmit (bytes the driver must write on a QUIC stream),
  /// or `None` if the queue is empty.
  ///
  /// Lending: the returned [`Transmit`] borrows the connection's transmit ring
  /// and is valid until the next `poll_transmit`.
  pub fn poll_transmit(&mut self) -> Option<Transmit<'_>> {
    self.tx.poll()
  }

  /// The next queued connection event, or `None` if the queue is empty.
  pub fn poll_event(&mut self) -> Option<Event> {
    self.events.pop()
  }
}

impl Connection<Client> {
  /// Opens the tunnel: enqueues the control + QPACK setup streams and the
  /// request HEADERS frame (the CONNECT request supplied by `request`).
  ///
  /// The driver pumps [`poll_transmit`](Connection::poll_transmit) afterwards,
  /// opening each requested stream and reporting its id via
  /// [`provide_stream`](Connection::provide_stream).
  pub fn open_with<H: Headers + ?Sized>(&mut self, request: &H) -> Result<(), Error> {
    self.enqueue_setup()?;
    self
      .tx
      .enqueue(StreamKind::OpenRequest, false, |out| {
        write_headers_frame(out, request)
      })
      .map_err(map_tx)
  }
}

impl Connection<Server> {
  /// Starts the server endpoint: enqueues the control + QPACK setup streams.
  /// The server has no request to send until it accepts the peer's.
  pub fn start(&mut self) -> Result<(), Error> {
    self.enqueue_setup()
  }

  /// Accepts the peer's request, enqueuing the response HEADERS frame on the
  /// (already-registered) request stream, marking the tunnel established, and
  /// enqueuing [`Event::Established`].
  ///
  /// The driver validates `response`'s `:status`; the core stays status-agnostic.
  /// Errors with [`Error::Closed`] if no request stream has been registered yet.
  pub fn accept_with<H: Headers + ?Sized>(&mut self, response: &H) -> Result<(), Error> {
    let id = self.request_id.ok_or(Error::Closed)?;
    self
      .tx
      .enqueue(StreamKind::Existing(id), false, |out| {
        write_headers_frame(out, response)
      })
      .map_err(map_tx)?;
    self.established = true;
    let _ = self.events.push(Event::Established);
    Ok(())
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

/// Writes a HEADERS frame (`[header][QPACK field section]`) for `headers`.
fn write_headers_frame<H: Headers + ?Sized>(out: &mut [u8], headers: &H) -> Result<usize, Error> {
  // Encode the field section into a scratch region to learn its length, then
  // prepend the frame header. The field section easily fits this bound for the
  // CONNECT request/response handshakes.
  let mut fs = [0u8; 512];
  let fs_len = qpack::encode_field_section_from(headers, &mut fs)?;
  let fs = fs.get(..fs_len).unwrap_or(&[]);
  let at = write_frame_header(out, 0, FrameType::Headers, fs_len)?;
  copy_into(out, at, fs)
}

/// Writes a DATA frame (`[header][payload]`) for `payload`.
fn write_data_frame(out: &mut [u8], payload: &[u8]) -> Result<usize, Error> {
  let at = write_frame_header(out, 0, FrameType::Data, payload.len())?;
  copy_into(out, at, payload)
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

/// Classifies an inbound uni-stream type code into the peer-side role we track,
/// or `None` for a GREASE / unknown stream type (whose bytes we discard).
fn classify_stream_type(ty: u64) -> Option<StreamRole> {
  Some(match ty {
    STREAM_TYPE_CONTROL => StreamRole::ControlIn,
    STREAM_TYPE_QPACK_ENC => StreamRole::QpackEncIn,
    STREAM_TYPE_QPACK_DEC => StreamRole::QpackDecIn,
    _ => return None,
  })
}

/// The inverse of [`StreamRole::index`].
fn role_from_index(i: usize) -> Option<StreamRole> {
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
