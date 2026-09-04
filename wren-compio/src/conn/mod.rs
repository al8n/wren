//! The WebSocket connection object. No background task: `next()` is the
//! pump — reads, timers, protocol transmits, and (when split) queued writes
//! all progress inside it.
//!
//! Concurrency model (thread-per-core, `!Send`): all state lives in
//! `Rc<RefCell<Inner>>`, and a `RefCell` borrow is NEVER held across an
//! `.await`.
//!
//! Cancellation model: the transport is the poll-based duplex produced by
//! [`IntoDuplex`](crate::IntoDuplex), so every IO future is
//! cancellation-atomic (`Pending` means nothing was consumed, and a
//! transport's in-flight completion operations live inside the adapter, not
//! inside the dropped future). On top of that, the pump moves the stream —
//! and any partially-written batch with its byte cursor — into a [`PumpIo`]
//! guard whose `Drop` puts them back into `Inner`. Dropping `next()` /
//! `send()` mid-await (a caller-side `timeout` or `select!`) therefore
//! neither loses the transport nor loses inbound bytes nor forgets write
//! progress: the next call resumes exactly where the cancelled one stopped.

use std::{
  cell::{Cell, RefCell},
  collections::VecDeque,
  pin::Pin,
  rc::Rc,
  task::Poll,
  time::Instant,
};

use event_listener::Event as Doorbell;
use futures_util::{AsyncReadExt, AsyncWriteExt, FutureExt};
use websocket_proto::{
  Connection, ConnectionConfig, Negotiated,
  connection::{Closed, Event, role},
  frame::CloseCode,
  message::{Message, MessageAssembler},
};
use wren_trace::{debug, trace, warn};

use crate::{
  error::Error,
  into_duplex::Duplex,
  options::{AcceptOptions, ClientOptions},
};

mod split;
pub use split::{ReadHalf, WriteHalf};

/// The masking client role, seeded from OS entropy.
pub type ClientRole = role::Client<rand::rngs::StdRng>;
/// The server role.
pub type ServerRole = role::Server;

const READ_CHUNK: usize = 16 * 1024;
/// Scratch for one protocol-generated frame (control frames are ≤ 131 B;
/// keepalive pings and close frames both fit).
const TRANSMIT_SCRATCH: usize = 256;

/// Delivery state of one queued outbound frame.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum FrameState {
  /// Waiting for the pump.
  Queued,
  /// On the wire.
  Written,
  /// The pump's write failed.
  Failed(std::io::ErrorKind),
  /// The read half was dropped before the pump wrote it.
  Orphaned,
  /// The close handshake completed before the pump wrote it. Not a failure
  /// of the transport and not an abandoned queue: the frame was legal when
  /// it was encoded and the peer's Close overtook it, and §5.5.1 (line 2023
  /// of `.rfc-cache/rfc6455.txt`) leaves nowhere for it to go.
  ClosedBeforeWrite,
}

pub(crate) struct OutboundFrame {
  bytes: Vec<u8>,
  state: Rc<Cell<FrameState>>,
}

/// One coalesced wire batch, with resume state: `cursor` bytes are already
/// on the wire. Lives in `Inner` between polls so a cancelled write picks
/// up where it stopped instead of resending (or never sending) bytes.
pub(crate) struct PendingWrite {
  bytes: Vec<u8>,
  cursor: usize,
  states: Vec<Rc<Cell<FrameState>>>,
  /// The batch contains a Close frame; flushing it discharges
  /// [`Inner::close_owed`]. Set from what the protocol actually drained, so
  /// it describes this batch rather than the connection's intent.
  carries_close: bool,
}

pub(crate) struct Inner<Ro, S> {
  conn: Connection<Instant, Ro>,
  /// `None` only while a [`PumpIo`] guard owns the stream, or after
  /// teardown.
  stream: Option<S>,
  /// **The one inbound vector**: unconsumed bytes at the front, the next
  /// read's window in the space behind them.
  ///
  /// `len` is what has arrived and has not yet been fed to `conn` — the
  /// handshake leftover first, then whatever the last read produced. A read
  /// arms the vector to `len + READ_CHUNK`, fills from `len` on, and truncates
  /// to what it actually got; Phase 1 feeds the whole of it and clears it,
  /// keeping the allocation. It travels into [`PumpIo`] with the stream,
  /// because a read borrows it across an await and the `RefCell` must not be
  /// borrowed there, and comes back on the guard's drop.
  ///
  /// **The retained bound is exactly one `READ_CHUNK` per connection.** It was
  /// TWO: a scratch and a stash, swapped on every read and each resized back
  /// to a full chunk, so a connection that had read once held ~32 KiB across
  /// two vectors — and an oversized handshake leftover was never given back.
  /// Ownership across the await is what needed the buffer moved into the
  /// guard; it never needed a second allocation. Every commit ends with
  /// `shrink_to(READ_CHUNK)`, so a prefix that briefly forced a longer vector
  /// gives the excess back as soon as it drains.
  ///
  /// Because `len` carries that meaning, a read window armed onto the end of
  /// it is NOT input until it is committed — see [`PumpIo::armed`] for the
  /// cancellation rule that keeps the two apart.
  inbound: Vec<u8>,
  /// `inbound` was read while a post-Close write was blocked, so it is
  /// OBSERVATION input: Phase 1 feeds it with data assembly discarded. Set by
  /// the arm that stashed it and consumed by the feed, rather than inferred
  /// from connection state — the mode is a property of where the bytes came
  /// from, not of when they are fed.
  observation_input: bool,
  /// **Nobody will read what these bytes would assemble.** The consumer-side
  /// twin of [`observation_input`](Inner::observation_input): that flag says
  /// WHERE the bytes came from — a read taken behind a blocked post-Close
  /// write — while this one says there is no reader left for the messages
  /// they would become, wherever they came from.
  ///
  /// Set by the unsplit [`WebSocket::close`], which CONSUMES the handle: no
  /// application code can ever call `next()` again, and `close`'s own loop
  /// discards every message the pump hands it. Without this, Phase 4's
  /// ordinary reads during the echo wait went through `handle` — inflating
  /// and assembling in full, up to the message cap, a peer's compressed bomb
  /// that the very next line threw away. Set again wherever
  /// [`read_half_alive`](Inner::read_half_alive) becomes false, which is the
  /// same situation one type over.
  ///
  /// It is NOT set by `WriteHalf::close` on a live split: that half's
  /// `ReadHalf` may keep reading messages after the local Close, and
  /// `Connection::observe`'s own contract — `MessageAbandoned` for a message
  /// in flight — is what covers a message that was mid-assembly when this
  /// flag went up.
  inbound_unread: bool,
  assembler: MessageAssembler,
  /// Completed messages not yet handed out (one input chunk can finish
  /// several).
  ready: VecDeque<Message>,
  outbound: VecDeque<OutboundFrame>,
  /// The in-progress wire batch (see [`PendingWrite`]); `None` when fully
  /// flushed.
  pending_write: Option<PendingWrite>,
  closed: Option<Closed>,
  /// A peer-reported close outcome that may not be published yet: the
  /// peer's Close arrived, but the echo we owe has not flushed. Promoted
  /// into `closed` when the close obligation completes — a clean close
  /// requires our echo on the wire, not just the peer's frame in hand.
  staged_close: Option<Closed>,
  /// `Some(t)` **iff** a Close frame is owed to the wire — queued locally via
  /// `close`, or the echo the protocol queued for a received Close — and `t`
  /// is when the FIRST such request was made.
  ///
  /// One field rather than a flag beside an anchor, because the two facts are
  /// one fact and every reader needs both: while it is set the close deadline
  /// is suspended (the echo budget cannot start before the peer can possibly
  /// have seen our Close), and the flush bound is the remaining time from `t`.
  /// A bound recomputed as a fresh whole budget on every re-entry is not a
  /// bound — a doorbell ring restores the partial batch and re-enters, so a
  /// local sender that rings faster than the budget keeps a wedged Close flush
  /// alive forever — and measuring from a fixed instant makes it monotone
  /// across cancellation, doorbell re-entry and resume. Raised with
  /// `get_or_insert`, so a second request while one is pending keeps the
  /// earlier anchor; cleared to `None` when the Close reaches the wire, which
  /// takes the anchor with it. Neither half can go stale without the other.
  close_owed: Option<Instant>,
  /// When the close-carrying batch reached the wire. The protocol arms
  /// its deadline when the Close DRAINS into a batch; under backpressure
  /// the flush can consume that whole budget, so the driver re-anchors
  /// the deadline here: it fires at `close_flushed_at + close_budget`.
  close_flushed_at: Option<Instant>,
  /// The effective close timeout (mirrors the protocol config).
  close_budget: core::time::Duration,
  /// The handshake completed over bytes the transport had already accepted
  /// but not yet flushed, so the teardown must NOT be graceful: `close()`
  /// pushes whatever the transport is holding before its close_notify, and
  /// those bytes would reach the wire after both Close frames. Set only where
  /// the handshake completes; the timeout teardown is a different verdict (the
  /// peer's Close never came) and keeps its bounded graceful close.
  ///
  /// **What this guarantees, exactly: NO FURTHER PUSH.** After a completed
  /// handshake abandoned bytes inside the transport, this driver neither
  /// flushes nor closes gracefully — it drops. It cannot RETRACT what the
  /// transport already committed lower down; a record handed to the kernel is
  /// on its way whatever happens here. And `AsyncWrite` offers no
  /// discard-on-`Drop` contract to lean on, so for a transport this crate does
  /// not know about the property is best-effort by construction.
  ///
  /// Measured for the transports it does support, none of which publishes
  /// buffered writes on drop: `compio_io::compat::AsyncStream` (0.10.1) has
  /// neither `Drop` nor `PinnedDrop` in its `compat` module — its write buffer
  /// is a plain `Vec` and its only flush is an async method;
  /// `compio_tls::TlsStream` (0.10.0) has none, and under this crate's
  /// `rustls` backend neither does `futures_rustls::TlsStream` (0.26.0) nor
  /// rustls itself (0.23), which is sans-I/O and holds no socket to write to;
  /// `MaybeTls` and `compio_net::TcpStream` have none; and the test pipe's
  /// halves only mark their direction closed.
  teardown_abortive: bool,
  /// Set on the first write-path failure. A failed batch may have left a
  /// partial frame on the wire, so everything after it is refused with
  /// this kind rather than splicing fresh frames into a corrupt stream.
  poisoned: Option<std::io::ErrorKind>,
  read_half_alive: bool,
  is_split: bool,
  #[cfg(test)]
  pings_seen: usize,
  /// How many reads the flush phase has taken behind a blocked post-Close
  /// write. The allocation regressions state their bound "across at least N
  /// observation reads", so N has to be a number a test can read rather than
  /// one it assumes from the bytes it wrote.
  #[cfg(test)]
  observation_reads: usize,
  /// How many ORDINARY reads Phase 4 has completed. The inbound-bound
  /// regression states "after at least eight reads", and that has to be a
  /// number it reads rather than one it infers from the bytes it wrote.
  #[cfg(test)]
  reads_seen: usize,
  /// The largest the one inbound vector has ever been, recorded at each
  /// commit. The retained bound is a claim about a LIVE connection, and a live
  /// connection's vector sits inside [`PumpIo`] whenever a read is in flight —
  /// so a test reading the field directly would see the empty one left behind.
  #[cfg(test)]
  inbound_capacity_high_water: usize,
  /// The deepest `ready` has ever been. The read behind a blocked write
  /// assembles into a queue nothing is draining, so its bound is a number a
  /// test has to be able to read.
  #[cfg(test)]
  ready_high_water: usize,
  /// The most the assembler's in-progress message has ever held. `ready` is
  /// only half the retention: a message still arriving is held entirely inside
  /// the assembler, where a queue-length bound cannot see it.
  #[cfg(test)]
  partial_high_water: usize,
  #[cfg(test)]
  pongs_seen: usize,
}

impl<Ro, S> Inner<Ro, S> {
  /// The inbound vector's capacity — this driver's whole retained inbound
  /// bound, and a number a test must be able to READ rather than infer from
  /// an allocator total.
  #[cfg(test)]
  fn inbound_capacity(&self) -> usize {
    self.inbound.capacity()
  }
}

/// Keeps the `n` bytes a read actually produced, gives the rest of the window
/// back, and normalises the capacity to one chunk.
///
/// Called on EVERY exit from a read, not only the successful one: the window
/// is zero-filled, so a truncation missed on an error path would hand those
/// zeros to the protocol as if the peer had sent them.
/// It takes the guard rather than the vector so that it can also RECORD the
/// capacity. A test cannot read that off `Inner` while a read is in flight —
/// the guard holds the vector and leaves an empty one behind, which is the
/// same reason the active batch is invisible then — so the high-water is
/// written here, at the one place where the live vector and the shared state
/// are both in hand.
fn commit_read<Ro, S>(io: &mut PumpIo<'_, Ro, S>, start: usize, n: usize) {
  io.inbound.truncate(start.saturating_add(n));
  io.inbound.shrink_to(READ_CHUNK);
  // The window is accounted for; the guard's drop has nothing left to undo.
  io.armed = None;
  #[cfg(test)]
  {
    let capacity = io.inbound.capacity();
    let mut guard = io.inner.borrow_mut();
    if capacity > guard.inbound_capacity_high_water {
      guard.inbound_capacity_high_water = capacity;
    }
  }
}

/// An established WebSocket connection over `S`.
///
/// `next()` must be polled to drive the protocol: pong echoes, keepalive
/// pings, the close handshake, and (after [`split`](Self::split)) queued
/// writes all progress inside it.
///
/// `next()` and the senders are cancellation-safe: dropping them mid-await
/// neither loses inbound bytes nor corrupts the outbound stream — the next
/// call resumes the interrupted work.
pub struct WebSocket<Ro, S> {
  inner: Rc<RefCell<Inner<Ro, S>>>,
  doorbell: Rc<Doorbell>,
}

impl<Ro, S> std::fmt::Debug for WebSocket<Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WebSocket").finish_non_exhaustive()
  }
}

fn build_config(
  keepalive: Option<core::time::Duration>,
  close_timeout: Option<core::time::Duration>,
  max_message_size: Option<usize>,
) -> (ConnectionConfig, usize, core::time::Duration) {
  let mut config = ConnectionConfig::new();
  if keepalive.is_some() {
    config = config.with_keepalive(keepalive);
  }
  if let Some(t) = close_timeout {
    config = config.with_close_timeout(t);
  }
  let cap = max_message_size.unwrap_or(64 << 20);
  config = config.with_max_message_size(cap as u64);
  let budget = config.close_timeout();
  (config, cap, budget)
}

impl<S: Duplex> WebSocket<ClientRole, S> {
  pub(crate) fn client(
    stream: S,
    negotiated: &Negotiated,
    options: &ClientOptions,
    leftover: Vec<u8>,
  ) -> Self {
    use rand::SeedableRng;
    let (config, cap, budget) = build_config(
      options.keepalive,
      options.close_timeout,
      options.max_message_size,
    );
    let conn = Connection::new(
      negotiated,
      config,
      role::Client::new(rand::rngs::StdRng::from_rng(&mut rand::rng())),
      Instant::now(),
    );
    Self::with_conn(stream, conn, cap, budget, leftover)
  }
}

impl<S: Duplex> WebSocket<ServerRole, S> {
  pub(crate) fn server(
    stream: S,
    negotiated: &Negotiated,
    options: &AcceptOptions,
    leftover: Vec<u8>,
  ) -> Self {
    let (config, cap, budget) = build_config(
      options.keepalive,
      options.close_timeout,
      options.max_message_size,
    );
    let conn = Connection::new(negotiated, config, role::Server::new(), Instant::now());
    Self::with_conn(stream, conn, cap, budget, leftover)
  }
}

impl<Ro: role::Role, S: Duplex> WebSocket<Ro, S> {
  fn with_conn(
    stream: S,
    conn: Connection<Instant, Ro>,
    cap: usize,
    close_budget: core::time::Duration,
    leftover: Vec<u8>,
  ) -> Self {
    Self {
      inner: Rc::new(RefCell::new(Inner {
        conn,
        stream: Some(stream),
        inbound: leftover,
        observation_input: false,
        inbound_unread: false,
        assembler: MessageAssembler::new(cap),
        ready: VecDeque::new(),
        outbound: VecDeque::new(),
        pending_write: None,
        closed: None,
        staged_close: None,
        close_owed: None,
        teardown_abortive: false,
        close_flushed_at: None,
        close_budget,
        poisoned: None,
        read_half_alive: true,
        is_split: false,
        #[cfg(test)]
        pings_seen: 0,
        #[cfg(test)]
        observation_reads: 0,
        #[cfg(test)]
        reads_seen: 0,
        #[cfg(test)]
        inbound_capacity_high_water: 0,
        #[cfg(test)]
        ready_high_water: 0,
        #[cfg(test)]
        partial_high_water: 0,
        #[cfg(test)]
        pongs_seen: 0,
      })),
      doorbell: Rc::new(Doorbell::new()),
    }
  }

  /// The next data message, or `None` once the connection has closed
  /// (inspect [`closed`](Self::closed) for the outcome).
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    next_message(&self.inner, &self.doorbell).await
  }

  /// How the connection ended, once `next()` has returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.inner.borrow().closed
  }

  /// Sends a whole data message.
  pub async fn send(&mut self, message: Message) -> Result<(), Error> {
    match &message {
      Message::Text(text) => self.send_text(text.as_ref()).await,
      Message::Binary(data) => self.send_binary(data.as_ref()).await,
    }
  }

  /// Sends a whole text message.
  pub async fn send_text(&mut self, text: &str) -> Result<(), Error> {
    let frame = encode_with(&self.inner, text.len(), |conn, out| {
      conn.encode_text(text, out)
    })?;
    send_frame(&self.inner, &self.doorbell, frame).await
  }

  /// Sends a whole binary message.
  pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), Error> {
    let frame = encode_with(&self.inner, data.len(), |conn, out| {
      conn.encode_binary(data, out)
    })?;
    send_frame(&self.inner, &self.doorbell, frame).await
  }

  /// Sends a Ping (the peer's Pong is consumed internally).
  pub async fn ping(&mut self, payload: &[u8]) -> Result<(), Error> {
    let frame = encode_with(&self.inner, payload.len(), |conn, out| {
      conn.encode_ping(payload, out)
    })?;
    send_frame(&self.inner, &self.doorbell, frame).await
  }

  /// Sends a whole text message compressed with permessage-deflate.
  ///
  /// Fails with [`EncodeError::CompressionUnavailable`] when deflate was not
  /// negotiated (RFC-legal fallback: send plain).
  ///
  /// [`EncodeError::CompressionUnavailable`]: websocket_proto::connection::EncodeError::CompressionUnavailable
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_text_compressed(&mut self, text: &str) -> Result<(), Error> {
    let frame = encode_with(&self.inner, text.len() * 2, |conn, out| {
      conn.encode_text_compressed(text, out)
    })?;
    send_frame(&self.inner, &self.doorbell, frame).await
  }

  /// Sends a whole binary message compressed with permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_binary_compressed(&mut self, data: &[u8]) -> Result<(), Error> {
    let frame = encode_with(&self.inner, data.len() * 2, |conn, out| {
      conn.encode_binary_compressed(data, out)
    })?;
    send_frame(&self.inner, &self.doorbell, frame).await
  }

  /// Starts the close handshake, drives it to completion (peer echo or the
  /// close deadline), tears the transport down, and reports the outcome.
  ///
  /// Data messages arriving while the close handshake runs are discarded.
  /// A peer that drops the transport without echoing the Close surfaces as
  /// the transport error (commonly `UnexpectedEof`).
  ///
  /// [`ClientOptions::with_close_timeout`] bounds each phase — flushing
  /// the Close (even against a peer that stopped reading), waiting for
  /// the echo (counted from the flush, so local backpressure cannot eat
  /// the budget), and the transport shutdown — so the whole call takes at
  /// most a small multiple of it.
  ///
  /// [`ClientOptions::with_close_timeout`]: crate::ClientOptions::with_close_timeout
  pub async fn close(self, code: CloseCode, reason: &str) -> Result<Closed, Error> {
    {
      let mut inner = self.inner.borrow_mut();
      // This method CONSUMES the handle, so no application code can ever
      // receive another message — and the loop below discards every one the
      // pump produces. Say so before the first pass, so the pump observes
      // rather than receives: otherwise a peer sending a compressed bomb
      // during the echo wait is inflated and assembled in full, to the
      // message cap, and then thrown away.
      inner.inbound_unread = true;
      // Nobody can read either half of what is held: the partial has no
      // consumer and neither do the complete messages behind it. Both go now
      // rather than living as long as the caller holds this connection.
      inner.assembler.reset();
      inner.ready.clear();
      if inner.closed.is_none() {
        debug!(code = ?code, reason, "starting close handshake");
        inner.conn.close(code, reason)?;
        inner.close_owed.get_or_insert(Instant::now());
      }
    }
    loop {
      match next_message(&self.inner, &self.doorbell).await {
        Some(Ok(_discarded)) => continue,
        Some(Err(e)) => {
          // Still shut the write side down (TLS close_notify / TCP FIN):
          // without it the peer may wait on a clean EOF forever.
          teardown(&self.inner).await;
          return Err(e);
        }
        None => break,
      }
    }
    let Some(closed) = self.inner.borrow().closed else {
      // `next_message` only returns `None` with the outcome recorded.
      return Err(Error::Closed);
    };
    Ok(closed)
  }

  /// Splits into independently-owned read and write halves.
  ///
  /// The write half's sends are pumped by the read half: they make progress
  /// only while [`ReadHalf::next`] is being polled (the same "keep polling"
  /// contract the timers have).
  pub fn split(self) -> (ReadHalf<Ro, S>, WriteHalf<Ro, S>) {
    self.inner.borrow_mut().is_split = true;
    split::pair(self.inner, self.doorbell)
  }

  #[cfg(test)]
  pub(crate) fn pings_seen(&self) -> usize {
    self.inner.borrow().pings_seen
  }

  #[cfg(test)]
  pub(crate) fn pongs_seen(&self) -> usize {
    self.inner.borrow().pongs_seen
  }
}

/// Encodes one frame under a short borrow into an owned buffer.
fn encode_with<Ro: role::Role, S>(
  inner: &Rc<RefCell<Inner<Ro, S>>>,
  payload_hint: usize,
  encode: impl FnOnce(
    &mut Connection<Instant, Ro>,
    &mut [u8],
  ) -> Result<usize, websocket_proto::connection::EncodeError>,
) -> Result<Vec<u8>, Error> {
  let mut inner = inner.borrow_mut();
  if let Some(kind) = inner.poisoned {
    return Err(Error::Io(kind.into()));
  }
  if inner.closed.is_some() {
    return Err(Error::Closed);
  }
  let mut buf = vec![0u8; payload_hint + websocket_proto::constants::MAX_FRAME_HEADER + 64];
  let n = encode(&mut inner.conn, &mut buf)?;
  buf.truncate(n);
  Ok(buf)
}

/// Moves the stream and the in-progress write out of `Inner` for the
/// duration of the IO awaits; `Drop` puts whatever is left back, so a
/// cancelled caller future never strands either.
struct PumpIo<'a, Ro, S> {
  inner: &'a Rc<RefCell<Inner<Ro, S>>>,
  stream: Option<S>,
  write: Option<PendingWrite>,
  /// The one inbound vector, out on loan for the same reason as the stream: a
  /// read borrows it across an await, and the `RefCell` may not be borrowed
  /// there. It goes back on `Drop`, so a cancelled caller future strands the
  /// bytes it holds no more than it strands the stream.
  inbound: Vec<u8>,
  /// Where an ARMED but uncommitted read window starts, if one is open.
  ///
  /// The window is zero-filled space appended to `inbound`, and `inbound`'s
  /// `len` is the protocol's unconsumed input — so between the arm and the
  /// commit the vector reads as 16 KiB of zeros the peer never sent. Every
  /// ordinary exit commits, but a CANCELLED caller drops this guard from
  /// inside the `.await`, with no exit to commit on, and `Drop` would restore
  /// those zeros into `Inner` for the next pass to feed to `handle` as if the
  /// peer had sent them. So the arm is recorded here and `Drop` gives back a
  /// vector that ends where the last committed byte does.
  ///
  /// One vector rather than two is what makes this a hazard: a scratch buffer
  /// separate from the input carried no such meaning in its `len`.
  armed: Option<usize>,
}

impl<'a, Ro, S> PumpIo<'a, Ro, S> {
  fn take(inner: &'a Rc<RefCell<Inner<Ro, S>>>) -> Self {
    let (stream, write, inbound) = {
      let mut guard = inner.borrow_mut();
      (
        guard.stream.take(),
        guard.pending_write.take(),
        std::mem::take(&mut guard.inbound),
      )
    };
    Self {
      inner,
      stream,
      write,
      inbound,
      armed: None,
    }
  }

  /// Arms the inbound vector for a read and answers where the window starts:
  /// the unconsumed prefix keeps the front, and a full `READ_CHUNK` of
  /// zero-filled space follows it for the read to fill.
  ///
  /// Zero-filled rather than spare capacity, because a `&mut [u8]` over a
  /// `Vec`'s uninitialised tail needs `unsafe` and would buy nothing the
  /// memset does not: the two-buffer design zeroed a whole chunk per read as
  /// well.
  ///
  /// A method rather than a free function over the vector, because arming
  /// must record the window on the guard — see [`PumpIo::armed`].
  fn arm_inbound(&mut self) -> usize {
    let start = self.inbound.len();
    self.inbound.resize(start.saturating_add(READ_CHUNK), 0);
    self.armed = Some(start);
    start
  }
}

impl<Ro, S> Drop for PumpIo<'_, Ro, S> {
  fn drop(&mut self) {
    // A read window that was armed and never committed is not input: it is
    // zeros this driver wrote. Give it back before the vector goes home. This
    // is the cancellation path — a caller that drops `next()` mid-read runs
    // this and no commit — and it is also the backstop for any future exit
    // that forgets one.
    if let Some(start) = self.armed.take() {
      self.inbound.truncate(start);
    }
    let mut guard = self.inner.borrow_mut();
    guard.stream = self.stream.take();
    guard.pending_write = self.write.take();
    guard.inbound = std::mem::take(&mut self.inbound);
  }
}

/// Fails every frame the pump still owes the wire but may no longer put on
/// it: the queue, and a batch already part-written that carries no Close.
/// [`FrameState::ClosedBeforeWrite`] is the state, so a sender learns its
/// frame was overtaken rather than that the transport broke.
///
/// A batch that DOES carry a Close is left alone — its Close is the frame the
/// handshake is waiting for, and no path records an outcome while one is still
/// unwritten (the settle cannot fire, because `effective_deadline` answers
/// `None` while a Close is owed, and the completion path requires ours to have
/// flushed already).
///
/// A free function over the two fields rather than a method on `Inner`,
/// because one of its two callers runs inside Phase 1's event loop where the
/// cursor holds `&mut conn` and `&mut Inner` as a whole is unavailable; two
/// disjoint field borrows are. It is one entrance either way, which is the
/// point: the rule that nothing follows a recorded outcome onto the wire is
/// written once and called from both places that can record one.
///
/// Answers **whether the discarded batch had already handed bytes to the
/// transport** (`cursor > 0`). Dropping the batch does not retract those: they
/// sit in an adapter buffer or a half-built TLS record, and the next thing that
/// flushes puts them on the wire. Only the caller knows whether that matters —
/// after a completed handshake it does, and it is what makes the teardown
/// abortive.
fn discard_unwritten(
  outbound: &mut VecDeque<OutboundFrame>,
  pending: &mut Option<PendingWrite>,
) -> bool {
  while let Some(frame) = outbound.pop_front() {
    frame.state.set(FrameState::ClosedBeforeWrite);
  }
  let Some(batch) = pending.take_if(|p| !p.carries_close) else {
    return false;
  };
  for state in &batch.states {
    state.set(FrameState::ClosedBeforeWrite);
  }
  batch.cursor > 0
}

fn stream_gone() -> Error {
  Error::Io(std::io::Error::from(std::io::ErrorKind::ResourceBusy))
}

/// Records an IRREVERSIBLE transport termination, and everything that follows
/// from it, in one place.
///
/// The condition becomes sticky (`poisoned`), so every later `next()` answers
/// the error before it reaches delivery and every later send is refused; the
/// queue is failed, because nothing will ever write it; and the folder's
/// partial and the completed messages behind it are dropped, because nothing
/// can ever hand them out. Those last two are the reason this is a function:
/// the fact was written at six sites and the release reached three of them,
/// which is the shape this branch has now paid for three times.
///
/// **`ready` is cleared rather than delivered, and that is a consequence of
/// the poison rather than a choice made here.** The sticky check is the first
/// thing the pump does, before Phase 1 and long before delivery, so a message
/// left in `ready` after this call could never be returned to anyone. A site
/// that wants its queued messages delivered must therefore NOT terminate here
/// — and one such site exists: the close-flush settle with a protocol verdict
/// records `closed`, resets the folder and keeps `ready`, because it falls
/// through to delivery instead of returning an error. It is a protocol
/// outcome, not an I/O termination, and it calls `reset()` directly; so do the
/// no-reader transitions, which clear `ready` themselves for the opposite
/// reason (nobody is left to receive it).
///
/// It does not touch the stream: whether the transport is dropped here, torn
/// down, or left to the guard is the caller's, and the two callers that own it
/// already differ.
fn terminate_io<Ro, S>(
  inner: &mut Inner<Ro, S>,
  kind: std::io::ErrorKind,
  doorbell: &Doorbell,
  in_hand: Option<PendingWrite>,
) {
  // First writer wins: a later symptom must not relabel the original fault.
  if inner.poisoned.is_none() {
    inner.poisoned = Some(kind);
  }
  // Every frame this termination strands, wherever it is. `in_hand` is the
  // batch a caller took out of the state and still holds — the write path's
  // own failure has it in a local, and a batch failed nowhere is a sender
  // parked on a `Queued` state that nothing will ever change. It is a
  // REQUIRED parameter rather than something the helper looks for, so a
  // caller holding one cannot pass this point without saying so.
  for batch in in_hand.into_iter().chain(inner.pending_write.take()) {
    for state in &batch.states {
      state.set(FrameState::Failed(kind));
    }
  }
  while let Some(frame) = inner.outbound.pop_front() {
    frame.state.set(FrameState::Failed(kind));
  }
  inner.assembler.reset();
  inner.ready.clear();
  // And wake everyone waiting on a state this just changed. The doorbell is a
  // parameter for the same reason `in_hand` is: the sticky poison means no
  // later pump pass settles anything, so a notify the caller forgot is a
  // sender that waits for the life of the process — and a caller that has to
  // hand the doorbell over cannot forget to ring it. (A `#[must_use]` return
  // was the alternative and is weaker: `let _ =` silences it.)
  doorbell.notify(usize::MAX);
}

/// What one drive resolved to.
pub(crate) enum DriveOutcome {
  /// The batch finished, or failed; the frame states are settled.
  Written(Result<(), Error>),
  /// Inbound bytes arrived while the write was blocked, and are in the
  /// guard's inbound vector, already committed. Reachable only when the caller
  /// asked for the read race.
  Input(std::io::Result<usize>),
  /// The deadline passed before a poll this drive was about to make.
  /// Reachable only when the caller hands over a deadline.
  Expired,
}

/// The same, before the frame states are settled.
enum RawDrive {
  Written(std::io::Result<()>),
  Input(std::io::Result<usize>),
  Expired,
}

/// Drives the guard's pending write to the wire: byte cursor loop, then
/// flush, then frame-state transitions. The cursor advances only on
/// completed sub-writes, so cancellation mid-batch resumes losslessly.
///
/// With `race_read`, a write that CANNOT progress also polls the inbound
/// direction — into the guard's own inbound vector, which is why the buffer is
/// not a parameter — and yields whatever arrives. The two directions are
/// independent,
/// and after our Close has flushed the peer's Close is the thing that ends the
/// handshake — leaving it unread until a blocked Pong batch times out turns a
/// handshake that completed at once into an unclean close at the deadline.
/// Written by hand rather than as two futures because both halves are
/// `Pin<&mut S>` calls on one poll-based stream, so there is nothing to split.
///
/// The write is polled FIRST and the read only on its `Pending`: the batch is
/// what this phase exists to finish, and reading while a write can still
/// progress would take inbound backpressure off a peer we are already behind
/// on. Which callers may hand over a buffer is Phase 3's decision, and it
/// hands one over on exactly one of its three bounds.
///
/// `deadline` is checked HERE, immediately before each poll, and answers
/// [`DriveOutcome::Expired`]. Racing a timer in the caller's `select!` is not
/// enough: the select is drive-biased, so a task that resumes past the
/// deadline polls a ready write and completes it before the timer is ever
/// looked at. The check belongs where the write happens.
async fn drive_pending_write<Ro, S: Duplex>(
  io: &mut PumpIo<'_, Ro, S>,
  doorbell: &Doorbell,
  race_read: bool,
  deadline: Option<Instant>,
) -> DriveOutcome {
  // Where a read would put its bytes: after whatever is still unconsumed.
  // Armed before the borrows below, and committed after them on EVERY exit.
  let start = if race_read {
    io.arm_inbound()
  } else {
    io.inbound.len()
  };
  // The two refusals come before the field borrows, so the window they leave
  // behind is committed through the guard like every other exit.
  if io.stream.is_none() {
    commit_read(io, start, 0);
    return DriveOutcome::Written(Err(stream_gone()));
  }
  if io.write.is_none() {
    commit_read(io, start, 0);
    return DriveOutcome::Written(Ok(()));
  }
  let raw = {
    // Three DISJOINT field borrows of one guard: the stream to poll, the batch
    // to write, and the vector to read into. That vector lives on the guard so
    // it survives `continue 'pump`, and a `&mut [u8]` parameter taken from it
    // would have aliased the `&mut PumpIo` this function already holds.
    let PumpIo {
      stream,
      write: batch,
      inbound,
      ..
    } = &mut *io;
    let Some(stream) = stream.as_mut() else {
      return DriveOutcome::Written(Err(stream_gone()));
    };
    let Some(pending) = batch.as_mut() else {
      return DriveOutcome::Written(Ok(()));
    };
    let mut read_into = race_read.then(|| inbound.get_mut(start..).unwrap_or(&mut []));
    futures_util::future::poll_fn(move |cx| {
      // Read afresh before every poll below: the deadline is an instant, and
      // an earlier reading of the clock says nothing about this one.
      let expired = || deadline.is_some_and(|at| Instant::now() >= at);
      loop {
        if expired() {
          return Poll::Ready(RawDrive::Expired);
        }
        if pending.cursor < pending.bytes.len() {
          let rest = pending.bytes.get(pending.cursor..).unwrap_or(&[]);
          match Pin::new(&mut *stream).poll_write(cx, rest) {
            Poll::Ready(Ok(0)) => {
              return Poll::Ready(RawDrive::Written(Err(std::io::Error::from(
                std::io::ErrorKind::WriteZero,
              ))));
            }
            Poll::Ready(Ok(n)) => {
              pending.cursor = pending.cursor.saturating_add(n);
              continue;
            }
            Poll::Ready(Err(e)) => return Poll::Ready(RawDrive::Written(Err(e))),
            Poll::Pending => {}
          }
        } else {
          // The batch is fully handed to the transport; flush puts buffered
          // bytes (the adapter's, TLS records) on the wire. Idempotent, so a
          // cancellation between the last write and here re-flushes on resume.
          match Pin::new(&mut *stream).poll_flush(cx) {
            Poll::Ready(result) => return Poll::Ready(RawDrive::Written(result)),
            Poll::Pending => {}
          }
        }
        // The write is blocked. Without a buffer this parks exactly as the
        // `.await`-per-sub-write version did.
        if expired() {
          return Poll::Ready(RawDrive::Expired);
        }
        return match read_into.as_deref_mut() {
          Some(buf) => match Pin::new(&mut *stream).poll_read(cx, buf) {
            Poll::Ready(result) => Poll::Ready(RawDrive::Input(result)),
            Poll::Pending => Poll::Pending,
          },
          None => Poll::Pending,
        };
      }
    })
    .await
  };
  // The window was zero-filled; keep only what the read produced, on every
  // arm — a missed truncation would hand those zeros to the protocol.
  let read_n = match &raw {
    RawDrive::Input(Ok(n)) => *n,
    _ => 0,
  };
  commit_read(io, start, read_n);
  let result = match raw {
    RawDrive::Input(result) => return DriveOutcome::Input(result),
    RawDrive::Expired => return DriveOutcome::Expired,
    RawDrive::Written(result) => result,
  };
  let Some(pending) = io.write.take() else {
    return DriveOutcome::Written(result.map_err(Error::Io));
  };
  DriveOutcome::Written(match result {
    Ok(()) => {
      for state in &pending.states {
        state.set(FrameState::Written);
      }
      if pending.carries_close {
        let mut guard = io.inner.borrow_mut();
        // The Close is out: the obligation and its anchor go together.
        guard.close_owed = None;
        // The peer can only now have seen the Close: anchor the deadline
        // budget here, not at the protocol's drain-into-batch instant.
        guard.close_flushed_at = Some(Instant::now());
        // The close obligation is met: publish a staged peer outcome.
        if guard.closed.is_none()
          && let Some(staged) = guard.staged_close.take()
        {
          guard.closed = Some(staged);
        }
      }
      doorbell.notify(usize::MAX);
      Ok(())
    }
    Err(e) => {
      warn!(error = %e, "transport write failed");
      let kind = e.kind();
      // A partial frame may be on the wire: this connection is over, and
      // nothing may splice into the corrupt stream after it. The failing
      // batch is IN HAND here rather than in the state — it was taken out
      // above — so it is handed over rather than failed separately, and the
      // entrance does the one notify.
      terminate_io(&mut io.inner.borrow_mut(), kind, doorbell, Some(pending));
      Err(Error::Io(e))
    }
  })
}

/// Direct write of one encoded frame. Only reachable unsplit — `split()`
/// consumes the `WebSocket`, and the halves enqueue through the doorbell
/// instead. Settles any write a cancelled earlier call left behind first.
async fn send_frame<Ro: role::Role, S: Duplex>(
  inner: &Rc<RefCell<Inner<Ro, S>>>,
  doorbell: &Rc<Doorbell>,
  frame: Vec<u8>,
) -> Result<(), Error> {
  debug_assert!(!inner.borrow().is_split);
  let mut mine = Some(frame);
  loop {
    let mut io = PumpIo::take(inner);
    if io.write.is_none() {
      match mine.take() {
        Some(bytes) => {
          io.write = Some(PendingWrite {
            bytes,
            cursor: 0,
            states: Vec::new(),
            carries_close: false,
          });
        }
        None => return Ok(()),
      }
    }
    match drive_pending_write(&mut io, doorbell, false, None).await {
      DriveOutcome::Written(result) => result?,
      // Neither the read race nor a deadline was asked for, so neither of
      // these is reachable. Looping re-drives the same batch, which is what
      // this path would want from a spurious wake anyway.
      DriveOutcome::Input(_) | DriveOutcome::Expired => {}
    }
  }
}

/// A timer over a caller-supplied duration that cannot panic.
///
/// `compio::time::sleep(d)` is `sleep_until(Instant::now() + d)`, and that
/// addition is the PANICKING one — so every duration this driver derives from
/// `close_timeout` would abort the process inside the timer for a budget the
/// caller is allowed to configure ([`ClientOptions::with_close_timeout`]
/// accepts any `Duration`, `Duration::MAX` included). A deadline the clock
/// cannot represent is a deadline that can never be reached, so it parks
/// instead — which is what an unreachable budget means, and it leaves the
/// other arms of every `select_biased!` this feeds exactly as they were.
///
/// The `Instant::now()` is read ONCE and the absolute deadline handed to
/// `sleep_until`, so the check and the arming cannot disagree about the time.
///
/// Its one caller is [`teardown`], and that is the point: a FRESH budget is
/// what the shutdown attempt wants. Phase 3 does not use it — its budget runs
/// from an anchor, so it computes one absolute instant per entry and hands
/// that to `sleep_until` directly, rather than a duration a second clock
/// reading would re-anchor.
///
/// [`ClientOptions::with_close_timeout`]: crate::ClientOptions::with_close_timeout
async fn sleep_for(duration: core::time::Duration) {
  match Instant::now().checked_add(duration) {
    Some(at) => compio::time::sleep_until(at).await,
    None => futures_util::future::pending::<()>().await,
  }
}

/// Tears the transport down after the close handshake (or on abandonment):
/// best-effort write-side close (TLS close_notify / TCP FIN), then drop.
/// The attempt runs under the close budget — a close_notify against a
/// peer that stopped reading must not turn a finished handshake into a
/// hang — and consuming the stream makes repeated calls no-ops.
async fn teardown<Ro, S: Duplex>(inner: &Rc<RefCell<Inner<Ro, S>>>) {
  let (stream, budget, abortive) = {
    let mut guard = inner.borrow_mut();
    (
      guard.stream.take(),
      guard.close_budget,
      guard.teardown_abortive,
    )
  };
  let Some(mut stream) = stream else {
    return;
  };
  if abortive {
    // A graceful close flushes what the transport is holding before it writes
    // close_notify, and what it is holding is a batch the completed handshake
    // discarded. Dropping abandons those bytes, which is the point: §5.5.1
    // (line 2023) leaves nowhere for them to go. The guarantee is "no further
    // push" and it is best-effort per transport — see `Inner::teardown_abortive`
    // for what that means and for the measurement behind it.
    warn!("bytes were abandoned inside the transport; dropping without close_notify");
    drop(stream);
    return;
  }
  trace!("shutting the transport down");
  let close = stream.close().fuse();
  let timer = sleep_for(budget).fuse();
  futures_util::pin_mut!(close, timer);
  futures_util::select_biased! {
    _ = close => {}
    () = timer => debug!("transport shutdown timed out; dropping"),
  }
}

/// The close-flush bound expired: the peer stopped draining while we owed
/// it a Close. Record the outcome, fail every waiting sender, and tear
/// the transport down (synchronous drop — the write path is wedged, a
/// close_notify could wedge with it). Returns what the pump reports:
/// `None` with the unclean close recorded, or the timeout as an error
/// when the Close never even drained into a batch (the protocol's
/// deadline only arms at drain).
fn close_flush_timed_out<Ro: role::Role, S: Duplex>(
  inner: &Rc<RefCell<Inner<Ro, S>>>,
  mut io: PumpIo<'_, Ro, S>,
  doorbell: &Doorbell,
) -> Option<Result<Message, Error>> {
  warn!("close flush timed out; tearing the transport down");
  let kind = std::io::ErrorKind::TimedOut;
  let stream = io.stream.take();
  let pending = io.write.take();
  drop(io);
  drop(stream);
  {
    let mut guard = inner.borrow_mut();
    if let Some(pending) = &pending {
      for state in &pending.states {
        state.set(FrameState::Failed(kind));
      }
    }
    while let Some(frame) = guard.outbound.pop_front() {
      frame.state.set(FrameState::Failed(kind));
    }
    drop(pending);
    // The echo never reached the wire: a staged peer outcome must not
    // surface as a clean close.
    guard.staged_close = None;
    // `handle_timeout` refuses an instant earlier than one the connection has
    // already been given. `std::time::Instant` is monotonic, so that cannot
    // happen here — it is spelled out rather than unwrapped because this driver
    // must not panic on a clock it does not own, and a refusal means exactly
    // what `None` means below: no protocol verdict.
    let verdict = match guard.conn.handle_timeout(Instant::now()) {
      Ok(verdict) => verdict,
      Err(e) => {
        warn!(error = %e, "clock went backwards settling the flush timeout");
        None
      }
    };
    if let Some(closed) = verdict {
      guard.closed = Some(closed);
      // The same settle, one function over: an outcome reached through our own
      // timer rather than through a peer frame, so nothing was pushed and a
      // partial in the folder has nothing left to close it.
      guard.assembler.reset();
      // A protocol outcome, not an I/O termination: this arm falls through to
      // delivery, so it keeps `ready` and rings the doorbell itself.
      doorbell.notify(usize::MAX);
      None
    } else {
      // No protocol verdict (the Close never even drained into a
      // batch): fail sticky instead of publishing any outcome. The entrance
      // notifies, so this arm must not — one ring, not two.
      terminate_io(&mut guard, kind, doorbell, None);
      Some(Err(Error::Io(kind.into())))
    }
  }
}

/// The protocol deadline, corrected for transport flush: while the Close
/// is still unflushed its budget has not started (`None`), and once it
/// flushed the deadline counts from that instant — the protocol arms it
/// when the Close drains into a batch, which under backpressure can be a
/// whole budget earlier than the peer could possibly have seen it. The
/// keepalive needs no correction (the protocol only arms it while open).
///
/// **Phase 3 does NOT go through this function, and that is deliberate.** Its
/// bound on a write performed after the Close has flushed reads
/// `close_flushed_at + close_budget` directly, because this function answers
/// `None` once the peer's Close has cleared the protocol timer
/// (`conn.poll_timeout()` is `None` on a terminal connection) — and a `None`
/// there would leave a post-Close Pong batch unbounded, which is the defect
/// that bound exists to close. The two readings of `close_flushed_at`
/// therefore differ on purpose, and an edit to either has to be checked
/// against the other.
///
/// The echo deadline is `checked_add`: `close_timeout` is a caller-supplied
/// `Duration` and `flushed + budget` can leave the clock's range, where the
/// panicking `Add` would kill the process. Overflow answers `None` — no
/// deadline — and that is the right answer rather than a clamp, because what
/// this function returns is the LATER of the protocol's deadline and the echo
/// deadline, and an echo deadline that cannot be represented is infinitely far
/// away. A `None` here means the pump parks on the peer, which is exactly what
/// a budget that large asks for.
fn effective_deadline<Ro: role::Role, S>(guard: &Inner<Ro, S>) -> Option<Instant> {
  let at = guard.conn.poll_timeout()?;
  if guard.close_owed.is_some() {
    return None;
  }
  match guard.close_flushed_at {
    // Overflow answers `None`: unreachable, hence later than `at`, hence the
    // deadline — and there is no such instant to return.
    Some(flushed) => flushed
      .checked_add(guard.close_budget)
      .map(|echo_at| at.max(echo_at)),
    None => Some(at),
  }
}

/// The shared pump: drives the connection until a data message completes,
/// the connection closes (`None`), or an error surfaces.
pub(crate) async fn next_message<Ro: role::Role, S: Duplex>(
  inner: &Rc<RefCell<Inner<Ro, S>>>,
  doorbell: &Rc<Doorbell>,
) -> Option<Result<Message, Error>> {
  'pump: loop {
    // Phase 1 (borrow): feed pending input through the state machine.
    // Buffered `ready` messages drain even after the close is recorded
    // (they arrived before the peer's Close); new input does not.
    let mut wake_senders = false;
    {
      let mut guard = inner.borrow_mut();
      if let Some(kind) = guard.poisoned {
        return Some(Err(Error::Io(kind.into())));
      }
      if guard.closed.is_none() && !guard.inbound.is_empty() {
        let mut input = std::mem::take(&mut guard.inbound);
        // Two independent reasons to observe rather than receive: these
        // bytes were read behind a blocked post-Close write, or nobody is
        // left to read what they would assemble. Only the first is a property
        // of the input, so only the first is taken.
        let observing = std::mem::take(&mut guard.observation_input) || guard.inbound_unread;
        // An explicit scope: the cursor borrows `input` AND `guard`, and both
        // borrows have to end before the buffers below can be put back.
        {
          let inner_mut = &mut *guard;
          // Observation: parse everything, decode nothing. The application has
          // said it is done — it called `close()` — and the write carrying our
          // reply is blocked, so nothing will drain a message decoded now and a
          // message still arriving would be held whole. Control frames are
          // processed exactly as ever: Pings queue Pongs into the protocol's own
          // bounded slots, and the peer's Close completes the handshake. Bounded
          // memory and a Close that is always seen are worth more here than late
          // data.
          //
          // The choice is `observe` vs `handle` at the PROTOCOL, not at the
          // assembler. Discarding the event was one layer too late: with
          // `deflate`, `handle` inflates the payload into the decompressor's
          // buffer before there is an event to discard, so a 16 KiB read of a
          // compressed bomb cost megabytes of output that nothing would ever
          // look at. The assembler learns the same fact from the events
          // themselves, rather than from a mode a caller has to pair with a
          // feed that may produce nothing to pair it with.
          //
          // Which call to make is decided per feed, from the flag taken above,
          // so no mode survives a feed that never happens.
          let now = Instant::now();
          let fed = if observing {
            inner_mut.conn.observe(now, &mut input)
          } else {
            inner_mut.conn.handle(now, &mut input)
          };
          match fed {
            Ok(mut events) => {
              while let Some(event) = events.next() {
                #[cfg(test)]
                if matches!(event, Event::Ping(_)) {
                  inner_mut.pings_seen += 1;
                }
                #[cfg(test)]
                if matches!(event, Event::Pong(_)) {
                  inner_mut.pongs_seen += 1;
                }
                if let Event::Closed(closed) = &event {
                  debug!(code = ?closed.code(), clean = closed.clean(), "connection closed");
                  if inner_mut.close_flushed_at.is_some() {
                    // Our Close is ALREADY on the wire, so the peer's completes
                    // the handshake right here: no echo is owed, nothing is
                    // staged, and the outcome holds now. §5.5.1 (line 2023 of
                    // `.rfc-cache/rfc6455.txt`) closes the connection at this
                    // instant, so every frame the pump has not written yet has
                    // missed its chance — the queue, and a batch already
                    // half-written whose remaining bytes would follow both
                    // Closes onto the wire.
                    inner_mut.closed = Some(*closed);
                    // Bytes the transport already accepted cannot be taken back,
                    // and a graceful `close()` would push them out after both
                    // Close frames. When there are any, the teardown abandons
                    // them with the transport instead.
                    if discard_unwritten(&mut inner_mut.outbound, &mut inner_mut.pending_write) {
                      inner_mut.teardown_abortive = true;
                    }
                    wake_senders = true;
                  } else {
                    // Stage, do not publish: the outcome only holds once the
                    // echo the protocol just queued reaches the wire. The event
                    // cursor borrows `conn`, so this raise is written as a
                    // disjoint FIELD access — `&mut Inner` as a whole is not
                    // available here.
                    inner_mut.staged_close = Some(*closed);
                    inner_mut.close_owed.get_or_insert(now);
                  }
                }
                // One call for both modes, and nothing else to do: the
                // protocol says which messages carry no payload
                // (`MessageStart::skipped`) and which one already in progress
                // is being given up on (`Event::MessageAbandoned`), so `push`
                // is safe on observed events and fabricates nothing.
                match inner_mut.assembler.push(&event) {
                  Ok(Some(message)) => {
                    inner_mut.ready.push_back(message);
                    #[cfg(test)]
                    {
                      let depth = inner_mut.ready.len();
                      if depth > inner_mut.ready_high_water {
                        inner_mut.ready_high_water = depth;
                      }
                    }
                  }
                  Ok(None) => {}
                  Err(e) => return Some(Err(e.into())),
                }
                #[cfg(test)]
                {
                  let held = inner_mut.assembler.buffered();
                  if held > inner_mut.partial_high_water {
                    inner_mut.partial_high_water = held;
                  }
                }
              }
            }
            Err(e) => return Some(Err(e.into())),
          }
        }
        // All input is consumed by the cursor (drop-drains), so clearing
        // loses nothing — and the ALLOCATION goes back rather than being
        // dropped with the local. Empty, so the next read's window starts at
        // the front; with its capacity, so that read allocates nothing.
        // (The early returns above do not restore it. They end this pump with
        // an error, and a connection that is failing has no next read.)
        input.clear();
        guard.inbound = input;
      }
      // Settle overdue protocol timers on every pass — AFTER the input
      // feed, so an echo that already arrived beats the deadline clock
      // (wall time may have advanced while the future sat unpolled), but
      // BEFORE message delivery, so a steady inbound flood of ready
      // messages cannot starve the close deadline or the keepalive.
      {
        let now = Instant::now();
        if effective_deadline(&guard).is_some_and(|at| at <= now) {
          // The refusal arm is unreachable with a monotonic `Instant::now()`;
          // see `close_flush_timed_out` for why it is spelled rather than
          // unwrapped.
          match guard.conn.handle_timeout(now) {
            Ok(Some(closed)) => {
              debug!(clean = closed.clean(), "close deadline elapsed");
              guard.closed = Some(closed);
              // The connection ended on OUR timer, so no peer frame said so
              // and no event carried it: `push` never runs, and a partial
              // accumulated before this instant would be held until the
              // caller drops the whole connection. `ready` is KEPT — this
              // pump promises to hand out complete messages before it
              // answers `None`, and they are still deliverable.
              guard.assembler.reset();
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "clock went backwards settling protocol timers"),
          }
        }
      }
    }
    // Outside the borrow, as every other notify in this file is.
    if wake_senders {
      doorbell.notify(usize::MAX);
    }

    // Phase 2 (borrow): if no batch is in progress, coalesce queued writer
    // frames + protocol transmits into one. Queue first: a writer frame
    // was encoded before any Close the protocol may have queued since, and
    // data frames must precede the Close on the wire (RFC 6455 §5.5.1).
    let deadline = {
      let mut guard = inner.borrow_mut();
      if guard.pending_write.is_none() {
        let mut bytes: Vec<u8> = Vec::new();
        let mut states = Vec::new();
        while let Some(frame) = guard.outbound.pop_front() {
          bytes.extend_from_slice(&frame.bytes);
          states.push(frame.state);
        }
        let mut scratch = [0u8; TRANSMIT_SCRATCH];
        let now = Instant::now();
        // The batch is labelled by its CONTENT, asked of the protocol across
        // the drain: `close_owed` is the driver's "a Close is owed", which
        // stays set until the frame FLUSHES and therefore also labels every
        // batch built while it sits unflushed — batches that carry no Close at
        // all. A mislabelled batch discharges `close_owed` and re-anchors the
        // echo budget on a flush that put no Close on the wire.
        let close_sent_before = guard.conn.close_sent();
        loop {
          match guard.conn.poll_transmit(now, &mut scratch) {
            Ok(Some(n)) => bytes.extend_from_slice(scratch.get(..n).unwrap_or(&[])),
            Ok(None) => break,
            Err(e) => return Some(Err(e.into())),
          }
        }
        let carries_close = !close_sent_before && guard.conn.close_sent();
        if !bytes.is_empty() {
          guard.pending_write = Some(PendingWrite {
            bytes,
            cursor: 0,
            states,
            carries_close,
          });
        }
        // No `else`: "a Close is owed and the protocol has nothing to give" is
        // settled in Phase 1, which completes the handshake on receipt when
        // `close_flushed_at` is set and never marks a Close owed for it, and in
        // `close_flush_timed_out`, which owns a batch that was torn down rather
        // than flushed. A branch here that discharged `close_owed` and
        // published a staged outcome was kept through R4 on a reachability
        // argument; deleting it reds nothing in `test -p wren-compio` (49
        // tests), so it is gone and the carrying flush is the sole publisher of
        // `staged_close`.
      }
      effective_deadline(&guard)
    };

    // Phase 3 (IO, guarded): put the batch on the wire, under one of THREE
    // bounds. While a Close is owed (in this batch, or queued behind it),
    // the flush gets the whole close budget — close_timeout must bound the
    // handshake even against a peer that stopped reading, and the echo
    // budget only starts once the Close is out (it re-arms at flush).
    //
    // Once the Close HAS flushed, any further write — a post-Close Pong
    // batch, which exists now that the protocol keeps answering Pings until
    // the peer's Close arrives — is bounded by what REMAINS of that echo
    // budget. It must be: such a batch carries no Close and `close_owed`
    // is already discharged, so the old two-way choice parked it unbounded and
    // a peer that filled the socket and stopped reading wedged it forever,
    // defeating the very bound `close_timeout` documents. The remaining time
    // is read from `close_flushed_at` DIRECTLY rather than through
    // `effective_deadline`, which answers `None` once the peer's Close has
    // cleared the protocol timer — and `None` there would leave exactly this
    // batch unbounded again.
    //
    // BOTH bounded arms are remaining time from an ABSOLUTE anchor, never a
    // fresh budget: `close_owed`'s own instant for the first,
    // `close_flushed_at` for the second. A `Reconsider` re-entry recomputes
    // from the same
    // anchor, so the bound only shrinks — a doorbell cannot buy a wedged
    // flush another budget, which is what made `close_timeout` unbounded in
    // the presence of any local sender. Zero remaining resolves to
    // `FlushArm::Budget` BEFORE the drive is polled: `select_biased!` polls
    // the drive first, so an already-ready write would otherwise complete
    // after the budget was spent, and the deadline is a hard boundary.
    //
    // Only a plain flush with no Close anywhere in its past parks unbounded,
    // and it still listens to the doorbell: a close requested mid-flush
    // re-enters as a bounded flush (the dropped drive's progress survives in
    // the cursor).
    //
    // The post-Close arm — and ONLY it — also polls a read while its write is
    // blocked. The peer's Close travels the independent inbound direction and
    // is what ends the handshake, so leaving it unread until this batch's
    // budget expires reports a handshake that completed at once as unclean at
    // the deadline. The other two arms must not: the close-carrying arm has to
    // write its Close whatever arrives, and the unbounded arm reading while a
    // plain flush is wedged would take inbound backpressure off a peer we are
    // already behind on.
    // Phase 3 runs BEFORE the terminal check, so unlike Phase 4 it can meet an
    // outcome that is already recorded — Phase 1's settle records one, and a
    // batch left parked by a cancelled pass is still here when it does. Such a
    // batch is moot: §5.5.1 (line 2023 of `.rfc-cache/rfc6455.txt`) closes the
    // connection at a completed handshake, and a passed deadline has spent the
    // only budget it could have been written under. It is discarded rather than
    // written, which is also what keeps `Input`'s `Ok(0)` from ever meeting a
    // recorded outcome — so that arm's `UnexpectedEof` stays the answer for the
    // open connection it was written for.
    let moot = {
      let guard = inner.borrow();
      guard.closed.is_some()
        && guard
          .pending_write
          .as_ref()
          .is_some_and(|p| !p.carries_close)
    };
    if moot {
      {
        let mut guard = inner.borrow_mut();
        // One reborrow, then two disjoint field borrows: `RefMut`'s `DerefMut`
        // is a call, so two of them are not disjoint to the compiler.
        let inner_mut = &mut *guard;
        // The answer is deliberately dropped here. This guard's outcome is the
        // deadline settle's — ONE Close exchanged, not two — so §5.5.1's
        // "nothing more may go out" is not in force and the teardown keeps its
        // bounded graceful close. (The completed-handshake case cannot reach
        // this guard anyway: the discard there empties the queue and the
        // protocol drops its owed pongs, so Phase 2 builds nothing for it to
        // find.)
        let _ = discard_unwritten(&mut inner_mut.outbound, &mut inner_mut.pending_write);
      }
      doorbell.notify(usize::MAX);
      // Nothing is left to write, so this reaches the terminal check below.
      continue 'pump;
    }

    // The read buffer is `Inner::inbound` and NOT a local of this phase: a
    // local would be dropped by the `Input` arm's `continue 'pump`. Armed by
    // the drive itself, and only on the arm that reads, so a plain flush still
    // allocates nothing.
    while inner.borrow().pending_write.is_some() {
      // `None` is the unbounded plain flush; `Some(d)` is what is LEFT of this
      // flush's slice of the close budget. `race_read` marks the post-Close
      // arm, the one that also listens to the peer.
      let (bound, race_read): (FlushBound, bool) = {
        let guard = inner.borrow();
        // ONE absolute instant per entry; see `FlushBound`. `checked_add`
        // because `close_budget` is whatever the caller passed to
        // `with_close_timeout` and the sum can leave the clock's range.
        let at = |anchor: Instant| anchor.checked_add(guard.close_budget);
        // Arm 1 is keyed on `close_owed` ALONE: it carries its own anchor, so
        // there is no bound-without-anchor case to fall back from. It needs no
        // `|| carries_close` either — a batch carrying an unflushed Close can
        // only exist while the Close is still owed, since the one site that
        // discharges `close_owed` is that batch's own flush.
        if let Some(anchor) = guard.close_owed {
          (FlushBound::Close(at(anchor)), false)
        } else if let Some(flushed) = guard.close_flushed_at {
          (
            FlushBound::Echo(at(flushed)),
            // Every read is allowed, because the peer's Close may be behind
            // any of them — a peer is entitled to finish its current message
            // before answering ours. What is bounded is not how much is READ
            // but how much is KEPT: this input is flagged as observation and
            // Phase 1 assembles none of it. A gate on `ready` was the wrong
            // shape twice over — a message still arriving leaves `ready` empty
            // while the assembler grows to `max_message_size`, and one
            // completed message closes the gate over the very next read, which
            // is where the Close would have been.
            true,
          )
        } else {
          (FlushBound::Plain, false)
        }
      };
      let deadline = bound.deadline();
      let mut io = PumpIo::take(inner);
      // An early exit, not the mechanism any more: the drive checks the same
      // deadline immediately before every poll it makes, so one reached after
      // this line is caught there rather than here.
      let outcome = if deadline.is_some_and(|at| Instant::now() >= at) {
        FlushArm::Budget
      } else {
        let drive = drive_pending_write(&mut io, doorbell, race_read, deadline).fuse();
        let timer = async {
          match deadline {
            Some(at) => compio::time::sleep_until(at).await,
            None => futures_util::future::pending::<()>().await,
          }
        }
        .fuse();
        let bell = doorbell.listen().fuse();
        futures_util::pin_mut!(drive, timer, bell);
        // Lost-wake guard: a close queued between the bound computation
        // above and the listener registration would have rung an
        // unregistered bell — re-enter instead of parking unbounded. Keyed
        // on the timer being unbounded, which is what "parking" means here.
        if matches!(bound, FlushBound::Plain) && inner.borrow().close_owed.is_some() {
          FlushArm::Reconsider
        } else {
          futures_util::select_biased! {
            result = drive => match result {
              DriveOutcome::Written(result) => FlushArm::Done(result),
              DriveOutcome::Input(result) => FlushArm::Input(result),
              DriveOutcome::Expired => FlushArm::Budget,
            },
            () = timer => FlushArm::Budget,
            () = bell => FlushArm::Reconsider,
          }
        }
      };
      match outcome {
        FlushArm::Done(Ok(())) => {
          drop(io);
          // Re-settle from the top: the close frame may have just gone
          // out, and frames enqueued during the flush coalesce next pass
          // (their doorbell ring predates any new listener).
          continue 'pump;
        }
        FlushArm::Done(Err(e)) => return Some(Err(e)),
        FlushArm::Budget => match close_flush_timed_out(inner, io, doorbell) {
          // The outcome is recorded and the transport is gone. Fall through to
          // delivery rather than returning it: messages assembled behind the
          // blocked write arrived BEFORE the peer stopped answering, and this
          // pump's contract is that buffered messages drain before `None`. The
          // terminal check is reached once `ready` empties, and there is
          // nothing left to write for Phase 3 to find.
          None => continue 'pump,
          Some(result) => return Some(result),
        },
        // Re-evaluate the bound (the guard restores the partial batch);
        // ordinary sender wake-ups simply resume the flush.
        FlushArm::Reconsider => drop(io),
        // Inbound bytes beat the blocked write. The guard restores the
        // partial batch, so Phase 1 feeds these bytes, Phase 2 skips building
        // (a batch is already in progress), and this loop resumes the SAME
        // batch under the same monotone remaining time. A peer Close with our
        // Close already flushed completes the handshake in Phase 1 and takes
        // this batch with it.
        FlushArm::Input(Ok(0)) => {
          drop(io);
          // The same reading Phase 4 gives it.
          debug!("transport EOF before the close handshake completed");
          let kind = std::io::ErrorKind::UnexpectedEof;
          terminate_io(&mut inner.borrow_mut(), kind, doorbell, None);
          return Some(Err(Error::Io(kind.into())));
        }
        FlushArm::Input(Ok(n)) => {
          drop(io);
          trace!(
            bytes = n,
            "transport read behind a blocked post-close write"
          );
          {
            let mut guard = inner.borrow_mut();
            // The flag describes the WHOLE of what is unconsumed, so nothing
            // else may be in front of these bytes: Phase 1 takes all of
            // `inbound` on every pass where `closed` is none, and Phase 4 —
            // the only other source — cannot run while a batch is pending.
            // Asserted rather than argued, so a future path that leaves
            // ordinary input in front of these fails loudly instead of having
            // it silently observed. (The drive has already committed the read,
            // so `inbound` is exactly those `n` bytes.)
            debug_assert!(
              guard.inbound.len() == n,
              "observation input must not be mixed with input nobody flagged"
            );
            guard.observation_input = true;
            #[cfg(test)]
            {
              guard.observation_reads += 1;
            }
          }
          continue 'pump;
        }
        FlushArm::Input(Err(e)) => {
          drop(io);
          terminate_io(&mut inner.borrow_mut(), e.kind(), doorbell, None);
          return Some(Err(Error::Io(e)));
        }
      }
    }

    // Deliver — only after everything the protocol owed (pong echoes,
    // close frames) reached the wire above: a caller may stop polling
    // after a returned message, and RFC 6455 §5.5 wants control replies
    // out "as soon as practical".
    if let Some(message) = inner.borrow_mut().ready.pop_front() {
      return Some(Ok(message));
    }

    // Terminal check — reached only once delivery is drained and phase 2
    // found NOTHING left to write, so a recorded close here means echo,
    // queue, and marker are all on the wire. The single `None` producer:
    // shut the transport down (TLS close_notify / TCP FIN) — the split
    // path tears down through here too.
    if inner.borrow().closed.is_some() {
      teardown(inner).await;
      return None;
    }

    // Phase 4 (IO, guarded): park on read / timer / doorbell. The losing
    // arms drop poll-based futures, which is loss-free: a partial read
    // lives in the transport's own buffers, never in the dropped future.
    let mut io = PumpIo::take(inner);
    // The same vector Phase 3 reads into, and for the same reason: a fresh
    // `vec![0u8; READ_CHUNK]` per parked read is an allocation a peer drives.
    let start = io.arm_inbound();
    if io.stream.is_none() {
      commit_read(&mut io, start, 0);
      return Some(Err(stream_gone()));
    }
    let PumpIo {
      stream, inbound, ..
    } = &mut io;
    let Some(stream) = stream.as_mut() else {
      return Some(Err(stream_gone()));
    };
    let outcome = {
      let read = stream
        .read(inbound.get_mut(start..).unwrap_or(&mut []))
        .fuse();
      let timer = async {
        match deadline {
          // An ABSOLUTE deadline, so no `Instant + Duration` anywhere on the
          // path: `sleep_until` takes the instant `effective_deadline` already
          // computed with `checked_add`, and a past one resolves at once.
          Some(at) => compio::time::sleep_until(at).await,
          None => futures_util::future::pending::<()>().await,
        }
      }
      .fuse();
      let bell = doorbell.listen().fuse();
      futures_util::pin_mut!(read, timer, bell);
      futures_util::select_biased! {
        result = read => Park::Read(result),
        () = timer => Park::Timer,
        () = bell => Park::Doorbell,
      }
    };
    // Every arm, not only the reading one: the window is zero-filled.
    let read_n = match &outcome {
      Park::Read(Ok(n)) => *n,
      _ => 0,
    };
    commit_read(&mut io, start, read_n);
    drop(io);

    match outcome {
      Park::Read(Ok(0)) => {
        // The terminal check returns `None` before this read is ever
        // created once `closed` is recorded, so a parked read only
        // resolves to EOF while the connection is open.
        debug!("transport EOF before the close handshake completed");
        let kind = std::io::ErrorKind::UnexpectedEof;
        terminate_io(&mut inner.borrow_mut(), kind, doorbell, None);
        return Some(Err(Error::Io(kind.into())));
      }
      Park::Read(Ok(n)) => {
        trace!(bytes = n, "transport read");
        // The bytes are already in `inbound`, committed above.
        #[cfg(test)]
        {
          inner.borrow_mut().reads_seen += 1;
        }
      }
      Park::Read(Err(e)) => {
        terminate_io(&mut inner.borrow_mut(), e.kind(), doorbell, None);
        return Some(Err(Error::Io(e)));
      }
      // The next pass's settle advances the timers (one code path, with
      // the flush-anchored deadline correction applied).
      Park::Timer | Park::Doorbell => {}
    }
  }
}

enum Park {
  Read(std::io::Result<usize>),
  Timer,
  Doorbell,
}

/// Which of Phase 3's three bounds an entry took, carrying the ONE absolute
/// instant it is measured against.
///
/// An instant rather than a remaining duration, computed once per entry: a
/// duration handed to a timer that reads the clock again schedules
/// `second_now + remaining`, which gives the gap between the two readings back
/// to the budget — and preemption between them is exactly when that gap is
/// worth having. `checked_add` for the reason `effective_deadline` uses it
/// (`close_timeout` is the caller's), and a deadline the clock cannot
/// represent is one that can never be reached, so it is no deadline at all.
///
/// The variant is kept rather than collapsed into the `Option<Instant>`,
/// because "no deadline" and "the plain unbounded arm" are different facts:
/// the lost-wake guard below asks about the arm, and an overflowed close
/// deadline would answer the other question the same way.
enum FlushBound {
  /// A Close is owed: the whole budget, from the request.
  Close(Option<Instant>),
  /// Our Close has flushed: what remains of the echo budget. The only arm
  /// that may also poll a read.
  ///
  /// **`None` here is an unbounded wait, and it is the caller's own request.**
  /// The instant is `close_flushed_at.checked_add(close_budget)`, so a budget
  /// the clock cannot represent — `with_close_timeout(Duration::MAX)` —
  /// answers `None`, the timer becomes `future::pending()`, and this arm parks
  /// on the peer with no end. What that costs is CHURN rather than retention:
  /// every pass of the loop below registers a doorbell listener and a timer
  /// (~600 bytes, freed when the pass ends), so a peer that keeps driving
  /// re-entry drives that allocation for as long as it likes. Retention stays
  /// bounded by one read chunk plus the protocol's own buffers, because the
  /// input this arm reads is observation input and nothing accumulates it.
  /// Disclosed rather than clamped: an unbounded wait is what the budget
  /// asked for, and flooring it would silently give a caller a deadline it
  /// did not choose.
  Echo(Option<Instant>),
  /// A plain flush with no Close in its past: unbounded, and it parks.
  Plain,
}

impl FlushBound {
  fn deadline(&self) -> Option<Instant> {
    match self {
      Self::Close(at) | Self::Echo(at) => *at,
      Self::Plain => None,
    }
  }
}

enum FlushArm {
  Done(Result<(), Error>),
  Budget,
  Reconsider,
  Input(std::io::Result<usize>),
}

#[cfg(test)]
mod tests;
