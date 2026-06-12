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
  rc::Rc,
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
  /// The batch contains a Close frame; flushing it settles
  /// `Inner::close_pending`.
  carries_close: bool,
}

pub(crate) struct Inner<Ro, S> {
  conn: Connection<Instant, Ro>,
  /// `None` only while a [`PumpIo`] guard owns the stream, or after
  /// teardown.
  stream: Option<S>,
  /// Inbound bytes not yet fed to `conn` (handshake leftover, then reads).
  pending_input: Vec<u8>,
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
  /// A Close frame is owed to the wire (queued locally via `close`, or
  /// the echo the protocol queued for a received Close) and has not been
  /// flushed yet. While set, the close deadline is suspended — its budget
  /// cannot start before the peer can possibly have seen our Close.
  close_pending: bool,
  /// When the close-carrying batch reached the wire. The protocol arms
  /// its deadline when the Close DRAINS into a batch; under backpressure
  /// the flush can consume that whole budget, so the driver re-anchors
  /// the deadline here: it fires at `close_flushed_at + close_budget`.
  close_flushed_at: Option<Instant>,
  /// The effective close timeout (mirrors the protocol config).
  close_budget: core::time::Duration,
  /// Set on the first write-path failure. A failed batch may have left a
  /// partial frame on the wire, so everything after it is refused with
  /// this kind rather than splicing fresh frames into a corrupt stream.
  poisoned: Option<std::io::ErrorKind>,
  read_half_alive: bool,
  is_split: bool,
  #[cfg(test)]
  pings_seen: usize,
  #[cfg(test)]
  pongs_seen: usize,
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
        pending_input: leftover,
        assembler: MessageAssembler::new(cap),
        ready: VecDeque::new(),
        outbound: VecDeque::new(),
        pending_write: None,
        closed: None,
        staged_close: None,
        close_pending: false,
        close_flushed_at: None,
        close_budget,
        poisoned: None,
        read_half_alive: true,
        is_split: false,
        #[cfg(test)]
        pings_seen: 0,
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
      if inner.closed.is_none() {
        debug!(code = ?code, reason, "starting close handshake");
        inner.conn.close(code, reason)?;
        inner.close_pending = true;
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
}

impl<'a, Ro, S> PumpIo<'a, Ro, S> {
  fn take(inner: &'a Rc<RefCell<Inner<Ro, S>>>) -> Self {
    let (stream, write) = {
      let mut guard = inner.borrow_mut();
      (guard.stream.take(), guard.pending_write.take())
    };
    Self {
      inner,
      stream,
      write,
    }
  }
}

impl<Ro, S> Drop for PumpIo<'_, Ro, S> {
  fn drop(&mut self) {
    let mut guard = self.inner.borrow_mut();
    guard.stream = self.stream.take();
    guard.pending_write = self.write.take();
  }
}

fn stream_gone() -> Error {
  Error::Io(std::io::Error::from(std::io::ErrorKind::ResourceBusy))
}

/// Drives the guard's pending write to the wire: byte cursor loop, then
/// flush, then frame-state transitions. The cursor advances only on
/// completed sub-writes, so cancellation mid-batch resumes losslessly.
async fn drive_pending_write<Ro, S: Duplex>(
  io: &mut PumpIo<'_, Ro, S>,
  doorbell: &Doorbell,
) -> Result<(), Error> {
  let Some(stream) = io.stream.as_mut() else {
    return Err(stream_gone());
  };
  let Some(pending) = io.write.as_mut() else {
    return Ok(());
  };
  let result = 'drive: {
    while pending.cursor < pending.bytes.len() {
      match stream.write(&pending.bytes[pending.cursor..]).await {
        Ok(0) => break 'drive Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
        Ok(n) => pending.cursor += n,
        Err(e) => break 'drive Err(e),
      }
    }
    // The batch is fully handed to the transport; flush puts buffered
    // bytes (the adapter's, TLS records) on the wire. Idempotent, so a
    // cancellation between the last write and here re-flushes on resume.
    stream.flush().await
  };
  let pending = io.write.take().expect("checked above");
  match result {
    Ok(()) => {
      for state in &pending.states {
        state.set(FrameState::Written);
      }
      if pending.carries_close {
        let mut guard = io.inner.borrow_mut();
        guard.close_pending = false;
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
      for state in &pending.states {
        state.set(FrameState::Failed(kind));
      }
      // A partial frame may be on the wire: poison the connection so no
      // later frame splices into the corrupt stream, and fail everything
      // still queued (nothing will ever drain it).
      {
        let mut guard = io.inner.borrow_mut();
        guard.poisoned = Some(kind);
        while let Some(frame) = guard.outbound.pop_front() {
          frame.state.set(FrameState::Failed(kind));
        }
      }
      doorbell.notify(usize::MAX);
      Err(Error::Io(e))
    }
  }
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
    drive_pending_write(&mut io, doorbell).await?;
  }
}

/// Tears the transport down after the close handshake (or on abandonment):
/// best-effort write-side close (TLS close_notify / TCP FIN), then drop.
/// The attempt runs under the close budget — a close_notify against a
/// peer that stopped reading must not turn a finished handshake into a
/// hang — and consuming the stream makes repeated calls no-ops.
async fn teardown<Ro, S: Duplex>(inner: &Rc<RefCell<Inner<Ro, S>>>) {
  let (stream, budget) = {
    let mut guard = inner.borrow_mut();
    (guard.stream.take(), guard.close_budget)
  };
  let Some(mut stream) = stream else {
    return;
  };
  trace!("shutting the transport down");
  let close = stream.close().fuse();
  let timer = compio::time::sleep(budget).fuse();
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
  let outcome = {
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
    if let Some(closed) = guard.conn.handle_timeout(Instant::now()) {
      guard.closed = Some(closed);
      None
    } else {
      // No protocol verdict (the Close never even drained into a
      // batch): fail sticky instead of publishing any outcome.
      guard.poisoned = Some(kind);
      Some(Err(Error::Io(kind.into())))
    }
  };
  doorbell.notify(usize::MAX);
  outcome
}

/// The protocol deadline, corrected for transport flush: while the Close
/// is still unflushed its budget has not started (`None`), and once it
/// flushed the deadline counts from that instant — the protocol arms it
/// when the Close drains into a batch, which under backpressure can be a
/// whole budget earlier than the peer could possibly have seen it. The
/// keepalive needs no correction (the protocol only arms it while open).
fn effective_deadline<Ro: role::Role, S>(guard: &Inner<Ro, S>) -> Option<Instant> {
  let at = guard.conn.poll_timeout()?;
  if guard.close_pending {
    return None;
  }
  match guard.close_flushed_at {
    Some(flushed) => Some(at.max(flushed + guard.close_budget)),
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
    {
      let mut guard = inner.borrow_mut();
      if let Some(kind) = guard.poisoned {
        return Some(Err(Error::Io(kind.into())));
      }
      if guard.closed.is_none() && !guard.pending_input.is_empty() {
        let mut input = std::mem::take(&mut guard.pending_input);
        let inner_mut = &mut *guard;
        let now = Instant::now();
        match inner_mut.conn.handle(now, &mut input) {
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
                // Stage, do not publish: the outcome only holds once the
                // echo the protocol just queued reaches the wire.
                inner_mut.staged_close = Some(*closed);
                inner_mut.close_pending = true;
              }
              match inner_mut.assembler.push(&event) {
                Ok(Some(message)) => inner_mut.ready.push_back(message),
                Ok(None) => {}
                Err(e) => return Some(Err(e.into())),
              }
            }
          }
          Err(e) => return Some(Err(e.into())),
        }
        // All input is consumed by the cursor (drop-drains).
      }
      // Settle overdue protocol timers on every pass — AFTER the input
      // feed, so an echo that already arrived beats the deadline clock
      // (wall time may have advanced while the future sat unpolled), but
      // BEFORE message delivery, so a steady inbound flood of ready
      // messages cannot starve the close deadline or the keepalive.
      {
        let now = Instant::now();
        if effective_deadline(&guard).is_some_and(|at| at <= now)
          && let Some(closed) = guard.conn.handle_timeout(now)
        {
          debug!(clean = closed.clean(), "close deadline elapsed");
          guard.closed = Some(closed);
        }
      }
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
        loop {
          match guard.conn.poll_transmit(now, &mut scratch) {
            Ok(Some(n)) => bytes.extend_from_slice(scratch.get(..n).unwrap_or(&[])),
            Ok(None) => break,
            Err(e) => return Some(Err(e.into())),
          }
        }
        if !bytes.is_empty() {
          guard.pending_write = Some(PendingWrite {
            bytes,
            cursor: 0,
            states,
            carries_close: guard.close_pending,
          });
        } else if guard.close_pending {
          // Nothing left to transmit: the owed Close is already on the
          // wire (e.g. the peer echoed a close we flushed earlier).
          guard.close_pending = false;
          if guard.closed.is_none()
            && let Some(staged) = guard.staged_close.take()
          {
            guard.closed = Some(staged);
          }
        }
      }
      effective_deadline(&guard)
    };

    // Phase 3 (IO, guarded): put the batch on the wire. While a Close is
    // owed (in this batch, or queued behind it), the flush itself gets
    // the close budget — close_timeout must bound the whole handshake
    // even against a peer that stopped reading, and the echo budget only
    // starts once the Close is out (it re-arms at flush). A plain flush
    // instead parks unbounded, but listens to the doorbell: a close
    // requested mid-flush re-enters as a bounded flush (the dropped
    // drive's progress survives in the cursor).
    while inner.borrow().pending_write.is_some() {
      let close_involved = {
        let guard = inner.borrow();
        guard.close_pending
          || guard
            .pending_write
            .as_ref()
            .is_some_and(|p| p.carries_close)
      };
      let budget = inner.borrow().close_budget;
      let mut io = PumpIo::take(inner);
      let outcome = {
        let drive = drive_pending_write(&mut io, doorbell).fuse();
        let timer = async {
          if close_involved {
            compio::time::sleep(budget).await;
          } else {
            futures_util::future::pending::<()>().await;
          }
        }
        .fuse();
        let bell = doorbell.listen().fuse();
        futures_util::pin_mut!(drive, timer, bell);
        // Lost-wake guard: a close queued between the close_involved
        // read and the listener registration above would have rung an
        // unregistered bell — re-enter instead of parking unbounded.
        if !close_involved && inner.borrow().close_pending {
          FlushArm::Reconsider
        } else {
          futures_util::select_biased! {
            result = drive => FlushArm::Done(result),
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
        FlushArm::Budget => return close_flush_timed_out(inner, io, doorbell),
        // Re-evaluate close_involved (the guard restores the partial
        // batch); ordinary sender wake-ups simply resume the flush.
        FlushArm::Reconsider => drop(io),
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
    let Some(stream) = io.stream.as_mut() else {
      return Some(Err(stream_gone()));
    };
    let mut scratch = vec![0u8; READ_CHUNK];
    let outcome = {
      let read = stream.read(&mut scratch).fuse();
      let timer = async {
        match deadline {
          Some(at) => {
            let now = Instant::now();
            compio::time::sleep(at.saturating_duration_since(now)).await;
          }
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
    drop(io);

    match outcome {
      Park::Read(Ok(0)) => {
        // The terminal check returns `None` before this read is ever
        // created once `closed` is recorded, so a parked read only
        // resolves to EOF while the connection is open.
        debug!("transport EOF before the close handshake completed");
        return Some(Err(Error::Io(std::io::Error::from(
          std::io::ErrorKind::UnexpectedEof,
        ))));
      }
      Park::Read(Ok(n)) => {
        trace!(bytes = n, "transport read");
        let mut guard = inner.borrow_mut();
        guard
          .pending_input
          .extend_from_slice(scratch.get(..n).unwrap_or(&[]));
      }
      Park::Read(Err(e)) => return Some(Err(Error::Io(e))),
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

enum FlushArm {
  Done(Result<(), Error>),
  Budget,
  Reconsider,
}

#[cfg(test)]
mod tests;
