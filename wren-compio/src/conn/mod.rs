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
  ///
  /// Written only by [`Inner::request_close`], which is what keeps it and
  /// `close_requested_at` from ever disagreeing.
  close_pending: bool,
  /// When the Close now owed was FIRST requested — the absolute anchor the
  /// flush bound is measured from. A bound recomputed as a fresh whole budget
  /// on every re-entry is not a bound: a doorbell ring restores the partial
  /// batch and re-enters, so a local sender that rings faster than the budget
  /// keeps a wedged Close flush alive forever. Reading the remaining time from
  /// a fixed instant instead makes it monotone across cancellation, doorbell
  /// re-entry, and resume.
  close_requested_at: Option<Instant>,
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

impl<Ro, S> Inner<Ro, S> {
  /// Records that a Close is owed to the wire, and anchors the budget for
  /// getting it there.
  ///
  /// The SOLE writer of `close_pending`, so that the flag and its anchor are
  /// set in one statement and no later site can raise one without the other.
  /// The anchor is the FIRST request's instant: a second Close requested while
  /// one is still pending (our `close()` and then the peer's, before either
  /// reached the wire) does not extend the budget, because the budget is for
  /// getting a Close out and that started at the first request.
  fn request_close(&mut self, now: Instant) {
    if !self.close_pending {
      self.close_pending = true;
      self.close_requested_at = Some(now);
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
        pending_input: leftover,
        assembler: MessageAssembler::new(cap),
        ready: VecDeque::new(),
        outbound: VecDeque::new(),
        pending_write: None,
        closed: None,
        staged_close: None,
        close_pending: false,
        close_requested_at: None,
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
        inner.request_close(Instant::now());
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

/// What one drive resolved to.
pub(crate) enum DriveOutcome {
  /// The batch finished, or failed; the frame states are settled.
  Written(Result<(), Error>),
  /// Inbound bytes arrived while the write was blocked. Reachable only when
  /// the caller hands over a read buffer.
  Input(std::io::Result<usize>),
}

/// The same, before the frame states are settled.
enum RawDrive {
  Written(std::io::Result<()>),
  Input(std::io::Result<usize>),
}

/// Drives the guard's pending write to the wire: byte cursor loop, then
/// flush, then frame-state transitions. The cursor advances only on
/// completed sub-writes, so cancellation mid-batch resumes losslessly.
///
/// With `read_into`, a write that CANNOT progress also polls the inbound
/// direction and yields whatever arrives. The two directions are independent,
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
async fn drive_pending_write<Ro, S: Duplex>(
  io: &mut PumpIo<'_, Ro, S>,
  doorbell: &Doorbell,
  read_into: Option<&mut [u8]>,
) -> DriveOutcome {
  let raw = {
    let PumpIo {
      stream,
      write: batch,
      ..
    } = &mut *io;
    let Some(stream) = stream.as_mut() else {
      return DriveOutcome::Written(Err(stream_gone()));
    };
    let Some(pending) = batch.as_mut() else {
      return DriveOutcome::Written(Ok(()));
    };
    let mut read_into = read_into;
    futures_util::future::poll_fn(move |cx| {
      loop {
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
  let result = match raw {
    RawDrive::Input(result) => return DriveOutcome::Input(result),
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
    match drive_pending_write(&mut io, doorbell, None).await {
      DriveOutcome::Written(result) => result?,
      // No read buffer was handed over, so nothing reads here. Looping
      // re-drives the same batch, which is what this path would want anyway.
      DriveOutcome::Input(_) => {}
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
  let (stream, budget) = {
    let mut guard = inner.borrow_mut();
    (guard.stream.take(), guard.close_budget)
  };
  let Some(mut stream) = stream else {
    return;
  };
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
  if guard.close_pending {
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
      if guard.closed.is_none() && !guard.pending_input.is_empty() {
        let mut input = std::mem::take(&mut guard.pending_input);
        let inner_mut = &mut *guard;
        let now = Instant::now();
        // The event cursor borrows `conn`, so nothing inside the loop may take
        // `&mut Inner` as a whole: the transition is flagged there and made
        // through its single writer once the cursor is gone, below. Deferring
        // it cannot lose the transition — `Closed` makes the connection
        // terminal and the cursor answers `None` from there on, and the
        // assembler passes `Closed` through as `Ok(None)`, so no early return
        // can sit between the flag and the call.
        let mut close_owed = false;
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
                  while let Some(frame) = inner_mut.outbound.pop_front() {
                    frame.state.set(FrameState::ClosedBeforeWrite);
                  }
                  if let Some(pending) = inner_mut.pending_write.take_if(|p| !p.carries_close) {
                    for state in &pending.states {
                      state.set(FrameState::ClosedBeforeWrite);
                    }
                  }
                  wake_senders = true;
                } else {
                  // Stage, do not publish: the outcome only holds once the
                  // echo the protocol just queued reaches the wire.
                  inner_mut.staged_close = Some(*closed);
                  close_owed = true;
                }
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
        // All input is consumed by the cursor (drop-drains). The cursor is
        // gone here, so the whole `Inner` is borrowable again — and this runs
        // BEFORE the settle below, which reads `close_pending`.
        if close_owed {
          guard.request_close(now);
        }
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
        // the drain: `close_pending` is the driver's "a Close is owed", which
        // stays set until the frame FLUSHES and therefore also labels every
        // batch built while it sits unflushed — batches that carry no Close at
        // all. A mislabelled batch settles `close_pending` and re-anchors the
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
        } else if guard.close_pending {
          // A Close is owed and the protocol has nothing to give: it drained
          // into a batch that then never reached the wire (a cancelled pump's
          // batch is restored, not dropped, so this is the torn-down cases).
          // The peer-echoed-a-close-we-flushed case that used to arrive here
          // is settled a phase earlier now — Phase 1 completes the handshake
          // on receipt when `close_flushed_at` is set, and never marks a Close
          // owed for it. Kept rather than deleted because it is the only other
          // publisher of a staged outcome, and dropping it would leave one
          // stranded instead of failing loudly.
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

    // Phase 3 (IO, guarded): put the batch on the wire, under one of THREE
    // bounds. While a Close is owed (in this batch, or queued behind it),
    // the flush gets the whole close budget — close_timeout must bound the
    // handshake even against a peer that stopped reading, and the echo
    // budget only starts once the Close is out (it re-arms at flush).
    //
    // Once the Close HAS flushed, any further write — a post-Close Pong
    // batch, which exists now that the protocol keeps answering Pings until
    // the peer's Close arrives — is bounded by what REMAINS of that echo
    // budget. It must be: such a batch carries no Close and `close_pending`
    // is already cleared, so the old two-way choice parked it unbounded and
    // a peer that filled the socket and stopped reading wedged it forever,
    // defeating the very bound `close_timeout` documents. The remaining time
    // is read from `close_flushed_at` DIRECTLY rather than through
    // `effective_deadline`, which answers `None` once the peer's Close has
    // cleared the protocol timer — and `None` there would leave exactly this
    // batch unbounded again.
    //
    // BOTH bounded arms are remaining time from an ABSOLUTE anchor, never a
    // fresh budget: `close_requested_at` for the first, `close_flushed_at`
    // for the second. A `Reconsider` re-entry recomputes from the same
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
    while inner.borrow().pending_write.is_some() {
      // `None` is the unbounded plain flush; `Some(d)` is what is LEFT of this
      // flush's slice of the close budget. `race_read` marks the post-Close
      // arm, the one that also listens to the peer.
      let (bound, race_read): (Option<core::time::Duration>, bool) = {
        let guard = inner.borrow();
        let carries_close = guard
          .pending_write
          .as_ref()
          .is_some_and(|p| p.carries_close);
        let now = Instant::now();
        // Subtract, never add: `close_budget` is whatever the caller passed to
        // `with_close_timeout`, and `anchor + budget` can leave the clock's
        // range and panic. An elapsed duration cannot.
        let remaining = |anchor: Instant| {
          guard
            .close_budget
            .saturating_sub(now.saturating_duration_since(anchor))
        };
        if guard.close_pending || carries_close {
          // `request_close` is the only writer of `close_pending` and it sets
          // the anchor in the same statement, so `None` here is unreachable.
          // It resolves to the whole budget rather than to no bound, because
          // an unbounded close flush is the defect `close_timeout` exists to
          // prevent and a lost anchor must not reintroduce it.
          (
            Some(
              guard
                .close_requested_at
                .map_or(guard.close_budget, remaining),
            ),
            false,
          )
        } else {
          (
            guard.close_flushed_at.map(remaining),
            guard.close_flushed_at.is_some(),
          )
        }
      };
      let mut read_scratch = race_read.then(|| vec![0u8; READ_CHUNK]);
      let mut io = PumpIo::take(inner);
      let outcome = if bound.is_some_and(|remaining| remaining.is_zero()) {
        FlushArm::Budget
      } else {
        let drive = drive_pending_write(&mut io, doorbell, read_scratch.as_deref_mut()).fuse();
        let timer = async {
          match bound {
            Some(remaining) => sleep_for(remaining).await,
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
        if bound.is_none() && inner.borrow().close_pending {
          FlushArm::Reconsider
        } else {
          futures_util::select_biased! {
            result = drive => match result {
              DriveOutcome::Written(result) => FlushArm::Done(result),
              DriveOutcome::Input(result) => FlushArm::Input(result),
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
        FlushArm::Budget => return close_flush_timed_out(inner, io, doorbell),
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
          return Some(Err(Error::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
          ))));
        }
        FlushArm::Input(Ok(n)) => {
          drop(io);
          trace!(
            bytes = n,
            "transport read behind a blocked post-close write"
          );
          let read = read_scratch.as_deref().and_then(|b| b.get(..n));
          inner
            .borrow_mut()
            .pending_input
            .extend_from_slice(read.unwrap_or(&[]));
          continue 'pump;
        }
        FlushArm::Input(Err(e)) => {
          drop(io);
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
    let Some(stream) = io.stream.as_mut() else {
      return Some(Err(stream_gone()));
    };
    let mut scratch = vec![0u8; READ_CHUNK];
    let outcome = {
      let read = stream.read(&mut scratch).fuse();
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
  Input(std::io::Result<usize>),
}

#[cfg(test)]
mod tests;
