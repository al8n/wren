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
  read_half_alive: bool,
  is_split: bool,
  #[cfg(test)]
  pings_seen: usize,
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
) -> (ConnectionConfig, usize) {
  let mut config = ConnectionConfig::new();
  if keepalive.is_some() {
    config = config.with_keepalive(keepalive);
  }
  if let Some(t) = close_timeout {
    config = config.with_close_timeout(t);
  }
  let cap = max_message_size.unwrap_or(64 << 20);
  config = config.with_max_message_size(cap as u64);
  (config, cap)
}

impl<S: Duplex> WebSocket<ClientRole, S> {
  pub(crate) fn client(
    stream: S,
    negotiated: &Negotiated,
    options: &ClientOptions,
    leftover: Vec<u8>,
  ) -> Self {
    use rand::SeedableRng;
    let (config, cap) = build_config(
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
    Self::with_conn(stream, conn, cap, leftover)
  }
}

impl<S: Duplex> WebSocket<ServerRole, S> {
  pub(crate) fn server(
    stream: S,
    negotiated: &Negotiated,
    options: &AcceptOptions,
    leftover: Vec<u8>,
  ) -> Self {
    let (config, cap) = build_config(
      options.keepalive,
      options.close_timeout,
      options.max_message_size,
    );
    let conn = Connection::new(negotiated, config, role::Server::new(), Instant::now());
    Self::with_conn(stream, conn, cap, leftover)
  }
}

impl<Ro: role::Role, S: Duplex> WebSocket<Ro, S> {
  fn with_conn(stream: S, conn: Connection<Instant, Ro>, cap: usize, leftover: Vec<u8>) -> Self {
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
        read_half_alive: true,
        is_split: false,
        #[cfg(test)]
        pings_seen: 0,
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
  /// the transport error (commonly `UnexpectedEof`); waiting out such peers
  /// is what [`ClientOptions::with_close_timeout`] bounds.
  ///
  /// [`ClientOptions::with_close_timeout`]: crate::ClientOptions::with_close_timeout
  pub async fn close(self, code: CloseCode, reason: &str) -> Result<Closed, Error> {
    {
      let mut inner = self.inner.borrow_mut();
      if inner.closed.is_none() {
        debug!(code = ?code, reason, "starting close handshake");
        inner.conn.close(code, reason)?;
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
      doorbell.notify(usize::MAX);
      Ok(())
    }
    Err(e) => {
      warn!(error = %e, "transport write failed");
      let kind = e.kind();
      for state in &pending.states {
        state.set(FrameState::Failed(kind));
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
/// Consuming the stream makes repeated calls no-ops.
async fn teardown<Ro, S: Duplex>(inner: &Rc<RefCell<Inner<Ro, S>>>) {
  let Some(mut stream) = inner.borrow_mut().stream.take() else {
    return;
  };
  trace!("shutting the transport down");
  let _ = stream.close().await;
}

/// The shared pump: drives the connection until a data message completes,
/// the connection closes (`None`), or an error surfaces.
pub(crate) async fn next_message<Ro: role::Role, S: Duplex>(
  inner: &Rc<RefCell<Inner<Ro, S>>>,
  doorbell: &Rc<Doorbell>,
) -> Option<Result<Message, Error>> {
  loop {
    // Phase 1 (borrow): feed pending input through the state machine.
    // Buffered `ready` messages drain even after the close is recorded
    // (they arrived before the peer's Close); new input does not.
    {
      let mut guard = inner.borrow_mut();
      if let Some(message) = guard.ready.pop_front() {
        return Some(Ok(message));
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
              if let Event::Closed(closed) = &event {
                debug!(code = ?closed.code(), clean = closed.clean(), "connection closed");
                inner_mut.closed = Some(*closed);
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
      if let Some(message) = guard.ready.pop_front() {
        return Some(Ok(message));
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
          });
        }
      }
      guard.conn.poll_timeout()
    };

    // Phase 3 (IO, guarded): put the batch on the wire.
    if inner.borrow().pending_write.is_some() {
      let mut io = PumpIo::take(inner);
      match drive_pending_write(&mut io, doorbell).await {
        Ok(()) => {
          drop(io);
          continue; // re-settle: the close frame may have just gone out
        }
        Err(e) => return Some(Err(e)),
      }
    }

    // Terminal check — reached only when phase 2 found NOTHING left to
    // write (a non-empty batch loops back through phase 1 instead), so a
    // recorded close here means echo, queue, and marker are all on the
    // wire. The single `None` producer: shut the transport down (TLS
    // close_notify / TCP FIN) — the split path tears down through here
    // too.
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
        // Phase 1/3 already return `None` whenever `closed` is recorded, so
        // a parked read only resolves to EOF while the connection is open.
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
      Park::Timer => {
        let mut guard = inner.borrow_mut();
        let now = Instant::now();
        if let Some(closed) = guard.conn.handle_timeout(now) {
          debug!(clean = closed.clean(), "close deadline elapsed");
          guard.closed = Some(closed);
        }
      }
      Park::Doorbell => {}
    }
  }
}

enum Park {
  Read(std::io::Result<usize>),
  Timer,
  Doorbell,
}

#[cfg(test)]
mod tests;
