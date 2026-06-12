//! The WebSocket connection object. No background task: `next()` is the
//! pump — reads, timers, protocol transmits, and (when split) queued writes
//! all progress inside it.
//!
//! Concurrency model (thread-per-core, `!Send`): all state lives in
//! `Rc<RefCell<Inner>>`, and a `RefCell` borrow is NEVER held across an
//! `.await`. The pump takes the stream out of `Inner` by value for the
//! duration of one step, so dropping a losing `select!` arm cancels only
//! that read future (and its per-read buffer) — the stream itself survives
//! in the pump's locals.

use std::{
  cell::{Cell, RefCell},
  collections::VecDeque,
  rc::Rc,
  time::Instant,
};

use compio_buf::BufResult;
use compio_io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use event_listener::Event as Doorbell;
use futures_util::FutureExt;
use websocket_proto::{
  Connection, ConnectionConfig, Negotiated,
  connection::{Closed, Event, role},
  frame::CloseCode,
  message::{Message, MessageAssembler},
};

use crate::{
  error::Error,
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

pub(crate) struct Inner<Ro, S> {
  conn: Connection<Instant, Ro>,
  /// `None` only while the pump owns the stream across an await.
  stream: Option<S>,
  /// Inbound bytes not yet fed to `conn` (handshake leftover, then reads).
  pending_input: Vec<u8>,
  assembler: MessageAssembler,
  /// Completed messages not yet handed out (one input chunk can finish
  /// several).
  ready: VecDeque<Message>,
  outbound: VecDeque<OutboundFrame>,
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

impl<S: AsyncRead + AsyncWrite + 'static> WebSocket<ClientRole, S> {
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

impl<S: AsyncRead + AsyncWrite + 'static> WebSocket<ServerRole, S> {
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

impl<Ro: role::Role, S: AsyncRead + AsyncWrite + 'static> WebSocket<Ro, S> {
  fn with_conn(stream: S, conn: Connection<Instant, Ro>, cap: usize, leftover: Vec<u8>) -> Self {
    Self {
      inner: Rc::new(RefCell::new(Inner {
        conn,
        stream: Some(stream),
        pending_input: leftover,
        assembler: MessageAssembler::new(cap),
        ready: VecDeque::new(),
        outbound: VecDeque::new(),
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
  pub async fn close(self, code: CloseCode, reason: &str) -> Result<Closed, Error> {
    {
      let mut inner = self.inner.borrow_mut();
      if inner.closed.is_none() {
        inner.conn.close(code, reason)?;
      }
    }
    loop {
      match next_message(&self.inner, &self.doorbell).await {
        Some(Ok(_discarded)) => continue,
        Some(Err(e)) => return Err(e),
        None => break,
      }
    }
    let Some(closed) = self.inner.borrow().closed else {
      // `next_message` only returns `None` with the outcome recorded.
      return Err(Error::Closed);
    };
    teardown(&self.inner).await;
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

/// Unsplit direct write, or enqueue-and-wait when split.
async fn send_frame<Ro: role::Role, S: AsyncRead + AsyncWrite + 'static>(
  inner: &Rc<RefCell<Inner<Ro, S>>>,
  doorbell: &Rc<Doorbell>,
  frame: Vec<u8>,
) -> Result<(), Error> {
  let is_split = inner.borrow().is_split;
  if !is_split {
    // Single owner: the stream is guaranteed parked in `Inner`.
    let mut stream = take_stream(inner)?;
    // compio-io contract: `write_all` may only fill a buffering stream's
    // internal buffer (TLS records); `flush` puts the bytes on the wire.
    let mut result = stream.write_all(frame).await.0;
    if result.is_ok() {
      result = stream.flush().await;
    }
    inner.borrow_mut().stream = Some(stream);
    return result.map_err(Error::from);
  }
  let state = Rc::new(Cell::new(FrameState::Queued));
  {
    let mut guard = inner.borrow_mut();
    if !guard.read_half_alive {
      return Err(Error::ReadHalfGone);
    }
    guard.outbound.push_back(OutboundFrame {
      bytes: frame,
      state: state.clone(),
    });
  }
  doorbell.notify(usize::MAX);
  loop {
    match state.get() {
      FrameState::Queued => {}
      FrameState::Written => return Ok(()),
      FrameState::Failed(kind) => return Err(Error::Io(kind.into())),
      FrameState::Orphaned => return Err(Error::ReadHalfGone),
    }
    let listener = doorbell.listen();
    if state.get() != FrameState::Queued {
      continue;
    }
    listener.await;
  }
}

fn take_stream<Ro, S>(inner: &Rc<RefCell<Inner<Ro, S>>>) -> Result<S, Error> {
  inner
    .borrow_mut()
    .stream
    .take()
    .ok_or(Error::Io(std::io::Error::from(
      std::io::ErrorKind::ResourceBusy,
    )))
}

/// Tears the transport down after the close handshake (or on abandonment):
/// best-effort write-side shutdown (TLS close_notify / TCP FIN).
async fn teardown<Ro, S: AsyncRead + AsyncWrite + 'static>(inner: &Rc<RefCell<Inner<Ro, S>>>) {
  let Some(mut stream) = inner.borrow_mut().stream.take() else {
    return;
  };
  let _ = stream.shutdown().await;
  inner.borrow_mut().stream = Some(stream);
}

/// The shared pump: drives the connection until a data message completes,
/// the connection closes (`None`), or an error surfaces.
pub(crate) async fn next_message<Ro: role::Role, S: AsyncRead + AsyncWrite + 'static>(
  inner: &Rc<RefCell<Inner<Ro, S>>>,
  doorbell: &Rc<Doorbell>,
) -> Option<Result<Message, Error>> {
  loop {
    // Phase 1 (borrow): feed pending input through the state machine.
    {
      let mut guard = inner.borrow_mut();
      if let Some(message) = guard.ready.pop_front() {
        return Some(Ok(message));
      }
      let drained_close = guard.closed.is_some() && guard.outbound.is_empty();
      if drained_close {
        return None;
      }
      if !guard.pending_input.is_empty() {
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

    // Phase 2 (borrow): coalesce protocol transmits + queued writer frames.
    let (coalesced, states, deadline) = {
      let mut guard = inner.borrow_mut();
      let mut coalesced: Vec<u8> = Vec::new();
      let mut scratch = [0u8; TRANSMIT_SCRATCH];
      let now = Instant::now();
      loop {
        match guard.conn.poll_transmit(now, &mut scratch) {
          Ok(Some(n)) => coalesced.extend_from_slice(scratch.get(..n).unwrap_or(&[])),
          Ok(None) => break,
          Err(e) => return Some(Err(e.into())),
        }
      }
      let mut states = Vec::new();
      while let Some(frame) = guard.outbound.pop_front() {
        coalesced.extend_from_slice(&frame.bytes);
        states.push(frame.state);
      }
      (coalesced, states, guard.conn.poll_timeout())
    };

    // Phase 3 (no borrow): put bytes on the wire.
    if !coalesced.is_empty() {
      let mut stream = match take_stream(inner) {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
      };
      // write_all may only buffer (TLS records); flush hits the wire.
      let mut result = stream.write_all(coalesced).await.0;
      if result.is_ok() {
        result = stream.flush().await;
      }
      inner.borrow_mut().stream = Some(stream);
      match result {
        Ok(()) => {
          for state in &states {
            state.set(FrameState::Written);
          }
          doorbell.notify(usize::MAX);
          continue; // re-settle: the close frame may have just gone out
        }
        Err(e) => {
          let kind = e.kind();
          for state in &states {
            state.set(FrameState::Failed(kind));
          }
          doorbell.notify(usize::MAX);
          return Some(Err(Error::Io(e)));
        }
      }
    }

    // Terminal re-check after transmit drain.
    if inner.borrow().closed.is_some() {
      return None;
    }

    // Phase 4 (no borrow): park on read / timer / doorbell.
    let mut stream = match take_stream(inner) {
      Ok(s) => s,
      Err(e) => return Some(Err(e)),
    };
    let outcome = {
      let read = async { stream.read(Vec::with_capacity(READ_CHUNK)).await }.fuse();
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
    inner.borrow_mut().stream = Some(stream);

    match outcome {
      Park::Read(BufResult(Ok(0), _buf)) => {
        // Phase 1/3 already return `None` whenever `closed` is recorded, so
        // a parked read only resolves to EOF while the connection is open.
        return Some(Err(Error::Io(std::io::Error::from(
          std::io::ErrorKind::UnexpectedEof,
        ))));
      }
      Park::Read(BufResult(Ok(_n), buf)) => {
        inner.borrow_mut().pending_input.extend_from_slice(&buf);
      }
      Park::Read(BufResult(Err(e), _buf)) => return Some(Err(Error::Io(e))),
      Park::Timer => {
        let mut guard = inner.borrow_mut();
        let now = Instant::now();
        if let Some(closed) = guard.conn.handle_timeout(now) {
          guard.closed = Some(closed);
        }
      }
      Park::Doorbell => {}
    }
  }
}

enum Park {
  Read(BufResult<usize, Vec<u8>>),
  Timer,
  Doorbell,
}

#[cfg(test)]
mod tests;
