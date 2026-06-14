//! The per-connection actor.
//!
//! Two tasks are spawned per connection, each owning its state exclusively —
//! no mutexes on the data path:
//! - the **driver** owns the proto `Connection` and the transport read half:
//!   it reads, decodes inbound into messages, accepts app commands, drives
//!   the keepalive/close timers, and emits encoded frames;
//! - the **writer** owns the transport write half: it drains a channel of
//!   encoded frames and performs the `write` (chunked) + `flush`.
//!
//! The app holds channel endpoints (`ReadHalf` / `WriteHalf`). A `send` enqueues
//! a command atomically and the real socket write lives in the writer task, never
//! tied to a caller's future — so a cancelled send never corrupts the stream,
//! never leaves a partial frame, and always preserves backpressure. It is **not**
//! transactional: cancelled while backpressured (awaiting channel room) the frame
//! is not sent, but once the command is admitted the frame is delivered even if
//! the future is dropped — so a cancelled/timed-out send may already be on the
//! wire and must not be blindly retried. The driver selects fairly across its arms
//! (reads, commands, timers, capacity), so neither an inbound flood nor a local
//! send stream starves the other; it pauses reading only when the outbound staging
//! queue backs up, which bounds memory under a control-frame flood.
//!
//! **Liveness and write deadlines are the caller's responsibility** (tungstenite
//! parity). Over `futures::io` an opaque `poll_flush` exposes no byte progress, so
//! the library cannot distinguish a slow-but-reading peer from a stuck one without
//! either false-aborting healthy transports or hanging on dead ones (see the crate
//! docs). So the library auto-pongs incoming pings, bounds the close handshake by
//! `close_timeout`, and otherwise lets a stuck/slow write or flush simply pend —
//! the caller bounds it with `timeout(send())`, the opt-in `write_timeout`, a
//! `timeout(next())` / ping loop for liveness, or OS TCP keepalive. `keepalive` is
//! opt-in (off by default) and only sends pings. Dropping both halves tears the
//! tasks down, so a pending write never leaks.

use std::{
  collections::VecDeque,
  marker::PhantomData,
  sync::{Arc, Mutex as StdMutex},
  time::Instant,
};

use agnostic_lite::RuntimeLite;
use futures_channel::{mpsc, oneshot};
use futures_util::{
  AsyncReadExt, FutureExt, StreamExt,
  io::{ReadHalf as IoRead, WriteHalf as IoWrite},
};
use websocket_proto::{
  Connection, ConnectionConfig, Negotiated,
  connection::{Closed, Event as WsEvent, role},
  frame::CloseCode,
  message::{Message, MessageAssembler},
};
use wren_trace::{debug, trace, warn};

use crate::{
  error::Error,
  options::{AcceptOptions, ClientOptions},
  runtime::Duplex,
};

mod write;
pub use write::WriteHalf;

/// The masking client role, seeded from OS entropy.
pub type ClientRole = role::Client<rand::rngs::StdRng>;
/// The server role.
pub type ServerRole = role::Server;

/// Phantom marker carrying the runtime, role, and stream types without owning
/// them — covariant, and `Send`/`Sync` regardless of the parameters.
pub(crate) type Marker<R, Ro, S> = PhantomData<fn() -> (R, Ro, S)>;

const READ_CHUNK: usize = 16 * 1024;
const TRANSMIT_SCRATCH: usize = 256;
const DATA_CAP: usize = 32;
const CONTROL_CAP: usize = 4;
const INBOUND_CAP: usize = 32;
const OUTBOUND_CAP: usize = 8;
/// Default bound for the close handshake (echo wait, clean-drain, transport
/// shutdown) when no close timeout is set — the protocol's own default.
const WRITER_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// The reply slot of a command: resolves with the write result (a data send) or
/// once the close is accepted/queued.
pub(crate) type Reply = oneshot::Sender<Result<(), Error>>;

/// A data command on the **backpressured** plane. The driver admits these only
/// while the outbound queue has room, so the bounded channel itself applies
/// write backpressure — no caller-side token, so cancellation can never leak a
/// frame past the bound.
pub(crate) enum DataCommand {
  Send(Message, Reply),
  #[cfg(feature = "deflate")]
  SendCompressed(Message, Reply),
  Ping(Vec<u8>, Reply),
}

/// A close request on the **control** plane. The driver always services this
/// channel (never gated on outbound room), so a close is never starved by a
/// full queue and arms its deadline at once; the channel closing also signals
/// that every write handle has dropped.
pub(crate) struct CloseRequest {
  code: CloseCode,
  reason: String,
  reply: Reply,
}

impl CloseRequest {
  pub(crate) fn new(code: CloseCode, reason: String, reply: Reply) -> Self {
    Self {
      code,
      reason,
      reply,
    }
  }
}

/// A frame queued for the writer. `reply` resolves with the write result once
/// the frame is flushed (app `Send`/`Ping`); control frames leave it `None`.
struct Outbound {
  bytes: Vec<u8>,
  reply: Option<oneshot::Sender<Result<(), Error>>>,
}

/// Sync result cell shared with the `ReadHalf` (off the data path).
#[derive(Default)]
pub(crate) struct Outcome {
  closed: Option<Closed>,
  /// Set by the writer task on a transport write error.
  write_err: Option<std::io::ErrorKind>,
  /// A terminal read/protocol/write error the driver could not deliver through
  /// the (full or closed) inbound channel. Surfaced durably on stream end so a
  /// failure is never masked as a generic `Closed`.
  terminal: Option<Error>,
  #[cfg(test)]
  pings_seen: usize,
  #[cfg(test)]
  pongs_seen: usize,
  /// Set by the writer task when it exits — proves it does not leak.
  #[cfg(test)]
  writer_done: bool,
  /// Peak `out_queue` length the driver reached — proves backpressure bounds it.
  #[cfg(test)]
  out_queue_peak: usize,
}

pub(crate) struct Shared {
  outcome: StdMutex<Outcome>,
}

impl Shared {
  pub(crate) fn write_err(&self) -> Option<std::io::ErrorKind> {
    self.outcome.lock().unwrap().write_err
  }
  /// Whether the connection has closed (peer-initiated or our completed
  /// handshake). Once set, the driver heads into its bounded clean-drain and stops
  /// servicing the data/control planes, so the write half uses this to fail a new
  /// frame fast instead of letting it wedge behind the drain.
  pub(crate) fn is_closed(&self) -> bool {
    self.outcome.lock().unwrap().closed.is_some()
  }
  #[cfg(test)]
  pub(crate) fn writer_done(&self) -> bool {
    self.outcome.lock().unwrap().writer_done
  }
  #[cfg(test)]
  pub(crate) fn out_queue_peak(&self) -> usize {
    self.outcome.lock().unwrap().out_queue_peak
  }
}

/// The read half: receives decoded messages from the driver.
pub struct ReadHalf<R, Ro, S> {
  inbound: mpsc::Receiver<Result<Message, Error>>,
  shared: Arc<Shared>,
  /// Dropped when this half is dropped → wakes the driver so it can tear down
  /// once BOTH halves are gone, regardless of drop order (no task leak).
  _reader_alive: oneshot::Sender<()>,
  _marker: Marker<R, Ro, S>,
}

impl<R, Ro, S> std::fmt::Debug for ReadHalf<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ReadHalf").finish_non_exhaustive()
  }
}

/// An established WebSocket connection. Unsplit = the two halves bundled.
pub struct WebSocket<R, Ro, S> {
  read: ReadHalf<R, Ro, S>,
  write: WriteHalf<R, Ro, S>,
}

impl<R, Ro, S> std::fmt::Debug for WebSocket<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WebSocket").finish_non_exhaustive()
  }
}

fn build_config(
  keepalive: Option<std::time::Duration>,
  close_timeout: Option<std::time::Duration>,
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

impl<R: RuntimeLite, S: Duplex> WebSocket<R, ClientRole, S> {
  pub(crate) fn client(
    stream: S,
    negotiated: &Negotiated,
    opts: &ClientOptions,
    leftover: Vec<u8>,
  ) -> Self {
    use rand::SeedableRng;
    let (config, cap) = build_config(opts.keepalive, opts.close_timeout, opts.max_message_size);
    let conn = Connection::new(
      negotiated,
      config,
      role::Client::new(rand::rngs::StdRng::from_rng(&mut rand::rng())),
      Instant::now(),
    );
    // A client sends on the client→server direction, so its outbound window is
    // `client_max_window_bits`. Compressed sends are usable only when deflate was
    // negotiated and that window is the full 15 bits (proto's `encode_compressed`
    // guard); precomputing it lets `WriteHalf` reject a doomed compressed send up
    // front instead of wedging it behind backpressure.
    #[cfg(feature = "deflate")]
    let compress_outbound = negotiated
      .deflate()
      .is_some_and(|p| p.client_max_window_bits() >= 15);
    Self::spawn(
      conn,
      cap,
      stream,
      leftover,
      opts.close_timeout,
      opts.write_timeout,
      #[cfg(feature = "deflate")]
      compress_outbound,
    )
  }
}

impl<R: RuntimeLite, S: Duplex> WebSocket<R, ServerRole, S> {
  pub(crate) fn server(
    stream: S,
    negotiated: &Negotiated,
    opts: &AcceptOptions,
    leftover: Vec<u8>,
  ) -> Self {
    let (config, cap) = build_config(opts.keepalive, opts.close_timeout, opts.max_message_size);
    let conn = Connection::new(negotiated, config, role::Server::new(), Instant::now());
    // A server sends on the server→client direction, so its outbound window is
    // `server_max_window_bits`. Compressed sends are usable only when deflate was
    // negotiated and that window is the full 15 bits (proto's `encode_compressed`
    // guard); precomputing it lets `WriteHalf` reject a doomed compressed send up
    // front instead of wedging it behind backpressure.
    #[cfg(feature = "deflate")]
    let compress_outbound = negotiated
      .deflate()
      .is_some_and(|p| p.server_max_window_bits() >= 15);
    Self::spawn(
      conn,
      cap,
      stream,
      leftover,
      opts.close_timeout,
      opts.write_timeout,
      #[cfg(feature = "deflate")]
      compress_outbound,
    )
  }
}

impl<R: RuntimeLite, Ro: role::Role + Send + 'static, S: Duplex> WebSocket<R, Ro, S> {
  fn spawn(
    conn: Connection<Instant, Ro>,
    cap: usize,
    stream: S,
    leftover: Vec<u8>,
    close_timeout: Option<std::time::Duration>,
    write_timeout: Option<std::time::Duration>,
    #[cfg(feature = "deflate")] compress_outbound: bool,
  ) -> Self {
    // The library does NOT autonomously detect a dead/non-reading peer
    // (tungstenite parity): liveness is the caller's job — `timeout(next())`, a
    // ping loop, or OS TCP keepalive. The only autonomous write bound is the
    // OPT-IN `write_timeout`; the close handshake is bounded by `close_timeout`.
    let writer_bounds = WriterBounds {
      write: write_timeout,
      flush: write_timeout,
      close: close_timeout.unwrap_or(WRITER_DRAIN_GRACE),
    };
    let (read, write) = stream.split();
    let (data_tx, data_rx) = mpsc::channel::<DataCommand>(DATA_CAP);
    let (control_tx, control_rx) = mpsc::channel::<CloseRequest>(CONTROL_CAP);
    let (in_tx, in_rx) = mpsc::channel(INBOUND_CAP);
    let (out_tx, out_rx) = mpsc::channel::<Outbound>(OUTBOUND_CAP);
    let shared = Arc::new(Shared {
      outcome: StdMutex::new(Outcome::default()),
    });
    let (alive_tx, alive_rx) = oneshot::channel::<()>();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    // Mirrors the writer's alive token: the `ReadHalf` holds `reader_alive_tx`, so
    // its drop wakes the driver even when otherwise idle — letting the driver tear
    // down once both halves are gone regardless of drop order.
    let (reader_alive_tx, reader_alive_rx) = oneshot::channel::<()>();
    R::spawn_detach(writer::<R, S>(
      write,
      out_rx,
      shared.clone(),
      writer_bounds,
      shutdown_rx,
      alive_tx,
    ));
    R::spawn_detach(driver::<R, Ro, S>(
      DriverState {
        conn,
        read,
        data_rx,
        control_rx,
        in_tx,
        out_tx,
        assembler: MessageAssembler::new(cap),
        shared: shared.clone(),
        pending_input: leftover,
        out_queue: VecDeque::new(),
        in_queue: VecDeque::new(),
        writer_alive: alive_rx,
        reader_alive: reader_alive_rx,
        closing: false,
        data_gone: false,
        control_gone: false,
        readers_gone: false,
        commands_rejected: false,
        close_timeout,
        close_flush_rx: None,
        close_flush_deadline: None,
        _rt: PhantomData,
      },
      shutdown_tx,
    ));
    Self {
      read: ReadHalf {
        inbound: in_rx,
        shared: shared.clone(),
        _reader_alive: reader_alive_tx,
        _marker: PhantomData,
      },
      write: WriteHalf::new(
        data_tx,
        control_tx,
        shared,
        #[cfg(feature = "deflate")]
        compress_outbound,
      ),
    }
  }

  /// The next data message, or `None` once the connection has closed.
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    self.read.next().await
  }
  /// How the connection ended, once `next()` returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.read.closed()
  }
  #[cfg(test)]
  pub(crate) fn pings_seen(&self) -> usize {
    self.read.pings_seen()
  }
  #[cfg(test)]
  pub(crate) fn pongs_seen(&self) -> usize {
    self.read.pongs_seen()
  }
  /// Sends a whole data message.
  pub async fn send(&mut self, msg: Message) -> Result<(), Error> {
    self.write.send(msg).await
  }
  /// Sends a whole text message.
  pub async fn send_text(&mut self, t: &str) -> Result<(), Error> {
    self.write.send_text(t).await
  }
  /// Sends a whole binary message.
  pub async fn send_binary(&mut self, d: &[u8]) -> Result<(), Error> {
    self.write.send_binary(d).await
  }
  /// Sends a Ping (the peer's Pong is consumed internally).
  pub async fn ping(&mut self, p: &[u8]) -> Result<(), Error> {
    self.write.ping(p).await
  }
  /// Sends a whole text message compressed with permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_text_compressed(&mut self, t: &str) -> Result<(), Error> {
    self.write.send_text_compressed(t).await
  }
  /// Sends a whole binary message compressed with permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_binary_compressed(&mut self, d: &[u8]) -> Result<(), Error> {
    self.write.send_binary_compressed(d).await
  }
  /// Starts the close handshake, drives it to completion, reports the outcome.
  ///
  /// If a transport or protocol failure interrupts the close, that error is
  /// returned (rather than a generic [`Error::Closed`]); a clean handshake
  /// returns the [`Closed`] outcome.
  pub async fn close(mut self, code: CloseCode, reason: &str) -> Result<Closed, Error> {
    match self.write.close(code, reason).await {
      Ok(()) => {}
      // The driver has already terminated: the real cause (if any) surfaces
      // from the read drain below, so fall through to it.
      Err(Error::Closed) => {}
      // A validation failure (invalid code / overlong reason) never armed the
      // close, so draining would hang on a still-live connection — return it.
      Err(e) => return Err(e),
    }
    // Drain inbound to completion, surfacing a failure that interrupts the
    // close instead of swallowing it.
    while let Some(msg) = self.read.next().await {
      msg?;
    }
    self.read.closed().ok_or(Error::Closed)
  }
  /// Splits into independently-owned read and write halves.
  pub fn split(self) -> (ReadHalf<R, Ro, S>, WriteHalf<R, Ro, S>) {
    (self.read, self.write)
  }
}

impl<R, Ro, S> ReadHalf<R, Ro, S> {
  /// The next data message, or `None` once the connection has closed.
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    match self.inbound.next().await {
      Some(msg) => Some(msg),
      // Stream drained: surface a terminal error the driver could not deliver
      // through a full channel, exactly once.
      None => self.take_terminal().map(Err),
    }
  }
  /// Takes the durable terminal error, if any (see [`Outcome::terminal`]).
  fn take_terminal(&self) -> Option<Error> {
    self.shared.outcome.lock().unwrap().terminal.take()
  }
  /// How the connection ended, once `next()` returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.shared.outcome.lock().unwrap().closed
  }
  #[cfg(test)]
  pub(crate) fn pings_seen(&self) -> usize {
    self.shared.outcome.lock().unwrap().pings_seen
  }
  #[cfg(test)]
  pub(crate) fn pongs_seen(&self) -> usize {
    self.shared.outcome.lock().unwrap().pongs_seen
  }
  #[cfg(test)]
  pub(crate) fn shared_for_test(&self) -> Arc<Shared> {
    self.shared.clone()
  }
}

impl<R, Ro, S> futures_util::Stream for ReadHalf<R, Ro, S> {
  type Item = Result<Message, Error>;
  fn poll_next(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Option<Self::Item>> {
    match self.inbound.poll_next_unpin(cx) {
      // Stream drained: surface a durable terminal error exactly once.
      std::task::Poll::Ready(None) => std::task::Poll::Ready(self.take_terminal().map(Err)),
      other => other,
    }
  }
}

// ── The writer task ──────────────────────────────────────────────────────

/// Marks the writer task as finished (test-only) on every exit path, so a
/// regression test can assert the task does not leak on a stuck write.
#[cfg(test)]
struct WriterDoneGuard(Arc<Shared>);
#[cfg(test)]
impl Drop for WriterDoneGuard {
  fn drop(&mut self) {
    self.0.outcome.lock().unwrap().writer_done = true;
  }
}

/// The error for a transport write that moves no bytes within the no-progress
/// bound — the peer has stopped reading (see [`writer`]).
fn write_stalled() -> std::io::Error {
  std::io::Error::new(
    std::io::ErrorKind::TimedOut,
    "outbound write stalled: peer stopped reading",
  )
}

/// The error for a flush that does not complete within the opt-in `write_timeout`
/// (see [`writer`]).
fn flush_stalled() -> std::io::Error {
  std::io::Error::new(
    std::io::ErrorKind::TimedOut,
    "outbound flush stalled (write_timeout exceeded): peer stopped reading",
  )
}

/// A timer that fires after `bound` if set, or never if `None` (the opt-in
/// `write_timeout` is `None` by default — the caller bounds writes instead).
async fn optional_timer<R: RuntimeLite>(bound: Option<std::time::Duration>) {
  match bound {
    Some(d) => {
      R::sleep(d).await;
    }
    None => futures_util::future::pending::<()>().await,
  }
}

/// The writer's timeout budgets (see [`writer`]). Ordinary writes/flushes are
/// bounded ONLY by the opt-in `write_timeout`; the close timeout governs only the
/// final transport shutdown.
struct WriterBounds {
  /// Opt-in per-`poll_write` no-progress bound (`write_timeout`): a write that
  /// moves no bytes for this long fails. `None` ⇒ no timer; a stalled write pends
  /// until the caller bounds it (or both halves drop, ending the task).
  write: Option<std::time::Duration>,
  /// Opt-in per-frame flush deadline (`write_timeout`): bounds an opaque flush a
  /// peer has stalled by not reading. `None` ⇒ no timer (the caller bounds it).
  flush: Option<std::time::Duration>,
  /// Total bound for the FINAL transport shutdown (`poll_close`) — the close
  /// handshake's budget (`close_timeout`).
  close: std::time::Duration,
}

async fn writer<R: RuntimeLite, S: Duplex>(
  mut write: IoWrite<S>,
  mut out_rx: mpsc::Receiver<Outbound>,
  shared: Arc<Shared>,
  bounds: WriterBounds,
  shutdown: oneshot::Receiver<()>, // fires when the driver task ends
  _alive: oneshot::Sender<()>,     // dropped when this task ends → wakes the driver
) {
  use futures_util::AsyncWriteExt;
  #[cfg(test)]
  let _done = WriterDoneGuard(shared.clone());
  let mut shutdown = shutdown.fuse();
  loop {
    // Receiving the next frame races shutdown FIRST: once the driver signals shutdown
    // (both halves gone, or the close handshake ended — possibly after a clean-drain
    // TIMEOUT that already recorded write_err), the writer must STOP rather than pull a
    // buffered frame, write it, and answer it `Ok`. The dropped reply then surfaces the
    // recorded terminal cause to a waiting sender instead of a false success.
    let recv = out_rx.next().fuse();
    futures_util::pin_mut!(recv);
    let outbound = futures_util::select_biased! {
      _ = shutdown => return,
      o = recv => o,
    };
    let Outbound { bytes, reply } = match outbound {
      Some(o) => o,
      None => break,
    };
    // A terminal cause recorded before the driver dropped shutdown (e.g. a clean-drain
    // timeout) means this frame is already abandoned: do not write it or answer Ok —
    // drop the reply so the sender sees the recorded terminal cause.
    if shared.write_err().is_some() {
      return;
    }
    // Write the frame, then flush. We drive `write` (not `write_all`) so partial
    // progress survives cancellation, and never await `flush` after a failed write.
    // Neither `write` nor the opaque `flush` carries a timer by default: a stalled
    // write/flush simply pends, and the CALLER bounds it (`timeout(send)`), as in
    // tungstenite. The opt-in `write_timeout` adds a per-`poll_write` no-progress
    // bound and a per-frame flush deadline for callers who want the library to do
    // it. The driver's `shutdown` (dropped when both halves are gone, or the close
    // handshake ends) is always an escape, so the task never leaks.
    let mut off = 0;
    let res: Result<(), std::io::Error> = 'frame: loop {
      if off == bytes.len() {
        let flush = write.flush().fuse();
        let flush_timer = optional_timer::<R>(bounds.flush).fuse();
        futures_util::pin_mut!(flush, flush_timer);
        break 'frame futures_util::select_biased! {
          _ = shutdown => return,
          r = flush => r,
          _ = flush_timer => Err(flush_stalled()),
        };
      }
      let chunk = write.write(&bytes[off..]).fuse();
      let timer = optional_timer::<R>(bounds.write).fuse();
      futures_util::pin_mut!(chunk, timer);
      let written: std::io::Result<usize> = futures_util::select_biased! {
        _ = shutdown => return,
        r = chunk => r,
        _ = timer => Err(write_stalled()),
      };
      match written {
        Ok(0) => break 'frame Err(std::io::ErrorKind::WriteZero.into()),
        Ok(n) => off += n,
        Err(e) => break 'frame Err(e),
      }
    };
    match res {
      Ok(()) => {
        // Linearize the success reply with terminal-cause recording. A clean-drain
        // TIMEOUT records write_err WHILE this frame's write/flush is completing (before
        // the driver returns and drops the shutdown signal, so the shutdown branch had
        // nothing to fire on yet). A bare check-then-send only NARROWS the multi-thread
        // window — the timeout can slip in between the check and the send. So hold the
        // outcome lock across BOTH the write_err check and the Ok reply; the timeout (and
        // the error path below) record write_err under the SAME lock, so an abandoned
        // frame can never be answered Ok after its cause exists. The reply is a oneshot
        // send (no re-entrancy into this lock), so holding it across the send is safe.
        let outcome = shared.outcome.lock().unwrap();
        if outcome.write_err.is_some() {
          return; // reply dropped → the waiting sender observes the terminal cause (`Io`)
        }
        if let Some(reply) = reply {
          let _ = reply.send(Ok(()));
        }
      }
      Err(e) => {
        warn!(error = %e, "transport write failed");
        shared
          .outcome
          .lock()
          .unwrap()
          .write_err
          .get_or_insert(e.kind());
        if let Some(reply) = reply {
          let _ = reply.send(Err(Error::Io(e)));
        }
        return; // dropping out_rx + write half signals the driver and FINs.
      }
    }
  }
  // Best-effort transport shutdown, but never block termination on it: a
  // `Duplex` whose `poll_close` stalls (TLS close_notify to a gone peer, a
  // custom transport) must not leak this task. `poll_close` exposes no progress,
  // so it gets a TOTAL deadline (`close_bound`, the close timeout) — plus the
  // driver's shutdown signal — rather than a no-progress bound.
  let close_fut = write.close().fuse();
  let timer = R::sleep(bounds.close).fuse();
  futures_util::pin_mut!(close_fut, timer);
  futures_util::select_biased! {
    r = close_fut => {
      if let Err(e) = r {
        shared.outcome.lock().unwrap().write_err.get_or_insert(e.kind());
      }
    }
    // A transport close that cannot complete within the bound is a stalled peer:
    // record it so the clean-close path surfaces Io rather than reporting clean.
    _ = timer => {
      shared
        .outcome
        .lock()
        .unwrap()
        .write_err
        .get_or_insert(std::io::ErrorKind::TimedOut);
    }
    _ = shutdown => {}
  }
}

// ── The driver task ──────────────────────────────────────────────────────

struct DriverState<R, Ro, S> {
  conn: Connection<Instant, Ro>,
  read: IoRead<S>,
  /// Backpressured data plane (admitted only while `out_queue` has room).
  data_rx: mpsc::Receiver<DataCommand>,
  /// Always-serviced control plane (close requests; closing it signals that
  /// the `WriteHalf` has dropped).
  control_rx: mpsc::Receiver<CloseRequest>,
  in_tx: mpsc::Sender<Result<Message, Error>>,
  out_tx: mpsc::Sender<Outbound>,
  assembler: MessageAssembler,
  shared: Arc<Shared>,
  pending_input: Vec<u8>,
  out_queue: VecDeque<Outbound>,
  in_queue: VecDeque<Result<Message, Error>>,
  /// Resolves when the writer task ends (it holds the paired sender).
  writer_alive: oneshot::Receiver<()>,
  /// Resolves when the `ReadHalf` drops (it holds the paired sender). Lets the
  /// driver observe a reader drop even while idle, so it tears down once both
  /// halves are gone regardless of drop order.
  reader_alive: oneshot::Receiver<()>,
  closing: bool,
  /// The data channel closed (the `WriteHalf`'s data sender dropped). Gates the
  /// data arm. Tracked separately from `control_gone` so a `CloseRequest` already
  /// queued on the control channel is still drained even after the data side ends.
  data_gone: bool,
  /// The control channel closed (the `WriteHalf`'s control sender dropped, AFTER
  /// any buffered `CloseRequest` is drained). Gates the control arm.
  control_gone: bool,
  /// The `ReadHalf` dropped. The driver keeps servicing the writer (sends/close)
  /// but its inbound has nowhere to go; once the write half is gone too it tears
  /// down.
  readers_gone: bool,
  /// The command receivers were closed and drained once closure was recorded (so the
  /// channel is the atomic admission gate). Guards `reject_pending_commands` to run
  /// exactly once.
  commands_rejected: bool,
  /// Bounds the wait for the peer's close echo, anchored at when the writer
  /// flushes our Close (see `close_flush_rx`), not at proto's drain time.
  close_timeout: Option<std::time::Duration>,
  /// Resolves when the writer has flushed our Close frame. Only then does the
  /// close-echo deadline start, so a slow flush of frames queued ahead of the
  /// Close cannot trip it. `None` until the Close is queued, and after the ack.
  close_flush_rx: Option<oneshot::Receiver<Result<(), Error>>>,
  /// The close-echo deadline, armed when `close_flush_rx` resolves.
  close_flush_deadline: Option<Instant>,
  _rt: PhantomData<fn() -> R>,
}

enum Wake {
  Read(std::io::Result<usize>),
  Data(Option<DataCommand>),
  Control(Option<CloseRequest>),
  Timer,
  Capacity,
  WriterGone,
  ReaderGone,
  CloseFlushed,
}

async fn driver<R: RuntimeLite, Ro: role::Role + Send + 'static, S: Duplex>(
  mut st: DriverState<R, Ro, S>,
  // Dropped when this task ends → releases a writer stuck on a stalled write.
  _writer_shutdown: oneshot::Sender<()>,
) {
  let mut buf = vec![0u8; READ_CHUNK];
  loop {
    // 1. Feed any buffered input through the state machine.
    if st.conn_handle_pending().is_break() {
      st.finish();
      return;
    }
    // 1b. The moment closure is recorded (peer-initiated or our completed handshake),
    // stop admitting and reject queued commands — NOT only at terminal. A
    // peer-initiated close does not set `closing`, so the data arm would otherwise
    // stay gated by outbound backpressure; a send already queued (or arriving) could
    // then hang if terminal is never reached (e.g. unread inbound). Closing the
    // receivers makes the channel the atomic admission gate (no preflight TOCTOU); the
    // async drain rejects what was queued, race-free. Idempotent via the flag.
    if st.has_closed() && !st.commands_rejected {
      st.reject_pending_commands().await;
      st.commands_rejected = true;
    }
    // 2. Drain proto transmits into the outbound queue.
    if st.drain_transmits().is_break() {
      st.finish();
      return;
    }
    // 3. Hand queued frames to the writer / messages to the app (non-blocking).
    match st.pump_queues() {
      PumpResult::Continue => {}
      PumpResult::Terminal => {
        st.finish();
        return;
      }
    }
    // 4. Terminal: closed, and all inbound delivered.
    if st.is_terminal() {
      // Commands were already rejected and the receivers closed at step 1b when
      // closure was recorded; nothing new can be admitted past the clean-drain.
      // A clean close flushes frames still staged or in the writer channel
      // (notably our close echo) to the peer before tear-down, BOUNDED by the
      // liveness deadline. The bound re-arms on every sign of life — inbound or
      // app-data egress — so a slow-but-progressing drain runs to completion (a
      // genuinely clean close to a slow peer), while a stalled flush to a peer
      // that stopped reading (no egress, no inbound) trips it; `finish` then drops
      // `_writer_shutdown`, aborting the parked writer so neither task leaks. On a
      // stall we record `write_err` so the close surfaces `Io` rather than a clean
      // report after abandoning data. Abortive terminals (unclean deadline, EOF,
      // write error) skip the flush entirely.
      if st.closed_clean() && st.drain_clean_bounded().await.is_break() {
        // `drain_clean_bounded` already recorded write_err(TimedOut) before abandoning
        // the in-flight frame, so a stalled write surfaces `Io`, not a bare `Closed`.
        debug!("clean-drain stalled past the close deadline; abandoning flush");
      }
      // A transport failure while flushing the final frames (notably our close
      // echo) must not be masked as a clean close. The writer records it in
      // `write_err` and exits, which bypasses the `WriterGone` arm that would
      // normally surface it — so surface it here, before tear-down, the same way.
      if let Some(kind) = st.shared.write_err() {
        st.in_queue.push_back(Err(Error::Io(kind.into())));
      }
      st.finish();
      return;
    }
    // 5. Park until something can make progress.
    let in_full = st.in_queue.len() >= INBOUND_CAP;
    let out_full = st.out_queue.len() >= OUTBOUND_CAP;
    // The only timer the driver arms: while closing, our close-echo deadline
    // (armed once the writer flushes our Close, `Wake::CloseFlushed`); otherwise
    // proto's own timer (the keepalive ping interval, when keepalive is enabled).
    // There is no autonomous liveness deadline — detecting a dead/non-reading peer
    // is the caller's job (tungstenite parity).
    let deadline = if st.closing {
      st.close_flush_deadline
    } else {
      st.conn.poll_timeout()
    };
    let wake = {
      // read arm — gated on inbound room, and on outbound room because reading
      // generates outbound (pong / close echoes): stop reading when the
      // outbound queue is backed up so a flooding peer cannot grow it without
      // bound while the writer drains slowly.
      let read = async {
        if in_full || out_full {
          futures_util::future::pending::<std::io::Result<usize>>().await
        } else {
          st.read.read(&mut buf).await
        }
      }
      .fuse();
      // data arm — gated on outbound room so the bounded channel applies write
      // backpressure (this is what bounds `out_queue`). While closing it stays
      // open (ungated by room) so post-close sends are rejected promptly rather
      // than stalling; once the data channel closes it is gated (separately from
      // control, so a queued close is still drained).
      let data = async {
        if (out_full && !st.closing) || st.data_gone {
          futures_util::future::pending::<Option<DataCommand>>().await
        } else {
          st.data_rx.next().await
        }
      }
      .fuse();
      // control arm — ALWAYS serviced (never gated on outbound room), so a close
      // is never starved by a full queue and the `WriteHalf` drop is observed
      // promptly. Kept open until the control channel itself yields `None` — even
      // after the data channel closed — so a `CloseRequest` already queued by
      // `Sink::poll_close` before the drop is drained, not masked.
      let control = async {
        if st.control_gone {
          futures_util::future::pending::<Option<CloseRequest>>().await
        } else {
          st.control_rx.next().await
        }
      }
      .fuse();
      // writer-liveness arm — resolves when the writer task ends.
      let gone = (&mut st.writer_alive).fuse();
      // reader-liveness arm — resolves when the `ReadHalf` drops (gated once seen,
      // so we don't spin on the resolved oneshot). Lets an idle driver observe a
      // reader drop and tear down once both halves are gone.
      let reader_gone = async {
        if st.readers_gone {
          futures_util::future::pending::<()>().await
        } else {
          let _ = (&mut st.reader_alive).await;
        }
      }
      .fuse();
      // timer arm
      let timer = async {
        match deadline {
          Some(at) => {
            R::sleep(at.saturating_duration_since(Instant::now())).await;
          }
          None => futures_util::future::pending::<()>().await,
        }
      }
      .fuse();
      // capacity arm — wake when a non-empty queue's channel has room
      let cap = async {
        let want_out = !st.out_queue.is_empty();
        let want_in = !st.in_queue.is_empty();
        if !want_out && !want_in {
          futures_util::future::pending::<()>().await;
        }
        futures_util::future::poll_fn(|cx| {
          use std::task::Poll;
          if want_out && let Poll::Ready(r) = st.out_tx.poll_ready(cx) {
            return Poll::Ready(r.is_err());
          }
          if want_in && let Poll::Ready(r) = st.in_tx.poll_ready(cx) {
            return Poll::Ready(r.is_err());
          }
          Poll::Pending
        })
        .await;
      }
      .fuse();
      // close-flush arm — resolves when the writer has flushed our Close frame
      // (its tagged reply), which is when the close-echo deadline should start.
      let close_flushed = async {
        if let Some(rx) = st.close_flush_rx.as_mut() {
          let _ = rx.await;
        } else {
          futures_util::future::pending::<()>().await
        }
      }
      .fuse();
      futures_util::pin_mut!(
        read,
        data,
        control,
        timer,
        cap,
        gone,
        reader_gone,
        close_flushed
      );
      // Fair (non-biased) selection. Strict priority in EITHER direction
      // starves the other side: read-first lets an inbound flood (unsolicited
      // pongs, endless fragments) starve commands and the close/keepalive
      // timer; command-first lets a local send flood starve reads (inbound and
      // peer Close). Random selection among the ready arms gives both bounded
      // progress, preserving full duplex. Command handling is non-blocking
      // (the socket write lives in the writer task), so it never delays a read
      // beyond one scheduling turn.
      futures_util::select! {
        _ = gone => Wake::WriterGone,
        () = reader_gone => Wake::ReaderGone,
        () = close_flushed => Wake::CloseFlushed,
        () = timer => Wake::Timer,
        c = control => Wake::Control(c),
        d = data => Wake::Data(d),
        () = cap => Wake::Capacity,
        r = read => Wake::Read(r),
      }
    };
    match wake {
      Wake::Read(Ok(0)) => {
        debug!("transport EOF");
        st.fail_eof();
        st.finish();
        return;
      }
      Wake::Read(Ok(n)) => {
        trace!(bytes = n, "transport read");
        st.pending_input.extend_from_slice(&buf[..n]);
      }
      Wake::Read(Err(e)) => {
        st.in_queue.push_back(Err(Error::Io(e)));
        st.finish();
        return;
      }
      Wake::Data(Some(cmd)) => st.handle_data(cmd),
      Wake::Control(Some(req)) => st.handle_close(req),
      Wake::Data(None) => {
        // The data channel closed (no more sends). Keep the control arm open so a
        // `CloseRequest` already queued by `Sink::poll_close` is still drained,
        // not masked. Tear down only once both halves are gone (and no close runs).
        st.data_gone = true;
        if st.try_finish_idle() {
          return;
        }
      }
      Wake::Control(None) => {
        // The control channel closed (all queued closes drained).
        st.control_gone = true;
        if st.try_finish_idle() {
          return;
        }
      }
      Wake::ReaderGone => {
        // The `ReadHalf` dropped. Keep servicing the writer (sends/close); tear
        // down only once the write half is gone too, so neither task leaks
        // regardless of drop order. (Pending inbound is dropped on teardown; while
        // both halves live, an undeliverable inbound is caught by `pump_queues`.)
        st.readers_gone = true;
        if st.try_finish_idle() {
          return;
        }
      }
      Wake::WriterGone => {
        // The writer task ended. If it died on a write error, surface it.
        if let Some(kind) = st.shared.write_err() {
          st.in_queue.push_back(Err(Error::Io(kind.into())));
        }
        st.finish();
        return;
      }
      Wake::Timer => {
        // proto's timer fired (keepalive ping interval, or — while closing — the
        // close deadline). No autonomous liveness check: detecting a dead peer is
        // the caller's job.
        if let Some(c) = st.conn.handle_timeout(Instant::now()) {
          debug!(clean = c.clean(), "close deadline elapsed");
          st.record_closed(c);
        }
      }
      Wake::CloseFlushed => {
        // The writer flushed our Close: NOW start the close-echo deadline. Proto's
        // own close deadline (armed back at drain time) has already passed by the
        // time this fires, so `handle_timeout` will still record the unclean close.
        st.close_flush_rx = None;
        let bound = st.close_timeout.unwrap_or(WRITER_DRAIN_GRACE);
        st.close_flush_deadline = Instant::now().checked_add(bound);
      }
      Wake::Capacity => {}
    }
  }
}

use std::ops::ControlFlow;

enum PumpResult {
  Continue,
  Terminal,
}

impl<R: RuntimeLite, Ro: role::Role, S> DriverState<R, Ro, S> {
  /// Hands staged frames to the writer (notably our close echo) and waits for it
  /// to flush them and exit, bounded by the close handshake's budget
  /// (`close_timeout`): the close must complete within it, so a peer too slow to
  /// drain loses the tail and we tear down rather than hang. Returns `Break` if the
  /// budget expired, `Continue` if the drain completed.
  async fn drain_clean_bounded(&mut self) -> ControlFlow<()> {
    use futures_util::SinkExt;
    // Cloned so the timeout branch can record the stall WITHOUT borrowing `self` while
    // the `drain` future still holds its &mut field borrows.
    let shared = self.shared.clone();
    let deadline = Instant::now().checked_add(self.close_timeout.unwrap_or(WRITER_DRAIN_GRACE));
    let drain = async {
      while let Some(frame) = self.out_queue.pop_front() {
        if self.out_tx.send(frame).await.is_err() {
          return; // writer gone (it faulted); write_err is set, surfaced by the caller
        }
      }
      self.out_tx.close_channel();
      let _ = (&mut self.writer_alive).await;
    }
    .fuse();
    let timer = async {
      match deadline {
        Some(at) => {
          R::sleep(at.saturating_duration_since(Instant::now())).await;
        }
        None => futures_util::future::pending::<()>().await,
      }
    }
    .fuse();
    futures_util::pin_mut!(drain, timer);
    let outcome = futures_util::select_biased! {
      () = drain => ControlFlow::Continue(()),
      () = timer => ControlFlow::Break(()),
    };
    if outcome.is_break() {
      // Record the stall NOW — before the cancelled `drain` future is dropped at scope
      // end. Dropping it drops the in-flight frame's reply sender; a `WriteHalf` still
      // awaiting that frame must then see write_err (→ `Io(TimedOut)`), not a bare
      // cancelled reply (→ `Closed`). On a multi-thread runtime the `WriteHalf` can be
      // polled the instant the reply drops, so setting the cause first closes that race
      // and stops a stalled write being misreported as a clean close.
      shared
        .outcome
        .lock()
        .unwrap()
        .write_err
        .get_or_insert(std::io::ErrorKind::TimedOut);
    }
    outcome
  }
}

impl<R, Ro: role::Role, S> DriverState<R, Ro, S> {
  fn record_closed(&mut self, c: Closed) {
    let mut o = self.shared.outcome.lock().unwrap();
    o.closed.get_or_insert(c);
  }
  fn has_closed(&self) -> bool {
    self.shared.outcome.lock().unwrap().closed.is_some()
  }
  fn closed_clean(&self) -> bool {
    self
      .shared
      .outcome
      .lock()
      .unwrap()
      .closed
      .is_some_and(|c| c.clean())
  }

  /// Feed `pending_input` through proto, folding events into messages.
  fn conn_handle_pending(&mut self) -> ControlFlow<()> {
    if self.has_closed() || self.pending_input.is_empty() {
      return ControlFlow::Continue(());
    }
    if let Some(kind) = self.shared.write_err() {
      self.in_queue.push_back(Err(Error::Io(kind.into())));
      return ControlFlow::Break(());
    }
    let mut input = std::mem::take(&mut self.pending_input);
    let assembler = &mut self.assembler;
    let in_queue = &mut self.in_queue;
    let shared = &self.shared;
    match self.conn.handle(Instant::now(), &mut input) {
      Ok(mut events) => {
        while let Some(ev) = events.next() {
          if let WsEvent::Closed(c) = &ev {
            shared.outcome.lock().unwrap().closed.get_or_insert(*c);
          }
          #[cfg(test)]
          match &ev {
            WsEvent::Ping(_) => shared.outcome.lock().unwrap().pings_seen += 1,
            WsEvent::Pong(_) => shared.outcome.lock().unwrap().pongs_seen += 1,
            _ => {}
          }
          match assembler.push(&ev) {
            Ok(Some(m)) => in_queue.push_back(Ok(m)),
            Ok(None) => {}
            Err(e) => {
              in_queue.push_back(Err(e.into()));
              return ControlFlow::Break(());
            }
          }
        }
      }
      Err(e) => {
        in_queue.push_back(Err(e.into()));
        return ControlFlow::Break(());
      }
    }
    ControlFlow::Continue(())
  }

  /// Drain proto-generated transmits (pong/ping/close echo) into `out_queue`.
  fn drain_transmits(&mut self) -> ControlFlow<()> {
    let mut scratch = [0u8; TRANSMIT_SCRATCH];
    let now = Instant::now();
    loop {
      // Bound the staging queue against protocol frames too. Unlike the read
      // and data arms, nothing here is gated on outbound room, and the keepalive
      // timer re-arms a ping every interval — so on a backed-up writer this would
      // otherwise grow `out_queue` one frame per interval without bound. Stop at
      // the cap and leave the frame in proto: a pending ping is a single coalesced
      // flag there (it cannot accumulate), and it drains once the writer makes
      // room.
      //
      // BUT never gate while closing: proto then emits only the one-shot Close
      // frame (and no more keepalives — those are Open-only). We must get it
      // queued so the writer can flush it; holding it back behind a saturated
      // queue would strand the close.
      if !self.closing && self.out_queue.len() >= OUTBOUND_CAP {
        return ControlFlow::Continue(());
      }
      match self.conn.poll_transmit(now, &mut scratch) {
        Ok(Some(n)) => {
          if n > 0 {
            // While closing, the only frame proto emits is our Close. Tag it with
            // a reply so the writer acks when it has actually FLUSHED it — that,
            // not this drain, is when the close-echo deadline should start (a slow
            // flush of frames queued ahead of the Close must not trip it).
            let reply = if self.closing && self.close_flush_rx.is_none() {
              let (tx, rx) = oneshot::channel();
              self.close_flush_rx = Some(rx);
              Some(tx)
            } else {
              None
            };
            self.out_queue.push_back(Outbound {
              bytes: scratch[..n].to_vec(),
              reply,
            });
          }
        }
        Ok(None) => return ControlFlow::Continue(()),
        Err(e) => {
          self.in_queue.push_back(Err(e.into()));
          return ControlFlow::Break(());
        }
      }
    }
  }

  /// Non-blocking handoff of queued frames to the writer and messages to the
  /// app. Returns `Terminal` if a consumer is gone.
  fn pump_queues(&mut self) -> PumpResult {
    #[cfg(test)]
    {
      let len = self.out_queue.len();
      let mut o = self.shared.outcome.lock().unwrap();
      o.out_queue_peak = o.out_queue_peak.max(len);
    }
    while let Some(frame) = self.out_queue.pop_front() {
      match self.out_tx.try_send(frame) {
        Ok(()) => {}
        Err(e) if e.is_full() => {
          self.out_queue.push_front(e.into_inner());
          break;
        }
        Err(e) => {
          // Writer gone: fail the un-handed frame and surface its error.
          let frame = e.into_inner();
          let err = self
            .shared
            .write_err()
            .map_or(Error::Closed, |k| Error::Io(k.into()));
          if let Some(reply) = frame.reply {
            let _ = reply.send(Err(err));
          }
          if let Some(kind) = self.shared.write_err() {
            self.in_queue.push_back(Err(Error::Io(kind.into())));
          }
          return PumpResult::Terminal;
        }
      }
    }
    while let Some(msg) = self.in_queue.pop_front() {
      match self.in_tx.try_send(msg) {
        Ok(()) => {}
        Err(e) if e.is_full() => {
          // Put it back; wait for capacity.
          self.in_queue.push_front(e.into_inner());
          break;
        }
        Err(e) => {
          // App reader gone (channel disconnected). A still-live `WriteHalf` keeps
          // working (send-only), so DROP an undeliverable `Ok(Message)` and keep
          // draining; only a terminal `Err` item — a real protocol/IO failure with
          // nowhere to go — tears the connection down. (Both halves gone is handled
          // by the reader/writer-gone arms.)
          if e.into_inner().is_err() {
            return PumpResult::Terminal;
          }
        }
      }
    }
    PumpResult::Continue
  }

  fn is_terminal(&self) -> bool {
    // Closed, and all inbound delivered. Outbound is handled at the terminal
    // step: a clean close flushes it (bounded); an unclean one abandons it.
    self.has_closed() && self.in_queue.is_empty()
  }

  /// Finishes when BOTH halves are gone and NO close is staged — a plain drop of
  /// both endpoints with no handshake to complete. Returns `true` if it finished
  /// (the driver should return). A close in flight is left to complete via the
  /// terminal / clean-drain path so its echo is not aborted — this covers BOTH a
  /// local close (`closing`) and a peer-initiated one (a recorded `Closed`, which
  /// does NOT set `closing`); deferring lets `pump_queues` drop undeliverable
  /// inbound and reach the `is_terminal` clean-drain. The write side counts as gone
  /// on `control_gone`: the `WriteHalf` holds both senders, and the control channel
  /// (unlike data, which can be gated by a full outbound queue) is always polled to
  /// `None` — after any queued `Sink` close is drained — so it is the reliable
  /// "write half dropped" signal regardless of backpressure.
  fn try_finish_idle(&mut self) -> bool {
    let read_gone = self.readers_gone || self.in_tx.is_closed();
    let close_staged = self.closing || self.has_closed();
    if self.control_gone && read_gone && !close_staged {
      self.finish();
      return true;
    }
    false
  }

  fn fail_eof(&mut self) {
    if !self.has_closed() {
      self
        .in_queue
        .push_back(Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into())));
    }
  }

  /// Best-effort final flush of buffered messages + close both channels.
  fn finish(&mut self) {
    // Try once more to hand off buffered inbound (best effort).
    while let Some(msg) = self.in_queue.pop_front() {
      if let Err(e) = self.in_tx.try_send(msg) {
        // The reader's channel is full or gone: a terminal error here would be
        // dropped, so stash it durably (and any later one) to surface on stream
        // end rather than masking the failure as a generic `Closed`.
        self.store_terminal(e.into_inner());
        while let Some(m) = self.in_queue.pop_front() {
          self.store_terminal(m);
        }
        break;
      }
    }
    self.in_tx.close_channel();
    self.out_tx.close_channel();
  }

  /// On terminal closure, BEFORE the bounded clean-drain: close the command
  /// receivers and reject anything already queued. Closing the receivers makes the
  /// channel itself the atomic admission gate — a send that raced the close (passed
  /// the write half's `terminal_preflight`, then enqueued just as the driver recorded
  /// closure) now fails immediately because the channel is closed, instead of sitting
  /// in the queue until the clean-drain tears the connection down. Draining what was
  /// already buffered resolves it promptly with the terminal cause rather than at
  /// teardown. The driver returns right after the drain, so it never selects on these
  /// receivers again.
  async fn reject_pending_commands(&mut self) {
    use futures_util::StreamExt as _;
    self.data_rx.close();
    self.control_rx.close();
    let write_err = self.shared.write_err();
    // Drain to None — NOT try_recv. Bounded-mpsc admission is not queue-visible
    // atomically: a sender can bump the in-flight count before its push lands, so
    // try_recv could observe empty while a command is mid-admission and leave it to
    // wait until teardown. After close() no new command is admitted, and next() yields
    // every buffered and in-flight command before None, so none slips through.
    while let Some(cmd) = self.data_rx.next().await {
      fail_data(cmd, terminal_cause(write_err));
    }
    while let Some(req) = self.control_rx.next().await {
      let _ = req.reply.send(Err(terminal_cause(write_err)));
    }
  }

  /// Stashes a terminal error durably (first one wins); drops `Ok` messages
  /// that could not be delivered.
  fn store_terminal(&self, msg: Result<Message, Error>) {
    if let Err(e) = msg {
      let mut o = self.shared.outcome.lock().unwrap();
      o.terminal.get_or_insert(e);
    }
  }
}

impl<R, Ro: role::Role, S> DriverState<R, Ro, S> {
  fn handle_data(&mut self, cmd: DataCommand) {
    if let Some(kind) = self.shared.write_err() {
      fail_data(cmd, Error::Io(kind.into()));
      return;
    }
    if self.has_closed() || self.closing {
      fail_data(cmd, Error::Closed);
      return;
    }
    match cmd {
      DataCommand::Send(msg, reply) => {
        let len = msg_len(&msg);
        self.encode_reply(len, reply, |c, o| match &msg {
          Message::Text(t) => c.encode_text(t.as_ref(), o),
          Message::Binary(d) => c.encode_binary(d.as_ref(), o),
        });
      }
      #[cfg(feature = "deflate")]
      DataCommand::SendCompressed(msg, reply) => {
        let len = msg_len(&msg) * 2;
        self.encode_reply(len, reply, |c, o| match &msg {
          Message::Text(t) => c.encode_text_compressed(t.as_ref(), o),
          Message::Binary(d) => c.encode_binary_compressed(d.as_ref(), o),
        });
      }
      DataCommand::Ping(p, reply) => {
        self.encode_reply(p.len(), reply, |c, o| c.encode_ping(&p, o));
      }
    }
  }

  fn handle_close(&mut self, req: CloseRequest) {
    let CloseRequest {
      code,
      reason,
      reply,
    } = req;
    if let Some(kind) = self.shared.write_err() {
      let _ = reply.send(Err(Error::Io(kind.into())));
      return;
    }
    if self.has_closed() || self.closing {
      // Already closing/closed: a second close can't start another handshake.
      let _ = reply.send(Err(Error::Closed));
      return;
    }
    // Deliver any inherent-send commands ALREADY admitted to the data channel BEFORE
    // applying the close: the close arrives on the separate, independently-serviced
    // control plane, so without this it could overtake buffered data and the `closing`
    // state below would reject it — violating the contract that a send cancelled after
    // admission is still delivered. Commands admitted AFTER this drain see `closing`
    // and are rejected, as documented. (Encoding here runs while the connection is
    // still open, before `conn.close` arms the handshake.)
    while let Ok(cmd) = self.data_rx.try_recv() {
      self.handle_data(cmd);
    }
    // Enter closing mode only if proto accepts the close: an invalid code or an
    // overlong reason leaves the connection live (the caller gets the error).
    let r = self.conn.close(code, &reason).map_err(Error::from);
    if r.is_ok() {
      self.closing = true;
      // Bound getting our Close flushed by the CLOSE timeout, even if the writer is
      // stuck (peer not reading) so the Close cannot drain. Re-armed to the
      // echo-wait deadline once the Close is actually flushed (`Wake::CloseFlushed`).
      // This is the close handshake's own budget — the one place it touches the
      // write path; ordinary sends are never governed by it.
      let bound = self.close_timeout.unwrap_or(WRITER_DRAIN_GRACE);
      self.close_flush_deadline = Instant::now().checked_add(bound);
    }
    let _ = reply.send(r);
  }

  /// Encodes one frame into a payload-sized buffer and queues it for the
  /// writer, attaching `reply` so the caller learns the actual write result.
  /// An encode failure replies immediately and queues nothing.
  ///
  /// The initial buffer is a heuristic guess; the compressed worst case for a
  /// tiny payload can exceed it. proto preflights the buffer before mutating
  /// its compressor, so on `BufferTooSmall` we grow to exactly the size it
  /// reports and retry — side-effect free, no double compression.
  fn encode_reply(
    &mut self,
    payload_hint: usize,
    reply: oneshot::Sender<Result<(), Error>>,
    f: impl Fn(
      &mut Connection<Instant, Ro>,
      &mut [u8],
    ) -> Result<usize, websocket_proto::connection::EncodeError>,
  ) {
    use websocket_proto::connection::EncodeError;
    let mut out = vec![0u8; payload_hint + websocket_proto::constants::MAX_FRAME_HEADER + 64];
    loop {
      match f(&mut self.conn, &mut out) {
        Ok(n) => {
          out.truncate(n);
          self.out_queue.push_back(Outbound {
            bytes: out,
            reply: Some(reply),
          });
          return;
        }
        Err(EncodeError::BufferTooSmall(d)) if d.needed() > out.len() => {
          out.resize(d.needed(), 0);
        }
        Err(e) => {
          let _ = reply.send(Err(e.into()));
          return;
        }
      }
    }
  }
}

fn msg_len(msg: &Message) -> usize {
  match msg {
    Message::Text(t) => t.len(),
    Message::Binary(d) => d.len(),
  }
}

/// The terminal cause to report to a queued-but-unserviced command at teardown: a
/// recorded transport write error (precise `Io` kind) else a clean `Closed`.
fn terminal_cause(write_err: Option<std::io::ErrorKind>) -> Error {
  match write_err {
    Some(kind) => Error::Io(kind.into()),
    None => Error::Closed,
  }
}

fn fail_data(cmd: DataCommand, e: Error) {
  let reply = match cmd {
    DataCommand::Send(_, r) => r,
    #[cfg(feature = "deflate")]
    DataCommand::SendCompressed(_, r) => r,
    DataCommand::Ping(_, r) => r,
  };
  let _ = reply.send(Err(e));
}

#[cfg(test)]
mod tests;
