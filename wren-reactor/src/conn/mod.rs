//! The WebSocket connection — a caller-driven adapter over `websocket-proto`.
//!
//! **No background tasks, no channels, no control plane.** `WebSocket<R, Ro, S>`
//! owns the proto [`Connection`] + the transport and implements
//! [`Stream`]`<Item = Result<Message, Error>>` + [`Sink`]`<Message>` plus the
//! convenience methods. [`split`](WebSocket::split) hands out a [`ReadHalf`] +
//! [`WriteHalf`] sharing the state through a mutex, so two tasks can read and
//! write concurrently (tokio-tungstenite-style); the lock is held only across
//! brief, non-blocking poll steps and never across a `Pending` — a stalled write
//! returns `Pending` and releases the lock, so reads never head-of-line-block.
//!
//! Parity contract (tungstenite/soketto): the library is a state machine, not a
//! supervisor. The CALLER owns liveness (`timeout(next())` / ping loop / OS
//! keepalive), write deadlines (`timeout(send(..))`), and the close handshake
//! (`timeout(close())`). A single ordered write buffer carries data, pongs, and
//! the Close in FIFO order, so a close never overtakes queued data. A send not
//! yet flushed when `close` is issued is not guaranteed delivered — await the
//! send (or flush) before closing.

use std::{
  collections::VecDeque,
  marker::PhantomData,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll, Wake, Waker},
  time::Instant,
};

use agnostic_lite::RuntimeLite;
use futures_util::{Sink, Stream, task::AtomicWaker};
use websocket_proto::{
  Connection, ConnectionConfig, Negotiated,
  connection::{Closed, Event, role},
  frame::CloseCode,
  message::{Message, MessageAssembler},
};
use wren_trace::{debug, trace, warn};

use crate::{
  error::Error,
  options::{AcceptOptions, ClientOptions},
  runtime::Duplex,
};

mod split;
pub use split::{ReadHalf, WriteHalf};

/// The masking client role, seeded from OS entropy.
pub type ClientRole = role::Client<rand::rngs::StdRng>;
/// The server role.
pub type ServerRole = role::Server;

const READ_CHUNK: usize = 16 * 1024;
/// Scratch for one protocol-generated frame (control frames are ≤ 131 B).
const TRANSMIT_SCRATCH: usize = 256;
/// Soft cap on the staged write buffer: *inter-message* backpressure, not a
/// per-message hard limit. Each send path waits until the buffer is below this
/// before encoding the next frame, and while it exceeds this AND a flush is stalled
/// the read pump stops reading — so a flooding peer cannot grow it without bound (a
/// pong/echo flood against a blocked transport), and a slow peer backpressures the
/// sender. It does NOT cap a single message: like tungstenite and soketto, one send
/// encodes and stages its whole frame, so the staged buffer is bounded by
/// `WRITE_BUF_SOFT_CAP + the largest single message`. Bound a single outbound
/// message caller-side (chunk it, or cap your own payloads) if that matters.
const WRITE_BUF_SOFT_CAP: usize = 64 * 1024;
/// After a drain, shrink the write buffer back to this if it grew beyond it (a single
/// oversized send can balloon the capacity, which `clear` would otherwise retain for
/// the life of the connection). Comfortably above normal traffic, so steady-state
/// sends never trigger a reallocation.
const WRITE_BUF_RETAIN_CAP: usize = 4 * WRITE_BUF_SOFT_CAP;

/// A tiny per-connection reactor: the transport is polled through *this* (a stable
/// waker tied to the connection, not to any task), and on readiness it wakes BOTH
/// the read pump and the write half. The read half registers its task in [`read`],
/// the writer in [`write`]; the transport's single waker slot therefore never has to
/// be shared between the two tasks, so neither can steal the other's wakeup, and a
/// cancelled task simply leaves a stale slot that is harmless to wake.
///
/// [`read`]: Reactor::read
/// [`write`]: Reactor::write
#[derive(Default)]
struct Reactor {
  /// Where the read pump parks (transport read, the soft-cap / closing / shutdown gates).
  read: AtomicWaker,
  /// Where the write half parks (flush, the soft-cap readiness gate).
  write: AtomicWaker,
}

impl Reactor {
  fn wake_write(&self) {
    self.write.wake();
  }
  fn wake_both(&self) {
    self.read.wake();
    self.write.wake();
  }
}

impl Wake for Reactor {
  /// Transport readiness wakes BOTH halves — the parked one makes progress, the other
  /// re-checks and re-parks. This fan-out is what makes the shared transport waker
  /// steal-proof and cancellation-safe.
  fn wake(self: Arc<Self>) {
    self.wake_both();
  }
  fn wake_by_ref(self: &Arc<Self>) {
    self.wake_both();
  }
}

/// Phantom marker carrying the runtime + role without owning them.
type Marker<R, Ro> = PhantomData<fn() -> (R, Ro)>;

/// The shared connection state. All I/O is poll-based; no lock (or `BiLock`
/// guard, when split) is ever held across a `Pending`.
pub(crate) struct Inner<R, Ro, S> {
  conn: Connection<Instant, Ro>,
  stream: S,
  /// Inbound bytes not yet fed to `conn` (handshake leftover, then reads).
  pending_input: Vec<u8>,
  assembler: MessageAssembler,
  /// Completed messages not yet handed out (one input chunk can finish many).
  ready: VecDeque<Message>,
  /// The single ordered outbound buffer: data, pongs, and Close in FIFO order.
  write_buf: Vec<u8>,
  /// Bytes of `write_buf` already on the wire; the rest awaits flush.
  write_cursor: usize,
  /// Protocol-generated bytes (pongs / echoes / Close) drained into `write_buf` since
  /// the last full clear. The read backpressure gate keys on THIS, not the total buffer
  /// length: app-data backpressure must not stop reads (that deadlocks a symmetric
  /// large send), but a read-pump-driven pong/echo flood against a blocked transport
  /// must. Reset on clear; conservative (not decremented on partial flush).
  protocol_unflushed: usize,
  closed: Option<Closed>,
  /// A peer close seen but not yet published: held until the echo we owe has
  /// flushed (a clean close needs our echo on the wire, not just theirs in hand).
  staged_close: Option<Closed>,
  /// A Close is owed to the wire (drained from proto transmits) and unflushed.
  /// Transient: cleared once flushed (it gates *publishing* the outcome).
  close_pending: bool,
  /// Sticky: set the moment either side begins the close handshake and never
  /// cleared. Unlike `close_pending` (which clears when our Close flushes, before
  /// the peer echo), this is what gates re-initiating the handshake and rejecting
  /// new sends, so a `timeout`-cancelled `close` is retryable mid-handshake.
  closing: bool,
  /// First write-path failure: poisons the connection (a partial frame may be on
  /// the wire) so no later frame splices into a corrupt stream.
  poisoned: Option<std::io::ErrorKind>,
  /// True once the terminal transport shutdown (`poll_close`) has completed.
  shutdown_done: bool,
  /// Fan-out reactor: the transport is polled through `transport_waker` (below), and
  /// each half parks by registering its task in `reactor.read` / `reactor.write`, so the
  /// two split tasks never contend for the transport's single waker slot.
  reactor: Arc<Reactor>,
  /// Cached `Waker` over `reactor`, handed to every transport poll so readiness fans
  /// out to both halves. Cloned (cheap `Arc`) per poll to satisfy the borrow checker.
  transport_waker: Waker,
  _marker: Marker<R, Ro>,
}

fn build_config(max_message_size: Option<usize>) -> (ConnectionConfig, usize) {
  let cap = max_message_size.unwrap_or(64 << 20);
  // Raise the per-frame cap to the message cap too: proto defaults `max_frame_payload`
  // to 16 MiB, which would otherwise reject an UNFRAGMENTED message between 16 MiB and
  // the configured message size (common — many peers send one frame per message).
  let config = ConnectionConfig::new()
    .with_max_message_size(cap as u64)
    .with_max_frame_payload(cap as u64);
  (config, cap)
}

impl<R, Ro, S> Inner<R, Ro, S> {
  fn new(conn: Connection<Instant, Ro>, cap: usize, leftover: Vec<u8>, stream: S) -> Self {
    let reactor = Arc::new(Reactor::default());
    let transport_waker = Waker::from(reactor.clone());
    Self {
      conn,
      stream,
      pending_input: leftover,
      assembler: MessageAssembler::new(cap),
      ready: VecDeque::new(),
      write_buf: Vec::new(),
      write_cursor: 0,
      protocol_unflushed: 0,
      closed: None,
      staged_close: None,
      close_pending: false,
      closing: false,
      poisoned: None,
      shutdown_done: false,
      reactor,
      transport_waker,
      _marker: PhantomData,
    }
  }

  /// Wakes a write half parked on flush/backpressure.
  fn wake_writer(&self) {
    self.reactor.wake_write();
  }

  /// Wakes both halves: used when the buffer clears, poisons, or closes — events
  /// that can release a parked writer *and* a reader stalled at a gate.
  fn wake_both(&self) {
    self.reactor.wake_both();
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> Inner<R, Ro, S> {
  /// Encodes one app frame and appends it to the ordered write buffer. Pure CPU
  /// (no I/O); the caller drives [`poll_flush`](Self::poll_flush) to put it out.
  fn encode_into_buf(
    &mut self,
    payload_hint: usize,
    encode: impl Fn(
      &mut Connection<Instant, Ro>,
      &mut [u8],
    ) -> Result<usize, websocket_proto::connection::EncodeError>,
  ) -> Result<(), Error> {
    use websocket_proto::connection::EncodeError;
    if let Some(kind) = self.poisoned {
      return Err(Error::Io(kind.into()));
    }
    // No new app frame once the handshake has begun (sticky `closing`), not just
    // once a Close is queued — `close_pending` clears when our Close flushes.
    if self.closing || self.closed.is_some() {
      return Err(Error::Closed);
    }
    // The hint is a guess; the compressed worst case for a tiny payload can exceed
    // it. proto preflights the buffer before mutating its compressor, so on
    // `BufferTooSmall` we grow to exactly the reported size and retry — side-effect
    // free, no double compression.
    let mut size = payload_hint + websocket_proto::constants::MAX_FRAME_HEADER + 64;
    loop {
      let mut buf = vec![0u8; size];
      match encode(&mut self.conn, &mut buf) {
        Ok(n) => {
          self.write_buf.extend_from_slice(&buf[..n]);
          return Ok(());
        }
        Err(EncodeError::BufferTooSmall(detail)) if detail.needed() > size => {
          size = detail.needed();
        }
        Err(e) => return Err(e.into()),
      }
    }
  }

  /// Queues the close handshake: proto encodes the Close (drained into the write
  /// buffer FIFO, after any queued data); the caller drives [`poll_next`] /
  /// [`poll_flush`] to put it on the wire and read the echo.
  fn start_close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
    if let Some(kind) = self.poisoned {
      return Err(Error::Io(kind.into()));
    }
    // Idempotent: once either side has begun (or finished) the handshake a repeat
    // call is a no-op, so a `timeout`-cancelled `close` can be retried without proto
    // rejecting a second Close as already-closing.
    if self.closing || self.closed.is_some() {
      return Ok(());
    }
    self.conn.close(code, reason)?;
    self.closing = true;
    self.close_pending = true;
    Ok(())
  }

  /// Drains proto's queued transmits (pong/close echo / our Close) into the
  /// ordered write buffer. Pure CPU.
  fn drain_transmits(&mut self) -> Result<(), Error> {
    let mut scratch = [0u8; TRANSMIT_SCRATCH];
    let now = Instant::now();
    loop {
      match self.conn.poll_transmit(now, &mut scratch) {
        Ok(Some(n)) => {
          self
            .write_buf
            .extend_from_slice(scratch.get(..n).unwrap_or(&[]));
          self.protocol_unflushed += n;
        }
        Ok(None) => return Ok(()),
        Err(e) => return Err(e.into()),
      }
    }
  }

  /// Flushes the ordered write buffer to the transport. `Ready(Ok)` once empty;
  /// `Pending` when the transport would block. Polls the transport through the
  /// fan-out `transport_waker` (not the caller's), so transport readiness wakes BOTH
  /// halves; the caller registers its own task via [`poll_flush_writer`] /
  /// [`poll_ready_writer`] / the read pump. Takes no `cx` for that reason.
  fn poll_flush(&mut self) -> Poll<Result<(), Error>> {
    if let Some(kind) = self.poisoned {
      return Poll::Ready(Err(Error::Io(kind.into())));
    }
    // Nothing staged: skip the transport flush entirely. There is nothing to push (the
    // buffer is cleared only after a successful transport flush), and polling an idle
    // flush through the reactor waker could fan out and self-wake the read pump (a
    // busy loop) on adapters that wake their flush waker on an empty flush.
    if self.write_buf.is_empty() && self.write_cursor == 0 {
      return Poll::Ready(Ok(()));
    }
    let waker = self.transport_waker.clone();
    let mut tcx = Context::from_waker(&waker);
    while self.write_cursor < self.write_buf.len() {
      let rest = &self.write_buf[self.write_cursor..];
      match Pin::new(&mut self.stream).poll_write(&mut tcx, rest) {
        Poll::Ready(Ok(0)) => return Poll::Ready(Err(self.poison(std::io::ErrorKind::WriteZero))),
        Poll::Ready(Ok(n)) => self.write_cursor += n,
        Poll::Ready(Err(e)) => {
          let kind = e.kind();
          return Poll::Ready(Err(self.poison(kind)));
        }
        // Transport full: it holds `transport_waker`, so its next writability wakes
        // both halves. No partial-progress wake needed (the buffer length, hence the
        // soft-cap gate, only changes on a full clear below).
        Poll::Pending => return Poll::Pending,
      }
    }
    // Fully written; flush the transport (TLS records / buffered adapter).
    match Pin::new(&mut self.stream).poll_flush(&mut tcx) {
      Poll::Ready(Ok(())) => {
        self.write_buf.clear();
        self.write_cursor = 0;
        self.protocol_unflushed = 0;
        // Don't retain a ballooned buffer after a single oversized send drains.
        if self.write_buf.capacity() > WRITE_BUF_RETAIN_CAP {
          self.write_buf.shrink_to(WRITE_BUF_RETAIN_CAP);
        }
        // A real drain (we only reach here with staged data): release a reader parked
        // at the soft-cap / closing gate and a writer parked at the write-side cap gate.
        self.wake_both();
        Poll::Ready(Ok(()))
      }
      Poll::Ready(Err(e)) => {
        let kind = e.kind();
        Poll::Ready(Err(self.poison(kind)))
      }
      Poll::Pending => Poll::Pending,
    }
  }

  /// The write half's flush entry point. Registers the caller in the reactor's write
  /// slot BEFORE polling: if the transport signals readiness between the poll and the
  /// register, `AtomicWaker` would forget it (a lost wakeup). Registering first means a
  /// readiness edge during [`poll_flush`] wakes this already-registered task. A stale
  /// registration on the `Ready` path is harmless.
  fn poll_flush_writer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    self.reactor.write.register(cx.waker());
    self.poll_flush()
  }

  /// Backpressure gate shared by every send path: ready once the staged buffer is
  /// below the soft cap, otherwise drain toward it. Bounds `write_buf` even under a
  /// cancelled-`timeout(send)` loop, since a send waits here before encoding more.
  fn poll_ready(&mut self) -> Poll<Result<(), Error>> {
    if let Some(kind) = self.poisoned {
      return Poll::Ready(Err(Error::Io(kind.into())));
    }
    // Reject a new app frame before waiting on backpressure: once the handshake has
    // begun (e.g. a peer Close the read pump just decoded), no send can be accepted,
    // and the buffer it would wait on may never drain — fail fast instead of hanging.
    if self.closing || self.closed.is_some() {
      return Poll::Ready(Err(Error::Closed));
    }
    if self.write_buf.len() < WRITE_BUF_SOFT_CAP {
      return Poll::Ready(Ok(()));
    }
    self.poll_flush()
  }

  /// The write half's backpressure gate. Registers in the reactor's write slot BEFORE
  /// polling, for the same register-before-poll reason as [`poll_flush_writer`].
  fn poll_ready_writer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    self.reactor.write.register(cx.waker());
    self.poll_ready()
  }

  /// Records the first write fault, fails everything queued, and wakes both halves
  /// so a parked writer and a reader stalled at the gate both observe the error.
  fn poison(&mut self, kind: std::io::ErrorKind) -> Error {
    warn!(error = ?kind, "transport write failed");
    self.poisoned.get_or_insert(kind);
    self.wake_both();
    Error::Io(kind.into())
  }

  /// Records a read-side terminal failure (transport EOF, a read error, or a protocol
  /// decode failure) so a parked *writer* wakes and later sends fail too — the write
  /// half cannot observe any of these on its own — then hands the error back to the
  /// reader. Protocol failures (no `io` kind) record a representative terminal kind.
  fn fail(&mut self, err: Error) -> Error {
    let kind = match &err {
      Error::Io(e) => e.kind(),
      _ => std::io::ErrorKind::ConnectionReset,
    };
    self.poisoned.get_or_insert(kind);
    self.wake_both();
    err
  }

  /// Feeds buffered input through the state machine into `ready` messages.
  fn decode_pending(&mut self) -> Result<(), Error> {
    if self.closed.is_some() || self.pending_input.is_empty() {
      return Ok(());
    }
    let mut input = std::mem::take(&mut self.pending_input);
    let now = Instant::now();
    let mut became_closing = false;
    let mut events = self.conn.handle(now, &mut input)?;
    while let Some(event) = events.next() {
      if let Event::Closed(closed) = &event {
        debug!(code = ?closed.code(), clean = closed.clean(), "connection closed");
        if closed.clean() {
          // Graceful close: stage, don't publish — our echo needs the wire first.
          self.staged_close = Some(*closed);
          self.close_pending = true;
          became_closing |= !self.closing;
          self.closing = true;
        } else {
          // Unclean close = a protocol failure proto raised (the only source of an
          // unclean `Closed` here, since we run no close-timeout). Fail fast: returning
          // an error lets `poll_next` poison and wake both halves, so the failure
          // surfaces to the reader and a pending writer's send fails — instead of
          // queueing the failure Close behind (possibly backpressured) app data and
          // parking. We tear down rather than flush the failure Close (the connection is
          // failing), but preserve the close code so the caller can tell e.g. a 1009
          // MessageTooBig from a transport reset. Drops already-decoded messages, which
          // is correct on failure.
          return Err(Error::Protocol(closed.code()));
        }
      }
      match self.assembler.push(&event) {
        Ok(Some(message)) => self.ready.push_back(message),
        Ok(None) => {}
        Err(e) => return Err(e.into()),
      }
    }
    drop(events); // release the borrow on `conn` before taking `&mut self` below
    // Wake a writer parked at the backpressure gate so it observes the close and fails
    // fast (its `poll_ready` now returns `Closed`) rather than waiting on a buffer that
    // may never drain.
    if became_closing {
      self.wake_writer();
    }
    Ok(())
  }

  /// The read pump: drive the connection until a data message completes, the
  /// connection closes (`None`), or an error surfaces. Also flushes pongs / the
  /// close echo so they go out even when the caller only reads.
  fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Message, Error>>> {
    loop {
      if let Some(kind) = self.poisoned {
        return Poll::Ready(Some(Err(Error::Io(kind.into()))));
      }
      // Register in the reactor's read slot BEFORE any transport poll below. If the
      // transport (read OR the write side we flush) signals readiness between a poll
      // and a register, `AtomicWaker` would forget it; registering first means any
      // readiness edge — or a `wake_both` from a writer drain — wakes this task. A
      // stale registration on a `Ready` return is harmless.
      self.reactor.read.register(cx.waker());
      // Decode buffered input, then drain proto transmits (pong/echo/Close) into
      // the ordered write buffer. A protocol failure is terminal: record it so a
      // parked writer wakes and fails too, not just the reader.
      if let Err(e) = self.decode_pending() {
        return Poll::Ready(Some(Err(self.fail(e))));
      }
      if let Err(e) = self.drain_transmits() {
        return Poll::Ready(Some(Err(self.fail(e))));
      }

      // Flush the write buffer (pongs/echo/Close). A stalled flush is fine — we still
      // try to read below; the transport holds the fan-out waker, so its readiness
      // wakes us, and a buffer clear wakes us via `wake_both`.
      let flush = self.poll_flush();
      if let Poll::Ready(Err(e)) = flush {
        return Poll::Ready(Some(Err(e)));
      }
      // The owed Close is on the wire once the buffer drains: publish the outcome.
      if self.close_pending && self.write_buf.is_empty() {
        self.close_pending = false;
        if self.closed.is_none() {
          self.closed = self.staged_close.take();
          self.wake_writer(); // a parked writer should observe the close
        }
      }

      // Deliver a completed message only after pongs/echo are out (RFC 6455 §5.5
      // wants control replies "as soon as practical", and the caller may stop
      // polling after a message).
      if let Some(message) = self.ready.pop_front() {
        return Poll::Ready(Some(Ok(message)));
      }

      // Terminal: shut the transport down (TLS close_notify / TCP FIN), bounded
      // by the caller's `timeout`, then end the stream.
      if self.closed.is_some() {
        if !self.shutdown_done {
          let waker = self.transport_waker.clone();
          let mut tcx = Context::from_waker(&waker);
          match Pin::new(&mut self.stream).poll_close(&mut tcx) {
            Poll::Ready(Ok(())) => self.shutdown_done = true,
            // A failed transport shutdown is surfaced once (not swallowed as a clean
            // close); mark it done so the stream then ends, and wake a parked writer.
            Poll::Ready(Err(e)) => {
              self.shutdown_done = true;
              self.wake_writer();
              return Poll::Ready(Some(Err(Error::Io(e))));
            }
            // Already registered (read slot, top of loop): the transport holds the
            // fan-out waker, so its readiness wakes us back to finish teardown even if a
            // split writer is concurrently polling the same write side.
            Poll::Pending => return Poll::Pending,
          }
        }
        return Poll::Ready(None);
      }

      // Park the read pump (durably) rather than read more when it must wait for the
      // write buffer to drain, in either of two cases:
      //  - protocol-flood backpressure: a stalled flush has backed up the read pump's
      //    OWN protocol output (pongs/echoes) past the cap, so a ping-flooding peer
      //    can't grow it unbounded. This keys on `protocol_unflushed`, NOT the total
      //    buffer: gating on app data would deadlock a symmetric large send (each side
      //    refusing to drain the other because its own send is backpressured); app sends
      //    are already bounded by the writer's own `poll_ready` gate.
      //  - closing with an unflushed Close/echo: don't feed bytes to a terminal proto,
      //    and don't miss the drain that lets us publish the close — the echo can be
      //    well below the cap.
      // The buffer empties only on a full clear, which wakes the read slot via
      // `wake_both`; the fan-out `transport_waker` also wakes us on transport progress.
      let flush_stalled = flush.is_pending();
      let protocol_flood = flush_stalled && self.protocol_unflushed >= WRITE_BUF_SOFT_CAP;
      let closing_unflushed = self.closing && !self.write_buf.is_empty();
      if protocol_flood || closing_unflushed {
        // Already registered in the read slot at the top of the loop; a writer drain
        // (`wake_both` on clear) or transport readiness wakes us.
        return Poll::Pending;
      }
      let mut scratch = [0u8; READ_CHUNK];
      let waker = self.transport_waker.clone();
      let mut tcx = Context::from_waker(&waker);
      match Pin::new(&mut self.stream).poll_read(&mut tcx, &mut scratch) {
        Poll::Ready(Ok(0)) => {
          debug!("transport EOF before the close handshake completed");
          let err = Error::Io(std::io::ErrorKind::UnexpectedEof.into());
          return Poll::Ready(Some(Err(self.fail(err))));
        }
        Poll::Ready(Ok(n)) => {
          trace!(bytes = n, "transport read");
          self
            .pending_input
            .extend_from_slice(scratch.get(..n).unwrap_or(&[]));
          // Loop: decode the new bytes.
        }
        Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(self.fail(Error::Io(e))))),
        // Nothing to read yet: already registered in the read slot at the top of the
        // loop, and the transport holds the fan-out waker, so inbound readiness wakes us.
        Poll::Pending => return Poll::Pending,
      }
    }
  }
}

/// An established WebSocket connection over `S`.
///
/// Drive [`next`](Self::next) (or poll the [`Stream`]) to receive messages and to
/// keep the protocol moving (pong echoes, the close handshake). Send via the
/// methods or the [`Sink`]. [`split`](Self::split) for concurrent read + write.
pub struct WebSocket<R, Ro, S> {
  inner: Inner<R, Ro, S>,
}

impl<R, Ro, S> std::fmt::Debug for WebSocket<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WebSocket").finish_non_exhaustive()
  }
}

impl<R: RuntimeLite, S: Duplex> WebSocket<R, ClientRole, S> {
  pub(crate) fn client(
    stream: S,
    negotiated: &Negotiated,
    opts: &ClientOptions,
    leftover: Vec<u8>,
  ) -> Self {
    use rand::SeedableRng;
    let (config, cap) = build_config(opts.max_message_size);
    let conn = Connection::new(
      negotiated,
      config,
      role::Client::new(rand::rngs::StdRng::from_rng(&mut rand::rng())),
      Instant::now(),
    );
    Self {
      inner: Inner::new(conn, cap, leftover, stream),
    }
  }
}

impl<R: RuntimeLite, S: Duplex> WebSocket<R, ServerRole, S> {
  pub(crate) fn server(
    stream: S,
    negotiated: &Negotiated,
    opts: &AcceptOptions,
    leftover: Vec<u8>,
  ) -> Self {
    let (config, cap) = build_config(opts.max_message_size);
    let conn = Connection::new(negotiated, config, role::Server::new(), Instant::now());
    Self {
      inner: Inner::new(conn, cap, leftover, stream),
    }
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> WebSocket<R, Ro, S> {
  /// The next data message, or `None` once the connection has closed (inspect
  /// [`closed`](Self::closed) for the outcome).
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    futures_util::future::poll_fn(|cx| self.inner.poll_next(cx)).await
  }

  /// How the connection ended, once [`next`](Self::next) returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.inner.closed
  }

  /// Backpressure gate: ready once the staged write buffer is below the soft cap.
  /// Awaited before each send so a stalled transport bounds the buffer (a
  /// cancelled-`timeout(send)` loop cannot grow it without bound).
  async fn ready(&mut self) -> Result<(), Error> {
    futures_util::future::poll_fn(|cx| self.inner.poll_ready_writer(cx)).await
  }

  /// Sends a whole data message (awaits its flush).
  pub async fn send(&mut self, message: Message) -> Result<(), Error> {
    match message {
      Message::Text(t) => self.send_text(t.as_ref()).await,
      Message::Binary(d) => self.send_binary(d.as_ref()).await,
    }
  }

  /// Sends a whole text message.
  pub async fn send_text(&mut self, text: &str) -> Result<(), Error> {
    self.ready().await?;
    self
      .inner
      .encode_into_buf(text.len(), |c, o| c.encode_text(text, o))?;
    self.flush().await
  }

  /// Sends a whole binary message.
  pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), Error> {
    self.ready().await?;
    self
      .inner
      .encode_into_buf(data.len(), |c, o| c.encode_binary(data, o))?;
    self.flush().await
  }

  /// Sends a Ping (the peer's Pong is consumed internally).
  pub async fn ping(&mut self, payload: &[u8]) -> Result<(), Error> {
    self.ready().await?;
    self
      .inner
      .encode_into_buf(payload.len(), |c, o| c.encode_ping(payload, o))?;
    self.flush().await
  }

  /// Sends a whole text message compressed with permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_text_compressed(&mut self, text: &str) -> Result<(), Error> {
    self.ready().await?;
    self
      .inner
      .encode_into_buf(text.len() * 2, |c, o| c.encode_text_compressed(text, o))?;
    self.flush().await
  }

  /// Sends a whole binary message compressed with permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_binary_compressed(&mut self, data: &[u8]) -> Result<(), Error> {
    self.ready().await?;
    self
      .inner
      .encode_into_buf(data.len() * 2, |c, o| c.encode_binary_compressed(data, o))?;
    self.flush().await
  }

  /// Flushes any buffered outbound bytes.
  pub async fn flush(&mut self) -> Result<(), Error> {
    futures_util::future::poll_fn(|cx| self.inner.poll_flush_writer(cx)).await
  }

  /// Starts the close handshake, drives it to completion (peer echo or transport
  /// EOF), and reports the outcome. Data messages arriving meanwhile are discarded.
  /// Bound the whole call with your own `timeout` (parity: the library imposes no
  /// close deadline). To guarantee a prior send is delivered, await it (or
  /// [`flush`](Self::flush)) before calling this.
  pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<Closed, Error> {
    // `start_close` is idempotent, so a retry after a `timeout`-cancelled close
    // (even one cancelled after our Close flushed) resumes driving the handshake
    // rather than re-initiating it.
    self.inner.start_close(code, reason)?;
    loop {
      match self.next().await {
        Some(Ok(_discarded)) => continue,
        Some(Err(e)) => return Err(e),
        None => break,
      }
    }
    self.inner.closed.ok_or(Error::Closed)
  }

  /// Splits into independently-owned read and write halves that share the
  /// connection through a mutex, so two tasks can read and write at once. A
  /// stalled write releases the lock and returns `Pending`, so reads never
  /// head-of-line-block behind it.
  pub fn split(self) -> (ReadHalf<R, Ro, S>, WriteHalf<R, Ro, S>) {
    split::pair(self.inner)
  }
}

impl<R: RuntimeLite, Ro: role::Role + Unpin, S: Duplex> Stream for WebSocket<R, Ro, S> {
  type Item = Result<Message, Error>;
  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    self.get_mut().inner.poll_next(cx)
  }
}

impl<R: RuntimeLite, Ro: role::Role + Unpin, S: Duplex> Sink<Message> for WebSocket<R, Ro, S> {
  type Error = Error;
  fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    self.get_mut().inner.poll_ready_writer(cx)
  }
  fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Error> {
    let inner = &mut self.get_mut().inner;
    match item {
      Message::Text(t) => inner.encode_into_buf(t.len(), |c, o| c.encode_text(t.as_ref(), o)),
      Message::Binary(d) => inner.encode_into_buf(d.len(), |c, o| c.encode_binary(d.as_ref(), o)),
    }
  }
  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    self.get_mut().inner.poll_flush_writer(cx)
  }
  fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    let inner = &mut self.get_mut().inner;
    // Idempotent: safe to call every poll; a poisoned connection surfaces via flush.
    let _ = inner.start_close(CloseCode::Normal, "");
    inner.drain_transmits()?;
    inner.poll_flush_writer(cx)
  }
}

#[cfg(test)]
mod tests;
