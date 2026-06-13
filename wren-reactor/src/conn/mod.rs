//! The split-transport WebSocket connection.
//!
//! Reads use the exclusively-owned read half (no lock). Writes — app frames
//! from [`WriteHalf`], control frames (pong/ping/close echo) from the
//! [`ReadHalf`] pump — share the write half behind `Arc<Mutex>`. The proto
//! `Connection` is a second `Arc<Mutex>`, locked only to encode/decode,
//! never across an IO await. Lock order, where both are taken in sequence,
//! is proto-then-write.

use std::{
  collections::VecDeque,
  marker::PhantomData,
  sync::{Arc, Mutex as StdMutex},
  time::Instant,
};

use agnostic_lite::RuntimeLite;
use async_lock::Mutex;
use event_listener::Event;
use futures_util::{
  AsyncReadExt, AsyncWriteExt, FutureExt,
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

const READ_CHUNK: usize = 16 * 1024;
pub(crate) const TRANSMIT_SCRATCH: usize = 256;

/// Cheap sync terminal metadata. Held only for trivial reads/writes —
/// NEVER across an await.
#[derive(Default)]
pub(crate) struct Meta {
  pub(crate) closed: Option<Closed>,
  /// `Some(kind)` once a write left a partial frame on the wire.
  pub(crate) poisoned: Option<std::io::ErrorKind>,
  /// A Close has been queued into proto (locally or as an echo) and is not
  /// yet flushed.
  pub(crate) close_pending: bool,
  pub(crate) close_flushed_at: Option<Instant>,
  #[cfg(test)]
  pub(crate) pings_seen: usize,
  #[cfg(test)]
  pub(crate) pongs_seen: usize,
}

/// Shared between the two halves.
pub(crate) struct Shared<Ro, S> {
  pub(crate) conn: Mutex<Connection<Instant, Ro>>,
  pub(crate) write: Mutex<IoWrite<S>>,
  pub(crate) meta: StdMutex<Meta>,
  /// Rung by [`WriteHalf::close`] so a parked split reader re-derives its
  /// close deadline.
  pub(crate) reader_wake: Event,
  pub(crate) close_budget: std::time::Duration,
}

impl<Ro, S> Shared<Ro, S> {
  pub(crate) fn poison(&self, kind: std::io::ErrorKind) {
    self.meta.lock().unwrap().poisoned.get_or_insert(kind);
  }
  pub(crate) fn poisoned(&self) -> Option<std::io::ErrorKind> {
    self.meta.lock().unwrap().poisoned
  }
}

/// The read half: the pump. Owns reads, timers, and control-frame writes.
pub struct ReadHalf<R, Ro, S> {
  shared: Arc<Shared<Ro, S>>,
  read: IoRead<S>,
  assembler: MessageAssembler,
  ready: VecDeque<Message>,
  pending_input: Vec<u8>,
  _rt: PhantomData<fn() -> R>,
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
) -> (ConnectionConfig, usize, std::time::Duration) {
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

impl<R: RuntimeLite, S: Duplex> WebSocket<R, ClientRole, S> {
  pub(crate) fn client(stream: S, negotiated: &Negotiated, opts: &ClientOptions, leftover: Vec<u8>) -> Self {
    use rand::SeedableRng;
    let (config, cap, budget) = build_config(opts.keepalive, opts.close_timeout, opts.max_message_size);
    let conn = Connection::new(
      negotiated,
      config,
      role::Client::new(rand::rngs::StdRng::from_rng(&mut rand::rng())),
      Instant::now(),
    );
    Self::assemble(stream, conn, cap, budget, leftover)
  }
}

impl<R: RuntimeLite, S: Duplex> WebSocket<R, ServerRole, S> {
  pub(crate) fn server(stream: S, negotiated: &Negotiated, opts: &AcceptOptions, leftover: Vec<u8>) -> Self {
    let (config, cap, budget) = build_config(opts.keepalive, opts.close_timeout, opts.max_message_size);
    let conn = Connection::new(negotiated, config, role::Server::new(), Instant::now());
    Self::assemble(stream, conn, cap, budget, leftover)
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> WebSocket<R, Ro, S> {
  fn assemble(stream: S, conn: Connection<Instant, Ro>, cap: usize, budget: std::time::Duration, leftover: Vec<u8>) -> Self {
    let (read, write) = stream.split(); // futures_util::io::split → BiLock halves
    let shared = Arc::new(Shared {
      conn: Mutex::new(conn),
      write: Mutex::new(write),
      meta: StdMutex::new(Meta::default()),
      reader_wake: Event::new(),
      close_budget: budget,
    });
    let read_half = ReadHalf {
      shared: shared.clone(),
      read,
      assembler: MessageAssembler::new(cap),
      ready: VecDeque::new(),
      pending_input: leftover,
      _rt: PhantomData,
    };
    let write_half = WriteHalf::new(shared);
    Self { read: read_half, write: write_half }
  }

  /// The next data message, or `None` once the connection has closed.
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    self.read.next().await
  }
  /// How the connection ended, once `next()` returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.read.closed()
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
  /// Starts the close handshake, drives it to completion (peer echo or the
  /// close deadline), tears the transport down, and reports the outcome.
  ///
  /// [`ClientOptions::with_close_timeout`] bounds each phase — flushing the
  /// Close, the echo wait (counted from the flush), and the shutdown.
  ///
  /// [`ClientOptions::with_close_timeout`]: crate::ClientOptions::with_close_timeout
  pub async fn close(mut self, code: CloseCode, reason: &str) -> Result<Closed, Error> {
    self.write.close(code, reason).await?;
    loop {
      match self.read.next().await {
        Some(Ok(_discard)) => continue,
        Some(Err(e)) => return Err(e),
        None => break,
      }
    }
    self.read.closed().ok_or(Error::Closed)
  }
  /// Splits into independently-owned read and write halves that progress
  /// concurrently.
  pub fn split(self) -> (ReadHalf<R, Ro, S>, WriteHalf<R, Ro, S>) {
    (self.read, self.write)
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> ReadHalf<R, Ro, S> {
  /// The next data message; drives reads, timers, and control writes.
  ///
  /// CORE INVARIANT: the proto lock is NEVER held across an IO await. Phase
  /// 1 drains the transmit batch into an owned `Vec` under the proto lock,
  /// then releases proto; Phase 2 writes that batch under the write lock
  /// only. The two locks are never held simultaneously.
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    loop {
      if let Some(kind) = self.shared.poisoned() {
        return Some(Err(Error::Io(kind.into())));
      }
      if let Some(m) = self.ready.pop_front() {
        return Some(Ok(m));
      }
      // Phase 1 (proto lock): feed input, fold messages, settle overdue
      // timers, drain the transmit batch — then RELEASE proto.
      let (batch, carries_close, deadline, terminal) = {
        let mut conn = self.shared.conn.lock().await;
        let mut meta = self.shared.meta.lock().unwrap();
        if meta.closed.is_none() && !self.pending_input.is_empty() {
          let mut input = std::mem::take(&mut self.pending_input);
          match conn.handle(Instant::now(), &mut input) {
            Ok(mut events) => {
              while let Some(ev) = events.next() {
                #[cfg(test)]
                match &ev {
                  WsEvent::Ping(_) => meta.pings_seen += 1,
                  WsEvent::Pong(_) => meta.pongs_seen += 1,
                  _ => {}
                }
                if let WsEvent::Closed(c) = &ev {
                  meta.closed = Some(*c);
                  meta.close_pending = true;
                }
                match self.assembler.push(&ev) {
                  Ok(Some(m)) => self.ready.push_back(m),
                  Ok(None) => {}
                  Err(e) => return Some(Err(e.into())),
                }
              }
            }
            Err(e) => return Some(Err(e.into())),
          }
        }
        // Overdue timer AFTER the input feed (a just-arrived echo beats the
        // wall clock), before delivery (a flood can't starve the deadline).
        let now = Instant::now();
        if effective_deadline(&conn, &meta, self.shared.close_budget).is_some_and(|at| at <= now)
          && let Some(c) = conn.handle_timeout(now)
        {
          meta.closed = Some(c);
        }
        // Drain proto transmits into an OWNED batch (still under proto).
        let mut scratch = [0u8; TRANSMIT_SCRATCH];
        let mut batch: Vec<u8> = Vec::new();
        let now = Instant::now();
        loop {
          match conn.poll_transmit(now, &mut scratch) {
            Ok(Some(n)) => batch.extend_from_slice(&scratch[..n]),
            Ok(None) => break,
            Err(e) => return Some(Err(e.into())),
          }
        }
        // Nothing-owed settle: a Close owed earlier is already on the wire.
        if batch.is_empty() && meta.close_pending {
          meta.close_pending = false;
          meta.close_flushed_at.get_or_insert(now);
        }
        let carries_close = meta.close_pending;
        let deadline = effective_deadline(&conn, &meta, self.shared.close_budget);
        let terminal = meta.closed.is_some();
        (batch, carries_close, deadline, terminal)
        // proto + meta guards drop here — NOTHING held across the IO below.
      };

      // Phase 2 (write lock only): put the batch on the wire.
      if !batch.is_empty() {
        if let Err(e) = self.write_batch(batch, carries_close).await {
          return Some(Err(e));
        }
        continue; // re-settle: a Close may have just gone out
      }

      // Deliver buffered messages only once no Close is owed (a caller may
      // stop polling after a returned message; the echo must precede it).
      {
        let meta = self.shared.meta.lock().unwrap();
        if !meta.close_pending && let Some(m) = self.ready.pop_front() {
          return Some(Ok(m));
        }
      }
      if terminal {
        self.teardown().await;
        return None;
      }

      // Phase 3 (no lock): park on read / timer / reader-wake.
      let mut buf = vec![0u8; READ_CHUNK];
      let outcome = {
        let rd = self.read.read(&mut buf).fuse();
        let timer = async {
          match deadline {
            Some(at) => {
              R::sleep(at.saturating_duration_since(Instant::now())).await;
            }
            None => futures_util::future::pending::<()>().await,
          }
        }
        .fuse();
        let bell = self.shared.reader_wake.listen().fuse();
        futures_util::pin_mut!(rd, timer, bell);
        futures_util::select_biased! {
          r = rd => Park::Read(r),
          _ = timer => Park::Tick,
          _ = bell => Park::Wake,
        }
      };
      match outcome {
        Park::Read(Ok(0)) => {
          debug!("transport EOF before the close handshake completed");
          return Some(Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into())));
        }
        Park::Read(Ok(n)) => {
          trace!(bytes = n, "transport read");
          self.pending_input.extend_from_slice(&buf[..n]);
        }
        Park::Read(Err(e)) => return Some(Err(Error::Io(e))),
        Park::Tick | Park::Wake => {} // loop re-derives state under the lock
      }
    }
  }

  /// Writes a drained transmit batch under the WRITE lock only (no proto
  /// held). Bounded by the close budget while a Close is owed.
  async fn write_batch(&self, batch: Vec<u8>, carries_close: bool) -> Result<(), Error> {
    let mut wr = self.shared.write.lock().await;
    let drive = async {
      wr.write_all(&batch).await?;
      wr.flush().await
    };
    let result = if carries_close {
      futures_util::pin_mut!(drive);
      let timer = R::sleep(self.shared.close_budget).fuse();
      futures_util::pin_mut!(timer);
      futures_util::select_biased! {
        r = drive.fuse() => Some(r),
        _ = timer => None,
      }
    } else {
      Some(drive.await)
    };
    drop(wr);
    match result {
      Some(Ok(())) => {
        if carries_close {
          let mut meta = self.shared.meta.lock().unwrap();
          meta.close_pending = false;
          meta.close_flushed_at.get_or_insert(Instant::now());
        }
        Ok(())
      }
      Some(Err(e)) => {
        warn!(error = %e, "transport write failed");
        self.shared.poison(e.kind());
        Err(Error::Io(e))
      }
      None => {
        // Close flush timed out against a wedged peer: mark unclean.
        let mut conn = self.shared.conn.lock().await;
        let mut meta = self.shared.meta.lock().unwrap();
        meta.close_pending = false;
        if let Some(c) = conn.handle_timeout(Instant::now()) {
          meta.closed = Some(c);
        }
        Err(Error::Io(std::io::ErrorKind::TimedOut.into()))
      }
    }
  }

  async fn teardown(&self) {
    let mut wr = self.shared.write.lock().await;
    trace!("shutting the transport down");
    let close = wr.close().fuse();
    let timer = R::sleep(self.shared.close_budget).fuse();
    futures_util::pin_mut!(close, timer);
    futures_util::select_biased! {
      _ = close => {}
      _ = timer => debug!("transport shutdown timed out; dropping"),
    }
  }

  /// How the connection ended, once `next()` returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.shared.meta.lock().unwrap().closed
  }

  #[cfg(test)]
  pub(crate) fn pings_seen(&self) -> usize {
    self.shared.meta.lock().unwrap().pings_seen
  }
  #[cfg(test)]
  pub(crate) fn pongs_seen(&self) -> usize {
    self.shared.meta.lock().unwrap().pongs_seen
  }
}

/// The flush-anchored close deadline: suspended while the Close is still
/// unflushed (`close_pending`), and once flushed it fires no earlier than
/// the flush instant + budget (so local backpressure can't eat the budget).
fn effective_deadline<Ro: role::Role>(
  conn: &Connection<Instant, Ro>,
  meta: &Meta,
  budget: std::time::Duration,
) -> Option<Instant> {
  let at = conn.poll_timeout()?;
  if meta.close_pending {
    return None;
  }
  Some(match meta.close_flushed_at {
    Some(f) => at.max(f + budget),
    None => at,
  })
}

enum Park {
  Read(std::io::Result<usize>),
  Tick,
  Wake,
}

#[cfg(test)]
mod tests;
