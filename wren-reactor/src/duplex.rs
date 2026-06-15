//! A loopback in-memory byte stream implementing `futures_io` AsyncRead/
//! AsyncWrite, so connection logic is unit-testable without sockets.
//! `Send` (Arc/Mutex) so it splits and crosses tasks like a real socket.

use std::{
  collections::VecDeque,
  io,
  pin::Pin,
  sync::{Arc, Mutex},
  task::{Context, Poll, Waker},
};

#[derive(Default)]
struct Shared {
  buf: VecDeque<u8>,
  /// Writes past this park until the reader drains (0 = unbounded).
  capacity: usize,
  /// `Some(n)`: accept `n` more bytes, then fail ONE write and recover.
  fault_after: Option<usize>,
  /// When set, `poll_close` never completes (models a hung TLS close_notify).
  stall_close: bool,
  /// When set, `poll_close` fails (models a transport whose shutdown errors, e.g. a
  /// TLS close_notify write to a reset peer).
  fail_close: bool,
  /// When set, `poll_write` wakes the polling task and THEN returns `Pending` — models
  /// the reactor becoming ready exactly at the poll (the register-before-poll race
  /// window): a register-after-poll drops this wake, a register-before-poll catches it.
  wake_then_block: bool,
  /// When set, `poll_flush` wakes the polling task (then returns `Ready`) — models an
  /// adapter that signals its flush waker even on an idle/empty flush. The driver must
  /// not poll the transport flush when nothing is staged, or it self-wakes.
  wake_on_flush: bool,
  /// When set, `poll_flush` never completes (models a peer that stopped reading
  /// so the buffered flush to the socket never drains).
  stall_flush: bool,
  closed: bool,
  read_waker: Option<Waker>,
  write_waker: Option<Waker>,
}

/// One end of a duplex pair. Splittable via `futures_util::io::split`.
pub(crate) struct Pipe {
  read: Arc<Mutex<Shared>>,
  write: Arc<Mutex<Shared>>,
}

pub(crate) fn duplex() -> (Pipe, Pipe) {
  duplex_with(0, None)
}

/// Writes past `cap` bytes park until the reader drains (models a bounded socket).
pub(crate) fn duplex_with_capacity(cap: usize) -> (Pipe, Pipe) {
  duplex_with(cap, None)
}

/// The first pipe's writes accept `after` bytes, then fail once and recover
/// (models a transport write error).
pub(crate) fn duplex_with_write_fault(after: usize) -> (Pipe, Pipe) {
  pair_with(Shared {
    fault_after: Some(after),
    ..Default::default()
  })
}

/// The first pipe's `poll_close` never completes (models a transport whose
/// shutdown — a TLS close_notify to a gone peer — hangs; the CALLER bounds it).
pub(crate) fn duplex_with_stalling_close() -> (Pipe, Pipe) {
  pair_with(Shared {
    stall_close: true,
    ..Default::default()
  })
}

/// The first pipe's writes succeed but its `poll_flush` never completes (models a
/// buffered transport whose peer stopped reading). Used to prove a stalled write
/// does not head-of-line-block the read half.
pub(crate) fn duplex_with_stalling_flush() -> (Pipe, Pipe) {
  pair_with(Shared {
    stall_flush: true,
    ..Default::default()
  })
}

/// The first pipe's `poll_close` fails (models a transport whose shutdown errors —
/// a TLS close_notify to a reset peer); the failure must surface, not be swallowed.
pub(crate) fn duplex_with_failing_close() -> (Pipe, Pipe) {
  pair_with(Shared {
    fail_close: true,
    ..Default::default()
  })
}

/// The first pipe's `poll_write` wakes the task then returns `Pending` (the
/// register-before-poll race window). Used to prove a wakeup is not lost.
pub(crate) fn duplex_with_eager_wake() -> (Pipe, Pipe) {
  pair_with(Shared {
    wake_then_block: true,
    ..Default::default()
  })
}

/// The first pipe's `poll_flush` wakes the task (models an adapter that signals its
/// flush waker even when idle). Used to prove an idle flush is skipped (no self-wake).
pub(crate) fn duplex_with_wake_on_flush() -> (Pipe, Pipe) {
  pair_with(Shared {
    wake_on_flush: true,
    ..Default::default()
  })
}

/// Builds a pair where the FIRST pipe writes through a `Shared` configured by
/// `quirk` (the second is plain).
fn pair_with(quirk: Shared) -> (Pipe, Pipe) {
  let a = Arc::new(Mutex::new(Shared::default()));
  let b = Arc::new(Mutex::new(quirk));
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

fn duplex_with(cap: usize, fault: Option<usize>) -> (Pipe, Pipe) {
  let mk = || {
    Arc::new(Mutex::new(Shared {
      capacity: cap,
      fault_after: fault,
      ..Default::default()
    }))
  };
  let (a, b) = (mk(), mk());
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

impl futures_util::AsyncRead for Pipe {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    out: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let mut g = self.read.lock().unwrap();
    if g.buf.is_empty() {
      if g.closed {
        return Poll::Ready(Ok(0));
      }
      g.read_waker = Some(cx.waker().clone());
      return Poll::Pending;
    }
    let n = out.len().min(g.buf.len());
    for slot in out.iter_mut().take(n) {
      *slot = g.buf.pop_front().unwrap();
    }
    if let Some(w) = g.write_waker.take() {
      w.wake();
    }
    Poll::Ready(Ok(n))
  }
}

impl futures_util::AsyncWrite for Pipe {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    data: &[u8],
  ) -> Poll<io::Result<usize>> {
    let mut g = self.write.lock().unwrap();
    if g.closed {
      return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
    }
    if g.wake_then_block {
      // Signal readiness right at the poll, then block: exercises the
      // register-before-poll ordering. Wake after dropping the lock (the waker only
      // touches lock-free `AtomicWaker`s, but dropping first keeps it deadlock-obvious).
      let w = cx.waker().clone();
      drop(g);
      w.wake();
      return Poll::Pending;
    }
    if g.fault_after == Some(0) {
      g.fault_after = None;
      return Poll::Ready(Err(io::Error::other("injected write fault")));
    }
    let room = if g.capacity == 0 {
      usize::MAX
    } else {
      g.capacity.saturating_sub(g.buf.len())
    };
    if room == 0 {
      g.write_waker = Some(cx.waker().clone());
      return Poll::Pending;
    }
    let mut n = data.len().min(room);
    if let Some(rem) = g.fault_after.as_mut() {
      n = n.min(*rem);
      *rem -= n;
    }
    g.buf.extend(&data[..n]);
    if let Some(w) = g.read_waker.take() {
      w.wake();
    }
    Poll::Ready(Ok(n))
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let g = self.write.lock().unwrap();
    if g.stall_flush {
      return Poll::Pending; // never completes; models a stuck flush
    }
    if g.wake_on_flush {
      let w = cx.waker().clone();
      drop(g);
      w.wake();
      return Poll::Ready(Ok(()));
    }
    Poll::Ready(Ok(()))
  }

  fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
    let mut g = self.write.lock().unwrap();
    if g.stall_close {
      return Poll::Pending; // never completes; only an external abort frees it
    }
    if g.fail_close {
      return Poll::Ready(Err(io::Error::other("injected close fault")));
    }
    g.closed = true;
    if let Some(w) = g.read_waker.take() {
      w.wake();
    }
    Poll::Ready(Ok(()))
  }
}

impl Drop for Pipe {
  fn drop(&mut self) {
    let mut g = self.write.lock().unwrap();
    g.closed = true;
    if let Some(w) = g.read_waker.take() {
      w.wake();
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use futures_util::{AsyncReadExt, AsyncWriteExt};

  #[tokio::test]
  async fn round_trips_and_eofs_on_close() {
    let (mut a, mut b) = duplex();
    a.write_all(b"hi").await.unwrap();
    let mut buf = [0u8; 2];
    b.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
    a.close().await.unwrap();
    let n = b.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
  }
}
