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
  /// When set, `poll_flush` never completes (models a write error followed by a
  /// stalled flush).
  stall_flush: bool,
  /// When set, `poll_flush` completes only once the reader has drained everything
  /// written (models a buffered transport where "flush" means the peer received
  /// it): it makes progress to a reading peer, but stalls to a non-reading one.
  flush_drains: bool,
  /// When set, every `poll_write` parks (frames back up behind it) until a
  /// [`FaultTrigger`] flips `fault_now`.
  stall_writes: bool,
  /// When set, the next `poll_write` fails once (then `stall_writes` is cleared).
  fault_now: bool,
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

pub(crate) fn duplex_with_capacity(cap: usize) -> (Pipe, Pipe) {
  duplex_with(cap, None)
}

/// First pipe's writes accept `after` bytes, then fail once and recover.
pub(crate) fn duplex_with_write_fault(after: usize) -> (Pipe, Pipe) {
  let a = Arc::new(Mutex::new(Shared::default()));
  let b = Arc::new(Mutex::new(Shared {
    fault_after: Some(after),
    ..Default::default()
  }));
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

/// The first pipe's `poll_close` never completes (models a transport whose
/// shutdown, e.g. a TLS close_notify, hangs on a gone peer).
pub(crate) fn duplex_with_stalling_close() -> (Pipe, Pipe) {
  let a = Arc::new(Mutex::new(Shared::default()));
  let b = Arc::new(Mutex::new(Shared {
    stall_close: true,
    ..Default::default()
  }));
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

/// The first pipe's writes succeed but its `poll_flush` never completes (models a
/// buffered transport whose peer stopped reading: bytes buffer on `write` but the
/// flush to the socket stalls). The writer's flush deadline must bound this.
pub(crate) fn duplex_with_stalling_flush() -> (Pipe, Pipe) {
  let a = Arc::new(Mutex::new(Shared::default()));
  let b = Arc::new(Mutex::new(Shared {
    stall_flush: true,
    ..Default::default()
  }));
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

/// The first pipe's writes always succeed (unbounded buffer), but its `poll_flush`
/// completes only once the reader has drained everything written — modelling a
/// buffered transport where "flush" means the peer has received the bytes. A flush
/// to a reading peer completes (as fast as it reads); to a non-reading peer it
/// stalls. Used to check that a slow-but-progressing flush is not false-aborted.
pub(crate) fn duplex_with_draining_flush() -> (Pipe, Pipe) {
  let a = Arc::new(Mutex::new(Shared::default()));
  let b = Arc::new(Mutex::new(Shared {
    flush_drains: true,
    ..Default::default()
  }));
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

/// The first pipe fails its first write, then its `poll_flush` never completes
/// (models a transport that errors a write and then stalls the flush).
pub(crate) fn duplex_with_write_fault_then_stuck_flush() -> (Pipe, Pipe) {
  let a = Arc::new(Mutex::new(Shared::default()));
  let b = Arc::new(Mutex::new(Shared {
    fault_after: Some(0),
    stall_flush: true,
    ..Default::default()
  }));
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

/// Fires a one-shot transport write fault on a stalled pipe (see
/// [`duplex_with_stalled_then_faulting_write`]).
pub(crate) struct FaultTrigger(Arc<Mutex<Shared>>);

impl FaultTrigger {
  /// Makes the stalled pipe's parked write wake and fail once.
  pub(crate) fn fire(&self) {
    let mut g = self.0.lock().unwrap();
    g.fault_now = true;
    if let Some(w) = g.write_waker.take() {
      w.wake();
    }
  }
}

/// The first pipe's writes park (frames back up behind them) until the returned
/// [`FaultTrigger`] fires, at which point the parked write fails once. Models a
/// transport that backs up and then errors, so a send queued behind the stalled
/// write can be observed surfacing the real Io error rather than a bare Closed.
pub(crate) fn duplex_with_stalled_then_faulting_write() -> (Pipe, Pipe, FaultTrigger) {
  let a = Arc::new(Mutex::new(Shared::default()));
  let b = Arc::new(Mutex::new(Shared {
    stall_writes: true,
    ..Default::default()
  }));
  let trigger = FaultTrigger(b.clone());
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
    trigger,
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
    if g.fault_now {
      g.fault_now = false;
      g.stall_writes = false; // recover so the transport is consistent post-fault
      return Poll::Ready(Err(io::Error::other("triggered write fault")));
    }
    if g.stall_writes {
      g.write_waker = Some(cx.waker().clone());
      return Poll::Pending; // park; frames pile up behind the stalled write
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
    let mut g = self.write.lock().unwrap();
    if g.stall_flush {
      return Poll::Pending; // never completes; models a stuck flush
    }
    if g.flush_drains && !g.buf.is_empty() {
      // Completes once the reader drains the buffer; `poll_read` wakes this.
      g.write_waker = Some(cx.waker().clone());
      return Poll::Pending;
    }
    Poll::Ready(Ok(()))
  }

  fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
    let mut g = self.write.lock().unwrap();
    if g.stall_close {
      return Poll::Pending; // never completes; only an external abort frees it
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
    // Closing `a`'s write side EOFs `b`'s reads.
    a.close().await.unwrap();
    let n = b.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
  }
}
