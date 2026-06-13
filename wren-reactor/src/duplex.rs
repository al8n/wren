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
  fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
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
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
    let mut g = self.write.lock().unwrap();
    if g.closed {
      return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
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

  fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
    let mut g = self.write.lock().unwrap();
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
