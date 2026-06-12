//! A loopback in-memory byte stream implementing compio's
//! AsyncRead/AsyncWrite (split into halves), so connection logic is
//! unit-testable without sockets — through the SAME `AsyncStream`
//! adapter path production sockets use.

use compio_buf::{BufResult, IoBuf, IoBufMut};
use compio_io::{AsyncRead, AsyncWrite, util::Splittable};
use event_listener::Event;
use std::{cell::RefCell, collections::VecDeque, io, rc::Rc};

#[derive(Debug, Default)]
struct Shared {
  buf: RefCell<VecDeque<u8>>,
  /// Writes past this park until the reader drains (0 = unbounded).
  capacity: usize,
  /// `Some(n)`: accept `n` more bytes, then fail ONE write and recover —
  /// for poisoning tests that need a transport which errors once.
  fault_after: RefCell<Option<usize>>,
  closed: RefCell<bool>,
  event: Event,
}

/// One end of a duplex pair; [`Splittable`] into a reader + writer whose
/// drops close their direction.
#[derive(Debug)]
pub(crate) struct Pipe {
  read: Rc<Shared>,
  write: Rc<Shared>,
}

pub(crate) struct PipeReader {
  shared: Rc<Shared>,
}

pub(crate) struct PipeWriter {
  shared: Rc<Shared>,
}

/// A connected in-memory stream pair.
pub(crate) fn duplex() -> (Pipe, Pipe) {
  duplex_with_capacity(0)
}

/// A connected pair whose per-direction buffer parks writers at `cap`
/// bytes until the peer drains (0 = unbounded) — for write-backpressure
/// tests.
pub(crate) fn duplex_with_capacity(cap: usize) -> (Pipe, Pipe) {
  let a = Rc::new(Shared {
    capacity: cap,
    ..Shared::default()
  });
  let b = Rc::new(Shared {
    capacity: cap,
    ..Shared::default()
  });
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

/// A connected pair where the FIRST pipe's writes accept `after` bytes,
/// then fail one write and recover — for write-poisoning tests.
pub(crate) fn duplex_with_write_fault(after: usize) -> (Pipe, Pipe) {
  let a = Rc::new(Shared::default());
  let b = Rc::new(Shared {
    fault_after: RefCell::new(Some(after)),
    ..Shared::default()
  });
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

impl Splittable for Pipe {
  type ReadHalf = PipeReader;
  type WriteHalf = PipeWriter;

  fn split(self) -> (PipeReader, PipeWriter) {
    (
      PipeReader { shared: self.read },
      PipeWriter { shared: self.write },
    )
  }
}

impl AsyncRead for PipeReader {
  async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
    loop {
      let listener = self.shared.event.listen();
      let copied: Option<usize> = {
        let mut q = self.shared.buf.borrow_mut();
        if !q.is_empty() {
          let start = buf.buf_len();
          let queued = q.len();
          let n = {
            let init = buf.ensure_init();
            match init.get_mut(start..) {
              Some(spare) if !<[u8]>::is_empty(spare) => {
                let n = usize::min(<[u8]>::len(spare), queued);
                for (dst, byte) in spare.iter_mut().zip(q.drain(..n)) {
                  *dst = byte;
                }
                n
              }
              // No spare capacity: report a zero-byte read.
              _ => 0,
            }
          };
          if n > 0 {
            // SAFETY: `ensure_init` initialized the whole capacity and the
            // first `start + n` bytes are now meaningful data.
            unsafe { buf.set_len(start + n) };
            // A capacity-bounded writer may be parked on the drain.
            self.shared.event.notify(usize::MAX);
          }
          Some(n)
        } else if *self.shared.closed.borrow() {
          Some(0)
        } else {
          None
        }
      };
      if let Some(n) = copied {
        return BufResult(Ok(n), buf);
      }
      listener.await;
    }
  }
}

impl Drop for PipeReader {
  fn drop(&mut self) {
    // The peer's writes fail and a parked peer writer wakes.
    *self.shared.closed.borrow_mut() = true;
    self.shared.event.notify(usize::MAX);
  }
}

impl AsyncWrite for PipeWriter {
  async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
    loop {
      let listener = self.shared.event.listen();
      let outcome: Option<io::Result<usize>> = {
        if *self.shared.closed.borrow() {
          Some(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
        } else if matches!(*self.shared.fault_after.borrow(), Some(0)) {
          // The armed fault fires once, then the transport recovers.
          *self.shared.fault_after.borrow_mut() = None;
          Some(Err(io::Error::other("injected write fault")))
        } else {
          let mut q = self.shared.buf.borrow_mut();
          let room = if self.shared.capacity == 0 {
            usize::MAX
          } else {
            self.shared.capacity.saturating_sub(q.len())
          };
          if room == 0 {
            None // full: park until the reader drains
          } else {
            let slice = buf.as_init();
            let mut n = usize::min(slice.len(), room);
            let mut fault = self.shared.fault_after.borrow_mut();
            if let Some(remaining) = fault.as_mut() {
              n = usize::min(n, *remaining);
              *remaining -= n;
            }
            drop(fault);
            q.extend(slice.get(..n).unwrap_or(&[]));
            self.shared.event.notify(usize::MAX);
            Some(Ok(n))
          }
        }
      };
      if let Some(result) = outcome {
        return BufResult(result, buf);
      }
      listener.await;
    }
  }

  async fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }

  async fn shutdown(&mut self) -> io::Result<()> {
    *self.shared.closed.borrow_mut() = true;
    self.shared.event.notify(usize::MAX);
    Ok(())
  }
}

impl Drop for PipeWriter {
  fn drop(&mut self) {
    // EOF for the peer's reads.
    *self.shared.closed.borrow_mut() = true;
    self.shared.event.notify(usize::MAX);
  }
}

crate::into_duplex::adapted_into_duplex!(Pipe);
