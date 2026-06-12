//! A loopback in-memory byte stream implementing compio's
//! AsyncRead/AsyncWrite, so connection logic is unit-testable without
//! sockets.

use compio_buf::{BufResult, IoBuf, IoBufMut};
use compio_io::{AsyncRead, AsyncWrite};
use event_listener::Event;
use std::{cell::RefCell, collections::VecDeque, io, rc::Rc};

#[derive(Debug, Default)]
struct Shared {
  buf: RefCell<VecDeque<u8>>,
  closed: RefCell<bool>,
  event: Event,
}

/// One end of a duplex pair. Deliberately NOT `Clone`: dropping an end
/// closes the channel, which a surviving clone would observe spuriously.
#[derive(Debug)]
pub(crate) struct Pipe {
  read: Rc<Shared>,
  write: Rc<Shared>,
}

/// A connected in-memory stream pair.
pub(crate) fn duplex() -> (Pipe, Pipe) {
  let a = Rc::new(Shared::default());
  let b = Rc::new(Shared::default());
  (
    Pipe {
      read: a.clone(),
      write: b.clone(),
    },
    Pipe { read: b, write: a },
  )
}

impl AsyncRead for Pipe {
  async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
    loop {
      let listener = self.read.event.listen();
      let copied: Option<usize> = {
        let mut q = self.read.buf.borrow_mut();
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
          }
          Some(n)
        } else if *self.read.closed.borrow() {
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

impl AsyncWrite for Pipe {
  async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
    if *self.write.closed.borrow() {
      return BufResult(Err(io::Error::from(io::ErrorKind::BrokenPipe)), buf);
    }
    let slice = buf.as_init();
    self.write.buf.borrow_mut().extend(slice);
    let n = slice.len();
    self.write.event.notify(usize::MAX);
    BufResult(Ok(n), buf)
  }

  async fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }

  async fn shutdown(&mut self) -> io::Result<()> {
    *self.write.closed.borrow_mut() = true;
    self.write.event.notify(usize::MAX);
    Ok(())
  }
}

impl Drop for Pipe {
  fn drop(&mut self) {
    // Dropping an end EOFs the peer's reads and fails its writes.
    *self.write.closed.borrow_mut() = true;
    self.write.event.notify(usize::MAX);
    // And wake any reader parked on data we will never send.
    self.read.event.notify(usize::MAX);
  }
}
