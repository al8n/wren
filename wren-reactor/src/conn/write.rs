//! The write half: direct app-data writes to the shared write transport.
//!
//! App frames go straight to the wire (not gated on the reader). Control
//! frames (pong/ping/close echo) are the [`ReadHalf`](super::ReadHalf)
//! pump's job.

use std::{marker::PhantomData, sync::Arc, time::Instant};

use agnostic_lite::RuntimeLite;
use futures_util::AsyncWriteExt;
use websocket_proto::{Connection, connection::role, frame::CloseCode, message::Message};
use wren_trace::debug;

use super::{Shared, TRANSMIT_SCRATCH};
use crate::{error::Error, runtime::Duplex};

/// The write half. App sends progress independently of the read half.
pub struct WriteHalf<R, Ro, S> {
  shared: Arc<Shared<Ro, S>>,
  _rt: PhantomData<fn() -> R>,
}

impl<R, Ro, S> std::fmt::Debug for WriteHalf<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WriteHalf").finish_non_exhaustive()
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> WriteHalf<R, Ro, S> {
  pub(crate) fn new(shared: Arc<Shared<Ro, S>>) -> Self {
    Self { shared, _rt: PhantomData }
  }

  /// Encodes one frame under the proto lock into an owned buffer.
  async fn encode(
    &self,
    hint: usize,
    f: impl FnOnce(&mut Connection<Instant, Ro>, &mut [u8]) -> Result<usize, websocket_proto::connection::EncodeError>,
  ) -> Result<Vec<u8>, Error> {
    if let Some(kind) = self.shared.poisoned() {
      return Err(Error::Io(kind.into()));
    }
    {
      let meta = self.shared.meta.lock().unwrap();
      if meta.closed.is_some() || meta.close_pending {
        return Err(Error::Closed);
      }
    }
    let mut conn = self.shared.conn.lock().await;
    let mut buf = vec![0u8; hint + websocket_proto::constants::MAX_FRAME_HEADER + 64];
    let n = f(&mut conn, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
  }

  /// Writes an encoded frame to the wire (whole-frame atomic under the lock).
  async fn write_frame(&self, frame: Vec<u8>) -> Result<(), Error> {
    let mut wr = self.shared.write.lock().await;
    let result = async {
      wr.write_all(&frame).await?;
      wr.flush().await
    }
    .await;
    drop(wr);
    if let Err(e) = result {
      self.shared.poison(e.kind());
      return Err(Error::Io(e));
    }
    Ok(())
  }

  /// Sends a whole data message.
  pub async fn send(&mut self, msg: Message) -> Result<(), Error> {
    match &msg {
      Message::Text(t) => self.send_text(t.as_ref()).await,
      Message::Binary(d) => self.send_binary(d.as_ref()).await,
    }
  }
  /// Sends a whole text message.
  pub async fn send_text(&mut self, t: &str) -> Result<(), Error> {
    let f = self.encode(t.len(), |c, o| c.encode_text(t, o)).await?;
    self.write_frame(f).await
  }
  /// Sends a whole binary message.
  pub async fn send_binary(&mut self, d: &[u8]) -> Result<(), Error> {
    let f = self.encode(d.len(), |c, o| c.encode_binary(d, o)).await?;
    self.write_frame(f).await
  }
  /// Sends a Ping.
  pub async fn ping(&mut self, p: &[u8]) -> Result<(), Error> {
    let f = self.encode(p.len(), |c, o| c.encode_ping(p, o)).await?;
    self.write_frame(f).await
  }

  /// Starts the close handshake by putting the Close frame on the wire. The
  /// [`ReadHalf`](super::ReadHalf) drives it to completion — its `next()`
  /// returns `None` and `closed()` carries the outcome. Wakes a parked split
  /// reader to re-derive its deadline.
  pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
    {
      let meta = self.shared.meta.lock().unwrap();
      if meta.closed.is_some() || meta.close_pending {
        return Err(Error::Closed);
      }
    }
    let frame = {
      let mut conn = self.shared.conn.lock().await;
      conn.close(code, reason)?;
      let mut scratch = [0u8; TRANSMIT_SCRATCH];
      let mut batch = Vec::new();
      let now = Instant::now();
      while let Ok(Some(n)) = conn.poll_transmit(now, &mut scratch) {
        batch.extend_from_slice(&scratch[..n]);
      }
      batch
    };
    debug!(code = ?code, reason, "starting close handshake");
    self.shared.meta.lock().unwrap().close_pending = true;
    self.write_frame(frame).await?;
    {
      let mut meta = self.shared.meta.lock().unwrap();
      meta.close_pending = false;
      meta.close_flushed_at.get_or_insert(Instant::now());
    }
    self.shared.reader_wake.notify(usize::MAX);
    Ok(())
  }
}
