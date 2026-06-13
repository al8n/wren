//! The write half: direct app-data writes to the shared write transport.
//!
//! App frames go straight to the wire (not gated on the reader). Control
//! frames (pong/ping/close echo) are the [`ReadHalf`](super::ReadHalf)
//! pump's job.

use std::{
  future::Future,
  marker::PhantomData,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
  time::Instant,
};

use agnostic_lite::RuntimeLite;
use futures_util::AsyncWriteExt;
use websocket_proto::{Connection, connection::role, frame::CloseCode, message::Message};
use wren_trace::debug;

use super::Shared;
use crate::{error::Error, runtime::Duplex};

type BoxSend = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

/// The write half. App sends progress independently of the read half.
pub struct WriteHalf<R, Ro, S> {
  shared: Arc<Shared<Ro, S>>,
  /// In-flight `Sink` send / close future (the inherent methods don't use it).
  pending: Option<BoxSend>,
  close_started: bool,
  _rt: PhantomData<fn() -> R>,
}

impl<R, Ro, S> std::fmt::Debug for WriteHalf<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WriteHalf").finish_non_exhaustive()
  }
}

/// Encodes one frame under the proto lock into an owned buffer.
async fn encode_frame<Ro: role::Role, S: Duplex>(
  shared: &Arc<Shared<Ro, S>>,
  hint: usize,
  f: impl FnOnce(&mut Connection<Instant, Ro>, &mut [u8]) -> Result<usize, websocket_proto::connection::EncodeError>,
) -> Result<Vec<u8>, Error> {
  if let Some(kind) = shared.poisoned() {
    return Err(Error::Io(kind.into()));
  }
  {
    let meta = shared.meta.lock().unwrap();
    if meta.closed.is_some() || meta.close_pending {
      return Err(Error::Closed);
    }
  }
  let mut conn = shared.conn.lock().await;
  let mut buf = vec![0u8; hint + websocket_proto::constants::MAX_FRAME_HEADER + 64];
  let n = f(&mut conn, &mut buf)?;
  buf.truncate(n);
  Ok(buf)
}

/// Writes an encoded frame to the wire (whole-frame atomic under the lock).
async fn write_frame<Ro: role::Role, S: Duplex>(shared: &Arc<Shared<Ro, S>>, frame: Vec<u8>) -> Result<(), Error> {
  let mut wr = shared.write.lock().await;
  let result = async {
    wr.write_all(&frame).await?;
    wr.flush().await
  }
  .await;
  drop(wr);
  if let Err(e) = result {
    shared.poison(e.kind());
    return Err(Error::Io(e));
  }
  Ok(())
}

/// Owned send (no `&self` borrow) — backs the `Sink` impl's stored future.
async fn send_message<Ro: role::Role + Send + 'static, S: Duplex>(shared: Arc<Shared<Ro, S>>, msg: Message) -> Result<(), Error> {
  let frame = match &msg {
    Message::Text(t) => encode_frame(&shared, t.len(), |c, o| c.encode_text(t.as_ref(), o)).await?,
    Message::Binary(d) => encode_frame(&shared, d.len(), |c, o| c.encode_binary(d.as_ref(), o)).await?,
  };
  write_frame(&shared, frame).await
}

/// Owned close (queues the Close and wakes the reader).
async fn close_owned<Ro: role::Role + Send + 'static, S: Duplex>(
  shared: Arc<Shared<Ro, S>>,
  code: CloseCode,
  reason: &str,
) -> Result<(), Error> {
  {
    let mut conn = shared.conn.lock().await;
    let mut meta = shared.meta.lock().unwrap();
    if meta.closed.is_some() || meta.close_pending {
      return Err(Error::Closed);
    }
    conn.close(code, reason)?;
    meta.close_pending = true;
  }
  debug!(code = ?code, reason, "close requested");
  shared.wake_reader();
  Ok(())
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> WriteHalf<R, Ro, S> {
  pub(crate) fn new(shared: Arc<Shared<Ro, S>>) -> Self {
    Self { shared, pending: None, close_started: false, _rt: PhantomData }
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
    let f = encode_frame(&self.shared, t.len(), |c, o| c.encode_text(t, o)).await?;
    write_frame(&self.shared, f).await
  }
  /// Sends a whole binary message.
  pub async fn send_binary(&mut self, d: &[u8]) -> Result<(), Error> {
    let f = encode_frame(&self.shared, d.len(), |c, o| c.encode_binary(d, o)).await?;
    write_frame(&self.shared, f).await
  }
  /// Sends a Ping.
  pub async fn ping(&mut self, p: &[u8]) -> Result<(), Error> {
    let f = encode_frame(&self.shared, p.len(), |c, o| c.encode_ping(p, o)).await?;
    write_frame(&self.shared, f).await
  }

  /// Requests the close handshake: queues the Close into proto and wakes the
  /// reader. The [`ReadHalf`](super::ReadHalf) flushes it (budget-bounded,
  /// even against a non-reading peer) and drives the handshake to completion
  /// — its `next()` returns `None` and `closed()` carries the outcome.
  ///
  /// Resolves once the Close is queued; poll the read half to complete it.
  pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
    {
      let mut conn = self.shared.conn.lock().await;
      let mut meta = self.shared.meta.lock().unwrap();
      if meta.closed.is_some() || meta.close_pending {
        return Err(Error::Closed);
      }
      conn.close(code, reason)?;
      meta.close_pending = true;
    }
    debug!(code = ?code, reason, "close requested");
    self.shared.wake_reader();
    Ok(())
  }
}

impl<R: RuntimeLite, Ro: role::Role + Send + 'static, S: Duplex> futures_util::Sink<Message> for WriteHalf<R, Ro, S> {
  type Error = Error;

  fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    self.poll_flush(cx)
  }

  fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Error> {
    let me = self.get_mut();
    let shared = me.shared.clone();
    me.pending = Some(Box::pin(send_message(shared, item)));
    Ok(())
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    let me = self.get_mut();
    if let Some(fut) = me.pending.as_mut() {
      match fut.as_mut().poll(cx) {
        Poll::Ready(r) => {
          me.pending = None;
          Poll::Ready(r)
        }
        Poll::Pending => Poll::Pending,
      }
    } else {
      Poll::Ready(Ok(()))
    }
  }

  fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    let me = self.get_mut();
    // Finish any in-flight send first.
    if me.pending.is_some() && !me.close_started {
      match me.pending.as_mut().unwrap().as_mut().poll(cx) {
        Poll::Ready(Ok(())) => me.pending = None,
        Poll::Ready(Err(e)) => {
          me.pending = None;
          return Poll::Ready(Err(e));
        }
        Poll::Pending => return Poll::Pending,
      }
    }
    // Then queue the close once.
    if !me.close_started {
      let shared = me.shared.clone();
      me.pending = Some(Box::pin(close_owned(shared, CloseCode::Normal, "")));
      me.close_started = true;
    }
    if let Some(fut) = me.pending.as_mut() {
      match fut.as_mut().poll(cx) {
        Poll::Ready(r) => {
          me.pending = None;
          Poll::Ready(r)
        }
        Poll::Pending => Poll::Pending,
      }
    } else {
      Poll::Ready(Ok(()))
    }
  }
}
