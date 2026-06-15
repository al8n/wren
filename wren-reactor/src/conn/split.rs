//! Independently-owned read and write halves over a shared [`Inner`].
//!
//! The two halves share `Inner` through an `Arc<Mutex<_>>`. The lock is held only
//! across brief, non-blocking poll steps (a `poll_read`/`poll_write` attempt plus
//! protocol CPU) and NEVER across a `Pending` — a stalled write returns `Pending`
//! and releases the lock, so reads never head-of-line-block behind it (and vice
//! versa). Concurrent read + write from two tasks; tokio-tungstenite-style split.

use std::{
  pin::Pin,
  sync::{Arc, Mutex},
  task::{Context, Poll},
};

use agnostic_lite::RuntimeLite;
use futures_util::{Sink, Stream};
use websocket_proto::{
  connection::{Closed, role},
  frame::CloseCode,
  message::Message,
};

use super::Inner;
use crate::{error::Error, runtime::Duplex};

/// The read half: receives decoded messages and keeps the protocol moving
/// (pong echoes, the close handshake) while it is polled.
pub struct ReadHalf<R, Ro, S> {
  inner: Arc<Mutex<Inner<R, Ro, S>>>,
}

/// The write half: sends messages independently of the read half.
pub struct WriteHalf<R, Ro, S> {
  inner: Arc<Mutex<Inner<R, Ro, S>>>,
}

impl<R, Ro, S> std::fmt::Debug for ReadHalf<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ReadHalf").finish_non_exhaustive()
  }
}
impl<R, Ro, S> std::fmt::Debug for WriteHalf<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WriteHalf").finish_non_exhaustive()
  }
}

pub(crate) fn pair<R, Ro, S>(inner: Inner<R, Ro, S>) -> (ReadHalf<R, Ro, S>, WriteHalf<R, Ro, S>) {
  let inner = Arc::new(Mutex::new(inner));
  (
    ReadHalf {
      inner: inner.clone(),
    },
    WriteHalf { inner },
  )
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> ReadHalf<R, Ro, S> {
  /// The next data message, or `None` once the connection has closed.
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    futures_util::future::poll_fn(|cx| self.inner.lock().unwrap().poll_next(cx)).await
  }

  /// How the connection ended, once [`next`](Self::next) returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.inner.lock().unwrap().closed
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> WriteHalf<R, Ro, S> {
  /// Backpressure gate: ready once the staged buffer is below the soft cap. Awaited
  /// before each send (so the buffer stays bounded), and it parks in the shared
  /// write-waker so a reader draining the buffer releases it.
  async fn ready(&mut self) -> Result<(), Error> {
    futures_util::future::poll_fn(|cx| self.inner.lock().unwrap().poll_ready_writer(cx)).await
  }

  /// Sends a whole data message.
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
      .lock()
      .unwrap()
      .encode_into_buf(text.len(), |c, o| c.encode_text(text, o))?;
    self.flush().await
  }

  /// Sends a whole binary message.
  pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), Error> {
    self.ready().await?;
    self
      .inner
      .lock()
      .unwrap()
      .encode_into_buf(data.len(), |c, o| c.encode_binary(data, o))?;
    self.flush().await
  }

  /// Sends a Ping (the peer's Pong is consumed by the read half).
  pub async fn ping(&mut self, payload: &[u8]) -> Result<(), Error> {
    self.ready().await?;
    self
      .inner
      .lock()
      .unwrap()
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
      .lock()
      .unwrap()
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
      .lock()
      .unwrap()
      .encode_into_buf(data.len() * 2, |c, o| c.encode_binary_compressed(data, o))?;
    self.flush().await
  }

  /// Flushes any buffered outbound bytes.
  pub async fn flush(&mut self) -> Result<(), Error> {
    futures_util::future::poll_fn(|cx| self.inner.lock().unwrap().poll_flush_writer(cx)).await
  }

  /// Queues the close handshake (FIFO after queued data) and flushes the Close.
  /// The [`ReadHalf`] drives it to completion (its `next` returns `None`); bound
  /// it with your own `timeout`. Await a prior send (or [`flush`](Self::flush))
  /// before this to guarantee its delivery. Idempotent and retryable: if a
  /// `timeout(close())` is cancelled after the Close was queued, a later `close`
  /// resumes flushing it rather than failing.
  pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
    // `start_close` is idempotent: a retry after a `timeout`-cancelled close — even
    // one cancelled after the Close flushed but before the peer echo — resumes
    // flushing the queued handshake instead of re-initiating (or rejecting) it.
    self.inner.lock().unwrap().start_close(code, reason)?;
    futures_util::future::poll_fn(|cx| {
      let mut inner = self.inner.lock().unwrap();
      inner.drain_transmits()?;
      inner.poll_flush_writer(cx)
    })
    .await
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> Stream for ReadHalf<R, Ro, S> {
  type Item = Result<Message, Error>;
  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    self.get_mut().inner.lock().unwrap().poll_next(cx)
  }
}

impl<R: RuntimeLite, Ro: role::Role, S: Duplex> Sink<Message> for WriteHalf<R, Ro, S> {
  type Error = Error;
  fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    self.get_mut().inner.lock().unwrap().poll_ready_writer(cx)
  }
  fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Error> {
    let mut inner = self.get_mut().inner.lock().unwrap();
    match item {
      Message::Text(t) => inner.encode_into_buf(t.len(), |c, o| c.encode_text(t.as_ref(), o)),
      Message::Binary(d) => inner.encode_into_buf(d.len(), |c, o| c.encode_binary(d.as_ref(), o)),
    }
  }
  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    self.get_mut().inner.lock().unwrap().poll_flush_writer(cx)
  }
  fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    let mut inner = self.get_mut().inner.lock().unwrap();
    // Idempotent: safe to call every poll; a poisoned connection surfaces via flush.
    let _ = inner.start_close(CloseCode::Normal, "");
    inner.drain_transmits()?;
    inner.poll_flush_writer(cx)
  }
}
