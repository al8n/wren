//! The write half: command senders to the driver task.
//!
//! A data send enqueues a [`DataCommand`] on the bounded **data** channel and
//! awaits its reply. The bounded channel — together with the driver's
//! outbound-room gate — is the write backpressure, and the real socket write
//! lives in the writer task. Cancelling a send is safe but **not transactional**:
//! the enqueue is atomic (all-or-nothing, never a partial frame), and a send
//! dropped while backpressured (awaiting channel room) is not sent — but one
//! dropped after its command is admitted (which happens before the future resolves
//! with the write result) is still delivered in full. So a cancelled send forfeits
//! only its result, never corrupts the stream or breaks backpressure, and a
//! timed-out send may already be on the wire and must not be blindly retried.
//! Close goes on a separate **control** channel the driver always services, so
//! it is never starved by a backed-up queue.

use std::{
  collections::VecDeque,
  marker::PhantomData,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll, ready},
};

use futures_channel::{mpsc, oneshot};
use futures_util::Sink;
use websocket_proto::{frame::CloseCode, message::Message};

use super::{CloseRequest, DataCommand, Marker, Reply, Shared};
use crate::error::Error;

/// The write half. App sends progress independently of the read half.
pub struct WriteHalf<R, Ro, S> {
  data: mpsc::Sender<DataCommand>,
  control: mpsc::Sender<CloseRequest>,
  shared: Arc<Shared>,
  /// Replies for frames queued via the `Sink` (`start_send`), awaited by
  /// `poll_flush`/`poll_close` so the sink confirms each write rather than
  /// acknowledging it the moment it is queued.
  pending: VecDeque<oneshot::Receiver<Result<(), Error>>>,
  /// Whether the `Sink` has already queued its close (`poll_close` repeats).
  close_sent: bool,
  /// Whether outbound permessage-deflate is usable (negotiated, full 15-bit
  /// window). Mirrors proto's `encode_compressed` guard so a compressed send that
  /// is guaranteed to fail with `CompressionUnavailable` is rejected up front
  /// rather than wedging behind backpressure (see [`Self::send_text_compressed`]).
  #[cfg(feature = "deflate")]
  compress_outbound: bool,
  _marker: Marker<R, Ro, S>,
}

impl<R, Ro, S> std::fmt::Debug for WriteHalf<R, Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WriteHalf").finish_non_exhaustive()
  }
}

impl<R, Ro, S> WriteHalf<R, Ro, S> {
  pub(crate) fn new(
    data: mpsc::Sender<DataCommand>,
    control: mpsc::Sender<CloseRequest>,
    shared: Arc<Shared>,
    #[cfg(feature = "deflate")] compress_outbound: bool,
  ) -> Self {
    Self {
      data,
      control,
      shared,
      pending: VecDeque::new(),
      close_sent: false,
      #[cfg(feature = "deflate")]
      compress_outbound,
      _marker: PhantomData,
    }
  }

  /// Polls queued `Sink` send replies front-to-back, dropping completed ones and
  /// surfacing the first failure. With `wait`, returns `Pending` while a send is
  /// still in flight (so `poll_flush` blocks until every write is confirmed);
  /// without it, stops at the first in-flight send (so `poll_ready` reaps only
  /// completed ones) with its waker registered.
  fn drain_pending(&mut self, cx: &mut Context<'_>, wait: bool) -> Poll<Result<(), Error>> {
    use futures_util::FutureExt;
    while !self.pending.is_empty() {
      let polled = self.pending.front_mut().unwrap().poll_unpin(cx);
      match polled {
        Poll::Ready(Ok(Ok(()))) => {
          self.pending.pop_front();
        }
        Poll::Ready(Ok(Err(e))) => {
          self.pending.pop_front();
          return Poll::Ready(Err(e));
        }
        Poll::Ready(Err(_)) => {
          self.pending.pop_front();
          return Poll::Ready(Err(self.terminal_error()));
        }
        Poll::Pending => {
          if wait {
            return Poll::Pending;
          }
          break;
        }
      }
    }
    Poll::Ready(Ok(()))
  }

  /// Enqueues a data command and awaits its write result. Backpressure is the
  /// bounded data channel (the driver admits only while the outbound queue has
  /// room). The enqueue is atomic (all-or-nothing, never a partial frame): a send
  /// cancelled before admission is not sent, but once admitted the frame is
  /// delivered even if this future is dropped — so a cancelled send forfeits only
  /// the result and must not be blindly retried.
  async fn issue(&mut self, make: impl FnOnce(Reply) -> DataCommand) -> Result<(), Error> {
    use futures_util::SinkExt;
    // Fail fast on a poisoned or already-closed connection BEFORE enqueuing: a
    // prior transport write error poisons the connection even after the driver has
    // gone (when the channel would only report `Closed`), and once closed the driver
    // is in its bounded clean-drain and no longer servicing the data plane, so an
    // enqueued frame would otherwise wait out the drain bound before failing.
    self.terminal_preflight()?;
    let (tx, rx) = oneshot::channel();
    // A closed channel or a dropped reply means the driver has gone. If it went
    // because the writer hit a transport error, surface that real `Io` error
    // rather than a generic `Closed` — a send queued behind the failing frame
    // (its reply dropped, not answered) must not collapse to `Closed`.
    if self.data.send(make(tx)).await.is_err() {
      return Err(self.terminal_error());
    }
    match rx.await {
      Ok(result) => result,
      Err(_) => Err(self.terminal_error()),
    }
  }

  /// The error to report when a command or its reply was dropped because the
  /// driver terminated: the recorded transport write error if there was one,
  /// else a generic [`Error::Closed`].
  fn terminal_error(&self) -> Error {
    match self.shared.write_err() {
      Some(kind) => Error::Io(kind.into()),
      None => Error::Closed,
    }
  }

  /// Fails fast when the connection can no longer accept a new frame: a recorded
  /// transport write error (poison, reported as the precise `Io` kind) or an
  /// already-closed connection. The latter matters because once closed the driver
  /// enters its bounded clean-drain and stops servicing the data/control planes, so
  /// a frame enqueued then would not get a reply until the drain bound elapsed —
  /// this returns the terminal cause up front instead of wedging behind the drain.
  /// Run BEFORE any enqueue or payload copy, and before any input/availability
  /// guard, so the real terminal cause is never masked.
  fn terminal_preflight(&self) -> Result<(), Error> {
    if self.shared.write_err().is_some() || self.shared.is_closed() {
      return Err(self.terminal_error());
    }
    Ok(())
  }

  /// Sends a whole data message.
  pub async fn send(&mut self, msg: Message) -> Result<(), Error> {
    self.issue(|tx| DataCommand::Send(msg, tx)).await
  }
  /// Sends a whole text message.
  pub async fn send_text(&mut self, t: &str) -> Result<(), Error> {
    self
      .issue(|tx| DataCommand::Send(Message::Text(t.into()), tx))
      .await
  }
  /// Sends a whole binary message.
  pub async fn send_binary(&mut self, d: &[u8]) -> Result<(), Error> {
    self
      .issue(|tx| DataCommand::Send(Message::Binary(d.to_vec().into()), tx))
      .await
  }
  /// Sends a Ping (payload at most 125 bytes, the control-frame limit).
  pub async fn ping(&mut self, p: &[u8]) -> Result<(), Error> {
    // Fail fast on a poisoned/closed connection FIRST so the terminal cause (`Io` /
    // `Closed`) is not masked by the length guard below (the `issue` preflight stays
    // the post-validation race guard). Then reject an oversized control payload
    // BEFORE the (backpressured) enqueue and before copying it: an invalid ping never
    // reaches the wire, so it must fail immediately rather than wedge behind a full
    // outbound queue. Mirrors the driver's `encode_ping` check.
    self.terminal_preflight()?;
    if p.len() > websocket_proto::constants::MAX_CONTROL_PAYLOAD {
      return Err(websocket_proto::connection::EncodeError::ControlTooLong.into());
    }
    self.issue(|tx| DataCommand::Ping(p.to_vec(), tx)).await
  }
  /// Sends a whole text message compressed with permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_text_compressed(&mut self, t: &str) -> Result<(), Error> {
    self.ensure_compressible()?;
    self
      .issue(|tx| DataCommand::SendCompressed(Message::Text(t.into()), tx))
      .await
  }
  /// Sends a whole binary message compressed with permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub async fn send_binary_compressed(&mut self, d: &[u8]) -> Result<(), Error> {
    self.ensure_compressible()?;
    self
      .issue(|tx| DataCommand::SendCompressed(Message::Binary(d.to_vec().into()), tx))
      .await
  }

  /// Rejects a compressed send that is guaranteed to fail BEFORE the (backpressured)
  /// enqueue and before copying the payload: if outbound permessage-deflate is not
  /// usable, the driver would only reject with `CompressionUnavailable` after the
  /// command is admitted, so under a saturated outbound queue a doomed send would
  /// otherwise wedge behind a full queue. Mirrors the driver's `encode_compressed`
  /// guard (deflate negotiated and the outbound window the full 15 bits).
  #[cfg(feature = "deflate")]
  fn ensure_compressible(&self) -> Result<(), Error> {
    // Surface a poisoned/closed connection first — exactly as `issue` does — so a
    // compressed send on a dead connection reports the real terminal cause (`Io` /
    // `Closed`) instead of masking it as `CompressionUnavailable`. Both run before
    // any enqueue or payload copy.
    self.terminal_preflight()?;
    if self.compress_outbound {
      Ok(())
    } else {
      Err(websocket_proto::connection::EncodeError::CompressionUnavailable.into())
    }
  }

  /// Requests the close handshake. The [`ReadHalf`](super::ReadHalf) drives it
  /// to completion — its `next()` returns `None` and `closed()` carries the
  /// outcome. Resolves once the close is accepted/queued. Routed on the control
  /// channel, so it reaches the driver even when the outbound queue is full.
  pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
    use futures_util::SinkExt;
    use websocket_proto::connection::EncodeError;
    // Fail fast on a poisoned or already-closed connection: a recorded write error
    // surfaces as `Io`, and on an already-closed connection the driver is in its
    // bounded clean-drain (not servicing the control plane), so routing a Close
    // there would wait out the drain bound before failing.
    self.terminal_preflight()?;
    // Validate the close BEFORE anything blocking: an invalid code or overlong
    // reason never arms a handshake, so it must be rejected immediately — without
    // waiting on `confirm_pending` (which could be parked on a stuck Sink write to
    // a non-reading peer) and without touching pending confirmations. Mirrors the
    // driver's `Connection::close` checks so the verdict can't diverge.
    if !code.is_valid_on_wire() {
      return Err(EncodeError::InvalidCloseCode.into());
    }
    if reason.len() > websocket_proto::constants::MAX_CONTROL_PAYLOAD - 2 {
      return Err(EncodeError::ReasonTooLong.into());
    }
    // Confirm any frames queued via the `Sink` first. The close is routed on the
    // control plane, which the driver services independently of the data plane;
    // without this, `feed(..).await; close(..).await` could let `closing` be set
    // before those data commands are admitted, so they would be rejected and
    // silently lost. Awaiting their replies here also surfaces a write failure.
    self.confirm_pending().await?;
    let (tx, rx) = oneshot::channel();
    if self
      .control
      .send(CloseRequest::new(code, reason.to_string(), tx))
      .await
      .is_err()
    {
      return Err(self.terminal_error());
    }
    match rx.await {
      Ok(result) => result,
      Err(_) => Err(self.terminal_error()),
    }
  }

  /// Awaits every frame queued via the `Sink` (`start_send`), surfacing the first
  /// failure. Lets the inherent [`close`](Self::close) flush queued sink writes
  /// before closing so a `feed`-then-`close` sequence cannot discard them.
  ///
  /// Cancellation-safe: it polls each receiver IN PLACE (via [`Self::drain_pending`])
  /// and removes one only once it resolves, so a cancelled `close` leaves the
  /// still-pending confirmations in the queue. A retried close re-confirms them
  /// instead of skipping ahead and letting `closing` be set before the data is
  /// admitted — which would reject and silently lose it.
  async fn confirm_pending(&mut self) -> Result<(), Error> {
    futures_util::future::poll_fn(|cx| self.drain_pending(cx, true)).await
  }

  /// Test-only fire-and-forget enqueue: pile frames onto the data channel
  /// without awaiting their writes, so tests can back the outbound queue up
  /// against a stuck writer.
  #[cfg(test)]
  pub(crate) fn try_enqueue(&mut self, msg: Message) {
    let (tx, _rx) = oneshot::channel();
    let _ = self.data.try_send(DataCommand::Send(msg, tx));
  }

  /// Test-only: count of `Sink` writes still awaiting confirmation. Proves
  /// `confirm_pending` is cancellation-safe (a cancelled close keeps them).
  #[cfg(test)]
  pub(crate) fn pending_len(&self) -> usize {
    self.pending.len()
  }

  /// Test-only: whether the driver has closed the data command receiver — true once
  /// the driver hits terminal closure and rejects pending commands. Proves the
  /// channel becomes the atomic admission gate before the bounded clean-drain.
  #[cfg(test)]
  pub(crate) fn data_channel_closed(&self) -> bool {
    self.data.is_closed()
  }
}

/// `Sink<Message>`: each item is queued on the bounded data channel (which, with
/// the driver's outbound-room gate, bounds the outbound queue under a slow peer).
/// `poll_flush`/`poll_close` **confirm** the queued writes — they await each
/// frame's write result and surface the first [`Error::Io`] — so a transport
/// failure is never masked as `Closed` nor silently flushed away. `poll_close`
/// performs a real WebSocket close after flushing.
impl<R, Ro, S> Sink<Message> for WriteHalf<R, Ro, S> {
  type Error = Error;

  fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    let this = self.get_mut();
    // Fail fast before accepting more work: a recorded transport error surfaces as
    // `Io` (the channel may still be briefly open after the writer faulted), and an
    // already-closed connection surfaces as `Closed` rather than admitting a frame
    // that would then wait out the driver's bounded clean-drain. (Flush/close keep
    // their write-error-only check — reaching the closed state is success there.)
    if let Err(e) = this.terminal_preflight() {
      return Poll::Ready(Err(e));
    }
    // Reap completed sends (surfacing any failure) and backpressure on the count
    // of in-flight, unconfirmed writes so `pending` cannot grow without bound.
    match this.drain_pending(cx, false) {
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
      Poll::Pending => return Poll::Pending,
    }
    if this.pending.len() >= super::DATA_CAP {
      return Poll::Pending; // a waker is registered on the front receiver
    }
    match this.data.poll_ready(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
      Poll::Ready(Err(_)) => Poll::Ready(Err(this.terminal_error())),
    }
  }
  fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Error> {
    let this = self.get_mut();
    // Close the poll_ready→start_send race: a fault or close recorded in between
    // must not let a message be enqueued onto a dead connection.
    this.terminal_preflight()?;
    let (tx, rx) = oneshot::channel();
    match this.data.start_send(DataCommand::Send(item, tx)) {
      Ok(()) => {
        this.pending.push_back(rx); // confirmed later by poll_flush/poll_close
        Ok(())
      }
      Err(_) => Err(this.terminal_error()),
    }
  }
  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    let this = self.get_mut();
    if let Some(kind) = this.shared.write_err() {
      return Poll::Ready(Err(Error::Io(kind.into())));
    }
    // Hand everything to the driver, then confirm every queued write completed.
    match Pin::new(&mut this.data).poll_flush(cx) {
      Poll::Pending => return Poll::Pending,
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(_)) => return Poll::Ready(Err(this.terminal_error())),
    }
    this.drain_pending(cx, true)
  }
  fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
    // Flush queued writes first — surfaces `write_err` and any per-frame failure,
    // and (before the close_sent fast path) means a repeated close after a fault
    // reports `Io` rather than a masked clean close.
    match self.as_mut().poll_flush(cx) {
      Poll::Ready(Ok(())) => {}
      other => return other,
    }
    let this = self.get_mut();
    // Perform a real WebSocket close: queue a Normal close once on the control
    // channel (so the peer observes a close), then report the sink closed. The
    // read half drives the handshake to completion. If the close was already queued
    // (`close_sent`) OR the connection has already closed cleanly — e.g. a
    // peer-initiated close that has since torn the driver down, dropping the control
    // channel — the close goal is already met: report success idempotently rather
    // than mapping the gone control channel to `Closed` below. A recorded write error
    // still takes precedence (already surfaced by `poll_flush` above).
    if this.close_sent || (this.shared.is_closed() && this.shared.write_err().is_none()) {
      return Poll::Ready(Ok(()));
    }
    match ready!(this.control.poll_ready(cx)) {
      Ok(()) => {}
      Err(_) => return Poll::Ready(Err(this.terminal_error())),
    }
    let (tx, _rx) = oneshot::channel();
    match this
      .control
      .start_send(CloseRequest::new(CloseCode::Normal, String::new(), tx))
    {
      Ok(()) => {}
      Err(_) => return Poll::Ready(Err(this.terminal_error())),
    }
    this.close_sent = true;
    Poll::Ready(Ok(()))
  }
}
