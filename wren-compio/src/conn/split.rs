//! Read/write halves over the shared connection state.
//!
//! The split works for ANY stream type (no `Clone` bound): the write half
//! never touches the stream. It encodes under a short borrow, enqueues the
//! frame, and rings the doorbell; the read half's pump flushes the queue.
//! Consequence (documented on every send): a split writer's sends progress
//! only while the read half is being polled.

use std::{
  cell::{Cell, RefCell},
  rc::Rc,
};

use event_listener::Event as Doorbell;
use websocket_proto::{
  connection::{Closed, role},
  frame::CloseCode,
  message::Message,
};

use super::{FrameState, Inner, OutboundFrame, encode_with, next_message};
use crate::error::Error;

/// The read half: the pump. Owns `next()` and the connection outcome.
pub struct ReadHalf<Ro, S> {
  pub(crate) inner: Rc<RefCell<Inner<Ro, S>>>,
  pub(crate) doorbell: Rc<Doorbell>,
}

/// The write half: enqueues frames for the read half's pump.
pub struct WriteHalf<Ro, S> {
  pub(crate) inner: Rc<RefCell<Inner<Ro, S>>>,
  pub(crate) doorbell: Rc<Doorbell>,
}

pub(crate) fn pair<Ro, S>(
  inner: Rc<RefCell<Inner<Ro, S>>>,
  doorbell: Rc<Doorbell>,
) -> (ReadHalf<Ro, S>, WriteHalf<Ro, S>) {
  (
    ReadHalf {
      inner: inner.clone(),
      doorbell: doorbell.clone(),
    },
    WriteHalf { inner, doorbell },
  )
}

impl<Ro, S> std::fmt::Debug for ReadHalf<Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ReadHalf").finish_non_exhaustive()
  }
}

impl<Ro, S> std::fmt::Debug for WriteHalf<Ro, S> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("WriteHalf").finish_non_exhaustive()
  }
}

impl<Ro: role::Role, S: crate::into_duplex::Duplex> ReadHalf<Ro, S> {
  /// The next data message, or `None` once the connection has closed.
  ///
  /// This is the connection's pump: queued writes from the
  /// [`WriteHalf`], pong echoes, keepalive pings, and the close handshake
  /// all progress inside it.
  pub async fn next(&mut self) -> Option<Result<Message, Error>> {
    next_message(&self.inner, &self.doorbell).await
  }

  /// How the connection ended, once `next()` has returned `None`.
  pub fn closed(&self) -> Option<Closed> {
    self.inner.borrow().closed
  }
}

impl<Ro, S> Drop for ReadHalf<Ro, S> {
  fn drop(&mut self) {
    let mut inner = self.inner.borrow_mut();
    inner.read_half_alive = false;
    // Nothing will ever pump these; fail the waiting senders loudly.
    while let Some(frame) = inner.outbound.pop_front() {
      frame.state.set(FrameState::Orphaned);
    }
    // A cancelled pump may have parked an in-progress batch with senders
    // still waiting on it; orphan those too.
    if let Some(pending) = inner.pending_write.take() {
      for state in &pending.states {
        state.set(FrameState::Orphaned);
      }
    }
    drop(inner);
    self.doorbell.notify(usize::MAX);
  }
}

impl<Ro: role::Role, S: crate::into_duplex::Duplex> WriteHalf<Ro, S> {
  /// Sends a whole data message (pumped by the read half).
  pub async fn send(&mut self, message: Message) -> Result<(), Error> {
    match &message {
      Message::Text(text) => self.send_text(text.as_ref()).await,
      Message::Binary(data) => self.send_binary(data.as_ref()).await,
    }
  }

  /// Sends a whole text message (pumped by the read half).
  pub async fn send_text(&mut self, text: &str) -> Result<(), Error> {
    let frame = encode_with(&self.inner, text.len(), |conn, out| {
      conn.encode_text(text, out)
    })?;
    self.enqueue(frame).await
  }

  /// Sends a whole binary message (pumped by the read half).
  pub async fn send_binary(&mut self, data: &[u8]) -> Result<(), Error> {
    let frame = encode_with(&self.inner, data.len(), |conn, out| {
      conn.encode_binary(data, out)
    })?;
    self.enqueue(frame).await
  }

  /// Sends a Ping (pumped by the read half).
  pub async fn ping(&mut self, payload: &[u8]) -> Result<(), Error> {
    let frame = encode_with(&self.inner, payload.len(), |conn, out| {
      conn.encode_ping(payload, out)
    })?;
    self.enqueue(frame).await
  }

  /// Starts the close handshake and resolves once the Close frame is on
  /// the wire. The [`ReadHalf`] drives the handshake to completion —
  /// its `next()` returns `None` and its `closed()` carries the outcome.
  pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
    {
      let mut inner = self.inner.borrow_mut();
      if let Some(kind) = inner.poisoned {
        return Err(Error::Io(kind.into()));
      }
      if inner.closed.is_some() {
        return Err(Error::Closed);
      }
      inner.conn.close(code, reason)?;
    }
    // Empty marker frame: the pump coalesces the queue and the protocol
    // transmits into one write, so its `Written` transition means the write
    // that also carried the Close frame reached the wire.
    self.enqueue(Vec::new()).await
  }

  async fn enqueue(&self, frame: Vec<u8>) -> Result<(), Error> {
    let state = Rc::new(Cell::new(FrameState::Queued));
    {
      let mut inner = self.inner.borrow_mut();
      if let Some(kind) = inner.poisoned {
        return Err(Error::Io(kind.into()));
      }
      if !inner.read_half_alive {
        return Err(Error::ReadHalfGone);
      }
      inner.outbound.push_back(OutboundFrame {
        bytes: frame,
        state: state.clone(),
      });
    }
    self.doorbell.notify(usize::MAX);
    loop {
      match state.get() {
        FrameState::Queued => {}
        FrameState::Written => return Ok(()),
        FrameState::Failed(kind) => return Err(Error::Io(kind.into())),
        FrameState::Orphaned => return Err(Error::ReadHalfGone),
      }
      let listener = self.doorbell.listen();
      if state.get() != FrameState::Queued {
        continue;
      }
      listener.await;
    }
  }
}
