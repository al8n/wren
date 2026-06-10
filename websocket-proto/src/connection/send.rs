//! The send path: zero-copy frame encoding into caller-supplied buffers.
//!
//! Task 4 fills in the application encoders and `poll_transmit`; this unit
//! lands only the state the receive machine needs to queue close echoes.

use crate::{
  constants::MAX_CONTROL_PAYLOAD,
  frame::{CloseCode, encode_close_payload},
};

/// Outbound fragmentation state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)] // consumed by Task 4's encoders
pub(crate) enum SendMessageState {
  /// Between messages.
  Idle,
  /// Inside a message.
  InMessage,
}

#[derive(Debug)]
pub(crate) struct SendState {
  #[allow(dead_code)] // consumed by Task 4's encoders
  pub(crate) message: SendMessageState,
  /// Close frame queued by the protocol or the application.
  pub(crate) pending_close: Option<([u8; MAX_CONTROL_PAYLOAD], u8)>,
  #[allow(dead_code)] // drained by Task 4's poll_transmit
  pub(crate) close_sent: bool,
}

impl SendState {
  pub(crate) const fn new() -> Self {
    Self {
      message: SendMessageState::Idle,
      pending_close: None,
      close_sent: false,
    }
  }

  /// Queues a close frame payload (best effort; oversized reasons are
  /// truncated at a char boundary by the caller before queueing). The first
  /// queued close wins — a later one (e.g. an echo after we already sent our
  /// own close) is dropped.
  pub(crate) fn queue_close(&mut self, code: CloseCode, reason: &str) {
    let mut buf = [0u8; MAX_CONTROL_PAYLOAD];
    let len = match encode_close_payload(code, reason, &mut buf) {
      Ok(n) => n,
      Err(_) => encode_close_payload(code, "", &mut buf).unwrap_or_default(),
    };
    if self.pending_close.is_none() {
      self.pending_close = Some((buf, u8::try_from(len).unwrap_or(0)));
    }
  }
}
