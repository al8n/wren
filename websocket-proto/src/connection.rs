//! The transport-blind WebSocket connection state machine (RFC 6455 §5–§8).
//!
//! One [`Connection`] serves any reliable byte stream — an HTTP/1.1-upgraded
//! TCP socket, an HTTP/2 stream (RFC 8441), or an HTTP/3 stream (RFC 9220) —
//! because those transports change only the opening handshake. Construct it
//! from the handshake's [`Negotiated`](crate::negotiation::Negotiated) plus a
//! [`ConnectionConfig`] and a [`role::Role`](crate::connection::role::Role) value.
//!
//! Receive: feed transport bytes to [`Connection::handle`]; payloads are
//! unmasked **in place** and surfaced as borrowed chunk events — internal
//! state is O(1) in message size. Send: the `encode_*` methods serialize
//! straight into your buffer (clients mask on the copy with a fresh key per
//! frame); only protocol-generated frames (pong echoes, close) are queued
//! internally and drained via [`Connection::poll_transmit`].
//!
//! Protocol violations are not `Err`s: the machine queues the prescribed
//! close frame, becomes terminal, and yields a final
//! `Closed` event with `clean == false`; keep draining
//! [`Connection::poll_transmit`] and then drop the transport.

mod events;
mod recv;
pub mod role;
mod send;

pub use events::{
  CloseReceived, Closed, ControlPayload, Event, MessageKind, MessageStart, TextChunk,
};
pub use recv::{Events, HandleError};
pub use send::{EncodeError, FragmentKind};

use crate::{negotiation::Negotiated, time::Instant};
use role::Role;

/// Connection limits and behavior knobs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
  max_frame_payload: u64,
  max_message_size: u64,
}

impl Default for ConnectionConfig {
  fn default() -> Self {
    Self {
      max_frame_payload: 16 * 1024 * 1024,
      max_message_size: 64 * 1024 * 1024,
    }
  }
}

impl ConnectionConfig {
  /// The defaults: 16 MiB frames, 64 MiB messages.
  pub fn new() -> Self {
    Self::default()
  }

  /// Caps a single frame's payload length (exceeding ⇒ close 1009).
  #[must_use]
  pub const fn with_max_frame_payload(mut self, max: u64) -> Self {
    self.max_frame_payload = max;
    self
  }

  /// Caps a whole message's accumulated size (exceeding ⇒ close 1009).
  #[must_use]
  pub const fn with_max_message_size(mut self, max: u64) -> Self {
    self.max_message_size = max;
    self
  }

  /// The frame-payload cap.
  #[inline(always)]
  pub const fn max_frame_payload(&self) -> u64 {
    self.max_frame_payload
  }

  /// The message-size cap.
  #[inline(always)]
  pub const fn max_message_size(&self) -> u64 {
    self.max_message_size
  }
}

/// The WebSocket connection state machine. `I` is the caller's monotonic
/// clock; `Ro` is the [`role`] (client or server), fixed at the type level.
#[derive(Debug)]
pub struct Connection<I, Ro> {
  pub(crate) role: Ro,
  pub(crate) config: ConnectionConfig,
  #[cfg(feature = "deflate")]
  pub(crate) deflate: Option<crate::negotiation::DeflateParams>,
  pub(crate) recv: recv::RecvState,
  pub(crate) send: send::SendState,
  pub(crate) lifecycle: Lifecycle,
  pub(crate) _clock: core::marker::PhantomData<I>,
}

/// Connection lifecycle (close handshake per RFC 6455 §7).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Lifecycle {
  /// Open for data both ways.
  Open,
  /// We sent (queued) a close; awaiting the peer's echo.
  CloseSent,
  /// Peer's close received (echo queued); inbound is drained/discarded.
  PeerClosed,
  /// Terminal: close exchange finished or the connection failed.
  Terminal,
}

impl<I, Ro> Connection<I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// Builds a connection from a completed handshake. `now` seeds the
  /// (plan 4b) timers; it is accepted today so the signature is stable.
  pub fn new(negotiated: &Negotiated, config: ConnectionConfig, role: Ro, now: I) -> Self {
    let _ = (now, negotiated);
    Self {
      role,
      config,
      #[cfg(feature = "deflate")]
      deflate: negotiated.deflate(),
      recv: recv::RecvState::new(),
      send: send::SendState::new(),
      lifecycle: Lifecycle::Open,
      _clock: core::marker::PhantomData,
    }
  }

  /// True once the connection is terminal (cleanly closed or failed):
  /// `handle` refuses further input and the transport can be dropped after
  /// a final [`poll_transmit`](Connection::poll_transmit) drain.
  pub const fn is_terminal(&self) -> bool {
    matches!(self.lifecycle, Lifecycle::Terminal)
  }
}

#[cfg(all(test, feature = "std"))]
pub(crate) mod tests {
  use super::{
    Connection, ConnectionConfig,
    role::{Client, Role, Server},
  };
  use crate::{negotiation::Negotiated, time::testing::TestInstant};

  /// Deterministic RngCore: fills with a repeating counter.
  pub(crate) struct CountingRng(pub(crate) u8);

  impl rand_core::TryRng for CountingRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
      let mut b = [0u8; 4];
      self.try_fill_bytes(&mut b)?;
      Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
      let mut b = [0u8; 8];
      self.try_fill_bytes(&mut b)?;
      Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
      for d in dest {
        *d = self.0;
        self.0 = self.0.wrapping_add(1);
      }
      Ok(())
    }
  }

  #[test]
  fn roles_declare_masking_direction() {
    const { assert!(!<Client<CountingRng> as Role>::EXPECT_MASKED_INBOUND) };
    const { assert!(<Server as Role>::EXPECT_MASKED_INBOUND) };

    let mut client = Client::new(CountingRng(0));
    assert_eq!(client.next_mask(), Some([0, 1, 2, 3]));
    assert_eq!(client.next_mask(), Some([4, 5, 6, 7]));
    assert_eq!(Server::new().next_mask(), None);
  }

  #[test]
  fn config_builders_and_defaults() {
    let c = ConnectionConfig::default();
    assert_eq!(c.max_frame_payload(), 16 * 1024 * 1024);
    assert_eq!(c.max_message_size(), 64 * 1024 * 1024);
    let c = ConnectionConfig::new()
      .with_max_frame_payload(10)
      .with_max_message_size(20);
    assert_eq!(c.max_frame_payload(), 10);
    assert_eq!(c.max_message_size(), 20);
  }

  #[test]
  fn connection_constructs_from_negotiated() {
    let conn: Connection<TestInstant, Server> = Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    );
    assert!(!conn.is_terminal());
  }
}
