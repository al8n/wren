//! Driver error types. Proto-layer errors are wrapped as typed variants so
//! callers can dispatch on the cause.

use websocket_proto::{
  connection::{EncodeError, HandleError},
  handshake::h1::{ClientHandshakeError, ServerHandshakeError},
  message::AssembleError,
};

/// Errors establishing a client connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
  /// The URL was not `ws://` or `wss://` (or was `wss://` without the
  /// `tls` feature compiled in).
  #[error("unsupported url scheme (expected ws:// or wss://)")]
  UnsupportedScheme,

  /// The URL failed structural splitting.
  #[error("invalid url: {0}")]
  InvalidUrl(&'static str),

  /// Transport-level failure (TCP connect, read, write, TLS).
  #[error("io: {0}")]
  Io(#[from] std::io::Error),

  /// The opening handshake failed (request build or response validation).
  #[error("handshake: {0}")]
  Handshake(#[from] ClientHandshakeError),

  /// The server answered with a non-101 status.
  #[error("server rejected the upgrade with status {status}")]
  Rejected {
    /// The HTTP status the server answered with.
    status: u16,
  },
}

/// Errors accepting a server connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AcceptError {
  /// Transport-level failure.
  #[error("io: {0}")]
  Io(#[from] std::io::Error),

  /// The request was not a valid WebSocket upgrade.
  #[error("handshake: {0}")]
  Handshake(#[from] ServerHandshakeError),
}

/// Errors on an established connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
  /// Transport-level failure.
  #[error("io: {0}")]
  Io(#[from] std::io::Error),

  /// Encoding an outbound frame failed.
  #[error("encode: {0}")]
  Encode(#[from] EncodeError),

  /// Feeding inbound bytes failed (use after the terminal state).
  #[error("handle: {0}")]
  Handle(#[from] HandleError),

  /// Assembling an inbound message failed (oversize, sequencing).
  #[error("assemble: {0}")]
  Assemble(#[from] AssembleError),

  /// The connection is closed; no further sends are possible.
  #[error("connection closed")]
  Closed,

  /// The read half was dropped, so queued writes can no longer be pumped.
  #[error("read half dropped; writes can no longer make progress")]
  ReadHalfGone,
}
