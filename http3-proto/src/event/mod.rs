//! The driver-facing vocabulary: stream identity, transmit intents, and events.

/// The driver's opaque identifier for a QUIC stream (the core never mints these).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct StreamId(u64);

impl StreamId {
  /// Wraps a driver-assigned stream id.
  #[inline(always)]
  pub const fn new(id: u64) -> Self {
    Self(id)
  }

  /// The underlying id.
  #[inline(always)]
  pub const fn get(self) -> u64 {
    self.0
  }
}

/// The role a tracked stream plays in the connection (a fixed, bounded set).
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::IsVariant, derive_more::Display)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum StreamRole {
  /// Our outbound control stream (carries our SETTINGS).
  ControlOut,
  /// The peer's control stream (carries its SETTINGS).
  ControlIn,
  /// Our QPACK encoder stream (idle; dynamic table disabled).
  QpackEncOut,
  /// The peer's QPACK encoder stream.
  QpackEncIn,
  /// Our QPACK decoder stream (idle).
  QpackDecOut,
  /// The peer's QPACK decoder stream.
  QpackDecIn,
  /// The bidirectional request stream carrying the CONNECT + DATA tunnel.
  Request,
}

impl StreamRole {
  /// A stable, snake_case name for the role (logging / diagnostics).
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::ControlOut => "control_out",
      Self::ControlIn => "control_in",
      Self::QpackEncOut => "qpack_enc_out",
      Self::QpackEncIn => "qpack_enc_in",
      Self::QpackDecOut => "qpack_dec_out",
      Self::QpackDecIn => "qpack_dec_in",
      Self::Request => "request",
    }
  }
}

/// What kind of stream a [`Transmit`] targets — so the driver knows the quinn call.
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::IsVariant)]
#[non_exhaustive]
pub enum StreamKind {
  /// An existing stream (already opened + provided).
  Existing(StreamId),
  /// Open a new unidirectional stream for this role, then write.
  OpenUni(StreamRole),
  /// Open the bidirectional request stream, then write.
  OpenRequest,
}

/// Bytes the driver must write on a stream (and whether to FIN afterwards).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Transmit<'a> {
  kind: StreamKind,
  bytes: &'a [u8],
  fin: bool,
}

impl<'a> Transmit<'a> {
  /// Construct a transmit intent.
  #[inline(always)]
  pub const fn new(kind: StreamKind, bytes: &'a [u8], fin: bool) -> Self {
    Self { kind, bytes, fin }
  }

  /// Which stream to write on / open.
  #[inline(always)]
  pub const fn kind(&self) -> StreamKind {
    self.kind
  }

  /// The bytes to write.
  #[inline(always)]
  pub const fn bytes(&self) -> &'a [u8] {
    self.bytes
  }

  /// Whether to FIN the stream after writing.
  #[inline(always)]
  pub const fn fin(&self) -> bool {
    self.fin
  }
}

/// An owned connection-level signal, drained via `Connection::poll_event`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::IsVariant)]
#[non_exhaustive]
pub enum Event {
  /// The driver must open a quinn stream for this role, then `provide_stream`.
  StreamNeeded(StreamRole),
  /// The CONNECT exchange completed (2xx sent/seen); the tunnel is open.
  Established,
  /// The request stream's FIN was observed (graceful tunnel end).
  PeerClosed,
  /// The peer reset the request stream with this application error code.
  Reset(u64),
  /// A terminal connection-level HTTP/3 error; the driver closes the connection.
  ConnError(crate::error::H3Error),
}

#[cfg(test)]
mod tests;
