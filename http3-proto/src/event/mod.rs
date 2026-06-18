//! The driver-facing vocabulary: stream identity, transmit intents, and events.

use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

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
#[derive(Debug, Copy, Clone, Eq, PartialEq, IsVariant, Display)]
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

/// The number of distinct [`StreamRole`] variants (the bound for role-indexed
/// fixed arrays in the connection).
pub(crate) const ROLE_COUNT: usize = 7;

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

  /// A dense `0..ROLE_COUNT` index for this role, for indexing a fixed array.
  #[inline(always)]
  pub(crate) const fn index(self) -> usize {
    match self {
      Self::ControlOut => 0,
      Self::ControlIn => 1,
      Self::QpackEncOut => 2,
      Self::QpackEncIn => 3,
      Self::QpackDecOut => 4,
      Self::QpackDecIn => 5,
      Self::Request => 6,
    }
  }
}

/// What kind of stream a [`Transmit`] targets — so the driver knows the quinn call.
#[derive(Debug, Copy, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum StreamKind {
  /// An existing stream (already opened + provided).
  Existing(StreamId),
  /// Open a new unidirectional stream for this role, then write.
  OpenUni(StreamRole),
  /// Open the bidirectional request stream, then write.
  OpenRequest,
  /// Abort the existing request stream `id` with QUIC `RESET_STREAM` carrying
  /// application error `code` — NOT "write bytes". A [`Transmit`] with this kind
  /// has empty [`bytes`](Transmit::bytes) and a `false` [`fin`](Transmit::fin); the
  /// driver issues `reset_stream(id, code)` on the QUIC stream instead of `write`.
  /// Emitted for a stream-scoped HTTP/3 error (a malformed message on a general
  /// request stream, or the capacity backstop with
  /// [`H3Error`](crate::error::H3Error)`::RequestRejected`), which resets just that
  /// stream while the connection and every other stream stay live — unlike a
  /// connection-fatal error, which surfaces an [`Event::ConnError`] and closes the
  /// whole connection.
  // `Unwrap`/`TryUnwrap` cannot generate an accessor for a struct-like (anonymous
  // record) variant, so skip it for those two derives; `IsVariant` still yields
  // `is_reset_stream`, and callers destructure the fields via a `match` / `if let`.
  #[unwrap(ignore)]
  #[try_unwrap(ignore)]
  ResetStream {
    /// The request stream to abort.
    id: StreamId,
    /// The QUIC application error code to reset it with (an [`H3Error`] code).
    ///
    /// [`H3Error`]: crate::error::H3Error
    code: u64,
  },
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
///
/// Stream opening is *not* signalled here: the core asks the driver to open a
/// stream via a [`Transmit`] whose [`StreamKind`] is
/// [`OpenUni`](StreamKind::OpenUni) / [`OpenRequest`](StreamKind::OpenRequest),
/// drained from `Connection::poll_transmit`. Events carry lifecycle signals only.
#[derive(Debug, Copy, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum Event {
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
