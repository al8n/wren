//! Cross-cutting error building blocks shared by multiple modules, plus the
//! HTTP/3 / QPACK error-code enum a driver uses to close the QUIC connection.

use derive_more::Display;

/// Detail payload: an output buffer was too small for the bytes a call needed.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display("output buffer too small: needed {needed} bytes, had {have}")]
pub struct BufferTooSmallDetail {
  needed: usize,
  have: usize,
}

impl BufferTooSmallDetail {
  /// Creates a detail from the required and available byte counts.
  #[inline(always)]
  pub const fn new(needed: usize, have: usize) -> Self {
    Self { needed, have }
  }

  /// Bytes the call needed to write.
  #[inline(always)]
  pub const fn needed(&self) -> usize {
    self.needed
  }

  /// Bytes the destination had available.
  #[inline(always)]
  pub const fn have(&self) -> usize {
    self.have
  }
}

/// Detail payload: a decode needs more bytes than the input held (the caller
/// should buffer more and retry).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display("truncated input: need at least {needed} more bytes")]
pub struct TruncatedDetail {
  needed: usize,
}

impl TruncatedDetail {
  /// Creates a detail from the minimum number of further bytes required.
  #[inline(always)]
  pub const fn new(needed: usize) -> Self {
    Self { needed }
  }

  /// The minimum number of further bytes required.
  #[inline(always)]
  pub const fn needed(&self) -> usize {
    self.needed
  }
}

/// HTTP/3 (RFC 9114 §8.1) and QPACK (RFC 9204 §6) error codes a driver uses to
/// close the QUIC connection on a protocol violation.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[non_exhaustive]
pub enum H3Error {
  /// `H3_GENERAL_PROTOCOL_ERROR` (0x0101).
  #[display("H3_GENERAL_PROTOCOL_ERROR")]
  GeneralProtocol,
  /// `H3_FRAME_UNEXPECTED` (0x0105).
  #[display("H3_FRAME_UNEXPECTED")]
  FrameUnexpected,
  /// `H3_FRAME_ERROR` (0x0106).
  #[display("H3_FRAME_ERROR")]
  FrameError,
  /// `H3_REQUEST_INCOMPLETE` (0x010d): the request stream terminated before the
  /// mandatory CONNECT HEADERS were received. A peer that FINs the request stream
  /// before sending the CONNECT request / response field section has sent an
  /// incomplete request (RFC 9114 §8.1), so the connection is closed rather than
  /// left waiting for HEADERS that will never arrive.
  #[display("H3_REQUEST_INCOMPLETE")]
  RequestIncomplete,
  /// `H3_MESSAGE_ERROR` (0x010e): a request or response message was malformed
  /// (RFC 9114 §8.1 / §4.1.2). A peer that sends tunnel DATA before the CONNECT
  /// exchange has completed — a client sending DATA before the server's 2xx, or
  /// any DATA on a request stream whose tunnel was never established — has sent a
  /// malformed message (RFC 9114 §4.4 forbids DATA ahead of the 2xx response), so
  /// the connection is closed rather than processing pre-accept tunnel bytes.
  #[display("H3_MESSAGE_ERROR")]
  MessageError,
  /// `H3_SETTINGS_ERROR` (0x0109).
  #[display("H3_SETTINGS_ERROR")]
  SettingsError,
  /// `H3_MISSING_SETTINGS` (0x010a).
  #[display("H3_MISSING_SETTINGS")]
  MissingSettings,
  /// `H3_STREAM_CREATION_ERROR` (0x0103).
  #[display("H3_STREAM_CREATION_ERROR")]
  StreamCreation,
  /// `H3_CLOSED_CRITICAL_STREAM` (0x0104).
  #[display("H3_CLOSED_CRITICAL_STREAM")]
  ClosedCriticalStream,
  /// `H3_ID_ERROR` (0x0108): the peer used a stream id or push id it was not
  /// permitted to. We never enable server push (we never send `MAX_PUSH_ID`, so
  /// the max push id stays 0), so receiving a push unidirectional stream
  /// (type 0x01) is this error.
  #[display("H3_ID_ERROR")]
  IdError,
  /// `H3_EXCESSIVE_LOAD` (0x0107): the peer placed an implausibly large load on a
  /// bounded resource. Two cases: it opened more inbound unidirectional streams
  /// than the bounded tracking table holds (returned instead of silently dropping
  /// a stream, so a flood cannot hide a later critical stream), or it sent a
  /// control-stream SETTINGS frame whose payload exceeds the generous buffer bound
  /// (large enough for many settings plus GREASE).
  #[display("H3_EXCESSIVE_LOAD")]
  ExcessiveLoad,
  /// `QPACK_DECOMPRESSION_FAILED` (0x0200): a field-section decode failed.
  #[display("QPACK_DECOMPRESSION_FAILED")]
  QpackDecompressionFailed,
  /// `QPACK_ENCODER_STREAM_ERROR` (0x0201): an error on the peer's QPACK encoder
  /// stream (RFC 9204 §6). We advertise `QPACK_MAX_TABLE_CAPACITY=0`, so any
  /// encoder-stream instruction the peer sends is a violation.
  #[display("QPACK_ENCODER_STREAM_ERROR")]
  QpackEncoderStreamError,
  /// `QPACK_DECODER_STREAM_ERROR` (0x0202): an error on the peer's QPACK decoder
  /// stream (RFC 9204 §6). We advertise `QPACK_MAX_TABLE_CAPACITY=0`, so any
  /// decoder-stream instruction the peer sends is a violation.
  #[display("QPACK_DECODER_STREAM_ERROR")]
  QpackDecoderStreamError,
}

impl H3Error {
  /// The wire error code (RFC 9114 §8.1 / RFC 9204 §6).
  #[inline(always)]
  pub const fn code(self) -> u64 {
    match self {
      Self::GeneralProtocol => 0x0101,
      Self::FrameUnexpected => 0x0105,
      Self::FrameError => 0x0106,
      Self::RequestIncomplete => 0x010d,
      Self::MessageError => 0x010e,
      Self::SettingsError => 0x0109,
      Self::MissingSettings => 0x010a,
      Self::StreamCreation => 0x0103,
      Self::ClosedCriticalStream => 0x0104,
      Self::ExcessiveLoad => 0x0107,
      Self::IdError => 0x0108,
      Self::QpackDecompressionFailed => 0x0200,
      Self::QpackEncoderStreamError => 0x0201,
      Self::QpackDecoderStreamError => 0x0202,
    }
  }
}

/// Errors from the connection-level driver API (e.g. a send after close).
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
  /// The tunnel is closed; no further payload can be sent.
  #[error("tunnel closed")]
  Closed,
  /// The outbound transmit queue is full; drain it with `poll_transmit` and retry.
  ///
  /// Also returned by `Connection::<Client>::open_with` when the peer's SETTINGS
  /// have not yet been received: pump more inbound bytes (so the peer's control
  /// stream SETTINGS are decoded) and retry.
  #[error("transmit queue full; drain and retry")]
  WouldBlock,
  /// The peer does not support Extended CONNECT (it did not advertise
  /// `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`), so the `:protocol` request must not
  /// be sent (RFC 8441 §3 / RFC 9220). This is a VALID refusal, not a protocol
  /// violation: the HTTP/3 connection stays healthy, but the WebSocket tunnel is
  /// unavailable and the driver should report tunnel-setup failure or fall back.
  #[error("peer does not support Extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL not 1)")]
  ExtendedConnectUnsupported,
  /// The header field section's decoded size exceeds the peer's advertised
  /// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2 / §7.2.4.1): the sum over
  /// every field of its name length + value length + 32 bytes of overhead is over
  /// the limit, so the request/response must not be sent.
  #[error("header field section exceeds the peer's advertised MAX_FIELD_SECTION_SIZE")]
  FieldSectionTooLarge,
  /// A connection-level HTTP/3 protocol violation (terminal).
  #[error("http/3 protocol error: {0}")]
  Protocol(H3Error),
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  #[test]
  fn detail_accessors() {
    let b = BufferTooSmallDetail::new(14, 3);
    assert_eq!((b.needed(), b.have()), (14, 3));
    assert_eq!(
      b.to_string(),
      "output buffer too small: needed 14 bytes, had 3"
    );
    let t = TruncatedDetail::new(7);
    assert_eq!(t.needed(), 7);
    assert_eq!(t.to_string(), "truncated input: need at least 7 more bytes");
  }

  #[test]
  fn h3_error_codes() {
    assert_eq!(H3Error::FrameUnexpected.code(), 0x0105);
    assert_eq!(H3Error::RequestIncomplete.code(), 0x010d);
    assert_eq!(H3Error::MessageError.code(), 0x010e);
    assert_eq!(H3Error::StreamCreation.code(), 0x0103);
    assert_eq!(H3Error::ClosedCriticalStream.code(), 0x0104);
    assert_eq!(H3Error::ExcessiveLoad.code(), 0x0107);
    assert_eq!(H3Error::IdError.code(), 0x0108);
    assert_eq!(H3Error::QpackDecompressionFailed.code(), 0x0200);
    assert_eq!(H3Error::QpackEncoderStreamError.code(), 0x0201);
    assert_eq!(H3Error::QpackDecoderStreamError.code(), 0x0202);
  }

  #[test]
  fn qpack_stream_error_display() {
    assert_eq!(
      H3Error::QpackEncoderStreamError.to_string(),
      "QPACK_ENCODER_STREAM_ERROR"
    );
    assert_eq!(
      H3Error::QpackDecoderStreamError.to_string(),
      "QPACK_DECODER_STREAM_ERROR"
    );
  }

  #[test]
  fn excessive_load_display() {
    assert_eq!(H3Error::ExcessiveLoad.to_string(), "H3_EXCESSIVE_LOAD");
  }

  #[test]
  fn id_error_display() {
    assert_eq!(H3Error::IdError.to_string(), "H3_ID_ERROR");
  }

  #[test]
  fn request_incomplete_display() {
    assert_eq!(
      H3Error::RequestIncomplete.to_string(),
      "H3_REQUEST_INCOMPLETE"
    );
  }

  #[test]
  fn message_error_display() {
    assert_eq!(H3Error::MessageError.to_string(), "H3_MESSAGE_ERROR");
  }
}
