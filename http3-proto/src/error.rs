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
  /// `H3_SETTINGS_ERROR` (0x0109).
  #[display("H3_SETTINGS_ERROR")]
  SettingsError,
  /// `H3_MISSING_SETTINGS` (0x010a).
  #[display("H3_MISSING_SETTINGS")]
  MissingSettings,
  /// `H3_STREAM_CREATION_ERROR` (0x0103).
  #[display("H3_STREAM_CREATION_ERROR")]
  StreamCreation,
  /// `QPACK_DECOMPRESSION_FAILED` (0x0200).
  #[display("QPACK_DECOMPRESSION_FAILED")]
  QpackDecompressionFailed,
}

impl H3Error {
  /// The wire error code (RFC 9114 §8.1 / RFC 9204 §6).
  #[inline(always)]
  pub const fn code(self) -> u64 {
    match self {
      Self::GeneralProtocol => 0x0101,
      Self::FrameUnexpected => 0x0105,
      Self::FrameError => 0x0106,
      Self::SettingsError => 0x0109,
      Self::MissingSettings => 0x010a,
      Self::StreamCreation => 0x0103,
      Self::QpackDecompressionFailed => 0x0200,
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
    assert_eq!(H3Error::QpackDecompressionFailed.code(), 0x0200);
  }
}
