//! Close status codes (RFC 6455 §7.4 + the IANA registry) and the close
//! frame payload format (§5.5.1).

use crate::{constants::MAX_CONTROL_PAYLOAD, error::BufferTooSmallDetail};
use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// A close status code. All `u16` values are representable; named variants
/// cover the RFC 6455 §7.4.1 / IANA-registered codes, and [`CloseCode::Other`]
/// carries everything else losslessly (including the application range
/// 3000–4999).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Display, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum CloseCode {
  /// 1000 — normal closure.
  Normal,
  /// 1001 — endpoint going away.
  GoingAway,
  /// 1002 — protocol error.
  ProtocolError,
  /// 1003 — unsupported data type.
  UnsupportedData,
  /// 1005 — reserved: no status code present (never sent on the wire).
  NoStatusReceived,
  /// 1006 — reserved: abnormal closure (never sent on the wire).
  AbnormalClosure,
  /// 1007 — invalid frame payload data (e.g. non-UTF-8 text).
  InvalidFramePayload,
  /// 1008 — policy violation.
  PolicyViolation,
  /// 1009 — message too big.
  MessageTooBig,
  /// 1010 — client expected the server to negotiate a mandatory extension.
  MandatoryExtension,
  /// 1011 — server encountered an internal error.
  InternalError,
  /// 1012 — service restart (IANA-registered).
  ServiceRestart,
  /// 1013 — try again later (IANA-registered).
  TryAgainLater,
  /// 1014 — bad gateway (IANA-registered).
  BadGateway,
  /// 1015 — reserved: TLS handshake failure (never sent on the wire).
  TlsHandshake,
  /// Any other code, kept losslessly (3000–4999 are legitimate
  /// application/registered codes; the rest are invalid on the wire).
  Other(u16),
}

impl CloseCode {
  /// Total decoder: every `u16` maps to a code and round-trips through
  /// [`CloseCode::as_u16`].
  pub const fn from_u16(raw: u16) -> Self {
    match raw {
      1000 => Self::Normal,
      1001 => Self::GoingAway,
      1002 => Self::ProtocolError,
      1003 => Self::UnsupportedData,
      1005 => Self::NoStatusReceived,
      1006 => Self::AbnormalClosure,
      1007 => Self::InvalidFramePayload,
      1008 => Self::PolicyViolation,
      1009 => Self::MessageTooBig,
      1010 => Self::MandatoryExtension,
      1011 => Self::InternalError,
      1012 => Self::ServiceRestart,
      1013 => Self::TryAgainLater,
      1014 => Self::BadGateway,
      1015 => Self::TlsHandshake,
      other => Self::Other(other),
    }
  }

  /// The numeric status code.
  pub const fn as_u16(&self) -> u16 {
    match self {
      Self::Normal => 1000,
      Self::GoingAway => 1001,
      Self::ProtocolError => 1002,
      Self::UnsupportedData => 1003,
      Self::NoStatusReceived => 1005,
      Self::AbnormalClosure => 1006,
      Self::InvalidFramePayload => 1007,
      Self::PolicyViolation => 1008,
      Self::MessageTooBig => 1009,
      Self::MandatoryExtension => 1010,
      Self::InternalError => 1011,
      Self::ServiceRestart => 1012,
      Self::TryAgainLater => 1013,
      Self::BadGateway => 1014,
      Self::TlsHandshake => 1015,
      Self::Other(raw) => *raw,
    }
  }

  /// Whether this code may legitimately appear in a close frame on the
  /// wire: 1000–1003, 1007–1014, and 3000–4999 (RFC 6455 §7.4 + the IANA
  /// registry — the table Autobahn case 7.9 enforces). The reserved
  /// signalling codes (1004, 1005, 1006, 1015) and everything outside the
  /// defined ranges are not.
  pub const fn is_valid_on_wire(&self) -> bool {
    matches!(self.as_u16(), 1000..=1003 | 1007..=1014 | 3000..=4999)
  }

  /// Stable lowercase name for logs and diagnostics.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Normal => "normal",
      Self::GoingAway => "going away",
      Self::ProtocolError => "protocol error",
      Self::UnsupportedData => "unsupported data",
      Self::NoStatusReceived => "no status received",
      Self::AbnormalClosure => "abnormal closure",
      Self::InvalidFramePayload => "invalid frame payload",
      Self::PolicyViolation => "policy violation",
      Self::MessageTooBig => "message too big",
      Self::MandatoryExtension => "mandatory extension",
      Self::InternalError => "internal error",
      Self::ServiceRestart => "service restart",
      Self::TryAgainLater => "try again later",
      Self::BadGateway => "bad gateway",
      Self::TlsHandshake => "tls handshake",
      Self::Other(_) => "other",
    }
  }
}

/// Errors decoding or encoding a close-frame payload (§5.5.1).
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ClosePayloadError {
  /// The body was exactly one byte; a status code needs two (§5.5.1).
  #[error("close payload is 1 byte; a status code needs 2")]
  TruncatedCode,

  /// The reason text after the status code was not valid UTF-8.
  #[error("close reason is not valid UTF-8")]
  InvalidReasonUtf8,

  /// The reason would push the control payload past 125 bytes; the value
  /// is the maximum reason length (123).
  #[error("close reason too long: at most {0} bytes fit a control frame")]
  ReasonTooLong(usize),

  /// The output buffer cannot hold the encoded payload.
  #[error("{0}")]
  BufferTooSmall(BufferTooSmallDetail),
}

/// A decoded close payload, borrowing the reason from the input.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DecodedClose<'a> {
  code: CloseCode,
  reason: &'a str,
}

impl<'a> DecodedClose<'a> {
  /// The status code (synthetic [`CloseCode::NoStatusReceived`] when the
  /// body was empty).
  #[inline(always)]
  pub const fn code(&self) -> CloseCode {
    self.code
  }

  /// The UTF-8 close reason (empty when absent).
  #[inline(always)]
  pub const fn reason(&self) -> &'a str {
    self.reason
  }
}

/// Decodes a close-frame body (§5.5.1): empty ⇒ no status code; otherwise a
/// two-byte big-endian code followed by an optional UTF-8 reason. The code's
/// wire-validity is NOT policed here (the connection does that) — but the
/// structure (length, UTF-8) is.
pub fn decode_close_payload(payload: &[u8]) -> Result<DecodedClose<'_>, ClosePayloadError> {
  match payload {
    [] => Ok(DecodedClose {
      code: CloseCode::NoStatusReceived,
      reason: "",
    }),
    [_] => Err(ClosePayloadError::TruncatedCode),
    [hi, lo, reason @ ..] => {
      let code = CloseCode::from_u16(u16::from_be_bytes([*hi, *lo]));
      let reason =
        core::str::from_utf8(reason).map_err(|_| ClosePayloadError::InvalidReasonUtf8)?;
      Ok(DecodedClose { code, reason })
    }
  }
}

/// Encodes a close-frame body: the two-byte big-endian code followed by the
/// reason. The result must fit a control frame (≤ 125 bytes), capping the
/// reason at 123 bytes.
///
/// Like [`decode_close_payload`], the code's wire-validity is NOT policed
/// here — callers check [`CloseCode::is_valid_on_wire`] before sending.
pub fn encode_close_payload(
  code: CloseCode,
  reason: &str,
  out: &mut [u8],
) -> Result<usize, ClosePayloadError> {
  let reason_max = MAX_CONTROL_PAYLOAD.saturating_sub(2);
  if reason.len() > reason_max {
    return Err(ClosePayloadError::ReasonTooLong(reason_max));
  }
  let needed = reason.len().saturating_add(2);
  let Some(out) = out.get_mut(..needed) else {
    return Err(ClosePayloadError::BufferTooSmall(
      BufferTooSmallDetail::new(needed, out.len()),
    ));
  };
  let [hi, lo, rest @ ..] = out else {
    return Err(ClosePayloadError::BufferTooSmall(
      BufferTooSmallDetail::new(needed, 0),
    ));
  };
  let [code_hi, code_lo] = code.as_u16().to_be_bytes();
  *hi = code_hi;
  *lo = code_lo;
  // `rest.len() == reason.len()` by construction; zip is the statically
  // panic-free spelling (`copy_from_slice` would panic on a mismatch).
  for (dst, src) in rest.iter_mut().zip(reason.as_bytes()) {
    *dst = *src;
  }
  Ok(needed)
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  #[test]
  fn named_codes_round_trip() {
    let table: &[(u16, CloseCode)] = &[
      (1000, CloseCode::Normal),
      (1001, CloseCode::GoingAway),
      (1002, CloseCode::ProtocolError),
      (1003, CloseCode::UnsupportedData),
      (1005, CloseCode::NoStatusReceived),
      (1006, CloseCode::AbnormalClosure),
      (1007, CloseCode::InvalidFramePayload),
      (1008, CloseCode::PolicyViolation),
      (1009, CloseCode::MessageTooBig),
      (1010, CloseCode::MandatoryExtension),
      (1011, CloseCode::InternalError),
      (1012, CloseCode::ServiceRestart),
      (1013, CloseCode::TryAgainLater),
      (1014, CloseCode::BadGateway),
      (1015, CloseCode::TlsHandshake),
    ];
    for &(raw, code) in table {
      assert_eq!(CloseCode::from_u16(raw), code);
      assert_eq!(code.as_u16(), raw);
    }
    assert_eq!(CloseCode::from_u16(3000), CloseCode::Other(3000));
    assert_eq!(CloseCode::Other(4321).as_u16(), 4321);
  }

  #[test]
  fn every_u16_round_trips() {
    for raw in 0u16..=u16::MAX {
      assert_eq!(CloseCode::from_u16(raw).as_u16(), raw);
    }
  }

  #[test]
  fn wire_validity_matches_rfc7_4_and_iana() {
    // Valid on the wire: 1000–1003, 1007–1014, 3000–4999 (Autobahn 7.9).
    let valid: &[u16] = &[
      1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000,
      4999,
    ];
    for &raw in valid {
      assert!(CloseCode::from_u16(raw).is_valid_on_wire(), "{raw}");
    }
    // Invalid on the wire: everything else — including the reserved
    // signalling codes 1005/1006/1015 and the unassigned 1004.
    let invalid: &[u16] = &[
      0,
      1,
      999,
      1004,
      1005,
      1006,
      1015,
      1016,
      1099,
      1100,
      2000,
      2999,
      5000,
      u16::MAX,
    ];
    for &raw in invalid {
      assert!(!CloseCode::from_u16(raw).is_valid_on_wire(), "{raw}");
    }
  }

  #[test]
  fn as_str_and_display() {
    assert_eq!(CloseCode::Normal.as_str(), "normal");
    assert_eq!(CloseCode::ProtocolError.as_str(), "protocol error");
    assert_eq!(CloseCode::Other(4000).as_str(), "other");
    assert_eq!(CloseCode::MessageTooBig.to_string(), "message too big");
  }

  #[test]
  fn close_payload_decode_per_5_5_1() {
    // Empty payload — no code on the wire — maps to NoStatusReceived.
    let d = decode_close_payload(b"").unwrap();
    assert_eq!(d.code(), CloseCode::NoStatusReceived);
    assert_eq!(d.reason(), "");

    // Code only.
    let d = decode_close_payload(&[0x03, 0xE8]).unwrap();
    assert_eq!(d.code(), CloseCode::Normal);
    assert_eq!(d.reason(), "");

    // Code + UTF-8 reason.
    let mut payload = vec![0x03, 0xE9];
    payload.extend_from_slice("going héme".as_bytes());
    let d = decode_close_payload(&payload).unwrap();
    assert_eq!(d.code(), CloseCode::GoingAway);
    assert_eq!(d.reason(), "going héme");

    // One-byte payload is malformed (§5.5.1: if there is a body, the first
    // two bytes MUST be the status code).
    let err = decode_close_payload(&[0x03]).unwrap_err();
    assert!(matches!(err, ClosePayloadError::TruncatedCode));

    // Invalid UTF-8 in the reason is malformed.
    let err = decode_close_payload(&[0x03, 0xE8, 0xFF, 0xFE]).unwrap_err();
    assert!(matches!(err, ClosePayloadError::InvalidReasonUtf8));

    // The code itself is decoded losslessly even when not wire-valid;
    // policing is the connection's job.
    let d = decode_close_payload(&[0x03, 0xED]).unwrap(); // 1005
    assert_eq!(d.code(), CloseCode::NoStatusReceived);
    assert!(!d.code().is_valid_on_wire());
  }

  #[test]
  fn close_payload_encode_per_5_5_1() {
    let mut buf = [0u8; 125];

    let n = encode_close_payload(CloseCode::Normal, "", &mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x03, 0xE8]);

    let n = encode_close_payload(CloseCode::GoingAway, "bye", &mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x03, 0xE9, b'b', b'y', b'e']);

    // Round-trip.
    let d = decode_close_payload(&buf[..n]).unwrap();
    assert_eq!(d.code(), CloseCode::GoingAway);
    assert_eq!(d.reason(), "bye");

    // Reason too long for the 125-byte control limit (2 + 124 > 125).
    let long = "x".repeat(124);
    let err = encode_close_payload(CloseCode::Normal, &long, &mut buf).unwrap_err();
    assert!(matches!(err, ClosePayloadError::ReasonTooLong(_)));

    // Output buffer too small.
    let mut tiny = [0u8; 3];
    let err = encode_close_payload(CloseCode::Normal, "abc", &mut tiny).unwrap_err();
    assert!(matches!(err, ClosePayloadError::BufferTooSmall(_)));

    // 123-byte reason is the maximum and fits exactly.
    let max = "y".repeat(123);
    let n = encode_close_payload(CloseCode::Normal, &max, &mut buf).unwrap();
    assert_eq!(n, 125);
  }
}
