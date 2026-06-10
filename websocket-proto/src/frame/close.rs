//! Close status codes (RFC 6455 §7.4 + the IANA registry) and the close
//! frame payload format (§5.5.1).

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
}
