//! Frame opcode (RFC 6455 §5.2) with a lossless escape for reserved values.

use derive_more::{Display, IsVariant, TryUnwrap};

/// A frame opcode. The four-bit wire values 0x3–0x7 and 0xB–0xF are reserved
/// by RFC 6455; they parse losslessly as [`Opcode::Reserved`] and protocol
/// policy (failing the connection with 1002) is applied by the connection
/// state machine, not this codec.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Display, IsVariant, TryUnwrap)]
#[try_unwrap(ref)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum Opcode {
  /// 0x0 — continuation of a fragmented message (§5.4).
  Continuation,
  /// 0x1 — text data frame (UTF-8 payload, §5.6).
  Text,
  /// 0x2 — binary data frame.
  Binary,
  /// 0x8 — connection close (§5.5.1).
  Close,
  /// 0x9 — ping (§5.5.2).
  Ping,
  /// 0xA — pong (§5.5.3).
  Pong,
  /// A reserved opcode (0x3–0x7 data class, 0xB–0xF control class), kept
  /// losslessly. Constructing it with a non-reserved value is inert:
  /// [`Opcode::as_bits`] masks to four bits and round-trips what the wire
  /// carried.
  Reserved(u8),
}

impl Opcode {
  /// Decodes a four-bit opcode field (the argument is masked to its low
  /// four bits, so this is total over `u8`).
  pub const fn from_bits(bits: u8) -> Self {
    match bits & 0x0F {
      0x0 => Self::Continuation,
      0x1 => Self::Text,
      0x2 => Self::Binary,
      0x8 => Self::Close,
      0x9 => Self::Ping,
      0xA => Self::Pong,
      other => Self::Reserved(other),
    }
  }

  /// The four-bit wire value.
  pub const fn as_bits(&self) -> u8 {
    match self {
      Self::Continuation => 0x0,
      Self::Text => 0x1,
      Self::Binary => 0x2,
      Self::Close => 0x8,
      Self::Ping => 0x9,
      Self::Pong => 0xA,
      Self::Reserved(bits) => *bits & 0x0F,
    }
  }

  /// §5.5 — control frames are opcodes 0x8..=0xF, including reserved ones.
  pub const fn is_control(&self) -> bool {
    self.as_bits() & 0x8 != 0
  }

  /// Data-class opcodes 0x0..=0x7, including reserved ones.
  pub const fn is_data(&self) -> bool {
    !self.is_control()
  }

  /// Stable lowercase name for logs and diagnostics.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Continuation => "continuation",
      Self::Text => "text",
      Self::Binary => "binary",
      Self::Close => "close",
      Self::Ping => "ping",
      Self::Pong => "pong",
      Self::Reserved(_) => "reserved",
    }
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  #[test]
  fn round_trips_all_sixteen_bit_patterns() {
    for bits in 0u8..=0x0F {
      let op = Opcode::from_bits(bits);
      assert_eq!(op.as_bits(), bits, "{bits:#x}");
    }
  }

  #[test]
  fn known_opcodes_map_per_rfc6455_5_2() {
    assert_eq!(Opcode::from_bits(0x0), Opcode::Continuation);
    assert_eq!(Opcode::from_bits(0x1), Opcode::Text);
    assert_eq!(Opcode::from_bits(0x2), Opcode::Binary);
    assert_eq!(Opcode::from_bits(0x8), Opcode::Close);
    assert_eq!(Opcode::from_bits(0x9), Opcode::Ping);
    assert_eq!(Opcode::from_bits(0xA), Opcode::Pong);
    for bits in [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
      assert_eq!(Opcode::from_bits(bits), Opcode::Reserved(bits));
    }
  }

  #[test]
  fn control_class_is_the_high_bit() {
    // §5.5: control frames are opcodes 0x8..=0xF — including reserved ones.
    for bits in 0u8..=0x0F {
      let op = Opcode::from_bits(bits);
      assert_eq!(op.is_control(), bits >= 0x8, "{bits:#x}");
      assert_eq!(op.is_data(), bits < 0x8, "{bits:#x}");
    }
  }

  #[test]
  fn reserved_detection_and_helpers() {
    assert!(Opcode::Reserved(0x3).is_reserved());
    assert!(!Opcode::Text.is_reserved());
    assert!(Opcode::Continuation.is_continuation());
    assert_eq!(
      Opcode::Reserved(0xB).try_unwrap_reserved_ref().copied(),
      Ok(0xB)
    );
  }

  #[test]
  fn as_str_and_display() {
    assert_eq!(Opcode::Continuation.as_str(), "continuation");
    assert_eq!(Opcode::Text.as_str(), "text");
    assert_eq!(Opcode::Binary.as_str(), "binary");
    assert_eq!(Opcode::Close.as_str(), "close");
    assert_eq!(Opcode::Ping.as_str(), "ping");
    assert_eq!(Opcode::Pong.as_str(), "pong");
    assert_eq!(Opcode::Reserved(0xB).as_str(), "reserved");
    assert_eq!(Opcode::Text.to_string(), "text");
  }

  #[test]
  fn from_bits_masks_to_four_bits() {
    // The wire field is 4 bits; from_bits is total over u8 by masking.
    assert_eq!(Opcode::from_bits(0xF1), Opcode::Text);
    assert_eq!(Opcode::Reserved(0xFB).as_bits(), 0x0B);
  }
}
