//! Frame header (RFC 6455 §5.2): incremental decode and canonical encode.

use crate::{error::BufferTooSmallDetail, frame::Opcode};
use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// A parsed (or to-be-encoded) frame header. RSV bits and reserved opcodes
/// are carried losslessly; the connection layer applies policy.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct FrameHeader {
  fin: bool,
  rsv1: bool,
  rsv2: bool,
  rsv3: bool,
  opcode: Opcode,
  mask: Option<[u8; 4]>,
  payload_len: u64,
}

impl FrameHeader {
  /// A FIN frame of `opcode` with `payload_len` bytes, no RSV bits, unmasked.
  /// Adjust with the `with_*` builders.
  pub const fn new(opcode: Opcode, payload_len: u64) -> Self {
    Self {
      fin: true,
      rsv1: false,
      rsv2: false,
      rsv3: false,
      opcode,
      mask: None,
      payload_len,
    }
  }

  /// Replaces the FIN flag.
  #[must_use]
  pub const fn with_fin(mut self, fin: bool) -> Self {
    self.fin = fin;
    self
  }

  /// Replaces the RSV1 flag (used by per-message compression).
  #[must_use]
  pub const fn with_rsv1(mut self, rsv1: bool) -> Self {
    self.rsv1 = rsv1;
    self
  }

  /// Replaces the RSV2 flag.
  #[must_use]
  pub const fn with_rsv2(mut self, rsv2: bool) -> Self {
    self.rsv2 = rsv2;
    self
  }

  /// Replaces the RSV3 flag.
  #[must_use]
  pub const fn with_rsv3(mut self, rsv3: bool) -> Self {
    self.rsv3 = rsv3;
    self
  }

  /// Replaces the masking key (`Some` ⇒ the MASK bit is set and the key is
  /// written after the length).
  #[must_use]
  pub const fn with_mask(mut self, mask: Option<[u8; 4]>) -> Self {
    self.mask = mask;
    self
  }

  /// FIN flag (§5.4: final fragment of a message).
  #[inline(always)]
  pub const fn fin(&self) -> bool {
    self.fin
  }

  /// RSV1 flag.
  #[inline(always)]
  pub const fn rsv1(&self) -> bool {
    self.rsv1
  }

  /// RSV2 flag.
  #[inline(always)]
  pub const fn rsv2(&self) -> bool {
    self.rsv2
  }

  /// RSV3 flag.
  #[inline(always)]
  pub const fn rsv3(&self) -> bool {
    self.rsv3
  }

  /// The frame opcode.
  #[inline(always)]
  pub const fn opcode(&self) -> Opcode {
    self.opcode
  }

  /// The masking key, when the MASK bit is set.
  #[inline(always)]
  pub const fn mask(&self) -> Option<[u8; 4]> {
    self.mask
  }

  /// The payload length in bytes.
  #[inline(always)]
  pub const fn payload_len(&self) -> u64 {
    self.payload_len
  }

  /// The encoded header size in bytes (2–14) — exactly what [`encode`]
  /// writes — without encoding. Lengths above the §5.2 maximum still report
  /// the 8-byte form here; [`encode`] is where they fail.
  ///
  /// [`encode`]: FrameHeader::encode
  pub const fn header_len(&self) -> usize {
    let ext: usize = match self.payload_len {
      0..=125 => 0,
      126..=65535 => 2,
      _ => 8,
    };
    let mask: usize = if self.mask.is_some() { 4 } else { 0 };
    2usize.saturating_add(ext).saturating_add(mask)
  }
}

/// Outcome of [`FrameHeader::decode`] on a (possibly partial) buffer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum Decoded {
  /// A full header was parsed.
  Complete(DecodedHeader),
  /// More bytes are required.
  Incomplete(MoreNeeded),
}

/// A complete header plus the number of input bytes it consumed.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DecodedHeader {
  header: FrameHeader,
  consumed: usize,
}

impl DecodedHeader {
  /// The parsed header.
  #[inline(always)]
  pub const fn header(&self) -> FrameHeader {
    self.header
  }

  /// Bytes of input the header occupied; the payload starts here.
  #[inline(always)]
  pub const fn consumed(&self) -> usize {
    self.consumed
  }
}

/// Exact additional byte count needed before the header can complete.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MoreNeeded {
  at_least: usize,
}

impl MoreNeeded {
  /// Additional bytes required (exact once the second byte has arrived;
  /// before that, the fixed-header deficit).
  #[inline(always)]
  pub const fn at_least(&self) -> usize {
    self.at_least
  }
}

/// Detail payload: a length used a longer encoding than required (§5.2
/// demands the minimal form).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display(
  "non-canonical length: {value} encoded in the {used_bytes}-byte form (minimal: {minimal_bytes}-byte)"
)]
pub struct NonCanonicalLengthDetail {
  value: u64,
  used_bytes: u8,
  minimal_bytes: u8,
}

impl NonCanonicalLengthDetail {
  /// Creates the detail.
  #[inline(always)]
  pub const fn new(value: u64, used_bytes: u8, minimal_bytes: u8) -> Self {
    Self {
      value,
      used_bytes,
      minimal_bytes,
    }
  }

  /// The decoded length value.
  #[inline(always)]
  pub const fn value(&self) -> u64 {
    self.value
  }

  /// Bytes the wire encoding used (2 or 8).
  #[inline(always)]
  pub const fn used_bytes(&self) -> u8 {
    self.used_bytes
  }

  /// Bytes the minimal encoding would use (0, 2).
  #[inline(always)]
  pub const fn minimal_bytes(&self) -> u8 {
    self.minimal_bytes
  }
}

/// Errors decoding a frame header.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum DecodeError {
  /// The length was not in its minimal encoding (§5.2).
  // `#[error("{0}")]`, not `transparent`: the detail derives Display only
  // (transparent would require it to implement Error).
  #[error("{0}")]
  NonCanonicalLength(NonCanonicalLengthDetail),

  /// The 64-bit length had its most significant bit set (§5.2 requires 0),
  /// i.e. the value exceeded `i64::MAX`.
  #[error("payload length {0:#x} exceeds the §5.2 maximum (most significant bit must be 0)")]
  PayloadTooLarge(u64),
}

/// Errors encoding a frame header.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum EncodeError {
  /// The output buffer cannot hold the encoded header (it never needs more
  /// than [`MAX_FRAME_HEADER`](crate::constants::MAX_FRAME_HEADER) bytes).
  #[error("{0}")]
  BufferTooSmall(BufferTooSmallDetail),

  /// The payload length exceeds the §5.2 maximum (`i64::MAX`).
  #[error("payload length {0:#x} exceeds the §5.2 maximum (most significant bit must be 0)")]
  PayloadTooLarge(u64),
}

impl FrameHeader {
  /// Encodes the header into `out` in its minimal (canonical) form,
  /// returning the byte count (2–14).
  // `#[inline]`: a tiny per-frame hot path, and inlining lets the `no-panic`
  // link-time test (`tests/no_panic.rs`) prove the body is panic-free at the
  // call site (a non-inlined cross-crate call is opaque to that analysis).
  #[inline]
  pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
    if self.payload_len & 0x8000_0000_0000_0000 != 0 {
      return Err(EncodeError::PayloadTooLarge(self.payload_len));
    }

    let ext_len: usize = match self.payload_len {
      0..=125 => 0,
      126..=65535 => 2,
      _ => 8,
    };
    let mask_len: usize = if self.mask.is_some() { 4 } else { 0 };
    let needed = 2usize.saturating_add(ext_len).saturating_add(mask_len);

    let Some(out) = out.get_mut(..needed) else {
      return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
        needed,
        out.len(),
      )));
    };
    let mut cursor = out.iter_mut();

    let mut write = |byte: u8| -> bool {
      match cursor.next() {
        Some(slot) => {
          *slot = byte;
          true
        }
        None => false,
      }
    };
    let short = |needed: usize| EncodeError::BufferTooSmall(BufferTooSmallDetail::new(needed, 0));

    let b0 = (u8::from(self.fin) << 7)
      | (u8::from(self.rsv1) << 6)
      | (u8::from(self.rsv2) << 5)
      | (u8::from(self.rsv3) << 4)
      | self.opcode.as_bits();
    let mask_bit = if self.mask.is_some() { 0x80u8 } else { 0 };

    if !write(b0) {
      return Err(short(needed));
    }
    match ext_len {
      0 => {
        // payload_len ≤ 125 here, so the cast is lossless.
        let len7 = u8::try_from(self.payload_len).unwrap_or(0);
        if !write(mask_bit | len7) {
          return Err(short(needed));
        }
      }
      2 => {
        if !write(mask_bit | 126) {
          return Err(short(needed));
        }
        // 126..=65535 here, so the cast is lossless.
        let be = u16::try_from(self.payload_len).unwrap_or(0).to_be_bytes();
        for byte in be {
          if !write(byte) {
            return Err(short(needed));
          }
        }
      }
      _ => {
        if !write(mask_bit | 127) {
          return Err(short(needed));
        }
        for byte in self.payload_len.to_be_bytes() {
          if !write(byte) {
            return Err(short(needed));
          }
        }
      }
    }
    if let Some(key) = self.mask {
      for byte in key {
        if !write(byte) {
          return Err(short(needed));
        }
      }
    }
    Ok(needed)
  }
}

impl FrameHeader {
  /// Incrementally decodes a header from the front of `buf`.
  ///
  /// Returns [`Decoded::Incomplete`] with the exact remaining byte count
  /// when `buf` holds only a prefix (exact once byte 1 is present), and
  /// [`Decoded::Complete`] with the header and its size otherwise. Reserved
  /// opcodes and RSV bits parse losslessly; length canonicality is enforced
  /// here because it is wire grammar, not policy.
  ///
  /// A satisfied [`Decoded::Incomplete`] does not guarantee the completing
  /// call returns [`Decoded::Complete`]: grammar errors (non-canonical or
  /// oversized lengths) surface only once the bytes that prove them arrive.
  // `#[inline]`: see [`FrameHeader::encode`] — hot per-frame path, and inlining
  // lets the `no-panic` link test prove panic-freedom at the call site.
  #[inline]
  pub fn decode(buf: &[u8]) -> Result<Decoded, DecodeError> {
    let (&b0, &b1) = match (buf.first(), buf.get(1)) {
      (None, _) => return Ok(Decoded::Incomplete(MoreNeeded { at_least: 2 })),
      (Some(_), None) => return Ok(Decoded::Incomplete(MoreNeeded { at_least: 1 })),
      (Some(b0), Some(b1)) => (b0, b1),
    };

    let masked = b1 & 0x80 != 0;
    let len7 = b1 & 0x7F;
    let ext_len: usize = match len7 {
      126 => 2,
      127 => 8,
      _ => 0,
    };
    let mask_len: usize = if masked { 4 } else { 0 };
    let total = 2usize.saturating_add(ext_len).saturating_add(mask_len);

    if buf.len() < total {
      return Ok(Decoded::Incomplete(MoreNeeded {
        at_least: total.saturating_sub(buf.len()),
      }));
    }

    let payload_len: u64 = match len7 {
      126 => {
        let (Some(&hi), Some(&lo)) = (buf.get(2), buf.get(3)) else {
          return Ok(Decoded::Incomplete(MoreNeeded { at_least: 2 }));
        };
        let value = u64::from(u16::from_be_bytes([hi, lo]));
        if value <= 125 {
          return Err(DecodeError::NonCanonicalLength(
            NonCanonicalLengthDetail::new(value, 2, 0),
          ));
        }
        value
      }
      127 => {
        let Some(ext) = buf.get(2..10) else {
          return Ok(Decoded::Incomplete(MoreNeeded { at_least: 8 }));
        };
        let &[a, b, c, d, e, f, g, h] = ext else {
          return Ok(Decoded::Incomplete(MoreNeeded { at_least: 8 }));
        };
        let value = u64::from_be_bytes([a, b, c, d, e, f, g, h]);
        if value & 0x8000_0000_0000_0000 != 0 {
          return Err(DecodeError::PayloadTooLarge(value));
        }
        if value <= 65535 {
          let minimal: u8 = if value <= 125 { 0 } else { 2 };
          return Err(DecodeError::NonCanonicalLength(
            NonCanonicalLengthDetail::new(value, 8, minimal),
          ));
        }
        value
      }
      small => u64::from(small),
    };

    let mask = if masked {
      let key_at = 2usize.saturating_add(ext_len);
      let Some(key) = buf.get(key_at..key_at.saturating_add(4)) else {
        return Ok(Decoded::Incomplete(MoreNeeded { at_least: 4 }));
      };
      let &[k0, k1, k2, k3] = key else {
        return Ok(Decoded::Incomplete(MoreNeeded { at_least: 4 }));
      };
      Some([k0, k1, k2, k3])
    } else {
      None
    };

    Ok(Decoded::Complete(DecodedHeader {
      header: FrameHeader {
        fin: b0 & 0x80 != 0,
        rsv1: b0 & 0x40 != 0,
        rsv2: b0 & 0x20 != 0,
        rsv3: b0 & 0x10 != 0,
        opcode: Opcode::from_bits(b0 & 0x0F),
        mask,
        payload_len,
      },
      consumed: total,
    }))
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::frame::Opcode;

  fn complete(buf: &[u8]) -> (FrameHeader, usize) {
    match FrameHeader::decode(buf).unwrap() {
      Decoded::Complete(d) => (d.header(), d.consumed()),
      Decoded::Incomplete(m) => panic!("unexpectedly incomplete: needs {}", m.at_least()),
    }
  }

  fn incomplete(buf: &[u8]) -> usize {
    match FrameHeader::decode(buf).unwrap() {
      Decoded::Incomplete(m) => m.at_least(),
      Decoded::Complete(_) => panic!("unexpectedly complete"),
    }
  }

  #[test]
  fn rfc6455_5_7_unmasked_hello() {
    // 81 05: FIN text, len 5.
    let (h, consumed) = complete(&[0x81, 0x05, 0x48, 0x65]);
    assert_eq!(consumed, 2);
    assert!(h.fin());
    assert!(!h.rsv1() && !h.rsv2() && !h.rsv3());
    assert_eq!(h.opcode(), Opcode::Text);
    assert_eq!(h.mask(), None);
    assert_eq!(h.payload_len(), 5);
  }

  #[test]
  fn rfc6455_5_7_masked_hello() {
    // 81 85 37 fa 21 3d: FIN text, masked, len 5.
    let (h, consumed) = complete(&[0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F]);
    assert_eq!(consumed, 6);
    assert_eq!(h.mask(), Some([0x37, 0xFA, 0x21, 0x3D]));
    assert_eq!(h.payload_len(), 5);
  }

  #[test]
  fn rfc6455_5_7_fragmented_pair() {
    let (h1, c1) = complete(&[0x01, 0x03]);
    assert!(!h1.fin());
    assert_eq!(h1.opcode(), Opcode::Text);
    assert_eq!(h1.payload_len(), 3);
    assert_eq!(c1, 2);

    let (h2, _) = complete(&[0x80, 0x02]);
    assert!(h2.fin());
    assert_eq!(h2.opcode(), Opcode::Continuation);
    assert_eq!(h2.payload_len(), 2);
  }

  #[test]
  fn rfc6455_5_7_extended_lengths() {
    // 82 7E 01 00: 256-byte binary.
    let (h, consumed) = complete(&[0x82, 0x7E, 0x01, 0x00]);
    assert_eq!(h.opcode(), Opcode::Binary);
    assert_eq!(h.payload_len(), 256);
    assert_eq!(consumed, 4);

    // 82 7F 00 00 00 00 00 01 00 00: 64 KiB binary.
    let (h, consumed) = complete(&[0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!(h.payload_len(), 65536);
    assert_eq!(consumed, 10);
  }

  #[test]
  fn rsv_and_reserved_opcodes_parse_losslessly() {
    // E3: FIN + RSV1 + RSV2 + opcode 3 (reserved). Policy is not this layer's job.
    // (0xE3 = 1110_0011: bit7=FIN, bit6=RSV1, bit5=RSV2, bit4=RSV3=0, opcode=3)
    let (h, _) = complete(&[0xE3, 0x00]);
    assert!(h.fin() && h.rsv1() && h.rsv2() && !h.rsv3());
    assert_eq!(h.opcode(), Opcode::Reserved(0x3));
    assert_eq!(h.payload_len(), 0);
  }

  #[test]
  fn incomplete_reports_exact_remaining_bytes() {
    // Empty: need at least the 2 fixed bytes.
    assert_eq!(incomplete(&[]), 2);
    // One byte: one more fixed byte.
    assert_eq!(incomplete(&[0x81]), 1);
    // len7=126: 2 extended bytes follow; have 2, need 2.
    assert_eq!(incomplete(&[0x82, 0x7E]), 2);
    assert_eq!(incomplete(&[0x82, 0x7E, 0x01]), 1);
    // len7=127: 8 extended bytes.
    assert_eq!(incomplete(&[0x82, 0x7F]), 8);
    assert_eq!(incomplete(&[0x82, 0x7F, 0, 0, 0]), 5);
    // Masked with 2-byte extended length: 2 ext + 4 key.
    assert_eq!(incomplete(&[0x82, 0xFE]), 6);
    assert_eq!(incomplete(&[0x82, 0xFE, 0x01, 0x00, 0xAA]), 3);
    // Masked, small length: 4 key bytes.
    assert_eq!(incomplete(&[0x81, 0x85]), 4);
    assert_eq!(incomplete(&[0x81, 0x85, 0x37, 0xFA, 0x21]), 1);
  }

  #[test]
  fn non_canonical_lengths_are_rejected() {
    // 2-byte form carrying ≤ 125.
    let err = FrameHeader::decode(&[0x82, 0x7E, 0x00, 0x7D]).unwrap_err();
    assert!(matches!(err, DecodeError::NonCanonicalLength(_)));
    // 8-byte form carrying ≤ 65535.
    let err = FrameHeader::decode(&[0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]).unwrap_err();
    assert!(matches!(err, DecodeError::NonCanonicalLength(_)));
    // Boundary acceptance: 126 in 2-byte form and 65536 in 8-byte form are minimal.
    complete(&[0x82, 0x7E, 0x00, 0x7E]);
    complete(&[0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0x00, 0x00]);
  }

  #[test]
  fn msb_set_in_64bit_length_is_rejected() {
    // §5.2: the most significant bit of the 64-bit length MUST be 0.
    let err = FrameHeader::decode(&[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap_err();
    assert!(matches!(err, DecodeError::PayloadTooLarge(_)));
  }

  #[test]
  fn encode_matches_rfc6455_5_7_vectors() {
    let mut buf = [0u8; 14];

    let n = FrameHeader::new(Opcode::Text, 5).encode(&mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x81, 0x05]);

    let n = FrameHeader::new(Opcode::Text, 5)
      .with_mask(Some([0x37, 0xFA, 0x21, 0x3D]))
      .encode(&mut buf)
      .unwrap();
    assert_eq!(&buf[..n], &[0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D]);

    let n = FrameHeader::new(Opcode::Text, 3)
      .with_fin(false)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(&buf[..n], &[0x01, 0x03]);

    let n = FrameHeader::new(Opcode::Continuation, 2)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(&buf[..n], &[0x80, 0x02]);

    let n = FrameHeader::new(Opcode::Binary, 256)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(&buf[..n], &[0x82, 0x7E, 0x01, 0x00]);

    let n = FrameHeader::new(Opcode::Binary, 65536)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(&buf[..n], &[0x82, 0x7F, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00]);
  }

  #[test]
  fn header_len_matches_encode() {
    let mut buf = [0u8; 14];
    let key = Some([1, 2, 3, 4]);
    for (len, mask) in [
      (0u64, None),
      (125, None),
      (126, None),
      (65535, key),
      (65536, key),
      (5, key),
    ] {
      let h = FrameHeader::new(Opcode::Binary, len).with_mask(mask);
      assert_eq!(
        h.header_len(),
        h.encode(&mut buf).unwrap(),
        "len={len} mask={mask:?}"
      );
    }
  }

  #[test]
  fn encode_picks_minimal_form_at_boundaries() {
    let mut buf = [0u8; 14];
    let n = FrameHeader::new(Opcode::Binary, 125)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(n, 2);
    let n = FrameHeader::new(Opcode::Binary, 126)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(n, 4);
    let n = FrameHeader::new(Opcode::Binary, 65535)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(n, 4);
    let n = FrameHeader::new(Opcode::Binary, 65536)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(n, 10);
  }

  #[test]
  fn encode_rejects_oversized_and_small_buffers() {
    let mut buf = [0u8; 14];
    let err = FrameHeader::new(Opcode::Binary, u64::MAX)
      .encode(&mut buf)
      .unwrap_err();
    assert!(matches!(err, EncodeError::PayloadTooLarge(_)));

    let mut tiny = [0u8; 3];
    let err = FrameHeader::new(Opcode::Binary, 256)
      .encode(&mut tiny)
      .unwrap_err();
    assert!(matches!(err, EncodeError::BufferTooSmall(_)));
  }

  #[test]
  fn rsv_bits_encode_into_byte0() {
    let mut buf = [0u8; 14];
    let n = FrameHeader::new(Opcode::Text, 0)
      .with_rsv1(true)
      .with_rsv3(true)
      .encode(&mut buf)
      .unwrap();
    assert_eq!(&buf[..n], &[0xD1, 0x00]); // FIN + RSV1 + RSV3 + text
  }

  mod properties {
    use super::*;
    use proptest::{prelude::*, test_runner::TestCaseError};

    proptest! {
      /// Every strict prefix of a decodable header reports Incomplete with
      /// a remaining-count that, when satisfied, completes consistently.
      #[test]
      fn prefixes_are_incomplete_then_consistent(
        b0 in any::<u8>(),
        masked in any::<bool>(),
        len in any::<u64>(),
        key in any::<[u8; 4]>(),
      ) {
        // Build a canonical header encoding by hand.
        let len = len & 0x7FFF_FFFF_FFFF_FFFF;
        let mut bytes = vec![b0];
        let mask_bit = if masked { 0x80u8 } else { 0 };
        if len <= 125 {
          bytes.push(mask_bit | u8::try_from(len).unwrap());
        } else if len <= 65535 {
          bytes.push(mask_bit | 126);
          bytes.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        } else {
          bytes.push(mask_bit | 127);
          bytes.extend_from_slice(&len.to_be_bytes());
        }
        if masked {
          bytes.extend_from_slice(&key);
        }

        // The full bytes decode completely, consuming everything.
        let full = FrameHeader::decode(&bytes).unwrap();
        let d = match full {
          Decoded::Complete(d) => d,
          Decoded::Incomplete(_) => return Err(TestCaseError::fail("full header incomplete")),
        };
        prop_assert_eq!(d.consumed(), bytes.len());
        prop_assert_eq!(d.header().payload_len(), len);
        prop_assert_eq!(d.header().mask().is_some(), masked);

        // Every strict prefix is Incomplete. Before byte 1 arrives the
        // decoder can only promise the fixed-header deficit (2 - have);
        // from byte 1 on it knows the exact total.
        for cut in 0..bytes.len() {
          let expected = if cut < 2 { 2 - cut } else { bytes.len() - cut };
          match FrameHeader::decode(&bytes[..cut]).unwrap() {
            Decoded::Incomplete(m) => {
              prop_assert_eq!(m.at_least(), expected, "cut at {}", cut);
            }
            Decoded::Complete(_) => {
              return Err(TestCaseError::fail(format!("prefix {cut} decoded as complete")));
            }
          }
        }
      }

      /// encode → decode is the identity, for headers across all three
      /// length forms, mask states, RSV combinations, and opcodes.
      #[test]
      fn encode_decode_round_trip(
        fin in any::<bool>(),
        rsv in any::<(bool, bool, bool)>(),
        opbits in 0u8..=0x0F,
        mask in any::<Option<[u8; 4]>>(),
        len in any::<u64>(),
      ) {
        let len = len & 0x7FFF_FFFF_FFFF_FFFF;
        let header = FrameHeader::new(Opcode::from_bits(opbits), len)
          .with_fin(fin)
          .with_rsv1(rsv.0)
          .with_rsv2(rsv.1)
          .with_rsv3(rsv.2)
          .with_mask(mask);

        let mut buf = [0u8; 14];
        let n = header.encode(&mut buf).unwrap();
        match FrameHeader::decode(&buf[..n]).unwrap() {
          Decoded::Complete(d) => {
            prop_assert_eq!(d.header(), header);
            prop_assert_eq!(d.consumed(), n);
            prop_assert_eq!(header.header_len(), n);
          }
          Decoded::Incomplete(_) => return Err(TestCaseError::fail("round trip incomplete")),
        }
      }
    }
  }
}
