//! QUIC variable-length integers (RFC 9000 §16).

use crate::error::{BufferTooSmallDetail, TruncatedDetail};

/// Largest value a QUIC varint can hold (2^62 − 1).
pub const MAX: u64 = (1 << 62) - 1;

/// A varint codec error.
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Display, derive_more::From)]
#[non_exhaustive]
pub enum VarintError {
  /// The output buffer was too small.
  #[display("{_0}")]
  Buffer(BufferTooSmallDetail),
  /// The input ended mid-integer.
  #[display("{_0}")]
  Truncated(TruncatedDetail),
  /// The value exceeds [`MAX`] and cannot be encoded.
  #[display("varint value exceeds 2^62-1")]
  TooLarge,
}

/// Bytes a value encodes to: 1, 2, 4, or 8.
#[inline]
pub const fn len_of(value: u64) -> usize {
  if value <= 0x3f {
    1
  } else if value <= 0x3fff {
    2
  } else if value <= 0x3fff_ffff {
    4
  } else {
    8
  }
}

/// Encodes `value` into `out`, returning bytes written.
#[inline]
pub fn encode(value: u64, out: &mut [u8]) -> Result<usize, VarintError> {
  if value > MAX {
    return Err(VarintError::TooLarge);
  }
  let n = len_of(value);
  let out_len = out.len();
  let dst = out
    .get_mut(..n)
    .ok_or(BufferTooSmallDetail::new(n, out_len))?;
  let tag: u8 = match n {
    1 => 0b00,
    2 => 0b01,
    4 => 0b10,
    _ => 0b11,
  };
  let be = value.to_be_bytes();
  for (d, s) in dst.iter_mut().zip(be.iter().skip(8usize.wrapping_sub(n))) {
    *d = *s;
  }
  // `dst` is non-empty here: `len_of` returns >= 1 and `out.get_mut(..n)`
  // succeeded, so `first_mut()` is always `Some`. The `if let` (rather than
  // `dst[0]`) is what keeps the `indexing_slicing` deny satisfied.
  if let Some(first) = dst.first_mut() {
    *first |= tag << 6;
  }
  Ok(n)
}

/// Decodes a varint from the front of `input`: (bytes consumed, value).
#[inline]
pub fn decode(input: &[u8]) -> Result<(usize, u64), VarintError> {
  let &first = input.first().ok_or(TruncatedDetail::new(1))?;
  let n = 1usize << (first >> 6);
  // `first` was already read, so `input.len() >= 1`; this slice only fails when
  // `input.len() < n`, hence `n - input.len()` never underflows. `saturating_sub`
  // is used purely to satisfy the `arithmetic_side_effects` deny.
  let bytes = input
    .get(..n)
    .ok_or(TruncatedDetail::new(n.saturating_sub(input.len())))?;
  // Build value via a fixed 8-byte array to avoid arithmetic_side_effects lint
  // from the shift-accumulate approach. We zero-pad `bytes` into the high end
  // of a u64 big-endian buffer, mask the two tag bits, then read with
  // from_be_bytes — no shifts, no arithmetic in production code.
  //
  // n ∈ {1, 2, 4, 8}, so offset = 8 - n ∈ {0, 4, 6, 7}: always in range.
  let mut arr = [0u8; 8];
  let offset = 8usize.wrapping_sub(n);
  if let Some(dest) = arr.get_mut(offset..) {
    dest.iter_mut().zip(bytes.iter()).for_each(|(d, s)| *d = *s);
  }
  // Clear the 2-bit length tag from the most-significant byte of the value.
  if let Some(b) = arr.get_mut(offset) {
    *b &= 0x3f;
  }
  let value = u64::from_be_bytes(arr);
  Ok((n, value))
}

#[cfg(test)]
mod tests;
