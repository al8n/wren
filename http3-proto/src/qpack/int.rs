//! Prefixed-integer codec (RFC 7541 §5.1), shared by the QPACK field-section
//! encoder and decoder. A value is packed into the low `prefix_bits` of a first
//! byte (whose high bits carry caller-supplied `flags`); values that do not fit
//! spill into 7-bit continuation bytes. Panic-free and bounds-checked.

use super::QpackError;
use crate::error::{BufferTooSmallDetail, TruncatedDetail};

/// Writes one byte at `at`, returning `at + 1`.
///
/// Errors with [`QpackError::Buffer`] if `at` is out of bounds for `out`.
fn put_byte(out: &mut [u8], at: usize, b: u8) -> Result<usize, QpackError> {
  let have = out.len();
  let slot = out
    .get_mut(at)
    .ok_or_else(|| QpackError::Buffer(BufferTooSmallDetail::new(at.saturating_add(1), have)))?;
  *slot = b;
  Ok(at.saturating_add(1))
}

/// Encodes `value` as a prefixed integer (RFC 7541 §5.1) into `out` starting at
/// index `at`, OR-ing `flags` into the high bits of the first byte.
///
/// `prefix_bits` is the width of the integer's first-byte prefix (1..=8); the
/// matching `flags` must leave those low bits clear. Returns the index just past
/// the last byte written. Errors with [`QpackError::Buffer`] if `out` is too
/// small.
pub fn encode_int(
  out: &mut [u8],
  at: usize,
  value: u64,
  prefix_bits: u32,
  flags: u8,
) -> Result<usize, QpackError> {
  let max = 1u64.wrapping_shl(prefix_bits).wrapping_sub(1);
  if value < max {
    let first = u8::try_from(value).map_err(|_| QpackError::BadInteger)?;
    return put_byte(out, at, flags | first);
  }
  // First byte: all prefix bits set (value spills into continuation bytes).
  let prefix = u8::try_from(max).map_err(|_| QpackError::BadInteger)?;
  let mut at = put_byte(out, at, flags | prefix)?;
  let mut value = value.wrapping_sub(max);
  while value >= 128 {
    let byte = u8::try_from((value & 0x7f) | 0x80).map_err(|_| QpackError::BadInteger)?;
    at = put_byte(out, at, byte)?;
    value = value.wrapping_shr(7);
  }
  let last = u8::try_from(value).map_err(|_| QpackError::BadInteger)?;
  put_byte(out, at, last)
}

/// Decodes a prefixed integer (RFC 7541 §5.1) from the front of `input`,
/// returning `(bytes consumed, value)`.
///
/// The high bits of the first byte above the low `prefix_bits` are flags and are
/// ignored. Errors with [`QpackError::Truncated`] if `input` ends mid-integer,
/// or [`QpackError::BadInteger`] if the continuation overflows `u64`.
pub fn decode_int(input: &[u8], prefix_bits: u32) -> Result<(usize, u64), QpackError> {
  let max = 1u64.wrapping_shl(prefix_bits).wrapping_sub(1);
  let &first = input
    .first()
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
  let prefix = u64::from(first) & max;
  if prefix < max {
    return Ok((1, prefix));
  }
  let mut value = max;
  let mut shift: u32 = 0;
  let mut consumed = 1usize;
  loop {
    let &b = input
      .get(consumed)
      .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
    consumed = consumed.saturating_add(1);
    let add = u64::from(b & 0x7f)
      .checked_shl(shift)
      .ok_or(QpackError::BadInteger)?;
    value = value.checked_add(add).ok_or(QpackError::BadInteger)?;
    if b & 0x80 == 0 {
      break;
    }
    shift = shift.checked_add(7).ok_or(QpackError::BadInteger)?;
    if shift >= 64 {
      return Err(QpackError::BadInteger);
    }
  }
  Ok((consumed, value))
}
