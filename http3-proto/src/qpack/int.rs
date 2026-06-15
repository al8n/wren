//! Prefixed-integer ENCODER (RFC 7541 §5.1), shared by the QPACK field-section
//! encoder. A value is packed into the low `prefix_bits` of a first byte (whose
//! high bits carry caller-supplied `flags`); values that do not fit spill into
//! 7-bit continuation bytes. Panic-free and bounds-checked. The decoder half
//! lands in a later task.

use super::QpackError;
use crate::error::BufferTooSmallDetail;

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
