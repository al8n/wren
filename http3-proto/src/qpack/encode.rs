//! QPACK field-section encoder (RFC 9204 §4.5), static-table-only. Values and
//! literal names are emitted raw (Huffman flag H=0); Huffman emission is a
//! future optimization. Output is a 2-byte prefix (RIC=0, Delta Base=0) then
//! one field line per header.

use super::{
  QpackError,
  int::encode_int,
  static_table::{find_name, find_name_value},
};
use crate::error::BufferTooSmallDetail;

/// Writes a string: its length as a prefixed integer carrying `flags` (Huffman
/// flag H=0), then the raw bytes. Returns the index just past the string.
fn encode_str(
  out: &mut [u8],
  at: usize,
  s: &str,
  prefix_bits: u32,
  flags: u8,
) -> Result<usize, QpackError> {
  let bytes = s.as_bytes();
  let len = u64::try_from(bytes.len()).map_err(|_| QpackError::BadInteger)?;
  let body_at = encode_int(out, at, len, prefix_bits, flags)?;
  let have = out.len();
  let end = body_at
    .checked_add(bytes.len())
    .ok_or_else(|| QpackError::Buffer(BufferTooSmallDetail::new(body_at, have)))?;
  let dst = out
    .get_mut(body_at..end)
    .ok_or_else(|| QpackError::Buffer(BufferTooSmallDetail::new(end, have)))?;
  dst.copy_from_slice(bytes);
  Ok(end)
}

/// Encodes `headers` into a QPACK field section in `out`, returning bytes
/// written.
///
/// Every line uses the static table only (no dynamic references). Names/values
/// are emitted raw (no Huffman). Errors with [`QpackError::Buffer`] if `out` is
/// too small.
pub fn encode_field_section<'a>(
  headers: impl Iterator<Item = (&'a str, &'a str)>,
  out: &mut [u8],
) -> Result<usize, QpackError> {
  // Prefix: Required Insert Count = 0, Delta Base = 0 (sign 0).
  let mut at = encode_int(out, 0, 0, 8, 0x00)?; // RIC=0 → single 0x00 byte
  at = encode_int(out, at, 0, 7, 0x00)?; // Delta Base=0, sign 0 → 0x00
  for (name, value) in headers {
    if let Some(idx) = find_name_value(name, value) {
      // Indexed Field Line, static: 1 T=1 index(6+).
      let idx = u64::try_from(idx).map_err(|_| QpackError::BadInteger)?;
      at = encode_int(out, at, idx, 6, 0b1100_0000)?;
    } else if let Some(idx) = find_name(name) {
      // Literal With Name Reference, static: 0 1 N=0 T=1 index(4+) ; value.
      let idx = u64::try_from(idx).map_err(|_| QpackError::BadInteger)?;
      at = encode_int(out, at, idx, 4, 0b0101_0000)?;
      at = encode_str(out, at, value, 7, 0x00)?;
    } else {
      // Literal With Literal Name: 0 0 1 N=0 H=0 namelen(3+) ; name ; value.
      at = encode_str(out, at, name, 3, 0b0010_0000)?;
      at = encode_str(out, at, value, 7, 0x00)?;
    }
  }
  Ok(at)
}
