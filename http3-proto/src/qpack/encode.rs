//! QPACK field-section encoder (RFC 9204 §4.5), static-table-only. Values and
//! literal names are emitted raw (Huffman flag H=0); Huffman emission is a
//! future optimization. Output is a 2-byte prefix (RIC=0, Delta Base=0) then
//! one field line per header.

use super::{
  QpackError,
  int::encode_int,
  static_table::{find_name, find_name_value},
};
use crate::{Error, error::BufferTooSmallDetail, headers::Headers};

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

/// Encodes one `(name, value)` field line into `out` starting at index `at`,
/// returning the index just past the line.
///
/// Selects the most compact static-table representation: an Indexed Field Line
/// when both name and value match, a Literal With Name Reference when only the
/// name matches, else a Literal With Literal Name. Names/values are emitted raw
/// (no Huffman).
pub(crate) fn encode_line(
  out: &mut [u8],
  at: usize,
  name: &str,
  value: &str,
) -> Result<usize, QpackError> {
  if let Some(idx) = find_name_value(name, value) {
    // Indexed Field Line, static: 1 T=1 index(6+).
    let idx = u64::try_from(idx).map_err(|_| QpackError::BadInteger)?;
    encode_int(out, at, idx, 6, 0b1100_0000)
  } else if let Some(idx) = find_name(name) {
    // Literal With Name Reference, static: 0 1 N=0 T=1 index(4+) ; value.
    let idx = u64::try_from(idx).map_err(|_| QpackError::BadInteger)?;
    let at = encode_int(out, at, idx, 4, 0b0101_0000)?;
    encode_str(out, at, value, 7, 0x00)
  } else {
    // Literal With Literal Name: 0 0 1 N=0 H=0 namelen(3+) ; name ; value.
    let at = encode_str(out, at, name, 3, 0b0010_0000)?;
    encode_str(out, at, value, 7, 0x00)
  }
}

/// Writes the 2-byte field-section prefix (RIC=0, Delta Base=0) at the front of
/// `out`, returning the offset of the first field line.
fn encode_prefix(out: &mut [u8]) -> Result<usize, QpackError> {
  // Required Insert Count = 0, Delta Base = 0 (sign 0).
  let at = encode_int(out, 0, 0, 8, 0x00)?; // RIC=0 → single 0x00 byte
  encode_int(out, at, 0, 7, 0x00) // Delta Base=0, sign 0 → 0x00
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
  let mut at = encode_prefix(out)?;
  for (name, value) in headers {
    at = encode_line(out, at, name, value)?;
  }
  Ok(at)
}

/// Maps a QPACK error to the connection-level [`Error`] (a protocol error
/// carrying the HTTP/3 error code).
fn qpack_to_err(e: QpackError) -> Error {
  Error::Protocol(e.to_h3())
}

/// Encodes a field section by driving a [`Headers`](crate::headers::Headers)
/// supplier in push style (its borrowed `&str` cannot be collected). Returns
/// bytes written, or the driver's error / a QPACK error.
///
/// `Headers` is taken by `&(impl Headers + ?Sized)` so the unsized
/// `[(&str, &str)]` blanket impl can be passed directly as `&slice[..]`.
pub fn encode_field_section_from<H: Headers + ?Sized>(
  headers: &H,
  out: &mut [u8],
) -> Result<usize, Error> {
  let at = encode_prefix(out).map_err(qpack_to_err)?;
  let mut cursor = at;
  let mut enc_err: Option<QpackError> = None;
  headers.for_each(&mut |n, v| {
    if enc_err.is_some() {
      return;
    }
    match encode_line(out, cursor, n, v) {
      Ok(next) => cursor = next,
      Err(e) => enc_err = Some(e),
    }
  })?; // propagates the supplier's crate::Error
  if let Some(e) = enc_err {
    return Err(qpack_to_err(e));
  }
  Ok(cursor)
}
