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

/// Why [`encode_field_section_from`] stopped before encoding the whole section.
///
/// The two "too large" outcomes are kept distinct from a genuine coding fault so
/// the connection can refuse oversized outbound HEADERS *locally* (mapping both
/// [`TooLarge`](Self::TooLarge) and [`BufferExhausted`](Self::BufferExhausted) to
/// [`Error::FieldSectionTooLarge`]) while still surfacing a real encoder bug as a
/// protocol error.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
  /// The running decoded field-section size (Σ `name.len() + value.len() + 32`,
  /// RFC 9114 §4.2.2) exceeded the caller-supplied `max_decoded` limit — the
  /// peer's advertised `MAX_FIELD_SECTION_SIZE`. Detected *inside* the single
  /// encode pass, before (and independent of) any output-buffer exhaustion.
  #[error("field section too large")]
  TooLarge,
  /// The output workspace ran out of room (a [`QpackError::Buffer`]). For
  /// outbound HEADERS this means the section is too large for us to send; the
  /// connection maps it to [`Error::FieldSectionTooLarge`], a local refusal.
  #[error("buffer exhausted")]
  BufferExhausted,
  /// A genuine QPACK encoding fault (e.g. a length that overflows `u64`) — not a
  /// size-limit or buffer condition. Surfaced as a protocol error.
  #[error(transparent)]
  Qpack(#[from] QpackError),
  /// The [`Headers`] supplier's `for_each` returned an error, propagated verbatim.
  #[error(transparent)]
  Supplier(#[from] Error),
}

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

/// Encodes a field section by driving a [`Headers`](crate::headers::Headers)
/// supplier in push style (its borrowed `&str` cannot be collected), in a SINGLE
/// traversal that BOTH encodes the wire bytes into `out` AND accumulates — and
/// bounds — the decoded field-section size. Returns `(encoded_len, decoded_size)`:
/// the number of bytes written to `out`, and the RFC 9114 §4.2.2 decoded size (the
/// sum over every visited field of `name.len() + value.len() + 32`, saturating).
///
/// `max_decoded`, when `Some(limit)`, is the peer's advertised
/// `MAX_FIELD_SECTION_SIZE`: the moment the running decoded size exceeds it the
/// pass stops with [`EncodeError::TooLarge`]. That check is applied *before*
/// encoding each line, so it is independent of — and takes precedence over — any
/// output-buffer exhaustion ([`EncodeError::BufferExhausted`]); a genuine encoder
/// fault is [`EncodeError::Qpack`], and a supplier error is
/// [`EncodeError::Supplier`].
///
/// The two outputs come from the *same* `for_each` pass on purpose: the public
/// [`Headers`](crate::headers::Headers) trait does not guarantee replayable or
/// deterministic output, so a one-shot / interior-mutable supplier could yield a
/// different field section on a second traversal. Measuring and encoding together
/// guarantees the size the caller validates is the size of the bytes it sends.
///
/// `Headers` is taken by `&(impl Headers + ?Sized)` so the unsized
/// `[(&str, &str)]` blanket impl can be passed directly as `&slice[..]`.
pub fn encode_field_section_from<H: Headers + ?Sized>(
  headers: &H,
  out: &mut [u8],
  max_decoded: Option<usize>,
) -> Result<(usize, usize), EncodeError> {
  let at = encode_prefix(out).map_err(map_encode_err)?;
  let mut cursor = at;
  let mut decoded_size: usize = 0;
  let mut enc_err: Option<EncodeError> = None;
  headers
    .for_each(&mut |n, v| {
      if enc_err.is_some() {
        return;
      }
      // RFC 9114 §4.2.2 per-field decoded size: name + value + 32 overhead,
      // saturating so a pathological supplier cannot overflow the running total.
      decoded_size = decoded_size
        .saturating_add(n.len())
        .saturating_add(v.len())
        .saturating_add(32);
      // Enforce the peer's limit FIRST — before encoding this line — so the
      // too-large signal is independent of (and prior to) any buffer exhaustion.
      if let Some(limit) = max_decoded
        && decoded_size > limit
      {
        enc_err = Some(EncodeError::TooLarge);
        return;
      }
      match encode_line(out, cursor, n, v) {
        Ok(next) => cursor = next,
        Err(e) => enc_err = Some(map_encode_err(e)),
      }
    })
    .map_err(EncodeError::Supplier)?;
  if let Some(e) = enc_err {
    return Err(e);
  }
  Ok((cursor, decoded_size))
}

/// Splits a [`QpackError`] from the encoder into the size-class-aware
/// [`EncodeError`]: an output-buffer-too-small error becomes
/// [`EncodeError::BufferExhausted`] (the section is too large for the workspace),
/// every other QPACK error a genuine [`EncodeError::Qpack`] fault.
fn map_encode_err(e: QpackError) -> EncodeError {
  match e {
    QpackError::Buffer(_) => EncodeError::BufferExhausted,
    other => EncodeError::Qpack(other),
  }
}
