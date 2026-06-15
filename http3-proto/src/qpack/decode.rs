//! QPACK field-section decoder (RFC 9204 §4.5), static-table-only. Rejects all
//! dynamic-table references (Indexed / Literal-name-ref with T=0, post-base
//! representations, and any non-zero Required Insert Count or Base). Raw string
//! literals borrow the input; Huffman literals are decoded into a scratch
//! buffer, so a yielded [`Pair`] is valid only until the next [`FieldLines::next`]
//! call (the scratch is reused per call).

use super::{QpackError, huffman, int::decode_int, static_table::STATIC_TABLE};
use crate::error::TruncatedDetail;

/// Scratch storage for Huffman-decoded names/values: a caller-supplied slice
/// (no-alloc) or an internally-owned buffer.
enum Scratch<'a> {
  Borrowed(&'a mut [u8]),
  #[cfg(any(feature = "std", feature = "alloc"))]
  Owned(std::vec::Vec<u8>),
}

impl Scratch<'_> {
  fn buf(&mut self) -> &mut [u8] {
    match self {
      Self::Borrowed(b) => b,
      #[cfg(any(feature = "std", feature = "alloc"))]
      Self::Owned(v) => v.as_mut_slice(),
    }
  }
}

/// Where a decoded name or value comes from: a static-table `&'static str`, a
/// raw (un-Huffman-coded) span of the input, or a Huffman-coded span to be
/// decoded into the scratch.
enum Src {
  Static(&'static str),
  Raw { start: usize, len: usize },
  Huff { start: usize, len: usize },
}

/// A decoded `(name, value)` pair.
///
/// Valid only until the next [`FieldLines::next`] call: Huffman-decoded names
/// and values are materialized into a scratch buffer that the next call reuses.
pub struct Pair<'b> {
  name: &'b str,
  value: &'b str,
}

impl Pair<'_> {
  /// The field name.
  #[inline]
  pub const fn name(&self) -> &str {
    self.name
  }

  /// The field value.
  #[inline]
  pub const fn value(&self) -> &str {
    self.value
  }
}

/// A lending iterator over the field lines of a QPACK field section.
///
/// Construct with [`decode_field_section_into`] (no-alloc, caller scratch) or
/// [`decode_field_section`] (owned scratch). Call [`FieldLines::next`] until it
/// returns `Ok(None)`.
pub struct FieldLines<'a> {
  input: &'a [u8],
  pos: usize,
  scratch: Scratch<'a>,
}

impl FieldLines<'_> {
  /// Decodes the next field line, or `Ok(None)` at the end of the section.
  ///
  /// The returned [`Pair`] borrows either the input (raw / static) or the
  /// internal scratch (Huffman) and is invalidated by the next call.
  // This is a lending iterator: each `Pair` borrows `self` (the per-call scratch
  // is reused), so the borrow `next` returns outlives no `self`-distinct
  // `Item` and `std::iter::Iterator` cannot be implemented.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Result<Option<Pair<'_>>, QpackError> {
    let Self {
      input,
      pos,
      scratch,
    } = self;
    if *pos >= input.len() {
      return Ok(None);
    }
    let (name_src, value_src) = parse_line(input, pos)?;
    let buf = scratch.buf();
    let (name, value) = materialize(input, buf, name_src, value_src)?;
    Ok(Some(Pair { name, value }))
  }
}

/// Parses ONE field line starting at `*pos`, advancing `*pos` past it and
/// returning index-based descriptors for the name and value. This phase only
/// reads `input` and writes `*pos` (it materializes no borrows).
fn parse_line(input: &[u8], pos: &mut usize) -> Result<(Src, Src), QpackError> {
  let &b = input
    .get(*pos)
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
  if b & 0x80 != 0 {
    // Indexed Field Line: 1 T index(6+).
    if b & 0x40 == 0 {
      return Err(QpackError::DynamicReference);
    }
    let rest = input
      .get(*pos..)
      .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
    let (consumed, index) = decode_int(rest, 6)?;
    *pos = pos.saturating_add(consumed);
    let (name, value) = static_pair(index)?;
    Ok((Src::Static(name), Src::Static(value)))
  } else if b & 0x40 != 0 {
    // Literal With Name Reference: 0 1 N T nameidx(4+) ; value.
    if b & 0x10 == 0 {
      return Err(QpackError::DynamicReference);
    }
    let rest = input
      .get(*pos..)
      .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
    let (consumed, nameidx) = decode_int(rest, 4)?;
    *pos = pos.saturating_add(consumed);
    let (name, _) = static_pair(nameidx)?;
    let value = parse_value(input, pos)?;
    Ok((Src::Static(name), value))
  } else if b & 0x20 != 0 {
    // Literal With Literal Name: 0 0 1 N H namelen(3+) ; name ; value.
    let huff_name = (b & 0x08) != 0;
    let rest = input
      .get(*pos..)
      .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
    // The 3-bit prefix masks b & 0x07; the H bit (0x08) is above the prefix and
    // is not part of the integer.
    let (consumed, namelen) = decode_int(rest, 3)?;
    *pos = pos.saturating_add(consumed);
    let name = read_string(input, pos, namelen, huff_name)?;
    let value = parse_value(input, pos)?;
    Ok((name, value))
  } else {
    // 0001xxxx Indexed Post-Base or 0000xxxx Literal Post-Base Name Ref: both
    // are dynamic-table representations.
    Err(QpackError::DynamicReference)
  }
}

/// Parses a value string: H is bit 7, the length uses a 7-bit prefix.
fn parse_value(input: &[u8], pos: &mut usize) -> Result<Src, QpackError> {
  let &b = input
    .get(*pos)
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
  let huff = (b & 0x80) != 0;
  let rest = input
    .get(*pos..)
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
  let (consumed, len) = decode_int(rest, 7)?;
  *pos = pos.saturating_add(consumed);
  read_string(input, pos, len, huff)
}

/// Records a string span of `len` bytes at `*pos`, advancing `*pos` past it.
/// Bounds-checks the span (truncated input → [`QpackError::Truncated`]).
fn read_string(input: &[u8], pos: &mut usize, len: u64, huff: bool) -> Result<Src, QpackError> {
  let len = usize::try_from(len).map_err(|_| QpackError::BadInteger)?;
  let start = *pos;
  let end = start
    .checked_add(len)
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
  if end > input.len() {
    return Err(QpackError::Truncated(TruncatedDetail::new(1)));
  }
  *pos = end;
  if huff {
    Ok(Src::Huff { start, len })
  } else {
    Ok(Src::Raw { start, len })
  }
}

/// Looks up a static-table entry, rejecting out-of-range indices.
fn static_pair(index: u64) -> Result<(&'static str, &'static str), QpackError> {
  let index = usize::try_from(index).map_err(|_| QpackError::BadStaticIndex)?;
  STATIC_TABLE
    .get(index)
    .copied()
    .ok_or(QpackError::BadStaticIndex)
}

/// Materializes the name and value from their descriptors, Huffman-decoding into
/// `buf` as needed. The two Huffman regions are placed disjointly so both can be
/// borrowed at once.
fn materialize<'a>(
  input: &'a [u8],
  buf: &'a mut [u8],
  name_src: Src,
  value_src: Src,
) -> Result<(&'a str, &'a str), QpackError> {
  match (name_src, value_src) {
    (Src::Huff { start: ns, len: nl }, Src::Huff { start: vs, len: vl }) => {
      // Decode name into the front of the scratch, value into the region after
      // it, then split into two disjoint immutable slices.
      let name_bytes = huff_span(input, ns, nl)?;
      let value_bytes = huff_span(input, vs, vl)?;
      let name_written = huffman::decode(name_bytes, buf)?;
      let (name_region, rest) = buf
        .split_at_mut_checked(name_written)
        .ok_or(QpackError::BadInteger)?;
      let value_written = huffman::decode(value_bytes, rest)?;
      let value_region = rest.get(..value_written).ok_or(QpackError::BadInteger)?;
      let name = str_from_huff(name_region)?;
      let value = str_from_huff(value_region)?;
      Ok((name, value))
    }
    (Src::Huff { start, len }, value_src) => {
      let name_bytes = huff_span(input, start, len)?;
      let written = huffman::decode(name_bytes, buf)?;
      let name_region = buf.get(..written).ok_or(QpackError::BadInteger)?;
      let name = str_from_huff(name_region)?;
      let value = non_huff_str(input, value_src)?;
      Ok((name, value))
    }
    (name_src, Src::Huff { start, len }) => {
      let value_bytes = huff_span(input, start, len)?;
      let written = huffman::decode(value_bytes, buf)?;
      let value_region = buf.get(..written).ok_or(QpackError::BadInteger)?;
      let value = str_from_huff(value_region)?;
      let name = non_huff_str(input, name_src)?;
      Ok((name, value))
    }
    (name_src, value_src) => {
      let name = non_huff_str(input, name_src)?;
      let value = non_huff_str(input, value_src)?;
      Ok((name, value))
    }
  }
}

/// The Huffman-coded bytes of a `Huff` span (bounds-checked).
fn huff_span(input: &[u8], start: usize, len: usize) -> Result<&[u8], QpackError> {
  let end = start
    .checked_add(len)
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
  input
    .get(start..end)
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))
}

/// Resolves a `Static` or `Raw` descriptor to a `&str` borrowing the input.
fn non_huff_str(input: &[u8], src: Src) -> Result<&str, QpackError> {
  match src {
    Src::Static(s) => Ok(s),
    Src::Raw { start, len } => {
      let end = start
        .checked_add(len)
        .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
      let bytes = input
        .get(start..end)
        .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
      core::str::from_utf8(bytes).map_err(|_| QpackError::InvalidString)
    }
    // Huffman is materialized by the caller against the scratch.
    Src::Huff { .. } => Err(QpackError::InvalidString),
  }
}

/// Validates Huffman-decoded bytes as UTF-8.
fn str_from_huff(bytes: &[u8]) -> Result<&str, QpackError> {
  core::str::from_utf8(bytes).map_err(|_| QpackError::InvalidString)
}

/// Decodes the 2-byte field-section prefix (RFC 9204 §4.5.1), returning the
/// offset of the first field line. Required Insert Count and Base must both be 0
/// (this decoder is static-table-only).
fn read_prefix(input: &[u8]) -> Result<usize, QpackError> {
  let (ric_consumed, ric) = decode_int(input, 8)?;
  if ric != 0 {
    return Err(QpackError::DynamicReference);
  }
  let rest = input
    .get(ric_consumed..)
    .ok_or(QpackError::Truncated(TruncatedDetail::new(1)))?;
  // Top bit of the Delta Base byte is the sign; the low 7 bits are the base.
  // The base must be 0, so the sign is irrelevant.
  let (base_consumed, base) = decode_int(rest, 7)?;
  if base != 0 {
    return Err(QpackError::DynamicReference);
  }
  Ok(ric_consumed.saturating_add(base_consumed))
}

/// Decodes a field section using a caller-supplied Huffman scratch buffer
/// (no-alloc).
///
/// The scratch must fit any single field line's decoded name+value. Raw string
/// literals borrow `input` directly; only Huffman literals use the scratch.
/// Errors if the 2-byte prefix is malformed or references the dynamic table.
pub fn decode_field_section_into<'a>(
  input: &'a [u8],
  scratch: &'a mut [u8],
) -> Result<FieldLines<'a>, QpackError> {
  let pos = read_prefix(input)?;
  Ok(FieldLines {
    input,
    pos,
    scratch: Scratch::Borrowed(scratch),
  })
}

/// Decodes a field section, Huffman-decoding into an internally-owned buffer.
///
/// Errors if the 2-byte prefix is malformed or references the dynamic table.
#[cfg(any(feature = "std", feature = "alloc"))]
pub fn decode_field_section(input: &[u8]) -> Result<FieldLines<'_>, QpackError> {
  let pos = read_prefix(input)?;
  let cap = input.len().saturating_mul(2).saturating_add(16);
  Ok(FieldLines {
    input,
    pos,
    scratch: Scratch::Owned(std::vec![0u8; cap]),
  })
}
