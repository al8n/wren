//! HTTP/3 frame layer (RFC 9114 §7.1): `[type][length][payload]`, where type
//! and length are QUIC varints. This module owns the *header* (type+length);
//! payloads are handled by the stream FSM (HEADERS via QPACK, DATA streamed).

use crate::{
  error::TruncatedDetail,
  varint::{self, VarintError},
};

// `as_str`/`IsVariant` (rust-type-conventions) are intentionally omitted on the
// frame enums: `FrameType`'s canonical projection is `code()`, `FrameKind::Other`
// collapses many wire types with no meaningful string slug, and no diagnostic
// consumer needs them yet. Add them if a human-readable frame name is later needed.
/// A frame type we emit.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameType {
  /// `DATA` (0x00) — tunnel payload.
  Data,
  /// `HEADERS` (0x01) — a QPACK-encoded field section.
  Headers,
  /// `SETTINGS` (0x04) — connection settings (control stream only).
  Settings,
}

impl FrameType {
  /// The wire type code.
  #[inline(always)]
  pub const fn code(self) -> u64 {
    match self {
      Self::Data => 0x00,
      Self::Headers => 0x01,
      Self::Settings => 0x04,
    }
  }
}

/// The classification of a decoded frame header.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrameKind {
  /// `DATA` (0x00).
  Data,
  /// `HEADERS` (0x01).
  Headers,
  /// `SETTINGS` (0x04).
  Settings,
  /// Any other type — reserved, GREASE, or known-but-unused; ignore the payload.
  Other,
}

/// A decoded frame header: its classification + payload length.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FrameHeader {
  kind: FrameKind,
  length: u64,
}

impl FrameHeader {
  /// The frame classification.
  #[inline(always)]
  pub const fn kind(&self) -> FrameKind {
    self.kind
  }

  /// The payload length in bytes.
  #[inline(always)]
  pub const fn length(&self) -> u64 {
    self.length
  }
}

/// A frame-layer error.
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Display, derive_more::From)]
#[non_exhaustive]
pub enum FrameError {
  /// The input ended mid-header.
  #[display("{_0}")]
  Truncated(TruncatedDetail),
  /// The output buffer was too small / a varint overflowed.
  #[display("{_0}")]
  Varint(VarintError),
}

/// Encodes a frame header (`type` + `length`) into `out`, returning bytes written.
#[inline]
pub fn encode_header(ty: FrameType, length: u64, out: &mut [u8]) -> Result<usize, FrameError> {
  let n0 = varint::encode(ty.code(), out)?;
  let out_len = out.len();
  // Unreachable in practice: `varint::encode` above wrote `n0` bytes, so
  // `out.len() >= n0` and this slice is always `Some`. Kept as a panic-free
  // fallback; the reported need is the full header size.
  let rest = out.get_mut(n0..).ok_or_else(|| {
    VarintError::Buffer(crate::error::BufferTooSmallDetail::new(
      n0.saturating_add(varint::len_of(length)),
      out_len,
    ))
  })?;
  let n1 = varint::encode(length, rest)?;
  // n0 and n1 are each ≤ 8 (max varint wire size); their sum cannot overflow usize.
  Ok(n0.saturating_add(n1))
}

/// Decodes a frame header from the front of `input`: (bytes consumed, header).
/// `Truncated` means "buffer more bytes and retry" (the type+length not yet whole).
#[inline]
pub fn decode_header(input: &[u8]) -> Result<(usize, FrameHeader), FrameError> {
  let (n0, ty) = map_varint(varint::decode(input))?;
  let rest = input.get(n0..).unwrap_or(&[]);
  let (n1, length) = map_varint(varint::decode(rest))?;
  let kind = match ty {
    0x00 => FrameKind::Data,
    0x01 => FrameKind::Headers,
    0x04 => FrameKind::Settings,
    _ => FrameKind::Other,
  };
  // n0 and n1 are each ≤ 8 (max varint wire size); their sum cannot overflow usize.
  Ok((n0.saturating_add(n1), FrameHeader { kind, length }))
}

// Map a varint Truncated through as a frame Truncated (so the FSM sees "need more").
#[inline]
fn map_varint(r: Result<(usize, u64), VarintError>) -> Result<(usize, u64), FrameError> {
  match r {
    Ok(v) => Ok(v),
    Err(VarintError::Truncated(t)) => Err(FrameError::Truncated(t)),
    Err(e) => Err(FrameError::Varint(e)),
  }
}

#[cfg(test)]
mod tests;
