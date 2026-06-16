//! Static-table-only QPACK (RFC 9204): field-section encode/decode with the
//! dynamic table disabled.

mod decode;
mod encode;
mod huffman;
mod int;
pub mod static_table;

#[cfg(any(feature = "std", feature = "alloc"))]
pub use decode::decode_field_section;
pub use decode::{FieldLines, Pair, decode_field_section_into};
pub use encode::{EncodeError, encode_field_section, encode_field_section_from};

use crate::error::{BufferTooSmallDetail, TruncatedDetail};

/// A QPACK error (field-section coding + Huffman string literals).
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum QpackError {
  /// The output buffer was too small.
  #[error(transparent)]
  Buffer(#[from] BufferTooSmallDetail),
  /// Huffman padding was longer than 7 bits or not all-ones (RFC 7541 §5.2).
  #[error("invalid huffman padding")]
  HuffmanPadding,
  /// The Huffman EOS symbol appeared in the input (RFC 7541 §5.2).
  #[error("huffman eos symbol in input")]
  HuffmanEos,
  /// No valid Huffman code matched (incomplete or overlong sequence).
  #[error("invalid huffman code")]
  HuffmanInvalid,
  /// A prefixed integer was malformed or overflowed.
  #[error("invalid qpack integer")]
  BadInteger,
  /// The input ended mid-field-line.
  #[error(transparent)]
  Truncated(#[from] TruncatedDetail),
  /// A dynamic-table reference (or non-zero Required Insert Count / Base) was
  /// used; this decoder is static-table-only.
  #[error("qpack dynamic table reference rejected")]
  DynamicReference,
  /// A static index was out of range (>= 99).
  #[error("qpack static index out of range")]
  BadStaticIndex,
  /// A decoded string was not valid UTF-8.
  #[error("qpack string is not valid utf-8")]
  InvalidString,
}

impl QpackError {
  /// Maps any QPACK error to the connection-level HTTP/3 error code
  /// (all decompression failures collapse to `QPACK_DECOMPRESSION_FAILED`).
  pub const fn to_h3(self) -> crate::error::H3Error {
    crate::error::H3Error::QpackDecompressionFailed
  }
}

#[cfg(test)]
mod tests;
