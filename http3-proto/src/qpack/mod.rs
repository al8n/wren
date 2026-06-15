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
pub use encode::encode_field_section;

use crate::error::{BufferTooSmallDetail, TruncatedDetail};

/// A QPACK error (field-section coding + Huffman string literals).
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Display, derive_more::From)]
#[non_exhaustive]
pub enum QpackError {
  /// The output buffer was too small.
  #[display("{_0}")]
  Buffer(BufferTooSmallDetail),
  /// Huffman padding was longer than 7 bits or not all-ones (RFC 7541 §5.2).
  #[display("invalid huffman padding")]
  HuffmanPadding,
  /// The Huffman EOS symbol appeared in the input (RFC 7541 §5.2).
  #[display("huffman eos symbol in input")]
  HuffmanEos,
  /// No valid Huffman code matched (incomplete or overlong sequence).
  #[display("invalid huffman code")]
  HuffmanInvalid,
  /// A prefixed integer was malformed or overflowed.
  #[display("invalid qpack integer")]
  BadInteger,
  /// The input ended mid-field-line.
  #[display("{_0}")]
  Truncated(TruncatedDetail),
  /// A dynamic-table reference (or non-zero Required Insert Count / Base) was
  /// used; this decoder is static-table-only.
  #[display("qpack dynamic table reference rejected")]
  DynamicReference,
  /// A static index was out of range (>= 99).
  #[display("qpack static index out of range")]
  BadStaticIndex,
  /// A decoded string was not valid UTF-8.
  #[display("qpack string is not valid utf-8")]
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
