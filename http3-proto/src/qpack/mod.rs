//! Static-table-only QPACK (RFC 9204): field-section encode/decode with the
//! dynamic table disabled. (Encoder/decoder land in later tasks.)

mod huffman;
pub mod static_table;

use crate::error::BufferTooSmallDetail;

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
}

#[cfg(test)]
mod tests;
