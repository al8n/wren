//! HPACK/QPACK Huffman coding (RFC 7541 Appendix B). Decode is mandatory
//! (peers may Huffman-code string literals); `encoded_len` sizes the encoder's
//! output. The decoder is a panic-free MSB-first canonical bit walk.

// Transient: `decode` and `encoded_len` are consumed by the QPACK field-section
// decoder/encoder in later tasks; until a production caller exists they are
// reachable only from tests, so dead_code is silenced for now.
#![allow(dead_code)]

use super::QpackError;
use crate::error::BufferTooSmallDetail;
mod generated;

use generated::{CODE_LENGTHS, HUFFMAN_ROOT, HuffmanStep};

/// The number of bytes `input` occupies Huffman-encoded: the sum of the per-byte
/// code lengths, rounded up to whole bytes.
pub fn encoded_len(input: &[u8]) -> usize {
  let bits = input.iter().fold(0usize, |acc, &byte| {
    acc.saturating_add(
      CODE_LENGTHS
        .get(usize::from(byte))
        .map_or(0, |&len| usize::from(len)),
    )
  });
  bits.div_ceil(8)
}

/// Decodes a Huffman-coded byte string from `input` into `out`, returning the
/// number of bytes written. Rejects the EOS symbol, padding longer than 7 bits,
/// and non-all-ones padding (RFC 7541 §5.2), and an over-long unmatched code.
pub fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, QpackError> {
  let mut acc: u32 = 0;
  let mut nbits: u32 = 0;
  let mut written: usize = 0;
  let mut node = HUFFMAN_ROOT;
  for &byte in input {
    for shift in (0..8u32).rev() {
      let bit = u32::from(byte.wrapping_shr(shift) & 1);
      acc = acc.wrapping_shl(1) | bit;
      nbits = nbits.saturating_add(1);
      if nbits > 30 {
        // No code is longer than 30 bits (EOS); an unmatched 31-bit run is invalid.
        return Err(QpackError::HuffmanInvalid);
      }
      match generated::step(node, bit) {
        HuffmanStep::Node(next) => node = next,
        HuffmanStep::Symbol(sym) => {
          if sym == 256 {
            return Err(QpackError::HuffmanEos);
          }
          let out_len = out.len();
          let slot = out
            .get_mut(written)
            .ok_or_else(|| BufferTooSmallDetail::new(written.saturating_add(1), out_len))?;
          // sym is 0..=255 here (256 handled above), so this conversion never fails.
          *slot = u8::try_from(sym).map_err(|_| QpackError::HuffmanInvalid)?;
          written = written.saturating_add(1);
          node = HUFFMAN_ROOT;
          acc = 0;
          nbits = 0;
        }
        HuffmanStep::Invalid => return Err(QpackError::HuffmanInvalid),
      }
    }
  }
  // Trailing bits must be valid EOS-prefix padding: at most 7 bits, all ones.
  if nbits > 7 {
    return Err(QpackError::HuffmanPadding);
  }
  if nbits > 0 && acc.count_ones() != nbits {
    return Err(QpackError::HuffmanPadding);
  }
  Ok(written)
}
