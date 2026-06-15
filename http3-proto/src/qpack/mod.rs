//! Static-table-only QPACK (RFC 9204): field-section encode/decode with the
//! dynamic table disabled. (Encoder/decoder/Huffman land in later tasks.)
pub mod static_table;

#[cfg(test)]
mod tests;
