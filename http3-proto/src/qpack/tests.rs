use super::static_table::{STATIC_TABLE, find_name, find_name_value};

#[test]
fn static_table_has_99_entries() {
  assert_eq!(STATIC_TABLE.len(), 99);
}

#[test]
fn known_static_indices() {
  // Spot-check entries the CONNECT handshake uses + transcription anchors (RFC 9204 App. A).
  assert_eq!(STATIC_TABLE[0], (":authority", ""));
  assert_eq!(STATIC_TABLE[1], (":path", "/"));
  assert_eq!(STATIC_TABLE[15], (":method", "CONNECT"));
  assert_eq!(STATIC_TABLE[17], (":method", "GET"));
  assert_eq!(STATIC_TABLE[22], (":scheme", "http"));
  assert_eq!(STATIC_TABLE[23], (":scheme", "https"));
  assert_eq!(STATIC_TABLE[25], (":status", "200"));
  // End + tricky-value anchors to lock the full transcription.
  assert_eq!(
    STATIC_TABLE[73],
    ("access-control-allow-credentials", "FALSE")
  );
  assert_eq!(
    STATIC_TABLE[85],
    (
      "content-security-policy",
      "script-src 'none'; object-src 'none'; base-uri 'none'"
    )
  );
  assert_eq!(STATIC_TABLE[98], ("x-frame-options", "sameorigin"));
}

#[test]
fn lookups() {
  assert_eq!(find_name_value(":method", "CONNECT"), Some(15));
  assert_eq!(find_name(":authority"), Some(0));
  assert_eq!(find_name_value(":protocol", "websocket"), None); // not in static table
}

mod huffman_tests {
  use crate::qpack::{
    QpackError,
    huffman::{decode as huff_decode, encoded_len},
  };

  #[test]
  fn decode_rfc7541_example() {
    // RFC 7541 §C.4.1: "www.example.com" Huffman-encoded.
    let encoded = [
      0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    let mut out = [0u8; 32];
    let n = huff_decode(&encoded, &mut out).unwrap();
    assert_eq!(&out[..n], b"www.example.com");
  }

  #[test]
  fn decode_valid_short_with_padding() {
    // '0' is code 00000 (5 bits); 0x07 = 00000_111 → '0' then 3 all-ones pad bits.
    let mut out = [0u8; 4];
    let n = huff_decode(&[0x07], &mut out).unwrap();
    assert_eq!(&out[..n], b"0");
  }

  #[test]
  fn decode_rejects_bad_padding() {
    // Trailing 000 padding is not all-ones (RFC 7541 §5.2).
    assert!(huff_decode(&[0x00], &mut [0u8; 8]).is_err());
  }

  #[test]
  fn decode_rejects_too_small_output() {
    let encoded = [
      0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];
    assert!(matches!(
      huff_decode(&encoded, &mut [0u8; 4]),
      Err(QpackError::Buffer(_))
    ));
  }

  #[test]
  fn decode_empty_is_empty() {
    assert_eq!(huff_decode(&[], &mut [0u8; 4]).unwrap(), 0);
  }

  #[test]
  fn encoded_len_known() {
    assert_eq!(encoded_len(b"www.example.com"), 12);
  }

  #[test]
  fn decode_rejects_eos_symbol() {
    // 30 one-bits form the EOS code (0x3fffffff); an explicit EOS symbol in the
    // input is a decoding error (RFC 7541 §5.2).
    assert!(matches!(
      huff_decode(&[0xff, 0xff, 0xff, 0xff], &mut [0u8; 8]),
      Err(QpackError::HuffmanEos)
    ));
  }

  #[test]
  fn decode_rejects_overlong_padding() {
    // '0' (00000) followed by 11 one-bits of trailing padding (> 7 bits) is an
    // error (RFC 7541 §5.2).
    assert!(matches!(
      huff_decode(&[0x07, 0xff], &mut [0u8; 8]),
      Err(QpackError::HuffmanPadding)
    ));
  }
}
