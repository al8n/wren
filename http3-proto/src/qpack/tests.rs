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

mod int_tests {
  use crate::qpack::{QpackError, int::encode_int};

  #[test]
  fn rfc7541_5_1_1_example() {
    // 1337 with a 5-bit prefix, zero flags → [0x1f, 0x9a, 0x0a].
    let mut buf = [0u8; 8];
    let n = encode_int(&mut buf, 0, 1337, 5, 0x00).unwrap();
    assert_eq!(&buf[..n], &[0x1f, 0x9a, 0x0a]);
  }

  #[test]
  fn small_value_fits_prefix() {
    let mut buf = [0u8; 8];
    let n = encode_int(&mut buf, 0, 10, 5, 0x00).unwrap();
    assert_eq!(&buf[..n], &[0x0a]);
  }

  #[test]
  fn flags_preserved() {
    // index 15, 6-bit prefix, indexed-static flags 0b11 → 0xcf.
    let mut buf = [0u8; 8];
    let n = encode_int(&mut buf, 0, 15, 6, 0b1100_0000).unwrap();
    assert_eq!(&buf[..n], &[0xcf]);
  }

  #[test]
  fn value_equal_to_max_spills() {
    // 31 == 2^5-1 is NOT < max, so it spills: first byte 0x1f, final byte 0x00.
    let mut buf = [0u8; 8];
    let n = encode_int(&mut buf, 0, 31, 5, 0x00).unwrap();
    assert_eq!(&buf[..n], &[0x1f, 0x00]);
  }

  #[test]
  fn writes_at_offset() {
    let mut buf = [0xaau8; 8];
    let end = encode_int(&mut buf, 2, 10, 5, 0x00).unwrap();
    assert_eq!(end, 3);
    assert_eq!(buf[2], 0x0a);
    assert_eq!(buf[0], 0xaa); // untouched
  }

  #[test]
  fn rejects_small_buffer() {
    assert!(matches!(
      encode_int(&mut [0u8; 1], 0, 1337, 5, 0),
      Err(QpackError::Buffer(_))
    ));
  }
}

mod encode_tests {
  use crate::qpack::encode_field_section;

  #[test]
  fn encodes_indexed_static_line() {
    let mut buf = [0u8; 16];
    let n = encode_field_section(core::iter::once((":method", "CONNECT")), &mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x00, 0x00, 0xcf]); // prefix + indexed static #15
  }

  #[test]
  fn encodes_literal_with_name_ref() {
    // :path has static name index 1; "/chat" is a literal (raw) value.
    let mut buf = [0u8; 32];
    let n = encode_field_section(core::iter::once((":path", "/chat")), &mut buf).unwrap();
    assert_eq!(
      &buf[..n],
      &[0x00, 0x00, 0x51, 0x05, b'/', b'c', b'h', b'a', b't']
    );
  }

  #[test]
  fn encodes_literal_with_literal_name() {
    // "x" is not in the static table → literal name (raw); "yz" literal value.
    let mut buf = [0u8; 32];
    let n = encode_field_section(core::iter::once(("x", "yz")), &mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x00, 0x00, 0x21, b'x', 0x02, b'y', b'z']);
  }

  #[test]
  fn encodes_value_length_continuation() {
    // 130-byte value → 7-bit length prefix spills: 0x7f, 0x03.
    let value = [b'a'; 130];
    let value_str = core::str::from_utf8(&value).unwrap();
    let mut buf = [0u8; 160];
    let n = encode_field_section(core::iter::once((":authority", value_str)), &mut buf).unwrap();
    assert_eq!(&buf[..4], &[0x00, 0x00, 0x50, 0x7f]); // prefix + name-ref idx0 + len hi
    assert_eq!(buf[4], 0x03); // len continuation
    assert_eq!(&buf[5..n], &value); // the 130 bytes
    assert_eq!(n, 135);
  }

  #[test]
  fn rejects_small_buffer() {
    let mut buf = [0u8; 2]; // only the prefix fits
    assert!(encode_field_section(core::iter::once((":method", "CONNECT")), &mut buf).is_err());
  }

  #[test]
  fn encodes_indexed_line_with_prefix_spill() {
    // ":status" "100" is static index 63 → the 6-bit indexed prefix spills:
    // first byte 0b1100_0000 | 63 = 0xff, then the 0x00 continuation.
    let mut buf = [0u8; 16];
    let n = encode_field_section(core::iter::once((":status", "100")), &mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x00, 0x00, 0xff, 0x00]);
  }

  #[test]
  fn encodes_name_ref_with_prefix_spill() {
    // ":scheme" name is static index 22; "ftp" is a literal value. The 4-bit
    // name-ref prefix spills: 0b0101_0000 | 15 = 0x5f, then 22-15 = 0x07.
    let mut buf = [0u8; 16];
    let n = encode_field_section(core::iter::once((":scheme", "ftp")), &mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x00, 0x00, 0x5f, 0x07, 0x03, b'f', b't', b'p']);
  }
}
