use super::static_table::{STATIC_TABLE_LEN, entry, find_name, find_name_value};

#[test]
fn static_table_has_99_entries() {
  assert_eq!(STATIC_TABLE_LEN, 99);
  assert!(entry(98).is_some());
  assert_eq!(entry(99), None);
}

#[test]
fn known_static_indices() {
  // Spot-check entries the CONNECT handshake uses + transcription anchors (RFC 9204 App. A).
  assert_eq!(entry(0), Some((":authority", "")));
  assert_eq!(entry(1), Some((":path", "/")));
  assert_eq!(entry(15), Some((":method", "CONNECT")));
  assert_eq!(entry(17), Some((":method", "GET")));
  assert_eq!(entry(22), Some((":scheme", "http")));
  assert_eq!(entry(23), Some((":scheme", "https")));
  assert_eq!(entry(25), Some((":status", "200")));
  // End + tricky-value anchors to lock the full transcription.
  assert_eq!(
    entry(73),
    Some(("access-control-allow-credentials", "FALSE"))
  );
  assert_eq!(
    entry(85),
    Some((
      "content-security-policy",
      "script-src 'none'; object-src 'none'; base-uri 'none'"
    ))
  );
  assert_eq!(entry(98), Some(("x-frame-options", "sameorigin")));
  // RFC 9204 App. A values verified against quic-go's production table and the
  // RFC 9204 HTML: indices 52, 57, 58 DO contain a space after each semicolon.
  // Index 54 ("text/plain;charset=utf-8") has NO space — that is also correct.
  assert_eq!(
    entry(52),
    Some(("content-type", "text/html; charset=utf-8"))
  );
  assert_eq!(
    entry(54),
    Some(("content-type", "text/plain;charset=utf-8"))
  );
  assert_eq!(
    entry(57),
    Some((
      "strict-transport-security",
      "max-age=31536000; includesubdomains"
    ))
  );
  assert_eq!(
    entry(58),
    Some((
      "strict-transport-security",
      "max-age=31536000; includesubdomains; preload"
    ))
  );
  assert_eq!(entry(31), Some(("accept-encoding", "gzip, deflate, br")));
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

mod decode_tests {
  use crate::qpack::{QpackError, decode_field_section_into, encode_field_section};

  #[test]
  fn errors_map_to_qpack_decompression_failed() {
    // Every QPACK error collapses to QPACK_DECOMPRESSION_FAILED (0x0200).
    assert_eq!(QpackError::DynamicReference.to_h3().code(), 0x0200);
    assert_eq!(QpackError::BadStaticIndex.to_h3().code(), 0x0200);
    assert_eq!(QpackError::InvalidString.to_h3().code(), 0x0200);
  }

  #[test]
  fn decodes_indexed_static() {
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&[0x00, 0x00, 0xcf], &mut sc).unwrap();
    let p = d.next().unwrap().unwrap();
    assert_eq!((p.name(), p.value()), (":method", "CONNECT"));
    assert!(d.next().unwrap().is_none());
  }

  #[test]
  fn decodes_static_section_with_nonzero_positive_base() {
    // RFC 9204 §4.5.1.2 permits any Base when the section has no dynamic-table
    // references. RIC=0, Sign=0, Delta Base=5, then indexed static #15.
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&[0x00, 0x05, 0xcf], &mut sc).unwrap();
    let p = d.next().unwrap().unwrap();
    assert_eq!((p.name(), p.value()), (":method", "CONNECT"));
    assert!(d.next().unwrap().is_none());
  }

  #[test]
  fn decodes_literal_name_ref_raw_value() {
    let bytes = [0x00, 0x00, 0x51, 0x05, b'/', b'c', b'h', b'a', b't'];
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    let p = d.next().unwrap().unwrap();
    assert_eq!((p.name(), p.value()), (":path", "/chat"));
    assert!(d.next().unwrap().is_none());
  }

  #[test]
  fn decodes_literal_literal_name_raw() {
    let bytes = [0x00, 0x00, 0x21, b'x', 0x02, b'y', b'z'];
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    let p = d.next().unwrap().unwrap();
    assert_eq!((p.name(), p.value()), ("x", "yz"));
    assert!(d.next().unwrap().is_none());
  }

  #[test]
  fn decodes_huffman_value() {
    // name-ref :authority (idx 0) + value Huffman("www.example.com") (H=1, len 12).
    let bytes = [
      0x00, 0x00, 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
      0xff,
    ];
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    let p = d.next().unwrap().unwrap();
    assert_eq!((p.name(), p.value()), (":authority", "www.example.com"));
    assert!(d.next().unwrap().is_none());
  }

  #[test]
  fn rejects_nonzero_required_insert_count() {
    assert!(matches!(
      decode_field_section_into(&[0x01, 0x00], &mut [0u8; 8]),
      Err(QpackError::DynamicReference)
    ));
  }

  #[test]
  fn rejects_dynamic_indexed_reference() {
    // Indexed with T=0 (dynamic) → reject.
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&[0x00, 0x00, 0x80], &mut sc).unwrap();
    assert!(matches!(d.next(), Err(QpackError::DynamicReference)));
  }

  #[test]
  fn rejects_post_base_representation() {
    // 0x00 field line = 0000_0000 → literal post-base name ref → dynamic.
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&[0x00, 0x00, 0x00], &mut sc).unwrap();
    assert!(matches!(d.next(), Err(QpackError::DynamicReference)));
  }

  #[test]
  fn decodes_huffman_name_literal() {
    // Literal-literal-name with H=1: name Huffman("custom-key") + raw value "v".
    // namelen=8 spills the 3-bit prefix (max 7): first byte 0b0010_1111 = 0x2f
    // (type 001, H, prefix all-ones) then continuation 8-7 = 0x01; the 8 Huffman
    // bytes encode "custom-key" (RFC 7541 §C.3.1).
    let bytes = [
      0x00, 0x00, // prefix
      0x2f, 0x01, // 0 0 1 N=0 H=1 namelen=8 (spilled)
      0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, // Huffman("custom-key")
      0x01, b'v', // value: H=0 len=1 "v"
    ];
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    let p = d.next().unwrap().unwrap();
    assert_eq!((p.name(), p.value()), ("custom-key", "v"));
    assert!(d.next().unwrap().is_none());
  }

  #[test]
  fn decodes_huffman_name_and_value() {
    // Both name and value Huffman → exercises the two-disjoint-scratch path.
    // name Huffman("custom-key") (8 bytes, namelen spills to 0x2f,0x01), value
    // Huffman("custom-value") (9 bytes, H=1 len=9 → 0b1000_1001 = 0x89).
    let bytes = [
      0x00, 0x00, // prefix
      0x2f, 0x01, // name: H=1 namelen=8 (spilled)
      0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, // Huffman("custom-key")
      0x89, // value: H=1 len=9
      0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf, // Huffman("custom-value")
    ];
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    let p = d.next().unwrap().unwrap();
    assert_eq!((p.name(), p.value()), ("custom-key", "custom-value"));
    assert!(d.next().unwrap().is_none());
  }

  #[test]
  fn rejects_truncated_value() {
    // name-ref :authority idx0, value claims len 5 but only 2 bytes follow.
    let bytes = [0x00, 0x00, 0x50, 0x05, b'a', b'b'];
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    assert!(matches!(d.next(), Err(QpackError::Truncated(_))));
  }

  #[test]
  fn rejects_static_index_out_of_range() {
    // Indexed static with index 99 (one past the table): 0b1100_0000 | 63 = 0xff
    // spills, then 99-63 = 36 = 0x24.
    let bytes = [0x00, 0x00, 0xff, 0x24];
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    assert!(matches!(d.next(), Err(QpackError::BadStaticIndex)));
  }

  #[test]
  fn huffman_value_scratch_too_small() {
    // Same as decodes_huffman_value but a 4-byte scratch cannot hold the 15-byte
    // decoded "www.example.com" → the huffman::decode buffer error propagates.
    let bytes = [
      0x00, 0x00, 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
      0xff,
    ];
    let mut sc = [0u8; 4];
    let mut d = decode_field_section_into(&bytes, &mut sc).unwrap();
    assert!(matches!(d.next(), Err(QpackError::Buffer(_))));
  }

  #[test]
  fn empty_section_yields_nothing() {
    let mut sc = [0u8; 8];
    let mut d = decode_field_section_into(&[0x00, 0x00], &mut sc).unwrap();
    assert!(d.next().unwrap().is_none());
  }

  // Uses `Vec`/`String`, so it only compiles on the std / alloc tiers; the
  // stack-only `roundtrip_connect_request_no_alloc` below covers the bare tier.
  #[cfg(any(feature = "std", feature = "alloc"))]
  #[test]
  fn roundtrip_connect_request() {
    let headers = [
      (":method", "CONNECT"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "example.com"),
      (":protocol", "websocket"),
      ("sec-websocket-protocol", "chat"),
    ];
    let mut buf = [0u8; 256];
    let n = encode_field_section(headers.iter().copied(), &mut buf).unwrap();
    let mut sc = [0u8; 256];
    let mut d = decode_field_section_into(&buf[..n], &mut sc).unwrap();
    let mut got: std::vec::Vec<(std::string::String, std::string::String)> = std::vec::Vec::new();
    while let Some(p) = d.next().unwrap() {
      got.push((p.name().into(), p.value().into()));
    }
    let want: std::vec::Vec<_> = headers.iter().map(|&(k, v)| (k.into(), v.into())).collect();
    assert_eq!(got, want);
  }

  // Same oracle as `roundtrip_connect_request`, but stack-only so it runs on the
  // bare `no_std` tier (no `Vec`/`String`).
  #[test]
  fn roundtrip_connect_request_no_alloc() {
    let headers = [
      (":method", "CONNECT"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "example.com"),
      (":protocol", "websocket"),
      ("sec-websocket-protocol", "chat"),
    ];
    let mut buf = [0u8; 256];
    let n = encode_field_section(headers.iter().copied(), &mut buf).unwrap();
    let mut sc = [0u8; 256];
    let mut d = decode_field_section_into(&buf[..n], &mut sc).unwrap();
    let mut i = 0;
    while let Some(p) = d.next().unwrap() {
      assert_eq!((p.name(), p.value()), headers[i]);
      i += 1;
    }
    assert_eq!(i, headers.len());
  }

  #[test]
  fn rejects_dynamic_name_ref() {
    // Literal-name-ref with T=0 (0x40) references the dynamic table → reject.
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&[0x00, 0x00, 0x40], &mut sc).unwrap();
    assert!(matches!(d.next(), Err(QpackError::DynamicReference)));
  }

  #[test]
  fn rejects_indexed_post_base() {
    // Indexed Post-Base (0001xxxx, here 0x10) is a dynamic representation → reject.
    let mut sc = [0u8; 64];
    let mut d = decode_field_section_into(&[0x00, 0x00, 0x10], &mut sc).unwrap();
    assert!(matches!(d.next(), Err(QpackError::DynamicReference)));
  }

  #[test]
  fn rejects_nonzero_base_sign() {
    // RIC=0, then Sign=1/DeltaBase=0 (0x80) → negative Base → reject.
    assert!(matches!(
      decode_field_section_into(&[0x00, 0x80], &mut [0u8; 8]),
      Err(QpackError::DynamicReference)
    ));
  }
}
