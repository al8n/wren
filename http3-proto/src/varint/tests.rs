use super::*;

#[test]
fn rfc9000_appendix_a_vectors() {
  let cases: &[(u64, &[u8])] = &[
    (0, &[0x00]),
    (37, &[0x25]),
    (63, &[0x3f]),
    (64, &[0x40, 0x40]),
    (16383, &[0x7f, 0xff]),
    (16384, &[0x80, 0x00, 0x40, 0x00]),
    (1073741823, &[0xbf, 0xff, 0xff, 0xff]),
    (
      1073741824,
      &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
    ),
    (
      151288809941952652,
      &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
    ),
  ];
  for (val, bytes) in cases {
    let mut buf = [0u8; 8];
    let n = encode(*val, &mut buf).unwrap();
    assert_eq!(&buf[..n], *bytes, "encode {val}");
    let (consumed, decoded) = decode(bytes).unwrap();
    assert_eq!((consumed, decoded), (bytes.len(), *val), "decode {val}");
  }
}

#[test]
fn encode_rejects_small_buffer() {
  let mut buf = [0u8; 1];
  assert!(matches!(encode(64, &mut buf), Err(VarintError::Buffer(_))));
}

#[test]
fn decode_truncated_reports_needed() {
  assert!(matches!(decode(&[]), Err(VarintError::Truncated(t)) if t.needed() == 1));
  assert!(matches!(decode(&[0x40]), Err(VarintError::Truncated(t)) if t.needed() == 1));
}

#[test]
fn encode_rejects_too_large() {
  assert!(matches!(
    encode(1u64 << 62, &mut [0u8; 8]),
    Err(VarintError::TooLarge)
  ));
}

mod properties {
  use super::*;
  use proptest::prelude::*;
  proptest! {
    #[test]
    fn roundtrip(v in 0u64..=MAX) {
      let mut buf = [0u8; 8];
      let n = encode(v, &mut buf).unwrap();
      let (consumed, decoded) = decode(&buf[..n]).unwrap();
      prop_assert_eq!((consumed, decoded), (n, v));
    }
  }
}
