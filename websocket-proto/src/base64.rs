//! Minimal standard-alphabet base64 (RFC 4648 §4): encoding plus
//! `Sec-WebSocket-Key` format validation.
//!
//! The WebSocket handshake needs exactly this subset (RFC 6455 §4.1 /
//! §4.2.2). Decoding is never required — servers treat the client key as an
//! opaque string and clients re-derive the accept value by re-encoding — so
//! it is intentionally not implemented.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

/// Number of bytes [`encode`] writes for `input_len` input bytes, or `None`
/// on arithmetic overflow.
pub(crate) const fn encoded_len(input_len: usize) -> Option<usize> {
  match input_len.checked_add(2) {
    Some(n) => n.div_euclid(3).checked_mul(4),
    None => None,
  }
}

// The `0x3f` mask keeps the index below `ALPHABET.len()`, so the `None` arm is
// unreachable; the `Option` shape exists only to satisfy the no-indexing wall.
#[inline]
fn sextet(idx: u8) -> Option<u8> {
  ALPHABET.get(usize::from(idx & 0x3f)).copied()
}

/// Encodes `input` into `out`, returning the number of bytes written, or
/// `None` if `out` is too small (callers size buffers via [`encoded_len`]).
///
/// Slice patterns are used instead of `copy_from_slice`/indexing so every
/// access is statically panic-free.
pub(crate) fn encode(input: &[u8], out: &mut [u8]) -> Option<usize> {
  let needed = encoded_len(input.len())?;
  let out = out.get_mut(..needed)?;

  let mut groups = input.chunks_exact(3);
  // `needed` is exactly `ceil(len/3) * 4`, so `dsts` yields one full 4-byte
  // block per input group PLUS one trailing block for a non-empty remainder
  // (taken via `dsts.next()` below — `into_remainder()` would be empty).
  let mut dsts = out.chunks_exact_mut(4);
  for (group, dst) in (&mut groups).zip(&mut dsts) {
    let &[a, b, c] = group else { return None };
    let [d0, d1, d2, d3] = dst else { return None };
    *d0 = sextet(a >> 2)?;
    *d1 = sextet((a << 4) | (b >> 4))?;
    *d2 = sextet((b << 2) | (c >> 6))?;
    *d3 = sextet(c)?;
  }

  // `chunks_exact(3).remainder()` is 0..=2 bytes; the compiler cannot see
  // that bound, so the wildcard arm is required (and unreachable).
  match groups.remainder() {
    [] => {}
    &[a] => {
      let [d0, d1, d2, d3] = dsts.next()? else {
        return None;
      };
      *d0 = sextet(a >> 2)?;
      *d1 = sextet(a << 4)?;
      *d2 = PAD;
      *d3 = PAD;
    }
    &[a, b] => {
      let [d0, d1, d2, d3] = dsts.next()? else {
        return None;
      };
      *d0 = sextet(a >> 2)?;
      *d1 = sextet((a << 4) | (b >> 4))?;
      *d2 = sextet(b << 2)?;
      *d3 = PAD;
    }
    _ => return None,
  }
  Some(needed)
}

#[inline]
const fn in_alphabet(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Returns whether `key` has the exact shape of a `Sec-WebSocket-Key` value:
/// the base64 encoding of 16 bytes — 22 alphabet characters plus `==`
/// (RFC 6455 §4.1). Non-canonical trailing bits are accepted: they still
/// decode to 16 bytes, which is all the RFC requires.
pub(crate) fn is_valid_key(key: &[u8]) -> bool {
  if key.len() != crate::constants::SEC_WEBSOCKET_KEY_LEN {
    return false;
  }
  match key.split_at_checked(22) {
    Some((data, pad)) => pad == b"==" && data.iter().all(|&b| in_alphabet(b)),
    None => false,
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  fn encode_to_string(input: &[u8]) -> String {
    let mut buf = [0u8; 192];
    let n = encode(input, &mut buf).unwrap();
    core::str::from_utf8(&buf[..n]).unwrap().to_owned()
  }

  #[test]
  fn rfc4648_vectors() {
    assert_eq!(encode_to_string(b""), "");
    assert_eq!(encode_to_string(b"f"), "Zg==");
    assert_eq!(encode_to_string(b"fo"), "Zm8=");
    assert_eq!(encode_to_string(b"foo"), "Zm9v");
    assert_eq!(encode_to_string(b"foob"), "Zm9vYg==");
    assert_eq!(encode_to_string(b"fooba"), "Zm9vYmE=");
    assert_eq!(encode_to_string(b"foobar"), "Zm9vYmFy");
  }

  #[test]
  fn rfc6455_1_3_accept_digest() {
    // SHA-1("dGhlIHNhbXBsZSBub25jZQ==" + GUID), from RFC 6455 §1.3.
    let digest: [u8; 20] = [
      0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6, 0x46, 0x06, 0xcf, 0x38, 0x59,
      0x45, 0xb2, 0xbe, 0xc4, 0xea,
    ];
    assert_eq!(encode_to_string(&digest), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  }

  #[test]
  fn encoded_len_matches() {
    assert_eq!(encoded_len(0), Some(0));
    assert_eq!(encoded_len(1), Some(4));
    assert_eq!(encoded_len(2), Some(4));
    assert_eq!(encoded_len(3), Some(4));
    assert_eq!(encoded_len(4), Some(8));
    assert_eq!(encoded_len(16), Some(24));
    assert_eq!(encoded_len(20), Some(28));
    assert_eq!(encoded_len(usize::MAX), None); // checked_add overflows
    assert_eq!(encoded_len(usize::MAX - 1), None); // checked_add overflows
    assert_eq!(encoded_len(usize::MAX - 2), None); // checked_mul overflows
    assert_eq!(encoded_len(usize::MAX - 3), None); // checked_mul overflows
  }

  #[test]
  fn encode_rejects_small_buffer() {
    let mut buf = [0u8; 23];
    assert_eq!(encode(&[0u8; 16], &mut buf), None);
    let mut buf = [0u8; 24];
    assert_eq!(encode(&[0u8; 16], &mut buf), Some(24));
  }

  #[test]
  fn key_format_validation() {
    // base64 of 16 bytes: 22 alphabet chars + "==".
    assert!(is_valid_key(b"dGhlIHNhbXBsZSBub25jZQ=="));
    assert!(is_valid_key(b"AAAAAAAAAAAAAAAAAAAAAA=="));
    assert!(!is_valid_key(b""));
    assert!(!is_valid_key(b"dGhlIHNhbXBsZSBub25jZQ=")); // 23 bytes
    assert!(!is_valid_key(b"dGhlIHNhbXBsZSBub25jZQa==")); // 25 bytes
    assert!(!is_valid_key(b"dGhlIHNhbXBsZSBub25jZQ=A")); // bad padding
    assert!(!is_valid_key(b"dGhlIHNhbXBsZSBub25jZ.==")); // bad alphabet
    assert!(!is_valid_key(b"dGhlIHNhbXBsZSBub25jZQAA")); // no padding
  }

  mod properties {
    use super::*;
    use base64::Engine as _;
    use proptest::prelude::*;

    proptest! {
      #[test]
      fn matches_oracle(input in proptest::collection::vec(any::<u8>(), 0..96)) {
        let mut buf = [0u8; 192];
        let n = encode(&input, &mut buf).unwrap();
        let ours = core::str::from_utf8(&buf[..n]).unwrap();
        let oracle = base64::engine::general_purpose::STANDARD.encode(&input);
        prop_assert_eq!(ours, oracle.as_str());
      }

      #[test]
      fn every_encoded_16_byte_nonce_is_a_valid_key(nonce in any::<[u8; 16]>()) {
        let mut buf = [0u8; 24];
        let n = encode(&nonce, &mut buf).unwrap();
        prop_assert_eq!(n, 24);
        prop_assert!(is_valid_key(&buf));
      }
    }
  }
}
