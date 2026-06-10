//! Payload (un)masking (RFC 6455 §5.3): XOR with a four-byte key, cycling.
//!
//! Masking is an involution — the same call masks and unmasks. The `offset`
//! parameter is the number of payload bytes already transformed, so chunked
//! payloads resume mid-frame: `mask(rest, key, bytes_done)` continues where
//! the previous call stopped (only `offset % 4` matters).

/// XORs `payload` in place with `key`, starting at key phase `offset % 4`.
pub fn mask(payload: &mut [u8], key: [u8; 4], offset: u64) {
  // `& 3` bounds the phase below the key length, so `get` never misses;
  // the Option dance exists only to satisfy the no-indexing wall.
  let phase = usize::try_from(offset & 3).unwrap_or(0);
  for (i, byte) in payload.iter_mut().enumerate() {
    let idx = i.wrapping_add(phase) & 3;
    if let Some(k) = key.get(idx) {
      *byte ^= *k;
    }
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  const RFC_KEY: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];

  #[test]
  fn rfc6455_5_7_hello_vector() {
    // §5.7: masked "Hello" payload bytes are 7f 9f 4d 51 58 under key 37 fa 21 3d.
    let mut payload = *b"Hello";
    mask(&mut payload, RFC_KEY, 0);
    assert_eq!(payload, [0x7F, 0x9F, 0x4D, 0x51, 0x58]);
    // Masking is an involution: applying it again restores the plaintext.
    mask(&mut payload, RFC_KEY, 0);
    assert_eq!(&payload, b"Hello");
  }

  #[test]
  fn rolling_offset_resumes_mid_payload() {
    // Masking the whole payload at once must equal masking it in pieces
    // with the running offset.
    let plain = b"The quick brown fox jumps over the lazy dog";
    let mut whole = *plain;
    mask(&mut whole, RFC_KEY, 0);

    for cut in 0..=plain.len() {
      let mut pieces = *plain;
      let (a, b) = pieces.split_at_mut(cut);
      mask(a, RFC_KEY, 0);
      mask(b, RFC_KEY, cut as u64);
      assert_eq!(pieces, whole, "cut at {cut}");
    }
  }

  #[test]
  fn offset_only_matters_modulo_four() {
    let mut a = *b"abcdefgh";
    let mut b = *b"abcdefgh";
    mask(&mut a, RFC_KEY, 3);
    mask(&mut b, RFC_KEY, 7);
    assert_eq!(a, b);
    let mut c = *b"abcdefgh";
    mask(&mut c, RFC_KEY, u64::MAX); // phase 3: u64::MAX & 3 == 3
    assert_eq!(c, a);
  }

  #[test]
  fn empty_and_all_zero_key() {
    let mut empty: [u8; 0] = [];
    mask(&mut empty, RFC_KEY, 5); // must not panic
    let mut data = *b"data";
    mask(&mut data, [0, 0, 0, 0], 1); // zero key is identity
    assert_eq!(&data, b"data");
  }

  mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
      /// Involution at any phase.
      #[test]
      fn mask_twice_is_identity(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        key in any::<[u8; 4]>(),
        offset in any::<u64>(),
      ) {
        let mut masked = data.clone();
        mask(&mut masked, key, offset);
        mask(&mut masked, key, offset);
        prop_assert_eq!(masked, data);
      }

      /// Chunked == whole, for arbitrary multi-way splits.
      #[test]
      fn split_anywhere_equals_whole(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        key in any::<[u8; 4]>(),
        cuts in proptest::collection::vec(any::<u16>(), 0..6),
      ) {
        let mut whole = data.clone();
        mask(&mut whole, key, 0);

        let mut points: Vec<usize> =
          cuts.iter().map(|&c| usize::from(c) % (data.len() + 1)).collect();
        points.sort_unstable();
        points.dedup();

        let mut pieces = data.clone();
        let mut start = 0usize;
        for &p in points.iter().chain(core::iter::once(&data.len())) {
          mask(&mut pieces[start..p], key, start as u64);
          start = p;
        }
        prop_assert_eq!(pieces, whole);
      }
    }
  }
}
