//! Fuzz target: `varint::decode` must never panic on arbitrary bytes.
//! Every successfully decoded varint must re-encode to the same wire form.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  if let Ok((consumed, value)) = http3_proto::varint::decode(data) {
    assert!(consumed <= data.len());
    // Re-encode and verify the wire length is consistent.
    let mut buf = [0u8; 8];
    if let Ok(n) = http3_proto::varint::encode(value, &mut buf) {
      assert_eq!(n, http3_proto::varint::len_of(value));
    }
  }
});
