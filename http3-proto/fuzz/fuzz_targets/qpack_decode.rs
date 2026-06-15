//! Fuzz target: QPACK field-section decoding must never panic on arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let mut scratch = [0u8; 4096];
  if let Ok(mut lines) = http3_proto::qpack::decode_field_section_into(data, &mut scratch) {
    while let Ok(Some(_)) = lines.next() {}
  }
});
