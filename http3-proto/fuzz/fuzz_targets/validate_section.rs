//! Fuzz: the role-aware semantic validator over arbitrary decoded field sections
//! must never panic — any `Result` is acceptable, only a panic is a failure.
#![no_main]

use http3_proto::{MessageKind, qpack::decode_field_section_into, validate::validate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // Each decoded `FieldLines` borrows its scratch for its whole lifetime and a
  // validate pass consumes the (lending) iterator, so re-decode the same bytes
  // per kind into a fresh scratch — the borrows then never overlap.
  for kind in [
    MessageKind::Request,
    MessageKind::Response,
    MessageKind::Interim,
    MessageKind::Trailers,
  ] {
    let mut scratch = [0u8; 4096];
    if let Ok(mut hs) = decode_field_section_into(data, &mut scratch) {
      let _ = validate(kind, &mut hs);
    }
  }
  // Also exercise raw iteration to completion (decode-only path, no validation).
  let mut scratch = [0u8; 4096];
  if let Ok(mut hs) = decode_field_section_into(data, &mut scratch) {
    while let Ok(Some(_)) = hs.next() {}
  }
});
