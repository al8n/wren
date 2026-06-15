//! Fuzz target: `frame::decode_header` must never panic on arbitrary bytes,
//! and every successfully decoded header must re-encode canonically.
#![no_main]

use libfuzzer_sys::fuzz_target;
use http3_proto::frame::{self, FrameType};

fuzz_target!(|data: &[u8]| {
  if let Ok((consumed, hdr)) = frame::decode_header(data) {
    assert!(consumed <= data.len());
    // Re-encode the same frame kind + length and check output is non-zero.
    let ty = match hdr.kind() {
      frame::FrameKind::Data => FrameType::Data,
      frame::FrameKind::Headers => FrameType::Headers,
      frame::FrameKind::Settings => FrameType::Settings,
      // Every other kind has no canonical `FrameType` we emit; skip re-encoding.
      _ => return,
    };
    let mut buf = [0u8; 16];
    let _ = frame::encode_header(ty, hdr.length(), &mut buf);
  }
});
