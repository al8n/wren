//! Fuzz target: `FrameHeader::decode` must never panic on arbitrary bytes,
//! and every successfully decoded header must re-encode canonically and
//! re-decode to the identical header.
#![no_main]

use libfuzzer_sys::fuzz_target;
use websocket_proto::frame::{Decoded, FrameHeader};

fuzz_target!(|data: &[u8]| {
  match FrameHeader::decode(data) {
    Ok(Decoded::Complete(d)) => {
      let header = d.header();
      assert!(d.consumed() <= data.len());
      let mut buf = [0u8; 14];
      let n = header.encode(&mut buf).expect("decoded header must re-encode");
      // The wire form was canonical (decode enforces it), so the re-encoding
      // must be byte-identical to what was consumed.
      assert_eq!(&buf[..n], &data[..d.consumed()], "re-encode differs from wire");
      match FrameHeader::decode(&buf[..n]).expect("re-encoded header must decode") {
        Decoded::Complete(d2) => {
          assert_eq!(d2.header(), header);
          assert_eq!(d2.consumed(), n);
        }
        Decoded::Incomplete(_) => panic!("re-encoded header decoded as incomplete"),
        _ => {}
      }
    }
    Ok(Decoded::Incomplete(_)) | Ok(_) | Err(_) => {}
  }
});
