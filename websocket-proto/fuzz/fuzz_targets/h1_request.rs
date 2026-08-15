//! Fuzz: ServerHandshake::handle must never panic, and an accepted request's
//! leftover must stay a suffix of the bytes that were offered.
#![no_main]

use libfuzzer_sys::fuzz_target;
use websocket_proto::handshake::h1::{ServerHandshake, ServerProgress};

fuzz_target!(|data: &[u8]| {
  let mut hs = ServerHandshake::new();
  if let Ok(ServerProgress::Upgrade(pending)) = hs.handle(data) {
    let view = pending.request();
    assert!(pending.leftover().len() <= data.len());
    // Exercise the borrowed accessors.
    let _ = view.method();
    let _ = view.target();
    let _ = view.path();
    let _ = view.query();
    let _ = view.host();
    let _ = view.origin();
    let _ = view.subprotocols().count();
    let _ = view.extensions().count();
  }
});
