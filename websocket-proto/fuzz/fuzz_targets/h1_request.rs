//! Fuzz: ServerHandshake::handle must never panic, and a Complete view's
//! consumed offset must stay in bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use websocket_proto::handshake::h1::{ServerHandshake, ServerProgress};

fuzz_target!(|data: &[u8]| {
  let hs = ServerHandshake::new();
  if let Ok(ServerProgress::Request(view)) = hs.handle(data) {
    assert!(view.consumed() <= data.len());
    // Exercise the borrowed accessors.
    let _ = view.path();
    let _ = view.host();
    let _ = view.origin();
    let _ = view.subprotocols().count();
  }
});
