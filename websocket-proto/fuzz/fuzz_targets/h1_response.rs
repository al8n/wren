//! Fuzz: ClientHandshake::handle must never panic on arbitrary response
//! bytes (fixed deterministic nonce).
#![no_main]

use libfuzzer_sys::fuzz_target;
use websocket_proto::handshake::h1::{ClientHandshake, ClientOptions, ClientProgress};

struct ZeroRng;

impl rand_core::TryRng for ZeroRng {
  type Error = core::convert::Infallible;
  fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
    Ok(0)
  }
  fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
    Ok(0)
  }
  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
    dest.fill(0);
    Ok(())
  }
}

fuzz_target!(|data: &[u8]| {
  let options = ClientOptions::new("example.com", "/").with_subprotocols(&["chat"]);
  let mut hs = ClientHandshake::new(options, &mut ZeroRng).expect("static options are valid");
  // The connection reads a response only for a handshake it opened.
  let mut request = [0u8; 512];
  hs.encode_request(&mut request)
    .expect("static options encode");
  // Every outcome that consumed a head says how far it reached, and that can
  // never be past what was offered.
  match hs.handle(data) {
    Ok(ClientProgress::Complete(done)) => assert!(done.consumed() <= data.len()),
    Ok(ClientProgress::Interim { consumed, .. }) => assert!(consumed <= data.len()),
    _ => {}
  }
});
