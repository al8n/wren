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
  let hs = ClientHandshake::new(options, &mut ZeroRng).expect("static options are valid");
  if let Ok(ClientProgress::Complete(done)) = hs.handle(data) {
    assert!(done.consumed() <= data.len());
  }
});
