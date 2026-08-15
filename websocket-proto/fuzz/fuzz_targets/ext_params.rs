//! Fuzz: the RFC 7692 param grammar never panics; whatever the server
//! accepts, the client accepts back, and both land on identical params.
#![no_main]

use libfuzzer_sys::fuzz_target;
use websocket_proto::negotiation::{
  DeflateOffer, ServerDeflateConfig, accept_deflate_offer, parse_deflate_response,
};

fuzz_target!(|data: &[u8]| {
  // The field value is raw bytes: RFC 9110 §5.5 admits `obs-text`, so the
  // input is fed in whole rather than through a UTF-8 gate.

  // Client-side parse of an arbitrary response value must never panic.
  let offer = DeflateOffer::new();
  let _ = parse_deflate_response([data], &offer);

  // Server-side scan of an arbitrary offer value must never panic; on accept,
  // the emitted response must round-trip through client validation to the
  // SAME params.
  if let Some((params, response)) = accept_deflate_offer([data], &ServerDeflateConfig::new()) {
    let mut buf = [0u8; 256];
    let n = response.write(&mut buf).expect("response fits 256 bytes");
    let text = &buf[..n];
    // The server accepted the client's offer params, so validate against an
    // equivalent offer: reconstruct one carrying the same declarations.
    let mut check = DeflateOffer::new();
    if params.server_no_context_takeover() {
      check = check.with_server_no_context_takeover(true);
    }
    if params.client_no_context_takeover() {
      check = check.with_client_no_context_takeover(true);
    }
    let client_params = parse_deflate_response([text], &check).expect("round trip");
    assert_eq!(
      client_params.server_max_window_bits(),
      params.server_max_window_bits()
    );
    assert_eq!(
      client_params.client_max_window_bits(),
      params.client_max_window_bits()
    );
  }
});
