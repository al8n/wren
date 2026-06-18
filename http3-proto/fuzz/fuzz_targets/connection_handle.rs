//! Fuzz: arbitrary bytes on every stream path of the Connection state machine
//! must never panic, and terminal state must be terminal. Also drives the
//! general request/response API (`open_request` / `send_data_on` / `send_response`)
//! with arbitrary-derived headers so the encode + guard paths are fuzzed too.
#![no_main]

use http3_proto::{
  Client, Connection, Server,
  event::{StreamId, StreamRole},
};
use libfuzzer_sys::fuzz_target;

// Peer control SETTINGS opting into Extended CONNECT (type byte 0x00 + a SETTINGS
// frame advertising ENABLE_CONNECT_PROTOCOL=1). Delivering this lets the general
// send paths pass their peer-SETTINGS gate and reach the HEADERS encode path
// rather than short-circuiting on `WouldBlock`.
const PEER_SETTINGS: &[u8] = &[0x00, 0x04, 0x02, 0x08, 0x01];

fuzz_target!(|data: &[u8]| {
  let mut scratch = [0u8; 4096];

  // ── 1) Inbound request-FSM drive (the original target). ──────────────────────
  let mut conn = Connection::<Client>::new();
  // Register a request stream (id 0) so handle_stream reaches the request FSM.
  conn.provide_stream(StreamRole::Request, StreamId::new(0));
  // Feed the fuzz data as request-stream bytes; ignore errors (they are protocol
  // violations, not panics — the goal is no panic on any input).
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(0), data, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  // Drain the transmit queue; must never panic.
  while conn.poll_transmit().is_some() {}
  // Drain any events.
  while conn.poll_event().is_some() {}

  // Arbitrary-but-UTF-8-safe header value: fixed names keep the field section
  // well-formed; the lossy conversion guarantees a valid `&str` from any bytes.
  let value = String::from_utf8_lossy(data);

  // ── 2) Client general request path: open_request + send_data_on. ─────────────
  let mut client = Connection::<Client>::new();
  let _ = client.start();
  // Opt the peer in so open_request reaches the encode path (id 2 = peer control).
  if let Ok(mut frames) = client.handle_stream(StreamId::new(2), PEER_SETTINGS, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  let req_headers: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "example.com"),
    (":path", "/"),
    ("x-fuzz", value.as_ref()),
  ];
  let id = StreamId::new(4);
  let _ = client.open_request(id, req_headers);
  // The heap-tier `send_data_on` takes `Into<DataBuf>` (a refcounted owned buffer),
  // so hand it an owned copy of the fuzz data rather than the borrowed slice.
  let _ = client.send_data_on(id, data.to_vec());
  while client.poll_transmit().is_some() {}
  while client.poll_event().is_some() {}

  // ── 3) Server general response path: provide_stream + send_response. ─────────
  let mut server = Connection::<Server>::new();
  let _ = server.start();
  if let Ok(mut frames) = server.handle_stream(StreamId::new(3), PEER_SETTINGS, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  let sid = StreamId::new(0);
  server.provide_stream(StreamRole::Request, sid);
  // Optionally drive the inbound request bytes too, then respond.
  if let Ok(mut frames) = server.handle_stream(sid, data, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  let resp_headers: &[(&str, &str)] = &[(":status", "200"), ("x-fuzz", value.as_ref())];
  let _ = server.send_response(sid, resp_headers, true);
  while server.poll_transmit().is_some() {}
  while server.poll_event().is_some() {}
});
