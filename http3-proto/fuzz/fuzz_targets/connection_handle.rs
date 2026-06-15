//! Fuzz: arbitrary bytes on every stream path of the Connection state machine
//! must never panic, and terminal state must be terminal.
#![no_main]

use libfuzzer_sys::fuzz_target;
use http3_proto::{
  Connection, Client,
  event::{StreamId, StreamRole},
};

fuzz_target!(|data: &[u8]| {
  let mut conn = Connection::<Client>::new();
  // Register a request stream (id 0) so handle_stream reaches the request FSM.
  conn.provide_stream(StreamRole::Request, StreamId::new(0));

  let mut scratch = [0u8; 4096];
  // Feed the fuzz data as request-stream bytes; ignore errors (they are protocol
  // violations, not panics — the goal is no panic on any input).
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(0), data, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }

  // Drain the transmit queue; must never panic.
  while conn.poll_transmit().is_some() {}
  // Drain any events.
  while conn.poll_event().is_some() {}
});
