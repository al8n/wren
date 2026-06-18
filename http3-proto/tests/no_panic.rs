//! Link-time panic-freedom verification for the crate's core hot paths.
//!
//! The crate's panic-freedom is a *production* guarantee enforced statically by
//! the clippy lint wall (`unwrap_used`, `indexing_slicing`,
//! `arithmetic_side_effects`, …) in `lib.rs`. That wall is necessary but not
//! sufficient: a lint-clean expression can still lower to a panicking branch
//! (slice bounds the optimizer cannot prove away, `core` intrinsics). This test
//! adds the *sufficient* half — it wraps the crate's hot **leaf** primitives
//! in [`no_panic::no_panic`] shims and a `#[test]` that calls each, so that
//! building the test binary in **release** forces the linker to materialize
//! their code. If a shim contains a reachable panic, the link fails with a
//! `no-panic` error naming the symbol.
//!
//! Coverage: `varint::decode` and `frame::decode_header` are each link-checked
//! via `#[no_panic]` shims — they are `#[inline]`, so they inline into the
//! shim where `no-panic` can see the whole body across the crate boundary.
//! `qpack::decode_field_section_into` is exercised as a **smoke test only**
//! (NOT link-checked): its call tree (field-line parser → Huffman decoder →
//! scratch materializer) is too deep to inline into a single shim across the
//! crate boundary, preventing `no-panic` from seeing the full body; its
//! panic-freedom is enforced by the crate-wide clippy lint wall
//! (`unwrap_used` / `indexing_slicing` / `arithmetic_side_effects` / …) +
//! fuzzing. The full `Connection::handle_stream` + drain step is similarly
//! exercised but NOT link-checked, for the same reason.
//!
//! Run it the way CI does (release is mandatory — the optimizer must prune
//! provably-dead panic branches first; in debug the link guard is disabled and
//! would false-positive):
//!
//! ```sh
//! cargo test -p http3-proto --release --features test-no-panic --test no_panic
//! ```
#![cfg(feature = "test-no-panic")]

// `no-panic` only proves anything once the optimizer has pruned provably-dead
// panic branches, so the link-time assertion is applied **in release only**
// (`cargo test --release …`). In debug the shims still run — exercising the
// code — but without the link guard, which would otherwise false-positive.
macro_rules! no_panic_shim {
  ($(#[$meta:meta])* fn $name:ident ($($arg:tt)*) $(-> $ret:ty)? $body:block) => {
    $(#[$meta])*
    #[cfg_attr(not(debug_assertions), no_panic::no_panic)]
    fn $name($($arg)*) $(-> $ret)? $body
  };
}

use http3_proto::__no_panic_internals::{
  frame_decode_header, qpack_decode_field_section_into, varint_decode,
};

// ── varint decode ─────────────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over [`varint::decode`] — the QUIC variable-length integer parser.
  fn shim_varint_decode(input: &[u8]) -> bool {
    varint_decode(input).is_ok()
  }
}

#[test]
fn varint_decode_is_panic_free() {
  // 1-byte varint (tag = 00).
  assert!(shim_varint_decode(&[0x00]));
  assert!(shim_varint_decode(&[0x3f]));
  // 2-byte varint (tag = 01).
  assert!(shim_varint_decode(&[0x40, 0x00]));
  // 4-byte varint (tag = 10).
  assert!(shim_varint_decode(&[0x80, 0x00, 0x00, 0x00]));
  // 8-byte varint (tag = 11).
  assert!(shim_varint_decode(&[
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]));
  // Truncated — must return Err, never panic.
  assert!(!shim_varint_decode(&[0x40])); // 2-byte but only 1 byte provided
  assert!(!shim_varint_decode(&[])); // empty
}

// ── frame header decode ───────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over [`frame::decode_header`] — the HTTP/3 frame type+length parser.
  fn shim_frame_decode(buf: &[u8]) -> bool {
    frame_decode_header(buf).is_ok()
  }
}

#[test]
fn frame_decode_is_panic_free() {
  // DATA frame, 5-byte payload: type=0x00 (1 byte), length=5 (1 byte).
  assert!(shim_frame_decode(&[0x00, 0x05]));
  // HEADERS frame with a 2-byte length varint.
  assert!(shim_frame_decode(&[0x01, 0x40, 0x80]));
  // Truncated (length varint incomplete) → Err, never panic.
  assert!(!shim_frame_decode(&[0x01, 0x40])); // 2-byte length, only 1 byte present
  assert!(!shim_frame_decode(&[])); // empty
}

// ── QPACK decode ─────────────────────────────────────────────────────────────
//
// NOTE — the QPACK path is NOT wrapped in `#[no_panic]`. `qpack_decode_field_section_into`
// calls through the field-line parser, Huffman decoder, and scratch-buffer
// materializer — a call tree whose depth prevents full inlining into a single
// shim. Its panic-freedom is held by the crate-wide clippy lint wall
// (`unwrap_used` / `indexing_slicing` / `arithmetic_side_effects` / … in
// `lib.rs`), transitively covering exactly these functions. The smoke below
// still *runs* the path in release so any panic would surface as a test failure.

fn qpack_decode_run(input: &[u8]) -> bool {
  let mut scratch = [0u8; 256];
  match qpack_decode_field_section_into(input, &mut scratch) {
    Err(_) => true, // prefix error is not a panic
    Ok(mut lines) => loop {
      match lines.next() {
        Ok(None) => break true,
        Ok(Some(_)) => {}
        Err(_) => break true, // decode error is not a panic
      }
    },
  }
}

#[test]
fn qpack_decode_runs_clean() {
  // Valid 2-byte prefix (RIC=0, base=0) followed by an indexed static-table
  // entry for ":method: GET" (index 17, 1 byte: 0xd1 = 0x80 | 0x51).
  assert!(qpack_decode_run(&[0x00, 0x00, 0xd1]));
  // Just the prefix, no field lines.
  assert!(qpack_decode_run(&[0x00, 0x00]));
  // Truncated prefix — Err, never panics.
  assert!(qpack_decode_run(&[0x00]));
  // Empty — Err (truncated prefix), never panics.
  assert!(qpack_decode_run(&[]));
  // Dynamic-table reference in prefix (RIC != 0) — Err, never panics.
  assert!(qpack_decode_run(&[0x01, 0x00]));
  // Garbage bytes — any outcome is OK as long as no panic.
  assert!(qpack_decode_run(&[0xff, 0xfe, 0xfd, 0xfc]));
}

// ── semantic validator ────────────────────────────────────────────────────────
//
// NOTE — `validate::validate` is NOT wrapped in `#[no_panic]`. It scans a
// (lending) decoded field section, so its call tree fans through the QPACK
// field-line iterator (the same too-deep-to-inline tree as the QPACK smoke
// above). Its panic-freedom is held by the crate-wide clippy lint wall in
// `lib.rs`; this smoke still *runs* the validator in release so any panic would
// surface as a test failure. `validate` is a public free function, so the test
// calls it directly (no `__no_panic_internals` forwarder needed).

#[test]
fn validate_runs_clean() {
  use http3_proto::{MessageKind, qpack::decode_field_section_into, validate::validate};
  // Valid 2-byte prefix (RIC=0, base=0) + indexed static entry 17 = ":method: GET".
  let bytes: &[u8] = &[0x00, 0x00, 0xd1];
  let mut scratch = [0u8; 256];
  if let Ok(mut hs) = decode_field_section_into(bytes, &mut scratch) {
    let _ = validate(MessageKind::Request, &mut hs); // any Result, no panic
  }
}

// ── connection handle + drain (client role) ───────────────────────────────────

type StaticConnection<Ro> =
  http3_proto::Connection<'static, 'static, 'static, 'static, 'static, Ro>;

/// One full receive step: `handle_stream` → drain frames → drain transmits
/// → drain events.
///
/// NOTE — this path is NOT wrapped in `#[no_panic]`. The call tree fans out
/// across the whole receive/transmit FSM; its panic-freedom is held by the
/// crate-wide clippy lint wall (`unwrap_used` / `indexing_slicing` /
/// `arithmetic_side_effects` / … in `lib.rs`), transitively covering exactly
/// these functions. This smoke still *runs* the path in release so any panic
/// would surface as a test failure.
fn handle_step(
  conn: &mut StaticConnection<http3_proto::Client>,
  bytes: &[u8],
  scratch: &mut [u8],
) -> bool {
  use http3_proto::event::{StreamId, StreamRole};
  // Ensure the request stream is registered.
  conn.provide_stream(StreamRole::Request, StreamId::new(0));
  match conn.handle_stream(StreamId::new(0), bytes, scratch) {
    Err(_) => return true, // protocol error, not a panic
    Ok(mut frames) => loop {
      match frames.next() {
        Ok(None) => break,
        Ok(Some(_)) => {}
        Err(_) => return true,
      }
    },
  }
  while conn.poll_transmit().is_some() {}
  while conn.poll_event().is_some() {}
  true
}

#[test]
fn connection_handle_step_runs_clean() {
  use http3_proto::Connection;
  let mut conn = Connection::<http3_proto::Client>::new();
  let mut scratch = [0u8; 4096];

  // Arbitrary bytes: a partial HEADERS frame header (type=0x01, length=5).
  assert!(handle_step(&mut conn, &[0x01, 0x05], &mut scratch));
  // Empty — must not panic.
  assert!(handle_step(&mut conn, &[], &mut scratch));
  // Garbage.
  assert!(handle_step(&mut conn, &[0xff, 0xfe, 0x00], &mut scratch));
}
