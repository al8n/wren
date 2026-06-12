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
//! Coverage: `FrameHeader::{decode, encode}`, `mask`, the streaming UTF-8
//! validator's `feed`, and the base64 encoder are each link-checked (they are
//! `#[inline]`, so they inline into the shim where `no-panic` can see the whole
//! body across the crate boundary). The full `Connection::handle` + drain step
//! is exercised but NOT link-checked — see [`handle_step`] for why (its call
//! tree is too deep to inline into one shim) and how its panic-freedom is held
//! instead.
//!
//! Run it the way CI does (release is mandatory — the optimizer must prune
//! provably-dead panic branches first; in debug the link guard is disabled and
//! would false-positive, so the shims merely run):
//!
//! ```sh
//! cargo test -p websocket-proto --release --features test-no-panic --test no_panic
//! ```
//!
//! Deflate paths are deliberately excluded: `miniz_oxide` is not panic-free and
//! is not part of the no-panic contract.
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

use websocket_proto::{
  __no_panic_internals::{Utf8Validator, base64_encode},
  connection::{Connection, ConnectionConfig, role::Server},
  frame::{FrameHeader, Opcode, mask},
  negotiation::Negotiated,
  time::Instant,
};

// ── frame header decode ──────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over [`FrameHeader::decode`] — the inbound frame-grammar parser.
  fn shim_decode(buf: &[u8]) -> bool {
    FrameHeader::decode(buf).is_ok()
  }
}

#[test]
fn frame_decode_is_panic_free() {
  // The point is that each call RETURNS rather than panics; the verdicts vary
  // (complete / need-more / grammar error) and are checked elsewhere. Exercise
  // the short, extended-length, truncated, and empty arms.
  let _ = shim_decode(&[0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
  let _ = shim_decode(&[0x82, 0xFE, 0x01, 0x00]);
  let _ = shim_decode(&[0x88, 0xFF, 0, 0, 0, 0, 0, 0, 0, 1]); // 64-bit length arm
  let _ = shim_decode(&[0x88]); // truncated → need more
  let _ = shim_decode(&[]); // empty → need more
}

// ── frame header encode ──────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over [`FrameHeader::encode`] — outbound header serialization.
  fn shim_encode(opcode: Opcode, len: u64, mask_key: Option<[u8; 4]>, out: &mut [u8]) -> bool {
    FrameHeader::new(opcode, len)
      .with_fin(true)
      .with_mask(mask_key)
      .encode(out)
      .is_ok()
  }
}

#[test]
fn frame_encode_is_panic_free() {
  let mut out = [0u8; 14];
  assert!(shim_encode(Opcode::Text, 5, None, &mut out));
  assert!(shim_encode(
    Opcode::Binary,
    70_000,
    Some([1, 2, 3, 4]),
    &mut out
  ));
  // Too-small buffer must return an error, never panic.
  let mut tiny = [0u8; 1];
  assert!(!shim_encode(Opcode::Text, 5, None, &mut tiny));
}

// ── masking ──────────────────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over [`mask`] — the in-place XOR transform.
  fn shim_mask(payload: &mut [u8], key: [u8; 4], offset: u64) {
    mask(payload, key, offset);
  }
}

#[test]
fn mask_is_panic_free() {
  let mut payload = *b"the quick brown fox";
  shim_mask(&mut payload, [0xAA, 0xBB, 0xCC, 0xDD], 0);
  shim_mask(&mut payload, [0xAA, 0xBB, 0xCC, 0xDD], 3); // non-zero offset arm
  let mut empty: [u8; 0] = [];
  shim_mask(&mut empty, [0; 4], 0); // empty-slice arm
}

// ── UTF-8 validation ─────────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over [`Utf8Validator::feed`] — the incremental text validator.
  fn shim_utf8(input: &[u8]) -> bool {
    let mut v = Utf8Validator::new();
    v.feed(input)
  }
}

#[test]
fn utf8_feed_is_panic_free() {
  assert!(shim_utf8("héllo wörld".as_bytes())); // multibyte
  assert!(shim_utf8(&[])); // empty
  assert!(!shim_utf8(&[0xFF, 0xFE])); // invalid → Err, never panics
  assert!(shim_utf8(&[0xE2, 0x82])); // truncated 3-byte char → Ok(prefix len)
}

// ── base64 encode ────────────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over the internal base64 encoder (used by the handshake accept value).
  fn shim_base64(input: &[u8], out: &mut [u8]) -> bool {
    base64_encode(input, out).is_some()
  }
}

#[test]
fn base64_encode_is_panic_free() {
  let mut out = [0u8; 64];
  assert!(shim_base64(b"", &mut out));
  assert!(shim_base64(b"any carnal pleasure", &mut out));
  let mut tiny = [0u8; 1];
  assert!(!shim_base64(b"too big for buffer", &mut tiny)); // None, never panics
}

// ── connection handle + drain (server role, no deflate) ──────────────────────

/// Newtype clock so the connection under test is a concrete, fully
/// monomorphized type.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Clock(u64);

impl Instant for Clock {
  fn checked_add_duration(self, dur: core::time::Duration) -> Option<Self> {
    u64::try_from(dur.as_nanos())
      .ok()
      .and_then(|n| self.0.checked_add(n))
      .map(Clock)
  }

  fn checked_duration_since(self, earlier: Self) -> Option<core::time::Duration> {
    self
      .0
      .checked_sub(earlier.0)
      .map(core::time::Duration::from_nanos)
  }
}

/// One full receive step: `handle` → drain every event → drain `poll_transmit`.
///
/// NOTE — this path is NOT wrapped in `#[no_panic]`. `no-panic` proves
/// panic-freedom only for code the optimizer fully inlines into the shim, and
/// across the test↔library crate boundary that means the *entire* call tree.
/// The five leaf shims above (`decode`/`encode`/`mask`/`utf8`/`base64`) inline
/// cleanly and ARE link-checked; the connection step fans out across the whole
/// receive/transmit state machine (frame dispatch, control assembly, close
/// decoding, frame serialization) — dozens of functions — which cannot inline
/// into one shim without pervasively `#[inline]`-annotating the library purely
/// to satisfy a test, an unacceptable hit to production codegen. Its
/// panic-freedom is instead held by the crate-wide clippy lint wall
/// (`unwrap_used`/`indexing_slicing`/`arithmetic_side_effects`/… in `lib.rs`),
/// transitively covering exactly these functions. This smoke still *runs* the
/// path in release so a panic would surface as a test failure.
fn handle_step(conn: &mut Connection<Clock, Server>, bytes: &mut [u8], out: &mut [u8]) -> bool {
  // Scope the events cursor so its borrow of `conn` ends before draining.
  {
    let mut events = match conn.handle(Clock(0), bytes) {
      Ok(ev) => ev,
      Err(_) => return false,
    };
    while events.next().is_some() {}
  }
  loop {
    match conn.poll_transmit(Clock(0), out) {
      Ok(Some(_)) => {}
      Ok(None) => return true,
      Err(_) => return false,
    }
  }
}

#[test]
fn connection_handle_step_runs_clean() {
  let mut conn: Connection<Clock, Server> = Connection::new(
    &Negotiated::none(),
    ConnectionConfig::new(),
    Server::new(),
    Clock(0),
  );

  // A masked text frame "Hi" (client→server) plus a masked ping — both data
  // and control paths, including the pong-echo queue and its drain.
  let mut text = masked_frame(Opcode::Text, b"Hi");
  let mut out = [0u8; 32];
  assert!(handle_step(&mut conn, &mut text, &mut out));

  let mut ping = masked_frame(Opcode::Ping, b"p");
  assert!(handle_step(&mut conn, &mut ping, &mut out));
}

/// Builds one masked client→server frame into an owned `Vec` (test helper —
/// not panic-checked; the production `mask`/`encode` it calls are shimmed
/// above).
fn masked_frame(opcode: Opcode, payload: &[u8]) -> Vec<u8> {
  const KEY: [u8; 4] = [0x21, 0x09, 0x77, 0x3A];
  let header = FrameHeader::new(opcode, payload.len() as u64)
    .with_fin(true)
    .with_mask(Some(KEY));
  let mut buf = vec![0u8; header.header_len() + payload.len()];
  let n = header.encode(&mut buf).expect("encode test frame header");
  buf[n..].copy_from_slice(payload);
  mask(&mut buf[n..], KEY, 0);
  buf
}
