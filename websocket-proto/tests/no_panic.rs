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
//! # Every argument goes through `black_box`
//!
//! Not a style choice — without it this file proves NOTHING about the branches
//! its literals do not take. A shim called only with compile-time constants is
//! constant-folded by LLVM before `no-panic`'s guard is evaluated: the body is
//! instantiated over those literals rather than over unknown input, every
//! branch they cannot reach is pruned as dead, and the symbol whose presence
//! would fail the link is never emitted for it. The shim then "passes"
//! whatever those branches do.
//!
//! MEASURED on this crate rather than assumed. With the call sites below still
//! carrying bare literals, `FrameHeader::encode`'s 63-bit-length refusal arm
//! was given a reachable `out[0]` — a real panic edge on a path any caller
//! reaches by asking to encode a length with the high bit set — and the
//! release link stayed CLEAN while the test reported `ok`. The two lengths
//! passed here are `5` and `70_000`, so LLVM proved that arm dead and
//! `shim_encode` proved nothing about it. With the `black_box` calls below, the
//! same injection reds the link naming `shim_encode`.
//!
//! [`core::hint::black_box`] is what stops that. It hands the optimizer a value
//! it must treat as opaque, so the shim is compiled for real over input it
//! cannot see through, and a reachable panic edge inside it survives to the
//! link. EVERY argument at EVERY call site below is wrapped, the smoke
//! included — a smoke that folded away would stop running the code it is there
//! to run. Two details are load-bearing rather than stylistic:
//!
//! * Slices are wrapped **as slices** (`black_box(bytes.as_slice())`,
//!   `black_box(&mut buf[..])`), never as arrays. `black_box(&[1, 2, 3])`
//!   hides the pointer and leaves the LENGTH a compile-time constant, which is
//!   the half of a bounds check that matters.
//! * A shim whose answer is unused can be deleted whole, taking its body and
//!   its symbol with it, so every call either feeds an assertion or is itself
//!   wrapped in `black_box`. `shim_mask` returns `()` and is held instead by
//!   the opaque `&mut` it writes through: stores through a pointer LLVM cannot
//!   see are not dead.
//!
//! [`the_link_proof_is_not_vacuous`] is the permanent check that this still
//! holds: under the internal `test-no-panic-lie` feature the file grows one
//! shim with a deliberately reachable panic, fed through `black_box` exactly as
//! the real ones are, and BUILDING IT MUST FAIL. CI asserts that failure (see
//! the `no-panic` job), so a future change that disarms the guard — a dropped
//! `black_box`, a `no-panic` release that stops emitting the symbol — turns
//! that step green and reds the build.
//!
//! # This crate's proof runs WITHOUT fat LTO, and what that costs the lie-check
//!
//! `http1-proto`'s and `http-semantics`' steps set
//! `CARGO_PROFILE_RELEASE_LTO=fat`, because their shims call leaves that are
//! not `#[inline]`: without whole-program optimization the linker sees an
//! opaque cross-crate call that might unwind and EVERY shim false-positives.
//! The leaves shimmed here are `#[inline]`, so they inline into the shim under
//! the default profile and the proof holds without it. Do not add fat LTO to
//! this crate's step to "match" theirs — the profile the shims were verified
//! under is the one that should keep running them.
//!
//! What it costs is worth stating, because it lands on the lie-check. There is
//! no second, LTO-shaped reason for the lie build to fail here, so CI's
//! reason-grep is the WHOLE control rather than an extra check on top of one:
//! a lie build that died of a typo, a renamed feature or an unrelated breakage
//! would satisfy "it did not build" while proving nothing — the same vacuity
//! one level up. Matching `no-panic`'s own link-error marker naming `shim_lie`
//! is what separates the two, and it is the only thing that does.
//!
//! # Running it
//!
//! Run it the way CI does. Release is mandatory rather than an optimization:
//! `no-panic` only proves anything once the optimizer has pruned provably-dead
//! panic branches, and in debug the link guard is disabled (see the macro
//! below) and would otherwise false-positive.
//!
//! ```sh
//! cargo test -p websocket-proto --release --features test-no-panic --test no_panic
//!
//! # …and the lie-check, which MUST fail to build:
//! ! cargo test -p websocket-proto --release --features test-no-panic-lie --test no_panic
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
    // Two things `shim-check`'s artifact half depends on, and neither is an
    // optimization. `#[inline(never)]` keeps the shim a symbol of its own
    // instead of vanishing into the `#[test]` that calls it; the `black_box`
    // around its ANSWER keeps a body the optimizer can prove pure and trivial
    // from being forwarded to its callers and deleted whole. Together they
    // make "this binary defines `no_panic::<shim>`, as a function" mean "this
    // shim was called", which is the question that check asks the linker — and
    // an uncalled shim and a deleted one are otherwise the same silence.
    //
    // Neither weakens what `no-panic` proves. The leaves still inline INTO the
    // body, which is what the fat-LTO steps are for; the body is compiled once,
    // standalone, over input `black_box` keeps opaque, which is the shape this
    // module doc already describes. The measurements behind both, and what
    // reads the symbol, are in `xtask/src/shim_check.rs`.
    #[inline(never)]
    fn $name($($arg)*) $(-> $ret)? {
      ::core::hint::black_box($body)
    }
  };
}

use core::hint::black_box;

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
  // (complete / need-more / grammar error) and are checked elsewhere. The
  // ANSWER is wrapped as well as the input, because a call whose result is
  // dropped can be deleted whole — and a deleted call proves nothing. Exercise
  // the short, extended-length, truncated, and empty arms.
  black_box(shim_decode(black_box(
    [0x81, 0x05, b'H', b'e', b'l', b'l', b'o'].as_slice(),
  )));
  black_box(shim_decode(black_box([0x82, 0xFE, 0x01, 0x00].as_slice())));
  // 64-bit length arm.
  black_box(shim_decode(black_box(
    [0x88, 0xFF, 0, 0, 0, 0, 0, 0, 0, 1].as_slice(),
  )));
  // Truncated → need more.
  black_box(shim_decode(black_box([0x88].as_slice())));
  // Empty → need more.
  black_box(shim_decode(black_box([].as_slice())));
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
  assert!(shim_encode(
    black_box(Opcode::Text),
    black_box(5),
    black_box(None),
    black_box(&mut out[..])
  ));
  assert!(shim_encode(
    black_box(Opcode::Binary),
    black_box(70_000),
    black_box(Some([1, 2, 3, 4])),
    black_box(&mut out[..])
  ));
  // A length with the high bit set: §5.2's `payload_len` refusal arm, which no
  // length written here as a literal can reach — `len` arrives opaque, so the
  // arm is compiled rather than pruned. Refused, never a panic.
  assert!(!shim_encode(
    black_box(Opcode::Binary),
    black_box(0x8000_0000_0000_0000),
    black_box(None),
    black_box(&mut out[..])
  ));
  // Too-small buffer must return an error, never panic — including a buffer
  // with no room at all.
  let mut tiny = [0u8; 1];
  assert!(!shim_encode(
    black_box(Opcode::Text),
    black_box(5),
    black_box(None),
    black_box(&mut tiny[..])
  ));
  assert!(!shim_encode(
    black_box(Opcode::Text),
    black_box(5),
    black_box(None),
    black_box(&mut [][..])
  ));
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
  // This shim answers `()`, so what keeps it from being deleted as dead is the
  // OPAQUE `&mut` it writes through: LLVM cannot prove a store through a
  // pointer it cannot see is unobserved.
  let mut payload = *b"the quick brown fox";
  shim_mask(
    black_box(&mut payload[..]),
    black_box([0xAA, 0xBB, 0xCC, 0xDD]),
    black_box(0),
  );
  // Non-zero offset arm — a continuation frame resumes mid-key.
  shim_mask(
    black_box(&mut payload[..]),
    black_box([0xAA, 0xBB, 0xCC, 0xDD]),
    black_box(3),
  );
  // An offset far past any payload length, which is the caller's counter
  // rather than this function's, so the wrap-around is its business.
  shim_mask(
    black_box(&mut payload[..]),
    black_box([0xAA, 0xBB, 0xCC, 0xDD]),
    black_box(u64::MAX),
  );
  // Empty-slice arm.
  let mut empty: [u8; 0] = [];
  shim_mask(black_box(&mut empty[..]), black_box([0; 4]), black_box(0));
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
  // Multibyte.
  assert!(shim_utf8(black_box("héllo wörld".as_bytes())));
  // Empty.
  assert!(shim_utf8(black_box([].as_slice())));
  // Invalid → Err, never panics.
  assert!(!shim_utf8(black_box([0xFF, 0xFE].as_slice())));
  // Truncated 3-byte char → Ok(prefix len).
  assert!(shim_utf8(black_box([0xE2, 0x82].as_slice())));
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
  assert!(shim_base64(
    black_box([].as_slice()),
    black_box(&mut out[..])
  ));
  assert!(shim_base64(
    black_box(b"any carnal pleasure".as_slice()),
    black_box(&mut out[..])
  ));
  // Each remainder class of `as_chunks::<3>()` in turn — 0, 1 and 2 trailing
  // bytes, which are three different write patterns rather than one.
  assert!(shim_base64(
    black_box(b"abc".as_slice()),
    black_box(&mut out[..])
  ));
  assert!(shim_base64(
    black_box(b"abcd".as_slice()),
    black_box(&mut out[..])
  ));
  assert!(shim_base64(
    black_box(b"abcde".as_slice()),
    black_box(&mut out[..])
  ));
  // None, never panics: a buffer too small for the encoding, and one with no
  // room at all.
  let mut tiny = [0u8; 1];
  assert!(!shim_base64(
    black_box(b"too big for buffer".as_slice()),
    black_box(&mut tiny[..])
  ));
  assert!(!shim_base64(
    black_box(b"x".as_slice()),
    black_box(&mut [][..])
  ));
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
/// path in release so a panic would surface as a test failure — which is why
/// its arguments go through `black_box` too: a smoke that folded away would
/// stop running the code it is here to run.
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
  assert!(handle_step(
    black_box(&mut conn),
    black_box(&mut text[..]),
    black_box(&mut out[..])
  ));

  let mut ping = masked_frame(Opcode::Ping, b"p");
  assert!(handle_step(
    black_box(&mut conn),
    black_box(&mut ping[..]),
    black_box(&mut out[..])
  ));
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

// ── the lie-check: this file's own guard against going vacuous ────────────────
//
// PERMANENT: the vacuous-proof failure mode the module doc's `black_box`
// section describes is silent by construction — it was measured happening in
// this very file — and this is the check that it has not come back. The file
// carries a shim that MUST NOT link — see `shim_lie` below for how — and CI
// asserts that the build FAILS (the `no-panic` job in
// `.github/workflows/ci.yml`); a green build there is the report that the guard
// has stopped working.
//
// It is a separate FEATURE rather than a `#[should_panic]` test because the
// failure is a link error: it kills the whole test binary, so it cannot share
// one with the shims it is checking. In debug the guard is off (the macro's
// `cfg_attr`), so `cargo hack --each-feature` and miri build and run this
// exactly like any other test and it passes on its assertion.
#[cfg(feature = "test-no-panic-lie")]
no_panic_shim! {
  /// A shim with a REACHABLE panic, fed the same way the real ones are.
  ///
  /// `input[0]` on a slice whose length the optimizer cannot see is a bounds
  /// check with a panicking edge. Nothing about it is subtle on purpose: what is
  /// being checked is the harness, not this expression.
  #[allow(clippy::indexing_slicing)]
  fn shim_lie(input: &[u8]) -> u8 {
    input[0]
  }
}

/// Building this test with `--features test-no-panic-lie --release` MUST FAIL to
/// link. See the block comment above.
#[cfg(feature = "test-no-panic-lie")]
#[test]
fn the_link_proof_is_not_vacuous() {
  assert_eq!(shim_lie(black_box(b"x".as_slice())), b'x');
}
