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
//! carrying bare literals, `frame::decode_header`'s
//! `input.get(n0..).unwrap_or(&[])` — the guarded re-slice between the type
//! varint and the length varint — was replaced by a bare `input[n0..]`, a real
//! panic edge, and the release link stayed CLEAN while the test reported `ok`.
//! Every input written here is a literal whose length LLVM can count against
//! the `n0` it folds out of the first varint, so the bound was proved and
//! `shim_frame_decode` proved nothing about it. With the `black_box` calls
//! below, the same injection reds the link naming `shim_frame_decode`.
//!
//! [`core::hint::black_box`] is what stops that. It hands the optimizer a value
//! it must treat as opaque, so the shim is compiled for real over input it
//! cannot see through, and a reachable panic edge inside it survives to the
//! link. EVERY argument at EVERY call site below is wrapped, the smokes
//! included — a smoke that folded away would stop running the code it is there
//! to run. Two details are load-bearing rather than stylistic:
//!
//! * Slices are wrapped **as slices** (`black_box(bytes.as_slice())`,
//!   `black_box(&mut scratch[..])`), never as arrays. `black_box(&[1, 2, 3])`
//!   hides the pointer and leaves the LENGTH a compile-time constant, which is
//!   the half of a bounds check that matters — and length is exactly what this
//!   crate's varint and frame readers reason about.
//! * A shim whose answer is unused can be deleted whole, taking its body and
//!   its symbol with it, so every call here feeds an assertion.
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
//! cargo test -p http3-proto --release --features test-no-panic --test no_panic
//!
//! # …and the lie-check, which MUST fail to build:
//! ! cargo test -p http3-proto --release --features test-no-panic-lie --test no_panic
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
  // 1-byte varint (tag = 00), at both ends of its range.
  assert!(shim_varint_decode(black_box([0x00].as_slice())));
  assert!(shim_varint_decode(black_box([0x3f].as_slice())));
  // 2-byte varint (tag = 01).
  assert!(shim_varint_decode(black_box([0x40, 0x00].as_slice())));
  // 4-byte varint (tag = 10).
  assert!(shim_varint_decode(black_box(
    [0x80, 0x00, 0x00, 0x00].as_slice()
  )));
  // 8-byte varint (tag = 11), at zero and at the 62-bit maximum.
  assert!(shim_varint_decode(black_box(
    [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice()
  )));
  assert!(shim_varint_decode(black_box(
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff].as_slice()
  )));
  // Trailing bytes past the encoding: the reader consumes its own width and
  // leaves the rest to the caller, never reading past it.
  assert!(shim_varint_decode(black_box(
    [0x40, 0x00, 0xff, 0xff].as_slice()
  )));
  // Truncated — must return Err, never panic. One byte short of each of the
  // three multi-byte widths, and empty input.
  assert!(!shim_varint_decode(black_box([0x40].as_slice())));
  assert!(!shim_varint_decode(black_box(
    [0x80, 0x00, 0x00].as_slice()
  )));
  assert!(!shim_varint_decode(black_box(
    [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice()
  )));
  assert!(!shim_varint_decode(black_box([].as_slice())));
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
  assert!(shim_frame_decode(black_box([0x00, 0x05].as_slice())));
  // HEADERS frame with a 2-byte length varint.
  assert!(shim_frame_decode(black_box([0x01, 0x40, 0x80].as_slice())));
  // A multi-byte TYPE varint, so the re-slice between the two reads is driven
  // at a non-trivial offset rather than always at one byte in.
  assert!(shim_frame_decode(black_box(
    [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x05].as_slice()
  )));
  // Both varints at their widest, which is the longest header the grammar
  // admits and the largest offset the re-slice can be asked for.
  assert!(shim_frame_decode(black_box(
    [
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff
    ]
    .as_slice()
  )));
  // Truncated (length varint incomplete) → Err, never panic.
  assert!(!shim_frame_decode(black_box([0x01, 0x40].as_slice())));
  // A complete type varint and NO length varint at all: the re-slice lands
  // exactly on the end of the input, which is in bounds and empty.
  assert!(!shim_frame_decode(black_box([0x01].as_slice())));
  assert!(!shim_frame_decode(black_box(
    [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21].as_slice()
  )));
  // Empty.
  assert!(!shim_frame_decode(black_box([].as_slice())));
}

// ── QPACK decode ─────────────────────────────────────────────────────────────
//
// NOTE — the QPACK path is NOT wrapped in `#[no_panic]`. `qpack_decode_field_section_into`
// calls through the field-line parser, Huffman decoder, and scratch-buffer
// materializer — a call tree whose depth prevents full inlining into a single
// shim. Its panic-freedom is held by the crate-wide clippy lint wall
// (`unwrap_used` / `indexing_slicing` / `arithmetic_side_effects` / … in
// `lib.rs`), transitively covering exactly these functions. The smoke below
// still *runs* the path in release so any panic would surface as a test failure
// — which is why its input AND its scratch buffer go through `black_box`: a
// smoke folded away would stop running the code it is here to run, and a
// scratch buffer whose length stayed a constant would let the materializer's
// capacity checks be proved rather than executed.

fn qpack_decode_run(input: &[u8]) -> bool {
  let mut scratch = [0u8; 256];
  match qpack_decode_field_section_into(black_box(input), black_box(&mut scratch[..])) {
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
  assert!(qpack_decode_run(black_box([0x00, 0x00, 0xd1].as_slice())));
  // Just the prefix, no field lines.
  assert!(qpack_decode_run(black_box([0x00, 0x00].as_slice())));
  // Truncated prefix — Err, never panics.
  assert!(qpack_decode_run(black_box([0x00].as_slice())));
  // Empty — Err (truncated prefix), never panics.
  assert!(qpack_decode_run(black_box([].as_slice())));
  // Dynamic-table reference in prefix (RIC != 0) — Err, never panics.
  assert!(qpack_decode_run(black_box([0x01, 0x00].as_slice())));
  // Garbage bytes — any outcome is OK as long as no panic.
  assert!(qpack_decode_run(black_box(
    [0xff, 0xfe, 0xfd, 0xfc].as_slice()
  )));
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
  if let Ok(mut hs) = decode_field_section_into(black_box(bytes), black_box(&mut scratch[..])) {
    // The verdict is wrapped as well as the inputs: a result that is dropped
    // lets the whole call be deleted, and a deleted call runs nothing.
    black_box(validate(black_box(MessageKind::Request), &mut hs).is_ok());
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
/// would surface as a test failure — which is why its arguments go through
/// `black_box` at the call sites below.
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
  assert!(handle_step(
    black_box(&mut conn),
    black_box([0x01, 0x05].as_slice()),
    black_box(&mut scratch[..])
  ));
  // Empty — must not panic.
  assert!(handle_step(
    black_box(&mut conn),
    black_box([].as_slice()),
    black_box(&mut scratch[..])
  ));
  // Garbage.
  assert!(handle_step(
    black_box(&mut conn),
    black_box([0xff, 0xfe, 0x00].as_slice()),
    black_box(&mut scratch[..])
  ));
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
