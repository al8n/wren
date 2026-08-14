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
//! Coverage: `find_head_end`, `parse_status_line` and `parse_chunk_size` are
//! each link-checked via `#[no_panic]` shims — the head-terminator scan, the
//! §4 status-line codec, and the `1*HEXDIG` reader whose checked accumulation
//! is the crate's one arithmetic overflow risk.
//!
//! Three paths are exercised as **smoke tests only** (NOT link-checked), each
//! for a reason recorded at its own section: `parse_request_line` and
//! `encode_request_head` both reach `parse_target`, and `scan_head` and the
//! `Connection::handle` step both fan out too far to inline into one shim.
//! Their panic-freedom is held by the crate-wide clippy lint wall
//! (`unwrap_used` / `indexing_slicing` / `arithmetic_side_effects` / …) plus
//! the split, smuggling and differential suites; the smokes still *run* them in
//! release, so any panic would surface as a test failure.
//!
//! # Every argument goes through `black_box`
//!
//! Not a style choice — without it this file proves NOTHING. A shim called only
//! with compile-time constants is constant-folded by LLVM before `no-panic`'s
//! guard is evaluated: the call disappears, the shim's body is never
//! instantiated over unknown input, and the symbol whose presence would fail
//! the link is never emitted. Every shim then "passes" whatever its body does.
//!
//! [`core::hint::black_box`] is what stops that. It hands the optimizer a value
//! it must treat as opaque, so the shim is compiled for real over input it
//! cannot see through, and a reachable panic edge inside it survives to the
//! link. EVERY argument at EVERY call site below is wrapped, smokes included —
//! a smoke that folded away would stop running the code it is there to run.
//!
//! [`the_link_proof_is_not_vacuous`] is the permanent check that this still
//! holds: under the internal `test-no-panic-lie` feature the file grows one
//! shim with a deliberately reachable panic, fed through `black_box` exactly as
//! the real ones are, and BUILDING IT MUST FAIL. CI asserts that failure (see
//! the `no-panic` job), so a future change that disarms the guard — a dropped
//! `black_box`, a profile without LTO, a `no-panic` release that stops
//! emitting the symbol — turns that step green and reds the build.
//!
//! # Running it
//!
//! Run it the way CI does. Two settings are part of the invocation rather than
//! optimizations:
//!
//! * **release** — `no-panic` only proves anything once the optimizer has
//!   pruned provably-dead panic branches. In debug the link guard is disabled
//!   (see the macro below) and would otherwise false-positive.
//! * **fat LTO** — the shims live in this crate and the code under test lives
//!   in `http1-proto`, whose leaves are not `#[inline]`. Without whole-program
//!   optimization the linker sees an opaque cross-crate call that might unwind,
//!   and EVERY shim false-positives regardless of its body. LTO is what gives
//!   `no-panic` the whole body to reason about; it is set on the command line
//!   so the crate's own release profile stays untouched.
//!
//! ```sh
//! CARGO_PROFILE_RELEASE_LTO=fat \
//!   cargo test -p http1-proto --release --features test-no-panic --test no_panic
//!
//! # …and the lie-check, which MUST fail to build:
//! ! CARGO_PROFILE_RELEASE_LTO=fat \
//!   cargo test -p http1-proto --release --features test-no-panic-lie --test no_panic
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

use core::hint::black_box;

use http1_proto::{
  __no_panic_internals::{
    encode_request_head, find_head_end, parse_chunk_size, parse_request_line, parse_status_line,
    scan_head,
  },
  Target,
};

// ── head-terminator scan ──────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over `head::find_head_end` — the incremental CRLFCRLF scan that
  /// decides where a head ends.
  fn shim_find_head_end(input: &[u8], from: usize) -> bool {
    find_head_end(input, from).is_ok()
  }
}

#[test]
fn find_head_end_is_panic_free() {
  const HEAD: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
  // A whole head, scanned from the start.
  assert!(shim_find_head_end(black_box(HEAD), black_box(0)));
  // Resumed past the first line — the watermark path with its three-byte
  // overlap re-read.
  assert!(shim_find_head_end(black_box(HEAD), black_box(16)));
  // A watermark past the end of the input: `from` is the caller's, so the
  // clamping is the function's business.
  assert!(shim_find_head_end(black_box(HEAD), black_box(999)));
  // No terminator yet → Ok(None), never a panic.
  assert!(shim_find_head_end(
    black_box(b"GET / HTTP/1.1\r\n"),
    black_box(0)
  ));
  // A lone trailing CR is inconclusive rather than bare.
  assert!(shim_find_head_end(
    black_box(b"GET / HTTP/1.1\r"),
    black_box(0)
  ));
  assert!(shim_find_head_end(black_box(b""), black_box(0)));
  // A bare LF → Err, never a panic.
  assert!(!shim_find_head_end(
    black_box(b"GET / HTTP/1.1\n"),
    black_box(0)
  ));
}

// ── status-line codec ─────────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over `head::parse_status_line` — the RFC 9112 §4 status-line codec.
  fn shim_parse_status_line(line: &[u8]) -> bool {
    parse_status_line(line).is_ok()
  }
}

#[test]
fn parse_status_line_is_panic_free() {
  assert!(shim_parse_status_line(black_box(b"HTTP/1.1 200 OK\r\n")));
  // §4 keeps the SP even when the reason-phrase is absent.
  assert!(shim_parse_status_line(black_box(b"HTTP/1.1 101 \r\n")));
  // A code that is not exactly three digits, a missing SP, and empty input.
  assert!(!shim_parse_status_line(black_box(b"HTTP/1.1 20 OK\r\n")));
  assert!(!shim_parse_status_line(black_box(b"HTTP/1.1 200\r\n")));
  assert!(!shim_parse_status_line(black_box(b"")));
  // Bare CR inside the line, and a control byte in the reason-phrase.
  assert!(!shim_parse_status_line(black_box(b"HTTP/1.1 200 O\rK\r\n")));
  assert!(!shim_parse_status_line(black_box(
    b"HTTP/1.1 200 O\x00K\r\n"
  )));
}

// ── chunk-size reader ─────────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over `body::chunked::parse_chunk_size` — the RFC 9112 §7.1
  /// `chunk-size = 1*HEXDIG` reader, including its checked accumulation.
  fn shim_parse_chunk_size(line: &[u8]) -> bool {
    parse_chunk_size(line).is_ok()
  }
}

#[test]
fn parse_chunk_size_is_panic_free() {
  assert!(shim_parse_chunk_size(black_box(b"1a")));
  assert!(shim_parse_chunk_size(black_box(b"0")));
  // Both HEXDIG cases, and a size with a chunk-ext behind it.
  assert!(shim_parse_chunk_size(black_box(b"FfF")));
  assert!(shim_parse_chunk_size(black_box(b"1a;ext=1")));
  // Sixteen hex digits is exactly `u64::MAX`; unlimited leading zeros are legal.
  assert!(shim_parse_chunk_size(black_box(b"ffffffffffffffff")));
  assert!(shim_parse_chunk_size(black_box(b"000000000000000001")));
  // Seventeen significant digits overflow the u64 — Err from the checked
  // accumulation, never a wrap and never a panic.
  assert!(!shim_parse_chunk_size(black_box(b"10000000000000000")));
  // No digit at all, and a non-HEXDIG first byte.
  assert!(!shim_parse_chunk_size(black_box(b"")));
  assert!(!shim_parse_chunk_size(black_box(b"g")));
  assert!(!shim_parse_chunk_size(black_box(b" 1")));
}

// ── request-line codec ────────────────────────────────────────────────────────
//
// NOTE — the request-line codec is NOT wrapped in `#[no_panic]`, and the reason
// is a `no-panic` limitation rather than anything in this crate. `parse_target`
// classifies a §3.2 target with `str::split_once`, and its authority validator
// (`grammar::is_valid_authority` → `is_valid_ipv6`) uses `str::rsplit_once` and
// `str::split`. Every `core::str` PATTERN search — `char` and `&str` patterns
// alike — keeps a panic branch that LLVM cannot prune even under fat LTO: a
// bare `#[no_panic] fn(s: &str) -> bool { s.split_once("::").is_some() }` fails
// to link on its own, while `s.parse::<u16>()` (the other suspect on this path)
// links clean. The searcher invariants make those branches unreachable in fact,
// so the path is smoke-tested here and held by the lint wall, exactly as the
// deep paths below are.

fn parse_request_line_run(line: &[u8]) -> bool {
  parse_request_line(line).is_ok()
}

#[test]
fn parse_request_line_runs_clean() {
  // All four §3.2 target forms.
  assert!(parse_request_line_run(black_box(
    b"GET /a?b=c HTTP/1.1\r\n"
  )));
  assert!(parse_request_line_run(black_box(
    b"GET http://example.com/ HTTP/1.1\r\n"
  )));
  assert!(parse_request_line_run(black_box(
    b"CONNECT example.com:443 HTTP/1.1\r\n"
  )));
  assert!(parse_request_line_run(black_box(b"OPTIONS * HTTP/1.1\r\n")));
  // The IP-literal authority shapes, which reach the IPv6 and IPvFuture
  // validators the note above names.
  assert!(parse_request_line_run(black_box(
    b"CONNECT [::1]:443 HTTP/1.1\r\n"
  )));
  assert!(parse_request_line_run(black_box(
    b"GET http://[2001:db8::1]/x HTTP/1.1\r\n"
  )));
  // Truncated, unterminated, and empty — Err, never a panic.
  assert!(!parse_request_line_run(black_box(b"GET /\r\n")));
  assert!(!parse_request_line_run(black_box(b"GET / HTTP/1.1")));
  assert!(!parse_request_line_run(black_box(b"")));
  // A version outside 1.x, and a non-token method: both Err.
  assert!(!parse_request_line_run(black_box(b"GET / HTTP/2.0\r\n")));
  assert!(!parse_request_line_run(black_box(b"G\x00T / HTTP/1.1\r\n")));
  // Bare LF inside the line, a malformed IP-literal, and a non-UTF-8 target.
  assert!(!parse_request_line_run(black_box(b"GET / HTTP/1.1\n")));
  assert!(!parse_request_line_run(black_box(
    b"CONNECT [::::]:443 HTTP/1.1\r\n"
  )));
  assert!(!parse_request_line_run(black_box(
    b"GET /\xff HTTP/1.1\r\n"
  )));
}

// ── request-head encoder ──────────────────────────────────────────────────────
//
// NOTE — the encoder is NOT wrapped in `#[no_panic]` either, for the same
// reason: it validates the outbound target by running `parse_target` over the
// bytes it is about to write, so it inherits the `core::str` pattern branches
// described above. (Its own field walk is a `&mut dyn FnMut` visitor written
// into a `&mut dyn Sink`, two indirections that a shim cannot see through
// either.) The smoke runs both passes in release.

fn encode_request_head_run(
  method: &str,
  target: &Target<'_>,
  headers: &[(&str, &[u8])],
  out: &mut [u8],
) -> bool {
  encode_request_head(method, target, headers, out).is_ok()
}

#[test]
fn encode_request_head_runs_clean() {
  const ORIGIN: Target<'static> = Target::Origin {
    path_and_query: "/",
  };
  const AUTHORITY: Target<'static> = Target::Authority {
    host_port: "example.com:443",
  };
  let headers: &[(&str, &[u8])] = &[("Host", b"example.com")];
  let mut out = [0u8; 128];

  assert!(encode_request_head_run(
    black_box("GET"),
    black_box(&ORIGIN),
    black_box(headers),
    black_box(&mut out)
  ));
  assert!(encode_request_head_run(
    black_box("CONNECT"),
    black_box(&AUTHORITY),
    black_box(headers),
    black_box(&mut out)
  ));
  // No fields at all.
  assert!(encode_request_head_run(
    black_box("GET"),
    black_box(&ORIGIN),
    black_box(&[]),
    black_box(&mut out)
  ));
  // A buffer too small for the head, and one with no room at all: `need` is
  // computed and the buffer left untouched — Err, never a panic.
  assert!(!encode_request_head_run(
    black_box("GET"),
    black_box(&ORIGIN),
    black_box(headers),
    black_box(&mut out[..8])
  ));
  assert!(!encode_request_head_run(
    black_box("GET"),
    black_box(&ORIGIN),
    black_box(headers),
    black_box(&mut [])
  ));
  // A method that is not a token, and a field value carrying a control byte.
  assert!(!encode_request_head_run(
    black_box("G T"),
    black_box(&ORIGIN),
    black_box(headers),
    black_box(&mut out)
  ));
  assert!(!encode_request_head_run(
    black_box("GET"),
    black_box(&ORIGIN),
    black_box(&[("Host", b"exa\x00mple")]),
    black_box(&mut out)
  ));
}

// ── head scan ─────────────────────────────────────────────────────────────────
//
// NOTE — the head scan is NOT wrapped in `#[no_panic]`. `scan_head` calls
// through the line delimiter, the shared field-line validator, the RFC 9110
// §5.6 grammar validators and the key-field recorder — a call tree whose depth
// prevents full inlining into a single shim. Its panic-freedom is held by the
// crate-wide clippy lint wall (`unwrap_used` / `indexing_slicing` /
// `arithmetic_side_effects` / … in `lib.rs`), transitively covering exactly
// these functions. The smoke below still *runs* the path in release so any
// panic would surface as a test failure.

fn scan_head_run(head: &[u8]) -> bool {
  match scan_head(head) {
    Err(_) => true, // a grammar violation is not a panic
    Ok(view) => {
      // The view re-walks the block on demand, so the walk is the other half of
      // the path and has to be driven here.
      for (name, value) in view.headers() {
        let _ = (name, value);
      }
      let _ = view.header("host");
      let _ = view.field_count();
      true
    }
  }
}

#[test]
fn scan_head_runs_clean() {
  // A whole head, its start-line delimited and its two field lines validated.
  assert!(scan_head_run(black_box(
    b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
  )));
  // A response head — the scanner does not parse either start line.
  assert!(scan_head_run(black_box(
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
  )));
  // Repeated and empty-valued fields, which the key-field recorder counts.
  assert!(scan_head_run(black_box(
    b"GET / HTTP/1.1\r\nHost:\r\nX-A: 1\r\nX-A: 2\r\n\r\n"
  )));
  // Blocks that never terminate, start empty, or fold — Err, never a panic.
  assert!(scan_head_run(black_box(
    b"GET / HTTP/1.1\r\nHost: example.com\r\n"
  )));
  assert!(scan_head_run(black_box(b"\r\n\r\n")));
  assert!(scan_head_run(black_box(
    b"GET / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n"
  )));
  assert!(scan_head_run(black_box(b"")));
  // Garbage.
  assert!(scan_head_run(black_box(&[
    0xff, 0xfe, 0x0d, 0x0a, 0x0d, 0x0a
  ])));
}

// ── connection handle + drain (server role) ───────────────────────────────────

/// One full receive step: `handle` → drain items → drain events.
///
/// NOTE — this path is NOT wrapped in `#[no_panic]`. The call tree fans out
/// across the whole receive FSM; its panic-freedom is held by the crate-wide
/// clippy lint wall (`unwrap_used` / `indexing_slicing` /
/// `arithmetic_side_effects` / … in `lib.rs`), transitively covering exactly
/// these functions. This smoke still *runs* the path in release so any panic
/// would surface as a test failure.
fn handle_step(
  conn: &mut http1_proto::Connection<http1_proto::Server, http1_proto::General>,
  bytes: &[u8],
) -> bool {
  {
    let mut items = conn.handle(bytes);
    loop {
      match items.next() {
        Ok(None) => break,
        Ok(Some(_)) => {}
        Err(_) => break, // protocol error, not a panic
      }
    }
  }
  while conn.poll_event().is_some() {}
  let _ = conn.wants_read();
  true
}

#[test]
fn connection_handle_step_runs_clean() {
  use http1_proto::{Connection, General, Server};
  let mut conn = Connection::<Server, General>::new();

  // A whole exchange: a chunked request head, one chunk, the last chunk and an
  // empty trailer section.
  assert!(handle_step(
    black_box(&mut conn),
    black_box(b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n")
  ));
  assert!(handle_step(
    black_box(&mut conn),
    black_box(b"5\r\nhello\r\n")
  ));
  assert!(handle_step(black_box(&mut conn), black_box(b"0\r\n\r\n")));

  // A partial head — must not panic.
  let mut conn = Connection::<Server, General>::new();
  assert!(handle_step(black_box(&mut conn), black_box(b"GET / HTTP")));
  assert!(handle_step(black_box(&mut conn), black_box(b"")));
  // Garbage.
  let mut conn = Connection::<Server, General>::new();
  assert!(handle_step(
    black_box(&mut conn),
    black_box(&[0xff, 0xfe, 0x00, 0x0d, 0x0a])
  ));
}

// ── the lie-check: this file's own guard against going vacuous ────────────────
//
// PERMANENT, and it is the thing that makes every assertion above mean
// something. `no-panic` proves a shim panic-free by failing the LINK when a
// reachable panic edge survives into it — so a shim that was never instantiated
// over opaque input, or a build whose optimizer folded the call away, "passes"
// with an empty proof. That failure mode is silent by construction: nothing in
// a green run distinguishes "proved panic-free" from "never compiled".
//
// So the file carries a shim that MUST NOT link. Under the internal
// `test-no-panic-lie` feature (which implies `test-no-panic`) the build below
// indexes a `black_box`-fed slice — a bounds check the optimizer cannot prune,
// because `black_box` is exactly the barrier that stops it proving the length —
// and `no-panic` therefore refuses to link it. CI asserts that the build FAILS
// (see the `no-panic` job in `.github/workflows/ci.yml`); a green build there is
// the report that the guard has stopped working, whether the cause is a dropped
// `black_box`, a profile without fat LTO, or a `no-panic` release that no longer
// emits the symbol.
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
  assert_eq!(shim_lie(black_box(b"x")), b'x');
}
