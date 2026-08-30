//! Link-time panic-freedom verification for this crate's hot leaf paths.
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
//! Coverage: `parameterised_list`, `parse_qvalue`, `weight_for`,
//! `parse_http_date`, `format_imf_fixdate`, `EntityTag::parse`,
//! `TagList::parse`, `RangesSpecifier::parse`, `RangesSpecifier::resolve`,
//! `ContentRange::parse`, `ContentRange::encode`, `auth::auth_param`,
//! `auth::token68_end`, `auth::credentials`, `auth::challenges` and
//! `auth::auth_info` are each link-checked via
//! `#[no_panic]` shims — the join-aware RFC 9110 §5.6.6 list walk, whose
//! cursors run over borrowed field lines the caller supplies and whose member
//! boundaries cross the §5.2 join; the §12.4.2 `qvalue` reader, whose
//! position-scaled accumulation is this crate's only checked accumulation; the
//! §12.5.1 weight selection, driven over the whole walk (the field's lines and
//! the §5.2 join between them, the range iterator, each range's parameter walk
//! and the candidate's, and the bounded per-instance match between the two);
//! §5.6.7's two halves — the reader, three fixed-column walks over an input
//! whose length it fixes itself plus the epoch conversion behind them, and the
//! writer, whose one bounds check stands between a caller's buffer and
//! twenty-nine bytes; and §11's authentication leaves — the `auth-param`
//! production with its `BWS`, the `token68` run behind it, and the three
//! entry points that read one credential, a list of challenges, and a bare
//! parameter list.
//!
//! **What that list does NOT cover is named where the shims are, not left to
//! be inferred from its absence.** The `§11's authentication leaves` section
//! below opens with the omissions its five shims leave — a `Display` impl no
//! shim in this file covers, and the instantiations of a generic entry point
//! that a shim driving ONE iterator type does not reach. al8n/wren#69 is the
//! issue filed when a 3312-line file went unshimmed and nothing said so; a gap
//! that reads as coverage is the defect, and a gap with its reason beside it is
//! not.
//!
//! # Why the proof lives here rather than in `http1-proto`'s copy
//!
//! NOT because a shim cannot reach across a crate boundary. It can, and it did.
//! While these three shims still sat in `http1-proto/tests/no_panic.rs` — after
//! `grammar` and `media` had already moved into this crate — a reachable `v[0]`
//! injected into `media::parse_qvalue` failed that crate's release + fat-LTO
//! link with `no-panic` naming `shim_parse_qvalue` AND `shim_weight_for`, and
//! the same injection into `grammar::is_token`, the §5.6.6 walk's default
//! member-name rule, named `shim_parameterised_list` and `shim_weight_for`.
//! Both measured on this branch, immediately before the move; either one on its
//! own refutes the claim that a cross-crate shim proves nothing. Fat LTO is
//! what makes such a shim provable and it was doing so, so the reasons to move
//! are the three below and not that one.
//!
//! **The proof travels with the code it proves.** An edit to `grammar` or
//! `media` and the shim covering it now land in one crate and one review. Split
//! across two, the shim is a file that a change to this crate does not open,
//! and the link failure it raises arrives out of a crate the author was not
//! editing — which is also how the `fn`-pointer hazard below took a while to
//! read.
//!
//! **`media::parse_qvalue` goes back to `pub(crate)`.** A crate boundary admits
//! no visibility narrower than `pub`, so serving `http1-proto`'s test meant
//! publishing a bare `qvalue` reader in this crate's API permanently, for no
//! caller — the derivation callers want is `weight_for`. The shim reaches it
//! through the feature-gated, doc-hidden `__no_panic_internals` forwarder
//! instead, and the function is crate-private again.
//!
//! **This crate's own `panic-free` claim gets a proof of its own.** Its
//! `Cargo.toml` description and its README both say `panic-free`; every sibling
//! that says so — `websocket-proto`, `http1-proto`, `http3-proto` — carries its
//! own `tests/no_panic.rs`, and until this file existed `http-semantics` was
//! the one making the claim with no link proof of its own. It was not
//! unproven: `http1-proto`'s step did red on a regression in this crate's
//! code, which is the measurement above. It was proved CONTINGENTLY — the
//! coverage belonged to another crate's test file and lasted exactly as long as
//! that file chose to carry these three shims. Deleting them there would have
//! been a green diff in a crate that owes this one nothing, and this crate's
//! own gates would have said the same thing before and after. A proof that can
//! be dropped by an edit its subject cannot see is the failure mode the
//! lie-control below exists for, one level up.
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
//! link. EVERY argument at EVERY call site below is wrapped.
//!
//! [`the_link_proof_is_not_vacuous`] is the permanent check that this still
//! holds: under the internal `test-no-panic-lie` feature the file grows one
//! shim with a deliberately reachable panic, fed through `black_box` exactly as
//! the real ones are, and BUILDING IT MUST FAIL. CI asserts that failure (see
//! the `no-panic` job), so a future change that disarms the guard — a dropped
//! `black_box`, a profile without LTO, a `no-panic` release that stops
//! emitting the symbol — turns that step green and reds the build.
//!
//! # Two shims may not share one `fn`-pointer instantiation
//!
//! The other way a shim here stops being provable, and unlike the one above it
//! fails LOUDLY — on a shim you did not touch.
//!
//! A generic walk that takes its behaviour as a `fn(&[u8]) -> bool` POINTER
//! rather than as a type parameter monomorphizes ONCE per iterator type, no
//! matter how many different predicates are passed to it.
//! `grammar::parameterised_list` and the
//! `parameterised_list_with(…, is_media_name)` behind `media::accept` are that
//! case: driven from the same adapter they are one and the same
//! `ParameterisedList<…>`. Two `#[no_panic]` shims reaching that single
//! instantiation with two different predicate VALUES leave the pointer
//! un-constant-foldable — LLVM cannot devirtualize it, the indirect call
//! survives, and the unwind edge it carries empties BOTH proofs at once.
//!
//! So the link reds naming BOTH of them, and nothing in either body says why.
//! Giving [`shim_weight_for`] a field's LINES to walk is what reds
//! [`shim_parameterised_list`] beside it; that is how this was found. A shim
//! your change never touched appearing in the failure is EXPECTED here rather
//! than a second bug, and the shim you just edited is not necessarily the
//! cause: the fault belongs to the PAIR, not to either one. Removing either of
//! the two named shims makes the whole build link clean again — measured both
//! ways round, and it is the confirmation that this is what you are looking at.
//!
//! The remedy is ONE ADAPTER TYPE PER SHIM, so each gets its own instantiation
//! and each devirtualizes its own predicate: [`shim_parameterised_list`] drives
//! the walk through `Copied`, [`shim_weight_for`] through `Map`. A third shim
//! over one of those walks needs a third. The mechanism, the measurement behind
//! it, and the `clippy::map_clone` allow that stops the difference being tidied
//! back into `copied()` are recorded on [`shim_weight_for`] itself.
//!
//! Making the name rule a type parameter would remove the hazard by
//! monomorphizing per predicate. It is deliberately not done: it changes the
//! walker's signature with the crates built on it, and costs code size on
//! exactly the no-alloc tier this crate exists for. Filed as a follow-up rather
//! than owed — this subsection is what states the problem it would solve.
//!
//! # Running it
//!
//! Run it the way CI does. Two settings are part of the invocation rather than
//! optimizations:
//!
//! * **release** — `no-panic` only proves anything once the optimizer has
//!   pruned provably-dead panic branches. In debug the link guard is disabled
//!   (see the macro below) and would otherwise false-positive.
//! * **fat LTO** — the shims live in this test binary and the code under test
//!   lives in `http-semantics`, whose leaves are not `#[inline]`. Without
//!   whole-program optimization the linker sees an opaque cross-crate call that
//!   might unwind, and EVERY shim false-positives regardless of its body. LTO
//!   is what gives `no-panic` the whole body to reason about; it is set on the
//!   command line so the crate's own release profile stays untouched.
//!
//! ```sh
//! CARGO_PROFILE_RELEASE_LTO=fat \
//!   cargo test -p http-semantics --release --features test-no-panic --test no_panic
//!
//! # …and the lie-check, which MUST fail to build:
//! ! CARGO_PROFILE_RELEASE_LTO=fat \
//!   cargo test -p http-semantics --release --features test-no-panic-lie --test no_panic
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

use http_semantics::{
  __no_panic_internals::{ValueTail, auth_param, parse_qvalue, token68_end},
  auth::{auth_info, challenges, credentials},
  date::{HttpDate, IMF_FIXDATE_LEN, format_imf_fixdate, parse_http_date, parse_http_date_from},
  grammar::{ParamValue, parameterised_list},
  media::{media_type, weight_for},
  range::{ContentRange, RangesSpecifier, Resolved},
  validator::{EntityTag, TagList},
};

// ── parameterised-list walk ───────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over `grammar::parameterised_list` — the RFC 9110 §5.6.6 list walk,
  /// driven through BOTH its levels, since the member iterator hands its work
  /// to a `ParamIter` the caller drives separately.
  ///
  /// Returns the bytes it read, so nothing here can be optimized out as
  /// unused: a call whose result is dead takes the shim's body with it and
  /// proves nothing.
  fn shim_parameterised_list(lines: &[&[u8]]) -> usize {
    let mut seen = 0usize;
    for member in parameterised_list(lines.iter().copied()) {
      let Ok(member) = member else { break };
      seen = seen.wrapping_add(member.name().len());
      for param in member.params() {
        let Ok((name, value)) = param else { break };
        seen = seen.wrapping_add(name.len());
        seen = seen.wrapping_add(match value {
          ParamValue::Token(bytes) | ParamValue::Quoted(bytes) => bytes.len(),
          // `#[non_exhaustive]`: `None` carries no bytes, and neither does a
          // variant this file has not been taught yet.
          _ => 0,
        });
      }
    }
    seen
  }
}

#[test]
fn parameterised_list_is_panic_free() {
  // One line, with a quoted comma and a quoted semicolon that are data.
  assert!(
    shim_parameterised_list(black_box(&[
      b"permessage-deflate; client_max_window_bits=10, x-private; note=\"a,b;c\"".as_slice(),
    ]))
      > 0
  );
  // A value that spans the §5.2 join, and the member behind it.
  assert!(shim_parameterised_list(black_box(&[b"ext; q=\"a".as_slice(), b"b\", other"])) > 0);
  // The same string left open when the LAST line ends.
  assert!(shim_parameterised_list(black_box(&[b"ext; q=\"a".as_slice(), b"b"])) > 0);
  // Empty elements, empty lines, and OWS-only lines.
  assert!(
    shim_parameterised_list(black_box(&[
      b", ext ,, other,".as_slice(),
      b"",
      b" ",
      b"last"
    ]))
      > 0
  );
  // A name that is not a token, a forbidden byte inside a quoted-string, no
  // lines at all, an empty line, and garbage: Err or nothing, never a panic.
  assert_eq!(
    shim_parameterised_list(black_box(&[b"ext@1".as_slice()])),
    0
  );
  assert_eq!(
    shim_parameterised_list(black_box(&[b"ext; q=\"a\x00b\"".as_slice()])),
    0
  );
  assert_eq!(shim_parameterised_list(black_box(&[])), 0);
  assert_eq!(shim_parameterised_list(black_box(&[b"".as_slice()])), 0);
  assert_eq!(
    shim_parameterised_list(black_box(&[[0xff, 0xfe, 0x00].as_slice()])),
    0
  );
}

// ── qvalue reader ─────────────────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over `media::parse_qvalue` — the `qvalue` reader whose digit
  /// accumulation is the media feature's only CHECKED accumulation.
  fn shim_parse_qvalue(v: &[u8]) -> u16 {
    match parse_qvalue(v) {
      Some(w) => w.thousandths(),
      None => 0,
    }
  }
}

#[test]
fn parse_qvalue_is_panic_free() {
  // The accumulation itself: three places, each scaled by its position, and
  // the largest and smallest sums the grammar admits.
  assert_eq!(shim_parse_qvalue(black_box(b"0.999".as_slice())), 999);
  assert_eq!(shim_parse_qvalue(black_box(b"0.001".as_slice())), 1);
  assert_eq!(shim_parse_qvalue(black_box(b"1.000".as_slice())), 1000);
  // `[ "." 0*3DIGIT ]` admits zero digits after the dot, and the bare forms
  // never enter the loop at all.
  assert_eq!(shim_parse_qvalue(black_box(b"0.".as_slice())), 0);
  assert_eq!(shim_parse_qvalue(black_box(b"1.".as_slice())), 1000);
  assert_eq!(shim_parse_qvalue(black_box(b"1".as_slice())), 1000);
  // Refusals, each reaching a different exit: a fourth digit, a byte ABOVE
  // `9`, a byte BELOW `0` (the checked subtraction's own edge), a first byte
  // that is neither `0` nor `1`, empty input, and a non-ASCII digit position.
  assert_eq!(shim_parse_qvalue(black_box(b"0.5000".as_slice())), 0);
  assert_eq!(shim_parse_qvalue(black_box(b"0.abc".as_slice())), 0);
  assert_eq!(shim_parse_qvalue(black_box(b"0.!!".as_slice())), 0);
  assert_eq!(shim_parse_qvalue(black_box(b"2".as_slice())), 0);
  assert_eq!(shim_parse_qvalue(black_box(b"".as_slice())), 0);
  assert_eq!(
    shim_parse_qvalue(black_box([0x30u8, 0x2e, 0xff].as_slice())),
    0
  );
}

// ── Accept weight selection ───────────────────────────────────────────────────

no_panic_shim! {
  /// Shim over `media::weight_for` — the §12.5.1 selection, driven over the
  /// whole walk: the range iterator, each range's parameter walk, and the
  /// candidate's, plus the per-instance match between them.
  ///
  /// Takes the field's LINES rather than one value, for the same reason
  /// `shim_parameterised_list` does: fixing the count at one monomorphizes
  /// `accept` over `[&[u8]; 1]` and leaves RFC 9110 §5.2's join branches —
  /// `ValueSpansFieldLines`, the after-join quoted scan — visibly dead, so the
  /// optimizer prunes the very code the proof is meant to cover.
  ///
  /// Returns the weight so nothing here is optimized out as unused.
  ///
  /// `map(|line| *line)` where `copied()` reads better, and clippy says so —
  /// hence the `allow`, which is the guardrail rather than an untidiness. The
  /// walker carries its member-name rule as a `fn(&[u8]) -> bool` POINTER, not
  /// as a generic parameter, so `parameterised_list(lines.iter().copied())` and
  /// the `parameterised_list_with(…, is_media_name)` behind `accept` are the
  /// SAME `ParameterisedList<Copied<Iter<'_, &[u8]>>>` instantiation. Two
  /// `#[no_panic]` shims reaching one instantiation with two different
  /// predicate values leave the pointer un-constant-foldable: LLVM keeps the
  /// indirect call, its unwind edge survives, and BOTH shims fail to link —
  /// `shim_parameterised_list` included, which is how this was found. A
  /// distinct adapter type gives each shim its own instantiation, the predicate
  /// devirtualizes in each, and both prove. Between the two shims `Copied` and
  /// `Map` are both covered, so nothing is lost by the split. Measured, not
  /// assumed: with `copied()` here the fat-LTO link fails naming both shims.
  #[allow(clippy::map_clone)]
  fn shim_weight_for(candidate: &[u8], lines: &[&[u8]]) -> u16 {
    match media_type(candidate) {
      Ok(m) => match weight_for(&m, lines.iter().map(|line| *line)) {
        Ok(w) => w.thousandths(),
        Err(_) => 0,
      },
      Err(_) => 0,
    }
  }
}

#[test]
fn weight_for_is_panic_free() {
  // §12.5.1's precedence over a field carrying both shapes, and over the §5.2
  // join: one repeated field is one comma-joined value, so the two ranges here
  // straddle a member boundary the walk has to reconstruct.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;q=0.5".as_slice(), b"*/*;q=0.1"])
    ),
    500
  );
  // The same field with an empty line between: §5.6.1.2 has the walk skip the
  // empty element the join produces.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;q=0.5".as_slice(), b"", b"*/*;q=0.1"])
    ),
    500
  );
  // A quoted value OPENED on one line and CLOSED on the next: well formed, not
  // one contiguous slice, and the branch a single-line fixture cannot reach.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;boundary=\"a".as_slice(), b"b\";q=0.5"])
    ),
    0
  );
  // The same string left OPEN when the last line ends.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;boundary=\"a".as_slice(), b"b"])
    ),
    0
  );
  // No lines at all is §12.4.1's ABSENCE, which short-circuits before the walk
  // and answers §12.4.2's default weight; one empty line is a field that WAS
  // sent, naming an empty list, which walks and matches nothing. Two inputs,
  // two answers, and the early return is a branch of its own to prove clean.
  assert_eq!(
    shim_weight_for(black_box(b"text/html".as_slice()), black_box(&[])),
    1000
  );
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"".as_slice()])
    ),
    0
  );
  // Each wildcard shape reached on its own.
  assert_eq!(
    shim_weight_for(
      black_box(b"application/json".as_slice()),
      black_box(&[b"*/*;q=0.25".as_slice()])
    ),
    250
  );
  assert_eq!(
    shim_weight_for(
      black_box(b"text/plain".as_slice()),
      black_box(&[b"text/*;q=0.75".as_slice()])
    ),
    750
  );
  // Nothing matched: §12.4.3's unacceptable, which is `Weight::ZERO`.
  assert_eq!(
    shim_weight_for(
      black_box(b"image/png".as_slice()),
      black_box(&[b"text/html".as_slice()])
    ),
    0
  );
  // The per-instance parameter match, over a quoted range value and over a
  // `quoted-pair` inside one — both reach `unescape_into`'s two passes and the
  // unescaped comparison.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html;charset=utf-8".as_slice()),
      black_box(&[b"text/html;charset=\"utf-8\";q=0.8".as_slice()])
    ),
    800
  );
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html;charset=utf-8".as_slice()),
      black_box(&[b"text/html;charset=\"ut\\f-8\";q=0.8".as_slice()])
    ),
    800
  );
  // A doubled parameter on both sides: the `taken` record has to spend two
  // distinct slots rather than the same one twice.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html;a=1;a=2".as_slice()),
      black_box(&[b"text/html;a=1;a=2;q=0.9".as_slice()])
    ),
    900
  );
  // The weight's own eight-byte unescape buffer: a quoted `qvalue` that fits,
  // and one longer than the buffer, which is `BufferTooSmall` lifted to
  // `BadWeight` rather than a write past the end.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;q=\"0.6\"".as_slice()])
    ),
    600
  );
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;q=\"000000000000\"".as_slice()])
    ),
    0
  );
  // Past `MAX_TRACKED_PARAMS` candidate instances, with a range parameter that
  // matches none of them, so the walk runs off the end of the record: refused,
  // never answered wrongly.
  assert_eq!(
    shim_weight_for(
      black_box(
        b"text/html;a=1;b=2;c=3;d=4;e=5;f=6;g=7;h=8;i=9;j=10;k=11;l=12;m=13;n=14;o=15;p=16;r=17"
          .as_slice()
      ),
      black_box(&[b"text/html;zz=1;q=0.4".as_slice()])
    ),
    0
  );
  // Faults on either side: a valueless range parameter, an unterminated
  // quoted-string, and a candidate that is a list.
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;q".as_slice()])
    ),
    0
  );
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[b"text/html;charset=\"ab".as_slice()])
    ),
    0
  );
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html, text/plain".as_slice()),
      black_box(&[b"*/*".as_slice()])
    ),
    0
  );
  // Empty input on both sides, then garbage on each side in turn, so neither
  // half can hide behind the other's refusal.
  assert_eq!(
    shim_weight_for(black_box(b"".as_slice()), black_box(&[b"".as_slice()])),
    0
  );
  assert_eq!(
    shim_weight_for(
      black_box([0xffu8, 0xfe, 0x00].as_slice()),
      black_box(&[b"*/*".as_slice()])
    ),
    0
  );
  assert_eq!(
    shim_weight_for(
      black_box(b"text/html".as_slice()),
      black_box(&[[0x2cu8, 0xff, 0x3b, 0x00].as_slice(), [0xfe].as_slice()])
    ),
    0
  );
}

// ── HTTP-date, both halves ────────────────────────────────────────────────────

/// 2026-01-01T00:00:00Z, this crate's own anchor — the reference instant a
/// caller with a clock in the year this was written would pass.
const NOW_2026: i64 = 1_767_225_600;

/// 0000-01-01T00:00:00Z, the earliest instant `year = 4DIGIT` can spell. The
/// fifty-year rule refuses most two-digit years measured from here, which is
/// the arm that would otherwise not be compiled.
const NOW_YEAR_ZERO: i64 = -62_167_219_200;

/// 9990-11-06T08:49:37Z, a clock late enough that the rule answers a year past
/// `year = 4DIGIT` — the input `format_imf_fixdate_is_panic_free` needs to
/// reach the writer's own ceiling.
const NOW_YEAR_9990: i64 = 253_113_497_377;

no_panic_shim! {
  /// Shim over `date::parse_http_date` and `date::parse_http_date_from` — the
  /// RFC 9110 §5.6.7 reader, which picks one of three formats from the input's
  /// own fourth byte and then walks that format's fixed columns.
  ///
  /// Both entry points, because the wrapper is not the general one: the fifty-
  /// year window is arithmetic over a reference INSTANT, and driving only
  /// `parse_http_date` hands it the crate's own CONSTANT anchor, which LLVM
  /// folds — leaving `fifty_year_window` proved over one input rather than
  /// compiled for real. `now_unix_seconds` arrives opaque, so it is not.
  ///
  /// That argument is an `i64` of seconds and every one of them is legal, so
  /// the two calendar conversions behind the window — `civil_from_days` on the
  /// way in and `days_from_civil` on the way back out — are compiled here over
  /// the whole of `i64` rather than over a plausible clock reading. The call
  /// sites drive both ends of it.
  ///
  /// `unix_seconds` is called on the way out rather than for the answer: it is
  /// where the epoch conversion and its four `div_euclid`s live, and nothing
  /// else in this file reaches them.
  ///
  /// Returns what it read, so nothing here is optimized out as unused.
  fn shim_parse_http_date(v: &[u8], now_unix_seconds: i64) -> i64 {
    let anchored = match parse_http_date(v) {
      Ok(date) => date.unix_seconds(),
      Err(_) => 0,
    };
    let measured = match parse_http_date_from(v, now_unix_seconds) {
      Ok(date) => i64::from(date.year()),
      Err(_) => 0,
    };
    anchored.wrapping_add(measured)
  }
}

#[test]
fn parse_http_date_is_panic_free() {
  // §5.6.7's own worked example, one instant in all three formats, so each of
  // the three column walks is compiled over input the optimizer cannot see.
  for input in [
    b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
    b"Sunday, 06-Nov-94 08:49:37 GMT",
    b"Sun Nov  6 08:49:37 1994",
  ] {
    assert!(shim_parse_http_date(black_box(input), black_box(NOW_2026)) > 0);
  }
  // The epoch conversion on both sides of its own origin, and at the far end of
  // `year = 4DIGIT`, where the era arithmetic floors rather than truncates.
  assert_eq!(
    shim_parse_http_date(
      black_box(b"Thu, 01 Jan 1970 00:00:00 GMT".as_slice()),
      black_box(NOW_2026)
    ),
    1970
  );
  assert!(
    shim_parse_http_date(
      black_box(b"Sat, 01 Jan 0000 00:00:00 GMT".as_slice()),
      black_box(NOW_2026)
    ) < 0
  );
  // The two-digit window, driven across the whole domain of the argument, since
  // every `i64` of seconds is an instant. `i64::MIN` and `i64::MAX` put
  // `civil_from_days` at the far ends of what it can be asked, and with
  // `NOW_YEAR_ZERO` they are the three at which §5.6.7's rule names a year
  // outside `u16` and the parse REFUSES — so the refusing arm is compiled here
  // rather than pruned. The other three answer: `94` reads as 1994 from the
  // epoch and from 2026, and as 9994 from `NOW_YEAR_9990`. The anchored half of
  // the answer is what keeps the sum non-zero across all six.
  for reference in [
    i64::MIN,
    NOW_YEAR_ZERO,
    0,
    NOW_2026,
    NOW_YEAR_9990,
    i64::MAX,
  ] {
    assert!(
      shim_parse_http_date(
        black_box(b"Sunday, 06-Nov-94 08:49:37 GMT".as_slice()),
        black_box(reference)
      ) != 0
    );
  }
  // A refusal reaching each of the rules: no fourth byte at all, a length no
  // format has, a name, a month, a separator, a zone, a field out of range, and
  // bytes that are not ASCII at every column the walks read.
  for refused in [
    b"".as_slice(),
    b"Sun",
    b"Sun, 06 Nov 1994",
    b"Xxx, 06 Nov 1994 08:49:37 GMT",
    b"Sun, 06 Xxx 1994 08:49:37 GMT",
    b"Sun, 06 Nov 1994 08.49:37 GMT",
    b"Sun, 06 Nov 1994 08:49:37 UTC",
    b"Wed, 31 Nov 1994 08:49:37 GMT",
    b"Sun, 06 Nov 19x4 08:49:37 GMT",
    &[0xffu8; 29],
    &[0xffu8; 30],
    &[0xffu8; 24],
    &[0x2cu8; 29],
  ] {
    assert_eq!(
      shim_parse_http_date(black_box(refused), black_box(NOW_2026)),
      0
    );
  }
}

no_panic_shim! {
  /// Shim over `date::format_imf_fixdate` — §5.6.7's writing half, whose one
  /// bounds check stands between a caller's buffer and twenty-nine bytes.
  ///
  /// The `HttpDate` arrives as an opaque REFERENCE and the buffer as an opaque
  /// slice, so neither the fields the writer spells nor the length it checks
  /// them against is a constant here. Parsing is deliberately left OUT of this
  /// shim: sharing a body with `shim_parse_http_date` would let a panic edge in
  /// the reader red this one too, and a shim should fail for the code it names.
  ///
  /// Returns the byte count so nothing here is optimized out as unused.
  fn shim_format_imf_fixdate(date: &HttpDate, out: &mut [u8]) -> usize {
    format_imf_fixdate(date, out).unwrap_or_default()
  }
}

#[test]
fn format_imf_fixdate_is_panic_free() {
  let mut out = [0u8; IMF_FIXDATE_LEN];
  // Every shape the writer has a branch for: the derived day name across the
  // epoch in both directions, the leap second `time-of-day` admits, and each
  // end of the year range it will spell — 1900, RFC 5322 §3.3's floor, and
  // 9999, `year = 4DIGIT`'s ceiling.
  for input in [
    b"Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
    b"Sun Nov  6 08:49:37 1994",
    b"Thu, 01 Jan 1970 00:00:00 GMT",
    b"Wed, 31 Dec 1969 23:59:59 GMT",
    b"Sun, 01 Jan 1900 00:00:00 GMT",
    b"Sun, 31 Dec 1995 23:59:60 GMT",
    b"Sun, 06 Nov 9999 08:49:37 GMT",
  ] {
    let date = parse_http_date(input).expect("a date this file supplies");
    assert_eq!(
      shim_format_imf_fixdate(black_box(&date), black_box(&mut out[..])),
      IMF_FIXDATE_LEN
    );
  }
  // The size check itself, over every length up to the exact one. `len` is
  // opaque, so the branch is compiled rather than folded — which is the whole
  // point of the shim: replace this check with an index and the link reds.
  let date = parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").expect("§5.6.7's own example");
  for len in 0..IMF_FIXDATE_LEN {
    let mut short = [0u8; IMF_FIXDATE_LEN];
    assert_eq!(
      shim_format_imf_fixdate(black_box(&date), black_box(&mut short[..len])),
      0
    );
  }
  // The two years the writer refuses with room to spare in the buffer, which
  // are its other two exits: one past `year = 4DIGIT`'s ceiling, and one below
  // RFC 5322 §3.3's floor. Both are dates this crate's own reader produced.
  let past_four_digits =
    parse_http_date_from(b"Sunday, 06-Nov-40 08:49:37 GMT", black_box(NOW_YEAR_9990))
      .expect("a five-digit year");
  assert_eq!(
    shim_format_imf_fixdate(black_box(&past_four_digits), black_box(&mut out[..])),
    0
  );
  let before_1900 =
    parse_http_date(b"Sat, 01 Jan 0000 00:00:00 GMT").expect("`year = 4DIGIT` spells 0000");
  assert_eq!(
    shim_format_imf_fixdate(black_box(&before_1900), black_box(&mut out[..])),
    0
  );
}

// ── §13's validators, and §14's ranges ───────────────────────────────────────

no_panic_shim! {
  /// Shim over `validator::EntityTag::parse` — RFC 9110 §8.8.3's `entity-tag`,
  /// the leaf every conditional field's tag path bottoms out in.
  ///
  /// Returns the opaque tag's length with the weak flag folded in, so nothing
  /// here is optimized out as unused and neither accessor can be dropped.
  fn shim_entity_tag(value: &[u8]) -> usize {
    match EntityTag::parse(value) {
      Ok(tag) => tag
        .opaque_tag()
        .len()
        .wrapping_add(usize::from(tag.is_weak())),
      Err(_) => 0,
    }
  }
}

#[test]
fn entity_tag_is_panic_free() {
  // §8.8.3's own two forms, and the shortest tag the grammar admits.
  assert!(shim_entity_tag(black_box(br#""xyzzy""#.as_slice())) > 0);
  assert!(shim_entity_tag(black_box(br#"W/"xyzzy""#.as_slice())) > 0);
  assert_eq!(shim_entity_tag(black_box(br#""""#.as_slice())), 0);
  // Each refusal on its own: no marks, one mark, a lone `W/`, a lowercase `w/`
  // (`weak = %s"W/"` is case-SENSITIVE), a byte outside `etagc`, and a
  // `quoted-string`-style escape, which an `entity-tag` does not admit.
  for refused in [
    b"xyzzy".as_slice(),
    br#""xyzzy"#,
    b"W/",
    br#"w/"xyzzy""#,
    b"\"xy\x7fzy\"",
    br#""xy\"zy""#,
    b"",
    &[0xffu8, 0x22, 0x00],
  ] {
    assert_eq!(shim_entity_tag(black_box(refused)), 0);
  }
}

no_panic_shim! {
  /// Shim over `validator::TagList::parse` — §13.1.1's and §13.1.2's
  /// `"*" / #entity-tag`, driven through the accessor walk as well, since the
  /// slots are read back one index at a time.
  ///
  /// Returns the bytes it read, so nothing here is optimized out as unused.
  fn shim_tag_list(value: &[u8]) -> usize {
    let Ok(list) = TagList::parse(value) else {
      return 0;
    };
    if list.is_star() {
      return 1;
    }
    let mut seen = 0usize;
    // One past the end as well: `get` answers `None` there, and an index the
    // caller chose is exactly the shape a bounds check has to survive.
    for index in 0..=list.len() {
      if let Some(tag) = list.get(index) {
        seen = seen.wrapping_add(tag.opaque_tag().len());
      }
    }
    seen
  }
}

#[test]
fn tag_list_is_panic_free() {
  // §13.1.1's own three examples.
  assert!(shim_tag_list(black_box(br#""xyzzy""#.as_slice())) > 0);
  assert!(shim_tag_list(black_box(br#""xyzzy", "r2d2xxxx", "c3piozzzz""#.as_slice())) > 0);
  assert_eq!(shim_tag_list(black_box(b"*".as_slice())), 1);
  // §5.6.1.2's empty elements, which spend no slot, and the empty list the
  // grammar still admits.
  assert!(shim_tag_list(black_box(br#", ,"xyzzy", ,"#.as_slice())) > 0);
  assert_eq!(shim_tag_list(black_box(b"".as_slice())), 0);
  // Exactly `MAX_TAGS`, and one past it: the second is the refusal that
  // constant documents, and it is the loop's own boundary.
  let mut full = std::vec::Vec::new();
  for _ in 0..http_semantics::validator::MAX_TAGS {
    full.extend_from_slice(br#""a","#);
  }
  full.pop();
  assert!(shim_tag_list(black_box(full.as_slice())) > 0);
  full.extend_from_slice(br#","a""#);
  assert_eq!(shim_tag_list(black_box(full.as_slice())), 0);
  // A member that is not an `entity-tag`, `*` beside another value (§13.1.1's
  // own closing note), and bytes that are not ASCII at all.
  for refused in [
    b"not-a-tag".as_slice(),
    br#""a", *"#,
    b"*, *",
    &[0xffu8, 0x2c, 0x22],
  ] {
    assert_eq!(shim_tag_list(black_box(refused)), 0);
  }
}

no_panic_shim! {
  /// Shim over `range::RangesSpecifier::parse` — §14.1.1's grammar with
  /// §14.1.2's digit-string validity, the deepest arithmetic-free walk this
  /// cycle adds.
  ///
  /// Returns the range-spec count so nothing here is optimized out as unused,
  /// with the non-`bytes` set's length folded in so `other_range_set` is
  /// reached too — a specifier under another unit holds no specs at all, and a
  /// count alone would report it as a refusal.
  fn shim_ranges_specifier(value: &[u8]) -> usize {
    match RangesSpecifier::parse(value) {
      Ok(spec) => spec
        .len()
        .wrapping_add(spec.other_range_set().map_or(0, <[u8]>::len))
        .wrapping_add(spec.unit().len()),
      Err(_) => 0,
    }
  }
}

no_panic_shim! {
  /// Shim over `range::RangesSpecifier::resolve` — §14.1.2's satisfiability and
  /// its two normalisations, which are this crate's only new checked
  /// arithmetic. Separate from the parse above so that each fails for the code
  /// it names.
  ///
  /// `complete_length` and the index both arrive opaque, so neither
  /// `checked_sub` nor the slot lookup is a constant here — the length is the
  /// whole of `u64` rather than a plausible representation size, and the index
  /// runs past the end.
  ///
  /// Returns the resolved positions so nothing here is optimized out as unused.
  fn shim_resolve(value: &[u8], index: usize, complete_length: u64) -> u64 {
    let Ok(spec) = RangesSpecifier::parse(value) else {
      return 0;
    };
    match spec.resolve(index, complete_length) {
      Some(Resolved::Range(first, last)) => first.wrapping_add(last).wrapping_add(1),
      Some(Resolved::EmptyRepresentation) => 2,
      Some(Resolved::Unsatisfiable) => 3,
      None => 0,
    }
  }
}

#[test]
fn ranges_specifier_is_panic_free() {
  // §14.1.1's own example, both forms of `range-spec`, and a unit that is not
  // `bytes` — which is the one input that reaches `other_range_set`.
  assert!(shim_ranges_specifier(black_box(b"bytes=0-499".as_slice())) > 0);
  assert!(shim_ranges_specifier(black_box(b"bytes=0-499, -500, 9500-".as_slice())) > 0);
  assert!(shim_ranges_specifier(black_box(b"exampleunit=1.2-4.3".as_slice())) > 0);
  // Erratum 7306's OWS after the `=`, which belongs to neither side.
  assert!(shim_ranges_specifier(black_box(b"bytes=  0-499".as_slice())) > 0);
  // Exactly `MAX_RANGE_SPECS`, then one past it.
  assert!(shim_ranges_specifier(black_box(b"bytes=0-,1-,2-,3-,4-,5-,6-,7-".as_slice())) > 0);
  assert_eq!(
    shim_ranges_specifier(black_box(b"bytes=0-,1-,2-,3-,4-,5-,6-,7-,8-".as_slice())),
    0
  );
  // A numeral past `u64::MAX` is NOT a refusal here, unlike in a
  // `Content-Range`: §14.1.2's "recipients MUST anticipate potentially large
  // decimal numerals and prevent parsing errors due to integer conversion
  // overflows" is met by `Pos::Beyond`, a position above every length, so the
  // specifier parses and `resolve` below is where it settles.
  assert!(shim_ranges_specifier(black_box(b"bytes=18446744073709551616-".as_slice())) > 0);
  // Each refusal on its own: no `=`, a unit that is not a token, an empty
  // range-set under `bytes` and under another unit, a spec that is neither
  // form, and bytes that are not ASCII.
  for refused in [
    b"0-499".as_slice(),
    b"by tes=0-499",
    b"bytes=",
    b"bytes=,,",
    b"exampleunit=",
    b"bytes=abc",
    b"",
    &[0xffu8, 0x3d, 0x2d],
  ] {
    assert_eq!(shim_ranges_specifier(black_box(refused)), 0);
  }

  // §14.1.2's three answers, and the arithmetic under each. The length runs to
  // both ends of `u64` and the index past the last slot, because every one of
  // those is a value a caller may pass.
  for &(value, index, length) in &[
    // An int-range inside, at, and past the length; a last-pos at and past it.
    (b"bytes=0-499".as_slice(), 0usize, 10_000u64),
    (b"bytes=9500-", 0, 10_000),
    (b"bytes=0-99999", 0, 10_000),
    (b"bytes=10000-", 0, 10_000),
    (b"bytes=0-499", 0, 0),
    (b"bytes=0-499", 1, 10_000),
    // A first-pos and a last-pos no `u64` holds — `Pos::Beyond` on each side.
    (b"bytes=18446744073709551616-", 0, 10_000),
    (b"bytes=0-18446744073709551616", 0, 10_000),
    // Every suffix-range shape: zero, shorter than the length, longer than it,
    // past `u64`, and each against a zero length.
    (b"bytes=-0", 0, 10_000),
    (b"bytes=-500", 0, 10_000),
    (b"bytes=-99999", 0, 10_000),
    (b"bytes=-18446744073709551616", 0, 10_000),
    (b"bytes=-500", 0, 0),
    (b"bytes=-0", 0, 0),
    (b"bytes=-500", 0, u64::MAX),
    (b"bytes=0-499", 0, u64::MAX),
    // Nothing to resolve: another unit's set, and a value that did not parse.
    (b"exampleunit=1.2-4.3", 0, 10_000),
    (b"bytes=abc", 0, 10_000),
  ] {
    let _ = black_box(shim_resolve(
      black_box(value),
      black_box(index),
      black_box(length),
    ));
  }
  // The two answers a zero length separates, asserted rather than merely run.
  assert_eq!(
    shim_resolve(
      black_box(b"bytes=-500".as_slice()),
      black_box(0),
      black_box(0)
    ),
    2
  );
  assert_eq!(
    shim_resolve(
      black_box(b"bytes=0-499".as_slice()),
      black_box(0),
      black_box(0)
    ),
    3
  );
}

no_panic_shim! {
  /// Shim over `range::ContentRange::parse` — §14.4's `range-resp`,
  /// `unsatisfied-range` and the `other-range-resp` span it hands back unread,
  /// plus §14.4's own two validity rules, which the constructor applies.
  ///
  /// Returns the positions it read so nothing here is optimized out as unused.
  fn shim_content_range_parse(value: &[u8]) -> u64 {
    let Ok(range) = ContentRange::parse(value) else {
      return 0;
    };
    let (first, last) = range.incl_range().unwrap_or((0, 0));
    first
      .wrapping_add(last)
      .wrapping_add(range.complete_length().unwrap_or(0))
      .wrapping_add(range.unit().len() as u64)
      .wrapping_add(range.other_range_resp().map_or(0, <[u8]>::len) as u64)
      .wrapping_add(u64::from(range.is_unsatisfied()))
      .wrapping_add(1)
  }
}

no_panic_shim! {
  /// Shim over `range::ContentRange::encode` — §14.4's writing half, whose one
  /// size test stands between a caller's buffer and the value.
  ///
  /// The value arrives as an opaque REFERENCE and the buffer as an opaque
  /// slice, so neither the digits it spells nor the length it checks them
  /// against is a constant here. Reading is left OUT of this shim, for the
  /// reason `shim_format_imf_fixdate` states: a shim should fail for the code
  /// it names.
  ///
  /// Returns the byte count so nothing here is optimized out as unused.
  fn shim_content_range_encode(range: &ContentRange<'_>, out: &mut [u8]) -> usize {
    range.encode(out).unwrap_or_default()
  }
}

#[test]
fn content_range_is_panic_free() {
  // §14.4's own printed examples: a `range-resp` with a known length, one with
  // an unknown one, and an `unsatisfied-range`.
  for accepted in [
    b"bytes 42-1233/1234".as_slice(),
    b"bytes 42-1233/*",
    b"bytes */1234",
    b"bytes 0-0/1",
    // §14.6's own `other-range-resp`, which the digits do not admit and which
    // is handed back unread.
    b"exampleunit 1.2-4.3/25",
  ] {
    assert!(shim_content_range_parse(black_box(accepted)) > 0);
  }
  // Each refusal on its own: no `SP`, a unit that is not a token, a second `SP`
  // in another unit's span, an empty span, `*/​*` (neither alternative), a
  // last-pos below the first (§14.4's first validity rule), a range at or past
  // the complete length (its second), a numeral past `u64::MAX`, and non-ASCII.
  for refused in [
    b"bytes42-1233/1234".as_slice(),
    b"by tes 42-1233/1234",
    b"exampleunit 1.2 4.3/25",
    b"exampleunit ",
    b"bytes */*",
    b"bytes 1233-42/1234",
    b"bytes 42-1233/1000",
    b"bytes 42-18446744073709551616/*",
    b"bytes */18446744073709551616",
    b"bytes 42-1233",
    b"",
    &[0xffu8, 0x20, 0x2f],
  ] {
    assert_eq!(shim_content_range_parse(black_box(refused)), 0);
  }

  // The writer, over every form it spells, and over every buffer length up to
  // the exact one — `len` is opaque, so the size test is compiled rather than
  // folded.
  let mut out = [0u8; 64];
  for value in [
    b"bytes 42-1233/1234".as_slice(),
    b"bytes 42-1233/*",
    b"bytes */1234",
    b"bytes */18446744073709551615",
    b"exampleunit 1.2-4.3/25",
  ] {
    let range = ContentRange::parse(value).expect("a value this test supplies");
    let written = black_box(shim_content_range_encode(
      black_box(&range),
      black_box(&mut out[..]),
    ));
    assert!(written > 0);
    for len in 0..written {
      let mut short = [0u8; 64];
      assert_eq!(
        shim_content_range_encode(black_box(&range), black_box(&mut short[..len])),
        0
      );
    }
  }
}

// ── §11's authentication leaves ──────────────────────────────────────────────
//
// WHAT IS NOT PROVEN HERE, said where the coverage is claimed rather than left
// to be inferred from its absence — al8n/wren#69 is the issue filed when a
// 3312-line file went unshimmed and nothing said so:
//
// * **`Display`.** `AuthError` and `ValueSpansFieldLines` derive theirs from
//   `thiserror`, and no shim in this file covers a `Display` impl — not
//   theirs, and not `TagError`'s or `RangeError`'s either. Formatting a
//   fixed string is not a leaf this file proves; it is one no shim has been
//   written for.
// * **Every instantiation but one, for the two generic entry points.**
//   `challenges` and `auth_info` take `I: IntoIterator<Item = &'a [u8]>` and
//   monomorphize per `I`. The shims below drive ONE — the `Copied<Iter<'_,
//   &[u8]>>` a slice gives — so what is proven is the walk's own code compiled
//   against that iterator. A caller handing them another iterator type gets a
//   second instantiation, and no `#[no_panic]` guard was ever put on it. The
//   crate's other list walks are in the same position; this is the first place
//   it is written down.
//
// What IS proven beyond the five shims' own names: `auth::token68` — the
// READING, as against `token68_end`'s run — and `Credential::read`,
// `BodyLines`, `SeenNames`, `ParamWalk` and the `Challenges`/`AuthInfo` steps
// have no shim of their own and need none. `credentials`, `challenges` and
// `auth_info` are their only entrances, and the fat LTO these steps run under
// inlines them into the three shims that drive those. That is coverage by
// inlining, and it is the same claim every other shim in this file makes
// about the leaves beneath its own entry point.

no_panic_shim! {
  /// Shim over `auth::auth_param` — RFC 9110 §11.2's
  /// `auth-param = token BWS "=" BWS ( token / quoted-string )`, read over one
  /// list element with the list's own `OWS` already off both ends.
  ///
  /// Reached through the `__no_panic_internals` forwarder: the walks above it
  /// are the crate's entry points and this is not, so it stays `pub(crate)`.
  ///
  /// `tail` is the `ValueTail` the `__no_panic_internals` forwarder mirrors the
  /// crate-private one as, and it is driven ALL THREE ways below. It is what
  /// separates a quoted value RFC 9110 §5.2's field-line join closed on a
  /// later line from one that closed there and then ran on past its close, and
  /// from one that never closes at all; the three take different exits. An
  /// enum, so there is no fourth value to drive and no arm that swallows one.
  ///
  /// Returns the bytes it read with `value()`'s answer folded in, so nothing
  /// here is optimized out as unused and neither accessor can be dropped.
  fn shim_auth_param(element: &[u8], tail: ValueTail) -> usize {
    let Ok(param) = auth_param(element, tail) else {
      return 0;
    };
    param.name().len().wrapping_add(match param.value() {
      Ok(ParamValue::Token(bytes) | ParamValue::Quoted(bytes)) => bytes.len(),
      // `#[non_exhaustive]`: `None` is unreachable for an `auth-param` — the
      // production names a value — and carries no bytes in any case, and
      // neither does a variant this file has not been taught yet.
      Ok(_) => 0,
      // The value crossed the join, so it is real and is not one slice.
      Err(_) => 1,
    })
  }
}

#[test]
fn auth_param_is_panic_free() {
  // RFC 9110 §11.2's two notations, and the §5.6.3 BWS a recipient removes
  // before interpreting the element — which is this production's own, and is
  // what §5.6.6's `parameter` walker refuses.
  let ends = ValueTail::Ends;
  assert!(shim_auth_param(black_box(br#"realm="x""#.as_slice()), black_box(ends)) > 0);
  assert!(shim_auth_param(black_box(b"realm=x".as_slice()), black_box(ends)) > 0);
  assert!(
    shim_auth_param(
      black_box(b"realm \t = \t \"x\"".as_slice()),
      black_box(ends)
    ) > 0
  );
  // A `quoted-pair`, which an `auth-param` value admits.
  assert!(shim_auth_param(black_box(br#"nonce="a\"b""#.as_slice()), black_box(ends)) > 0);
  // The join, all three ways: a value still open where the element ends is a
  // parameter when a later field line closed it and the element ended at that
  // close, a fault when bytes other than the list's own `OWS` stood behind the
  // close, and a fault when nothing closed it at all.
  assert!(
    shim_auth_param(
      black_box(b"opaque=\"a".as_slice()),
      black_box(ValueTail::Continues)
    ) > 0
  );
  assert_eq!(
    shim_auth_param(
      black_box(b"opaque=\"a".as_slice()),
      black_box(ValueTail::Trails)
    ),
    0
  );
  assert_eq!(
    shim_auth_param(black_box(b"opaque=\"a".as_slice()), black_box(ends)),
    0
  );
  // Each refusal on its own, and under every reading of the tail: no `=`, an
  // `=` with no value behind it, a name that is not a token, bytes behind a
  // closed string, a byte RFC 9110 §5.6.4 forbids inside one, nothing at all,
  // and bytes that are not ASCII.
  for refused in [
    b"realm".as_slice(),
    b"realm=",
    b"re alm=x",
    br#"realm="x"y"#,
    b"realm=\"a\x00b\"",
    b"",
    &[0xffu8, 0x3d, 0x22],
  ] {
    for tail in [ValueTail::Ends, ValueTail::Continues, ValueTail::Trails] {
      assert_eq!(shim_auth_param(black_box(refused), black_box(tail)), 0);
    }
  }
}

no_panic_shim! {
  /// Shim over `auth::token68_end` — the RUN behind RFC 9110 §11.2's
  /// `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`,
  /// which is two loops with no way back to the first.
  ///
  /// `at` arrives opaque and is driven PAST the end of `value`, because it is
  /// a cursor the caller carries and a bounds check on it is exactly what this
  /// has to survive.
  ///
  /// The READING built on that run — whether the bytes it names are taken as a
  /// `token68` at all — is `auth::token68`'s, and it has no shim of its own:
  /// it is reachable only through `credentials` and `challenges`, whose shims
  /// inline it.
  ///
  /// Returns the end it found, so nothing here is optimized out as unused.
  /// `None` and `Some(0)` are one answer here and cannot be confused: the run
  /// has a floor of one byte, so no `Some` this can return is zero.
  fn shim_token68_end(value: &[u8], at: usize) -> usize {
    token68_end(value, at).unwrap_or(0)
  }
}

#[test]
fn token68_end_is_panic_free() {
  // RFC 9110 §11.2's own shapes: a base64 run with padding, one without, and
  // the pad alone — which is not a run with an empty alphabet part but no run
  // at all, since `1*` puts a floor of one byte under it.
  assert_eq!(
    shim_token68_end(black_box(b"dGVzdA==".as_slice()), black_box(0)),
    8
  );
  assert_eq!(
    shim_token68_end(black_box(b"mF_9.B5f-4.1JqM".as_slice()), black_box(0)),
    15
  );
  assert_eq!(
    shim_token68_end(black_box(b"====".as_slice()), black_box(0)),
    0
  );
  // The pad is a tail and not a byte of the alphabet, so a run does not
  // resume behind one.
  assert_eq!(
    shim_token68_end(black_box(b"a=b".as_slice()), black_box(0)),
    2
  );
  // A cursor inside the value, at its end, and past it — the last is the
  // bounds check a caller's own arithmetic can hand this.
  assert_eq!(
    shim_token68_end(black_box(b"ab.cd".as_slice()), black_box(2)),
    5
  );
  assert_eq!(
    shim_token68_end(black_box(b"ab".as_slice()), black_box(2)),
    0
  );
  assert_eq!(
    shim_token68_end(black_box(b"ab".as_slice()), black_box(usize::MAX)),
    0
  );
  // No run at all: a byte outside both the alphabet and the pad, empty input,
  // and bytes that are not ASCII.
  assert_eq!(
    shim_token68_end(black_box(b"!x".as_slice()), black_box(0)),
    0
  );
  assert_eq!(shim_token68_end(black_box(b"".as_slice()), black_box(0)), 0);
  assert_eq!(
    shim_token68_end(black_box([0xffu8, 0x3d].as_slice()), black_box(0)),
    0
  );
}

no_panic_shim! {
  /// Shim over `auth::credentials` — RFC 9110 §11.6.2's `Authorization` and
  /// §11.7.2's `Proxy-Authorization`, whose value is ONE credential.
  ///
  /// Driven through the whole production: the scheme, §11.2's choice between
  /// a `token68` and a `#auth-param` list, the parameter walk, and the
  /// one-name-once record `Credential::read` spends before the value exists.
  /// Every accessor is read, so none of them can be dropped.
  ///
  /// Returns the bytes it read, so nothing here is optimized out as unused.
  fn shim_credentials(value: &[u8]) -> usize {
    let Ok(credential) = credentials(value) else {
      return 0;
    };
    let mut seen = credential.scheme().len();
    seen = seen.wrapping_add(usize::from(credential.scheme_is("basic")));
    seen = seen.wrapping_add(credential.token68().map_or(0, <[u8]>::len));
    for param in credential.params() {
      seen = seen.wrapping_add(param.name().len());
      seen = seen.wrapping_add(match param.value() {
        Ok(ParamValue::Token(bytes) | ParamValue::Quoted(bytes)) => bytes.len(),
        Ok(_) => 0,
        Err(_) => 1,
      });
    }
    seen.wrapping_add(1)
  }
}

#[test]
fn credentials_is_panic_free() {
  // RFC 9110 §11.2's two body forms, and the bare scheme its `[ … ]` admits.
  assert!(shim_credentials(black_box(b"Basic dGVzdA==".as_slice())) > 0);
  assert!(shim_credentials(black_box(br#"Newauth realm="apps", type=1"#.as_slice())) > 0);
  assert!(shim_credentials(black_box(b"Negotiate".as_slice())) > 0);
  // §11.2's other `token68` shapes, including the trailing-`=` case that reads
  // like a parameter whose value went missing and is not one.
  assert!(shim_credentials(black_box(b"Bearer mF_9.B5f-4.1JqM".as_slice())) > 0);
  assert!(shim_credentials(black_box(b"Scheme foo=".as_slice())) > 0);
  // Empty elements in quantity, which RFC 9110 §5.6.1.2 has a recipient ignore
  // and which spend no slot of the one-name-once record.
  assert!(shim_credentials(black_box(b"Basic ,, a=1 ,, b=2 ,,".as_slice())) > 0);
  // The HTAB that IS the OWS §5.6.1.2 hangs on the section's first comma, so
  // the section opens on the empty first element in front of it.
  assert!(shim_credentials(black_box(b"Basic \t, type=1".as_slice())) > 0);
  // Exactly `MAX_PARAMS_PER_CREDENTIAL` names, and one past it.
  assert!(
    shim_credentials(black_box(
      b"Basic a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11,l=12,m=13,n=14,o=15,p=16".as_slice()
    )) > 0
  );
  assert_eq!(
    shim_credentials(black_box(
      b"Basic a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11,l=12,m=13,n=14,o=15,p=16,q=17"
        .as_slice()
    )),
    0
  );
  // Each refusal on its own: no scheme, a scheme glued to an `=`, the HTAB
  // after `1*SP` that reaches an element rather than the comma RFC 9110
  // §5.6.1.2 would hang it on, a repeated name under
  // §11.2's case-insensitive fold, the trailing comma this field has no list
  // to make an empty element of, a second credential where a parameter name
  // belongs, an unterminated quoted value, one that closed with bytes behind
  // its close, a byte §5.6.4 forbids inside one, nothing at all, and bytes
  // that are not ASCII.
  for refused in [
    b"=x".as_slice(),
    b"Basic=1",
    b"Basic \ta=1",
    b"Basic a=1, A=2",
    b"Basic dGVzdA==,",
    b"Basic x=1, Digest y=2",
    b"Basic a=\"1",
    b"Basic a=\"x,y\"junk",
    b"Basic a=\"\x00\"",
    b"",
    &[0xffu8, 0x20, 0x3d],
  ] {
    assert_eq!(shim_credentials(black_box(refused)), 0);
  }
}

no_panic_shim! {
  /// Shim over `auth::challenges` — RFC 9110 §11.6.1's `WWW-Authenticate` and
  /// §11.7.1's `Proxy-Authenticate`, driven over the field's LINES and through
  /// every step of the walk: the boundary rule that decides what each comma
  /// separates, the §5.2 join between two lines, the region collection behind
  /// a challenge, and the seek that finds where a FAILED challenge ends.
  ///
  /// The loop goes on past an error rather than stopping at the first, and
  /// that is coverage rather than tidiness: this walk reports one fault per
  /// challenge and continues, so a shim that broke would leave the recovery
  /// path — `seek`, and the boundary rule run over a scan that collects
  /// nothing — out of the binary and out of the proof.
  ///
  /// Returns the bytes it read, so nothing here is optimized out as unused.
  fn shim_challenges(lines: &[&[u8]]) -> usize {
    let mut seen = 0usize;
    for challenge in challenges(lines.iter().copied()) {
      let Ok(credential) = challenge else {
        continue;
      };
      seen = seen.wrapping_add(credential.scheme().len());
      seen = seen.wrapping_add(usize::from(credential.scheme_is("basic")));
      seen = seen.wrapping_add(credential.token68().map_or(0, <[u8]>::len));
      for param in credential.params() {
        seen = seen.wrapping_add(param.name().len());
        seen = seen.wrapping_add(match param.value() {
          Ok(ParamValue::Token(bytes) | ParamValue::Quoted(bytes)) => bytes.len(),
          Ok(_) => 0,
          Err(_) => 1,
        });
      }
    }
    seen
  }
}

#[test]
fn challenges_is_panic_free() {
  // RFC 9110 §11.6.1's own printed value, whose commas mean both things at
  // once — a parameter of the challenge already open, and the scheme of the
  // next one.
  assert!(
    shim_challenges(black_box(&[
      br#"Basic realm="simple", Newauth realm="apps", type=1, title="Login to \"apps\"""#
        .as_slice()
    ]))
      > 0
  );
  // One challenge split at an element boundary by §5.2's join, and a quoted
  // value carried across that join — which `value()` reports and `name()`
  // survives.
  assert!(shim_challenges(black_box(&[b"Basic a=1".as_slice(), b"b=2"])) > 0);
  assert!(shim_challenges(black_box(&[b"Basic a=\"long".as_slice(), b"tail\""])) > 0);
  // A string left open at the join with its escape spent by the join's own
  // comma, so the next line's leading DQUOTE closes it.
  assert!(shim_challenges(black_box(&[b"Basic p=\"a\\".as_slice(), b"\", x=1"])) > 0);
  // A value that closed across the join with bytes behind that close, which
  // ends the first challenge's own reading and not the walk: those bytes are
  // taken raw to the comma that ends them, so `Newauth` behind it is read.
  assert!(
    shim_challenges(black_box(&[
      b"Basic a=\"x".as_slice(),
      b"y\"junk, Newauth c=3"
    ]))
      > 0
  );
  // The same, with a DQUOTE among those bytes — which opens no string, at each
  // of the three entrances to that rule: behind a close the join carried over,
  // behind one on the line the element began on, and inside the run a seek
  // recovers a refused challenge through.
  assert!(
    shim_challenges(black_box(&[
      b"Basic realm=x, Broken a=\"q".as_slice(),
      b"r\"junk\", Digest realm=z"
    ]))
      > 0
  );
  assert!(
    shim_challenges(black_box(&[
      b"Basic a=\"x\"ju\"nk, Digest realm=z".as_slice()
    ]))
      > 0
  );
  assert!(shim_challenges(black_box(&[b"=x\"j\x00unk, Digest realm=z".as_slice()])) > 0);
  // A DQUOTE where RFC 9110 §11.2 admits no string at all, so the element ends
  // at a RAW comma: on the line it began on, and across §5.2's join, where a
  // string would otherwise have carried it over a whole field line.
  assert!(shim_challenges(black_box(&[b"Basic a=x\"y, Digest realm=z".as_slice()])) > 0);
  assert!(shim_challenges(black_box(&[b"Basic a=x\"y".as_slice(), b"Digest realm=z"])) > 0);
  // Empty lines, OWS-only lines and empty elements, which spend no entry.
  assert!(
    shim_challenges(black_box(&[
      b"Basic a=1".as_slice(),
      b"",
      b" ",
      b",,",
      b"b=2"
    ]))
      > 0
  );
  // A `token68` body, and the trailing comma this field DOES have a list to
  // make an empty element of.
  assert!(shim_challenges(black_box(&[b"Basic dGVzdA==,".as_slice()])) > 0);
  // The OWS RFC 9110 §5.6.1.2 hangs on a comma, at each of the two edges that
  // read it: behind the scheme, where the challenge is bare and the comma ends
  // its element, and behind `1*SP`, where the parameter section opens on the
  // empty first element in front of that comma.
  assert!(shim_challenges(black_box(&[b"Basic\t, Newauth x=1".as_slice()])) > 0);
  assert!(shim_challenges(black_box(&[b"Basic \t, type=1".as_slice()])) > 0);
  // A fault, and the challenge behind it: the walk reports one and goes on,
  // which is the seek this drives.
  assert!(
    shim_challenges(black_box(&[
      b"Basic a=1, =x, type=b, Newauth c=1".as_slice()
    ]))
      > 0
  );
  // Exactly `MAX_CHALLENGE_LINES` lines of one challenge, then one past it.
  let split: [&[u8]; 17] = [
    b"Basic a=1",
    b"b=2",
    b"c=3",
    b"d=4",
    b"e=5",
    b"f=6",
    b"g=7",
    b"h=8",
    b"i=9",
    b"j=10",
    b"k=11",
    b"l=12",
    b"m=13",
    b"n=14",
    b"o=15",
    b"p=16",
    b"q=17",
  ];
  assert!(shim_challenges(black_box(&split[..16])) > 0);
  assert_eq!(shim_challenges(black_box(&split[..])), 0);
  // Values with nothing to hand back: every element refused, a scan that fails
  // inside a quoted-string and makes every comma behind it a guess, no lines
  // at all, one empty line, and bytes that are not ASCII.
  assert_eq!(shim_challenges(black_box(&[b"=x".as_slice()])), 0);
  assert_eq!(
    shim_challenges(black_box(&[b"Basic a=\"\x00\", Digest b=2".as_slice()])),
    0
  );
  assert_eq!(shim_challenges(black_box(&[])), 0);
  assert_eq!(shim_challenges(black_box(&[b"".as_slice()])), 0);
  assert_eq!(
    shim_challenges(black_box(&[[0xffu8, 0x2c, 0x20].as_slice()])),
    0
  );
}

no_panic_shim! {
  /// Shim over `auth::auth_info` — RFC 9110 §11.6.3's `Authentication-Info`,
  /// which is a `#auth-param` list and nothing else: no scheme in front of it,
  /// and so no `token68` reading to choose.
  ///
  /// Driven over the field's LINES, so the §5.2 join is crossed here too, and
  /// through the one-name-once record this walk carries ACROSS the parameters
  /// it hands out one at a time — the difference from the other two entry
  /// points, which spend theirs before their value exists.
  ///
  /// RFC 9110 §11.6.3 gives this field's parameters the "syntax defined in
  /// Section 11.3". They are not defined there: §11.3 is Challenge and
  /// Response, and the production is in §11.2 — which is the section this file
  /// and the module both cite.
  ///
  /// Returns the bytes it read, so nothing here is optimized out as unused.
  fn shim_auth_info(lines: &[&[u8]]) -> usize {
    let mut seen = 0usize;
    for param in auth_info(lines.iter().copied()) {
      let Ok(param) = param else { break };
      seen = seen.wrapping_add(param.name().len());
      seen = seen.wrapping_add(match param.value() {
        Ok(ParamValue::Token(bytes) | ParamValue::Quoted(bytes)) => bytes.len(),
        Ok(_) => 0,
        Err(_) => 1,
      });
    }
    seen
  }
}

#[test]
fn auth_info_is_panic_free() {
  // A list on one line, and the same list split by §5.2's join at an element
  // boundary and inside a quoted value.
  assert!(shim_auth_info(black_box(&[br#"nextnonce="x", qop=auth"#.as_slice()])) > 0);
  assert!(shim_auth_info(black_box(&[b"nextnonce=x".as_slice(), b"qop=auth"])) > 0);
  assert!(shim_auth_info(black_box(&[b"rspauth=\"a".as_slice(), b"b\", qop=auth"])) > 0);
  // Empty elements, empty lines and OWS-only lines, which spend no slot.
  assert!(shim_auth_info(black_box(&[b", a=1 ,,".as_slice(), b"", b" ", b"b=2"])) > 0);
  // Exactly `MAX_PARAMS_PER_CREDENTIAL` names, then one past it — the second is the
  // refusal that constant documents, reported AT the parameter that broke it.
  assert!(
    shim_auth_info(black_box(&[
      b"a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11,l=12,m=13,n=14,o=15,p=16".as_slice()
    ]))
      > 0
  );
  assert!(
    shim_auth_info(black_box(&[
      b"a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11,l=12,m=13,n=14,o=15,p=16,q=17".as_slice()
    ]))
      > 0
  );
  // A repeated name under RFC 9110 §11.2's case-insensitive fold. The walk
  // reports it AT the parameter that broke the rule, so the one in front of
  // the repeat was handed over already and this is not a value with nothing
  // in it.
  assert!(shim_auth_info(black_box(&[b"a=1, A=2".as_slice()])) > 0);
  // Nothing to hand back: an element that is no parameter at the head of the
  // list, a value that closed across RFC 9110 §5.2's join with bytes behind
  // that close, a byte §5.6.4 forbids inside a quoted-string, no lines at all,
  // one empty line, and bytes that are not ASCII.
  assert_eq!(shim_auth_info(black_box(&[b"realm".as_slice()])), 0);
  assert_eq!(
    shim_auth_info(black_box(&[b"a=\"x".as_slice(), b"y\"junk"])),
    0
  );
  // The same with a DQUOTE among those bytes, which opens no string of its
  // own: once behind a close §5.2's join carried over, and once behind one on
  // the line the element began on.
  assert_eq!(
    shim_auth_info(black_box(&[b"a=\"x".as_slice(), b"y\" \"z, b=2"])),
    0
  );
  assert_eq!(
    shim_auth_info(black_box(&[b"a=\"x\"ju\"nk, b=2".as_slice()])),
    0
  );
  // And a DQUOTE at a position RFC 9110 §11.2 admits no value at, which opens
  // no string either: the element ends at the raw comma and derives nothing.
  assert_eq!(shim_auth_info(black_box(&[b"a=x\"y, b=2".as_slice()])), 0);
  assert_eq!(shim_auth_info(black_box(&[b"a=\"\x00\"".as_slice()])), 0);
  assert_eq!(shim_auth_info(black_box(&[])), 0);
  assert_eq!(shim_auth_info(black_box(&[b"".as_slice()])), 0);
  assert_eq!(
    shim_auth_info(black_box(&[[0xffu8, 0x3d, 0x22].as_slice()])),
    0
  );
}

// ── the lie-check: this file's own guard against going vacuous ────────────────
//
// PERMANENT: the vacuous-proof failure mode the module doc's `black_box`
// section describes is silent by construction, and this is the check that it
// has not happened here. The file carries a shim that MUST NOT link — see
// `shim_lie` below for how — and CI asserts that the build FAILS (the
// `no-panic` job in `.github/workflows/ci.yml`); a green build there is the
// report that the guard has stopped working.
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
