//! The `no-panic` link proofs, checked from the two places their truth lives.
//!
//! Every crate here that publishes `panic-free` carries a `tests/no_panic.rs`
//! whose `#[no_panic]` shims fail the LINK when a panic path survives in the
//! leaf they wrap. That proof has one failure mode and it is silent: a shim
//! whose code the release build never generates emits no symbol, no link can
//! fail on it, and the step reports `ok` over an EMPTY proof.
//!
//! Two independent things have to hold for one shim's proof to be real, and
//! they are knowable in two different places. This module asks each where its
//! answer is, and that split is the whole design:
//!
//! - **How the shim is WRITTEN.** Every argument through
//!   [`core::hint::black_box`], and an answer that is consumed. Both are
//!   properties of the TEXT — a symbol table cannot see an argument — so they
//!   are read out of the source. [`check_file`] is this half.
//! - **Whether the shim was INSTANTIATED.** Did the release test binary the
//!   `no-panic` job links actually contain this shim's code? That is not a
//!   property of the text at all. It is the LINKER's answer, so it is read out
//!   of the artifact. [`instantiation`] is this half.
//!
//! # Why the second half stopped being a source check
//!
//! It was one, and it was bypassed four times.
//!
//! `no-panic` proves a shim by failing the link of code that REACHES it, so
//! "is this call real and reached" decides whether a shim's proof exists at
//! all. Reading that out of Rust source means writing a Rust reader, and four
//! separate reviews walked through four different corners of one:
//!
//! 1. a call inside `debug_assert!`, whose expression the `--release` every
//!    `no-panic` step builds in deletes entirely;
//! 2. a call under a `#[cfg]` the shim does not carry, so the shim is compiled
//!    in configurations nothing calls it in;
//! 3. a call in a helper no `#[test]` reaches;
//! 4. a call spelled inside a RAW string literal — `r#"…"#` — which the
//!    comment-and-string blanker read as ordinary quotes, so balanced `"` in
//!    the literal ended and restarted its blanking and handed the rest to the
//!    call scanner as code. `assert!(shim_x(black_box(…)))` written as string
//!    data counted as a rooted, opaque, consumed call.
//!
//! Each of the four leaves BOTH `no-panic` CI controls green: the real step
//! links a binary whose shim was never instantiated, and the crate's `shim_lie`
//! still reds on its own build, because `shim_lie` is its own subject. The
//! fourth was measured on this branch — `shim_varint_decode`'s whole `#[test]`
//! body replaced by one raw string, `shim-check` exit 0 over 139 "rooted" call
//! sites, `cargo test -p http3-proto --release --features test-no-panic` ok on
//! 5 tests, and `nm` over that binary finding no `shim_varint_decode` at all.
//!
//! Patching the fourth corner buys the fifth. A lexical scanner over Rust
//! source has an unbounded supply of them and this crate takes no dependencies,
//! so no real lexer is available to it. What has no corners is the question the
//! LINKER already answered: it does not read source, it reports what exists.
//! [`instantiation`] asks it.
//!
//! # How the linker is asked
//!
//! `cargo test --release --features test-no-panic --test no_panic --no-run
//! --message-format=json` per crate — the build the job already performs, so
//! its artifacts are the same ones the link steps below it reuse — then the
//! test binary's own symbol table, read by [`crate::symbols`], and, for every
//! declared shim, a symbol that DEFINES A FUNCTION in an executable section of
//! that file and whose mangled path is that binary's OWN crate followed by the
//! shim. Which crate the binary is, is read out of the binary too: see
//! [`CRATE_ANCHOR`].
//!
//! Three things had to be settled before that worked. The first two are
//! properties of how a shim is DECLARED, so they live on the `no_panic_shim!`
//! macro in each of the four files — the macro this check requires to be
//! DEFINED there, invoked unqualified, and to apply `#[no_panic::no_panic]` in
//! the release build the proofs are linked in — and they are what make "this
//! binary defines `no_panic::<shim>`" mean "this shim was called" rather than
//! something weaker:
//!
//! - **`#[inline(never)]`, or there is no symbol to find.** Measured: without
//!   it, `nm` over `http3-proto`'s release test binary finds no `shim_*`
//!   whatever, because a private `fn` with one call site is inlined into it and
//!   its own symbol dropped. `no-panic` cooperates by construction — its macro
//!   adds `#[inline]` only to a function carrying no `inline` attribute
//!   already.
//! - **`black_box` around the shim's ANSWER, or a trivial body is deleted even
//!   when it is called.** Measured, and by this check on its first run over the
//!   live files: `http1-proto`'s `shim_widen` wraps
//!   `u64::try_from(usize).unwrap_or(u64::MAX)`, which on a 64-bit target is
//!   the identity. LLVM marked the parameter `returned`, replaced every call
//!   with its argument, and dropped the now-unused function — leaving exactly
//!   the silence an uncalled shim leaves. Making the shim's own answer opaque
//!   is what separates the two: the optimizer can no longer reduce the body to
//!   "returns its argument" and forward that to the callers, so a shim that IS
//!   called keeps code of its own — and one that is not still disappears, which
//!   is the case this half exists to catch. Measured: with it, all eight of
//!   `http1-proto`'s shims carry a symbol, `shim_widen` included.
//!
//!   (A shim so deleted was not, in fact, unproven — a reachable panic calls
//!   `no-panic`'s undefined `trigger`, which is a side effect that stops the
//!   deletion. But "deleted because trivial" and "deleted because uncalled" are
//!   one silence in a symbol table, and a check that cannot tell them apart
//!   would have to be told which shims to excuse. A list of excused shims is a
//!   bypass with a name.)
//!
//! Neither weakens what `no-panic` proves: the leaves still inline INTO the
//! body, which is what the fat-LTO steps are for, and the body is compiled
//! once, standalone, over input `black_box` keeps opaque — the shape every one
//! of those four files already describes. Measured: with both, all four real
//! steps still link clean and all four lie-checks still refuse to link, naming
//! `shim_lie`.
//!
//! The third is about the artifact rather than the declaration:
//!
//! - **The rlib blindness the CI comment warns about does not apply.** A
//!   release-SYMBOL scan over a library crate is provably blind — a `pub fn`
//!   with a guaranteed panic emits no symbols into an rlib at all, because
//!   codegen is deferred to a downstream binary. A test binary is not an rlib.
//!   Codegen happens where the link happens, which is exactly why the
//!   `no-panic` guard works there and exactly why this can read it.
//!
//! ## What it does when it cannot tell
//!
//! It fails, and says which of them it was. A missing binary, a `cargo` that
//! did not link, an object format [`crate::symbols`] does not read, a stripped
//! table, a string table whose declared extent that reader cannot honour, a
//! name spelled by something that defines no function, a shim under a `#[cfg]`
//! this build does not enable — each is a named failure, never a shim counted
//! as fine and never a shorter denominator. The
//! rule this whole suite is written to is that a green run must be
//! distinguishable from a run that never looked, and this gate has now been
//! fooled four times.
//!
//! The one exemption is the lie-control shim, and it is exactly one: a
//! `shim_lie` gated on `feature = "test-no-panic-lie"` is not in the build this
//! reads, because that build is required to FAIL to link. It is named in the
//! report as excluded and as covered by the must-fail lie-check instead — and
//! the exemption is tied to that name and that gate, so it cannot be spread
//! over a real shim.
//!
//! # What the source half still owes
//!
//! `black_box` and a live answer say the call cannot be FOLDED. Neither says
//! the call is COMPILED, and that is now the artifact's question — but the
//! reverse holds too, which is why both halves are needed: a shim can be
//! instantiated and still prove nothing, if the optimizer got to see through
//! its arguments. The two halves are not redundant and neither is a check on
//! the other.
//!
//! The source half is over the text of ONE file, so it states its own edge: it
//! reads `no_panic_shim!` blocks and the call sites of the names they declare,
//! it blanks comments and every literal form Rust has, and it FAILS on any
//! literal it cannot finish reading rather than guessing where it ended. A shim
//! name used without a following `(` — a function pointer, a stored closure —
//! is a use whose arguments it cannot check, and is failed as such.
//!
//! # What neither half proves
//!
//! That a shim wraps the leaf it claims to. `black_box` at the arguments makes
//! the shim's own body opaque to the optimizer; it says nothing about which
//! function that body calls, and a symbol says only that the body exists. A
//! shim re-pointed at a trivial stub would pass both halves and link clean, and
//! only a reader of the shim body would notice. The `__no_panic_internals`
//! forwarders exist to make that body one line long, so that reading is short —
//! but it is a reading, not a gate.
//!
//! What a symbol DOES say, it is now made to say. The match was on the shim's
//! name as a mangled path component, which any crate or module in the link
//! could spell: an executable carries every dependency's symbols and every
//! symbol it merely references, so `shim_decode` from some other crate, or an
//! undefined entry of that name, satisfied it. No forgery was needed for that —
//! an ordinary dependency collision does it — and this doc used to describe the
//! narrow, deliberate case while the code admitted the wide, accidental one.
//! The rule is now the whole path, the symbol's kind, and WHOSE crate it is:
//!
//! - the path is PARSED rather than scanned for, down to the crate root it
//!   hangs off and the item under it — `_RNvC3foo26xNvC8no_panic11shim_decode`
//!   is a valid symbol for an item of crate `foo` whose name merely contains
//!   the bytes a scan looked for;
//! - the entry has to DEFINE A FUNCTION, in a section of that file that holds
//!   instructions — `STT_FUNC` is a claim, and `SHN_ABS` or a data section is
//!   that claim unpaid;
//! - and the crate root has to be the crate this binary IS, established from
//!   the binary's own [`CRATE_ANCHOR`] and compared with its v0 disambiguator,
//!   because a crate NAME is shared by every crate in the link that carries it
//!   and `no_panic` is a name a dependency can have.
//!
//! `no_panic::inner::shim_x`, `elsewhere::shim_x`, another `no_panic`'s
//! `shim_x`, a `static` of that name and an undefined reference to it are each
//! refused, and the failure names the symbol that spelled it so a collision
//! reads as one.
//!
//! What is left unproven is a shim RE-DECLARED under that exact path — the same
//! `fn` name, at the test crate's root, written by some other item in the one
//! file this check also reads as text. The two ways to write one that were
//! open are now closed there: the attribute written outside the macro, and the
//! macro NAMESAKE — `other::no_panic_shim!`, whose expansion this check has
//! never seen and need not apply the attribute at all, while its `fn` still
//! leaves the symbol the artifact half accepts.
//!
//! Nor does either half prove the link step ran, or ran under the profile its
//! shims were verified under. Those are the CI steps' own business, and the
//! lie-checks are what report them going vacuous.
use crate::{
  Error,
  report::Report,
  symbols::{self, Symbol},
};
use std::{
  fs,
  path::{Path, PathBuf},
  process::Command,
};

/// One crate's link proof: the crate, and the build its proof needs.
struct Proof {
  /// The crate whose `tests/no_panic.rs` declares the shims.
  krate: &'static str,
  /// Environment [`build`] sets for this crate's release build, over the
  /// environment it inherits.
  ///
  /// FAT LTO for the two crates whose shims call leaves across a crate
  /// boundary. It is not a preference: under the default thin-local LTO the
  /// panic paths of `core` are still separate codegen units at link time, and
  /// `no-panic` reports a panic in EVERY shim — so the build would not produce
  /// a binary for this check to read at all. That is also why a drift between
  /// this table and the workflow's own steps cannot go quiet: too little here
  /// and the build fails, too little there and the job's link step fails.
  ///
  /// What this table does NOT have to match is the workflow's profile exactly,
  /// and the reason is worth stating because it is what makes one table safe:
  /// the question this half asks is INSTANTIATION, and instantiation is decided
  /// by `#[inline(never)]` and the call graph, not by the LTO setting. A shim
  /// present in this build is present in the job's.
  env: &'static [(&'static str, &'static str)],
}

/// Every crate that carries a link proof, and the build each one needs.
///
/// A LIST rather than only a walk, for the reason `doc-check`'s `GATED_CRATES`
/// is one: a crate that grew a link proof and was forgotten here would be
/// silently ungated. The walk in [`unclaimed_files`] is the other direction —
/// the one an edit to this list cannot shrink — and it is what fails when a
/// name is REMOVED while its file stays on disk.
const PROOFS: &[Proof] = &[
  Proof {
    krate: "http-semantics",
    env: &[("CARGO_PROFILE_RELEASE_LTO", "fat")],
  },
  Proof {
    krate: "http1-proto",
    env: &[("CARGO_PROFILE_RELEASE_LTO", "fat")],
  },
  Proof {
    krate: "http3-proto",
    env: &[],
  },
  Proof {
    krate: "websocket-proto",
    env: &[],
  },
];

/// The file, under a crate root, this check reads.
const SHIM_FILE: &str = "tests/no_panic.rs";

/// The feature that compiles a crate's real shims, and the `--test` target they
/// live in. See [`PROOF_TARGET`].
const PROOF_FEATURE: &str = "test-no-panic";

/// The `--test` target, and so the CRATE NAME the test binary's own symbols are
/// mangled under.
///
/// [`verdicts`] REQUIRES that crate in a shim's mangled path, and requires it
/// exactly: a symbol answers for a shim only when its path is this crate
/// followed by that shim, and only when it defines a function. An executable
/// carries every dependency's symbols and every symbol it merely references, so
/// the shim's spelling on its own is available to any crate or module in the
/// link and to entries that define nothing at all — reading one of those as the
/// shim would accept a proof of nothing, and needs no forgery to happen.
///
/// It is the crate's NAME, and a name is not a crate: which `no_panic` the
/// binary is comes from [`CRATE_ANCHOR`], and this constant is what that anchor
/// is looked up under.
///
/// This paragraph used to describe a requirement the code did not enforce,
/// which is the defect class this whole check exists to remove.
const PROOF_TARGET: &str = "no_panic";

/// The item at that crate's root this establishes the binary's IDENTITY from.
///
/// A crate name is not a crate. Several crates in one link may be called
/// `no_panic` — a dependency may simply be named that, and this workspace's
/// `no-panic` dependency IS — and what tells two of them apart is the
/// disambiguator v0 writes beside the name. That disambiguator is not knowable
/// from the source, so it is read OUT of the binary, from a symbol that can
/// only be the test crate's own, and every shim symbol is then required to
/// carry the same one.
///
/// `main` is that symbol. `cargo test` builds `tests/no_panic.rs` through
/// rustc's `--test` harness, which synthesises a `main` at the crate ROOT and
/// hands its address to `std::rt::lang_start` — so it exists in every such
/// binary, and taking its address is what keeps it from being inlined away.
/// Measured over all four of this workspace's proof binaries, the two fat-LTO
/// ones included.
///
/// A binary with no such symbol is REFUSED rather than credited by name: see
/// [`identity`].
const CRATE_ANCHOR: &str = "main";

/// The one shim that is deliberately absent from the build this check reads,
/// and the gate that keeps it out.
///
/// Its build is required to FAIL to link, so there is no binary of it to read;
/// the must-fail lie-check in CI is its proof instead. The exemption is tied to
/// BOTH the name and the gate so it cannot be spread: a real shim moved under
/// this gate would leave the build this reads, and a second shim wearing the
/// gate would take the lie-check's own `shim_lie` marker with it.
const LIE_SHIM: &str = "shim_lie";

/// The `#[cfg(…)]` predicate, as written, that [`LIE_SHIM`] carries.
const LIE_GATE: &str = r#"feature = "test-no-panic-lie""#;

/// The macro every shim is declared through, and the attribute path its
/// expansion applies.
///
/// Both are checked in each file: a `no_panic_shim!` whose expansion no longer
/// carries the attribute declares plain functions, and every link proof in that
/// crate would then pass on nothing at all.
const SHIM_MACRO: &str = "no_panic_shim!";

/// The attribute that makes a shim a shim, as its expansion spells it.
const NO_PANIC_ATTR: &str = "no_panic::no_panic";

/// The whole attributes that count as applying [`NO_PANIC_ATTR`] in the release
/// build the proofs are linked in, each collapsed to one line.
///
/// A LIST of exact spellings, because what matters is the `cfg_attr` predicate
/// around the attribute and this crate has no `cfg` evaluator. See
/// [`release_attribute`].
const RELEASE_ATTRS: &[&str] = &[
  "#[no_panic::no_panic]",
  "#[cfg_attr(not(debug_assertions), no_panic::no_panic)]",
];

/// The spellings of the one wrapper that makes an argument opaque.
const BLACK_BOX: &[&str] = &["black_box", "hint::black_box", "core::hint::black_box"];

/// The callees whose argument list counts as CONSUMING a shim's answer.
///
/// `black_box` and the assertion macros that survive `--release`, which is
/// exactly the rule each of the four files states in its own module doc: "every
/// call either feeds an assertion or is itself wrapped in `black_box`". A `let`
/// binding is deliberately not here — an answer bound and then dropped is as
/// dead as one never taken, and no call site in the scanned set uses that
/// shape.
///
/// The `debug_assert` family was here and was REMOVED, and is deliberately not
/// coming back: `debug_assert!` and its two siblings expand to nothing when
/// `debug_assertions` is off, which is the `--release` every `no-panic` step
/// builds in. A call held up only by one of them is a call the linker never
/// sees — so it fails here for having no live consumer, and the shim it names
/// is reported as uninstantiated by [`instantiation`], which is the half that
/// decides the question.
const CONSUMING: &[&str] = &[
  "assert",
  "assert_eq",
  "assert_ne",
  "black_box",
  "core::hint::black_box",
  "hint::black_box",
];

/// Checks every declared shim in every claimed file — how it is written, and
/// whether the linker instantiated it — and reports its own denominator for
/// both.
///
/// `finish(true)` rather than a flag: nothing here may legitimately skip. The
/// artifact half needs a build rather than a toolchain component, and a build
/// that did not happen is a failure with a reason, not a check that stood down.
pub fn run() -> Result<(), Error> {
  let mut report = Report::new("shim-check");
  let root = crate::workspace_root()?;
  unclaimed_files(
    &root,
    &PROOFS.iter().map(|proof| proof.krate).collect::<Vec<_>>(),
    &mut report,
  )?;

  let mut census: Vec<String> = Vec::new();
  let mut linked: Vec<String> = Vec::new();
  let mut files = 0usize;
  let mut counts = Counts::default();

  for proof in PROOFS {
    let name = proof.krate;
    let path = root.join(name).join(SHIM_FILE);
    let Ok(text) = fs::read_to_string(&path) else {
      report.fail(format!(
        "`{name}` is listed as carrying a link proof but has no {} at {}.\n  \
         A listed crate with no proof file is a BROKEN gate, not an empty one: \
         every shim this check would have read is missing, and a per-crate \
         count is the only thing in a green run that would have said so.\n  \
         Either the file moved and this path is stale, or the crate belongs in \
         `PROOFS` no longer — in which case its `no-panic` CI steps go with it.",
        SHIM_FILE,
        path.display()
      ));
      census.push(format!("{name} UNREACHED"));
      linked.push(format!("{name} UNREACHED"));
      continue;
    };
    files += 1;
    let display = format!("{name}/{SHIM_FILE}");
    let mut problems: Vec<String> = Vec::new();
    let verdict = check_file(&display, &text, &mut counts, &mut problems);
    for problem in problems {
      report.fail(problem);
    }
    let declared = match verdict {
      FileVerdict::Unreached => {
        census.push(format!("{name} UNREACHED"));
        linked.push(format!("{name} UNREACHED"));
        continue;
      }
      FileVerdict::Shims(declared) => declared,
    };
    census.push(format!("{name} {}", declared.len()));
    linked.push(instantiation(
      &root,
      proof,
      &display,
      &declared,
      &mut counts,
      &mut report,
    ));
  }

  // The floor under discovery itself, and it is under the WHOLE scanned set
  // rather than under any one crate: a rename that stops `shims_in` matching
  // empties every file at once, and a check reporting zero shims and zero
  // problems is this one governing nothing while still reporting success.
  if counts.shims == 0 {
    report.fail(format!(
      "shim-check governed nothing: no `{SHIM_MACRO}` declaration was found \
       under any of {}.\n  \
       Those four `tests/no_panic.rs` files are the link proofs this workspace \
       publishes `panic-free` on. If the declaration shape changed, teach this \
       check the new one; if the proofs were deliberately removed, remove this \
       check and their CI steps with them.",
      PROOFS
        .iter()
        .map(|proof| proof.krate)
        .collect::<Vec<_>>()
        .join(", ")
    ));
  }

  report.checked(format!(
    "written — {} shim(s) in {files} file(s), {} call site(s), {} argument(s) \
     through `black_box`; {} span(s) this check could not analyse and did not \
     assume harmless; shims per crate: {}",
    counts.shims,
    counts.calls,
    counts.arguments,
    counts.unanalysable,
    census.join(", ")
  ));
  report.checked(format!(
    "instantiated — {} of {} declared shim(s) are DEFINED, as a function in an \
     executable section whose mangled path is `{PROOF_TARGET}::<shim>`, in the \
     release test binary their `no-panic` step links; over {} symbol(s) read, \
     {} of them defined functions; {} lie-control shim(s) excluded and covered \
     by the must-fail lie-check instead; each crate below names the identity \
     its binary was bound to, read out of that binary's own \
     `{PROOF_TARGET}::{CRATE_ANCHOR}` — a v0 disambiguator identifies the crate, \
     legacy has none and binds by name alone; per crate: {}",
    counts.instantiated,
    counts.shims,
    counts.symbols,
    counts.functions,
    counts.lie_shims,
    linked.join(", ")
  ));
  report.finish(true)
}

/// What one run examined, could not examine, and found, in both halves.
///
/// The lines a run prints are what a reader has instead of trust, so each rule
/// states the DENOMINATOR it ran over rather than only the violations it found.
#[derive(Default)]
struct Counts {
  shims: usize,
  calls: usize,
  arguments: usize,
  /// Declared shims whose code the release test binary actually contains.
  instantiated: usize,
  /// Shims excluded from that requirement because they are the lie-control,
  /// counted so the exclusion is on the line rather than in this file only.
  lie_shims: usize,
  /// Symbols read out of the binaries. A denominator for the artifact half
  /// itself: a table this read nothing out of would otherwise look exactly
  /// like a table with no shims in it.
  symbols: usize,
  /// How many of those DEFINE a function in the binary they came from — the
  /// only kind that can answer for a shim. On the line beside `symbols`
  /// because the gap between the two is the population a name test would have
  /// been free to match and this one is not.
  functions: usize,
  /// Spans this check could not resolve. Counted AND failed: a subject it
  /// cannot read is a subject it does not cover, which is the vacuity the whole
  /// module reports.
  unanalysable: usize,
}

/// How much of a file the source half could read.
enum FileVerdict {
  /// Nothing: the file has no `no_panic_shim!` applying the attribute, so
  /// every function below it is an ordinary one.
  Unreached,
  /// The shims it declares, which are also the subjects [`instantiation`] then
  /// requires of the linker.
  Shims(Vec<Shim>),
}

/// THE SOURCE HALF. Checks how each shim in one `tests/no_panic.rs` is written,
/// appending every problem to `problems`.
///
/// Two rules and their floors, and NOT reachability — that moved to
/// [`instantiation`] after four separate bypasses of four different corners of
/// reading Rust as text. What is left here is what a symbol table cannot see:
/// every argument at every call site is a whole `black_box(…)`, and every
/// call's answer is live.
///
/// A FUNCTION, and the test module below calls this one rather than a second
/// copy of it. That module used to re-implement this body over the same
/// helpers, which made it blind in both directions: a rule ADDED here and not
/// there was a rule no test exercised, and a rule REMOVED here left every test
/// still passing on the copy.
fn check_file(
  display: &str,
  text: &str,
  counts: &mut Counts,
  problems: &mut Vec<String>,
) -> FileVerdict {
  // Before anything else, because everything below reads the result: a literal
  // this cannot finish reading is a file whose code and whose prose this cannot
  // tell apart. It REFUSES rather than guesses — guessing is what read
  // `r#"assert!(shim_x(black_box(…)))"#` as a call.
  let code = match blank_noncode(text) {
    Ok(code) => code,
    Err(Unlexable { at, what }) => {
      counts.unanalysable += 1;
      problems.push(format!(
        "{display}:{}: {what}.\n  \
         This check separates code from comments and literals before it reads \
         anything, and it cannot see where this one ends. Everything after it \
         would be graded as whichever of the two the guess landed on — prose \
         read as calls, or calls read as prose — so it refuses the file \
         instead. Both are how a shim's proof goes empty with the run still \
         green.",
        line_of(text, at)
      ));
      return FileVerdict::Unreached;
    }
  };

  // The floor under the whole file: the macro that turns a `fn` into a shim,
  // DEFINED here and applying the attribute in the build that gets linked.
  //
  // This was two `contains` calls — the file spells `no_panic_shim!` somewhere
  // and spells `no_panic::no_panic` somewhere — and neither is that floor. A
  // file that only INVOKES a namesake macro spells the first; a definition
  // whose attribute is `#[cfg_attr(debug_assertions, …)]`, applied in the build
  // nothing links and left off the `--release` one every `no-panic` step
  // builds, spells the second. Either way every shim below expands to a plain
  // function and every link proof in the crate passes over nothing.
  let Some(definition) = definition_range(&code) else {
    problems.push(format!(
      "{display}: no `macro_rules! {}` defined in this file.\n  \
       That macro is what makes a shim a shim, and this check reads the blocks \
       of the one defined HERE. A file that only invokes a macro of that name \
       declares its shims through an expansion this check has never seen, which \
       need not apply `#[{NO_PANIC_ATTR}]` at all — and a shim without that \
       attribute fails no link, however many symbols it leaves in the binary.",
      SHIM_MACRO.trim_end_matches('!')
    ));
    return FileVerdict::Unreached;
  };
  if let Err(found) = release_attribute(text, &code, &definition) {
    problems.push(format!(
      "{display}:{}: `macro_rules! {}` does not apply `#[{NO_PANIC_ATTR}]` in \
       the release build its proofs are linked in.\n  \
       It applies {}. The build that decides this is `--release`: an attribute \
       under `cfg_attr(debug_assertions, …)` is applied in the build nothing \
       links and left OFF the one every `no-panic` step builds, so every shim \
       in the file would expand to a plain function while this file still \
       spelled the attribute. The spellings this check knows are {}. If the \
       shape changed, teach this check the new one — do not widen the match.",
      line_of(&code, definition.start),
      SHIM_MACRO.trim_end_matches('!'),
      if found.is_empty() {
        "none".to_string()
      } else {
        found
          .iter()
          .map(|attribute| format!("`{attribute}`"))
          .collect::<Vec<_>>()
          .join(", ")
      },
      RELEASE_ATTRS
        .iter()
        .map(|attribute| format!("`{attribute}`"))
        .collect::<Vec<_>>()
        .join(" and ")
    ));
    return FileVerdict::Unreached;
  }

  // And the floor under the macro's monopoly on the declaration. Everything
  // below reads `no_panic_shim!` blocks, so a shim declared by writing the
  // attribute directly is one this check never sees — a subject that opts out
  // of its own gate, and one [`instantiation`] never hears about either, since
  // its subjects are the shims this returns.
  for at in stray_attributes(&code) {
    counts.unanalysable += 1;
    problems.push(format!(
      "{display}:{}: `#[{NO_PANIC_ATTR}]` written outside `macro_rules! \
       no_panic_shim`.\n  \
       Every shim goes through that macro, and this check reads the macro's \
       blocks. A shim declared any other way is not examined here: its \
       arguments are never checked for `black_box`, its answer is never \
       checked for being live, and the linker is never asked whether it \
       exists. Declare it through `{SHIM_MACRO}`.",
      line_of(&code, at)
    ));
  }

  let Declarations {
    shims: found,
    unparsed,
    qualified,
  } = shims_in(text, &code);
  for at in &qualified {
    counts.unanalysable += 1;
    problems.push(format!(
      "{display}:{}: `{SHIM_MACRO}` invoked through a PATH.\n  \
       The macro this check reads is the `macro_rules! {}` defined in this \
       file. A namesake reached through a path is a different macro, its \
       expansion is one this check has never seen, and it need not apply \
       `#[{NO_PANIC_ATTR}]` at all — while the `fn` it declares is still a \
       root function of the shim's own name, which the linker reports and the \
       artifact half accepts. Both halves would then be green over a shim no \
       `no-panic` guard was ever put on. Invoke the local macro unqualified.",
      line_of(&code, *at),
      SHIM_MACRO.trim_end_matches('!')
    ));
  }
  for at in &unparsed {
    counts.unanalysable += 1;
    problems.push(format!(
      "{display}:{}: a `{SHIM_MACRO}` block this check cannot read.\n  \
       It expects `fn <name>(<params>) [-> <type>] {{ … }}`. A shim it cannot \
       read is a shim it does not cover, which is the vacuity it exists to \
       report — so it is counted as unanalysed and failed rather than \
       skipped.",
      line_of(&code, *at)
    ));
  }
  if found.is_empty() {
    problems.push(format!(
      "{display}: declares no shim.\n  \
       The file exists, the macro is there, and nothing goes through it — so \
       this crate's `no-panic` step links a test binary that asserts nothing \
       about any leaf. Either the shims were lost, or they are declared some \
       way this check does not see, which is the same hole."
    ));
    return FileVerdict::Shims(found);
  }
  counts.shims += found.len();

  let groups = paren_groups(&code);
  for shim in &found {
    // A use of the name that is not a call — `let f: fn(_) -> _ = shim_x;`, a
    // closure that captures it — instantiates the shim without this check ever
    // seeing an argument list. The linker will report it as present, and this
    // half will have graded nothing about it, so the span is failed rather than
    // left to the other half's `yes`.
    for at in bare_mentions(&code, &shim.name, &found) {
      counts.unanalysable += 1;
      problems.push(format!(
        "{display}:{}: `{}` is written without a call's `(`.\n  \
         Taking a shim's address instantiates it, so the linker will say it \
         exists — while this half, which reads call sites, has checked no \
         argument of that use for `black_box`. A shim reached only that way is \
         compiled over whatever the pointer's callers pass, and this check \
         cannot see them. Call it directly.",
        line_of(&code, at),
        shim.name
      ));
    }

    let sites = call_sites(&code, &shim.name, &found);
    if sites.is_empty() {
      // Not "never called" — that is the linker's word, and [`instantiation`]
      // says it. This one is about COVERAGE: no call site means no argument of
      // this shim was checked by anything, so a `yes` from the artifact half
      // would stand over an unexamined call.
      counts.unanalysable += 1;
      problems.push(format!(
        "{display}:{}: `{}` has no call site this check can read.\n  \
         Its arguments are therefore checked by nothing, and `black_box` at \
         every argument is the whole of what keeps a shim from being compiled \
         over literals it can see through. Whether the shim is INSTANTIATED is \
         a separate question, and the linker answers it below.",
        shim.line, shim.name
      ));
      continue;
    }
    for site in sites {
      counts.calls += 1;
      let line = line_of(&code, site.name_at);

      let mut writes_through_opaque = false;
      for argument in split_top_level(&code[site.args.clone()]) {
        counts.arguments += 1;
        let shown = shown_at(text, site.args.start + argument.start, argument.text.len());
        let Some(inner) = black_box_inner(argument.text) else {
          problems.push(format!(
            "{display}:{line}: `{}` is passed `{shown}`, which is not a \
             `black_box` call.\n  \
             EVERY argument at EVERY call site has to go through \
             `core::hint::black_box`. An argument the optimizer can see \
             through is constant-folded before `no-panic`'s guard is \
             evaluated: the body is compiled for that literal instead of for \
             unknown input, every branch it cannot reach is pruned, and the \
             symbol whose presence would fail the link is never emitted. The \
             shim then passes on whatever those branches do. A symbol in the \
             binary does not rescue this — the body is there and it was \
             compiled for the wrong input.",
            shim.name
          ));
          continue;
        };
        if inner.trim_start().starts_with("&mut") {
          writes_through_opaque = true;
        }
      }
      if shim.unit {
        // A `()` answer cannot be asserted on or wrapped, so what keeps the
        // call from being deleted as dead is the OPAQUE `&mut` it writes
        // through: LLVM cannot prove a store through a pointer it cannot see
        // is unobserved. `shim_mask` is the one such shim here, and its
        // module doc says exactly this.
        if !writes_through_opaque {
          problems.push(format!(
            "{display}:{line}: `{}` answers `()` and is called with no \
             `black_box(&mut …)` argument.\n  \
             A call whose answer is unused and whose arguments are all \
             by-value can be deleted whole, taking the body and its symbol \
             with it. What holds a `()` shim is the opaque `&mut` it writes \
             through — a store through a pointer the optimizer cannot see is \
             not dead. Give it one, or give the shim an answer and consume \
             it.",
            shim.name
          ));
        }
        continue;
      }
      if !consumed(&groups, site.name_at) {
        problems.push(format!(
          "{display}:{line}: `{}`'s answer is dropped.\n  \
           A shim whose answer is unused can be deleted whole, taking its \
           body and its symbol with it, and a deleted call proves nothing. \
           Every call either feeds an assertion ({}) or is itself wrapped in \
           `black_box`. `debug_assert!` and its siblings are deliberately not \
           on that list: the release build deletes their expression, so a call \
           there is a call the linker never sees.",
          shim.name,
          CONSUMING
            .iter()
            .filter(|name| !BLACK_BOX.contains(name))
            .map(|name| format!("{name}!"))
            .collect::<Vec<_>>()
            .join(", ")
        ));
      }
    }
  }
  FileVerdict::Shims(found)
}

/// THE ARTIFACT HALF. Asks the LINKER which of `declared` the release test
/// binary actually contains, and answers the census entry for this crate.
///
/// Nothing here reads the crate's source. That is the point: reachability is
/// the question a lexical checker kept getting wrong, and it has an exact
/// answer that costs no reading at all. A shim the binary DEFINES, as a
/// function at [`PROOF_TARGET`]'s root, had its code generated — which is
/// precisely the condition under which `no-panic`'s guard was evaluated and the
/// link could have failed on it. A name alone is not that condition: see
/// [`PROOF_TARGET`].
///
/// Every way this can fail to KNOW is a failure with a name — see the module
/// doc — because "no symbol found" and "no symbols read" must not arrive as one
/// answer.
fn instantiation(
  root: &Path,
  proof: &Proof,
  display: &str,
  declared: &[Shim],
  counts: &mut Counts,
  report: &mut Report,
) -> String {
  let name = proof.krate;
  let (binary, found) = match build(root, proof).and_then(|binary| {
    let symbols = symbols::read(&binary)?;
    Ok((binary, symbols))
  }) {
    Ok(pair) => pair,
    Err(err) => {
      report.fail(format!(
        "{name}: the release test binary its `no-panic` step links could not \
         be read, so which of its {} shim(s) were instantiated is UNKNOWN.\n  \
         {err}\n  \
         Reported rather than skipped: an unknown fate is not a passing one. \
         This half exists because the source cannot answer this question, and \
         a run that could not ask it has not asked it.",
        declared.len()
      ));
      return format!("{name} UNKNOWN");
    }
  };
  verdicts(display, name, &binary, declared, &found, counts, report)
}

/// Which crate the binary this half read actually IS.
///
/// Established from the binary rather than assumed from the name it was built
/// under, and then required of every symbol credited to a shim. See
/// [`CRATE_ANCHOR`].
struct Identity {
  scheme: symbols::Scheme,
  krate: String,
  /// The v0 crate-root disambiguator, as written. Empty under legacy, which
  /// writes none — see [`symbols::Rooted::same_crate_as`] for what that costs.
  disambiguator: String,
}

impl Identity {
  /// This identity as a path to compare others against.
  fn as_rooted(&self) -> symbols::Rooted<'_> {
    symbols::Rooted {
      scheme: self.scheme,
      krate: &self.krate,
      disambiguator: &self.disambiguator,
      item: CRATE_ANCHOR,
    }
  }

  /// Whether `symbol` is THIS crate's own root-level `ident`.
  fn credits(&self, symbol: &str, ident: &str) -> bool {
    symbols::rooted(symbol)
      .is_some_and(|path| path.same_crate_as(&self.as_rooted()) && path.item == ident)
  }

  /// How a run's own line names this binding, so a reader can see what the
  /// shims below were credited to — and, under legacy, that the binding is the
  /// weaker one.
  fn shown(&self) -> String {
    match self.scheme {
      symbols::Scheme::Legacy => format!("{} (legacy, by name)", self.krate),
      symbols::Scheme::V0 if self.disambiguator.is_empty() => {
        format!("{} (v0, no disambiguator)", self.krate)
      }
      symbols::Scheme::V0 => format!("{} (v0 {})", self.krate, self.disambiguator),
    }
  }
}

/// The crate `found` came out of, read out of `found` itself.
///
/// Exactly one crate named [`PROOF_TARGET`] may define a root [`CRATE_ANCHOR`]
/// in a test binary, and that crate is the one the binary IS. None and several
/// are both refused: with no anchor there is nothing to bind a shim symbol to
/// but its NAME, which is the whole defect this replaced, and with two there is
/// no saying which of them the shims below belong to.
fn identity(found: &[Symbol]) -> Result<Identity, String> {
  let mut anchors: Vec<symbols::Rooted<'_>> = Vec::new();
  for symbol in found.iter().filter(|symbol| symbol.defined_function) {
    let Some(path) = symbols::rooted(&symbol.name) else {
      continue;
    };
    if path.krate != PROOF_TARGET || path.item != CRATE_ANCHOR {
      continue;
    }
    if !anchors.iter().any(|seen| seen.same_crate_as(&path)) {
      anchors.push(path);
    }
  }
  match anchors.as_slice() {
    [only] => Ok(Identity {
      scheme: only.scheme,
      krate: only.krate.to_string(),
      disambiguator: only.disambiguator.to_string(),
    }),
    [] => Err(format!(
      "no symbol in it defines `{PROOF_TARGET}::{CRATE_ANCHOR}`, the `main` \
       rustc's `--test` harness synthesises at the test crate's own root. \
       Without it there is nothing to bind a shim symbol to except the NAME \
       `{PROOF_TARGET}`, and a name is shared by every crate in the link that \
       happens to carry it"
    )),
    many => Err(format!(
      "{} different crates named `{PROOF_TARGET}` define a root \
       `{CRATE_ANCHOR}` in it — {} — so which of them this binary IS cannot be \
       decided, and a shim credited to the wrong one is credited to a crate \
       whose code nothing here verified",
      many.len(),
      many
        .iter()
        .map(|path| format!(
          "`{}`",
          Identity {
            scheme: path.scheme,
            krate: path.krate.to_string(),
            disambiguator: path.disambiguator.to_string(),
          }
          .shown()
        ))
        .collect::<Vec<_>>()
        .join(", ")
    )),
  }
}

/// The artifact half's decision, over a symbol list rather than a build.
///
/// Split from [`instantiation`] so a test can hand it the symbols it wants:
/// this is the whole of what this half DECIDES, and a rule that can only be
/// exercised by linking four crates is a rule nothing exercises.
///
/// What satisfies a shim is one symbol that is BOTH a defined function in that
/// binary and rooted at `<this binary's own crate>::<shim>`. Each half of that
/// answers a different way of spelling the name without being the thing: an
/// undefined entry, a data symbol or a `STT_FUNC` in a section holding no
/// instructions defines no body, and a body defined under any other crate or
/// module — INCLUDING another crate of the same name, which is what the
/// disambiguator in [`Identity`] tells apart — is some other crate's function
/// that happens to share a name.
fn verdicts(
  display: &str,
  name: &str,
  binary: &Path,
  declared: &[Shim],
  found: &[Symbol],
  counts: &mut Counts,
  report: &mut Report,
) -> String {
  counts.symbols += found.len();
  counts.functions += found
    .iter()
    .filter(|symbol| symbol.defined_function)
    .count();
  // Which crate this binary IS, before any symbol is credited to it. A crate
  // NAME is what the paths below spell, and a name is not an identity: see
  // [`CRATE_ANCHOR`].
  let identity = match identity(found) {
    Ok(identity) => identity,
    Err(err) => {
      report.fail(format!(
        "{display}: which crate the release test binary its `no-panic` step \
         links actually IS could not be established, so none of its {} shim(s) \
         can be credited to it.\n  \
         {}\n  \
         {err}.\n  \
         Reported rather than fallen back on: crediting `{PROOF_TARGET}::<shim>` \
         to whatever crate spells that name is exactly the reading this check \
         was rewritten to stop making.",
        declared.len(),
        binary.display()
      ));
      return format!("{name} UNKNOWN");
    }
  };
  let mut instantiated = 0usize;
  let mut lies = 0usize;
  for shim in declared {
    if shim.gates.iter().any(|gate| gate == LIE_GATE) {
      // The one exemption, and it is narrow on purpose: see [`LIE_SHIM`].
      if shim.name != LIE_SHIM || shim.gates.len() != 1 || lies > 0 {
        report.fail(format!(
          "{display}:{}: `{}` is gated on `{LIE_GATE}` and is not the one \
           lie-control shim.\n  \
           That gate keeps a shim out of the build this half reads, and the \
           build it IS in is required to fail to link — so a shim wearing it \
           is proved by nothing here and by nothing there. Exactly one shim \
           per file may carry it, it must be `{LIE_SHIM}`, and it must carry \
           no other gate, because `{LIE_SHIM}` is the name CI's must-fail \
           lie-check greps `no-panic`'s marker for.",
          shim.line, shim.name
        ));
        continue;
      }
      lies += 1;
      counts.lie_shims += 1;
      continue;
    }
    if !shim.gates.is_empty() {
      report.fail(format!(
        "{display}:{}: `{}` is gated on `cfg({})`, which the build this half \
         reads does not enable.\n  \
         That build is `cargo test -p {name} --release --features \
         {PROOF_FEATURE} --test {PROOF_TARGET}`. A shim outside it is a shim \
         no binary here contains, so the linker has nothing to say about it \
         and this check will not say anything on the linker's behalf. Either \
         the gate belongs on the feature that build enables, or the shim needs \
         a `no-panic` step of its own.",
        shim.line,
        shim.name,
        shim.gates.join(", ")
      ));
      continue;
    }
    // The shim's own path under the crate this binary IS, not its name: the
    // path is parsed, and its crate root has to be the identity established
    // above — name, mangling scheme and v0 disambiguator alike.
    let rooted: Vec<&Symbol> = found
      .iter()
      .filter(|symbol| identity.credits(&symbol.name, &shim.name))
      .collect();
    if rooted.iter().any(|symbol| symbol.defined_function) {
      instantiated += 1;
      counts.instantiated += 1;
      continue;
    }
    if let Some(symbol) = rooted.first() {
      report.fail(format!(
        "{display}:{}: `{}` is spelled in the release test binary its \
         `no-panic` step links, by no symbol that DEFINES a function there.\n  \
         {}\n  \
         The nearest is `{}`. An undefined entry names a body that lives \
         somewhere else and a data symbol names no body at all, so neither is \
         evidence that this shim's code was generated here — which is the only \
         thing that puts `no-panic`'s guard on it. If the toolchain has begun \
         spelling a generated `fn` some other way, teach this check the new \
         spelling; until then it will not read a name as a body.",
        shim.line,
        shim.name,
        binary.display(),
        symbol.name
      ));
      continue;
    }
    // A name this binary does spell somewhere else is worth saying, because
    // "not instantiated" and "instantiated by something that is not this" send
    // a reader to two different places. DIAGNOSTIC ONLY: none of these counts.
    let elsewhere: Vec<&str> = found
      .iter()
      .filter(|symbol| symbols::names_component(&symbol.name, &shim.name))
      .map(|symbol| symbol.name.as_str())
      .take(3)
      .collect();
    let impostors = if elsewhere.is_empty() {
      String::new()
    } else {
      format!(
        "\n  \
         Something in that binary does spell this name — {} — and none of them \
         is this shim: what would satisfy this is a defined function whose \
         mangled path is `{PROOF_TARGET}::{}`, the test crate this binary is. \
         A dependency or another module can contribute the same spelling, and \
         that is a collision rather than a proof.",
        elsewhere.join(", "),
        shim.name
      )
    };
    report.fail(format!(
      "{display}:{}: `{}` is declared and is NOT INSTANTIATED in the release \
       test binary its `no-panic` step links.\n  \
       {}\n  \
       This is the LINKER's answer, not a reading of the source: no symbol in \
       that binary defines this shim, so none of its body was generated, so \
       `no-panic`'s guard was never evaluated for it and no link could have \
       failed on it. Whatever the file appears to say, this shim's proof is \
       empty and the step reporting `ok` is reporting nothing.\n  \
       The call that would instantiate it is missing, deleted by the release \
       build, or not a call at all. Note that the source half may well be \
       green: it grades the calls it can read, and a call that is not compiled \
       is still text.{impostors}",
      shim.line,
      shim.name,
      binary.display()
    ));
  }
  format!(
    "{name} {instantiated}/{} as {}",
    declared.len().saturating_sub(lies),
    identity.shown()
  )
}

/// Builds one crate's release test binary the way its `no-panic` step does, and
/// answers where `cargo` put it.
///
/// `--no-run` because the LINK is the whole of what this needs; the job's own
/// steps run the tests. `--message-format=json` because cargo reports the path
/// rather than leaving it to be guessed out of a target directory whose layout
/// is cargo's business — and because a guess that misses would read some other
/// binary and answer confidently about the wrong one.
///
/// It is the same invocation the job runs, so on any machine that has already
/// built it this costs a cache lookup, and on CI it warms the cache the link
/// steps below it then hit.
fn build(root: &Path, proof: &Proof) -> Result<PathBuf, String> {
  let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
  let mut command = Command::new(cargo);
  command
    .current_dir(root)
    .arg("test")
    .args(["-p", proof.krate])
    .arg("--release")
    .args(["--features", PROOF_FEATURE])
    .args(["--test", PROOF_TARGET])
    .arg("--no-run")
    .arg("--message-format=json");
  for (name, value) in proof.env {
    command.env(name, value);
  }
  let shown = format!(
    "{}cargo test -p {} --release --features {PROOF_FEATURE} --test \
     {PROOF_TARGET} --no-run",
    proof
      .env
      .iter()
      .map(|(name, value)| format!("{name}={value} "))
      .collect::<String>(),
    proof.krate
  );
  let output = command
    .output()
    .map_err(|err| format!("`{shown}` could not be run: {err}"))?;
  if !output.status.success() {
    return Err(format!(
      "`{shown}` exited {}. Its own output:\n{}",
      output.status,
      String::from_utf8_lossy(&output.stderr).trim_end()
    ));
  }
  executable(&String::from_utf8_lossy(&output.stdout), &shown)
}

/// The one test executable a `--message-format=json` build reported.
///
/// EXACTLY one, and a count is checked rather than a first match taken: with
/// `--test no_panic` cargo builds one test target, so two would mean this is
/// reading a build it does not understand and picking one of its artifacts
/// arbitrarily.
fn executable(stdout: &str, shown: &str) -> Result<PathBuf, String> {
  let mut found: Vec<PathBuf> = Vec::new();
  for line in stdout.lines() {
    if !line.contains(r#""reason":"compiler-artifact""#) {
      continue;
    }
    if let Some(path) = json_string(line, "executable") {
      found.push(PathBuf::from(path));
    }
  }
  let [binary] = found.as_slice() else {
    return Err(format!(
      "`{shown}` reported {} test executable(s) and this needs exactly one. \
       Either the build produced nothing to read — in which case nothing was \
       linked and no shim was instantiated — or cargo's JSON says something \
       this does not understand, which is not a difference it may guess \
       through.",
      found.len()
    ));
  };
  let stem = binary
    .file_name()
    .map(|name| name.to_string_lossy().into_owned())
    .unwrap_or_default();
  // Cargo names a test binary `<target>-<hash>`, so the TARGET is what stands
  // before the first `-` and it has to be this one exactly. A prefix test takes
  // `no_panic_extra-…` for the `no_panic` target — the same shape of mistake as
  // reading a symbol by a name that merely starts the same way.
  if stem.split('-').next() != Some(PROOF_TARGET) {
    return Err(format!(
      "`{shown}` reported `{stem}`, which is not the `{PROOF_TARGET}` test \
       target. Reading the wrong binary would answer this check's question \
       confidently about the wrong subject."
    ));
  }
  Ok(binary.clone())
}

/// The value of one `"key":"…"` string field of a JSON line.
///
/// A field reader rather than a parser, because one field is what is wanted and
/// `xtask` takes no dependencies. It undoes exactly the escapes JSON defines
/// and answers nothing at all on anything else — including a surrogate pair,
/// which a path would need a non-BMP character to produce. Nothing is the safe
/// answer here: the caller turns it into "no executable reported", which fails.
fn json_string(line: &str, key: &str) -> Option<String> {
  let needle = format!("\"{key}\":\"");
  let start = line.find(&needle)? + needle.len();
  let mut chars = line.get(start..)?.chars();
  let mut out = String::new();
  loop {
    match chars.next()? {
      '"' => return Some(out),
      '\\' => match chars.next()? {
        '"' => out.push('"'),
        '\\' => out.push('\\'),
        '/' => out.push('/'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'b' => out.push('\u{8}'),
        'f' => out.push('\u{c}'),
        'u' => {
          let hex: String = (0..4).map_while(|_| chars.next()).collect();
          out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
        }
        _ => return None,
      },
      ch => out.push(ch),
    }
  }
}

/// Fails when a `tests/no_panic.rs` exists under a workspace directory that
/// `claimed` does not name.
///
/// [`PROOFS`] is ITERATED by everything above, so deleting an entry
/// deletes the iteration that would have examined it: the crate silently loses
/// this check, its file stays committed and unread, and the run still prints
/// success over the shorter set. A directory walk is the only set that edit
/// cannot shrink, so the walk is what asks the question — the same argument
/// `doc-check`'s `unclaimed_snapshots` is written from.
///
/// `claimed` is a parameter rather than the constant read directly, so a test
/// can hand it a list it controls.
fn unclaimed_files(root: &Path, claimed: &[&str], report: &mut Report) -> Result<(), Error> {
  let entries =
    fs::read_dir(root).map_err(|err| format!("could not read {}: {err}", root.display()))?;
  let mut found: Vec<String> = Vec::new();
  for entry in entries {
    let entry =
      entry.map_err(|err| format!("could not read an entry of {}: {err}", root.display()))?;
    if !entry.path().is_dir() {
      continue;
    }
    if !entry.path().join(SHIM_FILE).is_file() {
      continue;
    }
    let name = entry.file_name().to_string_lossy().into_owned();
    if !claimed.contains(&name.as_str()) {
      found.push(name);
    }
  }
  found.sort();
  for name in found {
    report.fail(format!(
      "`{name}/{SHIM_FILE}` exists and no entry of `PROOFS` claims it.\n  \
       Either that crate grew a link proof this check has never read — in which \
       case add it to the list, and give it the `no-panic` CI steps its \
       siblings have — or it was dropped from the list while its file stayed on \
       disk, which is the edit that makes every list-driven assertion here get \
       shorter and stay green."
    ));
  }
  Ok(())
}

/// One `#[no_panic]` shim, as declared.
struct Shim {
  name: String,
  /// Whether the declaration answers `()` — no `->`, or `-> ()`.
  unit: bool,
  /// The `#[cfg(…)]` predicates written on the `no_panic_shim!` block.
  ///
  /// A call site's own gates are checked against THESE rather than against
  /// nothing: a shim and the `#[test]` that reaches it have to be compiled by
  /// the same configurations, or the shim exists in a build where its proof is
  /// empty. The lie-check's shim and test are both under
  /// `feature = "test-no-panic-lie"`, which is what that rule is written to
  /// admit.
  gates: Vec<String>,
  /// The declaration's own byte range, so its `fn name(` is not read as a call.
  decl: std::ops::Range<usize>,
  line: usize,
}

/// One call of a shim.
struct CallSite {
  /// Where the callee name starts, which is what positions it in the source.
  name_at: usize,
  /// The argument list, between the parentheses.
  args: std::ops::Range<usize>,
}

/// What one file's `no_panic_shim!` invocations came to.
///
/// The two lists beside the shims are RETURNED rather than skipped. A block
/// this cannot parse, or an invocation of a macro that is not this file's, is a
/// shim it does not cover, and silently covering fewer subjects than the file
/// declares is the exact shape of the defect this whole module reports.
struct Declarations {
  /// The shims this could read, which are also the subjects the artifact half
  /// then requires of the linker.
  shims: Vec<Shim>,
  /// Offsets of `no_panic_shim!` blocks whose `fn` this cannot read.
  unparsed: Vec<usize>,
  /// Offsets of invocations written through a PATH — `other::no_panic_shim!`.
  qualified: Vec<usize>,
}

/// Every `no_panic_shim! { … }` block in `code`, the ones this cannot read, and
/// the ones that are not this file's macro at all.
fn shims_in(text: &str, code: &str) -> Declarations {
  let bytes = code.as_bytes();
  let mut shims = Vec::new();
  let mut unparsed = Vec::new();
  let mut qualified = Vec::new();
  let mut from = 0usize;
  while let Some(at) = code[from..].find(SHIM_MACRO).map(|off| from + off) {
    from = at + SHIM_MACRO.len();
    // A whole word: `my_no_panic_shim!` is a different macro, and reading its
    // blocks as this one's would grade subjects that never carried the
    // attribute — and count them into the denominator this check prints.
    if at > 0 && is_ident_byte(bytes[at - 1]) {
      continue;
    }
    // And an UNQUALIFIED one. `other::no_panic_shim!` is a different macro too,
    // and the byte before it is `:`, which is not an identifier byte — so the
    // whole-word rule above admitted it, and its blocks were read as this
    // macro's. Reported rather than skipped: see [`Declarations::qualified`].
    if at > 0 && bytes[at - 1] == b':' {
      qualified.push(at);
      continue;
    }
    let Some(open) = bytes[from..]
      .iter()
      .position(|b| !b.is_ascii_whitespace())
      .map(|off| from + off)
      .filter(|at| bytes[*at] == b'{')
    else {
      unparsed.push(at);
      continue;
    };
    let Some(close) = matching(bytes, open) else {
      unparsed.push(at);
      continue;
    };
    from = close;
    let block = &code[open + 1..close];
    let Some((name, unit)) = signature(block) else {
      unparsed.push(at);
      continue;
    };
    shims.push(Shim {
      name,
      unit,
      gates: gates_of(&attributes_before(text, code, at)),
      decl: at..close,
      line: line_of(code, at),
    });
  }
  Declarations {
    shims,
    unparsed,
    qualified,
  }
}

/// The `fn <name>(…)` a shim block declares, and whether it answers `()`.
fn signature(block: &str) -> Option<(String, bool)> {
  let bytes = block.as_bytes();
  let mut from = 0usize;
  loop {
    let at = block[from..].find("fn ").map(|off| from + off)?;
    from = at + 3;
    // `fn` has to be a whole word: `#[allow(clippy::…)]` above a shim, or any
    // identifier ending in `fn`, is not a declaration.
    if at > 0 && is_ident_byte(bytes[at - 1]) {
      continue;
    }
    let rest = &block[from..];
    let name: String = rest
      .trim_start()
      .chars()
      .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
      .collect();
    if name.is_empty() {
      continue;
    }
    let params = from + rest.find('(')?;
    let close = matching(bytes, params)?;
    let tail = block[close + 1..].trim_start();
    let unit = match tail.strip_prefix("->") {
      None => true,
      Some(ret) => ret.split('{').next().is_some_and(|ty| ty.trim() == "()"),
    };
    return Some((name, unit));
  }
}

/// Every call of `name` in `code` that is not inside some shim's declaration.
fn call_sites(code: &str, name: &str, shims: &[Shim]) -> Vec<CallSite> {
  let bytes = code.as_bytes();
  let mut sites = Vec::new();
  let mut from = 0usize;
  while let Some(at) = code[from..].find(name).map(|off| from + off) {
    from = at + name.len();
    if at > 0 && is_ident_byte(bytes[at - 1]) {
      continue;
    }
    // `other::shim_x(…)` calls some other crate's function of that name, and
    // grading ITS arguments would let a shim of this file's own reach the
    // artifact half with no call site of its own ever examined — the coverage
    // floor below satisfied by a call to something else. The shim then has no
    // call site this check can read, which is what it says.
    if at > 0 && bytes[at - 1] == b':' {
      continue;
    }
    let Some(open) = bytes[from..]
      .iter()
      .position(|b| !b.is_ascii_whitespace())
      .map(|off| from + off)
      .filter(|at| bytes[*at] == b'(')
    else {
      continue;
    };
    if shims.iter().any(|shim| shim.decl.contains(&at)) {
      continue;
    }
    let Some(close) = matching(bytes, open) else {
      continue;
    };
    sites.push(CallSite {
      name_at: at,
      args: open + 1..close,
    });
    from = close;
  }
  sites
}

/// One parenthesised group, and the callee written immediately before it.
struct Group {
  open: usize,
  close: usize,
  callee: String,
}

/// Every parenthesised group in `code`, each with the identifier path written
/// immediately before its `(` — `black_box`, `assert_eq` for `assert_eq!(`, or
/// the empty string for a group nothing calls.
fn paren_groups(code: &str) -> Vec<Group> {
  let bytes = code.as_bytes();
  let mut open = Vec::new();
  let mut groups = Vec::new();
  for (at, byte) in bytes.iter().enumerate() {
    match byte {
      b'(' => open.push(at),
      b')' => {
        if let Some(start) = open.pop() {
          groups.push(Group {
            open: start,
            close: at,
            callee: callee_before(code, start),
          });
        }
      }
      _ => {}
    }
  }
  groups
}

/// The identifier path written immediately before the `(` at `open`, with a
/// macro's `!` stepped over so `assert_eq!(` reads as `assert_eq`.
fn callee_before(code: &str, open: usize) -> String {
  let bytes = code.as_bytes();
  let mut at = open;
  let mut skip_bang = true;
  loop {
    while at > 0 && bytes[at - 1].is_ascii_whitespace() {
      at -= 1;
    }
    if skip_bang && at > 0 && bytes[at - 1] == b'!' {
      at -= 1;
      skip_bang = false;
      continue;
    }
    break;
  }
  let end = at;
  while at > 0 && (is_ident_byte(bytes[at - 1]) || bytes[at - 1] == b':') {
    at -= 1;
  }
  code[at..end].trim_matches(':').to_string()
}

/// Whether the call whose name starts at `name_at` feeds something that
/// consumes its answer.
///
/// The innermost group that ENCLOSES the call — not the call's own — and its
/// callee has to be one of [`CONSUMING`].
fn consumed(groups: &[Group], name_at: usize) -> bool {
  groups
    .iter()
    .filter(|group| group.open < name_at && group.close > name_at)
    .max_by_key(|group| group.open)
    .is_some_and(|group| CONSUMING.contains(&group.callee.as_str()))
}

/// One argument of a call: its text, and where it starts within the list.
struct Argument<'a> {
  start: usize,
  text: &'a str,
}

/// `args` split at its top-level commas, empty parts dropped so a trailing
/// comma is not an argument.
fn split_top_level(args: &str) -> Vec<Argument<'_>> {
  let mut parts = Vec::new();
  let mut depth = 0i32;
  let mut start = 0usize;
  for (at, byte) in args.bytes().enumerate() {
    match byte {
      b'(' | b'[' | b'{' => depth += 1,
      b')' | b']' | b'}' => depth -= 1,
      b',' if depth == 0 => {
        push_argument(&mut parts, args, start, at);
        start = at + 1;
      }
      _ => {}
    }
  }
  push_argument(&mut parts, args, start, args.len());
  parts
}

/// Records `args[from..to]` as an argument unless it is only whitespace.
fn push_argument<'a>(into: &mut Vec<Argument<'a>>, args: &'a str, from: usize, to: usize) {
  let span = &args[from..to];
  let trimmed = span.trim();
  if trimmed.is_empty() {
    return;
  }
  let offset = span.len() - span.trim_start().len();
  into.push(Argument {
    start: from + offset,
    text: trimmed,
  });
}

/// The text inside `argument`'s `black_box(…)` when the WHOLE argument is such
/// a call, and nothing otherwise.
///
/// Whole, not merely leading: `black_box(v) + 1` hands the optimizer an opaque
/// value and then does arithmetic on it that it can see through, which is not
/// what the shim receives.
fn black_box_inner(argument: &str) -> Option<&str> {
  let open = argument.find('(')?;
  if !BLACK_BOX.contains(&argument[..open].trim_end()) {
    return None;
  }
  let close = matching(argument.as_bytes(), open)?;
  if argument[close + 1..].trim().is_empty() {
    Some(&argument[open + 1..close])
  } else {
    None
  }
}

/// The index of the `)`, `]` or `}` closing the delimiter at `open`.
fn matching(bytes: &[u8], open: usize) -> Option<usize> {
  let (opener, closer) = match bytes.get(open)? {
    b'(' => (b'(', b')'),
    b'[' => (b'[', b']'),
    b'{' => (b'{', b'}'),
    _ => return None,
  };
  let mut depth = 0usize;
  for (at, byte) in bytes.iter().enumerate().skip(open) {
    if *byte == opener {
      depth += 1;
    } else if *byte == closer {
      depth -= 1;
      if depth == 0 {
        return Some(at);
      }
    }
  }
  None
}

/// Whether `byte` can sit inside an identifier.
fn is_ident_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The 1-based line `at` sits on.
fn line_of(code: &str, at: usize) -> usize {
  code.as_bytes()[..at.min(code.len())]
    .iter()
    .filter(|byte| **byte == b'\n')
    .count()
    + 1
}

/// `len` bytes of the ORIGINAL source at `at`, whitespace collapsed and cut to
/// a readable width.
///
/// Read from the source rather than from the blanked copy so a failure quotes
/// the argument the author wrote instead of a string literal blanked to spaces.
fn shown_at(text: &str, at: usize, len: usize) -> String {
  let span: String = text
    .get(at..at + len)
    .unwrap_or_default()
    .split_whitespace()
    .collect::<Vec<_>>()
    .join(" ");
  if span.chars().count() > 60 {
    format!("{}…", span.chars().take(59).collect::<String>())
  } else {
    span
  }
}

/// `text` with every comment and every literal replaced by spaces, byte for
/// byte — or a refusal naming the one it could not finish reading.
///
/// Byte offsets are preserved, so a position found in the result addresses the
/// same byte of the source — which is what lets a failure quote the real text
/// and name the real line.
///
/// Blanking rather than deleting is also what keeps this check from reading its
/// own subject matter: each of the four files DOCUMENTS the `black_box` rule at
/// length, and a scan over raw text would find `shim_encode(` and
/// `black_box(…)` in prose and grade the paragraph.
///
/// # Every literal form, and a refusal for anything else
///
/// Rust's literal forms are enumerated here rather than approximated, and the
/// reason is the fourth bypass of this gate: this function used to know only
/// ordinary `"…"`, so in `r#"assert!(shim_x(black_box(b"a")))"#` the quotes
/// INSIDE the raw literal ended and restarted its blanking, and it handed the
/// call scanner a fake call as code. Raw and raw-byte strings of any hash
/// count, byte and C-string prefixes, character literals and the lifetimes that
/// share their `'` are each read whole.
///
/// A form it cannot finish — an unterminated literal or block comment — is an
/// [`Unlexable`], not a guess. Guessing where a literal ended is what let a
/// string be read as code; guessing the other way would let real calls be read
/// as prose and empty the whole check just as silently.
fn blank_noncode(text: &str) -> Result<String, Unlexable> {
  let mut out = String::with_capacity(text.len());
  let bytes = text.as_bytes();
  let mut at = 0usize;
  while at < bytes.len() {
    // Before the match, because a raw string's own opener is several bytes and
    // its first is not the `"` that would otherwise be matched on.
    if let Some((quote, hashes)) = raw_string(bytes, at) {
      let Some(end) = raw_string_end(bytes, quote + 1, hashes) else {
        return Err(Unlexable {
          at,
          what: "an unterminated raw string literal",
        });
      };
      while at <= end {
        blank(&mut out, text, &mut at);
      }
      continue;
    }
    match bytes[at] {
      b'/' if bytes.get(at + 1) == Some(&b'/') => {
        while at < bytes.len() && bytes[at] != b'\n' {
          blank(&mut out, text, &mut at);
        }
      }
      b'/' if bytes.get(at + 1) == Some(&b'*') => {
        let opened = at;
        let mut depth = 0usize;
        while at < bytes.len() {
          if bytes[at] == b'/' && bytes.get(at + 1) == Some(&b'*') {
            depth += 1;
            blank(&mut out, text, &mut at);
            blank(&mut out, text, &mut at);
            continue;
          }
          if bytes[at] == b'*' && bytes.get(at + 1) == Some(&b'/') {
            depth -= 1;
            blank(&mut out, text, &mut at);
            blank(&mut out, text, &mut at);
            if depth == 0 {
              break;
            }
            continue;
          }
          blank(&mut out, text, &mut at);
        }
        if depth != 0 {
          return Err(Unlexable {
            at: opened,
            what: "an unterminated `/*` block comment",
          });
        }
      }
      b'"' => {
        let opened = at;
        let mut closed = false;
        blank(&mut out, text, &mut at);
        while at < bytes.len() {
          if bytes[at] == b'\\' {
            blank(&mut out, text, &mut at);
            if at < bytes.len() {
              blank(&mut out, text, &mut at);
            }
            continue;
          }
          let quote = bytes[at] == b'"';
          blank(&mut out, text, &mut at);
          if quote {
            closed = true;
            break;
          }
        }
        if !closed {
          return Err(Unlexable {
            at: opened,
            what: "an unterminated string literal",
          });
        }
      }
      // A `'` opens a character literal only when a single character closes it
      // — `'x'`, `'\n'`. Otherwise it is a lifetime, and swallowing to the next
      // `'` would blank everything between `<'a, 'b>`.
      b'\'' if char_literal(bytes, at).is_some() => {
        let end = char_literal(bytes, at).unwrap_or(at);
        while at <= end {
          blank(&mut out, text, &mut at);
        }
      }
      _ => {
        let ch = text[at..].chars().next().unwrap_or('\0');
        out.push(ch);
        at += ch.len_utf8();
      }
    }
  }
  Ok(out)
}

/// A literal or comment [`blank_noncode`] could not finish reading.
///
/// Carried rather than swallowed so the failure can name the LINE: an
/// unterminated literal is usually a typo several screens above whatever the
/// check then reports.
struct Unlexable {
  at: usize,
  what: &'static str,
}

/// The opening `"` of a raw string starting at `at`, and how many `#` guard it.
///
/// Covers `r"…"`, `br"…"`, `cr"…"` and every hash count of each. `r#ident` is
/// deliberately not one: a raw IDENTIFIER has no `"` after its hashes, which is
/// the same test that distinguishes them in the language.
fn raw_string(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
  if at > 0 && bytes.get(at - 1).copied().is_some_and(is_ident_byte) {
    return None;
  }
  let mut cursor = at;
  if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
    cursor += 1;
  }
  if bytes.get(cursor) != Some(&b'r') {
    return None;
  }
  cursor += 1;
  let hashes = cursor;
  while bytes.get(cursor) == Some(&b'#') {
    cursor += 1;
  }
  (bytes.get(cursor) == Some(&b'"')).then_some((cursor, cursor - hashes))
}

/// The index of the last byte of the `"` + `hashes` × `#` that closes a raw
/// string whose content starts at `from`.
///
/// A raw string has no escapes at all, so the closing sequence is the only
/// thing that ends it — which is exactly why the ordinary-string reader was
/// wrong about one and why this is a separate walk rather than a flag on that
/// one.
fn raw_string_end(bytes: &[u8], from: usize, hashes: usize) -> Option<usize> {
  let mut at = from;
  while at < bytes.len() {
    if bytes[at] == b'"' && (1..=hashes).all(|nth| bytes.get(at + nth) == Some(&b'#')) {
      return Some(at + hashes);
    }
    at += 1;
  }
  None
}

/// Copies one character of `text` at `at` as spaces, keeping a newline so line
/// numbers survive, and advances `at` past it.
fn blank(out: &mut String, text: &str, at: &mut usize) {
  let ch = text[*at..].chars().next().unwrap_or('\0');
  if ch == '\n' {
    out.push('\n');
  } else {
    for _ in 0..ch.len_utf8() {
      out.push(' ');
    }
  }
  *at += ch.len_utf8();
}

/// The index of the `'` closing a character literal that opens at `at`, or
/// nothing when that `'` opens a lifetime instead.
fn char_literal(bytes: &[u8], at: usize) -> Option<usize> {
  if bytes.get(at) != Some(&b'\'') {
    return None;
  }
  if bytes.get(at + 1) == Some(&b'\\') {
    // `'\n'`, `'\\'`, `'\u{1F600}'` — the escape runs to the next `'`.
    return bytes
      .iter()
      .enumerate()
      .skip(at + 2)
      .find(|(_, byte)| **byte == b'\'')
      .map(|(index, _)| index);
  }
  // One character, whatever its width, then the closing `'`.
  let rest = core::str::from_utf8(bytes.get(at + 1..)?).ok()?;
  let ch = rest.chars().next()?;
  let end = at + 1 + ch.len_utf8();
  (bytes.get(end) == Some(&b'\'')).then_some(end)
}

/// Every `no_panic::no_panic` in `code` written outside the `macro_rules!
/// no_panic_shim` definition.
///
/// The macro's own expansion is the ONE place that attribute belongs. Written
/// anywhere else it declares a shim that never passes through
/// [`shims_in`] — a subject outside its own gate, whose arguments and answer
/// nothing here examines.
fn stray_attributes(code: &str) -> Vec<usize> {
  let definition = definition_range(code);
  let mut found = Vec::new();
  let mut from = 0usize;
  while let Some(at) = code[from..].find(NO_PANIC_ATTR).map(|off| from + off) {
    from = at + NO_PANIC_ATTR.len();
    if definition.as_ref().is_some_and(|range| range.contains(&at)) {
      continue;
    }
    found.push(at);
  }
  found
}

/// The shim attribute the macro at `definition` applies in the RELEASE build,
/// or every spelling it applies instead.
///
/// Written as a closed list of accepted forms rather than a predicate over
/// `cfg` expressions, because the question is not "is this attribute here" but
/// "is it applied in the build the proofs are LINKED in", and that is decided
/// by whatever `cfg_attr` predicate wraps it. `not(debug_assertions)` is the
/// one this workspace uses — `--release` turns debug assertions off, so the
/// attribute applies — and its negation would leave every shim in the file a
/// plain function with the file still spelling `no_panic::no_panic`. A form
/// this does not know is REFUSED rather than guessed at: an unknown predicate
/// is an unknown answer, and this module's rule is that an unknown fate is not
/// a passing one.
fn release_attribute(
  text: &str,
  code: &str,
  definition: &std::ops::Range<usize>,
) -> Result<String, Vec<String>> {
  let body = &code[definition.clone()];
  let bytes = body.as_bytes();
  let mut found = Vec::new();
  let mut from = 0usize;
  while let Some(at) = body[from..].find(NO_PANIC_ATTR).map(|off| from + off) {
    from = at + NO_PANIC_ATTR.len();
    let Some(open) = body[..at].rfind("#[") else {
      continue;
    };
    let Some(close) = matching(bytes, open + 1) else {
      continue;
    };
    if close < at {
      continue;
    }
    // DECIDED on the blanked copy, where a comment written inside the
    // attribute cannot make one spelling look like another — and SHOWN from
    // the source, because blanking replaces a literal with spaces and a
    // failure has to quote the predicate the author actually wrote.
    let attribute = collapsed(&body[open..=close]);
    if RELEASE_ATTRS.contains(&attribute.as_str()) {
      return Ok(attribute);
    }
    let start = definition.start + open;
    let stop = definition.start + close;
    // The source's own bytes when they can be taken — blanking preserves every
    // offset, so this is the same span — and the blanked one rather than a
    // panic if they ever cannot.
    found.push(text.get(start..=stop).map_or(attribute, collapsed));
  }
  Err(found)
}

/// The byte range of the `macro_rules! no_panic_shim { … }` definition.
fn definition_range(code: &str) -> Option<std::ops::Range<usize>> {
  let bytes = code.as_bytes();
  // Spelled from `SHIM_MACRO` rather than beside it, so the invocation and the
  // definition cannot come to mean two different names.
  let declared = SHIM_MACRO.trim_end_matches('!');
  let mut from = 0usize;
  loop {
    let at = code[from..].find("macro_rules!").map(|off| from + off)?;
    from = at + "macro_rules!".len();
    // A whole word here too. `my_macro_rules! no_panic_shim { … }` is some
    // other macro's invocation, and taking ITS body for the definition would
    // hand this file's one exemption — the `#[no_panic::no_panic]` inside the
    // definition — to a block that is not the definition.
    if at > 0 && is_ident_byte(bytes[at - 1]) {
      continue;
    }
    let rest = code[from..].trim_start();
    // The name has to END there too. `macro_rules! no_panic_shim_other` is a
    // different macro, and taking its body for this one's would excuse a
    // `#[no_panic::no_panic]` written inside it — the one exemption
    // [`stray_attributes`] grants, and it belongs to this definition alone.
    let Some(tail) = rest.strip_prefix(declared) else {
      continue;
    };
    if tail.as_bytes().first().copied().is_some_and(is_ident_byte) {
      continue;
    }
    let open = from + code[from..].find('{')?;
    let close = matching(bytes, open)?;
    return Some(at..close);
  }
}

/// A set of `cfg` predicates, sorted and deduplicated so two sets that gate the
/// same thing compare equal.
///
/// Read from the SOURCE rather than from the blanked copy, because blanking
/// replaces a string literal with spaces: over that copy `feature = "one"` and
/// `feature = "two"` would both read `feature = `, and [`LIE_GATE`] — the one
/// predicate this module treats specially — would be indistinguishable from
/// any other feature gate.
type GateSet = Vec<String>;

/// The outer attributes written immediately before `at`, in source order.
///
/// Stops at an INNER attribute (`#![…]`): that one belongs to the enclosing
/// module and not to the item below it, so a file-level `#![cfg(…)]` — which
/// gates the shims and their tests alike, and therefore cancels — is not read
/// as a gate on whichever item happens to be written first.
///
/// `pub`, `const`, `async`, `unsafe` and `extern` are stepped over, so an item
/// spelled with any of them still finds its own attributes.
fn attributes_before(text: &str, code: &str, at: usize) -> Vec<String> {
  let bytes = code.as_bytes();
  let mut out = Vec::new();
  let mut end = at;
  loop {
    loop {
      while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
      }
      let mut word = end;
      while word > 0 && is_ident_byte(bytes[word - 1]) {
        word -= 1;
      }
      if matches!(
        &code[word..end],
        "pub" | "const" | "async" | "unsafe" | "extern"
      ) {
        end = word;
        continue;
      }
      break;
    }
    if end == 0 || bytes[end - 1] != b']' {
      break;
    }
    let Some(open) = matching_backwards(bytes, end - 1) else {
      break;
    };
    if open == 0 || bytes[open - 1] != b'#' {
      break;
    }
    let hash = open - 1;
    out.push(collapsed(text.get(hash..end).unwrap_or_default()));
    end = hash;
  }
  out.reverse();
  out
}

/// The `cfg` predicates among `attributes`, as written.
///
/// `#[cfg_attr(…)]` is NOT one: it conditions an attribute rather than the
/// item's existence, and the shim macro's own
/// `#[cfg_attr(not(debug_assertions), no_panic::no_panic)]` is exactly that
/// case — the shim exists in debug too, it is only unguarded there.
fn gates_of(attributes: &[String]) -> GateSet {
  let mut gates: GateSet = attributes
    .iter()
    .filter_map(|attribute| {
      attribute
        .strip_prefix("#[cfg(")
        .and_then(|inner| inner.strip_suffix(")]"))
        .map(str::to_string)
    })
    .collect();
  gates.sort();
  gates.dedup();
  gates
}

/// Every use of `name` in `code` that is NOT a call and not its own
/// declaration.
///
/// Taking a shim's address — `let f: fn(&[u8]) -> bool = shim_x;`, a closure
/// that captures it — instantiates it, so the artifact half will report it as
/// present, while this half checks arguments at CALL sites and has therefore
/// checked none of that use's. The two halves would then agree that the shim is
/// fine with neither having looked at what it was passed, so the span is
/// failed. An identifier that merely STARTS with `name` is not one of these:
/// `shim_xy` is a different shim, with a declaration and call sites of its own.
fn bare_mentions(code: &str, name: &str, shims: &[Shim]) -> Vec<usize> {
  let bytes = code.as_bytes();
  let mut out = Vec::new();
  let mut from = 0usize;
  while let Some(at) = code[from..].find(name).map(|off| from + off) {
    from = at + name.len();
    if at > 0 && is_ident_byte(bytes[at - 1]) {
      continue;
    }
    if bytes.get(from).copied().is_some_and(is_ident_byte) {
      continue;
    }
    if shims.iter().any(|shim| shim.decl.contains(&at)) {
      continue;
    }
    let next = bytes[from..]
      .iter()
      .position(|byte| !byte.is_ascii_whitespace())
      .map(|off| from + off);
    if next.is_some_and(|at| bytes[at] == b'(') {
      continue;
    }
    out.push(at);
  }
  out
}

/// The index of the `(`, `[` or `{` opening the delimiter at `close`.
fn matching_backwards(bytes: &[u8], close: usize) -> Option<usize> {
  let (opener, closer) = match bytes.get(close)? {
    b')' => (b'(', b')'),
    b']' => (b'[', b']'),
    b'}' => (b'{', b'}'),
    _ => return None,
  };
  let mut depth = 0usize;
  let mut at = close;
  loop {
    if bytes[at] == closer {
      depth += 1;
    } else if bytes[at] == opener {
      depth -= 1;
      if depth == 0 {
        return Some(at);
      }
    }
    if at == 0 {
      return None;
    }
    at -= 1;
  }
}

/// `span` with every run of whitespace collapsed to one space, so an attribute
/// written across lines compares as one written on a line.
fn collapsed(span: &str) -> String {
  span.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A `tests/no_panic.rs` in miniature: the macro, one shim declared under
  /// `attributes`, and whatever `items` the caller writes below it.
  ///
  /// The macro is the one all four live files define, expansion included —
  /// `#[inline(never)]` and the `black_box` around the shim's ANSWER, which
  /// this module's own doc calls load-bearing. It used to be a shortened
  /// stand-in that dropped the `black_box` wrap, which made every test below
  /// run against a macro no file has. What GUARDS those two is the artifact
  /// half rather than a rule here — without `#[inline(never)]` there is no
  /// symbol to find, and without the wrap a trivial shim is deleted whole —
  /// so this fixture has to carry them or the tests describe a different
  /// subject than the one the four files declare.
  fn file_full(attributes: &str, shim: &str, items: &str) -> String {
    format!(
      "macro_rules! no_panic_shim {{\n  \
         ($(#[$meta:meta])* fn $name:ident ($($arg:tt)*) $(-> $ret:ty)? $body:block) => {{\n    \
           $(#[$meta])*\n    \
           #[cfg_attr(not(debug_assertions), no_panic::no_panic)]\n    \
           #[inline(never)]\n    \
           fn $name($($arg)*) $(-> $ret)? {{\n      \
             ::core::hint::black_box($body)\n    \
           }}\n  \
         }};\n\
       }}\n\
       use core::hint::black_box;\n\
       {attributes}no_panic_shim! {{\n  {shim}\n}}\n\
       {items}\n"
    )
  }

  /// The same file with an ungated shim.
  fn file_with(shim: &str, items: &str) -> String {
    file_full("", shim, items)
  }

  /// The same file again with one `#[test]` making one call — the shape most of
  /// the tests below want.
  fn file(shim: &str, call: &str) -> String {
    file_with(shim, &format!("#[test]\nfn t() {{\n  {call}\n}}"))
  }

  /// Runs the SOURCE half over one in-memory file, and answers the failures it
  /// recorded.
  ///
  /// [`check_file`] ITSELF, not a second copy of it. The copy that used to live
  /// here drove the same helpers in the same order, which is exactly as much
  /// coverage as remembering to update it: a rule added to `run` and not here
  /// was a rule no test could fail on, and a rule deleted from `run` left every
  /// test below still green on the copy. The real `run` reads the workspace and
  /// builds four crates, so this is the seam that lets a test hand it a file
  /// the workspace does not contain.
  fn problems(text: &str) -> Vec<String> {
    let mut counts = Counts::default();
    let mut out = Vec::new();
    check_file("f", text, &mut counts, &mut out);
    out
  }

  /// One declared shim, as [`shims_in`] would have returned it, for the
  /// artifact half's tests.
  fn shim(name: &str, gates: &[&str]) -> Shim {
    Shim {
      name: name.to_string(),
      unit: false,
      gates: gates.iter().map(|gate| (*gate).to_string()).collect(),
      decl: 0..0,
      line: 1,
    }
  }

  /// Runs the ARTIFACT half's verdicts over a symbol list a test controls, and
  /// answers what it recorded.
  ///
  /// The symbol list rather than a built binary: `verdicts` is the whole of
  /// what this half DECIDES, and the build and the object-file reader on either
  /// side of it are tested where they live — the reader in
  /// [`crate::symbols`], the build by the four live crates every run examines.
  fn linked(declared: &[Shim], found: &[Symbol]) -> (Counts, Vec<String>, String) {
    let mut counts = Counts::default();
    let mut report = Report::new("shim-check");
    let census = verdicts(
      "f",
      "some-crate",
      Path::new("/some/no_panic-0"),
      declared,
      found,
      &mut counts,
      &mut report,
    );
    (counts, report.failures.clone(), census)
  }

  /// The `main` rustc's `--test` harness synthesises at the test crate's own
  /// root, which every symbol list below carries because every real proof
  /// binary does — and which is what [`verdicts`] establishes the binary's
  /// IDENTITY from. A list without it does not model a smaller binary; it
  /// models one that could not have been linked.
  const ANCHOR: &str = "_RNvCsg8Ts9hS57d_8no_panic4main";

  /// How a run's own line names the identity that anchor establishes.
  const BOUND: &str = "no_panic (v0 sg8Ts9hS57d_)";

  /// One entry of a symbol table, as `symbols::read` would have returned it.
  ///
  /// Written out MANGLED at each call site rather than built from a name here:
  /// whose symbol it is is the whole question this half answers, and a helper
  /// that assembled the path would answer it on the test's behalf.
  fn symbol(name: &str, defined_function: bool) -> Symbol {
    Symbol {
      name: name.to_string(),
      defined_function,
    }
  }

  // ── the source half: how a shim is written ────────────────────────────────

  // The shapes the four live files actually use, so a rule tightened past them
  // fails here rather than in CI.
  #[test]
  fn the_documented_call_shapes_are_accepted() {
    for call in [
      "assert!(shim_x(black_box(b\"a\".as_slice())));",
      "assert!(!shim_x(black_box(b\"a\".as_slice())));",
      "assert_eq!(shim_x(black_box(b\"a\".as_slice())), true);",
      "assert_ne!(shim_x(black_box(b\"a\".as_slice())), false);",
      "black_box(shim_x(black_box(b\"a\".as_slice())));",
      "assert!(shim_x(black_box(b\"a\".as_slice())) || false);",
      "core::hint::black_box(shim_x(black_box(b\"a\".as_slice())));",
    ] {
      let found = problems(&file("fn shim_x(v: &[u8]) -> bool { v.is_empty() }", call));
      assert!(found.is_empty(), "{call}: {found:?}");
    }
  }

  // THE defect this module exists for: the opaque call put back to a literal.
  // `shim_lie` still reds its own build and the grep still finds its marker, so
  // nothing in CI moved — and neither does the artifact half, because the shim
  // IS instantiated. This is the only thing that moves.
  #[test]
  fn an_argument_that_is_not_opaque_is_a_failure() {
    let found = problems(&file(
      "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
      "assert!(shim_x(b\"a\".as_slice()));",
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("is not a `black_box` call"),
      "{}",
      found[0]
    );
  }

  // One argument of several, which is how a sweep loses coverage in practice.
  #[test]
  fn one_bare_argument_among_opaque_ones_is_a_failure() {
    let found = problems(&file(
      "fn shim_x(a: u8, b: u8) -> u8 { a.wrapping_add(b) }",
      "assert_eq!(shim_x(black_box(1), 2), 3);",
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("is not a `black_box` call"),
      "{}",
      found[0]
    );
  }

  // `black_box` at the head is not `black_box` around the whole argument: the
  // arithmetic after it is something the optimizer can still see through.
  #[test]
  fn an_argument_only_partly_opaque_is_a_failure() {
    let found = problems(&file(
      "fn shim_x(a: u8) -> u8 { a }",
      "assert_eq!(shim_x(black_box(1) + 1), 2);",
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("is not a `black_box` call"),
      "{}",
      found[0]
    );
  }

  // A shim whose answer is dropped can be deleted whole, and a deleted call
  // proves nothing.
  #[test]
  fn a_dropped_answer_is_a_failure() {
    let found = problems(&file(
      "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
      "shim_x(black_box(b\"a\".as_slice()));",
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("answer is dropped"), "{}", found[0]);
  }

  // A `let` binding is not on the accepted list, and that is deliberate rather
  // than an oversight: an answer bound and dropped is as dead as one never
  // taken. Pinned so a future author reads the rule instead of guessing it.
  #[test]
  fn a_let_binding_is_not_an_accepted_consumer() {
    let found = problems(&file(
      "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
      "let _held = shim_x(black_box(b\"a\".as_slice()));",
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("answer is dropped"), "{}", found[0]);
  }

  // `debug_assert` and its siblings are off the accepted-consumer list, and
  // that is what this half has left to say about them: the release build
  // deletes the expression, so the call is not in the binary and the artifact
  // half is what reports the shim as uninstantiated.
  #[test]
  fn a_debug_assertion_is_not_an_accepted_consumer() {
    for call in [
      "debug_assert!(shim_x(black_box(b\"a\".as_slice())));",
      "debug_assert_eq!(shim_x(black_box(b\"a\".as_slice())), true);",
      "debug_assert_ne!(shim_x(black_box(b\"a\".as_slice())), false);",
    ] {
      let found = problems(&file("fn shim_x(v: &[u8]) -> bool { v.is_empty() }", call));
      assert!(
        found
          .iter()
          .any(|problem| problem.contains("answer is dropped")),
        "{call}: {found:?}"
      );
    }
  }

  // A `()` shim has no answer to hold, so what holds it is the opaque `&mut` it
  // writes through — the exact rule `shim_mask`'s call sites are written to.
  #[test]
  fn a_unit_shim_is_held_by_its_opaque_mut() {
    let held = problems(&file(
      "fn shim_x(v: &mut [u8], k: u8) { v.fill(k) }",
      "shim_x(black_box(&mut buf[..]), black_box(0));",
    ));
    assert!(held.is_empty(), "{held:?}");

    let unheld = problems(&file(
      "fn shim_x(a: u8, b: u8) { let _ = a.wrapping_add(b); }",
      "shim_x(black_box(1), black_box(2));",
    ));
    assert_eq!(unheld.len(), 1, "{unheld:?}");
    assert!(
      unheld[0].contains("called with no `black_box(&mut …)` argument"),
      "{}",
      unheld[0]
    );
  }

  // A shim with no call site is one whose arguments were checked by nothing.
  // Whether it is INSTANTIATED is the linker's question, and the message says
  // so rather than claiming an answer this half does not have.
  #[test]
  fn a_shim_with_no_call_site_is_a_failure_about_coverage() {
    let mut counts = Counts::default();
    let mut found = Vec::new();
    check_file(
      "f",
      &file("fn shim_x(v: &[u8]) -> bool { v.is_empty() }", "let _ = 1;"),
      &mut counts,
      &mut found,
    );
    assert_eq!(counts.unanalysable, 1, "{found:?}");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("has no call site this check can read"),
      "{}",
      found[0]
    );
  }

  // Taking a shim's address instantiates it, so the artifact half says yes
  // while this half has checked no argument of that use. Neither half may be
  // left standing on the other's answer.
  #[test]
  fn a_shim_used_without_a_call_is_counted_and_failed() {
    let mut counts = Counts::default();
    let mut found = Vec::new();
    check_file(
      "f",
      &file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"a\".as_slice())));\n  \
         let f: fn(&[u8]) -> bool = shim_x;\n  \
         assert!(f(black_box(b\"b\".as_slice())));",
      ),
      &mut counts,
      &mut found,
    );
    assert_eq!(counts.unanalysable, 1, "{found:?}");
    assert!(
      found
        .iter()
        .any(|problem| problem.contains("is written without a call's `(`")),
      "{found:?}"
    );
  }

  // The floor under discovery. A shim declared by writing the attribute
  // directly is one `shims_in` never returns, so it would be examined by
  // nothing at all — and the linker would never be asked about it either,
  // because the artifact half's subjects are the shims this one found.
  #[test]
  fn an_attribute_outside_the_macro_is_a_failure() {
    let text = format!(
      "{}\n#[no_panic::no_panic]\nfn shim_y(v: &[u8]) -> bool {{ v.is_empty() }}\n",
      file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"a\".as_slice())));",
      )
    );
    let found = problems(&text);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("written outside `macro_rules!"),
      "{}",
      found[0]
    );
  }

  // The other half of the same floor: a file whose macro no longer applies the
  // attribute declares plain functions, and every link proof in that crate
  // passes on nothing.
  #[test]
  fn a_macro_that_stopped_applying_the_attribute_is_a_failure() {
    let text = file(
      "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
      "assert!(shim_x(black_box(b\"a\".as_slice())));",
    )
    .replace(
      "#[cfg_attr(not(debug_assertions), no_panic::no_panic)]\n    ",
      "",
    );
    let found = problems(&text);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("does not apply `#[no_panic::no_panic]`"),
      "{}",
      found[0]
    );
    assert!(found[0].contains("It applies none"), "{}", found[0]);
  }

  // ── separating code from text, which is where the fourth bypass came in ───

  // Every one of the four files documents the `black_box` rule at length and
  // quotes call shapes while doing it. A scan over raw text would grade the
  // prose; this is what stops it.
  #[test]
  fn prose_and_string_literals_are_not_read_as_code() {
    let text = format!(
      "//! `shim_x(1)` in a doc comment, and `#[no_panic::no_panic]` in one too.\n\
       {}",
      file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"shim_x(1) inside a literal\".as_slice())));",
      )
    );
    let found = problems(&text);
    assert!(found.is_empty(), "{found:?}");
  }

  // THE FOURTH BYPASS, as a unit test. A raw string's quotes used to end and
  // restart the blanker, so `assert!(shim_x(black_box(…)))` written as string
  // DATA was read as a rooted, opaque, consumed call — and a shim whose only
  // real call was replaced by one passed this check while the linker never saw
  // it. Every raw form, because the hash count and the byte and C prefixes are
  // each a way to spell the same trick.
  #[test]
  fn a_call_spelled_inside_a_raw_string_is_not_a_call() {
    for literal in [
      "r#\"\"assert!(shim_x(black_box(b\"a\".as_slice())));\"\"#",
      "r##\"assert!(shim_x(black_box(1)));\"##",
      "br#\"\"assert!(shim_x(black_box(b\"a\".as_slice())));\"\"#",
      "cr#\"\"assert!(shim_x(black_box(b\"a\".as_slice())));\"\"#",
      "r\"assert!(shim_x(black_box(1)));\"",
    ] {
      let found = problems(&file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        &format!("let _ = {literal};"),
      ));
      // The shim's only "call" is inside the literal, so the file has no call
      // site at all — which is what the source half is entitled to say. That
      // the shim is then never instantiated is the artifact half's sentence.
      assert_eq!(found.len(), 1, "{literal}: {found:?}");
      assert!(
        found[0].contains("has no call site this check can read"),
        "{literal}: {}",
        found[0]
      );
    }
  }

  // …and a raw string is still readable as itself: a real call beside one is
  // not lost, which is what says the fix reads the literal rather than giving
  // up at the first `r#`.
  #[test]
  fn a_raw_string_beside_a_real_call_costs_nothing() {
    let found = problems(&file(
      "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
      "let _ = r#\"a \"quoted\" word\"#;\n  \
       assert!(shim_x(black_box(b\"a\".as_slice())));",
    ));
    assert!(found.is_empty(), "{found:?}");
  }

  // `r#type` is a raw IDENTIFIER, not a raw string, and reading it as one would
  // swallow the rest of the file — every shim with it, and a green run over
  // nothing at all.
  #[test]
  fn a_raw_identifier_is_not_a_raw_string() {
    let found = problems(&file(
      "fn shim_x(r#type: &[u8]) -> bool { r#type.is_empty() }",
      "assert!(shim_x(black_box(b\"a\".as_slice())));",
    ));
    assert!(found.is_empty(), "{found:?}");
  }

  // Lifetimes and character literals share the `'`, and a blanker that reads
  // `<'a, 'b>` as an unterminated character literal erases the rest of the file
  // — every shim with it, and the run goes quietly green over nothing.
  #[test]
  fn a_lifetime_is_not_read_as_a_character_literal() {
    let found = problems(&file(
      "fn shim_x(v: &'static [u8], c: u8) -> bool { v.first() == Some(&c) }",
      "assert!(shim_x(black_box(b\"a\".as_slice()), black_box(b'a')));",
    ));
    assert!(found.is_empty(), "{found:?}");
  }

  // A literal this cannot finish reading is refused rather than guessed at.
  // Both guesses are silent: prose read as calls grades a paragraph, and calls
  // read as prose empties the file.
  #[test]
  fn a_literal_it_cannot_finish_reading_is_refused() {
    for (tail, expected) in [
      (
        "let _ = r#\"never closed;",
        "unterminated raw string literal",
      ),
      ("let _ = \"never closed;", "unterminated string literal"),
      ("/* never closed", "unterminated `/*` block comment"),
    ] {
      let text = format!(
        "{}\n{tail}",
        file(
          "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
          "assert!(shim_x(black_box(b\"a\".as_slice())));",
        )
      );
      let found = problems(&text);
      assert_eq!(found.len(), 1, "{tail}: {found:?}");
      assert!(found[0].contains(expected), "{tail}: {}", found[0]);
    }
  }

  // A macro whose name merely STARTS with this one's is a different macro, and
  // its body is not this one's definition. Taking it for one would move the
  // exemption `stray_attributes` grants — the attribute inside the decoy would
  // be excused and the real macro's own would be reported instead, which is a
  // failure of the same shape pointing at the wrong line.
  #[test]
  fn a_macro_whose_name_only_starts_the_same_does_not_take_the_exemption() {
    let decoy = "macro_rules! no_panic_shim_other {\n  \
                   () => {\n    \
                     #[no_panic::no_panic]\n    \
                     fn shim_z() {}\n  \
                   };\n\
                 }\n";
    let text = format!(
      "{decoy}{}",
      file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"a\".as_slice())));",
      )
    );
    let at = text
      .find("#[no_panic::no_panic]")
      .expect("the decoy writes the attribute");
    let line = text[..at].matches('\n').count() + 1;

    let found = problems(&text);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("written outside `macro_rules! no_panic_shim`"),
      "{}",
      found[0]
    );
    // The LINE is the subject: the count is one either way, and only this says
    // which of the two attributes was the one outside the definition.
    assert!(found[0].starts_with(&format!("f:{line}:")), "{}", found[0]);
  }

  // The same rule on the DEFINITION's own keyword. `my_macro_rules!` ends with
  // `macro_rules!`, so a search for that substring found it — and the block
  // after it would have become "the definition", which is the one place this
  // file may write `#[no_panic::no_panic]`. The exemption then covers a block
  // that is not the definition, and the real macro's own attribute is reported
  // in its place: a failure of the right shape pointing at the wrong line.
  #[test]
  fn a_keyword_another_word_ends_with_does_not_open_the_definition() {
    let decoy = "my_macro_rules! no_panic_shim {\n  \
                   () => {\n    \
                     #[no_panic::no_panic]\n    \
                     fn shim_z() {}\n  \
                   };\n\
                 }\n";
    let text = format!(
      "{decoy}{}",
      file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"a\".as_slice())));",
      )
    );
    let code = blank_noncode(&text).unwrap_or_else(|err| panic!("{} at byte {}", err.what, err.at));
    let range = definition_range(&code).expect("this file defines the macro");
    let real = text
      .find("macro_rules! no_panic_shim {\n  ($(")
      .expect("the real definition is in there");
    assert!(
      range.contains(&real),
      "the definition found starts at {}, and the real one at {real}",
      range.start
    );

    // And the attribute reported as stray is the decoy's, not the real
    // macro's, which is what says the exemption stayed where it belongs.
    let found = problems(&text);
    assert_eq!(found.len(), 1, "{found:?}");
    let at = text
      .find("#[no_panic::no_panic]")
      .expect("the decoy writes the attribute");
    let line = text[..at].matches('\n').count() + 1;
    assert!(found[0].starts_with(&format!("f:{line}:")), "{}", found[0]);
  }

  // The same rule at the other end of the name: `my_no_panic_shim!` contains
  // this macro's invocation as a substring and is not one. Its blocks would be
  // read as shim declarations — subjects that never carried the attribute,
  // counted into the denominator a green run prints.
  #[test]
  fn a_macro_whose_name_only_ends_the_same_is_not_an_invocation() {
    let text = format!(
      "{}my_no_panic_shim! {{\n  fn shim_z(v: &[u8]) -> bool {{ v.is_empty() }}\n}}\n",
      file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"a\".as_slice())));",
      )
    );
    let code = blank_noncode(&text).unwrap_or_else(|err| panic!("{} at byte {}", err.what, err.at));
    let found = shims_in(&text, &code);
    assert!(found.unparsed.is_empty(), "{:?}", found.unparsed);
    assert!(found.qualified.is_empty(), "{:?}", found.qualified);
    assert_eq!(
      found
        .shims
        .iter()
        .map(|shim| shim.name.as_str())
        .collect::<Vec<_>>(),
      ["shim_x"]
    );
  }

  // The same rule again, and the one that leaves BOTH halves green while the
  // proof is absent: `other::no_panic_shim!` is a different macro reached
  // through a path, and the byte before it is `:` rather than an identifier
  // byte, so the whole-word rule above admitted it. Its expansion is one this
  // check has never seen — here it applies no attribute at all — while the
  // `fn` it declares is still a root function the linker reports under the
  // shim's own name. The source half graded the block, the artifact half found
  // the symbol, and `no-panic` was never on it.
  #[test]
  fn a_macro_reached_through_a_path_is_not_this_ones_invocation() {
    let text = format!(
      "{}other::no_panic_shim! {{\n  \
         fn shim_z(v: &[u8]) -> bool {{ v.is_empty() }}\n\
       }}\n\
       #[test]\n\
       fn u() {{\n  assert!(shim_z(black_box(b\"a\".as_slice())));\n}}\n",
      file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"a\".as_slice())));",
      )
    );
    let code = blank_noncode(&text).unwrap_or_else(|err| panic!("{} at byte {}", err.what, err.at));
    let found = shims_in(&text, &code);
    assert_eq!(found.qualified.len(), 1, "{:?}", found.qualified);
    assert_eq!(
      found
        .shims
        .iter()
        .map(|shim| shim.name.as_str())
        .collect::<Vec<_>>(),
      ["shim_x"],
      "`shim_z` was declared by another macro and is not one of this file's"
    );

    // And it FAILS rather than being quietly left out of the denominator: a
    // shim this check never sees is a shim whose arguments nothing graded,
    // whose answer nothing graded, and which the artifact half would then
    // credit to the file all the same.
    let problems = problems(&text);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
      problems[0].contains("invoked through a PATH"),
      "{}",
      problems[0]
    );
    let at = text
      .find("other::no_panic_shim!")
      .expect("the decoy invokes it");
    let line = text[..at].matches('\n').count() + 1;
    assert!(
      problems[0].starts_with(&format!("f:{line}:")),
      "{}",
      problems[0]
    );
  }

  // The other half of the same finding: the macro is spelled right and DEFINED
  // here, and its expansion applies the attribute in the build nothing links.
  // `--release` turns `debug_assertions` off, so `cfg_attr(debug_assertions, …)`
  // leaves every shim in the file a plain function — while the file still
  // spells `no_panic::no_panic`, which is all the floor here used to ask for.
  #[test]
  fn an_attribute_the_release_build_does_not_apply_is_a_failure() {
    for (attribute, expected) in [
      (
        "#[cfg_attr(debug_assertions, no_panic::no_panic)]",
        "does not apply",
      ),
      (
        "#[cfg_attr(feature = \"something-else\", no_panic::no_panic)]",
        "does not apply",
      ),
    ] {
      let text = file(
        "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
        "assert!(shim_x(black_box(b\"a\".as_slice())));",
      )
      .replace(
        "#[cfg_attr(not(debug_assertions), no_panic::no_panic)]",
        attribute,
      );
      let found = problems(&text);
      assert_eq!(found.len(), 1, "{attribute}: {found:?}");
      assert!(found[0].contains(expected), "{attribute}: {}", found[0]);
      assert!(found[0].contains(attribute), "{attribute}: {}", found[0]);
    }

    // The unconditional spelling is the other form this accepts, and the one
    // the four files use is the `not(debug_assertions)` one above.
    let text = file(
      "fn shim_x(v: &[u8]) -> bool { v.is_empty() }",
      "assert!(shim_x(black_box(b\"a\".as_slice())));",
    )
    .replace(
      "#[cfg_attr(not(debug_assertions), no_panic::no_panic)]",
      "#[no_panic::no_panic]",
    );
    assert!(problems(&text).is_empty());
  }

  // And the floor under the definition itself: a file that only INVOKES the
  // macro declares its shims through an expansion this check has never seen.
  #[test]
  fn a_file_that_does_not_define_the_macro_is_a_failure() {
    let text = "no_panic_shim! {\n  \
                  fn shim_x(v: &[u8]) -> bool { v.is_empty() }\n\
                }\n\
                #[test]\n\
                fn t() {\n  assert!(shim_x(black_box(b\"a\".as_slice())));\n}\n";
    let found = problems(text);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
      found[0].contains("no `macro_rules! no_panic_shim` defined in this file"),
      "{}",
      found[0]
    );
  }

  // ── the artifact half: what the linker instantiated ───────────────────────

  // The whole point of the redesign, in one assertion: a shim's fate is decided
  // by a symbol, in either direction, and no reading of the source is involved.
  #[test]
  fn a_shim_is_instantiated_when_the_binary_names_it_and_not_otherwise() {
    let declared = [shim("shim_x", &[]), shim("shim_y", &[])];
    let (counts, failures, census) = linked(
      &declared,
      &[
        symbol("_RNvCsg8Ts9hS57d_8no_panic6shim_x", true),
        symbol(ANCHOR, true),
      ],
    );
    assert_eq!(counts.instantiated, 1, "{failures:?}");
    assert_eq!((counts.symbols, counts.functions), (2, 2), "{failures:?}");
    assert_eq!(census, format!("some-crate 1/2 as {BOUND}"));
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(failures[0].contains("`shim_y` is declared and is NOT INSTANTIATED"));
  }

  // A name is not an identity. An executable holds every dependency's symbols
  // and every symbol it merely references, so the shim's spelling is available
  // to anything in the link — no forgery required, an ordinary collision does
  // it — and a name test accepted all of this as proof.
  #[test]
  fn a_symbol_that_is_not_this_crates_defined_shim_does_not_instantiate_it() {
    // Defined, a function, spelled exactly right — and belonging to another
    // crate, or to a module one level down in this one.
    for foreign in [
      "_RNvCsg8Ts9hS57d_9elsewhere11shim_decode",
      "_ZN9elsewhere11shim_decode17hcafe0123456789abE",
      "_RNvNtCsg8Ts9hS57d_8no_panic5inner11shim_decode",
      "_ZN8no_panic5inner11shim_decode17hcafe0123456789abE",
    ] {
      let (counts, failures, census) = linked(
        &[shim("shim_decode", &[])],
        &[symbol(foreign, true), symbol(ANCHOR, true)],
      );
      assert_eq!(counts.instantiated, 0, "{foreign}: {failures:?}");
      assert_eq!(census, format!("some-crate 0/1 as {BOUND}"), "{foreign}");
      assert_eq!(failures.len(), 1, "{foreign}: {failures:?}");
      assert!(
        failures[0].contains("`shim_decode` is declared and is NOT INSTANTIATED"),
        "{foreign}: {}",
        failures[0]
      );
      // And the message says who DID spell it, because "nothing named this"
      // and "something else named this" send a reader to two different places.
      assert!(
        failures[0].contains("Something in that binary does spell this name"),
        "{foreign}: {}",
        failures[0]
      );
      assert!(failures[0].contains(foreign), "{foreign}: {}", failures[0]);
    }

    // The right path, under an entry that defines no function: an undefined
    // symbol names a body that is somewhere else, and a `static` names none.
    let (counts, failures, census) = linked(
      &[shim("shim_decode", &[])],
      &[
        symbol("_RNvCsg8Ts9hS57d_8no_panic11shim_decode", false),
        symbol(ANCHOR, true),
      ],
    );
    assert_eq!(
      (counts.instantiated, counts.functions),
      (0, 1),
      "{failures:?}"
    );
    assert_eq!(census, format!("some-crate 0/1 as {BOUND}"));
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
      failures[0].contains("by no symbol that DEFINES a function there"),
      "{}",
      failures[0]
    );
    assert!(
      failures[0].contains("_RNvCsg8Ts9hS57d_8no_panic11shim_decode"),
      "{}",
      failures[0]
    );

    // Both halves together, which is the shim's own symbol and nothing else.
    let (counts, failures, census) = linked(
      &[shim("shim_decode", &[])],
      &[
        symbol("_RNvCsg8Ts9hS57d_8no_panic11shim_decode", true),
        symbol(ANCHOR, true),
      ],
    );
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!((counts.instantiated, counts.functions), (1, 2));
    assert_eq!(census, format!("some-crate 1/1 as {BOUND}"));
  }

  // A crate NAME is not a crate, and the binary says which one it IS. Several
  // linked crates may be called `no_panic` — a dependency may simply be named
  // that, and this workspace's `no-panic` dependency is — so the disambiguator
  // beside the name is read out of the binary's own harness `main` and every
  // shim symbol is required to carry it. The matcher this replaced discarded
  // that field, and a dependency's root `fn` of the shim's name was credited
  // to the test crate.
  #[test]
  fn a_shim_symbol_of_another_crate_of_the_same_name_is_not_this_crates() {
    for foreign in [
      // The same crate name, another crate's disambiguator.
      "_RNvCskTPi6a8sh2G_8no_panic11shim_decode",
      // No disambiguator at all, which is zero and not "any".
      "_RNvC8no_panic11shim_decode",
      // The other mangling, which one crate is not compiled two ways under.
      "_ZN8no_panic11shim_decode17hcafe0123456789abE",
      // A valid symbol for `foo::xNvC8no_panic11shim_decode`, whose NAME
      // contains the three bytes the matcher this replaced scanned for.
      "_RNvC3foo26xNvC8no_panic11shim_decode",
    ] {
      let (counts, failures, census) = linked(
        &[shim("shim_decode", &[])],
        &[symbol(foreign, true), symbol(ANCHOR, true)],
      );
      assert_eq!(counts.instantiated, 0, "{foreign}: {failures:?}");
      assert_eq!(census, format!("some-crate 0/1 as {BOUND}"), "{foreign}");
      assert_eq!(failures.len(), 1, "{foreign}: {failures:?}");
      assert!(
        failures[0].contains("`shim_decode` is declared and is NOT INSTANTIATED"),
        "{foreign}: {}",
        failures[0]
      );
    }
  }

  // And the identity has to BE establishable. A binary with no
  // `no_panic::main` is one whose crate this cannot name, and crediting
  // `no_panic::<shim>` to whatever crate spells that name is the reading this
  // was rewritten to stop making — so it is a failure with a name, not a
  // fallback to the weaker test.
  #[test]
  fn a_binary_this_cannot_identify_is_refused_rather_than_matched_by_name() {
    let declared = [shim("shim_x", &[])];
    let (_, failures, census) = linked(
      &declared,
      &[symbol("_RNvCsg8Ts9hS57d_8no_panic6shim_x", true)],
    );
    assert_eq!(census, "some-crate UNKNOWN");
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
      failures[0].contains("could not be established"),
      "{}",
      failures[0]
    );
    assert!(failures[0].contains("no_panic::main"), "{}", failures[0]);

    // Two crates of that name each defining a root `main`: there is no saying
    // which of them this binary is, and one of them is not it.
    let (_, failures, census) = linked(
      &declared,
      &[
        symbol(ANCHOR, true),
        symbol("_RNvCskTPi6a8sh2G_8no_panic4main", true),
      ],
    );
    assert_eq!(census, "some-crate UNKNOWN");
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
      failures[0].contains("2 different crates named `no_panic`"),
      "{}",
      failures[0]
    );
  }

  // Legacy writes no crate disambiguator, so under it the binding IS the name
  // — the residual `same_crate_as` states. It is not silent: the line a run
  // prints names the scheme it bound to, so a toolchain that moved to the
  // weaker binding says so on its own line rather than in this file only.
  #[test]
  fn a_legacy_binary_binds_by_name_and_says_which() {
    let (counts, failures, census) = linked(
      &[shim("shim_decode", &[])],
      &[
        symbol("_ZN8no_panic11shim_decode17hcafe0123456789abE", true),
        symbol("_ZN8no_panic4main17hcafe0123456789abE", true),
      ],
    );
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(counts.instantiated, 1);
    assert_eq!(census, "some-crate 1/1 as no_panic (legacy, by name)");

    // And a v0 symbol in a legacy-bound binary is another crate's, since one
    // crate is compiled under one mangling.
    let (counts, _, census) = linked(
      &[shim("shim_decode", &[])],
      &[
        symbol("_RNvCsg8Ts9hS57d_8no_panic11shim_decode", true),
        symbol("_ZN8no_panic4main17hcafe0123456789abE", true),
      ],
    );
    assert_eq!(counts.instantiated, 0);
    assert_eq!(census, "some-crate 0/1 as no_panic (legacy, by name)");
  }

  // The one exemption, and both halves of what keeps it narrow: the gate is not
  // a general opt-out, and the name is the one CI's must-fail lie-check greps
  // `no-panic`'s marker for.
  #[test]
  fn the_lie_control_is_excluded_and_the_exemption_does_not_spread() {
    let (counts, failures, census) =
      linked(&[shim(LIE_SHIM, &[LIE_GATE])], &[symbol(ANCHOR, true)]);
    assert_eq!(counts.lie_shims, 1, "{failures:?}");
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(census, format!("some-crate 0/0 as {BOUND}"));

    // A real shim wearing the lie gate leaves the build this half reads, and
    // the build it IS in must fail to link — so it would be proved by nothing.
    let (_, failures, _) = linked(&[shim("shim_x", &[LIE_GATE])], &[symbol(ANCHOR, true)]);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
      failures[0].contains("is not the one lie-control shim"),
      "{}",
      failures[0]
    );

    // And a second one takes the marker with it.
    let (_, failures, _) = linked(
      &[shim(LIE_SHIM, &[LIE_GATE]), shim(LIE_SHIM, &[LIE_GATE])],
      &[symbol(ANCHOR, true)],
    );
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
      failures[0].contains("is not the one lie-control shim"),
      "{}",
      failures[0]
    );
  }

  // Any OTHER gate is a shim outside the build this reads, and this half will
  // not answer on the linker's behalf for a binary that does not contain it.
  #[test]
  fn a_shim_under_a_gate_this_build_does_not_enable_is_a_failure() {
    let (counts, failures, _) = linked(
      &[shim("shim_x", &["feature = \"other\""])],
      &[symbol(ANCHOR, true)],
    );
    assert_eq!(counts.instantiated, 0);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
      failures[0].contains("which the build this half reads does not enable"),
      "{}",
      failures[0]
    );
  }

  // The path to the binary comes from cargo rather than from a guess about a
  // target directory's layout — and exactly one, so a build this does not
  // understand is refused rather than half-read.
  #[test]
  fn the_test_binary_is_taken_from_cargos_own_report() {
    let artifact = |name: &str| {
      format!(
        r#"{{"reason":"compiler-artifact","target":{{"kind":["test"],"name":"no_panic"}},"executable":"/t/{name}"}}"#
      )
    };
    let lib = r#"{"reason":"compiler-artifact","target":{"kind":["lib"]},"executable":null}"#;

    let found = executable(&format!("{lib}\n{}\n", artifact("no_panic-abc")), "cmd")
      .expect("one test executable");
    assert_eq!(found, PathBuf::from("/t/no_panic-abc"));

    for (stdout, expected) in [
      (String::new(), "reported 0 test executable(s)"),
      (
        format!("{}\n{}", artifact("no_panic-a"), artifact("no_panic-b")),
        "reported 2 test executable(s)",
      ),
      (
        artifact("some_other-abc"),
        "is not the `no_panic` test target",
      ),
      // A longer target name that merely STARTS the same way is a different
      // target, and reading its binary would answer this check's question
      // confidently about the wrong subject.
      (
        artifact("no_panic_extra-abc"),
        "is not the `no_panic` test target",
      ),
    ] {
      let err = executable(&stdout, "cmd").expect_err("this is not one no_panic binary");
      assert!(err.contains(expected), "{expected}: {err}");
    }
  }

  // A path cargo escaped is a path this has to unescape, and a form it does not
  // know is nothing rather than a wrong path read confidently.
  #[test]
  fn a_json_string_field_is_read_with_its_escapes() {
    assert_eq!(
      json_string(r#"{"executable":"C:\\t\\no_panic.exe"}"#, "executable").as_deref(),
      Some(r"C:\t\no_panic.exe")
    );
    assert_eq!(
      json_string(r#"{"executable":"/t/caf\u00e9/no_panic"}"#, "executable").as_deref(),
      Some("/t/café/no_panic")
    );
    assert_eq!(json_string(r#"{"executable":null}"#, "executable"), None);
    assert_eq!(json_string(r#"{"executable":"\q"}"#, "executable"), None);
  }

  // ── the two lists, and the live files ─────────────────────────────────────

  // The line a green run prints is what a reader has instead of trust, so every
  // number in it is checked here against a file whose contents are known. A
  // count that stopped moving with the file would let this whole module go
  // quiet without failing.
  #[test]
  fn the_counts_a_run_prints_are_the_ones_it_checked() {
    let mut counts = Counts::default();
    let mut found = Vec::new();
    check_file(
      "f",
      &file(
        "fn shim_x(a: u8, b: u8) -> u8 { a.wrapping_add(b) }",
        "assert_eq!(shim_x(black_box(1), black_box(2)), 3);\n  \
         black_box(shim_x(black_box(3), black_box(4)));",
      ),
      &mut counts,
      &mut found,
    );
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(
      (
        counts.shims,
        counts.calls,
        counts.arguments,
        counts.unanalysable
      ),
      (1, 2, 4, 0)
    );

    let (counts, failures, _) = linked(
      &[
        shim("shim_a", &[]),
        shim("shim_b", &[]),
        shim(LIE_SHIM, &[LIE_GATE]),
      ],
      &[
        symbol("_RNvCs_8no_panic6shim_a", true),
        symbol("_RNvCs_8no_panic6shim_b", true),
        symbol("_RNvCs_8no_panic4main", true),
      ],
    );
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(
      (
        counts.instantiated,
        counts.lie_shims,
        counts.symbols,
        counts.functions
      ),
      (2, 1, 3, 3)
    );
  }

  // The walk an edit to `PROOFS` cannot shorten. Its own doc says `claimed` is
  // a parameter "so a test can hand it a list it controls", and until a review
  // asked, nothing did: the command passes the constant, so every run over the
  // real workspace only ever saw that list agreeing with itself, and the walk
  // could have stopped walking with the run still green.
  #[test]
  fn a_proof_file_no_entry_of_the_list_claims_is_a_failure() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .parent()
      .expect("the workspace root");

    // The real list with one crate dropped, its file still on disk: the edit
    // that makes every list-driven assertion in this module get shorter and
    // stay green.
    let mut report = Report::new("shim-check");
    unclaimed_files(
      root,
      &["http-semantics", "http1-proto", "http3-proto"],
      &mut report,
    )
    .expect("the workspace root is readable");
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
      report.failures[0].contains("`websocket-proto/tests/no_panic.rs` exists"),
      "{}",
      report.failures[0]
    );
    assert!(
      report.clone().finish(false).is_err(),
      "an unclaimed proof file fails without --require-all: it is a defect \
       found, not a check skipped"
    );

    // And the list as the command actually passes it claims every file the
    // walk finds — so the failure above is the dropped entry and not a fourth
    // file nobody has noticed.
    let mut report = Report::new("shim-check");
    unclaimed_files(
      root,
      &PROOFS.iter().map(|proof| proof.krate).collect::<Vec<_>>(),
      &mut report,
    )
    .expect("the workspace root is readable");
    assert!(report.failures.is_empty(), "{:?}", report.failures);
  }

  // The live files, read through the same helpers the command runs. A unit test
  // over literals cannot notice the day a real call site drops its `black_box`,
  // which is the edit this whole module was written for — so this one reads the
  // four files themselves and fails the suite, not only the binary.
  //
  // The ARTIFACT half is deliberately not here: it needs four release builds,
  // two of them fat-LTO, which belong to the command and its CI step rather
  // than to `cargo test -p xtask`.
  #[test]
  fn the_live_shim_files_pass_and_are_not_empty() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .parent()
      .expect("the workspace root");
    let mut total = 0usize;
    for proof in PROOFS {
      let name = proof.krate;
      let path = root.join(name).join(SHIM_FILE);
      let text =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
      let found = problems(&text);
      assert!(found.is_empty(), "{name}: {found:?}");
      let code = blank_noncode(&text)
        .unwrap_or_else(|err| panic!("{name}: {} at byte {}", err.what, err.at));
      let Declarations {
        shims,
        unparsed,
        qualified,
      } = shims_in(&text, &code);
      assert!(
        unparsed.is_empty(),
        "{name}: unreadable blocks {unparsed:?}"
      );
      assert!(
        qualified.is_empty(),
        "{name}: `{SHIM_MACRO}` invoked through a path at {qualified:?}"
      );
      // NOT `!shims.is_empty()`: the lie-control alone satisfies that, and a
      // file whose only shim is the lie-control has no real proof at all —
      // its `no-panic` step would link a binary that asserts nothing about
      // any leaf while its lie-check still refused, both steps behaving.
      let real = shims.iter().filter(|shim| shim.name != LIE_SHIM).count();
      assert!(
        real >= 1,
        "{name} declares {} shim(s) and none of them is a real one",
        shims.len()
      );
      // Every file's lie-control, spelled the one way the exemption admits.
      assert_eq!(
        shims
          .iter()
          .filter(|shim| shim.name == LIE_SHIM && shim.gates == [LIE_GATE])
          .count(),
        1,
        "{name} has no single `{LIE_SHIM}` gated on `{LIE_GATE}`"
      );
      total += real;
    }
    // A floor the assertions above do not already imply. Each file is
    // required to declare at least one real shim, which puts four under this;
    // the four declare 20 between them, and eight is a floor low enough not
    // to be a snapshot and high enough that a set shrunk to one real shim per
    // file — every per-file assertion above still green — fails here. The
    // assertion this replaced was `total >= PROOFS.len()`, which the per-file
    // one implied outright and which therefore could not fail at all.
    assert!(
      total >= 2 * PROOFS.len(),
      "{total} real shim(s) across {} files",
      PROOFS.len()
    );
  }
}
