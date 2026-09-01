//! The differential corpus for RFC 9110 §10.1.4's `transfer-coding` and
//! §5.6.6's `parameters`: one corpus, four readers, and an assertion that each
//! pair sharing a production answers alike.
//!
//! Four walks in this workspace parse those two closely-related productions,
//! each with its own tests, each of them written from the same reading that
//! produced the implementation beside it. A divergence between two of them is
//! invisible to every gate that exists — and one lived until an external
//! reviewer read the ABNF (issue #76, and PR #78, which closed the divergence
//! without closing the blind spot).
//!
//! # The four readers
//!
//! - `http_semantics::grammar::parameterised_list` under
//!   `ParamSyntax::TransferParameter` — RFC 9110 §10.1.4, the public API.
//! - `http1-proto`'s `Transfer-Encoding` accumulator, reached here through that
//!   crate's `differential` feature — RFC 9112 §7 over the same §10.1.4
//!   element, and the reader that actually sees the field on the wire.
//! - `http_semantics::grammar::Expectations` — RFC 9110 §10.1.1's
//!   `expectation`, which extends §5.6.6's `parameters` with a head of its own.
//! - `http_semantics::media::accept` — RFC 9110 §12.5.1's `media-range`, which
//!   concatenates that same §5.6.6 `parameters` behind a `type "/" subtype`
//!   head and behind NO bracket, so its element has the shape the walk's has
//!   and §10.1.1's does not. That is what makes the §5.6.6 comparison askable
//!   about a list of more than one element.
//!
//! `parameterised_list` under `ParamSyntax::Parameter` is the fifth answer, and
//! it is the same walk as the first — the one whose two arms PR #78 made a
//! required argument. It is read here both as a subject in its own right and as
//! the stub for `tests`'s demonstration.
//!
//! # Which pairs are held to what
//!
//! Each is labelled with its [`PairKind`], because two of the kinds below are
//! not the same kind of evidence and the next section is what that means.
//!
//! - **§10.1.4, equality. `cross-walk`.** `parameterised_list` under
//!   `ParamSyntax::TransferParameter` and the `Transfer-Encoding` accumulator
//!   read the identical production for the identical field, so nothing licenses
//!   a difference: they are held to equal well-formedness AND to the same RFC
//!   9112 §6.3 item 4 verdict, the second projected from the walk's member
//!   names so that a divergence in where a member ENDS is visible and not only
//!   one in whether the value parsed.
//! - **§5.6.6, equality on the shared payload, over THREE readers.** The walk
//!   under `ParamSyntax::Parameter`, `Expectations` and `accept` read the same
//!   `parameters` behind three different heads — §10.1.1 puts `parameters`
//!   inside `[ "=" ( token / quoted-string ) parameters ]`, §12.5.1 puts it
//!   behind `type "/" subtype` and no bracket, and §5.6.6's has no head at
//!   all — so the corpus writes each reader's own head in front of one shared
//!   payload and holds all three to equal well-formedness over it, pairwise,
//!   each pair with its own licensed exception. Three readers make three pairs,
//!   and they are NOT three of a kind: (walk, `Expectations`) and
//!   (`Expectations`, `accept`) are `cross-walk`, (walk, `accept`) is
//!   `one-walk-twice`.
//! - **§5.6.1.1, equality on bare-token lists. `cross-walk`.** The accumulator
//!   and `Expectations` both answer the sender's empty-element question over the
//!   §5.2-combined value. Their element grammars differ, so this is asked only
//!   of values whose non-empty elements both grammars derive.
//! - **§10.1.4 against §5.6.6, deliberately NOT equality.** Each arm is graded
//!   against its OWN production by `oracle`, so the differences PR #78
//!   enumerated fall out as grades rather than as special cases, and `tests`
//!   pins how many inputs reach each of them.
//!
//! # Which pairs are two walks, and which is one walk twice
//!
//! **A pair is worth what its two halves are independent about, and the five
//! pairs above are not one currency.** They are tallied apart, in
//! [`Tally::pairs`], under a key that carries the kind — so a run reports the
//! two counts separately, and a pair filed under the wrong kind reds in `tests`
//! rather than adding itself to a number it flatters.
//!
//! - **Two independent walks — [`PairKind::CrossWalk`].** Each half decides for
//!   itself where a member begins, where it ends, what a comma means, and how a
//!   value left open at a line's end resumes across RFC 9110 §5.2's join. A
//!   defect in one half is not a defect in the other, so the pair can catch it.
//!   That is what this harness is for, and it is where issue #76's divergence
//!   lived. Four of the five pairs: §10.1.4, §5.6.1.1, and two of the three
//!   §5.6.6 pairs.
//! - **One walk, twice — [`PairKind::OneWalkTwice`].** `media::accept` IS
//!   `parameterised_list_with(lines, is_media_name, …)`: the same
//!   `ParameterisedList` the §5.6.6 walk is, at a different member-name rule,
//!   with a latch and §12.4.2's weight wrapped round it. So the (walk,
//!   `accept`) pair establishes that the CONFIGURATION is wired the way each
//!   field needs — one `parameters` reading whatever grammar the field gave for
//!   the member's NAME, which is a stated invariant of the walk's design — and
//!   it establishes nothing about whether that reading of §5.6.6 is right. A
//!   defect in the walk is in both halves, and the pair stays green on it.
//!
//! **No pair here is independent all the way down, and the kind says WALK
//! rather than implementation for that reason.** All four READERS reach the
//! same `http_semantics::grammar` primitives for §5.6.2's `tchar`, §5.6.3's
//! `OWS` and §5.6.4's quoted-string scan: `http1-proto`'s accumulator imports
//! `token_end`, `skip_ows`, `scan_quoted` and `scan_quoted_after_join` from
//! there rather than spelling its own, and `Expectations` is written over those
//! same four. A wrong `tchar` table is therefore wrong in both halves of every
//! pair, and no pair would part on it. What grades THAT layer is `oracle`,
//! which derives §5.6.2 from the RFC and shares nothing with any of them; a
//! pair grades the walk above it.
//!
//! One more same-engine comparison is in the tally and is deliberately not a
//! pair: `arms-part` counts the records where `parameterised_list`'s two
//! `ParamSyntax` arms answer differently. They are one walk at two
//! configurations and are MEANT to differ, so that count is a reachability
//! guard over the differences PR #78 enumerated and never an equality.
//!
//! # What this compares, and what it does NOT
//!
//! Read a green run as this and no more.
//!
//! **It compares five pairs, and only four of them are two walks.** The fifth
//! is `parameterised_list` compared with itself at a second configuration, and
//! the section above says what that does and does not establish. The two counts
//! are separate in every place this harness reports, so a green run never has to
//! be read as more independence than it holds: 319 359 comparisons by a pair of
//! two walks, and 80 434 by one walk twice.
//!
//! **It compares whether a value parsed** — each reader against its own
//! production's oracle, and each pair sharing a production against the other
//! reader of it. **It compares where a member BEGINS**, against the offsets the
//! oracle licenses an element to start at. **It compares what a member is made
//! of all the way to where it ENDS**, against the parameter names of the one
//! derivation of that element which reaches a list boundary. **It compares the
//! RFC 9112 §6.3 item 4 verdict** of the one pair that has one. And it hashes
//! every reader's rendered answer, so an answer that moves inside its grade
//! moves the digest.
//!
//! **The `accept` half of that BEGINS comparison is weaker than the walk's, and
//! the tally says by how much.** `accept` stops at its first faulting member, so
//! on a value that faults it reports the starts before the fault and no others;
//! and RFC 9110 §12.5.1's `"*/*"` hands out no `type`, so a range of that shape
//! reports no start at all. Neither can manufacture a false positive — an
//! unreported start is a start ungraded, not a start graded wrongly — so both
//! are counted rather than repaired. Measured: the media half put 24 200 member
//! starts up for grading where the walk put 42 223, so it covers 57 % of what
//! the walk does; the 18 023 starts it did not report fall on 15 904 records
//! (`boundary-media-short`), 4 of them are §12.5.1 wildcards (`media-wildcard`),
//! and the opposite direction — a start `accept` reported and the walk did not —
//! is zero, which is what makes this half the weaker one rather than the
//! different one.
//!
//! **The extent comparison needs no accessor, and it is asked of 37 772
//! members.** Issue #79 costed a public one — a `Range<usize>` or a slice on
//! `ListMember` and `MediaRange` — and none of it is required: a parameter's
//! NAME is already a borrowed subslice of the line the member was read from,
//! which is what `ParamIter` yields, and `place` already maps any such subslice
//! to its offset in the RFC 9110 §5.2-joined value. So the offsets are had
//! through the public API as it stands, and what they are graded against is
//! `oracle`'s fourth question. The grading is EXACT — the walk's offsets are
//! the derivation's, not a subset of them — because a bound cannot tell a
//! member that ended where the list ends from one that ended a parameter early
//! and threw the rest away, and the second is the whole of issue #79's class.
//!
//! **It is asked of less than a fifth of the members it sees, and the two
//! numbers are both in `tests`.** A member's extent is answerable only where
//! the reader called the value well formed, the production derives it, the
//! member began where the grammar begins an element, and the member's own
//! parameter walk reported no fault; anywhere else the reader is recovering and
//! its members are a derivation of nothing. 37 772 graded against 225 779
//! unasked, and the second is not a licensed residue but the shape of a corpus
//! four fifths of which is deliberately malformed.
//!
//! Two smaller ones, argued in `tests`'s own module doc: a digest that moves
//! names the corpus and not the record, and only the manufactured subset of
//! `recovered-member` is a zero-target.
//!
//! # Contract
//!
//! Every record is one line of five tab-separated columns:
//!
//! ```text
//! corpus <TAB> case <TAB> spelling <TAB> grade <TAB> answer
//! ```
//!
//! - `corpus` — which generator produced the input: `A`..`E`.
//! - `case` — the field lines, escaped, `|`-separated. `(corpus, case,
//!   spelling)` is the record's key and is unique; `tests` asserts it.
//! - `spelling` — which readers answered and over what shape.
//! - `grade` — how the record grades on the axes below, `+`-joined, or `agree`.
//! - `answer` — every reader's answer for this spelling, `/`-separated. This is
//!   the column the digest is taken over.
//!
//! # What checks THIS
//!
//! `tests`, and `cargo test -p coding-corpus` in CI's `test` job. Its tallies
//! are asserted rather than narrated: every axis that should be zero IS a
//! zero-target, every interesting state carries the exact count of inputs that
//! reach it — so a generator change that makes one unreachable reds instead of
//! going quiet — and the one non-zero residue carries the argument for its
//! being non-zero and an exact characterisation of the records in it.
//!
//! Both of those rules are issue #77's findings about `auth-corpus` turned into
//! rules: its `over-yield` axis was pinned as a non-zero constant rather than
//! driven to zero, and its corpus reaches `TooManyParameters` zero times
//! because one generator always fires a different bound first. Neither failure
//! was of the code being watched.
//!
//! # Two constraints this file is written under
//!
//! **Public API only**, apart from the one `differential`-gated forwarder
//! `http1-proto` grew for it, which is a wrapper carrying no rule of its own.
//! A corpus that reached into a crate would measure a private reorganisation as
//! a behaviour change.
//!
//! **The oracle reads nothing from any of the four.** `oracle` is an
//! independent derivation from RFC 9110's grammar; if it agreed with them by
//! construction it would grade nothing.

mod oracle;
/// FIPS 180-4's SHA-256, shared with `xtask` by path rather than copied, for
/// the reason `auth-corpus` gives at its own copy of this declaration: two
/// hashes that can disagree while both stay green are worse than one.
///
/// It is `#[cfg(test)]` and has to stay so, so that a build of these sources
/// outside a checkout never has to resolve that relative path.
#[cfg(test)]
#[path = "../../xtask/src/sha256.rs"]
mod sha256;
#[cfg(test)]
mod tests;

use std::{
  collections::BTreeMap,
  env,
  fs::File,
  io::{BufWriter, Write},
  process,
};

use http_semantics::{
  grammar::{Expectations, ListError, ParamSyntax, ParamValue, parameterised_list},
  media::{MediaError, accept},
};
use http1_proto::__differential::{TransferCodings, Verdict};

use oracle::{Production, Reading};

/// The nine bytes corpora A and B draw their payloads from: the two `tchar`s a
/// name and a value need, the `=` RFC 9110 §5.6.6 and §10.1.4 both put between
/// them, the `;` their repetition is introduced by, the DQUOTE and the
/// backslash §5.6.4 gives meaning to, the comma §5.6.1 separates elements with,
/// and the two bytes §5.6.3's `OWS` and `BWS` are made of.
const ALPHABET: [u8; 9] = *b"ax=;\", \\\t";

/// The four bytes corpus C draws from: one `tchar`, the separator, and the two
/// `OWS` bytes.
///
/// Every non-empty element it can spell is a run of `a`, which is a §5.6.2
/// `token` — so it is a `transfer-coding` with no parameters and an
/// `expectation` with no argument at once, which is what lets the two readers
/// that answer RFC 9110 §5.6.1.1 be compared over it.
const EMPTY_ALPHABET: [u8; 4] = *b"a, \t";

/// The codings corpus E builds its RFC 9112 §7 `#transfer-coding` lists out of.
///
/// One decodable coding, one that is not, the two shapes RFC 9112 §6.1 makes a
/// framing question of — a `chunked` carrying a parameter and a `chunked` whose
/// `;` introduces nothing — a `chunked` in the other case (§10.1.4's `token` is
/// case-insensitive nowhere in its own grammar; RFC 9112 §7.1 is what compares
/// it), and the empty element §5.6.1.2 admits.
const CODINGS: [&[u8]; 6] = [
  b"chunked",
  b"gzip",
  b"chunked;p=1",
  b"chunked;",
  b"CHUNKED",
  b"",
];

fn main() {
  let mut args = env::args().skip(1);
  let out = args.next();
  if args.next().is_some() {
    eprintln!("coding-corpus: usage: coding-corpus [<output-path>]");
    process::exit(1);
  }
  let result = match out {
    Some(path) => match File::create(&path) {
      Ok(file) => emit(&mut BufWriter::new(file)),
      Err(err) => {
        eprintln!("coding-corpus: cannot write {path}: {err}");
        process::exit(1);
      }
    },
    None => emit(&mut BufWriter::new(std::io::stdout().lock())),
  };
  if let Err(err) = result {
    eprintln!("coding-corpus: {err}");
    process::exit(1);
  }
}

/// Writes every record, and the per-corpus counts to stderr.
fn emit(out: &mut impl Write) -> std::io::Result<()> {
  let mut sink = Sink::new(out);
  sink.run()?;
  for (name, count) in ["A", "B", "C", "D", "E"].iter().zip(sink.tally.per_corpus) {
    eprintln!("coding-corpus: {name} {count}");
  }
  eprintln!("coding-corpus: total {}", sink.tally.records);
  Ok(())
}

// ───────────────────────────────── the corpora ───────────────────────────────

/// Every RFC 9112 §7 `Transfer-Encoding` value corpus E writes: one to three
/// [`CODINGS`], joined by RFC 9110 §5.6.1.2's `OWS "," OWS`.
///
/// A free function rather than a loop inside the generator, so `tests` can
/// assert what THIS family reaches without restating how it is built — the
/// three verdicts it exists to reach would otherwise be claimed of a generator
/// the assertion never ran.
fn coding_lists() -> impl Iterator<Item = Vec<u8>> {
  (1..=3).flat_map(|len| {
    payload_indices(CODINGS.len(), len).map(|shape| {
      let mut value = Vec::new();
      for (index, coding) in shape.iter().enumerate() {
        if index > 0 {
          value.extend_from_slice(b", ");
        }
        value.extend_from_slice(CODINGS.get(*coding).copied().unwrap_or_default());
      }
      value
    })
  })
}

/// Every sequence of `len` indices below `count`, in a fixed order.
///
/// The same enumeration [`payloads`] is, over a vocabulary of whole strings
/// rather than of bytes.
fn payload_indices(count: usize, len: u32) -> impl Iterator<Item = Vec<usize>> {
  let total = count.pow(len);
  (0..total).map(move |mut index| {
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
      out.push(index % count.max(1));
      index /= count.max(1);
    }
    out
  })
}

/// Every payload of length `len` over `alphabet`, in a fixed order.
fn payloads(alphabet: &'static [u8], len: u32) -> impl Iterator<Item = Vec<u8>> {
  let count = alphabet.len().pow(len);
  (0..count).map(move |mut index| {
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
      out.push(*alphabet.get(index % alphabet.len()).unwrap_or(&b'a'));
      index /= alphabet.len();
    }
    out
  })
}

/// `Transfer-Encoding` values worth naming, each as the field lines RFC 9110
/// §5.2 joins into one.
///
/// The first four are the empty slot §10.1.4 brackets nowhere and §5.6.6 does,
/// which is the difference `gzip;` turns on. Then the `BWS` around the `=`,
/// which is the difference in the other direction. Then the bare parameter name
/// neither production derives and the two fields answer differently. Then the
/// boundary cases: a value carrying a comma, the same across the join, a string
/// that never closes, and the shape that manufactures a coding out of a
/// parameter's data.
const NAMED: &[&[&[u8]]] = &[
  &[b"gzip;"],
  &[b"gzip;;p=x"],
  &[b"gzip;p=x;"],
  &[b"chunked;"],
  &[b"gzip;p = x"],
  &[b"gzip;p\t=\tx"],
  &[b"gzip;p =\"a,b\", chunked"],
  &[b"gzip;q"],
  &[b"gzip;q, chunked"],
  &[b"gzip;p=\"a,b\""],
  &[b"gzip;p=\"a,b\", chunked"],
  &[b"gzip;p=\"a", b"b\", chunked"],
  &[b"gzip;p=\"a"],
  &[b"gzip;p=\"a\x00b\""],
  &[b"gzip;p=\"a\x7fb\""],
  &[b"gzip;p=\"a\x80b\""],
  &[b"gzip;p=\"a\\\"b\""],
  &[b"gzip;p=\"a\\\x80b\""],
  &[b"gzip;;p=\"a, chunked, b\", br"],
  &[b"gzip;;p=\"a\", chunked"],
  &[b"gzip;p=x;;q=y, chunked"],
  &[b"chunked"],
  &[b"chunked, chunked"],
  &[b"chunked, gzip"],
  &[b"gzip, chunked"],
  &[b"chunked;p=1"],
  &[b"chunked ;p=1"],
  &[b"gzip"],
  &[b""],
  &[b","],
  &[b" "],
  &[b"gzip,,chunked"],
  &[b"gzip,"],
  &[b",gzip"],
  &[b"\"abc\""],
  &[b"gzip", b"chunked"],
  &[b"gzip", b""],
  &[b"", b"chunked"],
  &[b"gzip;p=\"a", b"b", b"c\", chunked"],
  &[b"CHUNKED"],
  &[b"gzip, CHUNKED"],
  &[b"chunked, chunked, chunked"],
  &[b"a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, chunked"],
  &[b"gzip;p=x;q=y;r=z, chunked"],
  &[b"gzip ; p = x , chunked"],
];

/// The head each RFC 9110 §5.6.6 reader gets written in front of the shared
/// payload, in the order [`Sink::params_pair`] reads them.
///
/// - `x` for `parameterised_list` under `ParamSyntax::Parameter`: §5.6.6's
///   `parameters` has no head of its own and takes §5.6.2's `token` from
///   whatever rule concatenates it.
/// - `x=1` for `Expectations`, because §10.1.1 writes
///   `expectation = token [ "=" ( token / quoted-string ) parameters ]` and the
///   bracket closes AFTER `parameters` — a member carrying parameters and no
///   argument is not an `expectation` at all.
/// - `x/y` for `accept`, because §12.5.1's `media-range` heads the identical
///   `parameters` with `type "/" subtype`.
///
/// None of the three holds a comma or a DQUOTE, so a head opens exactly one
/// element and settles no question the payload behind it asks.
const HEADS: [&[u8]; 3] = [b"x", b"x=1", b"x/y"];

/// The flanking §5.6.6 payloads the two-element spelling writes on the other
/// side of the comma from the payload under test.
///
/// Each is a whole `parameters` string behind a head of its own, so the element
/// it makes is one all three readers derive, and what is being asked is where
/// the boundary between it and the payload under test lies. `open` is the one
/// that matters most: it leaves a §5.6.4 quoted-string unclosed, so the comma
/// behind it — and the next element's head — are that parameter's data under
/// every reading, which is the shape a reader that scans for a raw comma gets
/// wrong.
const FLANKS: [(&str, &[u8]); 3] = [("param", b";p=1"), ("open", b";p=\"a"), ("slot", b";")];

/// §5.6.6 `parameters` payloads worth naming, written behind each reader's own
/// head by [`Sink::params_one`].
///
/// They are payloads and not whole values: what goes in front of them is the
/// head §10.1.1 requires and the head §5.6.6 does not have, and writing that
/// here would put the difference inside the case instead of beside it.
const NAMED_PARAMS: &[&[u8]] = &[
  b"",
  b";",
  b";;",
  b";p=1",
  b";p=1;",
  b";;p=1",
  b";p=1;;q=2",
  b";p = 1",
  b";p\t=\t1",
  b";p",
  b";p;q=1",
  b";p=\"a,b\"",
  b";p=\"a",
  b";p=\"a\x00b\"",
  b";p=\"a\x80b\"",
  b";p=\"a\\\"b\"",
  b";p=\"\"",
  b" ; p = 1",
  b" ;p=1",
  b";p=1 ",
  b";p=,",
  b";=1",
  b";=1;p=\"a, b\", c",
  b";p = \"a, b\", c",
  // The parameter name RFC 9110 §12.5.1 gives a meaning the other two readers
  // do not: `Accept = #( media-range [ weight ] )` with
  // `weight = OWS ";" OWS "q=" qvalue`. The first two spell a `qvalue` and the
  // last three do not, so `accept` refuses three values §5.6.6 and §10.1.1
  // both derive — the one licensed difference the third reader brings, and the
  // reason it is a counted axis here rather than an unreached row.
  b";q=1",
  b";q=0.5",
  b";q=a",
  b";q=1.5",
  b";Q=2",
];

/// §5.6.6 `parameters` payloads written over the field lines RFC 9110 §5.2
/// joins, cut where the case says rather than at a midpoint.
///
/// The two faults a walk can only reach across the join —
/// `ListError::ValueSpansFieldLines`, which is a value that is well formed and
/// not one slice, and the shapes behind it — have to be spelled deliberately: a
/// brute force that cuts every payload in half reaches them only by accident,
/// and `tests` asserts the count of each fault, so an accident is not something
/// to build a count on.
const NAMED_PARAM_LINES: &[&[&[u8]]] = &[
  &[b";p=\"a", b"b\""],
  &[b";p=\"a", b"b\";q=2"],
  &[b";p=\"a", b"b"],
  &[b";p=\"a,b", b"c\""],
  &[b";p=1", b";q=2"],
  &[b";", b";"],
  &[b";p=\"a", b"b\", zzz"],
];

/// The three ways an asterisk reaches a RFC 9110 §12.5.1 `media-range` name,
/// written as the media reader's head so that the one the harness has to
/// survive is a case the corpus runs rather than one waiting in it.
///
/// ```text
/// media-range    = ( "*/*"
///                    / ( type "/" "*" )
///                    / ( type "/" subtype )
///                  ) parameters
/// ```
///
/// One per alternative, and they are three different answers to the question
/// the harness asks of every member — where does it begin?
///
/// - `*/*` is the first alternative, and it reports no `type` at all, so no
///   start can be placed for it. That is
///   [`Ranges::wildcard`], and it is the one shape whose boundary the media
///   half of the pair cannot answer for.
/// - `x/*` is the second, and reports `x`. The absent SUBTYPE costs nothing:
///   the start is the type's.
/// - `*/y` is the THIRD — `type "/" subtype` with a `type` that happens to be
///   the token `*`, since §5.6.2's `tchar` admits the asterisk — and it reports
///   that `*` as its type. It is here to hold the distinction: a harness that
///   keyed on the asterisk rather than on the alternative would place no start
///   for this one either, and nothing else would notice.
const MEDIA_NAMES: [(&str, &[u8]); 3] = [("both", b"*/*"), ("subtype", b"x/*"), ("type", b"*/y")];

/// The RFC 9110 §5.6.6 payloads written behind each of [`MEDIA_NAMES`].
///
/// Small on purpose: the question these ask is about the NAME in front of the
/// payload, and the payloads themselves are already brute-forced behind `x/y`.
/// One of each shape the media reader answers differently about — nothing, a
/// parameter, a parameter whose value swallows a comma, §12.4.2's weight, and
/// the bare name `accept` refuses.
const WILDCARD_PARAMS: &[&[u8]] = &[b"", b";p=1", b";p=\"a,b\"", b";q=0.5", b";p"];

// ──────────────────────────── the readers, rendered ──────────────────────────

/// One reader's own spelling of a shared RFC 9110 §5.6.6 payload.
struct Spelt {
  /// The field lines handed to that reader.
  lines: Vec<Vec<u8>>,
  /// The offsets in the RFC 9110 §5.2-joined value at which this generator
  /// wrote one of that reader's heads — that is, every element start the
  /// generator INTENDED.
  ///
  /// Decided by construction rather than by any reader or by the oracle's
  /// answer about the whole value: a filter that asked a reader which elements
  /// there are would exclude exactly the disagreements it exists to find, and
  /// one that asked the oracle whether the value derives would be the same
  /// question the comparison asks.
  heads: Vec<usize>,
}

impl Spelt {
  /// The lines as the readers take them.
  fn borrowed(&self) -> Vec<&[u8]> {
    self.lines.iter().map(Vec::as_slice).collect()
  }
}

/// Writes `head` in front of each of `elements` and joins them with RFC 9110
/// §5.6.1.2's `OWS "," OWS`, recording where each head went.
fn spell_elements(head: &[u8], elements: &[&[u8]]) -> Spelt {
  let mut value = Vec::new();
  let mut heads = Vec::with_capacity(elements.len());
  for (index, element) in elements.iter().enumerate() {
    if index > 0 {
      value.extend_from_slice(b", ");
    }
    heads.push(value.len());
    value.extend_from_slice(head);
    value.extend_from_slice(element);
  }
  Spelt {
    lines: vec![value],
    heads,
  }
}

/// Where one yielded member began, and where the parameter names inside it did.
///
/// The unit the extent grading consumes. A member start alone says where a
/// member BEGINS, which is what the licensing check has always asked; the
/// parameter offsets say what the member was made of all the way to its end,
/// which is the question issue #79 records that nothing here could ask.
struct Extent {
  /// Where the member's name begins in the value RFC 9110 §5.2 joins.
  at: usize,
  /// Where each parameter name the member yielded begins, in order.
  params: Vec<usize>,
  /// The member's parameter walk reported a fault, so the parameters it yielded
  /// are not all of the parameters it read.
  ///
  /// Where the reader also called the value well formed, this is
  /// `ListError::ValueSpansFieldLines` and nothing else — every other fault
  /// clears `well_formed` — so it names a parameter that is well formed and is
  /// not one contiguous slice. The reader is right to report it and right to
  /// stop, and the extent question about that member has no answer either way,
  /// so it is counted as unasked rather than graded.
  faulted: bool,
}

/// Everything one `parameterised_list` walk said about one value.
struct Walk {
  /// Every read it yielded, rendered.
  rendered: String,
  /// Nothing was refused. `ListError::ValueSpansFieldLines` is not a refusal —
  /// its own documentation says the value "is perfectly well formed and that a
  /// walker borrowing its input cannot hand over", and the member's boundaries
  /// are still correct — so it is the one fault that leaves this true.
  well_formed: bool,
  /// Where each yielded member's name begins in the value RFC 9110 §5.2 joins.
  starts: Vec<usize>,
  /// A yielded member's name — or one of its parameters' names — was a slice of
  /// none of the lines handed in, so its offset could not be placed. `tests`
  /// holds this at zero; a non-zero count would mean the licensing check graded
  /// fewer members, or fewer parameters, than the walk yielded and said nothing
  /// about the difference.
  ///
  /// A parameter name cannot span RFC 9110 §5.2's join — the join writes a
  /// comma, and §5.6.2's `tchar` excludes it, so a `token` never crosses one —
  /// which is why the extent grading can place every name it is handed and this
  /// stays a zero-target rather than gaining a licensed residue.
  unplaced: usize,
  /// Where each yielded member began and where its parameters' names began,
  /// one row per member whose own name was placed.
  extents: Vec<Extent>,
  /// The member names, in order.
  names: Vec<Vec<u8>>,
  /// Whether each member carried a `;` that introduced something.
  parameterised: Vec<bool>,
  /// Some parameter was handed over as `ParamValue::None` — the bare name
  /// §5.6.6's `parameter` does not derive and which a field whose own grammar
  /// brackets the value reads rather than refuses.
  valueless: bool,
  /// Every fault it reported, member-level and parameter-level.
  faults: Vec<ListError>,
}

/// Runs `parameterised_list` over `lines` and records everything it said.
fn walk(lines: &[&[u8]], syntax: ParamSyntax) -> Walk {
  let bases = line_bases(lines);
  let mut out = Walk {
    rendered: String::new(),
    well_formed: true,
    starts: Vec::new(),
    unplaced: 0,
    extents: Vec::new(),
    names: Vec::new(),
    parameterised: Vec::new(),
    valueless: false,
    faults: Vec::new(),
  };
  for read in parameterised_list(lines.iter().copied(), syntax) {
    if !out.rendered.is_empty() {
      out.rendered.push(' ');
    }
    let member = match read {
      Ok(member) => member,
      Err(fault) => {
        out.well_formed = false;
        out.faults.push(fault);
        out.rendered.push_str(&format!("Err({fault:?})"));
        continue;
      }
    };
    let member_at = place(lines, &bases, member.name());
    match member_at {
      Some(at) => out.starts.push(at),
      None => out.unplaced = out.unplaced.saturating_add(1),
    }
    out.names.push(member.name().to_vec());
    out.rendered.push_str("Ok[");
    out.rendered.push_str(&escape(member.name()));
    let mut any_param = false;
    let mut extent = Extent {
      at: member_at.unwrap_or_default(),
      params: Vec::new(),
      faulted: false,
    };
    for read in member.params() {
      any_param = true;
      out.rendered.push(';');
      match read {
        Ok((name, value)) => {
          // The same `place` a member's name goes through, over the same
          // pointer arithmetic: a parameter's name is a borrowed subslice of
          // the line the member was read from, exactly as the member's own name
          // is, and nothing new is needed to put it in the §5.2-joined value.
          match place(lines, &bases, name) {
            Some(at) => extent.params.push(at),
            None => out.unplaced = out.unplaced.saturating_add(1),
          }
          out.rendered.push_str(&escape(name));
          out.rendered.push('=');
          match value {
            ParamValue::Token(token) => {
              out.rendered.push_str("t:");
              out.rendered.push_str(&escape(token));
            }
            ParamValue::Quoted(quoted) => {
              out.rendered.push_str("q:");
              out.rendered.push_str(&escape(quoted));
            }
            ParamValue::None => {
              out.valueless = true;
              out.rendered.push_str("none");
            }
            _ => out.rendered.push('?'),
          }
        }
        Err(fault) => {
          // The one fault that leaves the value well formed: the member's
          // boundaries are settled and only this value is not one slice.
          if fault != ListError::ValueSpansFieldLines {
            out.well_formed = false;
          }
          extent.faulted = true;
          out.faults.push(fault);
          out.rendered.push_str(&format!("Err({fault:?})"));
        }
      }
    }
    if member_at.is_some() {
      out.extents.push(extent);
    }
    out.parameterised.push(any_param);
    out.rendered.push(']');
  }
  out
}

/// Everything `http1-proto`'s `Transfer-Encoding` accumulator said.
struct Listed {
  /// Its answers, rendered.
  rendered: String,
  /// Whether the whole combined value parsed as RFC 9112 §7's
  /// `#transfer-coding`.
  parsed: bool,
  /// Its answer to RFC 9110 §5.6.1.1, over the combined value.
  empty_element: bool,
  /// Its RFC 9112 §6.3 item 4 classification.
  verdict: Verdict,
}

/// Pushes `lines` into that accumulator and records everything it said.
fn codings(lines: &[&[u8]]) -> Listed {
  let mut list = TransferCodings::new();
  for line in lines {
    list.push(line);
  }
  let (parsed, empty_element, verdict) = (list.parsed(), list.empty_element(), list.verdict());
  Listed {
    rendered: format!("parsed={parsed} empty={empty_element} verdict={verdict:?}"),
    parsed,
    empty_element,
    verdict,
  }
}

/// Everything `Expectations` said.
struct Expect {
  /// Its answers, rendered.
  rendered: String,
  /// Whether the whole combined value parsed as RFC 9110 §10.1.1's
  /// `#expectation`.
  parsed: bool,
  /// Its answer to RFC 9110 §5.6.1.1, over the combined value.
  empty_element: bool,
}

/// Pushes `lines` into `Expectations` and records everything it said.
fn expectations(lines: &[&[u8]]) -> Expect {
  let mut read = Expectations::new();
  for line in lines {
    read.push(line);
  }
  let (parsed, empty_element) = (read.parsed(), read.empty_element());
  Expect {
    rendered: format!(
      "parsed={parsed} empty={empty_element} cont={} other={} fault={}",
      read.expects_continue(),
      read.has_other(),
      read.grammar_fault()
    ),
    parsed,
    empty_element,
  }
}

/// Everything one `media::accept` walk said about one `Accept` value.
struct Ranges {
  /// Its answers, rendered.
  rendered: String,
  /// Every member of the whole combined value read as RFC 9110 §12.5.1's
  /// `media-range` without a fault.
  ///
  /// Unlike the walk's `well_formed`, `ValueSpansFieldLines` is a refusal here,
  /// because for THIS reader it is one: `accept` documents that it stops at the
  /// first faulting member and hands over no range at all, where the walk
  /// yields the member with its boundaries settled and a parameter-level fault
  /// beside it. The
  /// harness licenses the difference rather than defining it away — see
  /// [`Sink::params_pair`] — since a `parsed` that ignored a fault the reader
  /// latched on would say the reader accepted a value it never finished
  /// reading.
  parsed: bool,
  /// Where each yielded range's `type` begins in the value RFC 9110 §5.2 joins.
  starts: Vec<usize>,
  /// A yielded range's `type`, or one of its parameters' names, was a slice of
  /// none of the lines handed in.
  ///
  /// Held at zero by `tests`, exactly as the walk's own count is. The one shape
  /// that would otherwise land here without being a defect is
  /// [`Self::wildcard`], which is counted apart for that reason.
  unplaced: usize,
  /// Where each yielded range began and where its parameters' names began, one
  /// row per range whose `type` was placed.
  ///
  /// A `"*/*"` range contributes none: it names no `type`, so there is no
  /// offset to key its extent on either. That is the same cost
  /// [`Self::wildcard`] already carries, one question further along.
  extents: Vec<Extent>,
  /// Ranges whose `type` is RFC 9110 §12.5.1's `"*/*"` alternative, for which
  /// `MediaRange::ty` reports `None` and there is no slice to place.
  ///
  /// It is not a defect and it is not an unplaced member: the reader yielded a
  /// range and reported, correctly, that the range names no type. What it costs
  /// is a boundary observation — that member's start is graded by nothing — so
  /// it is counted here, summed into `Tally::media_wildcard`, and asserted, in
  /// preference to being folded into `unplaced`, which is a zero-target for a
  /// different fact and would have turned the first wildcard case anyone wrote
  /// into a red with no name on it.
  ///
  /// `type/*` and `*/subtype` are NOT this: the first reports its `type` and
  /// the second reports the literal `*` as one, since §5.6.2's `tchar` admits
  /// the asterisk. Only the `"*/*"` alternative has no type at all.
  wildcard: usize,
  /// The one fault it stopped on, if it stopped on one.
  fault: Option<MediaError>,
}

/// Runs `media::accept` over `lines` and records everything it said.
fn ranges(lines: &[&[u8]]) -> Ranges {
  let bases = line_bases(lines);
  let mut out = Ranges {
    rendered: String::new(),
    parsed: true,
    starts: Vec::new(),
    unplaced: 0,
    extents: Vec::new(),
    wildcard: 0,
    fault: None,
  };
  for read in accept(lines.iter().copied()) {
    if !out.rendered.is_empty() {
      out.rendered.push(' ');
    }
    let range = match read {
      Ok(range) => range,
      Err(fault) => {
        out.parsed = false;
        out.fault = Some(fault);
        out.rendered.push_str(&format!("Err({fault:?})"));
        continue;
      }
    };
    let mut range_at = None;
    match range.ty() {
      // RFC 9110 §12.5.1's `"*/*"`: a range that names no type, so there is no
      // slice to place and this member's start is graded by nothing.
      None => out.wildcard = out.wildcard.saturating_add(1),
      Some(ty) => match place(lines, &bases, ty.as_bytes()) {
        Some(at) => {
          out.starts.push(at);
          range_at = Some(at);
        }
        None => out.unplaced = out.unplaced.saturating_add(1),
      },
    }
    let mut extent = Extent {
      at: range_at.unwrap_or_default(),
      params: Vec::new(),
      faulted: false,
    };
    out.rendered.push_str("Ok[");
    out.rendered.push_str(range.ty().unwrap_or("*"));
    out.rendered.push('/');
    out.rendered.push_str(range.subtype().unwrap_or("*"));
    out
      .rendered
      .push_str(&format!(":w{}", range.weight().thousandths()));
    for read in range.params() {
      out.rendered.push(';');
      match read {
        Ok((name, value)) => {
          match place(lines, &bases, name) {
            Some(at) => extent.params.push(at),
            None => out.unplaced = out.unplaced.saturating_add(1),
          }
          out.rendered.push_str(&escape(name));
          out.rendered.push('=');
          match value {
            ParamValue::Token(token) => {
              out.rendered.push_str("t:");
              out.rendered.push_str(&escape(token));
            }
            ParamValue::Quoted(quoted) => {
              out.rendered.push_str("q:");
              out.rendered.push_str(&escape(quoted));
            }
            // `MEDIA_VALUELESS` is `Refused`, so the bare name arrives as an
            // `Err` from `accept` and never as a value here.
            _ => out.rendered.push('?'),
          }
        }
        // Unreachable through `accept`, which reads every parameter itself
        // before it hands a range over; rendered rather than dropped, so a
        // change that made it reachable moves the digest instead of nothing.
        Err(fault) => {
          extent.faulted = true;
          out.rendered.push_str(&format!("Err({fault:?})"));
        }
      }
    }
    if range_at.is_some() {
      out.extents.push(extent);
    }
    out.rendered.push(']');
  }
  out
}

/// `http1-proto`'s own words for a list it could not parse, transcribed so the
/// projection below can spell the same verdict.
const MALFORMED_CODING_LIST: &str = "Transfer-Encoding is not a transfer-coding list";
/// Its own words for a coding it does not implement.
const ONLY_CHUNKED: &str = "this core decodes only chunked";

/// The RFC 9112 §6.3 item 4 and §6.1 classification, derived from the member
/// names one `parameterised_list` walk yielded.
///
/// This is the differential's SHARED OBSERVABLE and not a second implementation
/// of anybody's rule: the accumulator hands out a verdict and no member list,
/// the walk hands out members and no verdict, and without a projection between
/// them the pair could only be compared on whether the value parsed — which is
/// blind to the two readers putting a member boundary in different places, the
/// defect the pair exists to catch. The ordering is §6.3 item 4's framing MUST
/// ahead of §6.1's SHOULD-501, transcribed for that reason; a divergence in the
/// ordering alone shows up as a pair disagreement, which is a finding to
/// investigate and not a false one.
fn projected_verdict(walked: &Walk) -> Verdict {
  if !walked.well_formed {
    return Verdict::NotFramed(MALFORMED_CODING_LIST);
  }
  let mut chunked = 0usize;
  let mut final_is_chunked = false;
  let mut undecodable = false;
  let mut parameterised_chunked = false;
  for (index, name) in walked.names.iter().enumerate() {
    let is_chunked = name.eq_ignore_ascii_case(b"chunked");
    final_is_chunked = is_chunked;
    if is_chunked {
      chunked = chunked.saturating_add(1);
      parameterised_chunked |= walked.parameterised.get(index).copied().unwrap_or_default();
    } else {
      undecodable = true;
    }
  }
  if parameterised_chunked {
    return Verdict::NotFramed("chunked transfer coding carries parameters");
  }
  if walked.names.is_empty() {
    return Verdict::NotFramed("Transfer-Encoding lists no transfer coding");
  }
  if chunked > 0 && !final_is_chunked {
    return Verdict::NotFramed("chunked is not the final transfer coding");
  }
  if chunked > 1 {
    return Verdict::NotFramed("chunked transfer coding applied more than once");
  }
  if undecodable {
    return if final_is_chunked {
      Verdict::ChunkedUndecodable(ONLY_CHUNKED)
    } else {
      Verdict::Undecodable(ONLY_CHUNKED)
    };
  }
  Verdict::Chunked
}

// ────────────────────────────────── the axes ─────────────────────────────────

/// How one record grades.
///
/// The first three and [`manufactured_member`](Self::manufactured_member) are
/// zero-targets. [`recovered_member`](Self::recovered_member) and
/// [`residue_valueless`](Self::residue_valueless) are not, and each carries the
/// argument for that on its own doc — one is the walk refusing to let a
/// malformed member hide the members behind it, the other is RFC 9110 §5.6.6
/// being the production other fields extend. `tests` holds both to an exact
/// count anyway, so neither can move without saying so.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Grade {
  /// Two readers of one production gave different answers. The defect this
  /// whole crate exists to make visible.
  pair_disagree: bool,
  /// A reader said a value is well formed that its own production does not
  /// derive, and the bare-name residue below does not explain it.
  over_accept: bool,
  /// A reader refused a value its own production derives. None of the three has
  /// a bound of its own over these productions, so nothing could license one.
  over_refuse: bool,
  /// A walk yielded a member beginning at an offset no derivation of any prefix
  /// of the value begins an element at, and which no prefix derivation reads as
  /// a quoted-string's data either.
  ///
  /// **Not a defect, and not a zero-target.** This is RECOVERY, and it is the
  /// walk working as designed: a member that did not derive must not hide the
  /// members written behind it, so the walk reports the fault and goes on
  /// showing what is there. `gzip;p=,a` derives nothing from the `,` onward
  /// under either production, and showing the `a` anyway is the whole point.
  /// `tests` holds it to an exact count, so a walk that stopped recovering —
  /// or started recovering somewhere new — reds rather than goes quiet.
  recovered_member: bool,
  /// A walk yielded a member beginning at an offset some prefix derivation
  /// reads as a quoted-string's data, so the member was built out of bytes the
  /// sender wrote as a parameter's value.
  ///
  /// The strongest witness there is, and the defect issues #71 and #77 are both
  /// about: on a `Transfer-Encoding` it is a transfer coding manufactured out
  /// of somebody's data, which is a framing decision. A zero-target, and
  /// `tests`'s negative control is what says the metric bites rather than never
  /// being asked.
  manufactured_member: bool,
  /// A reader stated a member whose parameters are the parameters of no
  /// derivation of the element it began — one at an offset no derivation reads
  /// a parameter name at, one missing where every derivation reads one, or a
  /// member that stopped at an offset the list admits no end at.
  ///
  /// **The extent axis, and a zero-target.** It is what issue #79 records the
  /// absence of: every other axis here is a question about where a member
  /// BEGINS, so a walk that ended its LAST member one well-formed parameter
  /// early — and yielded nothing behind it — satisfied all of them. It is
  /// graded EXACTLY, against the one derivation of the element that reaches a
  /// list boundary, because a bound cannot tell that walk from a correct one:
  /// a truncated member reads a strict prefix of the parameters the grammar
  /// admits, and "no parameter the grammar does not admit" is a rule a strict
  /// prefix passes.
  member_extent: bool,
  /// The walk under `ParamSyntax::Parameter` accepted a value RFC 9110 §5.6.6
  /// does not derive, and the only thing it accepted past that production is a
  /// parameter with no value, handed over as `ParamValue::None`.
  ///
  /// Not a defect and not a zero-target, and the argument is the entry point's
  /// own: §5.6.6's `parameters` is the production other fields EXTEND, one of
  /// which may bracket the value — RFC 6455 §9.1's
  /// `extension-param = token [ "=" (token | quoted-string) ]` is such a
  /// grammar — so the walk hands the shape over for the field to answer.
  /// `tests` holds this to an exact characterisation rather than to a constant:
  /// every record graded here has a `ParamValue::None` in it, and every record
  /// whose walk reports one and whose value §5.6.6 does not derive is graded
  /// here.
  residue_valueless: bool,
}

impl Grade {
  /// The record's `grade` column.
  fn render(self) -> String {
    let mut out = Vec::new();
    if self.pair_disagree {
      out.push("pair-disagree");
    }
    if self.over_accept {
      out.push("over-accept");
    }
    if self.over_refuse {
      out.push("over-refuse");
    }
    if self.recovered_member {
      out.push("recovered-member");
    }
    if self.manufactured_member {
      out.push("manufactured-member");
    }
    if self.member_extent {
      out.push("member-extent");
    }
    if self.residue_valueless {
      out.push("residue-valueless");
    }
    if out.is_empty() {
      return String::from("agree");
    }
    out.join("+")
  }
}

/// Grades one walk against the production it declared, and against the offsets
/// that production licenses a member to begin at.
///
/// `valueless_ok` is whether a parameter with no value is this entry point's to
/// hand over rather than to refuse — true under `ParamSyntax::Parameter`, where
/// the walk reports `ParamValue::None`, and false under
/// `ParamSyntax::TransferParameter`, where RFC 9110 §10.1.4 is the whole of
/// what a `TE` or `Transfer-Encoding` parameter may be.
fn grade_walk(walked: &Walk, reading: &Reading, valueless_ok: bool) -> Grade {
  let mut grade = Grade::default();
  if walked.well_formed && !reading.derives {
    if valueless_ok && walked.valueless {
      grade.residue_valueless = true;
    } else {
      grade.over_accept = true;
    }
  }
  if !walked.well_formed && reading.derives {
    grade.over_refuse = true;
  }
  for &at in &walked.starts {
    if reading.licenses_member_at(at) {
      continue;
    }
    if reading.is_string_data(at) {
      grade.manufactured_member = true;
    } else {
      grade.recovered_member = true;
    }
  }
  grade
}

/// What grading one reader's member extents found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Extents {
  /// Some member's parameters are no derivation's — [`Grade::member_extent`].
  wrong: bool,
  /// Members whose extent was compared against a derivation.
  graded: usize,
  /// Members whose extent nothing could be asked about: the reader refused the
  /// value, the value derives under no reading, the member began where no
  /// derivation begins an element, or its own parameter walk faulted.
  unasked: usize,
  /// Graded members where a `q` the grammar derives as a parameter was dropped
  /// from what the reader handed over, because `weight_is_a_parameter_name` is
  /// how that reader answers RFC 9110 §12.5.1.
  q_dropped: usize,
}

/// Grades one reader's member extents against the derivations `reading` admits,
/// EXACTLY.
///
/// For each member the reader began at an offset the oracle licenses: the
/// offsets of the parameter names it handed over must be the offsets of the
/// parameter names of some derivation of an element there that reaches a list
/// boundary. Not a prefix of them — the whole of them, which is the difference
/// between catching a member that ended one parameter early and not.
///
/// # What it does NOT ask, and why each is unaskable rather than excused
///
/// - **A value the reader refused, or that its production does not derive.**
///   The reader is then recovering, and a recovering reader's members are not a
///   derivation of anything: `oracle`'s own doc says an element start is
///   licensed by the bytes in FRONT of it, and behind a fault there is no
///   derivation of the whole list for a member's END to be settled by. The
///   `recovered-member` axis is what watches those, and it is a counted state
///   rather than a zero-target for the same reason.
/// - **A member whose own parameter walk faulted.** See [`Extent::faulted`].
/// - **A member the oracle licenses no element start at.** It is already graded
///   `manufactured-member` or `recovered-member`, and asking a second question
///   about an element the grammar does not begin there would report the same
///   defect twice under a name that is a zero-target for something else.
///
/// `weight_is_a_parameter_name` is `false` for a reader that hands over every
/// parameter the grammar derives, and `true` for one that reads a parameter
/// named `q` as RFC 9110 §12.4.2's weight and so hands over the rest. Only
/// `media::accept` is the second, and §12.5.1 is why: "Recipients SHOULD
/// process any parameter named "q" as weight, regardless of parameter
/// ordering." That is a rule about a parameter's NAME and not about where the
/// parameter section stops, so the filter is applied at every position and not
/// only the last — which is what that reader does.
fn grade_extents(
  value: &[u8],
  extents: &[Extent],
  reading: &Reading,
  well_formed: bool,
  weight_is_a_parameter_name: bool,
) -> Extents {
  let mut out = Extents::default();
  for extent in extents {
    if !well_formed || !reading.derives || extent.faulted || !reading.licenses_member_at(extent.at)
    {
      out.unasked = out.unasked.saturating_add(1);
      continue;
    }
    out.graded = out.graded.saturating_add(1);
    let readings = reading.member_params(extent.at);
    let mut matched = None;
    for admitted in readings {
      let dropped =
        weight_is_a_parameter_name && admitted.iter().any(|name| is_weight_name(value, name));
      let wanted: Vec<usize> = admitted
        .iter()
        .filter(|name| !(weight_is_a_parameter_name && is_weight_name(value, name)))
        .map(|name| name.at)
        .collect();
      if wanted == extent.params {
        matched = Some(dropped);
        break;
      }
    }
    let Some(dropped) = matched else {
      out.wrong = true;
      continue;
    };
    if dropped {
      out.q_dropped = out.q_dropped.saturating_add(1);
    }
  }
  out
}

/// Whether a parameter name the oracle read is RFC 9110 §12.4.2's, which names
/// it "q" (case-insensitive).
fn is_weight_name(value: &[u8], name: &oracle::ParamName) -> bool {
  value
    .get(name.at..name.end)
    .is_some_and(|spelt| spelt.eq_ignore_ascii_case(b"q"))
}

// ──────────────────────── the pairs, and what each proves ────────────────────

/// What a pair's agreement establishes, which is settled by whether its two
/// halves WALK the value independently.
///
/// The crate doc's section of the same name is the argument; this is the label
/// the tally is keyed by, so the two counts are never one number.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PairKind {
  /// Two walks written independently of one another. Each decides for itself
  /// where a member begins and ends, what a comma means, and how a value
  /// resumes across RFC 9110 §5.2's join, so a defect in one half is not a
  /// defect in the other and the pair can catch it.
  ///
  /// Not `CrossImplementation`: every reader here reaches the same
  /// `http_semantics::grammar` primitives for §5.6.2's `tchar`, §5.6.3's `OWS`
  /// and §5.6.4's quoted-string scan, so no pair would part on a wrong `tchar`
  /// table. `oracle` is what grades that layer.
  CrossWalk,
  /// One walk, run at two configurations — `media::accept` is
  /// `parameterised_list_with` at a second member-name rule. Agreement
  /// establishes that the configuration is wired the way the field needs, and
  /// nothing about whether the walk's reading of the grammar is right: a defect
  /// in it is in both halves.
  OneWalkTwice,
}

impl PairKind {
  /// The tag every pair of this kind is counted behind.
  const fn tag(self) -> &'static str {
    match self {
      Self::CrossWalk => "cross-walk",
      Self::OneWalkTwice => "one-walk-twice",
    }
  }
}

/// One pair of readers this corpus holds to equality.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Pair {
  /// What the two halves read, and which two they are.
  name: &'static str,
  /// What their agreement proves.
  kind: PairKind,
}

impl Pair {
  /// RFC 9110 §10.1.4: the walk under `ParamSyntax::TransferParameter` against
  /// `http1-proto`'s `Transfer-Encoding` accumulator, which is a scan of its
  /// own in another crate.
  const TRANSFER_CODING: Self = Self {
    name: "te-walk-accumulator",
    kind: PairKind::CrossWalk,
  };
  /// RFC 9110 §5.6.6 behind two heads: the walk under `ParamSyntax::Parameter`
  /// against `Expectations`, which is its own accumulator over the same
  /// primitives.
  const PARAMS_WALK_EXPECT: Self = Self {
    name: "params-walk-expect",
    kind: PairKind::CrossWalk,
  };
  /// RFC 9110 §5.6.6 behind two heads: the walk under `ParamSyntax::Parameter`
  /// against `media::accept`, which is that same walk at a second
  /// configuration.
  const PARAMS_WALK_MEDIA: Self = Self {
    name: "params-walk-media",
    kind: PairKind::OneWalkTwice,
  };
  /// RFC 9110 §5.6.6 behind two heads: `Expectations` against `media::accept`.
  /// This is the §5.6.6 pair whose halves are two walks.
  const PARAMS_EXPECT_MEDIA: Self = Self {
    name: "params-expect-media",
    kind: PairKind::CrossWalk,
  };
  /// RFC 9110 §5.6.1.1's empty element: the accumulator against
  /// `Expectations`, over the values both element grammars derive.
  const EMPTY_ELEMENT: Self = Self {
    name: "empty-accumulator-expect",
    kind: PairKind::CrossWalk,
  };

  /// The key the tally counts this pair under. The kind comes first, so the
  /// two kinds sort apart and a pair moved between them moves its row.
  fn key(self) -> String {
    format!("{}/{}", self.kind.tag(), self.name)
  }
}

/// Every pair this corpus holds to equality.
///
/// `tests` asserts that the pairs the run counted are exactly these, so a pair
/// added at a call site and not here — or here and never reached — reds, and so
/// does one whose kind was chosen to flatter a count.
const PAIRS: [Pair; 5] = [
  Pair::TRANSFER_CODING,
  Pair::PARAMS_WALK_EXPECT,
  Pair::PARAMS_WALK_MEDIA,
  Pair::PARAMS_EXPECT_MEDIA,
  Pair::EMPTY_ELEMENT,
];

// ───────────────────────────────── the records ───────────────────────────────

/// How often one pair was compared, and how often its two halves parted.
///
/// Both, because they answer different questions: `asked` is the pair's
/// coverage — how many records it was in a position to catch a divergence on —
/// and `parted` is how many of those it answered differently about, licensed or
/// not. A pair whose `asked` fell to zero would have a perfect `parted` and
/// prove nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PairCount {
  /// Records the pair was compared on.
  asked: usize,
  /// Records its two halves answered differently about.
  parted: usize,
}

/// Every count `tests` asserts, accumulated as the records are written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Tally {
  /// Records written, per corpus.
  per_corpus: [usize; 5],
  /// Records written.
  records: usize,
  /// Records where two readers of one production parted.
  pair_disagree: usize,
  /// Records where a reader accepted what its production does not derive.
  over_accept: usize,
  /// Records where a reader refused what its production derives.
  over_refuse: usize,
  /// Records where the walk recovered past a fault and showed a member no
  /// derivation licenses. A counted state, not a zero-target.
  recovered_member: usize,
  /// Records with a member built out of a value's data.
  manufactured_member: usize,
  /// Records with a member whose parameters are no derivation's.
  member_extent: usize,
  /// Member extents compared against the derivations the oracle admits.
  ///
  /// The extent grading's own denominator, and the number that says whether the
  /// zero-target beside it was ever asked. A change that made every extent
  /// unaskable would drive `member_extent` to zero and this with it.
  extents_graded: usize,
  /// Member extents nothing could be asked about. See [`grade_extents`] for the
  /// four reasons, each of which is unaskable rather than excused.
  extents_unasked: usize,
  /// Graded extents where `media::accept` dropped a `q` the grammar derives as
  /// a parameter, per RFC 9110 §12.5.1.
  media_q_dropped: usize,
  /// Records in the bare-name residue.
  residue_valueless: usize,
  /// Records where a walk yielded a member whose name lay in none of the lines.
  unplaced: usize,
  /// How many faults of each `ListError` variant were reported, keyed by the
  /// pair that reported them and the variant's name.
  faults: BTreeMap<String, usize>,
  /// How many records reached each verdict of the `Transfer-Encoding`
  /// accumulator, keyed by its rendered form.
  verdicts: BTreeMap<String, usize>,
  /// How many records reached each of the states worth counting — the
  /// differences PR #78 enumerated among them.
  states: BTreeMap<String, usize>,
  /// How often each pair was compared and how often it parted, keyed by
  /// [`Pair::key`] — which begins with the pair's [`PairKind`], so the two
  /// kinds of evidence are separate rows and a total per kind is a sum over a
  /// prefix rather than a judgement made while reading.
  pairs: BTreeMap<String, PairCount>,
  /// Member starts the RFC 9110 §5.6.6 walk put up for grading, over every
  /// record of that comparison.
  ///
  /// The denominator of the boundary half. Beside [`Self::media_starts`] it is
  /// how much less of the value the media reader's boundary answer covers, and
  /// it is a count of STARTS rather than of records because that is the unit
  /// the licensing check consumes.
  walk_starts: usize,
  /// Member starts `media::accept` put up for grading, over the same records.
  media_starts: usize,
  /// Starts the walk reported and the media reader did not, summed. See
  /// [`Ranges::parsed`] for why `accept` reports fewer: it latches.
  media_starts_lost: usize,
  /// Starts the media reader reported and the walk did not, summed. The other
  /// direction of the same measurement, so the claim is a comparison rather
  /// than an assumption about which half stops first.
  walk_starts_lost: usize,
  /// Ranges `accept` yielded whose RFC 9110 §12.5.1 `"*/*"` shape reports no
  /// `type`, so no start could be placed for them. See [`Ranges::wildcard`].
  media_wildcard: usize,
}

impl Tally {
  /// A tally with a zero row for every pair in [`PAIRS`], and nothing else.
  ///
  /// The rows are seeded rather than created on first use so that a pair which
  /// is registered and never compared appears as `asked: 0` instead of as a
  /// missing row: a count that is asserted can red, and a row that is not there
  /// is a row nobody wrote an expectation for.
  fn new() -> Self {
    let mut tally = Self::default();
    for pair in PAIRS {
      tally.pairs.insert(pair.key(), PairCount::default());
    }
    tally
  }

  /// Counts one occurrence of `state`.
  fn state(&mut self, name: &str) {
    let slot = self.states.entry(name.to_string()).or_default();
    *slot = slot.saturating_add(1);
  }

  /// Counts one reader's extent grading over one record.
  fn extents(&mut self, extents: &Extents) {
    self.extents_graded = self.extents_graded.saturating_add(extents.graded);
    self.extents_unasked = self.extents_unasked.saturating_add(extents.unasked);
  }

  /// Counts one comparison of `pair`, and whether its two halves parted on it.
  fn pair(&mut self, pair: Pair, parted: bool) {
    let slot = self.pairs.entry(pair.key()).or_default();
    slot.asked = slot.asked.saturating_add(1);
    slot.parted = slot.parted.saturating_add(usize::from(parted));
  }
}

/// Where every record goes, and what is counted about it on the way.
struct Sink<'a, W: Write> {
  /// The records' destination.
  out: &'a mut W,
  /// What `tests` asserts.
  tally: Tally,
  /// A running SHA-256 over the `answer` column, per corpus and then over the
  /// whole run.
  ///
  /// `#[cfg(test)]`, because only the gate reads it: the binary's job is to
  /// print the records, and a reader who wants the digest of a dump has the
  /// dump. It is the same hash `xtask` publishes with, reached by path rather
  /// than copied, so the two cannot disagree while both stay green.
  #[cfg(test)]
  answers: [sha256::Sha256; 6],
}

impl<'a, W: Write> Sink<'a, W> {
  /// A sink writing to `out`.
  fn new(out: &'a mut W) -> Self {
    Self {
      out,
      tally: Tally::new(),
      #[cfg(test)]
      answers: std::array::from_fn(|_| sha256::Sha256::new()),
    }
  }

  /// Every generator, in a fixed order.
  fn run(&mut self) -> std::io::Result<()> {
    self.corpus_a()?;
    self.corpus_b()?;
    self.corpus_c()?;
    self.corpus_d()?;
    self.corpus_e()?;
    self.out.flush()
  }

  /// RFC 9110 §10.1.4's production, read four ways: the payload as the whole
  /// value, with a coding written behind it, behind a `transfer-parameter` the
  /// walk has already committed to, and cut across RFC 9110 §5.2's field-line
  /// join with a coding on the far side.
  ///
  /// The last is the shape that costs the most to get wrong: a value left open
  /// at a line's end resumes on the next one, and a reader that restarts its
  /// scan there reads the join's comma as a separator inside somebody's data.
  fn corpus_a(&mut self) -> std::io::Result<()> {
    for len in 1..=4 {
      for payload in payloads(&ALPHABET, len) {
        let mut tailed = payload.clone();
        tailed.extend_from_slice(b", chunked");
        let mut headed = b"gzip;p=".to_vec();
        headed.extend_from_slice(&payload);

        self.te("A", &[&payload], "te-bare")?;
        self.te("A", &[&tailed], "te-tail")?;
        self.te("A", &[&headed], "te-head")?;

        let cut = payload.len().checked_div(2).unwrap_or_default();
        let mut first = b"gzip;p=".to_vec();
        first.extend_from_slice(payload.get(..cut).unwrap_or_default());
        let mut second = payload.get(cut..).unwrap_or_default().to_vec();
        second.extend_from_slice(b", chunked");
        self.te("A", &[&first, &second], "te-split")?;
      }
    }
    for payload in payloads(&ALPHABET, 5) {
      let mut headed = b"gzip;p=".to_vec();
      headed.extend_from_slice(&payload);
      self.te("A", &[&payload], "te-bare")?;
      self.te("A", &[&headed], "te-head")?;
    }
    Ok(())
  }

  /// RFC 9110 §5.6.6's `parameters`, behind each reader's own head.
  ///
  /// `x` for the walk and `x=1` for `Expect`, because §10.1.1's
  /// `expectation = token [ "=" ( token / quoted-string ) parameters ]` closes
  /// its bracket AFTER `parameters` — a member carrying parameters and no
  /// argument is not an `expectation` at all — while §5.6.6's `parameters` has
  /// no head of its own and takes §5.6.2's `token` from the walk that
  /// concatenates it. The heads differ by exactly that, and the payload behind
  /// them is one string read under one production twice.
  ///
  /// The tail is `, zzz`: a bare `token`, which is a whole member under both.
  fn corpus_b(&mut self) -> std::io::Result<()> {
    for len in 1..=4 {
      for payload in payloads(&ALPHABET, len) {
        self.params_one("B", &payload, "params-bare")?;
        self.params_two("B", &payload, b"", &payload, "params-tail")?;
        let cut = payload.len().checked_div(2).unwrap_or_default();
        self.params_split("B", &payload, cut, "params-split")?;
      }
    }
    // The two-element spelling, over the shorter payloads: the list question is
    // about the ONE comma between two elements, and lengthening the payload
    // past the shapes that can reach that comma — a `,`, a DQUOTE, a `;` — buys
    // repetitions of an answer already given rather than a new one.
    for len in 1..=3 {
      for payload in payloads(&ALPHABET, len) {
        for (name, flank) in FLANKS {
          self.params_two(
            "B",
            &payload,
            flank,
            &payload,
            &format!("params-lead-{name}"),
          )?;
          self.params_two(
            "B",
            flank,
            &payload,
            &payload,
            &format!("params-trail-{name}"),
          )?;
        }
      }
    }
    for payload in payloads(&ALPHABET, 5) {
      self.params_one("B", &payload, "params-bare")?;
    }
    Ok(())
  }

  /// RFC 9110 §5.6.1.1's empty element, over values whose non-empty elements
  /// are bare `token`s and are therefore derived by both readers' element
  /// grammars.
  ///
  /// One field line, and then the same bytes cut at every interior position, so
  /// the §5.2 join stands where the single-line spelling has an ordinary byte.
  /// That pair is the point: a boundary is a fact about the COMBINED value, and
  /// a reader that answers per line reports one where the value has none.
  fn corpus_c(&mut self) -> std::io::Result<()> {
    for len in 1..=6 {
      for payload in payloads(&EMPTY_ALPHABET, len) {
        self.empty("C", &[&payload], "empty-one")?;
      }
    }
    for len in 2..=5 {
      for payload in payloads(&EMPTY_ALPHABET, len) {
        for cut in 1..payload.len() {
          let head = payload.get(..cut).unwrap_or_default();
          let tail = payload.get(cut..).unwrap_or_default();
          self.empty("C", &[head, tail], "empty-split")?;
        }
      }
    }
    Ok(())
  }

  /// The named vectors: every witness this cycle's issues and reviews argued
  /// over, plus the bytes RFC 9110 §5.6.4 decides a quoted-string on, which the
  /// two brute-force alphabets cannot spell.
  ///
  /// A brute force over nine bytes reaches the shapes; it does not reach `%x00`
  /// inside a string, `obs-text` beside it, or a seventeen-element list. This
  /// is where the rarer states `tests` counts get their witnesses, and it is
  /// what stops a state from being reachable only by accident of an alphabet.
  fn corpus_d(&mut self) -> std::io::Result<()> {
    for case in NAMED {
      self.te("D", case, "te-named")?;
      self.empty("D", case, "empty-named")?;
    }
    for case in NAMED_PARAMS {
      self.params_one("D", case, "params-named")?;
      self.params_two("D", case, b"", case, "params-named-tail")?;
      for (name, flank) in FLANKS {
        self.params_two("D", case, flank, case, &format!("params-named-lead-{name}"))?;
        self.params_two(
          "D",
          flank,
          case,
          case,
          &format!("params-named-trail-{name}"),
        )?;
      }
    }
    for case in NAMED_PARAM_LINES {
      self.params_lines("D", case, "params-named-lines")?;
    }
    // Every RFC 9110 §12.5.1 name an asterisk reaches, so the one that reports
    // no `type` is a case this corpus runs rather than a trap the next person
    // to write one springs. See [`MEDIA_NAMES`].
    for (shape, media_head) in MEDIA_NAMES {
      for case in WILDCARD_PARAMS {
        self.params_wildcard("D", media_head, case, &format!("params-wildcard-{shape}"))?;
      }
    }
    Ok(())
  }

  /// `Transfer-Encoding` values built as LISTS out of a vocabulary of codings,
  /// so the three verdicts RFC 9112 §6.3 item 4 and §6.1 order ahead of one
  /// another arise from a GENERATOR and not only from a name.
  ///
  /// Corpus A brute-forces the bytes INSIDE one coding and reaches those three
  /// once or twice each, entirely from corpus D: nine bytes spell no second
  /// `chunked`, so `chunked, gzip`, `chunked, chunked` and `chunked;p=1` were
  /// hand-written witnesses and nothing else reached them. A count asserted on
  /// a state one named case reaches is a count of that case. This enumerates
  /// the lists instead, so each of the three is reached by a family of values
  /// and a generator edit that dropped `NAMED` would leave them reached.
  fn corpus_e(&mut self) -> std::io::Result<()> {
    for value in coding_lists() {
      self.te("E", &[&value], "te-list")?;
      self.empty("E", &[&value], "empty-list")?;
    }
    Ok(())
  }

  /// Writes one record and counts it.
  fn record(
    &mut self,
    corpus: &str,
    lines: &[&[u8]],
    spelling: &str,
    grade: Grade,
    answer: &str,
  ) -> std::io::Result<()> {
    let index = match corpus {
      "A" => 0,
      "B" => 1,
      "C" => 2,
      "D" => 3,
      _ => 4,
    };
    if let Some(slot) = self.tally.per_corpus.get_mut(index) {
      *slot = slot.saturating_add(1);
    }
    let tally = &mut self.tally;
    tally.records = tally.records.saturating_add(1);
    tally.pair_disagree = tally
      .pair_disagree
      .saturating_add(usize::from(grade.pair_disagree));
    tally.over_accept = tally
      .over_accept
      .saturating_add(usize::from(grade.over_accept));
    tally.over_refuse = tally
      .over_refuse
      .saturating_add(usize::from(grade.over_refuse));
    tally.recovered_member = tally
      .recovered_member
      .saturating_add(usize::from(grade.recovered_member));
    tally.manufactured_member = tally
      .manufactured_member
      .saturating_add(usize::from(grade.manufactured_member));
    tally.member_extent = tally
      .member_extent
      .saturating_add(usize::from(grade.member_extent));
    tally.residue_valueless = tally
      .residue_valueless
      .saturating_add(usize::from(grade.residue_valueless));
    #[cfg(test)]
    for slot in [index, 5] {
      if let Some(digest) = self.answers.get_mut(slot) {
        digest.update(answer.as_bytes());
        digest.update(b"\n");
      }
    }
    let case = lines
      .iter()
      .map(|line| escape(line))
      .collect::<Vec<_>>()
      .join("|");
    writeln!(
      self.out,
      "{corpus}\t{case}\t{spelling}\t{}\t{answer}",
      grade.render()
    )
  }

  /// The RFC 9110 §10.1.4 pair: the walk under `ParamSyntax::TransferParameter`
  /// and `http1-proto`'s accumulator, over one `Transfer-Encoding` value.
  ///
  /// The walk under `ParamSyntax::Parameter` is recorded beside them, graded
  /// against §5.6.6 rather than against §10.1.4, so that the differences
  /// between the two productions are answers in the corpus rather than
  /// exceptions in this function.
  fn te(&mut self, corpus: &str, lines: &[&[u8]], spelling: &str) -> std::io::Result<()> {
    let joined = join(lines);
    let strict = walk(lines, ParamSyntax::TransferParameter);
    let lenient = walk(lines, ParamSyntax::Parameter);
    let list = codings(lines);
    let coding_reading = oracle::read(&joined, Production::TransferCoding);
    let param_reading = oracle::read(&joined, Production::TokenParameters);

    let mut grade = grade_walk(&strict, &coding_reading, false);
    let lenient_grade = grade_walk(&lenient, &param_reading, true);
    grade.over_accept |= lenient_grade.over_accept;
    grade.over_refuse |= lenient_grade.over_refuse;
    grade.recovered_member |= lenient_grade.recovered_member;
    grade.manufactured_member |= lenient_grade.manufactured_member;
    grade.residue_valueless |= lenient_grade.residue_valueless;

    // The accumulator reads §10.1.4 as well, so it is graded against the same
    // reading the strict walk is.
    if list.parsed && !coding_reading.derives {
      grade.over_accept = true;
    }
    if !list.parsed && coding_reading.derives {
      grade.over_refuse = true;
    }
    // The pair itself: equal well-formedness, and the same verdict. Nothing
    // licenses a difference here, so a parting IS the zero-target — and it is
    // counted as a pair as well, because `asked` is this pair's coverage and a
    // zero-target says nothing about how many records were behind it.
    let parted = strict.well_formed != list.parsed || projected_verdict(&strict) != list.verdict;
    self.tally.pair(Pair::TRANSFER_CODING, parted);
    grade.pair_disagree |= parted;

    // The extents, each arm against its OWN production, for the reason the
    // arms are graded apart everywhere else here.
    let strict_extents = grade_extents(
      &joined,
      &strict.extents,
      &coding_reading,
      strict.well_formed,
      false,
    );
    let lenient_extents = grade_extents(
      &joined,
      &lenient.extents,
      &param_reading,
      lenient.well_formed,
      false,
    );
    grade.member_extent |= strict_extents.wrong || lenient_extents.wrong;
    self.count_extents(&strict_extents);
    self.count_extents(&lenient_extents);

    self.count_faults(&strict, "te");
    self.count_te_states(&strict, &lenient, &list, &coding_reading, &param_reading);
    self.tally.unplaced = self
      .tally
      .unplaced
      .saturating_add(strict.unplaced.saturating_add(lenient.unplaced));
    let verdict = format!("{:?}", list.verdict);
    *self.tally.verdicts.entry(verdict.clone()).or_default() = self
      .tally
      .verdicts
      .get(&verdict)
      .copied()
      .unwrap_or_default()
      .saturating_add(1);

    let answer = format!(
      "tp={} / p={} / cl={}",
      empty_as_dash(&strict.rendered),
      empty_as_dash(&lenient.rendered),
      list.rendered
    );
    self.record(corpus, lines, spelling, grade, &answer)
  }

  /// One §5.6.6 payload as one element, each reader behind its own head.
  fn params_one(&mut self, corpus: &str, payload: &[u8], spelling: &str) -> std::io::Result<()> {
    let spelt = HEADS.map(|head| spell_elements(head, &[payload]));
    self.params_pair(corpus, &spelt, payload, spelling, false)
  }

  /// The same, with the media reader's head replaced by one of the RFC 9110
  /// §12.5.1 `media-range` names in [`MEDIA_NAMES`].
  ///
  /// The two token-headed readers keep their own heads from [`HEADS`], because
  /// the question is about §12.5.1's name grammar and not about theirs — and
  /// because a solidus is no §5.6.2 `token`, so there is no head all three
  /// could share here either.
  fn params_wildcard(
    &mut self,
    corpus: &str,
    media_head: &[u8],
    payload: &[u8],
    spelling: &str,
  ) -> std::io::Result<()> {
    let [token_head, expect_head, _] = HEADS;
    let spelt = [token_head, expect_head, media_head].map(|head| spell_elements(head, &[payload]));
    self.params_pair(corpus, &spelt, payload, spelling, false)
  }

  /// The same payload as the first or second element of a TWO-element list,
  /// each reader's own head in front of BOTH elements.
  ///
  /// The spelling that asks the §5.6.6 comparison about a list of more than one
  /// element. Writing a head in front of each element is what makes it askable:
  /// an element the payload's own comma opens carries no head, and a head is
  /// exactly where the three readers' grammars differ — §5.6.6's `parameters`
  /// takes §5.6.2's `token`, §10.1.1 puts a bracketed argument between the two,
  /// and §12.5.1 heads its `media-range` with `type "/" subtype`. So an element
  /// each reader heads itself is one all three read as the same `parameters`,
  /// and the boundary between two of them is a question they can be asked.
  ///
  /// `case` is the payload under test, which is `first` or `second` depending
  /// on which side this call is varying; the other is a fixed flank.
  fn params_two(
    &mut self,
    corpus: &str,
    first: &[u8],
    second: &[u8],
    case: &[u8],
    spelling: &str,
  ) -> std::io::Result<()> {
    let spelt = HEADS.map(|head| spell_elements(head, &[first, second]));
    self.params_pair(corpus, &spelt, case, spelling, !second.is_empty())
  }

  /// The same payload as one element, cut across RFC 9110 §5.2's join at `cut`.
  fn params_split(
    &mut self,
    corpus: &str,
    payload: &[u8],
    cut: usize,
    spelling: &str,
  ) -> std::io::Result<()> {
    let head = payload.get(..cut).unwrap_or_default();
    let tail = payload.get(cut..).unwrap_or_default();
    let spelt = HEADS.map(|reader_head| {
      let mut spelt = spell_elements(reader_head, &[head]);
      spelt.lines.push(tail.to_vec());
      spelt
    });
    self.params_pair(corpus, &spelt, payload, spelling, false)
  }

  /// The same payload written over the field lines RFC 9110 §5.2 joins, each
  /// reader's head in front of the first of them.
  fn params_lines(
    &mut self,
    corpus: &str,
    payload_lines: &[&[u8]],
    spelling: &str,
  ) -> std::io::Result<()> {
    let first = payload_lines.first().copied().unwrap_or_default();
    let rest = payload_lines.get(1..).unwrap_or_default();
    let spelt = HEADS.map(|head| {
      let mut spelt = spell_elements(head, &[first]);
      spelt.lines.extend(rest.iter().map(|line| line.to_vec()));
      spelt
    });
    let joined = join(payload_lines);
    self.params_pair(corpus, &spelt, &joined, spelling, false)
  }

  /// Records one §5.6.6 comparison: three readers over one payload, each behind
  /// its own head, held to equal well-formedness pairwise.
  ///
  /// `spelt` is in [`HEADS`] order — the walk, `Expectations`, `accept` — and
  /// is destructured rather than indexed, so a fourth reader added to that
  /// array stops this compiling instead of being written and never read.
  ///
  /// `beyond_first` is whether the generator wrote payload bytes in an element
  /// other than the first.
  fn params_pair(
    &mut self,
    corpus: &str,
    spelt: &[Spelt; 3],
    case: &[u8],
    spelling: &str,
    beyond_first: bool,
  ) -> std::io::Result<()> {
    let [walk_spelt, expect_spelt, media_spelt] = spelt;
    let (walk_lines, expect_lines, media_lines) = (
      walk_spelt.borrowed(),
      expect_spelt.borrowed(),
      media_spelt.borrowed(),
    );
    let walk_value = join(&walk_lines);
    let expect_value = join(&expect_lines);
    let media_value = join(&media_lines);
    let walked = walk(&walk_lines, ParamSyntax::Parameter);
    let read = expectations(&expect_lines);
    let ranged = ranges(&media_lines);
    let walk_reading = oracle::read(&walk_value, Production::TokenParameters);
    let expect_reading = oracle::read(&expect_value, Production::Expectation);
    let media_reading = oracle::read(&media_value, Production::MediaRange);

    let mut grade = grade_walk(&walked, &walk_reading, true);
    if read.parsed && !expect_reading.derives {
      grade.over_accept = true;
    }
    if !read.parsed && expect_reading.derives {
      grade.over_refuse = true;
    }
    // Two refusals `accept` owns that no reading of RFC 9110 §5.6.6's
    // `parameters` carries, each licensed here and counted below for the reason
    // the three differences between §10.1.4 and §5.6.6 are counted: they are
    // differences between FIELDS, and encoding them as states is what keeps
    // them out of the comparison as special cases.
    //
    // §12.5.1 writes `Accept = #( media-range [ weight ] )` with
    // `weight = OWS ";" OWS "q=" qvalue`, and this reader reads any `q` as that
    // weight — "Recipients SHOULD process any parameter named "q" as weight,
    // regardless of parameter ordering" — so a `q` whose value is no §12.4.2
    // `qvalue` is refused where §5.6.6 and §10.1.1 derive.
    //
    // And a quoted value that crosses RFC 9110 §5.2's field-line join is well
    // formed and not one contiguous slice. That is a fact about the LINES, and
    // the oracle grades the one value §5.2 joins them into and cannot see it —
    // so a refusal for that reason is the reader's borrow contract rather than
    // a reading of the grammar. The walk answers the same fact differently, by
    // yielding the member with its boundaries settled, which is the difference
    // the license is over.
    let weight_refusal = ranged.fault == Some(MediaError::BadWeight);
    let borrow_refusal = ranged.fault == Some(MediaError::ValueSpansFieldLines);
    let media_licensed = weight_refusal || borrow_refusal;
    if ranged.parsed && !media_reading.derives {
      grade.over_accept = true;
    }
    if !ranged.parsed && media_reading.derives && !media_licensed {
      grade.over_refuse = true;
    }
    for &at in &ranged.starts {
      if media_reading.licenses_member_at(at) {
        continue;
      }
      if media_reading.is_string_data(at) {
        grade.manufactured_member = true;
      } else {
        grade.recovered_member = true;
      }
    }

    // The extents. `Expectations` contributes none — it is an accumulator that
    // hands out a verdict and no member — so this is the walk and `accept`, the
    // two readers here that yield members at all.
    //
    // `accept` is graded with §12.4.2's `q` taken as a parameter NAME rather
    // than as a parameter, because that is what it does: `MediaRange::params`
    // hands over every parameter except one named `q`, at any position, which
    // is RFC 9110 §12.5.1's "Recipients SHOULD process any parameter named "q"
    // as weight, regardless of parameter ordering". The walk carries no such
    // rule and is graded against every parameter the grammar derives.
    let walk_extents = grade_extents(
      &walk_value,
      &walked.extents,
      &walk_reading,
      walked.well_formed,
      false,
    );
    let media_extents = grade_extents(
      &media_value,
      &ranged.extents,
      &media_reading,
      ranged.parsed,
      true,
    );
    grade.member_extent |= walk_extents.wrong || media_extents.wrong;
    self.count_extents(&walk_extents);
    self.count_extents(&media_extents);
    if media_extents.q_dropped > 0 {
      self.tally.state("media-q-dropped");
      self.tally.media_q_dropped = self
        .tally
        .media_q_dropped
        .saturating_add(media_extents.q_dropped);
    }

    let comparable = keeps_the_written_elements(&walk_reading, &walk_spelt.heads)
      && keeps_the_written_elements(&expect_reading, &expect_spelt.heads)
      && keeps_the_written_elements(&media_reading, &media_spelt.heads);
    if comparable {
      self.tally.state("params-comparable");
      if walk_spelt.heads.len() > 1 {
        // The reachability the exclusion is about: without this count, a filter
        // change that quietly re-excluded every list of more than one element
        // would leave `params-comparable` looking healthy and compare none of
        // them.
        self.tally.state("params-comparable-multi");
        if beyond_first {
          // And the sharper one. A two-element list whose second element is a
          // bare head asks §5.6.6's `parameters` about the FIRST element only,
          // which is the question a one-element value already asks; this counts
          // the records where an element other than the first carries a
          // `parameters` payload of its own, so the pair is asked about the
          // production where it had never been asked before.
          self.tally.state("params-comparable-multi-parameterised");
        }
      }
      // Three readers make THREE pairs, and they are not three of a kind: only
      // two of them are two walks. `Pair::PARAMS_WALK_MEDIA` is
      // `parameterised_list` against itself at a second member-name rule, so
      // it is counted under `one-walk-twice` and a run that added its `parted`
      // to the other two would be claiming independence it does not have.
      //
      // Two licensed differences, and nothing else. The bare parameter name:
      // the walk hands it over as `ParamValue::None` for the field to answer,
      // §10.1.1's `parameter` refuses it and so does `accept`, which declares
      // the refusal to the walk. And §12.4.2's weight, above.
      let licensed = grade.residue_valueless;
      let walk_expect = walked.well_formed != read.parsed;
      self.tally.pair(Pair::PARAMS_WALK_EXPECT, walk_expect);
      if walk_expect && !licensed {
        grade.pair_disagree = true;
      }
      let walk_media = walked.well_formed != ranged.parsed;
      self.tally.pair(Pair::PARAMS_WALK_MEDIA, walk_media);
      if walk_media && !licensed && !media_licensed {
        grade.pair_disagree = true;
      }
      let expect_media = read.parsed != ranged.parsed;
      self.tally.pair(Pair::PARAMS_EXPECT_MEDIA, expect_media);
      if expect_media && !media_licensed {
        grade.pair_disagree = true;
      }
    } else {
      self.tally.state("params-not-comparable");
    }

    // How much of the value each half of the boundary comparison put up for
    // grading, and how far apart the two are. `accept` latches at its first
    // faulting member, so on a faulting value it reports the starts in front of
    // the fault and no others; the walk recovers past a fault wherever the
    // member's own boundaries are still settled. The counts are comparable
    // because the generator wrote the same number of elements for both, one
    // head apiece — the OFFSETS are not, since the heads differ in length.
    //
    // Counted on every record of this comparison and not only the comparable
    // ones: the licensing check above runs on every record too, and this is the
    // measure of how much it saw.
    self.tally.walk_starts = self.tally.walk_starts.saturating_add(walked.starts.len());
    self.tally.media_starts = self.tally.media_starts.saturating_add(ranged.starts.len());
    let media_short = walked.starts.len().saturating_sub(ranged.starts.len());
    if media_short > 0 {
      self.tally.state("boundary-media-short");
      self.tally.media_starts_lost = self.tally.media_starts_lost.saturating_add(media_short);
    }
    let walk_short = ranged.starts.len().saturating_sub(walked.starts.len());
    if walk_short > 0 {
      self.tally.state("boundary-walk-short");
      self.tally.walk_starts_lost = self.tally.walk_starts_lost.saturating_add(walk_short);
    }
    if ranged.wildcard > 0 {
      self.tally.state("media-wildcard");
      self.tally.media_wildcard = self.tally.media_wildcard.saturating_add(ranged.wildcard);
    }

    self.count_faults(&walked, "params");
    if let Some(fault) = ranged.fault {
      let key = format!("media:{fault:?}");
      let seen = self.tally.faults.get(&key).copied().unwrap_or_default();
      self.tally.faults.insert(key, seen.saturating_add(1));
    }
    if weight_refusal {
      self.tally.state("axis-media-weight");
    }
    if borrow_refusal {
      self.tally.state("axis-media-borrow");
    }
    self.tally.unplaced = self
      .tally
      .unplaced
      .saturating_add(walked.unplaced.saturating_add(ranged.unplaced));
    self.tally.state(if read.parsed {
      "expect-parsed"
    } else {
      "expect-refused"
    });
    if read.empty_element {
      self.tally.state("expect-empty-element");
    }
    self.tally.state(if ranged.parsed {
      "media-parsed"
    } else {
      "media-refused"
    });

    let answer = format!(
      "p={} / exp={} / acc={}",
      empty_as_dash(&walked.rendered),
      read.rendered,
      empty_as_dash(&ranged.rendered)
    );
    // The case column carries the shared payload rather than any reader's
    // value: the three heads are the spelling, and a record keyed by one of
    // them would not say which payload the other two read.
    self.record(corpus, &[case], spelling, grade, &answer)
  }

  /// The RFC 9110 §5.6.1.1 pair: the two readers that answer a SENDER's
  /// empty-element question over the §5.2-combined value.
  fn empty(&mut self, corpus: &str, lines: &[&[u8]], spelling: &str) -> std::io::Result<()> {
    let joined = join(lines);
    let list = codings(lines);
    let read = expectations(lines);
    let mut grade = Grade::default();
    // Each reader against its OWN production first, which is a question about
    // one reader and is asked of every case whether or not the pair below can
    // be compared.
    for (parsed, production) in [
      (list.parsed, Production::TransferCoding),
      (read.parsed, Production::Expectation),
    ] {
      let derives = oracle::read(&joined, production).derives;
      if parsed && !derives {
        grade.over_accept = true;
      }
      if !parsed && derives {
        grade.over_refuse = true;
      }
    }
    // Held to equality only where both element grammars derive the same
    // elements, which is what `bare_token_list` decides. Elsewhere the two read
    // different productions and their answers are recorded, not compared.
    let comparable = bare_token_list(&joined);
    if comparable {
      self.tally.state("empty-comparable");
      let parted = list.parsed != read.parsed || list.empty_element != read.empty_element;
      self.tally.pair(Pair::EMPTY_ELEMENT, parted);
      grade.pair_disagree |= parted;
      if list.empty_element {
        self.tally.state("empty-comparable-empty");
      }
    }
    let answer = format!("cl={} / exp={}", list.rendered, read.rendered);
    self.record(corpus, lines, spelling, grade, &answer)
  }

  /// Counts one reader's extent grading, and the two states that say whether
  /// the grading was asked at all.
  ///
  /// Both directions are states rather than one being left to be inferred: a
  /// change that made every extent unaskable would drive the zero-target to
  /// zero by asking nothing, and `extent-graded` is what reds on it.
  fn count_extents(&mut self, extents: &Extents) {
    self.tally.extents(extents);
    if extents.graded > 0 {
      self.tally.state("extent-graded");
    }
    if extents.unasked > 0 {
      self.tally.state("extent-unasked");
    }
  }

  /// Counts every fault a walk reported.
  fn count_faults(&mut self, walked: &Walk, pair: &str) {
    for fault in &walked.faults {
      let key = format!("{pair}:{fault:?}");
      let seen = self.tally.faults.get(&key).copied().unwrap_or_default();
      self.tally.faults.insert(key, seen.saturating_add(1));
    }
  }

  /// Counts the states the two `ParamSyntax` arms are told apart by — the
  /// differences PR #78 enumerated — and the ones a `Transfer-Encoding` value
  /// is worth reaching at all.
  fn count_te_states(
    &mut self,
    strict: &Walk,
    lenient: &Walk,
    list: &Listed,
    coding_reading: &Reading,
    param_reading: &Reading,
  ) {
    if coding_reading.derives && !param_reading.derives {
      // §10.1.4 admits `BWS` around the `=` and §5.6.6 admits none, which is
      // the only way a value derives under the wider production and not the
      // narrower one.
      self.tally.state("axis-bws");
    }
    if param_reading.derives && !coding_reading.derives {
      // §5.6.6 brackets its slot and §10.1.4 brackets nothing, so an empty slot
      // is the only way a value derives under the narrower production and not
      // the wider one.
      self.tally.state("axis-empty-slot");
    }
    if lenient.valueless {
      // Neither production derives a bare name; the two fields answer it
      // differently, which is the fourth difference the walk's own source
      // enumerates.
      self.tally.state("axis-bare-name");
    }
    if strict.well_formed != lenient.well_formed {
      self.tally.state("arms-part");
    }
    if list.empty_element {
      self.tally.state("te-empty-element");
    }
    if strict.starts.len() > 1 {
      self.tally.state("te-multi-member");
    }
  }
}

/// Whether a §5.6.6 comparison's value has exactly the element structure its
/// generator wrote, and no other.
///
/// §5.6.6's `parameters` contains no comma, so a comma some reading of the
/// payload takes as RFC 9110 §5.6.1's separator opens a second ELEMENT — and
/// an element is where the three readers' grammars are different rules, which
/// is the difference this comparison factors out rather than measures. The
/// generator writes one reader's head in front of every element it intends, so
/// an element start it did not write is one that carries no head, and no byte
/// string is a head for all three: §5.6.2's `tchar` excludes the solidus, so a
/// name §12.5.1 derives is a name §5.6.6's `token` head refuses and the other
/// way round. A payload that opens such an element is therefore recorded and
/// not compared, and `tests` holds the count of those, so the exclusion cannot
/// quietly grow to swallow the corpus.
///
/// A payload whose comma is swallowed by an element's own quoted-string opens
/// nothing and stays comparable, which is the case worth keeping: it is where
/// RFC 9110 §5.2's join lands inside a value.
fn keeps_the_written_elements(reading: &Reading, heads: &[usize]) -> bool {
  reading.element_starts.iter().all(|at| heads.contains(at))
}

/// Whether every non-empty element of `value` is a bare RFC 9110 §5.6.2
/// `token`, with only §5.6.3 `OWS` around it.
///
/// The class over which a `transfer-coding` and an `expectation` are the same
/// element: §10.1.4's `token *( OWS ";" OWS transfer-parameter )` with the
/// repetition run zero times, and §10.1.1's
/// `token [ "=" ( token / quoted-string ) parameters ]` with the bracket empty.
/// Over it, the two readers' §5.6.1.1 answers are about one list.
fn bare_token_list(value: &[u8]) -> bool {
  value
    .split(|&byte| byte == b',')
    .all(|element| element.iter().all(|&byte| is_ows_or_tchar(byte)))
}

/// Whether `byte` is `SP`, `HTAB`, or one of RFC 9110 §5.6.2's `tchar`.
fn is_ows_or_tchar(byte: u8) -> bool {
  byte == b' '
    || byte == b'\t'
    || byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'!'
        | b'#'
        | b'$'
        | b'%'
        | b'&'
        | b'\''
        | b'*'
        | b'+'
        | b'-'
        | b'.'
        | b'^'
        | b'_'
        | b'`'
        | b'|'
        | b'~'
    )
}

// ────────────────────────────── offsets and bytes ────────────────────────────

/// Where each line begins in the value RFC 9110 §5.2 joins: the field line
/// values are "concatenated in order, with each field line value separated by a
/// comma", so each line starts one byte of separator past the end of the last.
fn line_bases(lines: &[&[u8]]) -> Vec<usize> {
  let mut bases = Vec::with_capacity(lines.len());
  let mut at = 0usize;
  for (index, line) in lines.iter().enumerate() {
    if index > 0 {
      at = at.saturating_add(1);
    }
    bases.push(at);
    at = at.saturating_add(line.len());
  }
  bases
}

/// The one value RFC 9110 §5.2 makes of the field lines.
fn join(lines: &[&[u8]]) -> Vec<u8> {
  let mut out = Vec::new();
  for (index, line) in lines.iter().enumerate() {
    if index > 0 {
      out.push(b',');
    }
    out.extend_from_slice(line);
  }
  out
}

/// Where `slice` — a subslice of one of `lines` — begins in the joined value.
///
/// The walk borrows its input, so a member's name IS a slice of the line it was
/// read from, and its address places it exactly. Nothing is dereferenced: the
/// two pointers are compared and subtracted as integers. A name that fits in no
/// line is reported as `None` and counted, rather than guessed at.
fn place(lines: &[&[u8]], bases: &[usize], slice: &[u8]) -> Option<usize> {
  let at = slice.as_ptr() as usize;
  for (index, line) in lines.iter().enumerate() {
    let base = line.as_ptr() as usize;
    let end = base.checked_add(line.len())?;
    if at >= base && at.checked_add(slice.len())? <= end {
      return bases.get(index)?.checked_add(at.checked_sub(base)?);
    }
  }
  None
}

/// One line of bytes as one printable, unambiguous field of the record.
///
/// Everything outside the printable US-ASCII range becomes `%XX`, and so do the
/// three bytes the record format itself gives meaning to.
fn escape(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len());
  for &byte in bytes {
    match byte {
      b'%' | b'|' | b'\\' => out.push_str(&format!("%{byte:02X}")),
      0x21..=0x7E => out.push(char::from(byte)),
      _ => out.push_str(&format!("%{byte:02X}")),
    }
  }
  out
}

/// An empty rendering as a `-`, so a record's columns never collapse.
fn empty_as_dash(rendered: &str) -> &str {
  if rendered.is_empty() { "-" } else { rendered }
}
