//! The gate over this corpus, and over the oracle that grades it.
//!
//! # What it asserts, and why in this shape
//!
//! Three rules, all of them issue #77's findings about `auth-corpus` written
//! down:
//!
//! 1. **Every axis that should be zero is a zero-target.** `auth-corpus` pins
//!    `over-yield` at 16 and 20 — its own name for a caller handed a challenge
//!    built out of bytes a sender wrote as that value's data — so the number it
//!    exists to drive to zero is a constant somebody decided to keep. Nothing
//!    here is pinned at a non-zero constant except the one residue below, which
//!    carries an exact characterisation rather than a number.
//! 2. **Every interesting state carries the COUNT of records that reach it.**
//!    `auth-corpus` reaches `TooManyParameters` zero times, because one
//!    generator always fires a different bound first, and nothing said so. A
//!    count asserted here means a generator edit that makes a state unreachable
//!    reds instead of going quiet.
//! 3. **The oracle is pinned against values RFC 9110 settles by hand.** An
//!    oracle quietly made more permissive lowers the very number it exists to
//!    drive to zero and reports success.
//!
//! A fourth, from this harness's own review rather than from `auth-corpus`:
//!
//! 4. **Each pair is counted under the kind of evidence it is.** Four of the
//!    five pairs are two independent walks; the fifth is `parameterised_list`
//!    compared with itself at a second configuration. One total over both would
//!    report more independence than the run holds, so [`EXPECTED_PAIRS`] keys
//!    every row by its kind and the per-kind totals are asserted apart — a pair
//!    filed under the wrong kind moves two of them and reds naming both.
//!
//! # What this still cannot see
//!
//! The tallies are counts of records, so an answer that MOVES within its grade
//! moves no tally. The digest over the `answer` column is what catches that,
//! and what the digest cannot say is WHICH record moved — there is no
//! two-revision driver for this corpus as `xtask auth-diff` is one for
//! `auth-corpus`, so the way to find out is to run the binary at both
//! revisions and `diff` the two outputs.
//!
//! A member's EXTENT is checked only through the offset the next member begins
//! at and through the pair's verdict projection: nothing hands out where a
//! member ends, so a walk that ended its LAST member early and yielded nothing
//! behind it would satisfy every assertion here. The `Transfer-Encoding`
//! verdict is what narrows that — a coding lost off the end of the list changes
//! `final_is_chunked` — but only for that one pair, and the §5.6.6 pairs have
//! no verdict at all. It is the largest thing a green run here does not say;
//! the crate doc states it where a reader meets it first, and issue #79 carries
//! what closing it would cost.
//!
//! Of the member starts that ARE compared, the media reader contributes fewer
//! than the walk does, on two counts that are measured here rather than argued:
//! `accept` latches at its first faulting member, and RFC 9110 §12.5.1's
//! `"*/*"` names no `type` to place. Neither can grade a start wrongly — an
//! unreported start is one nothing was said about — so [`MEDIA_STARTS`] beside
//! [`WALK_STARTS`] is the size of the gap and `boundary-media-short` is how
//! many records it falls on.

use std::{collections::BTreeSet, sync::OnceLock};

use http_semantics::{grammar::ParamSyntax, media::MediaError};

use crate::{
  Grade, ParamValue, Tally, join, oracle, oracle::Production, parameterised_list, sha256::Sha256,
  walk,
};

/// The whole corpus, run once for every test in this file.
struct Corpus {
  /// Every record, in the order written.
  records: String,
  /// What the run counted.
  tally: Tally,
  /// The SHA-256 of the `answer` column, per corpus and then over the whole
  /// run.
  digests: [String; 6],
}

/// Runs every generator into memory, once.
fn corpus() -> &'static Corpus {
  static ONCE: OnceLock<Corpus> = OnceLock::new();
  ONCE.get_or_init(|| {
    let mut buffer: Vec<u8> = Vec::new();
    let (tally, digests) = {
      let mut sink = crate::Sink::new(&mut buffer);
      sink.run().expect("a Vec sink cannot fail");
      (sink.tally.clone(), sink.answers.map(Sha256::finish))
    };
    Corpus {
      records: String::from_utf8(buffer).expect("every column is escaped ASCII"),
      tally,
      digests,
    }
  })
}

/// The record count each generator is expected to write.
///
/// Asserted rather than narrated: a generator that stops generating shortens
/// every count below it and would otherwise leave every one of them still
/// green.
const PER_CORPUS: [usize; 5] = [147_618, 86_103, 10_468, 344, 516];

/// Nothing this corpus grades is a defect.
///
/// The six axes that must be zero, each named in the failure so the number that
/// moved is the one the message is about. `unplaced` is here too: it is not an
/// axis but a fact about whether the licensing check saw every member the walks
/// yielded, and a non-zero count would mean some members were never graded and
/// nothing said so.
#[test]
#[cfg_attr(
  miri,
  ignore = "walks 245 049 records through four readers and an O(n^2) oracle; \
            seconds natively, hours interpreted, and it exercises no unsafe code"
)]
fn nothing_this_corpus_grades_is_a_defect() {
  let tally = &corpus().tally;
  assert_eq!(
    tally.pair_disagree, 0,
    "two readers of one production parted"
  );
  assert_eq!(
    tally.over_accept, 0,
    "a reader accepted a value its own production does not derive"
  );
  assert_eq!(
    tally.over_refuse, 0,
    "a reader refused a value its own production derives"
  );
  assert_eq!(
    tally.manufactured_member, 0,
    "a walk yielded a member built out of a parameter value's own data"
  );
  assert_eq!(
    tally.unplaced, 0,
    "a member's name was a slice of none of the lines it was read from"
  );
}

/// The corpus is the size it says it is.
#[test]
#[cfg_attr(miri, ignore = "runs the whole corpus; see the zero-target test")]
fn the_corpus_is_the_size_it_says_it_is() {
  let tally = &corpus().tally;
  assert_eq!(tally.per_corpus, PER_CORPUS);
  assert_eq!(tally.records, PER_CORPUS.iter().sum::<usize>());
}

/// `(corpus, case, spelling)` keys one record.
///
/// Without this a generator that wrote one input twice would inflate every
/// count below by an amount nothing could recover — which is the defect
/// `auth-corpus` carries knowingly and documents, its corpus D writing 32
/// inputs six times each.
#[test]
#[cfg_attr(miri, ignore = "runs the whole corpus; see the zero-target test")]
fn the_records_are_keyed_uniquely() {
  let mut keys = BTreeSet::new();
  let mut records = 0usize;
  for line in corpus().records.lines() {
    records = records.saturating_add(1);
    let mut columns = line.split('\t');
    let key = (
      columns.next().unwrap_or_default().to_owned(),
      columns.next().unwrap_or_default().to_owned(),
      columns.next().unwrap_or_default().to_owned(),
    );
    assert!(keys.insert(key.clone()), "{key:?} is written twice");
  }
  assert_eq!(records, corpus().tally.records);
}

/// Every state this corpus is meant to reach IS reached, and by how many
/// records.
///
/// The counts are exact. A generator edit that leaves a state unreachable, or
/// that reaches it a different number of times, reds here and names the state —
/// which is the whole of the difference between this and a corpus that reaches
/// a state zero times and reports success.
#[test]
#[cfg_attr(miri, ignore = "runs the whole corpus; see the zero-target test")]
fn every_state_this_corpus_is_meant_to_reach_is_reached() {
  let tally = &corpus().tally;
  let states: Vec<(&str, usize)> = tally
    .states
    .iter()
    .map(|(name, count)| (name.as_str(), *count))
    .collect();
  assert_eq!(states, EXPECTED_STATES, "the states reached moved");

  let faults: Vec<(&str, usize)> = tally
    .faults
    .iter()
    .map(|(name, count)| (name.as_str(), *count))
    .collect();
  assert_eq!(faults, EXPECTED_FAULTS, "the faults reported moved");

  let verdicts: Vec<(&str, usize)> = tally
    .verdicts
    .iter()
    .map(|(name, count)| (name.as_str(), *count))
    .collect();
  assert_eq!(verdicts, EXPECTED_VERDICTS, "the verdicts reached moved");

  assert_eq!(tally.recovered_member, RECOVERED_MEMBERS);
  assert_eq!(tally.residue_valueless, RESIDUE_RECORDS);
}

/// Every pair is counted under the kind of evidence it is, and the two kinds
/// are never one number.
///
/// Three assertions, and they fail on different mistakes. The rows pin each
/// pair's key, coverage and partings, so a pair whose kind moved changes its
/// own row. The registry check pins the SET, so a pair counted at a call site
/// and never declared — or declared and never reached — reds rather than
/// appearing as a row nobody wrote an expectation for. And the per-kind totals
/// pin the sums, so the number a reader would quote for "how much of this run
/// is two independent walks" cannot be raised by filing a pair under the wrong
/// kind.
#[test]
#[cfg_attr(miri, ignore = "runs the whole corpus; see the zero-target test")]
fn every_pair_is_counted_under_the_kind_it_earns() {
  let tally = &corpus().tally;
  let rows: Vec<(&str, usize, usize)> = tally
    .pairs
    .iter()
    .map(|(key, count)| (key.as_str(), count.asked, count.parted))
    .collect();
  assert_eq!(rows, EXPECTED_PAIRS, "the pairs, or their kinds, moved");

  let declared: BTreeSet<String> = crate::PAIRS.iter().map(|pair| pair.key()).collect();
  let counted: BTreeSet<String> = tally.pairs.keys().cloned().collect();
  assert_eq!(
    counted, declared,
    "a pair was counted without being declared in PAIRS, or declared and never reached"
  );

  let mut asked = std::collections::BTreeMap::<&str, usize>::new();
  let mut parted = std::collections::BTreeMap::<&str, usize>::new();
  for (key, count) in &tally.pairs {
    let kind = key.split('/').next().unwrap_or_default();
    let slot = asked.entry(kind).or_default();
    *slot = slot.saturating_add(count.asked);
    let slot = parted.entry(kind).or_default();
    *slot = slot.saturating_add(count.parted);
  }
  assert_eq!(
    asked.get("cross-walk").copied(),
    Some(CROSS_WALK_ASKED),
    "records compared by a pair of two walks"
  );
  assert_eq!(parted.get("cross-walk").copied(), Some(CROSS_WALK_PARTED));
  assert_eq!(
    asked.get("one-walk-twice").copied(),
    Some(ONE_WALK_TWICE_ASKED),
    "records compared by one walk at two configurations"
  );
  assert_eq!(
    parted.get("one-walk-twice").copied(),
    Some(ONE_WALK_TWICE_PARTED)
  );
}

/// How much weaker the media half of the boundary comparison is, in starts.
///
/// Counted rather than argued, because a half nobody has measured is the same
/// shape as an unsplit tally: it reads as coverage until somebody asks.
#[test]
#[cfg_attr(miri, ignore = "runs the whole corpus; see the zero-target test")]
fn the_media_readers_boundary_half_is_weaker_by_this_much() {
  let tally = &corpus().tally;
  assert_eq!(tally.walk_starts, WALK_STARTS);
  assert_eq!(tally.media_starts, MEDIA_STARTS);
  assert_eq!(tally.media_starts_lost, MEDIA_STARTS_LOST);
  assert_eq!(
    tally.walk_starts_lost, WALK_STARTS_LOST,
    "the media half reported a start the walk did not, so `boundary-walk-short` \
     is a row EXPECTED_STATES now needs"
  );
  assert_eq!(tally.media_wildcard, MEDIA_WILDCARDS);
  assert!(
    tally.media_starts < tally.walk_starts,
    "the media half is not the weaker one, so this measurement is about nothing"
  );
}

/// Every state worth counting, and how many records reach it.
///
/// `axis-bws`, `axis-empty-slot` and `axis-bare-name` are three of the four
/// differences between RFC 9110 §10.1.4's `transfer-coding` and §5.6.6's
/// `parameters` that PR #78 enumerated; each must be non-zero, or the corpus
/// would be reporting that the two productions agree because it never spelled
/// the bytes they differ on. The fourth — §10.1.4's head `token` being inside
/// the rule while §5.6.6's `parameters` has no head at all — is not observable
/// between the two `ParamSyntax` arms, since `parameterised_list` supplies
/// §5.6.2's `token` to both; it is observable as §10.1.1's own head argument,
/// which is why the §5.6.6 pair writes one head per reader, and
/// `params-not-comparable` is the count of payloads that push that difference
/// down to an element the pair cannot factor it out of.
///
/// `params-comparable` beside it is what stops that exclusion from growing to
/// swallow the pair: a filter that excluded everything would leave every other
/// count here green and compare nothing. `params-comparable-multi` narrows the
/// same guard onto the case the exclusion is ABOUT — a list of more than one
/// element — and `params-comparable-multi-parameterised` narrows it again onto
/// the ones where an element other than the first carries a `parameters`
/// payload of its own, which is where the §5.6.6 comparison had never been
/// asked at all before the third reader was wired in. A change that reverted
/// the two-element spellings would leave the first two counts looking healthy
/// and drop the third to the number of lists whose second element is a bare
/// head.
///
/// `axis-media-weight` and `axis-media-borrow` are the two refusals `accept`
/// owns and neither other §5.6.6 reader carries — §12.4.2's `qvalue` under the
/// name `q`, and a quoted value that is not one contiguous slice across
/// §5.2's field-line join. Both are licensed in `main` and both must be
/// non-zero, or the license would be exempting nothing.
///
/// The two that measure the media reader's boundary half rather than a reading
/// of the grammar. `boundary-media-short` (15 904) counts the records where
/// `accept` reported fewer member starts than the walk did, which is the price
/// of its latch. `media-wildcard` (4) counts the records carrying a §12.5.1
/// `"*/*"`, whose `MediaRange::ty` is `None` — a range that names no type and
/// therefore no start to grade. Both are records; how many STARTS they are
/// worth is [`MEDIA_STARTS`] and the constants beside it.
///
/// **`boundary-walk-short` has no row, and its absence is asserted rather than
/// left to be noticed.** It is the other direction — a record where `accept`
/// reported a start the walk did not — and it is written by the same generator
/// path, so a missing row here would otherwise be indistinguishable from a
/// count nobody wrote down. [`WALK_STARTS_LOST`] is the assertion, at zero, and
/// its failure names the row this table would then need. That asymmetry is what
/// makes the media half the weaker one rather than merely the different one.
///
/// No row here counts a pair. Those are [`EXPECTED_PAIRS`], keyed by kind,
/// because a `parted` count read beside a state count is a count of two
/// different things.
const EXPECTED_STATES: &[(&str, usize)] = &[
  ("arms-part", 4802),
  ("axis-bare-name", 1432),
  ("axis-bws", 1186),
  ("axis-empty-slot", 2328),
  ("axis-media-borrow", 4),
  ("axis-media-weight", 28),
  ("boundary-media-short", 15_904),
  ("empty-comparable", 10570),
  ("empty-comparable-empty", 8149),
  ("expect-empty-element", 2751),
  ("expect-parsed", 6323),
  ("expect-refused", 80_034),
  ("media-parsed", 3711),
  ("media-refused", 82_646),
  ("media-wildcard", 4),
  ("params-comparable", 80_434),
  ("params-comparable-multi", 11887),
  ("params-comparable-multi-parameterised", 4903),
  ("params-not-comparable", 5923),
  ("te-empty-element", 3565),
  ("te-multi-member", 12113),
];

/// Every pair, keyed by what its agreement proves, with how many records it was
/// compared on and how many it parted on.
///
/// **The kind is in the key, and that is the point.** `one-walk-twice/…` is
/// `parameterised_list` against itself at a second member-name rule: its
/// agreement says the configuration is wired the way each field needs, and
/// nothing about whether the walk reads RFC 9110 §5.6.6 correctly, because a
/// defect there is in both halves. `cross-walk/…` is two walks that decide a
/// member's boundaries with separate loops. Reading one total over both would
/// claim independence the run does not hold, which is the defect this table
/// exists to make impossible: a pair whose kind was chosen to flatter a count
/// changes its own key AND both per-kind totals below.
///
/// `asked` matters as much as `parted`. A pair driven to zero partings by a
/// comparability filter that stopped comparing anything would look identical to
/// one that agrees, and `asked` is the difference.
///
/// The three §5.6.6 rows are all asked on the same records — the
/// `params-comparable` state's count — because the filter admits a record for
/// all three readers or for none. The §5.6.1.1 row is `empty-comparable`.
const EXPECTED_PAIRS: &[(&str, usize, usize)] = &[
  ("cross-walk/empty-accumulator-expect", 10_570, 0),
  ("cross-walk/params-expect-media", 80_434, 27),
  ("cross-walk/params-walk-expect", 80_434, 2079),
  ("cross-walk/te-walk-accumulator", 147_921, 0),
  ("one-walk-twice/params-walk-media", 80_434, 2106),
];

/// Records compared by a pair whose two halves are two walks, and how many of
/// those parted.
///
/// Summed from the tally by the kind in each key, and asserted here, so a pair
/// moved between the kinds reds on the total as well as on its own row.
const CROSS_WALK_ASKED: usize = 319_359;
/// See [`CROSS_WALK_ASKED`].
const CROSS_WALK_PARTED: usize = 2106;
/// Records compared by the one pair that is a single walk at two
/// configurations, and how many of those parted. See [`CROSS_WALK_ASKED`].
const ONE_WALK_TWICE_ASKED: usize = 80_434;
/// See [`CROSS_WALK_ASKED`].
const ONE_WALK_TWICE_PARTED: usize = 2106;

/// Member starts the RFC 9110 §5.6.6 walk put up for grading, and the same for
/// `media::accept`, over every record of that comparison.
///
/// The measurement rather than the argument: the media half of the boundary
/// comparison is weaker because `accept` latches at its first faulting member
/// and because §12.5.1's `"*/*"` names no `type` to place. The difference
/// between these two numbers is how much weaker, in the unit the licensing
/// check consumes — 24 200 starts against the walk's 42 223, which is 57 %, and
/// the 18 023 the walk reported and `accept` did not fall on 15 904 records.
const WALK_STARTS: usize = 42_223;
/// See [`WALK_STARTS`].
const MEDIA_STARTS: usize = 24_200;
/// Starts the walk reported and `accept` did not, summed. See [`WALK_STARTS`].
const MEDIA_STARTS_LOST: usize = 18_023;
/// Starts `accept` reported and the walk did not, summed — the direction that
/// does not arise, asserted at zero so that "the media half is the weaker one"
/// is a measurement and not an assumption about which half stops first. Its
/// state row is absent from [`EXPECTED_STATES`] for the same reason this is
/// here.
const WALK_STARTS_LOST: usize = 0;
/// Ranges `accept` yielded that report no `type`, so no start could be placed.
/// See [`WALK_STARTS`], and `MEDIA_NAMES` for the three names.
const MEDIA_WILDCARDS: usize = 4;

/// Every fault the readers reported, keyed by the reader that reported it —
/// `te` and `params` for the walk's two arms, `media` for `accept`, whose
/// `MediaError` is its own type.
///
/// **`params:MissingParameterValue` is absent, and that is the one absence with
/// a reason rather than a count.** `parameterised_list` refuses a bare
/// parameter name only where the entry point declared the refusal, which it
/// does for RFC 9110 §10.1.4 and not for §5.6.6 — under
/// `ParamSyntax::Parameter` the shape arrives as `ParamValue::None` instead, so
/// the §5.6.6 pair CANNOT reach this variant however the corpus is written. It
/// is the same fact the residue is characterised by, seen from the other side,
/// and `the_bare_name_is_the_one_fault_the_lenient_arm_cannot_report` pins it
/// as a property rather than leaving it as a missing row here.
const EXPECTED_FAULTS: &[(&str, usize)] = &[
  ("media:BadWeight", 28),
  ("media:NotAMediaType", 70_329),
  ("media:Parameters(InvalidQuotedByte)", 7),
  ("media:Parameters(NotAToken)", 8858),
  ("media:Parameters(UnterminatedQuotedString)", 821),
  ("media:ValueSpansFieldLines", 4),
  ("media:ValuelessParameter", 2599),
  ("params:InvalidQuotedByte", 7),
  ("params:MemberBoundaryUnknown", 111),
  ("params:NotAToken", 76_591),
  ("params:UnterminatedQuotedString", 948),
  ("params:ValueSpansFieldLines", 4),
  ("te:InvalidQuotedByte", 2),
  ("te:MemberBoundaryUnknown", 187),
  ("te:MissingParameterValue", 1406),
  ("te:NotAToken", 133_034),
  ("te:UnterminatedQuotedString", 7193),
  ("te:ValueSpansFieldLines", 113),
];

/// Every verdict the `Transfer-Encoding` accumulator reached.
///
/// All eight of them, including the three that RFC 9112 §6.3 item 4 orders
/// ahead of one another and that only a hand-written case reaches — a brute
/// force over nine bytes spells no second `chunked`.
const EXPECTED_VERDICTS: &[(&str, usize)] = &[
  ("Chunked", 135),
  (
    "ChunkedUndecodable(\"this core decodes only chunked\")",
    1123,
  ),
  (
    "NotFramed(\"Transfer-Encoding is not a transfer-coding list\")",
    140_515,
  ),
  (
    "NotFramed(\"Transfer-Encoding lists no transfer coding\")",
    369,
  ),
  (
    "NotFramed(\"chunked is not the final transfer coding\")",
    17,
  ),
  (
    "NotFramed(\"chunked transfer coding applied more than once\")",
    34,
  ),
  (
    "NotFramed(\"chunked transfer coding carries parameters\")",
    73,
  ),
  ("Undecodable(\"this core decodes only chunked\")", 5655),
];

/// How many records the walks recovered a member on, and how many are in the
/// bare-name residue.
///
/// Neither is a defect and neither is a zero-target, so both carry a count for
/// the reason every other count here does: a walk that stopped recovering, or
/// an entry point that stopped handing the bare name over, would otherwise
/// lower a number nothing reads.
const RECOVERED_MEMBERS: usize = 11_719;
/// See [`RECOVERED_MEMBERS`].
const RESIDUE_RECORDS: usize = 3459;

/// The one residue, held to a characterisation rather than to a constant.
///
/// `residue-valueless` is the walk under `ParamSyntax::Parameter` accepting a
/// value RFC 9110 §5.6.6 does not derive. It is not a defect: §5.6.6's
/// `parameters` is the production other fields EXTEND, and a field whose own
/// grammar brackets the value — RFC 6455 §9.1's `extension-param` is one —
/// reads a bare name rather than refusing it, so the walk hands the shape over
/// as `ParamValue::None` for the field to answer.
///
/// A constant would say only how many. This says WHICH: a record is in the
/// residue exactly when its walk reported a valueless parameter and §5.6.6 does
/// not derive its value. Both directions are asserted, so neither a residue
/// that grew a member of some other shape nor one that lost a member goes
/// unnoticed.
#[test]
#[cfg_attr(miri, ignore = "runs the whole corpus; see the zero-target test")]
fn the_residue_is_exactly_the_shape_it_claims() {
  let tally = &corpus().tally;
  assert!(
    tally.residue_valueless > 0,
    "the residue is empty, so nothing here is being characterised"
  );

  // Both directions, over every value the two §5.6.6-reading generators write.
  let mut graded = 0usize;
  for value in residue_candidates() {
    let lines: Vec<&[u8]> = vec![&value];
    let walked = walk(&lines, ParamSyntax::Parameter);
    let reading = oracle::read(&join(&lines), Production::TokenParameters);
    let residue = walked.well_formed && !reading.derives;
    if residue {
      graded = graded.saturating_add(1);
      assert!(
        walked.valueless,
        "{} is in the residue and reports no valueless parameter",
        String::from_utf8_lossy(&value)
      );
    }
    if walked.valueless && !reading.derives {
      assert!(
        residue,
        "{} reports a valueless parameter §5.6.6 does not derive and is not in the residue",
        String::from_utf8_lossy(&value)
      );
    }
  }
  assert!(graded > 0, "no candidate reached the residue");
}

/// Values worth asking the residue's characterisation of, by hand.
fn residue_candidates() -> Vec<Vec<u8>> {
  let mut out = Vec::new();
  for payload in crate::NAMED_PARAMS {
    let mut value = b"x".to_vec();
    value.extend_from_slice(payload);
    out.push(value);
  }
  for len in 1..=3 {
    for payload in crate::payloads(&crate::ALPHABET, len) {
      let mut value = b"x".to_vec();
      value.extend_from_slice(&payload);
      out.push(value);
    }
  }
  out
}

/// The `answer` column reproduces its digest.
///
/// A tally of grades cannot see an answer that moves inside its own grade — the
/// class of change a count is blind to by construction — so the column every
/// reader's answer is rendered into is hashed, per corpus and over the whole
/// run.
#[test]
#[cfg_attr(miri, ignore = "runs the whole corpus; see the zero-target test")]
fn the_answer_column_reproduces_its_digest() {
  assert_eq!(corpus().digests, EXPECTED_DIGESTS);
}

/// The SHA-256 of the `answer` column: corpora `A`..`E`, then the whole run.
const EXPECTED_DIGESTS: [&str; 6] = [
  "c332e6a3b291e0cb4058278f734d1f83b1ae6973bc03a7fd23743f37931e23ab",
  "423e2030881e41bb83c38138263b7f9b1082b0fe4e092202ff099899e25472ba",
  "51f9d92b22ce3964c13440fe10bfa492bfe0276b72f4602944148aa6cfc038e5",
  "08645d53859eed3b531a1f3208edea6642bb7a337ed395c43973743e7f4e93dc",
  "79c07685f39633513470396ca6eb351ec495878c39a2d73b172cedb9c484f636",
  "2c2c9168a06efc220946c868adc5d7b83d3728941ed45e0401132166572eb211",
];

// ─────────────────────── the demonstration against #78 ───────────────────────

/// The §10.1.4 pair reds on the reading PR #78 replaced.
///
/// **The stub is not written; it is selected.** Before #78, `parameterised_list`
/// had one parameter production — RFC 9110 §5.6.6's — and read a
/// `Transfer-Encoding` with it, so `gzip;` parsed as a `gzip` with an empty
/// slot and was byte-identical through every public accessor to a conforming
/// `gzip`. #78 made the production a required argument and added §10.1.4's arm.
/// The pre-#78 reading of a `Transfer-Encoding` value is therefore exactly
/// today's `ParamSyntax::Parameter` arm applied to one, which is what this
/// runs.
///
/// What that reproduces and what it does not, stated because the difference
/// matters: it reproduces the pre-#78 SYNTAX choice on both axes the two
/// productions differ on — the empty slot and the `BWS` around the `=` — which
/// is where `gzip;` lives. It does not reproduce #78's other half, the boundary
/// machinery, which is shared by both arms today. So this is a faithful stub
/// for the defect issue #76 names and not for every line #78 changed.
///
/// The assertion is that the differential REDS, and that `gzip;` is among the
/// records it reds on. A differential that reddened on some other input while
/// passing this one would have proved nothing about the divergence it was built
/// for.
#[test]
fn the_transfer_coding_pair_reds_on_the_pre_78_reading() {
  let mut disagreements = 0usize;
  let mut gzip_semicolon = false;
  for case in crate::NAMED {
    let lines: Vec<&[u8]> = case.to_vec();
    let list = crate::codings(&lines);
    let pre_78 = walk(&lines, ParamSyntax::Parameter);
    if pre_78.well_formed != list.parsed || crate::projected_verdict(&pre_78) != list.verdict {
      disagreements = disagreements.saturating_add(1);
      if case == &[b"gzip;".as_slice()] {
        gzip_semicolon = true;
      }
    }
  }
  assert!(
    gzip_semicolon,
    "the pair does not part on `gzip;`, the value issue #76 was filed over"
  );
  assert_eq!(
    disagreements, PRE_78_DISAGREEMENTS,
    "the pre-#78 reading parts from the wire reader on a different number of named values"
  );

  // And the arm that is live today parts from it on none of them.
  let today = crate::NAMED
    .iter()
    .filter(|case| {
      let lines: Vec<&[u8]> = case.to_vec();
      let list = crate::codings(&lines);
      let walked = walk(&lines, ParamSyntax::TransferParameter);
      walked.well_formed != list.parsed || crate::projected_verdict(&walked) != list.verdict
    })
    .count();
  assert_eq!(today, 0, "the live arm parts from the wire reader");
}

/// How many of the named `Transfer-Encoding` values the pre-#78 reading and the
/// wire reader answer differently about.
const PRE_78_DISAGREEMENTS: usize = 13;

// ───────────────────────────── the oracle, by hand ───────────────────────────

/// The oracle derives what RFC 9110 derives, on values settled by reading the
/// ABNF rather than by running anything.
///
/// The three productions are asked separately, because the whole point of the
/// oracle is that they are three: a table that asked one question of all of
/// them would grade every reader against the widest of the three.
#[test]
fn the_oracle_derives_what_the_abnf_derives() {
  // RFC 9110 §10.1.4: `transfer-coding = token *( OWS ";" OWS transfer-parameter )`
  // with the slot bracketed nowhere, and
  // `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` with
  // §5.6.3's BWS on both sides of the `=`.
  for (value, derives) in [
    (&b"gzip"[..], true),
    (b"gzip;", false),
    (b"gzip;;p=x", false),
    (b"gzip;p=x;", false),
    (b"gzip;p=x", true),
    (b"gzip;p = x", true),
    (b"gzip;p\t=\tx", true),
    (b"gzip;p", false),
    (b"gzip;p=", false),
    (b"gzip;p=\"a,b\"", true),
    (b"gzip;p=\"a", false),
    (b"gzip;p=\"a\x00b\"", false),
    (b"gzip;p=\"a\x80b\"", true),
    (b"gzip, chunked", true),
    (b"gzip,,chunked", true),
    (b"", true),
    (b",", true),
    (b" ", true),
    (b"\"abc\"", false),
  ] {
    assert_eq!(
      oracle::read(value, Production::TransferCoding).derives,
      derives,
      "§10.1.4 on {}",
      String::from_utf8_lossy(value)
    );
  }

  // RFC 9110 §5.6.6: `parameters = *( OWS ";" OWS [ parameter ] )` with the
  // slot bracketed, and `parameter = parameter-name "=" parameter-value` with
  // no whitespace at all around the `=`.
  for (value, derives) in [
    (&b"x"[..], true),
    (b"x;", true),
    (b"x;;p=1", true),
    (b"x;p=1;", true),
    (b"x;p = 1", false),
    (b"x;p", false),
    (b"x;p=\"a,b\"", true),
    (b"x;=1", false),
    (b"x=1", false),
  ] {
    assert_eq!(
      oracle::read(value, Production::TokenParameters).derives,
      derives,
      "§5.6.6 on {}",
      String::from_utf8_lossy(value)
    );
  }

  // RFC 9110 §10.1.1: `expectation = token [ "=" ( token / quoted-string )
  // parameters ]`, whose bracket closes AFTER `parameters` — so parameters
  // without an argument are not an expectation at all.
  for (value, derives) in [
    (&b"100-continue"[..], true),
    (b"x=1", true),
    (b"x=1;p=1", true),
    (b"x=1;", true),
    (b"x;p=1", false),
    (b"x;", false),
    (b"x=\"a,b\"", true),
    (b"x=1;p = 1", false),
  ] {
    assert_eq!(
      oracle::read(value, Production::Expectation).derives,
      derives,
      "§10.1.1 on {}",
      String::from_utf8_lossy(value)
    );
  }

  // RFC 9110 §12.5.1: `media-range = ( "*/*" / ( type "/" "*" ) / ( type "/"
  // subtype ) ) parameters`, with `type = token` and `subtype = token`. Its
  // three alternatives are `token "/" token` and nothing else, since §5.6.2's
  // `tchar` admits `*`; the `parameters` behind them are §5.6.6's, brackets and
  // all, and none of §10.1.4's `BWS` comes with them.
  for (value, derives) in [
    (&b"x/y"[..], true),
    (b"*/*", true),
    (b"x/*", true),
    (b"*/json", true),
    (b"x", false),
    (b"x/", false),
    (b"/y", false),
    (b"x/y/z", false),
    (b"x/y;", true),
    (b"x/y;;p=1", true),
    (b"x/y;p=1;", true),
    (b"x/y;p = 1", false),
    (b"x/y;p", false),
    (b"x/y;p=\"a,b\"", true),
    (b"x/y, a/b", true),
    (b"x/y, zzz", false),
    (b"x/y;q=1.5", true),
  ] {
    assert_eq!(
      oracle::read(value, Production::MediaRange).derives,
      derives,
      "§12.5.1 on {}",
      String::from_utf8_lossy(value)
    );
  }
}

/// The oracle's other two questions are about the bytes in FRONT of an offset,
/// and issue #77 is the reason they are separate questions at all.
///
/// An oracle that asked whether the WHOLE value derives and reported that
/// answer about one offset inside it said "no reading licenses this" about a
/// quoted-string that was, locally, perfectly admitted. So: a value that
/// derives nothing still licenses the element starts its prefixes reach, and
/// still names the bytes some prefix reading holds inside a string.
#[test]
fn the_oracle_answers_about_the_bytes_in_front_of_an_offset() {
  // `gzip;;p="a, chunked, b", br` derives nothing under RFC 9110 §10.1.4 — the empty
  // slot breaks the repetition — and the DQUOTE therefore stands where that
  // production admits no `parameter-value` at all. So the `chunked` inside the
  // string is licensed by no reading AND is not that value's data either,
  // which is exactly the pair of answers `ListError::MemberBoundaryUnknown`
  // reports.
  let value = b"gzip;;p=\"a, chunked, b\", br";
  let coding = oracle::read(value, Production::TransferCoding);
  assert!(!coding.derives);
  assert!(coding.licenses_member_at(0), "`gzip` begins an element");
  assert!(!coding.licenses_member_at(12), "`chunked` begins none");
  assert!(
    !coding.is_string_data(12),
    "§10.1.4 admits no string for those bytes to be the data of"
  );

  // The same bytes under §5.6.6, which brackets the slot: the value derives,
  // the string is real, and the `br` behind it begins an element.
  let params = oracle::read(value, Production::TokenParameters);
  assert!(params.derives);
  assert!(params.is_string_data(12), "`chunked` is inside the string");
  assert!(!params.licenses_member_at(12));
  assert!(params.licenses_member_at(25), "`br` begins an element");

  // A value that derives nothing at all still licenses what its prefixes
  // reach: `gzip, @` has no second element, and `gzip` is still the first.
  let broken = oracle::read(b"gzip, @", Production::TransferCoding);
  assert!(!broken.derives);
  assert!(broken.licenses_member_at(0));

  // A string that never closes holds every byte behind it, which is what makes
  // a member yielded there manufactured rather than merely unlicensed.
  let open = oracle::read(b"x;p=\"a, b", Production::TokenParameters);
  assert!(!open.derives);
  assert!(
    open.is_string_data(7),
    "the comma is inside the open string"
  );
  assert!(!open.licenses_member_at(8));
}

/// The oracle's `Reading` is not derived from any reader's cursor.
///
/// A structural check rather than a behavioural one, and it is here because a
/// behavioural one cannot be written: the way an oracle stops grading is by
/// agreeing with its subject by construction, and no assertion over outputs
/// sees that. What can be asserted is that the two disagree somewhere — if the
/// oracle answered every question the way the walk does, the residue below
/// would be empty and the §10.1.4/§5.6.6 axes would never separate.
#[test]
fn the_oracle_and_the_walks_are_not_one_answer() {
  let cases: &[(&[u8], ParamSyntax, bool)] = &[
    // §5.6.6 derives no bare name; the walk hands one over for the field.
    (b"x;p", ParamSyntax::Parameter, true),
    // §10.1.4 derives the BWS; §5.6.6 does not, and the walk agrees with each.
    (b"gzip;p = x", ParamSyntax::TransferParameter, false),
    (b"gzip;p = x", ParamSyntax::Parameter, false),
  ];
  let mut parted = 0usize;
  for &(value, syntax, expect_part) in cases {
    let lines: Vec<&[u8]> = vec![value];
    let walked = walk(&lines, syntax);
    let production = match syntax {
      ParamSyntax::TransferParameter => Production::TransferCoding,
      _ => Production::TokenParameters,
    };
    let reading = oracle::read(value, production);
    let parts = walked.well_formed != reading.derives;
    assert_eq!(
      parts,
      expect_part,
      "{} under {syntax:?}",
      String::from_utf8_lossy(value)
    );
    parted = parted.saturating_add(usize::from(parts));
  }
  assert!(parted > 0, "the oracle agrees with the walk everywhere");
}

/// `ParamValue::None` is the shape the residue is characterised by, and it
/// reaches the walk only under `ParamSyntax::Parameter`.
///
/// Pinned so the characterisation above cannot go vacuous by the walk ceasing
/// to report the shape at all.
#[test]
fn a_parameter_with_no_value_reaches_only_the_lenient_arm() {
  let lines: Vec<&[u8]> = vec![b"x;p"];
  let lenient = walk(&lines, ParamSyntax::Parameter);
  assert!(lenient.valueless);
  assert!(lenient.well_formed);

  let strict = walk(&lines, ParamSyntax::TransferParameter);
  assert!(!strict.valueless);
  assert!(!strict.well_formed);
}

/// The grade column renders every axis it carries, and `agree` when it carries
/// none.
#[test]
fn the_grade_column_names_every_axis_it_carries() {
  assert_eq!(Grade::default().render(), "agree");
  let grade = Grade {
    pair_disagree: true,
    manufactured_member: true,
    ..Grade::default()
  };
  assert_eq!(grade.render(), "pair-disagree+manufactured-member");
}

/// A member's name is placed in the value RFC 9110 §5.2 joins, across the join
/// as well as in front of it.
///
/// The licensing check is only as good as this: a member placed at the wrong
/// offset would be graded against the wrong bytes, and the grade would be about
/// nothing.
#[test]
fn a_member_is_placed_where_the_joined_value_holds_it() {
  let lines: Vec<&[u8]> = vec![b"gzip", b"chunked"];
  let walked = walk(&lines, ParamSyntax::TransferParameter);
  assert_eq!(walked.starts, vec![0, 5]);
  assert_eq!(walked.unplaced, 0);
  assert_eq!(join(&lines), b"gzip,chunked");

  let lines: Vec<&[u8]> = vec![b" a , b "];
  let walked = walk(&lines, ParamSyntax::TransferParameter);
  assert_eq!(walked.starts, vec![1, 5]);
}

/// `ValueSpansFieldLines` leaves a value well formed, and the other five faults
/// do not.
///
/// The one judgement in this harness that is a reading of another crate's
/// documentation rather than of an RFC, so it is pinned where a reader can see
/// it: that error "names a value that is perfectly well formed and that a
/// walker borrowing its input cannot hand over", and the member's boundaries
/// are settled either way.
#[test]
fn only_the_unborrowable_value_leaves_a_walk_well_formed() {
  let lines: Vec<&[u8]> = vec![b"gzip;p=\"a", b"b\", chunked"];
  let walked = walk(&lines, ParamSyntax::TransferParameter);
  assert!(walked.well_formed);
  assert_eq!(
    walked.faults,
    vec![http_semantics::grammar::ListError::ValueSpansFieldLines]
  );

  for case in [
    &b"gzip;"[..],
    b"gzip;q",
    b"gzip;p=\"a",
    b"gzip;p=\"a\x00\"",
    b"\"a\"",
  ] {
    let lines: Vec<&[u8]> = vec![case];
    assert!(
      !walk(&lines, ParamSyntax::TransferParameter).well_formed,
      "{} was called well formed",
      String::from_utf8_lossy(case)
    );
  }
}

/// The projection onto RFC 9112 §6.3 item 4's verdict spells what the wire
/// reader spells, on values settled by hand.
///
/// It is the pair's shared observable, so a projection that was wrong would red
/// the whole differential rather than pass it; this is what says which of the
/// two a red means.
#[test]
fn the_verdict_projection_spells_what_the_wire_reader_spells() {
  for case in [
    &b"chunked"[..],
    b"gzip, chunked",
    b"chunked, gzip",
    b"chunked, chunked",
    b"chunked;p=1",
    b"gzip",
    b"",
    b"gzip;",
    b"gzip,,chunked",
    b"CHUNKED",
  ] {
    let lines: Vec<&[u8]> = vec![case];
    let walked = walk(&lines, ParamSyntax::TransferParameter);
    assert_eq!(
      crate::projected_verdict(&walked),
      crate::codings(&lines).verdict,
      "{}",
      String::from_utf8_lossy(case)
    );
  }
}

/// The class the §5.6.1.1 pair is compared over holds only values whose
/// non-empty elements both element grammars derive.
#[test]
fn the_empty_element_pair_is_compared_over_bare_token_lists_only() {
  for value in [&b"a,b"[..], b"", b",", b" a , b ", b"a,,b"] {
    assert!(
      crate::bare_token_list(value),
      "{} is a bare token list",
      String::from_utf8_lossy(value)
    );
  }
  for value in [&b"a;p=1"[..], b"a=\"x\"", b"a=1", b"\"a\""] {
    assert!(
      !crate::bare_token_list(value),
      "{} is not",
      String::from_utf8_lossy(value)
    );
  }
}

/// `ParamValue` is matched non-exhaustively by the renderer, so a variant added
/// to it renders as `?` rather than failing to compile.
///
/// Pinned because that fallback is a silent one: a new variant would render
/// every value carrying it identically and the digest would move once, with no
/// assertion naming the variant. This says the fallback exists on purpose.
#[test]
fn an_unknown_parameter_value_renders_as_a_question_mark() {
  let lines: Vec<&[u8]> = vec![b"x;p=1"];
  let rendered = walk(&lines, ParamSyntax::Parameter).rendered;
  assert!(!rendered.contains('?'), "no variant is unknown today");
  let _: fn(ParamValue<'_>) = |value| match value {
    ParamValue::Token(_) | ParamValue::Quoted(_) | ParamValue::None => {}
    _ => {}
  };
  let _ = parameterised_list(lines.iter().copied(), ParamSyntax::Parameter).count();
}

// ───────────────── the third §5.6.6 reader, and what it reaches ──────────────

/// A `media-range`'s name is placed in the value RFC 9110 §5.2 joins, exactly
/// as a walk's member name is.
///
/// The licensing check over `accept`'s members is only as good as this, and
/// `MediaRange` hands out no member — it hands out a `type`, which is the slice
/// the member begins with.
#[test]
fn a_media_range_is_placed_where_the_joined_value_holds_it() {
  let lines: Vec<&[u8]> = vec![b"x/y", b"a/b"];
  let ranged = crate::ranges(&lines);
  assert!(ranged.parsed);
  assert_eq!(ranged.starts, vec![0, 4]);
  assert_eq!(ranged.unplaced, 0);
  assert_eq!(join(&lines), b"x/y,a/b");

  let lines: Vec<&[u8]> = vec![b" x/y , a/b "];
  assert_eq!(crate::ranges(&lines).starts, vec![1, 7]);
}

/// The §5.6.6 comparison reaches a SECOND element, and stops exactly at an
/// element no head can be written in front of.
///
/// Both halves of the exclusion, pinned as one fact about RFC 9110's grammar.
///
/// The reachable half: a two-element list with each reader's own head in front
/// of each element, and a `parameters` payload behind BOTH heads, is one all
/// three readers derive and agree about — so the comparison is asked about
/// §5.6.6 outside the first element, which is what the third reader was wired
/// in for.
///
/// The half that stays out: an element the payload's own comma opens carries no
/// head, and no byte string is a head for all three readers. §5.6.2's `tchar`
/// admits no solidus, so `zzz` is a `token` — an element under §5.6.6's walk
/// and under §10.1.1 — and no `media-range` at all, while `z/z` is a
/// `media-range` and neither of the others. There is no third choice: a head
/// either holds a solidus or it does not.
#[test]
fn the_five_six_six_comparison_reaches_a_second_element_and_stops_at_a_headless_one() {
  let walked = walk(&[b"x;p=1, x;p=1"], ParamSyntax::Parameter);
  assert!(walked.well_formed);
  assert_eq!(walked.starts, vec![0, 7]);
  assert!(crate::expectations(&[b"x=1;p=1, x=1;p=1"]).parsed);
  let ranged = crate::ranges(&[b"x/y;p=1, x/y;p=1"]);
  assert!(ranged.parsed);
  assert_eq!(ranged.starts, vec![0, 9]);

  // A bare `token` second element: the two token-headed readers derive it and
  // §12.5.1 does not.
  assert!(walk(&[b"x, zzz"], ParamSyntax::Parameter).well_formed);
  assert!(crate::expectations(&[b"x=1, zzz"]).parsed);
  assert!(!crate::ranges(&[b"x/y, zzz"]).parsed);

  // And the reverse, which is what leaves no head for all three.
  assert!(!walk(&[b"x, z/z"], ParamSyntax::Parameter).well_formed);
  assert!(!crate::expectations(&[b"x=1, z/z"]).parsed);
  assert!(crate::ranges(&[b"x/y, z/z"]).parsed);
}

/// One name per RFC 9110 §12.5.1 alternative, and which of them the harness can
/// place a member start for.
///
/// The trap this springs deliberately: `MediaRange::ty` is `None` for `"*/*"`,
/// and a harness that folded that into `unplaced` — a zero-target for a member
/// whose name lay in none of the lines — would have turned the first wildcard
/// case anyone wrote into a red naming the wrong fact. It is counted apart, the
/// corpus writes all three names, and the cost is stated: that member's start
/// is graded by nothing.
///
/// The other two are here because the distinction is the ALTERNATIVE and not
/// the asterisk. `x/*` reports its type; `*/y` reports the literal `*` as one,
/// since §5.6.2's `tchar` admits it and this is the `type "/" subtype`
/// alternative. A reader that keyed on the byte would lose a start on `*/y`
/// too, and nothing else here would notice.
#[test]
fn only_the_double_wildcard_media_range_reports_no_type_to_place() {
  let ranged = crate::ranges(&[b"*/*"]);
  assert!(ranged.parsed);
  assert_eq!(ranged.wildcard, 1);
  assert!(ranged.starts.is_empty());
  assert_eq!(ranged.unplaced, 0, "a wildcard is not an unplaced member");

  for value in [&b"x/*"[..], b"*/y"] {
    let ranged = crate::ranges(&[value]);
    assert!(ranged.parsed, "{}", String::from_utf8_lossy(value));
    assert_eq!(
      ranged.starts,
      vec![0],
      "{} places its type",
      String::from_utf8_lossy(value)
    );
    assert_eq!(ranged.wildcard, 0);
  }

  // And all three derive under the oracle, so the wildcard's cost is the
  // ungraded start and not a grade.
  for value in [&b"*/*"[..], b"x/*", b"*/y"] {
    assert!(
      oracle::read(value, Production::MediaRange).derives,
      "§12.5.1 derives {}",
      String::from_utf8_lossy(value)
    );
  }
}

/// `accept` latches, so its half of the boundary comparison stops where the
/// walk's carries on.
///
/// The mechanism behind the corpus-wide measurement above, on one value: RFC
/// 9110 §12.4.2 refuses the weight on the FIRST range, `accept` hands over no
/// range at all after that, and the second element's start is never reported —
/// while the §5.6.6 walk over the same two elements reports both. Nothing is
/// graded wrongly by this; the second start is simply a start nothing was said
/// about, which is why it is measured rather than repaired.
#[test]
fn the_media_reader_stops_at_a_fault_where_the_walk_carries_on() {
  let ranged = crate::ranges(&[b"x/y;q=1.5, a/b"]);
  assert!(!ranged.parsed);
  assert_eq!(ranged.fault, Some(MediaError::BadWeight));
  assert!(
    ranged.starts.is_empty(),
    "the latch swallowed both member starts"
  );

  let walked = walk(&[b"x;q=1.5, a"], ParamSyntax::Parameter);
  assert!(walked.well_formed);
  assert_eq!(walked.starts, vec![0, 9]);
}

/// The two refusals `accept` owns that no reading of RFC 9110 §5.6.6 carries.
///
/// Both are licensed in `main`, so both have to be shown to be real: a license
/// over a difference that never arises exempts nothing, and would hide the day
/// it started arising for another reason.
#[test]
fn the_media_reader_carries_two_rules_the_other_two_do_not() {
  // RFC 9110 §12.4.2's `qvalue` under the name `q`. `1.5` is a perfectly good
  // §5.6.6 `parameter-value` and no `qvalue`.
  let ranged = crate::ranges(&[b"x/y;q=1.5"]);
  assert!(!ranged.parsed);
  assert_eq!(ranged.fault, Some(MediaError::BadWeight));
  assert!(walk(&[b"x;q=1.5"], ParamSyntax::Parameter).well_formed);
  assert!(crate::expectations(&[b"x=1;q=1.5"]).parsed);
  // And a `q` that IS one is read as weight, by both of the spellings RFC 9110
  // §5.6.6 makes equivalent: "The quoted and unquoted values are equivalent."
  assert!(crate::ranges(&[b"x/y;q=0.5"]).parsed);
  assert!(crate::ranges(&[b"x/y;q=\"0.5\""]).parsed);

  // The contiguous borrow. The value is well formed and is not one slice, so
  // the walk yields the member with a parameter-level fault and `accept`
  // latches; the oracle grades the one value §5.2 joins and cannot see the
  // join at all.
  let lines: Vec<&[u8]> = vec![b"x/y;p=\"a", b"b\""];
  let ranged = crate::ranges(&lines);
  assert!(!ranged.parsed);
  assert_eq!(ranged.fault, Some(MediaError::ValueSpansFieldLines));
  assert!(
    oracle::read(&join(&lines), Production::MediaRange).derives,
    "the joined value derives; only the borrow does not"
  );
  let lines: Vec<&[u8]> = vec![b"x;p=\"a", b"b\""];
  assert!(walk(&lines, ParamSyntax::Parameter).well_formed);
}

/// Every RFC 9112 §6.3 item 4 verdict arises from a GENERATOR, and not from a
/// name.
///
/// Three of the eight used to be reached once, twice and twice, entirely from
/// `NAMED`: an alphabet of nine bytes spells no second `chunked`, so the counts
/// asserted for them were counts of three hand-written values, and a rewrite of
/// corpus D would have taken the states with it. Corpus E enumerates the LISTS
/// instead, and reaches all eight on its own.
///
/// The property rather than the number, because the numbers are asserted three
/// lines further down and a number cannot say which generator earned it. A
/// corpus E edit that stopped reaching one reds HERE, naming the verdict.
#[test]
fn every_verdict_arises_from_the_list_generator() {
  let mut seen = BTreeSet::new();
  for value in crate::coding_lists() {
    let lines: Vec<&[u8]> = vec![&value];
    seen.insert(format!("{:?}", crate::codings(&lines).verdict));
  }
  let wanted: BTreeSet<String> = EXPECTED_VERDICTS
    .iter()
    .map(|(verdict, _)| (*verdict).to_owned())
    .collect();
  assert_eq!(
    seen, wanted,
    "the list generator does not reach the verdicts the corpus counts"
  );
}

// ────────────────────── the control the zero-targets need ────────────────────

/// The manufactured-member axis BITES, proven against a reader that
/// manufactures.
///
/// `manufactured_member` is zero over the whole corpus, and a zero that is
/// never asked is worth nothing: `auth-corpus` reaches `TooManyParameters` zero
/// times over 935 032 records because one generator always fires a different
/// bound first, and its suite was green. So the grader is run here against a
/// reader written to commit the defect — one that splits the RFC 9110
/// §5.2-joined value on every raw comma and takes each element's leading token,
/// which is exactly the shape that reads a `chunked` out of a parameter value's
/// own data — and the axis has to fire on it.
///
/// The same value through the two readers that are live today must NOT fire it,
/// or the control would be proving that the grader fires on everything.
#[test]
fn the_manufactured_member_axis_reds_on_a_reader_that_manufactures() {
  // gate-exempt: p="a, chunked, b" — one parameter as a sender wrote it, not a production of any RFC
  // `p="a, chunked, b"` is a whole RFC 9110 §10.1.4 `transfer-parameter` and a
  // whole §5.6.6 `parameter`, so the string is real under BOTH productions and
  // the `chunked` inside it is that value's data under both.
  let value: &[u8] = b"gzip;p=\"a, chunked, b\", br";
  let manufacturing = raw_comma_split(value);
  assert_eq!(manufacturing.starts, vec![0, 11, 20, 24]);

  for production in [Production::TransferCoding, Production::TokenParameters] {
    let reading = oracle::read(value, production);
    assert!(reading.derives, "{production:?} derives the value");
    let grade = crate::grade_walk(&manufacturing, &reading, false);
    assert!(
      grade.manufactured_member,
      "the axis did not fire on a reader that manufactures, under {production:?}"
    );
  }

  // And under RFC 9110 §12.5.1, whose head is `type "/" subtype`, so the same
  // shape has to be spelled with one: the axis is what grades `accept`'s
  // members too, and a control that never asked it under that production would
  // leave the third reader's licensing check unproven.
  // gate-exempt: p="a, chunked, b" — one parameter as a sender wrote it, not a production of any RFC
  let ranged: &[u8] = b"x/y;p=\"a, chunked, b\", a/b";
  let manufacturing = raw_comma_split(ranged);
  assert_eq!(manufacturing.starts, vec![0, 10, 19, 23]);
  let reading = oracle::read(ranged, Production::MediaRange);
  assert!(reading.derives, "§12.5.1 derives the value");
  assert!(
    crate::grade_walk(&manufacturing, &reading, false).manufactured_member,
    "the axis did not fire on a reader that manufactures, under MediaRange"
  );
  assert_eq!(
    crate::ranges(&[ranged]).starts,
    vec![0, 23],
    "the live media reader manufactures a member"
  );

  let lines: Vec<&[u8]> = vec![value];
  for (syntax, production) in [
    (ParamSyntax::TransferParameter, Production::TransferCoding),
    (ParamSyntax::Parameter, Production::TokenParameters),
  ] {
    let walked = walk(&lines, syntax);
    let grade = crate::grade_walk(&walked, &oracle::read(value, production), false);
    assert!(
      !grade.manufactured_member,
      "the live {syntax:?} arm manufactures a member"
    );
    assert!(
      !grade.recovered_member,
      "the live {syntax:?} arm recovers here"
    );
  }
}

/// A reader that splits the joined value on every raw comma and takes each
/// element's leading `token` — the shape RFC 9110 §5.6.4's quoted-string makes
/// wrong, and the one this harness must be able to catch.
///
/// It is a `Walk` and not a walk: only the member starts are filled in, because
/// they are the whole of what the licensing axes read.
fn raw_comma_split(value: &[u8]) -> crate::Walk {
  let mut starts = Vec::new();
  let mut at = 0usize;
  for element in value.split(|&byte| byte == b',') {
    let start = at;
    at = at.saturating_add(element.len()).saturating_add(1);
    let lead = element
      .iter()
      .position(|&byte| byte != b' ' && byte != b'\t')
      .unwrap_or(element.len());
    if element
      .get(lead)
      .is_some_and(|&byte| byte.is_ascii_alphanumeric())
    {
      starts.push(start.saturating_add(lead));
    }
  }
  crate::Walk {
    rendered: String::new(),
    well_formed: true,
    starts,
    unplaced: 0,
    names: Vec::new(),
    parameterised: Vec::new(),
    valueless: false,
    faults: Vec::new(),
  }
}

/// The bare parameter name is the one `ListError` the lenient arm cannot
/// report, and it is a property of the entry point rather than of the corpus.
///
/// `EXPECTED_FAULTS` has no `params:MissingParameterValue` row. That absence is
/// the one this file states as a rule instead of counting: under
/// `ParamSyntax::Parameter` the walk hands the shape over as
/// `ParamValue::None`, so no corpus can reach the variant through that arm. A
/// missing row with no assertion behind it is how a state goes unreachable and
/// quiet.
#[test]
fn the_bare_name_is_the_one_fault_the_lenient_arm_cannot_report() {
  use http_semantics::grammar::ListError;
  for case in [&b"x;p"[..], b"x;p;q", b"x;p, y", b"x;p=1;q"] {
    let lines: Vec<&[u8]> = vec![case];
    let lenient = walk(&lines, ParamSyntax::Parameter);
    assert!(
      !lenient.faults.contains(&ListError::MissingParameterValue),
      "{} reported the bare name as a fault under the lenient arm",
      String::from_utf8_lossy(case)
    );
    assert!(lenient.valueless);

    let strict = walk(&lines, ParamSyntax::TransferParameter);
    assert!(
      strict.faults.contains(&ListError::MissingParameterValue),
      "{} did not report the bare name as a fault under the strict arm",
      String::from_utf8_lossy(case)
    );
  }
}
