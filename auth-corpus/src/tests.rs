//! What grades the grader.
//!
//! [`oracle`](crate::oracle) is the only thing in this workspace that says
//! whether an answer from `http_semantics::auth` HID a challenge, and every
//! figure published about these fields is one of its verdicts counted. So an
//! edit making [`Verdict::excused`] fire more often would move records out of
//! `hider-unexcused` into `hider-excused`, lower the very number the module is
//! driven to zero on, and — without this module — no gate would disagree.
//!
//! That is not a hypothetical failure. A classifier here has twice excused
//! inputs it should not have: ten of a shape that was a live defect at the
//! time, and eight whose answer the same commit had just changed. Both times it
//! was an oracle nobody checked.
//!
//! # The four things here
//!
//! - **The oracle's verdicts, derived from RFC 9110 by hand.** Values whose
//!   answer is settled by the grammar rather than by this crate, asserted in
//!   both directions: a challenge no reading excuses, and a conforming value
//!   whose second challenge every reading reaches.
//! - **The record contract the differential relies on.** Five columns, a key,
//!   and an escape that loses nothing — all three claimed in `main`'s doc. The
//!   key is NOT unique, and the exception is pinned as the bounded thing it is
//!   rather than asserted away as a rule, with what it costs a corpus D figure
//!   spelled out both ways in [`D_DISTINCT`].
//! - **The tally, pinned, and the two cells of it that are ZERO.** [`AXIS`] is
//!   an assertion rather than a sentence, so a tree whose answers stop
//!   reproducing it says so from a red gate rather than from a reader's memory;
//!   and [`ZERO_TARGETS`] is what says that two of its classes are not pins at
//!   all but numbers this module is driven to zero on, with the argument for
//!   why the third one — [`UNRESOLVED`] — is a cost rather than a defect.
//! - **The answer column itself, digested.** [`ANSWERS`] and [`WHOLE`] pin the
//!   SHA-256 `cargo run -p xtask -- auth-diff` prints, taken with that driver's
//!   own hash over the same bytes in the same order. A tally of verdicts is
//!   blind by construction to an answer that moves inside its class; a digest
//!   of the answers is blind to nothing, and [`FAULTS`] names the fault whose
//!   count moved for the commonest kind of such a move.
//!
//! # What these tests cannot say
//!
//! - **They cannot say WHICH answer moved.** [`ANSWERS`] localises a move to
//!   one corpus and [`FAULTS`] names a fault whose count changed; naming the
//!   records themselves needs the two revisions
//!   `cargo run -p xtask -- auth-diff` builds, and that is not a per-commit
//!   gate. A digest that moves is an instruction to run it, and the failure
//!   says so.
//! - **They cannot attribute a move in [`AXIS`].** That tally is a function of
//!   the oracle AND of the module under test, so a cell that moved says only
//!   that one of them did. The hand-derived cases above it are what say which.
//!   [`ANSWERS`] is the narrower instrument and does attribute: the `answer`
//!   column is the module's output alone and no verdict of the oracle's reaches
//!   it, so a digest that moves while [`AXIS`] holds is the module, and a cell
//!   of [`AXIS`] that moves while the digests hold is the oracle or [`axis`].
//! - **They cannot rebuild `evidence/auth-before-forbidden-byte`, and no
//!   longer claim to.** [`RECOVERED`] carries what is left of that: the SET of
//!   records that commit moved is still identifiable and its size is asserted,
//!   but the tally it used to reconstruct is gone, because the commit that
//!   closed al8n/wren#77 moved the reader and the oracle at once. That
//!   constant records both halves of the move.
//! - **They cannot grade an input the corpus does not carry.** Corpus F is
//!   hand-shaped and small; these numbers pin the answers over the inputs that
//!   exist, which is not the same as over the inputs that matter. Measured:
//!   replacing one of F's twelve octets with a second spelling of another moves
//!   no count at all, so [`AXIS`] alone cannot see a corpus quietly narrowed —
//!   which is why `a_high_byte_is_the_data_a_forbidden_one_is_not` asserts the
//!   twelve are distinct. The shape no corpus carries at all is named at
//!   `corpus_d`: nothing folds a join comma across the line bound, so the
//!   asymmetry that crossing has is pinned by a unit test in `http-semantics`
//!   and by nothing here.

use std::collections::HashMap;

use super::*;
use crate::{oracle::Verdict, sha256::Sha256};

// ────────────────────────── the oracle, by hand ──────────────────────────────

/// The probe's offset in `value`, the way [`axis`] finds it.
fn probe_at(value: &[u8]) -> usize {
  last_index_of(value, PROBE).expect("the case carries the probe")
}

/// One value whose verdict RFC 9110's grammar settles, and the reading that
/// settles it.
struct Hand {
  value: &'static [u8],
  want: Verdict,
  why: &'static str,
}

#[test]
fn the_oracle_answers_the_readings_the_grammar_admits() {
  // Every row is derived from RFC 9110 §11.6.1's `#challenge` and §5.6.4's
  // `quoted-string` rather than from what this crate answers, and each names
  // the derivation it rests on. A row that has to be edited to make this pass
  // is a finding about the oracle, not a number to bless.
  let cases = [
    Hand {
      value: b"Basic realm=\"a\", Digest realm=z",
      want: Verdict {
        excused: false,
        reached: true,
        derives: true,
      },
      why: "the string closes in front of the comma, so the comma is \
            §5.6.1.2's separator and the probe is the list's second element",
    },
    Hand {
      value: b"Basic realm=\"a\", x=1, Digest realm=z",
      want: Verdict {
        excused: false,
        reached: true,
        derives: true,
      },
      why: "the same, with one more `auth-param` of the first challenge \
            between them — §11.2's one-name-once MUST refuses neither name",
    },
    Hand {
      value: b"Basic realm=\"a, Digest realm=z",
      want: Verdict {
        excused: true,
        reached: false,
        derives: true,
      },
      why: "nothing closes the string, so every byte behind the DQUOTE is \
            that parameter's data and no reading gets past it",
    },
    Hand {
      value: b"Basic realm=\"ab, Digest realm=z, c\"",
      want: Verdict {
        excused: true,
        reached: false,
        derives: true,
      },
      why: "the string closes PAST the probe, which excuses it just as an \
            unclosed one does — the case a control that grades hiders by \
            replacing every DQUOTE cannot see",
    },
    Hand {
      value: b"Basic a=b=c, Digest realm=z",
      want: Verdict {
        excused: false,
        reached: false,
        derives: true,
      },
      why: "no reading derives `a=b=c`: an auth-param's value is one token, \
            so it ends at `b`, and an element may not be followed by `=`; \
            token68 ends at `a=` for the same reason. So no derivation \
            reaches the probe — and none opens a string over it either",
    },
    Hand {
      value: b"Basic realm=\"a\xffb, Digest realm=z",
      want: Verdict {
        excused: true,
        reached: false,
        derives: true,
      },
      why: "`obs-text` IS `qdtext`, so the high byte leaves the string open \
            over the probe exactly as a letter would",
    },
    Hand {
      value: b"Basic realm=\"a\x00b, Digest realm=z",
      want: Verdict {
        excused: false,
        reached: false,
        derives: true,
      },
      why: "the control one byte apart: NUL is neither `qdtext` nor an octet \
            a `quoted-pair` may escape, so NO string opens here and there is \
            no excuse to give",
    },
    Hand {
      value: b"Basic realm=\"a\xffb, Digest realm=zc\"",
      want: Verdict {
        excused: true,
        reached: false,
        derives: false,
      },
      why: "the probe's own bytes end in a DQUOTE no `challenge` admits, so \
            nothing stands at the offset for any reader to hide",
    },
  ];

  for Hand { value, want, why } in cases {
    let got = crate::oracle::read(value, probe_at(value));
    assert_eq!(got, want, "{}: {why}", escape(value));
  }
}

#[test]
fn a_high_byte_is_the_data_a_forbidden_one_is_not() {
  // The `obs-text` pin on the ORACLE's side, over the twelve octets corpus F
  // varies. RFC 9110 §5.6.4 reads
  //
  // ```text
  // qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
  // quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
  // ```
  //
  // so a high byte — bare or escaped — leaves the string open across the
  // probe and excuses it, and an escaped DQUOTE does the same by not closing
  // it. Every other octet here is a CTL other than HTAB, which is neither
  // production: no string opens over the probe at all, and there is nothing to
  // excuse. An oracle that lost this distinction would excuse the very inputs
  // the axis exists to catch.
  let admitted = [
    "obs-text-80",
    "obs-text-ff",
    "escaped-obs-text",
    "escaped-dquote",
  ];

  // A corpus that varies an octet has to VARY it. Measured: replacing
  // `escaped-nul` with a second spelling of bare NUL moves no axis count and
  // no record count, so [`AXIS`] cannot see a corpus quietly narrowed to
  // fewer distinct octets — these two assertions are what can.
  let mut distinct: Vec<&[u8]> = OCTETS.iter().map(|(_, octet)| *octet).collect();
  distinct.sort_unstable();
  distinct.dedup();
  assert_eq!(
    distinct.len(),
    OCTETS.len(),
    "two rows carry the same octet"
  );
  assert_eq!(
    OCTETS
      .iter()
      .filter(|(name, _)| admitted.contains(name))
      .count(),
    admitted.len(),
    "every octet §5.6.4 admits is in the corpus, and each once"
  );

  for (name, octet) in OCTETS {
    let mut value = b"Basic realm=\"a".to_vec();
    value.extend_from_slice(octet);
    value.extend_from_slice(b"b, ");
    value.extend_from_slice(PROBE);
    value.push(b'c');
    let verdict = crate::oracle::read(&value, probe_at(&value));

    assert!(verdict.derives, "{name}: the probe's own bytes derive");
    assert!(!verdict.reached, "{name}: no reading gets past the DQUOTE");
    assert_eq!(
      verdict.excused,
      admitted.contains(&name),
      "{name}: {}",
      escape(&value)
    );
  }
}

// ─────────────────────────── the record contract ─────────────────────────────

/// Every record one corpus generator writes.
///
/// The generators are taken as `fn` pointers rather than called by name so the
/// table below drives all of them through one path; the coercion is what picks
/// `Vec<u8>` for their `impl Write`.
type Generator = fn(&mut Vec<u8>, &mut usize) -> std::io::Result<()>;

/// The ten generators, in the order [`emit`] runs them.
fn generators() -> [(&'static str, Generator); 10] {
  [
    ("A", corpus_a),
    ("B", corpus_b),
    ("C", corpus_c),
    ("D", corpus_d),
    ("E", corpus_e),
    ("F", corpus_f),
    ("G", corpus_g),
    ("H", corpus_h),
    ("I", corpus_i),
    ("J", corpus_j),
  ]
}

/// One generator's records, as lines, with its own count checked against them.
fn records(generator: Generator) -> Vec<String> {
  let mut out = Vec::new();
  let mut count = 0;
  generator(&mut out, &mut count).expect("a `Vec` does not fail to write");
  let text = String::from_utf8(out).expect("every column is printable US-ASCII");
  let lines: Vec<String> = text.lines().map(str::to_owned).collect();
  assert_eq!(lines.len(), count, "the generator counted what it wrote");
  lines
}

/// One record's five columns.
fn columns(line: &str) -> [&str; 5] {
  let mut split = line.split('\t');
  let (Some(corpus), Some(case), Some(spelling), Some(axis), Some(answer)) = (
    split.next(),
    split.next(),
    split.next(),
    split.next(),
    split.next(),
  ) else {
    panic!("a record is not five columns: {line:?}");
  };
  assert!(split.next().is_none(), "a record is six columns: {line:?}");
  [corpus, case, spelling, axis, answer]
}

#[test]
fn the_records_that_share_a_key_are_the_ones_no_mid_can_tell_apart() {
  // The key is NOT unique, whatever `main`'s doc says of it, and the shape of
  // the exception is pinned here rather than left unknown: corpus D varies a
  // head, a MIDDLE and a tail over
  // 0..=18 repeats of the middle, and at ZERO repeats the middle is not in the
  // case at all — so its six spellings collapse onto one input, recorded six
  // times. 4 heads x 8 tails = 32 such inputs, 192 records, 160 of them
  // surplus.
  //
  // Left in rather than deduplicated, deliberately. D's published figures were
  // computed over a corpus with this collapse in it, and [`AXIS`] is worth
  // having because it reproduces them; a generator fixed here would
  // move every one of them and take the reproduction with it. What the surplus
  // costs is stated instead, and pinned both ways in [`D_DISTINCT`]: 25
  // `hider-excused`, 20 `no-probe`, 50 `yields` and 65 `yields-underivable`
  // records in corpus D count one input more than once, so D's tally is 3648
  // records over 3488 distinct inputs.
  //
  // What that costs the figure this module still quotes about corpus D: the
  // NINETY records `evidence/auth-forbidden-byte-refuses` moved carry surplus —
  // five of the ninety were one input written six times — so over distinct
  // inputs that set is 85. [`D_DISTINCT`] asserts it.
  //
  // The differential is unaffected either way: it pairs the two sides by
  // POSITION and checks the keys agree, so a repeated key compares a case with
  // itself.
  let mut counts: HashMap<String, usize> = HashMap::new();
  let mut total = 0;
  for (name, generator) in generators() {
    for line in records(generator) {
      let [corpus, case, spelling, axis, _] = columns(&line);
      assert_eq!(corpus, name, "a record names another corpus: {line:?}");
      assert!(
        matches!(
          axis,
          "-"
            | "no-probe"
            | "yields"
            | "over-yield"
            | "yields-underivable"
            | "hider-excused"
            | "hider-unresolved"
            | "hider-unexcused"
        ),
        "a record grades on no axis this module names: {line:?}"
      );
      *counts
        .entry(format!("{corpus}\t{case}\t{spelling}"))
        .or_default() += 1;
      total += 1;
    }
  }
  assert_eq!(
    total, 935_692,
    "the corpus is the size every figure pinned here counts over"
  );

  let mut shared: Vec<&String> = counts
    .iter()
    .filter(|(_, times)| **times > 1)
    .map(|(key, _)| key)
    .collect();
  shared.sort();
  assert_eq!(shared.len(), 32, "the groups that share a key: {shared:?}");
  assert_eq!(counts.len(), 935_532, "distinct inputs behind the records");
  for key in shared {
    assert_eq!(counts.get(key), Some(&6), "{key}");
    assert!(key.starts_with("D\t"), "outside corpus D: {key}");
    // Two field lines is a head and a tail with no middle between them, which
    // is the whole of the exception: every case with a middle in it carries
    // that middle's bytes and is its own input.
    assert_eq!(
      key
        .split('\t')
        .nth(1)
        .unwrap_or_default()
        .split('|')
        .count(),
      2,
      "a case with a middle in it shares a key: {key}"
    );
  }
}

/// The inverse of [`escape`], for the round trip below.
fn unescape(field: &str) -> Vec<u8> {
  let mut out = Vec::new();
  let mut bytes = field.bytes();
  while let Some(byte) = bytes.next() {
    if byte != b'%' {
      out.push(byte);
      continue;
    }
    let mut hex = String::new();
    hex.push(char::from(bytes.next().expect("an escape is three bytes")));
    hex.push(char::from(bytes.next().expect("an escape is three bytes")));
    out.push(u8::from_str_radix(&hex, 16).expect("an escape is two hex digits"));
  }
  out
}

#[test]
fn the_escape_loses_nothing_and_takes_none_of_the_format_s_bytes() {
  // The `case` column is the only place a record carries the input's own
  // bytes, so a lossy escape would make two different inputs one record — and
  // the differential would then be comparing an input to a different one under
  // the same key. Over all 256 octets and over the separators themselves.
  for byte in 0..=u8::MAX {
    let escaped = escape(&[byte]);
    assert_eq!(unescape(&escaped), vec![byte], "{byte:#04x}");
    for taken in ['\t', '|', '\\', '\n'] {
      assert!(
        !escaped.contains(taken),
        "{byte:#04x} escapes to {escaped}, which carries {taken:?}"
      );
    }
  }

  let every = (0..=u8::MAX).collect::<Vec<u8>>();
  assert_eq!(unescape(&escape(&every)), every);
}

// ──────────────────────── the reproduction, pinned ───────────────────────────

/// One corpus's pinned shape: its name, how many records it writes, its axis
/// tally sorted by verdict, and the challenges and faults its answers hold
/// between them.
type Pinned = (
  &'static str,
  usize,
  &'static [(&'static str, usize)],
  usize,
  usize,
);

/// The axis tally this tree answers with, per corpus, and the challenges and
/// faults its answers hold between them.
///
/// # A reproduction this table used to carry, and no longer does
///
/// Five per-corpus figures were published over this module before there was a
/// committed harness, computed by one that was then deleted — so no digest of
/// theirs can ever be recomputed. This table used to reproduce that tally to the
/// digit, and that agreement was the reason anything downstream of it was worth
/// reading.
///
/// It does not now, and the reason is the point rather than an inconvenience:
/// the classifier those figures were computed with is the one al8n/wren#77
/// found a defect in. [`oracle`](crate::oracle)'s `excused` asked whether the
/// WHOLE value derives, so one malformed element made it answer "no reading
/// licenses this" about a quoted-string RFC 9110 §11.2 admits perfectly well —
/// and the axis therefore could not see the reader cutting such a value in half.
/// A tally taken with a defective classifier is reproduced by reproducing the
/// defect. The move, for the record:
///
/// | published as | this tree |
/// |---|---|
/// | A, `challenges` + tail: 328 hiders, 0 unexcused, 0 over-yields | 338 `hider-excused`, 0, 0 |
/// | B: 444 / 0 / 0 | 720 / 0 / 0 |
/// | C: 2472 / 0 / 0 | 2728 / 0 / 0, and 10 `hider-unresolved` |
/// | D: 485 hiders, 90 unexcused, 16 over-yields | 594 `hider-excused`, 0 unexcused, 0 over-yields, 18 `hider-unresolved` |
/// | E: 75 / 15 / 20 | 100 / 0 / 0, and 15 `hider-unresolved` |
///
/// What is left of the reproduction is the part that can still be checked:
/// [`RECOVERED`] identifies the record set one earlier commit moved and asserts
/// its size, and `the_oracle_answers_the_readings_the_grammar_admits` derives
/// the oracle's verdicts by hand from the RFC rather than from any tally.
///
/// # These numbers are expected to move
///
/// They are a pin, not a target. A change to `http_semantics::auth` that moves
/// an answer moves a cell here, and the point is that it moves in the DIFF —
/// where a reader can ask which cell and why — rather than in a figure nobody
/// can recompute. Re-derive them from a failure's own message.
const AXIS: [Pinned; 10] = [
  (
    "A",
    262_136,
    &[
      ("-", 149_792),
      ("hider-excused", 710),
      ("no-probe", 37_448),
      ("yields", 7_516),
      ("yields-underivable", 66_670),
    ],
    146_010,
    258_401,
  ),
  (
    "B",
    144_448,
    &[
      ("hider-excused", 720),
      ("yields", 14_102),
      ("yields-underivable", 129_626),
    ],
    241_426,
    187_640,
  ),
  (
    "C",
    524_288,
    &[
      ("-", 262_144),
      ("hider-excused", 2_728),
      ("hider-unresolved", 10),
      ("yields", 13_647),
      ("yields-underivable", 245_759),
    ],
    353_697,
    550_241,
  ),
  (
    "D",
    3_648,
    &[
      ("hider-excused", 594),
      ("hider-unresolved", 18),
      ("no-probe", 456),
      ("yields", 801),
      ("yields-underivable", 1_779),
    ],
    9_617,
    8_326,
  ),
  (
    "E",
    320,
    &[
      ("hider-excused", 100),
      ("hider-unresolved", 15),
      ("no-probe", 40),
      ("yields", 75),
      ("yields-underivable", 90),
    ],
    304,
    342,
  ),
  (
    "F",
    192,
    &[
      ("hider-excused", 112),
      ("no-probe", 48),
      ("yields-underivable", 32),
    ],
    64,
    256,
  ),
  (
    "G",
    180,
    &[
      ("hider-excused", 40),
      ("no-probe", 20),
      ("yields", 60),
      ("yields-underivable", 60),
    ],
    259,
    152,
  ),
  (
    "H",
    72,
    &[("hider-excused", 56), ("yields-underivable", 16)],
    16,
    104,
  ),
  (
    "I",
    288,
    &[("hider-excused", 224), ("yields-underivable", 64)],
    64,
    416,
  ),
  (
    "J",
    120,
    &[("hider-excused", 30), ("yields-underivable", 90)],
    240,
    159,
  ),
];

/// The two classes this module is driven to ZERO on, and the one it is not.
///
/// # Why a zero-target rather than a pinned number
///
/// `over-yield` was pinned at 16 for corpus D and 20 for corpus E, and the
/// suite was green over 36 records that each said the reader had handed a
/// caller a challenge built out of a parameter's own data. al8n/wren#77 is what
/// one of those was worth. A metric held at a non-zero constant is a defect
/// somebody decided to keep, and the only honest constant for these two is
/// zero.
///
/// # A zero that was met over a corpus that could not spell the case
///
/// The commit that first drove `over-yield` to zero did so over corpora A..G,
/// and corpus H then answered 24. Every corpus in front of it puts its tail at
/// the recovery cursor itself, so the DQUOTE that hides the probe is always at
/// the value position of the element the cursor is ON — and a check asked only
/// there was green over every one of them while RFC 9110 §11.6.1's OTHER
/// reading of that element, a whole `challenge` opening on the continuation
/// line §5.2's join makes, put its own parameter's DQUOTE at an offset the
/// check never asked about. `corpus_h` is that record. The lesson is corpus G's
/// repeated: a zero-target is only as strong as the shapes the generators can
/// write, so a target met is a claim about the corpus as much as about the
/// reader.
///
/// # And met again over a corpus that could not spell the NEXT case
///
/// Corpus H drove it to zero, and `corpus_i` then answered **128** against the
/// commit that added H. The axis H holds fixed is one byte wide: §5.6.1.2
/// expands its list as `#element => [ element ] *( OWS "," OWS [ element ] )`,
/// and every continuation H writes begins with the element rather than with the
/// `OWS` that comma may carry — so the openers a reader looks for at §5.2's join
/// offset were always AT that offset, and a check that never skipped the
/// whitespace was green over all 72. One space in front of the continuation
/// moves both openers, and the reader crossed the comma inside a `realm`.
///
/// Two families, and both defects lived where the generator could
/// not write. `corpus_i` and `corpus_j` say which axes were being held fixed —
/// the bytes between §5.2's join comma and the element, and the challenges that
/// COMPLETE in front of the one a recovery is behind — and
/// `ows_after_the_join_comma_and_a_challenge_completed_in_front_are_shapes_these_generators_write`
/// asserts that both are still being written.
///
/// `hider-unresolved` is the third class and is NOT zero, because it is not the
/// same kind of thing. Its records are ones where the reader declined to place a
/// boundary and SAID SO — the answer carries `ChallengeBoundaryUnknown`, so RFC
/// 9110 §11.4's user agent knows it has not been shown the whole list. A
/// challenge hidden in silence is the harm; a challenge the caller is told it
/// has not been shown is a cost. The 43 records are three shapes:
///
/// - **10 in corpus C**, `Basic a=","a, Digest realm=z`: the element's value
///   closes and runs on, so the reading that leaves its DQUOTE shut ends the
///   element at the comma INSIDE `","` and the reading that opens it ends the
///   element behind `a`. The two part in front of the probe, which both of them
///   would have reached — the walk cannot certify the earlier comma without
///   cutting a value in half, and cannot certify the later one without hiding
///   the element the earlier reading found.
/// - **18 in corpus D and 15 in corpus E**, the line bound met with a value
///   still OPEN across RFC 9110 §5.2's join: every comma behind that DQUOTE is
///   the value's data in the only reading there is, and the line that would
///   close the string is one `MAX_CHALLENGE_LINES` forbids this reader to hold.
///   That constant already records that it is a refusal which can meet
///   conforming input.
///
/// Driving these to zero needs a different answer to a different question —
/// whether the walk may read a line it may not NAME — and not a change to the
/// boundary rule.
const ZERO_TARGETS: [&str; 2] = ["over-yield", "hider-unexcused"];

/// What `hider-unresolved` costs, per corpus, so that a shape moving in or out
/// of it says so.
const UNRESOLVED: [(&str, usize); 10] = [
  ("A", 0),
  ("B", 0),
  ("C", 10),
  ("D", 18),
  ("E", 15),
  ("F", 0),
  ("G", 0),
  // Corpus H's 32 `ChallengeBoundaryUnknown` answers are all `hider-excused`:
  // the reading that carried the head's value across RFC 9110 §5.2's join
  // covers the probe, so the axis excuses the hiding before it asks whether the
  // caller was told. The notice is there all the same, and
  // `the_notice_that_separates_the_two_classes_is_read_from_the_answer` is what
  // reads it.
  ("H", 0),
  // Corpus I is corpus H with the list's own `OWS` in front of the
  // continuation, and its 128 `ChallengeBoundaryUnknown` answers are excused
  // for the same reason H's 32 are.
  ("I", 0),
  // Corpus J answered 6 here at `e2d72fc`, and answers 0 now: those six values
  // put a bare scheme between the challenge that opened a list and the one
  // refused behind it, and the stale list bit hid a `Digest` every reading
  // agrees on. `PREFIXES` names which rows moved and which must not.
  ("J", 0),
];

/// Corpus A read the three ways `challenges` is called on it.
///
/// Corpus A alone needs this: the figure published for it covers ONE of its
/// spellings — the tail behind a payload — and 328 is that spelling's figure
/// rather than the corpus's 694. Splitting the tally by spelling is what makes
/// the published number the one asserted.
const A_BY_SPELLING: [(&str, &[(&str, usize)]); 3] = [
  ("challenges-bare", &[("no-probe", 37_448)]),
  (
    "challenges-split-scheme",
    &[
      ("hider-excused", 372),
      ("yields", 4_027),
      ("yields-underivable", 33_049),
    ],
  ),
  (
    "challenges-tail",
    &[
      ("hider-excused", 338),
      ("yields", 3_489),
      ("yields-underivable", 33_621),
    ],
  ),
];

/// `(axis, count)` over `lines`, sorted, keeping only the records `keep` takes.
fn tally(lines: &[String], keep: impl Fn(&str) -> bool) -> Vec<(String, usize)> {
  let mut counts: Vec<(String, usize)> = Vec::new();
  for line in lines {
    let [_, _, spelling, axis, _] = columns(line);
    if !keep(spelling) {
      continue;
    }
    match counts.iter_mut().find(|(name, _)| name == axis) {
      Some((_, count)) => *count += 1,
      None => counts.push((axis.to_owned(), 1)),
    }
  }
  counts.sort();
  counts
}

/// How many challenges and how many faults the answers on `lines` hold.
fn answers(lines: &[String]) -> (usize, usize) {
  let mut challenges = 0;
  let mut faults = 0;
  for line in lines {
    let [_, _, _, _, answer] = columns(line);
    challenges += answer.matches("Ok[").count();
    faults += answer.matches("Err(").count();
  }
  (challenges, faults)
}

/// The pinned shape of one corpus, as [`AXIS`] spells it.
fn expected(axis: &[(&str, usize)]) -> Vec<(String, usize)> {
  axis
    .iter()
    .map(|(name, count)| ((*name).to_owned(), *count))
    .collect()
}

#[test]
fn the_axis_this_tree_answers_with_is_the_one_pinned() {
  for ((name, generator), (pinned, size, axis, challenges, faults)) in
    generators().into_iter().zip(AXIS)
  {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let lines = records(generator);
    assert_eq!(lines.len(), size, "corpus {name}: records");
    assert_eq!(
      tally(&lines, |_| true),
      expected(axis),
      "corpus {name}: axis"
    );
    assert_eq!(
      answers(&lines),
      (challenges, faults),
      "corpus {name}: challenges and faults"
    );

    if name == "A" {
      for (spelling, axis) in A_BY_SPELLING {
        assert_eq!(
          tally(&lines, |read| read == spelling),
          expected(axis),
          "corpus A, {spelling}"
        );
      }
    }
  }
}

// ───────────────────── the answer column, digested ───────────────────────────

/// What a moved digest asks for, since it can name the corpus and not the
/// record.
///
/// A pin whose failure reads "these two hashes differ" teaches a reader to
/// paste the new one. This is the message that stands beside every digest here
/// instead.
const MOVED: &str = "an answer moved. `cargo run -p xtask -- auth-diff <base-rev>` \
                     names the records that moved and what moved about each; take the new value \
                     from a run that did that, and say in the commit which moves were intended";

/// The SHA-256 of each corpus's `answer` column, over the same bytes in the
/// same order as `xtask`'s `auth-diff` takes its digest over: each record's
/// answer and the newline behind it.
///
/// # What this catches that [`AXIS`] cannot
///
/// Every move there is. [`AXIS`] counts axis verdicts and the challenges and
/// faults an answer holds, so an edit that renamed a parameter, swapped one
/// fault for another, or changed which bytes a value hands back moves no cell
/// of it — and until this constant nothing in a per-commit gate disagreed. The
/// only instrument that saw such a move was `auth-diff`, which needs two
/// revisions and so cannot run on a commit.
///
/// It is also the narrower attribution. The `answer` column is what
/// `http_semantics::auth` yielded and nothing else; no verdict of
/// [`oracle`](crate::oracle)'s reaches it. So a digest that moves while
/// [`AXIS`] holds is the module — and an [`AXIS`] cell that moves while these
/// hold is [`oracle`](crate::oracle) or [`axis`], since a digest that held over
/// changed inputs is not a thing this corpus can produce.
///
/// # These are expected to move, and are not to be blessed unread
///
/// Like [`AXIS`], a pin and not a target. The difference is that a digest
/// carries no information about WHAT moved, so blessing one is a strictly
/// blind act unless the `auth-diff` run that says what moved was actually made.
/// [`MOVED`] is the failure message for that reason, and it names the command.
const ANSWERS: [(&str, &str); 10] = [
  (
    "A",
    "48bf246fc3d1dae79b38cdc83cd184e90ec1bc4aee3bdd9a30f6a5eb5c5572a1",
  ),
  (
    "B",
    "d6adff583ff40b2fe641ca8d6043c34f81d92aadc19a7eb5d06cd969e6ff2ba3",
  ),
  (
    "C",
    "bcf4f202846d055d578239df6b436ea7cdaaa0f0353017c0720b4fe4a5aac1f8",
  ),
  (
    "D",
    "2b05330f2e8511a72158ff90191fbff21eee1c861f7772aa5cc072bcafeddfb0",
  ),
  (
    "E",
    "a537e56be7d00b764deb803fee30aab8a13aae00b238c204d19852312f7be4ab",
  ),
  (
    "F",
    "82ae70b5e4fb70f36bc31d811dc37fcdfb1f51547613f798d2e3e209bddd3b9c",
  ),
  (
    "G",
    "51cd8fd9763b6468cd246e3d1af4fa0a2544f21bbfa4a7ce6381cd21646e851c",
  ),
  (
    "H",
    "e5850914ec03586717aadc2c9a82cfe663307cee954ebfc0e78076e0cb6fb729",
  ),
  (
    "I",
    "16527a2f9b2f622f5166a5a8e413e5e212fce2fa7a6d2d5b103e1397c0d34c11",
  ),
  (
    "J",
    "ea5363b3129a0162f07232c61847d8757dee77f65c5d51f0755db4d8231b7791",
  ),
];

const WHOLE: &str = "b31bdd693fb019dd40fbb850d5457d2650e44667968c2c11859177e5497fe2dc";

/// Feeds `hash` what `auth-diff` digests: each record's `answer` column and the
/// newline behind it, in record order.
fn feed_answers(lines: &[String], hash: &mut Sha256) {
  for line in lines {
    let [_, _, _, _, answer] = columns(line);
    hash.update(answer.as_bytes());
    hash.update(b"\n");
  }
}

#[test]
fn the_answers_this_tree_gives_are_the_ones_the_differential_digested() {
  let mut whole = Sha256::new();
  for ((name, generator), (pinned, digest)) in generators().into_iter().zip(ANSWERS) {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let lines = records(generator);
    let mut corpus = Sha256::new();
    feed_answers(&lines, &mut corpus);
    feed_answers(&lines, &mut whole);
    assert_eq!(corpus.finish(), digest, "corpus {name}: {MOVED}");
  }
  assert_eq!(whole.finish(), WHOLE, "{MOVED}");
}

/// Every fault name each corpus's answers carry, and how many times.
///
/// [`ANSWERS`] sees a fault swapped for another and cannot say which; this
/// does, and it is the commonest shape of a move inside an axis class. It is
/// also the one table here a reader can check against a run of the corpus
/// without a hash: `auth-corpus | awk` gets the same numbers.
///
/// Its total per corpus is [`AXIS`]'s fault count, asserted below, so a parse
/// that silently dropped a fault reds rather than lowering a row.
const FAULTS: [(&str, &[(&str, usize)]); 10] = [
  (
    "A",
    &[
      ("ChallengeBoundaryUnknown", 16),
      ("MalformedParameter", 185_369),
      ("MalformedScheme", 27_180),
      ("MissingScheme", 43_434),
      ("UnterminatedQuotedString", 2_402),
    ],
  ),
  (
    "B",
    &[
      ("ChallengeBoundaryUnknown", 276),
      ("MalformedParameter", 75_246),
      ("MalformedScheme", 23_588),
      ("MissingScheme", 88_086),
      ("UnterminatedQuotedString", 444),
    ],
  ),
  (
    "C",
    &[
      ("ChallengeBoundaryUnknown", 266),
      ("MalformedParameter", 391_471),
      ("MalformedScheme", 77_250),
      ("MissingScheme", 76_314),
      ("UnterminatedQuotedString", 4_940),
    ],
  ),
  (
    "D",
    &[
      ("ChallengeBoundaryUnknown", 225),
      ("ChallengeSpansTooManyLines", 50),
      ("DuplicateParameter", 272),
      ("InvalidQuotedString", 180),
      ("MalformedParameter", 180),
      ("MalformedScheme", 978),
      ("MissingScheme", 6_048),
      ("UnterminatedQuotedString", 393),
    ],
  ),
  (
    "E",
    &[
      ("ChallengeBoundaryUnknown", 61),
      ("ChallengeSpansTooManyLines", 82),
      ("InvalidQuotedString", 30),
      ("MalformedParameter", 30),
      ("MalformedScheme", 40),
      ("MissingScheme", 40),
      ("UnterminatedQuotedString", 59),
    ],
  ),
  (
    "F",
    &[
      ("ChallengeBoundaryUnknown", 32),
      ("InvalidQuotedString", 128),
      ("MalformedParameter", 32),
      ("MissingScheme", 32),
      ("UnterminatedQuotedString", 32),
    ],
  ),
  (
    "G",
    &[
      ("ChallengeBoundaryUnknown", 11),
      ("MalformedScheme", 40),
      ("MissingScheme", 40),
      ("TooManyParameters", 46),
      ("UnterminatedQuotedString", 15),
    ],
  ),
  (
    "H",
    &[
      ("ChallengeBoundaryUnknown", 32),
      ("MalformedParameter", 48),
      ("UnterminatedQuotedString", 24),
    ],
  ),
  (
    "I",
    &[
      ("ChallengeBoundaryUnknown", 128),
      ("MalformedParameter", 192),
      ("UnterminatedQuotedString", 96),
    ],
  ),
  (
    "J",
    &[
      ("ChallengeBoundaryUnknown", 30),
      ("MalformedScheme", 89),
      ("MissingScheme", 40),
    ],
  ),
];

/// `(fault, count)` over `lines`, sorted by name.
fn faults(lines: &[String]) -> Vec<(String, usize)> {
  let mut counts: Vec<(String, usize)> = Vec::new();
  for line in lines {
    let [_, _, _, _, answer] = columns(line);
    // The answer renders every fault as `Err(<variant>)` and every variant of
    // `AuthError` is fieldless, so the name is what stands between the two.
    for tail in answer.split("Err(").skip(1) {
      let name = tail.split(')').next().unwrap_or_default();
      match counts.iter_mut().find(|(known, _)| known == name) {
        Some((_, count)) => *count += 1,
        None => counts.push((name.to_owned(), 1)),
      }
    }
  }
  counts.sort();
  counts
}

#[test]
fn the_faults_each_corpus_answers_with_are_the_ones_it_answered_with() {
  for ((name, generator), (pinned, wanted)) in generators().into_iter().zip(FAULTS) {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let lines = records(generator);
    let counted = faults(&lines);
    assert_eq!(counted, expected(wanted), "corpus {name}: {MOVED}");
    // The same faults [`AXIS`] counts, split by name — so the two tables cannot
    // drift apart, and a name this parse missed lowers the sum rather than
    // hiding in it.
    assert_eq!(
      counted.iter().map(|(_, count)| count).sum::<usize>(),
      answers(&lines).1,
      "corpus {name}: the named faults are all of them"
    );
  }
}

// ─────────────── the records one earlier commit moved, identified ────────────

/// How many records each corpus holds that `evidence/auth-forbidden-byte-refuses`
/// moved out of `hider-unexcused`, identified by
/// [`recovered_from_a_forbidden_byte`].
///
/// # What this used to be, and why it is less
///
/// It used to reconstruct the axis tally of
/// `evidence/auth-before-forbidden-byte` out of THIS tree, by moving that one
/// identified set back into the class it came from, and to assert that the
/// result reproduced the five per-corpus figures published before any harness
/// was committed. That reconstruction rested on one thing being true: that the
/// only difference between the two trees' verdicts was the set below.
///
/// It is no longer. The commit that closed al8n/wren#77 moved two things at
/// once — the reader, which now declines to place a boundary no reading of the
/// bytes agrees on, and [`oracle`](crate::oracle), whose `excused` had asked
/// whether the WHOLE value derives and so answered "no reading licenses this"
/// about quoted-strings §11.2 admits perfectly well. So D's row moved from
/// 395/90/16 to 594/90/18 and E's from 60/15/20 to 100/15/15, and no
/// single set of records reconstructs the base tree from this one.
///
/// **What is kept is the part that can still be checked**: the SET is still
/// identifiable, and its size in each corpus is asserted below. What is not
/// kept is a sentence claiming a reproduction that a later commit made false.
/// `cargo run -p xtask -- auth-diff evidence/auth-before-forbidden-byte` is
/// what still shows the whole move, over two revisions, and the tags that
/// command needs are annotated ones: the branch that produced those commits is
/// squash-merged, so no branch's history reaches either.
const RECOVERED: [(&str, usize); 2] = [("D", 90), ("E", 15)];

/// Whether this record is one `evidence/auth-forbidden-byte-refuses` moved out
/// of `hider-unexcused`: its axis is `yields-underivable`, its answer carries
/// `InvalidQuotedString`, and its answer shows the probe. Nothing else in this
/// tree holds all three.
fn recovered_from_a_forbidden_byte(line: &str) -> bool {
  let [_, _, _, axis, answer] = columns(line);
  axis == "yields-underivable"
    && answer.contains("Err(InvalidQuotedString)")
    && answer.contains(&format!("Ok[{}", escape(PROBE_SCHEME)))
}

/// How many records `counts` puts in `axis`, and none where it names no such
/// class.
fn of(counts: &[(String, usize)], axis: &str) -> usize {
  counts
    .iter()
    .find(|(name, _)| name == axis)
    .map_or(0, |(_, count)| *count)
}

#[test]
fn the_records_one_earlier_commit_moved_are_still_the_ones_it_moved() {
  for (name, moved) in RECOVERED {
    let (_, generator) = generators()
      .into_iter()
      .find(|(known, _)| *known == name)
      .expect("every corpus [`RECOVERED`] names has a generator");
    assert_eq!(
      records(generator)
        .iter()
        .filter(|line| recovered_from_a_forbidden_byte(line))
        .count(),
      moved,
      "corpus {name}: the set `evidence/auth-forbidden-byte-refuses` moved"
    );
  }
}

// ─────────────────────── the two numbers that are zero ───────────────────────

#[test]
fn the_two_classes_this_module_is_driven_to_zero_on_are_zero() {
  // A metric pinned at a non-zero constant is a defect somebody decided to
  // keep. `over-yield` stood at 16 for corpus D and 20 for corpus E while the
  // suite was green, and al8n/wren#77 — a `Digest` challenge with a `realm` of
  // `evil`, cut out of a parameter's own value on input RFC 9110 §11.2 bounds
  // nowhere — is what one of those records was worth.
  for (name, generator) in generators() {
    let counts = tally(&records(generator), |_| true);
    for class in ZERO_TARGETS {
      assert_eq!(
        of(&counts, class),
        0,
        "corpus {name}: {class} is a zero-target, and these are its records"
      );
    }
  }
}

/// What [`escape`] makes of RFC 9110 §5.6.3's two `OWS` bytes.
///
/// ```text
/// OWS = *( SP / HTAB )
/// ```
const ESCAPED_OWS: [&str; 2] = ["%20", "%09"];

/// Whether the probe stands behind [`PREFIXES`]'s each spelling when the trap
/// behind the refusal is the one that never closes — the two directions
/// `corpus_j` exists to hold apart.
///
/// `true` is a list every reading has CLOSED at the refusal, so the comma in
/// front of the probe is §5.6.1.2's separator whichever reading is the
/// sender's. `false` is one some reading still has open, where the probe is a
/// parameter's own data and crossing to it would manufacture a challenge —
/// which is what the `token68` rows are here to keep. RFC 9110 §11.3 writes
/// `token68 / #auth-param` as an unordered ABNF choice, so a `token68` body is
/// also a `#auth-param` list whose first element derives nothing, and the list
/// stands open behind that fault.
const PROBE_BEHIND_THE_OPEN_TRAP: [(&str, bool); 8] = [
  ("none", true),
  ("list", false),
  ("token68", false),
  ("token68-pad", false),
  ("bare", true),
  ("list-bare", true),
  ("list-token68", false),
  ("bare-list", false),
];

#[test]
fn ows_after_the_join_comma_and_a_challenge_completed_in_front_are_shapes_these_generators_write() {
  // A family that stopped writing its own shape would go quiet rather than red:
  // [`AXIS`] and [`ANSWERS`] would move, and a maintainer re-deriving them from
  // a failure would bless the silence. So each family's shape is asserted as a
  // property of the records themselves, beside the tallies taken over them.

  // Corpus I writes RFC 9110 §5.6.1.2's `OWS` between §5.2's join comma and the
  // element behind it, on every record.
  let i = records(corpus_i);
  for line in &i {
    let [_, case, _, _, _] = columns(line);
    let last = case.split('|').next_back().expect("a case has a line");
    assert!(
      ESCAPED_OWS.iter().any(|ows| last.starts_with(ows)),
      "corpus I writes the list's OWS in front of its continuation: {line}"
    );
  }

  // And corpus H writes none, which is the axis the two families differ by and
  // the one H holds fixed.
  for line in &records(corpus_h) {
    let [_, case, _, _, _] = columns(line);
    let last = case.split('|').next_back().expect("a case has a line");
    assert!(
      !ESCAPED_OWS.iter().any(|ows| last.starts_with(ows)),
      "corpus H starts its continuation at the element itself: {line}"
    );
  }

  // The opener that whitespace moves off the cursor is REACHED: 128 of corpus
  // I's records carry one, and the walk declines the comma behind it rather
  // than crossing into a value. Those 128 answered `over-yield` at the commit
  // that added corpus H.
  assert_eq!(
    i.iter()
      .filter(|line| columns(line)[4].contains("Err(ChallengeBoundaryUnknown)"))
      .count(),
    128,
    "corpus I: the openers a check asked at the join offset cannot see"
  );

  // Corpus J writes a challenge that COMPLETES in front of the refused one, and
  // both directions of what that challenge leaves open are in it.
  let j = records(corpus_j);
  for (prefix, shown) in PROBE_BEHIND_THE_OPEN_TRAP {
    let marker = format!(" prefix={prefix} ");
    let rows: Vec<&String> = j
      .iter()
      .filter(|line| {
        let [_, _, spelling, _, _] = columns(line);
        spelling.contains(&marker) && spelling.ends_with("trap=open")
      })
      .collect();
    assert_eq!(
      rows.len(),
      3,
      "corpus J, {prefix}: one row per scheme fault"
    );
    for line in rows {
      assert_eq!(
        columns(line)[4].contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
        shown,
        "corpus J, {prefix}, behind the trap that never closes: {line}"
      );
    }
  }
}

#[test]
fn the_notice_that_separates_the_two_classes_is_read_from_the_answer() {
  // `says_the_rest_is_unread` is what tells a challenge hidden in silence from
  // one the caller was told about, and over this corpus it cannot be told from
  // a constant `true`: every unexcused hider in it DOES report, which is the
  // zero-target being met. So the two answers are separated here instead, over
  // one value of each kind.
  //
  // The first is al8n/wren#77's own shape behind a duplicate name: the walk
  // refuses to place the boundary and says so. The second is a value refused
  // for a fault whose boundary every reading agrees on, so the walk crosses it
  // and reports nothing about the rest.
  assert!(
    says_the_rest_is_unread(&[b"Basic a=1, a=2, x=\"c, Digest realm=z, junk\""]),
    "a walk that declined to place a boundary must say so"
  );
  assert!(
    !says_the_rest_is_unread(&[b"Basic a=1, a=2, x=\"c\", Digest realm=z"]),
    "a walk that placed every boundary must claim nothing about what it read"
  );
}

#[test]
fn every_challenge_this_walk_declines_to_place_says_so_to_the_caller() {
  // `hider-unresolved` is the third class and the one that is not zero, so what
  // it costs is asserted rather than left to be read off a tally. [`ZERO_TARGETS`]
  // carries the argument for why it is a cost and not a defect; this is the
  // number, and the two halves of the claim.
  for ((name, generator), (pinned, unresolved)) in generators().into_iter().zip(UNRESOLVED) {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let lines = records(generator);
    assert_eq!(
      of(&tally(&lines, |_| true), "hider-unresolved"),
      unresolved,
      "corpus {name}: hider-unresolved"
    );
    // And the claim the class rests on: every one of those answers TELLS the
    // caller that the rest of the value is unread. A record graded here whose
    // answer carried no such notice would be a challenge hidden in silence.
    for line in &lines {
      let [_, _, _, axis, answer] = columns(line);
      if axis == "hider-unresolved" {
        assert!(
          answer.contains("Err(ChallengeBoundaryUnknown)"),
          "corpus {name}: graded hider-unresolved with no notice: {line}"
        );
      }
    }
  }
}

// ───────────────── corpus D's records against its inputs ─────────────────────

/// Corpus D over DISTINCT inputs: how many there are, and how they grade.
///
/// The tally beside this one, in [`AXIS`], counts RECORDS, and D writes 32 of
/// its inputs six times each. Both readings are pinned because both are needed
/// and neither is safe to infer from the other: [`AXIS`]'s row is what
/// reproduces the published figures, and this one is what a
/// maintainer should quote about corpus D from here on.
///
/// The last field is the count of DISTINCT inputs behind the 90 RECORDS
/// `evidence/auth-forbidden-byte-refuses` moved in corpus D — see
/// [`the_records_that_share_a_key_are_the_ones_no_mid_can_tell_apart`], which
/// is where the exception itself is pinned.
const D_DISTINCT: (usize, &[(&str, usize)], usize) = (
  3_488,
  &[
    ("hider-excused", 564),
    ("hider-unresolved", 18),
    ("no-probe", 436),
    ("yields", 751),
    ("yields-underivable", 1_719),
  ],
  85,
);

#[test]
fn what_corpus_d_says_about_distinct_inputs_is_not_what_its_records_say() {
  let (size, axis, unexcused) = D_DISTINCT;
  let lines = records(corpus_d);

  // One entry per distinct input, carrying the axis and whether it is one of
  // the records `evidence/auth-forbidden-byte-refuses` moved. Six copies of an
  // input agree on both, being the same bytes read by the same code.
  let mut inputs: HashMap<String, (String, bool)> = HashMap::new();
  for line in &lines {
    let [corpus, case, spelling, verdict, _] = columns(line);
    let entry = (verdict.to_owned(), recovered_from_a_forbidden_byte(line));
    let key = format!("{corpus}\t{case}\t{spelling}");
    if let Some(seen) = inputs.get(&key) {
      assert_eq!(*seen, entry, "one input, two answers: {key}");
    }
    inputs.insert(key, entry);
  }
  assert_eq!(inputs.len(), size, "distinct inputs in corpus D");

  let mut counts: Vec<(String, usize)> = Vec::new();
  for (verdict, _) in inputs.values() {
    match counts.iter_mut().find(|(name, _)| name == verdict) {
      Some((_, count)) => *count += 1,
      None => counts.push((verdict.clone(), 1)),
    }
  }
  counts.sort();
  assert_eq!(counts, expected(axis), "corpus D over distinct inputs");

  // The set `evidence/auth-forbidden-byte-refuses` moved is 90 RECORDS in
  // corpus D and 85 distinct inputs, which is the whole of what the two
  // readings differ by here.
  let moved = inputs.values().filter(|(_, moved)| *moved).count();
  assert_eq!(
    moved, unexcused,
    "distinct inputs behind the 90 records that commit moved"
  );
}
