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
//! - **The reproduction, pinned.** [`AXIS`] is the tally this harness is
//!   validated by. It is an assertion rather than a sentence, so a tree whose
//!   answers stop reproducing it says so from a red gate rather than from a
//!   reader's memory. Two of its five reproduced rows — D's and E's — can only
//!   be recovered from this tree by arithmetic; [`BEFORE`] executes that
//!   arithmetic, so no part of the reproduction is left standing in prose.
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
//! - **They cannot rebuild `evidence/auth-before-forbidden-byte`.** [`BEFORE`]
//!   recovers that tree's D and E rows from this one by moving a single
//!   identified set of records back into the class they came from. That the set
//!   is exactly the one `evidence/auth-forbidden-byte-refuses` moved is checked
//!   by the `auth-diff` run recorded at that constant — a run over two
//!   revisions, not an assertion here.
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
/// table below drives all six through one path; the coercion is what picks
/// `Vec<u8>` for their `impl Write`.
type Generator = fn(&mut Vec<u8>, &mut usize) -> std::io::Result<()>;

/// The six generators, in the order [`emit`] runs them.
fn generators() -> [(&'static str, Generator); 6] {
  [
    ("A", corpus_a),
    ("B", corpus_b),
    ("C", corpus_c),
    ("D", corpus_d),
    ("E", corpus_e),
    ("F", corpus_f),
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
  // What that costs the two figures this module is graded on.
  // `over-yield` carries no surplus at all, so D's published figure of 16 counts
  // 16 inputs. Its NINETY unexcused hiders do carry surplus: five of the ninety
  // were one input written six times, so that figure counts 85. One true fact
  // does not settle this and must not be read as if it did: no record is
  // `hider-unexcused` in corpus D at HEAD — `evidence/auth-forbidden-byte-refuses`
  // moved all ninety — which makes the surplus look free from here and does not
  // make the published figure a count of inputs. [`D_DISTINCT`] asserts the 85.
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
    total, 935_032,
    "the corpus is the size every figure pinned here counts over"
  );

  let mut shared: Vec<&String> = counts
    .iter()
    .filter(|(_, times)| **times > 1)
    .map(|(key, _)| key)
    .collect();
  shared.sort();
  assert_eq!(shared.len(), 32, "the groups that share a key: {shared:?}");
  assert_eq!(counts.len(), 934_872, "distinct inputs behind the records");
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
/// # Where these numbers come from, and which of them are the reproduction
///
/// Five per-corpus figures were published over this module before there was a
/// committed harness, computed by one that was then deleted — so no digest of
/// theirs can ever be recomputed. What CAN be reproduced is the tally, and it
/// was: this harness, whose oracle is an independent derivation from the RFC,
/// answers each of those five figures to the
/// digit. That agreement is the reason anything downstream of it is worth
/// reading, and it is pinned here so that a tree which stops reproducing it
/// says so.
///
/// | published as | where it is below |
/// |---|---|
/// | A, `challenges` + tail: 328 hiders, 0 unexcused, 0 over-yields | [`A_BY_SPELLING`]'s `challenges-tail` row — 328 `hider-excused`, no `hider-unexcused`, no `over-yield` |
/// | B: 444 / 0 / 0 | B's `hider-excused` 444, and neither other class present |
/// | C: 2472 / 0 / 0 | C's `hider-excused` 2472, likewise |
/// | D: 485 hiders, 90 unexcused, 16 over-yields | D's `hider-excused` 395 and `over-yield` 16. The other 90 hiders were `hider-unexcused` at `evidence/auth-before-forbidden-byte` and are `yields-underivable` here — 395 + 90 is the published 485 — because `evidence/auth-forbidden-byte-refuses` made a byte no field value admits refuse the challenge rather than the walk |
/// | E: 75 / 15 / 20 | E's `hider-excused` 60 and `over-yield` 20, with the other 15 moved the same way by the same commit — 60 + 15 is the published 75 |
///
/// Corpus F is newer than those figures and has none to reproduce. Its
/// 32 `hider-unexcused` records are the residue of a cost recorded rather than
/// paid: one value spelled two ways, answering differently because recovery
/// runs from where the scan stood.
///
/// # These numbers are expected to move
///
/// They are a pin, not a target. A change to `http_semantics::auth` that moves
/// an answer moves a cell here, and the point is that it moves in the DIFF —
/// where a reader can ask which cell and why — rather than in a figure nobody
/// can recompute. Re-derive them from a failure's own message.
const AXIS: [Pinned; 6] = [
  (
    "A",
    262_136,
    &[
      ("-", 149_792),
      ("hider-excused", 694),
      ("no-probe", 37_448),
      ("yields", 7_516),
      ("yields-underivable", 66_686),
    ],
    146_026,
    258_385,
  ),
  (
    "B",
    144_448,
    &[
      ("hider-excused", 444),
      ("yields", 14_102),
      ("yields-underivable", 129_902),
    ],
    241_702,
    187_364,
  ),
  (
    "C",
    524_288,
    &[
      ("-", 262_144),
      ("hider-excused", 2_472),
      ("yields", 13_647),
      ("yields-underivable", 246_025),
    ],
    353_963,
    549_975,
  ),
  (
    "D",
    3_648,
    &[
      ("hider-excused", 395),
      ("no-probe", 456),
      ("over-yield", 16),
      ("yields", 807),
      ("yields-underivable", 1_974),
    ],
    9_846,
    8_118,
  ),
  (
    "E",
    320,
    &[
      ("hider-excused", 60),
      ("no-probe", 40),
      ("over-yield", 20),
      ("yields", 80),
      ("yields-underivable", 120),
    ],
    363,
    297,
  ),
  (
    "F",
    192,
    &[
      ("hider-excused", 48),
      ("hider-unexcused", 32),
      ("no-probe", 48),
      ("yields-underivable", 64),
    ],
    96,
    256,
  ),
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
      ("hider-excused", 366),
      ("yields", 4_027),
      ("yields-underivable", 33_055),
    ],
  ),
  (
    "challenges-tail",
    &[
      ("hider-excused", 328),
      ("yields", 3_489),
      ("yields-underivable", 33_631),
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
const ANSWERS: [(&str, &str); 6] = [
  (
    "A",
    "ad25422fa6dbab72c73c8005e3dbcb7c3ba9a43da1988b6b6351005f73979db6",
  ),
  (
    "B",
    "2476780fa4b16b2acfe01e7ba928de7ec6647b91f9f9c672abaec4327432c587",
  ),
  (
    "C",
    "6586f15f2f103708f6612ed198d87aedfa402bbebf0086df9ecdd733a33d4c1f",
  ),
  (
    "D",
    "c3fffe735632a61f9c77f9de91376475cebc50f8777394ca46f3bfe3e047e115",
  ),
  (
    "E",
    "1f9a022cb4468ca2ab272870a675cfba4d2cc478d469b7512d31fc00bc3e5934",
  ),
  (
    "F",
    "bb035c35b4978d996b18b5b26d1f96f3de6378bf173b03f8ad7ae850cd625985",
  ),
];

/// The SHA-256 of the whole run's `answer` column, the six corpora in the order
/// [`emit`] writes them.
///
/// This is the number published for `evidence/auth-forbidden-byte-refuses` and
/// for head, and the one `cargo run -p xtask -- auth-diff` prints on both sides
/// of a range that moved nothing. Asserting it here is what makes a published
/// figure a thing a checkout can disagree with.
const WHOLE: &str = "3b86ad9a38dbddc8c400c1fb6f01b64907edf3f1ad34bb8f0160be42451cf181";

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
const FAULTS: [(&str, &[(&str, usize)]); 6] = [
  (
    "A",
    &[
      ("MalformedParameter", 185_369),
      ("MalformedScheme", 27_180),
      ("MissingScheme", 43_434),
      ("UnterminatedQuotedString", 2_402),
    ],
  ),
  (
    "B",
    &[
      ("MalformedParameter", 75_246),
      ("MalformedScheme", 23_588),
      ("MissingScheme", 88_086),
      ("UnterminatedQuotedString", 444),
    ],
  ),
  (
    "C",
    &[
      ("MalformedParameter", 391_471),
      ("MalformedScheme", 77_250),
      ("MissingScheme", 76_314),
      ("UnterminatedQuotedString", 4_940),
    ],
  ),
  (
    "D",
    &[
      ("ChallengeSpansTooManyLines", 60),
      ("DuplicateParameter", 272),
      ("InvalidQuotedString", 180),
      ("MalformedParameter", 176),
      ("MalformedScheme", 987),
      ("MissingScheme", 6_056),
      ("UnterminatedQuotedString", 387),
    ],
  ),
  (
    "E",
    &[
      ("ChallengeSpansTooManyLines", 87),
      ("InvalidQuotedString", 30),
      ("MalformedParameter", 28),
      ("MalformedScheme", 48),
      ("MissingScheme", 48),
      ("UnterminatedQuotedString", 56),
    ],
  ),
  (
    "F",
    &[
      ("InvalidQuotedString", 128),
      ("MalformedParameter", 32),
      ("MissingScheme", 64),
      ("UnterminatedQuotedString", 32),
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

// ─────────────── the tree the figures were measured on, recovered ────────────

/// One corpus as `evidence/auth-before-forbidden-byte` answered it: its name,
/// the axis tally that tree gave, and the two figures published from it — the
/// hiders it held and its over-yields.
type Recovered = (&'static str, &'static [(&'static str, usize)], usize, usize);

/// What was published for corpora D and E, and the axis each of them answered
/// with at `evidence/auth-before-forbidden-byte` — recovered from THIS tree
/// rather than quoted from that one.
///
/// # Why these two rows needed recovering at all
///
/// `evidence/auth-forbidden-byte-refuses` made a byte no field value admits
/// refuse the challenge rather than the walk, which moved every D and E record
/// that was `hider-unexcused` into `yields-underivable`. At head those records
/// are no longer separable BY THEIR AXIS from the class they moved into, so
/// [`AXIS`] pins 395 and 60 where the published figures are 485 and 75, and the
/// two are reconciled by adding back 90 and 15.
///
/// That addition must be executed and not merely written: a sentence stating it
/// stays green while a later change moves those records again, and the sum
/// stops holding with nothing to say so. Here it is taken by the machine and
/// compared against the published figure.
///
/// # How the 90 and the 15 are identified at head
///
/// [`recovered_from_a_forbidden_byte`]: the record's axis is
/// `yields-underivable`, its answer carries `InvalidQuotedString`, and its
/// answer shows the probe. Nothing else in this tree can hold all three: the
/// fault is the one `evidence/auth-forbidden-byte-refuses` changed the handling
/// of, and the probe standing behind it is what the recovery yielded.
///
/// **Verified, not argued.**
/// `cargo run -p xtask -- auth-diff evidence/auth-before-forbidden-byte`
/// reports D `hider-unexcused` 90 and `yields-underivable` 1884 on the base
/// side against 0 and 1974 on the head side, E 15 and 105 against 0 and 120,
/// and groups all 233 moved answers with D contributing exactly 90 and E
/// exactly 15 to `hider-unexcused -> yields-underivable`. The predicate selects
/// 90 records in D and 15 in E, and every record the run moved satisfies it, so
/// the two sets are equal rather than merely the same size.
///
/// **The two names above are annotated tags, and they are what keeps that
/// command runnable.** The branch that produced these commits is squash-merged,
/// so no branch's history reaches either one and the tags are the only refs
/// that do: `evidence/auth-before-forbidden-byte` is the base tree the figures
/// were measured on, and `evidence/auth-forbidden-byte-refuses` is the commit
/// that moved the records. Delete one as clutter and this paragraph becomes a
/// verification nobody can rerun — a figure with no way left to disagree with
/// it, which is the failure this crate exists to end.
const BEFORE: [Recovered; 2] = [
  (
    "D",
    &[
      ("hider-excused", 395),
      ("hider-unexcused", 90),
      ("no-probe", 456),
      ("over-yield", 16),
      ("yields", 807),
      ("yields-underivable", 1_884),
    ],
    485,
    16,
  ),
  (
    "E",
    &[
      ("hider-excused", 60),
      ("hider-unexcused", 15),
      ("no-probe", 40),
      ("over-yield", 20),
      ("yields", 80),
      ("yields-underivable", 105),
    ],
    75,
    20,
  ),
];

/// Whether this record is one `evidence/auth-forbidden-byte-refuses` moved out
/// of `hider-unexcused` — the identification [`BEFORE`]'s doc records the
/// verification of.
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
fn the_rows_that_needed_arithmetic_are_the_ones_this_tree_computes() {
  for (name, before, hiders, over_yields) in BEFORE {
    let (_, generator) = generators()
      .into_iter()
      .find(|(known, _)| *known == name)
      .expect("every corpus [`BEFORE`] names has a generator");
    let lines = records(generator);

    // The axis each record graded on at `evidence/auth-before-forbidden-byte`:
    // its own, with the records that tree called `hider-unexcused` put back.
    let mut counts: Vec<(String, usize)> = Vec::new();
    for line in &lines {
      let [_, _, _, axis, _] = columns(line);
      let axis = if recovered_from_a_forbidden_byte(line) {
        "hider-unexcused"
      } else {
        axis
      };
      match counts.iter_mut().find(|(known, _)| known == axis) {
        Some((_, count)) => *count += 1,
        None => counts.push((axis.to_owned(), 1)),
      }
    }
    counts.sort();
    assert_eq!(
      counts,
      expected(before),
      "corpus {name} at `evidence/auth-before-forbidden-byte`"
    );

    // And the two figures published for it, summed here rather than in a
    // sentence.
    assert_eq!(
      of(&counts, "hider-excused") + of(&counts, "hider-unexcused"),
      hiders,
      "corpus {name}: hider-excused plus hider-unexcused is the published hider figure"
    );
    assert_eq!(
      of(&counts, "over-yield"),
      over_yields,
      "corpus {name}: over-yield is the published over-yield figure"
    );
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
/// The last field is the count of DISTINCT inputs behind the 90 unexcused
/// hiders published for D — see
/// [`the_records_that_share_a_key_are_the_ones_no_mid_can_tell_apart`], which
/// is where the exception itself is pinned.
const D_DISTINCT: (usize, &[(&str, usize)], usize) = (
  3_488,
  &[
    ("hider-excused", 370),
    ("no-probe", 436),
    ("over-yield", 16),
    ("yields", 757),
    ("yields-underivable", 1_909),
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

  // The published D figures are 90 unexcused hiders and 485 hiders. Over inputs
  // rather than records those are 85 and 455, and the second is the sum of the
  // first with this tree's own `hider-excused`.
  let moved = inputs.values().filter(|(_, moved)| *moved).count();
  assert_eq!(
    moved, unexcused,
    "distinct inputs behind D's published 90 unexcused hiders"
  );
  assert_eq!(
    of(&counts, "hider-excused") + moved,
    455,
    "distinct inputs behind D's published 485 hiders"
  );
}
