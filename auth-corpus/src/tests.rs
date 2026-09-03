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
//! - **The tally, pinned, and the three cells of it that are ZERO.** [`AXIS`] is
//!   an assertion rather than a sentence, so a tree whose answers stop
//!   reproducing it says so from a red gate rather than from a reader's memory;
//!   and [`ZERO_TARGETS`] is what says that three of its classes are not pins at
//!   all but numbers this module is driven to zero on, with the argument for
//!   why the other two — [`UNRESOLVED`] and [`CONFORMING`] — are costs rather
//!   than defects.
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
        excused: true,
        reached: false,
        derives: true,
      },
      why: "the pair one byte apart: NUL is neither `qdtext` nor an octet a \
            `quoted-pair` may escape, so no `quoted-string` DERIVES — which \
            is `reached`'s answer and not this one. The sender opened a run \
            at the position RFC 9110 §11.2 admits a value at and it reaches \
            no close, so the reading that opened it holds the probe among \
            that value's own bytes",
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
  // probe, and an escaped DQUOTE does the same by not closing it. Every other
  // octet here is a CTL other than HTAB, which is neither production.
  //
  // # Which column the difference is in
  //
  // `excused` is the same for all twelve, and that is the correction this fix
  // makes. It asks whether some READING of the
  // value holds the probe among a value's own bytes, and the sender opened a
  // run at RFC 9110 §11.2's value position either way: a `qdtext` octet leaves
  // a `quoted-string` that is still open there, and a forbidden one leaves a
  // run that reaches no close at all — which
  // `http_semantics::grammar::Readings::absorb` calls SEALED and which holds
  // every comma left in the field. `oracle::open_at` collapsed the second into
  // "no string opens here", and while it did, 137 records of this corpus graded
  // `yields-underivable` over a reader handing back a `Digest realm=z` cut out
  // of a realm.
  //
  // What the octet DOES decide is `derives_all` — whether any `quoted-string`
  // derives — and that reaches the axis through `reached`, which is `false` for
  // all twelve here for a different reason: nothing gets past the DQUOTE. The
  // rows below assert the two columns that separate the twelve, and
  // `the_oracle_answers_the_readings_the_grammar_admits` carries the pair one
  // byte apart where `reached` is what moves.
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
    assert!(
      verdict.excused,
      "{name}: a run opened at §11.2's value position holds the probe, {}",
      escape(&value)
    );
  }

  // And the column the octet does decide, over the same twelve: with the realm
  // CLOSED in FRONT of the comma, the probe is a challenge of the outer list
  // and the only question left is whether a derivation of the whole value
  // reaches it. A `qdtext` octet leaves one; a byte RFC 9110 §5.5 admits
  // nowhere in a field value leaves none. Without this the loop above would
  // pass over an oracle that had stopped telling the twelve apart at all.
  for (name, octet) in OCTETS {
    let mut value = b"Basic realm=\"a".to_vec();
    value.extend_from_slice(octet);
    value.extend_from_slice(b"b\", ");
    value.extend_from_slice(PROBE);
    let verdict = crate::oracle::read(&value, probe_at(&value));
    assert!(verdict.derives, "{name}: the probe's own bytes derive");
    assert_eq!(
      verdict.reached,
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

/// The fourteen generators, in the order [`emit`] runs them.
fn generators() -> [(&'static str, Generator); 14] {
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
    ("K", corpus_k),
    ("L", corpus_l),
    ("M", corpus_m),
    ("N", corpus_n),
  ]
}

/// One §5.6.1.2 element with the list's own `OWS` off both ends, which is what
/// RFC 9110 §11.2 is asked about: the whitespace on either side of the comma
/// belongs to the list and not to the element.
fn trimmed(element: &[u8]) -> &[u8] {
  let ows = |byte: &u8| matches!(*byte, b' ' | b'\t');
  let start = element.iter().position(|byte| !ows(byte));
  let Some(start) = start else {
    return &[];
  };
  let end = element
    .iter()
    .rposition(|byte| !ows(byte))
    .map_or(start, |at| at.saturating_add(1));
  element.get(start..end).unwrap_or_default()
}

/// Every offset this crate asks `excused` about, for one record.
///
/// Two callers ask it and this is their union. [`axis`] asks at the probe, and
/// `oracle::every_comma_in_front_is_settled` asks at every RFC 9110 §5.6.1.2
/// comma in front of the probe — through `oracle::settled`, which is
/// `oracle::covered` twice over.
fn excused_questions(line: &str) -> Vec<(Vec<u8>, usize)> {
  let [_, case, _, _, _] = columns(line);
  let lines: Vec<Vec<u8>> = case.split('|').map(unescape).collect();
  let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
  let joined = join(&refs);
  let Some(probe) = last_index_of(&joined, PROBE) else {
    return Vec::new();
  };
  let mut out = vec![(joined.clone(), probe)];
  out.extend(
    joined
      .iter()
      .enumerate()
      .take(probe)
      .filter(|&(_, &byte)| byte == b',')
      .map(|(at, _)| (joined.clone(), at)),
  );
  out
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
            | "hider-conforming"
            | "hider-unresolved"
            | "hider-declined"
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
    total, 943_270,
    "the corpus is the size every figure pinned here counts over"
  );

  let mut shared: Vec<&String> = counts
    .iter()
    .filter(|(_, times)| **times > 1)
    .map(|(key, _)| key)
    .collect();
  shared.sort();
  assert_eq!(shared.len(), 32, "the groups that share a key: {shared:?}");
  assert_eq!(counts.len(), 943_110, "distinct inputs behind the records");
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
/// | D: 485 hiders, 90 unexcused, 16 over-yields | 594 `hider-excused`, 0 unexcused, 0 over-yields, 12 `hider-unresolved` and 6 `hider-conforming` |
/// | E: 75 / 15 / 20 | 100 / 0 / 0, and 10 `hider-unresolved` and 5 `hider-conforming` |
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
const AXIS: [Pinned; 14] = [
  (
    "A",
    262_136,
    &[
      ("-", 149_792),
      ("hider-excused", 706),
      ("no-probe", 37_448),
      ("yields", 7_516),
      ("yields-underivable", 66_674),
    ],
    145_780,
    258_807,
  ),
  (
    "B",
    144_448,
    &[
      ("hider-excused", 624),
      ("yields", 14_102),
      ("yields-underivable", 129_722),
    ],
    242_400,
    187_950,
  ),
  (
    "C",
    524_288,
    &[
      ("-", 262_144),
      ("hider-excused", 2_640),
      ("hider-unresolved", 10),
      ("yields", 13_647),
      ("yields-underivable", 245_847),
    ],
    354_849,
    550_153,
  ),
  (
    "D",
    3_648,
    &[
      ("hider-conforming", 6),
      ("hider-excused", 690),
      ("hider-unresolved", 6),
      ("no-probe", 456),
      ("yields", 801),
      ("yields-underivable", 1_689),
    ],
    9_527,
    8_506,
  ),
  (
    "E",
    320,
    &[
      ("hider-conforming", 5),
      ("hider-excused", 120),
      ("hider-unresolved", 5),
      ("no-probe", 40),
      ("yields", 75),
      ("yields-underivable", 75),
    ],
    289,
    372,
  ),
  (
    "F",
    192,
    &[("hider-excused", 144), ("no-probe", 48)],
    32,
    288,
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
    &[("hider-excused", 12), ("yields-underivable", 108)],
    258,
    150,
  ),
  (
    "K",
    288,
    &[("hider-excused", 224), ("yields-underivable", 64)],
    64,
    416,
  ),
  (
    "L",
    120,
    &[("hider-excused", 30), ("yields-underivable", 90)],
    264,
    225,
  ),
  (
    "M",
    1_050,
    &[
      ("hider-excused", 288),
      ("yields", 54),
      ("yields-underivable", 708),
    ],
    1847,
    2594,
  ),
  (
    "N",
    6_120,
    &[
      ("hider-excused", 1_784),
      ("hider-unresolved", 76),
      ("yields", 324),
      ("yields-underivable", 3_936),
    ],
    9_713,
    14_605,
  ),
];

/// The three classes this module is driven to ZERO on, and the two it is not.
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
/// # And a third time, over a corpus that could not spell a SEQUENCE
///
/// `over-yield` was zero over corpora A..M and `corpus_n` answers **240**
/// against the commit that added M. The axis every family up to there held
/// fixed is what the recovered SPAN contains: each of them varies how the
/// epoch OPENED — the prefix, the fault, what completes behind it, what the
/// trap holds — and puts at most one element between the refusal and the trap,
/// chosen from a set whose members either open a challenge or are the trap. No
/// cross of facts-at-the-opening writes a second element into the middle of a
/// span, which is why a model-derived table could not enumerate this one.
///
/// Four stages make the witness —
/// `Basic a=1, a=2, y=, Bearer, x="open, Digest realm=evil, junk"` — a
/// receiver-bound epoch, a malformed parameter-shaped element the recovery
/// crosses, a challenge that completes and closes the epoch, and the quoted
/// probe. The oracle graded it `over-yield` at `45da0e3` with no product change
/// at all; what could not see it was this corpus.
/// `over_yield_would_catch_this_witness_from_the_oracle_alone` derives that
/// class from the oracle alone, and `corpus_n` is the family that writes the
/// shape.
///
/// **And 60 of the 240 are a fifth stage the first draft of that family could
/// not spell either**: WHERE the refusal left the cursor. Every row of the
/// family's first half puts its span behind an element the refused challenge
/// already derived, so a span rule that skipped its first element was green
/// over all of them — and `MAX_CHALLENGE_LINES` leaves the cursor on an element
/// the walk never read. `corpus_n_at_the_cursor` is that half.
///
/// `hider-unresolved` and `hider-conforming` are the classes that are NOT zero,
/// because they are not the same kind of thing. Their records are ones where the
/// reader declined to place a boundary and SAID SO — the answer carries
/// `ChallengeBoundaryUnknown`, so RFC 9110 §11.4's user agent knows it has not
/// been shown the whole list. A challenge hidden in silence is the harm; a
/// challenge the caller is told it has not been shown is a cost. The 43 records
/// are three shapes, and the split between the two classes is the split between
/// the first and the other two:
///
/// - **10 in corpus C**, `Basic a=","a, Digest realm=z`, all `hider-unresolved`:
///   the element's value closes and runs on, so the reading that leaves its
///   DQUOTE shut ends the element at the comma INSIDE `","` and the reading that
///   opens it ends the element behind `a`. The two part in front of the probe,
///   which both of them would have reached — the walk cannot certify the earlier
///   comma without cutting a value in half, and cannot certify the later one
///   without hiding the element the earlier reading found. `oracle::settled`
///   answers `false` for that comma, which is what puts these here.
/// - **12 in corpus D and 10 in corpus E**, `hider-unresolved` too: the line
///   bound met with a value still open across RFC 9110 §5.2's join and NEVER
///   closing. A `quoted-string` needs its closing DQUOTE, so the element derives
///   nothing, so the DQUOTE is a reading's to open and a reading's to leave shut
///   — the same disagreement corpus C's rows have, reached a different way.
/// - **6 in corpus D and 5 in corpus E**, `hider-conforming`: the same line
///   bound, over a value whose string DOES close, on a line past
///   `MAX_CHALLENGE_LINES`. Every reading then derives the whole value and
///   agrees about every comma in it — `Verdict::reached` is `true` — so nothing
///   here is ambiguous at all. What refused it is this recipient's own bound,
///   and that constant already records that it is a refusal which can meet
///   conforming input.
///
/// Driving these to zero needs a different answer to a different question —
/// whether the walk may read a line it may not NAME — and not a change to the
/// boundary rule.
///
/// # The third target, and why the hiding direction needed one
///
/// `over-yield` and `hider-unexcused` watch the INVENTING direction and the
/// silent half of the hiding one. Nothing watched the hiding direction where
/// the caller WAS told, because `hider-unresolved` was one class doing three
/// jobs: a comma the readings disagree about, a value this recipient's own
/// bound refused although every reading derives it, and a boundary the walk
/// declined although every reading places it in the same byte. Only the third
/// is a defect: `Basic p1=1, …, p17=17, Bearer abc, x="open, Digest realm=z`,
/// where the `Digest` was declined for a `#auth-param` list that had ended
/// three elements earlier. This branch has produced hiding defects and
/// inventions in roughly equal numbers throughout, and only the inventions
/// had a gate.
///
/// `hider-declined` is that gate. `oracle::every_comma_in_front_is_settled` is
/// the split against `hider-unresolved` and `Verdict::reached` is the split
/// against `hider-conforming`, and the reason a metric could be built at all is
/// that the three questions are different rather than degrees of one:
///
/// - **Do the readings disagree about a comma in front of the probe?** If they
///   do, the walk may decline it. `oracle::settled` is that question and
///   `oracle::forced` is the half of it added here — a comma every reading
///   holds inside a value is settled as that value's DATA and is no more a
///   disagreement than one no reading holds inside a value is.
/// - **Does the whole value derive?** If it does, the grammar has no complaint
///   anywhere in these bytes and what refused them is a bound of this
///   recipient's — the trade `MAX_CHALLENGE_LINES` records where it is defined.
/// - **Neither?** Then the walk was in recovery and stopped at a boundary the
///   grammar had already made for it, and that is the defect.
///
/// `hider_declined_would_catch_this_witness_from_the_oracle_alone` is the proof
/// that this would have caught it: it derives the class of that witness from
/// the oracle alone, without a reader.
const ZERO_TARGETS: [&str; 3] = ["over-yield", "hider-unexcused", "hider-declined"];

/// What `hider-unresolved` costs, per corpus, so that a shape moving in or out
/// of it says so.
///
/// It counts ONE of the two costs now: a comma in front of the probe that the
/// readings disagree about, so the walk had a boundary it could not place.
/// [`CONFORMING`] counts the other, and `hider-declined` — what is left when
/// neither holds — is a zero-target rather than a cost. Corpus D's 18 and
/// corpus E's 15 split 12/6 and 10/5 between the two once the line was drawn;
/// the totals did not move and no record left the pair.
const UNRESOLVED: [(&str, usize); 14] = [
  ("A", 0),
  ("B", 0),
  ("C", 10),
  ("D", 6),
  ("E", 5),
  ("F", 0),
  ("G", 0),
  // Corpus H's `ChallengeBoundaryUnknown` answers are all `hider-excused`: the
  // reading that carried the head's value across RFC 9110 §5.2's join covers
  // the probe, so the axis excuses the hiding before it asks whether the caller
  // was told. The notice is there all the same, and
  // `the_notice_that_separates_the_two_classes_is_read_from_the_answer` is what
  // reads it.
  ("H", 0),
  // Corpus I is corpus H with the list's own `OWS` behind the join comma, and
  // corpus K is the same `OWS` in front of it. Both are excused for the reason
  // H's are.
  ("I", 0),
  // Corpus J answered 6 here at `e2d72fc` and 18 at `3c15602`; it answers 0
  // now. The 18 are the `token68` prefixes: a body §11.2's `token68` derives
  // opens no list, so the probe behind the trap is a challenge every reading
  // agrees on and hiding it was a cost paid for nothing. `PREFIXES` names which
  // rows moved and which must not.
  ("J", 0),
  ("K", 0),
  // Corpus L hides its probe wherever a list is open where the fault is met —
  // and it is EXCUSED there, because the reading that keeps that list open is
  // one this walk cannot rule out behind a fault. What it may not do is cross
  // it: at `3c15602` six of these rows did, and `over-yield` is where they sat.
  ("L", 0),
  // Corpus M is the family that varies how many recovery epochs the value
  // opens. It answered 36 here at `338e37a`: a bound this reader sets left a
  // `#auth-param` list open across a challenge the grammar had already ended,
  // so the trap behind that challenge was read as one more parameter's value
  // and the probe was declined with a notice nobody needed. It answers 0 now.
  // `REFUSALS` names which rows moved and which must not.
  ("M", 0),
  // Corpus N's 44 are its `open-quoted` span alone: the element the recovery
  // would absorb opens a RFC 9110 §5.6.4 quoted-string that is still open at
  // the comma, so some reading holds that comma as the value's own data, the
  // walk declines the boundary and never reaches the span rule at all. They
  // are the rows that say this family's own dimension does not settle every
  // boundary in front of it, and they answered 44 before the span rule existed
  // too. Every other span of that family answers 0.
  ("N", 76),
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
      ("hider-excused", 334),
      ("yields", 3_489),
      ("yields-underivable", 33_625),
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
const ANSWERS: [(&str, &str); 14] = [
  (
    "A",
    "a7390db7460bf1c1405a1829405b4a32ae7729ccda5cfa640598e0328826c486",
  ),
  (
    "B",
    "9017a575f6ae4f4a7552d26e914bc584c2be11e5be8bfbc1a302149ff84e234a",
  ),
  (
    "C",
    "7f342ee29b66ed0d2be26b7a23a4890f9877c356767bc4124a7b055e252d63c8",
  ),
  (
    "D",
    "7c55a0b26af7f9c57dde56c230cbfe9d08621056e3ec56fde28ae3ff29966354",
  ),
  (
    "E",
    "3c62b936fa9fda03b13c31dc0c71606e56482ac07d0d3a8f40f7e453304869bb",
  ),
  (
    "F",
    "dcdae6c0251a6e3d3af1561ae2b25cf3bac242a868d52a38bd09fff5d563e17f",
  ),
  (
    "G",
    "544d4e11490978d356cc2c528c65877a5a7b13c0d8d4b74b6cb672f279f29b5e",
  ),
  (
    "H",
    "4b0137c051df1c5eefb3e0e7843d7cd3864308d96f14b36ffbfe8c1f396fae03",
  ),
  (
    "I",
    "4631d9b0af79f76c1b9b7ed10858b6a48cef2354d19be7de59bd3ea9bb0051e8",
  ),
  (
    "J",
    "94266079dfabb47ddedc4a8ead414f8bac5880815a470c017d3207d255097e64",
  ),
  (
    "K",
    "71e5644e40aa51229bf44d5e0062a60960e4d9c7a13223df15a7c40f09aec49b",
  ),
  (
    "L",
    "2580ee6c9e84993c76c45c670b211d987759c02d6780f1d6e74cbba75ac7c0a0",
  ),
  (
    "M",
    "12869f9ecaebf9f6b55c0a5b90d142e018c7ad55a25dbd5b0dc96f3c83760873",
  ),
  (
    "N",
    "69f3d692a6d4429fb6c3eb89c29e38e2014fe39b7499837f282db9791e45e03f",
  ),
];

const WHOLE: &str = "1d600d6f1fc27a55008499fad4ebca456e7c9bc64f357f56c8bfa9d70c817cd1";

/// Feeds `hash` what `auth-diff` digests: each record's `answer` column and the
/// newline behind it, in record order.
fn feed_answers(lines: &[String], hash: &mut Sha256) {
  for line in lines {
    let [_, _, _, _, answer] = columns(line);
    hash.update(answer.as_bytes());
    hash.update(b"\n");
  }
}

/// One corpus's answers, digested under the name of the corpus they are about.
///
/// The name and a newline go in FIRST, so two families that answer alike do not
/// answer to the same constant. Corpus I and corpus K do answer alike, record
/// for record — RFC 9110 §5.6.1.2's `[ element ] *( OWS "," OWS [ element ] )`
/// spells one list two ways, and
/// `ows_before_the_join_comma_and_a_challenge_completed_behind_are_shapes_these_generators_write`
/// asserts the identity where it belongs. While their two rows in [`ANSWERS`]
/// held the same sixty-four characters, a maintainer pasting the actual digest
/// from one family's failure into the OTHER family's row was green: the
/// identity is the result, and an alarm two families share cannot say which of
/// them rang.
///
/// [`WHOLE`] is not keyed and must not be. It is the number
/// `cargo run -p xtask -- auth-diff` prints for the answer column, and the two
/// are the same number only if they are taken over the same bytes.
fn keyed_digest(name: &str, lines: &[String]) -> String {
  let mut hash = Sha256::new();
  hash.update(name.as_bytes());
  hash.update(b"\n");
  feed_answers(lines, &mut hash);
  hash.finish()
}

#[test]
fn the_answers_this_tree_gives_are_the_ones_the_differential_digested() {
  let mut whole = Sha256::new();
  let mut seen: Vec<String> = Vec::new();
  for ((name, generator), (pinned, digest)) in generators().into_iter().zip(ANSWERS) {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let lines = records(generator);
    feed_answers(&lines, &mut whole);
    assert_eq!(keyed_digest(name, &lines), digest, "corpus {name}: {MOVED}");
    seen.push(digest.to_owned());
  }
  assert_eq!(whole.finish(), WHOLE, "{MOVED}");

  // And no two rows carry the same constant, which is what the key buys. A
  // table with a repeat in it is one where blessing a failure in one row
  // blesses another family nobody looked at.
  let mut sorted = seen.clone();
  sorted.sort_unstable();
  sorted.dedup();
  assert_eq!(
    sorted.len(),
    seen.len(),
    "two corpora answer to the same pinned digest"
  );
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
const FAULTS: [(&str, &[(&str, usize)]); 14] = [
  (
    "A",
    &[
      ("ChallengeBoundaryUnknown", 12),
      ("MalformedParameter", 185_611),
      ("MalformedScheme", 27_348),
      ("MissingScheme", 43_434),
      ("UnterminatedQuotedString", 2_402),
    ],
  ),
  (
    "B",
    &[
      ("ChallengeBoundaryUnknown", 180),
      ("MalformedParameter", 74_456),
      ("MalformedScheme", 24_784),
      ("MissingScheme", 88_086),
      ("UnterminatedQuotedString", 444),
    ],
  ),
  (
    "C",
    &[
      ("ChallengeBoundaryUnknown", 178),
      ("MalformedParameter", 390_487),
      ("MalformedScheme", 78_234),
      ("MissingScheme", 76_314),
      ("UnterminatedQuotedString", 4_940),
    ],
  ),
  (
    "D",
    &[
      ("ChallengeBoundaryUnknown", 405),
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
      ("ChallengeBoundaryUnknown", 91),
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
      ("ChallengeBoundaryUnknown", 128),
      ("InvalidQuotedString", 128),
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
      ("ChallengeBoundaryUnknown", 12),
      ("MalformedScheme", 98),
      ("MissingScheme", 40),
    ],
  ),
  (
    "K",
    &[
      ("ChallengeBoundaryUnknown", 128),
      ("MalformedParameter", 192),
      ("UnterminatedQuotedString", 96),
    ],
  ),
  (
    "L",
    &[
      ("ChallengeBoundaryUnknown", 18),
      ("MalformedScheme", 161),
      ("MissingScheme", 40),
      ("UnterminatedQuotedString", 6),
    ],
  ),
  (
    "M",
    &[
      ("ChallengeBoundaryUnknown", 218),
      ("ChallengeSpansTooManyLines", 150),
      ("DuplicateParameter", 150),
      ("MalformedParameter", 150),
      ("MalformedScheme", 1381),
      ("MissingScheme", 150),
      ("TooManyParameters", 360),
      ("UnterminatedQuotedString", 35),
    ],
  ),
  (
    "N",
    &[
      ("ChallengeBoundaryUnknown", 1_286),
      ("ChallengeSpansTooManyLines", 1_080),
      ("DuplicateParameter", 1_120),
      ("MalformedParameter", 1_120),
      ("MalformedScheme", 4_972),
      ("MissingScheme", 560),
      ("TooManyParameters", 4_180),
      ("UnterminatedQuotedString", 287),
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
/// **What is kept is the part that can still be checked**: the shape's records
/// are still identifiable, and their count in each corpus is asserted below.
/// What is not kept is a sentence claiming a reproduction that a later commit
/// made false. `cargo run -p xtask -- auth-diff evidence/auth-before-forbidden-byte`
/// is what still shows the whole move, over two revisions, and the tags that
/// command needs are annotated ones: the branch that produced those commits is
/// squash-merged, so no branch's history reaches either.
///
/// # And this fix moved 137 of them again
///
/// The identification used to be *shows the probe behind an
/// `InvalidQuotedString`*, which was exactly the set `evidence/…-refuses`
/// moved. That set is now EMPTY — [`INVENTED_BEHIND_A_FORBIDDEN_BYTE`] is what
/// says so and what it used to be — because a string a forbidden byte sealed
/// holds every comma behind its DQUOTE, so those 137 records answer
/// `ChallengeBoundaryUnknown` where they used to hand back a `Digest`.
///
/// So the predicate below identifies the shape by the pair of faults it now
/// answers with. **It is exact for corpora D and E and not for F**: F's 192
/// rows put the octet BEHIND the probe as often as in front of it, and 64 of
/// those already answered these two faults while showing no probe at all. D's
/// 90 and E's 15 are the same records they always were; F's 96 are 32 of them
/// and 64 that were never in the set.
const RECOVERED: [(&str, usize); 3] = [("D", 90), ("E", 15), ("F", 96)];

/// What a challenge cut out of a run a forbidden byte sealed would count, over
/// every corpus.
///
/// **137 at `3e65d4e`**, one of them: `Basic x="%x01, Digest realm=evil`
/// handed a caller a `Digest`
/// with a `realm` no origin server sent. RFC 9110 §11.2 admits a value at that
/// DQUOTE, so the sender wrote every byte behind it as data, and a run that
/// reaches no close holds the lot.
///
/// It is a zero rather than a pin, and it is not in [`ZERO_TARGETS`] because
/// that table is over the AXIS. This is over the answer column alone, which is
/// the module's output with no verdict of the oracle's in it — so a
/// regression here reds without anything having to agree about a reading.
const INVENTED_BEHIND_A_FORBIDDEN_BYTE: usize = 0;

/// Whether this record answers with a boundary declined behind a byte RFC 9110
/// §5.6.4 forbids: its axis is `hider-excused` — some reading holds the probe
/// among a value's own bytes — its answer carries `InvalidQuotedString`, and it
/// carries `ChallengeBoundaryUnknown`.
fn recovered_from_a_forbidden_byte(line: &str) -> bool {
  let [_, _, _, axis, answer] = columns(line);
  axis == "hider-excused"
    && answer.contains("Err(InvalidQuotedString)")
    && answer.contains("Err(ChallengeBoundaryUnknown)")
}

/// Whether this record shows the probe behind an `InvalidQuotedString` — a
/// challenge cut out of a run the sender opened with a DQUOTE and never shut.
fn invented_behind_a_forbidden_byte(line: &str) -> bool {
  let [_, _, _, _, answer] = columns(line);
  answer.contains("Err(InvalidQuotedString)")
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
      "corpus {name}: the records answering behind a forbidden byte"
    );
  }

  // And the count that is not a pin. Every corpus, not only the three above:
  // the shape is one corpora A..C can write by accident, and a zero asserted
  // over the three that spell it deliberately would say nothing about them.
  for (name, generator) in generators() {
    assert_eq!(
      records(generator)
        .iter()
        .filter(|line| invented_behind_a_forbidden_byte(line))
        .count(),
      INVENTED_BEHIND_A_FORBIDDEN_BYTE,
      "corpus {name}: a challenge cut out of a run a forbidden byte sealed"
    );
  }
}

// ────────────────────── the three numbers that are zero ──────────────────────

#[test]
fn the_three_classes_this_module_is_driven_to_zero_on_are_zero() {
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
/// parameter's own data and crossing to it would manufacture a challenge.
///
/// The `token68` rows are `true`, and were `false` before this fix.
/// RFC 9110 §11.3 writes `token68 / #auth-param` as an unordered ABNF
/// choice, and unordered means a recipient may TRY either alternative — not
/// that an alternative deriving none of these bytes is a reading of them.
/// `auth-param = token BWS "=" BWS ( token / quoted-string )` needs a value
/// behind its `=` and a `token68` puts nothing but more `=` there, so the
/// `#auth-param` alternative does not derive a body the run reaches the end of
/// and no list is open behind that challenge.
const PROBE_BEHIND_THE_OPEN_TRAP: [(&str, bool); 8] = [
  ("none", true),
  ("list", false),
  ("token68", true),
  ("token68-pad", true),
  ("bare", true),
  ("list-bare", true),
  ("list-token68", true),
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
fn ows_before_the_join_comma_and_a_challenge_completed_behind_are_shapes_these_generators_write() {
  // The same rule as the test above, for corpora K and L.

  // Corpus K writes RFC 9110 §5.6.1.2's `OWS` at the END of every line §5.2's
  // join puts a comma behind — the side of that comma corpus I does not vary.
  let k = records(corpus_k);
  for line in &k {
    let [_, case, _, _, _] = columns(line);
    let mut lines = case.split('|').peekable();
    while let Some(one) = lines.next() {
      if lines.peek().is_none() {
        // The value's last line has no join comma behind it, so there is no
        // list `OWS` for it to carry.
        break;
      }
      assert!(
        ESCAPED_OWS.iter().any(|ows| one.ends_with(ows)),
        "corpus K writes the list's OWS in front of every join comma: {line}"
      );
    }
  }

  // And corpus H writes none on either side of that comma, which is the axis
  // both I and K unfix and the one H holds fixed.
  for line in &records(corpus_h) {
    let [_, case, _, _, _] = columns(line);
    for one in case.split('|') {
      assert!(
        !ESCAPED_OWS.iter().any(|ows| one.ends_with(ows)),
        "corpus H ends its lines at the element itself: {line}"
      );
    }
  }

  // K and I answer alike, record for record, over inputs that differ in every
  // record — which is §5.6.1.2's `[ element ] *( OWS "," OWS [ element ] )`
  // holding: the two spell the same list. It is not vacuous agreement, because
  // the readings differ where the tally cannot see: a §5.6.4 quoted-string
  // still open at the head's line end makes K's whitespace that VALUE's data
  // and I's the list's, so the two values are not the same bytes under the
  // reading that opens it.
  let i = records(corpus_i);
  assert_eq!(i.len(), k.len(), "the two families are the same shape");
  let mut cases_differ = 0;
  for (one, other) in i.iter().zip(&k) {
    assert_eq!(
      columns(one)[4],
      columns(other)[4],
      "corpus I and corpus K disagree: {one} / {other}"
    );
    cases_differ += usize::from(columns(one)[1] != columns(other)[1]);
  }
  assert_eq!(
    cases_differ,
    k.len(),
    "every K case differs from its I case"
  );

  // Corpus L completes a challenge BEHIND the fault, which is the shape corpus
  // J holds fixed: a fault, and then a challenge yielded past it. Asserted for
  // the three closers that close a list; the `list` closer opens one instead,
  // and a trap that never closes is then inside its value rather than behind
  // it, so those rows are the family's control and not its shape.
  let l = records(corpus_l);
  let mut completed = 0usize;
  for line in &l {
    let [_, _, spelling, _, answer] = columns(line);
    if spelling.contains("closer=list") {
      continue;
    }
    let (_, behind) = answer
      .split_once("Err(")
      .expect("every corpus L value is refused at its fault");
    assert!(
      behind.contains("Ok["),
      "corpus L completes a challenge behind its fault: {line}"
    );
    completed += 1;
  }
  assert_eq!(
    completed, 90,
    "corpus L: three closers over two openers, three faults, five traps"
  );

  // And the two directions the family holds apart, over the trap that never
  // closes: a list open where the fault is met stays open past the challenge
  // behind it, and one that never opened stays shut.
  for (opener, shown) in [("none", true), ("list", false)] {
    let marker = format!(" opener={opener} ");
    let rows: Vec<&String> = l
      .iter()
      .filter(|line| {
        let [_, _, spelling, _, _] = columns(line);
        spelling.contains(&marker)
          && spelling.ends_with("trap=open")
          && !spelling.contains("closer=list")
      })
      .collect();
    assert_eq!(
      rows.len(),
      9,
      "corpus L, {opener}: three faults by three closers"
    );
    for line in rows {
      assert_eq!(
        columns(line)[4].contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
        shown,
        "corpus L, {opener}, behind the trap that never closes: {line}"
      );
    }
  }
}

/// Which of corpus M's refusals is a bound THIS reader sets rather than a fault
/// of RFC 9110's grammar, and whether the refused challenge had entered a
/// `#auth-param` list of its own.
///
/// A bound is `true`: the grammar derives every byte of the refused challenge
/// with every element where §5.6.1.2 puts it, so the first element no
/// `auth-param` derives ends the list and the challenge behind the refusal ends
/// it — whatever was open in front. A fault is `false`: nothing derives behind
/// it, and one reading has every element since as garbage the open list still
/// holds, so the same challenge closes nothing.
///
/// The second flag is `1*SP`, RFC 9110 §11.3's only entrance to a body: a fault
/// met at an `auth-scheme` was met in whatever list the VALUE had open, and one
/// met inside a body was met in the list that body's own `1*SP` opened.
///
/// So the probe is reachable exactly where
/// `bound || !(the value had a list open || the refused challenge opened one)`,
/// and that is the axis corpus M adds with both directions of it named.
const M_REFUSAL_IS_A_BOUND: [(&str, bool, bool); 7] = [
  ("htab", false, false),
  ("no-token", false, false),
  ("punct", false, false),
  ("body", false, true),
  ("too-many-params", true, true),
  ("duplicate", true, true),
  ("too-many-lines", true, true),
];

#[test]
fn a_second_recovery_epoch_is_a_shape_this_generator_writes() {
  // Corpus M is the first family to open TWO recovery epochs, so it is the
  // first that can say anything about what one of them may outlive. Its shape
  // is a refusal, a challenge that COMPLETES behind it, and then a second
  // refusal at the trap — and the family is worth nothing unless every row
  // actually writes it.
  let m = records(corpus_m);
  assert_eq!(
    m.len(),
    1_050,
    "five openers, seven refusals, six separators, five traps"
  );

  // Every row is refused, and every row whose separator is not empty yields a
  // challenge BEHIND that refusal. `separator=none` is the control that puts
  // the second refusal straight behind the first, with nothing between them.
  let mut completed = 0usize;
  for line in &m {
    let [_, _, spelling, _, answer] = columns(line);
    assert!(
      answer.contains("Err("),
      "corpus M refuses its first challenge: {line}"
    );
    if spelling.contains("separator=none")
      || spelling.contains("separator=list")
      || spelling.contains("separator=fault")
    {
      continue;
    }
    let (_, behind) = answer
      .split_once("Err(")
      .expect("every corpus M value is refused at its first challenge");
    assert!(
      behind.contains("Ok["),
      "corpus M completes a challenge between its two epochs: {line}"
    );
    completed += 1;
  }
  assert_eq!(
    completed, 525,
    "corpus M: three closing separators over five openers, seven refusals, five traps"
  );

  // And the direction the family exists for, over the trap that never closes
  // and the three separators that end a list. The `fault` opener is the third
  // row of it: an epoch nothing can close already stands in front, so a bound
  // met behind one is a bound whose own epoch cannot be closed either — no
  // later bound of this reader's puts the grammar back.
  for (refusal, bound, its_own_list) in M_REFUSAL_IS_A_BOUND {
    // The four openers, as the two facts the answer turns on: whether a
    // `#auth-param` list is open where the family's own refusal is met, and
    // whether an earlier epoch's fault can still be ABOUT these bytes. The
    // second is `Epoch::reaches_past_itself` from the other side, and RFC
    // 9110 §11.2 is the whole of it — a value position occurs only inside a
    // list, so a fault met where none is open reaches nothing.
    for (opener, a_list_in_front, closable) in [
      ("none", false, true),
      ("list", true, true),
      // A grammar fault at the head of the value: no list stood at it, so it
      // poisons nothing and a bound behind it is closed by the next completed
      // challenge exactly as it would be with no prefix at all.
      ("fault", false, true),
      // The same fault, met inside a list this time. Now it reaches forward,
      // and a bound behind it cannot be closed.
      ("list-fault", true, false),
      // A bound of this RECIPIENT's, carrying a list and closable. A list alone
      // poisons nothing — only a list a FAULT left open does — so a bound
      // behind this one is closed by the challenge behind it exactly as it
      // would be with nothing in front at all.
      ("bound", true, true),
    ] {
      let marker = format!(" refusal={refusal} ");
      let opener_marker = format!(" opener={opener} ");
      let rows: Vec<&String> = m
        .iter()
        .filter(|line| {
          let [_, _, spelling, _, _] = columns(line);
          spelling.contains(&marker)
            && spelling.contains(&opener_marker)
            && spelling.ends_with("trap=open")
            && !spelling.contains("separator=none")
            && !spelling.contains("separator=list")
            && !spelling.contains("separator=fault")
        })
        .collect();
      assert_eq!(
        rows.len(),
        3,
        "corpus M, {refusal}, {opener}: the three closing separators"
      );
      let shown = (bound && closable) || !(a_list_in_front || its_own_list);
      for line in rows {
        assert_eq!(
          columns(line)[4].contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
          shown,
          "corpus M, {refusal}, {opener}, behind the trap that never closes: {line}"
        );
      }

      // And the separator that is a FAULT rather than a challenge, which is the
      // element `Challenges::seek` resumes on and the next thing it refuses.
      // Nothing completes there, so nothing closes an epoch and the bound's own
      // regime never comes back: the probe is reachable only where no list was
      // open anywhere in the first place.
      let resumed: Vec<&String> = m
        .iter()
        .filter(|line| {
          let [_, _, spelling, _, _] = columns(line);
          spelling.contains(&marker)
            && spelling.contains(&opener_marker)
            && spelling.ends_with("trap=open")
            && spelling.contains("separator=fault")
        })
        .collect();
      assert_eq!(
        resumed.len(),
        1,
        "corpus M, {refusal}, {opener}: the fault separator"
      );
      for line in resumed {
        assert_eq!(
          columns(line)[4].contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
          !(a_list_in_front || its_own_list),
          "corpus M, {refusal}, {opener}, resumed on a fault: {line}"
        );
      }
    }
  }

  // The sharpest thing this family asserts: a grammar fault that opens NO
  // `#auth-param` list, standing in
  // front of a value, must leave every one of its rows answering exactly as the
  // unprefixed row answers about the probe. RFC 9110 §11.2 admits a value
  // position only inside a list, so such a fault has no DQUOTE any reading may
  // choose behind it and can change nothing.
  //
  // `Broken;junk, …` against `…`, over all 210 (refusal, separator, trap)
  // triples. It used to fail in this direction — the reader poisoned the
  // later epoch and the ORACLE excused it for the same reason — which is
  // why the pairing is asserted here rather than left to two tallies that
  // happen to agree.
  let shown = |opener: &str| -> Vec<(String, bool)> {
    let marker = format!(" opener={opener} ");
    m.iter()
      .filter(|line| columns(line)[2].contains(&marker))
      .map(|line| {
        let [_, _, spelling, _, answer] = columns(line);
        (
          spelling.replace(&marker, " "),
          answer.contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
        )
      })
      .collect()
  };
  let differing = |one: &[(String, bool)], other: &[(String, bool)]| -> Vec<String> {
    one
      .iter()
      .zip(other)
      .filter(|((_, one), (_, other))| one != other)
      .map(|((name, _), _)| name.clone())
      .collect()
  };
  let bare = shown("none");
  let prefixed = shown("fault");
  let list = shown("list");
  let list_fault = shown("list-fault");
  assert_eq!(
    bare.len(),
    210,
    "seven refusals, six separators, five traps"
  );
  assert_eq!(
    differing(&bare, &prefixed),
    Vec::<String>::new(),
    "a list-free fault in front of the value moved a probe"
  );

  // And the control that says the pairing is about the LIST rather than about
  // the prefix's bytes: the SAME fault, met inside a list, moves exactly the
  // rows an unclosable epoch is supposed to move — the eighteen where a bound
  // of this reader's would otherwise have been closed by the challenge behind
  // it. Nowhere else, and never in the direction of showing more.
  let moved = differing(&list, &list_fault);
  assert_eq!(
    moved.len(),
    18,
    "three receiver bounds, three closing separators, two DQUOTE traps: {moved:?}"
  );
  for name in &moved {
    assert!(
      M_REFUSAL_IS_A_BOUND
        .iter()
        .any(|(refusal, bound, _)| { *bound && name.contains(&format!(" refusal={refusal} ")) }),
      "the fault moved a row no bound of this reader's refused: {name}"
    );
  }
  for ((name, list), (_, list_fault)) in list.iter().zip(&list_fault) {
    assert!(
      *list || !*list_fault,
      "a fault inside a list SHOWED a probe the list alone hid: {name}"
    );
  }
  assert!(
    !differing(&bare, &list).is_empty(),
    "the two directions of the axis are the same, so it measures nothing"
  );

  // The row that names each fault, so a refusal that stopped firing — a bound
  // this reader raised, or a grammar the walk stopped refusing — reds here
  // rather than going quiet in a tally.
  for (refusal, fault) in [
    ("htab", "MalformedScheme"),
    ("no-token", "MissingScheme"),
    ("punct", "MalformedScheme"),
    ("body", "MalformedParameter"),
    ("too-many-params", "TooManyParameters"),
    ("duplicate", "DuplicateParameter"),
    ("too-many-lines", "ChallengeSpansTooManyLines"),
  ] {
    let marker = format!(" refusal={refusal} ");
    let mut rows = 0usize;
    for line in &m {
      let [_, _, spelling, _, answer] = columns(line);
      if !spelling.contains(&marker) {
        continue;
      }
      assert!(
        answer.contains(&format!("Err({fault})")),
        "corpus M, {refusal}: the fault this row is about: {line}"
      );
      rows += 1;
    }
    assert_eq!(
      rows, 150,
      "corpus M, {refusal}: six separators, five traps, five openers"
    );
  }
}

/// What RFC 9110 §11.2 says about each of corpus N's spans, and whether the
/// walk ever gets far enough to ask.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `Some(true)` — every element of the span derives, so the epoch's claim that
/// this recipient's own limit is the ONLY reason the value stopped deriving
/// survives it and a challenge behind it may still close the epoch. `bws` and
/// `duplicate` are the two rows here that a rule written from the witness
/// rather than from the production would get wrong: §5.6.3's `BWS` is admitted
/// on both sides of the `=`, and a repeated name is §11.2's own MUST and no
/// fault of the grammar.
///
/// `Some(false)` — some element derives nothing, so the grammar is a reason too
/// and the claim is false from that element on. The two `trailing` spellings
/// are `( token / quoted-string )` taken WHOLE; the last two are the same pair
/// of elements in both orders, and a rule that asked only the span's first
/// element would answer one of them wrong.
///
/// `None` — `y="q` opens a quoted-string that is still open at the comma, so
/// some reading holds that comma as the value's own data and the walk declines
/// the boundary rather than absorbing anything. Nothing asks the span rule on
/// those rows and nothing may: they are [`UNRESOLVED`]'s own and they answered
/// the same before this family existed.
///
/// # §11.2 is the source, and this table is checked against it
///
/// The first column of this is not a second reading of `auth-param`. It is a
/// transcription, kept because each row's REASON is worth writing down, and
/// `the_spans_this_table_names_are_the_ones_11_2_derives` holds it to
/// `oracle::derives_a_parameter` element by element. Two transcriptions of one
/// production, each tested from the reading that produced it, is the shape
/// al8n/wren#76 was filed over.
///
/// Only the `Some(true)` / not-`Some(true)` split is §11.2's to decide. The
/// third state is a fact about the WALK — that it declines the boundary before
/// the span rule is asked at all — which no reading of the grammar can say, and
/// `the_four_stage_absorbed_element_sequence_is_a_shape_this_generator_writes` is what
/// asserts it.
const N_SPAN_DERIVES: [(&str, Option<bool>); 14] = [
  ("none", Some(true)),
  ("param", Some(true)),
  ("quoted", Some(true)),
  ("bws", Some(true)),
  ("duplicate", Some(true)),
  ("over-bound", Some(true)),
  ("two-params", Some(true)),
  ("ows-tail", Some(true)),
  ("no-value", Some(false)),
  ("trailing-token", Some(false)),
  ("trailing-quoted", Some(false)),
  ("open-quoted", None),
  ("param-then-fault", Some(false)),
  ("fault-then-param", Some(false)),
];

/// How many offsets the two derivations of `excused` are held equal at, per
/// corpus — which is every offset this crate ever asks the question at.
///
/// A REACH and not a target. It is here for the reason [`AXIS`]'s record counts
/// are: a differential that is driven to zero says nothing about the shapes it
/// was never run over, and a corpus quietly narrowed would drive the
/// disagreement count to zero by asking less. This is the denominator.
const EXCUSED_REACH: [(&str, usize); 14] = [
  ("A", 330_347),
  ("B", 521_808),
  ("C", 720_896),
  ("D", 42_636),
  ("E", 3_740),
  ("F", 384),
  ("G", 2_140),
  ("H", 280),
  ("I", 1_120),
  ("J", 486),
  ("K", 1_120),
  ("L", 516),
  ("M", 13_175),
  ("N", 128_596),
];

/// The number of offsets the two derivations of `excused` answer differently
/// at, which is the fourth zero-target of this module.
///
/// # Why `excused` needed one at all
///
/// It is the verdict that had nothing to disagree with it. `oracle::read`'s
/// other two are derived by hand in
/// `the_oracle_answers_the_readings_the_grammar_admits`; `excused` was derived
/// by hand for a handful of shapes and otherwise trusted — and it is the one
/// two of the three axis zero-targets consult FIRST. `hider-excused` against
/// `over-yield` is decided here, so a defect this shares with the reader is
/// invisible in the answer column, in the axis column and in every zero-target
/// at once.
///
/// That is not hypothetical. A witness turned up that the hiding zero-target
/// could not see, and the reason was that `oracle::resume` carried the
/// reader's own defect. It was caught by a
/// measurement taken BEFORE a fix rather than by any gate, and this is the gate
/// that was missing. Injected into `oracle::resume` again, that defect reds this
/// at 36 offsets; the `token68` guard dropped from `oracle::covers` reds it at
/// 1 684; a challenge admitted at a body's head reds it at 156;
/// `readings::cross` spelling `free: true` reds it at 36 and the body's empty
/// first element dropped from `readings` reds it at 24. Each is one injection
/// against a pristine 0, re-measured over this corpus.
///
/// # What it cannot see, measured
///
/// A misunderstanding the two SHARE, and it surfaced after this gate was
/// built.
///
/// `oracle::open_at` collapsed `Quoted::Invalid` to "this string is not open
/// here". It is the one line both derivations ask the question through:
/// `readings::covered` calls it over every opener `openable` found, and
/// `oracle::covers` calls it in both of its regimes. So a challenge cut out of
/// a run a forbidden byte sealed was excused by NEITHER derivation, this
/// differential answered 0 at every one of the offsets below, and 137 records
/// graded `yields-underivable` while the reader handed a caller a `Digest`
/// built from bytes behind an admitted opening DQUOTE.
///
/// **Measured before anything was fixed**, over both witnesses: `asked` 2
/// and 6, `differ` 0. And measured AFTER, which is the
/// stronger form: `open_at`'s fix reverted while everything else stands reds
/// this gate at **0** offsets, against a pristine 0 and beside five injections
/// that red it at 36, 1 684, 156, 36 and 24. The gate is not blind here by
/// accident — it is blind by construction, because the judgement lives in the
/// one transcription the two derivations deliberately share.
///
/// So the rule this gate rests on has a second half now: a differential over
/// two derivations grades the COMPOSITION and never the transcriptions, and a
/// judgement that lives in a shared transcription needs a reader outside this
/// crate. `http_semantics::grammar::Readings::absorb` was that reader here, and
/// it had answered the other way.
///
/// `readings`'s module doc names the other thing the two are not independent
/// about — where the free regime starts and stops — and says plainly that the
/// two agreeing about it is not evidence either.
const EXCUSED_DISAGREEMENTS: usize = 0;

#[test]
fn the_two_derivations_of_excused_answer_alike() {
  let mut differ: Vec<String> = Vec::new();
  for ((name, generator), (pinned, reach)) in generators().into_iter().zip(EXCUSED_REACH) {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let mut asked = 0usize;
    for line in records(generator) {
      for (joined, at) in excused_questions(&line) {
        asked += 1;
        let walked = crate::oracle::covered(&joined, at);
        let enumerated = crate::readings::covered(&joined, at);
        if walked != enumerated && differ.len() < 8 {
          differ.push(format!(
            "corpus {name} at {at}: oracle::covered {walked}, readings::covered \
             {enumerated} — {}",
            escape(&joined)
          ));
        }
        if walked != enumerated {
          differ.push(String::new());
        }
      }
    }
    assert_eq!(
      asked, reach,
      "corpus {name}: the offsets `excused` is asked at"
    );
  }
  let count = differ.iter().filter(|shown| shown.is_empty()).count();
  assert_eq!(
    count,
    EXCUSED_DISAGREEMENTS,
    "the two derivations of `excused` disagree; the first few are {:?}",
    differ
      .iter()
      .filter(|shown| !shown.is_empty())
      .collect::<Vec<_>>()
  );
}

#[test]
fn the_spans_this_table_names_are_the_ones_11_2_derives() {
  // [`N_SPAN_DERIVES`] restated §11.2 by hand beside `auth_param`, with
  // nothing cross-checking them. This is the
  // cross-check, and `oracle::derives_a_parameter` is the source — a row
  // entered wrong now reds here rather than pinning the reader's own answer.
  //
  // A span is one or more §5.6.1.2 elements, so it is split at the commas no
  // string holds and every element is asked. None of these spans holds a comma
  // inside a value, which `the_spans_hold_no_comma_a_string_could_swallow`
  // below is what says.
  for ((name, span), (pinned, derives)) in SPANS.into_iter().zip(N_SPAN_DERIVES) {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let whole = span.split(|&byte| byte == b',').all(|element| {
      let element = trimmed(element);
      element.is_empty() || crate::oracle::derives_a_parameter(element)
    });
    assert_eq!(
      whole,
      derives == Some(true),
      "span {name}: RFC 9110 §11.2 and this table disagree"
    );
  }
}

#[test]
fn the_two_rows_that_pin_the_span_rule_s_shape_can_fail() {
  // A row that cannot fail reports coverage it does not have.
  //
  // `duplicate` and `over-bound` are the rows that say the span rule asks RFC
  // 9110's grammar and not the walk's own bookkeeping, and no MUTATION of the
  // reader as it stands can red them — `auth_param` cannot see a repeated name
  // or a slot count, so there is no line to flip. What they red against is a
  // DESIGN: the obvious wrong implementation of the same sentence, which routes
  // an absorbed element through the walk's own `BodyCheck` and so refuses it for
  // a bound of this recipient's rather than for a fault of the grammar's.
  //
  // So this asserts what makes them able to fail at all: that each span really
  // does trip the bookkeeping it names, while §11.2 derives it. Weaken either
  // span — rename `a` to a fresh name, drop the nineteenth parameter — and the
  // row goes back to being a copy of `param`, and this reds.

  // A genuine repeat behind every one of `REFUSALS`'s three bounds, and not
  // behind one in seven. The names each of them uses are its own.
  for (refusal, name) in [
    ("duplicate", &b"a"[..]),
    ("too-many-lines", b"a1"),
    ("too-many-params", b"p1"),
  ] {
    let fragments = REFUSALS
      .iter()
      .find(|(spelled, _)| *spelled == refusal)
      .map(|(_, fragments)| *fragments)
      .unwrap_or_else(|| panic!("{refusal} is one of this family's refusals"));
    let mut used = false;
    for fragment in fragments {
      for element in fragment.split(|&byte| byte == b',') {
        let element = trimmed(element);
        // The refused challenge's first element carries the `auth-scheme` and
        // its first parameter behind §11.3's `1*SP`.
        let element = match element.iter().position(|&byte| byte == b' ') {
          Some(space) => trimmed(element.get(space..).unwrap_or_default()),
          None => element,
        };
        used |= crate::oracle::value_position(element, 0).is_some()
          && element.starts_with(name)
          && !element
            .get(name.len())
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
      }
    }
    assert!(used, "the {refusal} refusal never uses the name {name:?}");
    let span = SPANS
      .iter()
      .find(|(spelled, _)| *spelled == "duplicate")
      .map(|(_, span)| *span)
      .expect("the duplicate span");
    assert!(
      span
        .split(|&byte| byte == b',')
        .any(|element| trimmed(element).starts_with(name)),
      "the duplicate span does not repeat {name:?}, so it is a fresh name behind {refusal}"
    );
  }

  // And more parameters in one span than `MAX_PARAMS_PER_CREDENTIAL` admits in
  // one credential, so a rule that counted absorbed elements toward that bound
  // would refuse this span twice over.
  let span = SPANS
    .iter()
    .find(|(spelled, _)| *spelled == "over-bound")
    .map(|(_, span)| *span)
    .expect("the over-bound span");
  let elements = span.split(|&byte| byte == b',').count();
  assert!(
    elements > http_semantics::auth::MAX_PARAMS_PER_CREDENTIAL,
    "the over-bound span holds {elements} parameters, which is not past the bound"
  );

  // Both spans are ones §11.2 derives, which is what makes the refusal a bound
  // rather than a fault — and
  // `the_four_stage_absorbed_element_sequence_is_a_shape_this_generator_writes`
  // asserts that their rows SHOW the probe. Either rule change hides it there,
  // so both rows red.
  for name in ["duplicate", "over-bound"] {
    let derives = N_SPAN_DERIVES
      .iter()
      .find(|(spelled, _)| *spelled == name)
      .map(|(_, derives)| *derives)
      .unwrap_or_else(|| panic!("{name} is one of this family's spans"));
    assert_eq!(derives, Some(true), "span {name}: §11.2 derives it");
  }
}

#[test]
fn the_spans_hold_no_comma_a_string_could_swallow() {
  // What the split above rests on. A comma inside a `quoted-string` is that
  // value's data, so splitting on it would read one element as two and the
  // cross-check would be over elements no reading of the span has.
  //
  // `open-quoted` is the one span holding a DQUOTE that opens a string nothing
  // closes, and it holds no comma at all, so the split cannot reach one.
  for (name, span) in SPANS {
    let mut quoted = false;
    let mut escape = false;
    for &byte in span {
      match byte {
        _ if escape => escape = false,
        b'\\' if quoted => escape = true,
        b'"' => quoted = !quoted,
        b',' => assert!(!quoted, "span {name} holds a comma inside a value"),
        _ => {}
      }
    }
  }
}

#[test]
fn over_yield_would_catch_this_witness_from_the_oracle_alone() {
  // A zero-target that would not have caught the defect it was built for is
  // decoration, so this derives the class of that witness from the ORACLE
  // alone — no reader, and nothing about what any
  // revision of this workspace answers.
  //
  // `Basic a=1, a=2, y=, Bearer, x="open, Digest realm=z`. The duplicate name
  // is a bound of this recipient's, `y=` is an element RFC 9110 §11.2 derives
  // nothing at, `Bearer` completes, and the trap's DQUOTE stands at a value
  // position of the list the duplicate left open. A reader that shows the
  // `Digest` here grades `over-yield`, because the three facts below hold; the
  // reader at `45da0e3` did exactly that.
  let value = b"Basic a=1, a=2, y=, Bearer, x=\"open, Digest realm=z".to_vec();
  let verdict = crate::oracle::read(&value, probe_at(&value));

  // The probe's own bytes are a whole challenge, so there is something there
  // for a reader to show or hide.
  assert!(verdict.derives, "the probe derives where it stands");
  // And no derivation of the WHOLE value reads it as one: `y=` is neither of
  // §11.2's two alternatives, so nothing derives from it onward.
  assert!(!verdict.reached, "no reading of the whole value reaches it");
  // But a reading DOES put it inside `x`'s quoted-string, which is what makes
  // showing it an invention rather than recovery: the bytes a sender wrote as
  // that value's data were handed back as a challenge.
  assert!(verdict.excused, "a reading holds the probe inside a value");

  // The same three facts with the `y=` taken out, which is the control: the
  // span then derives, the epoch closes at `Bearer`, and no reading holds the
  // probe inside anything. Showing it there is recovery and not invention, and
  // the fix must not move this row.
  let control = b"Basic a=1, a=2, Bearer, x=\"open, Digest realm=z".to_vec();
  let verdict = crate::oracle::read(&control, probe_at(&control));
  assert!(
    verdict.derives,
    "the control's probe derives where it stands"
  );
  assert!(
    !verdict.reached,
    "the control's value does not derive either"
  );
  assert!(
    !verdict.excused,
    "no reading holds the control's probe inside a value"
  );
}

#[test]
fn the_four_stage_absorbed_element_sequence_is_a_shape_this_generator_writes() {
  // Corpus N is the first family whose dimension is what the recovered SPAN
  // CONTAINS rather than how the epoch opened, and the family is worth nothing
  // unless every row actually writes the four stages: a refusal, an element the
  // recovery absorbs, a challenge that completes, and the trap.
  let n = records(corpus_n);
  assert_eq!(
    n.len(),
    6_120,
    "two openers over seven refusals and fourteen spans, over one cursor row \
     and the thirteen spans that are a position, and over three joined \
     refusals and fourteen spans, by four closers and five traps"
  );

  // Every row is refused, and every row whose closer ENDS a list completes a
  // challenge behind that refusal — the stage the span's claim is spent at. No
  // `separator=none` control here: corpus N always writes a closer, because a
  // span nothing closes is corpus M's shape and is measured there.
  //
  // Two shapes are excluded and each for its own reason. `closer=list` is the
  // control that opens a list of its own rather than closing one, so the trap
  // behind it stands at a value position under every reading and the walk may
  // never leave that value — `Broken<HTAB>junk, Newauth b=2, x="open, Digest
  // realm=z` completes nothing at all. `span=open-quoted` is the span the walk
  // never gets past where a list IS open, and the assertion below is that one's
  // own.
  let mut completed = 0usize;
  for line in &n {
    let [_, _, spelling, _, answer] = columns(line);
    assert!(
      answer.contains("Err("),
      "corpus N refuses its first challenge: {line}"
    );
    if spelling.contains("closer=list") || spelling.contains(" span=open-quoted ") {
      continue;
    }
    let (_, behind) = answer
      .split_once("Err(")
      .expect("every corpus N value is refused at its first challenge");
    assert!(
      behind.contains("Ok["),
      "corpus N completes a challenge behind the refusal: {line}"
    );
    completed += 1;
  }
  assert_eq!(
    completed, 4_260,
    "two openers, seven refusals by thirteen spans, one cursor row by twelve \
     and three joined refusals by thirteen, three closing closers, five traps"
  );

  // And the direction the family exists for, over the trap that never closes
  // and the three closers that END a list. The probe is reachable exactly
  // where the epoch was never about these bytes — no list open anywhere — or
  // where a bound of this reader's opened an epoch a completed challenge may
  // close AND every element of the span derived.
  //
  // The malformed spans are the rows found at `45da0e3`: all
  // of them showed the probe, and 180 records of this family graded
  // `over-yield` for it.
  for (refusal, bound, its_own_list) in M_REFUSAL_IS_A_BOUND {
    for (opener, a_list_in_front) in [("none", false), ("bound", true)] {
      for (span, derives) in N_SPAN_DERIVES {
        let marker = format!(" refusal={refusal} ");
        let opener_marker = format!(" opener={opener} ");
        let span_marker = format!(" span={span} ");
        let rows: Vec<&String> = n
          .iter()
          .filter(|line| {
            let [_, _, spelling, _, _] = columns(line);
            spelling.contains(&marker)
              && spelling.contains(&opener_marker)
              && spelling.contains(&span_marker)
              && spelling.ends_with("trap=open")
              && !spelling.contains("closer=list")
          })
          .collect();
        assert_eq!(
          rows.len(),
          3,
          "corpus N, {refusal}, {opener}, {span}: the three closing closers"
        );
        // A fault with no `#auth-param` list anywhere reaches nothing, so the
        // span is not even a question there — RFC 9110 §11.2 admits a value
        // position only inside a list, and `Epoch::reaches_past_itself` is
        // what says so. Everywhere else the epoch has a list, and the probe is shown
        // only where that epoch can be CLOSED: by a bound of this reader's
        // whose whole span derived.
        let list_free = !(a_list_in_front || its_own_list);
        let shown = list_free || (bound && derives == Some(true));
        for line in rows {
          assert_eq!(
            columns(line)[4].contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
            shown,
            "corpus N, {refusal}, {opener}, {span}, behind the trap that never closes: {line}"
          );
        }
      }
    }
  }

  // And the rows where RFC 9110 §5.2's join stands between the refused
  // element's DQUOTE and its close, so the cursor is at the head of the
  // continuation line with that element's own bytes BEHIND it. The run
  // standing there is the element's SUFFIX and derives nothing; the ELEMENT
  // derives, and the span's claim is about the element.
  //
  // These rows red without that distinction: 192 of them graded
  // `hider-declined` — the reader gave a `ChallengeBoundaryUnknown` no reading
  // of the value warrants — while the walk read `y"` as a whole `auth-param`
  // and refuted a claim §11.2 never refuted.
  for (refusal, bound) in [
    ("join-duplicate", true),
    ("join-over-bound", true),
    ("join-malformed", false),
  ] {
    for opener in ["none", "bound"] {
      for (span, derives) in N_SPAN_DERIVES {
        let marker = format!(" refusal={refusal} ");
        let opener_marker = format!(" opener={opener} ");
        let span_marker = format!(" span={span} ");
        let rows: Vec<&String> = n
          .iter()
          .filter(|line| {
            let [_, _, spelling, _, _] = columns(line);
            spelling.contains(&marker)
              && spelling.contains(&opener_marker)
              && spelling.contains(&span_marker)
              && spelling.ends_with("trap=open")
              && !spelling.contains("closer=list")
          })
          .collect();
        assert_eq!(
          rows.len(),
          3,
          "corpus N, {refusal}, {opener}, {span}: the three closing closers"
        );
        // Every one of these refusals is met INSIDE the body §11.3's `1*SP`
        // opened, so a list is always open where the epoch starts and the
        // list-free case of the family above cannot arise here. The probe is
        // shown exactly where the epoch can be closed: a bound of this
        // reader's, whose whole span derived.
        let shown = bound && derives == Some(true);
        for line in rows {
          assert_eq!(
            columns(line)[4].contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
            shown,
            "corpus N across a join, {refusal}, {opener}, {span}: {line}"
          );
        }
      }
    }
  }

  // And the rows where the span begins AT the offset the refusal left the
  // cursor on. `MAX_CHALLENGE_LINES` is met when the challenge needs a line it
  // may not hold, with the cursor at the HEAD of that line — on an element the
  // walk never read — so the span's first element is one nothing has derived.
  // A span rule with a first-element exception was green over every row above
  // and invented a `Digest` here.
  for (opener, _) in [("none", ()), ("bound", ())] {
    for (span, derives) in N_SPAN_DERIVES {
      // `none` is not a position, so the cursor family does not write it: with
      // nothing at the head of that line the closer stands there, opens a
      // challenge, and the body ends in front of it within the bound.
      if span == "none" {
        continue;
      }
      let opener_marker = format!(" opener={opener} ");
      let span_marker = format!(" span={span} ");
      let rows: Vec<&String> = n
        .iter()
        .filter(|line| {
          let [_, _, spelling, _, _] = columns(line);
          spelling.contains(" refusal=line-bound-head ")
            && spelling.contains(&opener_marker)
            && spelling.contains(&span_marker)
            && spelling.ends_with("trap=open")
            && !spelling.contains("closer=list")
        })
        .collect();
      assert_eq!(
        rows.len(),
        3,
        "corpus N, line-bound-head, {opener}, {span}: the three closing closers"
      );
      // The refused challenge opened a `#auth-param` list of its own through
      // RFC 9110 §11.3's `1*SP`, so no row here is list-free and the probe is
      // shown exactly where the bound's epoch can still be CLOSED.
      for line in rows {
        assert_eq!(
          columns(line)[4].contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
          derives == Some(true),
          "corpus N, line-bound-head, {opener}, {span}: {line}"
        );
      }
    }
  }

  // The row the span rule may never reach, asserted for its own reason rather
  // than left to agree with the malformed spans by accident. `y="q` leaves a
  // string open at the comma, so the walk declines the boundary and says so —
  // and it says so wherever a list is open at all, whether or not any bound
  // could have closed the epoch.
  let mut declined = 0usize;
  let mut crossed = 0usize;
  for line in &n {
    let [_, _, spelling, _, answer] = columns(line);
    if !spelling.contains(" span=open-quoted ") || spelling.contains("closer=list") {
      continue;
    }
    // Whether a `#auth-param` list is open where the family's refusal is met,
    // which is the only thing that decides whether that DQUOTE stands at a
    // value position at all. RFC 9110 §11.2 admits one nowhere else.
    let list_free = spelling.contains(" opener=none ")
      && M_REFUSAL_IS_A_BOUND
        .iter()
        .any(|(refusal, bound, its_own)| {
          spelling.contains(&format!(" refusal={refusal} ")) && !*bound && !*its_own
        });
    if list_free {
      // No list anywhere, so no reading opens a string at that DQUOTE, the walk
      // crosses it raw and the closer behind it completes exactly as it does
      // for every other span.
      assert!(
        answer.contains("Ok["),
        "corpus N, open-quoted with no list open: the closer completes: {line}"
      );
      crossed += 1;
      continue;
    }
    assert!(
      answer.contains("Err(ChallengeBoundaryUnknown)"),
      "corpus N, open-quoted: the walk declines the boundary and says so: {line}"
    );
    declined += 1;
  }
  assert_eq!(
    crossed, 45,
    "corpus N: three list-free faults, three closing closers, five traps"
  );
  assert_eq!(
    declined, 285,
    "corpus N: the rows a list is open at, over three closing closers — the \
     joined refusals included, each of which is met inside a body and so has a \
     list of its own"
  );
}

#[test]
fn whitespace_at_the_head_of_the_value_is_the_one_edge_that_cannot_matter() {
  // The other half of the axis corpus K unfixes, closed by argument and a
  // control rather than by 288 more records — because there is no answer for
  // them to move.
  //
  // RFC 9110 §5.6.1.2 hangs `OWS` on its comma and puts none in front of the
  // first element, so whitespace at the head of the whole value derives
  // nowhere; and §5.5 says a field value "does not include leading or trailing
  // whitespace", so a field parser never hands one over. What the walk does
  // with one anyway is skip it — `Challenges::open_element` takes §5.6.3's
  // `OWS` at every cursor including the value's first — so the answer for
  // `<OWS>value` is the answer for `value`, byte for byte, and a family
  // spelling it would write 288 records that move together with corpus H's.
  //
  // Trailing whitespace on the LAST line is the same fact from the other end:
  // no join comma stands behind it, so it is the `OWS` §5.6.1.2 hangs on
  // nothing.
  let heads: [&[u8]; 4] = OPEN_HEADS;
  let mut compared = 0usize;
  for head in heads {
    for continuation in CONTINUATIONS {
      for (_, ows) in LIST_OWS {
        let mut led = ows.to_vec();
        led.extend_from_slice(head);
        let mut trailed = continuation.to_vec();
        trailed.extend_from_slice(ows);
        let read = |lines: [&[u8]; 2]| render(Ok(challenges(lines).collect()));
        let plain = read([head, continuation]);
        assert_eq!(
          read([&led, continuation]),
          plain,
          "leading OWS moved an answer: {led:?} / {continuation:?}"
        );
        assert_eq!(
          read([head, &trailed]),
          plain,
          "trailing OWS on the last line moved an answer: {head:?} / {trailed:?}"
        );
        compared += 2;
      }
    }
  }
  assert_eq!(compared, 288, "the comparisons this control makes");
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

/// What `hider-conforming` costs, per corpus.
///
/// The other half of what `hider-unresolved` used to count: a value every
/// reading derives, refused by a bound of THIS recipient's. The only such
/// refusal that ends the walk is `MAX_CHALLENGE_LINES` met with a quoted-string
/// still open across RFC 9110 §5.2's join, so the close that would settle the
/// boundary is on a line this reader may not hold — and these eleven records
/// are exactly the ones whose value CLOSES that string on a line past the
/// bound. Corpora D and E are the only families that can write one.
const CONFORMING: [(&str, usize); 14] = [
  ("A", 0),
  ("B", 0),
  ("C", 0),
  ("D", 6),
  ("E", 5),
  ("F", 0),
  ("G", 0),
  ("H", 0),
  ("I", 0),
  ("J", 0),
  ("K", 0),
  ("L", 0),
  ("M", 0),
  ("N", 0),
];

#[test]
fn hider_declined_would_catch_this_witness_from_the_oracle_alone() {
  // A zero-target that would not have caught the defect it was built for is
  // decoration, so this derives the class of al8n/wren#77's own witness from
  // the ORACLE alone — no reader, and nothing about what any revision of this
  // workspace answers.
  //
  // `Basic p1=1, …, p17=17, Bearer abc, x="open, Digest realm=z`. A reader that
  // hides the `Digest` here and says the rest is unread grades `hider-declined`,
  // because the two facts below hold; the reader at `338e37a` did exactly that,
  // and this corpus grades 36 records of corpus M's into that class against it.
  let mut value = Vec::new();
  value.extend_from_slice(b"Basic ");
  for name in 1..=17_u32 {
    if name > 1 {
      value.extend_from_slice(b", ");
    }
    value.extend_from_slice(format!("p{name}={name}").as_bytes());
  }
  value.extend_from_slice(b", Bearer abc, x=\"open, Digest realm=z");
  let probe = probe_at(&value);
  let verdict = oracle::read(&value, probe);

  // A challenge stands there, and nothing hides it: no reading of these bytes
  // puts the probe inside a §5.6.4 quoted-string, because opening the DQUOTE at
  // `x`'s value position needs a `#auth-param` list open at `x` — and `Bearer
  // abc` is §11.2's `token68`, which no `auth-param` derives, so every reading
  // has the list closed in front of it.
  assert!(verdict.derives, "a challenge derives from the probe");
  assert!(
    !verdict.excused,
    "no reading holds the probe inside a value"
  );
  // And nothing derives the WHOLE value — `x="open` is neither of §11.2's two
  // alternatives and no list is open for it to be a parameter of — so the walk
  // is in recovery rather than inside a bound of its own.
  assert!(
    !verdict.reached,
    "no derivation of the whole value reaches it"
  );
  // So every comma in front of the probe is one every reading places in the
  // same byte, and there was nothing to decline.
  assert!(
    oracle::every_comma_in_front_is_settled(&value, probe),
    "every comma in front of the probe is settled"
  );

  // The control that says the third fact is doing work: the same value with the
  // `Bearer abc` taken out. `Basic`'s list is then open where `x` stands, its
  // DQUOTE is at a value position, and the comma in front of the probe is one
  // the readings disagree about — so a walk that declines it is right to, and
  // the record grades `hider-excused` rather than into the target.
  let mut open = Vec::new();
  open.extend_from_slice(b"Basic ");
  for name in 1..=17_u32 {
    if name > 1 {
      open.extend_from_slice(b", ");
    }
    open.extend_from_slice(format!("p{name}={name}").as_bytes());
  }
  open.extend_from_slice(b", x=\"open, Digest realm=z");
  let probe = probe_at(&open);
  assert!(
    oracle::read(&open, probe).excused,
    "with no challenge between, the probe is that parameter's own data"
  );
}

#[test]
fn a_comma_every_reading_holds_inside_a_value_is_no_disagreement() {
  // `oracle::settled`'s three cases, one value each, derived from the
  // productions rather than from any tally.
  //
  // ```text
  // #element   => [ element ] *( OWS "," OWS [ element ] )
  // auth-param = token BWS "=" BWS ( token / quoted-string )
  // ```
  //
  // A comma no reading holds inside a §5.6.4 quoted-string — every reading has
  // it as §5.6.1.2's separator.
  let separator = &b"Basic a=1, Digest realm=z"[..];
  let at = separator.iter().position(|&b| b == b',').expect("a comma");
  assert!(oracle::settled(separator, at));

  // A comma EVERY reading holds inside one, because the element derives and
  // `parameter-value` beginning with a DQUOTE derives only the `quoted-string`
  // alternative — §5.6.2's `tchar` excludes DQUOTE, so the string is not a
  // choice and where it closes is where the element ends. Settled as that
  // parameter's DATA, and a walk that scans through it loses nothing.
  let data = &br#"Basic a="x,y", Digest realm=z"#[..];
  let at = data.iter().position(|&b| b == b',').expect("a comma");
  assert!(oracle::settled(data, at), "the grammar forces this string");

  // And a comma the readings DISAGREE about. `( token / quoted-string )` is one
  // alternative taken WHOLE, so the `a` behind the close leaves the element
  // deriving nothing — the string is one reading of the run and the raw comma
  // is another, and neither is forced.
  let disagreed = &br#"Basic a=","a, Digest realm=z"#[..];
  let at = disagreed.iter().position(|&b| b == b',').expect("a comma");
  assert!(
    !oracle::settled(disagreed, at),
    "an element that derives nothing forces no string"
  );

  // A string that never CLOSES forces nothing either, for the same reason: a
  // `quoted-string` needs its closing DQUOTE, so the element derives nothing
  // and a recipient reading those bytes as data is choosing one reading.
  let never = &b"Basic a=\"x, Digest realm=z"[..];
  let at = never.iter().position(|&b| b == b',').expect("a comma");
  assert!(
    !oracle::settled(never, at),
    "a string that never closes forces nothing"
  );
}

#[test]
fn every_challenge_this_walk_declines_to_place_says_so_to_the_caller() {
  // `hider-unresolved` and `hider-conforming` are the two classes that are not
  // zero, so what each costs is asserted rather than left to be read off a
  // tally. [`ZERO_TARGETS`] carries the argument for why each is a cost and not
  // a defect; this is the pair of numbers, and the claims they rest on.
  for (((name, generator), (pinned, unresolved)), (also, conforming)) in
    generators().into_iter().zip(UNRESOLVED).zip(CONFORMING)
  {
    assert_eq!(name, pinned, "the two tables are in the same order");
    assert_eq!(name, also, "the three tables are in the same order");
    let lines = records(generator);
    let counts = tally(&lines, |_| true);
    assert_eq!(
      of(&counts, "hider-unresolved"),
      unresolved,
      "corpus {name}: hider-unresolved"
    );
    assert_eq!(
      of(&counts, "hider-conforming"),
      conforming,
      "corpus {name}: hider-conforming"
    );
    // And the claim BOTH classes rest on: every one of those answers TELLS the
    // caller that the rest of the value is unread. A record graded here whose
    // answer carried no such notice would be a challenge hidden in silence.
    for line in &lines {
      let [_, _, _, axis, answer] = columns(line);
      if axis == "hider-unresolved" || axis == "hider-conforming" {
        assert!(
          answer.contains("Err(ChallengeBoundaryUnknown)"),
          "corpus {name}: graded {axis} with no notice: {line}"
        );
      }
      // And the claim `hider-conforming` alone rests on: the fault that refused
      // the value is `MAX_CHALLENGE_LINES`, which is the one bound of this
      // reader's that ends the walk. Nothing else can put a record here.
      if axis == "hider-conforming" {
        assert!(
          answer.contains("Err(ChallengeSpansTooManyLines)"),
          "corpus {name}: graded hider-conforming without the line bound: {line}"
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
    ("hider-conforming", 6),
    ("hider-excused", 655),
    ("hider-unresolved", 6),
    ("no-probe", 436),
    ("yields", 751),
    ("yields-underivable", 1_634),
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
