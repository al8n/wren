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
//!   constant records both halves of the move — and the SHAPE it identifies
//!   them by is wider than the set, so the surplus is a third asserted column
//!   rather than a caveat.
//! - **The differential over the two derivations of `excused` cannot grade
//!   what they share.** [`EXCUSED_DISAGREEMENTS`] is 0 over 1 839 285 offsets,
//!   and [`SHARED_JUDGEMENTS`] is what says which decisions that zero is not
//!   about: 29 judgements the two take through one transcription, 17 of which
//!   that gate answers nothing for. Eight now red a leaf property instead, and
//!   **nine are answered by nothing at all** — each measured, one injection at
//!   a time. [`PROSE_SHARED`] is the second class, the rules the two state
//!   twice in WORDS, which no parse of a `use` declaration can find; those six
//!   are caught, and by [`ZERO_TARGETS`] rather than by the differential.
//!
//! # Every number here is MEASURED or REASONED, and says which
//!
//! A number that was worked out and a number that was run look the same on the
//! page, and this module has shipped one of each side by side: [`RECOVERED`]'s
//! surplus was stated as 64 with the split the wrong way round, reasoned from a
//! true fact about corpus F, beside per-corpus counts that had been run. So the
//! convention from here: **a measured number carries the command that produced
//! it**, in its own doc or in the constant it is asserted against, and a
//! REASONED number says the word. Everything asserted in this file is measured
//! by definition — a failure prints the number — and what needs the mark is the
//! prose: the injection tables, the record counts quoted in doc comments, and
//! anything a report will quote later.
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
fn generators() -> [(&'static str, Generator); 15] {
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
    ("O", corpus_o),
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
    total, 948_544,
    "the corpus is the size every figure pinned here counts over"
  );

  let mut shared: Vec<&String> = counts
    .iter()
    .filter(|(_, times)| **times > 1)
    .map(|(key, _)| key)
    .collect();
  shared.sort();
  assert_eq!(shared.len(), 32, "the groups that share a key: {shared:?}");
  assert_eq!(counts.len(), 948_384, "distinct inputs behind the records");
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
/// [`RECOVERED`] identifies the record set one earlier commit moved, asserts
/// its size and asserts the surplus its identification carries, and
/// `the_oracle_answers_the_readings_the_grammar_admits` derives the oracle's
/// verdicts by hand from the RFC rather than from any tally.
///
/// # These numbers are expected to move
///
/// They are a pin, not a target. A change to `http_semantics::auth` that moves
/// an answer moves a cell here, and the point is that it moves in the DIFF —
/// where a reader can ask which cell and why — rather than in a figure nobody
/// can recompute. Re-derive them from a failure's own message.
const AXIS: [Pinned; 15] = [
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
    80,
    &[("hider-excused", 64), ("yields-underivable", 16)],
    16,
    120,
  ),
  (
    "I",
    320,
    &[("hider-excused", 256), ("yields-underivable", 64)],
    64,
    480,
  ),
  (
    "J",
    144,
    &[("hider-excused", 18), ("yields-underivable", 126)],
    306,
    180,
  ),
  (
    "K",
    320,
    &[("hider-excused", 256), ("yields-underivable", 64)],
    64,
    480,
  ),
  (
    "L",
    144,
    &[("hider-excused", 45), ("yields-underivable", 99)],
    303,
    282,
  ),
  (
    "M",
    1_260,
    &[
      ("hider-excused", 432),
      ("yields", 54),
      ("yields-underivable", 774),
    ],
    2_102,
    3_214,
  ),
  // `over-yield` stood at 135 and stands at 0: `sustain_the_epoch` asks a
  // crossed element both of RFC 9110 §11.6.1's readings now, and the one that
  // takes §11.3's `1*SP` opens a `#auth-param` list whose body derives nothing.
  // The 135 are `hider-excused` — that list is what puts the probe inside a
  // value.
  (
    "N",
    7_872,
    &[
      ("hider-excused", 2_864),
      ("hider-unresolved", 76),
      ("yields", 372),
      ("yields-underivable", 4_560),
    ],
    11_730,
    19_482,
  ),
  // The family that found both inventions, and neither cell it
  // found them in is a zero-target standing at a number any more.
  // `leading_empty_elements_before_a_quoted_parameter_are_a_shape_this_generator_writes` carries
  // both witnesses and what each says.
  //
  // `over-yield` stood at 54 and stands at 0. `Recovery` is now taken at the
  // offset the element the OUTER `#challenge` list holds begins at, so the one
  // value position that run carries is the one a recovery scans from; the 54
  // are `hider-excused`, because the reading that opens `x<SP>="…` holds the
  // probe inside its string and showing it was the invention.
  //
  // `hider-unexcused` stood at 18 and stands at 0, and `no-probe` is where they
  // went — with six `hider-excused` rows of the same shape beside them. That
  // move is the ORACLE's and not the module's: `derives_as_a_challenge` asks
  // whether an element of the outer list may BEGIN at the probe now, which is
  // what says nothing stands at a body's first element for a reader to hide.
  // Every answer digest held across it, which is the split [`ANSWERS`] is for.
  (
    "O",
    3_192,
    &[
      ("hider-excused", 1_344),
      ("hider-unresolved", 72),
      ("no-probe", 24),
      ("yields", 222),
      ("yields-underivable", 1_530),
    ],
    4_854,
    5_103,
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
const UNRESOLVED: [(&str, usize); 15] = [
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
  // Corpus O's 72 are the rows where the walk declined a comma the readings
  // disagree about, which is the cost this class counts and not a defect. What
  // this family found instead is in `over-yield` and in `hider-unexcused`.
  ("O", 72),
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
const ANSWERS: [(&str, &str); 15] = [
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
    "7438c7ab172900f849c516744f45c54c3c0a1536e6ee4ad12d75504c39292dd8",
  ),
  (
    "I",
    "a0f62be9c4e0214fc748d7989d4ab900e867a19418bbd397debaf29371aba081",
  ),
  (
    "J",
    "2fe0208d2cde7889ef96e758296125fb10bb18361bdbe0168cb249ec26aeffbe",
  ),
  (
    "K",
    "51ffbd35165c416fd8daf17554e6b68728c114f909bc929cd4c7b525bff91acb",
  ),
  (
    "L",
    "667dd61eead8026ea82e1a9ca1e39524ed910b7df917d3382a681e7ef5e553fb",
  ),
  (
    "M",
    "0b95a8bdee78c39fc371f4d70ab830c0fc31d9d3d286d4636861d335eeefd3f9",
  ),
  (
    "N",
    "4623a16a476c6b2000dd030f4cb35d88570b8b2ce3b1492abe984c13928fb535",
  ),
  (
    "O",
    "99b31741ea19915fd80464c1d4fe8cf93fdd748d83c1dfd4146dfb1fbc06e11c",
  ),
];

const WHOLE: &str = "c4943e11fcc9dc70954c449b5da8cdd49d37639c79b1ea58cf7d376c4f350fb6";

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
const FAULTS: [(&str, &[(&str, usize)]); 15] = [
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
      ("ChallengeBoundaryUnknown", 40),
      ("MalformedParameter", 56),
      ("UnterminatedQuotedString", 24),
    ],
  ),
  (
    "I",
    &[
      ("ChallengeBoundaryUnknown", 160),
      ("MalformedParameter", 224),
      ("UnterminatedQuotedString", 96),
    ],
  ),
  (
    "J",
    &[
      ("ChallengeBoundaryUnknown", 18),
      ("MalformedScheme", 114),
      ("MissingScheme", 48),
    ],
  ),
  (
    "K",
    &[
      ("ChallengeBoundaryUnknown", 160),
      ("MalformedParameter", 224),
      ("UnterminatedQuotedString", 96),
    ],
  ),
  (
    "L",
    &[
      ("ChallengeBoundaryUnknown", 27),
      ("MalformedParameter", 18),
      ("MalformedScheme", 177),
      ("MissingScheme", 48),
      ("UnterminatedQuotedString", 12),
    ],
  ),
  (
    "M",
    &[
      ("ChallengeBoundaryUnknown", 327),
      ("ChallengeSpansTooManyLines", 180),
      ("DuplicateParameter", 180),
      ("MalformedParameter", 285),
      ("MalformedScheme", 1_560),
      ("MissingScheme", 180),
      ("TooManyParameters", 432),
      ("UnterminatedQuotedString", 70),
    ],
  ),
  (
    "N",
    &[
      ("ChallengeBoundaryUnknown", 2_013),
      ("ChallengeSpansTooManyLines", 1_392),
      ("DuplicateParameter", 1_440),
      ("MalformedParameter", 2_367),
      ("MalformedScheme", 5_556),
      ("MissingScheme", 720),
      ("TooManyParameters", 5_376),
      ("UnterminatedQuotedString", 618),
    ],
  ),
  (
    "O",
    &[
      ("ChallengeBoundaryUnknown", 567),
      ("MalformedParameter", 627),
      ("MalformedScheme", 2_427),
      ("TooManyParameters", 798),
      ("UnterminatedQuotedString", 684),
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
/// moved out of `hider-unexcused`, and how many MORE the shape that identifies
/// them selects: corpus, moved, surplus.
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
/// So [`recovered_from_a_forbidden_byte`] identifies the SHAPE by the pair of
/// faults it now answers with, and the shape is wider than the set: two
/// records can carry it and only one of them be a record that commit moved.
/// The three columns are therefore corpus, the records it moved, and the
/// records the shape also selects that it did not — and BOTH are asserted, so
/// the surplus is a bounded quantity rather than a rounding a later reader
/// quotes as if it were exact.
///
/// # The surplus, and two numbers that were wrong
///
/// An over-selection nobody has bounded easily gets quoted as exact, and
/// this constant had already been quoted wrong. Its doc
/// said F's 96 were "32 of them and 64 that were never in the set", by the
/// argument that the surplus is where the octet stands BEHIND the probe. Both
/// halves are wrong and the argument is too: the commit moved 64 of F's
/// records, half of them with the octet behind the probe, and the surplus is
/// 32.
///
/// The numbers above were reasoned about; these were run. This tree's own
/// corpus source will not COMPILE against either revision — it names
/// `ChallengeBoundaryUnknown`, which neither had — so the source AT
/// `evidence/auth-forbidden-byte-refuses` was built against each of the two
/// trees instead, and the axis columns compared record by record. That
/// substitution is sound for exactly one reason and it was checked rather than
/// assumed: `corpus_f`, [`OCTETS`] and [`PROBE`] are byte-identical between
/// that tag and this tree, so the record keys line up.
///
/// ```text
/// git archive <tag> | tar -x -C <dir>            # both tags
/// cargo run --manifest-path <probe>/Cargo.toml -- <dump>   # one source, two http-semantics
/// paste <(cut -f1,2,3,4 before.tsv) <(cut -f4 refuses.tsv) |
///   awk -F'\t' '$4=="hider-unexcused" && $5!="hider-unexcused"'
/// ```
///
/// `90 D · 15 E · 64 F`, 169 records. Intersected by key with what the
/// predicate selects in this tree: every one of the 169 is selected, D and E
/// hold nothing else, and F holds 32 more.
///
/// **The surplus is exactly F's `behind=true split=true` rows** — the octet
/// behind the probe AND the value written across §5.2's join — all 8 forbidden
/// octets by 2 closers by 2 trailings. They were `hider-unexcused` at BOTH
/// tags, answering `InvalidQuotedString` alone at the first and
/// `InvalidQuotedString` then `MissingScheme` at the second; they became
/// `hider-excused` later on this branch, when the oracle stopped asking whether
/// the WHOLE value derives. [`selected_but_never_moved`] is that
/// identification, and it reads the spelling column because the answer column
/// no longer separates them: F's `behind=true` rows answer the same two faults
/// on one line as across a join, byte for byte.
const RECOVERED: [(&str, usize, usize); 3] = [("D", 90, 0), ("E", 15, 0), ("F", 64, 32)];

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
///
/// A SHAPE and not a set. [`selected_but_never_moved`] is the other half:
/// which records carrying the shape `evidence/auth-forbidden-byte-refuses` did
/// not move.
fn recovered_from_a_forbidden_byte(line: &str) -> bool {
  let [_, _, _, axis, answer] = columns(line);
  axis == "hider-excused"
    && answer.contains("Err(InvalidQuotedString)")
    && answer.contains("Err(ChallengeBoundaryUnknown)")
}

/// A byte no RFC 9110 field value admits: a CTL other than HTAB.
///
/// `OCTETS`'s doc carries the derivation and the §5.5 sentence it rests on;
/// this is that rule as a predicate, and it is the one fact
/// [`selected_but_never_moved`] needs about a byte.
fn a_byte_no_field_value_admits(byte: u8) -> bool {
  (byte < 0x20 && byte != b'\t') || byte == 0x7F
}

/// Whether this record carries [`recovered_from_a_forbidden_byte`]'s shape and
/// is one that `evidence/auth-forbidden-byte-refuses` did NOT move: the value
/// is written over more than one field line, and the byte that seals its string
/// stands BEHIND the probe.
///
/// # Read from the record's own bytes, and why that took a second look
///
/// This set was first identified from the SPELLING column — the
/// generator's own label for a case — on the ground that the answer column
/// cannot separate the two, which is true and measured: F's `behind=true` rows
/// answer `InvalidQuotedString` then `ChallengeBoundaryUnknown` on one line and
/// across a join, byte for byte, with the same axis. But the answer column is
/// not the only one that is not the label. The CASE column is the input, and
/// the input is where the difference lives — necessarily, because RFC 9110
/// §5.2 makes the two spellings ONE value, so what separates them is how it was
/// written and nothing else.
///
/// So both facts are read from the case: `|` is what the record contract
/// separates field lines with, and the sealing byte's offset is compared with
/// the probe's in the value those lines join to. Measured against the label it
/// replaces: the two agree on every one of the 201 records the shape selects,
/// and `the_records_one_earlier_commit_moved_are_still_the_ones_it_moved`
/// asserts that agreement rather than leaving it as a note, so a generator
/// whose label drifts from its inputs reds.
fn selected_but_never_moved(line: &str) -> bool {
  let [_, case, _, _, _] = columns(line);
  let lines: Vec<Vec<u8>> = case.split('|').map(unescape).collect();
  if lines.len() < 2 {
    return false;
  }
  let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
  let joined = join(&refs);
  let Some(probe) = last_index_of(&joined, PROBE) else {
    return false;
  };
  joined
    .iter()
    .position(|&byte| a_byte_no_field_value_admits(byte))
    .is_some_and(|sealed| sealed > probe)
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
  for (name, moved, surplus) in RECOVERED {
    let (_, generator) = generators()
      .into_iter()
      .find(|(known, _)| *known == name)
      .expect("every corpus [`RECOVERED`] names has a generator");
    let selected: Vec<String> = records(generator)
      .into_iter()
      .filter(|line| recovered_from_a_forbidden_byte(line))
      .collect();
    let counted = selected
      .iter()
      .filter(|line| selected_but_never_moved(line))
      .count();
    // Both halves, so the shape's over-selection is a quantity this gate holds
    // rather than a caveat in a doc comment. A record that leaves the surplus
    // and a record that joins it move different numbers here.
    assert_eq!(
      counted, surplus,
      "corpus {name}: records carrying the shape that commit never moved"
    );
    assert_eq!(
      selected.len().saturating_sub(counted),
      moved,
      "corpus {name}: the records that commit moved"
    );
    // The label the generator writes says the same thing as the bytes, on
    // every record the shape selects. [`selected_but_never_moved`] reads the
    // bytes; this is what stops the two readings drifting apart unnoticed, and
    // it is the whole of what the spelling column is still trusted for.
    for line in &selected {
      let [_, _, spelling, _, _] = columns(line);
      assert_eq!(
        selected_but_never_moved(line),
        spelling.contains("behind=true") && spelling.contains("split=true"),
        "corpus {name}: the case and the spelling disagree about this record"
      );
    }
  }

  // And the shape is written nowhere else. [`RECOVERED`] names three corpora
  // and asserts nothing about the other eleven, so without this a shape
  // appearing in one of them would be surplus nobody counted.
  //
  // A ZERO-target rather than a pin, and its non-vacuity is measured rather
  // than assumed: the sweep reaches 942 302 records and finds none, so deleting
  // it reds nothing on this tree. What it catches was shown by making one
  // corpus match — the failure then names that corpus rather than one of the
  // three, which is a different message from every other way this test can
  // fail.
  for (name, generator) in generators() {
    if RECOVERED.iter().any(|(known, _, _)| *known == name) {
      continue;
    }
    assert_eq!(
      records(generator)
        .iter()
        .filter(|line| recovered_from_a_forbidden_byte(line))
        .count(),
      0,
      "corpus {name}: the shape [`RECOVERED`] counts is written outside it"
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

  // The opener that whitespace moves off the cursor is REACHED: 160 of corpus
  // I's records carry one, and the walk declines the comma behind it rather
  // than crossing into a value. 128 of them answered `over-yield` at the commit
  // that added corpus H; the other 32 are the `realm = "c` continuation
  // added here, which spells §11.2's `BWS` in front of the same `=`.
  assert_eq!(
    i.iter()
      .filter(|line| columns(line)[4].contains("Err(ChallengeBoundaryUnknown)"))
      .count(),
    160,
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
    completed, 108,
    "corpus L: three closers over two openers, three faults, six traps"
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
    1_260,
    "five openers, seven refusals, six separators, six traps"
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
    completed, 630,
    "corpus M: three closing separators over five openers, seven refusals, six traps"
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
  assert_eq!(bare.len(), 252, "seven refusals, six separators, six traps");
  assert_eq!(
    differing(&bare, &prefixed),
    Vec::<String>::new(),
    "a list-free fault in front of the value moved a probe"
  );

  // And the control that says the pairing is about the LIST rather than about
  // the prefix's bytes: the SAME fault, met inside a list, moves exactly the
  // rows an unclosable epoch is supposed to move — the twenty-seven where a
  // bound of this reader's would otherwise have been closed by the challenge
  // behind it. Nowhere else, and never in the direction of showing more.
  let moved = differing(&list, &list_fault);
  assert_eq!(
    moved.len(),
    27,
    "three receiver bounds, three closing separators, three DQUOTE traps: {moved:?}"
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
      rows, 180,
      "corpus M, {refusal}: six separators, six traps, five openers"
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
/// # And a second column, which is a different production's question
///
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`. The `bool` is
/// whether some element of the span OPENS a `#auth-param` list under RFC 9110
/// §11.6.1's challenge reading of it — the reading `derives_a_parameter` knows
/// nothing about, because it is not the one that derives. A span that opens one
/// leaves a list open behind it whether or not §11.2 derives its elements, and
/// the value has stopped deriving inside that list: the body opens at an `=` or
/// at the `BWS` in front of one, and §11.2 derives neither.
///
/// It is cross-checked below out of `oracle`'s own transcriptions of
/// `token_end`, `skip_sp` and `token68_end`, composed here. One transcription
/// per production with the COMPOSITION written twice is this crate's rule, and
/// this is the second composition.
const N_SPAN_DERIVES: [(&str, Option<bool>, bool); 15] = [
  ("none", Some(true), false),
  ("param", Some(true), false),
  ("quoted", Some(true), false),
  ("bws", Some(true), false),
  // The one span that does. §11.2's `BWS` is §5.6.3's `OWS`, so the SP in front
  // of the `=` is also the `1*SP` §11.3's body needs — and the body it opens
  // begins AT the `=`, which no `token68` takes and no `auth-param` derives.
  ("bws-sp", Some(true), true),
  ("duplicate", Some(true), false),
  ("over-bound", Some(true), false),
  ("two-params", Some(true), false),
  ("ows-tail", Some(true), false),
  ("no-value", Some(false), false),
  ("trailing-token", Some(false), false),
  ("trailing-quoted", Some(false), false),
  ("open-quoted", None, false),
  ("param-then-fault", Some(false), false),
  ("fault-then-param", Some(false), false),
];

/// How many offsets the two derivations of `excused` are held equal at, per
/// corpus — which is every offset this crate ever asks the question at.
///
/// A REACH and not a target. It is here for the reason [`AXIS`]'s record counts
/// are: a differential that is driven to zero says nothing about the shapes it
/// was never run over, and a corpus quietly narrowed would drive the
/// disagreement count to zero by asking less. This is the denominator.
///
/// # And the denominator is not the coverage
///
/// 1 839 285 offsets and 0 disagreements is not *these two derivations agree
/// about everything*. **A differential over two derivations grades the
/// composition and never the transcriptions they share**, and
/// [`SHARED_JUDGEMENTS`] is the enumeration of what that leaves out: 29
/// judgements the two take through one piece of code, of which **9 can still be
/// broken without ANY gate of this crate reporting anything** — measured one
/// injection at a time, each against a pristine 0, each moving answers of both
/// derivations alike. It was 17 before this crate grew the eight leaf
/// properties, and the differential itself still answers 0 for all 17 of them:
/// what changed is that eight now red somewhere else. Whoever reads this number
/// should read that table in the same breath.
const EXCUSED_REACH: [(&str, usize); 15] = [
  ("A", 330_347),
  ("B", 521_808),
  ("C", 720_896),
  ("D", 42_636),
  ("E", 3_740),
  ("F", 384),
  ("G", 2_140),
  ("H", 312),
  ("I", 1_248),
  ("J", 588),
  ("K", 1_248),
  ("L", 624),
  ("M", 15_852),
  ("N", 164_864),
  ("O", 32_598),
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
/// # What it cannot see, enumerated and measured
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
/// accident — it is blind by construction, because the judgement lives in a
/// transcription the two derivations deliberately share.
///
/// So the rule this gate rests on has a second half: **a differential over two
/// derivations grades the COMPOSITION and never the transcriptions**, and a
/// judgement that lives in a shared transcription needs a reader outside this
/// crate. `http_semantics::grammar::Readings::absorb` was that reader for
/// `open_at`, and it had answered the other way.
///
/// That rule was a sentence, and a sentence does not say WHICH judgements it
/// covers. [`SHARED_JUDGEMENTS`] does: every decision the two take through one
/// piece of code, with the disagreement count this gate reports when it is
/// broken. **17 of the 29 are zeros for THIS gate**, and one of them is
/// `open_at`'s, so the rule is not an inference from a single incident but the
/// shape of the instrument; the four this gate does catch are caught only
/// because the two walks consume `boundary`, `token_end` and `token68_end` at
/// different places.
///
/// So this 0 means: over 1 839 285 offsets, the two COMPOSITIONS agree. It does
/// not mean the readings they compose are right. Eight of the seventeen are now
/// answered by a property instead — [`WRONGNESS_GATES`] is the whole set of
/// things in this crate that make a wrongness claim — and nine are answered by
/// nothing.
///
/// `readings`'s module doc names the other thing the two are not independent
/// about — where the free regime starts and stops — and says plainly that the
/// two agreeing about it is not evidence either.
const EXCUSED_DISAGREEMENTS: usize = 0;

#[test]
fn the_two_derivations_of_excused_answer_alike() {
  use std::io::Write;

  // The instrument behind [`SHARED_JUDGEMENTS`]'s `moves` column. With
  // `EXCUSED_DUMP` set, both derivations' answers are written as they are
  // taken, so a defect injected into a transcription the two SHARE can be shown
  // to move answers this gate then reports nothing about — which is the whole
  // difference between a blind row and an unexercised one. Unset, which is
  // every run but a measurement, nothing is opened and nothing is written.
  let mut dump = std::env::var_os("EXCUSED_DUMP").map(|path| {
    std::io::BufWriter::new(std::fs::File::create(path).expect("the dump path is writable"))
  });
  let mut differ: Vec<String> = Vec::new();
  for ((name, generator), (pinned, reach)) in generators().into_iter().zip(EXCUSED_REACH) {
    assert_eq!(name, pinned, "the two tables are in the same order");
    let mut asked = 0usize;
    for line in records(generator) {
      for (joined, at) in excused_questions(&line) {
        asked += 1;
        let walked = crate::oracle::covered(&joined, at);
        let enumerated = crate::readings::covered(&joined, at);
        if let Some(out) = dump.as_mut() {
          writeln!(out, "{name}\t{at}\t{walked}\t{enumerated}").expect("the dump is written");
        }
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
  if let Some(out) = dump.as_mut() {
    out.flush().expect("the dump is written");
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

// ───────── what that zero grades, and the judgements it is not about ─────────

/// One judgement the two derivations of `excused` take through a transcription
/// they SHARE, and what [`EXCUSED_DISAGREEMENTS`] reports when it is wrong.
///
/// A row is a DECISION and not a function. `open_at` is one function and four
/// decisions, and a defect can live in any one of them; listing the functions
/// would say where the sharing is without saying what it costs. The sharing is
/// right — two hand-written copies of one production is the shape al8n/wren#76
/// was filed over and the shape `coding-corpus` exists to prevent — so what was
/// missing was never the independence, it was a statement of which judgements
/// fall outside the comparison the sharing buys.
struct Shared {
  /// The item `readings` imports from [`oracle`](crate::oracle) rather than
  /// writing again.
  of: &'static str,
  /// The decision taken inside it — the branch a defect would live in.
  judgement: &'static str,
  /// The defect injected to measure the row, against the pristine source.
  injection: &'static str,
  /// How many of the offsets in [`EXCUSED_REACH`] change `oracle::covered`'s
  /// answer under that injection, and how many change `readings::covered`'s.
  ///
  /// This is what tells a BLIND row from an unexercised one, and the reason
  /// every row carries it: a zero disagreement count over an injection that
  /// moves nothing is not a blind spot, it is a state the corpus cannot spell
  /// at the offsets the question is asked at, and reporting the two alike would
  /// overstate the gate's blindness as badly as omitting them understates it.
  moves: (usize, usize),
  /// What [`EXCUSED_DISAGREEMENTS`] counts under the injection.
  differ: usize,
  /// The gate that reds under the injection because the answer is WRONG, or
  /// the empty string where none does.
  ///
  /// It must be one of [`WRONGNESS_GATES`], and the distinction is the whole
  /// content of this column. Almost every injection below also reds [`AXIS`],
  /// [`ANSWERS`] and [`WHOLE`] — but those are PINS, and [`AXIS`]'s own doc says
  /// so in as many words: a cell that moved says one of the reader and the
  /// oracle moved, and instructs a maintainer to go and look. A gate named here
  /// says the judgement is wrong.
  caught_by: &'static str,
  /// The known-wrong spelling this crate keeps so that [`caught_by`](Self::caught_by)
  /// is proven on every run rather than recorded, or the empty string where the
  /// row has none.
  ///
  /// Only the property gates can carry one: a control is an implementation
  /// passed to the property, and the differential's two derivations are whole
  /// walks rather than a function it takes.
  control: &'static str,
}

impl Shared {
  /// Whether the injection moves an answer of either derivation at all.
  const fn reached(&self) -> bool {
    self.moves.0 > 0 || self.moves.1 > 0
  }

  /// Whether any gate of this crate answers a defect in this judgement.
  const fn covered(&self) -> bool {
    !self.caught_by.is_empty()
  }

  /// Whether the gate is silent about a defect it demonstrably could have
  /// been asked about.
  const fn blind(&self) -> bool {
    self.reached() && !self.covered()
  }
}

/// Every judgement the two derivations of `excused` take through ONE
/// transcription, and the measured answer to *would this gate say so*.
///
/// # How each row was measured, and how to re-measure it
///
/// One injection at a time into `oracle`, applied to the pristine tree, with
/// nothing else changed:
///
/// - `differ` is `cargo test -p auth-corpus --release
///   the_two_derivations_of_excused_answer_alike`, read from the failure's own
///   `left:` — 0 where it passes.
/// - `moves` is a dump of `(oracle::covered, readings::covered)` over the same
///   offsets, compared to the pristine dump line by line. Setting `EXCUSED_DUMP`
///   makes the gate write that dump as it runs, so both numbers of a row come
///   from one command.
///
/// # What the table says
///
/// **9 of the 29 rows are BLIND**: the injection moves as many as 30 826 of the
/// differential's own answers — in BOTH derivations, identically — and nothing
/// in this crate says so. That pair was measured over a corpus of 1 767 244
/// offsets, which is [`EXCUSED_REACH`] BEFORE corpus O; the ratio is the claim
/// and neither figure has been re-measured since, so neither is restated
/// against the corpus as it now stands. It was 17, and the eight leaf properties
/// are the difference; each of those rows names the property that catches it
/// and the control that proves the property still does.
///
/// Twelve rows are covered, by two gates of very different kinds. Four are
/// caught by the differential, and the reason is worth naming because it is not
/// design: `boundary`, `token_end` and `token68_end` are asked at DIFFERENT
/// places by the two walks, so a defect in them reaches one derivation before
/// the other and the composition disagrees with itself — a shared transcription
/// is graded by a differential only where the two happen to consume it
/// asymmetrically. The other eight are caught by a property stated from the
/// production, which does not care how the two walks consume anything.
///
/// Eight rows move neither derivation's answer at any of the offsets asked, so
/// the gate's zero is not evidence about them either way. Two of those are the
/// most interesting rows here, because they are not dead code: `B2` moves the
/// axis of 491 628 records and `Q1` moves nothing at all. The gate asks one
/// question — *does some reading hold this offset inside a quoted-string* — and
/// a judgement the oracle needs for a DIFFERENT verdict is outside it however
/// live it is elsewhere.
///
/// Blind by transcription, which is the shape a reader should take away:
/// `value_position`, `skip_ows`, `skip_sp` and `raw_comma_end` were wholly
/// blind and are now wholly covered; `token_end` was and is wholly covered;
/// what is left blind is `open_at` two of four, `scan_quoted` three of seven,
/// `boundary` two of four, and `token68_end` two of three. Every remaining
/// blind row is a judgement about a §5.6.4 quoted-string or an element
/// boundary, which is where this crate's question lives — so the properties
/// took the leaves that were easiest to state from a production and left the
/// ones that are the question itself.
const SHARED_JUDGEMENTS: [Shared; 29] = [
  Shared {
    of: "open_at",
    judgement: "a DQUOTE standing AT the probe opens no string that covers it",
    injection: "`quote < probe` becomes `quote <= probe`",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "open_at",
    judgement: "a scan that reached a closing DQUOTE does not cover the probe",
    injection: "a scan still open at the probe stops covering it",
    moves: (30_826, 30_826),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "open_at",
    judgement: "a scan a forbidden byte SEALED does cover the probe",
    injection: "an invalid scan stops covering it",
    moves: (360, 360),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "open_at",
    judgement: "the scan is cut at the probe, so a close BEHIND it shuts nothing",
    injection: "the scan reads the whole value",
    moves: (10_534, 10_534),
    differ: 0,
    caught_by: "open_at_reads_no_byte_at_or_behind_the_probe",
    control: "open_at_reading_past_the_probe",
  },
  Shared {
    of: "scan_quoted",
    judgement: "input running out leaves the string open rather than invalid",
    injection: "the end of input reports an invalid scan",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "scan_quoted",
    judgement: "a close is reported one PAST the closing DQUOTE",
    injection: "the close is reported at it",
    moves: (876, 876),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "scan_quoted",
    judgement: "a backslash opens RFC 9110 §5.6.4's `quoted-pair`",
    injection: "the backslash is ordinary data",
    moves: (118, 118),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "scan_quoted",
    judgement: "a `quoted-pair` admits HTAB, SP, VCHAR and `obs-text` and nothing else",
    injection: "the escaped byte is admitted whatever it is",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "scan_quoted",
    judgement: "`obs-text` IS `qdtext`",
    injection: "the high half of the octet range is refused",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "scan_quoted",
    judgement: "a byte `qdtext` forbids makes the whole scan invalid",
    injection: "the last arm admits the byte and reads on",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "scan_quoted",
    judgement: "HTAB and SP are `qdtext`",
    injection: "the two are refused inside a string",
    moves: (764, 764),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "Quoted",
    judgement: "a scan reports THREE outcomes and not two: a close, an end of input, and a byte the grammar forbids",
    injection: "the invalid outcome is spelled as the open one at both of its returns",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "raw_comma_end",
    judgement: "only a raw comma or the value's end stops the run, never a DQUOTE",
    injection: "a DQUOTE stops it too",
    moves: (1_518, 1_518),
    differ: 0,
    caught_by: "a_raw_run_ends_at_the_first_raw_comma",
    control: "raw_comma_end_that_a_dquote_stops",
  },
  Shared {
    of: "boundary",
    judgement: "the `OWS` in front of the comma is the LIST's and not the element's",
    injection: "the element is asked to hold it",
    moves: (176, 176),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "boundary",
    judgement: "the value ENDING is an element boundary",
    injection: "it is no boundary",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "boundary",
    judgement: "the `OWS` behind the comma is the list's too",
    injection: "the next element starts on it",
    moves: (2_876, 2_876),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "boundary",
    judgement: "a byte that is neither `OWS` nor a comma ends NO element",
    injection: "it ends the value",
    moves: (29_112, 5_558),
    differ: 23_554,
    caught_by: "the_two_derivations_of_excused_answer_alike",
    control: "",
  },
  Shared {
    of: "Edge",
    judgement: "the value ending is not the next element starting",
    injection: "the end is reported as an element start at the value's length",
    moves: (0, 0),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "skip_ows",
    judgement: "RFC 9110 §5.6.3's `OWS` is SP and HTAB",
    injection: "HTAB is not crossed",
    moves: (2_386, 2_386),
    differ: 0,
    caught_by: "a_whitespace_run_is_crossed_whole",
    control: "skip_ows_without_htab",
  },
  Shared {
    of: "skip_sp",
    judgement: "the `1*SP` a challenge's body opens behind is SP alone, never HTAB",
    injection: "HTAB is crossed too",
    moves: (898, 898),
    differ: 0,
    caught_by: "a_whitespace_run_is_crossed_whole",
    control: "skip_sp_with_htab",
  },
  Shared {
    of: "token_end",
    judgement: "an empty run is no `token`",
    injection: "the empty run is one",
    moves: (34_847, 35_019),
    differ: 172,
    caught_by: "the_two_derivations_of_excused_answer_alike",
    control: "",
  },
  Shared {
    of: "token_end",
    judgement: "the comma RFC 9110 §5.6.1 separates with is no `tchar`",
    injection: "the alphabet admits it",
    moves: (8_582, 10_484),
    differ: 1_902,
    caught_by: "the_two_derivations_of_excused_answer_alike",
    control: "",
  },
  Shared {
    of: "token68_end",
    judgement: "an empty run is no `token68`",
    injection: "the empty run is one",
    moves: (2_290, 180),
    differ: 2_110,
    caught_by: "the_two_derivations_of_excused_answer_alike",
    control: "",
  },
  Shared {
    of: "token68_end",
    judgement: "the padding is TRAILING and no part of the alphabet",
    injection: "the trailing run stops being crossed",
    moves: (656, 656),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "token68_end",
    judgement: "`token68`'s alphabet excludes DQUOTE",
    injection: "the alphabet admits it",
    moves: (220, 220),
    differ: 0,
    caught_by: "",
    control: "",
  },
  Shared {
    of: "value_position",
    judgement: "an `auth-param`'s name is a `token`",
    injection: "an element with no name has a value position at its own first byte",
    moves: (34_391, 34_391),
    differ: 0,
    caught_by: "a_value_position_stands_behind_a_name_and_an_eq",
    control: "value_position_with_no_name",
  },
  Shared {
    of: "value_position",
    judgement: "RFC 9110 §5.6.3's `BWS` stands in front of the `=`",
    injection: "the `=` is looked for on the byte behind the name",
    moves: (2_132, 2_132),
    differ: 0,
    caught_by: "the_bws_in_front_of_the_eq_is_admitted",
    control: "value_position_with_no_bws_in_front",
  },
  Shared {
    of: "value_position",
    judgement: "an element with no `=` has NO value position",
    injection: "its value begins where the `=` was looked for",
    moves: (84_029, 84_029),
    differ: 0,
    caught_by: "a_value_position_stands_behind_a_name_and_an_eq",
    control: "value_position_with_no_eq_needed",
  },
  Shared {
    of: "value_position",
    judgement: "`BWS` stands behind the `=` too",
    injection: "the value begins on the byte behind the `=`",
    moves: (2_132, 2_132),
    differ: 0,
    caught_by: "a_value_position_stands_behind_a_name_and_an_eq",
    control: "value_position_with_no_bws_behind",
  },
];

/// How [`SHARED_JUDGEMENTS`] splits: blind, covered, and out of the gate's
/// reach.
///
/// Pinned rather than printed, so that editing a row's measured numbers to make
/// the gate look better moves a number here and reds. It is derived from the
/// table and so is not independent evidence — what it buys is that the table
/// cannot be quietly improved.
///
/// **It was `(17, 4, 8)`**, with the differential the only gate that made a
/// wrongness claim about any of these judgements. The eight leaf properties
/// moved eight rows — `open_at`'s O4, `raw_comma_end`'s, `skip_ows`'s,
/// `skip_sp`'s and all four of `value_position`'s — from the first class to the
/// second, and moved nothing else: the `moves` and `differ` columns re-measured
/// identically, row for row, over the same 29 injections.
const SHARED_SPLIT: (usize, usize, usize) = (9, 12, 8);

/// The gates a row of [`SHARED_JUDGEMENTS`] may name, and the whole of what
/// makes that column mean something.
///
/// Every one of these reds because an ANSWER IS WRONG. A pin — [`AXIS`],
/// [`ANSWERS`], [`WHOLE`], [`FAULTS`] — reds under most of these injections too
/// and is not coverage: it says a number moved, which is a thing to go and look
/// at rather than a finding. Without this set a row could claim to be covered
/// by a tally, and the blind count would fall to nearly zero while nothing had
/// been learned.
const WRONGNESS_GATES: [&str; 7] = [
  "the_two_derivations_of_excused_answer_alike",
  "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
  "a_value_position_stands_behind_a_name_and_an_eq",
  "the_bws_in_front_of_the_eq_is_admitted",
  "a_raw_run_ends_at_the_first_raw_comma",
  "a_whitespace_run_is_crossed_whole",
  "open_at_reads_no_byte_at_or_behind_the_probe",
];

/// This module's own source, read at compile time so that a name
/// [`SHARED_JUDGEMENTS`] claims can be held against the item that carries it.
///
/// It is the same device `readings.rs` is read with, turned on this file: a
/// table naming a test that no longer exists is the commonest way a record like
/// this rots, and it is the one kind of rot that can be caught without running
/// the sweep again.
const THIS_FILE: &str = include_str!("tests.rs");

/// Every item `readings` imports from [`oracle`](crate::oracle), read from that
/// file rather than listed by hand.
///
/// The list is the whole of what the two derivations share, so a list written
/// out here would go stale exactly when it mattered — at the commit that shares
/// one more.
fn shared_transcriptions() -> Vec<String> {
  const SOURCE: &str = include_str!("readings.rs");
  let code: String = SOURCE
    .lines()
    .filter(|line| !line.trim_start().starts_with("//"))
    .collect::<Vec<_>>()
    .join("\n");
  // One reach into the oracle and one only. A second import written any other
  // way would put a shared judgement outside this enumeration silently, which
  // is the failure this parse exists to make loud.
  assert_eq!(
    code.matches("oracle").count(),
    1,
    "`readings` reaches the oracle in exactly one place"
  );
  let list = code
    .split_once("use crate::oracle::{")
    .and_then(|(_, rest)| rest.split_once("};"))
    .expect("the one reach is the braced import")
    .0;
  list
    .split(',')
    .map(str::trim)
    .filter(|name| !name.is_empty())
    .map(str::to_owned)
    .collect()
}

#[test]
fn every_transcription_the_two_derivations_share_is_enumerated() {
  let shared = shared_transcriptions();
  for name in &shared {
    assert!(
      SHARED_JUDGEMENTS.iter().any(|row| row.of == name),
      "`readings` shares `{name}` and [`SHARED_JUDGEMENTS`] enumerates no \
       judgement taken inside it"
    );
  }
  for row in &SHARED_JUDGEMENTS {
    assert!(
      shared.iter().any(|name| name == row.of),
      "[`SHARED_JUDGEMENTS`] enumerates `{}` and `readings` does not share it",
      row.of
    );
    // A row that restates its neighbour measures the same defect twice and
    // makes the blind count look larger than the blindness is. Both columns,
    // because two rows can state one judgement in two sentences or two
    // judgements and then measure one of them.
    assert_eq!(
      SHARED_JUDGEMENTS
        .iter()
        .filter(|other| other.of == row.of && other.judgement == row.judgement)
        .count(),
      1,
      "`{}` states one judgement twice: {}",
      row.of,
      row.judgement
    );
    assert_eq!(
      SHARED_JUDGEMENTS
        .iter()
        .filter(|other| other.of == row.of && other.injection == row.injection)
        .count(),
      1,
      "`{}` measures two judgements with one injection: {}",
      row.of,
      row.injection
    );
    assert!(
      !row.injection.is_empty(),
      "`{}` has numbers with no injection behind them: {}",
      row.of,
      row.judgement
    );
  }
}

#[test]
fn every_guard_a_row_claims_is_one_this_crate_has() {
  // What this can hold, and it is the part of the table that rots first: a row
  // naming a gate that was renamed or deleted, or claiming coverage from a pin.
  // What it CANNOT hold is the causal claim itself — that injecting THIS
  // defect still reds THAT gate — because a gate cannot inject a defect into
  // the tree it is running in. The eight property rows close most of that
  // residue from the other side: each carries a control, and the property test
  // asserts on every run that the control violates the clause the row is about.
  // What is left is a reading: that the control spells the same defect the
  // `injection` column names.
  for row in &SHARED_JUDGEMENTS {
    if row.caught_by.is_empty() {
      assert!(
        row.control.is_empty(),
        "`{}` names a control and no gate to run it in: {}",
        row.of,
        row.judgement
      );
      assert_eq!(
        row.differ, 0,
        "`{}` is blind and the differential reports {} disagreements",
        row.of, row.differ
      );
      continue;
    }
    assert!(
      WRONGNESS_GATES.contains(&row.caught_by),
      "`{}` claims coverage from `{}`, which is not one of the gates that says \
       an answer is WRONG",
      row.of,
      row.caught_by
    );
    assert!(
      THIS_FILE.contains(&format!("fn {}(", row.caught_by)),
      "`{}` names the gate `{}` and this file defines no such item",
      row.of,
      row.caught_by
    );
    // The differential's column and the guard column say one thing between
    // them: a row the differential catches has a non-zero count, and a row it
    // does not has a zero and is caught by something else or by nothing.
    assert_eq!(
      row.differ > 0,
      row.caught_by == "the_two_derivations_of_excused_answer_alike",
      "`{}`: the disagreement count and the gate named disagree",
      row.of
    );
    if !row.control.is_empty() {
      assert!(
        THIS_FILE.contains(&format!("fn {}(", row.control)),
        "`{}` names the control `{}` and this file defines no such item",
        row.of,
        row.control
      );
    }
  }

  // And every gate in the set is claimed by some row. A gate nothing names is
  // one whose deletion this table would not notice.
  for gate in WRONGNESS_GATES {
    assert!(
      SHARED_JUDGEMENTS.iter().any(|row| row.caught_by == gate)
        || PROSE_SHARED.iter().any(|row| row.caught_by == gate),
      "`{gate}` is named as a wrongness gate and nothing claims it"
    );
    assert!(
      THIS_FILE.contains(&format!("fn {gate}(")),
      "`{gate}` is named as a wrongness gate and this file defines no such item"
    );
  }
}
// ─────────── the rules the two state twice in WORDS, and their guard ─────────

/// One rule both derivations of `excused` obey and NEITHER shares a line of
/// code for.
///
/// [`SHARED_JUDGEMENTS`] is held to `readings.rs`'s own `use` declaration, so
/// it finds every judgement the two share AS CODE and, by construction, no rule
/// they share as prose. That is a second blindness class and it is the one with
/// nothing keeping the copies honest: a shared function has a compiler, a
/// shared sentence has a reader.
///
/// The differential is blind to these the way it is blind to a transcription,
/// and worse: changing ONE spelling reds it — `readings::cross` writing
/// `free: true` reds it at 36 — so the gate looks like a guard right up until
/// somebody changes both, which is what a maintainer who has understood the
/// rule wrongly will do. Every row below is measured under a COORDINATED edit:
/// both spellings changed together.
struct Prose {
  /// The rule, as both files state it.
  rule: &'static str,
  /// A verbatim run of `oracle`'s statement of it, held against that file.
  in_oracle: &'static str,
  /// A verbatim run of `readings`'s statement of it, held against that file.
  in_readings: &'static str,
  /// The edit that changes both spellings at once.
  coordinated: &'static str,
  /// The gate that reds under that edit — one of [`WRONGNESS_GATES`].
  caught_by: &'static str,
  /// What it reds with: the class, the corpus and the count.
  reds: &'static str,
}

/// Every rule the two derivations state twice in words, and what catches the
/// two copies drifting apart.
///
/// # The result, which is not the one the enumeration was built expecting
///
/// **All six are caught, and none of them by the differential.** The guard is
/// [`ZERO_TARGETS`] — a class this module is driven to zero on going non-zero —
/// and it catches them in BOTH directions, which is the part worth keeping:
/// `over-yield` counts records where the reader yields a challenge the oracle
/// EXCUSES, so an oracle that excuses too much raises it; `hider-unexcused`
/// counts records where the reader hides one the oracle does not excuse, so an
/// oracle that excuses too little raises that. A prose rule loosened and a
/// prose rule tightened are therefore different failures with different gates,
/// and the module doc's warning — that an edit making `Verdict::excused` fire
/// more often lowers the number it is driven to zero on — names only the first.
///
/// Four of the six ALSO red the differential, and that is not evidence about
/// the class: a coordinated edit written by hand is only approximately
/// symmetric, and the residue is what the differential sees. PS1 and PS4 are
/// the clean cases, and they red nothing but a zero-target.
///
/// # A seventh row of a different kind
///
/// The last row is stated ONCE and relied on twice. `oracle::covers` argues at
/// length that §11.2's one-name-once MUST must not be applied where the
/// question is where a string may open; `readings` never mentions it and tracks
/// no names, so there is no second spelling to change and no coordinated edit
/// to make. A rule like that can only be broken one side at a time, and its row
/// records the one-sided break instead. It is the only row here that is not
/// two copies of a sentence, and it is enumerated because *stated once, relied
/// on twice* is the same blindness with one of the two copies missing.
///
/// # What this table cannot be held to
///
/// [`SHARED_JUDGEMENTS`] is complete against a `use` declaration a compiler
/// maintains. **This one is complete against a reading of two files**, and
/// nothing can make it otherwise: there is no declaration that says *this
/// sentence is also written over there*. What IS held below is each row's
/// citation — the verbatim run it quotes must still be in the file that is
/// supposed to state it — so a rule deleted from one side reds even though a
/// rule added to both would not.
///
/// # And the guard is the READER's, which is a coupling worth naming
///
/// Every row is caught by [`ZERO_TARGETS`], and a zero-target is 0 because of
/// what the MODULE UNDER TEST answers: `over-yield` is empty because the reader
/// yields no challenge the oracle excuses, `hider-unexcused` because it hides
/// none the oracle does not. So a change to `http_semantics::auth` that made
/// one of those classes non-zero for its own unrelated reasons would take the
/// only guard these six rules have with it, and nothing here would say that had
/// happened — the rows would still name a gate, and the gate would still exist
/// and still be red for a different reason. The differential does not stand in:
/// it is silent about a coordinated edit by construction, which is why this
/// table exists.
const PROSE_SHARED: [Prose; 7] = [
  Prose {
    rule: "the free regime reaches forward through the open `#auth-param` list \
           and never further",
    in_oracle: "So the fault propagates `list` rather than `true`.",
    in_readings: "**`free` behind the crossing is `list` and never `true`**",
    coordinated: "`resume` carries `faulted: true` and `cross` carries `free: true`",
    caught_by: "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
    reds: "over-yield, corpus M, 18 records",
  },
  Prose {
    rule: "the free regime starts at an element start no reading of the grammar \
           leaves",
    in_oracle: "Whether ANY reading of the grammar leaves this element start.",
    in_readings: "Whether ANY reading of the grammar derives this element.",
    coordinated: "both walks open the free regime only where one is already open",
    caught_by: "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
    reds: "hider-declined, corpus A, 12 records",
  },
  Prose {
    rule: "the DQUOTE at a value position is recorded whether or not the element \
           it stands in goes on to derive",
    in_oracle: "every DQUOTE §11.2 admits a value at whether or not the",
    in_readings: "The DQUOTE standing at the value position is recorded whether or not the",
    coordinated: "both walks count only a string that closes — the answer \
                  al8n/wren#77 corrected",
    caught_by: "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
    reds: "hider-unexcused, corpus A, 36 records",
  },
  Prose {
    rule: "a challenge whose `1*SP` was taken has entered a list even where the \
           body's first element is empty",
    in_oracle: "The empty element §5.6.1.2 admits",
    in_readings: "Including when that first element is EMPTY.",
    coordinated: "neither walk reads the body's first element as an empty one",
    caught_by: "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
    reds: "over-yield, corpus A, 4 records",
  },
  Prose {
    rule: "where nothing derives the body's first element the walk stands INSIDE \
           the list the `1*SP` opened",
    in_oracle: "alternative, whose first element starts at the",
    in_readings: "And where NOTHING derives the body's first element, the recipient that",
    coordinated: "both walks cross that run with no list open",
    caught_by: "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
    reds: "hider-declined, corpus A, 6 records",
  },
  Prose {
    rule: "RFC 9110 §11.2's one-name-once MUST is not applied where the question \
           is where a string may open",
    in_oracle: "§11.2's one-name-once MUST is deliberately NOT applied here",
    in_readings: "",
    coordinated: "one-sided, because `readings` tracks no names: `covers` \
                  un-derives an element whose folded name already stands in \
                  front of it followed by an `=`",
    caught_by: "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
    reds: "over-yield, corpus M, and the differential too",
  },
  Prose {
    rule: "no challenge opens at a body head",
    in_oracle: "The first element of a challenge's `#auth-param` list, where none may.",
    in_readings: "where §11.6.1 puts no second challenge",
    coordinated: "both walks read the body's first element as a whole challenge too",
    caught_by: "the_three_classes_this_module_is_driven_to_zero_on_are_zero",
    reds: "over-yield, corpus A, 4 records",
  },
];

#[test]
fn every_rule_the_two_derivations_state_twice_is_still_stated_twice() {
  const ORACLE: &str = include_str!("oracle.rs");
  const READINGS: &str = include_str!("readings.rs");
  for row in &PROSE_SHARED {
    assert!(
      ORACLE.contains(row.in_oracle),
      "`oracle` no longer states `{}` — the run cited is gone",
      row.rule
    );
    // An empty `in_readings` is the seventh row's shape and only its shape: a
    // rule stated once and relied on silently, whose break can only be
    // one-sided. The doc says which; this refuses a row that leaves the
    // citation out without saying so.
    if row.in_readings.is_empty() {
      assert!(
        row.coordinated.starts_with("one-sided"),
        "`{}` cites no statement in `readings` and does not say it is relied on \
         silently",
        row.rule
      );
    } else {
      assert!(
        READINGS.contains(row.in_readings),
        "`readings` no longer states `{}` — the run cited is gone",
        row.rule
      );
    }
    assert!(
      WRONGNESS_GATES.contains(&row.caught_by),
      "`{}` claims coverage from `{}`, which is not a gate that says an answer \
       is WRONG",
      row.rule,
      row.caught_by
    );
    assert!(
      THIS_FILE.contains(&format!("fn {}(", row.caught_by)),
      "`{}` names the gate `{}` and this file defines no such item",
      row.rule,
      row.caught_by
    );
    assert!(
      !row.coordinated.is_empty() && !row.reds.is_empty(),
      "`{}` is recorded with no coordinated edit or no result",
      row.rule
    );
    // A rule stated twice in one sentence is one rule counted twice, and it
    // would make the enumeration look wider than the reading behind it.
    assert_eq!(
      PROSE_SHARED
        .iter()
        .filter(|other| other.rule == row.rule)
        .count(),
      1,
      "`{}` is enumerated twice",
      row.rule
    );
  }
}

#[test]
fn the_shared_judgements_are_blind_covered_or_out_of_the_gates_reach() {
  let blind = SHARED_JUDGEMENTS.iter().filter(|row| row.blind()).count();
  let covered = SHARED_JUDGEMENTS.iter().filter(|row| row.covered()).count();
  let unreached = SHARED_JUDGEMENTS
    .iter()
    .filter(|row| !row.reached())
    .count();
  assert_eq!(
    (blind, covered, unreached),
    SHARED_SPLIT,
    "the split [`SHARED_JUDGEMENTS`] measures"
  );
  assert_eq!(
    blind + covered + unreached,
    SHARED_JUDGEMENTS.len(),
    "the three classes are exclusive and exhaustive"
  );
  // A covered row is one the two walks consume asymmetrically, so its two
  // `moves` differ; a blind row moves both derivations by the same count, which
  // is what makes the disagreement 0 rather than lucky.
  for row in &SHARED_JUDGEMENTS {
    if row.blind() {
      assert_eq!(
        row.moves.0, row.moves.1,
        "`{}`: a row the gate cannot see moves both derivations alike",
        row.of
      );
    }
  }
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
  for ((name, span), (pinned, derives, opens)) in SPANS.into_iter().zip(N_SPAN_DERIVES) {
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
    // And §11.3's question over the same elements, composed here out of
    // `oracle`'s productions: an `auth-scheme`, the `1*SP` that is the body's
    // only entrance, and a body the `token68` alternative does not take whole.
    // ANY element that opens one leaves it open, because nothing a recovery
    // crosses closes a list — a challenge that would is one the walk stops at
    // rather than crosses.
    let any = span.split(|&byte| byte == b',').any(|element| {
      let element = trimmed(element);
      let Some(scheme_end) = crate::oracle::token_end(element, 0) else {
        return false;
      };
      if element.get(scheme_end) != Some(&b' ') {
        return false;
      }
      let body = crate::oracle::skip_sp(element, scheme_end);
      body < element.len()
        && crate::oracle::token68_end(element, body).is_none_or(|end| end != element.len())
    });
    assert_eq!(
      any, opens,
      "span {name}: RFC 9110 §11.3 and this table disagree"
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
    let (derives, opens) = N_SPAN_DERIVES
      .iter()
      .find(|(spelled, _, _)| *spelled == name)
      .map(|(_, derives, opens)| (*derives, *opens))
      .unwrap_or_else(|| panic!("{name} is one of this family's spans"));
    assert_eq!(derives, Some(true), "span {name}: §11.2 derives it");
    // And §11.3 opens no list at either, which is the other half of what makes
    // their rows show the probe.
    assert!(!opens, "span {name}: §11.3 opens no list at it");
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
    7_872,
    "two openers over seven refusals and fifteen spans, over one cursor row \
     and the fourteen spans that are a position, and over three joined \
     refusals and fifteen spans, by four closers and six traps"
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
    completed, 5_508,
    "two openers, seven refusals by fourteen spans, one cursor row by thirteen \
     and three joined refusals by fourteen, three closing closers, six traps"
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
      for (span, derives, opens) in N_SPAN_DERIVES {
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
        // A span that opens a `#auth-param` list of its own is a list in front
        // of the trap wherever it stands, so a fault that opened none no longer
        // leaves the value list-free; and the value has stopped deriving inside
        // that list, so an epoch a bound opened cannot be closed behind it
        // either. Both terms are one fact —
        // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` — read
        // at the two places this rule asks about a list.
        let list_free = !(a_list_in_front || its_own_list || opens);
        let shown = list_free || (bound && derives == Some(true) && !opens);
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
      for (span, derives, opens) in N_SPAN_DERIVES {
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
        let shown = bound && derives == Some(true) && !opens;
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
    for (span, derives, opens) in N_SPAN_DERIVES {
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
          derives == Some(true) && !opens,
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
    crossed, 54,
    "corpus N: three list-free faults, three closing closers, six traps"
  );
  assert_eq!(
    declined, 342,
    "corpus N: the rows a list is open at, over three closing closers — the \
     joined refusals included, each of which is met inside a body and so has a \
     list of its own"
  );
}

/// One value in which an element the recovery CROSSES opens a `#auth-param`
/// list of its own, and the same value with that element's whitespace spelled
/// so that it cannot.
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `y<SP>=<SP>1` reads as one `auth-param` — which is what the walk takes, and
/// why `opens_a_challenge` answers `false` and `Challenges::seek` crosses it
/// without stopping. It ALSO reads as an `auth-scheme` `y` taking §11.3's
/// `1*SP`, whose `#auth-param` body opens at the `=` and derives nothing there.
/// Under that reading the value has stopped deriving INSIDE a list `y` opened,
/// so every element behind it is garbage that list still holds — and `x`'s
/// DQUOTE stands at a value position with the probe inside its data.
///
/// The recovery records neither half: `Epoch::inside_a_list` is written once at
/// the refusal and `Challenges::sustain_the_epoch` asks the crossed element
/// only what RFC 9110 §11.2 makes of it, which is the reading that derives. So
/// `Bearer` closes a list nothing opened, `x="open` is refused with no list in
/// front of it, `opener_at` admits no reading, and the comma inside `x`'s value
/// is crossed.
const SPAN_OPENS_A_LIST: &[u8] = b"Broken\tjunk, y = 1, Bearer, x=\"open, Digest realm=z";

/// The control: the same span with §11.2's `BWS` spelled the way [`SPANS`]
/// already wrote it. §11.3's opener is `1*SP` and §5.6.3's HTAB is not one, so
/// `y<HTAB>=<HTAB>1` takes no body, opens no list, and there is no second
/// reading of the value to lose. One SP is the whole of the difference.
const SPAN_OPENS_NO_LIST: &[u8] = b"Broken\tjunk, y\t=\t1, Bearer, x=\"open, Digest realm=z";

#[test]
fn the_span_that_opens_a_list_is_one_the_recovery_crosses() {
  // The second finding, and the shape it is now held at. It was
  // 135 `over-yield` records at `7c25761` — the commit that added the span this
  // family could not write — and 0 here.
  let n = records(corpus_n);
  assert_eq!(
    of(&tally(&n, |_| true), "over-yield"),
    0,
    "corpus N: the invented challenges"
  );

  // Identified by SHAPE and not by the verdict they used to carry: the span
  // opens a `#auth-param` list under RFC 9110 §11.6.1's challenge reading, a
  // closer that ENDS a list stands behind it, and the trap carries a DQUOTE at
  // a value position of the list the span opened. Every one of them hides the
  // probe, and every one says so — 135 of the 198 answered the other way at
  // `7c25761`, and the rest were already excused by an epoch that could not
  // close.
  let mut shaped = 0usize;
  for line in &n {
    let [_, _, spelling, axis, answer] = columns(line);
    let trap = spelling
      .rsplit_once(" trap=")
      .map(|(_, name)| name)
      .expect("every corpus N spelling names its trap");
    if !spelling.contains(" span=bws-sp ")
      || spelling.contains(" closer=list ")
      || !matches!(trap, "open" | "bws-open" | "closed-over")
    {
      continue;
    }
    assert_eq!(
      axis, "hider-excused",
      "corpus N: a span that opens a list graded elsewhere: {line}"
    );
    assert!(
      !answer.contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
      "corpus N: a span that opens a list still yields the probe: {line}"
    );
    assert!(
      answer.contains("Err(ChallengeBoundaryUnknown)"),
      "corpus N: a span that opens a list hides in silence: {line}"
    );
    shaped += 1;
  }
  assert_eq!(
    shaped, 198,
    "corpus N: two openers by nine refusals, three closing closers, three \
     DQUOTE traps"
  );

  // And the one-line witness, graded by the ORACLE alone. No reader is in this
  // derivation and nothing here is about what any revision of this workspace
  // answers.
  let verdict = oracle::read(SPAN_OPENS_A_LIST, probe_at(SPAN_OPENS_A_LIST));
  assert!(verdict.derives, "the probe's own bytes derive");
  assert!(
    !verdict.reached,
    "no derivation of the whole value reaches the probe"
  );
  assert!(
    verdict.excused,
    "a reading holds the probe inside the value of `x`, through the list the \
     span opened"
  );
  // So a walk that yields it has invented one. This tree does not, and it tells
  // the caller the rest is unread.
  assert!(
    !yields_the_probe(&[SPAN_OPENS_A_LIST]),
    "the second invention, now closed"
  );
  assert!(
    says_the_rest_is_unread(&[SPAN_OPENS_A_LIST]),
    "and the caller is told the rest is unread"
  );

  // The control is the same value with the span's whitespace spelled so that
  // §11.3's `1*SP` cannot be a prefix of it. No list opens there, no reading
  // holds the probe, and the walk SHOWS it — which is recovery rather than
  // invention, and is what says the fix turns on the list and not on the
  // bytes of the trap.
  let control = oracle::read(SPAN_OPENS_NO_LIST, probe_at(SPAN_OPENS_NO_LIST));
  assert!(control.derives, "the probe's own bytes derive");
  assert!(!control.reached, "and no derivation reaches it");
  assert!(
    !control.excused,
    "with no `1*SP` the span opens no list and no reading holds the probe"
  );
  assert!(
    yields_the_probe(&[SPAN_OPENS_NO_LIST]),
    "the control is shown, and showing it is recovery rather than invention"
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
  // spelling it would write 320 records that move together with corpus H's.
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
  assert_eq!(compared, 320, "the comparisons this control makes");
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
const CONFORMING: [(&str, usize); 15] = [
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
  ("O", 0),
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

// ───────────── the leaf productions, graded by property ──────────────────────

/// Every byte string the property checks are run over: [`payloads`] of length
/// 1..=5 over [`ALPHABET`], which is the eight bytes RFC 9110 §11.2's
/// `auth-param` is made of — the two `tchar`s a name and a value need, the `=`
/// that joins them, the DQUOTE and the backslash §5.6.4 gives meaning to,
/// §5.6.1's comma, and the two bytes §5.6.3's `OWS` is made of.
///
/// 37 448 strings, and every offset of each is asked, which is why a property
/// below can be stated over ALL inputs rather than over a hand-picked witness.
fn leaf_inputs() -> Vec<Vec<u8>> {
  (1..=5).flat_map(payloads).collect()
}

/// How many answers of `position` RFC 9110 §11.2 does not admit, by clause.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Three terminals stand in front of the value and each leaves a mark on the
/// offset handed back, so each is a clause here — and they are counted apart
/// rather than summed, because a control that breaks one must be shown to break
/// THAT one:
///
/// - the `token` is `1*tchar` and the `=` is one byte, so the value stands at
///   least two bytes past the element's start;
/// - the `=` is between them;
/// - and `BWS` is `OWS`, which is greedy, so the value position never stands ON
///   one of its bytes.
///
/// **This is not a second reading of `auth-param`.** None of the three decides
/// where a value position IS; each is a consequence a wrong one violates, which
/// is the whole difference between a property and the transcription al8n/wren#76
/// was filed over.
fn value_positions_no_auth_param_admits(
  position: impl Fn(&[u8], usize) -> Option<usize>,
  inputs: &[Vec<u8>],
) -> (usize, [usize; 3]) {
  let mut asked = 0_usize;
  let mut broken = [0_usize; 3];
  for value in inputs {
    for at in 0..=value.len() {
      asked = asked.saturating_add(1);
      let Some(place) = position(value, at) else {
        continue;
      };
      if place < at.saturating_add(2) {
        broken[0] = broken[0].saturating_add(1);
      }
      if !value.get(at..place).unwrap_or_default().contains(&b'=') {
        broken[1] = broken[1].saturating_add(1);
      }
      if matches!(value.get(place), Some(&b' ') | Some(&b'\t')) {
        broken[2] = broken[2].saturating_add(1);
      }
    }
  }
  (asked, broken)
}

/// How many values `position` stops admitting when one more SP is written in
/// front of their `=`.
///
/// RFC 9110 §5.6.3's `BWS` is admitted there, so a respelling that adds one is
/// the same `auth-param` with its value one byte further along. The `=` this
/// inserts in front of is the first at or after `at`, which is the one any
/// reading used: §5.6.2's `tchar` excludes `=`, so no `token` holds one, and
/// `OWS` is SP and HTAB.
///
/// A METAMORPHIC clause and the only one of the four that has to be: `BWS` in
/// front of the `=` is a rule about what a reading ACCEPTS, and a wrong one
/// answers `None` where the right one answers `Some` — which no property over a
/// returned offset can see.
fn respellings_that_lose_their_value_position(
  position: impl Fn(&[u8], usize) -> Option<usize>,
  inputs: &[Vec<u8>],
) -> (usize, usize) {
  let mut asked = 0_usize;
  let mut lost = 0_usize;
  for value in inputs {
    for at in 0..=value.len() {
      let Some(place) = position(value, at) else {
        continue;
      };
      let Some(eq) = value
        .iter()
        .enumerate()
        .skip(at)
        .find(|&(_, &byte)| byte == b'=')
        .map(|(offset, _)| offset)
      else {
        continue;
      };
      asked = asked.saturating_add(1);
      let mut respelt = value.clone();
      respelt.insert(eq, b' ');
      if position(&respelt, at) != Some(place.saturating_add(1)) {
        lost = lost.saturating_add(1);
      }
    }
  }
  (asked, lost)
}

/// How many answers of `end_of` are not the first comma no string was opened
/// in, or the value's end.
///
/// The run a reading crosses when it derives no part of what it is looking at
/// ends at RFC 9110 §5.6.1's separator read RAW — so the offset handed back
/// holds a comma or nothing at all, it does not go backwards, and no comma
/// stands between it and where the run began.
fn raw_runs_that_do_not_end_at_a_raw_comma(
  end_of: impl Fn(&[u8], usize) -> usize,
  inputs: &[Vec<u8>],
) -> (usize, usize) {
  let mut asked = 0_usize;
  let mut broken = 0_usize;
  for value in inputs {
    for at in 0..=value.len() {
      asked = asked.saturating_add(1);
      let end = end_of(value, at);
      let backwards = end < at || end > value.len();
      let not_a_comma = !matches!(value.get(end), None | Some(&b','));
      let comma_inside = value.get(at..end).unwrap_or_default().contains(&b',');
      if backwards || not_a_comma || comma_inside {
        broken = broken.saturating_add(1);
      }
    }
  }
  (asked, broken)
}

/// How many answers of `skip` leave a run of `admitted` half-crossed.
///
/// A whitespace run is crossed WHOLE: every byte between where the skip began
/// and where it stopped is one the production admits, and the byte it stopped
/// on is not. RFC 9110 §5.6.3's `OWS` is `*( SP / HTAB )` and §11.3's `1*SP` is
/// SP alone, so the two differ only in `admitted` and the property is the same
/// sentence for both — which is why the HTAB one transcription crosses and the
/// other does not is a difference this can see rather than one it assumes.
fn whitespace_runs_crossed_by_halves(
  skip: impl Fn(&[u8], usize) -> usize,
  admitted: impl Fn(u8) -> bool,
  inputs: &[Vec<u8>],
) -> (usize, usize) {
  let mut asked = 0_usize;
  let mut broken = 0_usize;
  for value in inputs {
    for at in 0..=value.len() {
      asked = asked.saturating_add(1);
      let stopped = skip(value, at);
      let backwards = stopped < at || stopped > value.len();
      let crossed_something_else = value
        .get(at..stopped)
        .unwrap_or_default()
        .iter()
        .any(|&byte| !admitted(byte));
      let stopped_on_one = value.get(stopped).is_some_and(|&byte| admitted(byte));
      if backwards || crossed_something_else || stopped_on_one {
        broken = broken.saturating_add(1);
      }
    }
  }
  (asked, broken)
}

/// How many answers of `open` depend on a byte at or behind the probe.
///
/// Whether some reading holds an offset inside a string is a question about the
/// bytes IN FRONT of that offset: the sender wrote them between an opening
/// DQUOTE and this position, and what stands behind the position cannot unwrite
/// them. So the answer over a value equals the answer over that value cut at the
/// probe — the same question, asked with the later bytes gone.
fn open_at_answers_that_read_past_the_probe(
  open: impl Fn(&[u8], usize, usize) -> bool,
  inputs: &[Vec<u8>],
) -> (usize, usize) {
  let mut asked = 0_usize;
  let mut broken = 0_usize;
  for value in inputs {
    for quote in 0..value.len() {
      for probe in quote.saturating_add(1)..=value.len() {
        asked = asked.saturating_add(1);
        let cut = value.get(..probe).unwrap_or_default();
        if open(value, quote, probe) != open(cut, quote, probe) {
          broken = broken.saturating_add(1);
        }
      }
    }
  }
  (asked, broken)
}

// The controls. Each is a KNOWN-WRONG spelling of one transcription, and each
// is asserted to violate the one clause it is wrong about — so a property that
// stopped catching its own defect reds here rather than passing quietly. They
// are not second transcriptions in al8n/wren#76's sense and cannot decay into
// them: a control edited until it is right stops violating, and the test that
// requires the violation is what says so.

/// `value_position` with an element that has no name at all admitted.
fn value_position_with_no_name(value: &[u8], at: usize) -> Option<usize> {
  let name_end = crate::oracle::token_end(value, at).unwrap_or(at);
  let eq = crate::oracle::skip_ows(value, name_end);
  if value.get(eq) != Some(&b'=') {
    return None;
  }
  Some(crate::oracle::skip_ows(value, eq.saturating_add(1)))
}

/// `value_position` with no `BWS` admitted in front of the `=`.
fn value_position_with_no_bws_in_front(value: &[u8], at: usize) -> Option<usize> {
  let name_end = crate::oracle::token_end(value, at)?;
  if value.get(name_end) != Some(&b'=') {
    return None;
  }
  Some(crate::oracle::skip_ows(value, name_end.saturating_add(1)))
}

/// `value_position` that hands back a position for an element with no `=`.
fn value_position_with_no_eq_needed(value: &[u8], at: usize) -> Option<usize> {
  let name_end = crate::oracle::token_end(value, at)?;
  let eq = crate::oracle::skip_ows(value, name_end);
  if value.get(eq) != Some(&b'=') {
    return Some(eq);
  }
  Some(crate::oracle::skip_ows(value, eq.saturating_add(1)))
}

/// `value_position` with no `BWS` admitted behind the `=`.
fn value_position_with_no_bws_behind(value: &[u8], at: usize) -> Option<usize> {
  let name_end = crate::oracle::token_end(value, at)?;
  let eq = crate::oracle::skip_ows(value, name_end);
  if value.get(eq) != Some(&b'=') {
    return None;
  }
  Some(eq.saturating_add(1))
}

/// `raw_comma_end` with a DQUOTE stopping the run too.
fn raw_comma_end_that_a_dquote_stops(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while !matches!(value.get(at), None | Some(&b',') | Some(&b'"')) {
    at = at.saturating_add(1);
  }
  at
}

/// `skip_ows` with HTAB left uncrossed.
fn skip_ows_without_htab(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while value.get(at) == Some(&b' ') {
    at = at.saturating_add(1);
  }
  at
}

/// `skip_sp` with HTAB crossed as though it were SP.
fn skip_sp_with_htab(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(&b' ') | Some(&b'\t')) {
    at = at.saturating_add(1);
  }
  at
}

/// `open_at` reading the whole value rather than the run in front of the probe.
fn open_at_reading_past_the_probe(value: &[u8], quote: usize, probe: usize) -> bool {
  quote < probe
    && !matches!(
      crate::oracle::scan_quoted(value, quote.saturating_add(1)),
      crate::oracle::Quoted::Closed(_)
    )
}

/// How many (value, offset) pairs the properties are asked over, per property.
///
/// A REACH, for [`EXCUSED_REACH`]'s reason: a property driven to zero says
/// nothing about inputs it was never run over, and a generator quietly narrowed
/// would drive every count below to zero by asking less.
const LEAF_REACH: (usize, usize, usize, usize, usize) = (37_448, 219_344, 6_658, 219_344, 535_752);

#[test]
fn a_value_position_stands_behind_a_name_and_an_eq() {
  let inputs = leaf_inputs();
  assert_eq!(
    inputs.len(),
    LEAF_REACH.0,
    "the strings every property is run over"
  );
  let (asked, broken) =
    value_positions_no_auth_param_admits(crate::oracle::value_position, &inputs);
  assert_eq!(asked, LEAF_REACH.1, "the offsets this property is asked at");
  assert_eq!(broken, [0, 0, 0], "answers RFC 9110 §11.2 does not admit");

  // Each clause against the control that breaks it, and only it. Without this
  // the three zeros above could all be vacuous and nothing would say so.
  let (_, name) = value_positions_no_auth_param_admits(value_position_with_no_name, &inputs);
  assert!(
    name[0] > 0,
    "an element with no name is caught by the first clause"
  );
  let (_, no_eq) = value_positions_no_auth_param_admits(value_position_with_no_eq_needed, &inputs);
  assert!(
    no_eq[1] > 0,
    "a position with no `=` in front of it is caught by the second"
  );
  let (_, bws) = value_positions_no_auth_param_admits(value_position_with_no_bws_behind, &inputs);
  assert!(
    bws[2] > 0,
    "a position standing on `BWS` is caught by the third"
  );
}

#[test]
fn the_bws_in_front_of_the_eq_is_admitted() {
  let inputs = leaf_inputs();
  let (asked, lost) =
    respellings_that_lose_their_value_position(crate::oracle::value_position, &inputs);
  assert_eq!(
    asked, LEAF_REACH.2,
    "the respellings this property is asked over"
  );
  assert_eq!(lost, 0, "values whose value position one more SP took away");

  let (_, control) =
    respellings_that_lose_their_value_position(value_position_with_no_bws_in_front, &inputs);
  assert!(
    control > 0,
    "a reading with no `BWS` in front of the `=` loses one"
  );
}

#[test]
fn a_raw_run_ends_at_the_first_raw_comma() {
  let inputs = leaf_inputs();
  let (asked, broken) =
    raw_runs_that_do_not_end_at_a_raw_comma(crate::oracle::raw_comma_end, &inputs);
  assert_eq!(asked, LEAF_REACH.3, "the offsets this property is asked at");
  assert_eq!(broken, 0, "runs that end somewhere else");

  let (_, control) =
    raw_runs_that_do_not_end_at_a_raw_comma(raw_comma_end_that_a_dquote_stops, &inputs);
  assert!(control > 0, "a run a DQUOTE stops does not end at a comma");
}

#[test]
fn a_whitespace_run_is_crossed_whole() {
  let inputs = leaf_inputs();
  let ows = |byte: u8| matches!(byte, b' ' | b'\t');
  let sp = |byte: u8| byte == b' ';

  let (asked, broken) = whitespace_runs_crossed_by_halves(crate::oracle::skip_ows, ows, &inputs);
  assert_eq!(asked, LEAF_REACH.3, "the offsets this property is asked at");
  assert_eq!(broken, 0, "§5.6.3's `OWS` half-crossed");
  let (_, control) = whitespace_runs_crossed_by_halves(skip_ows_without_htab, ows, &inputs);
  assert!(
    control > 0,
    "a skip that leaves HTAB uncrossed stops on one"
  );

  let (_, broken) = whitespace_runs_crossed_by_halves(crate::oracle::skip_sp, sp, &inputs);
  assert_eq!(broken, 0, "§11.3's `1*SP` half-crossed");
  let (_, control) = whitespace_runs_crossed_by_halves(skip_sp_with_htab, sp, &inputs);
  assert!(
    control > 0,
    "a skip that crosses HTAB crosses a byte `1*SP` does not"
  );
}

#[test]
fn open_at_reads_no_byte_at_or_behind_the_probe() {
  let inputs = leaf_inputs();
  let (asked, broken) = open_at_answers_that_read_past_the_probe(crate::oracle::open_at, &inputs);
  assert_eq!(
    asked, LEAF_REACH.4,
    "the (quote, probe) pairs this property is asked at"
  );
  assert_eq!(broken, 0, "answers a byte behind the probe changed");

  let (_, control) =
    open_at_answers_that_read_past_the_probe(open_at_reading_past_the_probe, &inputs);
  assert!(
    control > 0,
    "a scan that reads the whole value is changed by a close behind the probe"
  );
}

// ────────── the one row of that table that is a divergence, pinned ──────────

/// Values in which `readings::element` reads a bare `auth-scheme` where
/// `oracle::covers` does not: a scheme token, a whitespace run RFC 9110 §5.6.3
/// admits, and then the comma or the end of value that makes
/// `boundary(value, scheme_end)` an edge.
///
/// The last three put a fault, an open list, and a `quoted-string` carrying a
/// raw comma in front of the divergence, which is the one shape where a state
/// differing only by `list` can cross where its twin derives.
const BARE_SCHEME_WITNESSES: [&[u8]; 9] = [
  b"Basic , Digest realm=z",
  b"Basic ,Digest realm=z",
  b"Basic \t, Digest realm=z",
  b"Basic ",
  b"Basic \t",
  b"Basic , a=\", Digest realm=z",
  b"\",a ,a a=\"x, Digest realm=z",
  b"a=1,a ,a=\"x,y\", a b=\"c, Digest realm=z",
  b"a=1,a=1,a ,a b=\"c, Digest realm=z",
];

#[test]
fn a_bare_scheme_a_1_sp_stands_behind_is_a_reading_both_walks_reach() {
  // `readings`'s module doc carries the argument and the search. This is the
  // part of it that is a gate: the two derivations answer alike at every offset
  // of every witness, and the module under test takes the same reading.
  let mut asked = 0_usize;
  for value in BARE_SCHEME_WITNESSES {
    for probe in 0..=value.len() {
      asked = asked.saturating_add(1);
      assert_eq!(
        crate::oracle::covered(value, probe),
        crate::readings::covered(value, probe),
        "{} at {probe}: the bare scheme is a reading one walk spells and the \
         other reaches",
        escape(value)
      );
    }
  }
  assert_eq!(asked, 213, "the offsets this pins");

  // And the reading is the reader's. RFC 9110 §11.4 has a user agent SEARCH the
  // list, so a `Basic` the walk declined to yield is a challenge withheld —
  // this is the answer the divergence would have been about if it had been one.
  let lines: [&[u8]; 1] = [b"Basic , Digest realm=z"];
  let schemes: Vec<String> = challenges(lines.iter().copied())
    .map(|item| match item {
      Ok(challenge) => escape(challenge.scheme()),
      Err(fault) => format!("Err({fault:?})"),
    })
    .collect();
  assert_eq!(schemes, ["Basic", "Digest"], "the bare scheme is yielded");
}

// ──────── the strongest residual-pressure shape, and what it answers ────────

/// The scheme corpus O writes its continuation challenge with, which stands in
/// no other part of any case that family records.
const O_SCHEME_TOKEN: &[u8] = b"Newauth";

/// RFC 9110 §5.6.3's `OWS` skipped from `at`, written here rather than taken
/// from [`oracle`](crate::oracle) so that the check below is independent of the
/// derivation it grades.
///
/// ```text
/// OWS = *( SP / HTAB )
/// ```
fn past_ows(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(b' ' | b'\t')) {
    at = at.saturating_add(1);
  }
  at
}

/// How many EMPTY elements RFC 9110 §5.6.1.2 admits between `at` and the first
/// element that is not one.
///
/// ```text
/// #element => [ element ] *( OWS "," OWS [ element ] )
/// ```
///
/// `[ element ]` is optional at every position, so a run of commas with nothing
/// but the list's own whitespace between them is a run of empty elements — and
/// this counts them by walking the bytes rather than by trusting the spelling
/// column that names the number.
fn leading_empty_elements(value: &[u8], at: usize) -> usize {
  let mut at = past_ows(value, at);
  let mut empties = 0_usize;
  while value.get(at) == Some(&b',') {
    empties = empties.saturating_add(1);
    at = past_ows(value, at.saturating_add(1));
  }
  empties
}

/// One value in which RFC 9110 §11.2's `BWS` in FRONT of the `=` decided
/// whether a challenge was invented, and the four spellings of the same
/// whitespace that did not.
///
/// ```text
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// One field line, no §5.2 join, and no empty element anywhere: corpus O found
/// this, and the shape is corpus L's own cross — a list, a fault of the
/// grammar, a challenge that completes behind it, and a trap — with a trap
/// spelling the `BWS` that [`TRAPS`] does not.
///
/// **What one SP buys.** §11.2's `BWS` is §5.6.3's `OWS`, so the whitespace an
/// `auth-param` may write in front of its `=` includes the `1*SP` §11.3 needs
/// in front of a body. Where the sender writes at least one SP there, `x` reads
/// as an `auth-scheme` too, the walk enters a body at the `=`, and the value
/// position the `auth-param` reading admits is the one no scan from the body's
/// offset can reach.
const BWS_INVENTION: &[u8] = b"Basic a=1, Broken;junk, Bearer, x = \"c, Digest realm=z";

/// The second spelling that invented, and the one no generator writes: §11.3's
/// `1*SP` taken by the SP and a HTAB of the same `BWS` behind it, which the
/// walk refuses at the body POSITION rather than over the body's first element.
/// A different entrance and the same origin.
const BWS_INVENTION_MIXED: &[u8] = b"Basic a=1, Broken;junk, Bearer, x \t=\"c, Digest realm=z";

/// The spellings of the same value that never invented and must not start.
///
/// The `BWS` in front of the `=` is what §11.3's `1*SP` can be a prefix of, and
/// each of these writes it so that it cannot be: none, one HTAB, and whitespace
/// behind the `=` alone. Every one of them reaches
/// `Challenges::read_challenge`'s scheme fault, which has recovered from the
/// element's own first byte since al8n/wren#77 — so a fix that moved one of
/// these would be a fix that lost the recovery those already had.
///
/// The first is `corpus_l`'s `opener=list fault=punct closer=bare trap=open`
/// row. The other two are written nowhere else.
const BWS_SAFE: [(&str, &[u8]); 3] = [
  (
    "no BWS at all",
    b"Basic a=1, Broken;junk, Bearer, x=\"c, Digest realm=z",
  ),
  (
    "BWS behind the `=` only",
    b"Basic a=1, Broken;junk, Bearer, x= \"c, Digest realm=z",
  ),
  (
    "a HTAB on each side",
    b"Basic a=1, Broken;junk, Bearer, x\t=\t\"c, Digest realm=z",
  ),
];

/// Corpus O's `scheme` axis, written as the one-line values the family's own
/// rows are the general case of.
///
/// All 54 rows that invented carry `scheme=htab`, because `Newauth<HTAB>` takes
/// no body and leaves the trap an element of the OUTER `#challenge` list, where
/// the walk reads a challenge at it. `Newauth<SP>` takes §11.3's `1*SP`, so the
/// same trap is one more `auth-param` of that challenge's own body — an element
/// `opens_a_challenge` answers `false` for, which the body
/// loop keeps rather than reading as a challenge of its own.
///
/// The family writes both: 228 `scheme=sp body=bws` records against 228
/// `scheme=htab`, and the SP half graded `hider-excused` at `2dc787c` exactly
/// as it does here. So the SP spelling was written and was always safe, and
/// the HTAB scheme is not a control doing a witness's job — it is the axis
/// value that puts the trap where a challenge is read.
///
/// The `bool` is whether the walk DECLINES the trap's boundary, which is the
/// half of these two values that is observable from the answer: the HTAB scheme
/// reads a challenge at the trap and refuses it, so the caller is told the rest
/// is unread; the SP scheme reads one more `auth-param`, whose quoted-string
/// never closes, and `AuthError::UnterminatedQuotedString` is the whole of it.
/// Which of the two INVENTED at `2dc787c` is the HTAB one, and that is asserted
/// separately: a notice and a yielded challenge are two facts and one bool
/// cannot carry both.
const BWS_BY_SCHEME: [(&str, &[u8], bool); 2] = [
  (
    "htab",
    b"Basic a=1, Broken;junk, Newauth\t, realm = \"c, Digest realm=z",
    true,
  ),
  (
    "sp",
    b"Basic a=1, Broken;junk, Newauth , realm = \"c, Digest realm=z",
    false,
  ),
];

/// One value whose probe stands at the first element of a challenge's BODY,
/// with no RFC 9110 §5.6.1.2 comma between the two.
///
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` puts no second
/// challenge at a body's first element, so no reading of the outer `#challenge`
/// list has an element start here and hiding these bytes is what a reader must
/// do. `oracle::derives_as_a_challenge` asked only whether the probe's own
/// bytes derive as a challenge, and the axis graded the hide `hider-unexcused`
/// for it — a zero-target reporting the reader for the one thing this module
/// exists to make it do.
const PROBE_INSIDE_A_BODY: &[u8] = b"Broken;junk,Newauth Digest realm=z";

/// The control, one comma apart: RFC 9110 §5.6.1.2's separator in front of the
/// same bytes puts an element of the outer `#challenge` list at them, so a
/// challenge stands there and the walk shows it.
const PROBE_AT_AN_ELEMENT: &[u8] = b"Broken;junk,Newauth,Digest realm=z";

#[test]
fn leading_empty_elements_before_a_quoted_parameter_are_a_shape_this_generator_writes() {
  // Corpus O is the first family whose dimension is how far into the
  // continuation challenge its first quoted parameter stands. Every row has to
  // actually write the run, so the count comes first and the bytes are checked
  // after it.
  let o = records(corpus_o);
  assert_eq!(
    o.len(),
    3_192,
    "four heads over three join counts, two schemes and seven bodies, by the \
     nineteen (empties, spacing, cut) spellings — one at zero empties and six, \
     six and six at one, two and three"
  );

  // Every record writes the run its spelling names, counted off the JOINED
  // value rather than off the line the generator happened to put it on.
  let mut with_a_run = 0usize;
  for line in &o {
    let [_, case, spelling, _, _] = columns(line);
    let lines: Vec<Vec<u8>> = case.split('|').map(unescape).collect();
    let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    let joined = join(&refs);
    let scheme = last_index_of(&joined, O_SCHEME_TOKEN)
      .expect("every corpus O case carries the continuation's scheme");
    let empties = leading_empty_elements(&joined, scheme.saturating_add(O_SCHEME_TOKEN.len()));
    let named = spelling
      .split_once(" empties=")
      .and_then(|(_, rest)| rest.split(' ').next())
      .and_then(|digits| digits.parse::<usize>().ok())
      .expect("every corpus O spelling names its own run");
    assert_eq!(
      empties, named,
      "corpus O writes the empty run its spelling names: {line}"
    );
    with_a_run += usize::from(empties > 0);

    // And the join count, which is the other half of the shape: one field line
    // for the head, one per join past the first, one for the continuation —
    // and one more wherever the cut puts §5.2's join INSIDE the run.
    let joins = spelling
      .split_once(" joins=")
      .and_then(|(_, rest)| rest.split(' ').next())
      .and_then(|digits| digits.parse::<usize>().ok())
      .expect("every corpus O spelling names its join count");
    let cut = spelling
      .split_once(" cut=")
      .and_then(|(_, rest)| rest.split(' ').next())
      .and_then(|digits| digits.parse::<usize>().ok())
      .expect("every corpus O spelling names where the join falls");
    assert!(cut <= empties, "a cut past the run's end: {line}");
    assert_eq!(
      lines.len(),
      joins.saturating_add(1).saturating_add(usize::from(cut > 0)),
      "corpus O crosses the joins its spelling names: {line}"
    );
  }
  assert_eq!(
    with_a_run, 3_024,
    "corpus O rows carrying at least one empty element: the 168 that carry \
     none are the control"
  );

  // The cuts of one cell are ONE value spelled over different numbers of field
  // lines, because RFC 9110 §5.2 contributes exactly the comma the cut took
  // out. That identity is a fact about the generator and is asserted as one.
  let mut cells: HashMap<String, Vec<&String>> = HashMap::new();
  for line in &o {
    let [_, _, spelling, _, _] = columns(line);
    let cell = spelling
      .split(' ')
      .filter(|field| !field.starts_with("cut="))
      .collect::<Vec<_>>()
      .join(" ");
    cells.entry(cell).or_default().push(line);
  }
  assert_eq!(cells.len(), 1_176, "the cells the cut axis is taken over");
  let mut respelled = 0usize;
  let mut parted: Vec<&String> = Vec::new();
  for (cell, rows) in &cells {
    let mut answers: Vec<&str> = Vec::new();
    let mut values: Vec<Vec<u8>> = Vec::new();
    for line in rows {
      let [_, case, _, _, answer] = columns(line);
      let lines: Vec<Vec<u8>> = case.split('|').map(unescape).collect();
      let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
      values.push(join(&refs));
      answers.push(answer);
    }
    for value in &values {
      assert_eq!(
        value, &values[0],
        "corpus O: the cuts of {cell} are not one value"
      );
    }
    if answers.iter().any(|answer| *answer != answers[0]) {
      parted.push(rows.first().copied().expect("a cell has rows"));
    }
    respelled = respelled.saturating_add(rows.len().saturating_sub(1));
  }
  assert_eq!(
    respelled, 2_016,
    "corpus O rows that respell a value another row of the same cell writes"
  );
  the_cells_whose_cuts_answer_differently(&cells, &parted);

  // ── and what the family ANSWERS, which is not what it was written expecting.

  // `over-yield` is a zero-target of this module. Corpus O answered 54 at
  // `2dc787c` and answers 0 here: the rows are `hider-excused` now, which is
  // the reading that holds the probe inside the trap's own value saying so.
  //
  // The 54 are identified by SHAPE and not by their old verdict, because a
  // family that stopped writing the shape would go quiet rather than red. It is
  // not this family's own dimension: a list open where a grammar fault is met,
  // a challenge completing behind it that ends that list in the reading the
  // walk takes, and then an element RFC 9110 §11.2 derives as an `auth-param`
  // whose `BWS` holds a SP — so the same bytes ALSO read as `auth-scheme 1*SP`
  // with a body that derives nothing. The walk takes the challenge reading and
  // refuses at the body; what it did next was recover from the BODY's offset,
  // where the value position the `auth-param` reading admits is one no scan can
  // reach. `Recovery` is taken at the element the OUTER list holds now, and the
  // three rows of the same shape with an EMPTY run of length zero are the ones
  // whose trap stands behind no comma at all.
  assert_eq!(
    of(&tally(&o, |_| true), "over-yield"),
    0,
    "corpus O: the invented challenges"
  );
  let invented: Vec<&String> = o
    .iter()
    .filter(|line| {
      let [_, _, spelling, _, _] = columns(line);
      spelling.contains(" head=list-fault ")
        && spelling.contains(" scheme=htab ")
        && spelling.ends_with("body=bws")
        && !spelling.contains(" empties=0 ")
    })
    .collect();
  assert_eq!(invented.len(), 54, "corpus O: the rows that invented");
  for line in &invented {
    let [_, _, _, axis, answer] = columns(line);
    assert_eq!(
      axis, "hider-excused",
      "corpus O: a row that invented is graded elsewhere now: {line}"
    );
    assert!(
      !answer.contains(&format!("Ok[{}", escape(PROBE_SCHEME))),
      "corpus O: a row that invented still yields the probe: {line}"
    );
    assert!(
      answer.contains("Err(ChallengeBoundaryUnknown)"),
      "corpus O: a row that invented now hides in silence: {line}"
    );
  }

  // Derived from the ORACLE alone, over the one-line value the 54 are the
  // general case of — no reader, and nothing about what any revision of this
  // workspace answers. `Basic`'s list is open where `Broken;junk` is met,
  // nothing derives there, so the reading in which every element since is
  // garbage that list still holds survives — and under it `x = "c, Digest
  // realm=z` is one `auth-param` whose quoted-string never closes.
  let verdict = oracle::read(BWS_INVENTION, probe_at(BWS_INVENTION));
  assert!(verdict.derives, "the probe's own bytes derive");
  assert!(
    !verdict.reached,
    "no derivation of the whole value reaches the probe"
  );
  assert!(
    verdict.excused,
    "a reading holds the probe inside the value of `x`"
  );
  // So a walk that yields it has invented one. This tree does not, and it says
  // so to the caller — the two halves of not hiding a challenge in silence.
  for value in [BWS_INVENTION, BWS_INVENTION_MIXED] {
    assert!(
      !yields_the_probe(&[value]),
      "the invention this family found: {}",
      escape(value)
    );
    assert!(
      says_the_rest_is_unread(&[value]),
      "and the caller is told the rest is unread: {}",
      escape(value)
    );
  }
  // And the spellings of the same `BWS` that never invented, which say what
  // decides it: a HTAB where §11.3's `1*SP` needs a SP, or no whitespace in
  // front of the `=` at all, and the element is refused at its `auth-scheme`
  // rather than inside a body. None of them may start.
  for (spelling, value) in BWS_SAFE {
    assert!(
      !yields_the_probe(&[value]),
      "the `{spelling}` spelling crosses nothing"
    );
    assert!(
      says_the_rest_is_unread(&[value]),
      "and the `{spelling}` spelling tells the caller the rest is unread"
    );
  }
  // And the family's own `scheme` axis, as one-line values: the HTAB scheme is
  // what leaves the trap an element of the OUTER list, where a challenge is
  // read at it; the SP scheme keeps it inside the continuation's own body, an
  // element `opens_a_challenge` answers `false` for. Only the first ever
  // invented, and the SP half is written by the family rather than missing
  // from it.
  for (scheme, value, declines) in BWS_BY_SCHEME {
    assert!(
      !yields_the_probe(&[value]),
      "the `{scheme}` scheme yields the probe"
    );
    assert_eq!(
      says_the_rest_is_unread(&[value]),
      declines,
      "the `{scheme}` scheme's notice"
    );
  }

  // `hider-unexcused` was the other zero-target and corpus O answered 18. It
  // answers 0, and the 18 are `no-probe`: the probe stands at the first element
  // of a challenge's BODY with no §5.6.1.2 comma in front of it, so no reading
  // of the outer `#challenge` list has an element start there and there is
  // nothing for any reader to show or to hide. They were never a defect of the
  // reader — `oracle::derives_as_a_challenge` asked whether the probe's own
  // bytes derive as a challenge and not whether one may STAND at that offset,
  // which is the distinction `oracle::covers` has carried as `Start::Body`
  // since `Basic a a=", Digest realm=z`.
  //
  // Pinned by SHAPE, because a family that stopped writing the shape would go
  // quiet rather than red. The other six are `head=open`: the same body
  // position with a §5.2 join carrying an open string over it, which used to
  // grade `hider-excused` for a reading that has no challenge to hold.
  assert_eq!(
    of(&tally(&o, |_| true), "hider-unexcused"),
    0,
    "corpus O: the probes at a body position"
  );
  let mut bodied = 0usize;
  for line in &o {
    let [_, case, spelling, axis, _] = columns(line);
    if !(spelling.contains(" empties=0 ") && spelling.ends_with("body=probe")) {
      continue;
    }
    let lines: Vec<Vec<u8>> = case.split('|').map(unescape).collect();
    let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    let joined = join(&refs);
    let probe = probe_at(&joined);
    // Where §5.6.1.2 would put the element start in front of the probe, read
    // off the value here rather than taken from the oracle: the far side of the
    // last comma, with the `OWS` that comma carries skipped. The probe stands
    // PAST it, so no element of the outer list begins where the probe does.
    let element = last_index_of(joined.get(..probe).unwrap_or_default(), b",")
      .map_or(0, |at| at.saturating_add(1));
    assert!(
      past_ows(&joined, element) < probe,
      "corpus O: a body=probe row whose probe IS an element start: {line}"
    );
    assert_eq!(
      axis, "no-probe",
      "corpus O: a probe at a body position graded as one that stands there: {line}"
    );
    bodied += 1;
  }
  assert_eq!(
    bodied, 24,
    "corpus O: four heads by three join counts by two schemes"
  );
  // The same fact over the one-line witness, with the oracle's own verdict
  // beside it.
  let inside = oracle::read(PROBE_INSIDE_A_BODY, probe_at(PROBE_INSIDE_A_BODY));
  assert!(
    !inside.derives,
    "no element of the outer `#challenge` list begins at a body's first element"
  );
  assert!(
    !inside.reached,
    "no derivation of the whole value reaches it"
  );
  assert!(!inside.excused, "and no reading holds it inside a string");
  assert!(
    !yields_the_probe(&[PROBE_INSIDE_A_BODY]),
    "the walk does not invent a challenge out of a body's first element"
  );
  // And the control, one comma apart: with §5.6.1.2's separator in front of it
  // the same bytes ARE an element of the outer list, a challenge stands there,
  // and the walk shows it.
  let element = oracle::read(PROBE_AT_AN_ELEMENT, probe_at(PROBE_AT_AN_ELEMENT));
  assert!(
    element.derives,
    "a comma puts an element start at the probe"
  );
  assert!(
    yields_the_probe(&[PROBE_AT_AN_ELEMENT]),
    "and the walk shows the challenge that stands there"
  );
}

/// How many of corpus O's cells answer differently depending on where §5.2's
/// join was cut, and what shape every one of them has.
///
/// # The argument this constant used to lack
///
/// [`UNRESOLVED`] and [`CONFORMING`] are pinned because each is a cost this
/// module has an argument for. This one had none. It has one now, and the
/// argument is not that the divergence is acceptable — it is that the obvious
/// fix MOVES the class rather than closing it, which is a thing measured rather
/// than supposed. [`ONE_VALUE_THREE_SPELLINGS`] is that measurement pinned.
///
/// Every cut of a cell spells ONE value — RFC 9110 §5.2 contributes exactly the
/// comma the cut took out, and the test above asserts the byte identity before
/// it asks anything about answers. Over 1 140 of the 1 176 cells the answers
/// agree. Over 36 they do not: the probe is SHOWN where the join is the LAST
/// comma of the leading run — so the body's first non-empty element begins at
/// the head of a field line — and DECLINED with
/// `AuthError::ChallengeBoundaryUnknown` at every earlier cut of the same
/// value.
///
/// All 36 are `head=open body=closed-front`, and the shape says why the two
/// classes are the ones they are. `Basic a="x` opens a §5.6.4 quoted-string
/// that §5.2's joins carry, `realm="c"` CLOSES in front of the probe, and the
/// element the fault is met over ends at that close — so the walk recovers on
/// the line that close is on. Where a comma stands in front of it ON THAT LINE
/// the readings disagree about that comma and the walk declines; where the cut
/// moved the close to the head of its own line there is no such comma to see,
/// and the same value's probe is shown. `Recovery::floor` is the offset that
/// question is asked at.
///
/// **Neither answer is a zero-target**: the declining rows grade
/// `hider-unresolved` and the showing rows `yields-underivable`, and both are
/// classes this module holds at a pinned number rather than at zero. So the
/// whole divergence is invisible to [`ZERO_TARGETS`] by construction, and it is
/// the second thing corpus O found that no gate in front of it could see.
///
/// What it is NOT is a `MAX_CHALLENGE_LINES` effect, which is the one place
/// this module is entitled to answer by the spelling: corpus O writes at most
/// five field lines and that bound is seventeen.
///
/// # Why 36 and not 0, and what a fix would have to be
///
/// The reading that opened the refused element's value holds every comma in
/// front of its close, so no boundary may be CERTIFIED there — that is the
/// module's own invariant and `Recovery::floor` is where it is enforced. To
/// answer the earlier cuts as the last one does, the recovery would have to
/// reach the first comma BEHIND the close, which means getting past the commas
/// in front of it without certifying any of them.
///
/// **The obvious way to do that was built and measured, and it relocates the
/// class.** Making `floor` an offset the recovery may not STOP in front of —
/// rather than a test of whether it may run at all — takes these 36 cells to
/// zero, moves 72 corpus O records `hider-unresolved` -> `yields-underivable`,
/// moves nothing anywhere else, and leaves all three of [`ZERO_TARGETS`] at
/// zero. It also makes `Basic a="x,p, q"junk, Digest realm=z` answer
/// `Ok[Digest]` over two field lines and `ChallengeBoundaryUnknown` over one.
/// The same value, parted by its spelling, in the other direction.
///
/// The reason is the invariant: crossing the comma behind `p` is certifying a
/// comma the reading that opened `a`'s value holds. What a recovery would need
/// instead is the SHUT reading's elements across the whole run in front of the
/// close — and each of them may open a §5.6.4 quoted-string of its own, so the
/// question stops being the one-opener scan `opener_at` argues for and becomes
/// the subset construction `crate::grammar`'s `Readings` makes for RFC 9110
/// §5.6.6's `parameters`. Nor is the close itself a place to resume from: at
/// `Basic a="x` and a continuation whose first element is `r` with a quoted
/// value of `c`, the open reading's string closes at the DQUOTE the SHUT
/// reading's `r` opens its value with — so the two stand on opposite sides of
/// that one byte, and neither offset is one every reading is outside a string
/// at.
///
/// # And 36 is a LOWER BOUND on the class
///
/// Corpus O's `cut` axis moves §5.2's join inside a leading run of EMPTY
/// elements, which is the only place any generator here cuts a value. The class
/// is about a cut falling anywhere the carried value runs, and
/// [`ONE_VALUE_THREE_SPELLINGS`] is a value that parts at THIS commit over a
/// cut no family writes: three field lines show the probe where one and two
/// decline. So this number counts what corpus O can see and not what there is.
const CUTS_THAT_PART: usize = 36;

/// One value, spelled over one, two and three field lines, that this walk
/// answers about in two ways.
///
/// RFC 9110 §5.2 makes the three one value — "concatenated in order, with each
/// field line value separated by a comma" — so every byte of it is the same and
/// only where the sender cut it differs. The two-line spelling puts a comma in
/// front of the close of the value `a="x` opened; the three-line spelling puts
/// that close on the head of its own line; and the one-line spelling has no
/// join at all, so `Recovery::floor` is the element's own start and
/// `some_reading_holds` is asked at the DQUOTE rather than at a line head.
///
/// The last field is what the walk answers: `true` where it SHOWS the probe.
/// It is pinned rather than driven to one value because [`CUTS_THAT_PART`]
/// carries why, and because a constant nobody can see move is how this
/// divergence went unnoticed for so long.
const ONE_VALUE_THREE_SPELLINGS: [(&str, &[&[u8]], bool); 3] = [
  (
    "one line",
    &[b"Basic a=\"x,p, q\"junk, Digest realm=z"],
    false,
  ),
  (
    "two lines",
    &[b"Basic a=\"x", b"p, q\"junk, Digest realm=z"],
    false,
  ),
  (
    "three lines",
    &[b"Basic a=\"x", b"p", b" q\"junk, Digest realm=z"],
    true,
  ),
];

#[test]
fn one_value_spelled_over_three_line_counts_answers_two_ways() {
  // The bytes first, because the whole claim is that these are one value and
  // the answers below are therefore about a spelling.
  let joined: Vec<Vec<u8>> = ONE_VALUE_THREE_SPELLINGS
    .iter()
    .map(|(_, lines, _)| join(lines))
    .collect();
  for value in &joined {
    assert_eq!(value, &joined[0], "the three spellings are not one value");
  }
  // And no reading holds the probe inside a value, so showing it is recovery
  // and declining it is a cost — neither answer is a zero-target, which is why
  // no gate of this crate can see the divergence.
  let verdict = oracle::read(&joined[0], probe_at(&joined[0]));
  assert!(verdict.derives, "a challenge stands at the probe");
  assert!(
    !verdict.reached,
    "and no derivation of the value reaches it"
  );
  assert!(!verdict.excused, "and no reading holds it inside a string");

  for (spelling, lines, shows) in ONE_VALUE_THREE_SPELLINGS {
    assert_eq!(yields_the_probe(lines), shows, "the `{spelling}` spelling");
    assert_eq!(
      says_the_rest_is_unread(lines),
      !shows,
      "the `{spelling}` spelling's notice"
    );
  }
}

/// Whether every cell whose cuts answer differently has the shape
/// [`CUTS_THAT_PART`] names, and the direction it names.
fn the_cells_whose_cuts_answer_differently(
  cells: &HashMap<String, Vec<&String>>,
  parted: &[&String],
) {
  assert_eq!(
    parted.len(),
    CUTS_THAT_PART,
    "corpus O: the cells whose cuts answer differently"
  );
  let mut shown = 0usize;
  let mut declined = 0usize;
  for line in parted {
    let [_, _, spelling, _, _] = columns(line);
    assert!(
      spelling.contains(" head=open ") && spelling.ends_with("body=closed-front"),
      "corpus O: a parted cell outside the shape this constant names: {line}"
    );
    let cell = spelling
      .split(' ')
      .filter(|field| !field.starts_with("cut="))
      .collect::<Vec<_>>()
      .join(" ");
    let empties = spelling
      .split_once(" empties=")
      .and_then(|(_, rest)| rest.split(' ').next())
      .and_then(|digits| digits.parse::<usize>().ok())
      .expect("every corpus O spelling names its own run");
    for row in cells.get(&cell).expect("the cell the row came from") {
      let [_, _, its, _, answer] = columns(row);
      let cut = its
        .split_once(" cut=")
        .and_then(|(_, rest)| rest.split(' ').next())
        .and_then(|digits| digits.parse::<usize>().ok())
        .expect("every corpus O spelling names where the join falls");
      let yields = answer.contains(&format!("Ok[{}", escape(PROBE_SCHEME)));
      if cut == empties {
        assert!(
          yields,
          "corpus O: the cut that puts the element at a line's head hides the \
           probe: {row}"
        );
        shown = shown.saturating_add(1);
      } else {
        assert!(
          !yields && answer.contains("Err(ChallengeBoundaryUnknown)"),
          "corpus O: an earlier cut of a parted cell answers a third way: {row}"
        );
        declined = declined.saturating_add(1);
      }
    }
  }
  assert_eq!(
    shown, 36,
    "the cut of each parted cell that shows the probe"
  );
  assert_eq!(
    declined, 72,
    "the cuts of the same 36 values that decline it"
  );
}
