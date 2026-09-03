//! The differential corpus for `http-semantics`'s RFC 9110 §11 authentication
//! fields: one record per answer, naming what THIS build says about one input.
//!
//! Run it at two revisions and diff the records and you have answered the
//! question every change to this module has to answer —
//! *did this change move an answer, and was it one that should have moved?*
//! That is what `cargo run -p xtask -- auth-diff <base> [head]` does; see
//! `xtask/src/auth_diff.rs`.
//!
//! It is committed so that every digest published over these fields can be
//! recomputed from a checkout. A digest nobody can recompute is not evidence,
//! and a harness deleted once it has published one leaves behind a number and
//! no way to disagree with it.
//!
//! # Contract
//!
//! Every record is one line of five tab-separated columns:
//!
//! ```text
//! corpus <TAB> case <TAB> spelling <TAB> axis <TAB> answer
//! ```
//!
//! - `corpus` — which generator produced the input: `A`..`O`.
//! - `case` — the field lines, escaped, `|`-separated. `(corpus, case,
//!   spelling)` is the record's key, and it is unique everywhere but the 32
//!   inputs corpus D writes six times each — see
//!   `tests::the_records_that_share_a_key_are_the_ones_no_mid_can_tell_apart`,
//!   which pins that exception and says what it costs. 948 544 records stand
//!   for 948 384 distinct inputs — the two figures
//!   `tests::the_records_that_share_a_key_are_the_ones_no_mid_can_tell_apart`
//!   asserts, and they are quoted from it rather than counted again here.
//!   **Every corpus D figure quoted from this
//!   crate is a count of RECORDS, not of distinct inputs**;
//!   `corpus_d`'s own doc carries the arithmetic, and
//!   `tests::what_corpus_d_says_about_distinct_inputs_is_not_what_its_records_say`
//!   pins both readings side by side so neither can be mistaken for the other.
//! - `spelling` — which entry point was called and over what shape.
//! - `axis` — how the case grades on the ONE axis this module is graded on:
//!   does a malformed challenge hide a well-formed one
//!   behind it? See [`axis`]. `-` where the case carries no probe challenge to
//!   hide.
//! - `answer` — everything the entry point yielded, rendered. This is the
//!   column the differential's digest is taken over.
//!
//! # What checks THIS
//!
//! `tests`, and `cargo test -p auth-corpus` in CI's `test` job. Its own tally
//! is asserted rather than narrated, so a tree
//! whose answers stop reproducing the figures pinned there says so from a
//! red gate. It also pins a SHA-256 of the `answer` column, per corpus and
//! over the whole run, which is what catches an answer that moves without
//! moving a tally — the class of change a tally of verdicts is blind to by
//! construction. `tests`'s doc says what that gate still cannot see.
//!
//! # Two constraints this file is written under
//!
//! **Public API only.** A corpus that reached into the crate would measure a
//! private reorganisation as a behaviour change.
//!
//! **The oracle reads nothing from the module.** `oracle` is an independent
//! derivation from RFC 9110's grammar; if it agreed with `http_semantics::auth`
//! by construction it would grade nothing.

// gate-exempt: trap="open, Digest realm=z — one field value shown in prose, a
// tail this corpus names to contrast with its own; not a production of any RFC.
mod oracle;
/// The second derivation of `oracle::Verdict::excused`, and the differential
/// over the two. Its own doc says what the two share and what they do not.
mod readings;
/// FIPS 180-4's SHA-256, shared with `xtask` by path rather than copied.
///
/// `tests` pins a digest of the ANSWER column and
/// `cargo run -p xtask -- auth-diff` prints one; they are the same number only
/// if they are the same code, so this is the file that driver hashes with
/// rather than a second implementation of it. `auth-corpus` takes no
/// dependencies and `xtask` has no library target to take one on, and a copy
/// would be two hashes that can disagree while both stay green.
///
/// It is `#[cfg(test)]` and has to stay so. `auth-diff` builds this crate's
/// sources in a scratch directory beside a checkout, where that relative path
/// resolves to nothing — and never has to, because a module cfg'd out is never
/// loaded.
#[cfg(test)]
#[path = "../../xtask/src/sha256.rs"]
mod sha256;
#[cfg(test)]
mod tests;

use std::{
  env,
  fs::File,
  io::{BufWriter, Write},
  iter, process,
};

use http_semantics::{
  auth::{AuthError, Credential, MAX_CHALLENGE_LINES, auth_info, challenges, credentials},
  grammar::ParamValue,
};

/// The eight bytes corpora A, B and C draw their payloads from: the two
/// `tchar`s a name and a value need, the `=` that joins them, the DQUOTE and
/// the backslash RFC 9110 §5.6.4 gives meaning to, the comma §5.6.1 separates
/// with, and the two bytes §5.6.3's `OWS` is made of.
const ALPHABET: [u8; 8] = *b"ax=\", \\\t";

/// The challenge every corpus hides behind its payload, and the one the axis
/// is graded on.
const PROBE: &[u8] = b"Digest realm=z";

/// The scheme of that challenge.
const PROBE_SCHEME: &[u8] = b"Digest";

fn main() {
  let mut args = env::args().skip(1);
  let out = args.next();
  if args.next().is_some() {
    eprintln!("auth-corpus: usage: auth-corpus [<output-path>]");
    process::exit(1);
  }
  let result = match out {
    Some(path) => match File::create(&path) {
      Ok(file) => emit(&mut BufWriter::new(file)),
      Err(err) => {
        eprintln!("auth-corpus: cannot write {path}: {err}");
        process::exit(1);
      }
    },
    None => emit(&mut BufWriter::new(std::io::stdout().lock())),
  };
  if let Err(err) = result {
    eprintln!("auth-corpus: {err}");
    process::exit(1);
  }
}

/// Writes every record, and the per-corpus counts to stderr.
fn emit(out: &mut impl Write) -> std::io::Result<()> {
  let mut counts = [0_usize; 15];
  corpus_a(out, &mut counts[0])?;
  corpus_b(out, &mut counts[1])?;
  corpus_c(out, &mut counts[2])?;
  corpus_d(out, &mut counts[3])?;
  corpus_e(out, &mut counts[4])?;
  corpus_f(out, &mut counts[5])?;
  corpus_g(out, &mut counts[6])?;
  corpus_h(out, &mut counts[7])?;
  corpus_i(out, &mut counts[8])?;
  corpus_j(out, &mut counts[9])?;
  corpus_k(out, &mut counts[10])?;
  corpus_l(out, &mut counts[11])?;
  corpus_m(out, &mut counts[12])?;
  corpus_n(out, &mut counts[13])?;
  corpus_o(out, &mut counts[14])?;
  out.flush()?;
  let total: usize = counts.iter().sum();
  for (name, count) in [
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
  ]
  .iter()
  .zip(counts)
  {
    eprintln!("auth-corpus: {name} {count}");
  }
  eprintln!("auth-corpus: total {total}");
  Ok(())
}

// ───────────────────────────────── the corpora ───────────────────────────────

/// Every payload of length `len` over [`ALPHABET`], in a fixed order.
fn payloads(len: u32) -> impl Iterator<Item = Vec<u8>> {
  let count = ALPHABET.len().pow(len);
  (0..count).map(move |mut index| {
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
      out.push(ALPHABET[index % ALPHABET.len()]);
      index /= ALPHABET.len();
    }
    out
  })
}

/// A payload behind `Basic `, read seven ways: all three entry points, with and
/// without a probe challenge behind the payload, and across RFC 9110 §5.2's
/// join.
fn corpus_a(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for len in 1..=5 {
    for payload in payloads(len) {
      let mut tailed = b"Basic ".to_vec();
      tailed.extend_from_slice(&payload);
      tailed.extend_from_slice(b", ");
      tailed.extend_from_slice(PROBE);
      let mut bare = b"Basic ".to_vec();
      bare.extend_from_slice(&payload);
      let mut split = payload.clone();
      split.extend_from_slice(b", ");
      split.extend_from_slice(PROBE);

      record(out, "A", &[&tailed], "challenges-tail", count)?;
      record(out, "A", &[&bare], "challenges-bare", count)?;
      record(
        out,
        "A",
        &[b"Basic ", &split],
        "challenges-split-scheme",
        count,
      )?;
      record(out, "A", &[&tailed], "credentials-tail", count)?;
      record(out, "A", &[&bare], "credentials-bare", count)?;
      record(out, "A", &[&payload], "auth-info", count)?;
      record(out, "A", &[&payload, b"b=2"], "auth-info-join", count)?;
    }
  }
  Ok(())
}

/// The same payloads, split across RFC 9110 §5.2's join at every interior
/// position — the shape a sender writes when it repeats the field name.
fn corpus_b(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for len in 1..=5 {
    for payload in payloads(len) {
      for cut in 1..payload.len() {
        let mut head = b"Basic ".to_vec();
        head.extend_from_slice(payload.get(..cut).unwrap_or_default());
        let mut tail = payload.get(cut..).unwrap_or_default().to_vec();
        tail.extend_from_slice(b", ");
        tail.extend_from_slice(PROBE);
        record(out, "B", &[&head, &tail], "challenges-split", count)?;
      }
    }
  }
  Ok(())
}

/// The same alphabet one byte longer, read the two ways that reach the two
/// walks the module has to keep in step.
fn corpus_c(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for payload in payloads(6) {
    let mut tailed = b"Basic ".to_vec();
    tailed.extend_from_slice(&payload);
    tailed.extend_from_slice(b", ");
    tailed.extend_from_slice(PROBE);
    let mut bare = b"Basic ".to_vec();
    bare.extend_from_slice(&payload);
    record(out, "C", &[&tailed], "challenges-tail", count)?;
    record(out, "C", &[&bare], "credentials-bare", count)?;
  }
  Ok(())
}

/// The tails corpora D and E put behind a challenge that ran long: a byte RFC
/// 9110 §5.6.4 forbids, a close with junk behind it, a value left open, an
/// element that opens a challenge of its own, the probe with and without a
/// comma in front of it, and a forbidden byte with nothing behind it at all.
const TAILS: [&[u8]; 8] = [
  b"\x00, Digest realm=z",
  b"y\", Digest realm=z",
  b"trap=\"open, Digest realm=z",
  b"p, Digest realm=z",
  b"Digest realm=z",
  b", Digest realm=z",
  b"y\"junk, Digest realm=z",
  b"\x00",
];

/// A head, a middle repeated up to eighteen times, and a tail — the shape that
/// drives `MAX_CHALLENGE_LINES` with a value open across the regions.
///
/// # This generator writes 32 of its inputs six times each, and that is left in
///
/// At ZERO repeats the middle is not in the case at all, so the six middles
/// collapse onto one input: 4 heads x 8 tails = 32 inputs, 192 records, 160 of
/// them surplus. 3648 records over 3488 distinct inputs.
///
/// **So every figure quoted for corpus D counts records, and four of its five
/// classes count some input more than once**: 30
/// surplus `hider-excused`, 20 `no-probe`, 50 `yields`, 60
/// `yields-underivable`, 0 `hider-unresolved`. The 90 records
/// `evidence/auth-forbidden-byte-refuses` moved read 85 over distinct inputs.
///
/// It is left in rather than deduplicated because fixing the generator would
/// move every D figure and every D digest for a reason that is not a change in
/// what the module answers. What is done instead is to state both readings and
/// pin both — `tests::the_axis_this_tree_answers_with_is_the_one_pinned` holds
/// the record tally, and
/// `tests::what_corpus_d_says_about_distinct_inputs_is_not_what_its_records_say`
/// holds the distinct-input tally a maintainer should quote from here on.
/// Neither number is left for a reader to infer.
///
/// # What no corpus varies, and why not here
///
/// The line bound's recovery point has the same asymmetry the forbidden byte's
/// has — the same value written over one field line fewer answers with one
/// challenge fewer, because folding a join comma into the line in front of it
/// moves which line the overrun lands on. No corpus spells that fold AT THE
/// BOUND. Corpus F spells the fold itself — its `split` variants cut a value at
/// its own comma, so its one-line and two-line spellings are one value — but at
/// two lines, nowhere near the seventeen a bound needs; and this generator
/// varies its LINE COUNT rather than the spelling of one value, its middles
/// carrying a bare comma and never a comma folded onto the end of an element.
/// So the differential cannot see the pair at all.
/// It is pinned by a unit test instead —
/// `the_line_bound_met_inside_a_value_leaves_the_two_spellings_the_same_answer`
/// in `http-semantics/src/auth/tests.rs`, beside the forbidden byte's. That
/// asymmetry is gone as of the commit that closed al8n/wren#77: the bound met
/// with a value still open leaves no boundary either spelling can derive, so
/// both answer `ChallengeSpansTooManyLines` and then
/// `ChallengeBoundaryUnknown`. What the unit test now pins is the agreement.
fn corpus_d(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  let heads: [&[u8]; 4] = [b"Basic a=\"x", b"Basic a=x", b"Basic a=\"x\"", b"Basic"];
  let mids: [&[u8]; 6] = [b"j", b"b=2", b"", b" ", b",", b"\""];
  for head in heads {
    for mid in mids {
      for repeats in 0..=18 {
        for tail in TAILS {
          let mut lines: Vec<&[u8]> = Vec::with_capacity(repeats + 2);
          lines.push(head);
          for _ in 0..repeats {
            lines.push(mid);
          }
          lines.push(tail);
          record(out, "D", &lines, "challenges-lines", count)?;
        }
      }
    }
  }
  Ok(())
}

/// A challenge whose parameters are all DISTINCT, so RFC 9110 §11.2's
/// one-name-once MUST refuses nothing and the prefix derives right up to the
/// tail — with and without a value left open on the first field line.
fn corpus_e(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for open in [false, true] {
    for params in 1..=20 {
      for tail in TAILS {
        let mut owned: Vec<Vec<u8>> = Vec::with_capacity(params + 2);
        owned.push(if open {
          b"Basic p0=\"open".to_vec()
        } else {
          b"Basic p0=0".to_vec()
        });
        for index in 1..=params {
          owned.push(format!("p{index}={index}").into_bytes());
        }
        owned.push(tail.to_vec());
        let lines: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
        record(out, "E", &lines, "challenges-lines", count)?;
      }
    }
  }
  Ok(())
}

/// The octets corpus F puts inside a value, each with the name it is recorded
/// under.
///
/// The first six are RFC 9110 §5.6.4's forbidden ones — every byte that makes
/// a quoted-string scan fail is a CTL other than HTAB, and §5.5 says of them
/// "Field values containing other CTL characters are also invalid" one
/// sentence after putting a MUST on the three of them it names. The rest are
/// the controls that must NOT take that path: `obs-text` IS `qdtext`, an
/// escaped `obs-text` IS a `quoted-pair`, and an escaped DQUOTE is the one
/// §11.6.1's own worked example carries.
const OCTETS: [(&str, &[u8]); 12] = [
  ("nul", b"\x00"),
  ("soh", b"\x01"),
  ("lf", b"\x0a"),
  ("cr", b"\x0d"),
  ("us", b"\x1f"),
  ("del", b"\x7f"),
  ("escaped-nul", b"\\\x00"),
  ("escaped-del", b"\\\x7f"),
  ("obs-text-80", b"\x80"),
  ("obs-text-ff", b"\xff"),
  ("escaped-obs-text", b"\\\x80"),
  ("escaped-dquote", b"\\\""),
];

/// A probe challenge written INSIDE a `realm` value, with one octet beside it.
///
/// This is the shape the other five corpora cannot reach and the one the
/// `InvalidQuotedString` rule is about: a comma the sender put inside a value,
/// with a byte that decides whether that value derives at all standing in
/// front of the comma or behind it. `obs-text` is in the same corpus for the
/// same reason — it IS `qdtext`, so a high byte must leave the value deriving,
/// and a differential that only carried forbidden bytes could not tell the two
/// rules apart.
fn corpus_f(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for (name, octet) in OCTETS {
    for behind in [false, true] {
      for closed in [false, true] {
        for split in [false, true] {
          for trailing in [&b""[..], b", x=1"] {
            let mut line = b"Basic realm=\"a".to_vec();
            if !behind {
              line.extend_from_slice(octet);
            }
            line.push(b'b');
            // Where the sender's own comma stands. Splitting the value HERE
            // makes RFC 9110 §5.2's join comma the very byte the single-line
            // spelling carries, so the two spellings are one value.
            let cut = line.len();
            line.extend_from_slice(b", ");
            line.extend_from_slice(PROBE);
            if behind {
              // Behind the probe and behind a comma of its own, so the probe
              // itself is a whole challenge in whatever run a recovery cuts —
              // which is the shape that can MANUFACTURE one out of a value.
              line.extend_from_slice(b", ");
              line.extend_from_slice(octet);
            }
            line.push(b'c');
            if closed {
              line.push(b'"');
            }
            line.extend_from_slice(trailing);

            let spelling = format!(
              "octet={name} behind={behind} closed={closed} split={split} trailing={}",
              trailing.len()
            );
            if split {
              let head = line.get(..cut).unwrap_or_default();
              let tail = line.get(cut.saturating_add(1)..).unwrap_or_default();
              record(out, "F", &[head, tail], &spelling, count)?;
            } else {
              record(out, "F", &[&line], &spelling, count)?;
            }
          }
        }
      }
    }
  }
  Ok(())
}

/// The tail corpus G adds to [`TAILS`]: a parameter whose value is a
/// well-formed RFC 9110 §5.6.4 quoted-string carrying the probe, a comma, and
/// more of its own data, CLOSING behind all of it.
///
/// The shape al8n/wren#77 was measured on, and the one no other corpus spells.
/// Every quoted tail in [`TAILS`] leaves its string OPEN, so a reader could be
/// right about all of them for the wrong reason — by treating an unterminated
/// run as special — and still cut this one in half. Here nothing at all is
/// wrong with the value: the string opens where §11.2 admits one, closes, and
/// the commas between are `qdtext`.
const CLOSED_OVER_THE_PROBE: &[u8] = b"x=\"c, Digest realm=z, junk\"";

/// A challenge whose parameters are all DISTINCT and all on ONE field line, so
/// that [`MAX_PARAMS_PER_CREDENTIAL`](http_semantics::auth::MAX_PARAMS_PER_CREDENTIAL)
/// is the bound that fires.
///
/// # The witness no other corpus could reach
///
/// `TooManyParameters` occurred ZERO times in corpora A..F. Corpus E is the one
/// that varies a parameter count, and it writes one parameter per FIELD LINE —
/// so `MAX_CHALLENGE_LINES` always fired first and the parameter bound was never
/// met. The strongest trigger of the recovery al8n/wren#77 is about was
/// unreachable by the harness built to find it, and the differential was green
/// over a defect it could not spell.
///
/// The bound is the one refusal here that RFC 9110 admits nothing about: §11.2
/// bounds `#auth-param` nowhere, so every input this corpus writes CONFORMS, and
/// what refuses it is this reader's own storage. That makes it the trigger a
/// recovery may least afford to be wrong behind.
fn corpus_g(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for params in 1..=20 {
    for tail in TAILS.into_iter().chain([CLOSED_OVER_THE_PROBE]) {
      let mut line = b"Basic p0=0".to_vec();
      for index in 1..=params {
        line.extend_from_slice(format!(", p{index}={index}").as_bytes());
      }
      line.extend_from_slice(b", ");
      line.extend_from_slice(tail);
      record(out, "G", &[&line], "challenges-params", count)?;
    }
  }
  Ok(())
}

/// The continuation lines corpus H writes behind RFC 9110 §5.2's join.
///
/// Each is a whole field line, and the reading that left the head's value SHUT
/// at the join opens an element of the outer `#challenge` list at its first
/// byte — which §11.6.1 lets be a whole challenge, scheme and `1*SP` and
/// parameters. The first two carry the probe INSIDE such a challenge's own
/// quoted parameter, which is the shape that manufactures one; the rest are the
/// neighbours that must not be refused with them.
const CONTINUATIONS: [&[u8]; 10] = [
  // A challenge whose quoted `realm` opens in front of the probe and never
  // closes, so the probe is that realm's data under the reading that shut the
  // head at the join.
  b"Newauth realm=\"c, Digest realm=z",
  // The same, CLOSED behind the probe — nothing at all wrong with that value,
  // so a reader that is right about the unterminated one for the wrong reason
  // (by treating an unterminated run as special) is still wrong here. The probe
  // has bytes behind it that derive nothing, which is what a closing DQUOTE
  // costs, so the axis grades this `no-probe` and the answer column is what
  // pins it — the same trade [`CLOSED_OVER_THE_PROBE`] makes in corpus G.
  b"Newauth realm=\"c, Digest realm=z, junk\"",
  // Closed in FRONT of the probe, so both readings stand outside the string at
  // the comma and the probe is a challenge whose boundary they agree on.
  b"Newauth realm=\"c\", Digest realm=z",
  // No quoted value anywhere in the challenge.
  b"Newauth realm=c, Digest realm=z",
  // A challenge whose first body element admits a value position nowhere.
  b"Newauth p, Digest realm=z",
  // An `auth-param` and not a challenge: no `1*SP` stands behind its token, so
  // the opener is the element's OWN value position.
  b"realm=\"c, Digest realm=z",
  // The same element with RFC 9110 §11.2's `BWS` in FRONT of its `=`, which is
  // whitespace §11.3's `1*SP` IS a prefix of — so `realm` reads as an
  // `auth-scheme` too, with a body opening at the `=` that derives nothing. The
  // row above is this element with that whitespace off it, and the pair is the
  // one place this family parts §11.6.1's two readings behind the offset §5.2's
  // join left rather than at it. The `Newauth realm = "c` row below writes the
  // same `BWS` inside a challenge's BODY, where the element's own head is a
  // scheme and there is no second reading of it to lose.
  b"realm = \"c, Digest realm=z",
  // The probe itself at the head of the line.
  b"Digest realm=z",
  // §11.2's `BWS` around the `=`, which §5.6.6's `parameter` does not have: the
  // same opener, spelled with the whitespace.
  b"Newauth realm = \"c, Digest realm=z",
  // A HTAB where `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
  // writes `1*SP`, so no challenge opens here and the DQUOTE is at no value
  // position of any reading.
  b"Newauth\trealm=\"c, Digest realm=z",
];

/// The heads corpus H opens with: each leaves a RFC 9110 §5.6.4 quoted-string
/// OPEN where its field line ends, so §5.2's join carries the element onto the
/// continuation line and the readings of that element part AT the join.
const OPEN_HEADS: [&[u8]; 4] = [
  b"Basic a=\"x",
  // A parameter already taken, so the list is open with a name in it.
  b"Basic p=1, a=\"x",
  // §11.2's one-name-once MUST, which refuses the element rather than the
  // bytes behind it.
  b"Basic a=1, a=\"x",
  // A `quoted-pair` left half-written, whose escape §5.2's join comma spends.
  b"Basic a=\"x\\",
];

/// The middle line corpus H's two-join spelling inserts.
///
/// It carries no DQUOTE, so the head's string is still open where this line
/// ends — which is what keeps the reading that shut that string at the FIRST
/// join from opening one of its own before the last line. RFC 9110 §5.6.4 ends
/// a string only at a DQUOTE, and one this line held would either close the
/// head's value here or stand behind a backslash, where §11.2 admits no value.
const UNCLOSING: &[u8] = b"nothing here closes it";

/// A challenge that begins on the continuation line RFC 9110 §5.2's join opens.
///
/// # The shape no other corpus spells
///
/// Corpora D and E put a tail behind a join, but every tail of theirs is read
/// at the recovery cursor itself: `trap="open, Digest realm=z` is an
/// `auth-param`, so the DQUOTE that hides the probe stands at the value
/// position of the element the cursor is ON. RFC 9110 §11.6.1 admits a second
/// reading of that element — it "might contain more than one challenge, and
/// each challenge can contain a comma-separated list of authentication
/// parameters" — under which the line opens a whole `challenge`, and THAT
/// challenge's first parameter has its value position behind
/// `auth-scheme 1*SP`, at an offset a check asked only at the cursor never
/// looks at.
///
/// So a reader could answer every D and E record correctly and still hand a
/// caller a challenge read out of the middle of a realm written on the
/// continuation line. This corpus is that record, and its two-join spelling is
/// the pin that one line's worth of state answers for a value spread over more.
fn corpus_h(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for head in OPEN_HEADS {
    for continuation in CONTINUATIONS {
      for joins in [1_usize, 2] {
        let mut lines: Vec<&[u8]> = Vec::with_capacity(3);
        lines.push(head);
        if joins == 2 {
          lines.push(UNCLOSING);
        }
        lines.push(continuation);
        let spelling = format!("challenges-join joins={joins}");
        record(out, "H", &lines, &spelling, count)?;
      }
    }
  }
  Ok(())
}

/// The RFC 9110 §5.6.1.2 `OWS` corpus I writes between §5.2's join comma and
/// the element behind it, each with the name it is recorded under.
///
/// `#element => [ element ] *( OWS "," OWS [ element ] )` hangs whitespace on
/// BOTH sides of that comma, and §5.6.3's `OWS` is `*( SP / HTAB )`, so all
/// four spell the same list and the element begins where the whitespace ends.
const LIST_OWS: [(&str, &[u8]); 4] = [
  ("sp", b" "),
  ("htab", b"\t"),
  ("sp-sp", b"  "),
  ("sp-htab", b" \t"),
];

/// Corpus H's shapes with the list's own `OWS` in front of the continuation
/// element.
///
/// # The shape corpus H holds fixed
///
/// Every line in [`CONTINUATIONS`] begins with the element's own first byte, so
/// a reader that looked for either of RFC 9110 §11.6.1's two openers AT the
/// offset §5.2's join left the cursor on found them both. §5.6.1.2 puts `OWS`
/// behind its comma, and a sender that wrote one there moves the element — and
/// both of its openers — off that offset. §5.6.2's `tchar` excludes SP and
/// HTAB, so a check asked at the offset rather than at the element finds no
/// `token` at all, reads the run as one holding no opener, and crosses the comma
/// inside the continuation's own quoted value as if it were §5.6.1.2's
/// separator.
///
/// `Basic a="x` and `<SP>realm="evil, Digest realm=z` are that value — the
/// `<SP>` written visibly because one space is the whole of it — and the
/// `Digest` handed back was read out of the middle of a `realm` the sender
/// wrote whole. The `Newauth realm=...` continuations spell the same
/// defect through §11.6.1's OTHER reading, where the opener stands behind
/// `auth-scheme 1*SP` as well as behind the `OWS`.
fn corpus_i(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for head in OPEN_HEADS {
    for (name, ows) in LIST_OWS {
      for continuation in CONTINUATIONS {
        for joins in [1_usize, 2] {
          let mut spaced = ows.to_vec();
          spaced.extend_from_slice(continuation);
          let mut lines: Vec<&[u8]> = Vec::with_capacity(3);
          lines.push(head);
          if joins == 2 {
            lines.push(UNCLOSING);
          }
          lines.push(&spaced);
          let spelling = format!("challenges-join-ows joins={joins} ows={name}");
          record(out, "I", &lines, &spelling, count)?;
        }
      }
    }
  }
  Ok(())
}

/// The challenges corpus J COMPLETES in front of the one it refuses, each
/// leaving RFC 9110 §11.3's `#auth-param` list in a different state.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
const PREFIXES: [(&str, &[u8]); 8] = [
  // Nothing at all: the refused element is the value's first, and no list has
  // opened anywhere.
  ("none", b""),
  // A list, open behind it: `Basic` took the `1*SP`, so the element behind the
  // comma may be one more parameter of it.
  ("list", b"Basic a=1"),
  // A `token68` body, which closes a list for the same reason a bare scheme
  // does: `auth-param = token BWS "=" BWS ( token / quoted-string )` needs a
  // value behind an `=`, and a `token68` puts nothing but more `=` there — so
  // the `#auth-param` alternative derives none of these bytes rather than
  // deriving them badly, and no reading has a list open behind the challenge.
  ("token68", b"Bearer abc"),
  // The padded spelling of the same run.
  ("token68-pad", b"Bearer dGVzdA=="),
  // A scheme with no body at all. `1*SP` is the body's only entrance, so no
  // reading of these bytes opens a list.
  ("bare", b"Bearer"),
  // A list, and then the bare scheme that closes it in every reading.
  ("list-bare", b"Basic a=1, Bearer"),
  // A list, and then the `token68` that does NOT close it.
  ("list-token68", b"Basic a=1, Bearer abc"),
  // A bare scheme, and then the list that opens after it.
  ("bare-list", b"Bearer, Basic a=1"),
];

/// The elements corpus J refuses at their `auth-scheme`, which is the refusal
/// whose recovery asks whether a list is open at all.
const SCHEME_FAULTS: [(&str, &[u8]); 3] = [
  // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` writes `1*SP`,
  // and RFC 9110 §5.6.3's HTAB is not one — so a HTAB reaching an element
  // rather than §5.6.1.2's comma opens no body.
  ("htab", b"Broken\tjunk"),
  // No leading `token` at all.
  ("no-token", b"=x"),
  // A byte behind the token the production admits nothing after.
  ("punct", b"Broken;junk"),
];

/// The tails corpus J puts behind that refusal, carrying the probe.
const TRAPS: [(&str, &[u8]); 6] = [
  // A value position whose RFC 9110 §5.6.4 quoted-string opens over the probe
  // and never closes.
  ("open", b"x=\"open, Digest realm=z"),
  // The same opener with §11.2's `BWS` in FRONT of the `=`, spelled with the SP
  // that `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` needs.
  //
  // `auth-param = token BWS "=" BWS ( token / quoted-string )`, and §11.2's
  // `BWS` is §5.6.3's `OWS` — so one SP there makes the SAME element an
  // `auth-scheme` with a body opening AT the `=`, which derives nothing because
  // `=` is no `tchar`. The walk reads a challenge at a trap by construction, so
  // this is the one place in this family where §11.6.1's two readings of the
  // element the recovery stops on part behind the cursor rather than at it.
  //
  // Written nowhere until corpus O crossed it by accident: every trap above and
  // below spells the `=` tight, which is the spelling that reaches
  // `read_challenge`'s scheme fault and has recovered from the element's own
  // first byte since al8n/wren#77.
  ("bws-open", b"x = \"open, Digest realm=z"),
  // And one that CLOSES behind it, so nothing at all is wrong with the value.
  ("closed-over", b"x=\"c, Digest realm=z, junk\""),
  // Closed in FRONT of the probe: every reading stands outside the string at
  // the comma, so the probe is a challenge whose boundary they agree on.
  ("closed-front", b"x=\"c\", Digest realm=z"),
  // No DQUOTE anywhere.
  ("token", b"x=c, Digest realm=z"),
  // The probe itself at the recovery cursor.
  ("probe", b"Digest realm=z"),
];

/// A value whose refused challenge is NOT its first: challenges that complete
/// stand in front of it, and what each of them leaves open is what decides
/// whether a DQUOTE behind the refusal is at a value position at all.
///
/// # The shape no other corpus spells
///
/// Every generator in front of this one refuses the value's FIRST challenge, so
/// the list state a recovery reads was written by the very challenge that
/// failed. Nothing measures what an EARLIER challenge left behind. RFC 9110
/// §11.6.1 is why that matters: an element this walk read as a scheme is one an
/// earlier challenge's list could have taken as a malformed parameter of its
/// own, so the list a refusal inherits is the value's rather than the
/// challenge's — and a bit that only ever turns on cannot say that an
/// intervening challenge closed it.
///
/// `Basic a=1, Bearer, Broken<HTAB>junk, x="open, Digest realm=z` is the value
/// that needs the close: `Bearer` has no `1*SP`, so no reading of it opens a
/// list, and every reading has `Basic`'s closed at the comma in front of it —
/// yet `x` was read as a possible parameter and the `Digest` behind it hidden.
///
/// The rows this family exists to keep are the ones where the list is still
/// open — `list`, `bare-list` and the reopening spellings — beside the ones
/// where every reading has it closed: `bare`, `token68`, `token68-pad`,
/// `list-bare` and `list-token68`. The two sets move in OPPOSITE directions,
/// which is what makes this family a pin in both: a walk that stopped closing
/// lists hides the `Digest` behind the first set, and one that closed them
/// unconditionally invents a `Digest` out of the second's trap.
///
/// Every completed challenge here stands in FRONT of the refusal, where the
/// argument for closing a list is whole: nothing has failed to derive yet, so
/// every reading of the value has that element as a challenge. Corpus L is the
/// same question asked BEHIND a fault, where it is not.
fn corpus_j(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for (prefix_name, prefix) in PREFIXES {
    for (fault_name, fault) in SCHEME_FAULTS {
      for (trap_name, trap) in TRAPS {
        let mut line = Vec::new();
        if !prefix.is_empty() {
          line.extend_from_slice(prefix);
          line.extend_from_slice(b", ");
        }
        line.extend_from_slice(fault);
        line.extend_from_slice(b", ");
        line.extend_from_slice(trap);
        let spelling =
          format!("challenges-prefix prefix={prefix_name} fault={fault_name} trap={trap_name}");
        record(out, "J", &[&line], &spelling, count)?;
      }
    }
  }
  Ok(())
}

/// Corpus H's shapes with the list's own `OWS` at the END of every line RFC
/// 9110 §5.2's join puts a comma behind.
///
/// # The axis corpora A..J hold fixed
///
/// How the field LINES are spelled. Every line every generator in front of this
/// one writes begins with an element's first byte and ends with an element's
/// last, so §5.6.1.2's
/// `#element => [ element ] *( OWS "," OWS [ element ] )` has whitespace on
/// neither side of §5.2's join comma. Corpus I unfixed the side BEHIND that
/// comma; this is the side in front of it, and the two together are all that
/// expansion admits there.
///
/// It is not the same question. Behind the comma the whitespace moves an
/// element, and both of the openers §11.6.1 reads move with it. In FRONT of the
/// comma the whitespace is inside the element §5.2's join carries — and whether
/// it is §5.6.1.2's `OWS` at all depends on the reading: where the head's
/// §5.6.4 quoted-string is still open at the line's end those bytes are
/// `qdtext` and are the value's, and where the reading that leaves the DQUOTE
/// shut ends the element at the join they are the list's. So the two readings
/// disagree about BYTES rather than about a position, which is a disagreement
/// nothing else here spells. The `OWS` trim an element's end is taken with,
/// `Recovery::floor`'s offsets, and the region a challenge holds on the line it
/// leaves are each measured over it.
fn corpus_k(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for head in OPEN_HEADS {
    for (name, ows) in LIST_OWS {
      for continuation in CONTINUATIONS {
        for joins in [1_usize, 2] {
          let mut trailed = head.to_vec();
          trailed.extend_from_slice(ows);
          let mut middle = UNCLOSING.to_vec();
          middle.extend_from_slice(ows);
          let mut lines: Vec<&[u8]> = Vec::with_capacity(3);
          lines.push(&trailed);
          if joins == 2 {
            lines.push(&middle);
          }
          lines.push(continuation);
          let spelling = format!("challenges-join-trailing-ows joins={joins} ows={name}");
          record(out, "K", &lines, &spelling, count)?;
        }
      }
    }
  }
  Ok(())
}

/// The challenges corpus L completes BEHIND the fault, each of which would
/// close a `#auth-param` list if it stood in front of one.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
const CLOSERS: [(&str, &[u8]); 4] = [
  // No body at all.
  ("bare", b"Bearer"),
  // RFC 9110 §11.2's `token68`, which is not a list.
  ("token68", b"Bearer abc"),
  // The padded spelling of the same run.
  ("token68-pad", b"Bearer dGVzdA=="),
  // The control: a body that IS a list, so this one opens one rather than
  // closing anything, and the trap behind it stands at a value position under
  // every reading.
  ("list", b"Newauth b=2"),
];

/// What stands in front of corpus L's fault, which is the list state that fault
/// leaves behind it.
const OPENERS: [(&str, &[u8]); 2] = [
  // Nothing: no list has opened anywhere in the value.
  ("none", b""),
  // A list, open where the fault is met.
  ("list", b"Basic a=1"),
];

/// Corpus M's openers: [`OPENERS`] and two more, which together are the axis
/// this family's own dimension crosses.
///
/// A recovery epoch already open when the family's refusal is met makes some of
/// these rows THREE epochs, and what matters about that earlier epoch is not
/// that it exists but **whether a `#auth-param` list was open where its fault
/// was met.** RFC 9110 §11.2 admits a value position only inside a list, so a
/// fault with no list has no DQUOTE any reading may choose behind it and can
/// change nothing about the elements it precedes; a fault met inside one may
/// still be about them. The last two openers are that pair, over the same
/// fault:
///
/// - `fault` — `Broken;junk` at the head of the value, where no list is open.
///   Its rows must answer exactly as the `none` rows do, and
///   `a_second_recovery_epoch_is_a_shape_this_generator_writes`
///   asserts that pairing directly.
/// - `list-fault` — the same fault behind `Basic a=1`, so a list IS open where
///   it is met. Its rows must hide the probe wherever the `list` rows do and
///   wherever a bound behind it would otherwise have been closed by a
///   completing challenge.
/// - `bound` — a bound of this RECIPIENT's, with no completed challenge behind
///   it, so the epoch standing in front of the family's own refusal carries a
///   list AND is closable. It must poison nothing either, and it is the row
///   that says the channel is a list that a FAULT left open rather than any
///   list at all.
///
/// Those four are the whole cross of the two facts an earlier epoch has, less
/// the one combination that cannot occur: a receiver bound is only ever met
/// inside a body §11.3's `1*SP` opened, so an epoch that is closable and
/// carries no list is not a state `Challenges::refuse` can build.
///
/// The pair is the shape a generator was thought unable to write: a
/// list-free grammar fault followed by an independent receiver-bound epoch.
/// It could, in fact, write one — the `fault` opener already existed — but
/// the oracle grading it carried the same defect the reader did, so the rows
/// answered `hider-excused` and pinned the wrong direction.
/// `oracle::resume`'s doc carries that.
const M_OPENERS: [(&str, &[u8]); 5] = [
  ("none", b""),
  ("list", b"Basic a=1"),
  ("fault", b"Broken;junk"),
  ("list-fault", b"Basic a=1, Broken;junk"),
  ("bound", b"Basic p1=1, p2=2, p3=3, p4=4, p5=5, p6=6, p7=7, p8=8, p9=9, p10=10, p11=11, p12=12, p13=13, p14=14, p15=15, p16=16, p17=17"),
];

/// A value whose completed challenge stands BEHIND the fault rather than in
/// front of it.
///
/// # The shape corpus J holds fixed
///
/// Corpus J varies what completes in FRONT of the refusal, and there the
/// argument for closing a list is whole: that challenge's own element derives,
/// RFC 9110 §11.6.1's other reading of it derives nothing, and every reading of
/// the value therefore has the list closed at the comma in front of it. Behind
/// a fault the argument is gone. Nothing derives there, so the readings include
/// one in which every element since the fault is garbage the open list still
/// holds — and under THAT reading the list is open behind this challenge too,
/// and the trap's DQUOTE stands at a value position §11.2 admits.
///
/// `Basic a=1, Broken;junk, Bearer, x="open, Digest realm=z` is the value, and
/// the `Digest` a walk handed back for it was read out of the middle of `x`'s
/// own. No generator in front of this one can write it: each of them ends at
/// the trap, so nothing completes between the refusal and the probe.
///
/// The `list` closer is the control that says this family is about the fault
/// and not about the second challenge: it opens a list of its own, so its rows
/// hide the probe whichever way the condition goes.
fn corpus_l(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for (opener_name, opener) in OPENERS {
    for (fault_name, fault) in SCHEME_FAULTS {
      for (closer_name, closer) in CLOSERS {
        for (trap_name, trap) in TRAPS {
          let mut line = Vec::new();
          if !opener.is_empty() {
            line.extend_from_slice(opener);
            line.extend_from_slice(b", ");
          }
          line.extend_from_slice(fault);
          line.extend_from_slice(b", ");
          line.extend_from_slice(closer);
          line.extend_from_slice(b", ");
          line.extend_from_slice(trap);
          let spelling = format!(
            "challenges-behind opener={opener_name} fault={fault_name} closer={closer_name} trap={trap_name}"
          );
          record(out, "L", &[&line], &spelling, count)?;
        }
      }
    }
  }
  Ok(())
}

/// What refuses corpus M's first challenge, and which regime the refusal leaves
/// behind it.
///
/// Each is written as the field-line fragments it takes, because one of them
/// takes seventeen.
const REFUSALS: [(&str, &[&[u8]]); 7] = [
  // ── RFC 9110's own faults. Each is an element the grammar derives no part
  //    of, so behind it no boundary is fixed and every DQUOTE at a §11.2 value
  //    position is a reading's to open or to leave shut.
  //
  // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` writes `1*SP`,
  // and §5.6.3's HTAB is not one.
  ("htab", &[b"Broken\tjunk"]),
  // No leading `token` at all.
  ("no-token", &[b"=x"]),
  // A byte behind the token the production admits nothing after.
  ("punct", &[b"Broken;junk"]),
  // And one inside the BODY rather than at the scheme: `;` is no §5.6.2
  // `tchar`, so the body is neither of §11.2's two alternatives. This is the
  // fault reported over an extent already complete, which used to reach a
  // caller without passing through the walk's own refusal.
  ("body", &[b"Basic ;"]),
  // ── and this recipient's three, none of them RFC 9110's. The grammar
  //    derives every byte of these, with every element where §5.6.1.2 puts it;
  //    what the refusal says is that this reader will not HOLD the challenge.
  //
  // One name past `MAX_PARAMS_PER_CREDENTIAL`.
  ("too-many-params", &[b"Basic p1=1, p2=2, p3=3, p4=4, p5=5, p6=6, p7=7, p8=8, p9=9, p10=10, p11=11, p12=12, p13=13, p14=14, p15=15, p16=16, p17=17"]),
  // The same name twice, which is §11.2's one-name-once MUST and not a comma
  // anywhere.
  ("duplicate", &[b"Basic a=1, a=1"]),
  // One region past `MAX_CHALLENGE_LINES`, with sixteen names and not
  // seventeen: the first parameter's value crosses §5.2's join, so it spends
  // two regions on one name and the line bound is what this row is about.
  (
    "too-many-lines",
    &[
      b"Basic a1=\"x",
      b"y\"",
      b"a2=2",
      b"a3=3",
      b"a4=4",
      b"a5=5",
      b"a6=6",
      b"a7=7",
      b"a8=8",
      b"a9=9",
      b"a10=10",
      b"a11=11",
      b"a12=12",
      b"a13=13",
      b"a14=14",
      b"a15=15",
      b"a16=16",
    ],
  ),
];

/// A value that opens TWO recovery epochs, with a challenge that completes
/// between them.
///
/// # The axis corpora A..L hold fixed
///
/// **How many recovery epochs the value opens, and what kind each is.** Every
/// family in front of this one varies bytes WITHIN one epoch — which prefix
/// stands in front of the fault, which fault it is, what completes behind it,
/// what the trap holds — and every one of them opens exactly one. The count has
/// been fixed at one since the first family, so no generator here could write a
/// value in which a refusal's ambiguity has to end before a later refusal's
/// question can be answered.
///
/// That is a shape that kept hiding defects no corpus could spell.
/// `Basic <seventeen parameters>, Bearer abc, x="open, Digest
/// realm=z` is the value: `MAX_PARAMS_PER_CREDENTIAL` refuses the
/// `Basic`, recovery reaches `Bearer abc`, RFC 9110 §11.2's `token68` completes
/// it — and the list the refusal left open has to END there, because the
/// grammar derives every byte in front of the cursor and no `auth-param`
/// derives `Bearer abc`. Where it does not, the scheme refusal at `x=` reads
/// that element's DQUOTE as a parameter value's opener and the `Digest` behind
/// it is never shown.
///
/// # What it crosses
///
/// - **What opens the first epoch**, which is this family's own dimension:
///   four faults of RFC 9110's grammar and three bounds of this recipient's.
///   The two regimes differ in exactly one thing — whether a derivation of the
///   value still reaches the cursor — and every row is the same shape either
///   side of it.
/// - **What stands in front of it**, [`M_OPENERS`]: no list, a list, and the
///   same grammar fault twice — once where no list is open and once where one
///   is. That pair is the axis this family adds: an earlier epoch reaches
///   past its own challenge only through a list it stood in, so the first of
///   them must change no answer at all and the second must change the same ones
///   `list` does.
/// - **What stands between the two epochs**: [`CLOSERS`], the empty separator
///   that puts the second refusal straight behind the first, and a fault of the
///   grammar. [`CLOSERS`] are the challenge that has to stand between two
///   epochs — one that parses, with a bare body or §11.2's
///   `token68` — and `list` is their control, since that separator opens a list
///   of its own and its rows hide the probe whichever way the condition goes.
///
///   The `fault` separator is the other direction and the one that says what an
///   epoch may NOT be closed by: the walk resumes recovery on an element no
///   `auth-param` begins at, which is not the same as an element a challenge
///   derives at, and this separator is the element it resumes on AND the next
///   thing it refuses.
/// - **The trap**, [`TRAPS`], which is what opens the SECOND epoch — and the
///   `probe` trap, which opens none, so the family spans one epoch and two.
fn corpus_m(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for (opener_name, opener) in M_OPENERS {
    for (refusal_name, refusal) in REFUSALS {
      for (separator_name, separator) in iter::once(("none", &b""[..]))
        .chain(CLOSERS)
        .chain(iter::once(("fault", &b"Broken;junk"[..])))
      {
        for (trap_name, trap) in TRAPS {
          let mut lines: Vec<Vec<u8>> = Vec::with_capacity(refusal.len());
          for (index, fragment) in refusal.iter().enumerate() {
            let mut line = Vec::new();
            if index == 0 && !opener.is_empty() {
              line.extend_from_slice(opener);
              line.extend_from_slice(b", ");
            }
            line.extend_from_slice(fragment);
            lines.push(line);
          }
          // The separator and the trap stand behind the refusal, on its last
          // line: RFC 9110 §5.2's join would put a comma of its own between
          // them, and what this family is about is not where the field lines
          // are cut.
          let tail = lines.last_mut().expect("a refusal takes at least one line");
          if !separator.is_empty() {
            tail.extend_from_slice(b", ");
            tail.extend_from_slice(separator);
          }
          tail.extend_from_slice(b", ");
          tail.extend_from_slice(trap);
          let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
          let spelling = format!(
            "challenges-two-epochs opener={opener_name} refusal={refusal_name} separator={separator_name} trap={trap_name}"
          );
          record(out, "M", &refs, &spelling, count)?;
        }
      }
    }
  }
  Ok(())
}

/// What corpus N puts INSIDE the recovered span: the elements a recovery
/// absorbs between the refusal that opened it and the challenge that closes it.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Every one of these is an element `opens_a_challenge` answers `false` for, so
/// the walk crosses it rather than stopping on it, and RFC 9110 §11.2 is the
/// only production that has anything to say about it. The two halves are the
/// two directions this family is a pin in:
///
/// - **§11.2 derives it**, so the span's claim survives and the epoch still
///   closes. `bws` is RFC 9110 §5.6.3's `BWS` on both sides of the `=`, which
///   the production admits and a check written from the printed examples would
///   not.
///
///   `duplicate` and `over-bound` are the pair that says the span rule asks
///   §11.2's GRAMMAR and not the walk's own bookkeeping. `duplicate` names `a`,
///   `a1` and `p1` — one name from each of [`REFUSALS`]'s three bounds, so it
///   is a genuine repeat behind every one of them rather than behind one in
///   seven; `over-bound` is nineteen parameters, which is
///   `MAX_PARAMS_PER_CREDENTIAL` exceeded inside a single span. Both are
///   refusals THIS reader makes and neither is a fault of RFC 9110's, so both
///   must SUSTAIN the claim.
///
///   Neither can be reddened by any mutation of the reader as it stands, and
///   they are not counted as coverage: `auth_param` cannot see a repeated name
///   or a slot count, so what these rows pin is the SHAPE of the rule. They red
///   against a design that routed an absorbed element through the walk's own
///   `BodyCheck` — the obvious wrong implementation of the same sentence — and
///   `tests::the_two_rows_that_pin_the_span_rule_s_shape_can_fail` is the
///   injection that measures it rather than asserting it.
/// - **§11.2 derives nothing at it**, so the claim is false from that element
///   on and no challenge behind it may close the epoch. `( token /
///   quoted-string )` is one alternative taken WHOLE, which is what makes the
///   two `trailing` spellings faults rather than parameters with something
///   after them.
///
/// `open-quoted` is neither: the string it opens is still open at the comma, so
/// some reading holds that comma as the value's own data, the walk declines the
/// boundary and never reaches the span rule at all. Its rows must answer
/// exactly as they did before this family existed.
///
/// The last two are the same two elements in both orders, because the claim is
/// about EVERY element of the span and a rule that asked only the first would
/// be green over one of them.
const SPANS: [(&str, &[u8]); 15] = [
  // Nothing absorbed at all: corpus M's own shape, and the control every other
  // row here is read against.
  ("none", b""),
  // ── the ones RFC 9110 §11.2 derives.
  ("param", b"y=1"),
  ("quoted", b"y=\"q\""),
  ("bws", b"y\t=\t1"),
  // The same `BWS` spelled with §5.6.3's other byte. The row above writes HTAB
  // on both sides, which is the spelling
  // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` can never
  // take; this one writes the SP that it can, so an absorbed element carries
  // the whitespace that makes the other production a reading of the same bytes.
  // What a span element is asked is `auth_param` and nothing else — the walk
  // crosses these rather than reading a challenge at them — so the two are
  // expected to answer alike, and this row is what says so rather than assumes
  // it.
  ("bws-sp", b"y = 1"),
  ("duplicate", b"a=1, a1=1, p1=1"),
  ("over-bound", b"q1=1, q2=1, q3=1, q4=1, q5=1, q6=1, q7=1, q8=1, q9=1, q10=1, q11=1, q12=1, q13=1, q14=1, q15=1, q16=1, q17=1, q18=1, q19=1"),
  ("two-params", b"y=1, z=2"),
  // RFC 9110 §5.6.1.2 hangs `OWS` on BOTH sides of its comma, so this trailing
  // space belongs to the list and not to the element. An absorbed element read
  // with it still on is a `token` with a space behind it, which §11.2 derives
  // nothing at — so this row must sustain the claim and not refute it.
  ("ows-tail", b"y=1 "),
  // ── and the ones it does not.
  //
  // The production names a value and the `=` is not one.
  ("no-value", b"y="),
  // One `token` is the whole of a value.
  ("trailing-token", b"y=1 z"),
  // And one `quoted-string` is, so bytes behind its close derive nothing.
  ("trailing-quoted", b"y=\"q\"z"),
  // ── the element the walk never gets past.
  ("open-quoted", b"y=\"q"),
  // ── and the two orders.
  ("param-then-fault", b"y=1, z="),
  ("fault-then-param", b"y=, z=1"),
];

/// Whether an earlier recovery epoch stands in front of corpus N's own refusal.
///
/// `bound` is [`M_OPENERS`]'s: a refusal of this recipient's with a
/// `#auth-param` list open where it was met, so the epoch in front of the
/// family's refusal carries a list AND is closable. It is here because the
/// span's claim is inherited as well as sustained — a new epoch opened behind
/// one whose ambiguity can still reach it is underivable whatever its own span
/// holds — and a rule written for the sustaining half alone would be green over
/// these rows for the wrong reason.
const N_OPENERS: [(&str, &[u8]); 2] = [("none", b""), ("bound", M_OPENERS[4].1)];

/// A value whose recovery ABSORBS elements, and the axis that is about what
/// those elements are.
///
/// # The axis corpora A..M hold fixed
///
/// **What the recovered span CONTAINS.** Every family in front of this one
/// varies how the epoch OPENED — which prefix stands in front of the fault,
/// which fault it is, what completes behind it, what the trap holds — and each
/// puts at most one element between the refusal and the trap, chosen from a set
/// whose members either open a challenge or are the trap itself. Nothing
/// measures the elements a recovery crosses WITHOUT deriving them.
///
/// That cost is real: `Basic a=1, a=2, y=,
/// Bearer, x="open, Digest realm=evil, junk"` is a
/// four-stage sequence: a receiver-bound epoch, then a malformed
/// parameter-shaped element the recovery absorbs, then a challenge that
/// completes and closes the epoch, then the quoted probe. `y=` is an element
/// RFC 9110 §11.2 derives nothing at, so the grammar is a reason this value
/// stopped deriving and the epoch's claim — that this recipient's own limit is
/// the ONLY reason — was false from `y=` onward. The reader skipped it,
/// `Bearer` closed the epoch anyway, and the scheme fault at `x=` then stood in
/// front of no open list and crossed the comma inside `x`'s own value.
///
/// A model-derived table cannot enumerate a sequence: corpus M's dimensions are
/// the FACTS an epoch has when it opens, and no cross of them writes a second
/// element into the middle of a span. So this family's own dimension is the
/// span's contents, and [`SPANS`] is it.
///
/// # What it crosses
///
/// - [`N_OPENERS`] — whether an epoch already stands in front of the refusal,
///   which is the inheriting half of the same claim.
/// - [`REFUSALS`] — what opens this family's epoch. The three bounds are the
///   rows where the claim exists at all and the four grammar faults are the
///   control: those epochs are underivable from their first byte, so no span
///   element can change them and every one of their rows must answer as it did
///   before.
/// - [`SPANS`] — what the recovery absorbs, which is this family's own axis.
/// - [`CLOSERS`] — the challenge that closes the epoch, which is the stage the
///   span's claim is spent at. `list` is their control: it opens a list of its
///   own, so its rows hide the probe whichever way the claim goes.
/// - [`TRAPS`] — the quoted probe, which is what the certified boundary is
///   read over.
fn corpus_n(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for (opener_name, opener) in N_OPENERS {
    for (refusal_name, refusal) in REFUSALS {
      for (span_name, span) in SPANS {
        for (closer_name, closer) in CLOSERS {
          for (trap_name, trap) in TRAPS {
            let mut lines: Vec<Vec<u8>> = Vec::with_capacity(refusal.len());
            for (index, fragment) in refusal.iter().enumerate() {
              let mut line = Vec::new();
              if index == 0 && !opener.is_empty() {
                line.extend_from_slice(opener);
                line.extend_from_slice(b", ");
              }
              line.extend_from_slice(fragment);
              lines.push(line);
            }
            // The span, the closer and the trap all stand behind the refusal on
            // its last line: RFC 9110 §5.2's join would put a comma of its own
            // between them, and what this family is about is not where the
            // field lines are cut.
            let tail = lines.last_mut().expect("a refusal takes at least one line");
            if !span.is_empty() {
              tail.extend_from_slice(b", ");
              tail.extend_from_slice(span);
            }
            tail.extend_from_slice(b", ");
            tail.extend_from_slice(closer);
            tail.extend_from_slice(b", ");
            tail.extend_from_slice(trap);
            let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
            let spelling = format!(
              "challenges-span opener={opener_name} refusal={refusal_name} span={span_name} closer={closer_name} trap={trap_name}"
            );
            record(out, "N", &refs, &spelling, count)?;
          }
        }
      }
    }
  }
  corpus_n_at_the_cursor(out, count)?;
  corpus_n_across_a_join(out, count)
}

/// The refusals corpus N crosses RFC 9110 §5.2's join with: each is met over an
/// element whose §5.6.4 quoted-string spans one, so the recovery cursor lands
/// at the HEAD of the continuation line and the run standing there is that
/// element's suffix rather than an element of its own.
///
/// Two receiver bounds and one grammar fault, over the same shape. The bounds
/// are the rows where the span's claim exists at all — §11.2 derives
/// `a="x` + the join + `y"` whole, and a repeated name and a seventeenth
/// parameter move no comma — and the fault is the control, whose epoch is
/// underivable from its first byte whatever the span holds.
const JOINED_REFUSALS: [(&str, [&[u8]; 2]); 3] = [
  // §11.2's one-name-once MUST, over a value the join carried here.
  ("duplicate", [b"Basic a=1, a=\"x", b"y\""]),
  // `MAX_PARAMS_PER_CREDENTIAL` met at the seventeenth name, which is the one
  // that spans.
  (
    "over-bound",
    [
      b"Basic p1=1, p2=2, p3=3, p4=4, p5=5, p6=6, p7=7, p8=8, p9=9, p10=10, p11=11, p12=12, p13=13, p14=14, p15=15, p16=16, p17=\"x",
      b"y\"",
    ],
  ),
  // The control: `( token / quoted-string )` is one alternative taken WHOLE, so
  // a `z` behind the close derives nothing and the fault is the grammar's.
  ("malformed", [b"Basic a=\"x", b"y\"z"]),
];

/// The rows where RFC 9110 §5.2's join stands between the refused element's
/// DQUOTE and its close, so the span begins on a line the element did not.
///
/// # The stage the two families above cannot vary
///
/// Where a refusal leaves the cursor RELATIVE TO THE ELEMENT it is over. Every
/// row of `corpus_n` refuses an element that began and ended on one field line,
/// so the cursor lands on that element's own first byte; `corpus_n_at_the_cursor`
/// moves the cursor to a line head, but onto an element the walk never read.
/// Neither writes the third position: a cursor at a line head with the refused
/// element's own bytes BEHIND it.
///
/// `Basic a=1, a="x` and `y", Bearer, x="open, Digest realm=z` are two field
/// lines §5.2 joins into one value: `a`'s value is the one string `x,y`, §11.2
/// derives the element whole, and the repeated name that refused the challenge
/// is a bound of this recipient's. So the span is derivable, `Bearer` closes
/// the epoch, and the `Digest` is a challenge whose boundary every reading
/// agrees on. The reader sliced the continuation line at the cursor instead,
/// read the suffix `y"` as a whole `auth-param`, found that §11.2 derives
/// nothing at it, and refuted a claim the grammar never refuted — hiding the
/// `Digest` behind `AuthError::ChallengeBoundaryUnknown`.
///
/// Every generator in front of this one was green over that, and this is the
/// dimension none of them has.
fn corpus_n_across_a_join(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for (opener_name, opener) in N_OPENERS {
    for (refusal_name, fragments) in JOINED_REFUSALS {
      for (span_name, span) in SPANS {
        for (closer_name, closer) in CLOSERS {
          for (trap_name, trap) in TRAPS {
            let mut head = Vec::new();
            if !opener.is_empty() {
              head.extend_from_slice(opener);
              head.extend_from_slice(b", ");
            }
            head.extend_from_slice(fragments[0]);
            // The span, the closer and the trap stand behind the CLOSE of the
            // value the join carried here — which is what makes the first
            // element of the span begin at an offset the element it belongs to
            // does not.
            let mut tail = fragments[1].to_vec();
            if !span.is_empty() {
              tail.extend_from_slice(b", ");
              tail.extend_from_slice(span);
            }
            tail.extend_from_slice(b", ");
            tail.extend_from_slice(closer);
            tail.extend_from_slice(b", ");
            tail.extend_from_slice(trap);
            let spelling = format!(
              "challenges-span opener={opener_name} refusal=join-{refusal_name} span={span_name} closer={closer_name} trap={trap_name}"
            );
            record(out, "N", &[&head, &tail], &spelling, count)?;
          }
        }
      }
    }
  }
  Ok(())
}

/// The rows where the span begins AT the offset the refusal left the cursor on,
/// rather than one element behind it.
///
/// # The stage the family above cannot vary
///
/// Where a refusal leaves the cursor. Every row above appends its span behind
/// the last element of the refused challenge, so the element the walk stands on
/// when recovery starts is always one the challenge already DERIVED — and a
/// span rule that skipped that element was green over all of them.
///
/// `MAX_CHALLENGE_LINES` is the one refusal that leaves it somewhere else. RFC
/// 9110 §5.2 joins the field lines into one value, the bound is met when the
/// challenge needs a line it may not hold, and it is met with the cursor at the
/// HEAD of that line — on an element the walk has not read. So the first
/// element of the span is the first element of that line, and `Basic a1=1`
/// through `a16=16` on sixteen lines, with a seventeenth opening at the element
/// `y=` in front of `Bearer` and a trap whose string never closes, is the
/// value: `y=` is where the cursor stands, RFC 9110 §11.2 derives nothing at
/// it, and the `Digest` behind that trap was read out of its own data while a
/// rule with a first-element exception looked past it.
///
/// Sixteen fragments and not the seventeen [`REFUSALS`] writes, because the
/// span itself is what the seventeenth line has to begin with.
fn corpus_n_at_the_cursor(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  let (_, fragments) = REFUSALS[6];
  for (opener_name, opener) in N_OPENERS {
    for (span_name, span) in SPANS {
      // `none` is not a position. With nothing at the head of that line the
      // closer stands there instead, `opens_a_challenge` answers `true` for it,
      // and RFC 9110 §11.3's body ends in front of it — so the challenge
      // COMPLETES within the bound and this family has no refusal to be about.
      if span.is_empty() {
        continue;
      }
      for (closer_name, closer) in CLOSERS {
        for (trap_name, trap) in TRAPS {
          let mut lines: Vec<Vec<u8>> = Vec::with_capacity(MAX_CHALLENGE_LINES + 1);
          for (index, fragment) in fragments.iter().take(MAX_CHALLENGE_LINES).enumerate() {
            let mut line = Vec::new();
            if index == 0 && !opener.is_empty() {
              line.extend_from_slice(opener);
              line.extend_from_slice(b", ");
            }
            line.extend_from_slice(fragment);
            lines.push(line);
          }
          // The line the challenge may not hold, and the span is what it opens
          // with.
          let mut tail = Vec::new();
          tail.extend_from_slice(span);
          tail.extend_from_slice(b", ");
          tail.extend_from_slice(closer);
          tail.extend_from_slice(b", ");
          tail.extend_from_slice(trap);
          lines.push(tail);
          let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
          let spelling = format!(
            "challenges-span opener={opener_name} refusal=line-bound-head span={span_name} closer={closer_name} trap={trap_name}"
          );
          record(out, "N", &refs, &spelling, count)?;
        }
      }
    }
  }
  Ok(())
}

/// What corpus O brings its recovery to RFC 9110 §5.2's join with, and the
/// list state each head leaves where that join is crossed.
///
/// Two ways a recovery reaches a join, and this crate already knows both:
/// an element whose §5.6.4 quoted-string is still open where the field line
/// ends, so the refusal is met with the cursor at the head of the continuation;
/// and an element that ENDS at the line's end, so the recovery crosses the join
/// looking for the next one. The list state is the axis crossed with them,
/// because RFC 9110 §11.2 admits a value position only inside a `#auth-param`
/// list — so a head with none open leaves the continuation's OWN body list as
/// the only reading under which a DQUOTE behind the empty run stands at a value
/// position at all.
const O_HEADS: [(&str, &[u8]); 4] = [
  // The string spans the join. `Basic`'s `1*SP` has a list open, and the
  // reading that carries `a`'s value across the join covers everything behind
  // it — corpus H's head, and the one whose refusal is met AT the join rather
  // than in front of it.
  ("open", b"Basic a=\"x"),
  // A fault of RFC 9110's grammar at the line's end, with NO list open anywhere
  // in the value: `Broken;junk` is refused at its `auth-scheme`, and §11.3's
  // `1*SP` — the body's only entrance — was never taken.
  ("fault", b"Broken;junk"),
  // The same fault with a list open where it is met, which is the pair
  // [`M_OPENERS`] holds apart: an earlier epoch reaches past its own challenge
  // only through a list it stood in.
  ("list-fault", b"Basic a=1, Broken;junk"),
  // A bound of THIS recipient's, so the epoch standing in front of the
  // continuation carries a list AND is closable.
  ("bound", M_OPENERS[4].1),
];

/// The line corpus O repeats between its head and its continuation, once per
/// join past the first.
///
/// It carries no DQUOTE, so a head whose §5.6.4 quoted-string is open where its
/// line ends still has it open where this one does — [`UNCLOSING`]'s property,
/// which is what keeps the `open` head's element spanning every join. And RFC
/// 9110 §11.2 derives it whole, so a recovery crossing it absorbs an element
/// that SUSTAINS the epoch's claim rather than one that refutes it: the joins
/// this family counts are joins the recovery is still running at.
const O_MIDDLE: &[u8] = b"y=1";

/// The two spellings of RFC 9110 §11.3's body entrance corpus O writes, and the
/// list the empty run behind each belongs to.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
const O_SCHEMES: [(&str, &[u8]); 2] = [
  // `1*SP` taken, so the run behind it is the challenge's own `#auth-param`
  // list and its empty elements are that list's. This is the reading §11.6.1
  // admits at a join, and the one this family is about.
  ("sp", b"Newauth "),
  // The control. RFC 9110 §5.6.3's HTAB is `OWS` and is not `1*SP`, so no body
  // opens here: the scheme is a whole challenge that took no parameters, the
  // run behind it is the OUTER `#challenge` list's, and a DQUOTE past it stands
  // at no value position any reading of these bytes admits.
  ("htab", b"Newauth\t"),
];

/// What stands behind corpus O's leading empty elements: the first element of
/// the continuation challenge's body that is not empty, carrying the probe.
const O_BODIES: [(&str, &[u8]); 7] = [
  // A RFC 9110 §5.6.4 quoted-string that opens in front of the probe and never
  // closes, so the probe is that value's data under the reading the empty run
  // leads to.
  ("open", b"realm=\"c, Digest realm=z"),
  // The same, CLOSED behind the probe — nothing at all wrong with the value, so
  // a reader right about the unterminated one by treating an unterminated run
  // as special is still wrong here.
  ("closed-over", b"realm=\"c, Digest realm=z, junk\""),
  // Closed in FRONT of the probe, so every reading stands outside the string at
  // the comma and the probe is a challenge whose boundary they agree on.
  ("closed-front", b"realm=\"c\", Digest realm=z"),
  // No DQUOTE anywhere.
  ("token", b"realm=c, Digest realm=z"),
  // §11.2's `BWS` around the `=`, which moves the DQUOTE off the offset a check
  // written from the printed examples would look at.
  ("bws", b"realm = \"c, Digest realm=z"),
  // An element that admits a value position nowhere, so the run behind the
  // empties opens no string under any reading.
  ("no-value", b"p, Digest realm=z"),
  // The probe itself as the body's first non-empty element.
  ("probe", b"Digest realm=z"),
];

/// Where the `cut`-th comma of a run stands in `value`, counting from one.
fn nth_comma(value: &[u8], cut: usize) -> Option<usize> {
  value
    .iter()
    .enumerate()
    .filter(|&(_, &byte)| byte == b',')
    .map(|(at, _)| at)
    .nth(cut.checked_sub(1)?)
}

/// A continuation challenge whose body opens with EMPTY elements, and RFC 9110
/// §5.2's join falling anywhere in that run.
///
/// # The axis corpora A..N hold fixed
///
/// **How far into the continuation challenge its first quoted parameter
/// stands.** RFC 9110 §5.6.1.2's recipient expansion is what admits the
/// distance:
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `[ element ]` is optional at every position, so a challenge's `#auth-param`
/// body may open with any number of empty elements before the parameter that
/// carries a quoted value. Every continuation corpora H, I and K write puts
/// that parameter FIRST — `Newauth realm="c, Digest realm=z` — so the DQUOTE
/// §11.6.1's challenge reading admits stands inside the very run §5.2's join
/// left the cursor on, at `auth-scheme 1*SP` and a `token BWS "="` behind it.
/// One comma in front of it moves the DQUOTE out of that run entirely: the run
/// at the join ends at the first comma read raw, no reading opens a string in
/// it, the boundary is CERTIFIED, and everything about the parameter is decided
/// one or more elements later — by whatever the walk still carries about the
/// challenge that opened back at the join.
///
/// That is the strongest residual-pressure case of this shape.
///
/// # What it crosses
///
/// - **How many empty elements stand in front of the parameter**, 0..=3, which
///   is this family's own dimension. 0 is corpus H's own continuation and the
///   control every other row is read against.
/// - **How that run is spelled**, [`LIST_OWS`]'s question asked inside a body:
///   `tight` writes bare commas and `ows` hangs §5.6.3 whitespace behind each
///   of them, which §5.6.1.2 admits on both sides. At 0 empties there is no
///   comma for the spacing to be about, so the `ows` spelling is skipped rather
///   than recorded as a second name for one input.
/// - **Where §5.2's join falls**, `cut`: `0` puts the whole challenge on the
///   continuation line with the join comma in front of its scheme, and `i` puts
///   the join AT the `i`-th comma of the run — so the scheme and `i-1` of the
///   empties stand on the line in front of it. Every cut of one cell spells the
///   SAME value, because a join contributes exactly the comma it replaces, and
///   `leading_empty_elements_before_a_quoted_parameter_are_a_shape_this_generator_writes` asserts
///   that identity and the agreement of the answers over it. With the `ows`
///   spacing the cuts also walk corpus I's and corpus K's shapes — whitespace
///   behind the join comma, and whitespace in front of it — INSIDE a challenge
///   body, which is a position neither of those families can reach.
/// - **How many joins the recovery has already crossed**, 1..=3. Corpora H, I
///   and K stop at two; multiple earlier joins are what makes
///   the case worst, and [`O_MIDDLE`] is the line that adds one without closing
///   a string or refuting an epoch's claim.
/// - **What brought the recovery to the join**, [`O_HEADS`], which is also the
///   list state the continuation is read in.
/// - **The scheme**, [`O_SCHEMES`]: `1*SP` taken, so the empty run is the
///   challenge's own body list; and the HTAB control, where it is the outer
///   list's and no body opened at all.
/// - **What stands behind the run**, [`O_BODIES`].
fn corpus_o(out: &mut impl Write, count: &mut usize) -> std::io::Result<()> {
  for (head_name, head) in O_HEADS {
    for joins in 1_usize..=3 {
      for (scheme_name, scheme) in O_SCHEMES {
        for (body_name, body) in O_BODIES {
          for empties in 0_usize..=3 {
            for (spacing_name, ows) in [("tight", false), ("ows", true)] {
              // Nothing to space. The two spellings are one byte string with no
              // comma in it, and recording it twice would count one input as
              // two.
              if empties == 0 && ows {
                continue;
              }
              // RFC 9110 §5.6.1.2 hangs `OWS` on both sides of its comma, so
              // an empty element written with one is the same element.
              let separator: &[u8] = if ows { b", " } else { b"," };
              let mut continuation = scheme.to_vec();
              for _ in 0..empties {
                continuation.extend_from_slice(separator);
              }
              continuation.extend_from_slice(body);
              for cut in 0..=empties {
                let mut lines: Vec<Vec<u8>> = Vec::with_capacity(joins.saturating_add(2));
                lines.push(head.to_vec());
                for _ in 1..joins {
                  lines.push(O_MIDDLE.to_vec());
                }
                match nth_comma(&continuation, cut) {
                  // RFC 9110 §5.2 puts a comma between two field lines, so
                  // cutting the continuation AT one of its own commas and
                  // dropping that byte spells the same value over one more
                  // line.
                  Some(at) => {
                    lines.push(continuation.get(..at).unwrap_or_default().to_vec());
                    lines.push(
                      continuation
                        .get(at.saturating_add(1)..)
                        .unwrap_or_default()
                        .to_vec(),
                    );
                  }
                  None => lines.push(continuation.clone()),
                }
                let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
                let spelling = format!(
                  "challenges-empty-run head={head_name} joins={joins} scheme={scheme_name} \
                   empties={empties} spacing={spacing_name} cut={cut} body={body_name}"
                );
                record(out, "O", &refs, &spelling, count)?;
              }
            }
          }
        }
      }
    }
  }
  Ok(())
}

// ──────────────────────────────── one record ─────────────────────────────────

/// Writes the record for one case, choosing the entry point from `spelling`.
fn record(
  out: &mut impl Write,
  corpus: &str,
  lines: &[&[u8]],
  spelling: &str,
  count: &mut usize,
) -> std::io::Result<()> {
  *count = count.saturating_add(1);
  let case = lines
    .iter()
    .map(|line| escape(line))
    .collect::<Vec<_>>()
    .join("|");
  let (answer, graded) = match spelling {
    "credentials-tail" | "credentials-bare" => (
      render(credentials(lines.first().copied().unwrap_or_default()).map(|read| vec![Ok(read)])),
      false,
    ),
    "auth-info" | "auth-info-join" => {
      let mut out = String::new();
      for read in auth_info(lines.iter().copied()) {
        if !out.is_empty() {
          out.push(' ');
        }
        match read {
          Ok(param) => {
            out.push_str("Ok[");
            out.push_str(&render_param(&param));
            out.push(']');
          }
          Err(fault) => out.push_str(&format!("Err({fault:?})")),
        }
      }
      (out, false)
    }
    _ => (
      render(Ok(challenges(lines.iter().copied()).collect::<Vec<_>>())),
      true,
    ),
  };
  let axis = if graded {
    axis(lines)
  } else {
    String::from("-")
  };
  writeln!(out, "{corpus}\t{case}\t{spelling}\t{axis}\t{answer}")
}

/// Renders a sequence of `Result<Credential, AuthError>`, or the one fault a
/// single-credential field answers with instead of a sequence.
fn render(reads: Result<Vec<Result<Credential<'_>, AuthError>>, AuthError>) -> String {
  let reads = match reads {
    Ok(reads) => reads,
    Err(fault) => return format!("Err({fault:?})"),
  };
  let mut out = String::new();
  for read in reads {
    if !out.is_empty() {
      out.push(' ');
    }
    match read {
      Ok(credential) => {
        out.push_str("Ok[");
        out.push_str(&escape(credential.scheme()));
        if let Some(token68) = credential.token68() {
          out.push('~');
          out.push_str(&escape(token68));
        }
        for param in credential.params() {
          out.push(';');
          out.push_str(&render_param(&param));
        }
        out.push(']');
      }
      Err(fault) => out.push_str(&format!("Err({fault:?})")),
    }
  }
  out
}

/// Renders one parameter: its name, and what RFC 9110 §5.2's join left of its
/// value.
fn render_param(param: &http_semantics::auth::AuthParam<'_>) -> String {
  let mut out = escape(param.name());
  out.push('=');
  match param.value() {
    // The value crossed a field-line join, so it is not one slice to hand back.
    Err(_) => out.push_str("!spans"),
    Ok(ParamValue::Token(token)) => {
      out.push_str("t:");
      out.push_str(&escape(token));
    }
    Ok(ParamValue::Quoted(quoted)) => {
      out.push_str("q:");
      out.push_str(&escape(quoted));
    }
    Ok(ParamValue::None) => out.push_str("none"),
    Ok(_) => out.push('?'),
  }
  out
}

// ────────────────────────────────── the axis ─────────────────────────────────

/// How this case grades on the one axis this module is graded on: **a
/// malformed challenge must not hide a well-formed one behind
/// it**, because RFC 9110 §11.4's user agent answers by "selecting the
/// challenge with what it considers to be the most secure auth-scheme that it
/// understands" and cannot select one it was never shown.
///
/// - `no-probe` — no whole challenge derives from the probe's offset, so there
///   is nothing there for any reader to show or hide.
/// - `yields` — the reader showed it, and some derivation of the WHOLE value
///   reads it as a challenge. What the sender wrote is what the caller got.
/// - `over-yield` — the reader showed it, some reading puts it inside a
///   quoted-string, and none reads it as a challenge. The caller was handed a
///   challenge built out of bytes a sender wrote as that value's data. **This
///   is the other number this module is driven to zero on**, and al8n/wren#77
///   is what a non-zero one was.
// gate-exempt: Basic =aaaaa, Digest realm=z — one malformed field value this
// corpus feeds in, production-shaped only because a scheme name happens to be
// followed by an `=`; not a production of any RFC.
/// - `yields-underivable` — the reader showed it and NO derivation reads it
///   either way, because nothing derives the bytes in front of it. This is
///   RECOVERY, and the bulk of it is the axis working as intended: `Basic
///   =aaaaa, Digest realm=z` derives nothing at all, so no derivation reaches
///   the probe, and showing it anyway is the whole point of not letting a
///   malformed challenge hide a well-formed one. What it says about the
///   caller's answer is only that no reading of the value licenses it — never
///   that a sender wrote those bytes as data, which is `over-yield`.
///
///   A subset of it USED to be claimed as stronger than that: where the value
///   carries a byte RFC 9110 §5.5 admits nowhere in a field value, there was
///   said to be no reading of those bytes for the challenge to be the data of
///   either. That is a claim about what DERIVES, and it is not the question
///   this axis asks. A DQUOTE at §11.2's value position opens a run whatever
///   stands behind it, a forbidden byte means that run reaches no close, and
///   the sender wrote every byte behind the DQUOTE — the probe included — as
///   its data. `oracle::open_at` carries the correction and what collapsing it
///   cost: 137 records of this corpus graded here while the reader handed a
///   caller a `Digest realm=z` cut out of a realm, and both derivations of
///   `excused` agreed, because that judgement was the one line they share.
/// - `hider-excused` — the reader did not show it, and some reading puts it
///   inside a quoted-string. Not a defect: under that reading there is no
///   challenge there to show.
/// - `hider-unresolved` — the reader did not show it, no reading puts it inside
///   a quoted-string, the reader SAID SO — its answer carries
///   `ChallengeBoundaryUnknown`, which is the walk telling the caller that the
///   rest of the value is unread — **and some RFC 9110 §5.6.1.2 comma in front
///   of the probe is one the readings disagree about**, so the walk had a
///   boundary it could not place. A challenge nobody was shown and nobody was
///   told about is the harm this axis exists against, and this is the other
///   thing: §11.4's user agent knows it has not seen the whole list and can act
///   on that. It is a cost and not a defect, and `tests` pins its count with the
///   three shapes it is made of.
/// - `hider-conforming` — the same notice, and some derivation of the WHOLE
///   value reads the probe as a challenge. The grammar has no complaint
///   anywhere in these bytes, so what refused them is a bound of this
///   recipient's, and the only such refusal that ends the walk is the line
///   bound met with a value still open across §5.2's join. The close that would
///   settle the boundary is on a line `MAX_CHALLENGE_LINES` forbids this reader
///   to hold, and that constant records the trade where it is defined. A cost,
///   like `hider-unresolved`, and a different one.
/// - `hider-declined` — the same notice, nothing derives, and no comma in front
///   of the probe is one the readings disagree about. Every element boundary
///   between the head of the value and the probe is one every reading places in
///   the same byte, so there was nothing for the walk to decline: it stopped at
///   a boundary the grammar had already made for it, and told the caller about
///   an ambiguity that is not there. **This is the third number this module is
///   driven to zero on.**
///
///   It is the hiding direction's own zero-target, and it exists because
///   `hider-unresolved` was one class doing three jobs. A defect hid a
///   challenge behind a `ChallengeBoundaryUnknown` the value did not warrant,
///   and no metric here could see it: the class it graded into was pinned at a
///   non-zero constant, so the whole hiding direction of this axis was
///   unwatched while the inventing direction had two zero-targets.
///   `oracle::every_comma_in_front_is_settled` is the split, and
///   `Verdict::reached` is what holds the recipient's own bound apart from it.
/// - `hider-unexcused` — the same, with no such reading and no notice at all.
///   **This is the second number this module is driven to zero on**, beside
///   `over-yield`.
fn axis(lines: &[&[u8]]) -> String {
  let joined = join(lines);
  let Some(probe) = last_index_of(&joined, PROBE) else {
    return String::from("no-probe");
  };
  let verdict = oracle::read(&joined, probe);
  if !verdict.derives {
    return String::from("no-probe");
  }
  if yields_the_probe(lines) {
    return String::from(match (verdict.reached, verdict.excused) {
      (true, _) => "yields",
      (false, true) => "over-yield",
      (false, false) => "yields-underivable",
    });
  }
  if verdict.excused {
    return String::from("hider-excused");
  }
  if !says_the_rest_is_unread(lines) {
    return String::from("hider-unexcused");
  }
  // The notice was given, and whether it was WARRANTED is a second question.
  // Two things warrant it and they are different things.
  if verdict.reached {
    // Some derivation of the WHOLE value reads the probe as a challenge, so
    // the grammar has no complaint anywhere in these bytes and what refused
    // them is a bound of this recipient's. `MAX_CHALLENGE_LINES` records that
    // trade where the constant is defined: the walk stopped inside a value it
    // may not finish reading, and the close that would settle the boundary is
    // on a line it may not hold.
    return String::from("hider-conforming");
  }
  // Nothing derives, so the walk is in recovery — and a walk in recovery may
  // decline a comma the readings disagree about and may not decline one they
  // do not.
  String::from(if oracle::every_comma_in_front_is_settled(&joined, probe) {
    "hider-declined"
  } else {
    "hider-unresolved"
  })
}

/// Whether the `#challenge` walk told the caller that the rest of the value is
/// unread.
///
/// `AuthError::ChallengeBoundaryUnknown` is that notice, and it is what
/// separates a challenge silently hidden from one the caller is told it has not
/// been shown.
fn says_the_rest_is_unread(lines: &[&[u8]]) -> bool {
  challenges(lines.iter().copied())
    .any(|read| read.is_err_and(|fault| matches!(fault, AuthError::ChallengeBoundaryUnknown)))
}

/// Whether the `#challenge` walk yields the probe's scheme.
fn yields_the_probe(lines: &[&[u8]]) -> bool {
  challenges(lines.iter().copied())
    .any(|read| read.is_ok_and(|credential| credential.scheme() == PROBE_SCHEME))
}

/// The one value RFC 9110 §5.2 makes of the field lines: their values
/// "concatenated in order, with each field line value separated by a comma".
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

/// Where `needle` last stands in `haystack`.
fn last_index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || needle.len() > haystack.len() {
    return None;
  }
  (0..=haystack.len().saturating_sub(needle.len()))
    .rev()
    .find(|&at| haystack.get(at..at.saturating_add(needle.len())) == Some(needle))
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
