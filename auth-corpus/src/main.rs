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
//! - `corpus` — which generator produced the input: `A`..`J`.
//! - `case` — the field lines, escaped, `|`-separated. `(corpus, case,
//!   spelling)` is the record's key, and it is unique everywhere but the 32
//!   inputs corpus D writes six times each — see
//!   `tests::the_records_that_share_a_key_are_the_ones_no_mid_can_tell_apart`,
//!   which pins that exception and says what it costs. 935 692 records stand
//!   for 935 532 distinct inputs. **Every corpus D figure quoted from this
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
  process,
};

use http_semantics::{
  auth::{AuthError, Credential, auth_info, challenges, credentials},
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
  let mut counts = [0_usize; 10];
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
  out.flush()?;
  let total: usize = counts.iter().sum();
  for (name, count) in ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]
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
const CONTINUATIONS: [&[u8]; 9] = [
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
  // A `token68` body, which looks conclusive and is not. `token68 / #auth-param`
  // is an unordered ABNF choice, so the same bytes read as `#auth-param` are a
  // list whose first element derives nothing — and the list is open behind that
  // fault.
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
const TRAPS: [(&str, &[u8]); 5] = [
  // A value position whose RFC 9110 §5.6.4 quoted-string opens over the probe
  // and never closes.
  ("open", b"x=\"open, Digest realm=z"),
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
/// open: `list`, `token68` and `list-token68`. A `token68` body is a fault
/// under §11.3's other alternative, so the list stands open behind it and the
/// probe really is inside a value under some reading — which makes crossing it
/// an invention rather than a recovery. Those rows and the `bare` ones move in
/// opposite directions, which is what makes this family a pin in both.
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
///   that a sender wrote those bytes as data, which is `over-yield`. One
///   SUBSET of it is stronger than that: where the value carries a byte RFC
///   9110 §5.5 admits nowhere in a field value, there is no reading of those
///   bytes for the challenge to be the data of either. Corpus F is where that
///   subset lives; corpora A, B and C cannot spell it.
/// - `hider-excused` — the reader did not show it, and some reading puts it
///   inside a quoted-string. Not a defect: under that reading there is no
///   challenge there to show.
/// - `hider-unresolved` — the reader did not show it, no reading puts it inside
///   a quoted-string, and the reader SAID SO: its answer carries
///   `ChallengeBoundaryUnknown`, which is the walk telling the caller that the
///   rest of the value is unread. A challenge nobody was shown and nobody was
///   told about is the harm this axis exists against, and this is the other
///   thing: RFC 9110 §11.4's user agent knows it has not seen the whole list
///   and can act on that. It is a cost and not a defect, and `tests` pins its
///   count with the three shapes it is made of.
/// - `hider-unexcused` — the same, with no such reading and no such notice.
///   **This is the number this module is driven to zero on**, beside
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
  String::from(if verdict.excused {
    "hider-excused"
  } else if says_the_rest_is_unread(lines) {
    "hider-unresolved"
  } else {
    "hider-unexcused"
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
