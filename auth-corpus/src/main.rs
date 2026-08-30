//! The differential corpus for `http-semantics`'s RFC 9110 §11 authentication
//! fields: one record per answer, naming what THIS build says about one input.
//!
//! Run it at two revisions and diff the records and you have answered the
//! question every round of review on this module has had to answer by hand —
//! *did this change move an answer, and was it one that should have moved?*
//! That is what `cargo run -p xtask -- auth-diff <base> [head]` does; see
//! `xtask/src/auth_diff.rs`.
//!
//! It exists because four review rounds each published a sha256 of a harness
//! they then deleted, so not one of those four digests could be recomputed by
//! anybody, this crate's own authors included. A digest nobody can recompute is
//! not evidence. This one is committed.
//!
//! # Contract
//!
//! Every record is one line of five tab-separated columns:
//!
//! ```text
//! corpus <TAB> case <TAB> spelling <TAB> axis <TAB> answer
//! ```
//!
//! - `corpus` — which generator produced the input: `A`..`E`.
//! - `case` — the field lines, escaped, `|`-separated. `(corpus, case,
//!   spelling)` is the record's key and is unique.
//! - `spelling` — which entry point was called and over what shape.
//! - `axis` — how the case grades on the ONE axis this module has been
//!   reviewed against: does a malformed challenge hide a well-formed one
//!   behind it? See [`axis`]. `-` where the case carries no probe challenge to
//!   hide.
//! - `answer` — everything the entry point yielded, rendered. This is the
//!   column the differential's digest is taken over.
//!
//! # Two constraints this file is written under
//!
//! **Public API only.** A corpus that reached into the crate would measure a
//! private reorganisation as a behaviour change.
//!
//! **The oracle reads nothing from the module.** `oracle` is an independent
//! derivation from RFC 9110's grammar; if it agreed with `http_semantics::auth`
//! by construction it would grade nothing.

mod oracle;

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
  let mut counts = [0_usize; 6];
  corpus_a(out, &mut counts[0])?;
  corpus_b(out, &mut counts[1])?;
  corpus_c(out, &mut counts[2])?;
  corpus_d(out, &mut counts[3])?;
  corpus_e(out, &mut counts[4])?;
  corpus_f(out, &mut counts[5])?;
  out.flush()?;
  let total: usize = counts.iter().sum();
  for (name, count) in ["A", "B", "C", "D", "E", "F"].iter().zip(counts) {
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

/// How this case grades on the axis every round of review on this module has
/// been about: **a malformed challenge must not hide a well-formed one behind
/// it**, because RFC 9110 §11.4's user agent answers by "selecting the
/// challenge with what it considers to be the most secure auth-scheme that it
/// understands" and cannot select one it was never shown.
///
/// - `no-probe` — no whole challenge derives from the probe's offset, so there
///   is nothing there for any reader to show or hide.
/// - `yields` — the reader showed it, and some derivation of the WHOLE value
///   reads it as a challenge. What the sender wrote is what the caller got.
/// - `over-yield` — the reader showed it, some derivation puts it inside a
///   quoted-string, and none reads it as a challenge. The caller was handed a
///   challenge built out of bytes a sender wrote as that value's data.
/// - `yields-underivable` — the reader showed it and NO derivation reads it
///   either way, because nothing derives the bytes in front of it. The caller
///   was handed a challenge out of a field value RFC 9110 §5.5 does not admit,
///   and there is no reading of those bytes for it to be the data of either.
/// - `hider-excused` — the reader did not show it, and some derivation puts it
///   inside a quoted-string. Not a defect: under that reading there is no
///   challenge there to show.
/// - `hider-unexcused` — the same, with no such derivation. **This is the
///   number five rounds of review have been driving to zero.**
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
  } else {
    "hider-unexcused"
  })
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
