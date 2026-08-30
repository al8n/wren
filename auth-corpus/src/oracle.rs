//! An independent reading of RFC 9110 §11.6.1's `#challenge` value, written
//! from the RFC rather than from `http_semantics::auth`.
//!
//! It exists to grade one axis and one only: **does the reader under test hide
//! a challenge that a conforming reading would have shown?** RFC 9110 §11.4
//! has a user agent answer a response by "selecting the challenge with what it
//! considers to be the most secure auth-scheme that it understands", which it
//! cannot do over a challenge it was never handed.
//!
//! # What it does NOT model, deliberately
//!
//! `MAX_CHALLENGE_LINES` and `MAX_PARAMS_PER_CREDENTIAL` are the reader's own
//! bounds and not the grammar's. An oracle carrying them would be grading the
//! module against itself, so this one has neither: a challenge spread over
//! twenty field lines derives here exactly as one spread over two.
//!
//! # The ambiguity, resolved as "there EXISTS a derivation"
//!
//! RFC 9110 §11.6.1 states the problem: the field value "might contain more
//! than one challenge, and each challenge can contain a comma-separated list
//! of authentication parameters". Both levels are the same §5.6.1 construct,
//! one inside the other, so at a comma the next element may be either another
//! parameter of the challenge already open or the scheme of the next one. A
//! recipient picks one reading; this oracle enumerates all of them, because a
//! challenge is hidden only when NO reading shows it.
//!
//! The enumeration is a walk over states `(element start, context)`, where the
//! context is the parameter list still open. RFC 9110 §11.2's "each parameter
//! name MUST only occur once per challenge" is enforced along each derivation,
//! so a reading that repeats a name is not one.
//!
//! # The three questions it answers
//!
//! - **Derives.** A whole challenge derives from the probe's offset to the end
//!   of the value, asked of those bytes alone. Nothing is hidden where nothing
//!   stands.
//! - **Excused.** Some derivation reaches a §11.2 value position whose DQUOTE
//!   opens a §5.6.4 quoted-string that covers the probe. The bytes are that
//!   value's data under that reading, so a reader that showed no challenge
//!   among them is not hiding one.
//! - **Reached.** Some derivation has an element start exactly at the probe's
//!   offset, reads it as an `auth-scheme`, and derives the rest of the value
//!   from there. This is the whole value deriving, where **Derives** is the
//!   probe's own bytes deriving.

use std::collections::HashSet;

/// What the oracle says about one field value and the offset a probe challenge
/// stands at in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
  /// Some derivation puts the offset inside a §5.6.4 quoted-string, whether or
  /// not that string closes.
  pub excused: bool,
  /// Some derivation reads the offset as the `auth-scheme` of a challenge and
  /// derives the rest of the value from there.
  pub reached: bool,
  /// A whole challenge derives from the offset to the end of the value —
  /// asked of those bytes ALONE, with no claim that anything reaches them.
  ///
  /// This is what says a challenge stands there to be hidden. Grading a hider
  /// by a control instead — the same value with every DQUOTE replaced — is
  /// what an earlier round did, and a control can REPAIR: swapping the DQUOTE
  /// out of `Digest realm=zc"` leaves `Digest realm=zcq`, which parses where
  /// the original never could, so the control reports a challenge hidden that
  /// no reading of the real bytes has.
  pub derives: bool,
}

/// The parameter list still open at an element boundary, or its absence.
///
/// `None` is a boundary at which no challenge can take another parameter: the
/// value has not started, or the challenge before this comma took no `1*SP`,
/// or its body was RFC 9110 §11.2's `token68` alternative, which is not a list.
type Context = Option<Vec<Vec<u8>>>;

/// One position in the walk: where the next element starts, and what may
/// follow it. A position at the value's length is the value having derived.
type State = (usize, Context);

/// Where an element that ended at some offset leaves the walk.
enum Edge {
  /// Only the list's own `OWS` stood behind it, so the value ends there.
  Ends,
  /// A comma stood behind it, and the next element starts here.
  Next(usize),
}

/// Reads `value` as RFC 9110 §11.6.1's `#challenge` every way the grammar
/// admits, and reports the three facts the offset `probe` is graded by.
pub fn read(value: &[u8], probe: usize) -> Verdict {
  let mut verdict = Verdict {
    excused: false,
    reached: false,
    derives: derives_as_a_challenge(value, probe),
  };
  let mut seen: HashSet<State> = HashSet::new();
  let mut queue: Vec<State> = Vec::new();
  let start: State = (0, None);
  seen.insert(start.clone());
  queue.push(start);

  while let Some((at, context)) = queue.pop() {
    if at == probe && verdict.derives {
      verdict.reached = true;
    }
    for next in step(value, at, context.as_ref(), probe, &mut verdict) {
      if seen.insert(next.clone()) {
        queue.push(next);
      }
    }
  }
  verdict
}

/// Every element boundary reachable from the one at `at`, and the context each
/// leaves behind.
///
/// RFC 9110 §5.6.1.2 expands a list as
/// `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs every
/// `OWS` it has on a comma and none in front of the first element — so nothing
/// here skips whitespace before an element no comma was crossed to reach.
fn step(
  value: &[u8],
  at: usize,
  context: Option<&Vec<Vec<u8>>>,
  probe: usize,
  verdict: &mut Verdict,
) -> Vec<State> {
  let mut out = Vec::new();

  // The empty element RFC 9110 §5.6.1.2 admits, which ends no challenge: its
  // opening sentence is "Empty elements do not contribute to the count of
  // elements present."
  push(&mut out, value, boundary(value, at), context.cloned());

  for (end, opened) in challenge_readings(value, at, probe, verdict) {
    push(&mut out, value, boundary(value, end), opened);
  }

  // The element read as one more parameter of the challenge already open.
  if let Some(names) = context
    && let Some(param) = auth_param(value, at)
  {
    let name = folded(value, param.name);
    // RFC 9110 §11.2: "each parameter name MUST only occur once per
    // challenge". A reading that repeats one is not a reading — so the name is
    // answered BEFORE anything about this parameter's value is believed.
    if !names.contains(&name) {
      excuse(verdict, param.quoted, probe);
      if let Some(end) = param.end {
        let mut names = names.clone();
        names.push(name);
        names.sort();
        push(&mut out, value, boundary(value, end), Some(names));
      }
    }
  }

  out
}

/// Records the excuse a §5.6.4 quoted-string covering `probe` gives for showing
/// no challenge there: under this reading those bytes are that value's data.
fn excuse(verdict: &mut Verdict, quoted: Option<(usize, usize)>, probe: usize) {
  if let Some((from, to)) = quoted
    && from < probe
    && probe < to
  {
    verdict.excused = true;
  }
}

/// Every way the element at `at` reads as a whole `challenge`: where it ends,
/// and the parameter list it leaves open behind it.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
fn challenge_readings(
  value: &[u8],
  at: usize,
  probe: usize,
  verdict: &mut Verdict,
) -> Vec<(usize, Context)> {
  let mut out = Vec::new();
  let Some(scheme_end) = token_end(value, at) else {
    return out;
  };
  // `1*SP` is the only entrance the body has, so a scheme with no SP behind it
  // is a whole challenge that took no parameters.
  if value.get(scheme_end) != Some(&b' ') {
    out.push((scheme_end, None));
    return out;
  }
  let body = skip_sp(value, scheme_end);

  // RFC 9110 §11.2's `token68` alternative, which is not a list and holds no
  // name to repeat.
  if let Some(end) = token68_end(value, body) {
    out.push((end, None));
  }
  // The `#auth-param` alternative with its first element empty, which is how
  // `Basic , realm="x"` is one challenge carrying one parameter.
  out.push((body, Some(Vec::new())));
  // And with a parameter in that first element. No name stands in front of it,
  // so §11.2's MUST has nothing to refuse here.
  if let Some(param) = auth_param(value, body) {
    excuse(verdict, param.quoted, probe);
    if let Some(end) = param.end {
      out.push((end, Some(vec![folded(value, param.name)])));
    }
  }
  out
}

/// Whether a whole `challenge` derives from `at`, ending where RFC 9110
/// §5.6.1.2 lets a list element end.
///
/// The probe's OWN bytes, asked in isolation. What stands behind the element it
/// ends at is a different question — one about the rest of the list and not
/// about whether a challenge is written here — and one the bytes in FRONT of
/// `at` cannot answer either, which is why [`Verdict::reached`] is the separate
/// fact that a derivation gets here at all.
fn derives_as_a_challenge(value: &[u8], at: usize) -> bool {
  let mut ignored = Verdict {
    excused: false,
    reached: false,
    derives: false,
  };
  challenge_readings(value, at, usize::MAX, &mut ignored)
    .into_iter()
    .any(|(end, _)| boundary(value, end).is_some())
}

/// Records the state an [`Edge`] leads to, if it leads to one.
fn push(out: &mut Vec<State>, value: &[u8], edge: Option<Edge>, context: Context) {
  match edge {
    Some(Edge::Ends) => out.push((value.len(), None)),
    Some(Edge::Next(at)) => out.push((at, context)),
    None => {}
  }
}

/// One `auth-param` the walk read: where its name is, where it ends when this
/// reading has it end at all, and what a §5.6.4 quoted-string at its value
/// position covers.
struct Param {
  name: (usize, usize),
  /// One past the parameter's last byte, or `None` where the value is a string
  /// nothing closes and there is no parameter to hand back.
  end: Option<usize>,
  /// `(the DQUOTE's offset, one past the string's last byte)` when a string
  /// opened at the value position, `None` for a token value. The end of the
  /// field value is the second half where nothing closes it.
  quoted: Option<(usize, usize)>,
}

/// Reads RFC 9110 §11.2's `auth-param` at `at`.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// The value position is where a §5.6.4 quoted-string may open and the only
/// place it may, which is the fact the excuse is decided on. What that string
/// covers is reported rather than acted on here, because whether this reading
/// exists at all is the CALLER's question: §11.2's one-name-once MUST can
/// refuse the name in front of a value nothing else refuses.
fn auth_param(value: &[u8], at: usize) -> Option<Param> {
  let name_end = token_end(value, at)?;
  let eq = skip_ows(value, name_end);
  if value.get(eq) != Some(&b'=') {
    return None;
  }
  let start = skip_ows(value, eq.saturating_add(1));
  let name = (at, name_end);

  if value.get(start) == Some(&b'"') {
    return match scan_quoted(value, start.saturating_add(1)) {
      Quoted::Closed(end) => Some(Param {
        name,
        end: Some(end),
        quoted: Some((start, end)),
      }),
      // Nothing closes it, so this reading has no parameter to hand back — and
      // every byte from here to the end of the field value is inside it.
      Quoted::Open => Some(Param {
        name,
        end: None,
        quoted: Some((start, value.len())),
      }),
      Quoted::Invalid => None,
    };
  }
  let end = token_end(value, start)?;
  Some(Param {
    name,
    end: Some(end),
    quoted: None,
  })
}

/// Where the element that ends at `end` leaves the list, or `None` when bytes
/// the element cannot hold stand behind it.
///
/// RFC 9110 §5.6.1.2 puts `OWS` on both sides of the comma, so the whitespace
/// in front of it is the LIST's rather than the element's and is skipped here
/// and not by whatever read the element.
fn boundary(value: &[u8], end: usize) -> Option<Edge> {
  let at = skip_ows(value, end);
  match value.get(at) {
    None => Some(Edge::Ends),
    Some(&b',') => Some(Edge::Next(skip_ows(value, at.saturating_add(1)))),
    Some(_) => None,
  }
}

/// The name, lowercased. RFC 9110 §11.2's name token "is matched
/// case-insensitively", and the MUST above is checked under that fold.
fn folded(value: &[u8], (start, end): (usize, usize)) -> Vec<u8> {
  value
    .get(start..end)
    .unwrap_or_default()
    .to_ascii_lowercase()
}

/// RFC 9110 §5.6.2's `tchar`.
///
/// ```text
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///  "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
/// ```
fn is_tchar(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
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

/// The end of the `token` starting at `at`, or `None` when there is not one.
fn token_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).is_some_and(|&byte| is_tchar(byte)) {
    end = end.saturating_add(1);
  }
  (end > at).then_some(end)
}

/// The end of RFC 9110 §11.2's `token68` starting at `at`, or `None`.
///
/// ```text
/// token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
fn token68_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).is_some_and(|&byte| {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
  }) {
    end = end.saturating_add(1);
  }
  if end == at {
    return None;
  }
  while value.get(end) == Some(&b'=') {
    end = end.saturating_add(1);
  }
  Some(end)
}

/// Past RFC 9110 §5.6.3's `OWS` — `*( SP / HTAB )` — from `at`.
fn skip_ows(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(&b' ') | Some(&b'\t')) {
    at = at.saturating_add(1);
  }
  at
}

/// Past the `1*SP` that admits a challenge's body.
fn skip_sp(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while value.get(at) == Some(&b' ') {
    at = at.saturating_add(1);
  }
  at
}

/// How a §5.6.4 quoted-string scan ended.
enum Quoted {
  /// The closing DQUOTE was found; the value ends at this offset.
  Closed(usize),
  /// The input ran out first.
  Open,
  /// A byte the grammar forbids stood inside it.
  Invalid,
}

/// Scans the interior of a RFC 9110 §5.6.4 quoted-string from `at`.
///
/// ```text
/// quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// qdtext        = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
/// ```
fn scan_quoted(value: &[u8], at: usize) -> Quoted {
  let mut at = at;
  let mut escape = false;
  loop {
    let Some(&byte) = value.get(at) else {
      return Quoted::Open;
    };
    at = at.saturating_add(1);
    let vchar_or_obs_text = matches!(byte, 0x21..=0x7E | 0x80..=0xFF);
    if escape {
      if !(byte == b'\t' || byte == b' ' || vchar_or_obs_text) {
        return Quoted::Invalid;
      }
      escape = false;
      continue;
    }
    match byte {
      b'"' => return Quoted::Closed(at),
      b'\\' => escape = true,
      _ if byte == b'\t' || byte == b' ' || vchar_or_obs_text => {}
      _ => return Quoted::Invalid,
    }
  }
}
