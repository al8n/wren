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
//! - **Excused.** A §11.2 value position stands somewhere in front of the
//!   probe, holds a DQUOTE, and the bytes between that DQUOTE and the probe are
//!   ones §5.6.4 admits inside a quoted-string with none of them closing it. The
//!   bytes are that value's data under the reading that opens it, so a reader
//!   that showed no challenge among them is not hiding one.
//!
//!   **Asked of the POSITION and not of a derivation that reaches it**, which is
//!   the correction al8n/wren#77 forced. Asking whether the whole value derives
//!   let a malformed FIRST element decide that no reading licensed a
//!   quoted-string standing later in the value that §11.2 admits perfectly well
//!   — so inputs whose probe is plainly a parameter's data graded
//!   `yields-underivable`, and the axis could not see the reader manufacturing a
//!   challenge out of them. A reader in recovery is past the point where any
//!   derivation of the whole value exists; what it must not do is cut a value
//!   the grammar admits at that position, and that is what this now asks.
//! - **Reached.** Some derivation has an element start exactly at the probe's
//!   offset, reads it as an `auth-scheme`, and derives the rest of the value
//!   from there. This is the whole value deriving, where **Derives** is the
//!   probe's own bytes deriving.

use std::collections::HashSet;

/// What the oracle says about one field value and the offset a probe challenge
/// stands at in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
  /// Some reading puts the offset inside a §5.6.4 quoted-string, whether or
  /// not that string closes.
  ///
  /// [`covered`] is the whole of it, and the module doc says why it is a
  /// question about a POSITION rather than about a derivation that reaches one.
  pub excused: bool,
  /// Some derivation reads the offset as the `auth-scheme` of a challenge and
  /// derives the rest of the value from there.
  pub reached: bool,
  /// A whole challenge derives from the offset to the end of the value —
  /// asked of those bytes ALONE, with no claim that anything reaches them.
  ///
  /// This is what says a challenge stands there to be hidden, and it is asked
  /// of the real bytes for a reason. Grading a hider by a control instead — the
  /// same value with every DQUOTE replaced — lets the control REPAIR: swapping
  /// the DQUOTE out of `Digest realm=zc"` leaves `Digest realm=zcq`, which
  /// parses where the original never could, so the control reports a challenge
  /// hidden that no reading of the real bytes has.
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
    excused: covered(value, probe),
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
    for next in step(value, at, context.as_ref()) {
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
fn step(value: &[u8], at: usize, context: Option<&Vec<Vec<u8>>>) -> Vec<State> {
  let mut out = Vec::new();

  // The empty element RFC 9110 §5.6.1.2 admits, which ends no challenge: its
  // opening sentence is "Empty elements do not contribute to the count of
  // elements present."
  push(&mut out, value, boundary(value, at), context.cloned());

  for (end, opened) in challenge_readings(value, at) {
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
    if !names.contains(&name)
      && let Some(end) = param.end
    {
      let mut names = names.clone();
      names.push(name);
      names.sort();
      push(&mut out, value, boundary(value, end), Some(names));
    }
  }

  out
}

/// Every way the element at `at` reads as a whole `challenge`: where it ends,
/// and the parameter list it leaves open behind it.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
fn challenge_readings(value: &[u8], at: usize) -> Vec<(usize, Context)> {
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
  if let Some(param) = auth_param(value, body)
    && let Some(end) = param.end
  {
    out.push((end, Some(vec![folded(value, param.name)])));
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
  challenge_readings(value, at)
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

/// One `auth-param` the walk read: where its name is, and where it ends when
/// this reading has it end at all.
struct Param {
  name: (usize, usize),
  /// One past the parameter's last byte, or `None` where the value is a string
  /// nothing closes and there is no parameter to hand back.
  end: Option<usize>,
}

/// Where RFC 9110 §11.2's `auth-param` admits the VALUE of an element beginning
/// at `at`, or `None` for an element that is no `auth-param`.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Three terminals stand in front of that value and all three are read here:
/// the name `token`, the `=`, and the `BWS` §5.6.3 defines as `OWS`'s own bytes
/// on either side of it. This is the one position a §5.6.4 quoted-string may
/// open at behind an `auth-scheme` — §5.6.2's `tchar` and §11.2's `token68`
/// alphabet both exclude DQUOTE — which is the fact [`covered`] is decided on.
fn value_position(value: &[u8], at: usize) -> Option<usize> {
  let name_end = token_end(value, at)?;
  let eq = skip_ows(value, name_end);
  if value.get(eq) != Some(&b'=') {
    return None;
  }
  Some(skip_ows(value, eq.saturating_add(1)))
}

/// Reads RFC 9110 §11.2's `auth-param` at `at`.
fn auth_param(value: &[u8], at: usize) -> Option<Param> {
  let start = value_position(value, at)?;
  let name = (at, token_end(value, at)?);

  if value.get(start) == Some(&b'"') {
    return match scan_quoted(value, start.saturating_add(1)) {
      Quoted::Closed(end) => Some(Param {
        name,
        end: Some(end),
      }),
      // Nothing closes it, so this reading has no parameter to hand back.
      Quoted::Open => Some(Param { name, end: None }),
      Quoted::Invalid => None,
    };
  }
  let end = token_end(value, start)?;
  Some(Param {
    name,
    end: Some(end),
  })
}

/// Whether some reading of `value` puts `probe` inside an RFC 9110 §5.6.4
/// quoted-string.
///
/// # What a reading is
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// A left-to-right walk over element starts, and [`covers`] enumerates every
/// one of them. Two regimes, and which regime an element is in is the whole of
/// what this gets right that asking after the WHOLE value's derivation got
/// wrong:
///
/// - **In front of the first fault the grammar decides.** A `parameter-value`
///   beginning with a DQUOTE derives only the `quoted-string` alternative —
///   §5.6.2's `tchar` excludes DQUOTE — so that string is not a choice, and
///   where it closes is where the element ends.
/// - **Behind the first fault nothing derives, so every DQUOTE §11.2 admits a
///   value at is a choice**: a reading may open the string there, and a reading
///   may leave it shut and take the element to the next comma read raw. The
///   readings BETWEEN the two extremes are the ones a comparison of the raw
///   reading with the greedy one never asks, and they are where a manufactured
///   challenge comes from.
///
/// A fault is an element start no reading of the grammar leaves. That is the
/// correction al8n/wren#77 forced: the old question was whether a derivation of
/// the whole value REACHED the position, so one malformed element decided that
/// no reading licensed a quoted-string standing perfectly well behind it, and
/// the axis could not see the reader cutting that value in half.
fn covered(value: &[u8], probe: usize) -> bool {
  covers(
    value,
    0,
    Start::Element,
    false,
    false,
    probe,
    &mut HashSet::new(),
  )
}

/// Which list an element start belongs to.
///
/// A `challenge` stands at an element of the OUTER `#challenge` list and
/// nowhere else. The first element of a challenge's own `#auth-param` list
/// begins at the body position `1*SP` admits — inside the outer element — and
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` puts no second
/// challenge there. Reading one anyway is how `Basic a a=", Digest realm=z`
/// acquired a reading in which `a` is a scheme and the DQUOTE behind it opens a
/// value: the `#auth-param` list has one element, `a a=`, and no production
/// admits a string in it at all.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum Start {
  /// An element of the outer `#challenge` list, where a challenge may open.
  Element,
  /// The first element of a challenge's `#auth-param` list, where none may.
  Body,
}

/// One position of that walk.
///
/// - `at` — an element start, and an offset every reading in hand stands
///   OUTSIDE a quoted-string at.
/// - `list` — whether a challenge's `#auth-param` list is open here. At the head
///   of the value none is, which is why `Basic ="x, Digest realm=z` has no
///   reading in which `Basic` names a parameter whose value swallows the comma.
/// - `faulted` — whether an element start in front of this one is one no reading
///   of the grammar leaves.
fn covers(
  value: &[u8],
  at: usize,
  start: Start,
  list: bool,
  faulted: bool,
  probe: usize,
  seen: &mut HashSet<(usize, Start, bool, bool)>,
) -> bool {
  if at > probe || !seen.insert((at, start, list, faulted)) {
    return false;
  }
  // Whether ANY reading of the grammar leaves this element start. Where none
  // does, this start is the fault, and every reading behind it is free.
  let mut derived = false;
  let mut hit = false;

  // The empty element §5.6.1.2 admits: "A recipient MUST parse and ignore a
  // reasonable number of empty list elements".
  match boundary(value, at) {
    None => {}
    Some(Edge::Ends) => derived = true,
    Some(Edge::Next(next)) => {
      derived = true;
      hit |= covers(value, next, Start::Element, list, faulted, probe, seen);
    }
  }

  // The element read as a whole `challenge`, which only an element of the outer
  // list may be.
  if start == Start::Element
    && let Some(scheme_end) = token_end(value, at)
  {
    if value.get(scheme_end) == Some(&b' ') {
      // The scheme and its `1*SP` derive whatever the body does, so a fault
      // inside the body is the BODY's element start and not this one.
      derived = true;
      let body = skip_sp(value, scheme_end);
      // §11.2's `token68` alternative, which is not a list.
      if let Some(end) = token68_end(value, body)
        && let Some(Edge::Next(next)) = boundary(value, end)
      {
        hit |= covers(value, next, Start::Element, false, faulted, probe, seen);
      }
      // And the `#auth-param` alternative, whose first element starts at the
      // body position — an element start inside this outer element.
      hit |= covers(value, body, Start::Body, true, faulted, probe, seen);
    } else {
      // No `1*SP`, so the scheme is a whole challenge that took no parameters.
      match boundary(value, scheme_end) {
        None => {}
        Some(Edge::Ends) => derived = true,
        Some(Edge::Next(next)) => {
          derived = true;
          hit |= covers(value, next, Start::Element, false, faulted, probe, seen);
        }
      }
    }
  }

  // The element read as one more `auth-param` of a list already open. §11.2's
  // one-name-once MUST is not applied here: a repeat refuses the reading, which
  // makes this element a fault — and the regime behind a fault is the one this
  // function is for, so the answer is the same either way and the name record
  // is storage for nothing.
  if list && let Some(start) = value_position(value, at) {
    if value.get(start) == Some(&b'"') {
      if open_at(value, start, probe) {
        return true;
      }
      if let Quoted::Closed(end) = scan_quoted(value, start.saturating_add(1)) {
        match boundary(value, end) {
          None => {}
          Some(Edge::Ends) => derived = true,
          Some(Edge::Next(next)) => {
            derived = true;
            hit |= covers(value, next, Start::Element, list, faulted, probe, seen);
          }
        }
      }
    } else if let Some(end) = token_end(value, start) {
      match boundary(value, end) {
        None => {}
        Some(Edge::Ends) => derived = true,
        Some(Edge::Next(next)) => {
          derived = true;
          hit |= covers(value, next, Start::Element, list, faulted, probe, seen);
        }
      }
    }
  }

  if !(faulted || !derived) {
    return hit;
  }

  // Behind a fault. The DQUOTE §11.2 admits a value at is a choice: one reading
  // opens the string there, and one leaves it shut and reads the element to the
  // next comma raw.
  if list
    && let Some(start) = value_position(value, at)
    && value.get(start) == Some(&b'"')
  {
    if open_at(value, start, probe) {
      return true;
    }
    // The reading that opened it, past the close: what is left of the element
    // holds no value position of its own, so it runs to the next raw comma.
    if let Quoted::Closed(end) = scan_quoted(value, start.saturating_add(1)) {
      hit |= resume(value, raw_comma_end(value, end), list, probe, seen);
    }
  }
  // And the reading that opens nothing at all.
  hit |= resume(value, raw_comma_end(value, at), list, probe, seen);
  hit
}

/// The element start behind the comma at `end`, walked from there.
///
/// The end of `value` is no comma and opens no element, so a run that reaches
/// it ends the reading.
fn resume(
  value: &[u8],
  end: usize,
  list: bool,
  probe: usize,
  seen: &mut HashSet<(usize, Start, bool, bool)>,
) -> bool {
  match value.get(end) {
    Some(&b',') => covers(
      value,
      skip_ows(value, end.saturating_add(1)),
      Start::Element,
      list,
      true,
      probe,
      seen,
    ),
    _ => false,
  }
}

/// Whether the RFC 9110 §5.6.4 quoted-string opening at `quote` is still OPEN at
/// `probe`.
///
/// The scan is taken over `value` cut at `probe`, so what it reports is the
/// state the string is in THERE. A byte §5.6.4 forbids standing in FRONT of the
/// probe means no quoted-string derives over it and there is no excuse to give —
/// RFC 9110 §5.5 admits no CTL other than HTAB anywhere in a field value, so
/// those bytes are no value's data. One standing BEHIND the probe is not in
/// front of it: what the sender wrote between the DQUOTE and the probe is
/// `qdtext` either way, and a reader that cut it in half read a challenge out of
/// a value's interior.
fn open_at(value: &[u8], quote: usize, probe: usize) -> bool {
  quote < probe
    && matches!(
      scan_quoted(
        value.get(..probe).unwrap_or_default(),
        quote.saturating_add(1)
      ),
      Quoted::Open
    )
}

/// Where the run at `at` ends when no quoted-string is opened in it: the first
/// comma, read raw, or the end of `value`.
fn raw_comma_end(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while !matches!(value.get(at), None | Some(&b',')) {
    at = at.saturating_add(1);
  }
  at
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
