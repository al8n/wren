//! An independent reading of the two `parameter` productions and the three
//! list elements built out of them, written from RFC 9110's grammar rather
//! than from any of the three walks this corpus grades.
//!
//! # What it is for
//!
//! The differential's first question is whether two readers of one production
//! answer alike. Its second is whether they are allowed to be wrong TOGETHER,
//! and only a derivation written from the RFC can answer that. This module is
//! that derivation. It shares no code with `http_semantics::grammar` or with
//! `http1-proto`'s `Transfer-Encoding` accumulator; if it agreed with either by
//! construction it would grade nothing.
//!
//! # The productions
//!
//! The list construct, RFC 9110 §5.6.1.2, is the same for all three:
//!
//! ```text
//! #element => [ element ] *( OWS "," OWS [ element ] )
//! ```
//!
//! RFC 9110 §5.6.3's whitespace, cited on every `OWS` and `BWS` below:
//!
//! ```text
//! OWS            = *( SP / HTAB )
//! RWS            = 1*( SP / HTAB )
//! BWS            = OWS
//! ```
//!
//! RFC 9110 §5.6.2's `token` and §5.6.4's `quoted-string`, which every element
//! here is ultimately built out of:
//!
//! ```text
//! token          = 1*tchar
//! quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
//! qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
//! quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
//! ```
//!
//! Then one element rule per [`Production`], each carried WHOLE — its container
//! and its inner rule both, because half of what separates them lives in the
//! container and issue #75 records what an omitted container cost. RFC 9110
//! §10.1.4, the element of RFC 9112 §7's `Transfer-Encoding = #transfer-coding`:
//!
//! ```text
//! transfer-coding    = token *( OWS ";" OWS transfer-parameter )
//! transfer-parameter = token BWS "=" BWS ( token / quoted-string )
//! ```
//!
//! RFC 9110 §5.6.6, whose `parameters` has no head of its own and takes one
//! from whatever rule concatenates it — §5.6.2's `token`, for the walk this
//! grades:
//!
//! ```text
//! parameters      = *( OWS ";" OWS [ parameter ] )
//! parameter       = parameter-name "=" parameter-value
//! parameter-name  = token
//! parameter-value = ( token / quoted-string )
//! ```
//!
//! And RFC 9110 §10.1.1, which extends that same `parameters` with a head of
//! its own — note WHERE the bracket closes:
//!
//! ```text
//! Expect =      #expectation
//! expectation = token [ "=" ( token / quoted-string ) parameters ]
//! ```
//!
//! And RFC 9110 §12.5.1, which concatenates that same `parameters` behind a
//! head that is not a token and behind NO bracket at all:
//!
//! ```text
//! Accept = #( media-range [ weight ] )
//!
//! media-range    = ( "*/*"
//!                    / ( type "/" "*" )
//!                    / ( type "/" subtype )
//!                  ) parameters
//! type           = token
//! subtype        = token
//! weight         = OWS ";" OWS "q=" qvalue
//! ```
//!
//! Two facts about that rule, both of which this module depends on.
//!
//! Its three alternatives collapse to `token "/" token` EXACTLY, and the
//! collapse is a fact about RFC 9110 §5.6.2 rather than a simplification: `*`
//! is a `tchar`, so the two wildcard spellings are already derived by the third
//! alternative. That is why the reader this grades spells its name grammar as a
//! token on each side of one solidus, and why this module can too.
//!
//! And `[ weight ]` adds no string to what `media-range` already derives, since
//! `parameters` repeats without bound and §12.4.2's `qvalue` is a `token`. It
//! is a rule about MEANING — "Recipients SHOULD process any parameter named "q"
//! as weight, regardless of parameter ordering" — so a `q` whose value is no
//! `qvalue` is refused by the reader and derived here, which is a difference
//! between two FIELDS and not between two readings of `parameters`. `main`
//! licenses it as its own axis, counted, for the reason it counts the three
//! differences between §10.1.4 and §5.6.6.
//!
//! # The three questions, and what each is asked ABOUT
//!
//! Issue #77 records an oracle that answered "no reading licenses this" about a
//! quoted-string that was, locally, perfectly admitted, because it asked
//! whether the WHOLE value derives and reported that answer about one offset
//! inside it. So each question below names its subject:
//!
//! - [`Reading::derives`] — some derivation of the **whole** value as
//!   `#element` exists. Asked of the whole value, reported about the whole
//!   value, and about nothing inside it.
//! - [`Reading::element_starts`] — the offsets at which some derivation of a
//!   **prefix** of the value begins a non-empty element. A prefix, not the
//!   whole value: an offset is licensed as a member's start by the bytes in
//!   FRONT of it, and what stands behind it is a different question.
//! - [`Reading::string_data`] — the offsets that lie strictly inside a §5.6.4
//!   `quoted-string` whose DQUOTE stands at a `parameter-value` position some
//!   prefix derivation admits. Also a question about the bytes in front, and
//!   the one that tells a member invented out of a value's own data apart from
//!   a member shown at an offset no reading reaches.
//!
//! # Where the OWS at the value's two ends is admitted, and why
//!
//! §5.6.1.2's expansion hangs every `OWS` it has on a comma, so it admits none
//! in front of the first element and none behind the last. RFC 9110 §5.5 is
//! what admits them, one level up: "A field value does not include leading or
//! trailing whitespace." What reaches a field's walk has therefore already had
//! both ends removed, and grading a value that still carries them against
//! §5.6.1.2 alone would report a divergence about bytes no field value holds.
//! So the walk below starts past the leading `OWS` and ends past the trailing
//! one — the two ends §5.5 names, and nowhere else.
//!
//! # What it does NOT model
//!
//! No reader's own bounds, because none of the three has one over these
//! productions today. If one gains a parameter or member limit, it belongs in
//! the reader's grading and not here: a bound is the reader's refusal, not the
//! grammar's, and an oracle carrying one would be grading a module against
//! itself.

use std::collections::{BTreeSet, HashSet};

/// Which element production a value is read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Production {
  /// RFC 9110 §10.1.4's `transfer-coding` — the element of RFC 9112 §7's
  /// `Transfer-Encoding = #transfer-coding`, and what `TE` names too.
  TransferCoding,
  /// RFC 9110 §5.6.6's `parameters` behind a §5.6.2 `token` head, which is the
  /// member `http_semantics::grammar::parameterised_list` reads under
  /// `ParamSyntax::Parameter`.
  TokenParameters,
  /// RFC 9110 §10.1.1's `expectation`.
  Expectation,
  /// RFC 9110 §12.5.1's `media-range` — the SAME §5.6.6 `parameters`, behind a
  /// `type "/" subtype` head and behind no bracket at all.
  ///
  /// The third head this corpus writes, and the one that makes the §5.6.6
  /// comparison askable about a list of more than one element: §10.1.1 puts its
  /// `parameters` inside a bracket and §12.5.1 does not, so a `media-range` has
  /// the shape [`TokenParameters`](Self::TokenParameters) has — `NAME
  /// parameters` — with the name grammar as the whole of the difference.
  MediaRange,
}

/// What the oracle says about one field value under one production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
  /// Some derivation of the WHOLE value as `#element` exists.
  pub derives: bool,
  /// Offsets at which some derivation of a PREFIX of the value begins a
  /// non-empty element.
  pub element_starts: BTreeSet<usize>,
  /// Offsets strictly inside a §5.6.4 `quoted-string` that opened at a
  /// `parameter-value` position some prefix derivation admits.
  pub string_data: BTreeSet<usize>,
}

impl Reading {
  /// Whether a member a reader began at `at` is one some derivation begins an
  /// element at.
  ///
  /// The question a manufactured member fails: `gzip;;x="a, chunked, b", br`
  /// read under [`Production::TokenParameters`] licenses the `br` behind the
  /// string, and read under [`Production::TransferCoding`] licenses nothing
  /// past `gzip`, because RFC 9110 §10.1.4 brackets no empty slot and so admits
  /// no `parameter-value` for that DQUOTE to stand at.
  pub fn licenses_member_at(&self, at: usize) -> bool {
    self.element_starts.contains(&at)
  }

  /// Whether `at` is one of the offsets some prefix derivation reads as a
  /// quoted-string's data.
  pub fn is_string_data(&self, at: usize) -> bool {
    self.string_data.contains(&at)
  }
}

/// Reads `value` under `production` and answers the three questions.
pub fn read(value: &[u8], production: Production) -> Reading {
  let mut element_starts = BTreeSet::new();
  let mut string_data = BTreeSet::new();
  let mut derives = false;

  // §5.5 removes the field value's leading whitespace, so the list begins past
  // it; §5.6.1.2's own expansion admits none there.
  let first = skip_ows(value, 0);
  let mut seen: HashSet<usize> = HashSet::new();
  let mut queue = vec![first];
  seen.insert(first);

  while let Some(at) = queue.pop() {
    let mut ends = Vec::new();
    element_ends(value, at, production, &mut ends, &mut string_data);
    if !ends.is_empty() {
      element_starts.insert(at);
    }
    // The empty element §5.6.1.2 admits: `[ element ]` with nothing in it.
    // It contributes no element and ends nothing, so the boundary is asked at
    // the very offset the element would have started at.
    for end in std::iter::once(at).chain(ends) {
      match boundary(value, end) {
        Some(Edge::Ends) => derives = true,
        Some(Edge::Next(next)) if seen.insert(next) => queue.push(next),
        Some(Edge::Next(_)) => {}
        None => {}
      }
    }
  }

  Reading {
    derives,
    element_starts,
    string_data,
  }
}

/// Where the element that ended at `end` leaves the list.
enum Edge {
  /// Nothing but the value's trailing whitespace stood behind it, so the value
  /// ends there.
  Ends,
  /// A comma stood behind it, and the next element starts here.
  Next(usize),
}

/// Where an element ending at `end` leaves the list, or `None` when bytes no
/// list construct admits stand behind it.
///
/// RFC 9110 §5.6.1.2 puts `OWS` on both sides of its comma, so the whitespace
/// in front of one belongs to the LIST rather than to whatever read the
/// element; the whitespace in front of the value's END belongs to neither and
/// is RFC 9110 §5.5's, as this module's own doc says.
fn boundary(value: &[u8], end: usize) -> Option<Edge> {
  let at = skip_ows(value, end);
  match value.get(at) {
    None => Some(Edge::Ends),
    Some(&b',') => Some(Edge::Next(skip_ows(value, at.saturating_add(1)))),
    Some(_) => None,
  }
}

/// Every offset an element starting at `at` may end at, appended to `ends`,
/// with every quoted-string interior it passed through recorded in `data`.
///
/// The alternatives inside an element are all decided by the next byte, so this
/// is a walk rather than a search: a `quoted-string` ends at the first
/// unescaped DQUOTE because §5.6.4's `qdtext` excludes DQUOTE, and a `token`
/// takes every `tchar` it can because a `tchar` left behind can begin none of
/// `OWS`, `";"`, `","` or the end of the value. What is genuinely ambiguous is
/// how MANY repetitions of the parameter rule the element took, which is why
/// this reports a set of ends rather than one.
fn element_ends(
  value: &[u8],
  at: usize,
  production: Production,
  ends: &mut Vec<usize>,
  data: &mut BTreeSet<usize>,
) {
  let Some(head_end) = head_end(value, at, production) else {
    return;
  };
  let mut cursor = head_end;

  if production == Production::Expectation {
    // RFC 9110 §10.1.1's
    // `expectation = token [ "=" ( token / quoted-string ) parameters ]`: the
    // bracket closes AFTER `parameters`, so a member with parameters and no
    // argument is not an expectation, and the bare token is the only other
    // reading.
    ends.push(head_end);
    if value.get(head_end) != Some(&b'=') {
      return;
    }
    let Some(after) = argument_end(value, head_end.saturating_add(1), data) else {
      return;
    };
    ends.push(after);
    cursor = after;
  } else {
    // §10.1.4 and §5.6.6 both put the repetition outside any bracket the head
    // is in, so the head alone is an element under either.
    ends.push(head_end);
  }

  // The repetition: `*( OWS ";" OWS transfer-parameter )` for RFC 9110
  // §10.1.4, `*( OWS ";" OWS [ parameter ] )` for §5.6.6, for §10.1.1's tail
  // and for §12.5.1's `media-range`.
  loop {
    let semicolon = skip_ows(value, cursor);
    if value.get(semicolon) != Some(&b';') {
      return;
    }
    let slot = skip_ows(value, semicolon.saturating_add(1));
    let Some(name_end) = token_end(value, slot) else {
      // Only §5.6.6 brackets the slot. §10.1.4 does not, so a `;` that
      // introduces no `transfer-parameter` derives nothing.
      if production == Production::TransferCoding {
        return;
      }
      cursor = semicolon.saturating_add(1);
      ends.push(cursor);
      continue;
    };
    // The `=`, with the BWS §10.1.4 admits on both sides of it and §5.6.6
    // admits on neither.
    let bws = production == Production::TransferCoding;
    let eq = if bws {
      skip_ows(value, name_end)
    } else {
      name_end
    };
    if value.get(eq) != Some(&b'=') {
      return;
    }
    let start = eq.saturating_add(1);
    let start = if bws { skip_ows(value, start) } else { start };
    let Some(after) = argument_end(value, start, data) else {
      return;
    };
    cursor = after;
    ends.push(cursor);
  }
}

/// The end of the element's HEAD at `at` — the piece in front of the `;` every
/// one of these productions repeats.
///
/// RFC 9110 §10.1.4, §5.6.6-behind-a-token and §10.1.1 each head their element
/// with one §5.6.2 `token`; §12.5.1's `media-range` heads it with `type "/"
/// subtype`, which is a token on each side of ONE solidus. A second solidus
/// ends no token — `/` is not a `tchar` — so `a/b/c` heads nothing, which is
/// what the reader this grades says too.
fn head_end(value: &[u8], at: usize, production: Production) -> Option<usize> {
  let end = token_end(value, at)?;
  if production != Production::MediaRange {
    return Some(end);
  }
  if value.get(end) != Some(&b'/') {
    return None;
  }
  token_end(value, end.saturating_add(1))
}

/// The end of one `( token / quoted-string )` at `at`, recording the interior
/// of a quoted-string in `data`.
///
/// `None` where neither alternative derives — an unclosed string, a byte
/// §5.6.4 forbids inside one, or no `tchar` at all.
fn argument_end(value: &[u8], at: usize, data: &mut BTreeSet<usize>) -> Option<usize> {
  if value.get(at) != Some(&b'"') {
    return token_end(value, at);
  }
  match scan_quoted(value, at.saturating_add(1)) {
    Quoted::Closed(end) => {
      // Strictly inside: the two DQUOTEs are the string's own delimiters and
      // not its data.
      for offset in at.saturating_add(1)..end.saturating_sub(1) {
        data.insert(offset);
      }
      Some(end)
    }
    Quoted::Open => {
      // Nothing closes it, so this reading derives no element — and every byte
      // from here to the end of the value is inside the string it opened.
      for offset in at.saturating_add(1)..value.len() {
        data.insert(offset);
      }
      None
    }
    Quoted::Invalid => None,
  }
}

/// How a §5.6.4 quoted-string scan ended.
enum Quoted {
  /// The closing DQUOTE was found; the string ends at this offset.
  Closed(usize),
  /// The value ran out first.
  Open,
  /// A byte §5.6.4's `qdtext` / `quoted-pair` forbids stood inside it.
  Invalid,
}

/// Scans the interior of a RFC 9110 §5.6.4 `quoted-string` from `at`.
fn scan_quoted(value: &[u8], at: usize) -> Quoted {
  let mut at = at;
  let mut escaped = false;
  loop {
    let Some(&byte) = value.get(at) else {
      return Quoted::Open;
    };
    at = at.saturating_add(1);
    // VCHAR is %x21-7E; obs-text is %x80-FF. Together they are every byte a
    // `quoted-pair` may carry behind its backslash, and every `qdtext` byte
    // apart from DQUOTE and the backslash themselves.
    let vchar_or_obs_text = matches!(byte, 0x21..=0x7E | 0x80..=0xFF);
    if escaped {
      if !(byte == b'\t' || byte == b' ' || vchar_or_obs_text) {
        return Quoted::Invalid;
      }
      escaped = false;
      continue;
    }
    match byte {
      b'"' => return Quoted::Closed(at),
      b'\\' => escaped = true,
      _ if byte == b'\t' || byte == b' ' || vchar_or_obs_text => {}
      _ => return Quoted::Invalid,
    }
  }
}

/// RFC 9110 §5.6.2's `tchar`.
///
/// ```text
/// tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
///                / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
///                / DIGIT / ALPHA
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

/// The end of the `token` starting at `at`, or `None` where there is not one —
/// RFC 9110 §5.6.2's `token = 1*tchar` names at least one character.
fn token_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).is_some_and(|&byte| is_tchar(byte)) {
    end = end.saturating_add(1);
  }
  (end > at).then_some(end)
}

/// Past RFC 9110 §5.6.3's `OWS` from `at`.
fn skip_ows(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(&b' ') | Some(&b'\t')) {
    at = at.saturating_add(1);
  }
  at
}
