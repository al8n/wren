//! RFC 9110 §5.6 field grammar over raw byte values.
//!
//! Field NAMES are tokens (§5.6.2 `tchar`); field VALUES are byte strings whose
//! content is `field-vchar` / SP / HTAB with the surrounding OWS stripped
//! (§5.5) — never `str`, because `obs-text` (0x80-0xFF) is legal field content
//! and need not be UTF-8. Everything here works over borrowed bytes: no
//! allocation, no panics, and no state beyond a walk's own cursor.
//!
//! The request-target validators (`is_valid_path_and_query`, `is_valid_query`,
//! `is_valid_authority`) work on `&str` instead: a target is validated ASCII by
//! the time it reaches them, and they enforce the RFC 3986 grammar that
//! RFC 9112 §3.2 builds request-target forms out of.

/// RFC 9110 §5.6.2 `tchar`: a byte that may appear in a token (field names,
/// methods, transfer codings, `Connection` / `Upgrade` list elements).
#[inline]
pub const fn is_token_byte(b: u8) -> bool {
  matches!(b,
    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
    | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// Whether every byte of `s` is a token byte (and `s` is non-empty).
///
/// RFC 9110 §5.6.2 defines `token = 1*tchar`, so the empty string is not a
/// token — an empty field name or an empty coding name is a grammar violation,
/// not a degenerate-but-legal value.
#[inline]
pub fn is_token(s: &[u8]) -> bool {
  !s.is_empty() && s.iter().all(|&b| is_token_byte(b))
}

/// RFC 9110 §5.5 `field-vchar`: `VCHAR` (0x21-0x7E) or `obs-text` (0x80-0xFF).
///
/// Excludes SP and HTAB, which are legal *between* field-vchars but may not
/// start or end a value — see [`validate_field_value`] and [`trim_ows`].
#[inline]
pub const fn is_field_vchar(b: u8) -> bool {
  matches!(b, 0x21..=0x7E | 0x80..=0xFF)
}

/// Validates a raw field value: every byte is `field-vchar`, SP, or HTAB
/// (RFC 9110 §5.5). CTLs — NUL, VT, FF, and in particular a bare CR or LF, which
/// would smuggle a line break into the field section — are rejected.
///
/// The input must already be OWS-trimmed ([`trim_ows`]): SP/HTAB are accepted
/// anywhere here, so leading or trailing whitespace passes rather than being
/// diagnosed. Returns the offset of the first offending byte on error.
#[inline]
pub fn validate_field_value(v: &[u8]) -> Result<(), usize> {
  for (i, &b) in v.iter().enumerate() {
    if !is_field_vchar(b) && b != b' ' && b != b'\t' {
      return Err(i);
    }
  }
  Ok(())
}

/// Trims OWS (SP/HTAB, RFC 9110 §5.6.3) from both ends, returning the subslice.
///
/// OWS around a field value is not part of the value (§5.5), so trimming is
/// mandatory before the value is compared, parsed, or handed to the caller.
#[inline]
pub fn trim_ows(v: &[u8]) -> &[u8] {
  let mut out = v;
  while let Some((&b, rest)) = out.split_first() {
    if b != b' ' && b != b'\t' {
      break;
    }
    out = rest;
  }
  while let Some((&b, rest)) = out.split_last() {
    if b != b' ' && b != b'\t' {
      break;
    }
    out = rest;
  }
  out
}

/// Splits a comma-separated list value into its non-empty, OWS-trimmed
/// elements. RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a
/// reasonable number of empty list elements" — EVERY list consumer routes
/// through here, so the empty-element rule lives in exactly one place instead
/// of being rediscovered per open-coded `split(b',')`.
#[inline]
pub fn list_elements(value: &[u8]) -> impl Iterator<Item = &[u8]> {
  value
    .split(|&b| b == b',')
    .map(trim_ows)
    .filter(|item| !item.is_empty())
}

/// Whether a comma-separated token list contains `token`
/// (ASCII case-insensitive, OWS-tolerant) — e.g. `Connection: keep-alive, Upgrade`.
#[inline]
pub fn token_list_contains(value: &[u8], token: &str) -> bool {
  list_elements(value).any(|item| eq_ignore_ascii(item, token))
}

/// ASCII case-insensitive equality between a raw byte string and a known token.
///
/// Field names and the tokens defined by the specification are ASCII, so this
/// is the comparison RFC 9110 §5.6.2 and §5.1 call for; bytes outside ASCII
/// compare exactly, which is what a non-token value should do.
#[inline]
pub fn eq_ignore_ascii(a: &[u8], b: &str) -> bool {
  a.eq_ignore_ascii_case(b.as_bytes())
}

/// RFC 3986 `pchar` byte (plus `/`): what may appear literally in a URI
/// path segment. Everything else — including `#`, which is a fragment
/// delimiter and never part of a request-target — must arrive `%XX`-escaped.
const fn is_path_byte(b: u8) -> bool {
  matches!(b,
    // unreserved
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    // sub-delims
    | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    // pchar extras + segment separator
    | b':' | b'@' | b'/')
}

/// Validates an origin-form request-target's path-and-query string
/// (RFC 9112 §3.2.1) against the RFC 3986 grammar: a leading `/`, `pchar`/`/`
/// bytes in the path, `pchar`/`/`/`?` bytes after the first `?`, and `%` only
/// as `%XX` percent-escapes. A fragment is not part of a request-target, so a
/// raw `#` is rejected in both parts.
pub fn is_valid_path_and_query(s: &str) -> bool {
  s.starts_with('/') && valid_pq_bytes(s.bytes(), false)
}

/// Validates bare query bytes (everything after the `?`) under the same
/// grammar — for the absolute-form `http://host?q` shape, whose path-and-query
/// `/?q` is assembled positionally rather than borrowed.
pub fn is_valid_query(s: &str) -> bool {
  valid_pq_bytes(s.bytes(), true)
}

/// RFC 3986 §3.2.2 `reg-name` byte: unreserved / sub-delims (pct-escapes
/// handled by the caller). URI delimiters (`/ ? # @ :`) are NOT host bytes.
const fn is_reg_name_byte(b: u8) -> bool {
  matches!(b,
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
}

/// Validates a `Host:` value / authority-form target against the RFC 3986
/// §3.2.2 authority grammar (no userinfo, per RFC 9110 §7.2): a `reg-name` or a
/// bracketed IP-literal, then an optional `":" *DIGIT` port. An authority is
/// not a URL — `/`, `?`, `#`, `@`, whitespace, and controls are all out.
///
/// Non-empty-strict: an empty string is rejected here. RFC 9112 §3.2 does allow
/// an EMPTY `Host` field value for a target that carries no authority, and that
/// allowance is applied by the message-validation layer, which short-circuits
/// an empty value as legal before calling this.
pub fn is_valid_authority(s: &str) -> bool {
  let port = match s.strip_prefix('[') {
    // IP-literal: a real IPv6address or IPvFuture (RFC 3986 §3.2.2) — a
    // byte filter is not enough (`[127.0.0.1]` and `[::::]` are not
    // addresses; `[v1.a]` is).
    Some(rest) => {
      let Some((lit, after)) = rest.split_once(']') else {
        return false;
      };
      if !is_valid_ipv6(lit) && !is_valid_ipvfuture(lit) {
        return false;
      }
      if after.is_empty() {
        return true;
      }
      let Some(port) = after.strip_prefix(':') else {
        return false;
      };
      port
    }
    // reg-name [":" port] — a reg-name carries no `:`, so the LAST colon
    // starts the port and any earlier colon fails the byte check below.
    None => {
      let (host, port) = match s.rsplit_once(':') {
        Some((host, port)) => (host, port),
        None => (s, ""),
      };
      if host.is_empty() {
        return false;
      }
      let mut pending_hex: u8 = 0;
      for b in host.bytes() {
        if pending_hex > 0 {
          if !b.is_ascii_hexdigit() {
            return false;
          }
          pending_hex = pending_hex.saturating_sub(1);
          continue;
        }
        match b {
          b'%' => pending_hex = 2,
          _ if is_reg_name_byte(b) => {}
          _ => return false,
        }
      }
      if pending_hex > 0 {
        return false;
      }
      port
    }
  };
  // `port = *DIGIT` — empty is grammatically legal ("example.com:").
  port.bytes().all(|b| b.is_ascii_digit())
}

/// RFC 3986 `IPv6address`: up to 8 16-bit hex groups, at most one `::`
/// compression (standing for one or more zero groups), optionally an
/// IPv4 dotted-quad as the last two groups.
fn is_valid_ipv6(s: &str) -> bool {
  let (head, tail, compressed) = match s.split_once("::") {
    Some((head, tail)) => {
      if tail.contains("::") {
        return false; // a second `::`
      }
      (head, tail, true)
    }
    None => (s, "", false),
  };
  // Counts the h16 groups in one side; a trailing dotted-quad counts as 2.
  let count_groups = |part: &str, v4_may_end: bool| -> Option<usize> {
    if part.is_empty() {
      return Some(0);
    }
    let mut n = 0usize;
    let mut groups = part.split(':').peekable();
    while let Some(group) = groups.next() {
      let last = groups.peek().is_none();
      if group.is_empty() {
        return None; // `:` at an edge, or `:::`
      }
      if last && v4_may_end && group.contains('.') {
        if !is_valid_ipv4(group) {
          return None;
        }
        n = n.saturating_add(2);
      } else {
        if group.len() > 4 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
          return None;
        }
        n = n.saturating_add(1);
      }
    }
    Some(n)
  };
  // Without compression the dotted-quad (if any) ends the whole address —
  // i.e. it sits at the end of `head`; with compression it ends `tail`.
  let Some(head_groups) = count_groups(head, !compressed) else {
    return false;
  };
  let Some(tail_groups) = count_groups(tail, true) else {
    return false;
  };
  let total = head_groups.saturating_add(tail_groups);
  if compressed {
    total <= 7 // `::` expands to at least one more group
  } else {
    total == 8
  }
}

/// RFC 3986 `dec-octet` ×4: 0–255, no leading zeros.
fn is_valid_ipv4(s: &str) -> bool {
  let mut octets = 0usize;
  for octet in s.split('.') {
    octets = octets.saturating_add(1);
    if octet.is_empty()
      || octet.len() > 3
      || !octet.bytes().all(|b| b.is_ascii_digit())
      || (octet.len() > 1 && octet.starts_with('0'))
    {
      return false;
    }
    match octet.parse::<u16>() {
      Ok(v) if v <= 255 => {}
      _ => return false,
    }
  }
  octets == 4
}

/// RFC 3986 `IPvFuture`: `v` 1*HEXDIG `.` 1*(unreserved / sub-delims / ":")
/// (ABNF literals are case-insensitive, so `V` matches too).
fn is_valid_ipvfuture(s: &str) -> bool {
  let Some(rest) = s.strip_prefix(['v', 'V']) else {
    return false;
  };
  let Some((version, tail)) = rest.split_once('.') else {
    return false;
  };
  !version.is_empty()
    && version.bytes().all(|b| b.is_ascii_hexdigit())
    && !tail.is_empty()
    && tail.bytes().all(|b| is_reg_name_byte(b) || b == b':')
}

fn valid_pq_bytes(bytes: impl Iterator<Item = u8>, mut in_query: bool) -> bool {
  let mut pending_hex: u8 = 0;
  for b in bytes {
    if pending_hex > 0 {
      if !b.is_ascii_hexdigit() {
        return false;
      }
      pending_hex = pending_hex.saturating_sub(1);
      continue;
    }
    match b {
      b'%' => pending_hex = 2,
      b'?' if !in_query => in_query = true,
      b'?' => {} // additional `?` is legal query data (RFC 3986 §3.4)
      _ if is_path_byte(b) => {}
      _ => return false,
    }
  }
  pending_hex == 0
}

/// Skips RFC 9110 §5.6.3 `OWS` (and `BWS`, which §5.6.3 defines as the same
/// bytes) from `at`, returning where the next element begins.
pub(crate) fn skip_ows(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(b' ' | b'\t')) {
    at = at.saturating_add(1);
  }
  at
}

/// The end of the RFC 9110 §5.6.2 `token` starting at `at`, or `None` when there
/// is not one — `token = 1*tchar`, so an empty run is not a token.
pub(crate) fn token_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).copied().is_some_and(is_token_byte) {
    end = end.saturating_add(1);
  }
  (end > at).then_some(end)
}

/// Where a RFC 9110 §5.6.4 `quoted-string` scan got to.
///
/// [`Open`](Self::Open) exists because a field's value may arrive as several
/// field lines: RFC 9110 §5.2 makes them ONE value joined by commas, and a comma
/// inside a quoted-string is DATA — so a string opened on one line legitimately
/// continues into the next, with the join's comma as one of its characters. A
/// scanner that restarted at each physical line would call that value
/// unterminated and derive the wrong facts from it.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum QuotedScan {
  /// The string closed; the offset is just past its DQUOTE.
  Closed(usize),
  /// The input ended with the string still open.
  Open {
    /// The last byte was a backslash whose escaped byte has not arrived, so the
    /// NEXT byte is data whatever it is — including a DQUOTE, which must not be
    /// read as the close.
    escape: bool,
  },
  /// A byte §5.6.4's grammar forbids inside a quoted-string.
  Invalid,
}

/// RFC 9110 §5.2's separator, as a value: the field lines of one field are
/// "concatenated in order, with each field line value separated by a comma".
///
/// One comma and nothing else. §5.3 lets a recipient add OWS "for consistency"
/// when it REWRITES a section, but the combined VALUE §5.2 defines has none, and
/// a parser that invented one would put a space inside a quoted string that
/// spans the join.
const JOIN: &[u8] = b",";

/// Resumes a §5.6.4 quoted-string left open by the previous field line, at the
/// first byte of the NEXT one.
///
/// The separator is fed THROUGH the open string first, and that is the whole
/// point of the function: inside a quoted-string §5.2's comma is `qdtext` — or,
/// when the previous line ended on a backslash, it is the character that
/// `quoted-pair` escapes. Resuming at the next line's first byte with the
/// pending escape still set hands that escape to the wrong character, so
/// `p="a\` + `", chunked` (a legal value: the backslash escapes the join comma
/// and the quote then closes) was read as unterminated, and `p="a\` +
/// `\", chunked` (unterminated: the backslash escapes the quote) was read as a
/// closed string with a final `chunked` behind it. Either way the two ends
/// disagree about where the message stops.
///
/// Written as a scan of the actual separator rather than as the constant it
/// works out to, so the reasoning is not something a later reader has to
/// reconstruct — and so it stays correct if `JOIN` ever changes.
pub(crate) fn scan_quoted_after_join(value: &[u8], escape: bool) -> QuotedScan {
  match scan_quoted(JOIN, 0, escape) {
    // The only reachable arm: one comma is data inside a quoted-string whether
    // or not an escape was pending, so the string is still open at the start of
    // the next line — with no escape left over, because the comma consumed it.
    QuotedScan::Open { escape } => scan_quoted(value, 0, escape),
    // Unreachable for a lone comma, and answered rather than asserted away.
    settled => settled,
  }
}

/// Scans the INTERIOR of a §5.6.4 quoted-string from `at`, given whether the
/// previous byte was an unconsumed backslash.
///
/// ```text
/// quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// qdtext        = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
/// ```
///
/// `qdtext` deliberately excludes DQUOTE and the backslash, which is why each is
/// reached only through its own arm: `"a\"b"` is ONE string containing a quote,
/// and a reader that stopped at the second DQUOTE would resume parsing inside
/// quoted data.
pub(crate) fn scan_quoted(value: &[u8], at: usize, escape: bool) -> QuotedScan {
  let mut at = at;
  let mut escape = escape;
  loop {
    let Some(&byte) = value.get(at) else {
      return QuotedScan::Open { escape };
    };
    at = at.saturating_add(1);
    if escape {
      // `quoted-pair`: this byte is data whatever it is.
      if !(byte == b'\t' || byte == b' ' || is_field_vchar(byte)) {
        return QuotedScan::Invalid;
      }
      escape = false;
      continue;
    }
    match byte {
      b'"' => return QuotedScan::Closed(at),
      b'\\' => escape = true,
      b if b == b'\t' || b == b' ' || is_field_vchar(b) => {}
      _ => return QuotedScan::Invalid,
    }
  }
}

/// The end of the §5.6.4 `quoted-string` whose opening DQUOTE is at `at`, or
/// `None` when it is unterminated within this input or carries a forbidden byte.
///
/// The single-value convenience over [`scan_quoted`], for the callers that have
/// the whole value in hand.
pub(crate) fn quoted_string_end(value: &[u8], at: usize) -> Option<usize> {
  if value.get(at) != Some(&b'"') {
    return None;
  }
  match scan_quoted(value, at.saturating_add(1), false) {
    QuotedScan::Closed(end) => Some(end),
    QuotedScan::Open { .. } | QuotedScan::Invalid => None,
  }
}

/// The end of one top-level element of a `#`-list starting at `at`, respecting
/// quoted-strings.
///
/// The whole reason this is not `split(b',')`: RFC 9110 §5.6.1's list construct
/// separates elements with commas, but a comma INSIDE a §5.6.4 quoted-string is
/// data. A splitter that cuts there turns one element into two, and for a
/// parameterised list that can invent a coding the sender never named — which is
/// two recipients disagreeing about where the message ends (RFC 9112 §11.1).
///
/// `None` when a quoted-string in the element is unterminated or malformed, which
/// makes the whole field unusable rather than silently truncated.
pub(crate) fn list_element_end(value: &[u8], at: usize) -> Option<usize> {
  let mut at = at;
  loop {
    match value.get(at) {
      None | Some(b',') => return Some(at),
      Some(b'"') => at = quoted_string_end(value, at)?,
      Some(_) => at = at.saturating_add(1),
    }
  }
}

/// What one field-line value is, as a list, to a SENDER.
///
/// Three answers rather than two, because "no empty element" is a fact ABOUT a
/// list and a value whose §5.6.4 quoted-string never closes is not one — there
/// is no element boundary in it to call empty or full. Folding the two together
/// reported an unterminated quote as §5.6.1.1's empty element, which named a
/// rule the caller had not broken.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListShape {
  /// `1#element` with every element present.
  Sendable,
  /// A leading comma, a trailing one, two in a row, or an empty value: RFC 9110
  /// §5.6.1.1's "a sender MUST NOT generate empty list elements".
  EmptyElement,
  /// Not a list at all — a quoted-string opens and never closes, so the value
  /// ends inside one and its commas were never separators.
  Unparseable,
}

/// The SHAPE of a list a sender proposes to generate.
///
/// RFC 9110 §5.6.1.1: "In any production that uses the list construct, a sender
/// MUST NOT generate empty list elements", i.e. `1#element => element *( OWS ","
/// OWS element )`. So no leading comma, no trailing comma, no two in a row, and
/// not an empty value.
///
/// The counterpart to [`list_elements`], which DROPS empty elements because
/// §5.6.1.2 makes a recipient ignore them. Recipient tolerance is not a licence
/// to emit: this core reads `,chunked` and writes it never. Quote-aware, so a
/// comma inside a §5.6.4 quoted-string is data here too.
///
/// This checks the list's SHAPE. What each element must BE is the field's own
/// grammar, checked beside it.
pub(crate) fn sender_list_shape(value: &[u8]) -> ListShape {
  let mut at = 0usize;
  loop {
    let Some(end) = list_element_end(value, at) else {
      return ListShape::Unparseable;
    };
    if trim_ows(value.get(at..end).unwrap_or_default()).is_empty() {
      return ListShape::EmptyElement;
    }
    if value.get(end).is_none() {
      return ListShape::Sendable;
    }
    at = end.saturating_add(1);
  }
}

/// SENDER side: every non-empty member of this value is a bare RFC 9110 §5.6.2
/// `token`, and the value names at least one.
///
/// RFC 9110 §7.6.1's `connection-option = token` admits no argument, no
/// parameter and no quoted-string, so anything else means the value is not a
/// `Connection` header — and this core will not write one whose meaning a
/// recipient cannot read.
pub(crate) fn is_sender_token_list(value: &[u8]) -> bool {
  let mut at = 0usize;
  let mut named = false;
  loop {
    at = skip_ows(value, at);
    if !matches!(value.get(at), None | Some(b',')) {
      let Some(end) = token_end(value, at) else {
        return false;
      };
      named = true;
      at = skip_ows(value, end);
      if !matches!(value.get(at), None | Some(b',')) {
        return false;
      }
    }
    if value.get(at).is_none() {
      return named;
    }
    at = at.saturating_add(1);
  }
}

/// RFC 9110 §10.1.1's `Expect`, parsed as ONE value across every field line of
/// the section.
///
/// ```text
/// Expect      = #expectation
/// expectation = token [ "=" ( token / quoted-string ) parameters ]
/// parameters  = *( OWS ";" OWS [ parameter ] )        ; §5.6.6
/// parameter   = parameter-name "=" parameter-value
/// ```
///
/// Note WHERE the brackets are: `parameters` sits INSIDE the optional group, so
/// a member carrying a parameter without an argument (`ext;flag`) is not an
/// `expectation` at all. Note also what is absent: `parameter` has no BWS around
/// its `=`, unlike §7's `transfer-parameter`, so `ext = value` is not one
/// either. Both were accepted by the per-line sender check this replaces.
///
/// ONE parser for BOTH directions, with the two roles taking different facts out
/// of the same parse — the shape this crate settled on for every field it
/// interprets. A recipient reads §5.6.1.2's tolerance of empty elements and
/// §10.1.1's 417 for a member it cannot parse; a sender reads §5.6.1.1's
/// prohibition and is refused outright. Neither re-walks the value with rules of
/// its own, and neither can disagree with the other about what the value SAYS.
///
/// Every fact is PROVISIONAL until the whole combined value has been pushed:
/// `100-continue` is derived by [`expects_continue`](Self::expects_continue),
/// which asks [`parsed`](Self::parsed) first. Committing the fact the moment one
/// member parsed is what let `Expect: 100-continue, @` — a value that fails the
/// field's grammar — still deliver the ask.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Expectations {
  /// A `quoted-string` still open when the last field line ended, carrying the
  /// escape state §5.2's join comma will be fed through.
  open: Option<bool>,
  /// PROVISIONAL: some member parsed WHOLE as the bare `100-continue`.
  bare: bool,
  /// PROVISIONAL: some member parsed and was not that.
  other: bool,
  /// Some member did not parse, so nothing may be derived from the value.
  malformed: bool,
  /// Some element of the COMBINED list was empty — §5.6.1.1's prohibition for a
  /// sender, §5.6.1.2's "parse and ignore" for a recipient.
  saw_empty: bool,
  /// The parse is positioned where an element must appear: at the start, and
  /// after every comma. True at the end of the value means a trailing empty
  /// element.
  expecting: bool,
  /// Some field line was pushed, so the field is PRESENT. Distinguishes "the
  /// caller stated `Expect:` with nothing in it" from "the caller stated no
  /// `Expect` at all", which are the same accumulator otherwise.
  present: bool,
  /// Some member parsed. §5.6.1.1's `1#element` needs one.
  any: bool,
}

/// Where parsing one member's `parameters` got to.
enum Params {
  /// Ended at this offset.
  Ended(usize),
  /// A quoted parameter value is open and continues on the next field line.
  Suspended,
  /// The member does not parse.
  Malformed,
}

impl Default for Expectations {
  /// The `Default` a `KeyFields` derives, which is [`new`](Self::new) rather
  /// than a field-wise zero: `expecting` starts TRUE, and a derived default
  /// would start the parse in the middle of a list it has not seen.
  fn default() -> Self {
    Self::new()
  }
}

impl Expectations {
  pub(crate) const fn new() -> Self {
    Self {
      open: None,
      bare: false,
      other: false,
      malformed: false,
      saw_empty: false,
      // `#element` starts where an element may appear, so an entirely empty
      // value ends there too — which is exactly the empty element §5.6.1.1
      // forbids a sender to generate.
      expecting: true,
      present: false,
      any: false,
    }
  }

  /// Whether the whole combined value parsed.
  ///
  /// A string still open when the LAST line ended is not parsed either: §5.2 has
  /// no further line to continue it with.
  pub(crate) const fn parsed(&self) -> bool {
    !self.malformed && self.open.is_none()
  }

  /// RFC 9110 §10.1.1's one defined expectation, derived only from a value that
  /// parsed whole.
  pub(crate) const fn expects_continue(&self) -> bool {
    self.parsed() && self.bare
  }

  /// Whether the value states an expectation this core does not implement —
  /// §10.1.1's 417.
  ///
  /// A value that did not parse counts as one: §10.1.1 makes an unrecognised
  /// expectation a 417 rather than a framing fault, so a recipient answers
  /// rather than failing the connection.
  pub(crate) const fn has_other(&self) -> bool {
    !self.parsed() || self.other
  }

  /// SENDER side: the field is present and some element of it is empty
  /// (§5.6.1.1), counting a value that names nothing at all.
  pub(crate) const fn empty_element(&self) -> bool {
    // `parsed` first: an element BOUNDARY is a fact about a value that parsed,
    // and a value ending inside an open `quoted-string` has none to call empty.
    // Reporting one as §5.6.1.1's empty element named a rule the caller had not
    // broken — the same confusion `ListShape::Unparseable` exists to prevent.
    self.present && self.parsed() && (self.saw_empty || self.expecting)
  }

  /// SENDER side: the field is present and did not parse.
  pub(crate) const fn grammar_fault(&self) -> bool {
    self.present && !self.parsed()
  }

  /// Folds one `Expect` field line into the value.
  pub(crate) fn push(&mut self, value: &[u8]) {
    if self.malformed {
      // Nothing further may be derived from a value that did not parse.
      return;
    }
    let joined = self.present;
    self.present = true;
    let mut at = 0usize;
    match self.open.take() {
      Some(escape) => match scan_quoted_after_join(value, escape) {
        QuotedScan::Open { escape } => {
          self.open = Some(escape);
          return;
        }
        QuotedScan::Invalid => {
          self.malformed = true;
          return;
        }
        QuotedScan::Closed(end) => match self.parameters(value, end) {
          Params::Ended(next) => match self.end_member(value, next) {
            Some(next) => at = next,
            None => return,
          },
          Params::Suspended => return,
          Params::Malformed => {
            self.malformed = true;
            return;
          }
        },
      },
      // Not inside a string: §5.2's comma is the SEPARATOR, so it opens a new
      // element — and if one was already expected, the element between the two
      // commas is empty.
      None if joined => {
        self.saw_empty |= self.expecting;
        self.expecting = true;
      }
      None => {}
    }

    loop {
      at = skip_ows(value, at);
      match value.get(at) {
        // The end of this field line. Whether an element is still expected is
        // answered by the NEXT line's join, or by `empty_element` if there is
        // no next line.
        None => return,
        Some(b',') => {
          self.saw_empty |= self.expecting;
          self.expecting = true;
          at = at.saturating_add(1);
          continue;
        }
        Some(_) => {}
      }
      let Some(name_end) = token_end(value, at) else {
        self.malformed = true;
        return;
      };
      let bare = eq_ignore_ascii(value.get(at..name_end).unwrap_or_default(), "100-continue");
      at = name_end;
      // `[ "=" ( token / quoted-string ) parameters ]`. The `=` is IMMEDIATE:
      // §10.1.1's production has neither OWS nor BWS around it, and a member
      // carrying a parameter and no argument is not an `expectation`.
      if value.get(at) == Some(&b'=') {
        // Whatever the argument turns out to be, this member is not the bare
        // token §10.1.1 defines.
        self.other = true;
        let argument = at.saturating_add(1);
        match self.argument(value, argument) {
          Params::Ended(next) => at = next,
          Params::Suspended => {
            self.expecting = false;
            return;
          }
          Params::Malformed => {
            self.malformed = true;
            return;
          }
        }
        match self.parameters(value, at) {
          Params::Ended(next) => at = next,
          Params::Suspended => {
            self.expecting = false;
            return;
          }
          Params::Malformed => {
            self.malformed = true;
            return;
          }
        }
      } else if bare {
        self.bare = true;
      } else {
        self.other = true;
      }
      match self.end_member(value, at) {
        Some(next) => at = next,
        None => return,
      }
    }
  }

  /// One `( token / quoted-string )`, which is both an argument and a
  /// `parameter-value`.
  fn argument(&mut self, value: &[u8], at: usize) -> Params {
    if value.get(at) != Some(&b'"') {
      return match token_end(value, at) {
        Some(end) => Params::Ended(end),
        None => Params::Malformed,
      };
    }
    match scan_quoted(value, at.saturating_add(1), false) {
      QuotedScan::Closed(end) => Params::Ended(end),
      QuotedScan::Open { escape } => {
        self.open = Some(escape);
        Params::Suspended
      }
      QuotedScan::Invalid => Params::Malformed,
    }
  }

  /// `parameters = *( OWS ";" OWS [ parameter ] )`.
  fn parameters(&mut self, value: &[u8], at: usize) -> Params {
    let mut at = at;
    loop {
      let semicolon = skip_ows(value, at);
      if value.get(semicolon) != Some(&b';') {
        return Params::Ended(at);
      }
      at = skip_ows(value, semicolon.saturating_add(1));
      let Some(name_end) = token_end(value, at) else {
        // `[ parameter ]`: §5.6.6 admits an empty one.
        at = semicolon.saturating_add(1);
        continue;
      };
      // `parameter = parameter-name "=" parameter-value`: the `=` is required
      // and immediate.
      if value.get(name_end) != Some(&b'=') {
        return Params::Malformed;
      }
      match self.argument(value, name_end.saturating_add(1)) {
        Params::Ended(end) => at = end,
        suspended_or_bad => return suspended_or_bad,
      }
    }
  }

  /// The tail every member shares: `#rule` puts OWS and a comma — or the end of
  /// the value — after one, and nothing else.
  fn end_member(&mut self, value: &[u8], at: usize) -> Option<usize> {
    let at = skip_ows(value, at);
    if !matches!(value.get(at), None | Some(b',')) {
      self.malformed = true;
      return None;
    }
    self.any = true;
    self.expecting = false;
    Some(at)
  }
}

/// RFC 9110 §7.8 `Upgrade = #protocol`, asked as a SENDER: this one field-line
/// value names at least one protocol and every element of it is well formed.
///
/// Per LINE, and strict about empty elements, because that is what §5.6.1.1
/// requires of a sender: "In any production that uses the list construct, a
/// sender MUST NOT generate empty list elements". A caller handing this core an
/// `Upgrade:` with nothing in it is asking it to put an empty element on the
/// wire, and this refuses.
///
/// The RECIPIENT side is [`lists_a_protocol`], and it is deliberately more
/// tolerant. The two are not an inconsistency: §5.6.1.1 and §5.6.1.2 are
/// adjacent sections stating opposite MUSTs for the two roles, and this core
/// implements both.
pub(crate) fn is_protocol_list(value: &[u8]) -> bool {
  let mut named = false;
  for element in list_elements(value) {
    if !is_protocol(element) {
      return false;
    }
    named = true;
  }
  named
}

/// The same production asked as a RECIPIENT, over the COMBINED value of every
/// `Upgrade` field line the message carried.
///
/// RFC 9110 §5.2 makes repeated field lines one comma-separated list, so the
/// question can only be answered once, over all of them — a per-line reading
/// splits one list into several and asks each to satisfy the whole grammar. For
/// `Upgrade:` followed by `Upgrade: websocket` the combined value is
/// `, websocket`, which §5.6.1.2's own examples make VALID: it shows
/// `"foo , ,bar,charlie"` as a legal `1#element` and only `""`, `","` and
/// `",   ,"` as invalid, "since at least one non-empty element is required".
///
/// So the cardinality is global. Empty elements never contribute to it, and
/// §5.6.1.2 says why: "A recipient MUST parse and ignore a reasonable number of
/// empty list elements", which [`list_elements`] does by dropping them — while a
/// NON-empty element that is not a `protocol` still fails the list.
pub(crate) fn lists_a_protocol<'a>(values: impl Iterator<Item = &'a [u8]>) -> bool {
  let mut named = false;
  for value in values {
    for element in list_elements(value) {
      if !is_protocol(element) {
        return false;
      }
      named = true;
    }
  }
  named
}

/// RFC 9110 §7.8 `protocol = protocol-name ["/" protocol-version]`, both of them
/// `token`s (§5.6.2).
fn is_protocol(element: &[u8]) -> bool {
  match element.iter().position(|&b| b == b'/') {
    Some(at) => match (element.get(..at), element.get(at.saturating_add(1)..)) {
      (Some(name), Some(version)) => is_token(name) && is_token(version),
      _ => false,
    },
    None => is_token(element),
  }
}

/// Why a parameterised-list walk stopped.
///
/// The first three are grammar violations the sender committed, and the value
/// they describe cannot be read by anyone. The fourth is not: it names a value
/// that is perfectly well formed and that a walker borrowing its input cannot
/// hand over, which is a fact about this walk rather than about the field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ListError {
  /// A member name, a parameter name, or a bare parameter value is not the
  /// `token` RFC 9110 §5.6.2 defines — the empty string included, since
  /// `token = 1*tchar` names at least one character.
  #[error("member name, parameter name, or bare value is not a token")]
  NotAToken,
  /// A quoted-string was never closed (RFC 9110 §5.6.4). Asked of the WHOLE
  /// value: a string left open by one field line may still close on the next
  /// one §5.2 joins to it, and only a string open when the last line ends is
  /// unterminated.
  #[error("quoted-string is never closed")]
  UnterminatedQuotedString,
  /// A byte RFC 9110 §5.6.4's `qdtext` / `quoted-pair` grammar forbids appeared
  /// inside a quoted-string.
  #[error("byte forbidden inside a quoted-string")]
  InvalidQuotedByte,
  /// The value is a quoted-string that spans an RFC 9110 §5.2 field-line join,
  /// so its content is not one contiguous slice and cannot be borrowed. The
  /// member's boundaries are still correct; only this value is unreadable.
  #[error("quoted value spans a field-line join and is not one contiguous slice")]
  ValueSpansFieldLines,
}

/// A parameter's value: a bare token, or the CONTENT of a quoted-string with
/// its escapes still in place.
///
/// RFC 9110 §5.6.4 defines the `quoted-pair` escape but leaves what the
/// unescaped value MEANS to the field that used it — RFC 6455 §9.1, for one,
/// requires the unescaped form to be a `token` — so unescaping belongs to the
/// caller and this hands over exactly the bytes between the delimiting DQUOTEs.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParamValue<'a> {
  /// The parameter carried no `=`. RFC 9110 §5.6.6's `parameter` requires one;
  /// the fields whose parameters are optional-valued write that themselves, as
  /// RFC 6455 §9.1's `extension-param = token [ "=" (token | quoted-string) ]`
  /// does.
  None,
  /// A bare token (RFC 9110 §5.6.2).
  Token(&'a [u8]),
  /// The interior of a quoted-string (RFC 9110 §5.6.4), escapes untouched.
  Quoted(&'a [u8]),
}

/// Walks a parameter value with its RFC 9110 §5.6.4 `quoted-pair` escapes
/// removed. Total over any value the walker produced: a `quoted-pair`'s
/// backslash is only accepted with an octet behind it, so the lookahead below
/// can only run off the end of a value this crate did not validate.
struct Unescaped<'a> {
  bytes: &'a [u8],
  at: usize,
  quoted: bool,
}

impl Iterator for Unescaped<'_> {
  type Item = u8;

  fn next(&mut self) -> Option<u8> {
    let byte = *self.bytes.get(self.at)?;
    if self.quoted && byte == b'\\' {
      let escaped = *self.bytes.get(self.at.saturating_add(1))?;
      self.at = self.at.saturating_add(2);
      return Some(escaped);
    }
    self.at = self.at.saturating_add(1);
    Some(byte)
  }
}

impl<'a> ParamValue<'a> {
  /// The bytes as the walker found them: a token's own, a quoted-string's
  /// interior with escapes intact, or none at all.
  const fn raw(self) -> &'a [u8] {
    match self {
      Self::None => &[],
      Self::Token(bytes) | Self::Quoted(bytes) => bytes,
    }
  }

  /// The value with its `quoted-pair` escapes removed.
  ///
  /// RFC 9110 §5.6.4: "Recipients that process the value of a quoted-string
  /// MUST handle a quoted-pair as if it were replaced by the octet following
  /// the backslash." Removing them leaves a value that is not one contiguous
  /// slice, which is why this yields bytes rather than returning `&[u8]`.
  ///
  /// [`Token`](Self::Token) yields its bytes unchanged — a `token` carries no
  /// backslash — and [`None`](Self::None) yields nothing.
  #[inline]
  pub fn unescaped(self) -> impl Iterator<Item = u8> + 'a {
    Unescaped {
      bytes: self.raw(),
      at: 0,
      quoted: matches!(self, Self::Quoted(_)),
    }
  }

  /// [`unescaped`](Self::unescaped) written into a caller-supplied slice,
  /// returning the number of bytes written.
  ///
  /// Two passes: the length is counted before anything is written, so a call
  /// that does not fit writes NOTHING and leaves `out` as it found it.
  ///
  /// # Errors
  ///
  /// [`crate::Error::BufferTooSmall`] when `out` is shorter than the
  /// unescaped value.
  pub fn unescape_into(self, out: &mut [u8]) -> Result<usize, crate::Error> {
    let need = self.unescaped().count();
    if need > out.len() {
      return Err(crate::Error::BufferTooSmall {
        need,
        have: out.len(),
      });
    }
    for (slot, byte) in out.iter_mut().zip(self.unescaped()) {
      *slot = byte;
    }
    Ok(need)
  }

  /// Whether the unescaped value equals `s`, ASCII-case-insensitively — the
  /// common question ("is this charset utf-8?") answered without a buffer.
  ///
  /// Case folding here is the CALLER's assertion about this parameter, not
  /// this crate's: RFC 9110 §5.6.6 says "Parameter values might or might not
  /// be case-sensitive, depending on the semantics of the parameter name."
  pub fn eq_unescaped_ignore_ascii_case(self, s: &str) -> bool {
    let mut want = s.as_bytes().iter();
    for got in self.unescaped() {
      match want.next() {
        Some(byte) if got.eq_ignore_ascii_case(byte) => {}
        _ => return false,
      }
    }
    want.next().is_none()
  }
}

/// One member of a parameterised `#`-list: a name and its parameters, with
/// quoted-string values kept intact.
///
/// `PartialEq` is over these bytes as written, not the parsed parameters:
/// `params` is the untrimmed remainder after the member's first `;`, so
/// `ext; q=1` and `ext;  q=1` compare unequal here even though both walk to
/// the same `(name, ParamValue)` pairs through [`params`](ListMember::params).
/// A caller wanting that value equality compares `params()`'s output instead.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ListMember<'a> {
  name: &'a [u8],
  params: &'a [u8],
  tail: QuotedTail,
}

impl<'a> ListMember<'a> {
  /// The member's leading token, OWS-trimmed — RFC 9110 §5.6.3's whitespace
  /// around a list element is not part of it.
  #[inline]
  pub const fn name(&self) -> &'a [u8] {
    self.name
  }

  /// The parameters that followed it, `*( OWS ";" OWS [ parameter ] )`
  /// (RFC 9110 §5.6.6).
  #[inline]
  pub const fn params(&self) -> ParamIter<'a> {
    ParamIter {
      params: self.params,
      at: 0,
      tail: self.tail,
      done: false,
    }
  }
}

/// Walks a parameterised `#`-list spread over one or more field lines, splitting
/// it on the commas that are NOT inside a quoted-string.
///
/// RFC 9110 §5.6.1's list construct separates members with commas and §5.6.6
/// gives each member its `parameters`, so neither `split(b',')` nor
/// [`list_elements`] can read one: a comma inside a §5.6.4 quoted-string is
/// data, and a splitter that cuts there invents a member the sender never
/// named. Empty members are skipped rather than reported — §5.6.1.2 makes a
/// recipient "parse and ignore a reasonable number of empty list elements".
///
/// Pass one line as `[value]`; pass a field's several lines in wire order and
/// they are walked as the single value RFC 9110 §5.2 defines, "concatenated in
/// order, with each field line value separated by a comma". The join is walked
/// rather than materialised: nothing is allocated and every slice handed out
/// borrows the input.
///
/// # The join's comma
///
/// Inside an open quoted-string that comma is DATA, so a string opened on one
/// field line legitimately continues into the next. This walk crosses the join
/// through `scan_quoted_after_join` — the crate's one implementation of that
/// rule — rather than restarting the scan at each physical line. A restart
/// would call such a value unterminated and put the member boundary in the
/// wrong place, which is two recipients disagreeing about what the field says.
///
/// The one thing a borrowing walker then cannot do is hand that value over: its
/// content is not one contiguous slice. Boundaries are still computed across it
/// — the member AFTER it is found where it really is — and only reading that
/// one value fails, with [`ListError::ValueSpansFieldLines`].
///
/// A member that does not parse yields `Err` and ends the walk: a quoted-string
/// this walk could not resolve leaves it unable to tell a separator from data,
/// so nothing behind it can be trusted.
#[inline]
pub fn parameterised_list<'a, I>(
  lines: I,
) -> impl Iterator<Item = Result<ListMember<'a>, ListError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  parameterised_list_with(lines, is_token)
}

/// [`parameterised_list`] with the member-name grammar supplied by the caller.
///
/// The list construct is RFC 9110 §5.6.1's and the parameters are §5.6.6's, but
/// what a member NAME may be belongs to the field: §10.1.4 spells a
/// `transfer-coding`'s name `token`, while §8.3.1 spells a `media-type`
/// `type "/" subtype` — and `/` is not a `tchar`. One walk, one name rule per
/// entry point, and no caller re-reading bytes this crate already read.
#[inline]
pub(crate) fn parameterised_list_with<'a, I>(
  lines: I,
  name_ok: fn(&[u8]) -> bool,
) -> impl Iterator<Item = Result<ListMember<'a>, ListError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  ParameterisedList {
    lines: lines.into_iter(),
    // The walk starts with no line in hand, which is the same position as a
    // line that has been spent: the next member comes from the next line.
    line: &[],
    at: 0,
    exhausted: false,
    done: false,
    name_ok,
  }
}

/// Whether a comma appears OUTSIDE a §5.6.4 quoted-string.
///
/// A singleton field cannot answer this by counting members: §5.6.1.2 has the
/// walk skip empty elements, so `text/plain,` yields one member and looks
/// singular. The comma itself is the evidence.
#[inline]
pub(crate) fn has_bare_comma(value: &[u8]) -> bool {
  matches!(scan_to_delim(value, 0, b','), Delim::At(at) if at < value.len())
}

/// Walks one member's parameters, `*( OWS ";" OWS [ parameter ] )`
/// (RFC 9110 §5.6.6). A parameter that does not parse yields `Err` and ends the
/// walk.
#[derive(Debug, Clone)]
pub struct ParamIter<'a> {
  params: &'a [u8],
  at: usize,
  tail: QuotedTail,
  done: bool,
}

impl<'a> Iterator for ParamIter<'a> {
  type Item = Result<(&'a [u8], ParamValue<'a>), ListError>;

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      if self.done {
        return None;
      }
      let end = match scan_to_delim(self.params, self.at, b';') {
        Delim::At(end) => end,
        // A quoted-string open at the end of the member takes the rest of it
        // with it: there is no further `;` to be outside of.
        Delim::Open(_) => self.params.len(),
        Delim::Invalid => {
          self.done = true;
          return Some(Err(ListError::InvalidQuotedByte));
        }
      };
      let param = trim_ows(self.params.get(self.at..end).unwrap_or_default());
      match self.params.get(end) {
        Some(_) => self.at = end.saturating_add(1),
        None => self.done = true,
      }
      // §5.6.6's `[ parameter ]` is optional, so `a;;b` states two parameters
      // rather than violating anything.
      if param.is_empty() {
        continue;
      }
      let parsed = parse_param(param, self.tail);
      if parsed.is_err() {
        self.done = true;
      }
      return Some(parsed);
    }
  }
}

/// What became of a §5.6.4 quoted-string still open when a member's FIRST field
/// line ended — the only such string a borrowing walk can be asked about, since
/// the member's later lines are not part of the slice it hands out.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum QuotedTail {
  /// Nothing was open there, or what was open never closed on any later line.
  /// Either way what the member's first line holds is all there is of it.
  Ends,
  /// It closed on a later field line, across the comma RFC 9110 §5.2 joins them
  /// with — so the value is real, and is not one contiguous slice.
  Continues,
}

/// Where a scan for a top-level delimiter got to.
enum Delim {
  /// The delimiter — or the end of the input — is at this offset, with every
  /// §5.6.4 quoted-string before it closed.
  At(usize),
  /// The input ended inside a quoted-string, carrying the escape state §5.2's
  /// join comma has to be fed through.
  Open(bool),
  /// A byte §5.6.4 forbids appeared inside a quoted-string.
  Invalid,
}

/// The next `delim` OUTSIDE a §5.6.4 quoted-string, scanning from `at`.
///
/// The whole reason a list walk is not `split(b',')` and a parameter walk is not
/// `split(b';')`: a delimiter inside a quoted-string is data, and a splitter
/// that cuts there reports a member or a parameter the sender never wrote.
///
/// [`list_element_end`] answers the same question for a value held whole, and
/// answers it with `None` for anything it cannot resolve. This one keeps the
/// two unresolved cases apart, because a walk that must cross RFC 9110 §5.2's
/// join needs the open string's escape state to continue it. Both take what a
/// quoted-string IS from [`scan_quoted`], which is where that rule lives.
fn scan_to_delim(value: &[u8], at: usize, delim: u8) -> Delim {
  let mut at = at;
  loop {
    match value.get(at) {
      None => return Delim::At(at),
      Some(&byte) if byte == delim => return Delim::At(at),
      Some(&b'"') => match scan_quoted(value, at.saturating_add(1), false) {
        QuotedScan::Closed(end) => at = end,
        QuotedScan::Open { escape } => return Delim::Open(escape),
        QuotedScan::Invalid => return Delim::Invalid,
      },
      Some(_) => at = at.saturating_add(1),
    }
  }
}

/// One `parameter = parameter-name "=" parameter-value` (RFC 9110 §5.6.6), over
/// a slice already trimmed of the OWS that production puts around it.
///
/// The `=` is the first one outside a quoted-string, and §5.6.6 puts no BWS
/// around it: `q = 1` names `q `, which is not a `token`, so it is not a
/// parameter. The same reading as this crate's `Expect` parser, which is the
/// point — one rule, one answer.
fn parse_param(param: &[u8], tail: QuotedTail) -> Result<(&[u8], ParamValue<'_>), ListError> {
  let (name, value) = match scan_to_delim(param, 0, b'=') {
    Delim::At(eq) => match param.get(eq) {
      Some(_) => (
        param.get(..eq).unwrap_or_default(),
        Some(param.get(eq.saturating_add(1)..).unwrap_or_default()),
      ),
      // No `=` at all: the bare-name form the field's own grammar allows.
      None => (param, None),
    },
    // A quoted-string took the rest of the parameter, so any `=` behind it is
    // data. What is left is the name, and it is not a token.
    Delim::Open(_) => (param, None),
    Delim::Invalid => return Err(ListError::InvalidQuotedByte),
  };
  if !is_token(name) {
    return Err(ListError::NotAToken);
  }
  let Some(value) = value else {
    return Ok((name, ParamValue::None));
  };
  // `parameter-value = ( token / quoted-string )` — one or the other, whole.
  match value.first() {
    Some(&b'"') => match scan_quoted(value, 1, false) {
      QuotedScan::Closed(end) if end == value.len() => Ok((
        name,
        ParamValue::Quoted(value.get(1..end.saturating_sub(1)).unwrap_or_default()),
      )),
      // Bytes behind the closing DQUOTE: the value is neither a quoted-string
      // nor a token.
      QuotedScan::Closed(_) => Err(ListError::NotAToken),
      QuotedScan::Open { .. } => Err(match tail {
        // The string closed on a later field line, so the value exists and is
        // well formed — it is simply not one slice to borrow.
        QuotedTail::Continues => ListError::ValueSpansFieldLines,
        QuotedTail::Ends => ListError::UnterminatedQuotedString,
      }),
      QuotedScan::Invalid => Err(ListError::InvalidQuotedByte),
    },
    _ if is_token(value) => Ok((name, ParamValue::Token(value))),
    _ => Err(ListError::NotAToken),
  }
}

/// The walk [`parameterised_list`] hands out: the field lines still to come, the
/// one being walked, and where in it the next member starts.
struct ParameterisedList<'a, I> {
  lines: I,
  line: &'a [u8],
  at: usize,
  /// `lines` answered `None` once. An `Iterator` is not required to keep doing
  /// so, and RFC 9110 §5.2's value ends at the last line either way.
  exhausted: bool,
  done: bool,
  /// The grammar a member NAME must satisfy. Each public entry point supplies
  /// its own, so each guarantees its own name grammar and no caller re-checks.
  name_ok: fn(&[u8]) -> bool,
}

impl<'a, I> Iterator for ParameterisedList<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  type Item = Result<ListMember<'a>, ListError>;

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      if self.done {
        return None;
      }
      self.at = skip_ows(self.line, self.at);
      match self.line.get(self.at) {
        // This field line is spent OUTSIDE a quoted-string, so §5.2's join
        // comma is a separator and the next line opens a new member.
        None => match self.next_line() {
          Some(next) => {
            self.line = next;
            self.at = 0;
          }
          None => {
            self.done = true;
            return None;
          }
        },
        // §5.6.1.2: "A recipient MUST parse and ignore a reasonable number of
        // empty list elements".
        Some(&b',') => self.at = self.at.saturating_add(1),
        Some(_) => {
          let member = self.member();
          if member.is_err() {
            // Nothing behind an unresolved member can be trusted: the walk no
            // longer knows which commas were separators.
            self.done = true;
          }
          return Some(member);
        }
      }
    }
  }
}

impl<'a, I> ParameterisedList<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  /// The next field line of the value, or `None` once there are none left.
  fn next_line(&mut self) -> Option<&'a [u8]> {
    if self.exhausted {
      return None;
    }
    let next = self.lines.next();
    if next.is_none() {
      self.exhausted = true;
    }
    next
  }

  /// Takes the member starting at the cursor, leaving the cursor on whatever
  /// ended it — which may be on a LATER field line than the member began on.
  fn member(&mut self) -> Result<ListMember<'a>, ListError> {
    let head_line = self.line;
    let start = self.at;
    // What the member occupies on the field line it starts on — all a
    // borrowing walk can hand out — plus, when a quoted-string held it open at
    // that line's end, the escape state to continue that string with.
    let (head_end, mut open) = match scan_to_delim(head_line, start, b',') {
      Delim::At(end) => (end, None),
      Delim::Open(escape) => (head_line.len(), Some(escape)),
      Delim::Invalid => return Err(ListError::InvalidQuotedByte),
    };
    self.at = head_end;

    // A quoted-string still open when a field line ends does NOT end the
    // member: §5.2 joins the lines with a comma and §5.6.4 makes that comma
    // data inside the string, so the member runs on into the next line and
    // ends wherever the string closes. `scan_quoted_after_join` is this
    // crate's one implementation of that rule; restarting the scan at each
    // physical line would answer it differently.
    let mut tail = QuotedTail::Ends;
    while let Some(escape) = open.take() {
      let Some(next) = self.next_line() else {
        // No further field line, so the combined value ends inside the string:
        // `tail` stays `Ends` and the value is unterminated rather than merely
        // non-contiguous.
        break;
      };
      self.line = next;
      self.at = next.len();
      match scan_quoted_after_join(next, escape) {
        QuotedScan::Closed(end) => {
          tail = QuotedTail::Continues;
          // Past the string, the rest of this line is the member's like any
          // other, up to the comma that ends it.
          match scan_to_delim(next, end, b',') {
            Delim::At(at) => self.at = at,
            Delim::Open(escape) => open = Some(escape),
            Delim::Invalid => return Err(ListError::InvalidQuotedByte),
          }
        }
        QuotedScan::Open { escape } => open = Some(escape),
        QuotedScan::Invalid => return Err(ListError::InvalidQuotedByte),
      }
    }

    // The name runs to the member's first `;` outside a quoted-string (§5.6.6
    // `parameters`), and is always on the member's first line: a `token`
    // carries no DQUOTE, so nothing can hold a name open across the join.
    let head = head_line.get(start..head_end).unwrap_or_default();
    let (name, params) = match scan_to_delim(head, 0, b';') {
      Delim::At(semi) => (
        head.get(..semi).unwrap_or_default(),
        head.get(semi.saturating_add(1)..).unwrap_or_default(),
      ),
      // No `;` outside a string: the whole member is its name, and the string
      // the boundary scan resolved above belongs to whatever that turns out to
      // be — which is not a token, so this reports the name.
      Delim::Open(_) | Delim::Invalid => (head, [].as_slice()),
    };
    let name = trim_ows(name);
    if !(self.name_ok)(name) {
      return Err(ListError::NotAToken);
    }
    Ok(ListMember { name, params, tail })
  }
}

#[cfg(test)]
mod tests;
