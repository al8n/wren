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
/// reasonable number of empty list elements" — every RECIPIENT list consumer
/// this split can delimit comes through here, so the empty-element rule lives
/// in one place instead of being rediscovered per open-coded `split(b',')`.
/// RECIPIENT is part of the rule and not a hedge: what this drops is what
/// §5.6.1.2 tells a recipient to ignore and §5.6.1.1 forbids a SENDER to
/// generate, so a sender-side check that took its elements from here would
/// inherit a tolerance for the very elements it exists to refuse.
/// [`sender_list_shape`], [`is_sender_token_list`] and [`is_protocol_list`]
/// therefore delimit their own, though this split could have delimited all
/// three.
///
/// The entrance is conditional, and the condition is the element grammar rather
/// than a preference: a recipient consumer this can delimit MUST come through
/// here, and one it cannot has to delimit its own elements.
/// [`crate::validator::TagList`] is a consumer it cannot — `etagc` admits a
/// comma between the DQUOTEs, so `"a,b"` is one entity tag that this split
/// reads as two malformed elements — and any list whose own grammar hides a
/// delimiter inside an element is in the same position.
///
/// §5.6.1.2's MUST does not come along with a new walker, so an exception owns
/// the rule: it states it where it parses, and tests it there. Which is also
/// the limit on what this entrance proves — a reader may not conclude from it
/// alone that a given list value in this crate was split here.
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
pub fn skip_ows(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while matches!(value.get(at), Some(b' ' | b'\t')) {
    at = at.saturating_add(1);
  }
  at
}

/// The end of the RFC 9110 §5.6.2 `token` starting at `at`, or `None` when there
/// is not one — `token = 1*tchar`, so an empty run is not a token.
pub fn token_end(value: &[u8], at: usize) -> Option<usize> {
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
pub enum QuotedScan {
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
pub fn scan_quoted_after_join(value: &[u8], escape: bool) -> QuotedScan {
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
pub fn scan_quoted(value: &[u8], at: usize, escape: bool) -> QuotedScan {
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

/// What one field-line value is, as a list, to a SENDER.
///
/// Two answers, because both lists asked about here are delimited by RFC 9110
/// §5.6.1's commas read RAW: every boundary such a value has is one the walk
/// can see, so it is a list either way and the only question left is whether an
/// element of it is empty. [`sender_list_shape`] states which lists those are,
/// and what a list of the other kind has to do instead.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ListShape {
  /// `1#element` with every element present.
  Sendable,
  /// A leading comma, a trailing one, two in a row, or an empty value: RFC 9110
  /// §5.6.1.1's "a sender MUST NOT generate empty list elements".
  EmptyElement,
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
/// to emit: this core reads `,chunked` and writes it never.
///
/// # A DQUOTE opens nothing where no string may begin
///
/// Elements are delimited by a RAW comma scan, because a quoted-string is
/// something a production admits at a POSITION rather than something a DQUOTE
/// is. This is handed a value without being told which production wrote it, so
/// it may not assume some position admits one — and the two lists this core
/// asks about admit one nowhere. RFC 9110 §7.6.1 and §7.8:
///
/// ```text
/// Connection        = #connection-option
/// connection-option = token
///
/// Upgrade          = #protocol
/// protocol         = protocol-name ["/" protocol-version]
/// protocol-name    = token
/// protocol-version = token
/// ```
///
/// Every terminal in them is §5.6.2's `token`, whose `tchar` excludes DQUOTE.
/// So a DQUOTE in one of these values is one more byte of the element it fell
/// in, it opens no string, and every comma in the value is the separator it
/// looks like.
///
/// Reading a DQUOTE as an opener wherever it fell hid the very element this
/// exists to refuse. `keep-alive",,", close` carries the `,,` RFC 9110 §5.6.1.1
/// forbids a sender to generate, and a phantom string spanning those two commas
/// answered [`ListShape::Sendable`] — as did every other value that buried an
/// empty element between two DQUOTEs.
///
/// # The list that has to delimit its own
///
/// A list whose element grammar DOES admit a quoted-string cannot come through
/// here, on the condition [`list_elements`] states for a recipient consumer it
/// cannot delimit: it has to delimit its own elements and answer RFC 9110
/// §5.6.1.1 over them. This crate's [`Expectations`] and `http1-proto`'s
/// `CodingList` are the two — both carry §5.6.6 `parameters` — and each answers
/// from its own accumulator, where a value that ends inside an open string has
/// no boundary to call empty and is reported as the grammar fault it is
/// ([`Expectations::grammar_fault`]).
///
/// This checks the list's SHAPE. What each element must BE is the field's own
/// grammar, checked beside it — and for both lists above that check refuses a
/// DQUOTE anyway, since it is no `tchar`.
pub fn sender_list_shape(value: &[u8]) -> ListShape {
  let mut at = 0usize;
  loop {
    let end = raw_comma_end(value, at);
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
pub fn is_sender_token_list(value: &[u8]) -> bool {
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
/// ; the two below are §5.6.6's, not §10.1.1's
/// parameters  = *( OWS ";" OWS [ parameter ] )
/// parameter   = parameter-name "=" parameter-value
/// ```
///
// gate-exempt: ext = value — a counterexample the field's production does not admit, not RFC 9110 grammar
/// Note WHERE the brackets are: `parameters` sits INSIDE the optional group, so
/// a member carrying a parameter without an argument (`ext;flag`) is not an
/// `expectation` at all. Note also what is absent: `parameter` has no BWS around
/// its `=`, unlike §7's `transfer-parameter`, so `ext = value` is not one
/// either.
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
pub struct Expectations {
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
  /// What a `#[derive(Default)]` on any struct holding one of these gets,
  /// which is [`new`](Self::new) rather than a field-wise zero: `expecting`
  /// starts TRUE, and a field-wise zero would start the parse in the middle of
  /// a list it has not seen.
  fn default() -> Self {
    Self::new()
  }
}

impl Expectations {
  /// An accumulator no field line has been pushed into yet.
  ///
  /// Not a field-wise zero, and `expecting` is the difference: an RFC 9110
  /// §5.6.1 `#element` list begins where an element may appear, so the parse
  /// starts positioned there rather than in the middle of a list it has not
  /// seen. [`Default`] is this, for that reason.
  pub const fn new() -> Self {
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
  pub const fn parsed(&self) -> bool {
    !self.malformed && self.open.is_none()
  }

  /// RFC 9110 §10.1.1's one defined expectation, derived only from a value that
  /// parsed whole.
  pub const fn expects_continue(&self) -> bool {
    self.parsed() && self.bare
  }

  /// Whether the value states an expectation this core does not implement —
  /// §10.1.1's 417.
  ///
  /// A value that did not parse counts as one: §10.1.1 makes an unrecognised
  /// expectation a 417 rather than a framing fault, so a recipient answers
  /// rather than failing the connection.
  pub const fn has_other(&self) -> bool {
    !self.parsed() || self.other
  }

  /// SENDER side: the field is present and some element of it is empty
  /// (§5.6.1.1), counting a value that names nothing at all.
  pub const fn empty_element(&self) -> bool {
    // `parsed` first: an element BOUNDARY is a fact about a value that parsed,
    // and a value ending inside an open `quoted-string` has none to call empty.
    // Reporting one as §5.6.1.1's empty element named a rule the caller had not
    // broken. This is the distinction that keeps `Expect` out of
    // `sender_list_shape`: `expectation`'s value admits a §5.6.4 quoted-string,
    // so this list has to delimit its own elements and answer §5.6.1.1 here,
    // where `grammar_fault` is the separate answer for a value that never
    // parsed.
    self.present && self.parsed() && (self.saw_empty || self.expecting)
  }

  /// SENDER side: the field is present and did not parse.
  pub const fn grammar_fault(&self) -> bool {
    self.present && !self.parsed()
  }

  /// Folds one `Expect` field line into the value.
  pub fn push(&mut self, value: &[u8]) {
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
/// So it delimits its OWN elements, for the reason [`list_elements`] gives:
/// that split drops the empties §5.6.1.2 tells a RECIPIENT to ignore, and a
/// sender-side check taking its elements from there inherits a tolerance for
/// the very elements it exists to refuse — `,websocket`, `websocket,` and
/// `a,,b` are all sendable under one. The walk is [`sender_list_shape`]'s,
/// with the element grammar in place of its emptiness test, and
/// [`is_sender_token_list`] delimits its own for the same reason.
///
/// **The two refusals are one refusal here**, which is why no separate
/// emptiness test appears below: §7.8's `protocol` is built out of
/// `token = 1*tchar` (§5.6.2), which admits no empty run, so an empty element
/// fails as a `protocol` before §5.6.1.1 has to be consulted. The value naming
/// at least one protocol falls out of the same step — `""` is one empty element
/// rather than no elements.
///
/// The RECIPIENT side is [`lists_a_protocol`], and it is deliberately more
/// tolerant. The two are not an inconsistency: §5.6.1.1 and §5.6.1.2 are
/// adjacent sections stating opposite MUSTs for the two roles, and this core
/// implements both.
pub fn is_protocol_list(value: &[u8]) -> bool {
  let mut at = 0usize;
  loop {
    // Delimited by [`raw_comma_end`], the same as [`sender_list_shape`] and for
    // the reason stated there: §7.8's `protocol` is `token`s, RFC 9110 §5.6.2's
    // `tchar` excludes DQUOTE, so this production admits a §5.6.4 quoted-string
    // at no position and a DQUOTE here opens none. The element grammar below
    // then refuses the element that DQUOTE fell in, which is the fault the
    // sender's bytes actually have.
    let end = raw_comma_end(value, at);
    if !is_protocol(trim_ows(value.get(at..end).unwrap_or_default())) {
      return false;
    }
    if value.get(end).is_none() {
      return true;
    }
    at = end.saturating_add(1);
  }
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
pub fn lists_a_protocol<'a>(values: impl Iterator<Item = &'a [u8]>) -> bool {
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
/// [`NotAToken`](Self::NotAToken),
/// [`MissingParameterValue`](Self::MissingParameterValue),
/// [`UnterminatedQuotedString`](Self::UnterminatedQuotedString) and
/// [`InvalidQuotedByte`](Self::InvalidQuotedByte) are grammar violations the
/// sender committed, and the value they describe cannot be read by anyone. The
/// other two are not.
/// [`ValueSpansFieldLines`](Self::ValueSpansFieldLines) names a value that is
/// perfectly well formed and that a walker borrowing its input cannot hand
/// over. [`MemberBoundaryUnknown`](Self::MemberBoundaryUnknown) names a
/// malformed field whose remaining members this walk refuses to GUESS at. Both
/// are facts about this walk rather than about the field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ListError {
  /// A member name, a parameter name, or a bare parameter value is not the
  /// `token` RFC 9110 §5.6.2 defines — the empty string included, since
  /// `token = 1*tchar` names at least one character.
  #[error("member name, parameter name, or bare value is not a token")]
  NotAToken,
  /// A parameter carried no value: its name, and then the `;` that opens the
  /// next repetition, the `,` that ends the member, or the end of the value.
  ///
  /// RFC 9110 §5.6.6 and §10.1.4:
  /// ```text
  /// parameter          = parameter-name "=" parameter-value
  /// parameter-name     = token
  /// parameter-value    = ( token / quoted-string )
  /// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
  /// ```
  ///
  /// Neither brackets the `=` or the value behind it, so neither derives a bare
  /// name. Whether the walk SAYS so, or hands the shape over as
  /// [`ParamValue::None`] for a field whose own grammar makes the value
  /// optional, is that field's answer and arrives with the list — see
  /// [`parameterised_list`]. Where the field asked for the refusal this is what
  /// the walk reports, at every entrance it has, RFC 9110 §5.2's field-line
  /// join included: behind that join the walk hands no slice out, so a shape
  /// reported there would be a shape nobody could read.
  #[error("parameter carries no value")]
  MissingParameterValue,
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
  /// A parameter was refused, and the bytes behind it end the member at one
  /// comma read raw and at another — or at none at all — read with the RFC 9110
  /// §5.6.4 quoted-strings the field's own `parameter` production admits in
  /// them. Which comma ends the member is then not derivable, and the walk
  /// reports the field unreadable from there rather than picking one of the two
  /// answers.
  ///
  /// ```text
  /// quoted-string   = DQUOTE *( qdtext / quoted-pair ) DQUOTE
  /// parameters      = *( OWS ";" OWS [ parameter ] )
  /// parameter       = parameter-name "=" parameter-value
  /// parameter-name  = token
  /// parameter-value = ( token / quoted-string )
  /// ```
  ///
  /// The two answers are: the string is real, so every comma in it is data and
  /// the member runs to the comma behind its close; or `parameters` failed at
  /// the earlier repetition and derives nothing behind it, so the DQUOTE opens
  /// nothing and the first raw comma ends the member. Reading `chunked` out of
  /// `gzip;;x="a, chunked, b", br` is the second answer, and it MANUFACTURES a
  /// transfer coding out of bytes the sender wrote inside a parameter value
  /// while hiding the `br` written behind them. Reading the string is the
  /// first, and where it never closes it swallows a coding the sender did
  /// write. Neither is derivable, so neither is offered.
  ///
  /// This is reported only where SOME reading of those bytes holds the comma
  /// inside a string. `gzip;;x="a", chunked` has the same empty slot §10.1.4
  /// refuses and the same DQUOTE at the same admitted position, and the string
  /// it opens closes in front of the only comma — so every reading ends the
  /// member there, the comma is §5.6.1.2's separator in all of them, and
  /// `chunked` is yielded rather than hidden.
  ///
  /// This is the walk's LAST item: everything behind an unresolved boundary is
  /// unread, and saying so is the whole of what this reports. The member in
  /// front of it is yielded first, with the parameter fault that earned this on
  /// it — its name and the repetitions up to that fault are derived, and only
  /// what follows them is not.
  #[error("a parameter fault leaves the member's end underivable")]
  MemberBoundaryUnknown,
}

/// The caller-supplied output slice was smaller than the call needed.
///
/// [`ParamValue::unescape_into`]'s only failure. It is stated at this layer
/// because the replacement that call performs is RFC 9110 §5.6.4's and every
/// HTTP version inherits it, so the one way it can refuse is not any protocol
/// crate's to own. A crate carrying a buffer error of its own converts at its
/// own boundary rather than making this type carry a shape it cannot know.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[error("output buffer too small: need {need}, have {have}")]
pub struct BufferTooSmall {
  /// Bytes the call needed to write.
  pub need: usize,
  /// Bytes the destination had available.
  pub have: usize,
}

/// A parameter's value: a bare token, or the CONTENT of a quoted-string with
/// its escapes still in place.
///
/// RFC 9110 §5.6.4 defines the `quoted-pair` escape but leaves what the
/// unescaped value MEANS to the field that used it — RFC 6455 §9.1, for one,
/// requires the unescaped form to be a `token` — so this variant hands over
/// the bytes as the sender wrote them, escapes intact: what they mean is the
/// field's business, not this type's. Performing §5.6.4's replacement itself
/// is NOT the caller's job, though: [`unescaped`](Self::unescaped),
/// [`unescape_into`](Self::unescape_into) and
/// [`eq_unescaped_ignore_ascii_case`](Self::eq_unescaped_ignore_ascii_case)
/// below are how this type discharges it.
///
/// # There is no `PartialEq`, and the two halves fail it differently
///
/// This type derives neither `PartialEq` nor `Eq`. A derive would compare the
/// bytes as written AND which variant held them, and §5.6.6 settles half of
/// that outright: "A parameter value that matches the token production
/// can be transmitted either as a token or within a quoted-string.  The quoted
/// and unquoted values are equivalent." So [`Token`](Self::Token)`(b"utf-8")`
/// and [`Quoted`](Self::Quoted)`(b"utf-8")` are one parameter value spelled two
/// ways, and a derive calls them different — a wrong answer to a question the
/// RFC answers. §5.6.4's own MUST — quoted below on
/// [`unescaped`](Self::unescaped) — puts a second pair of spellings under one
/// value, because a `quoted-pair` is read as the octet behind its backslash: a
/// [`Quoted`](Self::Quoted) holding a redundant escape and a
/// [`Quoted`](Self::Quoted) holding that bare octet are one value, and a derive
/// separates them too.
///
/// **The other half is why a semantic `PartialEq` is not the fix.** §5.6.6:
/// "Parameter names are case-insensitive.  Parameter values might or might not
/// be case-sensitive, depending on the semantics of the parameter name." That
/// is conditional on the NAME, and this type is the value of every field that
/// spells its parameters in this grammar, so it does not know which name it
/// belongs to. Folding case would invent one answer and not folding it would
/// invent the other. The precedent for removing rather than repairing is
/// [`MediaType`](crate::media::MediaType), whose own doc gives the same
/// reasoning at length, and [`ContentRange`](crate::range::ContentRange) before
/// it.
///
/// What a caller says instead is the unconditional half, which is the whole of
/// what this crate can promise: [`unescaped`](Self::unescaped) is a `u8`
/// iterator over the value with the quoted-string's spelling gone, so
/// `a.unescaped().eq(b.unescaped())` compares two values across both variants,
/// and [`eq_unescaped_ignore_ascii_case`](Self::eq_unescaped_ignore_ascii_case)
/// adds the case fold where the caller's own parameter name is what makes it
/// right.
///
/// # Both sentences above are RFC 9110 §5.6.6's, and §10.1.4 has neither
///
/// A value walked as [`ParamSyntax::TransferParameter`] arrives here too, and
/// §10.1.4 says nothing whatever about a `transfer-parameter`'s case, nor that
/// its `token` and `quoted-string` spellings are equivalent — RFC 9112 §7 gives
/// case-insensitivity to the CODING name, not to a parameter. So the argument
/// for having no `PartialEq` is not weaker over there, it is stronger: under
/// §5.6.6 a derive would answer a question the RFC answers, and answer it
/// wrongly; under §10.1.4 it would answer one the RFC does not answer at all.
/// The methods below are the same either way — they state what the CALLER
/// asserts about its own parameter, which is the only thing that changes.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum ParamValue<'a> {
  /// The parameter carried no `=`. RFC 9110 §5.6.6's `parameter` requires one;
  /// the fields whose parameters are optional-valued write that themselves, as
  /// RFC 6455 §9.1's `extension-param = token [ "=" (token | quoted-string) ]`
  /// does.
  ///
  /// Reached only where the field asked for the shape rather than for the
  /// refusal. A field that refuses a parameter with no value says so to the
  /// walk instead — see [`parameterised_list`] — and gets
  /// [`ListError::MissingParameterValue`] at every entrance including the one
  /// behind RFC 9110 §5.2's join, where no value can be handed over at all.
  None,
  /// A bare token (RFC 9110 §5.6.2).
  Token(&'a [u8]),
  /// The interior of a quoted-string (RFC 9110 §5.6.4), escapes untouched.
  Quoted(&'a [u8]),
}

/// Walks a parameter value with its RFC 9110 §5.6.4 `quoted-pair` escapes
/// removed. Total over any value the walker produced: a `quoted-pair`'s
/// backslash is only accepted with an octet behind it, so the lookahead below
/// can only run off the end of a value this crate did not validate — reachable
/// only by building one directly, since `#[non_exhaustive]` blocks exhaustive
/// matching, not construction. There, the lone trailing backslash is simply
/// dropped: not yielded, not reported as an error, the same in all three
/// methods below.
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
  /// # What the caller owes the bytes afterwards
  ///
  /// This writes into the caller's own buffer and not into any wire grammar
  /// this crate governs, which is why it is the one writer here that carries no
  /// destination rule. A caller that re-emits these bytes into a
  /// `quoted-string` MUST re-escape them: the escapes were taken OFF, so a
  /// DQUOTE or a backslash in the result stands unescaped and would close or
  /// re-open the string it is written into. Nothing here can see where the
  /// bytes go next.
  ///
  /// # Errors
  ///
  /// [`BufferTooSmall`] when `out` is shorter than the unescaped value.
  pub fn unescape_into(self, out: &mut [u8]) -> Result<usize, BufferTooSmall> {
    let need = self.unescaped().count();
    if need > out.len() {
      return Err(BufferTooSmall {
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
  /// be case-sensitive, depending on the semantics of the parameter name." —
  /// and §10.1.4 says nothing at all about a `transfer-parameter`'s case, so a
  /// value read under [`ParamSyntax::TransferParameter`] has less standing to
  /// be folded here, not more.
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

/// Which of the two `parameter` productions a walk's members carry.
///
/// One walk serves both. The CONTAINER rule is written out here beside the
/// parameter, because half of what separates the two lives in the container and
/// a comparison that shows only the parameter cannot see it — RFC 9110 §5.6.6:
///
/// ```text
/// parameters      = *( OWS ";" OWS [ parameter ] )
/// parameter       = parameter-name "=" parameter-value
/// parameter-name  = token
/// parameter-value = ( token / quoted-string )
/// ```
///
/// and RFC 9110 §10.1.4:
///
/// ```text
/// transfer-coding    = token *( OWS ";" OWS transfer-parameter )
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// # The two differences, and there are two
///
/// 1. **`BWS` around the `=`.** §10.1.4 admits it on both sides; §5.6.6 admits
///    none, and says so in as many words — RFC 9110 §5.6.6: "Parameters do not
///    allow whitespace (not even `bad` whitespace) around the `=` character."
///    §5.6.3's `BWS = OWS` and `OWS = *( SP / HTAB )` are what that admits.
/// 2. **Whether a slot may be EMPTY.** §5.6.6 brackets its slot, so `m;`,
///    `m;;p=x` and `m;p=x;` are conforming and state no parameter there.
///    §10.1.4 brackets nothing: every `;` it writes introduces a whole
///    `transfer-parameter`, so `gzip;` is malformed and this walk says so —
///    [`ParamIter`] reports [`ListError::NotAToken`] for the `token` that is
///    missing and stops, and a member with NO `;` stays distinct from a member
///    with an empty slot rather than being folded into it.
///
/// A third asymmetry is real and is not carried here: §10.1.4 puts the head
/// `token` INSIDE `transfer-coding`, while §5.6.6's `parameters` has no head at
/// all and takes one from whatever rule concatenates it — §8.3.1's
/// `type "/" subtype`, for one. That is the member-NAME grammar, which each
/// entry point supplies separately, and [`parameterised_list`] supplies
/// §5.6.2's `token` for it, which is what §10.1.4 spells.
///
/// A fourth is real and is not carried here either: neither production spells a
/// bare name with no `=`, but §5.6.6's `parameters` is the production other
/// fields EXTEND and one of those may bracket the value — so what to do about a
/// bare name is the FIELD's answer, and each entry point states it separately.
/// [`parameterised_list`] gives what those two fields say.
///
/// Everything else is the same rule written twice: the `*( OWS ";" OWS … )`
/// repetition and its `OWS` on both sides of the `;`, the `token` a parameter
/// names, the `( token / quoted-string )` it values, one alternative taken
/// whole, and §5.6.4's quoted-string inside that. Neither admits whitespace
/// anywhere the other does not apart from that `BWS`.
///
/// # Why a boundary scan has to be told, rather than a caller checking after
///
/// The `=` and the `BWS` around it are the two terminals that put a
/// `parameter-value` at an offset, and the first byte of a `parameter-value` is
/// the ONE position either production admits a §5.6.4 quoted-string at. So this
/// choice decides where a string may open, which decides which commas are data,
/// which decides where the member ENDS — before any caller has been handed
/// anything to check.
///
/// Read `gzip;p = "a,b", chunked` with the narrower production and `p ` is no
/// `parameter-name`, no string opens, the member ends at the comma INSIDE
/// `"a,b"`, and the walk yields a member `b"` the sender never wrote whose
/// error hides the `chunked` written behind it. On a `Transfer-Encoding` that
/// is a hidden transfer coding, which is a framing decision. A boundary must
/// never be derived from a production narrower than the value's own.
///
/// Which is why this is carried rather than left to a caller: the extent
/// question is answered here and cannot be reopened downstream, while the
/// validity question — is this actually a well-formed parameter — is answered
/// by [`ParamIter`] over the same choice, so the two cannot disagree.
///
/// # Why not one wide boundary and a narrow verdict
///
/// Deriving EVERY member's extent with §10.1.4's wider production and checking
/// validity with the caller's satisfies that rule structurally, and asks the
/// caller for no correct declaration at all. It is not what this does. Under it
/// a §5.6.6 member's extent would be decided by a production §5.6.6 does not
/// contain — the `BWS` §10.1.4 admits would put a `parameter-value` position,
/// and so a place a quoted-string may open, where §5.6.6 has none — so a second
/// recipient implementing §5.6.6 straight from the RFC would put the member
/// boundary somewhere else, which is two recipients disagreeing about a hostile
/// field. The rule is that a boundary is never derived from a production
/// NARROWER than the value's own, not that it is always derived from the widest
/// one written down. What the wide-boundary shape would buy structurally is
/// bought instead by there being no default: no field enters the walk without
/// declaring the production it spells its own parameters with.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParamSyntax {
  /// RFC 9110 §5.6.6's `parameter`, whose `=` admits no whitespace on either
  /// side — "Parameters do not allow whitespace (not even "bad" whitespace)
  /// around the "=" character."
  ///
  /// Its slot is optional as well —
  /// `parameters = *( OWS ";" OWS [ parameter ] )` — so a `;` with nothing
  /// behind it states no parameter and violates nothing, and `text/plain;` is a
  /// conforming RFC 9110 §8.3.1 `media-type`.
  ///
  /// The fields: `Content-Type` (§8.3), `Accept` (§12.5.1) — both read by
  /// [`crate::media`] — and §10.1.1's `Expect`, which [`Expectations`] reads
  /// with a walk of its own.
  Parameter,
  /// RFC 9110 §10.1.4's `transfer-parameter`, whose `=` admits `BWS` on both
  /// sides, so `gzip;p = "a,b"` states one parameter whose value is the
  /// quoted-string `a,b` — comma and all.
  ///
  /// Its slot is NOT optional:
  /// `transfer-coding = token *( OWS ";" OWS transfer-parameter )` puts no
  /// brackets around it, so a `;` that introduces nothing is a
  /// `transfer-parameter` missing the `token` it starts with, and `gzip;`,
  /// `gzip;;p=x` and `gzip;p=x;` are each malformed. The empty LIST element
  /// §5.6.1.2 makes a recipient ignore is a different level and is still
  /// ignored: `gzip, , chunked` is two codings under both productions.
  ///
  /// The fields: `TE` (§10.1.4) and `Transfer-Encoding` (RFC 9112 §7). Reading
  /// that whitespace is not leniency; §5.6.3 makes it a MUST — "A recipient
  /// MUST parse for such bad whitespace and remove it before interpreting the
  /// protocol element."
  ///
  /// §11.2's `auth-param` is the identical production, and [`crate::auth`]
  /// keeps helpers of its own for it — an `auth-param` is a whole list element
  /// with no `;` level under it, so where a parameter ENDS is a different
  /// answer there even though where its value BEGINS is the same one.
  TransferParameter,
}

/// What the field reading a list wants done with a parameter that carried no
/// value — the shape [`ParamValue::None`] reports.
///
/// Neither production this walk serves derives a bare name: RFC 9110 §5.6.6's
/// `parameter = parameter-name "=" parameter-value` and §10.1.4's
/// `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` each put
/// the `=` and the value outside any brackets. So a bare name is always
/// SOMEBODY's refusal, and the only question is whose.
///
/// # Why it is not the walk's own answer
///
/// A field may spell its parameters with the value optional and reuse this walk
/// for the rest — RFC 6455 §9.1's
/// `extension-param = token [ "=" (token | quoted-string) ]` is one such
/// grammar — and for it the bare name is a value to READ, not a fault. That is
/// what [`Reported`](Self::Reported) is for, and it is why
/// [`ParamValue::None`] exists.
///
/// # Why it may not be left to the field either
///
/// A field that refuses the shape can only refuse what it is shown, and the
/// parameters behind an RFC 9110 §5.2 field-line join are shown to nobody: they
/// lie on lines the member hands no slice of. A field refusing bare names for
/// itself therefore enforces its rule in front of the join and nowhere behind
/// it, which is §5.2 turned into a way past the rule. [`Refused`](Self::Refused)
/// is that field saying so once, to the walk, which then applies it at every
/// entrance the walk has.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum ValuelessParameter {
  /// Hand the shape over as [`ParamValue::None`] and let the field decide. For
  /// a field whose own grammar brackets the value, that decision is to accept
  /// it.
  Reported,
  /// Refuse it here, as [`ListError::MissingParameterValue`], at every entrance
  /// — including the repetitions behind RFC 9110 §5.2's join, which is the
  /// entrance a field cannot reach for itself.
  Refused,
}

/// One member of a parameterised `#`-list: a name and its parameters, with
/// quoted-string values kept intact.
///
/// # There is no `PartialEq`, and documenting the trap is not a substitute
///
/// This type derives neither `PartialEq` nor `Eq`. `params` is the untrimmed
/// remainder after the member's first `;`, so a derive makes `ext; q=1` and
/// `ext;  q=1` unequal even though both walk to the same
/// `(name, `[`ParamValue`]`)` pairs through [`params`](Self::params). The
/// difference is the `OWS` §5.6.6's `parameters = *( OWS ";" OWS [ parameter ] )`
/// puts around the `;`, and it is the same defect
/// [`MediaType`](crate::media::MediaType) and
/// [`MediaRange`](crate::media::MediaRange) derive no equality over either —
/// each of them holding or built from one of these.
///
/// **Do not restore the derive with a doc note beside it.** A documented trap
/// is still a trap: the disclosure tells a reader that `==` answers a question
/// it should not have been asked, and leaves the wrong answer one keystroke
/// away. The derive compares the private `QuotedTail`, the [`ParamSyntax`] and
/// the fault carried from behind the join besides, so two members with
/// identical `name` and `params` bytes compare unequal when one was parsed
/// across an RFC 9110 §5.2 field-line join and the other was not, or when one
/// was walked as §5.6.6's `parameter` and the other as §10.1.4's
/// `transfer-parameter` — properties of how the input arrived and of which
/// field asked, not of what the sender said, and ones this type never claimed
/// to report.
///
/// A caller compares [`name`](Self::name) under whatever rule its own field
/// gives that token — §8.3.1's case-insensitivity for a media range, its own
/// for anything else — and walks [`params`](Self::params) pairwise, comparing
/// each name with [`eq_ignore_ascii`] and each [`ParamValue`] as that type's
/// own doc directs.
#[derive(Debug, Copy, Clone)]
pub struct ListMember<'a> {
  name: &'a [u8],
  /// What stood behind the member's FIRST `;`, or `None` where the member has
  /// no `;` at all — the repetition never ran.
  ///
  /// An `Option` rather than a slice that goes empty, because the two are
  /// different values under RFC 9110 §10.1.4 and a `&[]` cannot tell them
  /// apart. `gzip` runs the `*( OWS ";" OWS transfer-parameter )` zero times
  /// and is a conforming `transfer-coding`; `gzip;` runs it once with no
  /// `transfer-parameter` in it and is not. Storing both as `&[]` made the
  /// second indistinguishable from the first through every public accessor —
  /// a malformed `TE` reported as a well-formed one.
  params: Option<&'a [u8]>,
  tail: QuotedTail,
  /// The production the walk delimited this member with, carried so that
  /// [`params`](Self::params) reads its parameters under the same one.
  syntax: ParamSyntax,
  /// What the field wants done with a parameter that carried no value, carried
  /// for the same reason `syntax` is: the answer came from the entry point and
  /// [`params`](Self::params) may not pick a different one.
  valueless: ValuelessParameter,
  /// The first fault among the parameters that stood BEHIND an RFC 9110 §5.2
  /// field-line join, or `None` where each of them derived.
  ///
  /// `params` is what the member occupies on the line it BEGAN on, which is all
  /// a borrowing walk can hand out. The repetitions of RFC 9110 §5.6.6's
  /// `parameters = *( OWS ";" OWS [ parameter ] )`, or of the
  /// `*( OWS ";" OWS transfer-parameter )` §10.1.4 writes without the brackets,
  /// that lie on a LATER line are not in that slice, so
  /// [`params`](Self::params) cannot walk them and cannot report on them
  /// either. They are verdicted the moment their boundary is settled, which is
  /// the only moment this walk holds them, and the answer is carried here.
  ///
  /// Without it §5.2's join is a way past every rule this walk applies to a
  /// parameter. `gzip;p="a` + `";;q=x` and `gzip;p="a` + `";q=x` then read
  /// alike through every public accessor — member `gzip`, one parameter
  /// reported as [`ListError::ValueSpansFieldLines`], member `chunked` behind
  /// it — and the first of them states an empty `transfer-parameter` slot
  /// §10.1.4 does not admit.
  joined: Option<ListError>,
}

impl<'a> ListMember<'a> {
  /// The member's leading token, OWS-trimmed — RFC 9110 §5.6.3's whitespace
  /// around a list element is not part of it.
  #[inline]
  pub const fn name(&self) -> &'a [u8] {
    self.name
  }

  /// The parameters that followed it — RFC 9110 §5.6.6's
  /// `parameters = *( OWS ";" OWS [ parameter ] )`, or the
  /// `*( OWS ";" OWS transfer-parameter )` §10.1.4 wraps around the wider one,
  /// as this member's [`ParamSyntax`] says.
  ///
  /// A member with no `;` yields nothing under either production: the
  /// repetition ran zero times, which both spell `*`. A member whose `;`
  /// introduces nothing is a different value — §5.6.6 admits it and yields
  /// nothing for it, §10.1.4 does not admit it and this walk yields
  /// [`ListError::NotAToken`] and stops.
  ///
  /// # What a value crossing the RFC 9110 §5.2 join carries with it
  ///
  /// This walks the parameters on the line the member BEGAN on, because those
  /// are the only ones it can hand slices of. A parameter whose value crosses
  /// the join is reported as [`ListError::ValueSpansFieldLines`] — well formed,
  /// and not one contiguous slice — and the parameters behind it, on the later
  /// lines, are walked by [`parameterised_list`] itself and never reach here.
  ///
  /// So that the join is not a way past their grammar, the FIRST of those that
  /// does not derive is carried on the member and reported HERE, in place of
  /// `ValueSpansFieldLines`. That is the one verdict this walk gives which says
  /// the member is well formed, so it is the one that may not stand in front of
  /// a fault; every other verdict already refuses the member and is left as it
  /// is, in the order the parameters were written.
  ///
  /// What is NOT carried is a conforming parameter's name and value: those
  /// bytes are on a line no slice of this member reaches, and reporting a pair
  /// nobody can read is not something an iterator can do. So a rule ABOVE these
  /// two productions — one a field applies to a parameter both of them derive —
  /// is the field's to DECLARE with the list rather than to apply itself, which
  /// is what [`parameterised_list`] takes a parameter with no value to mean.
  #[inline]
  pub const fn params(&self) -> ParamIter<'a> {
    ParamIter {
      params: match self.params {
        Some(params) => params,
        None => &[],
      },
      at: 0,
      tail: self.tail,
      syntax: self.syntax,
      valueless: self.valueless,
      joined: self.joined,
      // No `;`, so there is no repetition to walk — as against one repetition
      // that happens to be empty, which is what an empty slice would be read
      // as and which §10.1.4 refuses.
      done: self.params.is_none(),
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
/// That is the LIST level and it holds for both productions this walk serves.
/// The PARAMETER level is not the same question and does not get the same
/// answer: §5.6.6 writes `[ parameter ]` and admits an empty slot, §10.1.4
/// writes `transfer-parameter` and admits none, and [`ParamIter`] is where the
/// two part. Reading §5.6.1.2's MUST as though it also governed the slot is how
/// `gzip;` passed as a `Transfer-Encoding`.
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
/// A value that closes across the join and is then RUN ON PAST is a different
/// thing, and is not reported as that one.
/// `parameter-value = ( token / quoted-string )` (§5.6.6) takes one alternative
/// whole, so bytes behind the close derive nothing and the parameter is
/// [`ListError::NotAToken`] — the same fault this walk reports when the close
/// and the bytes behind it lie on a single field line. Where a comma behind
/// those bytes is one EVERY reading of the rest of that member ends it at, the
/// member ends there and cannot swallow the member written after it; where some
/// reading holds that comma inside a string, the section below is what happens
/// instead.
///
/// A member that does not parse yields `Err` and ends the walk: a quoted-string
/// this walk could not resolve leaves it unable to tell a separator from data,
/// so nothing behind it can be trusted.
///
/// # A member whose PARAMETERS do not parse ends nothing it can end honestly
///
/// That fault is carried on the member, and where the member ENDS is then asked
/// of EVERY reading of the same bytes. Each DQUOTE the field's own `parameter`
/// production admits a value at is one a reading may open a string with or
/// leave shut, and the walk takes the earliest comma only where no reading at
/// all holds it inside a string — a proof over the readings rather than a
/// comparison of two of them. That comma is then the member's end whichever
/// reading is the sender's, §5.6.1.2's separator in all of them, and the member
/// behind it is one whose boundaries this walk KNOWS: `gzip;q, chunked`, which
/// holds no DQUOTE at all, `gzip;;q=x, chunked`, whose value is a `token`, and
/// `gzip;;x="a", chunked`, whose string closes in front of that comma, each
/// report the malformed `gzip` AND the `chunked` written behind it. What is
/// left of the refused member is got past by that same question rather than
/// read as members of its own, and the walk resumes at the first element whose
/// NAME this entry point's grammar admits.
///
/// Where SOME reading holds that comma inside a string — because it opened one
/// that covers it, or one that never closes — the walk stops with
/// [`ListError::MemberBoundaryUnknown`], after yielding the member the fault
/// was found in. Reading the string hides whatever the sender wrote behind it;
/// reading it raw hands the caller a member that stood INSIDE it —
/// `gzip;;x="a, chunked, b", br` yields a `chunked` on the field that decides
/// framing, and buries the `br`. `parameters` has already failed to derive at
/// that point, so no reading is one this walk can justify, and it offers
/// none.
///
/// # `syntax` is not a tolerance dial
///
/// It names the production the CALLER's field spells its parameters with, and
/// there is no default because there is no safe one: [`ParamSyntax`] carries
/// what picking the narrower of the two costs a value written in the wider. A
/// caller reading `Content-Type` or `Accept` passes
/// [`ParamSyntax::Parameter`]; one reading `Transfer-Encoding` or `TE` passes
/// [`ParamSyntax::TransferParameter`]. The member names this entry point
/// admits are RFC 9110 §5.6.2 `token`s, which is what both of those fields and
/// §10.1.1's `Expect` spell theirs with.
///
/// # A parameter with no value, under each of them
///
/// RFC 9110 §10.1.4's
/// `transfer-parameter = token BWS "=" BWS ( token / quoted-string )`
/// is the whole of what a `TE` or `Transfer-Encoding` parameter may be — those
/// two fields spell no grammar of their own over it — so `gzip;q` is refused
/// here, with [`ListError::MissingParameterValue`], at every entrance the walk
/// has. §5.6.6's `parameters` is not a field's whole grammar in the same way:
/// it is the production fields EXTEND, and one whose `parameter` brackets the
/// value reads a bare name rather than refusing it. So under
/// [`ParamSyntax::Parameter`] the shape is handed over as [`ParamValue::None`]
/// and the caller's field refuses it — as [`crate::media`] does, with
/// `MediaError::ValuelessParameter`, which it gets by declaring the refusal to
/// this walk rather than making it over what the walk hands back. That
/// declaration is the same reasoning as the empty slot's: what §10.1.4 brackets
/// nowhere, this walk may answer for; and a rule a field can only apply to what
/// it is SHOWN is a rule §5.2's join gets past, since behind that join a
/// parameter is shown to nobody.
#[inline]
pub fn parameterised_list<'a, I>(
  lines: I,
  syntax: ParamSyntax,
) -> impl Iterator<Item = Result<ListMember<'a>, ListError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  let valueless = match syntax {
    ParamSyntax::Parameter => ValuelessParameter::Reported,
    ParamSyntax::TransferParameter => ValuelessParameter::Refused,
  };
  parameterised_list_with(lines, is_token, syntax, valueless)
}

/// [`parameterised_list`] with the member-name grammar supplied by the caller.
///
/// The list construct is RFC 9110 §5.6.1's, but what a member NAME may be
/// belongs to the field: §10.1.4 spells a `transfer-coding`'s name `token`,
/// while §8.3.1 spells a `media-type` `type "/" subtype` — and `/` is not a
/// `tchar`. One walk, one name rule per entry point, and no caller re-reading
/// bytes this crate already read.
///
/// The two rules a member is made of are supplied SEPARATELY because the field
/// picks them separately: §8.3.1's name comes with §5.6.6's `parameter`, but
/// §10.1.4's name comes with `transfer-parameter` and §10.1.1's with §5.6.6's,
/// so neither implies the other. [`ParamSyntax`] is the second of them.
///
/// One pairing is fixed by the RFC even so, and it is the third difference
/// between the two productions. RFC 9110 §10.1.4 writes
/// `transfer-coding = token *( OWS ";" OWS transfer-parameter )`, putting the
/// head token INSIDE the rule that carries the parameters — so §10.1.4's member
/// name is §5.6.2's `token` and nothing else, while §5.6.6's `parameters` has
/// no head of its own and takes whatever rule concatenates it.
/// [`parameterised_list`] is the only entry point that can
/// select [`ParamSyntax::TransferParameter`], and it supplies `is_token`, which
/// is that pairing. A `name_ok` chosen here is therefore a §5.6.6 name rule;
/// pairing a wider one with `TransferParameter` would be a member grammar
/// RFC 9110 does not spell.
///
/// `valueless` is the third thing a field picks separately, and
/// [`ValuelessParameter`] says why a field picks it here rather than applying it
/// to what the walk hands back.
#[inline]
pub(crate) fn parameterised_list_with<'a, I>(
  lines: I,
  name_ok: fn(&[u8]) -> bool,
  syntax: ParamSyntax,
  valueless: ValuelessParameter,
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
    recovering: false,
    unresolved: false,
    name_ok,
    syntax,
    valueless,
  }
}

/// Whether a comma appears OUTSIDE the RFC 9110 §5.6.4 quoted-strings §5.6.6
/// admits — which is to say, whether the value holds more than one member.
///
/// A singleton field cannot answer this by counting members: §5.6.1.2 has the
/// walk skip empty elements, so `text/plain,` yields one member and looks
/// singular. The comma itself is the evidence.
///
/// Asked through [`member_end`], which is where this module decides where a
/// member stops, and under the caller's own [`ParamSyntax`] and
/// [`ValuelessParameter`], which are what decide where a string may open. A scan
/// with a rule of its own here would be a SECOND answer to that question: one
/// that read a DQUOTE the field's production admits no string at could call a
/// comma data while the walk behind it read the same comma as the separator, and
/// a value would pass as a singleton and then yield two members. Passing the
/// narrower production is the same defect one step earlier — the walk would then
/// find the comma too.
///
/// Both of the caller's rules are passed for that reason and not only the
/// production. A repetition the FIELD refuses ends the derivation exactly as one
/// the production refuses does, and where the extent behind such a refusal is
/// derivable at all it is derived once, by that same call, so the two cannot
/// read a comma differently.
///
/// # A boundary the walk cannot resolve is no evidence of a comma
///
/// [`Refusal::Unbounded`] says the member's end is not derivable — some reading
/// of the bytes behind the refused repetition holds the earliest comma inside a
/// quoted-string, whether one that covers it or one that never closes, so
/// whether that comma is data or a separator has no answer. So this reports no
/// comma: the evidence a singleton field wants is a comma the value provably
/// HAS at the top level, and there is none to be had here. The walk agrees, and
/// does so by construction: it yields that one member and then
/// [`ListError::MemberBoundaryUnknown`], so a value that passes here yields no
/// second member either. What the caller is told instead is the parameter fault
/// that earned the refusal, which is a violation of the field's own grammar and
/// the reason the value is unusable.
#[inline]
pub(crate) fn has_bare_comma(
  value: &[u8],
  syntax: ParamSyntax,
  valueless: ValuelessParameter,
) -> bool {
  let (delim, refused) = member_end(value, 0, syntax, valueless);
  if refused.is_some_and(|refusal| !refusal.bounded()) {
    return false;
  }
  matches!(delim, Delim::At(at) if at < value.len())
}

/// Walks one member's parameters, `*( OWS ";" OWS [ parameter ] )`
/// (RFC 9110 §5.6.6), or the `*( OWS ";" OWS transfer-parameter )` §10.1.4
/// spells with the same repetition, a wider `parameter` and no brackets around
/// it. A parameter that does not parse yields `Err` and ends the walk.
///
/// Which of the two it is came from the member, which came from the entry
/// point, so this walk cuts the parameters apart exactly where the walk that
/// delimited the member did.
///
/// # The brackets, and where they are answered
///
/// One private function is the ONE place §5.6.6's `[ parameter ]` and §10.1.4's
/// bare `transfer-parameter` are told apart, and this walk reaches it like every
/// other reader of a repetition does — including the boundary scan, which is
/// what keeps a verdict from arriving after the boundary it is a verdict
/// about.
/// Under [`ParamSyntax::Parameter`] an empty slot is skipped; under
/// [`ParamSyntax::TransferParameter`] it is [`ListError::NotAToken`] — the
/// `token` a `transfer-parameter` begins with, absent — and it ends this walk,
/// so nothing behind a `;` the sender never completed is reported as though the
/// sender had completed it.
#[derive(Debug, Clone)]
pub struct ParamIter<'a> {
  params: &'a [u8],
  at: usize,
  tail: QuotedTail,
  /// The production this member's parameters are read with — [`ListMember`]'s
  /// own, never chosen here.
  syntax: ParamSyntax,
  /// What the field does with a parameter carrying no value — [`ListMember`]'s
  /// own, never chosen here.
  valueless: ValuelessParameter,
  /// The member's [`joined`](ListMember#structfield.joined) fault, reported in
  /// place of [`ListError::ValueSpansFieldLines`].
  joined: Option<ListError>,
  done: bool,
}

/// What ONE repetition of the parameter loop derives, over the slice it occupies
/// with the `OWS` RFC 9110 §5.6.6 puts around it already trimmed off.
///
/// RFC 9110 §5.6.6 and §10.1.4:
/// ```text
/// parameters      = *( OWS ";" OWS [ parameter ] )
/// transfer-coding = token *( OWS ";" OWS transfer-parameter )
/// ```
///
/// `None` is a repetition that ran, derived nothing, and violated nothing —
/// §5.6.6's brackets and no other case. `Some(Err(_))` is a repetition the
/// member's own production refuses. `Some(Ok(_))` is a parameter.
///
/// **One statement of what a repetition is, for both places a repetition is
/// cut.** [`ParamIter::next`] cuts the ones a member hands slices of and
/// [`scan_parameters`] cuts them while it is still finding where that member
/// ENDS — and a rule spelled once cannot be enforced at one of those and absent
/// at the other. That is not a tidiness argument: `scan_parameters` decides
/// which bytes `ParamIter` is ever handed, so a verdict it did not take is a
/// verdict that can steer the boundary it is a verdict about.
fn repetition<'a>(
  param: &'a [u8],
  tail: QuotedTail,
  syntax: ParamSyntax,
  valueless: ValuelessParameter,
) -> Option<Result<(&'a [u8], ParamValue<'a>), ListError>> {
  if param.is_empty() {
    return empty_slot(syntax).map(Err);
  }
  Some(parse_param(param, tail, syntax, valueless))
}

/// The verdict on a repetition that RAN and derived no parameter — the whole of
/// the difference RFC 9110 §5.6.6's brackets make and §10.1.4's absent ones do
/// not.
///
/// ```text
/// parameters      = *( OWS ";" OWS [ parameter ] )
/// transfer-coding = token *( OWS ";" OWS transfer-parameter )
/// ```
///
/// §5.6.6 admits the empty slot, so `m;`, `m;;p=x` and `m;p=x;` state exactly
/// the parameters written and violate nothing. §10.1.4 brackets nothing, so
/// every `;` it writes introduces a whole `transfer-parameter` and an empty
/// slot is one whose leading `token` is missing — [`ListError::NotAToken`],
/// since `token = 1*tchar` (§5.6.2) names at least one character. Leading,
/// interior and trailing are one case: each is a repetition that ran and
/// derived nothing.
///
/// Read at one place, [`repetition`], which is what carries it to every walk
/// that cuts a repetition apart.
const fn empty_slot(syntax: ParamSyntax) -> Option<ListError> {
  match syntax {
    ParamSyntax::Parameter => None,
    ParamSyntax::TransferParameter => Some(ListError::NotAToken),
  }
}

impl<'a> Iterator for ParamIter<'a> {
  type Item = Result<(&'a [u8], ParamValue<'a>), ListError>;

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      if self.done {
        return None;
      }
      // `parameter_end`'s second half — whether bytes stood behind a value that
      // closed inside this parameter — is discarded here and is not a fact
      // dropped: those bytes are on THIS line, so they are inside the slice cut
      // below and `parse_param` reads them itself. Only a value that closed
      // across RFC 9110 §5.2's join has them on a line the member does not
      // hold, and [`QuotedTail`] is what carries the verdict there.
      let end = match parameter_end(self.params, self.at, self.syntax).0 {
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
      // What a repetition derives belongs to `repetition`, which is where RFC
      // 9110 §5.6.6's brackets, §10.1.4's absent ones and the field's answer for
      // a parameter with no value are read — once, for this walk and for the
      // boundary scan alike.
      let Some(parsed) = repetition(param, self.tail, self.syntax, self.valueless) else {
        continue;
      };
      let parsed = match parsed {
        // A value spanning RFC 9110 §5.2's join is well formed and merely not
        // contiguous, so it is the one verdict here a caller may act on and
        // keep the member — which makes it the one that may not stand in front
        // of a parameter BEHIND the join that derives nothing at all. Every
        // other verdict already refuses the member, and is left where the
        // sender's own order put it.
        Err(ListError::ValueSpansFieldLines) => Err(match self.joined {
          Some(joined) => joined,
          None => ListError::ValueSpansFieldLines,
        }),
        parsed => parsed,
      };
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
///
/// Three answers rather than two, because closing is not ending. RFC 9110
/// §5.6.6's `parameter-value = ( token / quoted-string )` takes one alternative
/// WHOLE, so what stands behind the close decides as much as the close does —
/// and those bytes are on a line the parameter does not hold either.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum QuotedTail {
  /// Nothing was open there, or what was open never closed on any later line.
  /// Either way what the member's first line holds is all there is of it.
  Ends,
  /// It closed on a later field line, across the comma RFC 9110 §5.2 joins them
  /// with, and the parameter ended there — so the value is real, and is not one
  /// contiguous slice.
  Continues,
  /// It closed on a later field line and the parameter did NOT end there: bytes
  /// other than the `OWS` RFC 9110 §5.6.6 puts in front of the next `;` stand
  /// behind that close.
  ///
  /// One token or one quoted-string is the whole of a `parameter-value`, so
  /// nothing derives those bytes and the parameter is [`ListError::NotAToken`].
  /// [`parse_param`]'s `QuotedScan::Closed` arm is the same fault spelled on one
  /// field line, and this is what keeps §5.2's join from being a way past it.
  Trails,
}

/// Where a scan for a top-level delimiter got to.
pub(crate) enum Delim {
  /// The delimiter — or the end of the input — is at this offset, with every
  /// §5.6.4 quoted-string before it closed.
  At(usize),
  /// The input ended inside a quoted-string, carrying the escape state §5.2's
  /// join comma has to be fed through.
  Open(bool),
  /// A byte §5.6.4 forbids appeared inside a quoted-string.
  Invalid,
}

/// Where the `parameter` beginning at `at` admits its VALUE, or `None` where no
/// `parameter` begins there.
///
/// ```text
/// parameter          = parameter-name "=" parameter-value
/// parameter-name     = token
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Two terminals stand in front of that value and both are read here: the name
/// `token` and the `=`. What may stand BETWEEN them is the whole of the
/// difference `syntax` names. RFC 9110 §5.6.6 admits nothing — "Parameters do
/// not allow whitespace (not even "bad" whitespace) around the "=" character."
/// — while §10.1.4's `transfer-parameter` admits `BWS` on both sides, and
/// §5.6.3 makes reading it a recipient's MUST rather than its choice.
///
/// [`crate::auth`] keeps a `param_value_at` of its own for §11.2's `auth-param`,
/// which is `transfer-parameter`'s production spelled again in another section
/// — so the [`ParamSyntax::TransferParameter`] arm below and that one answer
/// alike, deliberately and by the same two skips. They are not merged because
/// §11.2's element is a whole list member with no `;` level under it, which is
/// the difference [`after_close`] carries; sharing the value-position half
/// alone would leave a reader two functions to hold together for one
/// production anyway.
///
/// `Some` is no claim that the parameter parses. What stands at the offset may
/// be neither of the two alternatives either production allows, and
/// [`parse_param`] is the one place that is decided — under this same `syntax`,
/// so a boundary and a verdict never come from different grammars. This answers
/// about POSITION alone, which is all a boundary scan may take from it.
fn param_value_at(value: &[u8], at: usize, syntax: ParamSyntax) -> Option<usize> {
  let name_end = token_end(value, at)?;
  let equals = match syntax {
    ParamSyntax::Parameter => name_end,
    ParamSyntax::TransferParameter => skip_ows(value, name_end),
  };
  if value.get(equals) != Some(&b'=') {
    return None;
  }
  let after = equals.saturating_add(1);
  Some(match syntax {
    ParamSyntax::Parameter => after,
    ParamSyntax::TransferParameter => skip_ows(value, after),
  })
}

/// Where the run at `at` ends when the field's own `parameter` production —
/// RFC 9110 §5.6.6's or §10.1.4's, as its [`ParamSyntax`] says — admits no
/// quoted-string anywhere in it: the first `;` or `,`, read raw, or the end of
/// `value`.
///
/// # A DQUOTE opens nothing where no string may begin
///
/// What a quoted-string is, is not where one may START, and the productions a
/// member is made of leave exactly one such position:
///
/// ```text
/// parameters      = *( OWS ";" OWS [ parameter ] )
/// parameter       = parameter-name "=" parameter-value
/// parameter-value = ( token / quoted-string )
/// ```
///
/// RFC 9110 §5.6.2's `tchar` excludes DQUOTE and §5.6.3's `OWS` is SP and HTAB,
/// so the first byte of a `parameter-value` is the only place any of these
/// admits one, and [`param_value_at`] is that position — under the field's own
/// [`ParamSyntax`], since §10.1.4's `transfer-parameter` puts that same position
/// behind `BWS "=" BWS` instead. The member's NAME admits none anywhere: both of
/// this walk's name grammars are spelled out of `tchar` and `/`, neither of
/// which is a DQUOTE either.
/// Anywhere else a DQUOTE is a byte no production admits: it opens no string,
/// every delimiter in the run is the one it looks like, and the first of them is
/// where the run stops.
///
/// Reading a DQUOTE as an opener wherever it fell is how a malformed member hid
/// a well-formed one. In `m;p=x"y, second` the value of `p` already took the
/// `token` alternative, so the DQUOTE behind it begins nothing — yet it opened a
/// string that swallowed the comma in front of `second`, and the walk reported
/// one member where the sender wrote two.
///
/// # What the rule costs, and what it may not be made to cost
///
/// An unadmitted DQUOTE pairs with no later one, so a DQUOTE that a
/// pair-anywhere reading would have used to CLOSE a refused run leaves the next
/// admitted position free to OPEN instead. Walked as RFC 9110 §5.6.6's
/// `parameter`, `m;p ="a,b", second` cuts inside bytes the sender wrote as a
/// string — that production puts no whitespace around the `=`, so `p ` is no
/// `parameter-name` and the string is admitted nowhere in that member, which
/// makes the comma inside `"a,b"` §5.6.1.2's separator under every reading of
/// this production. The member ends there, `b"` is what is left of it and is
/// crossed rather than read, and `second` is yielded. The caller is handed a
/// fault for the bytes the sender actually wrote, and the member behind them.
///
/// That trade is available only because the value really was refused by the
/// field's OWN production. It is NOT available against a production the field
/// does have: `gzip;p = "a,b", chunked` is a conforming `TE` and
/// `Transfer-Encoding` value, its string opens where §10.1.4 says it does, and
/// cutting at the comma inside it invents a member and hides the `chunked`
/// written behind it. [`ParamSyntax`] is what keeps the two apart, and the
/// direction of the asymmetry is the whole reason it is carried rather than
/// defaulted.
fn raw_run_end(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while !matches!(value.get(at), None | Some(&b';' | &b',')) {
    at = at.saturating_add(1);
  }
  at
}

/// Where the run at `at` ends when no RFC 9110 §5.6.4 quoted-string is ADMITTED
/// anywhere in it: the first `,`, read raw, or the end of `value`.
///
/// A quoted-string is something a production admits at a POSITION. Where none
/// does, a DQUOTE is one more byte of the run — it opens nothing — so every
/// comma in the run is the §5.6.1.2 separator it looks like, and the first of
/// them is where the run stops.
///
/// The callers are the ones whose ELEMENT grammar puts no quoted-string in it at
/// all: [`sender_list_shape`] and [`is_protocol_list`], since §7.6.1's
/// `connection-option` and §7.8's `protocol` are `token`s and §5.6.2's `tchar`
/// excludes DQUOTE. There is nothing in such an element for a DQUOTE to be part
/// of, so the run is one element and the comma behind it is the separator.
/// The counterpart in `auth` is `auth::raw_comma_end`, which serves §11.2's
/// list the same way.
///
/// Stopping at the end of the line rather than crossing §5.2's join is the same
/// answer: the join IS a comma, so the run ends there either way.
///
/// # Which way to err
///
/// A run cut here is cut where the sender may have meant no boundary at all, and
/// these callers err toward finding MORE elements than the sender meant. They
/// pay nothing for it: the extra elements a cut can find are empty ones, and
/// finding an empty element is the refusal they exist to make.
///
/// The RECIPIENT-side walk does not cut this way on the strength of this answer
/// ALONE. [`parameterised_list`] stops at the first `Err`, so a member invented
/// behind a raw cut can end the walk AND be handed to the caller as a member
/// the sender named — and one raw cut too many turns a `Transfer-Encoding`
/// parameter's quoted value into a `chunked` coding. Behind a refusal that walk
/// asks this AND [`readings_at`], and cuts only where no reading of those bytes
/// holds this comma inside a quoted-string, which is [`refused_member_end`].
fn raw_comma_end(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while !matches!(value.get(at), None | Some(&b',')) {
    at = at.saturating_add(1);
  }
  at
}

/// The RFC 9110 §5.6.4 positions the readings of one run stand in at an
/// offset, as ONE value.
///
/// Behind a fault `parameters` derives nothing, so each DQUOTE the field's own
/// production admits a `parameter-value` at is a place a reading MAY open a
/// string and may equally leave shut — the bytes there need not be a
/// `parameter-value` at all. Enumerating the readings is exponential in the
/// number of those positions. Tracking the STATES they stand in is not: there
/// are four, a reading's next state depends on the byte and on its own state
/// alone, and [`readings_at`] carries the set of them across one left-to-right
/// pass.
///
/// The fourth state is the one with no flag here: OUTSIDE every string. It is
/// in the set at every offset, because the reading that opens nothing exists
/// over any bytes at all — so all three flags clear says every reading is
/// outside, and [`Readings::covers`] is the question that asks it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
struct Readings {
  /// Some reading is inside a `quoted-string` with no `quoted-pair` pending.
  inside: bool,
  /// Some reading is inside one whose previous byte was the backslash of a
  /// `quoted-pair`, so the next byte is that pair's data whatever it is —
  /// including a DQUOTE, which does not close the string there.
  escaped: bool,
  /// Some reading opened a string that has since reached a byte RFC 9110
  /// §5.6.4's grammar forbids. It reaches no close at all, so it covers every
  /// comma left in `value` and §5.2's join behind them.
  sealed: bool,
}

impl Readings {
  /// Whether ANY reading has the offset this set was taken at inside a
  /// quoted-string — which is what would make a comma there that reading's
  /// data rather than RFC 9110 §5.6.1.2's separator.
  const fn covers(self) -> bool {
    self.inside || self.escaped || self.sealed
  }

  /// Every reading still inside a string, advanced by one byte.
  ///
  /// [`scan_quoted`] is this crate's one implementation of what RFC 9110
  /// §5.6.4's `quoted-string` is, and it is what answers here — fed one byte,
  /// the way [`scan_quoted_after_join`] feeds it §5.2's separator. Writing
  /// `qdtext` and `quoted-pair` out again as byte tests would be a second
  /// answer to the same question, free to drift from the first.
  ///
  /// The reading standing OUTSIDE every string needs no step: it is outside at
  /// the next offset too, whatever the byte was. Where it may open one is
  /// [`readings_at`]'s, because that is the one thing a byte alone does not
  /// decide.
  fn step(self, byte: u8) -> Self {
    let mut next = Self {
      inside: false,
      escaped: false,
      // A string that can no longer close stays open over every byte behind
      // it, so nothing moves that reading anywhere.
      sealed: self.sealed,
    };
    if self.inside {
      next.absorb(scan_quoted(&[byte], 0, false));
    }
    if self.escaped {
      next.absorb(scan_quoted(&[byte], 0, true));
    }
    next
  }

  /// One reading's step, taken into the set.
  fn absorb(&mut self, step: QuotedScan) {
    match step {
      // The string closed on this byte, so that reading is outside from the
      // next one — which is where the reading that opened nothing has been all
      // along, and that one is in the set already.
      QuotedScan::Closed(_) => {}
      QuotedScan::Open { escape: false } => self.inside = true,
      QuotedScan::Open { escape: true } => self.escaped = true,
      // Deliberately more than RFC 9110 §5.6.4 requires. A forbidden octet
      // means no `quoted-string` derives at that position, so the GRAMMAR
      // leaves only the readings that opened nothing there — but the sender
      // still wrote those bytes between DQUOTEs, and `gzip;;x="a\x01, chunked,
      // b", br` cut raw hands back a `chunked` that stood among them.
      QuotedScan::Invalid => self.sealed = true,
    }
  }
}

/// The RFC 9110 §5.6.4 states the readings of `value` reach at `at`, given
/// that every one of them stood outside a string at `from`.
///
/// A subset construction over which admitted quoted-strings a reading opens,
/// and the whole of what makes a boundary behind a fault PROVABLE rather than
/// compared: two readings agreeing is a sample of two, and the mixed readings
/// between them are where a manufactured member came from.
///
/// # Where a string may open, and why one scan finds it for every reading
///
/// ```text
/// quoted-string      = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// parameters         = *( OWS ";" OWS [ parameter ] )
/// parameter          = parameter-name "=" parameter-value
/// parameter-name     = token
/// parameter-value    = ( token / quoted-string )
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// A string opens at a DQUOTE and nowhere else, and the one position either of
/// those productions puts one at is the first byte of a value —
/// [`param_value_at`], since RFC 9110 §5.6.2's `tchar` excludes DQUOTE and
/// §5.6.3's `OWS` is SP and HTAB. So an opener stands where a `;`, and behind
/// it that production's name and its `=`, stand in front of a DQUOTE.
///
/// None of those bytes is a DQUOTE and a string ends only at one, so a reading
/// standing outside at an opener stood outside at the `;` that named it too:
/// every reading in the set names the SAME openers. One scan therefore finds
/// them for all of them, and the set never has to remember where a reading's
/// own string began — which is why three flags are enough however many
/// openers stand in the run.
///
/// # The choice, and why it is one
///
/// A reading may open the string an admitted DQUOTE offers, or leave it shut.
/// `parameters` has already failed to derive here, so no production forces the
/// `quoted-string` alternative on those bytes — the repetition may be
/// malformed in any way at all, and a DQUOTE the sender typed by accident is
/// one of the ways. Opening every one is the greedy reading, opening none is
/// [`raw_comma_end`]'s, and the readings BETWEEN them are the ones a
/// comparison of those two never asked.
///
/// `m;;a="x;b="y,chunked,z",w` is what that cost. The empty slot RFC 9110
/// §10.1.4 refuses faults, and the greedy reading opens the string at `a`'s
/// value position — which swallows the DQUOTE that would have opened `b`'s —
/// so both extremes end the member at the comma behind `y`. The reading that
/// leaves `a` shut opens the string at `b`'s value position instead and holds
/// that comma, and the `chunked` behind it, inside bytes the sender wrote as a
/// value. On `TE` and `Transfer-Encoding` a coding read out of a quoted value
/// is a framing decision made up out of the sender's data.
fn readings_at(value: &[u8], from: usize, at: usize, syntax: ParamSyntax) -> Readings {
  let mut open = Readings::default();
  // The one position the last `;` crossed by the outside reading admits a
  // string at. No second `;` stands between a `;` and the value position it
  // names — RFC 9110 §5.6.6's `parameter-name` is a `token`, and neither the
  // `OWS` nor the `=` around it is a `;` — so at most one of these is unreached
  // at a time and overwriting it loses nothing.
  let mut opener = None;
  let mut from = from;
  while from < at {
    let Some(&byte) = value.get(from) else {
      break;
    };
    if byte == b';' {
      opener = param_value_at(value, skip_ows(value, from.saturating_add(1)), syntax)
        .filter(|&value_at| value.get(value_at) == Some(&b'"'));
    }
    let opens = opener == Some(from);
    open = open.step(byte);
    if opens {
      // The reading that takes this DQUOTE as an opener is inside the string
      // from the NEXT byte on. The one that leaves it shut is the reading
      // outside every string, which is in the set already.
      open.inside = true;
    }
    from = from.saturating_add(1);
  }
  open
}

/// Where the RFC 9110 §5.6.6 `parameter` whose value just CLOSED at `end` ends,
/// and whether anything underivable stood between the two.
///
/// # A close is not an end
///
/// Past the close only whitespace is derivable.
/// `parameter-value = ( token / quoted-string )` takes one alternative WHOLE and
/// `parameters = *( OWS ";" OWS [ parameter ] )` wraps the loop around it — so
/// between a value that closed here and the `;` that opens the next repetition,
/// or the `,` §5.6.1.2 ends the member with, there is room for that `OWS` and
/// for nothing else. Reaching one of those, or the end of `value`, the parameter
/// is what it looked like and `trails` is false; the end of a line counts as
/// that comma, since §5.2 puts one at every join and the value ends where the
/// lines run out.
///
/// # What a proven-malformed remainder may not decide
///
/// Reaching anything ELSE, the remainder of THIS repetition derives nothing —
/// and a run that derives nothing contains no quoted-string, so a DQUOTE in it
/// opens none. [`raw_run_end`] therefore takes the rest of the repetition RAW,
/// and this reports `trails` for the parameter.
///
/// Granting those bytes quoted-string semantics is how a malformed member hides
/// a well-formed one: `m;p="a` and `r"ju"nk, second` are two field lines that
/// §5.2 joins into one value, the value of `p` closes at `r"`, and a DQUOTE in
/// `ju"nk` read as an opener swallows the comma in front of `second`. What is
/// hidden there is a media type, a transfer coding or an extension — whichever
/// field this walk was entered for — and the caller is not told it was ever
/// sent.
///
/// The raw scan stops at this repetition's own end — the `;` that opens the
/// next one as much as the `,` that ends the member — and does NOT run on to
/// the comma. A repetition behind a refused one is one the field's `parameter`
/// admits a quoted-string INSIDE, at the position [`param_value_at`] names, and
/// whether crossing that raw moves the comma is [`refused_member_end`]'s to
/// answer rather than this scan's to assume.
///
/// [`crate::auth`] keeps this rule for RFC 9110 §11.2's `auth-param`, under the
/// same name and for the same reason; the `;` is what the two answers differ by.
/// An `auth-param` is one whole element of a list and nothing may follow its
/// value inside that element, while a `parameter` is one repetition of
/// `parameters` and the next repetition may follow it.
///
/// # Why this one takes no [`ParamSyntax`]
///
/// Neither of the two differences between the productions is reachable from
/// here. The `BWS` stands in FRONT of the value, between the name and the `=`,
/// and this is asked BEHIND a value that closed. The other — whether the slot
/// may be empty, which RFC 9110 §5.6.6 brackets and §10.1.4 does not — is a
/// question about a slot's CONTENT and not about where one ends: an empty slot
/// stops at the same `;`, `,` or end of value under both, so it moves no
/// boundary, and [`ParamIter`] is where the verdict on it is given.
///
/// Behind a value the two spell the same thing:
/// §5.6.6's `parameters = *( OWS ";" OWS [ parameter ] )` and §10.1.4's
/// `transfer-coding = token *( OWS ";" OWS transfer-parameter )` each put `OWS`
/// and then a `;`, and §5.6.1.2's `,` ends the member either way. A parameter
/// this function would take is one the two grammars agree about, so taking one
/// would be a knob with one setting — and a caller could set it wrong.
fn after_close(value: &[u8], end: usize) -> (usize, bool) {
  let at = skip_ows(value, end);
  match value.get(at) {
    None | Some(&b';' | &b',') => (at, false),
    Some(_) => (raw_run_end(value, at), true),
  }
}

/// Where a member whose `parameters` have already been REFUSED ends, or `None`
/// where that is not derivable.
///
/// `fault` is the last offset at which EVERY reading of these bytes still
/// stands outside a quoted-string, and both the candidate comma and the state
/// walk are taken from it. [`scan_parameters`] passes the `;` that opened the
/// refused repetition; the arm of [`ParameterisedList::member`] behind RFC 9110
/// §5.2's join passes the offset [`after_close`] left it on; and
/// [`ParameterisedList::seek`] passes the first byte of an element of the
/// refused member. Up to the fault the member's `parameters` derive, and a
/// `parameter-value` that begins with a DQUOTE derives only the
/// `quoted-string` alternative — §5.6.2's `tchar` excludes DQUOTE, so the
/// `token` alternative is not available — so those strings are the grammar's
/// and not a choice. From the fault on nothing derives and every admitted
/// DQUOTE is a choice, which is what [`readings_at`] enumerates the states of.
///
/// # No reading may have terminated in front of the comma being certified
///
/// The analysis below proves that no reading holds the candidate comma inside
/// a string. That is a proof about the member's BOUNDARY only where no reading
/// had already ended the member EARLIER: a reading that stopped at a comma
/// behind this one is a reading in which the bytes between the two are a
/// member of their own, and certifying this comma hides it.
///
/// Taking the candidate from `fault` is what keeps that true, and taking it
/// from anywhere else is what broke it. The earliest comma from the fault is
/// where the member ends under the reading that opens nothing, and no reading
/// ends it earlier — an open string only ever HIDES a comma, never reveals one
/// — so every reading's own end lies at or behind that comma and none can have
/// terminated in front of it. A candidate taken from a LATER offset has no
/// such standing. [`scan_parameters`] finds its fault at a repetition whose
/// extent [`parameter_end`] cut by OPENING that repetition's string, and a
/// comma that string swallowed is one the reading leaving it shut ends the
/// member at.
///
/// `gzip;p="a, chunked;q="x", br` read as RFC 9110 §10.1.4's
/// `transfer-parameter` is that input. The greedy extent runs to the DQUOTE
/// behind `q=` and then to the comma in front of `br`, which every reading
/// does stand outside of — while the reading that never opens `p`'s string
/// ended the member at the comma behind `"a`, leaving `chunked;q="x"` as a
/// `transfer-coding` of its own. Certifying the later comma resumed the walk
/// at `br` and hid that coding. The candidate is the comma behind `"a`, the
/// greedy reading holds it inside a string, and the answer is `None`.
///
/// `m;;a="x;b="y,chunked,z",w` read as §5.6.6's `parameter` is why the state
/// walk starts at the fault rather than at the refused repetition's end:
/// §5.6.6 brackets the empty slot, so the fault is the `a` repetition itself,
/// and a walk beginning behind it would miss the reading that leaves `a` shut
/// and holds `chunked` inside the value at `b`'s position.
///
/// # Every reading, and the offset none of them covers
///
/// A refused `parameters` derives nothing behind the refusal, so the bytes in
/// front of the next comma have many readings and no rule left to pick between
/// them:
///
/// ```text
/// quoted-string      = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// parameter-value    = ( token / quoted-string )
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Each DQUOTE the field's own production admits a value at is one a reading
/// may open a string with or leave shut, so the readings number two to the
/// power of however many of those stand in the run. They are not enumerated:
/// [`readings_at`] carries the SET of RFC 9110 §5.6.4 states they reach across
/// one left-to-right pass, which is [`Readings`] and is three flags wide.
///
/// The earliest comma from the fault read RAW ([`raw_comma_end`]) is where the
/// member ends under the reading that opens nothing, and no reading ends it
/// earlier — an open string only ever HIDES a comma, never reveals one. So
/// every reading ends the member at that offset exactly when no reading holds
/// it inside a string, and that is the whole question: [`Readings::covers`],
/// asked once, at that offset. Where some reading does cover it the readings
/// part, the end is genuinely underivable, and `None` says so; the walk's
/// answer for that is [`ListError::MemberBoundaryUnknown`].
///
/// This is a proof over every reading rather than a sample of two, and the
/// difference is not academic. Comparing the raw reading with the greedy one
/// accepted `m;;a="x;b="y,chunked,z",w` under RFC 9110 §10.1.4, whose middle
/// reading holds that comma and the `chunked` behind it inside the value at
/// `b`'s position — [`readings_at`] carries that reading, so it is refused.
///
/// # Both sides, and neither is a small place
///
/// `gzip;;x="a, chunked, b", br` is a `Transfer-Encoding` whose empty slot
/// §10.1.4 refuses. Under the reading that opens nothing the member ends at
/// the comma inside `x`'s value, and the walk goes on to yield a `chunked`
/// that stood INSIDE that value and then a `b"` that is no `token` — which
/// ends the walk and hides the `br` the sender really did write. Under the
/// reading that opens the string it ends at the comma behind the close. One
/// reading covers the earliest comma, so neither offset is offered:
/// manufacturing a transfer coding and hiding one are the same harm on the
/// field that decides framing, and this recovery would do both at once.
///
/// `gzip;;x="a", chunked` and `gzip;;q=x, chunked` and `gzip;q, chunked` are
/// the other side. In the first, the string opens where §10.1.4 says it does
/// and CLOSES in front of the only comma, so the reading that opened it is
/// outside there too; in the others no string is admitted before that comma at
/// all. Either way no reading covers it, `chunked` is a member whose
/// boundaries this walk knows, and refusing to report it would hide a transfer
/// coding for nothing.
///
/// # A DQUOTE that no `parameter-value` admits is in no reading
///
/// [`raw_run_end`]'s rule is unchanged and [`readings_at`] is built on the
/// same one. In `m;p ="a,b", second` read as RFC 9110 §5.6.6's `parameter`,
/// `p ` is no `parameter-name`, so no `parameter-value` begins there, so the
/// DQUOTE opens nothing in ANY reading and the comma inside the bytes the
/// sender wrote as a string is the separator in all of them. The refused
/// repetition ends at that comma, `b"` is crossed as what is left of the
/// member, and `second` is yielded. That is a fact about the production rather
/// than a concession made after a fault, and it is why the state walk and the
/// raw scan share [`param_value_at`] rather than one of them guessing.
fn refused_member_end(value: &[u8], fault: usize, syntax: ParamSyntax) -> Option<usize> {
  let end = raw_comma_end(value, fault);
  (!readings_at(value, fault, end, syntax).covers()).then_some(end)
}

/// A repetition the member's own `parameter` production refused, and what the
/// scan that found it could still say about where that member ENDS.
///
/// The fault itself is the same either way. What differs is whether the
/// delimiter reported beside it is the member's end or merely the last offset
/// the walk can vouch for, and [`refused_member_end`] is where that is decided.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Refusal {
  /// The member ends at the delimiter reported beside this. No reading of the
  /// bytes between the refusal and it holds that offset inside a RFC 9110
  /// §5.6.4 quoted-string, so every reading ends the member there and the comma
  /// is §5.6.1.2's separator in all of them.
  Bounded(ListError),
  /// The member's end is not derivable, and the delimiter reported beside this
  /// is only where the REFUSED repetition stopped. Everything behind it is
  /// unread, which is what [`ListError::MemberBoundaryUnknown`] tells the
  /// caller.
  Unbounded(ListError),
}

impl Refusal {
  /// The repetition's own fault, which the member carries whichever of the two
  /// this is.
  const fn fault(self) -> ListError {
    match self {
      Self::Bounded(fault) | Self::Unbounded(fault) => fault,
    }
  }

  /// Whether the member's end is derivable.
  const fn bounded(self) -> bool {
    matches!(self, Self::Bounded(_))
  }
}

/// Where the one `[ parameter ]` beginning at `at` ends — the `;` that opens RFC
/// 9110 §5.6.6's next repetition, the `,` §5.6.1.2 ends the member with, or the
/// end of `value` — and whether anything underivable stood behind a value that
/// closed inside it. §10.1.4's `*( OWS ";" OWS transfer-parameter )` repeats the
/// same way, and `syntax` says which of the two `parameter`s is inside it.
///
/// **The one place a `parameter`'s extent is derived.** [`ParamIter`] cuts a
/// member's parameters apart with it and [`scan_parameters`] finds the member's
/// own end with it, over the same bytes from the same offsets, so the two cannot
/// put a boundary in different places — and they must not, since the second
/// decides which bytes the first is ever handed.
///
/// `at` stands where the repetition begins, which is on the `OWS` §5.6.6 puts
/// behind the `;`.
fn parameter_end(value: &[u8], at: usize, syntax: ParamSyntax) -> (Delim, bool) {
  let at = skip_ows(value, at);
  let opens =
    param_value_at(value, at, syntax).filter(|&value_at| value.get(value_at) == Some(&b'"'));
  let Some(quote) = opens else {
    return (Delim::At(raw_run_end(value, at)), false);
  };
  match scan_quoted(value, quote.saturating_add(1), false) {
    QuotedScan::Closed(end) => {
      let (end, trails) = after_close(value, end);
      (Delim::At(end), trails)
    }
    QuotedScan::Open { escape } => (Delim::Open(escape), false),
    QuotedScan::Invalid => (Delim::Invalid, false),
  }
}

/// Where the member ends, from a position at which one repetition of RFC 9110
/// §5.6.6's `parameters` — or of the identical loop §10.1.4 wraps around a
/// `transfer-parameter` — has just been settled: `at` stands on the `;` that
/// opens the next, on the `,` that ends the member, or on the end of `value`.
/// Reported beside it: the first repetition this scan refused, where one was.
///
/// The loop RFC 9110 §5.2's join has to be able to re-enter. A value that closed
/// across the join leaves the walk standing exactly here, on a LATER field line,
/// with the rest of that member's `parameters` still in front of it — and each
/// of those admits a quoted-string of its own at the one position
/// [`param_value_at`] names. A join that refused to re-enter would call
/// `ext;p="a` + `"; q="b, c", other` two members instead of one, cutting inside
/// a value the sender wrote.
///
/// # The verdict is taken where the boundary is, in one pass
///
/// Every repetition this scan SETTLES — one whose bytes all lie on the line in
/// hand — is derived through [`repetition`] the moment its extent is known, and
/// before the next repetition's bytes are read. Two things follow, and each of
/// them was a defect while the two passes were apart:
///
/// - **A refused repetition can steer no boundary.** `parameters` has already
///   failed to derive at that repetition, so a scan that read on would let a
///   `q="oops, chunked` written behind the fault swallow the comma in front of
///   `chunked` and hide a transfer coding that decides framing. Where the
///   member ends is then [`refused_member_end`]'s, which crosses only the runs
///   no reading holds the comma inside a string in — and answers `None`, as
///   [`Refusal::Unbounded`], where one does. Cutting raw THERE would
///   manufacture a member out of a quoted-string's interior, which on the same
///   field is the same harm the other way round.
/// - **A repetition behind §5.2's join is verdicted at the only moment this walk
///   holds it.** A member's own slice holds the repetitions on the line it BEGAN
///   on and nothing else, so the ones on a LATER line are verdicted here or
///   never — and never is §5.2's join turned into a way past `[ parameter ]`,
///   past `transfer-parameter`, and past every rule [`parse_param`] applies.
///
/// The repetition a [`Delim::Open`] leaves UNSETTLED is not derived here: its
/// bytes are not all on this line. It is `ParameterisedList::member`'s to
/// answer, the same way [`QuotedTail`] answers for the member's own.
fn scan_parameters(
  value: &[u8],
  at: usize,
  syntax: ParamSyntax,
  valueless: ValuelessParameter,
) -> (Delim, Option<Refusal>) {
  let mut at = at;
  loop {
    if value.get(at) != Some(&b';') {
      // The `,` RFC 9110 §5.6.1.2 separates members with, or the end of this
      // field line — which §5.2 makes the same thing, since it puts a comma at
      // every join.
      return (Delim::At(at), None);
    }
    // Each repetition begins strictly behind the `;` that opened it, so `at`
    // rises on every pass and this loop is finite.
    match parameter_end(value, at.saturating_add(1), syntax) {
      // `trails` is not read here: the bytes it names are inside the repetition
      // cut below, where `parse_param` reads them itself. Only a value that
      // closed across §5.2's join has them on another line, and `QuotedTail` and
      // `ParameterisedList::member` are what carry the verdict there.
      (Delim::At(end), _) => {
        let param = trim_ows(value.get(at.saturating_add(1)..end).unwrap_or_default());
        if let Some(Err(fault)) = repetition(param, QuotedTail::Ends, syntax, valueless) {
          // Refused, so the rest of the member is refused with it. Where the
          // member ENDS is the one thing this scan may not decide for itself,
          // and `end` is no part of that answer: `parameter_end` cut it by
          // opening this repetition's own string, so a comma that string
          // swallowed is one the reading leaving it shut ends the member at.
          // The `;` this repetition opened at is the last offset every reading
          // stands outside a string, and the candidate comma is taken from
          // there.
          return match refused_member_end(value, at, syntax) {
            Some(member) => (Delim::At(member), Some(Refusal::Bounded(fault))),
            // No boundary, so `end` is handed back as an EXTENT and nothing
            // more: it is where the refused repetition stopped, which is all of
            // the member this scan read, and `Refusal::Unbounded` tells the
            // caller that what stands behind it is unread.
            None => (Delim::At(end), Some(Refusal::Unbounded(fault))),
          };
        }
        at = end;
      }
      (settled, _) => return (settled, None),
    }
  }
}

/// Where the RFC 9110 §5.6.1.2 member starting at `at` ends — the comma that
/// separates it from the next, or the end of `value`.
///
/// A member is its name and then its `parameters` — §5.6.6's repetition or the
/// one §10.1.4 spells the same way, which is what `syntax` picks between and
/// the only thing this function does with it. The name admits no quoted-string
/// under either: this walk's names are `token` (§5.6.2) and
/// `type "/" subtype` (§8.3.1), and neither holds a DQUOTE. So it is read raw,
/// and everything behind it is [`scan_parameters`]'s.
///
/// [`scan_quoted`] is this crate's one implementation of what a quoted-string
/// IS, and every answer here is taken from it, so a comma inside one is data
/// here exactly as it is everywhere else in the crate. What these functions add
/// is where one may BEGIN, which [`raw_run_end`] carries.
///
/// The refusal [`scan_parameters`] reports beside the delimiter is passed
/// through, and what a caller does with it differs by caller. `ParameterisedList`
/// takes a [`Refusal::Bounded`] as the signal that this member is refused and
/// that what is left of it is to be got past rather than read, and a
/// [`Refusal::Unbounded`] as the signal that there is nothing behind it it may
/// report at all; [`has_bare_comma`] reads only which of the two it is, because
/// its question is only where the first member stops. Neither may put the FAULT
/// on the member: the repetitions on the line the member BEGAN on are inside
/// the member's own slice, so [`ParamIter`] hands the caller each one's verdict
/// in the order the sender wrote them, and a member-level first fault recorded
/// here would name one of those parameters before the walk had reached it — and
/// name it as the fault of the parameter that crosses RFC 9110 §5.2's join,
/// which is a fault of the wrong parameter.
fn member_end(
  value: &[u8],
  at: usize,
  syntax: ParamSyntax,
  valueless: ValuelessParameter,
) -> (Delim, Option<Refusal>) {
  scan_parameters(value, raw_run_end(value, at), syntax, valueless)
}

/// One `parameter` — RFC 9110 §5.6.6's or §10.1.4's, as `syntax` says — over a
/// slice already trimmed of the OWS that production puts around it, and never
/// empty: whether an empty slot is admitted at all is §5.6.6's brackets against
/// §10.1.4's lack of them, and [`repetition`] settles that before reaching here.
///
// gate-exempt: q = 1 — a weight value in prose, not RFC 9110 grammar
/// Under RFC 9110 §5.6.6 the name is a `token` and the `=` is the byte
/// immediately behind it — "Parameters do not allow whitespace (not even "bad"
/// whitespace) around the "=" character." — so `q = 1` names `q `, which is not
/// a `token`, and is not a parameter. The same reading as this crate's `Expect`
/// parser, which is the point: one rule, one answer. Under §10.1.4 the same
/// bytes ARE a parameter, because `transfer-parameter` puts `BWS` on both sides
/// of that `=` and §5.6.3 makes a recipient read it.
///
/// [`param_value_at`] asks those same terminals of the same bytes under the same
/// `syntax` so that a boundary scan knows where a quoted-string may open, and
/// this is that question asked for the value rather than a second spelling of it
/// that could drift. A DQUOTE in front of the `=` is refused HERE by the name
/// not being a token, and it opens no string THERE — neither reading gives it
/// any standing.
///
/// Neither production spells a bare name with no `=`, and `valueless` says what
/// the field wants done about it: [`ParamValue::None`] reports the SHAPE for a
/// field whose own grammar brackets the value, and
/// [`ListError::MissingParameterValue`] refuses it for a field that does not.
/// What a `parameter` admits is one question and what a FIELD does with a
/// parameter is another; this takes the second as an argument rather than
/// deciding it, and [`ValuelessParameter`] is where the reason a field states
/// it HERE rather than over what the walk hands back is written down.
fn parse_param(
  param: &[u8],
  tail: QuotedTail,
  syntax: ParamSyntax,
  valueless: ValuelessParameter,
) -> Result<(&[u8], ParamValue<'_>), ListError> {
  let Some(name_end) = token_end(param, 0) else {
    return Err(ListError::NotAToken);
  };
  let name = param.get(..name_end).unwrap_or_default();
  // `param` is trimmed, so under either production this lands on the `=`, on
  // the byte that should have been one, or on the end.
  let equals = match syntax {
    ParamSyntax::Parameter => name_end,
    ParamSyntax::TransferParameter => skip_ows(param, name_end),
  };
  let value = match param.get(equals) {
    // No `=` at all: the bare-name form, which neither production derives and
    // which the field either reads or refuses.
    None => {
      return match valueless {
        ValuelessParameter::Reported => Ok((name, ParamValue::None)),
        ValuelessParameter::Refused => Err(ListError::MissingParameterValue),
      };
    }
    Some(&b'=') => {
      let after = equals.saturating_add(1);
      let start = match syntax {
        ParamSyntax::Parameter => after,
        ParamSyntax::TransferParameter => skip_ows(param, after),
      };
      param.get(start..).unwrap_or_default()
    }
    // A byte behind the name that is neither: `parameter-name` is a `token`
    // taken whole, so what is here is one name with a tail neither production
    // derives anything for.
    Some(_) => return Err(ListError::NotAToken),
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
        // It closed there and the parameter ran on past that close, which the
        // arm above this `match` already refuses when both lie on one field
        // line. One rule, and RFC 9110 §5.2's join is not a way past it.
        QuotedTail::Trails => ListError::NotAToken,
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
  /// The member the cursor stands behind was REFUSED, and what is left of it has
  /// still to be got past.
  ///
  /// Set only by [`refuse`](ParameterisedList::refuse), so the pairing with
  /// [`seek`](ParameterisedList::seek) cannot be forgotten at a new fault, and
  /// cleared only by reaching an element whose name this walk's own grammar
  /// admits. While it is set the walk crosses exactly the runs
  /// [`refused_member_end`] can vouch for: those no reading of which holds the
  /// comma inside a quoted-string, so that comma is a separator whichever
  /// reading the sender meant.
  recovering: bool,
  /// A member's `parameters` were refused and where that member ENDS is not
  /// derivable — [`Refusal::Unbounded`], or the same answer from
  /// [`seek`](ParameterisedList::seek).
  ///
  /// Set only by [`refuse`](ParameterisedList::refuse), the same one writer the
  /// other flag has. The member in front of the fault is yielded first, since
  /// its name and the repetitions up to that fault are derived; then this makes
  /// [`ListError::MemberBoundaryUnknown`] the walk's last item, because
  /// everything behind an unresolved boundary is unread and there is nothing
  /// honest left to yield.
  unresolved: bool,
  /// The grammar a member NAME must satisfy. Each public entry point supplies
  /// its own, so each guarantees its own name grammar and no caller re-checks.
  name_ok: fn(&[u8]) -> bool,
  /// The `parameter` production this field spells, which decides where a
  /// quoted-string may open and so where every member ENDS.
  syntax: ParamSyntax,
  /// What this field does with a parameter carrying no value.
  valueless: ValuelessParameter,
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
      if self.unresolved {
        // The member that earned this has already been yielded, with the
        // parameter fault on it. What is behind it is bytes this walk will not
        // guess at, and it is every one of them: the value ends here.
        self.done = true;
        return Some(Err(ListError::MemberBoundaryUnknown));
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
        // What is left of a member already refused is got past here, and is
        // never read as members of its own.
        Some(_) if self.recovering && !self.opens_a_member() => self.seek(),
        Some(_) => {
          self.recovering = false;
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

  /// Whether an element that this walk's own name grammar admits begins at the
  /// cursor.
  ///
  /// The name is read the way [`member`](Self::member) reads it — to the first
  /// `;` or `,`, taken RAW, since neither name grammar this walk is entered with
  /// holds a DQUOTE — so the two cannot disagree about what opens a member.
  ///
  /// Asked only while recovering, where it is the whole of the question: an
  /// element that no member of this list could be is one more piece of the
  /// member already refused, and one that could be is where the refusal stops.
  fn opens_a_member(&self) -> bool {
    let end = raw_run_end(self.line, self.at);
    (self.name_ok)(trim_ows(self.line.get(self.at..end).unwrap_or_default()))
  }

  /// Refuses the member the cursor stands behind, and says which of the two
  /// things follows from it: `bounded` is whether that member's END was
  /// derivable, which is [`refused_member_end`]'s answer.
  ///
  /// The one writer of BOTH flags, so neither pairing can be forgotten at a new
  /// fault. A member refused without `recovering` would leave what is left of
  /// it to be read as members of its own, and the bytes behind a fault would
  /// decide where members are. A member refused without `unresolved` where its
  /// end was NOT derivable would leave the walk standing at an offset it cannot
  /// vouch for, reading whatever a quoted-string of the sender's happens to
  /// hold as members of the list.
  fn refuse(&mut self, bounded: bool) {
    if bounded {
      self.recovering = true;
    } else {
      self.unresolved = true;
    }
  }

  /// Gets past one element of a member already refused, by the comma every
  /// reading of it ends at — or gives up, where [`refused_member_end`] can
  /// vouch for none.
  ///
  /// # A refused member decides no boundary
  ///
  /// The comma is found by [`raw_comma_end`] and [`readings_at`], and not by
  /// the parameter walk [`member`](Self::member) runs, and that is the
  /// difference between reading a member and getting past one. Every byte
  /// this crosses belongs to a member whose `parameters` have already failed to
  /// derive, so letting those bytes DECIDE where a quoted-string begins would
  /// let them say which commas separate members, and so where the refused
  /// member ends and the next one may start. That is the whole harm: a
  /// `Transfer-Encoding` of `gzip;;q="oops, chunked` would otherwise report the
  /// malformed `gzip` and never say that `chunked` was sent.
  ///
  /// Stopping at the end of the line is the same answer as stopping at a comma,
  /// since RFC 9110 §5.2 puts one at every join; [`next`](Iterator::next) takes
  /// the next line and this resumes there.
  ///
  /// No fault is reported from here, because none belongs here: a string a
  /// reading leaves unclosed, or one carrying a byte RFC 9110 §5.6.4 forbids,
  /// is a string no reading of these bytes HAS to derive — they are the remains
  /// of a member already refused — and the answer that costs is the boundary,
  /// which is the one thing this reports.
  ///
  /// # An element of a refused member may still OPEN a quoted-string
  ///
  /// The elements this crosses were never derived, but the field's `parameter`
  /// production still names a position in each of them at which an RFC 9110
  /// §5.6.4 quoted-string may open. Crossing one raw resumes the walk wherever
  /// that string's own commas happen to fall — which is how a `y"z;w="a,
  /// chunked, b"` standing behind a refused member would hand the caller a
  /// `chunked` the sender wrote INSIDE a parameter value. So this asks
  /// [`refused_member_end`], the same question [`scan_parameters`] asks one
  /// level in and the same one [`member`](Self::member) asks behind a value
  /// that ran on past its close: whether ANY reading of these bytes holds the
  /// earliest comma inside a string. Where none does, that comma is a separator
  /// whichever reading is the sender's and this crosses to it —
  /// `y"z;w="a", second` is that same element with a string that CLOSES in
  /// front of the comma, and `second` is reported. Where one does, the walk
  /// stops rather than resume somewhere it cannot justify.
  fn seek(&mut self) {
    match refused_member_end(self.line, self.at, self.syntax) {
      Some(end) => self.at = end,
      None => self.unresolved = true,
    }
  }

  /// Takes the member starting at the cursor, leaving the cursor on whatever
  /// ended it — which may be on a LATER field line than the member began on.
  ///
  /// A fault found among the member's PARAMETERS is CARRIED — on the member for
  /// the ones behind RFC 9110 §5.2's join, and in the member's own slice for the
  /// rest, where [`ParamIter`] reports each in the order the sender wrote them.
  /// It is never returned from here. Returning it would end the walk — `next`
  /// stops on any `Err` — and the member written behind this one would be hidden
  /// by a fault in a parameter of this one, which is the harm the boundary work
  /// is for.
  ///
  /// What the fault DOES decide is where this member stops: at the first comma
  /// from the `;` that OPENED the refused repetition that
  /// [`refused_member_end`] can vouch for — one no reading of those bytes holds
  /// inside a quoted-string — which [`scan_parameters`] answers, and after
  /// which [`refuse`](Self::refuse) leaves the walk to get past what is left of
  /// it rather than read it. Not from behind that repetition: its extent was
  /// cut by opening its own string, and a comma that string swallowed is one
  /// the reading leaving it shut ends the member at. Where some reading does
  /// hold the comma, the member stops at the refused repetition itself and the
  /// walk stops behind it, since a boundary it cannot derive is one it will not
  /// invent.
  fn member(&mut self) -> Result<ListMember<'a>, ListError> {
    let head_line = self.line;
    let start = self.at;
    // What the member occupies on the field line it starts on — all a
    // borrowing walk can hand out — plus, when a quoted-string held it open at
    // that line's end, the escape state to continue that string with.
    let (delim, refused) = member_end(head_line, start, self.syntax, self.valueless);
    if let Some(refusal) = refused {
      // The fault itself is not taken here: it is inside the member's own
      // slice, and `ParamIter` reports it at the repetition that earned it.
      // Only the extent is this walk's business — and whether there is one.
      self.refuse(refusal.bounded());
    }
    let (head_end, mut open) = match delim {
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
    // Whether the string this loop is carrying is still the HEAD line's own.
    // That is the only one `params` holds, so it is the only one `parse_param`
    // can be asked about and the only one whose verdict `tail` may report: a
    // later parameter's trailing bytes reported through `tail` would be a fault
    // of the wrong parameter, and `QuotedTail` is a statement about ONE value.
    // What a later parameter earns goes to `joined` below, which states nothing
    // about any one of them — it says the member's parameters hold a fault.
    let mut carried = true;
    // The first fault among the parameters BEHIND the join. They lie on lines
    // the member hands no slice of, so `ParamIter` never reaches them and this
    // is the only place they are read; first rather than last, because that is
    // the order the sender wrote them in and the order the member's own are
    // reported in.
    let mut joined = None;
    while let Some(escape) = open.take() {
      let Some(next) = self.next_line() else {
        // No further field line, so the combined value ends inside the string:
        // `tail` keeps whatever the head's own string already earned, and a
        // string still open here is unterminated rather than merely
        // non-contiguous.
        if !carried {
          // The open string is not the head line's parameter's — that one
          // closed, which is what cleared `carried` — but one a LATER
          // parameter opened, and RFC 9110 §5.6.4 never sees it closed. That
          // repetition can be malformed in no other way: this state is reached
          // only through `param_value_at`, so its `token`, its `=` and its
          // opening DQUOTE are all there.
          joined = joined.or(Some(ListError::UnterminatedQuotedString));
        }
        break;
      };
      self.line = next;
      self.at = next.len();
      match scan_quoted_after_join(next, escape) {
        QuotedScan::Closed(end) => {
          // A close is not an end. §5.6.6 admits `OWS ";" OWS [ parameter ]`
          // behind that close and the `,` that ends the member, and nothing
          // else — the same rule `member_end` applies on the line the member
          // began on, so §5.2's join is neither a way past it nor a second
          // spelling of it.
          let (at, trails) = after_close(next, end);
          if carried {
            tail = if trails {
              QuotedTail::Trails
            } else {
              QuotedTail::Continues
            };
            carried = false;
          } else if trails {
            // What `QuotedTail::Trails` says about the member's own value, said
            // about a parameter behind the join: RFC 9110 §5.6.6's
            // `parameter-value = ( token / quoted-string )` takes one
            // alternative WHOLE — and §10.1.4's `transfer-parameter` writes the
            // same two — so bytes standing behind the close derive nothing.
            joined = joined.or(Some(ListError::NotAToken));
          }
          if trails {
            // Either way the value that just closed is refused, and
            // `after_close` has already taken the rest of that REPETITION raw.
            // What is left of the member is got past where a comma can be
            // vouched for, and is left unread where none can — the same
            // question `scan_parameters` asks for a refusal it found itself,
            // asked here because this one is `after_close`'s.
            let bounded = refused_member_end(next, at, self.syntax);
            self.at = bounded.unwrap_or(at);
            self.refuse(bounded.is_some());
            break;
          }
          // Verdicted where they are cut, under this member's own production,
          // because no slice handed out downstream contains them — and in the
          // same pass that cuts them, so a refusal here can steer no boundary
          // behind itself.
          let (delim, refused) = scan_parameters(next, at, self.syntax, self.valueless);
          if let Some(refusal) = refused {
            joined = joined.or(Some(refusal.fault()));
            self.refuse(refusal.bounded());
          }
          match delim {
            Delim::At(at) => self.at = at,
            Delim::Open(escape) => open = Some(escape),
            Delim::Invalid => return Err(ListError::InvalidQuotedByte),
          }
        }
        QuotedScan::Open { escape } => open = Some(escape),
        QuotedScan::Invalid => return Err(ListError::InvalidQuotedByte),
      }
    }

    // The name runs to the member's first `;` (§5.6.6 `parameters`), and is
    // always on the member's first line: neither name grammar this walk is
    // entered with holds a DQUOTE, so nothing can open a string inside a name
    // and nothing can hold one open across the join. `raw_run_end` is that
    // reading, and it stops at the `,` as well for the member whose name is all
    // there is of it.
    let head = head_line.get(start..head_end).unwrap_or_default();
    let name_end = raw_run_end(head, 0);
    let (name, params) = match head.get(name_end) {
      Some(_) => (
        head.get(..name_end).unwrap_or_default(),
        Some(head.get(name_end.saturating_add(1)..).unwrap_or_default()),
      ),
      // No `;` at all: the whole member is its name, and the repetition both
      // productions wrap around a parameter ran zero times. That is NOT the
      // same value as a `;` with nothing behind it, which ran it once and
      // derived nothing — RFC 9110 §5.6.6 admits that and §10.1.4 does not, so
      // recording both as an empty slice would hide a malformed
      // `transfer-coding` behind a well-formed one's shape.
      None => (head, None),
    };
    let name = trim_ows(name);
    if !(self.name_ok)(name) {
      return Err(ListError::NotAToken);
    }
    Ok(ListMember {
      name,
      params,
      tail,
      syntax: self.syntax,
      valueless: self.valueless,
      joined,
    })
  }
}

#[cfg(test)]
mod tests;
