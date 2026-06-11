//! Bounded, strict, borrowed HTTP/1.1 head parsing for the opening
//! handshake. Strict CRLF; obs-fold rejected; names must be RFC 9110
//! tokens; values are OWS-trimmed and must be visible ASCII / UTF-8-free
//! bytes mapped through `str` (the head must be UTF-8 — handshake fields
//! are ASCII in practice and anything else is rejected as malformed).
//!
//! The whole head must fit [`MAX_HEAD_BYTES`] with at most [`MAX_HEADERS`]
//! header fields — both fixed for cycle 1.

use derive_more::Display;

/// Maximum bytes of a request/response head (start line through the blank
/// line) this parser will buffer-scan before rejecting.
pub(crate) const MAX_HEAD_BYTES: usize = 8192;

/// Maximum number of header fields in a head.
pub(crate) const MAX_HEADERS: usize = 64;

/// Detail payload: where and why a head failed grammar.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display("malformed head at byte {at}: {what}")]
pub struct MalformedDetail {
  at: usize,
  what: &'static str,
}

impl MalformedDetail {
  #[inline(always)]
  pub(crate) const fn new(at: usize, what: &'static str) -> Self {
    Self { at, what }
  }

  /// Byte offset of the offending input.
  #[inline(always)]
  pub const fn at(&self) -> usize {
    self.at
  }

  /// Static description of the violation.
  #[inline(always)]
  pub const fn what(&self) -> &'static str {
    self.what
  }
}

/// Errors parsing a head. Public because the handshake errors re-export it
/// inside their variants.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum HeadError {
  /// No terminating blank line within the byte cap.
  #[error("head exceeds {0} bytes without terminating")]
  TooLarge(usize),

  /// More header fields than the cap.
  #[error("head has more than {0} header fields")]
  TooManyHeaders(usize),

  /// Grammar violation.
  #[error("{0}")]
  Malformed(MalformedDetail),
}

/// Borrowed header fields in arrival order.
#[derive(Debug, Copy, Clone)]
pub(crate) struct HeaderMap<'a> {
  entries: [(&'a str, &'a str); MAX_HEADERS],
  len: usize,
}

impl<'a> HeaderMap<'a> {
  const fn empty() -> Self {
    Self {
      entries: [("", ""); MAX_HEADERS],
      len: 0,
    }
  }

  fn push(&mut self, name: &'a str, value: &'a str) -> bool {
    match self.entries.get_mut(self.len) {
      Some(slot) => {
        *slot = (name, value);
        self.len = self.len.saturating_add(1);
        true
      }
      None => false,
    }
  }

  /// Number of header fields.
  // Only consumed by tests (gated on `feature = "std"`); production code
  // uses `count` / `get_all` instead.
  #[allow(dead_code)]
  pub(crate) const fn len(&self) -> usize {
    self.len
  }

  /// All fields in arrival order.
  pub(crate) fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
    self.entries.iter().take(self.len).copied()
  }

  /// First value for `name` (ASCII case-insensitive).
  pub(crate) fn get(&self, name: &str) -> Option<&'a str> {
    self.get_all(name).next()
  }

  /// Every value for `name`, in arrival order.
  pub(crate) fn get_all<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'a str> + 's {
    self
      .iter()
      .filter_map(move |(n, v)| n.eq_ignore_ascii_case(name).then_some(v))
  }

  /// Occurrence count for `name`.
  pub(crate) fn count(&self, name: &str) -> usize {
    self.get_all(name).count()
  }
}

/// A parsed head: the start line, its header fields, and how many input
/// bytes it consumed (the frame stream begins at `consumed`).
#[derive(Debug, Copy, Clone)]
pub(crate) struct Head<'a> {
  start_line: &'a str,
  headers: HeaderMap<'a>,
  consumed: usize,
}

impl<'a> Head<'a> {
  pub(crate) const fn start_line(&self) -> &'a str {
    self.start_line
  }

  pub(crate) const fn headers(&self) -> &HeaderMap<'a> {
    &self.headers
  }

  pub(crate) const fn consumed(&self) -> usize {
    self.consumed
  }
}

/// Outcome of [`parse_head`] on a possibly-partial buffer.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Copy, Clone)]
pub(crate) enum Parsed<'a> {
  /// The head is complete.
  Complete(Head<'a>),
  /// No blank line yet — read more and re-parse.
  NeedMore,
}

/// RFC 9110 token characters (header names, subprotocol names).
pub(crate) const fn is_token_byte(b: u8) -> bool {
  matches!(b,
    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
    | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// Whether every byte of `s` is a token byte (and `s` is non-empty).
pub(crate) fn is_token(s: &str) -> bool {
  !s.is_empty() && s.bytes().all(is_token_byte)
}

/// RFC 3986 `pchar` byte (plus `/`): what may appear literally in a URI
/// path segment. Everything else — including `#`, which RFC 6455 §3 says
/// MUST be percent-encoded in a resource name — must arrive `%XX`-escaped.
const fn is_path_byte(b: u8) -> bool {
  matches!(b,
    // unreserved
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    // sub-delims
    | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    // pchar extras + segment separator
    | b':' | b'@' | b'/')
}

/// Validates a WebSocket /resource name/'s path-and-query string against the
/// RFC 3986 grammar RFC 6455 §3 builds on: a leading `/`, `pchar`/`/` bytes
/// in the path, `pchar`/`/`/`?` bytes after the first `?`, and `%` only as
/// `%XX` percent-escapes. Fragments are not part of a resource name — a raw
/// `#` "MUST be escaped as %23" (§3) — so `#` is rejected in both parts.
pub(crate) fn is_valid_path_and_query(s: &str) -> bool {
  s.starts_with('/') && valid_pq_bytes(s.bytes(), false)
}

/// Validates bare query bytes (everything after the `?`) under the same
/// grammar — for the absolute-form `http://host?q` shape, whose resource
/// name `/?q` is assembled positionally rather than borrowed.
pub(crate) fn is_valid_query(s: &str) -> bool {
  valid_pq_bytes(s.bytes(), true)
}

/// RFC 3986 §3.2.2 `reg-name` byte: unreserved / sub-delims (pct-escapes
/// handled by the caller). URI delimiters (`/ ? # @ :`) are NOT host bytes.
const fn is_reg_name_byte(b: u8) -> bool {
  matches!(b,
    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
}

/// Validates a `Host:` / `:authority` value against the RFC 3986 §3.2.2
/// authority grammar (no userinfo, per RFC 9110 §7.2): a `reg-name` or a
/// bracketed IP-literal, then an optional `":" *DIGIT` port. An authority is
/// not a URL — `/`, `?`, `#`, `@`, whitespace, and controls are all out.
pub(crate) fn is_valid_authority(s: &str) -> bool {
  let port = match s.strip_prefix('[') {
    // IP-literal: hex / `:` / `.` covers IPv6 incl. IPv4-mapped forms.
    Some(rest) => {
      let Some((lit, after)) = rest.split_once(']') else {
        return false;
      };
      if lit.is_empty()
        || !lit
          .bytes()
          .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
      {
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

/// Splits a comma-separated list value into its non-empty, OWS-trimmed
/// elements. RFC 9110 §5.6.1.2: "a recipient MUST parse and ignore a
/// reasonable number of empty list elements" — EVERY list consumer in the
/// crate routes through here, so the empty-element rule lives in exactly one
/// place instead of being rediscovered per open-coded `split(',')`.
pub(crate) fn list_elements(value: &str) -> impl Iterator<Item = &str> {
  value
    .split(',')
    .map(|item| item.trim_matches([' ', '\t']))
    .filter(|item| !item.is_empty())
}

/// Whether a comma-separated token list contains `token`
/// (ASCII case-insensitive, OWS-tolerant) — e.g. `Connection: keep-alive, Upgrade`.
pub(crate) fn token_list_contains(value: &str, token: &str) -> bool {
  list_elements(value).any(|item| item.eq_ignore_ascii_case(token))
}

/// Parses one head from the front of `input`.
pub(crate) fn parse_head(input: &[u8]) -> Result<Parsed<'_>, HeadError> {
  // Locate the CRLFCRLF terminator within the cap. Scanning exactly
  // MAX_HEAD_BYTES means any found head satisfies consumed ≤ the cap, and
  // a cap-full buffer without a terminator can never become valid (the
  // terminator would have to start past byte cap−4).
  let scan = input
    .get(..input.len().min(MAX_HEAD_BYTES))
    .unwrap_or(input);
  let head_end = match scan.windows(4).position(|w| w == b"\r\n\r\n") {
    Some(pos) => pos,
    None if input.len() >= MAX_HEAD_BYTES => return Err(HeadError::TooLarge(MAX_HEAD_BYTES)),
    None => return Ok(Parsed::NeedMore),
  };
  let consumed = head_end.saturating_add(4);

  let head_bytes = input.get(..head_end).unwrap_or(&[]);
  let head_str = core::str::from_utf8(head_bytes).map_err(|e| {
    HeadError::Malformed(MalformedDetail::new(e.valid_up_to(), "head is not UTF-8"))
  })?;

  let mut lines = head_str.split("\r\n");
  let Some(start_line) = lines.next() else {
    return Err(HeadError::Malformed(MalformedDetail::new(0, "empty head")));
  };
  if start_line.is_empty() {
    return Err(HeadError::Malformed(MalformedDetail::new(
      0,
      "empty start line",
    )));
  }
  if start_line.bytes().any(|b| b == b'\r' || b == b'\n') {
    return Err(HeadError::Malformed(MalformedDetail::new(
      0,
      "bare CR or LF in start line",
    )));
  }

  let mut headers = HeaderMap::empty();
  let mut offset = start_line.len().saturating_add(2);
  for line in lines {
    if line.bytes().next().is_some_and(|b| b == b' ' || b == b'\t') {
      return Err(HeadError::Malformed(MalformedDetail::new(
        offset,
        "obs-fold continuation",
      )));
    }
    if line.bytes().any(|b| b == b'\r' || b == b'\n') {
      return Err(HeadError::Malformed(MalformedDetail::new(
        offset,
        "bare CR or LF in header line",
      )));
    }
    let Some(colon) = line.find(':') else {
      return Err(HeadError::Malformed(MalformedDetail::new(
        offset,
        "header line without colon",
      )));
    };
    let (name, rest) = line.split_at(colon);
    if !is_token(name) {
      return Err(HeadError::Malformed(MalformedDetail::new(
        offset,
        "invalid header name",
      )));
    }
    let value = rest.get(1..).unwrap_or("").trim_matches([' ', '\t']);
    // RFC 9110 §5.5 restricts field content to VCHAR/SP/HTAB; reject the
    // other control bytes (CR/LF were rejected line-wise above).
    if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7F) {
      return Err(HeadError::Malformed(MalformedDetail::new(
        offset,
        "control byte in header value",
      )));
    }
    if !headers.push(name, value) {
      return Err(HeadError::TooManyHeaders(MAX_HEADERS));
    }
    offset = offset.saturating_add(line.len()).saturating_add(2);
  }

  Ok(Parsed::Complete(Head {
    start_line,
    headers,
    consumed,
  }))
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  const REQ: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: keep-alive, Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\nLEFTOVER";

  #[test]
  fn parses_a_request_head() {
    let head = match parse_head(REQ).unwrap() {
      Parsed::Complete(h) => h,
      Parsed::NeedMore => panic!("complete head reported NeedMore"),
    };
    assert_eq!(head.start_line(), "GET /chat HTTP/1.1");
    assert_eq!(head.consumed(), REQ.len() - "LEFTOVER".len());
    assert_eq!(head.headers().len(), 5);
    assert_eq!(head.headers().get("host"), Some("server.example.com"));
    // Lookup is case-insensitive; values keep their case, OWS trimmed.
    assert_eq!(
      head.headers().get("SEC-WEBSOCKET-KEY"),
      Some("dGhlIHNhbXBsZSBub25jZQ==")
    );
    assert_eq!(head.headers().get("absent"), None);
  }

  #[test]
  fn ows_around_values_is_trimmed_and_names_validated() {
    let raw = b"GET / HTTP/1.1\r\nX-Pad: \t padded value \t \r\n\r\n";
    let head = unwrap_complete(raw);
    assert_eq!(head.headers().get("x-pad"), Some("padded value"));
  }

  #[test]
  fn token_list_contains_is_case_insensitive_and_comma_aware() {
    assert!(token_list_contains("keep-alive, Upgrade", "upgrade"));
    assert!(token_list_contains("Upgrade", "UPGRADE"));
    assert!(token_list_contains(" upgrade ,x", "upgrade"));
    assert!(!token_list_contains("upgraded", "upgrade"));
    assert!(!token_list_contains("up grade", "upgrade"));
    assert!(!token_list_contains("", "upgrade"));
  }

  #[test]
  fn get_all_iterates_repeated_headers_in_order() {
    let raw =
      b"GET / HTTP/1.1\r\nSec-WebSocket-Protocol: a, b\r\nx: 1\r\nSec-WebSocket-Protocol: c\r\n\r\n";
    let head = unwrap_complete(raw);
    let got: Vec<&str> = head.headers().get_all("sec-websocket-protocol").collect();
    assert_eq!(got, ["a, b", "c"]);
    assert_eq!(head.headers().count("sec-websocket-protocol"), 2);
  }

  #[test]
  fn incomplete_heads_need_more() {
    for cut in 0..REQ.len() - "LEFTOVER".len() - 1 {
      assert!(
        matches!(parse_head(&REQ[..cut]).unwrap(), Parsed::NeedMore),
        "cut at {cut}"
      );
    }
  }

  #[test]
  fn malformed_heads_are_rejected() {
    // Header line without a colon.
    assert!(matches!(
      parse_head(b"GET / HTTP/1.1\r\nbogus line\r\n\r\n").unwrap_err(),
      HeadError::Malformed(_)
    ));
    // Empty header name.
    assert!(matches!(
      parse_head(b"GET / HTTP/1.1\r\n: v\r\n\r\n").unwrap_err(),
      HeadError::Malformed(_)
    ));
    // Non-token byte in a header name.
    assert!(matches!(
      parse_head(b"GET / HTTP/1.1\r\nbad name: v\r\n\r\n").unwrap_err(),
      HeadError::Malformed(_)
    ));
    // obs-fold continuation lines are rejected (RFC 7230 3.2.4).
    assert!(matches!(
      parse_head(b"GET / HTTP/1.1\r\na: 1\r\n folded\r\n\r\n").unwrap_err(),
      HeadError::Malformed(_)
    ));
    // Bare CR inside a line.
    assert!(matches!(
      parse_head(b"GET / HTTP/1.1\r\na: 1\rx\r\n\r\n").unwrap_err(),
      HeadError::Malformed(_)
    ));
    // Non-UTF-8 in the head.
    assert!(matches!(
      parse_head(b"GET / HTTP/1.1\r\na: \xFF\r\n\r\n").unwrap_err(),
      HeadError::Malformed(_)
    ));
    // C0 control bytes in a value (NUL here) are rejected; HTAB inside
    // field content is legal and stays.
    assert!(matches!(
      parse_head(b"GET / HTTP/1.1\r\na: b\x00c\r\n\r\n").unwrap_err(),
      HeadError::Malformed(_)
    ));
    let head = match parse_head(b"GET / HTTP/1.1\r\na: b\tc\r\n\r\n").unwrap() {
      Parsed::Complete(h) => h,
      Parsed::NeedMore => panic!("complete"),
    };
    assert_eq!(head.headers().get("a"), Some("b\tc"));
  }

  #[test]
  fn caps_are_enforced() {
    // Oversized head: no terminator within MAX_HEAD_BYTES.
    let big = vec![b'a'; MAX_HEAD_BYTES + 1];
    assert!(matches!(
      parse_head(&big).unwrap_err(),
      HeadError::TooLarge(MAX_HEAD_BYTES)
    ));

    // Too many headers.
    let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..=MAX_HEADERS {
      raw.extend_from_slice(format!("h{i}: v\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    assert!(matches!(
      parse_head(&raw).unwrap_err(),
      HeadError::TooManyHeaders(MAX_HEADERS)
    ));
  }

  fn unwrap_complete(raw: &[u8]) -> Head<'_> {
    match parse_head(raw).unwrap() {
      Parsed::Complete(h) => h,
      Parsed::NeedMore => panic!("expected a complete head"),
    }
  }

  mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
      /// The parser never panics and never reports Complete with
      /// consumed > input length.
      #[test]
      fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(Parsed::Complete(head)) = parse_head(&bytes) {
          prop_assert!(head.consumed() <= bytes.len());
        }
      }
    }
  }
}
