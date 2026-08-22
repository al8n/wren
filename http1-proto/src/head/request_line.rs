//! RFC 9112 §3 `request-line = method SP request-target SP HTTP-version`.
//!
//! Strict single-SP parsing: §3 allows a recipient to accept "any amount of
//! whitespace" in place of the two SPs, and that leniency is deliberately not
//! taken here — a recipient that disagrees with a stricter one downstream about
//! where a field ends is the request-smuggling primitive.

use super::{
  StartLine, malformed, split_before_sp, strip_crlf,
  version::{Version, parse_version},
};
use crate::{
  error::H1Error,
  grammar::{is_token_byte, is_valid_authority, is_valid_path_and_query, is_valid_query},
};

/// RFC 9112 §3.2 `request-target`, classified by form.
///
/// Pairing a form with a method — `authority-form` is CONNECT's (§3.2.3),
/// `asterisk-form` is server-wide OPTIONS' (§3.2.4) — is a message-level rule
/// enforced by head validation. Parsing only classifies.
///
/// Deliberately NOT `#[non_exhaustive]`, unlike [`Item`](crate::Item) and
/// [`StartLine`](crate::StartLine). §3.2 closes this set —
/// `request-target = origin-form / absolute-form / authority-form /
/// asterisk-form` — so a fifth variant would be a change to HTTP/1.1 rather than
/// to this crate. A consumer matches all four exhaustively and gets a compile
/// error if it forgets one, which is what routing code wants.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Target<'a> {
  /// §3.2.1 `origin-form`: absolute path plus optional query, the form of an
  /// ordinary request to an origin server.
  Origin {
    /// Path and query, leading `/` included.
    path_and_query: &'a str,
  },
  /// §3.2.2 `absolute-form`: a complete `http`/`https` URI, which a request
  /// through a proxy must use.
  Absolute {
    /// The whole URI, scheme included.
    uri: &'a str,
  },
  /// §3.2.3 `authority-form`: host and optional port, nothing else.
  Authority {
    /// The `host[:port]` authority; RFC 9110 §7.2 leaves no room for userinfo.
    host_port: &'a str,
  },
  /// §3.2.4 `asterisk-form`: a bare `*`, addressing the server rather than a
  /// resource.
  Asterisk,
}

/// A parsed RFC 9112 §3 request-line, borrowed from the line it was parsed
/// from.
#[derive(Debug, Copy, Clone)]
pub struct RequestLine<'a> {
  /// The method: a validated token, compared case-SENSITIVELY (RFC 9110 §9.1).
  pub method: &'a str,
  /// The request-target, classified by form.
  pub target: Target<'a>,
  /// The announced HTTP version.
  pub version: Version,
}

/// Parses one complete request-line, its terminating CRLF included.
///
/// `line` is exactly the bytes up to and including that CRLF. Offsets in the
/// errors are relative to the start of `line`, so a caller scanning a whole
/// head rebases them onto the head.
///
/// Rejects, all `Malformed` at the offset of the offending byte: a method that
/// is not a token, whitespace other than the two single SPs, a request-target
/// that fails its form's grammar, a bare CR or LF inside the line, and a
/// missing CRLF terminator.
///
/// The one exception is the version. RFC 9112 §2.3 spells `HTTP-name` as
/// `%s"HTTP"`, i.e. case-SENSITIVE, so `http/1.1` is a grammar violation like
/// any other; a well-formed `HTTP/<DIGIT>.<DIGIT>` outside 1.x — `HTTP/0.9`,
/// `HTTP/2.0` — is `VersionNotSupported`, which a server driver answers with
/// 505 rather than 400.
// The head scanner delimits this line but deliberately does not parse it:
// request against response is the connection's context, not the scanner's, so
// the connection runs this codec over `HeadView::start_line_bytes`.
pub(crate) fn parse_request_line(line: &[u8]) -> Result<RequestLine<'_>, H1Error> {
  let body = strip_crlf(line, StartLine::Request)?;

  let Some((method_bytes, after_method)) = split_before_sp(body) else {
    return Err(malformed(
      body.len(),
      "request-line has no SP after the method",
    ));
  };
  let method = parse_method(method_bytes)?;

  let target_at = method_bytes.len().saturating_add(1);
  let Some((target_bytes, version_bytes)) = split_before_sp(after_method) else {
    return Err(malformed(
      body.len(),
      "request-line has no SP after the request-target",
    ));
  };
  let target = parse_target(target_bytes, target_at)?;

  let version_at = target_at
    .saturating_add(target_bytes.len())
    .saturating_add(1);
  let version = parse_version(version_bytes, version_at)?;

  Ok(RequestLine {
    method,
    target,
    version,
  })
}

/// RFC 9110 §9.1 `method = token`, case-sensitive and never empty.
///
/// Visible to the module so `head::encode` validates an outbound method with
/// the same function that reads an inbound one: one rule and one diagnostic
/// vocabulary per element, in both directions.
pub(super) fn parse_method(bytes: &[u8]) -> Result<&str, H1Error> {
  if bytes.is_empty() {
    return Err(malformed(0, "empty method"));
  }
  // `is_token` over the same `is_token_byte` predicate, unrolled because the
  // error has to carry WHICH byte broke the token.
  if let Some(at) = bytes.iter().position(|&b| !is_token_byte(b)) {
    return Err(malformed(at, "method is not a token"));
  }
  // Unreachable: every tchar is ASCII. Answered rather than unwrapped.
  as_str(bytes, 0, "method is not a token")
}

/// Classifies and validates the request-target (RFC 9112 §3.2). `at` is the
/// offset of `bytes` within the line.
///
/// A target that fails its form's grammar is reported at its first byte: the
/// grammar validators are predicates over the whole element, so the element,
/// not a byte inside it, is what the parser can name.
///
/// Visible to the module because `head::encode` validates an outbound target by
/// running this over the bytes it is about to write and requiring the same form
/// back — the sender's classification checked against the reading every
/// recipient will make of it, rather than against a second copy of the grammar.
pub(super) fn parse_target(bytes: &[u8], at: usize) -> Result<Target<'_>, H1Error> {
  let target = as_str(bytes, at, "request-target is not valid UTF-8")?;
  if target.is_empty() {
    return Err(malformed(at, "empty request-target"));
  }
  // §3.2.4 asterisk-form is exactly one `*` — an exact match, not a prefix, is
  // what separates it from a target that merely starts with one.
  if target == "*" {
    return Ok(Target::Asterisk);
  }
  if target.starts_with('/') {
    return if is_valid_path_and_query(target) {
      Ok(Target::Origin {
        path_and_query: target,
      })
    } else {
      Err(malformed(at, "invalid origin-form request-target"))
    };
  }
  // §3.2.2 absolute-form. A `/` before the `://` means the `://` is data inside
  // a path, not a scheme delimiter, so the target is not a URI.
  if let Some((scheme, after_scheme)) = target.split_once("://")
    && !scheme.contains('/')
  {
    return parse_absolute(target, scheme, after_scheme, at);
  }
  if is_valid_authority(target) {
    Ok(Target::Authority { host_port: target })
  } else {
    Err(malformed(at, "invalid authority-form request-target"))
  }
}

/// RFC 9112 §3.2.2 `absolute-form`: `scheme "://" authority [path ["?" query]]`.
///
/// Only `http` and `https` name a target this core can serve (RFC 9110 §4.2),
/// and RFC 3986 §3.1 makes the scheme ASCII case-insensitive.
fn parse_absolute<'a>(
  uri: &'a str,
  scheme: &str,
  after_scheme: &'a str,
  at: usize,
) -> Result<Target<'a>, H1Error> {
  if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
    return Err(malformed(
      at,
      "absolute-form scheme is neither http nor https",
    ));
  }
  // Past the scheme and the three bytes of `://`.
  let authority_at = at.saturating_add(scheme.len()).saturating_add(3);
  // The authority ends at the first `/` or `?`, or at the end of the target.
  let end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
  let Some((authority, rest)) = after_scheme.split_at_checked(end) else {
    return Err(malformed(
      authority_at,
      "invalid absolute-form request-target",
    ));
  };
  if !is_valid_authority(authority) {
    return Err(malformed(
      authority_at,
      "invalid authority in absolute-form request-target",
    ));
  }
  // What follows an authority is nothing, a path (with an optional query), or
  // a bare query — `http://host?q` has no path to borrow, so its query is
  // validated on its own.
  let valid_rest = match rest.strip_prefix('?') {
    Some(query) => is_valid_query(query),
    None => rest.is_empty() || is_valid_path_and_query(rest),
  };
  if !valid_rest {
    return Err(malformed(
      authority_at.saturating_add(authority.len()),
      "invalid path or query in absolute-form request-target",
    ));
  }
  Ok(Target::Absolute { uri })
}

/// Borrows `bytes` as a `str`. `at` is the offset of `bytes` within the line,
/// so a non-UTF-8 byte is reported at its own position.
fn as_str<'a>(bytes: &'a [u8], at: usize, what: &'static str) -> Result<&'a str, H1Error> {
  core::str::from_utf8(bytes).map_err(|e| malformed(at.saturating_add(e.valid_up_to()), what))
}

#[cfg(test)]
mod tests {
  use super::*;

  // RFC 9112 §3 + §3.2.1: `method SP request-target SP HTTP-version CRLF` over
  // an origin-form target.
  #[test]
  fn parses_origin_form() {
    let rl = parse_request_line(b"GET /chat?x=1 HTTP/1.1\r\n").unwrap();
    assert_eq!(rl.method, "GET");
    assert_eq!(
      rl.target,
      Target::Origin {
        path_and_query: "/chat?x=1"
      }
    );
    assert_eq!(rl.version, Version::Http11);
  }

  // RFC 9112 §3.2.1-§3.2.4: the four request-target forms.
  #[test]
  fn parses_all_four_target_forms() {
    assert!(matches!(
      parse_request_line(b"OPTIONS * HTTP/1.1\r\n")
        .unwrap()
        .target,
      Target::Asterisk
    ));
    assert!(matches!(
      parse_request_line(b"CONNECT example.com:443 HTTP/1.1\r\n")
        .unwrap()
        .target,
      Target::Authority {
        host_port: "example.com:443"
      }
    ));
    assert!(matches!(
      parse_request_line(b"GET http://example.com/p?q HTTP/1.1\r\n")
        .unwrap()
        .target,
      Target::Absolute { .. }
    ));
  }

  // RFC 9112 §2.3: `HTTP-version = HTTP-name "/" DIGIT "." DIGIT` with a
  // case-sensitive `HTTP-name`; RFC 9110 §15.6.6 for the unsupported ones.
  #[test]
  fn version_variants() {
    assert_eq!(
      parse_request_line(b"GET / HTTP/1.0\r\n").unwrap().version,
      Version::Http10
    );
    // RFC 9112 §2.3: higher minor is backwards-compatible → 1.1 semantics.
    assert_eq!(
      parse_request_line(b"GET / HTTP/1.7\r\n").unwrap().version,
      Version::Http11
    );
    assert!(parse_request_line(b"GET / HTTP/0.9\r\n").is_err());
    assert!(parse_request_line(b"GET / http/1.1\r\n").is_err());
    // A version outside 1.x is WELL FORMED grammar this core does not speak, so
    // it is `VersionNotSupported` — RFC 9110 §15.6.6's 505 — and not a malformed
    // start line. The distinction is what a server answers with, so the variant
    // is pinned rather than merely the failure: `is_err()` alone would pass on a
    // 400 for a message that deserves a 505.
    let unsupported = parse_request_line(b"GET / HTTP/2.0\r\n").unwrap_err();
    assert_eq!(unsupported, H1Error::VersionNotSupported);
    assert_eq!(
      unsupported.suggested_status(),
      crate::SuggestedStatus::VersionNotSupported
    );
  }

  // RFC 9112 §3: single SP only — the lenient whitespace MAY is not taken.
  #[test]
  fn rejects_whitespace_variants() {
    for bad in [
      b"GET  / HTTP/1.1\r\n".as_slice(), // double SP
      b"GET\t/ HTTP/1.1\r\n",            // HTAB separator
      b"GET / HTTP/1.1 \r\n",            // trailing SP
      b" GET / HTTP/1.1\r\n",            // leading SP
      b"GET /a b HTTP/1.1\r\n",          // SP in target
    ] {
      assert!(parse_request_line(bad).is_err(), "{bad:?}");
    }
  }

  // RFC 9110 §9.1 (`method = token`); RFC 9112 §3.2.1 with RFC 3986 §3.3-§3.5
  // (a fragment is never part of a request-target).
  #[test]
  fn rejects_malformed_methods_and_targets() {
    assert!(parse_request_line(b"GE T / HTTP/1.1\r\n").is_err());
    assert!(parse_request_line(b"G{}T / HTTP/1.1\r\n").is_err());
    assert!(parse_request_line(b" / HTTP/1.1\r\n").is_err()); // empty method
    assert!(parse_request_line(b"GET /\x7Fx HTTP/1.1\r\n").is_err()); // DEL in path
    assert!(parse_request_line(b"GET /a#f HTTP/1.1\r\n").is_err()); // fragment
  }

  // RFC 9112 §3: the offset locates the byte that broke the grammar, relative
  // to the start of the line.
  #[test]
  fn error_offsets_point_at_offender() {
    let e = parse_request_line(b"GET /a b HTTP/1.1\r\n").unwrap_err();
    let H1Error::Malformed(d) = e else { panic!() };
    // The SP at 6 ended the target early, so the version field starts at 7 —
    // at `b`, which is not `HTTP/`.
    assert_eq!(d.at(), 7);
  }
}
