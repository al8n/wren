//! Semantic-validation tests: the RFC 9112 §3.2 `Host` and target/method
//! rules, the §6.3 body-framing list on both sides of the connection, and the
//! connection directives a validated head carries.
//!
//! Every head literal is written out in full and fed through the real receive
//! path — `find_head_end`, then `scan_head`, then the matching start-line codec
//! — so no test asserts against a hand-built view that the scanner would never
//! have produced.

use super::*;
use crate::{
  error::SuggestedStatus,
  head::{
    request_line::parse_request_line,
    scan::{find_head_end, scan_head},
    status_line::parse_status_line,
  },
};

/// Runs a request head literal through the receive path: `find_head_end` proves
/// the literal is exactly one complete head block, `scan_head` validates its
/// field lines, and the RFC 9112 §3 codec parses the start line.
fn req(head: &[u8]) -> (RequestLine<'_>, HeadView<'_>) {
  assert_eq!(
    find_head_end(head, 0).unwrap(),
    Some(head.len()),
    "the literal is not exactly one complete head block"
  );
  let view = scan_head(head).unwrap();
  let line = parse_request_line(view.start_line_bytes()).unwrap();
  (line, view)
}

/// The same for a response head literal, through the RFC 9112 §4 codec.
fn resp(head: &[u8]) -> (StatusLine<'_>, HeadView<'_>) {
  assert_eq!(
    find_head_end(head, 0).unwrap(),
    Some(head.len()),
    "the literal is not exactly one complete head block"
  );
  let view = scan_head(head).unwrap();
  let line = parse_status_line(view.start_line_bytes()).unwrap();
  (line, view)
}

/// Validates a request head literal.
fn vreq(head: &[u8]) -> Result<(BodyFraming, HeadDirectives), H1Error> {
  let (line, view) = req(head);
  validate_request(&line, &view)
}

/// The framing a valid request head resolves to.
fn freq(head: &[u8]) -> BodyFraming {
  vreq(head).unwrap().0
}

/// The directives a valid request head carries.
fn d(head: &[u8]) -> HeadDirectives {
  vreq(head).unwrap().1
}

/// The status a server driver is advised to answer a rejected request with.
fn sreq(head: &[u8]) -> SuggestedStatus {
  vreq(head).unwrap_err().suggested_status()
}

/// Validates a response head literal against the request context it answers.
fn vresp_ctx(
  head: &[u8],
  req_method_head: bool,
  req_connect: bool,
) -> Result<(BodyFraming, HeadDirectives), H1Error> {
  let (line, view) = resp(head);
  validate_response(&line, &view, req_method_head, req_connect)
}

/// The framing a response to an ordinary request resolves to.
fn vresp(head: &[u8]) -> BodyFraming {
  vresp_ctx(head, false, false).unwrap().0
}

/// The framing a response to a HEAD request resolves to.
fn vresp_head(head: &[u8]) -> BodyFraming {
  vresp_ctx(head, true, false).unwrap().0
}

/// The framing a response to a CONNECT request resolves to.
fn vresp_connect(head: &[u8]) -> BodyFraming {
  vresp_ctx(head, false, true).unwrap().0
}

/// Whether a response head is rejected outright.
fn vresp_err(head: &[u8]) -> bool {
  vresp_ctx(head, false, false).is_err()
}

// RFC 9112 §3.2: a client MUST send a `Host` field in all HTTP/1.1 request
// messages, and a server MUST answer with 400 "any HTTP/1.1 request message
// that lacks a Host header field" and "any request message that contains more
// than one Host header field line or a Host header field with an invalid field
// value". The MISSING rule is version-scoped and the other two are not, which
// is what `host_version_scoping` below pins. An EMPTY field value is itself a
// client MUST when the target URI's authority is missing or undefined, so it is
// legal and is short-circuited before the RFC 3986 §3.2.2 authority grammar
// (which is non-empty-strict).
#[test]
fn host_rules() {
  assert!(vreq(b"GET / HTTP/1.1\r\n\r\n").is_err());
  assert!(vreq(b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n").is_err());
  assert!(vreq(b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n").is_err());
  assert!(vreq(b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n").is_ok());
  assert!(vreq(b"GET / HTTP/1.1\r\nHost:\r\n\r\n").is_ok());
  // The empty-value short-circuit is exactly that: a non-empty invalid
  // authority is still refused, whether it breaks the grammar in ASCII, in
  // `obs-text` that decodes (RFC 9110 §5.5 admits it in a field value), or in
  // bytes that are not UTF-8 at all.
  assert!(vreq(b"GET / HTTP/1.1\r\nHost: exa mple.com\r\n\r\n").is_err());
  assert!(vreq(b"GET / HTTP/1.1\r\nHost: caf\xC3\xA9.example\r\n\r\n").is_err());
  assert!(vreq(b"GET / HTTP/1.1\r\nHost: \xFF\r\n\r\n").is_err());
  // A repeated `Host` is a 400 even when both lines agree: §3.2 counts lines.
  assert!(vreq(b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: a.example\r\n\r\n").is_err());
  assert_eq!(sreq(b"GET / HTTP/1.1\r\n\r\n"), SuggestedStatus::BadRequest);
  // The offset names where the missing field belongs — just past the
  // request-line — and where an invalid one sits.
  assert!(matches!(
    vreq(b"GET / HTTP/1.1\r\n\r\n"),
    Err(H1Error::Malformed(d)) if d.at() == 16
  ));
  assert!(matches!(
    vreq(b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n"),
    Err(H1Error::Malformed(d)) if d.at() == 22
  ));
}

// RFC 9112 §3.2, read for its scopes: the 400-MUST for a message that LACKS a
// `Host` names "any HTTP/1.1 request message" — `Host` is an HTTP/1.1 addition,
// so a 1.0 request without one is a legal message this core must accept. The
// repeat and invalid-value MUSTs name "any request message" with no version
// qualifier, so a 1.0 request that does send `Host` is held to both.
#[test]
fn host_version_scoping() {
  assert!(vreq(b"GET / HTTP/1.0\r\n\r\n").is_ok());
  assert!(vreq(b"POST / HTTP/1.0\r\nContent-Length: 5\r\n\r\n").is_ok());
  assert!(vreq(b"GET / HTTP/1.0\r\nHost: a.example\r\nHost: b.example\r\n\r\n").is_err());
  assert!(vreq(b"GET / HTTP/1.0\r\nHost: bad host\r\n\r\n").is_err());
  // A single valid or empty `Host` on 1.0 is accepted exactly as on 1.1.
  assert!(vreq(b"GET / HTTP/1.0\r\nHost: a.example\r\n\r\n").is_ok());
  assert!(vreq(b"GET / HTTP/1.0\r\nHost:\r\n\r\n").is_ok());
  // The version scoping is on `Host` alone: a 1.0 request is still held to the
  // target/method pairing and to the framing rules.
  assert!(vreq(b"GET * HTTP/1.0\r\n\r\n").is_err());
  assert!(vreq(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
  // And 1.1 still requires it.
  assert!(vreq(b"GET / HTTP/1.1\r\n\r\n").is_err());
}

// RFC 9110 §8.6 (`Content-Length = 1*DIGIT`) and RFC 9112 §6.3 item 5: an
// invalid value is an unrecoverable framing error, UNLESS the value parses as a
// comma-separated list whose values are all valid and all the same, in which
// case that single value is used.
#[test]
fn content_length_anomalies() {
  assert_eq!(parse_content_length(b"42").unwrap(), 42);
  assert_eq!(parse_content_length(b"0").unwrap(), 0);
  // `1*DIGIT` takes leading zeros, and the maximum is the u64 the core stores.
  assert_eq!(parse_content_length(b"007").unwrap(), 7);
  assert_eq!(
    parse_content_length(b"18446744073709551615").unwrap(),
    u64::MAX
  );
  assert!(parse_content_length(b"").is_err());
  assert!(parse_content_length(b"+42").is_err());
  assert!(parse_content_length(b"-42").is_err());
  assert!(parse_content_length(b"4 2").is_err());
  assert!(parse_content_length(b"0x2a").is_err());
  assert!(parse_content_length(b"99999999999999999999").is_err()); // u64 overflow

  assert_eq!(
    freq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 3\r\n\r\n"),
    BodyFraming::ContentLength(3)
  );
  // Identical comma-list collapses (item 5's exception, the MAY taken):
  assert_eq!(
    freq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 42, 42\r\n\r\n"),
    BodyFraming::ContentLength(42)
  );
  // Differing values → unrecoverable:
  assert!(vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 42, 43\r\n\r\n").is_err());
  // Two separate field lines, same value → collapses; differing → err. RFC 9110
  // §5.2 makes repeated lines one comma-joined list, so the same rule applies
  // across lines as within one — the span of the first line alone would miss
  // the second, which is the smuggling case.
  assert_eq!(
    freq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 42\r\nContent-Length: 42\r\n\r\n"),
    BodyFraming::ContentLength(42)
  );
  assert!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 42\r\nContent-Length: 43\r\n\r\n")
      .is_err()
  );
  // An invalid value on the second line is caught for the same reason.
  assert!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 42\r\nContent-Length: x\r\n\r\n")
      .is_err()
  );
  // A `Content-Length` with no value at all frames nothing.
  assert!(vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length:\r\n\r\n").is_err());
  assert_eq!(
    sreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 42, 43\r\n\r\n"),
    SuggestedStatus::BadRequest
  );
}

// RFC 9112 §6.3 item 3 (both fields → handled as an error, §6.1: the server
// MUST close the connection after responding), item 4's request half (chunked
// not the final coding → 400), §6.1 (a coding the server does not understand →
// 501; chunked applied more than once is forbidden; an HTTP/1.0 message with
// Transfer-Encoding has faulty framing), and §7.1 (chunked defines no
// parameters; their presence SHOULD be an error).
#[test]
fn transfer_encoding_rules() {
  // TE + CL:
  assert!(
    vreq(
      b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
    )
    .is_err()
  );
  assert!(matches!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked\r\n\r\n"),
    Ok((BodyFraming::Chunked, _))
  ));
  // RFC 9112 §7: transfer-coding names are case-insensitive.
  assert!(matches!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: Chunked\r\n\r\n"),
    Ok((BodyFraming::Chunked, _))
  ));
  // Unknown coding (chunked is still final, so the framing MUST does not fire):
  assert!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
      .is_err()
  );
  // chunked not final:
  assert!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked, gzip\r\n\r\n")
      .is_err()
  );
  // chunked twice:
  assert!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked, chunked\r\n\r\n")
      .is_err()
  );
  // Parameters on chunked (§7.1 SHOULD):
  assert!(
    vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked;a=b\r\n\r\n").is_err()
  );
  // No coding at all, and a coding without chunked anywhere: neither frames the
  // message.
  assert!(vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding:\r\n\r\n").is_err());
  assert!(vreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: gzip\r\n\r\n").is_err());
  // Transfer-Encoding from an HTTP/1.0 peer:
  assert!(
    vreq(b"POST / HTTP/1.0\r\nHost: h.example\r\nTransfer-Encoding: chunked\r\n\r\n").is_err()
  );
  // Split over two field lines, the list folds: `chunked, gzip` — chunked is no
  // longer final, which the first line's span alone would not show.
  assert!(
    vreq(
      b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
    )
    .is_err()
  );

  // The two failure classes are distinguished by the status a server is advised
  // to answer with: §6.1's SHOULD-501 for a coding it cannot decode, §6.3 item
  // 4's MUST-400 for a chunked that does not frame the message.
  assert_eq!(
    sreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
    SuggestedStatus::NotImplemented
  );
  assert_eq!(
    sreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
    SuggestedStatus::BadRequest
  );
  assert_eq!(
    sreq(
      b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
    ),
    SuggestedStatus::BadRequest
  );
  assert_eq!(
    sreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked, chunked\r\n\r\n"),
    SuggestedStatus::BadRequest
  );
  // A list with no chunked in it at all is not a misplaced chunked: item 4's
  // MUST-400 is a rule about the chunked a message carries, so what is left is
  // §6.1's SHOULD-501 for a coding the server does not understand.
  assert_eq!(
    sreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: gzip\r\n\r\n"),
    SuggestedStatus::NotImplemented
  );
  // A field line with no coding on it frames nothing, which is the 400.
  assert_eq!(
    sreq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding:\r\n\r\n"),
    SuggestedStatus::BadRequest
  );
  assert_eq!(
    sreq(
      b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
    ),
    SuggestedStatus::BadRequest
  );
}

// RFC 9112 §6.3 item 7 with the note under item 8: a request is never
// close-delimited, so a request without chunked and without Content-Length ends
// at its head. Item 4 makes chunked override a Content-Length that cannot be
// present anyway (§6.2: a sender MUST NOT send both).
#[test]
fn request_framing_precedence() {
  assert_eq!(
    freq(b"GET / HTTP/1.1\r\nHost: h.example\r\n\r\n"),
    BodyFraming::None
  );
  assert_eq!(
    freq(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 0\r\n\r\n"),
    BodyFraming::ContentLength(0)
  );
  assert_eq!(
    freq(b"POST / HTTP/1.1\r\nHost: h.example\r\nTransfer-Encoding: chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  // An HTTP/1.0 request is framed by Content-Length or not at all.
  assert_eq!(
    freq(b"POST / HTTP/1.0\r\nHost: h.example\r\nContent-Length: 5\r\n\r\n"),
    BodyFraming::ContentLength(5)
  );
}

// RFC 9112 §3.2.3 (a client sending CONNECT MUST use the authority-form) and
// §3.2.4 (the asterisk-form is only for a server-wide OPTIONS request).
#[test]
fn target_method_pairing() {
  assert!(vreq(b"CONNECT /tunnel HTTP/1.1\r\nHost: example.com:443\r\n\r\n").is_err());
  assert!(vreq(b"GET example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").is_err());
  assert!(vreq(b"GET * HTTP/1.1\r\nHost: example.com\r\n\r\n").is_err());
  assert!(vreq(b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n").is_ok());
  // The pairings that hold:
  assert!(vreq(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").is_ok());
  assert!(vreq(b"OPTIONS /where HTTP/1.1\r\nHost: example.com\r\n\r\n").is_ok());
  // RFC 9112 §3.2.2: absolute-form is any method's to send, and is not CONNECT's.
  assert!(vreq(b"GET http://example.com/p?q HTTP/1.1\r\nHost: example.com\r\n\r\n").is_ok());
  assert!(vreq(b"CONNECT http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").is_err());
  // RFC 9110 §9.1: a method is a case-SENSITIVE token, so `connect` is not
  // CONNECT and may not carry the authority-form.
  assert!(vreq(b"connect example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").is_err());
  assert_eq!(
    sreq(b"GET * HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    SuggestedStatus::BadRequest
  );
}

// RFC 9112 §6.3 applied AS THE ORDERED LIST IT IS: items 1-2 (a bodiless status,
// a HEAD response, a CONNECT 2xx) resolve BEFORE any Content-Length or
// Transfer-Encoding is consulted, item 4 frames a response by chunked or by the
// connection close, items 5-6 by Content-Length, and item 8 catches the rest.
#[test]
fn response_framing_branches() {
  assert_eq!(
    vresp(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n"),
    BodyFraming::None // item 1 wins over the Content-Length
  );
  assert_eq!(
    vresp(b"HTTP/1.1 304 Not Modified\r\n\r\n"),
    BodyFraming::None
  );
  assert_eq!(
    vresp_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
    BodyFraming::None
  );
  assert_eq!(
    vresp_connect(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
    BodyFraming::None // item 2
  );
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"),
    BodyFraming::ContentLength(7)
  );
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\n\r\n"),
    BodyFraming::ReadToClose // item 8
  );
  // NOT errors on the response side: a Transfer-Encoding a server MUST NOT have
  // sent (§6.1) is a sender violation, not a recipient framing failure, and
  // items 1-2 have already answered the length question.
  assert_eq!(
    vresp(b"HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n"),
    BodyFraming::None
  );
  assert_eq!(
    vresp(b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"),
    BodyFraming::None
  );
  assert_eq!(
    vresp_connect(
      b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n"
    ),
    BodyFraming::None // item 2: a client MUST ignore both fields here
  );
  // Item 4 ¶2: chunked is NOT the final coding, so the list delimits nothing
  // and the body is read until the server closes the connection.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  // Item 4 ¶1: chunked IS the final coding, so the body ends where the chunked
  // stream ends. A coding beneath it changes what the delimited octets MEAN,
  // not where the message ends — delimitation is this module's question, and
  // decoding the gzip layer sits above the core. (The same list on the REQUEST
  // side is a 501: a server has to process what it received, §6.1.)
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  // A list naming no chunked at all delimits nothing either (¶2).
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  // §6.1 (chunked applied more than once) and §7.1 (chunked takes no
  // parameters): neither is a list this core will delimit by.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked;a=b\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  // Split lines fold on the response side too, and the fold decides
  // delimitation exactly as one comma-joined line would (RFC 9110 §5.2) — in
  // both directions.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  // Item 3, and it is the SAME rule as the request path's: the item is stated
  // over "a message" and names §11.1 response splitting beside §11.2 request
  // smuggling, so a response carrying both fields is refused rather than
  // resolved by ignoring one of them. Items 1-2 still take precedence over it —
  // see `bodiless_responses_keep_item_one_over_item_three` below.
  assert!(vresp_err(
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n"
  ));
  // Item 5 applies to responses as it does to requests.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nContent-Length: 7, 7\r\n\r\n"),
    BodyFraming::ContentLength(7)
  );
  assert!(vresp_err(
    b"HTTP/1.1 200 OK\r\nContent-Length: 7, 8\r\n\r\n"
  ));
  assert!(vresp_err(
    b"HTTP/1.1 200 OK\r\nContent-Length: seven\r\n\r\n"
  ));
  // A CONNECT response that is not 2xx is an ordinary response with a body.
  assert_eq!(
    vresp_connect(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 5\r\n\r\n"),
    BodyFraming::ContentLength(5)
  );
  // Still an error: Transfer-Encoding from an HTTP/1.0 peer (§6.1 — the framing
  // is faulty and the connection must not be reused).
  assert!(vresp_err(
    b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
  ));
  // RFC 9110 §15.2: 101 is a 1xx, so it is bodiless here as well — the
  // connection layer refuses it before General validation ever sees it.
  assert_eq!(
    vresp(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"),
    BodyFraming::None
  );
}

// RFC 9112 §6.3 item 3, whose text is stated over "a message" and names §11.1
// response splitting beside §11.2 request smuggling: the pair is a framing error
// in BOTH directions, and the two directions refuse it with the same words.
//
// The rule is the response half of `request_framing_precedence`'s item-3 row.
// Whatever spelling of the pair a peer chooses — one line each, the fields split
// across repeated lines (RFC 9110 §5.2 folds them), a `Content-Length` this core
// could not have read anyway — the answer is the same, because the fault is the
// COEXISTENCE and not what either field says.
#[test]
fn a_response_carrying_both_framing_fields_is_unframable() {
  for head in [
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n".as_slice(),
    // Field order does not decide it.
    b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n",
    // A list item 4 ¶2 would have made close-delimited is still the pair.
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 9\r\n\r\n",
    // Repeated lines fold into one field either way (RFC 9110 §5.2).
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\nContent-Length: 9\r\n\r\n",
    // The length need not be readable for the pair to be the fault: item 3 is
    // about the two fields being there at all.
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: nine\r\n\r\n",
    // Any status that is not items 1-2's, including the ones a proxy sends.
    b"HTTP/1.1 407 Proxy Authentication Required\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n",
    b"HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
  ] {
    assert!(vresp_err(head), "{:?}", core::str::from_utf8(head));
  }

  // The exchange context does not excuse it either, where that context does not
  // make the status bodiless: a NON-2xx answer to CONNECT is an ordinary
  // response (item 2 covers only the 2xx), and the pair is the same fault there.
  assert!(vresp_ctx(
    b"HTTP/1.1 407 Proxy Authentication Required\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n",
    false,
    true
  )
  .is_err());
}

// The PRECEDENCE half of the same rule: RFC 9112 §6.3 is a list "in order of
// precedence", and items 1-2 answer before item 3 is reached — item 1 in the
// words "regardless of the header fields present in the message", item 2 by
// making a client "ignore any Content-Length or Transfer-Encoding header fields
// received in such a message". A recipient that read the fields first and
// applied the status rule afterwards would attribute a body nobody expects to
// the next message (§11.1), so item 3's refusal may not run ahead of them.
//
// Every shape here carries BOTH framing fields and is nonetheless BODILESS.
#[test]
fn bodiless_responses_keep_item_one_over_item_three() {
  const BOTH: &str = "Transfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\n";
  for code in ["100 Continue", "199 ", "204 No Content", "304 Not Modified"] {
    let mut head = [0u8; 128];
    let n = write_head(&mut head, code, BOTH);
    assert_eq!(
      vresp(head.get(..n).unwrap()),
      BodyFraming::None,
      "item 1 answers {code} before item 3 is reached"
    );
  }
  // Item 1's other half: ANY response to HEAD, whatever its status.
  let mut head = [0u8; 128];
  let n = write_head(&mut head, "200 OK", BOTH);
  assert_eq!(vresp_head(head.get(..n).unwrap()), BodyFraming::None);
  // Item 2: a 2xx to CONNECT, where §9.3.6 makes ignoring both fields a client
  // MUST rather than a tolerance.
  assert_eq!(vresp_connect(head.get(..n).unwrap()), BodyFraming::None);
}

/// Builds `HTTP/1.1 <status>\r\n<fields>` into `head`, returning its length.
///
/// A helper rather than a `format!`: this module runs on the bare `no_std` tier,
/// where there is no allocator to build a string with.
fn write_head(head: &mut [u8; 128], status: &str, fields: &str) -> usize {
  let mut at = 0usize;
  for part in [
    b"HTTP/1.1 ".as_slice(),
    status.as_bytes(),
    b"\r\n",
    fields.as_bytes(),
  ] {
    head
      .get_mut(at..at.saturating_add(part.len()))
      .expect("the fixtures fit")
      .copy_from_slice(part);
    at = at.saturating_add(part.len());
  }
  at
}

// `Transfer-Encoding` is a PARAMETERISED list, so it may not be cut with the
// bare token splitter.
//
// RFC 9112 §7: `transfer-coding = token *( OWS ";" OWS transfer-parameter )`,
// and a `transfer-parameter`'s value may be an RFC 9110 §5.6.4 quoted-string —
// inside which a comma is DATA. Splitting on commas first turned
// `gzip;p="unterminated, chunked` into two elements and concluded `chunked` was
// the final coding, framing the body by a chunked stream the sender never
// announced, while any recipient parsing the real grammar rejects the field or
// close-delimits. That disagreement is §11.1.
//
// The bare splitter stays correct for token-only lists; it is PARAMETERISED
// lists that must not use it, and `Transfer-Encoding` is one.
#[test]
fn a_comma_inside_a_transfer_parameter_is_not_a_list_separator() {
  // Unterminated quoted-string: the field is not a coding list at all, so
  // nothing may be concluded from it — least of all the framing `chunked` the
  // old splitter concluded. The existing fault paths take it from there, and
  // they differ by role exactly as §6.3 item 4 does: a RESPONSE whose list
  // delimits nothing is close-delimited (¶2), a REQUEST is the MUST-400 (¶3).
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip;p=\"unterminated, chunked\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  assert!(
    vreq(
      b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip;p=\"unterminated, chunked\r\n\r\n"
    )
    .is_err()
  );

  // THE WELL-FORMED TWIN, and the pair is the point: the same comma inside a
  // CLOSED quoted-string is one element's data, not a separator. Two codings
  // here — `gzip;p="a,b"` and `chunked` — with chunked final, so §6.3 item 4 ¶1
  // delimits the body by the chunked stream.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip;p=\"a,b\", chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  // …and a request says the same about delimitation while §6.1 answers 501,
  // because a server has to process what it was sent.
  assert!(matches!(
    vreq(b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip;p=\"a,b\", chunked\r\n\r\n"),
    Err(H1Error::UnsupportedCoding(_))
  ));

  // A quoted comma cannot manufacture a coding either: this names ONE coding,
  // `gzip`, whose parameter happens to contain the text `chunked`. Read as two
  // elements it would have looked like a chunked list.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip;p=\", chunked\"\r\n\r\n"),
    BodyFraming::ReadToClose
  );

  // An escaped DQUOTE does not close the string (§5.6.4 `quoted-pair`), so this
  // is still one unterminated element rather than a closed one plus `chunked`.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip;p=\"a\\\", chunked\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  // The same bytes with the string properly closed are two codings again.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip;p=\"a\\\"b\", chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
}

// The rest of §7's grammar, which the splitter never checked at all: a list this
// recipient cannot parse is one the next recipient may parse differently, so the
// verdict is the framing fault rather than a coding guessed from the wreckage.
#[test]
fn a_transfer_encoding_that_is_not_a_coding_list_frames_nothing() {
  // (A CTL inside a quoted value never reaches here: RFC 9110 §5.5 makes it a
  // field-value violation, and the scan refuses the whole head first.)
  for bad in [
    // A parameter with no value — §7 gives no production for a bare name.
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked;p\r\n\r\n".as_slice(),
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked;=v\r\n\r\n",
    // A coding name that is not a token.
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \"chunked\"\r\n\r\n",
    // Two codings with no comma between them.
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip chunked\r\n\r\n",
  ] {
    assert_eq!(
      vresp(bad),
      BodyFraming::ReadToClose,
      "{:?}",
      core::str::from_utf8(bad)
    );
  }
  // The request half of the same rule is item 4's MUST-400 rather than item 4
  // ¶2's close-delimitation.
  assert!(matches!(
    vreq(b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked;p\r\n\r\n"),
    Err(H1Error::Framing(
      "Transfer-Encoding is not a transfer-coding list"
    ))
  ));

  // Well-formed parameters still parse, including OWS around the separators and
  // the `=` (§5.6.3's BWS), and a token-valued parameter.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip ; q = 1 , chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  // §5.6.1.2's empty elements are still ignored wherever they fall.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: , gzip, , chunked,\r\n\r\n"),
    BodyFraming::Chunked
  );
}

// RFC 9110 §10.1.1 `Expect` is parameterised too — `expectation = token
// [ "=" ( token / quoted-string ) parameters ]` — so the same rule applies to
// it, and its own token is what identifies it. The parameters are §5.6.6's
// `parameters`, not RFC 7231 §5.1.1's spelled-out `*( OWS ";" OWS
// [ expect-param ] )`: the two bracket the slot differently, which is the
// difference between an empty element being admitted and being refused.
//
// Read leniently rather than refused: §10.1.1 makes an unrecognised expectation
// a 417 the semantic layer MAY send, not a framing fault. Nothing about a
// message's extent depends on this field, which is why it differs from
// `Transfer-Encoding` above.
#[test]
fn an_expectation_is_recognised_only_when_it_parses_whole() {
  // A PARAMETERISED `100-continue` is not the expectation §10.1.1 defines. That
  // section defines exactly one — the bare token — so a member carrying an
  // argument or a parameter is an expectation this core does not recognise,
  // which is what §10.1.1's 417 is for. Recognising it by its leading token
  // alone would act on an ask whose parameters this end never read.
  let e = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue;charset=utf-8\r\n\r\n");
  assert!(
    !e.expect_continue,
    "a parameterised expectation is not the plain ask"
  );
  assert!(e.has_other_expect);

  // And a token that merely STARTS with it is a different token entirely.
  let e = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue@x\r\n\r\n");
  assert!(!e.expect_continue, "a prefix match is not a match");
  assert!(e.has_other_expect);

  // A comma inside a quoted parameter is data, so this is ONE other
  // expectation — not one of them plus a 100-continue.
  let e =
    d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: x=\", 100-continue\"\r\n\r\n");
  assert!(
    !e.expect_continue,
    "a quoted comma manufactured an expectation"
  );
  assert!(e.has_other_expect);

  // And the ordinary shapes are unchanged.
  let e = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n");
  assert!(e.expect_continue && !e.has_other_expect);
  let e = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: x, 100-continue\r\n\r\n");
  assert!(e.expect_continue && e.has_other_expect);
}

// RFC 9110 §5.2 makes repeated field lines ONE value joined by commas, so
// parser state must carry ACROSS the join — and a comma inside a quoted-string
// is data, including the one the join itself inserts.
//
// `Transfer-Encoding: foo;p="a` + `b", chunked` combines to
// `foo;p="a,b", chunked`: two codings, `chunked` final, so §6.3 item 4 ¶1
// delimits the body by the chunked stream. Restarting the scan at each physical
// line called the first line unterminated and took item 4 ¶2's close-delimitation
// instead — on a persistent connection that eats the next response as body, or
// leaves the reader waiting for an EOF that never comes.
#[test]
fn a_quoted_parameter_may_span_the_line_join() {
  assert_eq!(
    vresp(
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\r\nTransfer-Encoding: b\", chunked\r\n\r\n"
    ),
    BodyFraming::Chunked
  );
  // The request direction reaches the same combined value, and §6.1 answers 501
  // because a server has to process what it was sent.
  assert!(matches!(
    vreq(
      b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: foo;p=\"a\r\nTransfer-Encoding: b\", chunked\r\n\r\n"
    ),
    Err(H1Error::UnsupportedCoding(_))
  ));

  // The join's comma is DATA here, so the value names ONE coding whose parameter
  // merely contains the text `chunked` — not two with chunked final.
  assert_eq!(
    vresp(
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\r\nTransfer-Encoding: chunked\"\r\n\r\n"
    ),
    BodyFraming::ReadToClose
  );

  // A backslash left at the end of a line escapes the join's own comma.
  assert_eq!(
    vresp(
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\\\r\nTransfer-Encoding: b\", chunked\r\n\r\n"
    ),
    BodyFraming::Chunked
  );

  // Still open when the LAST line ends: §5.2 has no further line to continue it
  // with, so the field is unterminated and frames nothing.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\r\nTransfer-Encoding: b\r\n\r\n"),
    BodyFraming::ReadToClose
  );

  // And the ordinary two-line list is unchanged: with no quote open, the join's
  // comma is the separator it is meant to be.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
}

// The RECIPIENT half of the §5.6.1.1 / §5.6.1.2 asymmetry, on the field where
// the sender half had escaped: "A recipient MUST parse and ignore a reasonable
// number of empty list elements". The empty elements below change NOTHING about
// the framing, and each of these values is one this core will not GENERATE.
#[test]
fn a_recipient_ignores_the_empty_elements_a_sender_may_not_write() {
  // The trailing comma the sender check used to miss entirely.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n"),
    BodyFraming::Chunked
  );
  // Between two codings, and leading.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,,chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ,chunked\r\n\r\n"),
    BodyFraming::Chunked
  );
  // And across §5.2's join, in both arrangements.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: \r\n\r\n"),
    BodyFraming::Chunked
  );
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\nTransfer-Encoding: chunked\r\n\r\n"),
    BodyFraming::Chunked
  );

  // What an empty element is NOT is a licence to drop the separator rule: a
  // coding followed by anything other than a comma is still not a list.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip chunked\r\n\r\n"),
    BodyFraming::ReadToClose
  );
  // Including where the element resumed across the join, which reaches the same
  // check through the same routine.
  assert_eq!(
    vresp(
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\r\nTransfer-Encoding: b\" chunked\r\n\r\n"
    ),
    BodyFraming::ReadToClose
  );
}

// THE SEPARATOR IS A CHARACTER, not a boundary the scanner steps over. RFC 9110
// §5.2 joins the field lines "separated by a comma", and inside an open
// `quoted-string` that comma is one of the string's own characters — so a
// backslash left at the end of a line escapes IT, and the next line's first byte
// starts with no escape pending.
//
// Resuming at that byte with the previous escape still set hands the escape to
// the wrong character, and the two arrangements below are the two ways that goes
// wrong. Both are framing disagreements with the peer, in opposite directions.
#[test]
fn the_join_comma_consumes_a_pending_escape() {
  // LEGAL, and it was read as unterminated: the backslash escapes the join's
  // comma, the DQUOTE then closes the string, and `chunked` is final. Resuming
  // with the escape still pending fed it to the DQUOTE instead, leaving the
  // string open forever and close-delimiting a chunked response — which on a
  // persistent connection reads the NEXT response as this one's body.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\\\r\nTransfer-Encoding: \", chunked\r\n\r\n"),
    BodyFraming::Chunked
  );

  // MALFORMED, and it was read as final-chunked: the backslash escapes the join
  // comma, the SECOND backslash escapes the DQUOTE, and the string never closes
  // — so the list frames nothing. Resuming with the escape pending ate the first
  // backslash as data, let the DQUOTE close the string, and produced a chunked
  // body out of a value the peer never terminated.
  assert_eq!(
    vresp(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\\\r\nTransfer-Encoding: \\\", chunked\r\n\r\n"),
    BodyFraming::ReadToClose
  );

  // The control: no escape pending at the join, so the comma is ordinary data
  // inside the string and the value is the same one either reading would give.
  assert_eq!(
    vresp(
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: foo;p=\"a\r\nTransfer-Encoding: \", chunked\r\n\r\n"
    ),
    BodyFraming::Chunked
  );

  // The same character, the same rule, in the other field that carries quoted
  // state across the join. `Expect` never frames a body, so what the escape
  // decides here is which expectation the server was asked for.
  let closed = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: ext=\"a\\\r\nExpect: \", 100-continue\r\n\r\n");
  assert!(
    closed.expect_continue,
    "the backslash escapes the join comma, the quote closes, and the bare member is the next element"
  );
  let never_closed = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: ext=\"a\\\r\nExpect: \\\", 100-continue\r\n\r\n");
  assert!(
    !never_closed.expect_continue,
    "a string that never closes derives no expectation"
  );
  assert!(never_closed.has_other_expect);
}

// A2: the facts an `Expect` value yields are PROVISIONAL until the whole
// combined value has parsed. RFC 9110 §5.2 makes every line one value, so a
// member that fails the grammar condemns the value however many members before
// it were fine — and committing the ask when the first one parsed delivered it
// out of a field this core could not read.
#[test]
fn an_expectation_is_derived_only_from_a_value_that_parses_whole() {
  let one_line =
    d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue, @\r\n\r\n");
  assert!(
    !one_line.expect_continue,
    "a later member that does not parse retracts the ask"
  );
  assert!(one_line.has_other_expect, "§10.1.1 answers that with 417");

  // The repeated-line twin: §5.2 makes these the same value, so they get the
  // same answer. The malformed verdict has to survive the join for that to be
  // true.
  let two_lines =
    d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue\r\nExpect: @\r\n\r\n");
  assert!(!two_lines.expect_continue, "and across the join too");
  assert!(two_lines.has_other_expect);

  // The other order, since the fault is a fact about the VALUE and not about
  // which line carried it.
  let reversed =
    d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: @\r\nExpect: 100-continue\r\n\r\n");
  assert!(!reversed.expect_continue);
  assert!(reversed.has_other_expect);

  // And the control: the same two members, both well formed, still ask.
  let clean =
    d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue\r\nExpect: ext=v\r\n\r\n");
  assert!(clean.expect_continue && clean.has_other_expect);
}

// RFC 9110 §7.6.1 `Connection = #connection-option` with
// `connection-option = token`. An option was recorded whenever ONE member
// matched, with no requirement that the others parse — so `Connection:
// upgrade,@` set the upgrade fact and could authorise a protocol switch off a
// field whose real meaning is unknown.
//
// The value is parsed whole; a member that is not a token means it is not a
// `Connection` header, and NO option is derived from it.
#[test]
fn a_connection_option_comes_only_from_a_value_that_parses() {
  // The switch is not authorised.
  let head = b"GET /c HTTP/1.1\r\nHost: h\r\nConnection: upgrade,@\r\nUpgrade: websocket\r\n\r\n";
  assert!(
    !d(head).has_upgrade,
    "a malformed value authorised a switch"
  );

  // …and the conservative consequence, which is this crate's existing answer to
  // an untrustworthy connection-control field: persistence ENDS. RFC 9112 §6.3
  // item 4 ¶2 does the same for a chunked declaration that cannot be trusted —
  // close-delimit rather than believe it — and the same reasoning applies here,
  // so no new error class is invented for it.
  assert!(
    d(head).close,
    "an unparseable Connection was trusted to persist"
  );
  // Even when the unreadable value is the one that would have said keep-alive.
  assert!(d(b"GET / HTTP/1.0\r\nHost: h\r\nConnection: keep-alive,@\r\n\r\n").close);
  // …and on a response, through the same predicate.
  assert!(
    vresp_ctx(
      b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close,@\r\n\r\n",
      false,
      false
    )
    .unwrap()
    .1
    .close
  );

  // Malformed on ANY line spoils the value they are all part of (§5.2).
  assert!(!d(b"GET /c HTTP/1.1\r\nHost: h\r\nConnection: @\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").has_upgrade);

  // The well-formed twins are untouched, empty elements included (§5.6.1.2).
  assert!(
    d(b"GET /c HTTP/1.1\r\nHost: h\r\nConnection: , upgrade ,\r\nUpgrade: websocket\r\n\r\n")
      .has_upgrade
  );
  assert!(d(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").close);
  assert!(!d(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\n\r\n").close);
}

// An expectation is recognised only when the WHOLE member parses, and §10.1.1
// defines exactly one — the bare `100-continue`.
#[test]
fn an_expectation_spanning_lines_is_read_as_one_value() {
  // §5.2's join, with the comma as quoted data: ONE other expectation, not one
  // of them plus a 100-continue.
  let e = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: x=\"a\r\nExpect: 100-continue\"\r\n\r\n");
  assert!(!e.expect_continue, "a spanning quote manufactured an ask");
  assert!(e.has_other_expect);

  // A quote still open when the last line ends is not a 100-continue either.
  let e =
    d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: x=\"a\r\nExpect: b\r\n\r\n");
  assert!(!e.expect_continue);

  // Across lines with no quote open, the join separates as it should.
  let e = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: x\r\nExpect: 100-continue\r\n\r\n");
  assert!(e.expect_continue && e.has_other_expect);

  // An ARGUMENT disqualifies it as surely as a parameter does.
  let e = d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: 100-continue=x\r\n\r\n");
  assert!(!e.expect_continue && e.has_other_expect);

  // §5.6.1.2's empty elements still contribute nothing, and the bare ask still
  // reads as one.
  let e =
    d(b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nExpect: , 100-continue ,\r\n\r\n");
  assert!(e.expect_continue && !e.has_other_expect);
}

// RFC 9112 §9.3 (persistence: 1.1 is persistent by default, 1.0 is not unless
// it sends `keep-alive`), §9.6 (`Connection: close`), RFC 9110 §7.8 (a server
// MUST ignore an `Upgrade` field in an HTTP/1.0 request, and a sender of
// `Upgrade` must also send the `upgrade` connection option), §10.1.1 (a server
// MUST ignore a 100-continue expectation in an HTTP/1.0 request; any other
// expectation MAY be answered 417).
#[test]
fn directives() {
  assert!(d(b"GET / HTTP/1.1\r\nHost: h.example\r\nConnection: close\r\n\r\n").close);
  assert!(d(b"GET / HTTP/1.0\r\nHost: h.example\r\n\r\n").close);
  assert!(!d(b"GET / HTTP/1.0\r\nHost: h.example\r\nConnection: keep-alive\r\n\r\n").close);
  assert!(!d(b"GET / HTTP/1.1\r\nHost: h.example\r\n\r\n").close);
  // A 1.0 message that sends BOTH is closed: `close` is the stronger signal.
  assert!(d(b"GET / HTTP/1.0\r\nHost: h.example\r\nConnection: keep-alive, close\r\n\r\n").close);
  assert!(
    d(
      b"GET /chat HTTP/1.1\r\nHost: h.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    )
    .has_upgrade
  );
  assert!(!d(b"GET /chat HTTP/1.1\r\nHost: h.example\r\nUpgrade: websocket\r\n\r\n").has_upgrade);
  assert!(!d(b"GET /chat HTTP/1.1\r\nHost: h.example\r\nConnection: Upgrade\r\n\r\n").has_upgrade);
  assert!(
    d(b"GET /chat HTTP/1.1\r\nHost: h.example\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
      .has_upgrade
  );
  assert!(
    d(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")
      .expect_continue
  );
  let other =
    d(b"POST / HTTP/1.1\r\nHost: h.example\r\nContent-Length: 4\r\nExpect: 102-processing\r\n\r\n");
  assert!(other.has_other_expect && !other.expect_continue);

  // Version guards — the two MUST-ignores, applied here rather than in the
  // scan, which records the token facts version-agnostically.
  assert!(
    !d(
      b"GET /chat HTTP/1.0\r\nHost: h.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    )
    .has_upgrade
  );
  assert!(
    !d(b"POST / HTTP/1.0\r\nHost: h.example\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")
      .expect_continue
  );

  // The same connection rules on the response side, where `Expect` never
  // applies: RFC 9110 §10.1.1 defines it as a request field.
  let r = vresp_ctx(
    b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
    false,
    false,
  )
  .unwrap()
  .1;
  assert!(r.close && !r.expect_continue && !r.has_other_expect);
  let r = vresp_ctx(
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    false,
    false,
  )
  .unwrap()
  .1;
  assert!(!r.close);
  let r = vresp_ctx(
    b"HTTP/1.1 426 Upgrade Required\r\nConnection: upgrade, close\r\nUpgrade: websocket\r\nContent-Length: 0\r\n\r\n",
    false,
    false,
  )
  .unwrap()
  .1;
  assert!(r.has_upgrade && r.close);
}
