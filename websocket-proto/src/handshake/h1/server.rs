//! Server side of the h1 opening handshake (RFC 6455 §4.2).

use crate::{
  constants,
  error::BufferTooSmallDetail,
  handshake::{
    ExtraHeaders, WriteCursor, accept_value,
    parser::{self, Head, HeadError, Parsed, is_token, token_list_contains},
  },
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{IsVariant, TryUnwrap};

/// Errors from the server handshake (parsing, validation, encoding).
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ServerHandshakeError {
  /// The request head failed HTTP grammar or the head caps.
  #[error("{0}")]
  Head(#[from] HeadError),

  /// The request method was not GET.
  #[error("handshake request method must be GET")]
  NotAGet,

  /// The request was not HTTP/1.1.
  #[error("handshake request must be HTTP/1.1")]
  NotHttp11,

  /// The request target was neither origin-form nor an absolute http/https
  /// URI (RFC 6455 §4.2.1.1), or contained whitespace/control bytes.
  #[error("request target is not a websocket resource name")]
  InvalidTarget,

  /// No (single, non-empty) Host header.
  #[error("handshake request must carry a Host header")]
  MissingHost,

  /// `Upgrade`/`Connection` did not contain the required tokens.
  #[error("request is not a websocket upgrade")]
  NotAnUpgrade,

  /// `Sec-WebSocket-Key` missing or not the base64 of 16 bytes.
  #[error("missing or malformed Sec-WebSocket-Key")]
  InvalidKey,

  /// A request header that must appear at most once appeared twice.
  #[error("duplicate singleton request header")]
  DuplicateHeader,

  /// `Sec-WebSocket-Version` was not 13 — answer with
  /// [`Rejection::unsupported_version`].
  #[error("unsupported Sec-WebSocket-Version (only 13)")]
  UnsupportedVersion,

  /// The accept named a subprotocol the client did not offer (or a
  /// non-token).
  #[error("accepted subprotocol was not offered")]
  SubprotocolNotOffered,

  /// A `Sec-WebSocket-Protocol` offer element was not an RFC 9110 token, or
  /// the list repeated an element (RFC 6455 §4.1 requires unique offers).
  #[error("malformed Sec-WebSocket-Protocol offer list")]
  MalformedSubprotocols,

  /// Rejection status must be a client/server error or redirect (300–599),
  /// not a success code.
  #[error("rejection status {0} is not in 300..=599")]
  InvalidRejectionStatus(u16),

  /// The output buffer cannot hold the response.
  #[error("{0}")]
  BufferTooSmall(BufferTooSmallDetail),

  /// Invalid extra header or reason in the accept/rejection config.
  #[error("invalid response option: {0}")]
  InvalidResponseOption(&'static str),

  /// Retaining the negotiation result failed (bounded-tier storage).
  #[error("{0}")]
  Negotiation(#[from] NegotiationError),
}

/// A validated upgrade request, borrowed from the caller's buffer. The
/// application inspects it (path, origin, offers, arbitrary headers) and
/// decides to accept or reject.
#[derive(Debug, Copy, Clone)]
pub struct RequestView<'a> {
  head: Head<'a>,
  path: &'a str,
  host: &'a str,
  key: &'a str,
}

impl<'a> RequestView<'a> {
  /// The request target (origin-form path + query, verbatim).
  pub const fn path(&self) -> &'a str {
    self.path
  }

  /// The Host header value.
  pub const fn host(&self) -> &'a str {
    self.host
  }

  /// The `Sec-WebSocket-Key` value (24 base64 bytes, format-validated).
  pub fn key(&self) -> &'a [u8] {
    self.key.as_bytes()
  }

  /// The Origin header, when present (browser clients send it; RFC 6455
  /// §4.2.2 leaves the policy to the application).
  pub fn origin(&self) -> Option<&'a str> {
    self.head.headers().get("origin")
  }

  /// The client's subprotocol offers in order, across repeated
  /// `Sec-WebSocket-Protocol` headers and comma lists. Every element was
  /// token-validated and deduplicated during [`ServerHandshake::handle`].
  pub fn subprotocols(&self) -> impl Iterator<Item = &'a str> + '_ {
    self
      .head
      .headers()
      .get_all("sec-websocket-protocol")
      .flat_map(parser::list_elements)
  }

  /// Any request header by name (ASCII case-insensitive) — for cookie,
  /// auth, and origin policy in the application.
  pub fn header(&self, name: &str) -> Option<&'a str> {
    self.head.headers().get(name)
  }

  /// The raw `Sec-WebSocket-Extensions` values in arrival order (for
  /// [`crate::negotiation::accept_deflate_offer`]).
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub fn extensions(&self) -> impl Iterator<Item = &'a str> + '_ {
    self.head.headers().get_all("sec-websocket-extensions")
  }

  /// Bytes the request head consumed; data at and beyond this offset
  /// belongs to the frame stream.
  pub const fn consumed(&self) -> usize {
    self.head.consumed()
  }
}

/// Outcome of feeding request bytes to [`ServerHandshake::handle`].
// `RequestView` embeds an inline HeaderMap (64 entries); the enum's NeedMore
// variant carries no data, so the size difference is expected and intentional
// — boxing would require `alloc`, which is unavailable on the bare tier.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, IsVariant, TryUnwrap)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ServerProgress<'a> {
  /// The head is not complete yet — read more and call again with the
  /// whole accumulated buffer.
  NeedMore,
  /// A validated upgrade request, ready for the accept/reject decision.
  Request(RequestView<'a>),
}

/// Accept configuration: the subprotocol decision plus extra response
/// headers (plan 3b adds the extension decision).
#[derive(Debug, Copy, Clone, Default)]
pub struct Accept<'a> {
  subprotocol: Option<&'a str>,
  extra_headers: ExtraHeaders<'a, 'a>,
  #[cfg(feature = "deflate")]
  deflate: Option<crate::negotiation::DeflateResponse>,
}

impl<'a> Accept<'a> {
  /// Accept with no subprotocol and no extra headers.
  pub const fn new() -> Self {
    Self {
      subprotocol: None,
      extra_headers: ExtraHeaders::new(),
      #[cfg(feature = "deflate")]
      deflate: None,
    }
  }

  /// Selects the subprotocol to echo (must be one the client offered —
  /// use [`crate::negotiation::select_subprotocol`]).
  #[must_use]
  pub const fn with_subprotocol(mut self, subprotocol: Option<&'a str>) -> Self {
    self.subprotocol = subprotocol;
    self
  }

  /// Additional response headers. CR/LF, non-token names, and collisions
  /// with the handshake-managed headers are all rejected at encode time —
  /// a colliding extra (e.g. `Sec-WebSocket-Extensions`) would grant
  /// capabilities on the wire that the returned
  /// [`Negotiated`](crate::negotiation::Negotiated) does not carry.
  #[must_use]
  pub fn with_extra_headers(mut self, extra_headers: impl Into<ExtraHeaders<'a, 'a>>) -> Self {
    self.extra_headers = extra_headers.into();
    self
  }

  /// Grant permessage-deflate (from
  /// [`crate::negotiation::accept_deflate_offer`]).
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  #[must_use]
  pub const fn with_deflate(
    mut self,
    deflate: Option<crate::negotiation::DeflateResponse>,
  ) -> Self {
    self.deflate = deflate;
    self
  }
}

/// A handshake rejection: status code (300–599), reason phrase, extra
/// headers.
#[derive(Debug, Copy, Clone)]
pub struct Rejection<'a> {
  status: u16,
  reason: &'a str,
  extra_headers: ExtraHeaders<'a, 'a>,
}

impl<'a> Rejection<'a> {
  /// A rejection with the given status (300–599 enforced at encode time)
  /// and reason phrase.
  pub const fn new(status: u16, reason: &'a str) -> Self {
    Self {
      status,
      reason,
      extra_headers: ExtraHeaders::new(),
    }
  }

  /// The RFC 6455 §4.2.2 wrong-version answer: 426 Upgrade Required with
  /// `Sec-WebSocket-Version: 13`.
  pub const fn unsupported_version() -> Self {
    Self {
      status: 426,
      reason: "Upgrade Required",
      extra_headers: ExtraHeaders::from_entries(&[("Sec-WebSocket-Version", "13")]),
    }
  }

  /// Additional response headers.
  #[must_use]
  pub fn with_extra_headers(mut self, extra_headers: impl Into<ExtraHeaders<'a, 'a>>) -> Self {
    self.extra_headers = extra_headers.into();
    self
  }
}

/// The server side of the h1 opening handshake. Stateless: one instance
/// serves any number of handshakes.
#[derive(Debug, Copy, Clone, Default)]
pub struct ServerHandshake {}

impl ServerHandshake {
  /// Creates the (stateless) machine.
  pub const fn new() -> Self {
    Self {}
  }

  /// Parses and validates the accumulated request buffer (stateless
  /// re-parse; call again with more bytes after
  /// [`ServerProgress::NeedMore`]).
  pub fn handle<'a>(&self, data: &'a [u8]) -> Result<ServerProgress<'a>, ServerHandshakeError> {
    let head = match parser::parse_head(data)? {
      Parsed::NeedMore => return Ok(ServerProgress::NeedMore),
      Parsed::Complete(head) => head,
    };

    // Request line: "GET <target> HTTP/1.1".
    let mut parts = head.start_line().split(' ');
    let (method, target, version) = (
      parts.next().unwrap_or(""),
      parts.next().unwrap_or(""),
      parts.next().unwrap_or(""),
    );
    if method != "GET" {
      return Err(ServerHandshakeError::NotAGet);
    }
    if version != "HTTP/1.1" || parts.next().is_some() || target.is_empty() {
      return Err(ServerHandshakeError::NotHttp11);
    }
    let Some(target) = request_target_resource(target) else {
      return Err(ServerHandshakeError::InvalidTarget);
    };

    let headers = head.headers();
    if headers.count("host") != 1 {
      return Err(ServerHandshakeError::MissingHost);
    }
    let host = headers.get("host").unwrap_or("");
    if host.is_empty() {
      return Err(ServerHandshakeError::MissingHost);
    }

    // RFC 9110 §5.3: repeated field lines are one comma-joined list, so the
    // token may arrive in ANY occurrence (proxies split lists across lines).
    let upgrade_ok = headers
      .get_all("upgrade")
      .any(|v| token_list_contains(v, "websocket"));
    let connection_ok = headers
      .get_all("connection")
      .any(|v| token_list_contains(v, "upgrade"));
    if !upgrade_ok || !connection_ok {
      return Err(ServerHandshakeError::NotAnUpgrade);
    }

    if headers.count("sec-websocket-key") > 1 || headers.count("sec-websocket-version") > 1 {
      return Err(ServerHandshakeError::DuplicateHeader);
    }
    let Some(key) = headers.get("sec-websocket-key") else {
      return Err(ServerHandshakeError::InvalidKey);
    };
    if !crate::base64::is_valid_key(key.as_bytes()) {
      return Err(ServerHandshakeError::InvalidKey);
    }

    if headers.get("sec-websocket-version") != Some(constants::WEBSOCKET_VERSION) {
      return Err(ServerHandshakeError::UnsupportedVersion);
    }

    // RFC 6455 §4.2.1.8: the offer list is `1#token` whose elements the
    // client MUST keep unique (§4.1 item 10) — a non-token element or a
    // repeat makes the handshake invalid and processing stops (§4.2.1).
    // EMPTY elements are ignored, not rejected: RFC 9110 §5.6.1.2 requires
    // a recipient to parse and ignore a reasonable number of empty list
    // elements (`list_elements` filters them).
    let offers = || {
      headers
        .get_all("sec-websocket-protocol")
        .flat_map(parser::list_elements)
    };
    let mut seen = 0usize;
    for offer in offers() {
      if !is_token(offer) || offers().take(seen).any(|prev| prev == offer) {
        return Err(ServerHandshakeError::MalformedSubprotocols);
      }
      seen = seen.saturating_add(1);
    }

    Ok(ServerProgress::Request(RequestView {
      head,
      path: target,
      host,
      key,
    }))
  }

  /// Writes the 101 acceptance for `request`, returning the byte count and
  /// the negotiation result to configure the connection machine with.
  pub fn encode_response(
    &self,
    request: &RequestView<'_>,
    accept: &Accept<'_>,
    out: &mut [u8],
  ) -> Result<(usize, Negotiated), ServerHandshakeError> {
    let negotiated = match accept.subprotocol {
      None => Negotiated::none(),
      Some(chosen) => {
        let offered = request.subprotocols().any(|o| o == chosen);
        if !offered || !is_token(chosen) {
          return Err(ServerHandshakeError::SubprotocolNotOffered);
        }
        Negotiated::with_subprotocol(chosen)?
      }
    };
    accept
      .extra_headers
      .validate()
      .map_err(ServerHandshakeError::InvalidResponseOption)?;
    // No managed collisions: an extra `Sec-WebSocket-Extensions` /
    // `Sec-WebSocket-Protocol` would grant capabilities ON THE WIRE that the
    // returned `Negotiated` does not carry — the peer then compresses or
    // assumes a subprotocol against a connection configured for neither.
    accept
      .extra_headers
      .validate_no_managed_collision(&[])
      .map_err(ServerHandshakeError::InvalidResponseOption)?;

    #[cfg(feature = "deflate")]
    let negotiated = negotiated.with_deflate(accept.deflate.map(|r| r.params()));

    let accept_bytes = accept_value(request.key());
    let mut w = WriteCursor::new(out);
    write_accept_response(&mut w, &accept_bytes, accept)
      .map_err(ServerHandshakeError::BufferTooSmall)?;
    Ok((w.written(), negotiated))
  }

  /// Writes a rejection response (e.g. 403, or
  /// [`Rejection::unsupported_version`] for the 426 path), returning its
  /// length. The connection is closed after sending it.
  pub fn encode_rejection(
    &self,
    rejection: &Rejection<'_>,
    out: &mut [u8],
  ) -> Result<usize, ServerHandshakeError> {
    if !(300..=599).contains(&rejection.status) {
      return Err(ServerHandshakeError::InvalidRejectionStatus(
        rejection.status,
      ));
    }
    if rejection.reason.bytes().any(|b| b == b'\r' || b == b'\n') {
      return Err(ServerHandshakeError::InvalidResponseOption(
        "reason contains CR/LF",
      ));
    }
    rejection
      .extra_headers
      .validate()
      .map_err(ServerHandshakeError::InvalidResponseOption)?;
    // Managed collisions are rejected here too — `encode_rejection` writes
    // its own `Connection: close`, and a spoofed `Sec-WebSocket-Accept`
    // could dress a rejection up as an acceptance. `Sec-WebSocket-Version`
    // is exempt: a rejection legitimately advertises the supported version
    // (RFC 6455 §4.2.2's 426 answer — see `Rejection::unsupported_version`),
    // and no `Negotiated` exists on this path to contradict.
    rejection
      .extra_headers
      .validate_no_managed_collision(&["sec-websocket-version"])
      .map_err(ServerHandshakeError::InvalidResponseOption)?;

    let mut status = [0u8; 3];
    encode_status(rejection.status, &mut status);

    let mut w = WriteCursor::new(out);
    write_rejection(&mut w, &status, rejection).map_err(ServerHandshakeError::BufferTooSmall)?;
    Ok(w.written())
  }
}

/// Validates the request target and returns the /resource name/ (path +
/// query) it carries. RFC 6455 §4.2.1.1 admits TWO target shapes: origin-form
/// (`/chat`) or "an absolute HTTP/HTTPS URI containing the resource name" —
/// and RFC 9112 §3.2.2 separately requires origin servers to accept
/// absolute-form, so a strict leading-`/` gate would reject conforming
/// (typically proxied) clients. Whitespace, control bytes, and DEL never
/// appear in a valid request-target (RFC 9112 §3.2 grammar).
fn request_target_resource(target: &str) -> Option<&str> {
  if target.bytes().any(|b| b < 0x21 || b == 0x7F) {
    return None;
  }
  if target.starts_with('/') {
    return Some(target);
  }
  // Absolute-form: case-insensitive http/https scheme (RFC 3986 §3.1), a
  // non-empty authority, then the resource name from the first `/`.
  let rest = ["http://", "https://"].iter().find_map(|scheme| {
    target
      .get(..scheme.len())
      .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
      .and_then(|_| target.get(scheme.len()..))
  })?;
  match rest.find(['/', '?']) {
    // "http://host" → resource name "/" (RFC 6455 §3: empty path reads "/").
    None if !rest.is_empty() => Some("/"),
    // A query with no path ("http://h?x") would need a SYNTHESIZED leading
    // slash we cannot borrow; reject the degenerate spelling (no real
    // WebSocket client emits it). An empty authority is malformed outright.
    Some(i) if i > 0 => {
      let resource = rest.get(i..)?;
      resource.starts_with('/').then_some(resource)
    }
    _ => None,
  }
}

// Separate helpers (not immediately-invoked closures: that trips
// `clippy::redundant_closure_call`).
fn write_accept_response(
  w: &mut WriteCursor<'_>,
  accept_bytes: &[u8],
  accept: &Accept<'_>,
) -> Result<(), BufferTooSmallDetail> {
  w.push(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")?;
  w.push(accept_bytes)?;
  w.push(b"\r\n")?;
  if let Some(proto) = accept.subprotocol {
    w.push(b"Sec-WebSocket-Protocol: ")?;
    w.push(proto.as_bytes())?;
    w.push(b"\r\n")?;
  }
  #[cfg(feature = "deflate")]
  if let Some(response) = &accept.deflate {
    w.push(b"Sec-WebSocket-Extensions: ")?;
    response.write_to(w)?;
    w.push(b"\r\n")?;
  }
  for (name, value) in accept.extra_headers.iter() {
    w.push(name.as_bytes())?;
    w.push(b": ")?;
    w.push(value.as_bytes())?;
    w.push(b"\r\n")?;
  }
  w.push(b"\r\n")
}

fn write_rejection(
  w: &mut WriteCursor<'_>,
  status: &[u8; 3],
  rejection: &Rejection<'_>,
) -> Result<(), BufferTooSmallDetail> {
  w.push(b"HTTP/1.1 ")?;
  w.push(status)?;
  w.push(b" ")?;
  w.push(rejection.reason.as_bytes())?;
  w.push(b"\r\nConnection: close\r\n")?;
  for (name, value) in rejection.extra_headers.iter() {
    w.push(name.as_bytes())?;
    w.push(b": ")?;
    w.push(value.as_bytes())?;
    w.push(b"\r\n")?;
  }
  w.push(b"\r\n")
}

/// Renders a 300–599 status code as three ASCII digits.
fn encode_status(status: u16, out: &mut [u8; 3]) {
  let [d0, d1, d2] = out;
  *d0 = b'0'.wrapping_add(u8::try_from(status.div_euclid(100).rem_euclid(10)).unwrap_or(0));
  *d1 = b'0'.wrapping_add(u8::try_from(status.div_euclid(10).rem_euclid(10)).unwrap_or(0));
  *d2 = b'0'.wrapping_add(u8::try_from(status.rem_euclid(10)).unwrap_or(0));
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::handshake::accept_value;

  const GOOD: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: keep-alive, Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Origin: http://example.com\r\n\
Sec-WebSocket-Protocol: chat, superchat\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

  fn view(raw: &[u8]) -> RequestView<'_> {
    match ServerHandshake::new().handle(raw).unwrap() {
      ServerProgress::Request(v) => v,
      ServerProgress::NeedMore => panic!("complete request reported NeedMore"),
    }
  }

  #[test]
  fn parses_and_validates_a_browser_request() {
    let v = view(GOOD);
    assert_eq!(v.path(), "/chat");
    assert_eq!(v.host(), "server.example.com");
    assert_eq!(v.key(), b"dGhlIHNhbXBsZSBub25jZQ==");
    assert_eq!(v.origin(), Some("http://example.com"));
    let offers: Vec<&str> = v.subprotocols().collect();
    assert_eq!(offers, ["chat", "superchat"]);
    assert_eq!(v.consumed(), GOOD.len());
    // Pass-through inspection of arbitrary request headers.
    assert_eq!(v.header("origin"), Some("http://example.com"));
    assert_eq!(v.header("absent"), None);
  }

  #[test]
  fn offers_split_across_repeated_protocol_headers() {
    let raw = String::from_utf8(GOOD.to_vec()).unwrap().replace(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: superchat , last\r\n",
    );
    let raw = raw.into_bytes();
    let v = view(&raw);
    let offers: Vec<&str> = v.subprotocols().collect();
    assert_eq!(offers, ["chat", "superchat", "last"]);
  }

  #[test]
  fn split_connection_header_lines_are_conforming() {
    // RFC 9110 §5.3: a proxy may split a list across repeated field lines.
    let raw = String::from_utf8(GOOD.to_vec()).unwrap().replace(
      "Connection: keep-alive, Upgrade\r\n",
      "Connection: keep-alive\r\nConnection: Upgrade\r\n",
    );
    let v = view(raw.as_bytes());
    assert_eq!(v.host(), "server.example.com");
  }

  /// Regression (Codex R11): the request target must be a websocket
  /// /resource name/ — origin-form, or an absolute http/https URI
  /// (RFC 6455 §4.2.1.1 admits BOTH; rejecting absolute-form would fail
  /// conforming proxied clients, so that half of the review's
  /// recommendation is deliberately not taken).
  #[test]
  fn request_targets_are_validated() {
    let hs = ServerHandshake::new();

    // Rejected shapes: bare token, asterisk-form, authority-form,
    // tab/control bytes inside the target, query-without-path absolutes,
    // empty-authority absolutes, non-http schemes.
    for bad in [
      "websocket",
      "*",
      "server.example.com:80",
      "/\tadmin",
      "/a\x01b",
      "http://h?x=1",
      "http://?x",
      "ftp://h/chat",
    ] {
      let req = replaced("GET /chat HTTP/1.1\r\n", &format!("GET {bad} HTTP/1.1\r\n"));
      assert!(
        matches!(
          hs.handle(&req).unwrap_err(),
          ServerHandshakeError::InvalidTarget
        ),
        "{bad:?}"
      );
    }

    // Accepted shapes: absolute-form yields the embedded resource name;
    // a path-less absolute URI reads as "/" (RFC 6455 §3); the scheme is
    // case-insensitive (RFC 3986 §3.1).
    for (good, want) in [
      ("http://server.example.com/chat?x=1", "/chat?x=1"),
      ("HTTPS://server.example.com", "/"),
      ("/chat", "/chat"),
    ] {
      let req = replaced(
        "GET /chat HTTP/1.1\r\n",
        &format!("GET {good} HTTP/1.1\r\n"),
      );
      let v = match hs.handle(&req).unwrap() {
        ServerProgress::Request(v) => v,
        ServerProgress::NeedMore => panic!("complete"),
      };
      assert_eq!(v.path(), want, "{good:?}");
    }
  }

  /// Regression (Codex R10): the offer list is `1#token` with unique
  /// elements — a non-token element or a repeat fails the handshake. Empty
  /// elements are IGNORED, not rejected: RFC 9110 §5.6.1.2 requires a
  /// recipient to parse and ignore a reasonable number of empty list
  /// elements (this part deliberately diverges from the review's
  /// reject-empties recommendation, with the citation).
  #[test]
  fn malformed_subprotocol_offers_fail_the_handshake() {
    let hs = ServerHandshake::new();

    // Non-token element ("bad token" has a space).
    let bad = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: bad token, admin\r\n",
    );
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::MalformedSubprotocols
    ));

    // Duplicate element, including across repeated headers.
    let dup = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat, chat\r\n",
    );
    assert!(matches!(
      hs.handle(&dup).unwrap_err(),
      ServerHandshakeError::MalformedSubprotocols
    ));
    let dup = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: chat\r\n",
    );
    assert!(matches!(
      hs.handle(&dup).unwrap_err(),
      ServerHandshakeError::MalformedSubprotocols
    ));

    // Empty elements are ignored per RFC 9110 §5.6.1.2; the remaining
    // offer list is valid and negotiable.
    let stray = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: , admin\r\n",
    );
    let v = match hs.handle(&stray).unwrap() {
      ServerProgress::Request(v) => v,
      ServerProgress::NeedMore => panic!("complete"),
    };
    let offers: Vec<&str> = v.subprotocols().collect();
    assert_eq!(offers, ["admin"]);

    // Case-only difference is NOT a duplicate (subprotocols are
    // case-sensitive per RFC 6455 §11.5).
    let cased = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat, CHAT\r\n",
    );
    assert!(hs.handle(&cased).is_ok());
  }

  #[test]
  fn need_more_until_terminator() {
    let hs = ServerHandshake::new();
    for cut in [0usize, 1, 10, GOOD.len() - 1] {
      assert!(
        matches!(hs.handle(&GOOD[..cut]).unwrap(), ServerProgress::NeedMore),
        "cut {cut}"
      );
    }
  }

  fn replaced(needle: &str, replacement: &str) -> Vec<u8> {
    String::from_utf8(GOOD.to_vec())
      .unwrap()
      .replace(needle, replacement)
      .into_bytes()
  }

  #[test]
  fn validation_failures() {
    let hs = ServerHandshake::new();

    let bad = replaced("GET ", "POST ");
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::NotAGet
    ));

    let bad = replaced(" HTTP/1.1\r\n", " HTTP/1.0\r\n");
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::NotHttp11
    ));

    let bad = replaced("Host: server.example.com\r\n", "");
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::MissingHost
    ));

    let bad = replaced("Upgrade: websocket\r\n", "Upgrade: h2c\r\n");
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::NotAnUpgrade
    ));

    let bad = replaced(
      "Connection: keep-alive, Upgrade\r\n",
      "Connection: close\r\n",
    );
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::NotAnUpgrade
    ));

    let bad = replaced(
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
      "Sec-WebSocket-Key: tooShort\r\n",
    );
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::InvalidKey
    ));

    let bad = replaced("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "");
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::InvalidKey
    ));

    let bad = String::from_utf8(GOOD.to_vec()).unwrap().replace(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 12\r\n",
    );
    assert!(matches!(
      hs.handle(bad.as_bytes()).unwrap_err(),
      ServerHandshakeError::UnsupportedVersion
    ));

    // Duplicate singleton headers.
    let mut dup = GOOD.to_vec();
    let insert = dup.len() - 2;
    dup.splice(
      insert..insert,
      b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        .iter()
        .copied(),
    );
    assert!(matches!(
      hs.handle(&dup).unwrap_err(),
      ServerHandshakeError::DuplicateHeader
    ));
  }

  #[test]
  fn accept_response_and_negotiated() {
    let v = view(GOOD);
    let mut buf = [0u8; 512];
    let accept = Accept::new().with_subprotocol(Some("superchat"));
    let (n, negotiated) = ServerHandshake::new()
      .encode_response(&v, &accept, &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
      "{resp}"
    );
    assert!(resp.contains("\r\nUpgrade: websocket\r\n"));
    assert!(resp.contains("\r\nConnection: Upgrade\r\n"));
    assert!(resp.contains("\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    assert!(resp.contains("\r\nSec-WebSocket-Protocol: superchat\r\n"));
    assert!(resp.ends_with("\r\n\r\n"));
    assert_eq!(negotiated.subprotocol(), Some("superchat"));
    assert_eq!(&accept_value(v.key())[..], b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  }

  #[test]
  fn accepting_an_unoffered_subprotocol_is_rejected() {
    let v = view(GOOD);
    let mut buf = [0u8; 512];
    let accept = Accept::new().with_subprotocol(Some("nope"));
    assert!(matches!(
      ServerHandshake::new()
        .encode_response(&v, &accept, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::SubprotocolNotOffered
    ));

    // Case matters (RFC 6455 §11.5): the client offered "chat", not "CHAT".
    let accept = Accept::new().with_subprotocol(Some("CHAT"));
    assert!(matches!(
      ServerHandshake::new()
        .encode_response(&v, &accept, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::SubprotocolNotOffered
    ));
  }

  #[test]
  fn rejection_responses() {
    let mut buf = [0u8; 256];
    let n = ServerHandshake::new()
      .encode_rejection(&Rejection::new(403, "Forbidden"), &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(resp.contains("\r\nConnection: close\r\n"));
    assert!(resp.ends_with("\r\n\r\n"));

    let n = ServerHandshake::new()
      .encode_rejection(&Rejection::unsupported_version(), &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 426 Upgrade Required\r\n"));
    assert!(resp.contains("\r\nSec-WebSocket-Version: 13\r\n"));

    assert!(matches!(
      ServerHandshake::new()
        .encode_rejection(&Rejection::new(200, "OK"), &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidRejectionStatus(200)
    ));
  }

  #[test]
  fn accept_emits_extra_headers() {
    let v = view(GOOD);
    let mut buf = [0u8; 512];
    let accept = Accept::new().with_extra_headers(&[("X-Trace-Id", "abc123"), ("Server", "wren")]);
    let (n, _) = ServerHandshake::new()
      .encode_response(&v, &accept, &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("\r\nX-Trace-Id: abc123\r\n"), "{resp}");
    assert!(resp.contains("\r\nServer: wren\r\n"), "{resp}");
  }

  #[test]
  fn extra_headers_builder_round_trips_and_overflows_loudly() {
    use crate::handshake::ExtraHeadersBuilder;

    // Incrementally-built headers reach the wire like slice-built ones.
    let v = view(GOOD);
    let mut buf = [0u8; 512];
    let headers = ExtraHeadersBuilder::new()
      .with_header("X-Trace-Id", "abc123")
      .with_header("Server", "wren");
    assert_eq!(headers.len(), 2);
    assert!(!headers.is_full());
    let accept = Accept::new().with_extra_headers(&headers);
    let (n, _) = ServerHandshake::new()
      .encode_response(&v, &accept, &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("\r\nX-Trace-Id: abc123\r\n"), "{resp}");
    assert!(resp.contains("\r\nServer: wren\r\n"), "{resp}");

    // Past the capacity nothing is dropped silently: the overflow flag is
    // set and the handshake fails loudly at encode time.
    let mut overflowing = ExtraHeadersBuilder::<2>::with_capacity();
    overflowing = overflowing.with_header("A", "1").with_header("B", "2");
    assert!(overflowing.is_full());
    assert!(!overflowing.overflowed());
    overflowing = overflowing.with_header("C", "3");
    assert!(overflowing.overflowed());
    assert_eq!(overflowing.len(), 2, "the overflowing pair is not stored");

    let accept = Accept::new().with_extra_headers(&overflowing);
    assert!(matches!(
      ServerHandshake::new()
        .encode_response(&v, &accept, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidResponseOption("extra headers exceeded the builder capacity")
    ));
  }

  #[test]
  fn accept_rejects_bad_extra_headers() {
    let v = view(GOOD);
    let mut buf = [0u8; 512];

    let bad_name = Accept::new().with_extra_headers(&[("bad name", "x")]);
    assert!(matches!(
      ServerHandshake::new()
        .encode_response(&v, &bad_name, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidResponseOption(_)
    ));

    let crlf = Accept::new().with_extra_headers(&[("X-Evil", "a\r\nX: b")]);
    assert!(matches!(
      ServerHandshake::new()
        .encode_response(&v, &crlf, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidResponseOption(_)
    ));
  }

  #[test]
  fn rejection_emits_and_validates_extra_headers() {
    let mut buf = [0u8; 256];

    let r = Rejection::new(403, "Forbidden").with_extra_headers(&[("Retry-After", "30")]);
    let n = ServerHandshake::new()
      .encode_rejection(&r, &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("\r\nRetry-After: 30\r\n"), "{resp}");

    let bad = Rejection::new(403, "Forbidden").with_extra_headers(&[("X-Evil", "a\r\nX: b")]);
    assert!(matches!(
      ServerHandshake::new()
        .encode_rejection(&bad, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidResponseOption(_)
    ));
  }

  /// Regression (Codex R9): a managed-name extra would put bytes on the wire
  /// that contradict the returned `Negotiated` — an extra
  /// `Sec-WebSocket-Extensions: permessage-deflate` makes the peer compress
  /// against a connection configured without deflate. All managed names are
  /// rejected on the accept path.
  #[test]
  fn accept_rejects_managed_name_collisions() {
    let v = view(GOOD);
    let mut buf = [0u8; 512];
    for bad in [
      [("Sec-WebSocket-Accept", "spoof")],
      [("Sec-WebSocket-Extensions", "permessage-deflate")],
      [("Sec-WebSocket-Protocol", "chat")],
      [("Upgrade", "h2c")],
      [("Connection", "close")],
    ] {
      let accept = Accept::new().with_extra_headers(&bad);
      assert!(
        matches!(
          ServerHandshake::new()
            .encode_response(&v, &accept, &mut buf)
            .unwrap_err(),
          ServerHandshakeError::InvalidResponseOption(
            "extra header collides with a managed header"
          )
        ),
        "{bad:?}"
      );
    }
  }

  /// Rejections police managed names too (a spoofed `Sec-WebSocket-Accept`
  /// could dress a rejection up as an acceptance) — but
  /// `Sec-WebSocket-Version` is exempt: the RFC 6455 §4.2.2 wrong-version
  /// answer carries it, and no `Negotiated` exists on the rejection path.
  #[test]
  fn rejection_polices_managed_names_except_version() {
    let mut buf = [0u8; 256];

    // The 426 preset (which sets Sec-WebSocket-Version) still works.
    let n = ServerHandshake::new()
      .encode_rejection(&Rejection::unsupported_version(), &mut buf)
      .unwrap();
    assert!(
      core::str::from_utf8(&buf[..n])
        .unwrap()
        .contains("\r\nSec-WebSocket-Version: 13\r\n")
    );

    // Other managed names are rejected.
    let bad =
      Rejection::new(403, "Forbidden").with_extra_headers(&[("Sec-WebSocket-Accept", "spoof")]);
    assert!(matches!(
      ServerHandshake::new()
        .encode_rejection(&bad, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidResponseOption("extra header collides with a managed header")
    ));
    let bad = Rejection::new(403, "Forbidden").with_extra_headers(&[("Upgrade", "h2c")]);
    assert!(
      ServerHandshake::new()
        .encode_rejection(&bad, &mut buf)
        .is_err()
    );
  }

  // The outbound validation mirrors the inbound parser's CR/LF rejection but
  // deliberately does NOT screen the other C0 control bytes (only CR/LF have
  // ever been rejected outbound). A bare control byte passes through.
  #[test]
  fn extra_header_value_with_non_crlf_control_is_allowed() {
    let v = view(GOOD);
    let mut buf = [0u8; 512];
    let accept = Accept::new().with_extra_headers(&[("X-Bell", "a\x07b")]);
    let (n, _) = ServerHandshake::new()
      .encode_response(&v, &accept, &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("\r\nX-Bell: a\x07b\r\n"), "{resp:?}");
  }

  #[test]
  fn extra_headers_accessors() {
    let empty = ExtraHeaders::default();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.iter().count(), 0);

    let two = ExtraHeaders::from(&[("A", "1"), ("B", "2")]);
    assert!(!two.is_empty());
    assert_eq!(two.len(), 2);
    let collected: Vec<(&str, &str)> = two.iter().collect();
    assert_eq!(collected, [("A", "1"), ("B", "2")]);
  }

  #[cfg(feature = "deflate")]
  #[test]
  fn deflate_accept_flow() {
    use crate::negotiation::{ServerDeflateConfig, accept_deflate_offer};

    let raw = String::from_utf8(GOOD.to_vec()).unwrap().replace(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
    );
    let v = view(raw.as_bytes());

    let config = ServerDeflateConfig::new();
    let granted = accept_deflate_offer(v.extensions(), &config);
    let (params, response) = granted.unwrap();
    assert_eq!(params.client_max_window_bits(), 15);

    let mut buf = [0u8; 512];
    let accept = Accept::new().with_deflate(Some(response));
    let (n, negotiated) = ServerHandshake::new()
      .encode_response(&v, &accept, &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.contains("\r\nSec-WebSocket-Extensions: permessage-deflate\r\n"),
      "{resp}"
    );
    assert_eq!(negotiated.deflate(), Some(params));

    // Declining: no header, no deflate.
    let accept = Accept::new();
    let (n, negotiated) = ServerHandshake::new()
      .encode_response(&v, &accept, &mut buf)
      .unwrap();
    assert!(
      !core::str::from_utf8(&buf[..n])
        .unwrap()
        .contains("Sec-WebSocket-Extensions")
    );
    assert!(negotiated.deflate().is_none());
  }
}
