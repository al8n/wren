//! Server side of the h1 opening handshake (RFC 6455 §4.2).

use crate::{
  constants,
  error::BufferTooSmallDetail,
  handshake::{
    WriteCursor, accept_value,
    parser::{self, Head, HeadError, Parsed, is_token, token_list_contains},
  },
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{IsVariant, TryUnwrap, Unwrap};

/// Errors from the server handshake (parsing, validation, encoding).
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
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
  /// `Sec-WebSocket-Protocol` headers and comma lists.
  pub fn subprotocols(&self) -> impl Iterator<Item = &'a str> + '_ {
    self
      .head
      .headers()
      .get_all("sec-websocket-protocol")
      .flat_map(|v| v.split(','))
      .map(|s| s.trim_matches([' ', '\t']))
      .filter(|s| !s.is_empty())
  }

  /// Any request header by name (ASCII case-insensitive) — for cookie,
  /// auth, and origin policy in the application.
  pub fn header(&self, name: &str) -> Option<&'a str> {
    self.head.headers().get(name)
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
#[derive(Debug, IsVariant, Unwrap, TryUnwrap)]
#[unwrap(ref)]
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
  extra_headers: &'a [(&'a str, &'a str)],
}

impl<'a> Accept<'a> {
  /// Accept with no subprotocol and no extra headers.
  pub const fn new() -> Self {
    Self {
      subprotocol: None,
      extra_headers: &[],
    }
  }

  /// Selects the subprotocol to echo (must be one the client offered —
  /// use [`crate::negotiation::select_subprotocol`]).
  #[must_use]
  pub const fn with_subprotocol(mut self, subprotocol: Option<&'a str>) -> Self {
    self.subprotocol = subprotocol;
    self
  }

  /// Additional response headers (same restrictions as the client's
  /// extra headers).
  #[must_use]
  pub const fn with_extra_headers(mut self, extra_headers: &'a [(&'a str, &'a str)]) -> Self {
    self.extra_headers = extra_headers;
    self
  }
}

/// A handshake rejection: status code (300–599), reason phrase, extra
/// headers.
#[derive(Debug, Copy, Clone)]
pub struct Rejection<'a> {
  status: u16,
  reason: &'a str,
  extra_headers: &'a [(&'a str, &'a str)],
}

impl<'a> Rejection<'a> {
  /// A rejection with the given status (300–599 enforced at encode time)
  /// and reason phrase.
  pub const fn new(status: u16, reason: &'a str) -> Self {
    Self {
      status,
      reason,
      extra_headers: &[],
    }
  }

  /// The RFC 6455 §4.2.2 wrong-version answer: 426 Upgrade Required with
  /// `Sec-WebSocket-Version: 13`.
  pub const fn unsupported_version() -> Self {
    Self {
      status: 426,
      reason: "Upgrade Required",
      extra_headers: &[("Sec-WebSocket-Version", "13")],
    }
  }

  /// Additional response headers.
  #[must_use]
  pub const fn with_extra_headers(mut self, extra_headers: &'a [(&'a str, &'a str)]) -> Self {
    self.extra_headers = extra_headers;
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

    let headers = head.headers();
    if headers.count("host") != 1 {
      return Err(ServerHandshakeError::MissingHost);
    }
    let host = headers.get("host").unwrap_or("");
    if host.is_empty() {
      return Err(ServerHandshakeError::MissingHost);
    }

    let upgrade_ok = headers
      .get("upgrade")
      .is_some_and(|v| token_list_contains(v, "websocket"));
    let connection_ok = headers
      .get("connection")
      .is_some_and(|v| token_list_contains(v, "upgrade"));
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
        let offered = request
          .subprotocols()
          .any(|o| o.eq_ignore_ascii_case(chosen));
        if !offered || !is_token(chosen) {
          return Err(ServerHandshakeError::SubprotocolNotOffered);
        }
        #[cfg(any(feature = "alloc", feature = "heapless"))]
        {
          Negotiated::with_subprotocol(chosen)?
        }
        #[cfg(not(any(feature = "alloc", feature = "heapless")))]
        {
          Negotiated::none()
        }
      }
    };
    validate_extras(accept.extra_headers)?;

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
    validate_extras(rejection.extra_headers)?;

    let mut status = [0u8; 3];
    encode_status(rejection.status, &mut status);

    let mut w = WriteCursor::new(out);
    write_rejection(&mut w, &status, rejection).map_err(ServerHandshakeError::BufferTooSmall)?;
    Ok(w.written())
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
  for (name, value) in accept.extra_headers {
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
  for (name, value) in rejection.extra_headers {
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

fn validate_extras(extras: &[(&str, &str)]) -> Result<(), ServerHandshakeError> {
  for (name, value) in extras {
    if !is_token(name) {
      return Err(ServerHandshakeError::InvalidResponseOption(
        "extra header name is not a token",
      ));
    }
    if value.bytes().any(|b| b == b'\r' || b == b'\n') {
      return Err(ServerHandshakeError::InvalidResponseOption(
        "extra header value contains CR/LF",
      ));
    }
  }
  Ok(())
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
}
