//! Client side of the h1 opening handshake (RFC 6455 §4.1, §4.2.2 client
//! validation).

use crate::{
  constants,
  error::BufferTooSmallDetail,
  handshake::{
    ExtraHeaders, WriteCursor, accept_value,
    parser::{self, HeadError, Parsed, is_token, token_list_contains},
  },
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{Display, IsVariant, TryUnwrap};
use rand_core::Rng as RngCore;

/// Detail payload: which handshake option was rejected and why.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display)]
#[display("invalid handshake option: {what}")]
pub struct InvalidOptionsDetail {
  what: &'static str,
}

impl InvalidOptionsDetail {
  #[inline(always)]
  pub(crate) const fn new(what: &'static str) -> Self {
    Self { what }
  }

  /// Static description of the rejected option.
  #[inline(always)]
  pub const fn what(&self) -> &'static str {
    self.what
  }
}

/// Errors from the client handshake (configuration, encoding, validation).
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ClientHandshakeError {
  /// An option failed validation at construction.
  #[error("{0}")]
  InvalidOptions(InvalidOptionsDetail),

  /// The output buffer cannot hold the request.
  #[error("{0}")]
  BufferTooSmall(BufferTooSmallDetail),

  /// The response head failed HTTP grammar or the head caps.
  #[error("{0}")]
  Head(#[from] HeadError),

  /// The response status was not 101.
  #[error("expected status 101, got {0}")]
  UnexpectedStatus(u16),

  /// `Upgrade`/`Connection` did not contain the required tokens.
  #[error("response is not a websocket upgrade")]
  NotAnUpgrade,

  /// `Sec-WebSocket-Accept` missing or not the derivation of our key.
  #[error("Sec-WebSocket-Accept mismatch")]
  AcceptMismatch,

  /// A response header that must appear at most once appeared twice.
  #[error("duplicate singleton response header")]
  DuplicateHeader,

  /// The server selected a subprotocol the client never offered, listed
  /// more than one, or sent a malformed token.
  #[error("server selected an unoffered subprotocol")]
  SubprotocolNotOffered,

  /// The server granted an extension the client never offered (RFC 6455
  /// §4.1 step 6 — fail the connection).
  #[error("server granted an unoffered extension")]
  ExtensionNotOffered,

  /// Retaining the negotiation result failed (bounded-tier storage).
  #[error("{0}")]
  Negotiation(#[from] NegotiationError),
}

/// Client handshake configuration. Borrowed: keep it (and the slices it
/// references) alive for the machine's lifetime.
#[derive(Debug, Copy, Clone)]
pub struct ClientOptions<'a> {
  host: &'a str,
  path: &'a str,
  subprotocols: &'a [&'a str],
  extra_headers: ExtraHeaders<'a, 'a>,
  #[cfg(feature = "deflate")]
  deflate: Option<crate::negotiation::DeflateOffer>,
}

impl<'a> ClientOptions<'a> {
  /// Options for `GET {path}` against `Host: {host}`. `path` must start
  /// with `/` (origin-form request target).
  pub const fn new(host: &'a str, path: &'a str) -> Self {
    Self {
      host,
      path,
      subprotocols: &[],
      extra_headers: ExtraHeaders::new(),
      #[cfg(feature = "deflate")]
      deflate: None,
    }
  }

  /// Subprotocols to offer, in preference order.
  #[must_use]
  pub const fn with_subprotocols(mut self, subprotocols: &'a [&'a str]) -> Self {
    self.subprotocols = subprotocols;
    self
  }

  /// Additional request headers (auth, origin, cookies). Names must be
  /// tokens, must not collide with the managed handshake headers, and
  /// values must not contain CR/LF.
  #[must_use]
  pub fn with_extra_headers(mut self, extra_headers: impl Into<ExtraHeaders<'a, 'a>>) -> Self {
    self.extra_headers = extra_headers.into();
    self
  }

  /// Offers permessage-deflate (RFC 7692) in the upgrade request.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  #[must_use]
  pub const fn with_deflate(mut self, offer: crate::negotiation::DeflateOffer) -> Self {
    self.deflate = Some(offer);
    self
  }
}

/// Outcome of feeding response bytes to [`ClientHandshake::handle`].
#[derive(Debug, IsVariant, TryUnwrap)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ClientProgress {
  /// The head is not complete yet — read more bytes and call again with
  /// the whole accumulated buffer.
  NeedMore,
  /// Handshake complete.
  Complete(ClientComplete),
}

/// A completed client handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientComplete {
  negotiated: Negotiated,
  consumed: usize,
}

impl ClientComplete {
  /// The negotiation result — feed it to the connection machine.
  pub fn negotiated(&self) -> &Negotiated {
    &self.negotiated
  }

  /// Consumes self into the negotiation result.
  pub fn into_negotiated(self) -> Negotiated {
    self.negotiated
  }

  /// Bytes of the input buffer the handshake consumed; everything at and
  /// beyond this offset is frame-stream data.
  pub const fn consumed(&self) -> usize {
    self.consumed
  }
}

/// The client side of the h1 opening handshake. Construct, write the
/// request with [`encode_request`], then feed the accumulating response
/// buffer to [`handle`] until it completes.
///
/// [`encode_request`]: ClientHandshake::encode_request
/// [`handle`]: ClientHandshake::handle
#[derive(Debug, Clone)]
pub struct ClientHandshake<'a> {
  options: ClientOptions<'a>,
  key: [u8; constants::SEC_WEBSOCKET_KEY_LEN],
}

impl<'a> ClientHandshake<'a> {
  /// Validates `options` and draws the 16-byte nonce from `rng`
  /// (RFC 6455 §4.1 requires it to be selected randomly; use a
  /// CSPRNG-quality source for public-internet connections).
  pub fn new<R: RngCore>(
    options: ClientOptions<'a>,
    rng: &mut R,
  ) -> Result<Self, ClientHandshakeError> {
    let invalid =
      |what: &'static str| ClientHandshakeError::InvalidOptions(InvalidOptionsDetail::new(what));
    // A `Host:` value is an RFC 3986 authority (RFC 9110 §7.2), not a free
    // string — URI delimiters, whitespace, and controls are all invalid.
    if !crate::handshake::parser::is_valid_authority(options.host) {
      return Err(invalid("host is not a valid authority"));
    }
    // Full RFC 3986 path-and-query grammar (shared with the server gate):
    // rejects whitespace/controls AND a raw `#` — RFC 6455 §3 says the
    // resource name MUST NOT carry a fragment (escape literal `#` as %23).
    if !crate::handshake::parser::is_valid_path_and_query(options.path) {
      return Err(invalid("path is not a valid origin-form resource name"));
    }
    // RFC 6455 §4.1 item 10: offered subprotocols MUST all be unique — and
    // must fit [`Negotiated`]'s inline storage, or a conforming server
    // SELECTING the offer would fail our own response validation
    // (self-interop).
    for (i, proto) in options.subprotocols.iter().enumerate() {
      if !is_token(proto) {
        return Err(invalid("subprotocol is not a token"));
      }
      if proto.len() > crate::negotiation::MAX_SUBPROTOCOL_LEN {
        return Err(invalid("subprotocol exceeds the retainable length"));
      }
      if options
        .subprotocols
        .get(..i)
        .is_some_and(|prev| prev.contains(proto))
      {
        return Err(invalid("duplicate subprotocol offer"));
      }
    }
    options.extra_headers.validate().map_err(invalid)?;
    options
      .extra_headers
      .validate_no_managed_collision(&[])
      .map_err(invalid)?;
    #[cfg(feature = "deflate")]
    if let Some(offer) = &options.deflate {
      offer
        .validate()
        .map_err(|_| invalid("deflate offer window bits out of range"))?;
    }

    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let mut key = [0u8; constants::SEC_WEBSOCKET_KEY_LEN];
    // encoded_len(16) == 24 == the array length; encode always succeeds here.
    // Using `if let` to satisfy clippy::single_match and the panic-freedom wall.
    if let Some(written) = crate::base64::encode(&nonce, &mut key) {
      let _ = written;
    }
    Ok(Self { options, key })
  }

  /// The base64 `Sec-WebSocket-Key` this handshake sends (exposed for
  /// tests and diagnostics).
  pub const fn key(&self) -> &[u8; constants::SEC_WEBSOCKET_KEY_LEN] {
    &self.key
  }

  /// Writes the upgrade request, returning its length.
  pub fn encode_request(&self, out: &mut [u8]) -> Result<usize, ClientHandshakeError> {
    let mut w = WriteCursor::new(out);
    self
      .write_request(&mut w)
      .map_err(ClientHandshakeError::BufferTooSmall)?;
    Ok(w.written())
  }

  // Separate helper (not an immediately-invoked closure: that trips
  // `clippy::redundant_closure_call`).
  fn write_request(&self, w: &mut WriteCursor<'_>) -> Result<(), BufferTooSmallDetail> {
    w.push(b"GET ")?;
    w.push(self.options.path.as_bytes())?;
    w.push(b" HTTP/1.1\r\nHost: ")?;
    w.push(self.options.host.as_bytes())?;
    w.push(b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ")?;
    w.push(&self.key)?;
    w.push(b"\r\nSec-WebSocket-Version: ")?;
    w.push(constants::WEBSOCKET_VERSION.as_bytes())?;
    w.push(b"\r\n")?;
    if let Some((first, rest)) = self.options.subprotocols.split_first() {
      w.push(b"Sec-WebSocket-Protocol: ")?;
      w.push(first.as_bytes())?;
      for proto in rest {
        w.push(b", ")?;
        w.push(proto.as_bytes())?;
      }
      w.push(b"\r\n")?;
    }
    #[cfg(feature = "deflate")]
    if let Some(offer) = &self.options.deflate {
      w.push(b"Sec-WebSocket-Extensions: ")?;
      offer.write_to(w)?;
      w.push(b"\r\n")?;
    }
    for (name, value) in self.options.extra_headers.iter() {
      w.push(name.as_bytes())?;
      w.push(b": ")?;
      w.push(value.as_bytes())?;
      w.push(b"\r\n")?;
    }
    w.push(b"\r\n")
  }

  /// Parses and validates the accumulated response buffer (stateless:
  /// re-parses from the start; call again with MORE bytes after
  /// [`ClientProgress::NeedMore`]).
  pub fn handle(&self, data: &[u8]) -> Result<ClientProgress, ClientHandshakeError> {
    let head = match parser::parse_head(data)? {
      Parsed::NeedMore => return Ok(ClientProgress::NeedMore),
      Parsed::Complete(head) => head,
    };

    // Status line: "HTTP/1.1 NNN[ reason]".
    let line = head.start_line();
    let Some(rest) = line.strip_prefix("HTTP/1.1 ") else {
      return Err(ClientHandshakeError::Head(HeadError::Malformed(
        parser::MalformedDetail::new(0, "not an HTTP/1.1 status line"),
      )));
    };
    let code_str = rest.split(' ').next().unwrap_or("");
    // RFC 9112 §4: status-code = 3DIGIT. `u16::parse` alone would accept
    // `0101` and `+101` as 101 (Codex R23) — not an HTTP status line.
    if code_str.len() != 3 || !code_str.bytes().all(|b| b.is_ascii_digit()) {
      return Err(ClientHandshakeError::Head(HeadError::Malformed(
        parser::MalformedDetail::new(9, "status code is not 3DIGIT"),
      )));
    }
    let Ok(code) = code_str.parse::<u16>() else {
      return Err(ClientHandshakeError::Head(HeadError::Malformed(
        parser::MalformedDetail::new(9, "unparsable status code"),
      )));
    };
    if code != 101 {
      return Err(ClientHandshakeError::UnexpectedStatus(code));
    }

    let headers = head.headers();
    // RFC 9110 §5.3: repeated field lines are one comma-joined list, so the
    // token may arrive in ANY occurrence (proxies split lists across lines).
    let upgrade_ok = headers
      .get_all("upgrade")
      .any(|v| token_list_contains(v, "websocket"));
    let connection_ok = headers
      .get_all("connection")
      .any(|v| token_list_contains(v, "upgrade"));
    if !upgrade_ok || !connection_ok {
      return Err(ClientHandshakeError::NotAnUpgrade);
    }

    match headers.count("sec-websocket-accept") {
      0 => return Err(ClientHandshakeError::AcceptMismatch),
      1 => {}
      _ => return Err(ClientHandshakeError::DuplicateHeader),
    }
    let accept_ok = headers
      .get("sec-websocket-accept")
      .is_some_and(|v| v.as_bytes() == accept_value(&self.key));
    if !accept_ok {
      return Err(ClientHandshakeError::AcceptMismatch);
    }

    if headers.count("sec-websocket-protocol") > 1 {
      return Err(ClientHandshakeError::DuplicateHeader);
    }
    let negotiated = match headers.get("sec-websocket-protocol") {
      None => Negotiated::none(),
      Some(chosen) => {
        let offered = self.options.subprotocols.contains(&chosen);
        if !offered || !is_token(chosen) {
          return Err(ClientHandshakeError::SubprotocolNotOffered);
        }
        Negotiated::with_subprotocol(chosen)?
      }
    };

    #[cfg(not(feature = "deflate"))]
    if headers.get("sec-websocket-extensions").is_some() {
      return Err(ClientHandshakeError::ExtensionNotOffered);
    }
    #[cfg(feature = "deflate")]
    let negotiated = {
      let mut negotiated = negotiated;
      match (
        &self.options.deflate,
        headers.count("sec-websocket-extensions"),
      ) {
        (_, 0) => {}
        (None, _) => return Err(ClientHandshakeError::ExtensionNotOffered),
        (Some(_), n) if n > 1 => return Err(ClientHandshakeError::DuplicateHeader),
        (Some(offer), _) => {
          let value = headers.get("sec-websocket-extensions").unwrap_or("");
          let params = crate::negotiation::parse_deflate_response(value, offer)?;
          negotiated = negotiated.with_deflate(Some(params));
        }
      }
      negotiated
    };

    Ok(ClientProgress::Complete(ClientComplete {
      negotiated,
      consumed: head.consumed(),
    }))
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::handshake::accept_value;

  /// Deterministic Rng: fills with 0,1,2,3,…
  struct CountingRng(u8);

  impl rand_core::TryRng for CountingRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
      let mut b = [0u8; 4];
      self.try_fill_bytes(&mut b)?;
      Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
      let mut b = [0u8; 8];
      self.try_fill_bytes(&mut b)?;
      Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
      for d in dest {
        *d = self.0;
        self.0 = self.0.wrapping_add(1);
      }
      Ok(())
    }
  }

  fn handshake() -> ClientHandshake<'static> {
    let options = ClientOptions::new("server.example.com", "/chat")
      .with_subprotocols(&["chat", "superchat"])
      .with_extra_headers(&[("Origin", "http://example.com")]);
    ClientHandshake::new(options, &mut CountingRng(0)).unwrap()
  }

  fn response_for(hs: &ClientHandshake<'_>, extra: &str) -> Vec<u8> {
    let accept = accept_value(hs.key());
    let mut s = String::from(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
    );
    s.push_str("Sec-WebSocket-Accept: ");
    s.push_str(core::str::from_utf8(&accept).unwrap());
    s.push_str("\r\n");
    s.push_str(extra);
    s.push_str("\r\n");
    s.into_bytes()
  }

  #[test]
  fn request_contains_the_required_lines() {
    let hs = handshake();
    let mut buf = [0u8; 1024];
    let n = hs.encode_request(&mut buf).unwrap();
    let req = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(req.starts_with("GET /chat HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("\r\nHost: server.example.com\r\n"));
    assert!(req.contains("\r\nUpgrade: websocket\r\n"));
    assert!(req.contains("\r\nConnection: Upgrade\r\n"));
    assert!(req.contains("\r\nSec-WebSocket-Version: 13\r\n"));
    assert!(req.contains("\r\nSec-WebSocket-Protocol: chat, superchat\r\n"));
    assert!(req.contains("\r\nOrigin: http://example.com\r\n"));
    // The key line carries the deterministic nonce: base64 of 0..16.
    assert!(req.contains("\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\n"));
    assert!(req.ends_with("\r\n\r\n"));
  }

  #[test]
  fn buffer_too_small_is_reported() {
    let hs = handshake();
    let mut buf = [0u8; 32];
    assert!(matches!(
      hs.encode_request(&mut buf).unwrap_err(),
      ClientHandshakeError::BufferTooSmall(_)
    ));
  }

  #[test]
  fn options_reject_header_injection_and_reserved_names() {
    let bad = ClientOptions::new("h", "/").with_extra_headers(&[("X-Evil", "a\r\nX-Injected: b")]);
    assert!(matches!(
      ClientHandshake::new(bad, &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    let reserved = ClientOptions::new("h", "/").with_extra_headers(&[("Sec-WebSocket-Key", "x")]);
    assert!(matches!(
      ClientHandshake::new(reserved, &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    assert!(matches!(
      ClientHandshake::new(ClientOptions::new("", "/"), &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    assert!(matches!(
      ClientHandshake::new(ClientOptions::new("h", "nope"), &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    let badproto = ClientOptions::new("h", "/").with_subprotocols(&["has space"]);
    assert!(matches!(
      ClientHandshake::new(badproto, &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    // RFC 6455 §4.1 item 10: offered subprotocols MUST all be unique
    // (case-sensitively — "CHAT" is a different identifier per §11.5).
    let dup = ClientOptions::new("h", "/").with_subprotocols(&["chat", "chat"]);
    assert!(matches!(
      ClientHandshake::new(dup, &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    let cased = ClientOptions::new("h", "/").with_subprotocols(&["chat", "CHAT"]);
    assert!(ClientHandshake::new(cased, &mut CountingRng(0)).is_ok());

    // Regression (Codex R18): offers past `Negotiated`'s inline storage are
    // rejected at the emitter — a conforming server SELECTING the 65-byte
    // offer would otherwise fail our own response validation. 64 fits.
    let at_cap = "a".repeat(crate::negotiation::MAX_SUBPROTOCOL_LEN);
    let over_cap = "a".repeat(crate::negotiation::MAX_SUBPROTOCOL_LEN + 1);
    let ok: &[&str] = &[at_cap.as_str()];
    let over: &[&str] = &[over_cap.as_str()];
    assert!(
      ClientHandshake::new(
        ClientOptions::new("h", "/").with_subprotocols(ok),
        &mut CountingRng(0)
      )
      .is_ok()
    );
    assert!(matches!(
      ClientHandshake::new(
        ClientOptions::new("h", "/").with_subprotocols(over),
        &mut CountingRng(0)
      )
      .unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));

    // Regression (Codex R13+R14): the managed Host field is a full RFC 3986
    // authority — control bytes, whitespace, AND URI delimiters are all
    // invalid (a Host is not a URL).
    for bad_host in [
      "h\x07st", "h\0st", "h\x7Fst", "h st", "h\tst", "h/chat", "h?x", "h#f", "u@h", "a:b:c",
    ] {
      assert!(
        matches!(
          ClientHandshake::new(ClientOptions::new(bad_host, "/"), &mut CountingRng(0)).unwrap_err(),
          ClientHandshakeError::InvalidOptions(_)
        ),
        "{bad_host:?}"
      );
    }

    // Regression (Codex R12 class): a raw `#` in the path is a fragment —
    // RFC 6455 §3 forbids it (escape as %23).
    let frag = ClientOptions::new("h", "/chat#frag");
    assert!(matches!(
      ClientHandshake::new(frag, &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    let escaped = ClientOptions::new("h", "/chat%23frag");
    assert!(ClientHandshake::new(escaped, &mut CountingRng(0)).is_ok());
  }

  #[test]
  fn complete_handshake_with_leftover_and_subprotocol() {
    let hs = handshake();
    let mut resp = response_for(&hs, "Sec-WebSocket-Protocol: superchat\r\n");
    resp.extend_from_slice(&[0x81, 0x00]); // first frame bytes after the head
    match hs.handle(&resp).unwrap() {
      ClientProgress::Complete(done) => {
        assert_eq!(done.consumed(), resp.len() - 2);
        assert_eq!(done.negotiated().subprotocol(), Some("superchat"));
      }
      ClientProgress::NeedMore => panic!("complete response reported NeedMore"),
    }
    // Stateless: handling again yields the same result.
    assert!(matches!(
      hs.handle(&resp).unwrap(),
      ClientProgress::Complete(_)
    ));
  }

  #[test]
  fn partial_response_needs_more() {
    let hs = handshake();
    let resp = response_for(&hs, "");
    for cut in 0..resp.len() - 1 {
      assert!(
        matches!(hs.handle(&resp[..cut]).unwrap(), ClientProgress::NeedMore),
        "cut at {cut}"
      );
    }
  }

  #[test]
  fn validation_failures() {
    let hs = handshake();

    // Wrong status.
    let resp = b"HTTP/1.1 404 Not Found\r\n\r\n";
    assert!(matches!(
      hs.handle(resp).unwrap_err(),
      ClientHandshakeError::UnexpectedStatus(404)
    ));

    // Regression (Codex R23): status-code = 3DIGIT — spellings that PARSE
    // to 101 but are not three digits are malformed, not accepted.
    for bad in ["0101", "+101", "1 01", "10"] {
      let resp = format!("HTTP/1.1 {bad} Switching Protocols\r\n\r\n");
      assert!(
        matches!(
          hs.handle(resp.as_bytes()).unwrap_err(),
          ClientHandshakeError::Head(_) | ClientHandshakeError::UnexpectedStatus(_)
        ),
        "{bad:?}"
      );
      // The 3DIGIT shapes specifically are Head(Malformed), not 101.
      if bad.len() != 3 {
        assert!(matches!(
          hs.handle(resp.as_bytes()).unwrap_err(),
          ClientHandshakeError::Head(_)
        ));
      }
    }

    // Garbled status line.
    let resp = b"HTTP/1.1 abc\r\n\r\n";
    assert!(matches!(
      hs.handle(resp).unwrap_err(),
      ClientHandshakeError::Head(_)
    ));

    // Missing upgrade token.
    let mut resp = response_for(&hs, "");
    let s = String::from_utf8(resp.clone())
      .unwrap()
      .replace("Upgrade: websocket", "Upgrade: h2c");
    resp = s.into_bytes();
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::NotAnUpgrade
    ));

    // Wrong accept value.
    let mut wrong = response_for(&hs, "");
    let s = String::from_utf8(wrong.clone()).unwrap().replace(
      core::str::from_utf8(&accept_value(hs.key())).unwrap(),
      "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    wrong = s.into_bytes();
    assert!(matches!(
      hs.handle(&wrong).unwrap_err(),
      ClientHandshakeError::AcceptMismatch
    ));

    // Subprotocol the client never offered.
    let resp = response_for(&hs, "Sec-WebSocket-Protocol: nope\r\n");
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::SubprotocolNotOffered
    ));

    // An extension when none was offered (plan 3a offers none).
    let resp = response_for(&hs, "Sec-WebSocket-Extensions: permessage-deflate\r\n");
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::ExtensionNotOffered
    ));

    // Two accept headers.
    let resp = response_for(&hs, "Sec-WebSocket-Accept: bogus\r\n");
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::DuplicateHeader
    ));

    // No accept header at all is a mismatch, not a "duplicate".
    let resp =
      b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    assert!(matches!(
      hs.handle(resp).unwrap_err(),
      ClientHandshakeError::AcceptMismatch
    ));
  }

  #[test]
  fn subprotocol_selection_is_case_sensitive() {
    // RFC 6455 §11.5: identifiers are case-sensitive. The client offered
    // "chat"/"superchat"; a server selecting "CHAT" selected something we
    // never offered.
    let hs = handshake();
    let resp = response_for(&hs, "Sec-WebSocket-Protocol: CHAT\r\n");
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::SubprotocolNotOffered
    ));
  }

  #[test]
  fn split_connection_header_lines_are_conforming() {
    // RFC 9110 §5.3: a proxy may split a list across repeated field lines.
    let hs = handshake();
    let resp = response_for(&hs, "");
    let s = String::from_utf8(resp).unwrap().replace(
      "Connection: Upgrade\r\n",
      "Connection: keep-alive\r\nConnection: Upgrade\r\n",
    );
    assert!(matches!(
      hs.handle(s.as_bytes()).unwrap(),
      ClientProgress::Complete(_)
    ));
  }

  #[cfg(feature = "deflate")]
  #[test]
  fn deflate_offer_and_response_flow() {
    use crate::negotiation::DeflateOffer;

    let options = ClientOptions::new("h", "/")
      .with_deflate(DeflateOffer::new().with_server_no_context_takeover(true));
    let hs = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();

    let mut buf = [0u8; 1024];
    let n = hs.encode_request(&mut buf).unwrap();
    let req = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(req.contains(
      "\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_max_window_bits\r\n"
    ));

    // Server grants it.
    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n",
    );
    match hs.handle(&resp).unwrap() {
      ClientProgress::Complete(done) => {
        let d = done.negotiated().deflate().unwrap();
        assert!(d.server_no_context_takeover());
        assert_eq!(d.client_max_window_bits(), 15);
      }
      ClientProgress::NeedMore => panic!("complete"),
    }

    // Server declines (no extensions header): no deflate in Negotiated.
    let resp = response_for(&hs, "");
    match hs.handle(&resp).unwrap() {
      ClientProgress::Complete(done) => assert!(done.negotiated().deflate().is_none()),
      ClientProgress::NeedMore => panic!("complete"),
    }

    // Server grants something invalid → connection fails.
    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate; bogus\r\n",
    );
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::Negotiation(_)
    ));

    // Two extension headers in a response → fail (only one extension legal).
    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Extensions: permessage-deflate\r\n",
    );
    assert!(hs.handle(&resp).is_err());
  }
}
