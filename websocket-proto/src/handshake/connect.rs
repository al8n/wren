//! The RFC 8441 (HTTP/2) / RFC 9220 (HTTP/3) extended-CONNECT handshake as
//! header *data*. The HTTP stack owns the bytes (HPACK/QPACK, SETTINGS,
//! `:protocol` plumbing, the `SETTINGS_ENABLE_CONNECT_PROTOCOL` gate); this
//! module builds and validates the header lists and produces the same
//! [`Negotiated`] the h1 machines do. No `Sec-WebSocket-Key`/`Accept`
//! exists on these transports (RFC 8441 §5).

use crate::{
  handshake::parser::is_token,
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};
use std::{string::String, vec, vec::Vec};

/// The `:scheme` pseudo-header value.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display, IsVariant)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum Scheme {
  /// `https` — TLS-protected (wss-equivalent).
  Https,
  /// `http` — cleartext (ws-equivalent).
  Http,
}

impl Scheme {
  /// The pseudo-header value.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Https => "https",
      Self::Http => "http",
    }
  }
}

/// Errors building or validating an extended-CONNECT request.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ConnectRequestError {
  /// Empty authority, non-origin-form path, or CR/LF in a value.
  #[error("invalid connect request field: {0}")]
  InvalidField(&'static str),

  /// `:protocol` was present but not `websocket`.
  #[error(":protocol is not websocket")]
  NotWebSocket,

  /// `sec-websocket-version` missing.
  #[error("missing sec-websocket-version")]
  MissingVersion,

  /// `sec-websocket-version` present but not 13.
  #[error("unsupported sec-websocket-version (only 13)")]
  UnsupportedVersion,

  /// Negotiation storage/grammar failure.
  #[error("{0}")]
  Negotiation(#[from] NegotiationError),
}

/// Errors validating an extended-CONNECT response (client side). These fail
/// the WebSocket connection.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ConnectResponseError {
  /// The server selected a subprotocol that was not offered (or sent more
  /// than one / a non-token).
  #[error("server selected an unoffered subprotocol")]
  SubprotocolNotOffered,

  /// The server granted an extension that was not offered.
  #[error("server granted an unoffered extension")]
  ExtensionNotOffered,

  /// A response header that must appear at most once appeared twice.
  #[error("duplicate singleton response header")]
  DuplicateHeader,

  /// Negotiation storage/grammar failure.
  #[error("{0}")]
  Negotiation(#[from] NegotiationError),
}

/// An extended-CONNECT request builder. `headers()` yields the full list —
/// pseudo-headers first, as HTTP/2/3 require.
#[derive(Debug, Copy, Clone)]
pub struct ConnectRequest<'a> {
  scheme: Scheme,
  authority: &'a str,
  path: &'a str,
  subprotocols: &'a [&'a str],
  #[cfg(feature = "deflate")]
  deflate: Option<crate::negotiation::DeflateOffer>,
}

impl<'a> ConnectRequest<'a> {
  /// A request for `:scheme://:authority:path`.
  pub const fn new(scheme: Scheme, authority: &'a str, path: &'a str) -> Self {
    Self {
      scheme,
      authority,
      path,
      subprotocols: &[],
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

  /// Offer permessage-deflate.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  #[must_use]
  pub const fn with_deflate(mut self, offer: crate::negotiation::DeflateOffer) -> Self {
    self.deflate = Some(offer);
    self
  }

  /// Builds the header list for the HTTP/2/3 stack: `(":method","CONNECT")`,
  /// `(":protocol","websocket")`, scheme/authority/path, then the
  /// `sec-websocket-*` set.
  pub fn headers(&self) -> Result<Vec<(&'static str, String)>, ConnectRequestError> {
    if self.authority.is_empty() || self.authority.bytes().any(|b| b == b'\r' || b == b'\n') {
      return Err(ConnectRequestError::InvalidField("authority"));
    }
    if !self.path.starts_with('/')
      || self
        .path
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b' ')
    {
      return Err(ConnectRequestError::InvalidField("path"));
    }
    for proto in self.subprotocols {
      if !is_token(proto) {
        return Err(ConnectRequestError::InvalidField("subprotocol"));
      }
    }
    #[cfg(feature = "deflate")]
    if let Some(offer) = &self.deflate {
      offer.validate()?;
    }

    let mut out: Vec<(&'static str, String)> = vec![
      (":method", String::from("CONNECT")),
      (":protocol", String::from("websocket")),
      (":scheme", String::from(self.scheme.as_str())),
      (":authority", String::from(self.authority)),
      (":path", String::from(self.path)),
      (
        "sec-websocket-version",
        String::from(crate::constants::WEBSOCKET_VERSION),
      ),
    ];
    if let Some((first, rest)) = self.subprotocols.split_first() {
      let mut value = String::from(*first);
      for proto in rest {
        value.push_str(", ");
        value.push_str(proto);
      }
      out.push(("sec-websocket-protocol", value));
    }
    #[cfg(feature = "deflate")]
    if let Some(offer) = &self.deflate {
      let mut buf = [0u8; 160];
      let n = offer
        .write(&mut buf)
        .map_err(|_| ConnectRequestError::InvalidField("deflate offer too long"))?;
      let value = core::str::from_utf8(buf.get(..n).unwrap_or(&[]))
        .unwrap_or("")
        .into();
      out.push(("sec-websocket-extensions", value));
    }
    Ok(out)
  }
}

/// A validated extended-CONNECT request (server side). Borrowed from the
/// caller's header list.
#[derive(Debug, Copy, Clone)]
pub struct ConnectRequestView<'a> {
  headers: &'a [(&'a str, &'a str)],
}

impl<'a> ConnectRequestView<'a> {
  fn get(&self, name: &str) -> Option<&'a str> {
    self
      .headers
      .iter()
      .find_map(|(n, v)| n.eq_ignore_ascii_case(name).then_some(*v))
  }

  /// The `:path` pseudo-header, when the stack passed it through.
  pub fn path(&self) -> Option<&'a str> {
    self.get(":path")
  }

  /// The `:authority` pseudo-header, when present.
  pub fn authority(&self) -> Option<&'a str> {
    self.get(":authority")
  }

  /// Any header by name (ASCII case-insensitive).
  pub fn header(&self, name: &str) -> Option<&'a str> {
    self.get(name)
  }

  /// Subprotocol offers across repeated headers and comma lists.
  pub fn subprotocols(&self) -> impl Iterator<Item = &'a str> + '_ {
    self
      .headers
      .iter()
      .filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-protocol"))
      .flat_map(|(_, v)| v.split(','))
      .map(|s| s.trim_matches([' ', '\t']))
      .filter(|s| !s.is_empty())
  }

  /// Raw `sec-websocket-extensions` values for
  /// [`crate::negotiation::accept_deflate_offer`].
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub fn extensions(&self) -> impl Iterator<Item = &'a str> + '_ {
    self
      .headers
      .iter()
      .filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-extensions"))
      .map(|(_, v)| *v)
  }
}

/// Server-side validation of an extended-CONNECT header list. Pseudo-headers
/// are validated only when present (the H2/H3 stack normally enforces
/// `:method`/`:protocol` before this layer sees the request).
pub fn validate_connect_request<'a>(
  headers: &'a [(&'a str, &'a str)],
) -> Result<ConnectRequestView<'a>, ConnectRequestError> {
  let view = ConnectRequestView { headers };
  if let Some(protocol) = view.get(":protocol")
    && !protocol.eq_ignore_ascii_case("websocket")
  {
    return Err(ConnectRequestError::NotWebSocket);
  }
  match view.get("sec-websocket-version") {
    None => return Err(ConnectRequestError::MissingVersion),
    Some(v) if v != crate::constants::WEBSOCKET_VERSION => {
      return Err(ConnectRequestError::UnsupportedVersion);
    }
    Some(_) => {}
  }
  Ok(view)
}

/// Accept configuration for the CONNECT response (the 2xx itself belongs to
/// the HTTP stack; we contribute the `sec-websocket-*` response headers).
#[derive(Debug, Copy, Clone, Default)]
pub struct ConnectAccept<'a> {
  subprotocol: Option<&'a str>,
  #[cfg(feature = "deflate")]
  deflate: Option<crate::negotiation::DeflateResponse>,
}

impl<'a> ConnectAccept<'a> {
  /// Accept with no subprotocol and no extensions.
  pub const fn new() -> Self {
    Self {
      subprotocol: None,
      #[cfg(feature = "deflate")]
      deflate: None,
    }
  }

  /// Echo a subprotocol (must be one the client offered; validated by the
  /// caller via [`ConnectRequestView::subprotocols`] +
  /// [`crate::negotiation::select_subprotocol`]).
  #[must_use]
  pub const fn with_subprotocol(mut self, subprotocol: Option<&'a str>) -> Self {
    self.subprotocol = subprotocol;
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

  /// Builds the response header list.
  pub fn headers(&self) -> Result<Vec<(&'static str, String)>, ConnectRequestError> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    if let Some(proto) = self.subprotocol {
      if !is_token(proto) {
        return Err(ConnectRequestError::InvalidField("subprotocol"));
      }
      out.push(("sec-websocket-protocol", String::from(proto)));
    }
    #[cfg(feature = "deflate")]
    if let Some(response) = &self.deflate {
      let mut buf = [0u8; 160];
      let n = response
        .write(&mut buf)
        .map_err(|_| ConnectRequestError::InvalidField("deflate response too long"))?;
      let value = core::str::from_utf8(buf.get(..n).unwrap_or(&[]))
        .unwrap_or("")
        .into();
      out.push(("sec-websocket-extensions", value));
    }
    Ok(out)
  }
}

/// Client-side validation of the CONNECT response headers (after the HTTP
/// stack confirmed a 2xx), yielding the [`Negotiated`] result.
pub fn validate_connect_response(
  headers: &[(&str, &str)],
  request: &ConnectRequest<'_>,
) -> Result<Negotiated, ConnectResponseError> {
  let count = |name: &str| {
    headers
      .iter()
      .filter(|(n, _)| n.eq_ignore_ascii_case(name))
      .count()
  };
  let get = |name: &str| {
    headers
      .iter()
      .find_map(|(n, v)| n.eq_ignore_ascii_case(name).then_some(*v))
  };

  if count("sec-websocket-protocol") > 1 {
    return Err(ConnectResponseError::DuplicateHeader);
  }
  #[cfg_attr(not(feature = "deflate"), allow(unused_mut))]
  let mut negotiated = match get("sec-websocket-protocol") {
    None => Negotiated::none(),
    Some(chosen) => {
      let offered = request
        .subprotocols
        .iter()
        .any(|p| p.eq_ignore_ascii_case(chosen));
      if !offered || !is_token(chosen) {
        return Err(ConnectResponseError::SubprotocolNotOffered);
      }
      Negotiated::with_subprotocol(chosen)?
    }
  };

  #[cfg(feature = "deflate")]
  {
    match (request.deflate.as_ref(), count("sec-websocket-extensions")) {
      (_, 0) => {}
      (None, _) => return Err(ConnectResponseError::ExtensionNotOffered),
      (Some(_), n) if n > 1 => return Err(ConnectResponseError::DuplicateHeader),
      (Some(offer), _) => {
        let value = get("sec-websocket-extensions").unwrap_or("");
        let params = crate::negotiation::parse_deflate_response(value, offer)?;
        negotiated = negotiated.with_deflate(Some(params));
      }
    }
  }
  #[cfg(not(feature = "deflate"))]
  if count("sec-websocket-extensions") != 0 {
    return Err(ConnectResponseError::ExtensionNotOffered);
  }

  Ok(negotiated)
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  fn find<'a>(headers: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
    headers
      .iter()
      .find(|(n, _)| *n == name)
      .map(|(_, v)| v.as_str())
  }

  #[test]
  fn request_headers_cover_rfc8441_4() {
    let req = ConnectRequest::new(Scheme::Https, "server.example.com", "/chat")
      .with_subprotocols(&["chat", "superchat"]);
    let headers = req.headers().unwrap();

    assert_eq!(find(&headers, ":method"), Some("CONNECT"));
    assert_eq!(find(&headers, ":protocol"), Some("websocket"));
    assert_eq!(find(&headers, ":scheme"), Some("https"));
    assert_eq!(find(&headers, ":authority"), Some("server.example.com"));
    assert_eq!(find(&headers, ":path"), Some("/chat"));
    assert_eq!(find(&headers, "sec-websocket-version"), Some("13"));
    assert_eq!(
      find(&headers, "sec-websocket-protocol"),
      Some("chat, superchat")
    );
    // No Key/Accept over h2/h3 (RFC 8441 §5).
    assert_eq!(find(&headers, "sec-websocket-key"), None);
  }

  #[test]
  fn request_validation_rejects_bad_inputs() {
    assert!(
      ConnectRequest::new(Scheme::Https, "", "/")
        .headers()
        .is_err()
    );
    assert!(
      ConnectRequest::new(Scheme::Https, "h", "nope")
        .headers()
        .is_err()
    );
    assert!(
      ConnectRequest::new(Scheme::Https, "h", "/")
        .with_subprotocols(&["bad token"])
        .headers()
        .is_err()
    );
  }

  #[test]
  fn server_validates_a_connect_request() {
    let headers: &[(&str, &str)] = &[
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      (":scheme", "https"),
      (":authority", "server.example.com"),
      (":path", "/chat"),
      ("sec-websocket-version", "13"),
      ("sec-websocket-protocol", "chat, superchat"),
      ("origin", "https://example.com"),
    ];
    let view = validate_connect_request(headers).unwrap();
    assert_eq!(view.path(), Some("/chat"));
    assert_eq!(view.authority(), Some("server.example.com"));
    let offers: Vec<&str> = view.subprotocols().collect();
    assert_eq!(offers, ["chat", "superchat"]);

    // Version must be 13 when present (and is required).
    let bad: &[(&str, &str)] = &[("sec-websocket-version", "12")];
    assert!(matches!(
      validate_connect_request(bad).unwrap_err(),
      ConnectRequestError::UnsupportedVersion
    ));
    let missing: &[(&str, &str)] = &[(":method", "CONNECT")];
    assert!(matches!(
      validate_connect_request(missing).unwrap_err(),
      ConnectRequestError::MissingVersion
    ));

    // Pseudo-headers are validated only when present.
    let wrong_protocol: &[(&str, &str)] = &[
      (":protocol", "webtransport"),
      ("sec-websocket-version", "13"),
    ];
    assert!(matches!(
      validate_connect_request(wrong_protocol).unwrap_err(),
      ConnectRequestError::NotWebSocket
    ));
  }

  #[test]
  fn accept_and_client_validation_round_trip() {
    let accept = ConnectAccept::new().with_subprotocol(Some("chat"));
    let headers = accept.headers().unwrap();
    assert_eq!(find(&headers, "sec-websocket-protocol"), Some("chat"));

    let req = ConnectRequest::new(Scheme::Https, "h", "/").with_subprotocols(&["chat"]);
    let response: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let negotiated = validate_connect_response(&response, &req).unwrap();
    assert_eq!(negotiated.subprotocol(), Some("chat"));

    // A subprotocol we didn't offer fails.
    let response: &[(&str, &str)] = &[("sec-websocket-protocol", "nope")];
    assert!(validate_connect_response(response, &req).is_err());

    // No subprotocol → none negotiated.
    let response: &[(&str, &str)] = &[];
    let negotiated = validate_connect_response(response, &req).unwrap();
    assert_eq!(negotiated.subprotocol(), None);
  }

  #[cfg(feature = "deflate")]
  #[test]
  fn deflate_flows_through_connect() {
    use crate::negotiation::{DeflateOffer, ServerDeflateConfig, accept_deflate_offer};

    let req = ConnectRequest::new(Scheme::Https, "h", "/").with_deflate(DeflateOffer::new());
    let headers = req.headers().unwrap();
    let ext = find(&headers, "sec-websocket-extensions").unwrap();
    assert!(ext.starts_with("permessage-deflate"));

    // Server side: validate, accept, respond.
    let reqh: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let view = validate_connect_request(&reqh).unwrap();
    let (params, response) =
      accept_deflate_offer(view.extensions(), &ServerDeflateConfig::new()).unwrap();
    let accept = ConnectAccept::new().with_deflate(Some(response));
    let response_headers = accept.headers().unwrap();

    // Client side: validate the response.
    let resp: Vec<(&str, &str)> = response_headers
      .iter()
      .map(|(n, v)| (*n, v.as_str()))
      .collect();
    let negotiated = validate_connect_response(&resp, &req).unwrap();
    assert_eq!(negotiated.deflate(), Some(params));
  }
}
