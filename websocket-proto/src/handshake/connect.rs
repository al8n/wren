//! The RFC 8441 (HTTP/2) / RFC 9220 (HTTP/3) extended-CONNECT handshake as
//! header *data*. The HTTP stack owns the bytes (HPACK/QPACK, SETTINGS,
//! `:protocol` plumbing, the `SETTINGS_ENABLE_CONNECT_PROTOCOL` gate); this
//! module builds and validates the header lists and produces the same
//! [`Negotiated`] the h1 machines do. No `Sec-WebSocket-Key`/`Accept`
//! exists on these transports (RFC 8441 §5).
//!
//! The header views ([`ConnectRequestHeaders`] / [`ConnectAcceptHeaders`])
//! borrow everything from the request/accept and render any deflate value
//! once into an inline buffer, so the whole surface is allocation-free and
//! available on every storage tier.

use crate::{
  handshake::parser::is_token,
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{Display, IsVariant, TryUnwrap, Unwrap};

/// Upper bound on a rendered `Sec-WebSocket-Extensions` value — the same bound
/// the deflate offer/response renderers are sized against. Both views hold one
/// inline buffer of this size.
#[cfg(feature = "deflate")]
const EXT_BUF_LEN: usize = 160;

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

  /// `:method` missing, repeated, or not `CONNECT` (RFC 8441 §4 requires the
  /// extended CONNECT method).
  #[error(":method is not exactly one CONNECT")]
  NotConnect,

  /// `:protocol` missing, repeated, or not `websocket`.
  #[error(":protocol is not exactly one websocket")]
  NotWebSocket,

  /// `sec-websocket-version` missing.
  #[error("missing sec-websocket-version")]
  MissingVersion,

  /// `sec-websocket-version` appeared more than once — ambiguous, since
  /// another layer might combine or pick a different occurrence.
  #[error("sec-websocket-version must appear exactly once")]
  DuplicateVersion,

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

/// An extended-CONNECT request builder. [`headers`](Self::headers) yields a
/// borrowed view whose iterator emits the full list — pseudo-headers first,
/// as HTTP/2/3 require.
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

  /// Validates the request and returns a borrowed [`ConnectRequestHeaders`]
  /// view. The view's [`iter`](ConnectRequestHeaders::iter) emits, in order:
  /// `(":method","CONNECT")`, `(":protocol","websocket")`, scheme/authority/
  /// path, `("sec-websocket-version","13")`, one `("sec-websocket-protocol",
  /// _)` per offered subprotocol, then `("sec-websocket-extensions", _)` when
  /// a deflate offer is present. No allocation: any deflate value is rendered
  /// once into the view.
  pub fn headers(&self) -> Result<ConnectRequestHeaders<'a>, ConnectRequestError> {
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
    let extensions = match &self.deflate {
      None => None,
      Some(offer) => {
        offer.validate()?;
        let mut buf = [0u8; EXT_BUF_LEN];
        let n = offer
          .write(&mut buf)
          .map_err(|_| ConnectRequestError::InvalidField("deflate offer too long"))?;
        Some((buf, n))
      }
    };

    Ok(ConnectRequestHeaders {
      scheme: self.scheme,
      authority: self.authority,
      path: self.path,
      subprotocols: self.subprotocols,
      #[cfg(feature = "deflate")]
      extensions,
    })
  }
}

/// A borrowed, allocation-free view of an extended-CONNECT request's header
/// list. Produced by [`ConnectRequest::headers`]; iterate with
/// [`iter`](Self::iter).
#[derive(Debug, Clone)]
pub struct ConnectRequestHeaders<'a> {
  scheme: Scheme,
  authority: &'a str,
  path: &'a str,
  subprotocols: &'a [&'a str],
  /// The rendered `sec-websocket-extensions` value and its length, present
  /// only when a deflate offer was made.
  #[cfg(feature = "deflate")]
  extensions: Option<([u8; EXT_BUF_LEN], usize)>,
}

impl ConnectRequestHeaders<'_> {
  /// The rendered deflate extension value, if any.
  #[cfg(feature = "deflate")]
  fn extensions(&self) -> Option<&str> {
    self
      .extensions
      .as_ref()
      .map(|(buf, n)| core::str::from_utf8(buf.get(..*n).unwrap_or(&[])).unwrap_or(""))
  }

  /// Iterates the full header list as `(name, value)` pairs, pseudo-headers
  /// first. Borrows the view; allocation-free.
  pub fn iter(&self) -> ConnectRequestHeadersIter<'_> {
    ConnectRequestHeadersIter {
      view: self,
      state: ReqState::Method,
    }
  }
}

/// Cursor over the fixed leading pseudo/`sec-*` headers, then the (possibly
/// repeated) subprotocol headers, then the single extensions header.
#[derive(Debug, Clone, Copy)]
enum ReqState {
  Method,
  Protocol,
  Scheme,
  Authority,
  Path,
  Version,
  /// Emitting `sec-websocket-protocol` for `subprotocols[idx]`.
  Subprotocol(usize),
  Extensions,
  Done,
}

/// Iterator over [`ConnectRequestHeaders`]. See
/// [`ConnectRequestHeaders::iter`].
#[derive(Debug, Clone)]
pub struct ConnectRequestHeadersIter<'a> {
  view: &'a ConnectRequestHeaders<'a>,
  state: ReqState,
}

impl<'a> Iterator for ConnectRequestHeadersIter<'a> {
  type Item = (&'static str, &'a str);

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      match self.state {
        ReqState::Method => {
          self.state = ReqState::Protocol;
          return Some((":method", "CONNECT"));
        }
        ReqState::Protocol => {
          self.state = ReqState::Scheme;
          return Some((":protocol", "websocket"));
        }
        ReqState::Scheme => {
          self.state = ReqState::Authority;
          return Some((":scheme", self.view.scheme.as_str()));
        }
        ReqState::Authority => {
          self.state = ReqState::Path;
          return Some((":authority", self.view.authority));
        }
        ReqState::Path => {
          self.state = ReqState::Version;
          return Some((":path", self.view.path));
        }
        ReqState::Version => {
          self.state = ReqState::Subprotocol(0);
          return Some(("sec-websocket-version", crate::constants::WEBSOCKET_VERSION));
        }
        ReqState::Subprotocol(idx) => match self.view.subprotocols.get(idx) {
          Some(proto) => {
            self.state = ReqState::Subprotocol(idx.saturating_add(1));
            return Some(("sec-websocket-protocol", proto));
          }
          None => {
            self.state = ReqState::Extensions;
          }
        },
        ReqState::Extensions => {
          self.state = ReqState::Done;
          #[cfg(feature = "deflate")]
          if let Some(value) = self.view.extensions() {
            return Some(("sec-websocket-extensions", value));
          }
        }
        ReqState::Done => return None,
      }
    }
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

/// Server-side validation of an extended-CONNECT header list. STRICT: this is
/// usable as the WebSocket gate on its own — it requires exactly one
/// `:method` of `CONNECT` (case-sensitive, RFC 9110 §9.1) and exactly one
/// `:protocol` of `websocket` (RFC 8441 §4 / RFC 9220 §3), so a plain CONNECT
/// or an ordinary request can never be mistaken for a WebSocket handshake,
/// even when the H2/H3 stack passes pseudo-headers through unchecked.
pub fn validate_connect_request<'a>(
  headers: &'a [(&'a str, &'a str)],
) -> Result<ConnectRequestView<'a>, ConnectRequestError> {
  let view = ConnectRequestView { headers };
  let count = |name: &str| {
    headers
      .iter()
      .filter(|(n, _)| n.eq_ignore_ascii_case(name))
      .count()
  };
  if count(":method") != 1 || view.get(":method") != Some("CONNECT") {
    return Err(ConnectRequestError::NotConnect);
  }
  let protocol_ok = count(":protocol") == 1
    && view
      .get(":protocol")
      .is_some_and(|p| p.eq_ignore_ascii_case("websocket"));
  if !protocol_ok {
    return Err(ConnectRequestError::NotWebSocket);
  }
  // Singleton, like the pseudo-headers above: an ambiguous repeated version
  // (which another layer might combine or read differently) must not pass
  // the gate — h1's duplicate-singleton rejection, mirrored.
  match count("sec-websocket-version") {
    0 => return Err(ConnectRequestError::MissingVersion),
    1 => {}
    _ => return Err(ConnectRequestError::DuplicateVersion),
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

  /// Validates and returns a borrowed [`ConnectAcceptHeaders`] view. The
  /// view's [`iter`](ConnectAcceptHeaders::iter) emits an optional
  /// `("sec-websocket-protocol", _)` then an optional
  /// `("sec-websocket-extensions", _)`. No allocation: any deflate value is
  /// rendered once into the view.
  pub fn headers(&self) -> Result<ConnectAcceptHeaders<'a>, ConnectRequestError> {
    if let Some(proto) = self.subprotocol
      && !is_token(proto)
    {
      return Err(ConnectRequestError::InvalidField("subprotocol"));
    }

    #[cfg(feature = "deflate")]
    let extensions = match &self.deflate {
      None => None,
      Some(response) => {
        let mut buf = [0u8; EXT_BUF_LEN];
        let n = response
          .write(&mut buf)
          .map_err(|_| ConnectRequestError::InvalidField("deflate response too long"))?;
        Some((buf, n))
      }
    };

    Ok(ConnectAcceptHeaders {
      subprotocol: self.subprotocol,
      #[cfg(feature = "deflate")]
      extensions,
    })
  }
}

/// A borrowed, allocation-free view of an extended-CONNECT response's header
/// list. Produced by [`ConnectAccept::headers`]; iterate with
/// [`iter`](Self::iter).
#[derive(Debug, Clone)]
pub struct ConnectAcceptHeaders<'a> {
  subprotocol: Option<&'a str>,
  #[cfg(feature = "deflate")]
  extensions: Option<([u8; EXT_BUF_LEN], usize)>,
}

impl ConnectAcceptHeaders<'_> {
  #[cfg(feature = "deflate")]
  fn extensions(&self) -> Option<&str> {
    self
      .extensions
      .as_ref()
      .map(|(buf, n)| core::str::from_utf8(buf.get(..*n).unwrap_or(&[])).unwrap_or(""))
  }

  /// Iterates the response header list as `(name, value)` pairs.
  /// Allocation-free.
  pub fn iter(&self) -> ConnectAcceptHeadersIter<'_> {
    ConnectAcceptHeadersIter {
      view: self,
      state: AcceptState::Subprotocol,
    }
  }
}

/// Cursor over the optional subprotocol header then the optional extensions
/// header.
#[derive(Debug, Clone, Copy)]
enum AcceptState {
  Subprotocol,
  Extensions,
  Done,
}

/// Iterator over [`ConnectAcceptHeaders`]. See
/// [`ConnectAcceptHeaders::iter`].
#[derive(Debug, Clone)]
pub struct ConnectAcceptHeadersIter<'a> {
  view: &'a ConnectAcceptHeaders<'a>,
  state: AcceptState,
}

impl<'a> Iterator for ConnectAcceptHeadersIter<'a> {
  type Item = (&'static str, &'a str);

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      match self.state {
        AcceptState::Subprotocol => {
          self.state = AcceptState::Extensions;
          if let Some(proto) = self.view.subprotocol {
            return Some(("sec-websocket-protocol", proto));
          }
        }
        AcceptState::Extensions => {
          self.state = AcceptState::Done;
          #[cfg(feature = "deflate")]
          if let Some(value) = self.view.extensions() {
            return Some(("sec-websocket-extensions", value));
          }
        }
        AcceptState::Done => return None,
      }
    }
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

  fn find<'a, I>(headers: I, name: &str) -> Option<&'a str>
  where
    I: IntoIterator<Item = (&'static str, &'a str)>,
  {
    headers
      .into_iter()
      .find(|(n, _)| *n == name)
      .map(|(_, v)| v)
  }

  #[test]
  fn request_headers_cover_rfc8441_4() {
    let req = ConnectRequest::new(Scheme::Https, "server.example.com", "/chat")
      .with_subprotocols(&["chat", "superchat"]);
    let headers = req.headers().unwrap();

    assert_eq!(find(headers.iter(), ":method"), Some("CONNECT"));
    assert_eq!(find(headers.iter(), ":protocol"), Some("websocket"));
    assert_eq!(find(headers.iter(), ":scheme"), Some("https"));
    assert_eq!(
      find(headers.iter(), ":authority"),
      Some("server.example.com")
    );
    assert_eq!(find(headers.iter(), ":path"), Some("/chat"));
    assert_eq!(find(headers.iter(), "sec-websocket-version"), Some("13"));

    // Subprotocols arrive as one repeated header per offer (RFC 9110
    // §5.3-equivalent to the comma join).
    let protos: Vec<&str> = headers
      .iter()
      .filter(|(n, _)| *n == "sec-websocket-protocol")
      .map(|(_, v)| v)
      .collect();
    assert_eq!(protos, ["chat", "superchat"]);

    // No Key/Accept over h2/h3 (RFC 8441 §5).
    assert_eq!(find(headers.iter(), "sec-websocket-key"), None);
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

    // STRICT gate: missing or wrong :method fails before anything else.
    for bad in [
      &[("sec-websocket-version", "13")] as &[(&str, &str)],
      &[
        (":method", "GET"),
        (":protocol", "websocket"),
        ("sec-websocket-version", "13"),
      ],
      &[
        (":method", "connect"),
        (":protocol", "websocket"),
        ("sec-websocket-version", "13"),
      ],
      &[
        (":method", "CONNECT"),
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        ("sec-websocket-version", "13"),
      ],
    ] {
      assert!(
        matches!(
          validate_connect_request(bad).unwrap_err(),
          ConnectRequestError::NotConnect
        ),
        "{bad:?}"
      );
    }

    // STRICT gate: :protocol must be exactly one `websocket`.
    for bad in [
      &[(":method", "CONNECT"), ("sec-websocket-version", "13")] as &[(&str, &str)],
      &[
        (":method", "CONNECT"),
        (":protocol", "webtransport"),
        ("sec-websocket-version", "13"),
      ],
      &[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":protocol", "websocket"),
        ("sec-websocket-version", "13"),
      ],
    ] {
      assert!(
        matches!(
          validate_connect_request(bad).unwrap_err(),
          ConnectRequestError::NotWebSocket
        ),
        "{bad:?}"
      );
    }

    // Version must be 13 (and is required) — checked after the gate.
    let bad: &[(&str, &str)] = &[
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      ("sec-websocket-version", "12"),
    ];
    assert!(matches!(
      validate_connect_request(bad).unwrap_err(),
      ConnectRequestError::UnsupportedVersion
    ));
    let missing: &[(&str, &str)] = &[(":method", "CONNECT"), (":protocol", "websocket")];
    assert!(matches!(
      validate_connect_request(missing).unwrap_err(),
      ConnectRequestError::MissingVersion
    ));

    // The version header is a singleton: a repeat is ambiguous and fails the
    // gate — even when every occurrence says 13, and regardless of order.
    for dup in [
      &[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-version", "13"),
      ] as &[(&str, &str)],
      &[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-version", "12"),
      ],
      &[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        ("sec-websocket-version", "12"),
        ("sec-websocket-version", "13"),
      ],
    ] {
      assert!(
        matches!(
          validate_connect_request(dup).unwrap_err(),
          ConnectRequestError::DuplicateVersion
        ),
        "{dup:?}"
      );
    }
  }

  #[test]
  fn request_headers_round_trip_repeated_subprotocols() {
    // The repeated-header form the request iterator emits must round-trip
    // through the server validator, which flat-maps repeated headers and
    // comma lists back into individual offers.
    let req = ConnectRequest::new(Scheme::Https, "server.example.com", "/chat")
      .with_subprotocols(&["chat", "superchat", "v2.bot"]);
    let headers = req.headers().unwrap();
    let list: Vec<(&str, &str)> = headers.iter().collect();
    let view = validate_connect_request(&list).unwrap();
    let offers: Vec<&str> = view.subprotocols().collect();
    assert_eq!(offers, ["chat", "superchat", "v2.bot"]);
  }

  #[test]
  fn accept_and_client_validation_round_trip() {
    let accept = ConnectAccept::new().with_subprotocol(Some("chat"));
    let headers = accept.headers().unwrap();
    assert_eq!(find(headers.iter(), "sec-websocket-protocol"), Some("chat"));

    let req = ConnectRequest::new(Scheme::Https, "h", "/").with_subprotocols(&["chat"]);
    let response: Vec<(&str, &str)> = headers.iter().collect();
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
    let ext = find(headers.iter(), "sec-websocket-extensions").unwrap();
    assert!(ext.starts_with("permessage-deflate"));

    // Server side: validate, accept, respond.
    let reqh: Vec<(&str, &str)> = headers.iter().collect();
    let view = validate_connect_request(&reqh).unwrap();
    let (params, response) =
      accept_deflate_offer(view.extensions(), &ServerDeflateConfig::new()).unwrap();
    let accept = ConnectAccept::new().with_deflate(Some(response));
    let response_headers = accept.headers().unwrap();

    // Client side: validate the response.
    let resp: Vec<(&str, &str)> = response_headers.iter().collect();
    let negotiated = validate_connect_response(&resp, &req).unwrap();
    assert_eq!(negotiated.deflate(), Some(params));
  }
}
