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
  handshake::fields::{ConnectRequestFields, ConnectResponseFields},
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{Display, IsVariant, TryUnwrap};
use http_semantics::grammar::{
  eq_ignore_ascii, is_token, is_valid_authority, is_valid_path_and_query,
};

/// Both header views hold one inline buffer of this size for the rendered
/// `Sec-WebSocket-Extensions` value.
#[cfg(feature = "deflate")]
use crate::negotiation::MAX_EXTENSION_VALUE_BYTES;

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
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
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

  /// `:scheme` missing, repeated, or not `http`/`https` (RFC 8441 §4 makes
  /// the target pseudo-headers mandatory alongside `:protocol`).
  #[error(":scheme is not exactly one http or https")]
  NotHttpScheme,

  /// `:path` missing, repeated, or not an origin-form target.
  #[error(":path is not exactly one origin-form target")]
  InvalidPath,

  /// `:authority` missing, repeated, or empty.
  #[error(":authority is not exactly one non-empty value")]
  InvalidAuthority,

  /// A `sec-websocket-protocol` offer element was not an RFC 9110 token, or
  /// the list repeated an element (RFC 6455 §4.1 requires unique offers).
  #[error("malformed sec-websocket-protocol offer list")]
  MalformedSubprotocols,

  /// A `sec-websocket-extensions` value did not conform to RFC 6455 §9.1's
  /// ABNF. §9.1's MUST is about the negotiation, not about the transport that
  /// carries it, so this gate enforces it exactly as the h1 server does.
  #[error("malformed sec-websocket-extensions value")]
  MalformedExtensions,

  /// The request carried an h1-only upgrade field (`Connection`, `Upgrade`,
  /// `Sec-WebSocket-Key`, …) that RFC 8441 §5 / RFC 9113 §8.2.2 forbid on
  /// this transport.
  #[error("h1-only header forbidden on an extended CONNECT")]
  ForbiddenHeader,

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

  /// `origin` appeared more than once, which is ambiguous and is therefore
  /// refused rather than resolved — the h1 server's rule, on the transport RFC
  /// 8441 §5 carries the same field onto.
  ///
  /// §5: "The Origin \[RFC6454\], Sec-WebSocket-Version, Sec-WebSocket-Protocol,
  /// and Sec-WebSocket-Extensions header fields are used in the CONNECT request
  /// and response-header fields as defined in \[RFC6455\]." RFC 6454 §7 gives it
  /// one `origin-list-or-null` — SP-separated, not a comma list — so RFC 9110
  /// §5.3's "a sender MUST NOT generate multiple field lines with the same name
  /// … unless that field's definition allows … a comma-separated list" forbids
  /// repeating it.
  ///
  /// Refused rather than resolved for the reason the h1 gate gives: the FIRST
  /// of two contradicting values authorizes against a value the peer also
  /// denied, and `None` reads to `if let Some(origin) = view.origin()` as a
  /// client that sent no origin at all, which skips the policy entirely.
  #[error("origin must appear at most once")]
  DuplicateOrigin,

  /// Negotiation storage/grammar failure.
  #[error("{0}")]
  Negotiation(#[from] NegotiationError),
}

/// Errors validating an extended-CONNECT response (client side). These fail
/// the WebSocket connection.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
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

  /// The response carried an h1-only upgrade field (`Connection`,
  /// `Upgrade`, `Sec-WebSocket-Accept`, …) that RFC 8441 §5 /
  /// RFC 9113 §8.2.2 forbid on this transport.
  #[error("h1-only header forbidden on an extended CONNECT response")]
  ForbiddenHeader,

  /// A `sec-websocket-extensions` value did not conform to RFC 6455 §9.1's
  /// ABNF — the client half of the same MUST the request gate enforces.
  #[error("malformed sec-websocket-extensions value")]
  MalformedExtensions,

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
    // Same bar as the h1 client's Host: an `:authority` is an RFC 3986
    // authority, not a free string.
    if !is_valid_authority(self.authority) {
      return Err(ConnectRequestError::InvalidField("authority"));
    }
    // Shared RFC 3986 path-and-query grammar — also rejects a raw `#`
    // (RFC 6455 §3: a resource name carries no fragment; escape as %23).
    if !is_valid_path_and_query(self.path) {
      return Err(ConnectRequestError::InvalidField("path"));
    }
    // The same bound the gate reads back: without it this builder emits a list
    // `validate_connect_request` refuses, which is the emit/accept asymmetry
    // this crate screens for field by field.
    if self.subprotocols.len() > crate::negotiation::MAX_SUBPROTOCOL_OFFERS {
      return Err(ConnectRequestError::InvalidField(
        "more subprotocol offers than this crate reads from a peer",
      ));
    }
    // RFC 6455 §4.1 item 10: offered subprotocols MUST all be unique — and
    // must fit [`Negotiated`]'s inline storage, or a conforming peer
    // SELECTING the offer would fail our own retention (self-interop).
    for (i, proto) in self.subprotocols.iter().enumerate() {
      if !is_token(proto.as_bytes()) {
        return Err(ConnectRequestError::InvalidField("subprotocol"));
      }
      if proto.len() > crate::negotiation::MAX_SUBPROTOCOL_LEN {
        return Err(ConnectRequestError::InvalidField(
          "subprotocol exceeds the retainable length",
        ));
      }
      if self
        .subprotocols
        .get(..i)
        .is_some_and(|prev| prev.contains(proto))
      {
        return Err(ConnectRequestError::InvalidField("duplicate subprotocol"));
      }
    }

    #[cfg(feature = "deflate")]
    let extensions = match &self.deflate {
      None => None,
      Some(offer) => {
        offer.validate()?;
        let mut buf = [0u8; MAX_EXTENSION_VALUE_BYTES];
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
  extensions: Option<([u8; MAX_EXTENSION_VALUE_BYTES], usize)>,
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
  fields: ConnectRequestFields<'a>,
}

impl<'a> ConnectRequestView<'a> {
  /// The `:path` pseudo-header, when the stack passed it through.
  pub fn path(&self) -> Option<&'a str> {
    self.fields.path().single().ok().flatten()
  }

  /// The `:authority` pseudo-header, when present.
  pub fn authority(&self) -> Option<&'a str> {
    self.fields.authority().single().ok().flatten()
  }

  /// The `origin` header, when present — RFC 8441 §5 carries RFC 6455's
  /// `Origin` onto this transport unchanged, so this is the same field, with the
  /// same semantics, that the h1 server hands its own view.
  ///
  /// §5, verbatim: "The Origin \[RFC6454\], Sec-WebSocket-Version,
  /// Sec-WebSocket-Protocol, and Sec-WebSocket-Extensions header fields are used
  /// in the CONNECT request and response-header fields as defined in
  /// \[RFC6455\]." So RFC 6455 §4.2.2's origin policy — "The server MAY use this
  /// information as part of a determination of whether to accept the incoming
  /// connection" — is the application's here exactly as it is there.
  ///
  /// Unambiguous by construction: a request carrying more than one `origin`
  /// never reaches a view, because [`validate_connect_request`] refuses it as
  /// [`DuplicateOrigin`](ConnectRequestError::DuplicateOrigin). So `Some` is THE
  /// value the client sent and `None` is a client that sent none — never "the
  /// first of several" and never "too many to say". An `origin` with an empty
  /// value is `Some("")`: a field the peer sent, not one it omitted.
  pub fn origin(&self) -> Option<&'a str> {
    // The repeated arm is unreachable behind the gate; answered rather than
    // unwrapped, like the other post-gate impossibilities here.
    self.fields.origin().single().ok().flatten()
  }

  /// Any header by name (ASCII case-insensitive).
  ///
  /// # The FIRST occurrence only
  ///
  /// An escape hatch for fields this crate does not manage, and it cannot know
  /// their cardinality: it reports the first entry and says nothing about a
  /// second. **Do not make a security decision on it for a field whose value is
  /// not a list** — a peer that sent two `cookie`s or two `x-forwarded-for`s
  /// gets authorized against one value while another contradicts it, which is
  /// the header-confusion shape. A caller that must decide what more than one
  /// means counts the occurrences in the list it handed
  /// [`validate_connect_request`] — it still owns that slice.
  ///
  /// The fields RFC 6455 and RFC 8441 themselves define are NOT reached this
  /// way: they are resolved by the named accessors, which refuse the ambiguity
  /// rather than hiding it. `origin` is the one an application would otherwise
  /// have asked for here, and this hatch answers it through
  /// [`origin`](Self::origin) rather than as a first line.
  pub fn header(&self, name: &str) -> Option<&'a str> {
    self.fields.other(name)
  }

  /// Subprotocol offers across repeated headers and comma lists. Every element
  /// was token-validated, deduplicated, and held to RFC 6455 §11.3.4's
  /// `1#token` during [`validate_connect_request`], so there is at least one
  /// whenever the field was present.
  ///
  /// The same walk the gate ran — the `crate::negotiation` list reader that
  /// [`crate::negotiation::subprotocol_list_conforms`] is driven from — over
  /// the field's complete value, so what passed the gate is exactly what
  /// arrives here.
  pub fn subprotocols(&self) -> impl Iterator<Item = &'a str> + '_ {
    crate::negotiation::subprotocol_list(self.offer_bytes())
      // Unreachable: the value is a `str`, and the splitter cuts only on the
      // ASCII bytes `,`, SP and HTAB, which never occur inside a multi-byte
      // UTF-8 sequence — so every element is a substring on char boundaries.
      .filter_map(|offer| core::str::from_utf8(offer).ok())
  }

  /// The offer field's complete value as bytes, which is what the grammar layer
  /// reads (RFC 9110 §5.5 admits `obs-text`, so bytes are the honest shape even
  /// where the transport handed us `str`).
  fn offer_bytes(self) -> impl Iterator<Item = &'a [u8]> + Clone {
    self
      .fields
      .subprotocol_offers()
      .into_iter()
      .map(str::as_bytes)
  }

  /// Raw `sec-websocket-extensions` values for
  /// [`crate::negotiation::accept_deflate_offer`] — every occurrence, in
  /// arrival order, because RFC 6455 §9.1 lets the field be "split or combined
  /// across multiple lines".
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub fn extensions(&self) -> impl Iterator<Item = &'a str> + '_ {
    self.fields.extension_offers().into_iter()
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
  // The gate reads through the SAME accessors the returned view hands the
  // application, so nothing it validated can be re-derived differently later.
  let view = ConnectRequestView {
    fields: ConnectRequestFields::new(headers),
  };
  let fields = &view.fields;
  if fields.method().single() != Ok(Some("CONNECT")) {
    return Err(ConnectRequestError::NotConnect);
  }
  // Case-INSENSITIVE deliberately: `:protocol` carries an HTTP upgrade
  // token (RFC 8441 §4), and RFC 9110 §7.8 says "recipients SHOULD use
  // case-insensitive comparison when matching each protocol-name to
  // supported protocols" — exact matching would reject a conforming peer.
  // (Contrast subprotocols, which RFC 6455 grants no such case-insensitive
  // comparison anywhere, so they are matched exactly.)
  let protocol_ok = fields
    .protocol()
    .single()
    .is_ok_and(|p| p.is_some_and(|p| eq_ignore_ascii(p.as_bytes(), "websocket")));
  if !protocol_ok {
    return Err(ConnectRequestError::NotWebSocket);
  }
  // RFC 8441 §4: with `:protocol`, the target pseudo-headers are mandatory —
  // a CONNECT with no scheme/path/authority has nothing to bootstrap a
  // WebSocket onto, and a gate that passed it would push routing and origin
  // policy onto optional-`None` checks in application code.
  let scheme_ok = fields
    .scheme()
    .single()
    .is_ok_and(|s| s.is_some_and(|s| s == "http" || s == "https"));
  if !scheme_ok {
    return Err(ConnectRequestError::NotHttpScheme);
  }
  // Origin-form under the shared RFC 3986 path-and-query grammar (also
  // rejects a raw `#`: RFC 6455 §3 forbids fragments in resource names).
  let path_ok = fields
    .path()
    .single()
    .is_ok_and(|p| p.is_some_and(is_valid_path_and_query));
  if !path_ok {
    return Err(ConnectRequestError::InvalidPath);
  }
  let authority_ok = fields
    .authority()
    .single()
    .is_ok_and(|a| a.is_some_and(is_valid_authority));
  if !authority_ok {
    return Err(ConnectRequestError::InvalidAuthority);
  }
  // Singleton, like the pseudo-headers above: an ambiguous repeated version
  // (which another layer might combine or read differently) must not pass
  // the gate — h1's duplicate-singleton rejection, mirrored.
  match fields.websocket_version().single() {
    Err(_) => return Err(ConnectRequestError::DuplicateVersion),
    Ok(None) => return Err(ConnectRequestError::MissingVersion),
    Ok(Some(v)) if v != crate::constants::WEBSOCKET_VERSION => {
      return Err(ConnectRequestError::UnsupportedVersion);
    }
    Ok(Some(_)) => {}
  }
  // RFC 8441 §5 carries RFC 6455's optional `Origin` onto this transport with
  // RFC 6455's own semantics, RFC 6454 §7 defines it as ONE
  // `origin-list-or-null`, and RFC 9110 §5.3 therefore forbids repeating it.
  // The h1 server's rule, and refused for the h1 server's reason: this crate
  // hands the application a `ConnectRequestView` as the thing it authorizes
  // through, so an ambiguous answer here is one the CRATE produced. Reject-only,
  // so the caller still answers with a status of its choosing.
  if fields.origin().single().is_err() {
    return Err(ConnectRequestError::DuplicateOrigin);
  }
  if fields.has_forbidden_h1_field() {
    return Err(ConnectRequestError::ForbiddenHeader);
  }
  // Not a mirror of the h1 server's offer-list rule — the SAME rule, from the
  // grammar layer that knows RFC 6455 §11.3.4's `1#token`: non-token or
  // repeated elements fail, empty elements are ignored (RFC 2616 §2.1), and a
  // field that is present while naming nothing satisfies no `1#`.
  if !crate::negotiation::subprotocol_list_conforms(view.offer_bytes()) {
    return Err(ConnectRequestError::MalformedSubprotocols);
  }
  // RFC 6455 §9.1's MUST, in the h1 server gate's own place in the order: a
  // value that does not conform fails the connection, whatever this build
  // supports and whatever the server would have granted.
  if !crate::negotiation::extension_list_conforms(
    fields.extension_offers().into_iter().map(str::as_bytes),
  ) {
    return Err(ConnectRequestError::MalformedExtensions);
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

  /// Echo a subprotocol (must be one the client offered —
  /// [`headers_for`](Self::headers_for) enforces it against the validated
  /// request, exactly like the h1 server's `encode_response`).
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

  /// Validates the accept AGAINST THE REQUEST and returns the borrowed
  /// [`ConnectAcceptHeaders`] view plus the [`Negotiated`] result — the same
  /// contract as the h1 server's `encode_response`. A selected subprotocol
  /// must be one the (already-validated) request offered; an unbound accept
  /// surface could otherwise emit an RFC 6455 §4.2.2-invalid response and
  /// leave the application configured by convention instead of by the
  /// validated result. The view's [`iter`](ConnectAcceptHeaders::iter) emits
  /// an optional `("sec-websocket-protocol", _)` then an optional
  /// `("sec-websocket-extensions", _)`. No allocation: any deflate value is
  /// rendered once into the view.
  pub fn headers_for(
    &self,
    request: &ConnectRequestView<'_>,
  ) -> Result<(ConnectAcceptHeaders<'a>, Negotiated), ConnectAcceptError> {
    let negotiated = match self.subprotocol {
      None => Negotiated::none(),
      Some(chosen) => {
        // Offers were token-validated and deduplicated by the gate;
        // membership (EXACT — RFC 6455 grants no folding here) is the
        // remaining bind.
        if !request.subprotocols().any(|offer| offer == chosen) {
          return Err(ConnectAcceptError::SubprotocolNotOffered);
        }
        Negotiated::with_subprotocol(chosen)?
      }
    };
    // The deflate grant is request-bound exactly like the subprotocol: a
    // `DeflateResponse` minted for a different request (or none) must not
    // be emitted for one whose offers cannot legalize it.
    #[cfg(feature = "deflate")]
    if let Some(response) = &self.deflate
      && !crate::negotiation::response_matches_offer(
        request.extensions().map(str::as_bytes),
        response,
      )
    {
      return Err(ConnectAcceptError::ExtensionNotOffered);
    }
    #[cfg(feature = "deflate")]
    let negotiated = negotiated.with_deflate(self.deflate.map(|r| r.params()));

    #[cfg(feature = "deflate")]
    let extensions = match &self.deflate {
      None => None,
      Some(response) => {
        let mut buf = [0u8; MAX_EXTENSION_VALUE_BYTES];
        let n = response
          .write(&mut buf)
          .map_err(|_| ConnectAcceptError::ResponseTooLong)?;
        Some((buf, n))
      }
    };

    Ok((
      ConnectAcceptHeaders {
        subprotocol: self.subprotocol,
        #[cfg(feature = "deflate")]
        extensions,
      },
      negotiated,
    ))
  }
}

/// Errors binding a [`ConnectAccept`] to its request.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ConnectAcceptError {
  /// The accept named a subprotocol the request did not offer.
  #[error("accepted subprotocol was not offered")]
  SubprotocolNotOffered,

  /// The accept carried a deflate grant the request's offers cannot
  /// legalize.
  #[error("granted extension was not offered")]
  ExtensionNotOffered,

  /// The rendered deflate response exceeds the inline buffer.
  #[error("deflate response too long")]
  ResponseTooLong,

  /// Retaining the negotiation result failed.
  #[error("{0}")]
  Negotiation(#[from] NegotiationError),
}

/// A borrowed, allocation-free view of an extended-CONNECT response's header
/// list. Produced by [`ConnectAccept::headers_for`]; iterate with
/// [`iter`](Self::iter).
#[derive(Debug, Clone)]
pub struct ConnectAcceptHeaders<'a> {
  subprotocol: Option<&'a str>,
  #[cfg(feature = "deflate")]
  extensions: Option<([u8; MAX_EXTENSION_VALUE_BYTES], usize)>,
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
  // One accessor per field, exactly as on the h1 response path — the two
  // transports read the same values by the same rules.
  let fields = ConnectResponseFields::new(headers);

  // Symmetric with the request gate: h1-only and connection-specific
  // fields are just as forbidden on the response (RFC 8441 §5 /
  // RFC 9113 §8.2.2).
  if fields.has_forbidden_h1_field() {
    return Err(ConnectResponseError::ForbiddenHeader);
  }

  // RFC 6455 §9.1's MUST on the CLIENT side of the same negotiation, asked
  // before the value is interpreted (and whatever this build offered).
  let granted_bytes = || fields.granted_extensions().into_iter().map(str::as_bytes);
  if !crate::negotiation::extension_list_conforms(granted_bytes()) {
    return Err(ConnectResponseError::MalformedExtensions);
  }

  // §4.2.2 item 4 makes the response ONE selection, so a second field line is
  // a second answer rather than a continuation of the first.
  #[cfg_attr(not(feature = "deflate"), allow(unused_mut))]
  let mut negotiated = match fields.selected_subprotocol().single() {
    Err(_) => return Err(ConnectResponseError::DuplicateHeader),
    Ok(None) => Negotiated::none(),
    Ok(Some(chosen)) => {
      let offered = request.subprotocols.contains(&chosen);
      if !offered || !is_token(chosen.as_bytes()) {
        return Err(ConnectResponseError::SubprotocolNotOffered);
      }
      Negotiated::with_subprotocol(chosen)?
    }
  };

  #[cfg(feature = "deflate")]
  {
    match (
      request.deflate.as_ref(),
      fields.granted_extensions().present(),
    ) {
      (_, false) => {}
      (None, true) => return Err(ConnectResponseError::ExtensionNotOffered),
      // Every line, not the first: §9.1 lets the field be split across them,
      // and "exactly one granted extension" is `parse_deflate_response`'s rule
      // over the joined value — see the h1 client for the whole argument.
      (Some(offer), true) => {
        let params = crate::negotiation::parse_deflate_response(granted_bytes(), offer)?;
        negotiated = negotiated.with_deflate(Some(params));
      }
    }
  }
  #[cfg(not(feature = "deflate"))]
  if fields.granted_extensions().present() {
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

  /// A minimal conforming extended-CONNECT request with `field` spelled as
  /// `lines` — one header entry each, in the given order.
  fn request_with<'a>(field: &'a str, lines: &'a [&'a str]) -> Vec<(&'a str, &'a str)> {
    let mut headers: Vec<(&str, &str)> = vec![
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "server.example.com"),
      ("sec-websocket-version", "13"),
    ];
    headers.extend(lines.iter().map(|line| (field, *line)));
    headers
  }

  /// The whole outcome of gating such a request: the verdict, and every value
  /// the crate then derives from its fields.
  fn request_verdict(field: &str, lines: &[&str]) -> String {
    let headers = request_with(field, lines);
    match validate_connect_request(&headers) {
      Err(error) => format!("error: {error:?}"),
      Ok(view) => {
        let offers: Vec<&str> = view.subprotocols().collect();
        #[cfg(feature = "deflate")]
        let extensions = format!(
          "{:?}",
          crate::negotiation::accept_deflate_offer(
            view.extensions().map(str::as_bytes),
            &crate::negotiation::ServerDeflateConfig::new(),
          )
        );
        #[cfg(not(feature = "deflate"))]
        let extensions = String::from("(no deflate tier)");
        format!("ok: offers={offers:?} extensions={extensions}")
      }
    }
  }

  /// The same for the client half: a response whose `field` is spelled as
  /// `lines`, answered against a request that offered permessage-deflate.
  fn response_verdict(field: &str, lines: &[&str]) -> String {
    #[cfg(feature = "deflate")]
    let request = ConnectRequest::new(Scheme::Https, "h", "/chat")
      .with_deflate(crate::negotiation::DeflateOffer::new());
    #[cfg(not(feature = "deflate"))]
    let request = ConnectRequest::new(Scheme::Https, "h", "/chat");
    let headers: Vec<(&str, &str)> = lines.iter().map(|line| (field, *line)).collect();
    match validate_connect_response(&headers, &request) {
      Err(error) => format!("error: {error:?}"),
      Ok(negotiated) => {
        #[cfg(feature = "deflate")]
        let deflate = format!("{:?}", negotiated.deflate());
        #[cfg(not(feature = "deflate"))]
        let deflate = String::from("(no deflate tier)");
        format!(
          "ok: subprotocol={:?} deflate={deflate}",
          negotiated.subprotocol()
        )
      }
    }
  }

  /// One logical value however it is spelled, on the extended-CONNECT
  /// transports, both roles. Identical property and identical fixtures to the h1
  /// tests: the two transports read the same fields by the same rules, so a
  /// spelling that is one value on h1 is one value here.
  #[test]
  fn equivalent_spellings_of_a_connect_field_reach_one_verdict() {
    use crate::handshake::spellings;

    // ── request role ────────────────────────────────────────────────────
    let one = spellings::agree("one offer", &spellings::one("chat"), |lines| {
      request_verdict("sec-websocket-protocol", lines)
    });
    assert!(one.contains(r#"offers=["chat"]"#), "{one}");
    let two = spellings::agree(
      "two offers",
      &spellings::two("chat", "superchat"),
      |lines| request_verdict("sec-websocket-protocol", lines),
    );
    assert!(two.contains(r#"offers=["chat", "superchat"]"#), "{two}");
    let nothing = spellings::agree("no offer named", &spellings::nothing(), |lines| {
      request_verdict("sec-websocket-protocol", lines)
    });
    assert_eq!(nothing, "error: MalformedSubprotocols");
    let absent = request_verdict("sec-websocket-protocol", &[]);
    assert!(absent.contains("offers=[]"), "{absent}");
    assert_ne!(absent, nothing);

    let one = spellings::agree(
      "one extension",
      &spellings::one("permessage-deflate"),
      |lines| request_verdict("sec-websocket-extensions", lines),
    );
    assert!(one.starts_with("ok:"), "{one}");
    let nothing = spellings::agree("no extension named", &spellings::nothing(), |lines| {
      request_verdict("sec-websocket-extensions", lines)
    });
    assert_eq!(nothing, "error: MalformedExtensions");

    // ── response role ───────────────────────────────────────────────────
    let one = spellings::agree(
      "one grant",
      &spellings::one("permessage-deflate"),
      |lines| response_verdict("sec-websocket-extensions", lines),
    );
    #[cfg(feature = "deflate")]
    assert!(
      one.starts_with("ok: subprotocol=None deflate=Some"),
      "{one}"
    );
    #[cfg(not(feature = "deflate"))]
    assert_eq!(one, "error: ExtensionNotOffered");

    let two = spellings::agree(
      "two grants",
      &spellings::two("permessage-deflate", "x-private"),
      |lines| response_verdict("sec-websocket-extensions", lines),
    );
    #[cfg(feature = "deflate")]
    assert_eq!(two, "error: Negotiation(ExtensionMismatch)");
    #[cfg(not(feature = "deflate"))]
    assert_eq!(two, "error: ExtensionNotOffered");

    let nothing = spellings::agree("no grant named", &spellings::nothing(), |lines| {
      response_verdict("sec-websocket-extensions", lines)
    });
    assert_eq!(nothing, "error: MalformedExtensions");
    let absent = response_verdict("sec-websocket-extensions", &[]);
    assert!(absent.starts_with("ok: subprotocol=None"), "{absent}");
    assert_ne!(absent, nothing);
  }

  /// The h1 and extended-CONNECT gates answer the SAME question the same way:
  /// the two paths are one rule with two transports under it, not two rules
  /// that happen to agree today.
  #[test]
  fn the_two_transports_agree_on_the_offer_list_rule() {
    use crate::handshake::{
      h1::{ServerHandshake, ServerProgress},
      spellings,
    };

    /// The h1 spelling of the same request, offers included.
    fn h1_offers(lines: &[&str]) -> Result<Vec<String>, ()> {
      let mut raw = String::from(
        "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n",
      );
      for line in lines {
        raw.push_str(&format!("Sec-WebSocket-Protocol: {line}\r\n"));
      }
      raw.push_str("\r\n");
      let mut hs = ServerHandshake::new();
      match hs.handle(raw.as_bytes()) {
        Ok(ServerProgress::Upgrade(pending)) => Ok(
          pending
            .request()
            .subprotocols()
            .map(String::from)
            .collect::<Vec<_>>(),
        ),
        _ => Err(()),
      }
    }

    fn connect_offers(lines: &[&str]) -> Result<Vec<String>, ()> {
      let headers = request_with("sec-websocket-protocol", lines);
      match validate_connect_request(&headers) {
        Ok(view) => Ok(view.subprotocols().map(String::from).collect::<Vec<_>>()),
        Err(_) => Err(()),
      }
    }

    let groups = [
      spellings::one("chat"),
      spellings::two("chat", "superchat"),
      spellings::nothing(),
      vec![vec![]],
      // Non-token and repeated elements: the other two rules of the same gate.
      vec![vec![String::from("has space")], vec![String::from("a, a")]],
    ];
    for group in groups.iter().flatten() {
      let borrowed: Vec<&str> = group.iter().map(String::as_str).collect();
      assert_eq!(
        h1_offers(&borrowed),
        connect_offers(&borrowed),
        "the two transports disagree about {group:?}"
      );
    }
  }

  /// A repeated `origin` is REFUSED on this transport too, and for the same
  /// reason as on h1.
  ///
  /// The argument that used to leave it alone — "RFC 8441 does not carry
  /// `Origin` into the extended-CONNECT handshake" — is contradicted by §5's own
  /// words: "The Origin \[RFC6454\], Sec-WebSocket-Version, Sec-WebSocket-Protocol,
  /// and Sec-WebSocket-Extensions header fields are used in the CONNECT request
  /// and response-header fields as defined in \[RFC6455\]." RFC 6454 §7 makes it
  /// one `origin-list-or-null` and RFC 9110 §5.3 forbids repeating it.
  ///
  /// The second half of that argument — that an h2/h3 caller owns the slice and
  /// can count occurrences itself — does not survive either: the thing the
  /// application authorizes through is the [`ConnectRequestView`] this crate
  /// hands it, so an ambiguous answer is the CRATE's to have produced.
  #[test]
  fn a_repeated_origin_is_refused_on_extended_connect() {
    let with_origins = |lines: &[&'static str]| -> Vec<(&'static str, &'static str)> {
      let mut headers: Vec<(&str, &str)> = vec![
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":path", "/chat"),
        (":authority", "server.example.com"),
        ("sec-websocket-version", "13"),
      ];
      headers.extend(lines.iter().map(|line| ("origin", *line)));
      headers
    };

    let two = with_origins(&["https://example.com", "https://evil.example"]);
    assert!(matches!(
      validate_connect_request(&two).unwrap_err(),
      ConnectRequestError::DuplicateOrigin
    ));
    // Case does not launder it: RFC 9110 §5.1 matches field names ASCII
    // case-insensitively, and RFC 8441 §5's note about lowercase encoding is
    // about what a sender writes, not about what a reader may miss.
    let mixed: Vec<(&str, &str)> = with_origins(&["https://example.com"])
      .into_iter()
      .chain([("Origin", "https://evil.example")])
      .collect();
    assert!(matches!(
      validate_connect_request(&mixed).unwrap_err(),
      ConnectRequestError::DuplicateOrigin
    ));

    // Behind the gate the view's answer is unambiguous by construction, and the
    // escape hatch answers THROUGH it rather than reporting a first entry.
    let one = with_origins(&["https://example.com"]);
    let view = validate_connect_request(&one).unwrap();
    assert_eq!(view.origin(), Some("https://example.com"));
    assert_eq!(view.header("origin"), view.origin());
    assert_eq!(view.header("ORIGIN"), view.origin());

    let empty = with_origins(&[""]);
    let view = validate_connect_request(&empty).unwrap();
    assert_eq!(
      view.origin(),
      Some(""),
      "`origin:` with no value is a field the peer sent, not one it omitted"
    );
    assert_eq!(view.header("origin"), Some(""));

    let none = with_origins(&[]);
    let view = validate_connect_request(&none).unwrap();
    assert_eq!(view.origin(), None);
    assert_eq!(view.header("origin"), None);
  }

  /// The two transports answer the ORIGIN question the same way, over the same
  /// fixtures: one rule with two transports under it.
  #[test]
  fn the_two_transports_agree_on_the_origin_rule() {
    use crate::handshake::h1::{ServerHandshake, ServerProgress};

    /// `Ok(the origin, as the view answers it)` or `Err(())` when the gate
    /// refused the request.
    fn h1_origin(lines: &[&str]) -> Result<Option<String>, ()> {
      let mut raw = String::from(
        "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n",
      );
      for line in lines {
        raw.push_str(&format!("Origin: {line}\r\n"));
      }
      raw.push_str("\r\n");
      let mut hs = ServerHandshake::new();
      match hs.handle(raw.as_bytes()) {
        Ok(ServerProgress::Upgrade(pending)) => Ok(
          pending
            .request()
            .origin()
            .map(|o| String::from_utf8_lossy(o).into_owned()),
        ),
        _ => Err(()),
      }
    }

    fn connect_origin(lines: &[&str]) -> Result<Option<String>, ()> {
      let mut headers: Vec<(&str, &str)> = vec![
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":path", "/chat"),
        (":authority", "server.example.com"),
        ("sec-websocket-version", "13"),
      ];
      headers.extend(lines.iter().map(|line| ("origin", *line)));
      match validate_connect_request(&headers) {
        Ok(view) => Ok(view.origin().map(String::from)),
        Err(_) => Err(()),
      }
    }

    for spelling in [
      &[] as &[&str],
      &[""],
      &["https://example.com"],
      &["null"],
      &["https://example.com", "https://evil.example"],
      &["https://example.com", "https://example.com"],
    ] {
      assert_eq!(
        h1_origin(spelling),
        connect_origin(spelling),
        "the two transports disagree about {spelling:?}"
      );
    }
  }

  /// The offer-count bound is the SAME number on the way out as on the way in:
  /// a list this builder writes is one this crate's own gate reads back.
  #[test]
  fn the_offer_count_bound_is_the_same_in_both_directions() {
    use crate::negotiation::MAX_SUBPROTOCOL_OFFERS;

    let names: Vec<String> = (0..=MAX_SUBPROTOCOL_OFFERS)
      .map(|i| format!("p{i}"))
      .collect();
    let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();

    let at_cap = borrowed.get(..MAX_SUBPROTOCOL_OFFERS).unwrap();
    let request = ConnectRequest::new(Scheme::Https, "h", "/chat").with_subprotocols(at_cap);
    let headers = request.headers().expect("the cap itself is writable");
    // Emitted AND read back: the builder writes the pseudo-headers itself, so
    // its own list is the whole request.
    let pairs: Vec<(&str, &str)> = headers.iter().collect();
    let view = validate_connect_request(&pairs).expect("what we emit, we read");
    assert_eq!(view.subprotocols().count(), MAX_SUBPROTOCOL_OFFERS);

    // One past it is refused at the BUILDER, not left for the peer to fail on.
    assert!(matches!(
      ConnectRequest::new(Scheme::Https, "h", "/chat")
        .with_subprotocols(&borrowed)
        .headers()
        .unwrap_err(),
      ConnectRequestError::InvalidField(_)
    ));
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
    // RFC 6455 §4.1 item 10: offers MUST be unique (case-sensitively).
    assert!(
      ConnectRequest::new(Scheme::Https, "h", "/")
        .with_subprotocols(&["chat", "chat"])
        .headers()
        .is_err()
    );
    assert!(
      ConnectRequest::new(Scheme::Https, "h", "/")
        .with_subprotocols(&["chat", "CHAT"])
        .headers()
        .is_ok()
    );

    // Regression: an offer past `Negotiated`'s inline storage would make a
    // conforming peer's SELECTION fail our own retention — reject it at the
    // emitter. 64 fits; 65 does not.
    let at_cap = "a".repeat(crate::negotiation::MAX_SUBPROTOCOL_LEN);
    let over_cap = "a".repeat(crate::negotiation::MAX_SUBPROTOCOL_LEN + 1);
    let offers_ok: &[&str] = &[at_cap.as_str()];
    let offers_over: &[&str] = &[over_cap.as_str()];
    assert!(
      ConnectRequest::new(Scheme::Https, "h", "/")
        .with_subprotocols(offers_ok)
        .headers()
        .is_ok()
    );
    assert!(
      ConnectRequest::new(Scheme::Https, "h", "/")
        .with_subprotocols(offers_over)
        .headers()
        .is_err()
    );
  }

  /// Regression: `Host:`/`:authority` values are RFC 3986
  /// authorities — URI delimiters, whitespace, controls, and malformed
  /// IP-literals/ports fail BOTH the builders and the gates; valid
  /// reg-names, ports, and bracketed IPv6 forms pass.
  #[test]
  fn authorities_are_grammar_checked() {
    let base = |authority: &'static str| -> Vec<(&'static str, &'static str)> {
      vec![
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":path", "/chat"),
        (":authority", authority),
        ("sec-websocket-version", "13"),
      ]
    };
    for bad in [
      "example.com/chat",
      "example.com?x",
      "example.com#frag",
      "user@example.com",
      "ex am.com",
      "ex\tam.com",
      "ex\x07am.com",
      "ex\x7Fam.com",
      "a:b:c",
      "example.com:8x",
      "[::1",
      "[::1]x",
      "[]",
      "",
      // Regression: a bracket is an IP-LITERAL, not a byte soup —
      // dotted-quads and over-compressed colons are not addresses.
      "[127.0.0.1]",
      "[::::]",
      "[1:2:3:4:5:6:7:8:9]",
      "[12345::]",
      "[1:2:3:4:5:6:7:8::]",
    ] {
      // Inbound gate.
      let headers = base(bad);
      assert!(
        matches!(
          validate_connect_request(&headers).unwrap_err(),
          ConnectRequestError::InvalidAuthority
        ),
        "gate accepted {bad:?}"
      );
      // Outbound builder.
      assert!(
        ConnectRequest::new(Scheme::Https, bad, "/")
          .headers()
          .is_err(),
        "builder accepted {bad:?}"
      );
    }
    for good in [
      "example.com",
      "example.com:8080",
      "example.com:",
      "10.0.0.1:443",
      "[::1]:8080",
      "[2001:db8::1]",
      "%41.com",
      // Regression: real RFC 3986 IP-literals all pass —
      // full-length IPv6, IPv4-mapped tails, and IPvFuture.
      "[1:2:3:4:5:6:7:8]",
      "[::ffff:127.0.0.1]",
      "[1:2:3:4:5:6:7.7.7.7]",
      "[v1.a]",
      "[1:2:3:4:5:6:7::]",
    ] {
      let headers = base(good);
      assert!(validate_connect_request(&headers).is_ok(), "{good:?}");
      assert!(
        ConnectRequest::new(Scheme::Https, good, "/")
          .headers()
          .is_ok(),
        "{good:?}"
      );
    }
  }

  /// Regression: `HTTP2-Settings` is an h1-upgrade artifact and
  /// `TE` may only appear in REQUESTS as exactly `trailers`
  /// (RFC 9113 §8.2.2) — anything else fails either gate.
  #[test]
  fn te_and_http2_settings_are_screened() {
    let base: &[(&str, &str)] = &[
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "h"),
      ("sec-websocket-version", "13"),
    ];
    let with = |name: &'static str, value: &'static str| -> Vec<(&'static str, &'static str)> {
      base.iter().copied().chain([(name, value)]).collect()
    };

    // Request side: TE is legal ONLY as exactly `trailers`.
    let ok = with("te", "trailers");
    assert!(validate_connect_request(&ok).is_ok());
    let ok = with("TE", " Trailers\t");
    assert!(validate_connect_request(&ok).is_ok());
    for (name, value) in [
      ("te", "gzip"),
      ("te", "trailers, deflate"),
      ("http2-settings", "AAMAAABkAAQAoAAAAAIAAAAA"),
    ] {
      let headers = with(name, value);
      assert!(
        matches!(
          validate_connect_request(&headers).unwrap_err(),
          ConnectRequestError::ForbiddenHeader
        ),
        "{name}: {value}"
      );
    }

    // Response side: TE never belongs, even as `trailers`.
    let req = ConnectRequest::new(Scheme::Https, "h", "/");
    for (name, value) in [
      ("te", "trailers"),
      ("http2-settings", "AAMAAABkAAQAoAAAAAIAAAAA"),
    ] {
      let response: &[(&str, &str)] = &[(name, value)];
      assert!(
        matches!(
          validate_connect_response(response, &req).unwrap_err(),
          ConnectResponseError::ForbiddenHeader
        ),
        "{name}"
      );
    }
  }

  /// Regression: the response check is symmetric with the
  /// request gate — h1-only fields fail `validate_connect_response` too.
  #[test]
  fn connect_response_rejects_h1_only_headers() {
    let req = ConnectRequest::new(Scheme::Https, "h", "/");
    for (name, value) in [
      ("connection", "Upgrade"),
      ("Upgrade", "websocket"),
      ("keep-alive", "timeout=5"),
      ("proxy-connection", "keep-alive"),
      ("transfer-encoding", "chunked"),
      ("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA=="),
      ("sec-websocket-accept", "x"),
    ] {
      let response: &[(&str, &str)] = &[(name, value)];
      assert!(
        matches!(
          validate_connect_response(response, &req).unwrap_err(),
          ConnectResponseError::ForbiddenHeader
        ),
        "{name}"
      );
    }
    // A clean (empty) response still validates.
    assert!(validate_connect_response(&[], &req).is_ok());
  }

  /// Regression: RFC 8441 §5 / RFC 9113 §8.2.2 — h1 upgrade
  /// machinery and connection-specific fields are forbidden on this
  /// transport; the strict gate rejects them itself.
  #[test]
  fn connect_gate_rejects_h1_only_headers() {
    let base: &[(&str, &str)] = &[
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "h"),
      ("sec-websocket-version", "13"),
    ];
    for (name, value) in [
      ("connection", "Upgrade"),
      ("Upgrade", "websocket"),
      ("keep-alive", "timeout=5"),
      ("proxy-connection", "keep-alive"),
      ("transfer-encoding", "chunked"),
      ("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA=="),
      ("sec-websocket-accept", "x"),
    ] {
      let headers: Vec<(&str, &str)> = base.iter().copied().chain([(name, value)]).collect();
      assert!(
        matches!(
          validate_connect_request(&headers).unwrap_err(),
          ConnectRequestError::ForbiddenHeader
        ),
        "{name}"
      );
    }
    // The clean request still passes.
    assert!(validate_connect_request(base).is_ok());
  }

  /// The `h2`/`h3` convenience modules are pure aliases: items reached
  /// through them ARE the `connect` items (same types, not copies).
  #[test]
  fn h2_and_h3_reexport_the_connect_surfaces() {
    let via_h2: crate::handshake::h2::Scheme = Scheme::Https;
    let via_h3: crate::handshake::h3::Scheme = via_h2;
    assert_eq!(via_h3, Scheme::Https);
    // And the gate called through the alias is the same function: its view
    // interchanges with `connect`'s error type.
    let err: ConnectRequestError = crate::handshake::h3::validate_connect_request(&[]).unwrap_err();
    assert!(matches!(err, ConnectRequestError::NotConnect));
  }

  /// Regression: the CONNECT gate validates offer lists like the
  /// h1 server — non-token or repeated elements fail; empty elements are
  /// ignored per RFC 9110 §5.6.1.2.
  #[test]
  fn connect_gate_validates_subprotocol_offers() {
    let base: &[(&str, &str)] = &[
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "h"),
      ("sec-websocket-version", "13"),
    ];
    let with_offers = |value: &'static str| -> Vec<(&'static str, &'static str)> {
      base
        .iter()
        .copied()
        .chain([("sec-websocket-protocol", value)])
        .collect()
    };

    for bad in ["bad token, admin", "chat, chat"] {
      let headers = with_offers(bad);
      assert!(
        matches!(
          validate_connect_request(&headers).unwrap_err(),
          ConnectRequestError::MalformedSubprotocols
        ),
        "{bad}"
      );
    }

    // Empty elements ignored; the rest negotiable.
    let headers = with_offers(", admin");
    let view = validate_connect_request(&headers).unwrap();
    let offers: Vec<&str> = view.subprotocols().collect();
    assert_eq!(offers, ["admin"]);

    // Duplicate across repeated headers is still a repeat.
    let headers: Vec<(&str, &str)> = base
      .iter()
      .copied()
      .chain([
        ("sec-websocket-protocol", "chat"),
        ("sec-websocket-protocol", "chat"),
      ])
      .collect();
    assert!(matches!(
      validate_connect_request(&headers).unwrap_err(),
      ConnectRequestError::MalformedSubprotocols
    ));
  }

  /// RFC 6455 §9.1's MUST is a rule about the NEGOTIATION, not about the
  /// transport that carries it: "If a value is received by either the client or
  /// the server during negotiation that does not conform to the ABNF below, the
  /// recipient of such malformed data MUST immediately _Fail the WebSocket
  /// Connection_." Both extended-CONNECT gates enforce it, on every tier, so
  /// the h2/h3 path cannot admit bytes the h1 path refuses.
  #[test]
  fn connect_gates_enforce_the_extension_grammar() {
    let base: &[(&str, &str)] = &[
      (":method", "CONNECT"),
      (":protocol", "websocket"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "h"),
      ("sec-websocket-version", "13"),
    ];
    let with_extensions = |value: &'static str| -> Vec<(&'static str, &'static str)> {
      base
        .iter()
        .copied()
        .chain([("sec-websocket-extensions", value)])
        .collect()
    };
    let req = ConnectRequest::new(Scheme::Https, "h", "/");

    for bad in [
      "permessage-deflate; x=\"open",
      "x@y",
      "permessage-deflate; x=\"a b\"",
      "",
      // `extension = extension-token *( ";" extension-param )` — a semicolon
      // with no parameter behind it, which RFC 9110 §5.6.6's `[ parameter ]`
      // would have allowed.
      "permessage-deflate;",
      "permessage-deflate;;client_max_window_bits",
    ] {
      let headers = with_extensions(bad);
      assert!(
        matches!(
          validate_connect_request(&headers).unwrap_err(),
          ConnectRequestError::MalformedExtensions
        ),
        "request gate accepted {bad:?}"
      );
      let response: &[(&str, &str)] = &[("sec-websocket-extensions", bad)];
      assert!(
        matches!(
          validate_connect_response(response, &req).unwrap_err(),
          ConnectResponseError::MalformedExtensions
        ),
        "response gate accepted {bad:?}"
      );
    }

    // The response gate carries the rule on its own, not merely by standing in
    // front of §4.1 step 5: with an offer present `permessage-deflate;` would
    // otherwise reach `parse_deflate_response`, and the gate is what names the
    // fault as a grammar fault rather than a mismatch.
    #[cfg(feature = "deflate")]
    {
      let offered = ConnectRequest::new(Scheme::Https, "h", "/")
        .with_deflate(crate::negotiation::DeflateOffer::new());
      let response: &[(&str, &str)] = &[("sec-websocket-extensions", "permessage-deflate;")];
      assert!(matches!(
        validate_connect_response(response, &offered).unwrap_err(),
        ConnectResponseError::MalformedExtensions
      ));
    }

    // RFC 6455 §9.1 states its ABNF "including the 'implied *LWS rule'", so a
    // conforming server may put whitespace around the `;` and the `=`. RFC 7692
    // §8.1 makes an extension response the client will not accept FAIL the
    // connection, so reading the field here with a grammar stricter than the
    // gate's would refuse a handshake §9.1 admits. Both sides of the CONNECT
    // negotiation read §9.1's one grammar, so the value is GRANTED.
    #[cfg(feature = "deflate")]
    {
      let offered = ConnectRequest::new(Scheme::Https, "h", "/").with_deflate(
        crate::negotiation::DeflateOffer::new()
          .with_server_max_window_bits(Some(12))
          .with_client_max_window_bits(Some(11)),
      );
      let lws = "permessage-deflate ;  server_max_window_bits = 12 ; \
                 client_max_window_bits = \"11\"";
      assert!(validate_connect_request(&with_extensions(lws)).is_ok());
      let response: &[(&str, &str)] = &[("sec-websocket-extensions", lws)];
      let negotiated = validate_connect_response(response, &offered).unwrap();
      let params = negotiated.deflate().unwrap();
      assert_eq!(params.server_max_window_bits(), 12);
      assert_eq!(params.client_max_window_bits(), 11);
    }

    // Well formed but unsupported is not a grammar fault: the request gate
    // passes it (the server then simply declines), and the response gate
    // reaches §4.1 step 5's "granted an extension we never offered".
    let headers = with_extensions("x-private; a; b=c");
    assert!(validate_connect_request(&headers).is_ok());
    let response: &[(&str, &str)] = &[("sec-websocket-extensions", "x-private; a; b=c")];
    assert!(matches!(
      validate_connect_response(response, &req).unwrap_err(),
      ConnectResponseError::ExtensionNotOffered
    ));
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

    // Pinned contract: `:protocol` matching is case-INSENSITIVE — it carries
    // an HTTP upgrade token, and RFC 9110 §7.8 says recipients SHOULD use
    // case-insensitive comparison when matching protocol-names. A conforming
    // peer sending `WebSocket` must not be rejected.
    let mixed: &[(&str, &str)] = &[
      (":method", "CONNECT"),
      (":protocol", "WebSocket"),
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "h"),
      ("sec-websocket-version", "13"),
    ];
    assert!(validate_connect_request(mixed).is_ok());

    // RFC 8441 §4: the target pseudo-headers are mandatory with :protocol —
    // missing, repeated, or invalid scheme/path/authority fail the gate.
    const GATED: [(&str, &str); 2] = [(":method", "CONNECT"), (":protocol", "websocket")];
    let with_gate = |rest: &[(&'static str, &'static str)]| -> Vec<(&'static str, &'static str)> {
      GATED.iter().chain(rest).copied().collect()
    };
    for (rest, expect) in [
      // :scheme missing / duplicated / not http(s).
      (
        &[
          (":path", "/c"),
          (":authority", "h"),
          ("sec-websocket-version", "13"),
        ] as &[_],
        "scheme",
      ),
      (
        &[
          (":scheme", "https"),
          (":scheme", "https"),
          (":path", "/c"),
          (":authority", "h"),
          ("sec-websocket-version", "13"),
        ],
        "scheme",
      ),
      (
        &[
          (":scheme", "ftp"),
          (":path", "/c"),
          (":authority", "h"),
          ("sec-websocket-version", "13"),
        ],
        "scheme",
      ),
      // :path missing / non-origin-form.
      (
        &[
          (":scheme", "https"),
          (":authority", "h"),
          ("sec-websocket-version", "13"),
        ],
        "path",
      ),
      (
        &[
          (":scheme", "https"),
          (":path", "nope"),
          (":authority", "h"),
          ("sec-websocket-version", "13"),
        ],
        "path",
      ),
      // Regression: a leading `/` is not enough — `/bad path`
      // is not a request-target (origin-form admits no SP).
      (
        &[
          (":scheme", "https"),
          (":path", "/bad path"),
          (":authority", "h"),
          ("sec-websocket-version", "13"),
        ],
        "path",
      ),
      // :authority missing / empty.
      (
        &[
          (":scheme", "https"),
          (":path", "/c"),
          ("sec-websocket-version", "13"),
        ],
        "authority",
      ),
      (
        &[
          (":scheme", "https"),
          (":path", "/c"),
          (":authority", ""),
          ("sec-websocket-version", "13"),
        ],
        "authority",
      ),
    ] {
      let headers = with_gate(rest);
      let err = validate_connect_request(&headers).unwrap_err();
      let matched = match expect {
        "scheme" => matches!(err, ConnectRequestError::NotHttpScheme),
        "path" => matches!(err, ConnectRequestError::InvalidPath),
        _ => matches!(err, ConnectRequestError::InvalidAuthority),
      };
      assert!(matched, "{rest:?} → {err:?}");
    }

    // Version must be 13 (and is required) — checked after the target gate.
    const TARGET: [(&str, &str); 3] = [
      (":scheme", "https"),
      (":path", "/chat"),
      (":authority", "h"),
    ];
    let with_target = |rest: &[(&'static str, &'static str)]| -> Vec<(&'static str, &'static str)> {
      GATED
        .iter()
        .chain(TARGET.iter())
        .chain(rest)
        .copied()
        .collect()
    };
    let bad = with_target(&[("sec-websocket-version", "12")]);
    assert!(matches!(
      validate_connect_request(&bad).unwrap_err(),
      ConnectRequestError::UnsupportedVersion
    ));
    let missing = with_target(&[]);
    assert!(matches!(
      validate_connect_request(&missing).unwrap_err(),
      ConnectRequestError::MissingVersion
    ));

    // The version header is a singleton: a repeat is ambiguous and fails the
    // gate — even when every occurrence says 13, and regardless of order.
    for rest in [
      &[
        ("sec-websocket-version", "13"),
        ("sec-websocket-version", "13"),
      ] as &[_],
      &[
        ("sec-websocket-version", "13"),
        ("sec-websocket-version", "12"),
      ],
      &[
        ("sec-websocket-version", "12"),
        ("sec-websocket-version", "13"),
      ],
    ] {
      let dup = with_target(rest);
      assert!(
        matches!(
          validate_connect_request(&dup).unwrap_err(),
          ConnectRequestError::DuplicateVersion
        ),
        "{rest:?}"
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
    let req = ConnectRequest::new(Scheme::Https, "h", "/").with_subprotocols(&["chat"]);
    let request_headers = req.headers().unwrap();
    let request_pairs: Vec<(&str, &str)> = request_headers.iter().collect();
    let view = validate_connect_request(&request_pairs).unwrap();

    let accept = ConnectAccept::new().with_subprotocol(Some("chat"));
    let (headers, server_negotiated) = accept.headers_for(&view).unwrap();
    assert_eq!(find(headers.iter(), "sec-websocket-protocol"), Some("chat"));
    assert_eq!(server_negotiated.subprotocol(), Some("chat"));

    // Regression: the accept is BOUND to the request — an
    // unoffered selection is an error here, not wire bytes.
    let unoffered = ConnectAccept::new().with_subprotocol(Some("nope"));
    assert!(matches!(
      unoffered.headers_for(&view).unwrap_err(),
      ConnectAcceptError::SubprotocolNotOffered
    ));

    let response: Vec<(&str, &str)> = headers.iter().collect();
    let negotiated = validate_connect_response(&response, &req).unwrap();
    assert_eq!(negotiated.subprotocol(), Some("chat"));

    // A subprotocol we didn't offer fails.
    let response: &[(&str, &str)] = &[("sec-websocket-protocol", "nope")];
    assert!(validate_connect_response(response, &req).is_err());

    // Case matters (RFC 6455 grants no folding here): "CHAT" is not the
    // offered "chat".
    let response: &[(&str, &str)] = &[("sec-websocket-protocol", "CHAT")];
    assert!(matches!(
      validate_connect_response(response, &req).unwrap_err(),
      ConnectResponseError::SubprotocolNotOffered
    ));

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
    let (params, response) = accept_deflate_offer(
      view.extensions().map(str::as_bytes),
      &ServerDeflateConfig::new(),
    )
    .unwrap();
    let accept = ConnectAccept::new().with_deflate(Some(response));
    let (response_headers, server_negotiated) = accept.headers_for(&view).unwrap();
    assert_eq!(server_negotiated.deflate(), Some(params));

    // Regression: replaying the grant onto a request with NO
    // deflate offer fails the bind.
    let plain_req = ConnectRequest::new(Scheme::Https, "h", "/");
    let plain_headers = plain_req.headers().unwrap();
    let plain_pairs: Vec<(&str, &str)> = plain_headers.iter().collect();
    let plain_view = validate_connect_request(&plain_pairs).unwrap();
    let replay = ConnectAccept::new().with_deflate(Some(response));
    assert!(matches!(
      replay.headers_for(&plain_view).unwrap_err(),
      ConnectAcceptError::ExtensionNotOffered
    ));

    // Client side: validate the response.
    let resp: Vec<(&str, &str)> = response_headers.iter().collect();
    let negotiated = validate_connect_response(&resp, &req).unwrap();
    assert_eq!(negotiated.deflate(), Some(params));
  }
}
