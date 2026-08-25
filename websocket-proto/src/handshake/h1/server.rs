//! Server side of the h1 opening handshake (RFC 6455 §4.2), driven by one
//! `http1-proto` tunnel connection.
//!
//! The split between the two crates is the split between the two
//! specifications: `http1-proto` owns HTTP — the head grammar, the RFC 9112
//! §3.2 `Host` and request-target rules, RFC 9110 §7.8's upgrade offer and the
//! 101 that answers it — and this module owns what RFC 6455 adds on top: the
//! GET-only rule, the `Sec-WebSocket-Key`/`-Accept` SHA-1, the version check,
//! the subprotocol and extension negotiation, and the §4.2.1 item 1
//! resource-name policy.
//!
//! # Answering takes two calls, and that is the point
//!
//! A tunnel connection is a phase machine, so [`ServerHandshake::handle`]
//! ADVANCES it: the request head is borrowed from the driver's buffer and its
//! borrow ends when the driver goes away to decide. RFC 6455 §4.2.2 nevertheless
//! binds the answer to the request — "the server MUST NOT accept a subprotocol
//! the client did not offer", and the same for an extension grant — so every
//! request-bound check runs in [`validate_accept`](PendingUpgrade::validate_accept)
//! while the view is alive, and what it settles is stored INSIDE the handshake.
//! [`encode_response`](ServerHandshake::encode_response) then writes the
//! subprotocol and the grant out of that stored answer, never out of an
//! [`Accept`] handed in beside it, so encoding an answer nobody validated is not
//! expressible.
//!
//! # Neither half of the pairing is a value a caller can cross
//!
//! Both used to be. `validate_accept` returned an owned decision that
//! `encode_response` took, and it took the classified [`RequestView`] as an
//! argument — so a caller held two objects per exchange and could pair either
//! one with the wrong partner. Both mistakes were caught by COMPARING the
//! request's `Sec-WebSocket-Key`, which is data the PEER chooses: RFC 6455 §4.1
//! asks a client for a randomly selected value, which binds a conforming client
//! and says nothing about a hostile one. Two concurrent requests carrying one
//! key defeated the comparison, and A's subprotocol and A's extension grant then
//! reached the 101 answering B, whose client offered neither, with every
//! individual call returning `Ok`.
//!
//! Neither fix is a better comparison. The answer lives in the handshake that
//! validated it, so there is no decision value to hand anywhere. And the request
//! is no longer handed in either: [`handle`](ServerHandshake::handle) yields a
//! [`PendingUpgrade`] that holds its handshake by MUTABLE BORROW alongside the
//! view, and `validate_accept` is a method on it that takes no view argument. No
//! function in this crate accepts a [`RequestView`], so validating one
//! handshake's answer against another's offers is not a guarded mistake — it is
//! a program that does not compile, and one handshake cannot even have two
//! pending upgrades outstanding.
//!
//! Extra response headers are the exception, and they are not request-bound at
//! all — they are the server's own configuration, and checking them (token
//! names, no collision with the fields this handshake manages) never needed a
//! request. They are passed to `encode_response` and validated there.
//!
//! # A request may arrive already read
//!
//! A server that speaks ordinary HTTP before it speaks WebSocket reads the
//! upgrade request on an `http1-proto` General connection — which has the body
//! machinery a tunnel does not — and takes that crate's mode edge once it
//! decides to switch. [`ServerHandshake::adopt`] takes the connection that comes
//! back, and [`classify`](ServerHandshake::classify) validates the head the
//! caller kept, in place of [`handle`](ServerHandshake::handle) reading one.
//!
//! Everything above still holds on that path, and one thing more is weaker
//! rather than absent: `handle` knows the head it validates is the head its
//! connection read, and no signature can say that about a head a caller kept.
//! `classify` asks the connection instead — [`Connection::head_binding`]
//! compares the head against a digest of the one that armed it, and a mismatch
//! is refused — and behind that runtime binding it keeps §4.2.1's HTTP/1.1
//! floor, RFC 9110 §7.8's two-halved offer, §7.8's outstanding `100 (Continue)`,
//! and one request per handshake. All of it is documented on the call.

use crate::{
  constants,
  error::BufferTooSmallDetail,
  handshake::{ExtraHeaders, accept_value, fields::RequestFields},
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{IsVariant, TryUnwrap};
use http_semantics::grammar::{is_token, token_list_contains};
use http1_proto::{
  Connection, HeadBinding, HeadView, Headers, RequestLine, Server, ServerTunnelRequest, Target,
  Tunnel, Version,
};

/// The budget the borrowing view exists to hold: the view BORROWS the head
/// instead of materializing a field table, so it costs a handful of slices
/// rather than the ~2 KB an inline `HeaderMap` costs. Checked at module scope so
/// every `cargo check` on every tier enforces it. (`'_` is not legal in a const
/// item, so `'static` stands in; the size does not depend on the lifetime.)
const _: () = assert!(core::mem::size_of::<RequestView<'static>>() <= 256);

/// RFC 9110 §15.2.1's `100 (Continue)` — the status code — sent to discharge
/// §10.1.1's `Expect`, and which §7.8 orders before the 101.
const CONTINUE: u16 = 100;

/// An empty outbound field section — what a `100 (Continue)` carries.
const NO_HEADERS: &[(&str, &[u8])] = &[];

/// Errors from the server handshake (parsing, validation, encoding).
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum ServerHandshakeError {
  /// The tunnel connection refused the request or the answer: a head that
  /// broke RFC 9110 / RFC 9112 grammar, a request that is not RFC 9110 §7.8's
  /// upgrade offer at all, or a call this connection's phase does not allow.
  #[error(transparent)]
  Http(http1_proto::Error),

  /// The request method was not GET.
  #[error("handshake request method must be GET")]
  NotAGet,

  /// The request target was neither origin-form nor an absolute http/https
  /// URI (RFC 6455 §4.2.1 item 1), or contained whitespace/control bytes.
  #[error("request target is not a websocket resource name")]
  InvalidTarget,

  /// No (single, non-empty) Host header.
  #[error("handshake request must carry a Host header")]
  MissingHost,

  /// The Host value is not an RFC 3986 authority (RFC 9110 §7.2).
  #[error("Host is not a valid authority")]
  InvalidHost,

  /// `Upgrade`/`Connection` did not contain the required tokens.
  #[error("request is not a websocket upgrade")]
  NotAnUpgrade,

  /// The head handed to [`classify`](ServerHandshake::classify) announced a
  /// version below HTTP/1.1, whose `Upgrade` field RFC 9110 §7.8 makes a server
  /// MUST ignore — so RFC 6455 §4.2.1 item 1's floor is not met and no 101 can
  /// answer it.
  ///
  /// Distinct from [`UnsupportedVersion`](Self::UnsupportedVersion), which is
  /// RFC 6455 §4.2.1 item 6's `Sec-WebSocket-Version` and is answered with a
  /// 426: this is the HTTP version, and there is no version to advertise back.
  #[error("upgrade request is not HTTP/1.1")]
  UnsupportedHttpVersion,

  /// The connection still owes RFC 9110 §7.8's `100 (Continue)` while the head
  /// handed to [`classify`](ServerHandshake::classify) states no such
  /// expectation, so the two describe different requests.
  #[error("head states no 100-continue expectation, which the connection owes")]
  ExpectationMismatch,

  /// The head handed to [`classify`](ServerHandshake::classify) is not the head
  /// the adopted connection read: [`HeadBinding::Mismatch`], which is either a
  /// head that armed some OTHER connection or a connection armed by RFC 9110
  /// §9.3.6's CONNECT, which made no §7.8 upgrade offer for any head to be.
  ///
  /// Answering it would answer one request out of another's facts, against RFC
  /// 9110 §7.8's "A server MUST NOT switch to a protocol that was not indicated
  /// by the client in the corresponding request's Upgrade header field" — so the
  /// pairing is refused instead. A connection this handshake did not adopt from
  /// a caller cannot produce it: [`handle`](ServerHandshake::handle) reads the
  /// head it validates.
  #[error("this connection did not read this head, or its handshake is a CONNECT")]
  HeadMismatch,

  /// The head handed to [`classify`](ServerHandshake::classify) does not begin
  /// with an RFC 9112 §3 request-line, so there is no method, request-target or
  /// version to validate RFC 6455 §4.2.1 against.
  ///
  /// A view of a RESPONSE head is the reachable case. Distinct from
  /// [`HeadMismatch`](Self::HeadMismatch) on purpose: a status-line head handed
  /// to a connection holding nothing raises no binding question at all, so
  /// reporting one would be untrue.
  #[error("head does not begin with a request-line")]
  NotARequestHead,

  /// [`classify`](ServerHandshake::classify) was offered a second request.
  ///
  /// RFC 6455 §4.2.2 binds one answer to one request: a second classification
  /// would replace the key the `Sec-WebSocket-Accept` is derived from while
  /// leaving the subprotocol and extension grants settled against the first
  /// request, which is the cross-pairing this module exists to refuse.
  #[error("this handshake has already classified a request")]
  AlreadyClassified,

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

  /// [`encode_response`](ServerHandshake::encode_response) was called before
  /// [`validate_accept`](PendingUpgrade::validate_accept) settled an answer.
  ///
  /// RFC 6455 §4.2.2's request-bound checks run against the borrowed head, so
  /// an answer that was never checked against one cannot be written: there is no
  /// unvalidated path to a 101.
  #[error("no validated answer to encode")]
  AnswerNotValidated,

  /// The accept named a subprotocol the client did not offer (or a
  /// non-token).
  #[error("accepted subprotocol was not offered")]
  SubprotocolNotOffered,

  /// A `Sec-WebSocket-Protocol` offer element was not an RFC 9110 token, or
  /// the list repeated an element (RFC 6455 §4.1 requires unique offers).
  #[error("malformed Sec-WebSocket-Protocol offer list")]
  MalformedSubprotocols,

  /// A `Sec-WebSocket-Extensions` field did not conform to RFC 6455 §9.1's
  /// ABNF, which the recipient of "such malformed data MUST immediately _Fail
  /// the WebSocket Connection_" over — whatever extensions this server
  /// supports.
  #[error("malformed Sec-WebSocket-Extensions value")]
  MalformedExtensions,

  /// The accept carried a deflate grant the request's offers cannot
  /// legalize (RFC 6455 §4.2.2 /extensions/: only offered extensions may be
  /// granted).
  #[error("granted extension was not offered")]
  ExtensionNotOffered,

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

/// Turns a tunnel-layer fault into this layer's error, with `offset` bytes
/// already written into the caller's buffer ahead of the failing call.
///
/// A short output buffer keeps this crate's own [`BufferTooSmall`] shape, so a
/// caller that sizes its buffer from the detail reads one kind of answer
/// whichever layer measured it — rebased past anything already in the buffer,
/// because what the caller has to grow is the WHOLE buffer. Everything else is
/// the tunnel's verdict, forwarded intact.
///
/// [`BufferTooSmall`]: ServerHandshakeError::BufferTooSmall
fn from_h1(error: http1_proto::Error, offset: usize) -> ServerHandshakeError {
  match error {
    http1_proto::Error::BufferTooSmall { need, have } => ServerHandshakeError::BufferTooSmall(
      BufferTooSmallDetail::new(need.saturating_add(offset), have.saturating_add(offset)),
    ),
    // `http1_proto::Error` is `#[non_exhaustive]`: a fault this layer has no
    // WebSocket meaning for is the tunnel's to describe, and it is forwarded
    // rather than flattened into a guess.
    other => ServerHandshakeError::Http(other),
  }
}

/// A validated upgrade request, borrowed from the caller's buffer. The
/// application inspects it (path, origin, offers, arbitrary headers) and
/// decides to accept or reject.
///
/// Reached through the [`PendingUpgrade`] that classified it, and inert on its
/// own: no function in this crate takes one, which is what keeps an answer from
/// being validated against another exchange's offers. The borrow ends where the
/// driver's buffer does, so anything the answer depends on is frozen by
/// [`validate_accept`](PendingUpgrade::validate_accept) before the view goes
/// away.
#[derive(Debug, Copy, Clone)]
pub struct RequestView<'a> {
  fields: RequestFields<'a>,
  method: &'a str,
  target: &'a str,
  path: &'a str,
  query: Option<&'a str>,
  host: &'a str,
  key: &'a [u8],
}

impl<'a> RequestView<'a> {
  /// The `Sec-WebSocket-Key` this request offered (RFC 6455 §4.1): 24 base64
  /// bytes, format-validated.
  pub const fn key(&self) -> &'a [u8] {
    self.key
  }

  /// The request method — always `GET`, which RFC 6455 §4.2.1 item 1 requires
  /// and this layer enforces (RFC 9110 §7.8 scopes an upgrade offer to the
  /// fields, so http1-proto delegates the method).
  pub const fn method(&self) -> &'a str {
    self.method
  }

  /// The request target, as the client wrote it: RFC 9112 §3.2.1's origin-form
  /// or §3.2.2's absolute-form.
  pub const fn target(&self) -> &'a str {
    self.target
  }

  /// The /resource name/'s path component (always `/`-leading; `/` when the
  /// target's path was empty). The query rides separately in
  /// [`query`](Self::query) — the two are split because the absolute-form
  /// `http://host?q` target's resource name `/?q` contains a slash RFC 6455
  /// §3 constructs rather than one on the wire, so no single borrowed slice
  /// can carry it.
  pub const fn path(&self) -> &'a str {
    self.path
  }

  /// The query component (bytes after `?`), when the target carried one.
  pub const fn query(&self) -> Option<&'a str> {
    self.query
  }

  /// The EFFECTIVE authority: for an absolute-form request target this is
  /// the target's embedded authority — RFC 9112 §3.2.2 requires an origin
  /// server to ignore the Host field in that case — otherwise the Host
  /// header value. Routing and origin policy should use this, never the raw
  /// Host header.
  pub const fn host(&self) -> &'a str {
    self.host
  }

  /// The Origin header, when present (browser clients send it; RFC 6455
  /// §4.2.2 leaves the policy to the application).
  ///
  /// Bytes, because RFC 9110 §5.5 admits `obs-text` in a field value.
  ///
  /// Unambiguous by construction: a request carrying more than one `Origin`
  /// never reaches a view, because [`ServerHandshake::handle`] refuses it as a
  /// duplicated singleton (RFC 6454 §7 defines one `origin-list-or-null`). So
  /// `Some` is THE value the client sent and `None` is a client that sent none
  /// — never "the first of several" and never "too many to say". An `Origin:`
  /// with an empty value is `Some(b"")`: a field the peer sent, not one it
  /// omitted, which is the distinction an origin policy needs.
  pub fn origin(&self) -> Option<&'a [u8]> {
    // The repeated arm is unreachable behind the gate above; answered rather
    // than unwrapped, like the other post-gate impossibilities here.
    self.fields.origin().single().ok().flatten()
  }

  /// The client's subprotocol offers in order, across repeated
  /// `Sec-WebSocket-Protocol` headers and comma lists. Every element was
  /// token-validated, deduplicated, and held to RFC 6455 §11.3.4's `1#token`
  /// during [`ServerHandshake::handle`], so they are ASCII by construction and
  /// there is at least one whenever the field was present (RFC 6455 §4.2.1
  /// item 8).
  ///
  /// The same walk the gate ran — the `crate::negotiation` list reader that
  /// [`crate::negotiation::subprotocol_list_conforms`] is driven from — over
  /// the field's complete value, so what passed the gate is exactly what
  /// arrives here.
  pub fn subprotocols(&self) -> impl Iterator<Item = &'a str> + 'a {
    crate::negotiation::subprotocol_list(self.fields.subprotocol_offers())
      // Unreachable: classification proved every element a token. Answered by
      // dropping the element rather than by an unwrap.
      .filter_map(|offer| core::str::from_utf8(offer).ok())
  }

  /// The `Sec-WebSocket-Extensions` field lines in arrival order, for the
  /// [`negotiation`](crate::negotiation) entry points (RFC 6455 §9.1).
  ///
  /// Raw lines rather than parsed entries: RFC 9110 §5.2 makes the several
  /// lines of one field a single comma-joined value, and only a walker that
  /// sees all of them can split it where the field's own grammar says. EVERY
  /// line, for the same reason: the field "MAY be split or combined across
  /// multiple lines" (§9.1), so a reader that saw one of them would be reading
  /// a different value than the gate did.
  pub fn extensions(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
    self.fields.extension_offers().into_iter()
  }

  /// Any request header by name (ASCII case-insensitive) — for cookie and
  /// auth policy in the application.
  ///
  /// Bytes, because RFC 9110 §5.5 admits `obs-text` in a field value.
  ///
  /// # The FIRST occurrence only
  ///
  /// This is an escape hatch for fields this crate does not manage, and it
  /// cannot know their cardinality: it reports the first line and says nothing
  /// about a second. **Do not make a security decision on it for a field whose
  /// value is not a list** — a peer that sent two `Cookie`s or two
  /// `X-Forwarded-For`s gets authorized against one value while another
  /// contradicts it, which is the header-confusion shape. Read
  /// [`head`](Self::head)`.header_all(name)` instead and decide what more than
  /// one means; the fields RFC 6455 itself defines are already resolved by the
  /// named accessors, which refuse that ambiguity rather than hiding it.
  pub fn header(&self, name: &str) -> Option<&'a [u8]> {
    self.fields.other(name)
  }

  /// The borrowed head, for a caller that needs a field this view does not
  /// name — a repeated one, or several lines of one field.
  pub const fn head(&self) -> &HeadView<'a> {
    self.fields.head()
  }
}

/// Outcome of feeding request bytes to [`ServerHandshake::handle`].
///
/// `'h` is the borrow of the handshake that classified the request; `'a` is the
/// buffer the head was read out of.
///
/// No `TryUnwrap`: the variant that matters carries the handshake as well as the
/// request, and a driver has to match it to reach either.
#[derive(Debug, IsVariant)]
#[non_exhaustive]
pub enum ServerProgress<'h, 'a> {
  /// The head is not complete yet — read more and call again with the whole
  /// accumulated buffer. Consumes nothing.
  NeedMore,
  /// A validated upgrade request, ready for the accept/reject decision.
  Upgrade(PendingUpgrade<'h, 'a>),
  /// The peer closed WITHOUT sending a request: a clean ending that owes no
  /// answer. A peer that closed part-way through one left an ambiguous
  /// message, which is an error rather than this.
  Closed,
}

/// A classified request, held together with the handshake that classified it.
///
/// This is where RFC 6455 §4.2.2's binding of an answer to a request is made
/// structural. The offers §4.2.2 checks against live in the borrowed head, so
/// something has to carry them to the check — and what carries them ALSO carries
/// the handshake, by mutable borrow, so the check is a method rather than a
/// function taking a view. There is no API that accepts a foreign
/// [`RequestView`], so answering one exchange out of another's offers is not
/// expressible; and while this object is alive its handshake is exclusively
/// borrowed, so a second pending upgrade cannot exist beside it.
///
/// The request itself is inert: [`request`](Self::request) hands out a `Copy` of
/// the view, and nothing consumes one.
///
/// # The cross-pairing does not compile
///
/// Two clients may send the SAME `Sec-WebSocket-Key` — RFC 6455 §4.1 asks for a
/// randomly selected value, which binds a conforming client and not a hostile
/// one — so the two exchanges below were once indistinguishable to a comparison.
/// Answering `b` out of `a`'s offers now needs an argument `validate_accept`
/// does not take:
///
/// ```compile_fail,E0061
/// use websocket_proto::handshake::h1::{Accept, ServerHandshake, ServerProgress};
/// # const A: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
/// # Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
/// # Sec-WebSocket-Protocol: superchat\r\nSec-WebSocket-Version: 13\r\n\r\n";
/// # const B: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
/// # Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
/// # Sec-WebSocket-Version: 13\r\n\r\n";
/// // `A` offers `superchat` under a key `B` — which offers nothing — repeats.
/// let mut a = ServerHandshake::new();
/// let mut b = ServerHandshake::new();
/// let ServerProgress::Upgrade(a_pending) = a.handle(A).unwrap() else { panic!() };
/// let ServerProgress::Upgrade(mut b_pending) = b.handle(B).unwrap() else { panic!() };
///
/// // B's answer, legalized by A's offers: there is no such call.
/// b_pending.validate_accept(
///   &a_pending.request(),
///   &Accept::new().with_subprotocol(Some("superchat")),
/// );
/// ```
///
/// One handshake cannot hold two of these at once either, so the crossing cannot
/// be staged inside a single exchange:
///
/// ```compile_fail,E0499
/// use websocket_proto::handshake::h1::{ServerHandshake, ServerProgress};
/// # const REQ: &[u8] = b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
/// # Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
/// # Sec-WebSocket-Version: 13\r\n\r\n";
/// let mut hs = ServerHandshake::new();
/// let ServerProgress::Upgrade(first) = hs.handle(REQ).unwrap() else { panic!() };
/// let second = hs.handle(REQ);
/// let _ = first.request();
/// ```
#[derive(Debug)]
pub struct PendingUpgrade<'h, 'a> {
  handshake: &'h mut ServerHandshake,
  view: RequestView<'a>,
  leftover: &'a [u8],
}

impl<'a> PendingUpgrade<'_, 'a> {
  /// The classified request, borrowed from the buffer it was read out of.
  ///
  /// By value — it is `Copy`, and its lifetime is the BUFFER's, so a caller may
  /// keep inspecting the request after this object is gone.
  pub const fn request(&self) -> RequestView<'a> {
    self.view
  }

  /// The bytes after the head, verbatim: frames the client pipelined behind the
  /// request, which belong to the connection machine.
  pub const fn leftover(&self) -> &'a [u8] {
    self.leftover
  }

  /// Validates an answer against THIS request, settling it inside the handshake
  /// that classified the request so that it outlives the head.
  ///
  /// RFC 6455 §4.2.2 binds the answer to the request — the subprotocol echoed
  /// must be one the client offered, and an extension may be granted only if
  /// this request's offers legalize it — so both are checked here, while the
  /// offers can still be read. There is no request parameter: the one this
  /// checks against is the one this handshake classified, which is what makes
  /// crossing two exchanges a compile error rather than a runtime guard. And
  /// nothing comes back: what was settled is
  /// [`encode_response`](ServerHandshake::encode_response)'s to write, and a
  /// value handed to the caller would be a value the caller could hand to
  /// another handshake.
  ///
  /// Extra response headers are not checked here and are not part of the answer:
  /// nothing about them depends on the request, so they go to `encode_response`
  /// with their own validation.
  ///
  /// # Errors
  ///
  /// [`SubprotocolNotOffered`](ServerHandshakeError::SubprotocolNotOffered) or
  /// [`ExtensionNotOffered`](ServerHandshakeError::ExtensionNotOffered) when the
  /// answer states something this request's offers do not legalize;
  /// [`Negotiation`](ServerHandshakeError::Negotiation) when the agreed
  /// subprotocol does not fit the handshake's inline storage. A refused answer
  /// is not stored, and calling this again re-decides: the last validated answer
  /// is the one written.
  pub fn validate_accept(&mut self, accept: &Accept<'_>) -> Result<(), ServerHandshakeError> {
    let request = &self.view;
    let negotiated = match accept.subprotocol {
      None => Negotiated::none(),
      Some(chosen) => {
        let offered = request.subprotocols().any(|offer| offer == chosen);
        if !offered || !is_token(chosen.as_bytes()) {
          return Err(ServerHandshakeError::SubprotocolNotOffered);
        }
        // Stored, not borrowed: this is the copy the 101 is written from, so
        // the field on the wire and the `Negotiated` the connection is
        // configured with cannot drift apart.
        Negotiated::with_subprotocol(chosen)?
      }
    };

    // The deflate grant is request-bound exactly like the subprotocol: a
    // `DeflateResponse` minted for a different request (or none) must not
    // be emitted for one whose offers cannot legalize it — the peer would
    // receive compressed RSV1 frames it never negotiated.
    #[cfg(feature = "deflate")]
    if let Some(response) = &accept.deflate
      && !crate::negotiation::response_matches_offer(request.extensions(), response)
    {
      return Err(ServerHandshakeError::ExtensionNotOffered);
    }
    #[cfg(feature = "deflate")]
    let negotiated = negotiated.with_deflate(accept.deflate.map(|grant| grant.params()));

    self.handshake.answer = Some(Answer {
      negotiated,
      #[cfg(feature = "deflate")]
      deflate: accept.deflate,
    });
    Ok(())
  }
}

/// The request-bound half of an answer: the subprotocol to echo and the
/// extension grant.
///
/// Only what RFC 6455 §4.2.2 checks AGAINST the request lives here. Extra
/// response headers do not: they are server configuration, they are validated
/// without a request, and they are handed to
/// [`encode_response`](ServerHandshake::encode_response) instead.
#[derive(Debug, Copy, Clone, Default)]
pub struct Accept<'a> {
  subprotocol: Option<&'a str>,
  #[cfg(feature = "deflate")]
  deflate: Option<crate::negotiation::DeflateResponse>,
}

impl<'a> Accept<'a> {
  /// Accept with no subprotocol and no extension grant.
  pub const fn new() -> Self {
    Self {
      subprotocol: None,
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

/// The validated answer to one request: what RFC 6455 §4.2.2 bound to a head
/// that is no longer readable.
///
/// PRIVATE, and that is the design. It lives in the [`ServerHandshake`] that
/// validated it, so there is no value for a caller to hold beside a second
/// handshake and no pairing for a mistake — or a hostile client's key collision
/// — to get wrong. [`ServerHandshake::encode_response`] reads the subprotocol
/// and the grant out of here, so an answer that reaches the wire is one that was
/// checked against the request being answered.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct Answer {
  negotiated: Negotiated,
  /// The grant to render, kept beside the [`Negotiated`] because the
  /// `Sec-WebSocket-Extensions` response echoes parameters that the agreed
  /// [`DeflateParams`](crate::negotiation::DeflateParams) alone do not decide
  /// (RFC 7692 §7.1.2.1: acceptance is BY inclusion).
  #[cfg(feature = "deflate")]
  deflate: Option<crate::negotiation::DeflateResponse>,
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
  ///
  /// Unbounded here, and read under the RECEIVING peer's limits exactly as
  /// [`ServerHandshake::encode_response`]'s are: for a `websocket-proto` client
  /// that is [`http1_proto::MAX_HEADERS`] (64 field lines, one of them the
  /// `Connection: close` a rejection writes itself) and
  /// [`http1_proto::MAX_HEAD_BYTES`] (16 KiB).
  #[must_use]
  pub fn with_extra_headers(mut self, extra_headers: impl Into<ExtraHeaders<'a, 'a>>) -> Self {
    self.extra_headers = extra_headers.into();
    self
  }
}

/// The server side of the h1 opening handshake (RFC 6455 §4.2), driving one
/// `http1-proto` tunnel connection.
///
/// STATEFUL, and one instance serves ONE handshake. What the decision needs
/// later — the key, and whether RFC 9110 §7.8 still owes a `100 (Continue)` —
/// is kept here rather than re-read from a buffer that has moved on.
///
/// # Two ways a request reaches one
///
/// [`new`](Self::new) opens a connection this handshake reads the request on
/// itself, through [`handle`](Self::handle). [`adopt`](Self::adopt) takes one
/// the caller already read the request on — an `http1-proto` General connection
/// it transitioned once it saw RFC 9110 §7.8's offer — and
/// [`classify`](Self::classify) validates the head the caller kept.
///
/// The single-handshake rule is ONE rule over both, not one per path: a
/// handshake is OFFERED a request exactly once, whichever entry point offers it
/// and whatever this layer then makes of it. The offer is spent when the request
/// becomes irrevocable — the connection has taken it, or a head has been handed
/// to [`classify`](Self::classify) — and not when validation succeeds, because
/// between those two points sit every way this layer can refuse a request the
/// connection is nonetheless committed to. Both entry points read that one
/// latch before either looks at a request.
///
/// A refusal therefore ends the handshake rather than inviting a second attempt.
/// That is not a convenience: the connection carries ONE armed request, so there
/// is exactly one correct head for it, and nothing here can show that a second
/// head is that one. A retry that might be legitimate is indistinguishable from
/// an attempt to answer a different request on this connection. A caller with
/// several candidate heads spends a `ServerHandshake` per head, which costs
/// nothing — see [`adopt`](Self::adopt).
///
/// The connection's own idle gate sits behind the latch as a second, narrower
/// guard that only [`handle`](Self::handle) reaches, and it is not enough on its
/// own: `classify` never advances the connection, and the gate says nothing
/// about a request the connection took and this layer refused. Everything
/// downstream of classification — the answer, the 101, the rejection — is one
/// path for both.
#[derive(Debug)]
pub struct ServerHandshake {
  connection: Connection<Server, Tunnel>,
  /// THE LATCH: whether this handshake has been offered its one request.
  ///
  /// A fact of its own rather than one read off some other field's value,
  /// because every artifact of a SUCCESSFUL classification says something
  /// narrower than what the latch has to mean: by the time either entry point
  /// can fail, the connection is already committed to the one request that
  /// armed it. The rule this carries, and what answering a second request on
  /// that connection would break, are on [`ServerHandshake`] itself.
  ///
  /// Set at the point the offer becomes IRREVOCABLE — see
  /// [`take_request`](Self::take_request) — never at the point validation
  /// succeeds.
  request_offered: bool,
  /// The key of the classified request (RFC 6455 §4.1), stored so that
  /// encoding does not need the expired borrow.
  ///
  /// Not the latch, and deliberately not: it is written only when RFC 6455
  /// §4.2.1 validation SUCCEEDS, so a latch read off it would be open on every
  /// connection a request had armed and this layer had then refused.
  key: Option<[u8; constants::SEC_WEBSOCKET_KEY_LEN]>,
  /// RFC 9110 §7.8's outstanding ordering MUST, as the tunnel reported it at
  /// classification.
  ///
  /// Mirrored rather than re-read at encode time — and NOT re-derived from
  /// `Expect`, which is http1-proto's rule to read — because the tunnel
  /// discharges the obligation the moment the 100 is written into the caller's
  /// buffer, while a call that then fails to fit the 101 hands the caller an
  /// `Err` it must not send. Latching here keeps the retry writing both heads
  /// in RFC 9110 §7.8's order instead of dropping the 100 on the floor.
  continue_owed: bool,
  /// The answer [`validate_accept`](Self::validate_accept) settled against the
  /// request this handshake classified, and the only one
  /// [`encode_response`](Self::encode_response) will write. `None` until one is
  /// validated — a handshake that never was cannot accept.
  ///
  /// Kept rather than consumed on the way out: a short output buffer is a
  /// retryable failure, and the answer the retry writes must be the same one.
  answer: Option<Answer>,
}

impl Default for ServerHandshake {
  fn default() -> Self {
    Self::new()
  }
}

impl ServerHandshake {
  /// Creates a handshake for one connection.
  pub const fn new() -> Self {
    Self {
      connection: Connection::new(),
      request_offered: false,
      key: None,
      continue_owed: false,
      answer: None,
    }
  }

  /// Classifies the bytes offered so far, ADVANCING the connection.
  ///
  /// `data` is the driver's accumulated buffer from its unconsumed start.
  /// [`ServerProgress::NeedMore`] consumes nothing — offer the same bytes again
  /// with more behind them — and a request the connection TAKES is taken once:
  /// this is not a replayable re-parse.
  ///
  /// # Errors
  ///
  /// [`AlreadyClassified`](ServerHandshakeError::AlreadyClassified) once this
  /// handshake has been offered a request — by this call OR by
  /// [`classify`](Self::classify), which is the same latch and the same answer,
  /// and whatever RFC 6455 §4.2.1 then made of that request. A `NeedMore` and a
  /// `Closed` consumed none, so neither spends the offer. Otherwise whatever
  /// §4.2.1 refuses the offered request for.
  pub fn handle<'h, 'a>(
    &'h mut self,
    data: &'a [u8],
  ) -> Result<ServerProgress<'h, 'a>, ServerHandshakeError> {
    // Read before a byte is consumed: a handshake that has been offered a
    // request must not read another, whichever entry point was offered the
    // first.
    self.unclassified()?;
    let outcome = self
      .connection
      .handle_request(data)
      .map_err(|error| from_h1(error, 0))?;
    // The two outcomes that consumed NO request. The offer is still open after
    // either, and it has to be: a driver re-offers a growing buffer until a
    // head terminates, so arming on `NeedMore` would break the one sequence
    // every h1 driver runs, and a peer that closed without sending a request
    // never made one.
    //
    // Everything else IS a request the connection has taken — an upgrade, RFC
    // 9110 §9.3.6's CONNECT, or whatever variant this `#[non_exhaustive]` enum
    // gains next — and the connection is armed with it whatever this layer goes
    // on to decide. Taken HERE, ahead of RFC 6455 §4.2.1, because a request this
    // layer refuses has armed the connection just as firmly as one it accepts.
    if !matches!(
      outcome,
      ServerTunnelRequest::NeedMore | ServerTunnelRequest::Closed
    ) {
      self.take_request();
    }
    let (head, request, leftover) = match outcome {
      ServerTunnelRequest::Upgrade {
        head,
        request,
        leftover,
      } => (head, request, leftover),
      ServerTunnelRequest::NeedMore => return Ok(ServerProgress::NeedMore),
      ServerTunnelRequest::Closed => return Ok(ServerProgress::Closed),
      // RFC 9110 §9.3.6's CONNECT tunnel is a different takeover: RFC 6455
      // §4.2.1 item 1 wants a GET, and CONNECT is not one.
      ServerTunnelRequest::Connect { .. } => return Err(ServerHandshakeError::NotAGet),
      // `ServerTunnelRequest` is `#[non_exhaustive]`: a classification this
      // layer does not know is not RFC 6455 §4.2.1's handshake, and switching
      // protocols on a request nobody here read is the one answer never
      // available.
      _ => return Err(ServerHandshakeError::NotAnUpgrade),
    };

    let view = websocket_request(head, &request)?;
    self.record(&view);
    Ok(ServerProgress::Upgrade(PendingUpgrade {
      handshake: self,
      view,
      leftover,
    }))
  }

  /// Adopts a connection the caller classified as an upgrade and transitioned
  /// with [`Connection::into_tunnel`].
  ///
  /// The request has already been READ, through the General connection whose
  /// pump has the body machinery a tunnel does not, so [`handle`](Self::handle)
  /// is not the entry point on this path: the head is the caller's, and
  /// [`classify`](Self::classify) is what validates it.
  ///
  /// Adopting an UNtransitioned connection is safe, and no gate is possible
  /// here in any case: a tunnel's phase is `http1-proto`'s own and not nameable
  /// from this crate. Two things make it safe, and BOTH are load-bearing. The
  /// mistake surfaces at encode time, where `http1-proto` refuses a 101 on a
  /// connection carrying no classified handshake. And the latch spends this
  /// handshake's one offer on the first request either entry point is given, so
  /// [`handle`](Self::handle) cannot arm that still-idle connection with a
  /// SECOND request afterwards — which is the one way a 101 could escape here,
  /// since `handle` does leave the connection classified and `encode_response`
  /// would then write the second request's accept value beside whatever the
  /// first had already settled.
  ///
  /// # Pre-validating without spending the connection
  ///
  /// [`Connection::into_tunnel`] is one-way, so a request that is a valid RFC
  /// 9110 §7.8 upgrade but an invalid RFC 6455 §4.2.1 handshake — a bad key, a
  /// version this crate does not speak, a resource name §4.2.1.1 refuses —
  /// leaves a caller that transitioned FIRST holding a tunnel it must reject,
  /// with no keep-alive HTTP connection left to serve.
  ///
  /// Adopting a FRESH connection is the way round it, and it is the whole
  /// recipe: `ServerHandshake::adopt(Connection::new())` plus
  /// [`classify`](Self::classify) runs every §4.2.1 check against the head the
  /// General pump produced, touching neither that pump's connection nor the
  /// throwaway one — `classify` advances nothing. A rejection costs a discarded
  /// `ServerHandshake` and leaves the real connection General and answerable; an
  /// acceptance is the go-ahead to transition and adopt for real.
  ///
  /// The head-to-connection binding `classify` checks does not stand in the way
  /// of this, by design: a fresh connection classified nothing, so it answers
  /// [`HeadBinding::NoHandshake`] for every head and there is no armed request to
  /// contradict. What makes that safe is the backstop this recipe already leans
  /// on — [`encode_response`](Self::encode_response) writes the 101 through the
  /// connection, which refuses one it never classified a request on, so a
  /// throwaway validates and never answers.
  ///
  /// Discarding it is REQUIRED rather than merely tidy: a handshake is offered
  /// one request whatever the outcome, so a refused head spends this one. That
  /// is what makes the recipe a per-head loop — cheap, since a `ServerHandshake`
  /// is a `Connection` and four small fields, and none of it allocates.
  ///
  /// [`Connection::into_tunnel`]: http1_proto::Connection::into_tunnel
  pub const fn adopt(connection: Connection<Server, Tunnel>) -> Self {
    Self {
      connection,
      request_offered: false,
      key: None,
      continue_owed: false,
      answer: None,
    }
  }

  /// Validates the request an [adopted](Self::adopt) connection carries
  /// (RFC 6455 §4.2.1), against a head the CALLER read.
  ///
  /// [`handle`](Self::handle) advances the connection, so the head it validates
  /// is the one that connection classified. This does not: the head and the
  /// bytes behind it come from the General pump the caller drove before the
  /// transition, and no signature can state that they belong to the connection
  /// beside them. [`Connection::head_binding`] states it at runtime instead —
  /// the connection kept a digest of the head that armed it, and a
  /// [`Mismatch`](http1_proto::HeadBinding::Mismatch) is refused with
  /// [`HeadMismatch`](ServerHandshakeError::HeadMismatch). That refusal covers
  /// a head from another connection and a connection armed by RFC 9110 §9.3.6's
  /// CONNECT alike — the latter offered no §7.8 upgrade for any head to be, and
  /// left unrefused it produced a 101 from here while the connection's own
  /// `accept` wrote `200 Connection Established`.
  ///
  /// [`NoHandshake`](http1_proto::HeadBinding::NoHandshake) PROCEEDS rather than
  /// refusing, and that is what keeps the pre-validation recipe above working: a
  /// throwaway connection classified nothing, so there is no armed request the
  /// head could contradict, and `accept` refuses a 101 on such a connection
  /// anyway.
  ///
  /// # What the binding does not reach
  ///
  /// Digest equality is not byte equality, and against adversarially shaped
  /// traffic it is not a boundary at all — see [`Connection::head_binding`]. So
  /// three content checks stay, and on the throwaway path, where no identity
  /// check runs, the first two are the WHOLE of the protection: item 1's
  /// "HTTP/1.1 or higher" floor, which RFC 9110 §7.8 makes a MUST by making an
  /// HTTP/1.0 `Upgrade` field a MUST-ignore, and item 4's `Connection` naming
  /// `upgrade`, which is the half of §7.8's offer the §4.2.1 walk shared with
  /// `handle` does not state (item 3's `Upgrade` naming `websocket` is stated
  /// there, on both paths).
  ///
  /// The third is RFC 9110 §7.8's outstanding `100 (Continue)`, and it is
  /// ONE-DIRECTIONAL for a reason of its own, which is about STATE rather than
  /// content: a connection that owes one against a head stating no such
  /// expectation is a mismatched pair, while a head that states one against a
  /// connection owing none is LEGAL — a `100 (Continue)` sent on the General
  /// connection before the transition discharges the obligation while leaving
  /// the answer owed, so refusing that head would refuse a conforming sequence.
  ///
  /// # The request-line is derived, not passed
  ///
  /// [`HeadView::request_line`] reads it out of the block this call was handed,
  /// so there is no second argument to mispair. A caller-supplied line the
  /// digest says nothing about would carry exactly the class of mistake this
  /// call exists to refuse: RFC 9112 §3.2.2's absolute-form target overrides
  /// `Host`, so a foreign line grants the right request's key against a
  /// different request's resource name and authority. A head whose start line is
  /// a §4 status-line answers
  /// [`NotARequestHead`](ServerHandshakeError::NotARequestHead).
  ///
  /// ONE request per handshake, across both entry points and WHATEVER THE
  /// OUTCOME. This call spends the handshake's offer before it validates
  /// anything, and so does [`handle`](Self::handle) the moment its connection
  /// takes a request; a second request offered to either answers
  /// [`AlreadyClassified`](ServerHandshakeError::AlreadyClassified). Why the
  /// offer is spent on the ATTEMPT rather than on success is on
  /// [`ServerHandshake`] itself.
  ///
  /// # Errors
  ///
  /// [`HeadMismatch`](ServerHandshakeError::HeadMismatch) when the head is not
  /// the one this connection read;
  /// [`NotARequestHead`](ServerHandshakeError::NotARequestHead) when it holds no
  /// request-line;
  /// [`UnsupportedHttpVersion`](ServerHandshakeError::UnsupportedHttpVersion),
  /// [`NotAnUpgrade`](ServerHandshakeError::NotAnUpgrade) or
  /// [`ExpectationMismatch`](ServerHandshakeError::ExpectationMismatch) from the
  /// three content checks above, and everything [`handle`](Self::handle) answers
  /// a non-conforming §4.2.1 request with otherwise. On error the handshake
  /// survives and stays reject-only, so §4.2.1's "return an HTTP response with
  /// an appropriate error code" is still writable — but the offer is SPENT: a
  /// corrected pairing needs a fresh handshake, not a second call on this one.
  pub fn classify<'h, 'a>(
    &'h mut self,
    head: &HeadView<'a>,
    leftover: &'a [u8],
  ) -> Result<ServerProgress<'h, 'a>, ServerHandshakeError> {
    // The same latch `handle` reads, through the same place: a handshake that
    // has been offered a request has nothing to learn from a second one, and
    // two copies of that rule are what later come to disagree.
    self.unclassified()?;
    // Taken before anything is validated, the binding and the three tripwires
    // included. The connection was armed with its one request before this
    // handshake existed, so a head that fails a check is definitively not that
    // request — and nothing here can show that the NEXT head is it either. A
    // retry that might be legitimate is indistinguishable from an attempt to
    // answer a different request on this connection.
    //
    // This is also why the binding is checked BELOW the latch rather than
    // before it: a second `classify` is `AlreadyClassified` whatever head it
    // carries, and reporting a binding failure there would say the offer is
    // still open.
    self.take_request();

    // RFC 9112 §3, out of the block itself — see "The request-line is derived,
    // not passed" above for why it is not a parameter.
    let Some(line) = head.request_line() else {
      return Err(ServerHandshakeError::NotARequestHead);
    };

    // The identity `handle` gets from having read the head itself. RFC 9110
    // §7.8: "A server MUST NOT switch to a protocol that was not indicated by
    // the client in the corresponding request's Upgrade header field" — the
    // CORRESPONDING request, which is a question about which request this
    // connection is holding rather than about what this head says.
    //
    // `NoHandshake` proceeds: a connection carrying no classified request is
    // the throwaway `adopt(Connection::new())` the recipe above prescribes, and
    // it has no armed request for this head to contradict.
    if matches!(self.connection.head_binding(head), HeadBinding::Mismatch) {
      return Err(ServerHandshakeError::HeadMismatch);
    }

    // RFC 9110 §7.8: "A server that receives an Upgrade header field in an
    // HTTP/1.0 request MUST ignore that Upgrade field", so a pre-1.1 head
    // states no offer this handshake could answer, whatever its fields say.
    if !matches!(line.version, Version::Http11) {
      return Err(ServerHandshakeError::UnsupportedHttpVersion);
    }

    let fields = RequestFields::new(*head);

    // §7.8's other half — "A sender of Upgrade MUST also send an `Upgrade`
    // connection option in the Connection header field". `websocket_request`
    // states the `Upgrade: websocket` half below, on both paths; this one has
    // no gate behind it here, because the connection's own gate read a head
    // this call was not handed.
    if !fields
      .connection()
      .into_iter()
      .any(|value| token_list_contains(value, "upgrade"))
    {
      return Err(ServerHandshakeError::NotAnUpgrade);
    }

    if !expectation_matches(self.connection.owes_continue(), &fields) {
      return Err(ServerHandshakeError::ExpectationMismatch);
    }

    let view = websocket_request(*head, &line)?;
    self.record(&view);
    Ok(ServerProgress::Upgrade(PendingUpgrade {
      handshake: self,
      view,
      leftover,
    }))
  }

  /// Checks that this handshake has not been offered a request yet — the state
  /// BOTH entry points need before either looks at one.
  ///
  /// The read side of the latch, and the only one: `handle` and `classify` call
  /// this rather than each testing the fact for itself, because RFC 6455
  /// §4.2.2's binding of an answer to a request is one rule and a second copy of
  /// it is free to drift. What it reads is
  /// [`request_offered`](Self::request_offered), which is the reason it works in
  /// every direction — a guard on `classify` alone leaves `classify` → `handle`
  /// open, and a guard derived from a SUCCESSFUL classification's artifacts is
  /// open on every connection a request armed and this layer then refused.
  ///
  /// The connection's own `handle_request` has a second, narrower guard of its
  /// own — it refuses a request on a connection that is no longer idle — which
  /// covers `handle` after `handle` on a connection that advanced, and covers
  /// neither the path where `classify` left the connection untouched nor the one
  /// where this layer refused what the connection had already taken.
  fn unclassified(&self) -> Result<(), ServerHandshakeError> {
    if self.request_offered {
      return Err(ServerHandshakeError::AlreadyClassified);
    }
    Ok(())
  }

  /// Spends the one request this handshake is ever offered.
  ///
  /// The write side of the latch, and the only one. Called at the point the
  /// offer becomes IRREVOCABLE — the connection has taken a request, or a head
  /// has been handed to [`classify`](Self::classify) — never at the point
  /// validation succeeds. Everything between those two points is a way for this
  /// layer to refuse a request the connection is nonetheless committed to, and a
  /// latch that waited for success would be open on exactly those connections.
  fn take_request(&mut self) {
    self.request_offered = true;
  }

  /// Stores what the answer still needs once the head's borrow has ended: the
  /// key RFC 6455 §4.2.2 derives the `Sec-WebSocket-Accept` from, and RFC 9110
  /// §7.8's outstanding ordering MUST as the connection reports it.
  ///
  /// The two are written together, on BOTH classification paths, because
  /// dropping either one dead-ends the same 101: without the key there is no
  /// accept value to write, and without the mirrored obligation
  /// [`encode_response`](Self::encode_response) skips the 100 and the
  /// connection refuses the switch it was ordered before.
  ///
  /// Neither is the latch: the offer was spent by
  /// [`take_request`](Self::take_request) before this ran, so what is stored
  /// here is only what the ANSWER needs.
  fn record(&mut self, view: &RequestView<'_>) {
    let mut stored = [0u8; constants::SEC_WEBSOCKET_KEY_LEN];
    for (slot, byte) in stored.iter_mut().zip(view.key) {
      *slot = *byte;
    }
    self.key = Some(stored);
    // Asked of the connection, which read `Expect` when the request was
    // classified; a second reading here would be a second implementation of RFC
    // 9110 §7.8's rule, free to disagree with the gate that enforces it.
    self.continue_owed = self.connection.owes_continue();
  }

  /// Reports that the transport's read side has ended.
  ///
  /// Idempotent, and it decides nothing on its own: the next
  /// [`handle`](Self::handle) resolves the offer that ran out — nothing
  /// buffered is [`ServerProgress::Closed`], a partial head is an error.
  pub fn handle_eof(&mut self) -> Result<(), ServerHandshakeError> {
    self
      .connection
      .handle_eof()
      .map_err(|error| from_h1(error, 0))
  }

  /// Writes the 101 for the answer this handshake validated, returning the byte
  /// count and the [`Negotiated`] to configure the connection machine with.
  ///
  /// The subprotocol and the extension grant come out of THIS handshake, so the
  /// field section states exactly what
  /// [`validate_accept`](PendingUpgrade::validate_accept)
  /// checked against the request this connection read, and the
  /// `Sec-WebSocket-Accept` value is derived from that request's own key (RFC
  /// 6455 §4.2.2). There is no answer parameter, so there is no way to write one
  /// belonging to a different exchange: a handshake that validated nothing
  /// answers with
  /// [`AnswerNotValidated`](ServerHandshakeError::AnswerNotValidated) instead.
  ///
  /// `extras` are the server's own additional headers, validated here because
  /// nothing about them is request-bound: CR/LF and non-token names are refused,
  /// and so is a collision with a field this handshake manages — a colliding
  /// extra (`Sec-WebSocket-Extensions`, say) would grant capabilities on the
  /// wire that the returned [`Negotiated`] does not carry, leaving the peer
  /// compressing against a connection configured for no compression. Pass
  /// [`ExtraHeaders::new()`] when there are none.
  ///
  /// **How many, and how large, is the RECEIVING peer's limit rather than
  /// this one**: nothing here is bounded — a large head violates nothing, and
  /// refusing to write one a lenient peer would accept is a rule no RFC has —
  /// but a `websocket-proto` client reads the 101 under
  /// [`http1_proto::MAX_HEADERS`] (64 field lines, of which this response spends
  /// three, or five when a subprotocol is echoed and an extension granted) and
  /// [`http1_proto::MAX_HEAD_BYTES`] (16 KiB), so past either the peer fails the
  /// handshake this side considered complete.
  ///
  /// When the request carried `Expect: 100-continue` the buffer receives TWO
  /// heads: RFC 9110 §7.8 makes the `100 (Continue)` a MUST before the 101
  /// whenever an upgrade request stated the expectation, so it is written into
  /// the front of `out` and the 101 follows it. The count covers both, and one
  /// flush sends them in order.
  ///
  /// TERMINAL: the bytes after the 101 belong to the frame stream, so nothing
  /// further may be written on this handshake.
  pub fn encode_response(
    &mut self,
    extras: &ExtraHeaders<'_, '_>,
    out: &mut [u8],
  ) -> Result<(usize, Negotiated), ServerHandshakeError> {
    let Some(key) = self.key else {
      return Err(ServerHandshakeError::InvalidKey);
    };
    // The whole of what used to be a cross-check between two objects: there is
    // one answer, it is this handshake's, and a handshake that validated none
    // has nothing to write. RFC 6455 §4.2.2's "the server MUST NOT select a
    // subprotocol the client did not offer" cannot be broken by pairing, only
    // by a bug in `validate_accept` itself.
    let Some(answer) = self.answer else {
      return Err(ServerHandshakeError::AnswerNotValidated);
    };
    let accept_bytes = accept_value(&key);

    extras
      .validate()
      .map_err(ServerHandshakeError::InvalidResponseOption)?;
    // No managed collisions: an extra `Sec-WebSocket-Extensions` /
    // `Sec-WebSocket-Protocol` would grant capabilities ON THE WIRE that the
    // decision's `Negotiated` does not carry — the peer then compresses or
    // assumes a subprotocol against a connection configured for neither.
    extras
      .validate_no_managed_collision(&[])
      .map_err(ServerHandshakeError::InvalidResponseOption)?;

    let interim = if self.continue_owed {
      self
        .connection
        .send_interim(CONTINUE, NO_HEADERS, out)
        .map_err(|error| from_h1(error, 0))?
    } else {
      0
    };

    // Rendered ONCE, ahead of the walk: `Headers::for_each` is visited three
    // times on the way out and every walk must yield the identical section, so
    // nothing may be formatted into a shared scratch while it runs.
    #[cfg(feature = "deflate")]
    let mut extension_value = [0u8; crate::negotiation::MAX_EXTENSION_VALUE_BYTES];
    #[cfg(feature = "deflate")]
    let extensions = match &answer.deflate {
      Some(grant) => {
        let written = grant
          .write(&mut extension_value)
          .map_err(ServerHandshakeError::BufferTooSmall)?;
        extension_value.get(..written)
      }
      None => None,
    };
    #[cfg(not(feature = "deflate"))]
    let extensions: Option<&[u8]> = None;

    let headers = AcceptHeaders {
      accept: &accept_bytes,
      // From the answer's own storage: the field the peer reads and the
      // `Negotiated` returned below are one value.
      subprotocol: answer.negotiated.subprotocol(),
      extensions,
      extras: *extras,
    };
    // `interim` never exceeds the buffer it was written into.
    let rest = out.get_mut(interim..).unwrap_or_default();
    let written = self
      .connection
      .accept(&headers, rest)
      .map_err(|error| from_h1(error, interim))?;
    // Both heads are in the caller's buffer, so §7.8's order is satisfied by a
    // single flush and the obligation is spent.
    self.continue_owed = false;
    Ok((interim.saturating_add(written), answer.negotiated))
  }

  /// Writes a rejection response (e.g. 403, or
  /// [`Rejection::unsupported_version`] for the 426 path), returning its
  /// length. The connection is closed after sending it.
  pub fn encode_rejection(
    &mut self,
    rejection: &Rejection<'_>,
    out: &mut [u8],
  ) -> Result<usize, ServerHandshakeError> {
    if !(300..=599).contains(&rejection.status) {
      return Err(ServerHandshakeError::InvalidRejectionStatus(
        rejection.status,
      ));
    }
    // reason-phrase grammar = HTAB / SP / VCHAR / obs-text (RFC 9112 §4):
    // the same field-value control screen the extra headers get.
    if rejection
      .reason
      .bytes()
      .any(|b| (b < 0x20 && b != b'\t') || b == 0x7F)
    {
      return Err(ServerHandshakeError::InvalidResponseOption(
        "reason contains control bytes",
      ));
    }
    rejection
      .extra_headers
      .validate()
      .map_err(ServerHandshakeError::InvalidResponseOption)?;
    // Managed collisions are rejected here too — the rejection writes its own
    // `Connection: close`, and a spoofed `Sec-WebSocket-Accept` could dress a
    // rejection up as an acceptance. `Sec-WebSocket-Version` is exempt: a
    // rejection legitimately advertises the supported version (RFC 6455 §4.2.2's
    // 426 answer — see `Rejection::unsupported_version`), and no `Negotiated`
    // exists on this path to contradict.
    rejection
      .extra_headers
      .validate_no_managed_collision(&["sec-websocket-version"])
      .map_err(ServerHandshakeError::InvalidResponseOption)?;

    let headers = RejectionHeaders {
      extras: rejection.extra_headers,
    };
    self
      .connection
      .reject(rejection.status, rejection.reason.as_bytes(), &headers, out)
      .map_err(|error| from_h1(error, 0))
  }
}

/// RFC 9110 §7.8's ordering MUST as a tripwire over a caller-supplied head:
/// `false` when the connection still owes a `100 (Continue)` and `fields` state
/// no such expectation, so the two describe different requests.
///
/// ONE-DIRECTIONAL. A head that states the expectation against a connection
/// owing none is LEGAL, not a mismatch: a `100 (Continue)` sent on the General
/// connection before the transition discharges the obligation while leaving the
/// answer owed (RFC 9110 §15.2 makes the 1xx not the answer), so refusing it
/// would refuse a conforming sequence.
///
/// The head is read coarsely, as a `#expectation` list naming the bare token,
/// rather than through §10.1.1's full `expectation = token [ "=" ( token /
/// quoted-string ) parameters ]`: that grammar is `http1-proto`'s, and the
/// obligation this compares against is what ITS reading produced. A coarse read
/// can only widen what counts as stating the expectation, which lets a
/// mismatched pair through rather than refusing a conforming one — the only
/// direction a tripwire may err in.
///
/// A FUNCTION rather than two lines inside
/// [`classify`](ServerHandshake::classify), and the reason is testability. The
/// head-to-connection binding runs ahead of this and refuses a head the
/// connection did not read, so the only heads that reach here are heads whose
/// own bytes armed the connection — and identical bytes state an identical
/// expectation. The `false` direction is therefore unreachable end-to-end
/// without a digest collision, and this is the seam its four input combinations
/// are pinned through instead.
fn expectation_matches(owed: bool, fields: &RequestFields<'_>) -> bool {
  !owed
    || fields
      .expect()
      .into_iter()
      .any(|value| token_list_contains(value, "100-continue"))
}

/// RFC 6455 §4.2.1's rules over a request head `http1-proto` has already framed
/// and whose target grammar it has already validated, yielding the view an
/// answer is checked against.
///
/// The ONE implementation of §4.2.1, shared by the two ways a request reaches a
/// handshake — [`handle`](ServerHandshake::handle), which reads it through the
/// tunnel, and [`classify`](ServerHandshake::classify), which adopts one the
/// caller read — so the two cannot come to enforce the section differently.
/// What is deliberately NOT here is what the two paths know differently: the
/// tunnel proved RFC 9110 §7.8's `Connection: upgrade` half and the HTTP/1.1
/// floor as it classified the head, and a caller-supplied head has had neither
/// proved, so `classify` states both itself before calling this.
fn websocket_request<'a>(
  head: HeadView<'a>,
  request: &RequestLine<'a>,
) -> Result<RequestView<'a>, ServerHandshakeError> {
  // §4.2.1 item 1. http1-proto scopes the offer to the FIELDS, as RFC 9110
  // §7.8 does ("an OPTIONS request can be honored by any protocol"), so the
  // method rule is this layer's.
  if request.method != "GET" {
    return Err(ServerHandshakeError::NotAGet);
  }

  // Every field below is read through THIS, and so is the `RequestView` the
  // caller gets: the gate and the reader cannot disagree about a field's
  // occurrences or its presence when neither of them looks the field up.
  let fields = RequestFields::new(head);

  // §4.2.1 item 3: an `Upgrade` field "containing the value 'websocket'".
  // WHICH protocol is a WebSocket rule, and what the caller proved before
  // getting here differs by path: `handle`'s connection proved BOTH halves of
  // RFC 9110 §7.8 as it classified the head, so the field is known present and
  // known to name some protocol; `classify`'s tripwire proved only the
  // `Connection: upgrade` half, so on that path this line is the first and only
  // check that the `Upgrade` field is there at all. Neither premise is relied
  // on — the walk below answers a missing field and a wrong one alike.
  // RFC 9110 §5.3: repeated field lines are one comma-joined list, so the
  // token may arrive in ANY occurrence (proxies split lists across lines).
  if !fields
    .upgrade()
    .into_iter()
    .any(|value| token_list_contains(value, "websocket"))
  {
    return Err(ServerHandshakeError::NotAnUpgrade);
  }

  // §4.2.1 item 1 / §3: the resource name. http1-proto validated the target's
  // GRAMMAR and classified its form; the split into path and query, and the
  // http/https scheme policy, are RFC 6455's.
  let Some(target) = resource_name(&request.target) else {
    return Err(ServerHandshakeError::InvalidTarget);
  };

  // §4.2.1 item 2: a `Host` field "containing the server's authority". RFC
  // 9112 §3.2 already required exactly one field line whose value is an
  // authority or EMPTY — the empty spelling is what a target with no
  // authority component sends, and it names no server, so it fails here.
  // Present-and-empty is therefore NOT absent: both fail, and they fail for
  // different reasons the singleton read keeps apart.
  let Ok(Some(host)) = fields.host().single().map(|v| v.filter(|h| !h.is_empty())) else {
    return Err(ServerHandshakeError::MissingHost);
  };
  // Unreachable: §3.2 held the value to the authority grammar, and every
  // byte of that grammar is ASCII. Answered rather than unwrapped.
  let Ok(host) = core::str::from_utf8(host) else {
    return Err(ServerHandshakeError::InvalidHost);
  };
  // RFC 9112 §3.2.2: with an absolute-form target, an origin server MUST
  // ignore the Host field and use the target's authority — otherwise a
  // proxy-form request could be routed/authorized as one host while its
  // target names another.
  let host = target.authority.unwrap_or(host);

  // §4.2.1 item 5: present exactly once, and 24 base64 bytes.
  let key = match fields.websocket_key().single() {
    Ok(Some(key)) => key,
    Ok(None) => return Err(ServerHandshakeError::InvalidKey),
    Err(_) => return Err(ServerHandshakeError::DuplicateHeader),
  };
  if !crate::base64::is_valid_key(key) {
    return Err(ServerHandshakeError::InvalidKey);
  }

  // §4.2.1 item 6: present exactly once, and 13.
  let version = match fields.websocket_version().single() {
    Ok(Some(version)) => version,
    Ok(None) => return Err(ServerHandshakeError::UnsupportedVersion),
    Err(_) => return Err(ServerHandshakeError::DuplicateHeader),
  };
  if version != constants::WEBSOCKET_VERSION.as_bytes() {
    return Err(ServerHandshakeError::UnsupportedVersion);
  }

  // §4.2.1 item 7's optional `Origin`, which RFC 6454 §7 defines as ONE
  // `origin-list-or-null` and RFC 9110 §5.3 therefore forbids repeating.
  // Refused rather than RESOLVED, because neither answer an `Option` can
  // carry is safe: the FIRST of two contradicting values authorizes against a
  // value the peer also denied, and `None` reads to the obvious call shape —
  // `if let Some(origin) = view.origin()` — as a client that sent no origin
  // at all, which skips the policy entirely. A field this crate cannot
  // resolve is one it ANSWERS, exactly as it answers a duplicated key or
  // version, and the handshake stays reject-only so the driver still writes
  // RFC 6455 §4.2.1's "HTTP response with an appropriate error code".
  if fields.origin().single().is_err() {
    return Err(ServerHandshakeError::DuplicateHeader);
  }

  // §11.3.4 with §4.1 item 10: `1#token`, elements the client MUST keep
  // unique. The rule lives in the grammar layer that knows the ABNF and is
  // asked over the field's COMPLETE value — every line, empty elements
  // ignored (RFC 2616 §2.1), a present field naming nothing refused. The
  // `RequestView::subprotocols` the caller reads is the same walk, so what
  // passes here is exactly what the application sees.
  if !crate::negotiation::subprotocol_list_conforms(fields.subprotocol_offers()) {
    return Err(ServerHandshakeError::MalformedSubprotocols);
  }

  // §9.1: "If a value is received by either the client or the server during
  // negotiation that does not conform to the ABNF below, the recipient of
  // such malformed data MUST immediately _Fail the WebSocket Connection_."
  // Independent of which extensions this build supports, and of whether the
  // server would have granted any: §9.1's freedom to DECLINE is about
  // extensions a server does not want, not about data it cannot read. The
  // handshake is left reject-only, so the fault is answered with §4.2.1's
  // "HTTP response with an appropriate error code" rather than dropped.
  if !crate::negotiation::extension_list_conforms(fields.extension_offers()) {
    return Err(ServerHandshakeError::MalformedExtensions);
  }

  Ok(RequestView {
    fields,
    method: request.method,
    target: target.target,
    path: target.path,
    query: target.query,
    host,
    key,
  })
}

/// The 101's field section (RFC 6455 §4.2.2), supplied to `http1-proto`'s
/// encoder.
///
/// Every value is a slice fixed before the walk begins, so the three walks the
/// encoder makes — the framing reduction, the measuring pass, the writing pass
/// — see byte-for-byte the same section, which is the [`Headers`] contract.
struct AcceptHeaders<'a> {
  /// The base64 `Sec-WebSocket-Accept` value.
  accept: &'a [u8],
  /// The selected subprotocol, when one was.
  subprotocol: Option<&'a str>,
  /// The rendered extension grant, when one was.
  extensions: Option<&'a [u8]>,
  /// Caller-supplied extras, already validated.
  extras: ExtraHeaders<'a, 'a>,
}

impl Headers for AcceptHeaders<'_> {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), http1_proto::Error> {
    // RFC 9110 §15.2.2 makes the `Upgrade` field a MUST on the 101 and §7.8
    // requires the connection option beside it; http1-proto refuses to write a
    // 101 without both.
    f("Upgrade", b"websocket");
    f("Connection", b"Upgrade");
    f("Sec-WebSocket-Accept", self.accept);
    if let Some(subprotocol) = self.subprotocol {
      f("Sec-WebSocket-Protocol", subprotocol.as_bytes());
    }
    if let Some(extensions) = self.extensions {
      f("Sec-WebSocket-Extensions", extensions);
    }
    for (name, value) in self.extras.iter() {
      f(name, value.as_bytes());
    }
    Ok(())
  }
}

/// The refusal's field section (RFC 6455 §4.2.2 step 5 / RFC 9110 §15.5.22).
struct RejectionHeaders<'a> {
  /// Caller-supplied extras, already validated.
  extras: ExtraHeaders<'a, 'a>,
}

impl Headers for RejectionHeaders<'_> {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), http1_proto::Error> {
    // RFC 9112 §9.6: the handshake is over either way, and the driver closes
    // behind this message — so the peer is told, rather than left to discover
    // it at the close. `Connection::reject` does not add the option itself.
    f("Connection", b"close");
    for (name, value) in self.extras.iter() {
      f(name, value.as_bytes());
    }
    Ok(())
  }
}

/// RFC 6455 §3's /resource name/, split out of an RFC 9112 §3.2 request target,
/// plus the absolute-form's embedded authority.
struct TargetParts<'a> {
  /// The target exactly as the client wrote it.
  target: &'a str,
  /// The path component, always `/`-leading.
  path: &'a str,
  /// The query component, without its `?`.
  query: Option<&'a str>,
  /// The authority an absolute-form target carried, which RFC 9112 §3.2.2
  /// makes the effective host.
  authority: Option<&'a str>,
}

/// Splits a validated request target into RFC 6455 §3's resource name.
///
/// http1-proto has already classified the form and validated its grammar; what
/// is applied here is RFC 6455 §4.2.1 item 1's own policy — the target is
/// origin-form, or "an absolute HTTP/HTTPS URI containing the resource name",
/// so the two other §3.2 forms name nothing this handshake could be answered
/// for — and the split into the separately borrowable path and query the view
/// hands out. The `http://h?q` shape's resource name `/?q` carries a slash §3
/// CONSTRUCTS rather than one on the wire, which is why no single slice can
/// carry it.
///
/// `None` means the target is not a websocket resource name.
fn resource_name<'a>(target: &Target<'a>) -> Option<TargetParts<'a>> {
  match *target {
    Target::Origin { path_and_query } => {
      let (path, query) = split_query(path_and_query);
      Some(TargetParts {
        target: path_and_query,
        path,
        query,
        authority: None,
      })
    }
    Target::Absolute { uri } => {
      // RFC 3986 §3.1 makes the scheme ASCII case-insensitive; RFC 6455
      // §4.2.1 item 1 admits http and https only.
      let rest = ["http://", "https://"].iter().find_map(|scheme| {
        uri
          .get(..scheme.len())
          .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
          .and_then(|_| uri.get(scheme.len()..))
      })?;
      match rest.find(['/', '?']) {
        // "http://host" → resource name "/" (RFC 6455 §3), no query.
        None => Some(TargetParts {
          target: uri,
          path: "/",
          query: None,
          authority: Some(rest),
        }),
        Some(at) => {
          let authority = rest.get(..at)?;
          let resource = rest.get(at..)?;
          let (path, query) = match resource.strip_prefix('?') {
            // "http://host?q" → resource name "/?q".
            Some(query) => ("/", Some(query)),
            None => split_query(resource),
          };
          Some(TargetParts {
            target: uri,
            path,
            query,
            authority: Some(authority),
          })
        }
      }
    }
    // RFC 9112 §3.2.3 scopes the authority-form to CONNECT and §3.2.4 the
    // asterisk-form to a server-wide OPTIONS: neither names a resource RFC
    // 6455 §3 could take a resource name from.
    Target::Authority { .. } | Target::Asterisk => None,
  }
}

/// Splits a path-and-query at its first `?`. An empty path reads as `/`
/// (RFC 6455 §3), which only an absolute-form target can present here —
/// origin-form is `/`-leading by grammar.
fn split_query(path_and_query: &str) -> (&str, Option<&str>) {
  match path_and_query.split_once('?') {
    None => (path_and_query, None),
    Some((path, query)) => (if path.is_empty() { "/" } else { path }, Some(query)),
  }
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

  /// Drives one request to classification. The handshake comes back alone: a
  /// pending upgrade borrows it, so no helper can hand out both.
  fn classified(raw: &[u8]) -> ServerHandshake {
    let mut hs = ServerHandshake::new();
    match hs.handle(raw) {
      Ok(ServerProgress::Upgrade(_)) => {}
      other => panic!("expected an upgrade request, got {other:?}"),
    }
    hs
  }

  /// The same, with `accept` validated against the request while it is still
  /// readable — so what comes back owes the peer a 101 it has already settled.
  fn accepted(raw: &[u8], accept: &Accept<'_>) -> ServerHandshake {
    let mut hs = ServerHandshake::new();
    match hs.handle(raw) {
      Ok(ServerProgress::Upgrade(mut pending)) => pending
        .validate_accept(accept)
        .expect("the fixture answer validates"),
      other => panic!("expected an upgrade request, got {other:?}"),
    }
    hs
  }

  /// The classified request, outliving the handshake that read it: the view
  /// borrows the BUFFER, and nothing in this crate consumes one.
  fn view(raw: &[u8]) -> RequestView<'_> {
    let mut hs = ServerHandshake::new();
    match hs.handle(raw) {
      Ok(ServerProgress::Upgrade(pending)) => pending.request(),
      other => panic!("expected an upgrade request, got {other:?}"),
    }
  }

  fn replaced(needle: &str, replacement: &str) -> Vec<u8> {
    String::from_utf8(GOOD.to_vec())
      .unwrap()
      .replace(needle, replacement)
      .into_bytes()
  }

  /// The size the borrow buys, reported rather than merely bounded.
  #[test]
  fn the_view_is_a_borrow_not_a_table() {
    let size = core::mem::size_of::<RequestView<'static>>();
    assert!(size <= 256, "RequestView is {size} bytes");
  }

  #[test]
  fn parses_and_validates_a_browser_request() {
    let v = view(GOOD);
    assert_eq!(v.method(), "GET");
    assert_eq!(v.target(), "/chat");
    assert_eq!(v.path(), "/chat");
    assert_eq!(v.query(), None);
    assert_eq!(v.host(), "server.example.com");
    assert_eq!(v.key(), b"dGhlIHNhbXBsZSBub25jZQ==");
    assert_eq!(v.origin(), Some(b"http://example.com".as_slice()));
    let offers: Vec<&str> = v.subprotocols().collect();
    assert_eq!(offers, ["chat", "superchat"]);
    // Pass-through inspection of arbitrary request headers.
    assert_eq!(v.header("origin"), Some(b"http://example.com".as_slice()));
    assert_eq!(v.header("absent"), None);
    // The borrowed head is reachable for fields the view does not name.
    assert_eq!(v.head().header("upgrade"), Some(b"websocket".as_slice()));
  }

  #[test]
  fn the_view_reads_a_query_without_a_header_table() {
    let raw = replaced("GET /chat HTTP/1.1\r\n", "GET /chat?v=1 HTTP/1.1\r\n");
    let v = view(&raw);
    assert_eq!(v.target(), "/chat?v=1");
    assert_eq!(v.path(), "/chat");
    assert_eq!(v.query(), Some("v=1"));
  }

  #[test]
  fn pipelined_bytes_after_the_head_are_handed_back() {
    let mut buf = GOOD.to_vec();
    buf.extend_from_slice(b"\x81\x03abc"); // a frame the peer sent immediately
    let mut hs = ServerHandshake::new();
    let Ok(ServerProgress::Upgrade(pending)) = hs.handle(&buf) else {
      panic!("complete request")
    };
    assert_eq!(pending.leftover(), b"\x81\x03abc");

    // Nothing pipelined is an empty leftover, not a missing one.
    let mut hs = ServerHandshake::new();
    let Ok(ServerProgress::Upgrade(pending)) = hs.handle(GOOD) else {
      panic!("complete request")
    };
    assert_eq!(pending.leftover(), b"");
  }

  #[test]
  fn offers_split_across_repeated_protocol_headers() {
    let raw = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: superchat , last\r\n",
    );
    let v = view(&raw);
    let offers: Vec<&str> = v.subprotocols().collect();
    assert_eq!(offers, ["chat", "superchat", "last"]);
  }

  #[test]
  fn split_connection_header_lines_are_conforming() {
    // RFC 9110 §5.3: a proxy may split a list across repeated field lines.
    let raw = replaced(
      "Connection: keep-alive, Upgrade\r\n",
      "Connection: keep-alive\r\nConnection: Upgrade\r\n",
    );
    let v = view(&raw);
    assert_eq!(v.host(), "server.example.com");
  }

  /// Regression: the request target must be a websocket
  /// /resource name/ — origin-form, or an absolute http/https URI
  /// (RFC 6455 §4.2.1 item 1 admits BOTH; absolute-form is deliberately
  /// accepted, since rejecting it would fail conforming proxied clients).
  ///
  /// Every shape below is refused; WHICH layer refuses it follows the split
  /// between the crates. RFC 9112 §3.2's grammar and the §3.2.3/§3.2.4 pairing are
  /// http1-proto's, so those arrive as [`ServerHandshakeError::Http`], and no
  /// target that survives them fails RFC 6455's own policy.
  #[test]
  fn request_targets_are_validated() {
    // Rejected shapes: bare token, asterisk-form, authority-form,
    // tab/control bytes inside the target, query-without-path absolutes,
    // empty-authority absolutes, non-http schemes.
    for bad in [
      "websocket",
      "*",
      "server.example.com:80",
      "/\tadmin",
      "/a\x01b",
      // Raw `#` introduces a fragment — RFC 6455 §3: fragments MUST NOT be
      // used; a literal `#` must arrive as %23. Both target forms.
      "/chat#frag",
      "http://h/chat#frag",
      "http://h?x=#",
      // Malformed percent-escapes and an empty-authority absolute.
      "/chat%2",
      "/chat%zz",
      "http://?x",
      "ftp://h/chat",
      // Regression: the absolute-form AUTHORITY is grammar-
      // checked too — bad port, userinfo, multi-colon, unterminated
      // bracket, and non-address bracket forms all fail.
      "http://example.com:bad/chat",
      "http://u@h/chat",
      "http://a:b:c/chat",
      "http://[::1/chat",
      "http://[127.0.0.1]/chat",
    ] {
      let req = replaced("GET /chat HTTP/1.1\r\n", &format!("GET {bad} HTTP/1.1\r\n"));
      assert!(
        matches!(
          ServerHandshake::new().handle(&req).unwrap_err(),
          ServerHandshakeError::Http(_)
        ),
        "{bad:?}"
      );
    }

    // Accepted shapes: absolute-form yields the embedded resource name;
    // a path-less absolute URI reads as "/" (RFC 6455 §3) — INCLUDING the
    // query-only spelling `http://h?q`, whose resource name `/?q` carries a
    // constructed slash; the scheme is case-insensitive (RFC 3986 §3.1).
    for (good, want_path, want_query) in [
      ("http://server.example.com/chat?x=1", "/chat", Some("x=1")),
      ("http://server.example.com?token=1", "/", Some("token=1")),
      ("HTTPS://server.example.com", "/", None),
      ("http://[::1]:8080/chat", "/chat", None),
      ("/chat", "/chat", None),
      ("/chat?x=%23", "/chat", Some("x=%23")),
    ] {
      let req = replaced(
        "GET /chat HTTP/1.1\r\n",
        &format!("GET {good} HTTP/1.1\r\n"),
      );
      let v = view(&req);
      assert_eq!(v.target(), good, "{good:?}");
      assert_eq!(v.path(), want_path, "{good:?}");
      assert_eq!(v.query(), want_query, "{good:?}");
    }
  }

  #[test]
  fn absolute_form_authority_is_the_effective_host() {
    // Regression: RFC 9112 §3.2.2 — with an absolute-form
    // target, the target's authority IS the effective host and the Host
    // field is ignored; otherwise `GET http://admin.example/ws` with
    // `Host: public.example` would be routed/authorized as public.example.
    let req = replaced(
      "GET /chat HTTP/1.1\r\n",
      "GET http://admin.example/ws HTTP/1.1\r\n",
    );
    let v = view(&req);
    assert_eq!(v.host(), "admin.example", "target authority wins");
    assert_eq!(v.path(), "/ws");

    // The Host field is not merely overridden when it agrees — it is ignored
    // even when it names something else entirely.
    let req = String::from_utf8(req)
      .unwrap()
      .replace("Host: server.example.com\r\n", "Host: lied.example\r\n");
    let v = view(req.as_bytes());
    assert_eq!(v.host(), "admin.example");

    // Same-authority absolute-form agrees trivially.
    let req = replaced(
      "GET /chat HTTP/1.1\r\n",
      "GET http://server.example.com/chat HTTP/1.1\r\n",
    );
    assert_eq!(view(&req).host(), "server.example.com");

    // Origin-form keeps using the Host header.
    assert_eq!(view(GOOD).host(), "server.example.com");
  }

  #[test]
  fn host_values_are_grammar_checked() {
    // RFC 9112 §3.2's authority grammar is http1-proto's rule now, and it
    // refuses the same values this gate used to; what stays here is RFC 6455
    // §4.2.1 item 2's own requirement, that the field NAME a server — which
    // §3.2's legal EMPTY spelling does not.
    for bad in ["h/chat", "h?x", "h#f", "u@h", "h st", "a:b:c", "[::1"] {
      let req = replaced("Host: server.example.com\r\n", &format!("Host: {bad}\r\n"));
      assert!(
        matches!(
          ServerHandshake::new().handle(&req).unwrap_err(),
          ServerHandshakeError::Http(_)
        ),
        "{bad:?}"
      );
    }
    let empty = replaced("Host: server.example.com\r\n", "Host: \r\n");
    assert!(matches!(
      ServerHandshake::new().handle(&empty).unwrap_err(),
      ServerHandshakeError::MissingHost
    ));
    for good in ["server.example.com:8080", "[::1]:9001", "10.0.0.1"] {
      let req = replaced("Host: server.example.com\r\n", &format!("Host: {good}\r\n"));
      assert_eq!(view(&req).host(), good, "{good:?}");
    }
  }

  #[test]
  fn malformed_subprotocol_offers_fail_the_handshake() {
    // Non-token element ("bad token" has a space).
    let bad = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: bad token, admin\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::MalformedSubprotocols
    ));

    // Duplicate element, including across repeated headers.
    let dup = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat, chat\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&dup).unwrap_err(),
      ServerHandshakeError::MalformedSubprotocols
    ));
    let dup = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: chat\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&dup).unwrap_err(),
      ServerHandshakeError::MalformedSubprotocols
    ));

    // Empty elements are ignored per RFC 9110 §5.6.1.2; the remaining
    // offer list is valid and negotiable.
    let stray = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: , admin\r\n",
    );
    let offers: Vec<&str> = view(&stray).subprotocols().collect();
    assert_eq!(offers, ["admin"]);

    // Case-only difference is NOT a duplicate (RFC 6455 grants subprotocols no
    // case-insensitive comparison).
    let cased = replaced(
      "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: chat, CHAT\r\n",
    );
    assert!(ServerHandshake::new().handle(&cased).is_ok());
  }

  /// A request head whose `field` is spelled as `lines` — one field line each,
  /// in the given order — with the fixture's own copy of that field removed.
  fn head_with(field: &str, lines: &[&str]) -> Vec<u8> {
    let mut head = String::from_utf8(GOOD.to_vec())
      .unwrap()
      .replace("Sec-WebSocket-Protocol: chat, superchat\r\n", "");
    let mut fields = String::new();
    for line in lines {
      fields.push_str(&format!("{field}: {line}\r\n"));
    }
    // Ahead of the terminator, so the spelled field is part of the head.
    head = head.replace("Sec-WebSocket-Version: 13\r\n", &{
      let mut with = String::from("Sec-WebSocket-Version: 13\r\n");
      with.push_str(&fields);
      with
    });
    head.into_bytes()
  }

  /// The WHOLE outcome of classifying such a request, as one comparable
  /// string: what the gate decided, and — when it accepted — every value the
  /// crate then derives from the request's fields.
  ///
  /// Not the raw field lines, which differ between spellings by construction:
  /// the point is that what the transport RESOLVES them to does not.
  fn request_verdict(field: &str, lines: &[&str]) -> String {
    let raw = head_with(field, lines);
    let mut hs = ServerHandshake::new();
    match hs.handle(&raw) {
      Err(error) => format!("error: {error:?}"),
      Ok(ServerProgress::Upgrade(pending)) => {
        let request = pending.request();
        let offers: Vec<&str> = request.subprotocols().collect();
        #[cfg(feature = "deflate")]
        let extensions = format!(
          "{:?}",
          crate::negotiation::accept_deflate_offer(
            request.extensions(),
            &crate::negotiation::ServerDeflateConfig::new(),
          )
        );
        #[cfg(not(feature = "deflate"))]
        let extensions = String::from("(no deflate tier)");
        format!("upgrade: offers={offers:?} extensions={extensions}")
      }
      Ok(other) => format!("other: {other:?}"),
    }
  }

  /// The property the gate/reader defect class violates, asserted directly on
  /// the h1 REQUEST role: two spellings of one logical field value must reach
  /// one verdict.
  ///
  /// RFC 9110 §5.2/§5.3 join a field's several lines with commas, and RFC 2616
  /// §2.1 makes null elements ignorable — so "one value" and "the same value
  /// split across lines, with empty occurrences around it" are the same value,
  /// and every reader that resolves the field must say so. Stated as the
  /// property rather than as two named spellings, because the defect relocated
  /// twice into spellings nobody had listed.
  #[test]
  fn equivalent_spellings_of_a_request_field_reach_one_verdict() {
    use crate::handshake::spellings;

    // `Sec-WebSocket-Protocol`: RFC 6455 §11.3.4's `1#token`.
    let one = spellings::agree("one offer", &spellings::one("chat"), |lines| {
      request_verdict("Sec-WebSocket-Protocol", lines)
    });
    assert!(one.contains(r#"offers=["chat"]"#), "{one}");
    let two = spellings::agree(
      "two offers",
      &spellings::two("chat", "superchat"),
      |lines| request_verdict("Sec-WebSocket-Protocol", lines),
    );
    assert!(two.contains(r#"offers=["chat", "superchat"]"#), "{two}");

    // Present and naming nothing satisfies no `1#`, however it is spelled…
    let nothing = spellings::agree("no offer named", &spellings::nothing(), |lines| {
      request_verdict("Sec-WebSocket-Protocol", lines)
    });
    assert_eq!(nothing, "error: MalformedSubprotocols");
    // …and is NOT the same value as an absent field, which conforms vacuously.
    let absent = request_verdict("Sec-WebSocket-Protocol", &[]);
    assert!(absent.contains("offers=[]"), "{absent}");
    assert_ne!(absent, nothing);

    // `Sec-WebSocket-Extensions`: RFC 6455 §9.1's `1#extension`, whose lines
    // §9.1 explicitly permits splitting.
    let one = spellings::agree(
      "one extension",
      &spellings::one("permessage-deflate"),
      |lines| request_verdict("Sec-WebSocket-Extensions", lines),
    );
    assert!(one.starts_with("upgrade:"), "{one}");
    let two = spellings::agree(
      "two extensions",
      &spellings::two("x-private; a=b", "permessage-deflate"),
      |lines| request_verdict("Sec-WebSocket-Extensions", lines),
    );
    assert!(two.starts_with("upgrade:"), "{two}");
    let nothing = spellings::agree("no extension named", &spellings::nothing(), |lines| {
      request_verdict("Sec-WebSocket-Extensions", lines)
    });
    assert_eq!(nothing, "error: MalformedExtensions");
    let absent = request_verdict("Sec-WebSocket-Extensions", &[]);
    assert!(absent.starts_with("upgrade:"), "{absent}");
    assert_ne!(absent, nothing);
  }

  /// The other half of the same rule, and the reason it is not simply "more
  /// lines are always fine": a field whose value is NOT a list gets one line
  /// (RFC 9110 §5.3), and the transports agree on that too.
  #[test]
  fn a_singleton_request_field_is_not_splittable() {
    // The key and the version are the request's singletons; splitting either is
    // a duplicate rather than a longer value.
    let dup_key = replaced(
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
       Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&dup_key).unwrap_err(),
      ServerHandshakeError::DuplicateHeader
    ));
    let dup_version = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&dup_version).unwrap_err(),
      ServerHandshakeError::DuplicateHeader
    ));
  }

  /// A repeated `Origin` is REFUSED, not resolved. RFC 6454 §7 defines one
  /// `origin-list-or-null` and RFC 9110 §5.3 forbids repeating a field whose
  /// value is not a list, so this is the crate's existing duplicated-singleton
  /// policy — the one that already answers a repeated key or version — applied
  /// to the singleton it was missing.
  ///
  /// Neither `Option` answer would have been safe, which is why there is no
  /// `Option` answer: the FIRST of two contradicting values authorizes against
  /// a value the peer also denied, and `None` reads to `if let Some(origin) =
  /// view.origin()` — the obvious call shape — as a client that sent no origin,
  /// silently skipping the check. Refusing the message cannot be mis-consumed
  /// by any caller shape.
  #[test]
  fn a_repeated_origin_is_refused() {
    let two = replaced(
      "Origin: http://example.com\r\n",
      "Origin: http://example.com\r\nOrigin: http://evil.example\r\n",
    );
    let mut hs = ServerHandshake::new();
    assert!(matches!(
      hs.handle(&two).unwrap_err(),
      ServerHandshakeError::DuplicateHeader
    ));
    // …and the refusal is ANSWERABLE: §4.2.1 wants "an HTTP response with an
    // appropriate error code", so the handshake stays reject-only and the
    // driver still writes one.
    let mut buf = [0u8; 256];
    let n = hs
      .encode_rejection(&Rejection::new(400, "Bad Request"), &mut buf)
      .unwrap();
    assert!(
      core::str::from_utf8(&buf[..n])
        .unwrap()
        .starts_with("HTTP/1.1 400 Bad Request\r\n")
    );

    // Behind that gate the view's answer is unambiguous by construction: one
    // line is that line, and a present-but-EMPTY value is an origin the peer
    // sent rather than one it omitted.
    let empty = replaced("Origin: http://example.com\r\n", "Origin: \r\n");
    assert_eq!(view(&empty).origin(), Some(b"".as_slice()));
    let none = replaced("Origin: http://example.com\r\n", "");
    assert_eq!(view(&none).origin(), None);
    assert_eq!(
      view(GOOD).origin(),
      Some(b"http://example.com".as_slice()),
      "one Origin is still the one Origin"
    );
  }

  #[test]
  fn need_more_until_terminator() {
    for cut in [0usize, 1, 10, GOOD.len() - 1] {
      assert!(
        matches!(
          ServerHandshake::new().handle(&GOOD[..cut]).unwrap(),
          ServerProgress::NeedMore
        ),
        "cut {cut}"
      );
    }
  }

  #[test]
  fn a_split_request_needs_more_and_then_classifies() {
    // One handshake, fed the growing buffer a driver accumulates.
    let mut hs = ServerHandshake::new();
    let cut = GOOD.len() - 10;
    assert!(matches!(
      hs.handle(&GOOD[..cut]).unwrap(),
      ServerProgress::NeedMore
    ));
    assert!(matches!(
      hs.handle(GOOD).unwrap(),
      ServerProgress::Upgrade(_)
    ));
    // …and classification happens ONCE: the pairing latch refuses the second
    // request before the connection is consulted at all, so the answer is the
    // same one `classify` gives and does not depend on what the connection did
    // with the bytes.
    assert!(
      matches!(
        hs.handle(GOOD),
        Err(ServerHandshakeError::AlreadyClassified)
      ),
      "handle is not replayable"
    );
  }

  /// `Closed` is "closed without sending a request". A peer that closed
  /// part-way through one left an ambiguous message, which is an error.
  #[test]
  fn eof_with_nothing_buffered_is_closed() {
    let mut hs = ServerHandshake::new();
    hs.handle_eof().unwrap();
    assert!(matches!(hs.handle(b"").unwrap(), ServerProgress::Closed));
  }

  #[test]
  fn eof_part_way_through_a_request_is_an_error() {
    let mut hs = ServerHandshake::new();
    assert!(matches!(
      hs.handle(&GOOD[..20]).unwrap(),
      ServerProgress::NeedMore
    ));
    hs.handle_eof().unwrap();
    assert!(hs.handle(&GOOD[..20]).is_err());
  }

  #[test]
  fn a_request_that_is_not_an_upgrade_is_refused() {
    // No upgrade offer at all: RFC 9110 §7.8's two halves are http1-proto's
    // rule, so it classifies this as a request a tunnel cannot serve.
    let plain = b"GET /chat HTTP/1.1\r\nHost: h\r\n\r\n";
    assert!(matches!(
      ServerHandshake::new().handle(plain).unwrap_err(),
      ServerHandshakeError::Http(_)
    ));

    // A CONNECT is the OTHER takeover, and not RFC 6455 §4.2.1 item 1's GET.
    let connect = b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n";
    assert!(matches!(
      ServerHandshake::new().handle(connect).unwrap_err(),
      ServerHandshakeError::NotAGet
    ));
  }

  #[test]
  fn validation_failures() {
    // RFC 6455 §4.2.1 item 1: the method is this layer's rule, since RFC 9110
    // §7.8 scopes the offer to the fields.
    let bad = replaced("GET ", "POST ");
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::NotAGet
    ));

    // RFC 9110 §7.8 makes a server IGNORE an HTTP/1.0 request's `Upgrade`, so
    // such a request is not a handshake at all — http1-proto's verdict now.
    let bad = replaced(" HTTP/1.1\r\n", " HTTP/1.0\r\n");
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::Http(_)
    ));

    // RFC 9112 §3.2 makes a missing Host a 400 for any HTTP/1.1 request —
    // http1-proto's rule; RFC 6455 §4.2.1 item 2's "containing the server's
    // authority" is what `MissingHost` still answers (see the Host test).
    let bad = replaced("Host: server.example.com\r\n", "");
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::Http(_)
    ));

    // §4.2.1 item 3: the offer is well formed, but the protocol it names is
    // not websocket — which is this layer's rule.
    let bad = replaced("Upgrade: websocket\r\n", "Upgrade: h2c\r\n");
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::NotAnUpgrade
    ));

    // Without §7.8's connection option there is no offer for http1-proto to
    // classify.
    let bad = replaced(
      "Connection: keep-alive, Upgrade\r\n",
      "Connection: close\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::Http(_)
    ));

    let bad = replaced(
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
      "Sec-WebSocket-Key: tooShort\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::InvalidKey
    ));

    let bad = replaced("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "");
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::InvalidKey
    ));

    let bad = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 12\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
      ServerHandshakeError::UnsupportedVersion
    ));

    let bad = replaced("Sec-WebSocket-Version: 13\r\n", "");
    assert!(matches!(
      ServerHandshake::new().handle(&bad).unwrap_err(),
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
      ServerHandshake::new().handle(&dup).unwrap_err(),
      ServerHandshakeError::DuplicateHeader
    ));

    let mut dup = GOOD.to_vec();
    let insert = dup.len() - 2;
    dup.splice(
      insert..insert,
      b"Sec-WebSocket-Version: 13\r\n".iter().copied(),
    );
    assert!(matches!(
      ServerHandshake::new().handle(&dup).unwrap_err(),
      ServerHandshakeError::DuplicateHeader
    ));
  }

  /// A WebSocket-level refusal leaves the handshake REJECT-ONLY: the driver
  /// still owes the peer an answer (RFC 6455 §4.2.2's 426 for a bad version),
  /// and the connection must still be able to write it.
  #[test]
  fn a_validation_failure_can_still_be_answered() {
    let bad = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 8\r\n",
    );
    let mut hs = ServerHandshake::new();
    assert!(matches!(
      hs.handle(&bad).unwrap_err(),
      ServerHandshakeError::UnsupportedVersion
    ));
    let mut buf = [0u8; 256];
    let n = hs
      .encode_rejection(&Rejection::unsupported_version(), &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.starts_with("HTTP/1.1 426 Upgrade Required\r\n"),
      "{resp}"
    );
    assert!(resp.contains("\r\nSec-WebSocket-Version: 13\r\n"), "{resp}");

    // The same holds one layer down: a request http1-proto itself refused
    // leaves the single owed answer, and the driver spends it here.
    let mut hs = ServerHandshake::new();
    assert!(matches!(
      hs.handle(b"GET /chat HTTP/1.1\r\nHost : bad\r\n\r\n")
        .unwrap_err(),
      ServerHandshakeError::Http(_)
    ));
    let n = hs
      .encode_rejection(&Rejection::new(400, "Bad Request"), &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{resp}");
    assert!(resp.contains("\r\nConnection: close\r\n"), "{resp}");
  }

  #[test]
  fn a_complete_upgrade_request_classifies_and_answers() {
    let mut hs = ServerHandshake::new();
    {
      let ServerProgress::Upgrade(mut pending) = hs.handle(GOOD).unwrap() else {
        panic!("complete request")
      };
      assert_eq!(pending.leftover(), b"");
      pending
        .validate_accept(&Accept::new().with_subprotocol(Some("superchat")))
        .unwrap();
    } // the pending upgrade is gone; the answer the handshake settled is not
    let mut buf = [0u8; 512];
    let (n, negotiated) = hs.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
      "{resp}"
    );
    assert!(resp.contains("\r\nUpgrade: websocket\r\n"), "{resp}");
    assert!(resp.contains("\r\nConnection: Upgrade\r\n"), "{resp}");
    // RFC 6455 §4.2.2: the accept value is the SHA-1 of key + GUID, base64'd.
    assert!(
      resp.contains("\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"),
      "{resp}"
    );
    assert!(
      resp.contains("\r\nSec-WebSocket-Protocol: superchat\r\n"),
      "{resp}"
    );
    assert!(resp.ends_with("\r\n\r\n"));
    assert_eq!(negotiated.subprotocol(), Some("superchat"));
    assert_eq!(
      &accept_value(b"dGhlIHNhbXBsZSBub25jZQ==")[..],
      b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
  }

  /// The two properties that let a driver put an application's choice between
  /// classification and the answer: the SELECTION outlives the list it was
  /// chosen from, and the ANSWER outlives both the request and the options it
  /// was built out of. Neither compiles if either borrows what it reports, so
  /// this test is as much a compile-time assertion as a runtime one.
  #[test]
  fn an_answer_outlives_the_request_and_the_options() {
    let mut hs = ServerHandshake::new();
    // The server's configured names, owned somewhere the handshake cannot see.
    let supported = [String::from("superchat")];
    {
      let ServerProgress::Upgrade(mut pending) = hs.handle(GOOD).unwrap() else {
        panic!("complete request")
      };
      let chosen = {
        let entries: Vec<&str> = supported.iter().map(String::as_str).collect();
        crate::negotiation::select_subprotocol(pending.request().subprotocols(), &entries)
      }; // the list is gone; the selection is an entry of it, not a borrow of it
      assert_eq!(chosen, Some("superchat"));
      pending
        .validate_accept(&Accept::new().with_subprotocol(chosen))
        .unwrap();
    } // the pending upgrade is gone
    drop(supported); // and so are the names the answer was built from
    let mut buf = [0u8; 512];
    let (n, negotiated) = hs.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.contains("\r\nSec-WebSocket-Protocol: superchat\r\n"),
      "{resp}"
    );
    assert_eq!(negotiated.subprotocol(), Some("superchat"));
  }

  /// A second request with no subprotocol offers, under a key the caller
  /// chooses: the point of the parameter is that a HOSTILE client picks it.
  fn other_request(key: &str) -> Vec<u8> {
    String::from_utf8(GOOD.to_vec())
      .unwrap()
      .replace("dGhlIHNhbXBsZSBub25jZQ==", key)
      .replace("Sec-WebSocket-Protocol: chat, superchat\r\n", "")
      .into_bytes()
  }

  /// The answer A validated must not be writable through B. The check that used
  /// to enforce that compared the request's `Sec-WebSocket-Key`, which is the
  /// CLIENT's to choose: RFC 6455 §4.1 asks for a randomly selected value, which
  /// binds a conforming client and says nothing about a hostile one, so two
  /// concurrent requests carrying one key made A's decision pass B's check and
  /// A's subprotocol and extension grant could be written into the 101 answering
  /// a client that offered neither — every call returning `Ok`.
  ///
  /// Both handshakes below classify the SAME key, so the old guard would have
  /// let this through. There is no longer anything to guard: the answer lives in
  /// the handshake that validated it and the request never leaves the pending
  /// upgrade that carries it, which is what
  /// [`PendingUpgrade`](super::PendingUpgrade)'s `compile_fail` proofs pin. What
  /// stays runtime-checkable is the other end of it — B has no answer of its
  /// own until it validates one, and the one it validates is its own client's.
  #[test]
  fn an_answer_cannot_cross_to_a_handshake_that_shares_its_key() {
    let mut a = accepted(GOOD, &Accept::new().with_subprotocol(Some("superchat")));

    // The same key, a different client, and no offers behind it.
    let raw = other_request("dGhlIHNhbXBsZSBub25jZQ==");
    let mut b = ServerHandshake::new();
    let ServerProgress::Upgrade(mut pending) = b.handle(&raw).unwrap() else {
      panic!("complete request")
    };
    assert_eq!(
      pending.request().key(),
      b"dGhlIHNhbXBsZSBub25jZQ==",
      "the two exchanges share the key the old binding was made of"
    );

    // Its own answer names no subprotocol, because its own client offered none
    // — while A's still names one.
    pending.validate_accept(&Accept::new()).unwrap();
    let mut buf = [0u8; 512];
    let (n, negotiated) = b.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
      "{resp}"
    );
    assert!(!resp.contains("Sec-WebSocket-Protocol"), "{resp}");
    assert_eq!(negotiated.subprotocol(), None);

    let (n, negotiated) = a.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.contains("\r\nSec-WebSocket-Protocol: superchat\r\n"),
      "{resp}"
    );
    assert_eq!(negotiated.subprotocol(), Some("superchat"));
  }

  /// A handshake that has validated nothing has nothing to write — the state a
  /// crossed answer used to reach into.
  #[test]
  fn a_handshake_that_validated_nothing_cannot_answer() {
    let mut hs = classified(GOOD);
    let mut buf = [0u8; 512];
    assert!(matches!(
      hs.encode_response(&ExtraHeaders::new(), &mut buf)
        .unwrap_err(),
      ServerHandshakeError::AnswerNotValidated
    ));

    // Including one that never classified a request at all.
    assert!(matches!(
      ServerHandshake::new()
        .encode_response(&ExtraHeaders::new(), &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidKey
    ));
  }

  /// RFC 6455 §4.2.2: the server selects from what the client offered — and
  /// the check must survive the move into the handshake's own storage.
  #[test]
  fn a_subprotocol_that_was_not_offered_is_refused_at_validation() {
    let mut hs = ServerHandshake::new();
    {
      let ServerProgress::Upgrade(mut pending) = hs.handle(GOOD).unwrap() else {
        panic!("complete request")
      };
      assert!(matches!(
        pending
          .validate_accept(&Accept::new().with_subprotocol(Some("never-offered")))
          .unwrap_err(),
        ServerHandshakeError::SubprotocolNotOffered
      ));

      // Case matters (RFC 6455 grants no folding here): the client offered
      // "chat", not "CHAT".
      assert!(matches!(
        pending
          .validate_accept(&Accept::new().with_subprotocol(Some("CHAT")))
          .unwrap_err(),
        ServerHandshakeError::SubprotocolNotOffered
      ));
    }

    // A refused validation leaves nothing to encode: the failed answer was not
    // stored, so the 101 is not reachable through it.
    let mut buf = [0u8; 512];
    assert!(matches!(
      hs.encode_response(&ExtraHeaders::new(), &mut buf)
        .unwrap_err(),
      ServerHandshakeError::AnswerNotValidated
    ));
  }

  /// RFC 9110 §7.8: "If a server receives both an Upgrade and an Expect header
  /// field with the 100-continue expectation, the server MUST send a 100
  /// (Continue) response before sending a 101 (Switching Protocols) response."
  /// Two heads, one buffer, in that order.
  #[test]
  fn a_hundred_continue_precedes_the_switch() {
    let raw = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nExpect: 100-continue\r\n",
    );
    let mut hs = accepted(&raw, &Accept::new());
    let mut buf = [0u8; 512];
    let (n, _) = hs.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 100 \r\n\r\n"), "{resp}");
    let (interim, switch) = resp.split_at("HTTP/1.1 100 \r\n\r\n".len());
    assert!(!interim.is_empty());
    assert!(
      switch.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
      "{resp}"
    );
    assert!(switch.contains("\r\nSec-WebSocket-Accept: "), "{resp}");

    // A request that never carried the expectation gets ONE head.
    let mut hs = accepted(GOOD, &Accept::new());
    let (n, _) = hs.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 101 "), "{resp}");
  }

  /// A short buffer must not swallow the 100: the obligation stays owed until
  /// BOTH heads are in the caller's buffer, so the retry writes them in order.
  #[test]
  fn a_short_buffer_does_not_lose_the_hundred_continue() {
    let raw = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nExpect: 100-continue\r\n",
    );
    let mut hs = accepted(&raw, &Accept::new());
    let mut small = [0u8; 64];
    let err = hs
      .encode_response(&ExtraHeaders::new(), &mut small)
      .unwrap_err();
    let ServerHandshakeError::BufferTooSmall(detail) = err else {
      panic!("expected a size fault, got {err:?}")
    };
    // The size quoted covers the whole buffer, the interim head included.
    assert!(detail.needed() > small.len(), "{detail}");
    assert_eq!(detail.have(), small.len());

    let mut buf = [0u8; 512];
    let (n, _) = hs.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 100 \r\n\r\n"), "{resp}");
    assert!(
      resp.contains("HTTP/1.1 101 Switching Protocols\r\n"),
      "{resp}"
    );
  }

  #[test]
  fn rejection_responses() {
    let mut buf = [0u8; 256];
    let mut hs = classified(GOOD);
    let n = hs
      .encode_rejection(&Rejection::new(403, "Forbidden"), &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(resp.contains("\r\nConnection: close\r\n"), "{resp}");
    assert!(resp.ends_with("\r\n\r\n"));

    let mut hs = classified(GOOD);
    let n = hs
      .encode_rejection(&Rejection::unsupported_version(), &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 426 Upgrade Required\r\n"));
    assert!(resp.contains("\r\nSec-WebSocket-Version: 13\r\n"));

    // A success status is not a refusal, and the check runs before the
    // connection is touched.
    assert!(matches!(
      ServerHandshake::new()
        .encode_rejection(&Rejection::new(200, "OK"), &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidRejectionStatus(200)
    ));
  }

  #[test]
  fn accept_emits_extra_headers() {
    let mut hs = accepted(GOOD, &Accept::new());
    // The extras never needed the request: they are supplied at encode time,
    // after the view is gone.
    let mut buf = [0u8; 512];
    let (n, _) = hs
      .encode_response(
        &ExtraHeaders::from(&[("X-Trace-Id", "abc123"), ("Server", "wren")]),
        &mut buf,
      )
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("\r\nX-Trace-Id: abc123\r\n"), "{resp}");
    assert!(resp.contains("\r\nServer: wren\r\n"), "{resp}");
  }

  #[test]
  fn extra_headers_builder_round_trips_and_overflows_loudly() {
    use crate::handshake::ExtraHeadersBuilder;

    // Incrementally-built headers reach the wire like slice-built ones.
    let headers = ExtraHeadersBuilder::new()
      .with_header("X-Trace-Id", "abc123")
      .with_header("Server", "wren");
    assert_eq!(headers.len(), 2);
    assert!(!headers.is_full());

    let mut hs = accepted(GOOD, &Accept::new());
    let mut buf = [0u8; 512];
    let (n, _) = hs
      .encode_response(&ExtraHeaders::from(&headers), &mut buf)
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("\r\nX-Trace-Id: abc123\r\n"), "{resp}");
    assert!(resp.contains("\r\nServer: wren\r\n"), "{resp}");

    // Past the capacity nothing is dropped silently: the overflow flag is
    // set and the handshake fails loudly when the extras are encoded.
    let mut overflowing = ExtraHeadersBuilder::<2>::with_capacity();
    overflowing = overflowing.with_header("A", "1").with_header("B", "2");
    assert!(overflowing.is_full());
    assert!(!overflowing.overflowed());
    overflowing = overflowing.with_header("C", "3");
    assert!(overflowing.overflowed());
    assert_eq!(overflowing.len(), 2, "the overflowing pair is not stored");

    let mut hs = accepted(GOOD, &Accept::new());
    assert!(matches!(
      hs.encode_response(&ExtraHeaders::from(&overflowing), &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidResponseOption("extra headers exceeded the builder capacity")
    ));
  }

  /// The extras are screened where they are encoded, and a screen that fails
  /// leaves the connection able to try again — the checks run before anything
  /// is written.
  #[test]
  fn accept_rejects_bad_extra_headers() {
    let mut hs = accepted(GOOD, &Accept::new());
    let mut buf = [0u8; 512];

    let bad_name = ExtraHeaders::from(&[("bad name", "x")]);
    assert!(matches!(
      hs.encode_response(&bad_name, &mut buf).unwrap_err(),
      ServerHandshakeError::InvalidResponseOption(_)
    ));

    let crlf = ExtraHeaders::from(&[("X-Evil", "a\r\nX: b")]);
    assert!(matches!(
      hs.encode_response(&crlf, &mut buf).unwrap_err(),
      ServerHandshakeError::InvalidResponseOption(_)
    ));

    // Neither refusal spent the answer: the good extras still encode.
    assert!(hs.encode_response(&ExtraHeaders::new(), &mut buf).is_ok());
  }

  #[test]
  fn rejection_emits_and_validates_extra_headers() {
    let mut buf = [0u8; 256];

    let mut hs = classified(GOOD);
    let r = Rejection::new(403, "Forbidden").with_extra_headers(&[("Retry-After", "30")]);
    let n = hs.encode_rejection(&r, &mut buf).unwrap();
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

  /// Regression: a managed-name extra would put bytes on the wire
  /// that contradict the decision's `Negotiated` — an extra
  /// `Sec-WebSocket-Extensions: permessage-deflate` makes the peer compress
  /// against a connection configured without deflate. All managed names are
  /// rejected on the accept path.
  #[test]
  fn accept_rejects_managed_name_collisions() {
    let mut hs = accepted(GOOD, &Accept::new());
    let mut buf = [0u8; 512];
    for bad in [
      [("Sec-WebSocket-Accept", "spoof")],
      [("Sec-WebSocket-Extensions", "permessage-deflate")],
      [("Sec-WebSocket-Protocol", "chat")],
      [("Upgrade", "h2c")],
      [("Connection", "close")],
    ] {
      assert!(
        matches!(
          hs.encode_response(&ExtraHeaders::from(&bad), &mut buf)
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
    let mut hs = classified(GOOD);
    let n = hs
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

  /// The 426 answer may advertise SEVERAL versions on several field lines, and
  /// the same rejection still may not carry two `Origin`s.
  ///
  /// RFC 6455 §11.3.5 states the response half itself: the field "MAY appear
  /// multiple times in an HTTP response (which is logically the same as a single
  /// |Sec-WebSocket-Version| header field that contains all values)", with
  /// `Sec-WebSocket-Version-Server = 1#version` (§4.3) for the ABNF and §4.4's
  /// "or multiple |Sec-WebSocket-Version| header fields" for the instruction. So
  /// the repeat screen must not reach the one managed name a rejection is exempt
  /// from — while `Origin`, which no role's ABNF makes a comma list, stays a
  /// singleton on every path that writes extras.
  #[test]
  fn a_rejection_may_advertise_several_versions_but_not_two_origins() {
    let mut buf = [0u8; 256];

    let several = Rejection::new(426, "Upgrade Required").with_extra_headers(&[
      ("Sec-WebSocket-Version", "13"),
      ("Sec-WebSocket-Version", "8"),
    ]);
    let mut hs = classified(GOOD);
    let n = hs.encode_rejection(&several, &mut buf).unwrap();
    let head = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      head.contains("\r\nSec-WebSocket-Version: 13\r\n"),
      "{head:?}"
    );
    assert!(
      head.contains("\r\nSec-WebSocket-Version: 8\r\n"),
      "{head:?}"
    );

    let two_origins = Rejection::new(403, "Forbidden").with_extra_headers(&[
      ("Origin", "http://a.example"),
      ("Origin", "http://evil.example"),
    ]);
    assert!(matches!(
      ServerHandshake::new()
        .encode_rejection(&two_origins, &mut buf)
        .unwrap_err(),
      ServerHandshakeError::InvalidResponseOption("extra header repeats a field name")
    ));
  }

  /// Regression: the managed rejection reason-phrase gets the
  /// same control screen as the extras (RFC 9112 §4 grammar) — not just
  /// CR/LF.
  #[test]
  fn rejection_reason_control_bytes_are_rejected() {
    let mut buf = [0u8; 256];
    for bad in ["For\x07bidden", "For\0bidden", "For\x7Fbidden"] {
      assert!(
        matches!(
          ServerHandshake::new().encode_rejection(&Rejection::new(403, bad), &mut buf),
          Err(ServerHandshakeError::InvalidResponseOption(
            "reason contains control bytes"
          ))
        ),
        "{bad:?}"
      );
    }
    // SP and HTAB are legal reason-phrase bytes.
    let mut hs = classified(GOOD);
    assert!(
      hs.encode_rejection(&Rejection::new(403, "Not\tToday Friend"), &mut buf)
        .is_ok()
    );
  }

  /// Regression: outbound extra-header values follow the
  /// RFC 9110 §5.5 field-value grammar — C0 controls (except HTAB) and DEL
  /// are rejected at validation time, exactly mirroring what the inbound
  /// parser screens. HTAB and obs-text stay legal.
  #[test]
  fn extra_header_value_control_bytes_are_rejected() {
    let mut hs = accepted(GOOD, &Accept::new());
    let mut buf = [0u8; 512];
    for bad in [
      [("X-Bell", "a\x07b")],
      [("X-Nul", "a\0b")],
      [("X-Del", "a\x7Fb")],
    ] {
      assert!(
        matches!(
          hs.encode_response(&ExtraHeaders::from(&bad), &mut buf)
            .unwrap_err(),
          ServerHandshakeError::InvalidResponseOption("extra header value contains control bytes")
        ),
        "{bad:?}"
      );
    }

    // HTAB (legal field-value byte) and obs-text (0x80+) still pass.
    let mut hs = accepted(GOOD, &Accept::new());
    let (n, _) = hs
      .encode_response(
        &ExtraHeaders::from(&[("X-Tab", "a\tb"), ("X-Obs", "café")]),
        &mut buf,
      )
      .unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.contains("\r\nX-Tab: a\tb\r\n"), "{resp:?}");
    assert!(resp.contains("\r\nX-Obs: café\r\n"), "{resp:?}");
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

  /// RFC 6455 §9.1: "If a value is received by either the client or the server
  /// during negotiation that does not conform to the ABNF below, the recipient
  /// of such malformed data MUST immediately _Fail the WebSocket Connection_."
  ///
  /// Not "decline the extension": §9.1's freedom to decline is about an
  /// extension a server does not WANT, and it does not reach data the server
  /// cannot READ. The gate runs during classification, before the application
  /// is ever asked, and independently of which extensions this build supports —
  /// so a `--no-default-features` server refuses the same bytes a deflate one
  /// does.
  #[test]
  fn a_malformed_extension_list_fails_the_handshake() {
    for bad in [
      // A quoted-string that never closes.
      "permessage-deflate; x=\"open",
      // A member name that is not a token.
      "x@y",
      // A quoted value whose unescaped form is not a token.
      "permessage-deflate; x=\"a b\"",
      // `extension-list = 1#extension` — the field names nothing.
      "",
      // `extension = extension-token *( ";" extension-param )` — a semicolon
      // with no parameter behind it, which RFC 9110 §5.6.6's `[ parameter ]`
      // would have allowed. Refused rather than declined: §9.1 makes malformed
      // data fail the connection.
      "permessage-deflate;",
      "permessage-deflate;;client_max_window_bits",
    ] {
      let raw = replaced(
        "Sec-WebSocket-Version: 13\r\n",
        &format!("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: {bad}\r\n"),
      );
      assert!(
        matches!(
          ServerHandshake::new().handle(&raw).unwrap_err(),
          ServerHandshakeError::MalformedExtensions
        ),
        "{bad:?}"
      );
    }

    // A value that spans the RFC 9110 §5.2 join is malformed at THIS layer:
    // the join's comma becomes part of the value §9.1 requires to unescape to
    // a token, and a comma is not a tchar. (http1-proto keeps it as its own
    // outcome, because down there the value is well formed and merely not
    // contiguous.)
    let split = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; x=\"a\r\n\
       Sec-WebSocket-Extensions: b\"\r\n",
    );
    assert!(matches!(
      ServerHandshake::new().handle(&split).unwrap_err(),
      ServerHandshakeError::MalformedExtensions
    ));

    // The empty parameter slot is refused by the gate AND unreadable to the
    // negotiation behind it, because both ask RFC 6455 §9.1's one grammar.
    // Not `is_some()`: a negotiation walking RFC 9110 §5.6.6 instead, where the
    // parameter after a `;` is optional, grants a value the gate called
    // malformed.
    #[cfg(feature = "deflate")]
    assert!(
      crate::negotiation::accept_deflate_offer(
        [b"permessage-deflate;".as_slice()],
        &crate::negotiation::ServerDeflateConfig::new()
      )
      .is_none(),
      "the gate and the negotiation read one grammar"
    );

    // The refusal is answerable: §4.2.1 requires "an HTTP response with an
    // appropriate error code", so the connection stays reject-only.
    let raw = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: x@y\r\n",
    );
    let mut hs = ServerHandshake::new();
    assert!(hs.handle(&raw).is_err());
    let mut buf = [0u8; 256];
    let n = hs
      .encode_rejection(&Rejection::new(400, "Bad Request"), &mut buf)
      .unwrap();
    assert!(
      core::str::from_utf8(&buf[..n])
        .unwrap()
        .starts_with("HTTP/1.1 400 Bad Request\r\n")
    );
  }

  /// The other half of §9.1: a well-formed offer this server cannot use is
  /// DECLINED, not refused. Including the implied-*LWS spellings §9.1 admits
  /// and RFC 9110 §5.6.6's `parameter` does not — those are now READ, since the
  /// gate and the negotiation share §9.1's grammar, and
  /// `server_max_window_bits = 11` is declined for the reason an unspaced
  /// `=11` would be: a sub-15 window this server's compressor cannot honour.
  #[test]
  fn a_conforming_extension_list_is_declined_rather_than_refused() {
    for good in [
      "x-private; a; b=c",
      "permessage-deflate; server_max_window_bits = 11",
      "permessage-deflate; x=\"1\\2\"",
    ] {
      let raw = replaced(
        "Sec-WebSocket-Version: 13\r\n",
        &format!("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: {good}\r\n"),
      );
      let v = view(&raw);
      assert_eq!(
        v.extensions().collect::<Vec<_>>(),
        [good.as_bytes()],
        "{good:?}"
      );
      // …and the negotiation layer declines rather than failing: no grant,
      // no 400.
      #[cfg(feature = "deflate")]
      assert!(
        crate::negotiation::accept_deflate_offer(
          v.extensions(),
          &crate::negotiation::ServerDeflateConfig::new()
        )
        .is_none(),
        "{good:?}"
      );
    }
  }

  #[cfg(feature = "deflate")]
  #[test]
  fn deflate_accept_flow() {
    use crate::negotiation::{ServerDeflateConfig, accept_deflate_offer};

    let raw = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
    );

    let config = ServerDeflateConfig::new();
    let mut hs = ServerHandshake::new();
    let (params, response) = {
      let ServerProgress::Upgrade(mut pending) = hs.handle(&raw).unwrap() else {
        panic!("complete request")
      };
      let (params, response) =
        accept_deflate_offer(pending.request().extensions(), &config).unwrap();
      assert_eq!(params.client_max_window_bits(), 15);
      pending
        .validate_accept(&Accept::new().with_deflate(Some(response)))
        .unwrap();
      (params, response)
    };

    let mut buf = [0u8; 512];
    let (n, negotiated) = hs.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    let resp = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      resp.contains("\r\nSec-WebSocket-Extensions: permessage-deflate\r\n"),
      "{resp}"
    );
    assert_eq!(negotiated.deflate(), Some(params));

    // Regression: the grant is REQUEST-BOUND — replaying the
    // DeflateResponse onto a request with NO deflate offer is an error, not
    // an RSV1 surprise for the peer.
    let mut plain = ServerHandshake::new();
    let ServerProgress::Upgrade(mut pending) = plain.handle(GOOD).unwrap() else {
      panic!("complete request")
    };
    assert!(matches!(
      pending
        .validate_accept(&Accept::new().with_deflate(Some(response)))
        .unwrap_err(),
      ServerHandshakeError::ExtensionNotOffered
    ));

    // Param-level binding: a grant whose params the request's offer cannot
    // legalize is rejected too — not just the no-offer case. A response
    // carrying client_max_window_bits=10 (minted from an offer that
    // declared it) is illegal against a bare permessage-deflate offer
    // (§7.1.2.2: MUST NOT include it when the offer lacked the param).
    let cmwb_raw = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=10\r\n",
    );
    let cmwb_view = view(&cmwb_raw);
    let (_, cmwb_response) = accept_deflate_offer(cmwb_view.extensions(), &config).unwrap();
    let bare_raw = replaced(
      "Sec-WebSocket-Version: 13\r\n",
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n",
    );
    let mut bare = ServerHandshake::new();
    let ServerProgress::Upgrade(mut bare_pending) = bare.handle(&bare_raw).unwrap() else {
      panic!("complete request")
    };
    assert!(matches!(
      bare_pending
        .validate_accept(&Accept::new().with_deflate(Some(cmwb_response)))
        .unwrap_err(),
      ServerHandshakeError::ExtensionNotOffered
    ));

    // Declining: no header, no deflate.
    let mut hs = accepted(&raw, &Accept::new());
    let (n, negotiated) = hs.encode_response(&ExtraHeaders::new(), &mut buf).unwrap();
    assert!(
      !core::str::from_utf8(&buf[..n])
        .unwrap()
        .contains("Sec-WebSocket-Extensions")
    );
    assert!(negotiated.deflate().is_none());
  }

  /// The consumer side of the mode EDGE: a request read through a
  /// `Connection<Server, General>` and carried into the
  /// `Connection<Server, Tunnel>` that answers it.
  ///
  /// Its own module because every fixture here is a request driven through the
  /// General pump rather than fed to [`ServerHandshake::handle`], and because
  /// the argument the tests make is one argument: what
  /// [`ServerHandshake::classify`] cannot be told by the type system — that the
  /// head it is handed is the head the connection read — it states as a rule.
  mod adopted {
    use super::*;
    use http1_proto::{General, Item, StartLine};

    /// A conforming RFC 6455 §4.2.1 upgrade request, on the HTTP/1.1 RFC 9110
    /// §7.8 requires.
    const UPGRADE: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    /// The same, stating RFC 9110 §10.1.1's expectation — so §7.8 orders a
    /// `100 (Continue)` before the 101 and the connection carries the
    /// obligation across the transition.
    const UPGRADE_WITH_EXPECT: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Expect: 100-continue\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    /// Two conforming requests whose keys differ, so a `Sec-WebSocket-Accept`
    /// written for one is visibly not the other's.
    const UPGRADE_A: &[u8] = UPGRADE;
    const UPGRADE_B: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    /// RFC 6455 §4.2.1 item 6 wants 13; this states 8, which §4.2.2 answers
    /// with the 426.
    const BAD_VERSION: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 8\r\n\
\r\n";

    /// `UPGRADE` with only the HTTP version changed, so a refusal pins the
    /// version and nothing else. RFC 9110 §7.8: "A server that receives an
    /// Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade
    /// field."
    const UPGRADE_HTTP_10: &[u8] = b"GET /chat HTTP/1.0\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    /// `UPGRADE` with only §7.8's `Connection` half removed: the `Upgrade`
    /// field still names websocket, so the offer is half-stated.
    const UPGRADE_WITHOUT_CONNECTION_TOKEN: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: keep-alive\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    /// Pulls one request to exhaustion through the General pump, keeping the
    /// head the driver was handed and reporting what the pump consumed.
    ///
    /// No request-line comes back beside it: `classify` derives that from the
    /// head, so a test that carried one would be carrying a value the API no
    /// longer has a place for.
    fn read_request<'a>(
      general: &mut Connection<Server, General>,
      req: &'a [u8],
    ) -> (HeadView<'a>, usize) {
      let mut items = general.handle(req);
      let mut head = None;
      while let Some(item) = items.next().expect("the fixture is a conforming request") {
        if let Item::Head {
          view,
          line: StartLine::Request(_),
          ..
        } = item
        {
          head = Some(view);
        }
      }
      (head.expect("one complete request head"), items.consumed())
    }

    /// Drives a General server over `req`, keeps what the pump handed out, and
    /// takes the mode edge — so what comes back is what a caller of
    /// `into_tunnel` holds when it reaches this handshake.
    ///
    /// `discharge` sends RFC 9110 §7.8's `100 (Continue)` before the
    /// transition. §15.2 makes a 1xx not the answer, so the obligation is spent
    /// while the answer stays owed and the edge still switches.
    ///
    /// The lifetimes are the CALLER's `req`, not an internal buffer: a function
    /// cannot return a view borrowing its own local, so the caller's slice is
    /// fed straight in.
    fn edged(req: &[u8], discharge: bool) -> (Connection<Server, Tunnel>, HeadView<'_>, &[u8]) {
      let mut general = Connection::<Server, General>::new();
      let (head, consumed) = read_request(&mut general, req);
      if discharge {
        let mut out = [0u8; 64];
        general
          .send_interim(CONTINUE, NO_HEADERS, &mut out)
          .expect("RFC 9110 §7.8's 100 goes out before the 101");
      }
      let tunnel = general
        .into_tunnel()
        .expect("a completely read request that offered a switch");
      (tunnel, head, req.get(consumed..).unwrap_or_default())
    }

    fn server_edged(req: &[u8]) -> (Connection<Server, Tunnel>, HeadView<'_>, &[u8]) {
      edged(req, false)
    }

    fn server_edged_with_continue_already_sent(
      req: &[u8],
    ) -> (Connection<Server, Tunnel>, HeadView<'_>, &[u8]) {
      edged(req, true)
    }

    /// A head parsed WITHOUT transitioning anything: what a test hands
    /// `classify` when the head is meant to be one the connection never read.
    fn head_of(bytes: &[u8]) -> HeadView<'_> {
      let mut general = Connection::<Server, General>::new();
      read_request(&mut general, bytes).0
    }

    #[test]
    fn an_adopted_connection_classifies_the_request_it_carries() {
      let (conn, head, leftover) = server_edged(UPGRADE);
      let mut hs = ServerHandshake::adopt(conn);
      let ServerProgress::Upgrade(pending) = hs.classify(&head, leftover).unwrap() else {
        panic!("a conforming §4.1 request")
      };
      assert_eq!(pending.request().key(), b"dGhlIHNhbXBsZSBub25jZQ==");
    }

    /// The obligation the mode edge carries across the seam must survive the
    /// consumer: without the mirror, `encode_response` skips the 100 and the
    /// connection refuses the 101 it was ordered before.
    #[test]
    fn an_adopted_expect_carrying_upgrade_writes_the_100_before_the_101() {
      let (conn, head, leftover) = server_edged(UPGRADE_WITH_EXPECT);
      let mut hs = ServerHandshake::adopt(conn);
      let mut out = [0u8; 512];
      let n = {
        let ServerProgress::Upgrade(mut pending) = hs.classify(&head, leftover).unwrap() else {
          panic!("a conforming §4.1 request")
        };
        pending.validate_accept(&Accept::new()).unwrap();
        hs.encode_response(&ExtraHeaders::new(), &mut out)
          .unwrap()
          .0
      };
      let written = core::str::from_utf8(&out[..n]).unwrap();
      assert!(
        written.starts_with("HTTP/1.1 100 "),
        "RFC 9110 §7.8 orders the 100 first: {written}"
      );
      assert!(
        written.contains("HTTP/1.1 101 "),
        "and the 101 follows it: {written}"
      );
    }

    /// RFC 6455 §4.2.2's cross-pairing, reached without crossing two
    /// handshakes and without leaving one entry point.
    ///
    /// It also pins the ORDER the two refusals stand in. B's head would fail the
    /// head-to-connection binding as surely as it fails the latch, and the latch
    /// is what must answer: the offer is spent, and a binding failure reported
    /// here would say it is still open and a corrected pairing still possible.
    #[test]
    fn a_second_classify_is_refused_so_an_answer_cannot_cross_requests() {
      let (conn, head_a, left_a) = server_edged(UPGRADE_A);
      let mut hs = ServerHandshake::adopt(conn);
      hs.classify(&head_a, left_a).unwrap();
      let (_, head_b, left_b) = server_edged(UPGRADE_B);
      assert!(matches!(
        hs.classify(&head_b, left_b),
        Err(ServerHandshakeError::AlreadyClassified)
      ));
    }

    /// A refused pairing still owes its peer RFC 6455 §4.2.1's "HTTP response
    /// with an appropriate error code", so the handshake survives reject-only.
    /// What it does NOT leave is a second attempt on the same handshake — that
    /// offer is spent — so a caller that wants to pre-validate several heads
    /// spends a `ServerHandshake` per head, which costs nothing and is the
    /// recipe [`adopt`](ServerHandshake::adopt) documents.
    #[test]
    fn a_failed_classify_leaves_the_handshake_answerable() {
      let (conn, bad_head, bad_left) = server_edged(BAD_VERSION);
      let mut hs = ServerHandshake::adopt(conn);
      assert!(matches!(
        hs.classify(&bad_head, bad_left),
        Err(ServerHandshakeError::UnsupportedVersion)
      ));

      let mut out = [0u8; 256];
      let n = hs
        .encode_rejection(&Rejection::unsupported_version(), &mut out)
        .unwrap();
      assert!(out[..n].starts_with(b"HTTP/1.1 426 "));

      // A corrected pairing is classified by a FRESH handshake; the one above
      // has spent its offer, which `a_failed_classify_spends_the_offer_too`
      // pins.
      let (conn2, head, leftover) = server_edged(UPGRADE);
      let mut hs2 = ServerHandshake::adopt(conn2);
      assert!(hs2.classify(&head, leftover).is_ok());
    }

    /// The version tripwire, on the path where it is the whole of the
    /// protection rather than residue: a THROWAWAY connection classified
    /// nothing, so `head_binding` answers `NoHandshake` and no identity check
    /// runs ahead of it.
    ///
    /// Pairing this head with an ARMED connection would be refused by the
    /// binding first — correctly, since a 1.0 head is definitively not the 1.1
    /// request such a connection read — which is why the tripwire is pinned
    /// here.
    #[test]
    fn the_version_tripwire_catches_a_ten_head() {
      let mut hs = ServerHandshake::adopt(Connection::<Server, Tunnel>::new());
      assert!(matches!(
        hs.classify(&head_of(UPGRADE_HTTP_10), &[]),
        Err(ServerHandshakeError::UnsupportedHttpVersion)
      ));
    }

    /// The `Connection: upgrade` tripwire, on the same path and for the same
    /// reason: `http1-proto` never read this head, so nothing but this check
    /// states RFC 9110 §7.8's other half.
    #[test]
    fn the_offer_tripwire_catches_a_head_missing_a_seven_eight_half() {
      let mut hs = ServerHandshake::adopt(Connection::<Server, Tunnel>::new());
      // `Upgrade: websocket` present, `Connection` does not contain `upgrade`.
      assert!(matches!(
        hs.classify(&head_of(UPGRADE_WITHOUT_CONNECTION_TOKEN), &[]),
        Err(ServerHandshakeError::NotAnUpgrade)
      ));
    }

    /// The `Expect` tripwire, at its own seam rather than through `classify`.
    ///
    /// Its refusing direction is UNREACHABLE end-to-end, and that is a property
    /// of the binding rather than a gap: the only heads that reach the check are
    /// heads whose own bytes armed the connection, and identical bytes state an
    /// identical expectation. A `classify`-level test of it would need a digest
    /// collision. All four combinations are pinned on the function instead —
    /// including the LEGAL converse, which `a_discharged_expectation_is_not_a_
    /// tripwire` also drives end-to-end.
    #[test]
    fn the_expect_tripwire_is_one_directional() {
      let states = RequestFields::new(head_of(UPGRADE_WITH_EXPECT));
      let silent = RequestFields::new(head_of(UPGRADE));

      // Owed and stated: the pair agrees.
      assert!(expectation_matches(true, &states));
      // Owed and NOT stated: the head describes some other request.
      assert!(!expectation_matches(true, &silent));
      // Not owed, whatever the head says. RFC 9110 §15.2 makes the 1xx not the
      // answer, so a 100 already sent leaves a stating head conforming.
      assert!(expectation_matches(false, &states));
      assert!(expectation_matches(false, &silent));
    }

    /// `UPGRADE` offering a subprotocol, so a 101 answering a DIFFERENT request
    /// out of this one's grants is visibly the §4.2.2 violation rather than a
    /// difference only the key shows.
    const UPGRADE_WITH_OFFER: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Protocol: superchat\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    /// The crossing the latch has to be SHARED to refuse, and the reason a
    /// guard on `classify` alone is not the rule it looks like.
    ///
    /// `classify` never advances the connection, so on a handshake whose
    /// connection is still idle — what [`ServerHandshake::adopt`] takes when the
    /// caller has not transitioned, and what `new` starts at — `handle`'s own
    /// idle gate is still open after a `classify` succeeded. Left open, the
    /// sequence below arms the connection with B's request behind A's validated
    /// answer and RFC 6455 §4.2.2's "The value chosen MUST be derived from the
    /// client's handshake" is broken by a 101 that every call returned `Ok` for.
    #[test]
    fn a_handle_after_a_classify_cannot_cross_an_answer_onto_a_second_request() {
      let mut hs = ServerHandshake::adopt(Connection::<Server, Tunnel>::new());
      let head = head_of(UPGRADE_WITH_OFFER);
      let ServerProgress::Upgrade(mut pending) = hs.classify(&head, &[]).unwrap() else {
        panic!("a conforming §4.1 request")
      };
      pending
        .validate_accept(&Accept::new().with_subprotocol(Some("superchat")))
        .unwrap();

      // B carries a different key and offers no subprotocol at all.
      assert!(matches!(
        hs.handle(UPGRADE_B),
        Err(ServerHandshakeError::AlreadyClassified)
      ));

      // The refusal is what leaves the connection unarmed, so there is no 101
      // for the crossing to ride out on.
      let mut out = [0u8; 512];
      assert!(hs.encode_response(&ExtraHeaders::new(), &mut out).is_err());
    }

    /// The mirror image. `classify` never ADVANCES the connection, so the idle
    /// gate that stopped a second `handle` reaches nothing on this side, and the
    /// latch is what answers. The head-to-connection binding would refuse THIS
    /// pair as well — A armed the connection and B's head is not A's — but it
    /// refuses nothing on the unarmed connection the test above uses, so the
    /// latch is the only guard covering both directions. Removing either entry
    /// point's read of it fails that direction and leaves the other green, which
    /// is why both are pinned.
    #[test]
    fn a_classify_after_a_handle_cannot_cross_an_answer_onto_a_second_request() {
      let mut hs = ServerHandshake::new();
      let ServerProgress::Upgrade(mut pending) = hs.handle(UPGRADE_WITH_OFFER).unwrap() else {
        panic!("a conforming §4.1 request")
      };
      pending
        .validate_accept(&Accept::new().with_subprotocol(Some("superchat")))
        .unwrap();

      assert!(matches!(
        hs.classify(&head_of(UPGRADE_B), &[]),
        Err(ServerHandshakeError::AlreadyClassified)
      ));

      // And the answer that survives is A's, paired with A's own key: the 101
      // states the subprotocol A offered and the accept value A's key derives.
      let mut out = [0u8; 512];
      let (n, negotiated) = hs.encode_response(&ExtraHeaders::new(), &mut out).unwrap();
      let written = core::str::from_utf8(&out[..n]).unwrap();
      assert_eq!(negotiated.subprotocol(), Some("superchat"));
      assert!(
        written.contains("\r\nSec-WebSocket-Protocol: superchat\r\n"),
        "{written}"
      );
      let expected = accept_value(b"dGhlIHNhbXBsZSBub25jZQ==");
      assert!(
        written.contains(core::str::from_utf8(&expected).unwrap()),
        "{written}"
      );
    }

    /// One-directional: this head is legal, not a mismatch. RFC 9110 §15.2
    /// makes the 1xx not the answer, so a 100 sent before the transition
    /// discharges §7.8's ordering MUST while leaving the answer owed.
    #[test]
    fn a_discharged_expectation_is_not_a_tripwire() {
      let (conn, head, leftover) = server_edged_with_continue_already_sent(UPGRADE_WITH_EXPECT);
      let mut hs = ServerHandshake::adopt(conn);
      assert!(hs.classify(&head, leftover).is_ok());
    }

    /// A conforming RFC 9110 §7.8 upgrade offering a protocol this crate does
    /// not speak. `http1-proto` classifies it and arms the connection with it —
    /// §7.8's rule is that both halves are present and that SOME protocol is
    /// named, not which one — so the connection is committed before RFC 6455
    /// §4.2.1 gets a say.
    const H2C_UPGRADE: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: h2c\r\n\
Connection: Upgrade\r\n\
\r\n";

    /// A websocket upgrade `http1-proto` arms the connection with and RFC 6455
    /// §4.2.1 item 5 then refuses.
    const UPGRADE_BAD_KEY: &[u8] = b"GET /chat HTTP/1.1\r\n\
Host: server.example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: not-a-key\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";

    /// RFC 9110 §9.3.6's other takeover, which arms the connection as a CONNECT
    /// tunnel rather than an upgrade.
    const CONNECT_REQUEST: &[u8] = b"CONNECT server.example.com:443 HTTP/1.1\r\n\
Host: server.example.com:443\r\n\
\r\n";

    /// The class, at its sharpest: A is not a websocket request at all, so this
    /// layer refuses it — but `http1-proto` has already armed the connection
    /// with it, so the offer is spent and B cannot be answered on a connection
    /// whose client asked for `h2c`. RFC 9110 §7.8: a server must not switch to
    /// a protocol the client did not indicate IN THAT REQUEST.
    ///
    /// The head-to-connection binding refuses this pair too. What the latch
    /// adds is that it refuses BEFORE the connection is consulted, and on the
    /// unarmed connections the binding cannot speak for.
    #[test]
    fn a_generic_upgrade_this_layer_refuses_still_spends_the_offer() {
      let mut hs = ServerHandshake::new();
      assert!(matches!(
        hs.handle(H2C_UPGRADE),
        Err(ServerHandshakeError::NotAnUpgrade)
      ));
      assert!(matches!(
        hs.classify(&head_of(UPGRADE_B), &[]),
        Err(ServerHandshakeError::AlreadyClassified)
      ));
      // …and with nothing classified there is no answer, so no 101 either.
      let mut out = [0u8; 512];
      assert!(hs.encode_response(&ExtraHeaders::new(), &mut out).is_err());
    }

    /// The same shape reached through a WebSocket request that arms the
    /// connection and then fails a §4.2.1 gate: the offer is spent by the
    /// arming, not by the validation that follows it.
    #[test]
    fn a_websocket_upgrade_that_fails_a_later_gate_still_spends_the_offer() {
      let mut hs = ServerHandshake::new();
      assert!(matches!(
        hs.handle(UPGRADE_BAD_KEY),
        Err(ServerHandshakeError::InvalidKey)
      ));
      assert!(matches!(
        hs.classify(&head_of(UPGRADE_B), &[]),
        Err(ServerHandshakeError::AlreadyClassified)
      ));
    }

    /// A CONNECT arms the connection as RFC 9110 §9.3.6's tunnel, and that
    /// spends the offer as any other request the connection takes does.
    ///
    /// The disagreement it forecloses — a `classify` reporting a websocket
    /// handshake this layer would answer while `accept` wrote the CONNECT 2xx —
    /// is also foreclosed by the binding, which refuses EVERY head on a
    /// CONNECT-armed connection
    /// (`a_connect_armed_connection_matches_no_head_at_all`). What this pins is
    /// that the latch answers first, so the rule does not turn on which head
    /// the caller happened to pass.
    #[test]
    fn a_connect_still_spends_the_offer() {
      let mut hs = ServerHandshake::new();
      assert!(matches!(
        hs.handle(CONNECT_REQUEST),
        Err(ServerHandshakeError::NotAGet)
      ));
      assert!(matches!(
        hs.classify(&head_of(UPGRADE_B), &[]),
        Err(ServerHandshakeError::AlreadyClassified)
      ));
    }

    /// A failed `classify` spends the offer as surely as a successful one, and
    /// no `handle` is involved: the connection was armed by A before `adopt`
    /// was called at all.
    ///
    /// There is exactly ONE armed request on the connection, so there is exactly
    /// one correct head — and nothing here can show that a second head is it. A
    /// retry that might be legitimate is indistinguishable from an attempt to
    /// answer a different request on this connection, so the retry is refused
    /// and the driver rejects instead.
    #[test]
    fn a_failed_classify_spends_the_offer_too() {
      let (conn, _, leftover) = server_edged(UPGRADE);
      let mut hs = ServerHandshake::adopt(conn);
      // The 1.0 head is not the request this connection read, and the binding
      // is what says so — the version tripwire behind it would say the same.
      assert!(matches!(
        hs.classify(&head_of(UPGRADE_HTTP_10), leftover),
        Err(ServerHandshakeError::HeadMismatch)
      ));
      // Even the RIGHT head is refused now: the offer went with the attempt.
      assert!(matches!(
        hs.classify(&head_of(UPGRADE), leftover),
        Err(ServerHandshakeError::AlreadyClassified)
      ));
    }

    /// The control the arming point exists to keep working: `NeedMore` consumed
    /// no request, so the offer is still open and the driver's
    /// accumulate-and-re-offer loop still reaches a classification. Arming there
    /// would break the one sequence every h1 driver runs.
    #[test]
    fn need_more_does_not_spend_the_offer() {
      let mut hs = ServerHandshake::new();
      for cut in [1usize, 10, UPGRADE.len() - 1] {
        assert!(
          matches!(
            hs.handle(&UPGRADE[..cut]).unwrap(),
            ServerProgress::NeedMore
          ),
          "cut {cut}"
        );
      }
      assert!(matches!(
        hs.handle(UPGRADE).unwrap(),
        ServerProgress::Upgrade(_)
      ));
    }

    /// The other control: a peer that closed WITHOUT sending a request consumed
    /// none either, so `handle_eof` and the [`ServerProgress::Closed`] it
    /// resolves to leave the offer open.
    #[test]
    fn an_eof_with_no_request_does_not_spend_the_offer() {
      let mut hs = ServerHandshake::new();
      hs.handle_eof().unwrap();
      assert!(matches!(hs.handle(b"").unwrap(), ServerProgress::Closed));
      assert!(hs.classify(&head_of(UPGRADE), &[]).is_ok());
    }

    /// Spending the offer must not cost the driver the answer it owes: RFC 6455
    /// §4.2.1 wants "an HTTP response with an appropriate error code" for a
    /// request this layer refuses, from EITHER entry point.
    #[test]
    fn a_spent_offer_still_writes_the_rejection_it_owes() {
      let mut out = [0u8; 256];

      // Refused by `handle`, on a connection its own request armed.
      let mut hs = ServerHandshake::new();
      assert!(hs.handle(UPGRADE_BAD_KEY).is_err());
      let n = hs
        .encode_rejection(&Rejection::new(400, "Bad Request"), &mut out)
        .unwrap();
      assert!(out[..n].starts_with(b"HTTP/1.1 400 "));

      // Refused by `classify`, on a connection the caller transitioned: the
      // head is this connection's own, and RFC 6455 §4.2.1 item 6 turns it down.
      let (conn, bad_head, leftover) = server_edged(BAD_VERSION);
      let mut hs = ServerHandshake::adopt(conn);
      assert!(hs.classify(&bad_head, leftover).is_err());
      let n = hs
        .encode_rejection(&Rejection::unsupported_version(), &mut out)
        .unwrap();
      assert!(out[..n].starts_with(b"HTTP/1.1 426 "));
    }

    /// The head-to-connection binding, and the three silent misuses it closes.
    ///
    /// Without it every one of them returns `Ok` from every call. None is
    /// reachable by a PEER through the protocol — each needs the caller to hand
    /// over material that did not come from its own connection — but "the
    /// application must not make this mistake" is the obligation
    /// `PendingUpgrade` exists so as not to hand out, and this is the same rule
    /// for the half no signature can state.
    mod binding {
      use super::*;
      use http1_proto::{Client, ClientTunnelOutcome};

      /// Outcome 1, WRONG PROTOCOL. The connection was armed by a request
      /// offering only `h2c` — `http1-proto` is protocol-agnostic, so RFC 9110
      /// §7.8's "some protocol is named" is all it asks — and the head is a
      /// conforming WebSocket request the client never sent. Answered, it is a
      /// 101 for a protocol the client did not indicate: §7.8's MUST, broken.
      #[test]
      fn a_head_naming_websocket_cannot_answer_an_h2c_armed_connection() {
        let (conn, _, leftover) = server_edged(H2C_UPGRADE);
        let mut hs = ServerHandshake::adopt(conn);
        assert!(matches!(
          hs.classify(&head_of(UPGRADE), leftover),
          Err(ServerHandshakeError::HeadMismatch)
        ));
      }

      /// Outcome 2, WRONG REQUEST AND RIGHT PROTOCOL — the case the content
      /// tripwires cannot see, since both heads state every §7.8 and §4.2.1 fact
      /// identically and differ only in WHICH request they are.
      ///
      /// The server-side damage is the worse half: an answer written here
      /// derives its `Sec-WebSocket-Accept` from B's key and configures a
      /// `Negotiated` out of B's offers, on a connection whose wire peer sent A
      /// — a frame-layer desync, of which an honest client's own §4.1 accept
      /// check catches only the visible part.
      #[test]
      fn a_head_from_another_websocket_request_is_refused() {
        let (conn, _, leftover) = server_edged(UPGRADE_A);
        let mut hs = ServerHandshake::adopt(conn);
        // A fresh handshake, so the latch is open and this refusal is the
        // binding's own rather than `AlreadyClassified` standing in for it.
        assert!(matches!(
          hs.classify(&head_of(UPGRADE_B), leftover),
          Err(ServerHandshakeError::HeadMismatch)
        ));
      }

      /// Outcome 3, WRONG TAKEOVER ENTIRELY. `handle_request` is public, so a
      /// caller can classify a CONNECT on the very connection it then adopts;
      /// the handshake is fresh, the latch is open, and the tripwires all pass
      /// on a synthetic WebSocket head.
      ///
      /// Unrefused, this layer answers `Ok(Negotiated)` while `encode_response`
      /// reaches `Connection::accept`, which for a CONNECT writes `200
      /// Connection Established` — the two ends disagreeing about what the
      /// connection became. A CONNECT made no §7.8 offer, so EVERY head
      /// mismatches it, its own included.
      #[test]
      fn a_connect_armed_connection_matches_no_head_at_all() {
        let mut conn = Connection::<Server, Tunnel>::new();
        let ServerTunnelRequest::Connect { .. } = conn
          .handle_request(CONNECT_REQUEST)
          .expect("a well-formed CONNECT with a port")
        else {
          panic!("a CONNECT classifies as RFC 9110 §9.3.6's takeover")
        };
        let mut hs = ServerHandshake::adopt(conn);
        assert!(matches!(
          hs.classify(&head_of(UPGRADE), &[]),
          Err(ServerHandshakeError::HeadMismatch)
        ));
      }

      /// …and the CONNECT connection refuses its OWN head too, which is what
      /// makes the answer a statement about the offer rather than about the
      /// bytes: a CONNECT made no upgrade offer for any head to be.
      #[test]
      fn a_connect_armed_connection_refuses_even_its_own_head() {
        let mut conn = Connection::<Server, Tunnel>::new();
        // Read off the tunnel rather than through `head_of`: a General server
        // refuses a CONNECT where it arrives, so this head has only one source.
        let ServerTunnelRequest::Connect { head, .. } = conn
          .handle_request(CONNECT_REQUEST)
          .expect("a well-formed CONNECT with a port")
        else {
          panic!("a CONNECT classifies as RFC 9110 §9.3.6's takeover")
        };
        assert_eq!(conn.head_binding(&head), HeadBinding::Mismatch);
      }

      /// The recipe `adopt` documents, unbroken: a throwaway connection
      /// classified nothing, so there is no armed request the head could
      /// contradict and every §4.2.1 check still runs.
      ///
      /// The property this pins is that `NoHandshake` PROCEEDS. A binding that
      /// refused it would refuse the only way to validate a head before
      /// spending a one-way transition, which is what makes the question
      /// three-valued rather than a `bool`.
      #[test]
      fn the_throwaway_pre_validation_recipe_still_classifies() {
        let conn = Connection::<Server, Tunnel>::new();
        assert_eq!(
          conn.head_binding(&head_of(UPGRADE)),
          HeadBinding::NoHandshake
        );
        let mut hs = ServerHandshake::adopt(conn);
        let ServerProgress::Upgrade(pending) = hs
          .classify(&head_of(UPGRADE), &[])
          .expect("a fresh connection contradicts no head")
        else {
          panic!("a conforming §4.1 request")
        };
        assert_eq!(pending.request().key(), b"dGhlIHNhbXBsZSBub25jZQ==");
      }

      /// A head with no RFC 9112 §3 request-line in it — a RESPONSE head, which
      /// the client tunnel hands back on a refusal — is diagnosed as that and
      /// not as a binding failure: an idle connection raises no binding question
      /// for it to have failed.
      #[test]
      fn a_response_head_is_not_a_request_head() {
        let mut client = Connection::<Client, Tunnel>::new();
        let mut out = [0u8; 256];
        let headers: &[(&str, &[u8])] = &[
          ("Host", b"example.com"),
          ("Upgrade", b"websocket"),
          ("Connection", b"upgrade"),
        ];
        client
          .open_upgrade(
            &Target::Origin {
              path_and_query: "/chat",
            },
            headers,
            &mut out,
          )
          .expect("a well-formed upgrade request");
        let ClientTunnelOutcome::Refused { head, .. } = client
          .handle_response(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
          .expect("a well-formed response head")
        else {
          panic!("a 400 refuses the switch")
        };
        assert!(head.request_line().is_none());

        let mut hs = ServerHandshake::adopt(Connection::<Server, Tunnel>::new());
        assert!(matches!(
          hs.classify(&head, &[]),
          Err(ServerHandshakeError::NotARequestHead)
        ));
      }
    }
  }
}
