//! Client side of the h1 opening handshake (RFC 6455 §4.1, §4.2.2 client
//! validation), driven by one `http1-proto` tunnel connection.
//!
//! The split between the two crates is the split between the two
//! specifications: `http1-proto` owns HTTP — the request head it writes, RFC
//! 9112 §3.2's `Host` rules, RFC 9110 §7.8's upgrade offer and the 101 that
//! answers it, and RFC 9110 §15.2's classification of everything else the
//! server may say — and this module owns what RFC 6455 adds on top: the
//! `Sec-WebSocket-Key`/`-Accept` SHA-1, the version, the subprotocol and
//! extension acceptance, and the check that the protocol the 101 names is the
//! one that was offered.
//!
//! # An interim response is progress, not a failure
//!
//! RFC 9110 §15.2 lets any number of 1xx responses precede the final one and
//! makes parsing them a client MUST, so [`ClientProgress::Interim`] reports
//! each one AND how far the buffer advanced past it. Both halves are load
//! bearing: a driver told only that an interim arrived cannot advance, so it
//! re-offers the same head and reads it forever.
//!
//! # A refusal is the peer's answer, not this crate's fault
//!
//! RFC 6455 §4.1 tells a client that did not get the switch to handle what it
//! did get "per HTTP procedures. In particular, the client might perform
//! authentication if it receives a 401 status code; the server might redirect
//! the client using a 3xx status code." Authenticating reads
//! `WWW-Authenticate`, redirecting reads `Location` — so a status code alone
//! answers neither, and a consumer holding only one would need a second head
//! parser just to find where the fields were.
//!
//! So a refusal is [`ClientProgress::Refused`], which says where its head
//! ended, and not an error. An error could not carry that offset honestly: it
//! is lifetime-free precisely so it can propagate past the buffer, where an
//! offset would index whatever happens to be at hand. The outcome stays where
//! the bytes still are, and the caller hands `data[..consumed]` to whatever
//! HTTP client it already has — which is all §4.1 asks of a WebSocket library.

use crate::{
  constants,
  error::BufferTooSmallDetail,
  handshake::{ExtraHeaders, accept_value, fields::ResponseFields},
  negotiation::{Negotiated, NegotiationError},
};
use derive_more::{Display, IsVariant, TryUnwrap};
use http1_proto::{
  Client, ClientTunnelOutcome, Connection, Headers, Target, Tunnel,
  grammar::{is_token, is_valid_authority, is_valid_path_and_query, token_list_contains},
};
use rand_core::Rng as RngCore;

/// The most the comma-joined `Sec-WebSocket-Protocol` request value may measure,
/// separators included. [`ClientHandshake::new`] refuses a longer offer list
/// with [`ClientHandshakeError::InvalidOptions`] rather than putting a head on
/// the wire for a peer to refuse.
///
/// # Why 512
///
/// The offers must reach the peer as ONE field line (RFC 9110 §5.3 makes the
/// repeated spelling the same field, but a head has a finite number of lines —
/// `http1-proto`'s own server caps a head at 64 of them), and a no-alloc
/// handshake can only join them into storage fixed at construction. So the
/// question is what that storage should measure:
///
/// - It is 8 × [`MAX_SUBPROTOCOL_LEN`](crate::negotiation::MAX_SUBPROTOCOL_LEN):
///   seven offers at the per-name cap this crate can retain, with 52 bytes to
///   spare. That cap is itself around three times the length of a long
///   registered name — RFC 6455 §11.5's registry runs to entries like
///   `syncpoint.timeline` (18 bytes) — so at lengths like that the value holds
///   25 offers, and 171 at the one-byte floor.
/// - `Sec-WebSocket-Protocol: ` and CRLF put the widest line at 538 bytes,
///   about 3% of the 16 KiB head an `http1-proto` peer reads, so the joined
///   field can never be why a head is refused.
/// - It keeps `ClientHandshake` under a kilobyte (760 bytes) on the bare
///   `no_std` tier, where it may sit on a task stack.
pub const MAX_SUBPROTOCOL_OFFER_BYTES: usize = 512;

/// The refusal, naming the limit. The assertion beside it keeps the number in
/// the message and the constant from drifting apart.
const TOO_MANY_SUBPROTOCOL_BYTES: &str =
  "subprotocol offers exceed 512 bytes when joined into one field value";
const _: () = assert!(MAX_SUBPROTOCOL_OFFER_BYTES == 512);

/// The other refusal: more offers than the crate's own gate will READ.
///
/// The byte cap above is this emitter's STORAGE limit; this one is the shared
/// work limit [`MAX_SUBPROTOCOL_OFFERS`](crate::negotiation::MAX_SUBPROTOCOL_OFFERS)
/// states for both transports and both directions. They are separate questions
/// and 512 bytes admits 171 one-byte offers, so without this check a request
/// this client encodes is one this crate's own server refuses — the emit/accept
/// asymmetry that keeps being found in a different field.
const TOO_MANY_SUBPROTOCOL_OFFERS: &str =
  "subprotocol offers exceed the 64 this crate reads from a peer";
const _: () = assert!(crate::negotiation::MAX_SUBPROTOCOL_OFFERS == 64);

/// The comma-joined `Sec-WebSocket-Protocol` value, built ONCE by
/// [`ClientHandshake::new`] and only read afterwards.
///
/// The [`Headers`] contract is that every walk of the section yields the
/// identical bytes, and the encoder walks three times — so a value formatted
/// into scratch DURING the walk is forbidden. A buffer written before the first
/// walk and never touched again is not: it is as stable as the `&str`s beside
/// it, which is what lets the offers travel as one field line instead of one
/// line each.
#[derive(Debug)]
struct OfferedSubprotocols {
  buf: [u8; MAX_SUBPROTOCOL_OFFER_BYTES],
  len: usize,
}

impl OfferedSubprotocols {
  const fn empty() -> Self {
    Self {
      buf: [0u8; MAX_SUBPROTOCOL_OFFER_BYTES],
      len: 0,
    }
  }

  /// Appends `bytes`; `false` when they do not fit.
  fn push(&mut self, bytes: &[u8]) -> bool {
    let end = self.len.saturating_add(bytes.len());
    let Some(slot) = self.buf.get_mut(self.len..end) else {
      return false;
    };
    for (dst, src) in slot.iter_mut().zip(bytes) {
      *dst = *src;
    }
    self.len = end;
    true
  }

  /// The joined value, or `None` when nothing was offered (no field line).
  fn value(&self) -> Option<&[u8]> {
    match self.len {
      0 => None,
      len => Some(self.buf.get(..len).unwrap_or_default()),
    }
  }
}

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
///
/// A server that will not switch is NOT one of these. RFC 6455 §4.1 makes its
/// answer something the caller acts on rather than a fault of this crate, so it
/// arrives as [`ClientProgress::Refused`] — with the offset that keeps its head
/// readable.
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

  /// The tunnel connection refused the request or the answer: a head that
  /// broke RFC 9110 / RFC 9112 grammar, a 101 that did not state both halves
  /// of RFC 9110 §7.8's switch, a peer that closed before answering, or a call
  /// this connection's phase does not allow.
  #[error(transparent)]
  Http(http1_proto::Error),

  /// The 101 named a protocol other than `websocket` in its `Upgrade` field,
  /// or the answer was not the switch this handshake asked for.
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
  /// §4.1 step 5 — fail the connection).
  #[error("server granted an unoffered extension")]
  ExtensionNotOffered,

  /// A `Sec-WebSocket-Extensions` field did not conform to RFC 6455 §9.1's
  /// ABNF, which the recipient of "such malformed data MUST immediately _Fail
  /// the WebSocket Connection_" over. §9.1 says "by either the client or the
  /// server", so this side enforces it on the 101 exactly as the server does on
  /// the request.
  #[error("malformed Sec-WebSocket-Extensions value")]
  MalformedExtensions,

  /// Retaining the negotiation result failed (bounded-tier storage).
  #[error("{0}")]
  Negotiation(#[from] NegotiationError),
}

/// Turns a tunnel-layer fault into this layer's error.
///
/// A short output buffer keeps this crate's own [`BufferTooSmall`] shape, so a
/// caller that sizes its buffer from the detail reads one kind of answer
/// whichever layer measured it. Everything else is the tunnel's verdict,
/// forwarded intact.
///
/// No `offset` to rebase past, unlike the server's: this side writes ONE head
/// into the caller's buffer, so nothing precedes the message that did not fit.
///
/// [`BufferTooSmall`]: ClientHandshakeError::BufferTooSmall
fn from_h1(error: http1_proto::Error) -> ClientHandshakeError {
  match error {
    http1_proto::Error::BufferTooSmall { need, have } => {
      ClientHandshakeError::BufferTooSmall(BufferTooSmallDetail::new(need, have))
    }
    // `http1_proto::Error` is `#[non_exhaustive]`: a fault this layer has no
    // WebSocket meaning for is the tunnel's to describe, and it is forwarded
    // rather than flattened into a guess.
    other => ClientHandshakeError::Http(other),
  }
}

/// How far into the offer the head the tunnel just read reached.
///
/// Every outcome that consumes a head hands back the bytes behind it verbatim,
/// so `leftover` is a suffix of `data` and the difference is the consumed
/// prefix. Saturating because this crate denies arithmetic that can wrap, not
/// because the subtraction has a second answer.
fn consumed(data: &[u8], leftover: &[u8]) -> usize {
  data.len().saturating_sub(leftover.len())
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
  ///
  /// Two bounds, and [`ClientHandshake::new`] refuses a list that breaks
  /// either: they travel as one comma-joined field line that must fit
  /// [`MAX_SUBPROTOCOL_OFFER_BYTES`], and there may be at most
  /// [`MAX_SUBPROTOCOL_OFFERS`](crate::negotiation::MAX_SUBPROTOCOL_OFFERS) of
  /// them — the count this crate's own server will read back.
  #[must_use]
  pub const fn with_subprotocols(mut self, subprotocols: &'a [&'a str]) -> Self {
    self.subprotocols = subprotocols;
    self
  }

  /// Additional request headers (auth, origin, cookies). Names must be
  /// tokens, must not collide with the managed handshake headers, and
  /// values must not contain CR/LF.
  ///
  /// **How many, and how large, is the RECEIVING peer's limit rather than
  /// this one**: nothing here is bounded — a large head violates nothing, and
  /// refusing to write one a lenient peer would accept is a rule no RFC has —
  /// but a `websocket-proto` server reads the request under
  /// [`http1_proto::MAX_HEADERS`] (64 field lines, of which the managed
  /// handshake spends five, or seven when subprotocols and an extension are
  /// offered) and [`http1_proto::MAX_HEAD_BYTES`] (16 KiB), so past either the
  /// answer is that peer's refusal rather than the switch.
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
///
/// Lifetime-free, and every variant that consumed a head says how far it
/// reached: a driver advances its buffer by that offset rather than by
/// re-finding the head itself.
///
/// No `TryUnwrap`: the two variants that report an unfinished or refused
/// handshake each carry two fields and a driver needs BOTH, so they are matched
/// rather than unwrapped — and an unwrap of the completion alone would turn an
/// interim response into the "not yet" arm, which is the read-it-forever loop
/// [`Interim`](Self::Interim) exists to prevent.
#[derive(Debug, IsVariant)]
#[non_exhaustive]
pub enum ClientProgress {
  /// The response head is not complete yet — read more bytes and call again
  /// with the whole accumulated buffer. Consumes nothing.
  NeedMore,
  /// An interim response arrived and was consumed; keep reading (RFC 9110
  /// §15.2: any number of them may precede the final answer).
  Interim {
    /// Which one — a `100 (Continue)` discharges an expectation, a `103 (Early
    /// Hints)` carries links to act on.
    status: u16,
    /// Bytes of the buffer it consumed; the next head starts here.
    consumed: usize,
  },
  /// The server will not switch, and this is the answer it sent instead (RFC
  /// 9110 §7.8: "Upgrade cannot be used to insist on a protocol change").
  ///
  /// TERMINAL for the handshake, and not an error: the peer answered, and RFC
  /// 6455 §4.1 makes what it said the caller's to act on — "the client might
  /// perform authentication if it receives a 401 status code; the server might
  /// redirect the client using a 3xx status code". Authenticating reads
  /// `WWW-Authenticate` and redirecting reads `Location`, so the status alone
  /// answers neither: `consumed` is what keeps them reachable. The refusal's
  /// head is the offered buffer BELOW this offset — hand it to whatever HTTP
  /// client the caller already has — and the response's content begins at it.
  ///
  /// A 1xx can appear here. RFC 9112 §9.6 makes a sender of the `close`
  /// connection option close "after it sends the response containing" it, and
  /// a 1xx is a response message — so an interim that states `close` has ended
  /// the handshake as surely as a 403 does, and the status is what tells the
  /// two apart.
  Refused {
    /// The status code of the refusing response.
    status: u16,
    /// Bytes of the buffer its head consumed: the head is everything below
    /// this offset, and the response's content everything at and beyond it.
    consumed: usize,
  },
  /// The switch happened.
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

/// The client side of the h1 opening handshake (RFC 6455 §4.1), driving one
/// `http1-proto` tunnel connection. Construct, write the request with
/// [`encode_request`], then feed the accumulating response buffer to
/// [`handle`] until it completes.
///
/// STATEFUL, and one instance serves ONE handshake: [`encode_request`] opens
/// the connection and [`handle`] advances it, so a response is classified
/// exactly once and the bytes cannot be replayed. What the answer is checked
/// against — the key, the offers, the extension offer — is kept here rather
/// than re-read from a buffer that has moved on.
///
/// [`encode_request`]: ClientHandshake::encode_request
/// [`handle`]: ClientHandshake::handle
#[derive(Debug)]
pub struct ClientHandshake<'a> {
  connection: Connection<Client, Tunnel>,
  options: ClientOptions<'a>,
  /// The `Sec-WebSocket-Key` this handshake sent (RFC 6455 §4.1). The expected
  /// `Sec-WebSocket-Accept` is derived from it when the 101 arrives — once per
  /// handshake, since no other outcome needs the SHA-1.
  key: [u8; constants::SEC_WEBSOCKET_KEY_LEN],
  /// The offers as one field value, joined at construction (see
  /// [`OfferedSubprotocols`]).
  subprotocols: OfferedSubprotocols,
}

impl<'a> ClientHandshake<'a> {
  /// Validates `options` and draws the 16-byte nonce from `rng`
  /// (RFC 6455 §4.1 requires it to be selected randomly; use a
  /// CSPRNG-quality source for public-internet connections).
  pub fn new<R: RngCore>(
    options: ClientOptions<'a>,
    rng: &mut R,
  ) -> Result<Self, ClientHandshakeError> {
    Self::validated(options, rng, Connection::new())
  }

  /// Opens a handshake on a connection the caller already holds — one
  /// transitioned out of `General` with [`Connection::into_tunnel`] — so a
  /// handshake can ride a connection kept warm by ordinary keep-alive
  /// exchanges instead of opening a new one.
  ///
  /// Validates `options` exactly as [`new`](Self::new) does: same path, no
  /// divergence. It performs NO check on `connection` itself. None is
  /// possible from here — `TunnelPhase` is crate-private to `http1-proto`, so
  /// this crate cannot read whether a handshake is already outstanding on the
  /// connection it was handed — and none is needed: a connection that already
  /// carries a handshake, or whose read side has ended, is refused by
  /// `open_upgrade` when [`encode_request`](Self::encode_request) reaches it.
  /// The misuse surfaces where the bytes would have been written, which is
  /// where the caller can act on it.
  ///
  /// [`Connection::into_tunnel`]: http1_proto::Connection::into_tunnel
  pub fn with_connection<R: RngCore>(
    options: ClientOptions<'a>,
    rng: &mut R,
    connection: Connection<Client, Tunnel>,
  ) -> Result<Self, ClientHandshakeError> {
    Self::validated(options, rng, connection)
  }

  /// The one validation path [`new`](Self::new) and
  /// [`with_connection`](Self::with_connection) both run: the host and path
  /// grammar gates, the subprotocol uniqueness/length/count walk that builds
  /// the joined value, extra-header validation, the deflate offer validation,
  /// and the nonce draw plus base64 encode. `connection` is placed on the
  /// result unchanged — the two public entry points differ only in what they
  /// pass here, so neither can drift a gate the other lacks.
  fn validated<R: RngCore>(
    options: ClientOptions<'a>,
    rng: &mut R,
    connection: Connection<Client, Tunnel>,
  ) -> Result<Self, ClientHandshakeError> {
    let invalid =
      |what: &'static str| ClientHandshakeError::InvalidOptions(InvalidOptionsDetail::new(what));
    // A `Host:` value is an RFC 3986 authority (RFC 9110 §7.2), not a free
    // string — URI delimiters, whitespace, and controls are all invalid.
    if !is_valid_authority(options.host) {
      return Err(invalid("host is not a valid authority"));
    }
    // Full RFC 3986 path-and-query grammar (shared with the server gate):
    // rejects whitespace/controls AND a raw `#` — RFC 6455 §3 says the
    // resource name MUST NOT carry a fragment (escape literal `#` as %23).
    if !is_valid_path_and_query(options.path) {
      return Err(invalid("path is not a valid origin-form resource name"));
    }
    // RFC 6455 §4.1 item 10: offered subprotocols MUST all be unique — and
    // must fit [`Negotiated`]'s inline storage, or a conforming server
    // SELECTING the offer would fail our own response validation
    // (self-interop).
    //
    // The joined field value is built in the same pass, ONCE, before any walk
    // of the section can begin. §4.1 item 10 makes the offers "one or more
    // comma-separated subprotocol", and one field line is what fits a head: a
    // line per offer is the same field to RFC 9110 §5.3, but a peer counts
    // lines — http1-proto's own server refuses a head past 64 of them, so 60
    // one-byte offers used to make a request this crate's own server rejected.
    // A list too long for the buffer is refused HERE, naming the limit,
    // rather than encoded for the peer to fail on.
    if options.subprotocols.len() > crate::negotiation::MAX_SUBPROTOCOL_OFFERS {
      return Err(invalid(TOO_MANY_SUBPROTOCOL_OFFERS));
    }
    let mut subprotocols = OfferedSubprotocols::empty();
    for (i, proto) in options.subprotocols.iter().enumerate() {
      if !is_token(proto.as_bytes()) {
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
      if i > 0 && !subprotocols.push(b", ") {
        return Err(invalid(TOO_MANY_SUBPROTOCOL_BYTES));
      }
      if !subprotocols.push(proto.as_bytes()) {
        return Err(invalid(TOO_MANY_SUBPROTOCOL_BYTES));
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
    Ok(Self {
      connection,
      options,
      key,
      subprotocols,
    })
  }

  /// The base64 `Sec-WebSocket-Key` this handshake sends (exposed for
  /// tests and diagnostics).
  pub const fn key(&self) -> &[u8; constants::SEC_WEBSOCKET_KEY_LEN] {
    &self.key
  }

  /// Writes the RFC 6455 §4.1 upgrade request, returning its length, and opens
  /// the handshake this connection then reads the answer to.
  ///
  /// Once per handshake: a second successful call is caller-side misuse rather
  /// than a re-render. A call that FAILS changes nothing — the phase and the
  /// output buffer are as they were — so a short buffer can be retried.
  pub fn encode_request(&mut self, out: &mut [u8]) -> Result<usize, ClientHandshakeError> {
    // Rendered ONCE, ahead of the walk: `Headers::for_each` is visited three
    // times on the way out and every walk must yield the identical section, so
    // nothing may be formatted into a shared scratch while it runs.
    #[cfg(feature = "deflate")]
    let mut extension_value = [0u8; crate::negotiation::MAX_EXTENSION_VALUE_BYTES];
    #[cfg(feature = "deflate")]
    let extensions = match &self.options.deflate {
      Some(offer) => {
        let written = offer.write(&mut extension_value)?;
        extension_value.get(..written)
      }
      None => None,
    };
    #[cfg(not(feature = "deflate"))]
    let extensions: Option<&[u8]> = None;

    let headers = RequestHeaders {
      host: self.options.host,
      key: &self.key,
      // Read, never written: the join happened in `new`, so all three walks
      // see the same bytes.
      subprotocols: self.subprotocols.value(),
      extensions,
      extras: self.options.extra_headers,
    };
    // RFC 9112 §3.2.1's origin-form, which §4.2.1 item 1 of RFC 6455 makes the
    // shape of a websocket resource name; `ClientOptions::new` held `path` to
    // that grammar before this connection existed.
    let target = Target::Origin {
      path_and_query: self.options.path,
    };
    self
      .connection
      .open_upgrade(&target, &headers, out)
      .map_err(from_h1)
  }

  /// Classifies the accumulated response buffer, ADVANCING the connection.
  ///
  /// `data` is the driver's buffer from its unconsumed start.
  /// [`NeedMore`](ClientProgress::NeedMore) consumes nothing — offer the same
  /// bytes again with more behind them — while
  /// [`Interim`](ClientProgress::Interim),
  /// [`Refused`](ClientProgress::Refused) and
  /// [`Complete`](ClientProgress::Complete) each consume one head and say how
  /// far it reached; a driver that does not advance past an interim response
  /// re-offers it and reads it forever.
  ///
  /// Not replayable: the response is classified once, and offering bytes after
  /// the switch — they belong to the frame stream — is caller-side misuse.
  pub fn handle(&mut self, data: &[u8]) -> Result<ClientProgress, ClientHandshakeError> {
    let (head, leftover) = match self.connection.handle_response(data).map_err(from_h1)? {
      ClientTunnelOutcome::Switched { head, leftover } => (head, leftover),
      // RFC 9110 §15.2: not the answer, so the handshake stays open — and the
      // offset is what lets the caller reach the head that IS the answer.
      ClientTunnelOutcome::Interim {
        status, leftover, ..
      } => {
        return Ok(ClientProgress::Interim {
          status: status.code,
          consumed: consumed(data, leftover),
        });
      }
      // RFC 9110 §7.8: "Upgrade cannot be used to insist on a protocol change".
      // A 1xx that stated RFC 9112 §9.6's `close` arrives here too; the status
      // is what tells the two apart. An answer, not a fault — and RFC 6455
      // §4.1's "handle the response per HTTP procedures" needs the head this
      // offset delimits, not just the code.
      ClientTunnelOutcome::Refused {
        status, leftover, ..
      } => {
        return Ok(ClientProgress::Refused {
          status: status.code,
          consumed: consumed(data, leftover),
        });
      }
      ClientTunnelOutcome::NeedMore => return Ok(ClientProgress::NeedMore),
      // RFC 9110 §9.3.6's CONNECT tunnel answers a request this layer never
      // writes, and a 2xx is not RFC 6455 §4.2.2's switch.
      ClientTunnelOutcome::Tunneled { .. } => return Err(ClientHandshakeError::NotAnUpgrade),
      // `ClientTunnelOutcome` is `#[non_exhaustive]`: an answer this layer does
      // not know is not the switch, and reporting it as one would hand the
      // frame codec a stream nobody validated.
      _ => return Err(ClientHandshakeError::NotAnUpgrade),
    };

    // Every field below is read through THIS: one accessor per field, yielding
    // the field's complete logical value, so the §9.1 gate and the readers
    // behind it cannot disagree about occurrences or presence.
    let fields = ResponseFields::new(head);

    // §4.1 step 2: an `Upgrade` field "equal to 'websocket'". http1-proto
    // proved BOTH halves of RFC 9110 §7.8 are present and that the field names
    // some protocol; WHICH protocol was offered is known only here, so §7.8
    // delegates the match upward. RFC 9110 §5.3: repeated field lines are one
    // comma-joined list, so the token may arrive in ANY occurrence (proxies
    // split lists across lines).
    if !fields
      .upgrade()
      .into_iter()
      .any(|value| token_list_contains(value, "websocket"))
    {
      return Err(ClientHandshakeError::NotAnUpgrade);
    }

    // §4.1 step 4: present exactly once, and the SHA-1 derivation of the key
    // this handshake sent.
    let accept = match fields.websocket_accept().single() {
      Ok(Some(accept)) => accept,
      Ok(None) => return Err(ClientHandshakeError::AcceptMismatch),
      Err(_) => return Err(ClientHandshakeError::DuplicateHeader),
    };
    if accept != accept_value(&self.key).as_slice() {
      return Err(ClientHandshakeError::AcceptMismatch);
    }

    // §4.1 step 6: at most one, and one this client offered. RFC 6455 grants the
    // identifiers NO case-insensitive comparison, and the whole value must be a
    // single token — a server that answered with a LIST selected nothing that
    // was offered.
    // Unlike the REQUEST role's `1#token`, §4.2.2 item 4 makes the response one
    // selection, so a second field line is a second answer rather than a
    // continuation of the first.
    let negotiated = match fields.selected_subprotocol().single() {
      Err(_) => return Err(ClientHandshakeError::DuplicateHeader),
      Ok(None) => Negotiated::none(),
      Ok(Some(chosen)) => {
        // A non-UTF-8 value is not a token either; answered by refusing the
        // selection rather than by a lossy conversion.
        let Ok(chosen) = core::str::from_utf8(chosen) else {
          return Err(ClientHandshakeError::SubprotocolNotOffered);
        };
        if !self.options.subprotocols.contains(&chosen) || !is_token(chosen.as_bytes()) {
          return Err(ClientHandshakeError::SubprotocolNotOffered);
        }
        Negotiated::with_subprotocol(chosen)?
      }
    };

    // §9.1: "If a value is received by either the client or the server during
    // negotiation that does not conform to the ABNF below, the recipient of
    // such malformed data MUST immediately _Fail the WebSocket Connection_."
    // Asked before the value is interpreted, and whatever this build offered —
    // the rule is about the data, not about the negotiation it feeds.
    if !crate::negotiation::extension_list_conforms(fields.granted_extensions()) {
      return Err(ClientHandshakeError::MalformedExtensions);
    }

    // §4.1 step 5: an extension the client did not offer fails the connection.
    #[cfg(not(feature = "deflate"))]
    if fields.granted_extensions().present() {
      return Err(ClientHandshakeError::ExtensionNotOffered);
    }
    #[cfg(feature = "deflate")]
    let negotiated = {
      let mut negotiated = negotiated;
      match (&self.options.deflate, fields.granted_extensions().present()) {
        (_, false) => {}
        (None, true) => return Err(ClientHandshakeError::ExtensionNotOffered),
        (Some(offer), true) => {
          // The whole field, every line: §9.1 says this field "MAY be split or
          // combined across multiple lines", so counting LINES would answer a
          // question the grammar does not ask — an empty occurrence beside a
          // real one is the same value as the two joined by a comma, which the
          // gate above already accepted. How many extensions a response may
          // GRANT is the one cardinality that matters, and
          // `parse_deflate_response` enforces it over the joined value
          // ("exactly one non-empty member") because it is the only reader that
          // knows what a member is.
          let params =
            crate::negotiation::parse_deflate_response(fields.granted_extensions(), offer)?;
          negotiated = negotiated.with_deflate(Some(params));
        }
      }
      negotiated
    };

    Ok(ClientProgress::Complete(ClientComplete {
      negotiated,
      consumed: consumed(data, leftover),
    }))
  }

  /// Reports that the transport's read side has ended.
  ///
  /// Idempotent, and it decides nothing on its own: the next
  /// [`handle`](Self::handle) resolves the offer that ran out. RFC 9112 §2.1
  /// makes a part-arrived head a truncated message, and §9.5 with RFC 9110
  /// §15.2 makes a close with no FINAL response a fault however many interim
  /// ones arrived first — none of them is the answer.
  pub fn handle_eof(&mut self) -> Result<(), ClientHandshakeError> {
    self.connection.handle_eof().map_err(from_h1)
  }
}

/// The upgrade request's field section (RFC 6455 §4.1), supplied to
/// `http1-proto`'s encoder.
///
/// Every value is a slice fixed before the walk begins, so the three walks the
/// encoder makes — the framing reduction, the measuring pass, the writing pass
/// — see byte-for-byte the same section, which is the [`Headers`] contract.
struct RequestHeaders<'a> {
  /// The authority for RFC 9112 §3.2's `Host`, which every HTTP/1.1 request
  /// owes and http1-proto refuses to write a request without.
  host: &'a str,
  /// The base64 `Sec-WebSocket-Key` value.
  key: &'a [u8],
  /// The offers as one comma-joined value, or `None` when none were made.
  subprotocols: Option<&'a [u8]>,
  /// The rendered permessage-deflate offer, when one was configured.
  extensions: Option<&'a [u8]>,
  /// Caller-supplied extras, already validated.
  extras: ExtraHeaders<'a, 'a>,
}

impl Headers for RequestHeaders<'_> {
  fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) -> Result<(), http1_proto::Error> {
    f("Host", self.host.as_bytes());
    // RFC 9110 §7.8 requires both halves of the offer — the `Upgrade` field and
    // the connection option beside it — and http1-proto will not open an
    // upgrade without them.
    f("Upgrade", b"websocket");
    f("Connection", b"Upgrade");
    f("Sec-WebSocket-Key", self.key);
    f(
      "Sec-WebSocket-Version",
      constants::WEBSOCKET_VERSION.as_bytes(),
    );
    // ONE field line, as RFC 6455 §4.1 item 10 spells the offer ("one or more
    // comma-separated subprotocol") — joined in `ClientHandshake::new` and
    // only read here, so the walk stays stable without a line per offer. RFC
    // 9110 §5.3 would make a line per offer the same FIELD, but not the same
    // number of field lines, and a head has a finite number of those.
    if let Some(subprotocols) = self.subprotocols {
      f("Sec-WebSocket-Protocol", subprotocols);
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

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::handshake::accept_value;
  use http1_proto::General;

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

  /// A handshake whose request has been written: the connection is waiting for
  /// the answer, which is the only phase `handle` reads one in.
  fn opened() -> ClientHandshake<'static> {
    let mut hs = handshake();
    let mut out = [0u8; 1024];
    hs.encode_request(&mut out)
      .expect("the fixture request encodes");
    hs
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

  /// A tunnel connection whose one handshake has already been opened, so
  /// `open_upgrade` refuses a second.
  fn spent_client_tunnel() -> Connection<Client, Tunnel> {
    let mut conn = Connection::<Client, General>::new()
      .into_tunnel()
      .expect("a fresh client connection has nothing outstanding");
    let headers = RequestHeaders {
      host: "server.example.com",
      key: b"dGhlIHNhbXBsZSBub25jZQ==",
      subprotocols: None,
      extensions: None,
      extras: ExtraHeaders::new(),
    };
    let mut out = [0u8; 1024];
    conn
      .open_upgrade(
        &Target::Origin {
          path_and_query: "/chat",
        },
        &headers,
        &mut out,
      )
      .expect("the first handshake opens");
    conn
  }

  #[test]
  fn request_contains_the_required_lines() {
    let mut hs = handshake();
    let mut buf = [0u8; 1024];
    let n = hs.encode_request(&mut buf).unwrap();
    let req = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(req.starts_with("GET /chat HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("\r\nHost: server.example.com\r\n"));
    assert!(req.contains("\r\nUpgrade: websocket\r\n"));
    assert!(req.contains("\r\nConnection: Upgrade\r\n"));
    assert!(req.contains("\r\nSec-WebSocket-Version: 13\r\n"));
    // ONE line, comma-joined at construction (RFC 6455 §4.1 item 10).
    assert!(
      req.contains("\r\nSec-WebSocket-Protocol: chat, superchat\r\n"),
      "{req}"
    );
    assert_eq!(req.matches("Sec-WebSocket-Protocol").count(), 1, "{req}");
    assert!(req.contains("\r\nOrigin: http://example.com\r\n"));
    // The key line carries the deterministic nonce: base64 of 0..16.
    assert!(req.contains("\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\n"));
    assert!(req.ends_with("\r\n\r\n"));
  }

  /// The request is written ONCE: a second call answers a connection whose
  /// handshake has already begun.
  #[test]
  fn the_request_is_written_once() {
    let mut hs = opened();
    let mut buf = [0u8; 1024];
    assert!(matches!(
      hs.encode_request(&mut buf).unwrap_err(),
      ClientHandshakeError::Http(_)
    ));
  }

  #[test]
  fn buffer_too_small_is_reported() {
    let mut hs = handshake();
    let mut small = [0u8; 32];
    assert!(matches!(
      hs.encode_request(&mut small).unwrap_err(),
      ClientHandshakeError::BufferTooSmall(_)
    ));
    // Nothing was written and no handshake was opened, so the caller grows its
    // buffer and asks again.
    let mut buf = [0u8; 1024];
    assert!(hs.encode_request(&mut buf).is_ok());
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
    // (exactly — RFC 6455 grants no folding, so "CHAT" is a different
    // identifier).
    let dup = ClientOptions::new("h", "/").with_subprotocols(&["chat", "chat"]);
    assert!(matches!(
      ClientHandshake::new(dup, &mut CountingRng(0)).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
    let cased = ClientOptions::new("h", "/").with_subprotocols(&["chat", "CHAT"]);
    assert!(ClientHandshake::new(cased, &mut CountingRng(0)).is_ok());

    // Regression: offers past `Negotiated`'s inline storage are
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

    // Regression: the managed Host field is a full RFC 3986
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

    // Regression: a raw `#` in the path is a fragment —
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
    let mut hs = opened();
    let mut resp = response_for(&hs, "Sec-WebSocket-Protocol: superchat\r\n");
    let head_len = resp.len();
    resp.extend_from_slice(&[0x81, 0x00]); // first frame bytes after the head
    match hs.handle(&resp).unwrap() {
      ClientProgress::Complete(done) => {
        assert_eq!(done.consumed(), head_len);
        assert_eq!(done.negotiated().subprotocol(), Some("superchat"));
      }
      other => panic!("complete response head, got {other:?}"),
    }
  }

  #[test]
  fn partial_response_needs_more() {
    let mut hs = opened();
    let resp = response_for(&hs, "");
    for cut in 0..resp.len().saturating_sub(1) {
      let offered = resp.get(..cut).unwrap();
      assert!(
        matches!(hs.handle(offered).unwrap(), ClientProgress::NeedMore),
        "cut at {cut}"
      );
    }
    assert!(matches!(
      hs.handle(&resp).unwrap(),
      ClientProgress::Complete(_)
    ));
  }

  /// One handshake per instance: the checks below each need a connection that
  /// has written its request and read nothing.
  fn rejects(response: &[u8]) -> ClientHandshakeError {
    opened().handle(response).unwrap_err()
  }

  /// The status of a refusal, for the cases that only care which one it was.
  fn refusal_status(response: &[u8]) -> u16 {
    let mut hs = opened();
    let ClientProgress::Refused { status, .. } = hs.handle(response).unwrap() else {
      panic!("a non-101 answer is a refusal")
    };
    status
  }

  #[test]
  fn validation_failures() {
    let hs = opened();

    // A final response that is not the switch is an ANSWER, not an error.
    assert_eq!(refusal_status(b"HTTP/1.1 404 Not Found\r\n\r\n"), 404);

    // Regression: status-code = 3DIGIT — spellings that PARSE to 101 but are
    // not three digits are malformed heads, which is http1-proto's verdict.
    for bad in ["0101", "+101", "1 01", "10"] {
      let resp = format!("HTTP/1.1 {bad} Switching Protocols\r\n\r\n");
      assert!(
        matches!(rejects(resp.as_bytes()), ClientHandshakeError::Http(_)),
        "{bad:?}"
      );
    }

    // Garbled status line.
    assert!(matches!(
      rejects(b"HTTP/1.1 abc\r\n\r\n"),
      ClientHandshakeError::Http(_)
    ));

    // A 101 that switches to a protocol we did not offer. Both halves of RFC
    // 9110 §7.8 are present, so the tunnel is satisfied and the WebSocket rule
    // is what refuses it.
    let resp = String::from_utf8(response_for(&hs, ""))
      .unwrap()
      .replace("Upgrade: websocket", "Upgrade: h2c");
    assert!(matches!(
      rejects(resp.as_bytes()),
      ClientHandshakeError::NotAnUpgrade
    ));

    // Wrong accept value.
    let resp = String::from_utf8(response_for(&hs, "")).unwrap().replace(
      core::str::from_utf8(&accept_value(hs.key())).unwrap(),
      "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    assert!(matches!(
      rejects(resp.as_bytes()),
      ClientHandshakeError::AcceptMismatch
    ));

    // Subprotocol the client never offered.
    assert!(matches!(
      rejects(&response_for(&hs, "Sec-WebSocket-Protocol: nope\r\n")),
      ClientHandshakeError::SubprotocolNotOffered
    ));

    // A LIST where §4.2.2 admits one selection: nothing offered was named.
    assert!(matches!(
      rejects(&response_for(
        &hs,
        "Sec-WebSocket-Protocol: chat, superchat\r\n"
      )),
      ClientHandshakeError::SubprotocolNotOffered
    ));

    // Two subprotocol field lines are two selections.
    assert!(matches!(
      rejects(&response_for(
        &hs,
        "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: superchat\r\n"
      )),
      ClientHandshakeError::DuplicateHeader
    ));

    // An extension when none was offered.
    assert!(matches!(
      rejects(&response_for(
        &hs,
        "Sec-WebSocket-Extensions: permessage-deflate\r\n"
      )),
      ClientHandshakeError::ExtensionNotOffered
    ));

    // Two accept headers.
    assert!(matches!(
      rejects(&response_for(&hs, "Sec-WebSocket-Accept: bogus\r\n")),
      ClientHandshakeError::DuplicateHeader
    ));

    // No accept header at all is a mismatch, not a "duplicate".
    assert!(matches!(
      rejects(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
      ),
      ClientHandshakeError::AcceptMismatch
    ));
  }

  /// RFC 6455 §9.1's MUST names BOTH roles: "If a value is received by either
  /// the client or the server during negotiation that does not conform to the
  /// ABNF below". So a malformed `Sec-WebSocket-Extensions` in the 101 fails
  /// this side exactly as it fails the server, and before the value is read
  /// against what this client offered.
  #[test]
  fn a_malformed_extension_response_fails_the_handshake() {
    let hs = opened();
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
      // would have allowed and §9.1 does not.
      "permessage-deflate;",
      "permessage-deflate;;client_max_window_bits",
    ] {
      let resp = response_for(&hs, &format!("Sec-WebSocket-Extensions: {bad}\r\n"));
      assert!(
        matches!(rejects(&resp), ClientHandshakeError::MalformedExtensions),
        "{bad:?}"
      );
    }

    // A quoted value spanning the RFC 9110 §5.2 join carries the join's comma
    // into the value §9.1 requires to unescape to a token.
    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate; x=\"a\r\nSec-WebSocket-Extensions: b\"\r\n",
    );
    assert!(matches!(
      rejects(&resp),
      ClientHandshakeError::MalformedExtensions
    ));

    // Well formed but unoffered is the OTHER answer (§4.1 step 5), which the
    // gate must not swallow.
    let resp = response_for(&hs, "Sec-WebSocket-Extensions: x-private; a=b\r\n");
    assert!(matches!(
      rejects(&resp),
      ClientHandshakeError::ExtensionNotOffered
    ));

    // …and with an offer on the wire the empty parameter slot is not merely
    // unoffered. The gate is what names the fault: §9.1's MUST fails the
    // connection over malformed data, so the client never reaches the question
    // of what such a response granted.
    #[cfg(feature = "deflate")]
    {
      let options = ClientOptions::new("server.example.com", "/chat")
        .with_deflate(crate::negotiation::DeflateOffer::new());
      let mut hs = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
      let mut out = [0u8; 1024];
      hs.encode_request(&mut out).unwrap();
      let resp = response_for(&hs, "Sec-WebSocket-Extensions: permessage-deflate;\r\n");
      assert!(matches!(
        hs.handle(&resp).unwrap_err(),
        ClientHandshakeError::MalformedExtensions
      ));
    }
  }

  /// A handshake that offered permessage-deflate (when the tier has it) and no
  /// subprotocol, plus the WHOLE outcome of feeding it a 101 whose `field` is
  /// spelled as `lines`.
  ///
  /// The verdict is the resolved negotiation, never the raw field lines: those
  /// differ between spellings by construction, and the property under test is
  /// that what the client RESOLVES them to does not.
  fn response_verdict(field: &str, lines: &[&str]) -> String {
    #[cfg(feature = "deflate")]
    let options =
      ClientOptions::new("h", "/").with_deflate(crate::negotiation::DeflateOffer::new());
    #[cfg(not(feature = "deflate"))]
    let options = ClientOptions::new("h", "/");
    let mut hs = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
    let mut out = [0u8; 1024];
    hs.encode_request(&mut out).unwrap();

    let mut extra = String::new();
    for line in lines {
      extra.push_str(&format!("{field}: {line}\r\n"));
    }
    let resp = response_for(&hs, &extra);
    match hs.handle(&resp) {
      Err(error) => format!("error: {error:?}"),
      Ok(ClientProgress::Complete(done)) => {
        let negotiated = done.negotiated();
        #[cfg(feature = "deflate")]
        let deflate = format!("{:?}", negotiated.deflate());
        #[cfg(not(feature = "deflate"))]
        let deflate = String::from("(no deflate tier)");
        format!(
          "complete: subprotocol={:?} deflate={deflate}",
          negotiated.subprotocol()
        )
      }
      Ok(other) => format!("other: {other:?}"),
    }
  }

  /// One logical value however it is spelled, on the h1 RESPONSE role: RFC 6455
  /// §9.1 says the extension field "MAY be split or combined across multiple
  /// lines", so a grant written on two lines is the grant written on one, and an
  /// empty occupancy beside it changes nothing (RFC 2616 §2.1).
  ///
  /// The failure this pins is the gate and the reader disagreeing: the gate read
  /// every line and accepted, and the reader counted lines and refused the
  /// handshake the gate had passed.
  #[test]
  fn equivalent_spellings_of_a_response_field_reach_one_verdict() {
    use crate::handshake::spellings;

    let one = spellings::agree(
      "one grant",
      &spellings::one("permessage-deflate"),
      |lines| response_verdict("Sec-WebSocket-Extensions", lines),
    );
    #[cfg(feature = "deflate")]
    assert!(
      one.starts_with("complete: subprotocol=None deflate=Some"),
      "{one}"
    );
    #[cfg(not(feature = "deflate"))]
    assert_eq!(one, "error: ExtensionNotOffered");

    // Two grants where one extension was offered: a mismatch, and the same
    // mismatch however the two are spelled.
    let two = spellings::agree(
      "two grants",
      &spellings::two("permessage-deflate", "x-private"),
      |lines| response_verdict("Sec-WebSocket-Extensions", lines),
    );
    #[cfg(feature = "deflate")]
    assert_eq!(two, "error: Negotiation(ExtensionMismatch)");
    #[cfg(not(feature = "deflate"))]
    assert_eq!(two, "error: ExtensionNotOffered");

    // Present and granting nothing fails §9.1's `1#extension` at the gate,
    // however it is spelled — and is not the same as an absent field, which is
    // simply a server that declined.
    let nothing = spellings::agree("no grant named", &spellings::nothing(), |lines| {
      response_verdict("Sec-WebSocket-Extensions", lines)
    });
    assert_eq!(nothing, "error: MalformedExtensions");
    let absent = response_verdict("Sec-WebSocket-Extensions", &[]);
    assert!(absent.starts_with("complete: subprotocol=None"), "{absent}");
    assert_ne!(absent, nothing);
  }

  /// The response's subprotocol is deliberately NOT splittable: RFC 6455
  /// §4.2.2 item 4 makes it the ONE subprotocol the server selected, so a
  /// second field line is a second answer rather than a continuation of the
  /// first. The asymmetry with the request role is the roles', not two readers'.
  #[test]
  fn the_selected_subprotocol_is_one_line_by_role() {
    let hs = opened();
    assert!(matches!(
      rejects(&response_for(
        &hs,
        "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: chat\r\n"
      )),
      ClientHandshakeError::DuplicateHeader
    ));
    // And the accept field, the response's other singleton.
    assert!(matches!(
      rejects(&response_for(&hs, "Sec-WebSocket-Accept: bogus\r\n")),
      ClientHandshakeError::DuplicateHeader
    ));
  }

  /// RFC 9110 §15.2: "A client MUST be able to parse one or more 1xx
  /// responses received prior to a final response" — any number of them may
  /// precede the switch, so an interim is progress rather than a failure.
  #[test]
  fn an_interim_response_before_the_switch_is_not_a_failure() {
    let mut hs = opened();
    let mut buf = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
    let ClientProgress::Interim { status, consumed } = hs.handle(&buf).unwrap() else {
      panic!("an interim response is not the final answer")
    };
    assert_eq!(status, 100);
    assert_eq!(consumed, buf.len());

    // A second one: §15.2 bounds the number at nothing.
    buf.drain(..consumed);
    buf.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n");
    let ClientProgress::Interim { status, consumed } = hs.handle(&buf).unwrap() else {
      panic!("a second interim response is still not the final answer")
    };
    assert_eq!(status, 103);
    assert_eq!(consumed, buf.len());

    buf.drain(..consumed);
    buf.extend_from_slice(&response_for(&hs, ""));
    assert!(matches!(
      hs.handle(&buf).unwrap(),
      ClientProgress::Complete(_)
    ));
  }

  /// One read can carry both heads, so `consumed` covers the interim ALONE: a
  /// driver that advanced by the whole buffer would throw the answer away, and
  /// one that advanced by nothing would read the interim forever.
  #[test]
  fn an_interim_glued_to_the_switch_advances_by_the_interim_only() {
    let mut hs = opened();
    let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
    let mut buf = interim.to_vec();
    buf.extend_from_slice(&response_for(&hs, ""));

    let ClientProgress::Interim { consumed, .. } = hs.handle(&buf).unwrap() else {
      panic!("the first head is the interim response")
    };
    assert_eq!(consumed, interim.len());

    buf.drain(..consumed);
    let ClientProgress::Complete(done) = hs.handle(&buf).unwrap() else {
      panic!("the second head is the switch")
    };
    assert_eq!(done.consumed(), buf.len());
  }

  /// RFC 9112 §9.6: a sender of the `close` option closes "after it sends the
  /// response containing" it, and a 1xx is a response message — so the switch
  /// cannot follow, and the interim is the end of the handshake. One class of
  /// fact with the 403s: the handshake is over and the status says why.
  #[test]
  fn an_interim_that_states_close_ends_the_handshake() {
    assert_eq!(
      refusal_status(b"HTTP/1.1 100 Continue\r\nConnection: close\r\n\r\n"),
      100
    );
  }

  #[test]
  fn a_refusal_carries_its_status_to_the_caller() {
    assert_eq!(
      refusal_status(b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\n\r\n"),
      426
    );
  }

  /// RFC 6455 §4.1: a client that does not get the switch "handles the response
  /// per HTTP procedures. In particular, the client might perform
  /// authentication if it receives a 401 status code; the server might redirect
  /// the client using a 3xx status code."
  ///
  /// Both of those read FIELDS — `WWW-Authenticate`, `Location` — so the status
  /// on its own is not enough, and a consumer must be able to get back to the
  /// head. `consumed` is what does it: the head is the caller's own bytes below
  /// that offset, and an ordinary HTTP client parses the challenge straight out
  /// of them.
  #[test]
  fn a_refusal_hands_its_head_back_for_http_procedures() {
    use http1_proto::{BodyPlan, General, Item, StartLine};

    let challenge = "Basic realm=\"chat\", charset=\"UTF-8\"";
    let head = format!(
      "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {challenge}\r\nContent-Length: 5\r\n\r\n"
    );
    let mut data = head.clone().into_bytes();
    data.extend_from_slice(b"nope!");

    let mut hs = opened();
    let ClientProgress::Refused { status, consumed } = hs.handle(&data).unwrap() else {
      panic!("a 401 is the peer refusing, not a fault of this crate")
    };
    assert_eq!(status, 401);
    // The offset delimits the HEAD: the content the challenge belongs to is
    // still ahead of it, where §4.1's "HTTP procedures" will look for it.
    assert_eq!(consumed, head.len());
    assert_eq!(data.get(consumed..).unwrap(), b"nope!");

    // Hand `data[..consumed]` to an ordinary HTTP client — the whole point of
    // reporting the offset instead of hiding the bytes behind a status code.
    let mut http = Connection::<Client, General>::new();
    let host: &[(&str, &str)] = &[("Host", "server.example.com")];
    let mut request = [0u8; 128];
    http
      .open_request(
        "GET",
        &Target::Origin {
          path_and_query: "/chat",
        },
        host,
        BodyPlan::None,
        &mut request,
      )
      .expect("the probe request encodes");

    let mut items = http.handle(data.get(..consumed).unwrap());
    let Some(Item::Head { view, line, .. }) = items.next().unwrap() else {
      panic!("the refusal's head is a complete HTTP head on its own")
    };
    let StartLine::Status(status_line) = line else {
      panic!("a client connection reads status lines")
    };
    assert_eq!(status_line.code, 401);
    assert_eq!(
      view.header("www-authenticate"),
      Some(challenge.as_bytes()),
      "RFC 9110 §11.6.1's challenge is what a 401 is answered with"
    );
    // And nothing else: the slice is the head exactly, so the content the
    // caller reads next is not already half-eaten.
    assert!(
      items.next().unwrap().is_none(),
      "the announced content begins at `consumed`, not below it"
    );
  }

  /// The accepted behaviour change: the status line's version is http1-proto's
  /// to read (RFC 9110 §6.2), so an HTTP/1.0 refusal is answered rather than
  /// refused as a malformed head.
  #[test]
  fn an_http_1_0_refusal_is_read_as_a_refusal() {
    assert_eq!(refusal_status(b"HTTP/1.0 404 Not Found\r\n\r\n"), 404);
  }

  #[test]
  fn frames_that_follow_the_switch_are_handed_back() {
    let mut hs = opened();
    let mut resp = response_for(&hs, "");
    resp.extend_from_slice(b"\x81\x03abc");
    let ClientProgress::Complete(done) = hs.handle(&resp).unwrap() else {
      panic!("complete response head")
    };
    assert_eq!(resp.get(done.consumed()..).unwrap(), b"\x81\x03abc");

    // The switch is answered ONCE: the bytes behind it belong to the frame
    // stream, so re-offering them is caller-side misuse rather than a re-parse.
    assert!(hs.handle(&resp).is_err());
  }

  /// RFC 9112 §9.5 with RFC 9110 §15.2: the request went out and no FINAL
  /// response came back, which is a fault however many interim ones did.
  #[test]
  fn a_close_before_the_final_response_ends_the_handshake() {
    let mut hs = opened();
    hs.handle_eof().unwrap();
    assert!(matches!(
      hs.handle(b"").unwrap_err(),
      ClientHandshakeError::Http(_)
    ));
  }

  #[test]
  fn subprotocol_selection_is_case_sensitive() {
    // RFC 6455 grants identifiers no case-insensitive comparison. The client
    // offered "chat"/"superchat"; a server selecting "CHAT" selected something
    // we never offered.
    let mut hs = opened();
    let resp = response_for(&hs, "Sec-WebSocket-Protocol: CHAT\r\n");
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::SubprotocolNotOffered
    ));
  }

  #[test]
  fn split_connection_header_lines_are_conforming() {
    // RFC 9110 §5.3: a proxy may split a list across repeated field lines.
    let mut hs = opened();
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

  /// RFC 9110 §5.3 again, on the field the WebSocket rule reads: the token may
  /// arrive in any occurrence of `Upgrade`.
  #[test]
  fn split_upgrade_header_lines_are_conforming() {
    let mut hs = opened();
    let resp = String::from_utf8(response_for(&hs, "")).unwrap().replace(
      "Upgrade: websocket\r\n",
      "Upgrade: h2c\r\nUpgrade: websocket\r\n",
    );
    assert!(matches!(
      hs.handle(resp.as_bytes()).unwrap(),
      ClientProgress::Complete(_)
    ));
  }

  #[cfg(feature = "deflate")]
  #[test]
  fn deflate_offer_and_response_flow() {
    use crate::negotiation::DeflateOffer;

    /// One offering handshake per response — a connection classifies one — with
    /// the request it wrote.
    fn offering() -> (ClientHandshake<'static>, Vec<u8>) {
      let options = ClientOptions::new("h", "/")
        .with_deflate(DeflateOffer::new().with_server_no_context_takeover(true));
      let mut hs = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
      let mut buf = [0u8; 1024];
      let n = hs.encode_request(&mut buf).unwrap();
      let request = buf.get(..n).unwrap().to_vec();
      (hs, request)
    }

    let (mut hs, request) = offering();
    let req = core::str::from_utf8(&request).unwrap();
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
      other => panic!("complete, got {other:?}"),
    }

    // Server declines (no extensions header): no deflate in Negotiated.
    let (mut hs, _) = offering();
    let resp = response_for(&hs, "");
    match hs.handle(&resp).unwrap() {
      ClientProgress::Complete(done) => assert!(done.negotiated().deflate().is_none()),
      other => panic!("complete, got {other:?}"),
    }

    // Server grants something invalid → connection fails.
    let (mut hs, _) = offering();
    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate; bogus\r\n",
    );
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::Negotiation(_)
    ));

    // Two GRANTS in a response → fail. Not because they arrived on two lines —
    // §9.1 lets the field be split — but because the joined value names two
    // extensions where this client offered one, which is
    // `parse_deflate_response`'s "exactly one non-empty member" rule and
    // therefore an `ExtensionMismatch`.
    let (mut hs, _) = offering();
    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Extensions: permessage-deflate\r\n",
    );
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::Negotiation(NegotiationError::ExtensionMismatch)
    ));
    // …and the single-line spelling of the same value gets the same verdict.
    let (mut hs, _) = offering();
    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate, permessage-deflate\r\n",
    );
    assert!(matches!(
      hs.handle(&resp).unwrap_err(),
      ClientHandshakeError::Negotiation(NegotiationError::ExtensionMismatch)
    ));
  }

  /// The offers are ONE field line, and the cliff they used to fall off is a
  /// local, documented byte limit instead.
  ///
  /// Regression: a line per offer made sixty one-byte offers a sixty-five-line
  /// head, and `http1-proto`'s own server — the one behind `ServerHandshake` and
  /// both drivers — refuses a head past `MAX_HEADERS = 64`, so the failure
  /// surfaced as the PEER's. The offers join into
  /// `MAX_SUBPROTOCOL_OFFER_BYTES` instead, one past it is refused here by name,
  /// and the walk stays stable because the join happened at construction.
  #[test]
  fn subprotocol_offers_travel_as_one_bounded_field_line() {
    let names: Vec<String> = (0..60).map(|i| format!("p{i}")).collect();
    let offers: Vec<&str> = names.iter().map(String::as_str).collect();
    let options = ClientOptions::new("h", "/").with_subprotocols(&offers);
    let mut hs = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();

    let mut buf = [0u8; 4096];
    let n = hs.encode_request(&mut buf).unwrap();
    let req = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(req.matches("Sec-WebSocket-Protocol").count(), 1, "{req}");
    assert!(
      req.contains("\r\nSec-WebSocket-Protocol: p0, p1, p2,"),
      "{req}"
    );
    assert!(req.contains(", p59\r\n"), "{req}");

    // Exactly at the limit: seven offers at the per-name cap, then one sized to
    // land the joined value on the boundary.
    let cap = crate::negotiation::MAX_SUBPROTOCOL_LEN;
    let wide: Vec<String> = (0..7)
      .map(|i| format!("{}{i}", "a".repeat(cap - 1)))
      .collect();
    let mut exact: Vec<&str> = wide.iter().map(String::as_str).collect();
    // Seven names at the cap, plus the seven two-byte separators between eight
    // elements.
    let used = 7 * cap + 7 * 2;
    let last = "b".repeat(MAX_SUBPROTOCOL_OFFER_BYTES - used);
    exact.push(last.as_str());
    assert_eq!(exact.join(", ").len(), MAX_SUBPROTOCOL_OFFER_BYTES);
    let options = ClientOptions::new("h", "/").with_subprotocols(&exact);
    let mut hs = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
    let n = hs.encode_request(&mut buf).unwrap();
    let req = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(
      req.contains(&format!(
        "\r\nSec-WebSocket-Protocol: {}\r\n",
        exact.join(", ")
      )),
      "{req}"
    );

    // One byte past it: refused HERE, naming the limit — not encoded for a peer
    // to reject.
    let over = "b".repeat(MAX_SUBPROTOCOL_OFFER_BYTES - used + 1);
    let mut over_list: Vec<&str> = wide.iter().map(String::as_str).collect();
    over_list.push(over.as_str());
    assert_eq!(over_list.join(", ").len(), MAX_SUBPROTOCOL_OFFER_BYTES + 1);
    let options = ClientOptions::new("h", "/").with_subprotocols(&over_list);
    let error = ClientHandshake::new(options, &mut CountingRng(0)).unwrap_err();
    let ClientHandshakeError::InvalidOptions(detail) = error else {
      panic!("invalid options, got {error:?}")
    };
    assert_eq!(detail.what(), TOO_MANY_SUBPROTOCOL_BYTES);
    assert!(detail.what().contains("512"));
  }

  /// The byte cap is not the only bound, and it was never the one the SERVER
  /// applies: 512 joined bytes admits 171 one-byte offers, and this crate's own
  /// gate reads at most
  /// [`MAX_SUBPROTOCOL_OFFERS`](crate::negotiation::MAX_SUBPROTOCOL_OFFERS).
  ///
  /// Without the count check the client encodes a request its own server
  /// refuses — the emit/accept asymmetry the repeated-`Origin` case took in a
  /// different field. The two numbers answer different questions
  /// (this emitter's inline storage; the work an unauthenticated peer can buy),
  /// so both are checked.
  #[test]
  fn the_offer_count_is_bounded_by_what_our_own_server_reads() {
    use crate::negotiation::MAX_SUBPROTOCOL_OFFERS;

    let names: Vec<String> = (0..=MAX_SUBPROTOCOL_OFFERS)
      .map(|i| format!("p{i}"))
      .collect();
    let all: Vec<&str> = names.iter().map(String::as_str).collect();

    // At the cap: encodes, and the joined value is far inside the byte limit —
    // so the count is the only thing this pair of cases varies.
    let at_cap = all.get(..MAX_SUBPROTOCOL_OFFERS).unwrap();
    assert!(at_cap.join(", ").len() < MAX_SUBPROTOCOL_OFFER_BYTES);
    let options = ClientOptions::new("h", "/").with_subprotocols(at_cap);
    assert!(ClientHandshake::new(options, &mut CountingRng(0)).is_ok());

    // One past it: refused HERE, by name.
    let options = ClientOptions::new("h", "/").with_subprotocols(&all);
    let error = ClientHandshake::new(options, &mut CountingRng(0)).unwrap_err();
    let ClientHandshakeError::InvalidOptions(detail) = error else {
      panic!("invalid options, got {error:?}")
    };
    assert_eq!(detail.what(), TOO_MANY_SUBPROTOCOL_OFFERS);
    assert!(detail.what().contains("64"));
  }

  /// A caller may send one `Origin`, and may not send two — while a field this
  /// crate does not resolve may repeat.
  ///
  /// RFC 9110 §5.3 binds the SENDER, but its exception is wide: a name may
  /// repeat "unless that field's definition allows multiple field line values to
  /// be recombined as a comma-separated list", which is every list-valued field
  /// and so an open set nobody can enumerate. RFC 6454 §7.1's `origin-list` is
  /// SP-separated, so `Origin` is not in it: this crate's own server refuses the
  /// repeat as a duplicated singleton, and a client that emits what its own
  /// server rejects is the drift this screen exists to catch.
  ///
  /// So the screen is stated over the names this crate itself resolves, and a
  /// conforming `Cache-Control` or `Via` layout stays writable.
  #[test]
  fn an_extra_header_may_not_repeat_a_singleton_field_name() {
    let refused = |extras: &[(&str, &str)]| -> Option<&'static str> {
      let options = ClientOptions::new("h", "/").with_extra_headers(extras);
      match ClientHandshake::new(options, &mut CountingRng(0)) {
        Ok(_) => None,
        Err(ClientHandshakeError::InvalidOptions(detail)) => Some(detail.what()),
        Err(other) => panic!("invalid options, got {other:?}"),
      }
    };

    assert_eq!(refused(&[("Origin", "http://a.example")]), None);
    assert_eq!(
      refused(&[
        ("Origin", "http://a.example"),
        ("Origin", "http://evil.example"),
      ]),
      Some("extra header repeats a field name")
    );
    // Case does not launder it (RFC 9110 §5.1 matches names case-insensitively).
    assert_eq!(
      refused(&[("origin", "http://a.example"), ("ORIGIN", "http://b")]),
      Some("extra header repeats a field name")
    );
    // Nor does distance: the pair need not be adjacent.
    assert_eq!(
      refused(&[
        ("Origin", "http://a"),
        ("X-Trace", "t"),
        ("Origin", "http://b"),
      ]),
      Some("extra header repeats a field name")
    );

    // The list-valued fields an over-broad screen would break. Both are
    // `#(values)` (RFC 9111 §5.2, RFC 9110 §7.6.3), so §5.3's exception is
    // theirs.
    assert_eq!(
      refused(&[("Cache-Control", "no-store"), ("Cache-Control", "no-cache")]),
      None
    );
    assert_eq!(refused(&[("Via", "1.1 alpha"), ("Via", "1.1 beta")]), None);
    // A field this crate neither writes nor reads is the caller's to spell.
    assert_eq!(refused(&[("X-Trace", "a"), ("X-Trace", "b")]), None);
    assert_eq!(
      refused(&[
        ("WWW-Authenticate", "Basic realm=\"a\""),
        ("WWW-Authenticate", "Newauth realm=\"b\""),
      ]),
      None
    );
    assert_eq!(
      refused(&[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]),
      None
    );

    // A managed name is still refused on its FIRST occurrence, so narrowing the
    // repeat rule cannot become a way to smuggle one in.
    assert_eq!(
      refused(&[("Sec-WebSocket-Version", "13")]),
      Some("extra header collides with a managed header")
    );
    assert_eq!(
      refused(&[
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Version", "8"),
      ]),
      Some("extra header collides with a managed header")
    );
  }

  /// The `Headers` contract: every walk of the section yields byte-identical
  /// output. The joined offers are the one value built rather than borrowed, so
  /// this is where a scratch buffer written DURING the walk would show up.
  #[test]
  fn repeated_encodes_of_one_handshake_are_byte_identical() {
    let options = ClientOptions::new("h", "/").with_subprotocols(&["chat", "superchat", "v2"]);
    let mut first = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
    let mut second = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
    let (mut a, mut b) = ([0u8; 1024], [0u8; 1024]);
    let n = first.encode_request(&mut a).unwrap();
    let m = second.encode_request(&mut b).unwrap();
    assert_eq!(a.get(..n), b.get(..m));
    assert!(
      core::str::from_utf8(&a[..n])
        .unwrap()
        .contains("\r\nSec-WebSocket-Protocol: chat, superchat, v2\r\n")
    );
  }

  /// Adopting changes nothing observable on the wire: a handshake built on a
  /// connection this crate minted and one built on a connection the caller
  /// transitioned out of `General` must write byte-identical requests when
  /// seeded with the same key.
  #[test]
  fn a_handshake_on_an_adopted_connection_writes_the_same_request() {
    let options = ClientOptions::new("server.example.com", "/chat")
      .with_subprotocols(&["chat", "superchat"])
      .with_extra_headers(&[("Origin", "http://example.com")]);
    let mut via_new = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
    let tunnel = Connection::<Client, General>::new()
      .into_tunnel()
      .expect("a fresh client connection has nothing outstanding");
    let mut via_adopted =
      ClientHandshake::with_connection(options, &mut CountingRng(0), tunnel).unwrap();

    let mut a = [0u8; 1024];
    let mut b = [0u8; 1024];
    let n = via_new.encode_request(&mut a).unwrap();
    let m = via_adopted.encode_request(&mut b).unwrap();
    assert_eq!(a.get(..n), b.get(..m));
  }

  /// [`ClientHandshake::with_connection`] has no gate of its own on the
  /// connection it is handed, so a connection whose one handshake is already
  /// spent is still accepted here — and the refusal instead lands where the
  /// bytes would be written, exactly as it would on a connection this crate
  /// misused itself.
  #[test]
  fn adopting_a_spent_connection_is_refused_where_the_bytes_would_be_written() {
    let options = ClientOptions::new("server.example.com", "/chat");
    let mut hs =
      ClientHandshake::with_connection(options, &mut CountingRng(0), spent_client_tunnel())
        .expect("the constructor performs no check on the connection");
    let mut out = [0u8; 1024];
    assert!(matches!(
      hs.encode_request(&mut out).unwrap_err(),
      ClientHandshakeError::Http(_)
    ));
  }

  /// [`ClientHandshake::with_connection`] validates `options` on the same path
  /// as [`ClientHandshake::new`]: a refactor that leaves it on a shortcut would
  /// let a bad host through.
  #[test]
  fn with_connection_validates_options_exactly_as_new_does() {
    let options = ClientOptions::new("not a valid authority!", "/");
    let tunnel = Connection::<Client, General>::new()
      .into_tunnel()
      .expect("a fresh client connection has nothing outstanding");
    assert!(matches!(
      ClientHandshake::with_connection(options, &mut CountingRng(0), tunnel).unwrap_err(),
      ClientHandshakeError::InvalidOptions(_)
    ));
  }

  /// RFC 6455 §9.1 states its ABNF "including the 'implied *LWS rule'", so a
  /// conforming server may write `permessage-deflate ; server_max_window_bits =
  /// 12`. RFC 7692 §7 makes an extension response the client will not accept
  /// FAIL the connection, so reading the granted value with a grammar stricter
  /// than the §9.1 gate's does not merely decline the extension — it refuses a
  /// handshake the RFC admits. Regression for exactly that: the gate accepted
  /// this response and `parse_deflate_response`, reading RFC 9110 §5.6.6, then
  /// rejected it.
  #[cfg(feature = "deflate")]
  #[test]
  fn a_response_written_with_implied_lws_completes_the_handshake() {
    use crate::negotiation::DeflateOffer;

    let options = ClientOptions::new("h", "/").with_deflate(
      DeflateOffer::new()
        .with_server_max_window_bits(Some(12))
        .with_client_max_window_bits(Some(11)),
    );
    let mut hs = ClientHandshake::new(options, &mut CountingRng(0)).unwrap();
    let mut buf = [0u8; 1024];
    hs.encode_request(&mut buf).unwrap();

    let resp = response_for(
      &hs,
      "Sec-WebSocket-Extensions: permessage-deflate ;  server_max_window_bits = 12 ; \
       client_max_window_bits = \"11\"\r\n",
    );
    match hs.handle(&resp).unwrap() {
      ClientProgress::Complete(done) => {
        let d = done.negotiated().deflate().unwrap();
        assert_eq!(d.server_max_window_bits(), 12);
        assert_eq!(d.client_max_window_bits(), 11);
      }
      other => panic!("complete, got {other:?}"),
    }
  }
}
