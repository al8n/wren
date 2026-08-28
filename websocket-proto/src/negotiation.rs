//! Negotiation results shared by every handshake transport.
//!
//! [`Negotiated`] is the sole gate into the connection state machine: the h1
//! machines produce it from header bytes, and the RFC 8441/9220 `connect`
//! types produce it from header data. The module is **allocation-free on
//! every tier** — the subprotocol lives in an inline buffer capped at
//! [`MAX_SUBPROTOCOL_LEN`](crate::negotiation::MAX_SUBPROTOCOL_LEN) bytes (registered subprotocol names are short
//! tokens; the longest in the IANA registry is well under half the cap), so
//! [`Negotiated`] is `Copy` and fully available on the bare `no_std` tier.

use derive_more::{IsVariant, TryUnwrap};
use http_semantics::grammar::{is_token, is_token_byte, list_elements, trim_ows};

/// Maximum retained subprotocol length, on every tier. Longer offers are
/// rejected as [`NegotiationError::InvalidSubprotocol`].
pub const MAX_SUBPROTOCOL_LEN: usize = 64;

/// The most subprotocol offers this crate will READ from a peer or WRITE to
/// one — the same number on h1 and on extended CONNECT, and in both directions.
///
/// # Why the list needs a bound at all
///
/// RFC 6455 §4.1 item 10 requires the offers to "all be unique", and this crate
/// allocates nothing, so [`subprotocol_list_conforms`] proves uniqueness by
/// re-walking the value once per offer. That is Θ(offers × bytes), and the
/// input is an unauthenticated peer's: without a bound, a 16 KiB h1 head holds
/// thousands of two-byte offers and buys millions of byte steps, while extended
/// CONNECT hands the same function a header slice with no length of its own.
///
/// **The clause that licenses this bound is RFC 9110 §5.4**, which is about
/// the size of what a server agrees to process: "A server that receives a
/// request header field line, field value, or set of fields larger than it
/// wishes to process MUST respond with an appropriate 4xx (Client Error) status
/// code". A field value carrying more offers than this is one larger than this
/// crate wishes to process, and the 4xx is exactly what a reject-only handshake
/// writes.
///
/// **§5.6.1.2 is not that clause.** Its
/// "not so much that they could be used as a denial-of-service mechanism"
/// closes a sentence about EMPTY list elements — the ones
/// [`http_semantics::grammar::list_elements`] drops before an offer is ever
/// counted, and which this constant therefore does not bound at all
/// (`the_offer_list_is_bounded` pins that: a value padded with commas still
/// conforms). What §5.6.1.2 does say about real elements is the opposite
/// direction of the same distinction — "Empty elements do not contribute to the
/// count of elements present" — which is why the count below is a count of
/// offers rather than of commas. [`http_semantics::validator::MAX_TAGS`] draws
/// the same distinction for the bound it states.
///
/// # Why 64
///
/// - It cannot be LOWER than 60: `sixty_subprotocol_offers_round_trip_through_
///   our_own_server` is a committed regression fixture asserting that sixty
///   offers reach this crate's own server, so any bound under it would refuse a
///   configuration the crate already promises.
/// - It is `http1_proto::MAX_HEADERS`: a head cannot carry more than 64 field
///   LINES at all, so 64 offers is already at the shape limit of the transport
///   the h1 side reads.
/// - RFC 6455 §4.1 item 10 makes the list a preference order the client's
///   author wrote ("ordered by preference"); the registered names are few and
///   real lists are one to five long.
/// - It bounds the uniqueness proof at 64 re-walks — 2016 element comparisons —
///   whatever the peer sends.
///
/// This one is a COUNT rather than a length because the two shapes cost
/// differently: one long element is cheap to check and is a shape real
/// deployments use (a bearer token carried as a subprotocol name), while many
/// short elements are what costs the quadratic. What the count does NOT bound is
/// the bytes each re-walk crosses, and that is [`MAX_SUBPROTOCOL_LIST_BYTES`]'s.
pub const MAX_SUBPROTOCOL_OFFERS: usize = 64;

/// The most a `Sec-WebSocket-Protocol` REQUEST value may measure, every field
/// line of it joined — the second half of the bound above, and the half that
/// makes the two transports cost the same rather than merely refuse the same.
///
/// [`MAX_SUBPROTOCOL_OFFERS`] bounds the re-walks at 64; this bounds what each
/// one crosses. Together they cap the uniqueness proof at 63 × 16 KiB ≈ 1 MiB of
/// byte steps — measured at 0.42 ms — for any input either server accepts.
///
/// # Why 16384, and why it is not a new number
///
/// It is `http1_proto::MAX_HEAD_BYTES`, the cap the h1 head scanner already
/// applies to the WHOLE head. So on h1 this refuses nothing that could have
/// arrived: a field value cannot outgrow the head that carries it. What it does
/// is give extended CONNECT the ceiling h1 has always had, on a transport where
/// this crate is handed an already-decoded `&[(&str, &str)]` with no length of
/// its own — 63 × B byte steps for a B this crate would otherwise not bound.
///
/// RFC 9110 §5.4 is the licence: "HTTP does not place a predefined limit on the
/// length of each field line, field value, or on the length of a header or
/// trailer section as a whole … A server that receives a request header field
/// line, field value, or set of fields larger than it wishes to process MUST
/// respond with an appropriate 4xx (Client Error) status code." The limit is the
/// recipient's to choose and the answer is a refusal, which is what a
/// reject-only handshake writes.
///
/// NOT [`MAX_SUBPROTOCOL_OFFER_BYTES`](crate::handshake::h1::MAX_SUBPROTOCOL_OFFER_BYTES),
/// which is 512 and answers a different question: that one is the h1 CLIENT's
/// inline storage for the value it WRITES, so it is far smaller than what either
/// server will READ. Emit ⊆ accept, in both directions and on both transports.
pub const MAX_SUBPROTOCOL_LIST_BYTES: usize = http1_proto::MAX_HEAD_BYTES;

/// Inline subprotocol storage (token bytes + length). Tokens are ASCII by
/// the RFC 9110 grammar, so the stored bytes are always valid UTF-8.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct SubprotocolBuf {
  buf: [u8; MAX_SUBPROTOCOL_LEN],
  len: u8,
}

impl SubprotocolBuf {
  fn try_from_str(s: &str) -> Result<Self, NegotiationError> {
    if s.len() > MAX_SUBPROTOCOL_LEN {
      return Err(NegotiationError::InvalidSubprotocol);
    }
    let mut buf = [0u8; MAX_SUBPROTOCOL_LEN];
    for (d, b) in buf.iter_mut().zip(s.as_bytes()) {
      *d = *b;
    }
    Ok(Self {
      buf,
      len: u8::try_from(s.len()).unwrap_or(0),
    })
  }

  fn as_str(&self) -> &str {
    let bytes = self.buf.get(..usize::from(self.len)).unwrap_or(&[]);
    core::str::from_utf8(bytes).unwrap_or("")
  }
}

/// Errors validating negotiation inputs.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum NegotiationError {
  /// A subprotocol was empty, not an RFC 9110 token, or longer than
  /// [`MAX_SUBPROTOCOL_LEN`].
  #[error("invalid or unretainable subprotocol")]
  InvalidSubprotocol,

  /// A `Sec-WebSocket-Extensions` value failed the RFC 7692 grammar or its
  /// parameter rules (duplicate/unknown/malformed/out-of-range).
  #[error("invalid Sec-WebSocket-Extensions value")]
  InvalidExtension,

  /// The server's response granted something the offer did not allow, or
  /// granted an extension other than exactly one permessage-deflate.
  #[error("extension response does not match the offer")]
  ExtensionMismatch,

  /// A window-bits value outside 8..=15 at configuration time.
  #[error("window bits must be within 8..=15")]
  InvalidWindowBits,

  /// The output buffer cannot hold the rendered extension value.
  #[error("{0}")]
  BufferTooSmall(crate::error::BufferTooSmallDetail),
}

/// The agreed handshake outcome: what the connection machine is configured
/// from. Construct via [`Negotiated::none`] (no subprotocol, no extensions)
/// or the handshake machines. Inline storage — `Copy`, every tier.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Negotiated {
  subprotocol: Option<SubprotocolBuf>,
  #[cfg(feature = "deflate")]
  deflate: Option<DeflateParams>,
}

impl Negotiated {
  /// No subprotocol, no extensions — the result of a handshake that
  /// negotiated nothing, and the entry point for drivers that skip
  /// negotiation entirely.
  pub const fn none() -> Self {
    Self {
      subprotocol: None,
      #[cfg(feature = "deflate")]
      deflate: None,
    }
  }

  /// A result carrying an agreed subprotocol (validated as a token of at
  /// most [`MAX_SUBPROTOCOL_LEN`] bytes).
  pub fn with_subprotocol(subprotocol: &str) -> Result<Self, NegotiationError> {
    if !is_token(subprotocol.as_bytes()) {
      return Err(NegotiationError::InvalidSubprotocol);
    }
    Ok(Self {
      subprotocol: Some(SubprotocolBuf::try_from_str(subprotocol)?),
      #[cfg(feature = "deflate")]
      deflate: None,
    })
  }

  /// The agreed subprotocol, when one was negotiated.
  pub fn subprotocol(&self) -> Option<&str> {
    self.subprotocol.as_ref().map(SubprotocolBuf::as_str)
  }

  /// The agreed permessage-deflate parameters, when negotiated.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub const fn deflate(&self) -> Option<DeflateParams> {
    self.deflate
  }

  /// Attaches agreed permessage-deflate parameters.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  #[must_use]
  pub const fn with_deflate(mut self, deflate: Option<DeflateParams>) -> Self {
    self.deflate = deflate;
    self
  }
}

/// A `Sec-WebSocket-Extensions` value that RFC 6455 §9.1's ABNF does not admit.
///
/// One outcome and no detail, because every caller acts on it the same way:
/// §9.1 makes malformed data fail the connection, so the gate refuses the
/// handshake and the readers behind it stop walking.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Malformed;

/// One `extension` of a §9.1 `extension-list`: the token that names it, and the
/// `*( ";" extension-param )` that followed it, read on demand.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Extension<'a> {
  /// Validated on every tier — RFC 6455 §9.1's MUST is about the data, not
  /// about the extensions a build can negotiate — but only a build that HAS an
  /// extension to look for has a reason to read it.
  #[cfg_attr(not(feature = "deflate"), allow(dead_code))]
  name: &'a [u8],
  /// The bytes after the member's FIRST semicolon, or `None` when it carried
  /// none. The distinction is the grammar: `ext` states no parameters and
  /// `ext;` states a parameter slot §9.1 has no spelling for, and a plain
  /// `&[]` could not tell the two apart.
  params: Option<&'a [u8]>,
}

impl<'a> Extension<'a> {
  /// The `extension-token`, OWS-trimmed.
  #[cfg_attr(not(feature = "deflate"), allow(dead_code))]
  pub(crate) const fn name(&self) -> &'a [u8] {
    self.name
  }

  /// Its parameters, in order.
  pub(crate) const fn params(&self) -> ExtensionParams<'a> {
    ExtensionParams {
      params: self.params,
      at: 0,
      done: false,
    }
  }
}

/// An `extension-param`'s value: `[ "=" ( token | quoted-string ) ]`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum ExtensionValue<'a> {
  /// The parameter carried no `=`, which `[ … ]` makes legal — and is how
  /// RFC 7692 §7.1.2.2 offers `client_max_window_bits`.
  None,
  /// A bare token.
  Token(&'a [u8]),
  /// The interior of a quoted-string, escapes untouched: §9.1 requires the
  /// UNESCAPED form to be a token, so unescaping belongs to the reader that
  /// knows how long a legal value is.
  Quoted(&'a [u8]),
}

/// Walks one member's `*( ";" extension-param )`. A parameter the grammar does
/// not admit yields `Err` and ends the walk.
#[derive(Debug, Clone)]
pub(crate) struct ExtensionParams<'a> {
  params: Option<&'a [u8]>,
  at: usize,
  done: bool,
}

impl<'a> Iterator for ExtensionParams<'a> {
  type Item = Result<(&'a [u8], ExtensionValue<'a>), Malformed>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    let Some(params) = self.params else {
      self.done = true;
      return None;
    };
    let Some(end) = scan_to(params, self.at, b';') else {
      self.done = true;
      return Some(Err(Malformed));
    };
    let param = trim_ows(params.get(self.at..end).unwrap_or_default());
    match params.get(end) {
      Some(_) => self.at = end.saturating_add(1),
      None => self.done = true,
    }
    let parsed = parse_param(param);
    if parsed.is_err() {
      self.done = true;
    }
    Some(parsed)
  }
}

/// Walks a `Sec-WebSocket-Extensions` field as RFC 6455 §9.1's ABNF defines it.
/// A member the grammar does not admit yields `Err` and ends the walk.
#[derive(Debug, Clone)]
pub(crate) struct ExtensionList<'a, I> {
  lines: I,
  /// The remainder of the field line being walked, or `None` between lines.
  line: Option<&'a [u8]>,
  at: usize,
  /// Whether the field was present at all — one line, even an empty one, is a
  /// field that must satisfy `1#`, while no lines is a field that is absent.
  present: bool,
  done: bool,
}

impl<'a, I: Iterator<Item = &'a [u8]>> ExtensionList<'a, I> {
  /// Whether any field line was offered. Meaningful once the walk has run to
  /// `None`, which is where `1#`'s "present but naming nothing" is decided.
  pub(crate) const fn field_present(&self) -> bool {
    self.present
  }
}

impl<'a, I: Iterator<Item = &'a [u8]>> Iterator for ExtensionList<'a, I> {
  type Item = Result<Extension<'a>, Malformed>;

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      if self.done {
        return None;
      }
      let Some(line) = self.line else {
        match self.lines.next() {
          Some(next) => {
            self.present = true;
            self.line = Some(next);
            self.at = 0;
          }
          None => self.done = true,
        }
        continue;
      };
      let Some(end) = scan_to(line, self.at, b',') else {
        self.done = true;
        return Some(Err(Malformed));
      };
      let element = trim_ows(line.get(self.at..end).unwrap_or_default());
      match line.get(end) {
        Some(_) => self.at = end.saturating_add(1),
        None => self.line = None,
      }
      if element.is_empty() {
        // RFC 2616 §2.1's `#rule` — RFC 822 §2.7's wording verbatim — which is
        // what `1#extension` is written in:
        // "null elements are allowed, but do not contribute to the count of
        // elements present". (RFC 9110 §5.6.1.2 says the same in the modern
        // spelling: "A recipient MUST parse and ignore a reasonable number of
        // empty list elements".)
        continue;
      }
      let parsed = parse_extension(element);
      if parsed.is_err() {
        self.done = true;
      }
      return Some(parsed);
    }
  }
}

/// Reads a `Sec-WebSocket-Extensions` field with RFC 6455 §9.1's own grammar —
/// the ONE reading of this field in this crate.
///
/// The grammar, why it is not RFC 9110 §5.6.6's, and why the field's several
/// lines are walked one by one are all on [`extension_list_conforms`], which is
/// this walk driven to the end and the public face of it.
// `single_use_lifetimes` false-positive: anonymous lifetimes in `impl Trait`
// argument position are unstable (E0658), so the once-used lifetime must be
// named.
#[allow(single_use_lifetimes)]
pub(crate) fn extension_list<'a, I>(lines: I) -> ExtensionList<'a, I::IntoIter>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  ExtensionList {
    lines: lines.into_iter(),
    line: None,
    at: 0,
    present: false,
    done: false,
  }
}

/// `extension = extension-token *( ";" extension-param )`, over one list
/// element already trimmed of the whitespace the implied *LWS rule puts around
/// it.
fn parse_extension(extension: &[u8]) -> Result<Extension<'_>, Malformed> {
  let Some(end) = scan_to(extension, 0, b';') else {
    return Err(Malformed);
  };
  let name = trim_ows(extension.get(..end).unwrap_or_default());
  if !is_token(name) {
    return Err(Malformed);
  }
  Ok(Extension {
    name,
    // `None` exactly when there was no semicolon: with none, `scan_to` stops at
    // the end of the slice, and `get` one past that yields nothing.
    params: extension.get(end.saturating_add(1)..),
  })
}

/// `extension-param = token [ "=" (token | quoted-string) ]`, over one
/// parameter already trimmed of the surrounding whitespace.
fn parse_param(param: &[u8]) -> Result<(&[u8], ExtensionValue<'_>), Malformed> {
  if param.is_empty() {
    // gate-exempt: between any two adjacent words … and between adjacent words and separators — RFC 2616's own wording for the implied *LWS rule; its current successor dropped that whole convention for explicit OWS/RWS grammar instead, so no loaded spec restates it
    //
    // `*( ";" extension-param )` puts a MANDATORY `extension-param` after every
    // semicolon: what §9.1 makes optional is the `[ "=" … ]` half, not the
    // production itself, so `ext;` and `ext;;x` state a parameter slot the
    // grammar has no spelling for. RFC 2616 §2.1's implied *LWS rule — the one
    // §9.1 imports — lets whitespace stand "between any two adjacent words …
    // and between adjacent words and separators"; it does not let a required
    // word be absent.
    //
    // Unlike the empty LIST elements above, which RFC 2616 §2.1's `#rule`
    // permits in as many words. The two look alike and are not: `#` is defined
    // to allow null elements, `*( ";" extension-param )` is not.
    return Err(Malformed);
  }
  let Some(end) = scan_to(param, 0, b'=') else {
    return Err(Malformed);
  };
  let name = trim_ows(param.get(..end).unwrap_or_default());
  if !is_token(name) {
    return Err(Malformed);
  }
  // No `=` at all: §9.1 makes the value optional, which is how
  // `client_max_window_bits` is offered (RFC 7692 §7.1.2.2).
  let Some(value) = param.get(end.saturating_add(1)..) else {
    return Ok((name, ExtensionValue::None));
  };
  let value = trim_ows(value);
  match value.first() {
    Some(&b'"') => match quoted_end(value, 0) {
      // The quoted-string is the WHOLE value: bytes behind its closing DQUOTE
      // are neither a `token` nor a `quoted-string`.
      Some(close) if close == value.len() => {
        let interior = value.get(1..close.saturating_sub(1)).unwrap_or_default();
        if unescaped_is_token(interior) {
          Ok((name, ExtensionValue::Quoted(interior)))
        } else {
          Err(Malformed)
        }
      }
      _ => Err(Malformed),
    },
    _ if is_token(value) => Ok((name, ExtensionValue::Token(value))),
    _ => Err(Malformed),
  }
}

/// Whether a received `Sec-WebSocket-Extensions` field conforms to RFC 6455
/// §9.1's ABNF — the check §9.1 makes a MUST rather than a preference:
///
/// > If a value is received by either the client or the server during
/// > negotiation that does not conform to the ABNF below, the recipient of such
/// > malformed data MUST immediately _Fail the WebSocket Connection_.
///
/// ```text
/// Sec-WebSocket-Extensions = extension-list
/// extension-list = 1#extension
/// extension = extension-token *( ";" extension-param )
/// extension-token = registered-token
/// registered-token = token
/// extension-param = token [ "=" (token | quoted-string) ]
///     ;When using the quoted-string syntax variant, the value
///     ;after quoted-string unescaping MUST conform to the
///     ;'token' ABNF.
/// ```
///
/// It runs on EVERY handshake that carries the field, on both sides, and
/// whatever extensions the build supports: §9.1's other freedom — a recipient
/// may decline any extension for any reason — is about extensions it does not
/// WANT, not about data it cannot READ. Declining stays
/// `accept_deflate_offer`'s answer; this one decides whether there is a
/// handshake left to decline within.
///
/// # One grammar
///
/// This is not a separate reading standing in front of the negotiation: it is
/// the crate's one §9.1 walk driven to the end, and `accept_deflate_offer` /
/// `parse_deflate_response` resolve what the peer said out of the same walk. Two
/// implementations of one field could only agree by coincidence, and the
/// DIRECTION of a disagreement decides how bad it is — on the offer path a
/// stricter reader merely declines an extension, while on the response path RFC
/// 7692 §7 makes a grant the client will not accept fail the connection, so
/// there it refuses a conforming handshake.
///
/// # Why not `http_semantics::grammar::parameterised_list`
///
/// Because §9.1's grammar is not RFC 9110 §5.6.6's, and the two disagree in
/// BOTH directions:
///
// gate-exempt: x = 1 — an INSTANCE the imported RFC 2616 rule admits, not a production; no spec spells this string
/// - §9.1 states its ABNF in RFC 2616's syntax "including the 'implied *LWS
///   rule'", so `x = 1` is a conforming `extension-param` there. §5.6.6 removed
///   that rule, and the walker implements §5.6.6 — deliberately, because that is
///   the grammar HTTP's own fields are read with.
/// - §5.6.6 writes its repetition as `*( OWS ";" OWS [ parameter ] )`, where the
///   parameter after a semicolon is optional; §9.1 writes `*( ";"
///   extension-param )`, where it is not. So `ext;;x` is a value the walker
///   resolves and §9.1 does not admit, and reading with it would let a malformed
///   value be NEGOTIATED rather than failed.
///
/// The walker stays correct for what it is for — the HTTP fields RFC 9110
/// §5.6.6 governs, which is what `http1-proto` parses. `Sec-WebSocket-Extensions`
/// is not one of them.
///
/// # Lines, not one value
///
/// §9.1 says so itself — "like other HTTP header fields, this header field MAY
/// be split or combined across multiple lines", with `foo` + `bar; baz=2` given
/// as exactly `foo, bar; baz=2` — which is RFC 2616 §4.2's rule that repeated
/// field lines combine "by appending each subsequent field-value to the first,
/// each separated by a comma". (RFC 9110 §5.2 and §5.3 restate it.)
///
/// The lines are nevertheless walked ONE BY ONE, which for this grammar is the
/// same question: the join's comma separates members, so no member spans it
/// except through a quoted-string, and such a string either never closes
/// (malformed) or swallows the join's comma into a value §9.1 requires to
/// unescape to a `token` — and a comma is not a `tchar`. Either way it is
/// malformed, so no member ever has to be READ across the join. The `1#`
/// cardinality is the one global question, and it is asked here over all of
/// them: a field present but naming nothing does not conform, while a field that
/// is absent (no lines at all) conforms vacuously.
///
/// `accept_deflate_offer` and `parse_deflate_response` are named above in plain
/// code rather than linked: they exist only under the `deflate` feature, and an
/// intra-doc link to a gated item is a rustdoc error in every build without it.
/// This function is not gated.
// `single_use_lifetimes` false-positive: anonymous lifetimes in `impl Trait`
// argument position are unstable (E0658), so the once-used lifetime must be
// named.
#[allow(single_use_lifetimes)]
pub fn extension_list_conforms<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> bool {
  let mut list = extension_list(lines);
  let mut named = false;
  for member in list.by_ref() {
    let Ok(member) = member else {
      return false;
    };
    named = true;
    // Driven to the end: the members' boundaries conform, and the parameters
    // inside them are the rest of the same ABNF.
    if member.params().any(|param| param.is_err()) {
      return false;
    }
  }
  // `extension-list = 1#extension`, read with the `#rule` of RFC 2616 §2.1 —
  // the ABNF §9.1 imports, and RFC 822 §2.7's wording apart from the capitalised
  // MUST: "null elements are allowed, but do not contribute to
  // the count of elements present … where at least one element is required, at
  // least one non-null element MUST be present". (RFC 9110 §5.6.1.2 restates it,
  // with `""`, `","` and `",   ,"` as its examples of values that do not
  // satisfy `1#`.)
  !list.field_present() || named
}

/// The next `delim` outside a quoted-string, or the end of `value`.
///
/// `None` when a quoted-string opened and did not close in `value` — malformed
/// either way, per the module note above.
fn scan_to(value: &[u8], at: usize, delim: u8) -> Option<usize> {
  let mut at = at;
  loop {
    match value.get(at) {
      None => return Some(at),
      Some(&byte) if byte == delim => return Some(at),
      Some(&b'"') => at = quoted_end(value, at)?,
      Some(_) => at = at.saturating_add(1),
    }
  }
}

/// The index just past the closing DQUOTE of the quoted-string opening at
/// `open`; `None` when it never closes.
///
/// Only the BOUNDARY is decided here — RFC 2616 §2.2's `qdtext = <any TEXT
/// except <">>` and `quoted-pair = "\" CHAR` are not enforced against the
/// interior, because they cannot change the answer: every surviving byte of the
/// value must be a `tchar` ([`unescaped_is_token`]), and the only bytes an
/// unescape removes are backslashes. So a byte outside `TEXT` or a `\` before a
/// non-`CHAR` fails at the token check instead, and a value that passes both is
/// one the strict grammar also admits.
fn quoted_end(value: &[u8], open: usize) -> Option<usize> {
  let mut at = open.saturating_add(1);
  loop {
    match value.get(at)? {
      // `quoted-pair = "\" CHAR`: the backslash escapes what follows it, the
      // closing DQUOTE included, so the pair is skipped whole.
      b'\\' => at = at.saturating_add(2),
      b'"' => return Some(at.saturating_add(1)),
      _ => at = at.saturating_add(1),
    }
  }
}

/// §9.1's parenthetical: "the value after quoted-string unescaping MUST conform
/// to the 'token' ABNF". Asked over the DQUOTEs' interior, escapes intact.
///
/// Streamed rather than materialised: a conforming value is a token of any
/// length, so a fixed unescaping buffer would call a legal one malformed.
fn unescaped_is_token(interior: &[u8]) -> bool {
  let mut escaped = false;
  let mut len = 0usize;
  for &byte in interior {
    if !escaped && byte == b'\\' {
      escaped = true;
      continue;
    }
    escaped = false;
    if !is_token_byte(byte) {
      return false;
    }
    len = len.saturating_add(1);
  }
  // `token = 1*tchar`, and a trailing backslash escapes nothing.
  !escaped && len > 0
}

#[cfg(feature = "deflate")]
mod deflate {
  use super::{ExtensionParams, ExtensionValue, NegotiationError, extension_list};
  use crate::{error::BufferTooSmallDetail, handshake::WriteCursor};
  use http_semantics::grammar::is_token;

  /// How large a buffer holds any `Sec-WebSocket-Extensions` value this crate
  /// RENDERS — [`DeflateOffer::write`] and [`DeflateResponse::write`], and the
  /// four inline scratches the handshakes call them into.
  ///
  /// # Why 160
  ///
  /// Both roles write the same shape: `permessage-deflate` and RFC 7692 §7.1's
  /// four parameters, window bits at their widest two digits. That is 128 bytes,
  /// so the size is the bound plus room — a buffer this size can never be why a
  /// render reports [`BufferTooSmallDetail`], which
  /// `the_widest_rendered_extension_value_fits` pins.
  ///
  /// # Why it is one constant
  ///
  /// It was four numbers: the h1 client's offer scratch, the h1 server's grant
  /// scratch, the inline buffer in each extended-CONNECT header view, and the
  /// re-render `response_matches_offer` checks a grant against — three named
  /// separately and the fourth an anonymous literal. Divergence fails closed (a
  /// short buffer refuses; it does not truncate), so this is not a fix; it is
  /// the reason there is no fifth spelling to drift.
  ///
  /// # What it does NOT bound
  ///
  /// A value a PEER sends. That one is bounded by the transport's own head cap
  /// ([`http1_proto::MAX_HEAD_BYTES`] on h1) and read in place, never copied
  /// into a buffer of this size.
  pub const MAX_EXTENSION_VALUE_BYTES: usize = 160;

  /// The agreed permessage-deflate configuration (RFC 7692 §7): what each
  /// side may assume about windows and context takeover. Plan 5's
  /// transform consumes it; plan 4's connection uses its presence for the
  /// RSV1 policy.
  #[derive(Debug, Copy, Clone, PartialEq, Eq)]
  pub struct DeflateParams {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
  }

  impl Default for DeflateParams {
    fn default() -> Self {
      Self {
        server_no_context_takeover: false,
        client_no_context_takeover: false,
        server_max_window_bits: 15,
        client_max_window_bits: 15,
      }
    }
  }

  impl DeflateParams {
    /// Whether the server must reset its compression context per message.
    #[inline(always)]
    pub const fn server_no_context_takeover(&self) -> bool {
      self.server_no_context_takeover
    }

    /// Whether the client must reset its compression context per message.
    #[inline(always)]
    pub const fn client_no_context_takeover(&self) -> bool {
      self.client_no_context_takeover
    }

    /// LZ77 window exponent for server→client payloads (8..=15).
    #[inline(always)]
    pub const fn server_max_window_bits(&self) -> u8 {
      self.server_max_window_bits
    }

    /// LZ77 window exponent for client→server payloads (8..=15).
    #[inline(always)]
    pub const fn client_max_window_bits(&self) -> u8 {
      self.client_max_window_bits
    }
  }

  const fn bits_in_range(bits: u8) -> bool {
    bits >= 8 && bits <= 15
  }

  /// The client's permessage-deflate offer (RFC 7692 §7.1). The default
  /// offer includes the valueless `client_max_window_bits` parameter so a
  /// server may pick a smaller client window.
  #[derive(Debug, Copy, Clone, PartialEq, Eq)]
  pub struct DeflateOffer {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    client_max_window_bits: Option<u8>,
    offer_client_max_window_bits: bool,
  }

  impl Default for DeflateOffer {
    fn default() -> Self {
      Self::new()
    }
  }

  impl DeflateOffer {
    /// The default offer: no takeover restrictions, no window caps, but
    /// advertise that the server may set `client_max_window_bits`.
    pub const fn new() -> Self {
      Self {
        server_no_context_takeover: false,
        client_no_context_takeover: false,
        server_max_window_bits: None,
        client_max_window_bits: None,
        offer_client_max_window_bits: true,
      }
    }

    /// Request that the server resets its context per message.
    #[must_use]
    pub const fn with_server_no_context_takeover(mut self, v: bool) -> Self {
      self.server_no_context_takeover = v;
      self
    }

    /// Declare that this client resets its context per message.
    #[must_use]
    pub const fn with_client_no_context_takeover(mut self, v: bool) -> Self {
      self.client_no_context_takeover = v;
      self
    }

    /// Cap the server's window (8..=15; validated by [`validate`]).
    ///
    /// [`validate`]: DeflateOffer::validate
    #[must_use]
    pub const fn with_server_max_window_bits(mut self, bits: Option<u8>) -> Self {
      self.server_max_window_bits = bits;
      self
    }

    /// Cap this client's own window (8..=15) — implies offering the
    /// parameter.
    #[must_use]
    pub const fn with_client_max_window_bits(mut self, bits: Option<u8>) -> Self {
      self.client_max_window_bits = bits;
      self.offer_client_max_window_bits = true;
      self
    }

    /// Omit `client_max_window_bits` entirely (the server then must not
    /// send it back).
    #[must_use]
    pub const fn without_client_max_window_bits(mut self) -> Self {
      self.client_max_window_bits = None;
      self.offer_client_max_window_bits = false;
      self
    }

    /// Validates the configured window ranges.
    pub fn validate(&self) -> Result<(), NegotiationError> {
      for bits in [self.server_max_window_bits, self.client_max_window_bits]
        .into_iter()
        .flatten()
      {
        if !bits_in_range(bits) {
          return Err(NegotiationError::InvalidWindowBits);
        }
      }
      Ok(())
    }

    /// Writes the offer as a `Sec-WebSocket-Extensions` value. Validates
    /// first: an out-of-range window-bits config is an
    /// [`NegotiationError::InvalidWindowBits`] error here, never wire bytes
    /// — emitting `server_max_window_bits=7` would be rejected by this
    /// crate's own acceptor (and any conforming peer), so the public
    /// emitter refuses to produce it.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, NegotiationError> {
      self.validate()?;
      let mut w = WriteCursor::new(out);
      self
        .write_to(&mut w)
        .map_err(NegotiationError::BufferTooSmall)?;
      Ok(w.written())
    }

    /// Crate-internal render path; the h1/CONNECT builders run
    /// [`validate`](Self::validate) before reaching it.
    pub(crate) fn write_to(&self, w: &mut WriteCursor<'_>) -> Result<(), BufferTooSmallDetail> {
      w.push(b"permessage-deflate")?;
      if self.server_no_context_takeover {
        w.push(b"; server_no_context_takeover")?;
      }
      if self.client_no_context_takeover {
        w.push(b"; client_no_context_takeover")?;
      }
      if let Some(bits) = self.server_max_window_bits {
        w.push(b"; server_max_window_bits=")?;
        w.push(two_digit(bits).as_slice())?;
      }
      if self.offer_client_max_window_bits {
        w.push(b"; client_max_window_bits")?;
        if let Some(bits) = self.client_max_window_bits {
          w.push(b"=")?;
          w.push(two_digit(bits).as_slice())?;
        }
      }
      Ok(())
    }
  }

  /// 8..=15 rendered as ASCII digits without allocation; returns a slice
  /// of length 1 or 2.
  fn two_digit(bits: u8) -> TwoDigit {
    if bits < 10 {
      TwoDigit {
        buf: [b'0'.wrapping_add(bits), 0],
        len: 1,
      }
    } else {
      TwoDigit {
        buf: [b'1', b'0'.wrapping_add(bits.wrapping_sub(10))],
        len: 2,
      }
    }
  }

  struct TwoDigit {
    buf: [u8; 2],
    len: usize,
  }

  impl TwoDigit {
    fn as_slice(&self) -> &[u8] {
      self.buf.get(..self.len).unwrap_or(&self.buf)
    }
  }

  /// A parameter value after quoted-string unescaping (RFC 6455 §9.1 allows
  /// `token | quoted-string`; the unescaped form must itself be a token).
  /// Inline storage: every legal permessage-deflate value is 1–2 digits;
  /// the slack absorbs escaped spellings without allocating.
  struct UnquotedValue {
    buf: [u8; 8],
    len: usize,
  }

  impl UnquotedValue {
    fn as_slice(&self) -> &[u8] {
      self.buf.get(..self.len).unwrap_or(&[])
    }
  }

  /// Resolves a parameter value to its token form: a bare token passes
  /// through; a quoted-string's content (which the walk hands over with its
  /// escapes intact) is unescaped (quoted-pair: `\X` → `X`) and the result
  /// must be a non-empty token, as RFC 6455 §9.1 requires of every
  /// `extension-param` value. `None` = a valueless parameter, or one whose
  /// value is longer than any legal permessage-deflate one.
  fn token_value(value: ExtensionValue<'_>) -> Option<UnquotedValue> {
    let (raw, quoted) = match value {
      ExtensionValue::Token(v) => (v, false),
      ExtensionValue::Quoted(v) => (v, true),
      // A parameter that carried no `=` at all.
      ExtensionValue::None => return None,
    };
    let mut out = UnquotedValue {
      buf: [0u8; 8],
      len: 0,
    };
    let mut escape = false;
    for &b in raw {
      if escape {
        escape = false;
      } else if quoted && b == b'\\' {
        escape = true;
        continue;
      }
      let slot = out.buf.get_mut(out.len)?;
      *slot = b;
      out.len = out.len.saturating_add(1);
    }
    if escape {
      // A quoted-pair with nothing to escape. The walker resolves the one
      // that swallows the closing DQUOTE, so this guards the rest.
      return None;
    }
    is_token(out.as_slice()).then_some(out)
  }

  /// Parses a window-bits value: 1–2 plain digits after unescaping,
  /// canonical (no leading zero), in 8..=15.
  fn parse_bits(value: &[u8]) -> Option<u8> {
    let bits = match value {
      [d] if d.is_ascii_digit() => d.wrapping_sub(b'0'),
      // RFC 7692 §7.1.2.1 spells the value as DIGITs of the number itself,
      // so `08` is not a spelling of 8.
      [tens, units] if tens.is_ascii_digit() && *tens != b'0' && units.is_ascii_digit() => tens
        .wrapping_sub(b'0')
        .wrapping_mul(10)
        .wrapping_add(units.wrapping_sub(b'0')),
      _ => return None,
    };
    bits_in_range(bits).then_some(bits)
  }

  /// Accumulates one entry's params with duplicate detection.
  #[derive(Default)]
  struct EntryParams {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    client_max_window_bits: Option<u8>,
    client_max_window_bits_valueless: bool,
  }

  /// Parses the params of one `permessage-deflate` entry. `in_response`
  /// distinguishes responses (client_max_window_bits must carry a value)
  /// from offers (it may be valueless). `None` = this entry is unusable —
  /// a parameter the §9.1 walk refused, a duplicate, an unknown name, or a
  /// value where none is allowed.
  fn collect_params(params: ExtensionParams<'_>, in_response: bool) -> Option<EntryParams> {
    let mut out = EntryParams::default();
    for param in params {
      let (name, raw) = param.ok()?;
      // Both spellings of `extension-param`'s value resolve to the same
      // token (RFC 6455 §9.1), so the arms below read one form.
      let value = match raw {
        ExtensionValue::None => None,
        valued => Some(token_value(valued)?),
      };
      match (name, value.as_ref().map(UnquotedValue::as_slice)) {
        (b"server_no_context_takeover", None) => {
          if out.server_no_context_takeover {
            return None;
          }
          out.server_no_context_takeover = true;
        }
        (b"client_no_context_takeover", None) => {
          if out.client_no_context_takeover {
            return None;
          }
          out.client_no_context_takeover = true;
        }
        (b"server_max_window_bits", Some(v)) => {
          if out.server_max_window_bits.is_some() {
            return None;
          }
          out.server_max_window_bits = Some(parse_bits(v)?);
        }
        (b"client_max_window_bits", None) if !in_response => {
          if out.client_max_window_bits.is_some() || out.client_max_window_bits_valueless {
            return None;
          }
          out.client_max_window_bits_valueless = true;
        }
        (b"client_max_window_bits", Some(v)) => {
          if out.client_max_window_bits.is_some() || out.client_max_window_bits_valueless {
            return None;
          }
          out.client_max_window_bits = Some(parse_bits(v)?);
        }
        _ => return None, // unknown param, or a value where none is allowed
      }
    }
    Some(out)
  }

  /// Client-side: validates the server's `Sec-WebSocket-Extensions`
  /// response against `offer`, yielding the agreed parameters. Errors here
  /// fail the WebSocket connection (RFC 7692 §7).
  ///
  /// The values are the field's LINES in wire order, read with RFC 6455 §9.1's
  /// own grammar — bytes rather than `&str` because a field value admits
  /// `obs-text` (RFC 9110 §5.5) and §9.1 lets a parameter value be a
  /// quoted-string, neither of which `&str` can carry losslessly.
  ///
  /// The very walk
  /// [`extension_list_conforms`](crate::negotiation::extension_list_conforms)
  /// gates the handshake with, and that is the point: a response this reader
  /// cannot resolve FAILS the connection (RFC 7692 §7), so a second, stricter
  /// reading here would refuse handshakes §9.1 admits rather than merely decline
  /// them.
  // `single_use_lifetimes` false-positive: anonymous lifetimes in `impl
  // Trait` argument position are unstable (E0658), so the once-used
  // lifetime must be named.
  #[allow(single_use_lifetimes)]
  pub fn parse_deflate_response<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
    offer: &DeflateOffer,
  ) -> Result<DeflateParams, NegotiationError> {
    // The response must contain exactly one extension entry. Empty list
    // elements (a stray comma) are ignored per RFC 2616 §2.1's `#rule` — only a
    // second NON-EMPTY entry is a mismatch.
    let mut members = extension_list(values);
    let Some(member) = members.next() else {
      return Err(NegotiationError::ExtensionMismatch);
    };
    // A member the §9.1 walk could not resolve is a `Sec-WebSocket-Extensions`
    // value that failed the grammar, which is what `InvalidExtension` names.
    let Ok(member) = member else {
      return Err(NegotiationError::InvalidExtension);
    };
    if members.next().is_some() {
      return Err(NegotiationError::ExtensionMismatch);
    }
    if member.name() != b"permessage-deflate" {
      return Err(NegotiationError::ExtensionMismatch);
    }
    let Some(p) = collect_params(member.params(), true) else {
      return Err(NegotiationError::InvalidExtension);
    };

    // Strict server_max_window_bits check (IMPLEMENTER NOTE applied):
    // absence of the param when we requested a cap → ExtensionMismatch.
    if p.server_max_window_bits.is_none() && offer.server_max_window_bits.is_some() {
      return Err(NegotiationError::ExtensionMismatch);
    }
    let server_bits = match (p.server_max_window_bits, offer.server_max_window_bits) {
      (Some(got), Some(requested)) if got > requested => {
        return Err(NegotiationError::ExtensionMismatch);
      }
      (Some(got), _) => got,
      (None, _) => 15,
    };

    // client_max_window_bits: only allowed if our offer included the param;
    // must not exceed the cap we declared (if any).
    let client_bits = match p.client_max_window_bits {
      None => offer.client_max_window_bits.unwrap_or(15),
      Some(got) => {
        if !offer.offer_client_max_window_bits {
          return Err(NegotiationError::ExtensionMismatch);
        }
        if offer
          .client_max_window_bits
          .is_some_and(|declared| got > declared)
        {
          return Err(NegotiationError::ExtensionMismatch);
        }
        got
      }
    };

    // RFC 7692 §7.1.1.1: the server AGREES to a requested
    // server_no_context_takeover by echoing the parameter — omission means
    // it was not granted, and a server that then reuses its window would
    // desync our per-message-reset inflater mid-stream. Strict, like the
    // server_max_window_bits absence check above.
    if offer.server_no_context_takeover && !p.server_no_context_takeover {
      return Err(NegotiationError::ExtensionMismatch);
    }

    Ok(DeflateParams {
      // Response-derived: the wire decides what the server committed to.
      server_no_context_takeover: p.server_no_context_takeover,
      // §7.1.1.2: OUR offer declaration is a unilateral promise (binding
      // whether or not echoed); the server's echo additionally demands it.
      client_no_context_takeover: p.client_no_context_takeover || offer.client_no_context_takeover,
      server_max_window_bits: server_bits,
      client_max_window_bits: client_bits,
    })
  }

  /// Server-side acceptance policy.
  #[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
  pub struct ServerDeflateConfig {
    require_client_no_context_takeover: bool,
    server_no_context_takeover: bool,
  }

  impl ServerDeflateConfig {
    /// Accept offers with the RFC defaults.
    pub const fn new() -> Self {
      Self {
        require_client_no_context_takeover: false,
        server_no_context_takeover: false,
      }
    }

    /// Demand that the client resets its context per message (emitted in
    /// the response even when the client didn't declare it — §7.1.1.1).
    #[must_use]
    pub const fn with_require_client_no_context_takeover(mut self, v: bool) -> Self {
      self.require_client_no_context_takeover = v;
      self
    }

    /// Voluntarily reset the server context per message.
    #[must_use]
    pub const fn with_server_no_context_takeover(mut self, v: bool) -> Self {
      self.server_no_context_takeover = v;
      self
    }
  }

  /// The response entry the server emits for an accepted offer.
  #[derive(Debug, Copy, Clone, PartialEq, Eq)]
  pub struct DeflateResponse {
    params: DeflateParams,
    /// The offer carried `server_max_window_bits`, so the response MUST
    /// echo the parameter (RFC 7692 §7.1.2.1: acceptance is BY inclusion)
    /// — even when the agreed value is the 15 default, or a strict client
    /// (ours included) correctly fails the handshake on the omission.
    echo_server_max_window_bits: bool,
    echo_client_max_window_bits: bool,
  }

  impl DeflateResponse {
    /// The agreed parameters (same value `accept_deflate_offer` returns).
    pub const fn params(&self) -> DeflateParams {
      self.params
    }

    /// Writes the response as a `Sec-WebSocket-Extensions` value.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, BufferTooSmallDetail> {
      let mut w = WriteCursor::new(out);
      self.write_to(&mut w)?;
      Ok(w.written())
    }

    pub(crate) fn write_to(&self, w: &mut WriteCursor<'_>) -> Result<(), BufferTooSmallDetail> {
      w.push(b"permessage-deflate")?;
      if self.params.server_no_context_takeover {
        w.push(b"; server_no_context_takeover")?;
      }
      if self.params.client_no_context_takeover {
        w.push(b"; client_no_context_takeover")?;
      }
      if self.echo_server_max_window_bits || self.params.server_max_window_bits != 15 {
        w.push(b"; server_max_window_bits=")?;
        w.push(two_digit(self.params.server_max_window_bits).as_slice())?;
      }
      if self.echo_client_max_window_bits && self.params.client_max_window_bits != 15 {
        w.push(b"; client_max_window_bits=")?;
        w.push(two_digit(self.params.client_max_window_bits).as_slice())?;
      }
      Ok(())
    }
  }

  /// Server-side bind (the extension twin of the subprotocol-membership
  /// rule): whether `response` is a conforming grant for SOME
  /// permessage-deflate offer among `offered`. Reuses the client-side
  /// response rules verbatim — each raw offer entry is re-synthesized as a
  /// [`DeflateOffer`] and the rendered grant must satisfy
  /// [`parse_deflate_response`] against one of them — so a `DeflateResponse`
  /// minted for a DIFFERENT request (or no request) can never be emitted for
  /// one that did not offer compatible parameters.
  // `single_use_lifetimes` false-positive: anonymous lifetimes in `impl
  // Trait` argument position are unstable (E0658), so the once-used
  // lifetime must be named.
  #[allow(single_use_lifetimes)]
  pub(crate) fn response_matches_offer<'a>(
    offered: impl IntoIterator<Item = &'a [u8]>,
    response: &DeflateResponse,
  ) -> bool {
    let mut rendered = [0u8; MAX_EXTENSION_VALUE_BYTES];
    let Ok(n) = response.write(&mut rendered) else {
      return false;
    };
    let Some(value) = rendered.get(..n) else {
      return false;
    };
    for member in extension_list(offered) {
      let Ok(member) = member else {
        break; // see `accept_deflate_offer` for why the walk ends here
      };
      if member.name() != b"permessage-deflate" {
        continue;
      }
      let Some(p) = collect_params(member.params(), false) else {
        continue;
      };
      let offer = DeflateOffer {
        server_no_context_takeover: p.server_no_context_takeover,
        client_no_context_takeover: p.client_no_context_takeover,
        server_max_window_bits: p.server_max_window_bits,
        client_max_window_bits: p.client_max_window_bits,
        offer_client_max_window_bits: p.client_max_window_bits.is_some()
          || p.client_max_window_bits_valueless,
      };
      if parse_deflate_response([value], &offer).is_ok() {
        return true;
      }
    }
    false
  }

  /// Server-side: scans the client's offer list — the
  /// `Sec-WebSocket-Extensions` field lines in wire order, walked as the
  /// single comma-joined value RFC 9110 §5.2 defines — and accepts the
  /// FIRST valid `permessage-deflate` offer, returning the agreed params
  /// plus the response entry to emit.
  ///
  /// `None` means "decline the extension" (omit the response header) and is
  /// never fatal — RFC 7692 §7.1.1 lets a server simply not accept. An
  /// unknown extension, or one whose parameters this server cannot honour,
  /// is skipped and the alternatives after it are still considered; a member
  /// the field grammar itself does not admit ends the scan, because past one
  /// the walk can no longer tell a list separator from data.
  ///
  /// The values are bytes rather than `&str` because a field value admits
  /// `obs-text` (RFC 9110 §5.5) and RFC 6455 §9.1 lets a parameter value be a
  /// quoted-string.
  ///
  /// Read with RFC 6455 §9.1's own grammar — the very walk
  /// [`extension_list_conforms`](crate::negotiation::extension_list_conforms)
  /// gates the handshake with, so what this declines and what that fails are
  /// two answers from one reading of the field rather than two readings.
  // `single_use_lifetimes` false-positive: anonymous lifetimes in `impl
  // Trait` argument position are unstable (E0658), so the once-used
  // lifetime must be named.
  #[allow(single_use_lifetimes)]
  pub fn accept_deflate_offer<'a>(
    header_values: impl IntoIterator<Item = &'a [u8]>,
    config: &ServerDeflateConfig,
  ) -> Option<(DeflateParams, DeflateResponse)> {
    for member in extension_list(header_values) {
      // A member the walk could not resolve ends the walk rather than
      // skipping one entry: past a value §9.1's grammar does not admit, no
      // offer behind it is one this server can be sure the client wrote —
      // and the gate has already refused such a field anyway. Declining is
      // always available (§7.1.1).
      let Ok(member) = member else {
        break;
      };
      if member.name() != b"permessage-deflate" {
        continue;
      }
      // A parameter the walk refused makes this ONE entry unusable — the
      // member boundaries are still sound, so the next alternative is
      // still readable.
      let Some(p) = collect_params(member.params(), false) else {
        continue;
      };

      // An offer demanding server_max_window_bits below 15 caps OUR
      // compressor — which miniz_oxide cannot bound (the same limit that
      // makes outbound sub-15 windows CompressionUnavailable on send).
      // Granting it would negotiate deflate and then fail every
      // compressed send, so DECLINE the offer instead (§7.1.1 skip):
      // the handshake completes without the extension. The peer-side
      // caps (client_max_window_bits, and server bits on the CLIENT)
      // bind the PEER'S compressor — RFC 7692 §7.1.2 places the limit
      // on the sender, no receiver enforcement is required, and our
      // fixed 32 KiB inflater decodes any conforming-or-narrower stream.
      if p.server_max_window_bits.is_some_and(|bits| bits < 15) {
        continue;
      }

      let params = DeflateParams {
        server_no_context_takeover: p.server_no_context_takeover
          || config.server_no_context_takeover,
        client_no_context_takeover: p.client_no_context_takeover
          || config.require_client_no_context_takeover,
        server_max_window_bits: p.server_max_window_bits.unwrap_or(15),
        client_max_window_bits: p.client_max_window_bits.unwrap_or(15),
      };
      // Echo client_max_window_bits only when the offer included the
      // param (with or without value) — otherwise it's illegal to send.
      let echo = p.client_max_window_bits.is_some() || p.client_max_window_bits_valueless;
      return Some((
        params,
        DeflateResponse {
          params,
          echo_server_max_window_bits: p.server_max_window_bits.is_some(),
          echo_client_max_window_bits: echo,
        },
      ));
    }
    None
  }
}

#[cfg(feature = "deflate")]
pub(crate) use deflate::response_matches_offer;
#[cfg(feature = "deflate")]
#[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
pub use deflate::{
  DeflateOffer, DeflateParams, DeflateResponse, MAX_EXTENSION_VALUE_BYTES, ServerDeflateConfig,
  accept_deflate_offer, parse_deflate_response,
};

/// Walks a `Sec-WebSocket-Protocol` REQUEST value — RFC 6455 §11.3.4's
/// `Sec-WebSocket-Protocol-Client = 1#token` — over every field line the client
/// sent, yielding the offers in preference order.
///
/// The `#rule` of RFC 2616 §2.1 (which RFC 9110 §5.6.1.2 restates) makes null
/// elements ignorable, so `list_elements` drops them; it also makes the `1` in
/// `1#` a rule about NON-null elements, which is
/// [`subprotocol_list_conforms`]'s to enforce. Reading is separated from
/// conformance exactly as [`extension_list`] is from
/// [`extension_list_conforms`], and for the same reason: one walk, two
/// questions, no second implementation to drift.
// `single_use_lifetimes` false-positive: anonymous lifetimes in `impl Trait`
// argument position are unstable (E0658), so the once-used lifetime must be
// named.
#[allow(single_use_lifetimes)]
pub(crate) fn subprotocol_list<'a, I>(lines: I) -> impl Iterator<Item = &'a [u8]>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  lines.into_iter().flat_map(list_elements)
}

/// Whether a received `Sec-WebSocket-Protocol` REQUEST value conforms to RFC
/// 6455's offer rules, read across every field line as one value.
///
/// Three rules, all of them the field's own grammar rather than any reader's
/// preference:
///
/// - `Sec-WebSocket-Protocol-Client = 1#token` (RFC 6455 §11.3.4). Read with the
///   `#rule` of RFC 2616 §2.1 — the ABNF RFC 6455 states its grammars in, and
///   RFC 822 §2.7's wording apart from the capitalised MUST:
///   "null elements are allowed, but do not contribute to the count of elements
///   present … where at least one element is required, at least one non-null
///   element MUST be present". So a field that is PRESENT and names nothing —
///   `""`, `","`, `",  ,"` — satisfies no `1#`, while a field that is ABSENT
///   conforms vacuously. (RFC 9110 §5.6.1.2 gives those three as its own
///   examples.)
/// - Every element is a `token` (§4.1 item 10: "non-empty strings with
///   characters in the range U+0021 to U+007E not including separator
///   characters").
/// - The elements "MUST all be unique strings" (§4.1 item 10), compared
///   EXACTLY: RFC 6455 grants case-insensitivity where it wants one (§4.2.1
///   items 3 and 4) and grants none to a subprotocol identifier.
///
/// Two further rules are this reader's own, and they are rules about WORK rather
/// than about the grammar: a value past [`MAX_SUBPROTOCOL_LIST_BYTES`] once its
/// lines are joined does not conform and is never walked, and a list past
/// [`MAX_SUBPROTOCOL_OFFERS`] elements does not conform, with the walk stopping
/// at the element that breaks the bound rather than reading what follows it.
/// Together they cap the uniqueness proof at 63 × 16 KiB byte steps — 0.42 ms,
/// measured — on either transport. See those constants for the numbers.
///
/// # One rule, both roles, both transports
///
/// This is the subprotocol twin of [`extension_list_conforms`], and it exists
/// because the crate used to answer the same `1#` question two ways: §9.1's
/// gate refused a present `Sec-WebSocket-Extensions` that named nothing, while
/// a present `Sec-WebSocket-Protocol` that named nothing read as a client that
/// had offered none — and the handshake reached a 101. Both h1 and
/// extended-CONNECT servers now ask this one function, over the complete value
/// their field accessor yields.
///
/// The lines are re-walked to compare each offer with the ones before it, which
/// is why the iterator must be `Clone`: this crate allocates nothing, so there
/// is no set to remember them in. That re-walk is why the element bound is
/// enforced BEFORE each comparison rather than after the walk: the bound is
/// what keeps the quadratic from being an unauthenticated peer's to choose.
// `single_use_lifetimes` false-positive: anonymous lifetimes in `impl Trait`
// argument position are unstable (E0658), so the once-used lifetime must be
// named.
#[allow(single_use_lifetimes)]
pub fn subprotocol_list_conforms<'a, I>(lines: I) -> bool
where
  I: IntoIterator<Item = &'a [u8]>,
  I::IntoIter: Clone,
{
  let lines = lines.into_iter();
  let present = lines.clone().next().is_some();
  // Ahead of every walk: the combined value RFC 9110 §5.2 makes of the lines is
  // what each re-walk crosses, so its length is the other half of the work
  // bound. Counted over the LINES rather than their bytes, and one comma-space
  // per join, which is the value §5.2 defines.
  let mut bytes = 0usize;
  for (i, line) in lines.clone().enumerate() {
    bytes = bytes
      .saturating_add(line.len())
      .saturating_add(if i == 0 { 0 } else { 2 });
    if bytes > MAX_SUBPROTOCOL_LIST_BYTES {
      return false;
    }
  }
  let offers = || subprotocol_list(lines.clone());
  let mut named = 0usize;
  for offer in offers() {
    // Ahead of the token check and the duplicate scan alike, so the element
    // that breaks the bound is the last one this walk reads: what follows it in
    // the value is never split, never compared, and never paid for.
    if named >= MAX_SUBPROTOCOL_OFFERS {
      return false;
    }
    if !is_token(offer) || offers().take(named).any(|prev| prev == offer) {
      return false;
    }
    named = named.saturating_add(1);
  }
  !present || named > 0
}

/// Server-side helper: the first of the CLIENT's offers (in client order)
/// that the server supports. Returns `None` when there is no overlap —
/// the server then accepts without a subprotocol.
///
/// Matching is EXACT. RFC 6455 nowhere states outright that subprotocol
/// identifiers are case-sensitive; what it does is grant case-insensitivity
/// wherever it wants one — `Upgrade` and `Connection` are "treated as an ASCII
/// case-insensitive value" (§4.2.1 items 3 and 4) — and grant none to a
/// subprotocol identifier, which §11.5 registers as nothing more than a token
/// (§4.1 item 10). Exact match is the reading that invents no folding.
///
/// The offers decide WHICH entry wins; the entry returned is `supported`'s,
/// so the selection outlives the request head the offers were read from. A
/// selection that borrowed the head could not survive it, and the server
/// must still be holding the chosen name when it encodes the 101.
///
/// The result's lifetime follows the ENTRIES, not the slice holding them: a
/// caller whose supported names live in owned strings elsewhere collects them
/// into a temporary list, and the selection outlives that list.
///
/// Both sides are `&str`: RFC 6455 §4.2.1 item 8 makes a subprotocol a token, so
/// unlike an extension value there is no `obs-text` or quoted-string for
/// `&str` to lose.
// `single_use_lifetimes` false-positive: anonymous lifetimes in `impl Trait`
// argument position are unstable (E0658), so the once-used lifetime must be
// named.
#[allow(single_use_lifetimes)]
pub fn select_subprotocol<'o, 's>(
  offered: impl IntoIterator<Item = &'o str>,
  supported: &[&'s str],
) -> Option<&'s str> {
  offered
    .into_iter()
    .find_map(|offer| supported.iter().copied().find(|entry| *entry == offer))
}

#[cfg(all(test, feature = "std", feature = "deflate"))]
mod deflate_tests {
  use super::*;

  #[test]
  fn params_default_to_the_rfc_defaults() {
    let p = DeflateParams::default();
    assert!(!p.server_no_context_takeover());
    assert!(!p.client_no_context_takeover());
    assert_eq!(p.server_max_window_bits(), 15);
    assert_eq!(p.client_max_window_bits(), 15);
  }

  /// [`MAX_EXTENSION_VALUE_BYTES`] is the size four inline buffers are declared
  /// at, and the reason it is safe is that nothing this crate renders reaches
  /// it. That is checked rather than asserted in prose: the widest OFFER and the
  /// widest GRANT — every RFC 7692 §7.1 parameter, window bits at two digits —
  /// must fit, with the slack the constant is chosen to carry.
  #[test]
  fn the_widest_rendered_extension_value_fits() {
    // Both window parameters spelled with two digits, and the client's below the
    // 15 default so the grant must echo it too (a 15 is the default and is left
    // out, which would make the answer NARROWER).
    let widest_offer = DeflateOffer::new()
      .with_server_no_context_takeover(true)
      .with_client_no_context_takeover(true)
      .with_server_max_window_bits(Some(15))
      .with_client_max_window_bits(Some(14));

    let mut buf = [0u8; MAX_EXTENSION_VALUE_BYTES];
    let offer_len = widest_offer.write(&mut buf).expect("the widest offer fits");

    // The server's answer to it is the widest grant: acceptance is BY inclusion
    // (RFC 7692 §7.1.2.1), so both window parameters are echoed.
    let (_, response) = accept_deflate_offer(
      [buf.get(..offer_len).unwrap()],
      &ServerDeflateConfig::new()
        .with_server_no_context_takeover(true)
        .with_require_client_no_context_takeover(true),
    )
    .expect("the widest offer is acceptable");
    let grant_len = response.write(&mut buf).expect("the widest grant fits");

    // Both are the same 128 bytes, and the constant carries slack over them: a
    // buffer of this size can never be why a render fails.
    assert_eq!(offer_len, 128);
    assert_eq!(grant_len, 128);
    assert!(
      offer_len.max(grant_len) < MAX_EXTENSION_VALUE_BYTES,
      "{MAX_EXTENSION_VALUE_BYTES} must exceed the widest rendered value"
    );
  }

  #[test]
  fn offer_renders_canonically() {
    let mut buf = [0u8; 256];

    let n = DeflateOffer::new().write(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"permessage-deflate; client_max_window_bits");

    let offer = DeflateOffer::new()
      .with_server_no_context_takeover(true)
      .with_client_no_context_takeover(true)
      .with_server_max_window_bits(Some(10))
      .with_client_max_window_bits(Some(12));
    let n = offer.write(&mut buf).unwrap();
    assert_eq!(
      &buf[..n],
      b"permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=10; client_max_window_bits=12"
    );
  }

  #[test]
  fn offer_rejects_out_of_range_bits_at_build() {
    assert!(
      DeflateOffer::new()
        .with_server_max_window_bits(Some(7))
        .validate()
        .is_err()
    );
    assert!(
      DeflateOffer::new()
        .with_client_max_window_bits(Some(16))
        .validate()
        .is_err()
    );
    assert!(
      DeflateOffer::new()
        .with_server_max_window_bits(Some(8))
        .validate()
        .is_ok()
    );
  }

  #[test]
  fn client_accepts_valid_response_params() {
    let offer = DeflateOffer::new(); // no server cap requested
    let p = parse_deflate_response([b"permessage-deflate".as_slice()], &offer).unwrap();
    assert_eq!(p.server_max_window_bits(), 15);
    assert_eq!(p.client_max_window_bits(), 15);
    let offer = DeflateOffer::new().with_server_max_window_bits(Some(12));
    let p = parse_deflate_response(
      [b"permessage-deflate; server_max_window_bits=12".as_slice()],
      &offer,
    )
    .unwrap();
    assert_eq!(p.server_max_window_bits(), 12);

    let p = parse_deflate_response(
      [b"permessage-deflate; server_no_context_takeover; server_max_window_bits=10".as_slice()],
      &offer,
    )
    .unwrap();
    assert!(p.server_no_context_takeover());
    assert_eq!(p.server_max_window_bits(), 10);

    // Server may demand client_no_context_takeover even if undeclared.
    // Use a fresh offer with no server cap so absence of server_max_window_bits
    // in the response is not a mismatch.
    let offer = DeflateOffer::new();
    let p = parse_deflate_response(
      [b"permessage-deflate; client_no_context_takeover".as_slice()],
      &offer,
    )
    .unwrap();
    assert!(p.client_no_context_takeover());

    // client_max_window_bits in the response is allowed: the default offer
    // includes the valueless param.
    let p = parse_deflate_response(
      [b"permessage-deflate; client_max_window_bits=9".as_slice()],
      &offer,
    )
    .unwrap();
    assert_eq!(p.client_max_window_bits(), 9);

    // RFC 6455 §9.1 states its ABNF "including the 'implied *LWS rule'", so
    // whitespace stands between any two adjacent words and between words and
    // separators — around the `;` and around the `=` alike. A server writing
    // the conforming spelling must not lose the negotiation: RFC 7692 §7
    // makes an extension response this side rejects FAIL the connection, so
    // "declined" here would mean "handshake refused". A reader holding this
    // value to a grammar stricter than §9.1's answers `is_err()` instead.
    let p = parse_deflate_response(
      [b"permessage-deflate ;  server_max_window_bits = 11".as_slice()],
      &offer,
    )
    .unwrap();
    assert_eq!(p.server_max_window_bits(), 11);
    // The same value quoted, and with LWS around the quoted form too.
    let p = parse_deflate_response(
      [b"permessage-deflate ; server_max_window_bits = \"11\"".as_slice()],
      &offer,
    )
    .unwrap();
    assert_eq!(p.server_max_window_bits(), 11);
    let p = parse_deflate_response(
      [b"permessage-deflate; server_max_window_bits=11".as_slice()],
      &offer,
    )
    .unwrap();
    assert_eq!(p.server_max_window_bits(), 11);
    // And on the OFFER path, where a divergence only ever declined: the server
    // reads the same spelling.
    let (params, _) = accept_deflate_offer(
      [b"permessage-deflate ; client_max_window_bits = 9".as_slice()],
      &ServerDeflateConfig::new(),
    )
    .unwrap();
    assert_eq!(params.client_max_window_bits(), 9);
  }

  /// Regression: the PUBLIC offer emitter refuses out-of-range
  /// window bits — `server_max_window_bits=7` on the wire would be rejected
  /// by this crate's own acceptor, so it must be an error, not bytes.
  #[test]
  fn out_of_range_offer_cannot_be_emitted() {
    let mut buf = [0u8; MAX_EXTENSION_VALUE_BYTES];
    for bad in [
      DeflateOffer::new().with_server_max_window_bits(Some(7)),
      DeflateOffer::new().with_server_max_window_bits(Some(16)),
      DeflateOffer::new().with_client_max_window_bits(Some(255)),
    ] {
      assert!(matches!(
        bad.write(&mut buf).unwrap_err(),
        NegotiationError::InvalidWindowBits
      ));
    }
    // In-range offers still render.
    assert!(
      DeflateOffer::new()
        .with_server_max_window_bits(Some(8))
        .write(&mut buf)
        .is_ok()
    );
  }

  /// Regression: an explicit `server_max_window_bits=15` offer
  /// must be ECHOED in the response — RFC 7692 §7.1.2.1 says a server
  /// accepts the parameter BY including it, and our own client parser
  /// rightly fails on the omission. Before the fix, a websocket-proto
  /// server accepting a websocket-proto client's explicit-15 offer
  /// produced a response that same client rejected (self-interop failure).
  #[test]
  fn sub_15_server_window_offers_are_declined() {
    // Regression: an offer demanding `server_max_window_bits`
    // BELOW 15 caps a compressor miniz_oxide cannot bound — granting it
    // would negotiate deflate whose every compressed send fails, so the
    // server DECLINES (no extension) instead. A later acceptable
    // alternative in the same list is still granted.
    let config = ServerDeflateConfig::new();
    assert!(
      accept_deflate_offer(
        [b"permessage-deflate; server_max_window_bits=10".as_slice()],
        &config
      )
      .is_none()
    );
    let (params, _) = accept_deflate_offer(
      [b"permessage-deflate; server_max_window_bits=10, permessage-deflate".as_slice()],
      &config,
    )
    .unwrap();
    assert_eq!(params.server_max_window_bits(), 15);
    assert!(
      accept_deflate_offer(
        [b"permessage-deflate; server_max_window_bits=15".as_slice()],
        &config
      )
      .is_some()
    );
  }

  #[test]
  fn explicit_server_window_bits_15_round_trips() {
    let offer = DeflateOffer::new().with_server_max_window_bits(Some(15));
    let mut offer_buf = [0u8; MAX_EXTENSION_VALUE_BYTES];
    let n = offer.write(&mut offer_buf).unwrap();
    let offer_value = &offer_buf[..n];

    let (params, response) =
      accept_deflate_offer([offer_value], &ServerDeflateConfig::new()).unwrap();
    assert_eq!(params.server_max_window_bits(), 15);

    let mut resp_buf = [0u8; MAX_EXTENSION_VALUE_BYTES];
    let n = response.write(&mut resp_buf).unwrap();
    let resp_value = &resp_buf[..n];
    let resp_text = core::str::from_utf8(resp_value).unwrap();
    assert!(
      resp_text.contains("server_max_window_bits=15"),
      "{resp_text}"
    );

    // The strict client parser accepts its own server's response.
    let agreed = parse_deflate_response([resp_value], &offer).unwrap();
    assert_eq!(agreed.server_max_window_bits(), 15);

    // An offer WITHOUT the parameter still gets no echo (it is illegal to
    // introduce a parameter the offer did not carry).
    let plain = DeflateOffer::new();
    let mut buf = [0u8; MAX_EXTENSION_VALUE_BYTES];
    let n = plain.write(&mut buf).unwrap();
    let (_, response) = accept_deflate_offer([&buf[..n]], &ServerDeflateConfig::new()).unwrap();
    let n = response.write(&mut resp_buf).unwrap();
    let resp_text = core::str::from_utf8(&resp_buf[..n]).unwrap();
    assert!(!resp_text.contains("server_max_window_bits"), "{resp_text}");
  }

  #[test]
  fn client_rejects_invalid_response_params() {
    let offer = DeflateOffer::new(); // includes valueless client_max_window_bits

    let bad_values: [&[u8]; 12] = [
      b"permessage-deflate; server_max_window_bits", // valueless where value required
      b"permessage-deflate; server_max_window_bits=7", // out of range
      b"permessage-deflate; server_max_window_bits=16", // out of range
      b"permessage-deflate; server_max_window_bits=\"12", // unterminated quote
      b"permessage-deflate; server_max_window_bits=\"12\\\"", // trailing escape
      b"permessage-deflate; server_max_window_bits=\"\"", // empty quoted value
      b"permessage-deflate; client_max_window_bits=08", // leading zero (not DIGIT canonical)
      b"permessage-deflate; unknown_param",          // unknown
      b"permessage-deflate; client_no_context_takeover; client_no_context_takeover", // dup
      b"gzip",                                       // not what we offered
      b"permessage-deflate, permessage-deflate",     // two accepted extensions
      b"",                                           // empty value
    ];
    for bad in bad_values {
      assert!(
        parse_deflate_response([bad], &offer).is_err(),
        "{}",
        core::str::from_utf8(bad).unwrap()
      );
    }

    // Regression: RFC 6455 §9.1 lets a parameter value be a
    // quoted-string whose unescaped form is a token — a conforming peer may
    // send server_max_window_bits="10" and must not lose the negotiation.
    let p = parse_deflate_response(
      [b"permessage-deflate; server_max_window_bits=\"10\"".as_slice()],
      &offer,
    )
    .unwrap();
    assert_eq!(p.server_max_window_bits(), 10);
    // Quoted-pair unescaping: "1\2" unescapes to 12.
    let p = parse_deflate_response(
      [b"permessage-deflate; client_max_window_bits=\"1\\2\"".as_slice()],
      &offer,
    )
    .unwrap();
    assert_eq!(p.client_max_window_bits(), 12);

    // Regression: empty list elements are ignored, not fatal
    // (RFC 9110 §5.6.1.2) — a stray comma around the single entry is fine,
    // while a second NON-EMPTY entry stays a mismatch (tested above).
    assert!(parse_deflate_response([b"permessage-deflate,".as_slice()], &offer).is_ok());
    assert!(parse_deflate_response([b", permessage-deflate".as_slice()], &offer).is_ok());

    // server_max_window_bits above what we requested.
    let capped = DeflateOffer::new().with_server_max_window_bits(Some(10));
    assert!(
      parse_deflate_response(
        [b"permessage-deflate; server_max_window_bits=12".as_slice()],
        &capped
      )
      .is_err()
    );

    // Our requested server cap silently ignored (param absent) → mismatch.
    let capped = DeflateOffer::new().with_server_max_window_bits(Some(10));
    assert!(parse_deflate_response([b"permessage-deflate".as_slice()], &capped).is_err());

    // Regression: a requested server_no_context_takeover that the
    // response does NOT echo was not granted (RFC 7692 §7.1.1.1) — accepting
    // it would desync our per-message-reset inflater against a server that
    // keeps its window. Echoed, it is granted.
    let want_reset = DeflateOffer::new().with_server_no_context_takeover(true);
    assert!(matches!(
      parse_deflate_response([b"permessage-deflate".as_slice()], &want_reset).unwrap_err(),
      NegotiationError::ExtensionMismatch
    ));
    let p = parse_deflate_response(
      [b"permessage-deflate; server_no_context_takeover".as_slice()],
      &want_reset,
    )
    .unwrap();
    assert!(p.server_no_context_takeover());
    // Unrequested but echoed: the server self-restricts — fine, and the
    // negotiated flag is response-derived.
    let p = parse_deflate_response(
      [b"permessage-deflate; server_no_context_takeover".as_slice()],
      &DeflateOffer::new(),
    )
    .unwrap();
    assert!(p.server_no_context_takeover());

    // client_max_window_bits in the response when our offer disabled it.
    let no_cmwb = DeflateOffer::new().without_client_max_window_bits();
    assert!(
      parse_deflate_response(
        [b"permessage-deflate; client_max_window_bits=12".as_slice()],
        &no_cmwb
      )
      .is_err()
    );
  }

  #[test]
  fn server_picks_the_first_acceptable_offer() {
    let config = ServerDeflateConfig::new();

    // Two alternative offers: the first is unacceptable (unknown param),
    // the second is fine — the server takes the second.
    let value = b"permessage-deflate; nonsense, permessage-deflate; client_max_window_bits";
    let (params, _) = accept_deflate_offer([value.as_slice()], &config).unwrap();
    assert_eq!(params.client_max_window_bits(), 15);

    // No acceptable offer → None (the server just omits the extension).
    assert!(accept_deflate_offer([b"permessage-deflate; bogus".as_slice()], &config).is_none());
    assert!(accept_deflate_offer([], &config).is_none());

    // The server honors client-requested takeover restrictions and echoes
    // an explicit (honorable, =15) window demand.
    let value = b"permessage-deflate; server_no_context_takeover; server_max_window_bits=15";
    let (params, response) = accept_deflate_offer([value.as_slice()], &config).unwrap();
    assert!(params.server_no_context_takeover());
    assert_eq!(params.server_max_window_bits(), 15);
    let mut buf = [0u8; 256];
    let n = response.write(&mut buf).unwrap();
    let s = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(s.starts_with("permessage-deflate"));
    assert!(s.contains("server_no_context_takeover"));
    assert!(s.contains("server_max_window_bits=15"));

    // A config that demands client_no_context_takeover emits it even when
    // the client didn't declare it.
    let demanding = ServerDeflateConfig::new().with_require_client_no_context_takeover(true);
    let (params, response) =
      accept_deflate_offer([b"permessage-deflate".as_slice()], &demanding).unwrap();
    assert!(params.client_no_context_takeover());
    let n = response.write(&mut buf).unwrap();
    assert!(
      core::str::from_utf8(&buf[..n])
        .unwrap()
        .contains("client_no_context_takeover")
    );
  }

  // RFC 6455 §9.1: a parameter value may be a quoted-string, and a comma or
  // semicolon inside it is data, not a separator.
  #[test]
  fn an_extension_parameter_may_quote_its_separators() {
    let offered: &[u8] = b"x-note; v=\"a,b\", permessage-deflate; server_no_context_takeover";
    let (params, _response) =
      accept_deflate_offer([offered], &ServerDeflateConfig::default()).unwrap();
    // The quoted comma did not split `x-note` into two members, so the deflate
    // offer that follows it was found — and its parameter was read.
    assert!(params.server_no_context_takeover());
  }

  /// The conformance defect quoted-string awareness fixes: a comma-splitter
  /// without it cuts inside a quoted-string and reads its CONTENT as list
  /// members, so a client that
  /// never offered permessage-deflate gets it negotiated — and then receives
  /// RSV1-compressed frames it never agreed to. Here the whole value is ONE
  /// `x-note` member (RFC 9110 §5.6.4 makes the interior data), so there is
  /// no deflate offer to accept.
  #[test]
  fn an_offer_cannot_be_fabricated_from_inside_a_quoted_string() {
    let config = ServerDeflateConfig::default();
    let offered: &[u8] = b"x-note; v=\"a,permessage-deflate;client_max_window_bits=8,b\"";
    assert!(accept_deflate_offer([offered], &config).is_none());

    // The same for the response bind: a grant minted elsewhere must not be
    // legalized by an offer that exists only inside a quoted-string.
    let real: &[u8] = b"permessage-deflate; client_max_window_bits=8";
    let (_, response) = accept_deflate_offer([real], &config).unwrap();
    assert!(response_matches_offer([real], &response));
    assert!(!response_matches_offer([offered], &response));
  }

  #[test]
  fn an_unterminated_quoted_parameter_does_not_yield_an_offer() {
    let offered: &[u8] = b"permessage-deflate; x=\"open";
    assert!(accept_deflate_offer([offered], &ServerDeflateConfig::default()).is_none());
  }

  // A member the walk cannot resolve ENDS the walk — past a value §9.1's
  // grammar does not admit, nothing behind it is what the peer wrote — so an
  // offer behind one is not granted.
  // A refused PARAMETER is different: it spoils only its own member, and the
  // alternatives after it are still read (`server_picks_the_first_acceptable_offer`).
  // Declining is always available to a server (RFC 7692 §7.1.1), so the
  // handshake still completes, just without compression.
  #[test]
  fn an_offer_behind_an_unresolvable_member_is_not_granted() {
    let config = ServerDeflateConfig::default();
    assert!(accept_deflate_offer([b"x@y, permessage-deflate".as_slice()], &config).is_none());
    // Without the unresolvable member ahead of it the very same offer IS
    // granted, so the refusal is that member's doing.
    assert!(accept_deflate_offer([b"permessage-deflate".as_slice()], &config).is_some());
  }

  #[test]
  fn response_round_trips_through_client_validation() {
    // Whatever accept_deflate_offer emits, parse_deflate_response accepts,
    // and both sides land on identical DeflateParams.
    let offer = DeflateOffer::new()
      .with_server_no_context_takeover(true)
      .with_server_max_window_bits(Some(15));
    let mut offer_buf = [0u8; 256];
    let n = offer.write(&mut offer_buf).unwrap();

    let config = ServerDeflateConfig::new();
    let (server_params, response) = accept_deflate_offer([&offer_buf[..n]], &config).unwrap();

    let mut resp_buf = [0u8; 256];
    let n = response.write(&mut resp_buf).unwrap();

    let client_params = parse_deflate_response([&resp_buf[..n]], &offer).unwrap();
    assert_eq!(client_params, server_params);
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  #[test]
  fn none_negotiated_is_empty() {
    let n = Negotiated::none();
    assert_eq!(n.subprotocol(), None);
  }

  #[test]
  fn subprotocol_round_trips_through_storage() {
    let n = Negotiated::with_subprotocol("graphql-ws").unwrap();
    assert_eq!(n.subprotocol(), Some("graphql-ws"));
  }

  #[test]
  fn invalid_subprotocol_tokens_are_rejected() {
    assert!(matches!(
      Negotiated::with_subprotocol("has space").unwrap_err(),
      NegotiationError::InvalidSubprotocol
    ));
    assert!(matches!(
      Negotiated::with_subprotocol("").unwrap_err(),
      NegotiationError::InvalidSubprotocol
    ));
  }

  #[test]
  fn subprotocol_matching_is_case_sensitive() {
    // RFC 6455 grants a subprotocol identifier no case-insensitive comparison
    // (contrast §4.2.1 items 3 and 4), so `CHAT` is NOT the offered `chat`.
    assert_eq!(select_subprotocol(["chat"], &["CHAT"]), None);
    assert_eq!(select_subprotocol(["CHAT"], &["chat"]), None);
    assert_eq!(select_subprotocol(["chat"], &["chat"]), Some("chat"));
  }

  #[test]
  fn subprotocol_cap_is_uniform_across_tiers() {
    // Exactly at the cap: retained.
    let max = "a".repeat(MAX_SUBPROTOCOL_LEN);
    let n = Negotiated::with_subprotocol(&max).unwrap();
    assert_eq!(n.subprotocol(), Some(max.as_str()));

    // One past the cap: rejected on EVERY tier (inline storage).
    let over = "a".repeat(MAX_SUBPROTOCOL_LEN + 1);
    assert!(matches!(
      Negotiated::with_subprotocol(&over).unwrap_err(),
      NegotiationError::InvalidSubprotocol
    ));

    // Negotiated is Copy now — a copy observes the same subprotocol.
    let copied = n;
    assert_eq!(copied.subprotocol(), n.subprotocol());
  }

  #[test]
  fn select_subprotocol_prefers_client_order() {
    let offers = ["b", "a", "c"];
    assert_eq!(
      select_subprotocol(offers.iter().copied(), &["a", "b"]),
      Some("b") // first CLIENT offer the server supports
    );
    assert_eq!(select_subprotocol(offers.iter().copied(), &["zzz"]), None);
    assert_eq!(select_subprotocol(core::iter::empty(), &["a"]), None);

    // The order is the CLIENT's, but the bytes returned are the SERVER's
    // entry. Both spellings are built at runtime so neither can borrow the
    // other's storage through a shared literal, and the pointer says which
    // list the answer came from.
    let client: [String; 3] = ["b".into(), "a".into(), "c".into()];
    let supported: [String; 2] = ["a".into(), "b".into()];
    let supported: [&str; 2] = [supported[0].as_str(), supported[1].as_str()];
    let chosen = select_subprotocol(client.iter().map(String::as_str), &supported).unwrap();
    assert_eq!(chosen, "b");
    assert!(core::ptr::eq(chosen.as_ptr(), supported[1].as_ptr()));
  }

  /// RFC 6455 §9.1's ABNF, which the field MUST conform to or the connection
  /// fails. Everything here is malformed under every reading of it.
  #[test]
  fn a_malformed_extension_list_does_not_conform() {
    for bad in [
      // `extension-token = registered-token`, `registered-token = token`.
      "x@y",
      "permessage-deflate, x@y",
      "x@y, permessage-deflate",
      "\"quoted-name\"",
      // `extension-param`'s name is a token too.
      "permessage-deflate; x@y",
      "permessage-deflate; x@y=1",
      // A bare value is a token; an empty one is not (`token = 1*tchar`).
      "permessage-deflate; x=@",
      "permessage-deflate; x=",
      // quoted-string: never closed, trailing escape, bytes behind the close.
      "permessage-deflate; x=\"open",
      "permessage-deflate; x=\"open\\\"",
      "permessage-deflate; x=\"ok\"tail",
      // "the value after quoted-string unescaping MUST conform to the 'token'
      // ABNF" — a space, an escaped backslash, and the empty string do not.
      "permessage-deflate; x=\"a b\"",
      "permessage-deflate; x=\"\\\\\"",
      "permessage-deflate; x=\"\"",
      // `extension-list = 1#extension`: at least one non-empty element.
      "",
      ",",
      ",   ,",
      // `extension = extension-token *( ";" extension-param )`: the parameter
      // after a semicolon is MANDATORY — `[ … ]` covers only the `=` value —
      // and RFC 2616 §2.1's implied *LWS rule puts whitespace between
      // productions rather than removing one.
      "permessage-deflate;",
      "permessage-deflate; ",
      "permessage-deflate;;client_max_window_bits",
      "permessage-deflate; ; client_max_window_bits",
      "permessage-deflate; client_max_window_bits;",
      "x-private; a; b=c;",
      // The same slot, on a member that is not the last of the list.
      "permessage-deflate;, x-other",
      "x-other, permessage-deflate;;a",
    ] {
      assert!(
        !extension_list_conforms([bad.as_bytes()]),
        "{bad:?} conforms"
      );
    }
  }

  /// The other half of the same MUST: a value §9.1 admits must NOT fail the
  /// handshake, however little this build can do with it. Declining an
  /// unsupported extension is a separate answer, given one layer up.
  #[test]
  fn a_conforming_extension_list_conforms() {
    for good in [
      "permessage-deflate",
      "permessage-deflate; client_max_window_bits",
      "permessage-deflate; server_max_window_bits=15",
      "permessage-deflate; x=\"12\"",
      // A quoted-pair whose unescaped form is still a token.
      "permessage-deflate; x=\"1\\2\"",
      // Extensions this crate has never heard of are well formed all the same.
      "x-private; a; b=c, permessage-deflate",
      // RFC 9110 §5.6.1.2's ignorable empty elements, around a real one.
      ", permessage-deflate,",
      // RFC 6455 §9.1 states its ABNF "including the 'implied *LWS rule'", so
      // whitespace between words and separators does not make a value
      // malformed — even where RFC 9110 §5.6.6's `parameter` would refuse it.
      // The negotiation behind this gate reads the same grammar, so it
      // negotiates the spelling rather than declining it
      // (`client_accepts_valid_response_params`).
      "permessage-deflate ;  server_max_window_bits = 11",
      "permessage-deflate; x = \"12\"",
      // A named parameter with no value is what `[ "=" … ]` makes optional, and
      // it is how RFC 7692 §7.1.2.2 offers `client_max_window_bits`.
      "permessage-deflate; client_max_window_bits; server_no_context_takeover",
    ] {
      assert!(
        extension_list_conforms([good.as_bytes()]),
        "{good:?} does not conform"
      );
    }
    // An absent field conforms vacuously; a present but empty one does not.
    assert!(extension_list_conforms(core::iter::empty()));
    assert!(!extension_list_conforms([b"".as_slice()]));
  }

  /// RFC 9110 §5.2 makes the field's several lines one comma-joined value, and
  /// §9.1 permits a client to split the list that way. The `1#` cardinality is
  /// therefore asked globally — and a quoted-string that spans the join is
  /// malformed, because the join's comma lands inside the value §9.1 requires
  /// to unescape to a `token`.
  #[test]
  fn an_extension_list_split_across_field_lines_is_one_value() {
    assert!(extension_list_conforms([
      b"permessage-deflate".as_slice(),
      b"x-other; a=b".as_slice(),
    ]));
    // Neither line names anything, so the joined value satisfies no `1#`.
    assert!(!extension_list_conforms([
      b"".as_slice(),
      b" ".as_slice(),
      b",".as_slice()
    ]));
    // One empty line beside a real one is fine (the join is `, permessage-…`).
    assert!(extension_list_conforms([
      b"".as_slice(),
      b"permessage-deflate".as_slice()
    ]));
    // The quoted value that spans the join: `x="a` + `b"` is `x="a,b"`, whose
    // unescaped form carries a comma and is not a token.
    assert!(!extension_list_conforms([
      b"permessage-deflate; x=\"a".as_slice(),
      b"b\"".as_slice()
    ]));
    // Even escaping the join comma does not rescue it — it is still a comma.
    assert!(!extension_list_conforms([
      b"permessage-deflate; x=\"a\\".as_slice(),
      b"b\"".as_slice()
    ]));
    // A malformed member on ANY line fails the whole value.
    assert!(!extension_list_conforms([
      b"permessage-deflate".as_slice(),
      b"x@y".as_slice()
    ]));
  }

  /// The offer list is bounded, and the bound is what keeps the uniqueness
  /// proof from being an unauthenticated peer's to make expensive.
  ///
  /// RFC 9110 §5.4 is the clause: a server refuses a "request header field
  /// line, field value, or set of fields larger than it wishes to process" with
  /// a 4xx, which is what a reject-only handshake writes. §5.6.1.2's
  /// denial-of-service sentence is NOT the clause — it governs empty elements,
  /// and the padded case below is this test's own evidence that they are
  /// unbounded here.
  #[test]
  fn the_offer_list_is_bounded() {
    let names: Vec<String> = (0..=MAX_SUBPROTOCOL_OFFERS)
      .map(|i| format!("p{i}"))
      .collect();

    // Exactly the cap conforms; one past it does not — and the reason is the
    // COUNT, since every element is a distinct token either way.
    let at_cap = names.get(..MAX_SUBPROTOCOL_OFFERS).unwrap().join(", ");
    assert!(subprotocol_list_conforms([at_cap.as_bytes()]));
    let over_cap = names.join(", ");
    assert!(!subprotocol_list_conforms([over_cap.as_bytes()]));

    // Split across field lines is the same value (RFC 9110 §5.2), so it reaches
    // the same verdict: the bound is over the field, not over a line.
    let lines: Vec<&[u8]> = names.iter().map(|n| n.as_bytes()).collect();
    assert!(!subprotocol_list_conforms(lines.iter().copied()));
    assert!(subprotocol_list_conforms(
      lines.get(..MAX_SUBPROTOCOL_OFFERS).unwrap().iter().copied()
    ));

    // Null elements do not count toward it — RFC 9110 §5.6.1.2 says empty
    // elements "do not contribute to the count of elements present" — so a
    // value padded with commas is still read, and still bounded by the
    // elements that name something.
    let padded = format!(",,,{at_cap},,,");
    assert!(subprotocol_list_conforms([padded.as_bytes()]));

    // The worst input the bound ADMITS: the cap's worth of offers with the
    // whole of a 16 KiB h1 head's remaining bytes in front of them, which is
    // what maximises the prefix each re-walk pays for. It conforms, and it is
    // the most work any accepted value can cost.
    let filler = "f".repeat(http1_proto::MAX_HEAD_BYTES - at_cap.len() - 512);
    let worst = format!("{filler}, {at_cap}");
    assert!(worst.len() < http1_proto::MAX_HEAD_BYTES);
    assert!(
      !subprotocol_list_conforms([worst.as_bytes()]),
      "one filler element plus the cap is one past the cap"
    );
    let worst = format!(
      "{filler}, {}",
      names.get(..MAX_SUBPROTOCOL_OFFERS - 1).unwrap().join(", ")
    );
    assert!(subprotocol_list_conforms([worst.as_bytes()]));

    // And the bound stops the WALK, not just the verdict: a value with the cap
    // exceeded early is refused however much follows it.
    let refused = format!("{over_cap}, {}", "x".repeat(1024));
    assert!(!subprotocol_list_conforms([refused.as_bytes()]));

    // ── the byte half of the same bound ───────────────────────────────────
    // One element, so the COUNT cannot be what decides it: at the ceiling it
    // conforms, one byte past it does not.
    let at_bytes = "b".repeat(MAX_SUBPROTOCOL_LIST_BYTES);
    assert!(subprotocol_list_conforms([at_bytes.as_bytes()]));
    let over_bytes = "b".repeat(MAX_SUBPROTOCOL_LIST_BYTES + 1);
    assert!(!subprotocol_list_conforms([over_bytes.as_bytes()]));

    // It is the JOINED value that is measured (RFC 9110 §5.2), not a line: two
    // lines that fit separately can exceed it together, and the comma-space the
    // join inserts counts toward the total. Distinct fills, so §4.1 item 10's
    // uniqueness is not what decides either case.
    let first = "b".repeat(MAX_SUBPROTOCOL_LIST_BYTES / 2);
    let second = "c".repeat(MAX_SUBPROTOCOL_LIST_BYTES / 2 - 2);
    assert_eq!(
      first.len() + second.len() + 2,
      MAX_SUBPROTOCOL_LIST_BYTES,
      "the two lines join to exactly the ceiling"
    );
    assert!(subprotocol_list_conforms([
      first.as_bytes(),
      second.as_bytes()
    ]));
    let one_over = "c".repeat(MAX_SUBPROTOCOL_LIST_BYTES / 2 - 1);
    assert!(!subprotocol_list_conforms([
      first.as_bytes(),
      one_over.as_bytes()
    ]));

    // On h1 the ceiling refuses nothing that could have arrived — a field value
    // cannot outgrow the head that carries it — so it is the extended-CONNECT
    // path, handed an already-decoded slice, that it actually bounds.
    assert_eq!(MAX_SUBPROTOCOL_LIST_BYTES, http1_proto::MAX_HEAD_BYTES);
  }

  // RFC 6455 grants a subprotocol identifier no case-insensitive comparison, and
  // the selected name must outlive the request head.
  #[test]
  fn the_selected_subprotocol_borrows_the_server_list() {
    let supported = ["chat", "superchat"];
    let chosen = {
      let offers = String::from("superchat, chat");
      select_subprotocol(offers.split(", "), &supported)
    }; // the offers are gone; `chosen` is still valid
    assert_eq!(chosen, Some("superchat"));
  }
}
