//! Negotiation results shared by every handshake transport.
//!
//! [`Negotiated`] is the sole gate into the connection state machine: the h1
//! machines produce it from header bytes, and the RFC 8441/9220 `connect`
//! types produce it from header data. The module is **allocation-free on
//! every tier** — the subprotocol lives in an inline buffer capped at
//! [`MAX_SUBPROTOCOL_LEN`](crate::negotiation::MAX_SUBPROTOCOL_LEN) bytes (registered subprotocol names are short
//! tokens; the longest in the IANA registry is well under half the cap), so
//! [`Negotiated`] is `Copy` and fully available on the bare `no_std` tier.

use crate::handshake::parser::is_token;
use derive_more::{IsVariant, TryUnwrap, Unwrap};

/// Maximum retained subprotocol length, on every tier. Longer offers are
/// rejected as [`NegotiationError::InvalidSubprotocol`].
pub const MAX_SUBPROTOCOL_LEN: usize = 64;

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
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
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
    if !is_token(subprotocol) {
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

#[cfg(feature = "deflate")]
mod deflate {
  use super::NegotiationError;
  use crate::{error::BufferTooSmallDetail, handshake::WriteCursor};

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

    /// Writes the offer as a `Sec-WebSocket-Extensions` value.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, BufferTooSmallDetail> {
      let mut w = WriteCursor::new(out);
      self.write_to(&mut w)?;
      Ok(w.written())
    }

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

  /// One parsed parameter: name plus optional unquoted value.
  struct Param<'a> {
    name: &'a str,
    value: Option<&'a str>,
  }

  /// Splits one extension entry (`name; p1; p2=v`) — strict ABNF: no OWS
  /// inside params beyond the separator pattern `"; "` being tolerated as
  /// `;` OWS-trimmed per RFC 6455 §9.1's extension-list grammar.
  fn parse_entry(entry: &str) -> Option<(&str, ParamIter<'_>)> {
    let mut parts = entry.split(';');
    let name = parts.next()?.trim_matches([' ', '\t']);
    Some((name, ParamIter { parts }))
  }

  struct ParamIter<'a> {
    parts: core::str::Split<'a, char>,
  }

  impl<'a> Iterator for ParamIter<'a> {
    type Item = Option<Param<'a>>; // None item = malformed param

    fn next(&mut self) -> Option<Self::Item> {
      let raw = self.parts.next()?;
      let raw = raw.trim_matches([' ', '\t']);
      if raw.is_empty() {
        return Some(None);
      }
      match raw.split_once('=') {
        None => {
          if crate::handshake::parser::is_token(raw) {
            Some(Some(Param {
              name: raw,
              value: None,
            }))
          } else {
            Some(None)
          }
        }
        Some((name, value)) => {
          if crate::handshake::parser::is_token(name) && !value.is_empty() {
            Some(Some(Param {
              name,
              value: Some(value),
            }))
          } else {
            Some(None)
          }
        }
      }
    }
  }

  /// Parses a window-bits value: 1–2 plain digits, canonical (no leading
  /// zero), in 8..=15.
  fn parse_bits(value: &str) -> Option<u8> {
    if value.len() > 2 || value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
      return None;
    }
    let bits: u8 = value.parse().ok()?;
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
  /// from offers (it may be valueless).
  fn collect_params(params: ParamIter<'_>, in_response: bool) -> Option<EntryParams> {
    let mut out = EntryParams::default();
    for param in params {
      let param = param?;
      match (param.name, param.value) {
        ("server_no_context_takeover", None) => {
          if out.server_no_context_takeover {
            return None;
          }
          out.server_no_context_takeover = true;
        }
        ("client_no_context_takeover", None) => {
          if out.client_no_context_takeover {
            return None;
          }
          out.client_no_context_takeover = true;
        }
        ("server_max_window_bits", Some(v)) => {
          if out.server_max_window_bits.is_some() {
            return None;
          }
          out.server_max_window_bits = Some(parse_bits(v)?);
        }
        ("client_max_window_bits", None) if !in_response => {
          if out.client_max_window_bits.is_some() || out.client_max_window_bits_valueless {
            return None;
          }
          out.client_max_window_bits_valueless = true;
        }
        ("client_max_window_bits", Some(v)) => {
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
  /// response value against `offer`, yielding the agreed parameters.
  /// Errors here fail the WebSocket connection (RFC 7692 §8.1).
  pub fn parse_deflate_response(
    value: &str,
    offer: &DeflateOffer,
  ) -> Result<DeflateParams, NegotiationError> {
    // The response must contain exactly one extension entry.
    let mut entries = value.split(',');
    let entry = entries.next().unwrap_or("").trim_matches([' ', '\t']);
    if entries.next().is_some() || entry.is_empty() {
      return Err(NegotiationError::ExtensionMismatch);
    }
    let Some((name, params)) = parse_entry(entry) else {
      return Err(NegotiationError::InvalidExtension);
    };
    if name != "permessage-deflate" {
      return Err(NegotiationError::ExtensionMismatch);
    }
    let Some(p) = collect_params(params, true) else {
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

    Ok(DeflateParams {
      server_no_context_takeover: p.server_no_context_takeover || offer.server_no_context_takeover,
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
      if self.params.server_max_window_bits != 15 {
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

  /// Server-side: scans the client's offer list (across repeated
  /// `Sec-WebSocket-Extensions` headers, comma-separated alternatives) and
  /// accepts the FIRST valid `permessage-deflate` offer, returning the
  /// agreed params plus the response entry to emit. `None` means "decline
  /// the extension" (omit the response header) — malformed or unknown
  /// offers are skipped, not fatal (§7.1.1: the server simply doesn't
  /// accept them).
  pub fn accept_deflate_offer<'a>(
    header_values: impl Iterator<Item = &'a str>,
    config: &ServerDeflateConfig,
  ) -> Option<(DeflateParams, DeflateResponse)> {
    for value in header_values {
      for entry in value.split(',') {
        let entry = entry.trim_matches([' ', '\t']);
        if entry.is_empty() {
          continue;
        }
        let Some((name, params)) = parse_entry(entry) else {
          continue;
        };
        if name != "permessage-deflate" {
          continue;
        }
        let Some(p) = collect_params(params, false) else {
          continue;
        };

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
            echo_client_max_window_bits: echo,
          },
        ));
      }
    }
    None
  }
}

#[cfg(feature = "deflate")]
#[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
pub use deflate::{
  DeflateOffer, DeflateParams, DeflateResponse, ServerDeflateConfig, accept_deflate_offer,
  parse_deflate_response,
};

/// Server-side helper: the first of the CLIENT's offers (in client order)
/// that the server supports. Returns `None` when there is no overlap —
/// the server then accepts without a subprotocol.
///
/// Matching is case-SENSITIVE: RFC 6455 §11.5 registers subprotocol
/// identifiers as case-sensitive (unlike `Upgrade`/`Connection` tokens).
pub fn select_subprotocol<'a>(
  offered: impl IntoIterator<Item = &'a str>,
  supported: &[&str],
) -> Option<&'a str> {
  offered.into_iter().find(|offer| supported.contains(offer))
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
    let p = parse_deflate_response("permessage-deflate", &offer).unwrap();
    assert_eq!(p.server_max_window_bits(), 15);
    assert_eq!(p.client_max_window_bits(), 15);
    let offer = DeflateOffer::new().with_server_max_window_bits(Some(12));
    let p =
      parse_deflate_response("permessage-deflate; server_max_window_bits=12", &offer).unwrap();
    assert_eq!(p.server_max_window_bits(), 12);

    let p = parse_deflate_response(
      "permessage-deflate; server_no_context_takeover; server_max_window_bits=10",
      &offer,
    )
    .unwrap();
    assert!(p.server_no_context_takeover());
    assert_eq!(p.server_max_window_bits(), 10);

    // Server may demand client_no_context_takeover even if undeclared.
    // Use a fresh offer with no server cap so absence of server_max_window_bits
    // in the response is not a mismatch.
    let offer = DeflateOffer::new();
    let p =
      parse_deflate_response("permessage-deflate; client_no_context_takeover", &offer).unwrap();
    assert!(p.client_no_context_takeover());

    // client_max_window_bits in the response is allowed: the default offer
    // includes the valueless param.
    let p = parse_deflate_response("permessage-deflate; client_max_window_bits=9", &offer).unwrap();
    assert_eq!(p.client_max_window_bits(), 9);

    // OWS tolerance around separators.
    let p = parse_deflate_response("permessage-deflate ;  server_max_window_bits = 11", &offer);
    assert!(p.is_err(), "spaces around '=' are not in the ABNF");
    let p =
      parse_deflate_response("permessage-deflate; server_max_window_bits=11", &offer).unwrap();
    assert_eq!(p.server_max_window_bits(), 11);
  }

  #[test]
  fn client_rejects_invalid_response_params() {
    let offer = DeflateOffer::new(); // includes valueless client_max_window_bits

    for bad in [
      "permessage-deflate; server_max_window_bits", // valueless where value required
      "permessage-deflate; server_max_window_bits=7", // out of range
      "permessage-deflate; server_max_window_bits=16", // out of range
      "permessage-deflate; server_max_window_bits=\"12\"", // quoted
      "permessage-deflate; client_max_window_bits=08", // leading zero (not DIGIT canonical)
      "permessage-deflate; unknown_param",          // unknown
      "permessage-deflate; client_no_context_takeover; client_no_context_takeover", // dup
      "gzip",                                       // not what we offered
      "permessage-deflate, permessage-deflate",     // two accepted extensions
      "",                                           // empty value
    ] {
      assert!(parse_deflate_response(bad, &offer).is_err(), "{bad}");
    }

    // server_max_window_bits above what we requested.
    let capped = DeflateOffer::new().with_server_max_window_bits(Some(10));
    assert!(
      parse_deflate_response("permessage-deflate; server_max_window_bits=12", &capped).is_err()
    );

    // Our requested server cap silently ignored (param absent) → mismatch.
    let capped = DeflateOffer::new().with_server_max_window_bits(Some(10));
    assert!(parse_deflate_response("permessage-deflate", &capped).is_err());

    // client_max_window_bits in the response when our offer disabled it.
    let no_cmwb = DeflateOffer::new().without_client_max_window_bits();
    assert!(
      parse_deflate_response("permessage-deflate; client_max_window_bits=12", &no_cmwb).is_err()
    );
  }

  #[test]
  fn server_picks_the_first_acceptable_offer() {
    let config = ServerDeflateConfig::new();

    // Two alternative offers: the first is unacceptable (unknown param),
    // the second is fine — the server takes the second.
    let value = "permessage-deflate; nonsense, permessage-deflate; client_max_window_bits";
    let (params, _) = accept_deflate_offer([value].into_iter(), &config).unwrap();
    assert_eq!(params.client_max_window_bits(), 15);

    // No acceptable offer → None (the server just omits the extension).
    assert!(accept_deflate_offer(["permessage-deflate; bogus"].into_iter(), &config).is_none());
    assert!(accept_deflate_offer([].into_iter(), &config).is_none());

    // The server honors client-requested takeover/window restrictions.
    let value = "permessage-deflate; server_no_context_takeover; server_max_window_bits=10";
    let (params, response) = accept_deflate_offer([value].into_iter(), &config).unwrap();
    assert!(params.server_no_context_takeover());
    assert_eq!(params.server_max_window_bits(), 10);
    let mut buf = [0u8; 256];
    let n = response.write(&mut buf).unwrap();
    let s = core::str::from_utf8(&buf[..n]).unwrap();
    assert!(s.starts_with("permessage-deflate"));
    assert!(s.contains("server_no_context_takeover"));
    assert!(s.contains("server_max_window_bits=10"));

    // A config that demands client_no_context_takeover emits it even when
    // the client didn't declare it.
    let demanding = ServerDeflateConfig::new().with_require_client_no_context_takeover(true);
    let (params, response) =
      accept_deflate_offer(["permessage-deflate"].into_iter(), &demanding).unwrap();
    assert!(params.client_no_context_takeover());
    let n = response.write(&mut buf).unwrap();
    assert!(
      core::str::from_utf8(&buf[..n])
        .unwrap()
        .contains("client_no_context_takeover")
    );
  }

  #[test]
  fn response_round_trips_through_client_validation() {
    // Whatever accept_deflate_offer emits, parse_deflate_response accepts,
    // and both sides land on identical DeflateParams.
    let offer = DeflateOffer::new()
      .with_server_no_context_takeover(true)
      .with_server_max_window_bits(Some(11));
    let mut offer_buf = [0u8; 256];
    let n = offer.write(&mut offer_buf).unwrap();
    let offer_value = core::str::from_utf8(&offer_buf[..n]).unwrap();

    let config = ServerDeflateConfig::new();
    let (server_params, response) =
      accept_deflate_offer([offer_value].into_iter(), &config).unwrap();

    let mut resp_buf = [0u8; 256];
    let n = response.write(&mut resp_buf).unwrap();
    let resp_value = core::str::from_utf8(&resp_buf[..n]).unwrap();

    let client_params = parse_deflate_response(resp_value, &offer).unwrap();
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
    // RFC 6455 §11.5: subprotocol identifiers are case-sensitive — `CHAT`
    // is NOT the offered `chat`.
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
  }
}
