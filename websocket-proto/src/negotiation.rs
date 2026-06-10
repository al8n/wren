//! Negotiation results shared by every handshake transport.
//!
//! [`Negotiated`] is the sole gate into the connection state machine
//! (plan 4): the h1 machines produce it from header bytes, and the RFC
//! 8441/9220 `connect` types (plan 3b) produce it from header data. Its
//! string storage follows the crate tiers: `SmolStr` under `alloc`,
//! `heapless::String<64>` under `heapless`, absent on the bare tier
//! (where a negotiated subprotocol cannot be retained and is reported as
//! `None`).

#[cfg(any(feature = "alloc", feature = "heapless"))]
use crate::handshake::parser::is_token;
use derive_more::{IsVariant, TryUnwrap, Unwrap};

/// Maximum retained subprotocol length on the `heapless` tier.
pub const MAX_SUBPROTOCOL_LEN: usize = 64;

#[cfg(feature = "alloc")]
type SubprotocolString = smol_str::SmolStr;
#[cfg(all(not(feature = "alloc"), feature = "heapless"))]
type SubprotocolString = heapless::String<MAX_SUBPROTOCOL_LEN>;

/// Errors validating negotiation inputs.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum NegotiationError {
  /// A subprotocol was empty, not an RFC 9110 token, or (on the `heapless`
  /// tier) longer than [`MAX_SUBPROTOCOL_LEN`].
  #[error("invalid or unretainable subprotocol")]
  InvalidSubprotocol,
}

/// The agreed handshake outcome: what the connection machine is configured
/// from. Construct via [`Negotiated::none`] (no subprotocol, no extensions)
/// or the handshake machines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Negotiated {
  #[cfg(any(feature = "alloc", feature = "heapless"))]
  subprotocol: Option<SubprotocolString>,
}

impl Negotiated {
  /// No subprotocol, no extensions — the result of a handshake that
  /// negotiated nothing, and the entry point for drivers that skip
  /// negotiation entirely.
  pub const fn none() -> Self {
    Self {
      #[cfg(any(feature = "alloc", feature = "heapless"))]
      subprotocol: None,
    }
  }

  /// A result carrying an agreed subprotocol (validated as a token and,
  /// on bounded tiers, for retainable length).
  #[cfg(any(feature = "alloc", feature = "heapless"))]
  #[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "heapless"))))]
  pub fn with_subprotocol(subprotocol: &str) -> Result<Self, NegotiationError> {
    if !is_token(subprotocol) {
      return Err(NegotiationError::InvalidSubprotocol);
    }
    let stored = Self::store(subprotocol)?;
    Ok(Self {
      subprotocol: Some(stored),
    })
  }

  #[cfg(feature = "alloc")]
  fn store(s: &str) -> Result<SubprotocolString, NegotiationError> {
    Ok(smol_str::SmolStr::new(s))
  }

  #[cfg(all(not(feature = "alloc"), feature = "heapless"))]
  fn store(s: &str) -> Result<SubprotocolString, NegotiationError> {
    SubprotocolString::try_from(s).map_err(|_| NegotiationError::InvalidSubprotocol)
  }

  /// The agreed subprotocol, when one was negotiated and the tier can
  /// retain it.
  pub fn subprotocol(&self) -> Option<&str> {
    #[cfg(any(feature = "alloc", feature = "heapless"))]
    {
      self.subprotocol.as_deref()
    }
    #[cfg(not(any(feature = "alloc", feature = "heapless")))]
    {
      None
    }
  }
}

/// Server-side helper: the first of the CLIENT's offers (in client order)
/// that the server supports. Returns `None` when there is no overlap —
/// the server then accepts without a subprotocol.
pub fn select_subprotocol<'a>(
  offered: impl IntoIterator<Item = &'a str>,
  supported: &[&str],
) -> Option<&'a str> {
  offered
    .into_iter()
    .find(|offer| supported.iter().any(|s| s.eq_ignore_ascii_case(offer)))
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
