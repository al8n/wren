#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

mod error;
// Staged: consumed by `connect`/`accept` later in the cycle.
#[allow(dead_code)]
mod handshake;
mod options;
// Staged: consumed by `connect` later in the cycle.
#[allow(dead_code)]
mod url;

#[cfg(test)]
mod duplex;

pub use error::{AcceptError, ConnectError, Error};
pub use options::{AcceptOptions, ClientOptions};

/// Owned snapshot of an accepted upgrade request.
///
/// The borrowed request view dies with the handshake buffer; this carries
/// the routing-relevant fields. Applications that need arbitrary request
/// headers should drive the [`proto`] handshake machines directly.
#[derive(Debug, Clone)]
pub struct RequestSummary {
  pub(crate) path: smol_str::SmolStr,
  pub(crate) query: Option<smol_str::SmolStr>,
  pub(crate) host: smol_str::SmolStr,
  pub(crate) origin: Option<smol_str::SmolStr>,
}

impl RequestSummary {
  /// The resource path (always `/`-leading).
  pub fn path(&self) -> &str {
    self.path.as_str()
  }

  /// The query component, when the target carried one.
  pub fn query(&self) -> Option<&str> {
    self.query.as_deref()
  }

  /// The effective authority the request addressed.
  pub fn host(&self) -> &str {
    self.host.as_str()
  }

  /// The Origin header, when present.
  pub fn origin(&self) -> Option<&str> {
    self.origin.as_deref()
  }
}

/// The negotiation outcome of a completed client handshake.
#[derive(Debug, Clone)]
pub struct ConnectResponse {
  pub(crate) negotiated: websocket_proto::Negotiated,
}

impl ConnectResponse {
  /// The agreed subprotocol, when one was negotiated.
  pub fn subprotocol(&self) -> Option<&str> {
    self.negotiated.subprotocol()
  }

  /// The agreed permessage-deflate parameters, when negotiated.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub fn deflate(&self) -> Option<websocket_proto::negotiation::DeflateParams> {
    self.negotiated.deflate()
  }
}

/// The Sans-I/O protocol layer, re-exported as an escape hatch for bespoke
/// handshake or framing flows the driver API does not cover.
pub mod proto {
  pub use websocket_proto::*;
}
