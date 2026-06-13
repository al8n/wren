#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

mod conn;
#[cfg(test)]
mod duplex;
mod error;
mod handshake;
mod options;
mod runtime;
mod url;

pub use conn::{ClientRole, ReadHalf, ServerRole, WebSocket, WriteHalf};
pub use error::{AcceptError, ConnectError, Error};
pub use options::{AcceptOptions, ClientOptions};
pub use runtime::Duplex;
pub use websocket_proto::{Negotiated, connection::Closed, frame::CloseCode, message::Message};

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

/// The Sans-I/O protocol layer, re-exported as an escape hatch for bespoke
/// handshake or framing flows the driver API does not cover.
pub mod proto {
  pub use websocket_proto::*;
}
