#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

#[cfg(test)]
mod duplex;
mod error;
mod options;
mod runtime;
mod url;

pub use error::{AcceptError, ConnectError, Error};
pub use options::{AcceptOptions, ClientOptions};
pub use runtime::Duplex;

/// The Sans-I/O protocol layer, re-exported as an escape hatch for bespoke
/// handshake or framing flows the driver API does not cover.
pub mod proto {
  pub use websocket_proto::*;
}
