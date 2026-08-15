//! Byte-level HTTP/1.1 opening handshake (RFC 6455 §4.1–§4.2).

mod client;
mod server;

// Every public type these modules name in a signature or carry in an error
// variant is re-exported: a `pub` type a downstream crate cannot NAME is one it
// cannot store or match on, and rustdoc has nothing to link the item to.
pub use client::{
  ClientComplete, ClientHandshake, ClientHandshakeError, ClientOptions, ClientProgress,
  InvalidOptionsDetail, MAX_SUBPROTOCOL_OFFER_BYTES,
};
pub use server::{
  Accept, PendingUpgrade, Rejection, RequestView, ServerHandshake, ServerHandshakeError,
  ServerProgress,
};
