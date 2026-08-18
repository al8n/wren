//! Byte-level HTTP/1.1 opening handshake (RFC 6455 §4.1–§4.2).

mod client;
mod server;

// Every public type these modules name in a signature or carry in an error
// variant is nameable from this crate: a `pub` type a downstream crate cannot
// NAME is one it cannot store, match on, or build an argument out of, and
// rustdoc has nothing to link the item to. Two routes, and between them they
// have to cover the whole surface. The types defined HERE are re-exported
// below. The ones borrowed from `http1-proto` — `Connection`, `Server`,
// `Client`, `Tunnel` and `HeadView`, which `adopt`, `classify` and
// `with_connection` take — are reached through the crate re-export at
// `websocket_proto::http1_proto`, which additionally guarantees a caller is
// holding the copy this crate compiled against rather than a second one from a
// version that has since diverged.
pub use client::{
  ClientComplete, ClientHandshake, ClientHandshakeError, ClientOptions, ClientProgress,
  InvalidOptionsDetail, MAX_SUBPROTOCOL_OFFER_BYTES,
};
pub use server::{
  Accept, PendingUpgrade, Rejection, RequestView, ServerHandshake, ServerHandshakeError,
  ServerProgress,
};
