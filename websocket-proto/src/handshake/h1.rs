//! Byte-level HTTP/1.1 opening handshake (RFC 6455 §4.1–§4.2).

mod client;
// mod server;

pub use client::{
  ClientComplete, ClientHandshake, ClientHandshakeError, ClientOptions, ClientProgress,
};
// pub use server::{
//   Accept, Rejection, RequestView, ServerComplete, ServerHandshake, ServerHandshakeError,
//   ServerProgress,
// };
