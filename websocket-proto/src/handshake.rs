//! Opening handshakes (RFC 6455 §4).
//!
//! Over HTTP/1.1 this crate owns the bytes: [`h1::ClientHandshake`] emits the
//! upgrade request and validates the response; [`h1::ServerHandshake`] parses
//! and validates the request and emits the response or a rejection. Both are
//! **stateless re-parsers**: feed the whole accumulated buffer each time
//! (heads are capped at 8 KiB), and on completion the `consumed` offset says
//! where the frame stream begins.
//!
//! Over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220) the HTTP stack owns the
//! bytes; the `connect` module (plan 3b) expresses the same negotiation as
//! header data instead.

#[allow(dead_code)]
pub(crate) mod parser;

pub use parser::{HeadError, MalformedDetail};

// pub mod h1;
