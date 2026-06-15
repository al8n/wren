#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![cfg_attr(
  not(test),
  deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::arithmetic_side_effects,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::string_slice
  )
)]

// Aliased so alloc-gated modules can name heap items via `std::` on both the
// `std` and `no_std + alloc` tiers (the QPACK decoder's owned scratch is a
// consumer).
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

/// Cross-cutting error building blocks + the HTTP/3 error-code enum.
pub mod error;
pub use error::{BufferTooSmallDetail, Error, H3Error, TruncatedDetail};

/// QUIC variable-length integer codec (RFC 9000 §16).
pub mod varint;

/// HTTP/3 frame header codec (RFC 9114 §7.1): type + length varints.
pub mod frame;

/// QPACK static-table codec (RFC 9204): field-section compression with the
/// dynamic table disabled.
pub mod qpack;

/// HTTP/3 SETTINGS frame payload codec (RFC 9114 §7.2.4, RFC 9204 §5, RFC 9220 §3).
pub mod settings;

/// Driver-facing vocabulary: stream identity, transmit intents, and connection events.
pub mod event;
pub use event::{Event, StreamId, StreamKind, StreamRole, Transmit};

/// Outbound-header supplier trait and blanket slice impl.
pub mod headers;
pub use headers::Headers;

/// The request-stream inbound FSM: HEADERS-then-DATA frame parsing (RFC 9114 §7).
pub mod stream;
pub use stream::{Items, RequestStream, StreamItem};

pub use qpack::{FieldLines as HeaderSet, Pair};

/// The top-level HTTP/3 Extended-CONNECT tunnel connection state machine.
pub mod connection;
pub use connection::{Client, Connection, Frame, Frames, Role, Server};
