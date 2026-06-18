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

// Aliased so alloc-gated modules can name heap items via `std::` on the `std`,
// `no_std + alloc`, and `no-atomic` (a no-`std` heap) tiers (the QPACK decoder's
// owned scratch is a consumer). The `no-atomic` tier carries the alias for the
// heap-backed stores wired in later phases; until then it has no consumer on
// that tier, so the unused-crate lint is suppressed here rather than letting the
// gate drift between tiers.
#[cfg_attr(
  all(not(feature = "std"), feature = "no-atomic", not(feature = "alloc")),
  allow(unused_extern_crates)
)]
#[cfg(all(not(feature = "std"), any(feature = "alloc", feature = "no-atomic")))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

// Must precede any module that uses `cfg_heap!` (e.g. `backend`).
#[macro_use]
mod macros;

/// Cross-cutting error building blocks + the HTTP/3 error-code enum.
pub mod error;
pub use error::{BufferTooSmallDetail, Error, H3Error, TruncatedDetail};

/// Storage-backend alias for outbound DATA payload bytes (tier-selected).
pub mod backend;

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
pub use connection::{
  BorrowedConnection, Client, Connection, DefaultCtrlBuf, DefaultEventBuf, DefaultReqBuf,
  DefaultTxBuf, DefaultUniBuf, Frame, Frames, Role, Server, UniSlot,
};

/// Internal hot-path accessors for the `no-panic` link-time test
/// (`tests/no_panic.rs`). Gated behind `test-no-panic`, doc-hidden, and exempt
/// from semver: these `pub` forwarders expose the crate's panic-free leaf entry
/// points so the test can wrap them in `#[no_panic]` shims (`varint_decode`,
/// `frame_decode_header`) or run as plain smoke tests (`qpack_decode_field_section_into` —
/// its call tree is too deep to inline into a single shim). A `pub use` of a
/// `pub(crate)` item is illegal (E0364/E0365), so thin forwarders are used.
#[cfg(feature = "test-no-panic")]
#[doc(hidden)]
pub mod __no_panic_internals {
  /// Forwards to [`crate::varint::decode`].
  #[inline]
  pub fn varint_decode(input: &[u8]) -> Result<(usize, u64), crate::varint::VarintError> {
    crate::varint::decode(input)
  }

  /// Forwards to [`crate::frame::decode_header`].
  #[inline]
  pub fn frame_decode_header(
    input: &[u8],
  ) -> Result<(usize, crate::frame::FrameHeader), crate::frame::FrameError> {
    crate::frame::decode_header(input)
  }

  /// Forwards to [`crate::qpack::decode_field_section_into`].
  #[inline]
  pub fn qpack_decode_field_section_into<'a>(
    input: &'a [u8],
    scratch: &'a mut [u8],
  ) -> Result<crate::qpack::FieldLines<'a>, crate::qpack::QpackError> {
    crate::qpack::decode_field_section_into(input, scratch)
  }
}
