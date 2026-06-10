#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
// Panic-freedom restriction lints are a PRODUCTION concern (this is a no_std /
// no-panic-capable core); test code legitimately uses unwrap/expect/panic/etc.,
// so gate the denies on `not(test)` (mirrors the `unsafe_code` split above).
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

// The alias trips `unused_extern_crates` until the first alloc-backed module lands.
#[allow(unused_extern_crates)]
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

/// Protocol-level constants (RFC 6455 limits and well-known values).
pub mod constants;

/// Monotonic time abstraction.
pub mod time;

pub use time::Instant;

/// Cross-cutting error types.
pub mod error;

pub use error::BufferTooSmallDetail;

mod base64;

mod utf8;

/// WebSocket frame codec — lossless RFC 6455 §5.2 parsing and serialization.
pub mod frame;

/// Opening handshakes (RFC 6455 §4) and their completion type.
pub mod handshake;

/// Handshake-result negotiation: subprotocols and (plan 3b) extensions.
pub mod negotiation;

pub use negotiation::Negotiated;

/// The transport-blind connection state machine.
pub mod connection;

pub use connection::{Connection, ConnectionConfig};

/// Alloc-tier owned-message assembly over connection events.
#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub mod message;

#[cfg(any(feature = "alloc", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "alloc", feature = "std"))))]
pub use message::{AssembleError, Message, MessageAssembler};

/// Internal hot-path accessors for the `no-panic` link-time test
/// (`tests/no_panic.rs`). Gated behind `test-no-panic`, doc-hidden, and exempt
/// from semver: these `pub` wrappers expose otherwise-`pub(crate)` hot paths so
/// the panic-freedom test can wrap them in `#[no_panic]` shims. A `pub use` of
/// a `pub(crate)` item is illegal (E0364/E0365), so they are thin forwarders.
#[cfg(feature = "test-no-panic")]
#[doc(hidden)]
pub mod __no_panic_internals {
  /// Forwards to the crate-internal base64 encoder. `#[inline]` so the
  /// no-panic link test can prove the wrapped body panic-free at the call site.
  #[inline]
  pub fn base64_encode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    crate::base64::encode(input, out)
  }

  /// A `pub` newtype over the crate-internal streaming UTF-8 validator,
  /// exposing only the `feed` hot path the no-panic test exercises.
  pub struct Utf8Validator(crate::utf8::Utf8Validator);

  impl Utf8Validator {
    /// A fresh validator at a character boundary.
    #[inline]
    pub fn new() -> Self {
      Self(crate::utf8::Utf8Validator::new())
    }

    /// Validates `input`, returning whether it was accepted (the no-panic
    /// shim only needs the panic-free verdict, not the detail).
    #[inline]
    pub fn feed(&mut self, input: &[u8]) -> bool {
      self.0.feed(input).is_ok()
    }
  }

  impl Default for Utf8Validator {
    fn default() -> Self {
      Self::new()
    }
  }
}
