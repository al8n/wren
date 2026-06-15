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

// The `alloc as std` alias has no consumer yet; this allow is transient and is
// removed by the first alloc-gated module that uses `std::`-aliased heap items.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
#[allow(unused_extern_crates)]
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
