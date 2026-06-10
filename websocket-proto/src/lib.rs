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
