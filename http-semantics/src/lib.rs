#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
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

// Aliased so the heap-gated modules can name heap items via `std::` on the
// `std`, `no_std + alloc`, and `no-atomic` (a no-`std` heap) tiers — the
// spelling this code carried in `http1-proto`, which runs the same alias for
// the same reason. The only consumers today are the heap-gated test modules, so
// a non-test build of a heap tier has none and the unused-crate lint is
// suppressed here rather than letting the gate drift between tiers.
#[allow(unused_extern_crates)]
#[cfg(all(not(feature = "std"), any(feature = "alloc", feature = "no-atomic")))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

// Each module below carries its own summary as an inner doc, and takes no doc
// comment HERE. A doc comment on the DECLARATION resolves the whole merged
// block in the crate root's scope rather than in the module's own, and
// `media`'s summary links `media_type`, `accept` and `weight_for` as the
// siblings they are — names this root does not re-export. In `http1-proto` the
// same three links resolved only because that root re-exports all three, so the
// summary read as self-contained while depending on a list one file away.
pub mod auth;
pub mod conditional;
pub mod date;
pub mod grammar;
pub mod media;
pub mod range;
pub mod status;
pub mod validator;

/// Leaf-path forwarders for the `no-panic` link-time test. Gated behind
/// `test-no-panic`, doc-hidden, and exempt from semver.
// The module name carries the leading-underscore marker `http1-proto` and
// `http3-proto` use for this same module; the FILE is named without it, so the
// path is spelled out.
#[cfg(feature = "test-no-panic")]
#[doc(hidden)]
#[path = "no_panic_internals.rs"]
pub mod __no_panic_internals;
