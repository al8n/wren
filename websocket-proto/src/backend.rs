//! Storage-backend type aliases — the cheap-clone owned text / binary buffers
//! selected by the `alloc`/`std` (native-atomic) vs `no-atomic`
//! (portable-atomic) feature.
//!
//! - **atomic** (`alloc`/`std`): [`smol_str::SmolStr`] text + [`bytes::Bytes`]
//!   binary, cheap-clone via native atomics.
//! - **no-atomic** (`no-atomic`): [`portable_atomic_util::Arc<str>`] text +
//!   `portable_atomic_util::Arc<[u8]>` binary, cheap-clone via
//!   `portable-atomic` + a `critical-section` impl the final binary provides —
//!   for cores without native atomic CAS (Cortex-M0+ / thumbv6m / RP2040).
//!
//! No `Bytes`-specific zero-copy slicing is used anywhere, so `Arc<[u8]>` is a
//! drop-in. Both buffers are sealed from owned accumulators via
//! [`text_from_string`] / [`binary_from_vec`].

// Staging: `message.rs` (the next task) is the sole consumer; these aliases land
// in their own commit so the backend can be reviewed in isolation. The `Message`
// rebuild removes this allow.
#![allow(dead_code, unused_imports)]

// `alloc`/`std` take precedence over `no-atomic` (matching negotiation.rs's
// `SubprotocolString`), so `--all-features` (which turns on both) resolves to a
// single, consistent atomic backend rather than mixing `Bytes`/`SmolStr` with
// the portable-atomic `Arc` flavors.
#[cfg(any(feature = "alloc", feature = "std"))]
mod imp {
  pub(crate) use bytes::Bytes as BinaryBufInner;
  pub(crate) use smol_str::SmolStr as TextBufInner;

  /// Seal an owned byte buffer into a cheap-clone `BinaryBufInner` (`Bytes`
  /// has `From<Vec<u8>>`, an O(1) move).
  pub(crate) fn binary_from_vec(v: std::vec::Vec<u8>) -> BinaryBufInner {
    BinaryBufInner::from(v)
  }

  /// Seal an owned string into a cheap-clone `TextBufInner` (`SmolStr` copies
  /// once for payloads longer than its inline capacity).
  pub(crate) fn text_from_string(s: std::string::String) -> TextBufInner {
    TextBufInner::from(s)
  }
}

#[cfg(all(feature = "no-atomic", not(any(feature = "alloc", feature = "std"))))]
mod imp {
  /// Refcounted, read-only binary payload (portable-atomic `Arc<[u8]>`).
  pub(crate) type BinaryBufInner = portable_atomic_util::Arc<[u8]>;

  /// Refcounted, read-only text payload (portable-atomic `Arc<str>`).
  pub(crate) type TextBufInner = portable_atomic_util::Arc<str>;

  /// Seal an owned byte buffer into a cheap-clone `BinaryBufInner`.
  pub(crate) fn binary_from_vec(v: std::vec::Vec<u8>) -> BinaryBufInner {
    // `Arc<[u8]>` has `From<Vec<u8>>` but no `From<Box<[u8]>>`, so feed the
    // `Vec` directly.
    BinaryBufInner::from(v)
  }

  /// Seal an owned string into a cheap-clone `TextBufInner`.
  pub(crate) fn text_from_string(s: std::string::String) -> TextBufInner {
    TextBufInner::from(s)
  }
}

pub(crate) use imp::{BinaryBufInner, TextBufInner, binary_from_vec, text_from_string};
