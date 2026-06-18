//! Storage-backend alias for outbound DATA payload bytes — the refcounted
//! flavor selected by the `alloc`/`std` (native-atomic) vs `no-atomic`
//! (portable-atomic) tier.
//!
//! - **atomic** (`alloc`/`std`): [`bytes::Bytes`], cheap-clone via native atomics.
//! - **no-atomic** (`no-atomic`): [`portable_atomic_util::Arc<[u8]>`], cheap-clone
//!   via `portable-atomic` + a `critical-section` impl from the final binary —
//!   for cores without native atomic CAS (Cortex-M0+ / thumbv6m / RP2040).
//! - **bare `no_std`** (no heap features): no shared type; DATA bytes are copied
//!   into caller TX storage. `DataBufMarker` is a zero-sized placeholder so the
//!   tier exposes a consistent name.
//!
//! Discipline: only the cheap-clone + `&[u8]` (+ offset) surface is used, so
//! `Arc<[u8]>` is a literal drop-in for `Bytes` (no `Bytes`-specific zero-copy
//! slicing anywhere).

// `alloc`/`std` take precedence over `no-atomic`, so `--all-features` (both on)
// resolves to one consistent atomic backend rather than mixing the two.
#[cfg(any(feature = "alloc", feature = "std"))]
mod imp {
  /// Refcounted, read-only DATA bytes (native-atomic `bytes::Bytes`).
  pub type DataBuf = bytes::Bytes;
}

#[cfg(all(feature = "no-atomic", not(any(feature = "alloc", feature = "std"))))]
mod imp {
  /// Refcounted, read-only DATA bytes (portable-atomic `Arc<[u8]>`).
  pub type DataBuf = portable_atomic_util::Arc<[u8]>;
}

cfg_heap! {
  pub use imp::DataBuf;
}

/// Zero-sized DATA-buffer placeholder for the bare `no_std` tier (no allocator,
/// no refcount type): DATA bytes are copied into caller TX storage instead.
#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct DataBufMarker;
