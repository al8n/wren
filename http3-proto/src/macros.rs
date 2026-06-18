//! Internal `cfg` macros that bundle a feature gate with its matching docs.rs
//! `doc(cfg(...))` badge, so each storage-tier predicate lives in exactly one
//! place and cannot drift between the gate and the badge.

#![allow(unused_macros)]

/// Items that need a heap allocator AND a refcounted DATA buffer — the
/// `alloc` / `std` / `no-atomic` tiers (excludes bare `no_std`).
macro_rules! cfg_heap {
  ($($item:item)*) => {
    $(
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "alloc", feature = "std", feature = "no-atomic")))
      )]
      $item
    )*
  };
}
