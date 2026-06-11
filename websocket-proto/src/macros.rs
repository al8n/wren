//! Internal `cfg` macros that bundle a feature gate with its matching docs.rs
//! `doc(cfg(...))` badge, so each storage-tier predicate lives in exactly one
//! place. Wrapping items in one of these is equivalent to writing both
//! `#[cfg(PRED)]` and `#[cfg_attr(docsrs, doc(cfg(PRED)))]` on each — but the
//! predicate cannot drift between the two (the source of past tier bugs), and a
//! new item can never silently omit its docs.rs badge.
//!
//! They wrap *items* (`mod` / `use` / `fn` / `struct` / `enum` / `impl` / `const`
//! / `type`) and methods. Struct fields, function parameters, `match` arms and
//! statements are not items, so a handful of those keep an explicit `#[cfg(...)]`.

// Items that need a heap allocator — the owned-storage (Message) tier:
// `alloc`, `std`, or the `no-atomic` (portable-atomic) tier. Mirrors the
// backend heap arms.
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
