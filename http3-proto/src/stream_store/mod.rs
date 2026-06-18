//! Per-tier storage for the connection's request/response streams, keyed by
//! [`StreamId`]. Two impls share one trait so the connection's stream dispatch
//! is allocation-agnostic:
//!
//! - bare `no_std`: [`ArrayStore`] — a fixed inline `[ArraySlot<S>; N]` or a
//!   caller-provided `&mut [ArraySlot<S>]`, linear scan + slot reuse, zero alloc
//!   (same shape as the connection's inbound-uni table).
//! - `alloc`/`std`/`no-atomic`: `SlabStore` (Task 3) — `slab::Slab` + a hash
//!   index, O(1) and dynamically growing.
//!
//! HTTP/3 has no `SETTINGS_MAX_CONCURRENT_STREAMS`; the real bound is QUIC's
//! `MAX_STREAMS`. The driver sets that from [`StreamStore::capacity`]; a stream
//! presented beyond capacity ([`insert`](StreamStore::insert) → `Err`) is reset
//! with [`H3Error::RequestRejected`](crate::error::H3Error::RequestRejected) as a
//! backstop, without failing the connection.

use crate::event::StreamId;

mod sealed {
  pub trait Sealed {}
}

/// Per-tier keyed storage for request/response streams.
///
/// Sealed: only the crate's [`ArrayStore`] and `SlabStore` implement it.
pub trait StreamStore<S>: sealed::Sealed {
  /// A shared reference to the stream stored under `id`, if any.
  fn get(&self, id: StreamId) -> Option<&S>;
  /// A mutable reference to the stream stored under `id`, if any.
  fn get_mut(&mut self, id: StreamId) -> Option<&mut S>;
  /// Stores `s` under `id`. Returns `Err(s)` (the value handed back) when the
  /// store is at capacity, so the caller can reset the overflow stream.
  fn insert(&mut self, id: StreamId, s: S) -> Result<(), S>;
  /// Removes and returns the stream stored under `id`, freeing its slot.
  fn remove(&mut self, id: StreamId) -> Option<S>;
  /// Visits every live `(id, &mut stream)`.
  fn iter_mut<'s>(&'s mut self) -> impl Iterator<Item = (StreamId, &'s mut S)>
  where
    S: 's;
  /// The maximum number of concurrent streams this store can hold (the driver
  /// derives QUIC `MAX_STREAMS` from it). `None` if unbounded (the slab impl).
  fn capacity(&self) -> Option<usize>;
  /// The number of live streams currently stored.
  fn len(&self) -> usize;
  /// Whether the store holds no streams.
  fn is_empty(&self) -> bool {
    self.len() == 0
  }
}

/// One slot of an [`ArrayStore`]: either empty or holding `(id, stream)`.
#[derive(Clone, Copy)]
pub struct ArraySlot<S> {
  entry: Option<(StreamId, S)>,
}

impl<S> ArraySlot<S> {
  /// An empty slot, for initializing caller-provided storage.
  pub const EMPTY: Self = Self { entry: None };
}

/// Backing storage for [`ArrayStore`]: an owned inline array (const-generic `N`)
/// or a caller-provided slice.
enum Slots<'a, S, const N: usize> {
  Inline([ArraySlot<S>; N]),
  Borrowed(&'a mut [ArraySlot<S>]),
}

impl<S, const N: usize> Slots<'_, S, N> {
  fn as_slice(&self) -> &[ArraySlot<S>] {
    match self {
      Self::Inline(a) => a,
      Self::Borrowed(s) => s,
    }
  }
  fn as_mut_slice(&mut self) -> &mut [ArraySlot<S>] {
    match self {
      Self::Inline(a) => a,
      Self::Borrowed(s) => s,
    }
  }
}

/// A zero-allocation fixed-capacity [`StreamStore`] — inline `[ArraySlot<S>; N]`
/// or a caller-provided slice, linear scan keyed by [`StreamId`] with slot reuse.
pub struct ArrayStore<'a, S, const N: usize = 0> {
  slots: Slots<'a, S, N>,
  len: usize,
}

impl<S: Copy, const N: usize> ArrayStore<'_, S, N> {
  /// A fresh store backed by an inline `[ArraySlot<S>; N]` (all empty).
  ///
  /// Bounded to `S: Copy` because `[ArraySlot::EMPTY; N]` splats the empty slot,
  /// which requires `Copy`. The connection's stored `Stream` carries buffers and
  /// is **not** `Copy`, so the real bare connection path uses [`with_slots`]
  /// over caller-provided storage (the same pattern the inbound-uni table uses);
  /// [`new`] is for trivial inline-array values.
  ///
  /// No `Default` is implemented: the real bare connection path stores a
  /// non-`Copy` `Stream` via [`with_slots`], so there is no honest
  /// feature-independent default value.
  ///
  /// [`with_slots`]: ArrayStore::with_slots
  /// [`new`]: ArrayStore::new
  #[allow(clippy::new_without_default)]
  pub const fn new() -> Self {
    Self {
      slots: Slots::Inline([ArraySlot::EMPTY; N]),
      len: 0,
    }
  }
}

impl<'a, S, const N: usize> ArrayStore<'a, S, N> {
  /// A fresh store backed by caller-provided slots (all should be
  /// [`ArraySlot::EMPTY`]).
  pub fn with_slots(slots: &'a mut [ArraySlot<S>]) -> Self {
    Self {
      slots: Slots::Borrowed(slots),
      len: 0,
    }
  }
}

impl<S, const N: usize> sealed::Sealed for ArrayStore<'_, S, N> {}

impl<S, const N: usize> StreamStore<S> for ArrayStore<'_, S, N> {
  fn get(&self, id: StreamId) -> Option<&S> {
    self.slots.as_slice().iter().find_map(|s| match &s.entry {
      Some((sid, v)) if *sid == id => Some(v),
      _ => None,
    })
  }

  fn get_mut(&mut self, id: StreamId) -> Option<&mut S> {
    self
      .slots
      .as_mut_slice()
      .iter_mut()
      .find_map(|s| match &mut s.entry {
        Some((sid, v)) if *sid == id => Some(v),
        _ => None,
      })
  }

  fn insert(&mut self, id: StreamId, s: S) -> Result<(), S> {
    let slots = self.slots.as_mut_slice();
    // Replace an existing entry for the same id (idempotent re-bind).
    if let Some(slot) = slots
      .iter_mut()
      .find(|s| matches!(&s.entry, Some((sid, _)) if *sid == id))
    {
      slot.entry = Some((id, s));
      return Ok(());
    }
    match slots.iter_mut().find(|s| s.entry.is_none()) {
      Some(slot) => {
        slot.entry = Some((id, s));
        self.len = self.len.saturating_add(1);
        Ok(())
      }
      None => Err(s),
    }
  }

  fn remove(&mut self, id: StreamId) -> Option<S> {
    let slots = self.slots.as_mut_slice();
    let slot = slots
      .iter_mut()
      .find(|s| matches!(&s.entry, Some((sid, _)) if *sid == id))?;
    let v = slot.entry.take().map(|(_, v)| v);
    if v.is_some() {
      self.len = self.len.saturating_sub(1);
    }
    v
  }

  fn iter_mut<'s>(&'s mut self) -> impl Iterator<Item = (StreamId, &'s mut S)>
  where
    S: 's,
  {
    self
      .slots
      .as_mut_slice()
      .iter_mut()
      .filter_map(|s| s.entry.as_mut().map(|(id, v)| (*id, v)))
  }

  fn capacity(&self) -> Option<usize> {
    Some(self.slots.as_slice().len())
  }

  fn len(&self) -> usize {
    self.len
  }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod tests;
