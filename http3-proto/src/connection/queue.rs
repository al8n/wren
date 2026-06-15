//! Fixed-capacity, no-alloc storage backing the connection's event queue and
//! transmit ring. Both are simple rings over inline arrays; pushes fail (rather
//! than allocate or overwrite) when full, which the connection treats as a
//! capacity-exceeded error.

use crate::event::{StreamKind, Transmit};

/// Adds `a + b` and reduces it modulo `cap` without using `%` (which would trip
/// the `arithmetic_side_effects` deny on a possible `% 0`). Callers guarantee
/// `a < cap` and `b <= cap`, so the sum is `< 2*cap` and one subtraction wraps it.
#[inline]
const fn wrap_add(a: usize, b: usize, cap: usize) -> usize {
  let sum = a.wrapping_add(b);
  if sum >= cap {
    sum.wrapping_sub(cap)
  } else {
    sum
  }
}

/// A fixed-capacity ring buffer of `Copy` items (used for queued [`Event`]s).
///
/// [`Event`]: crate::event::Event
pub(crate) struct BoundedQueue<T, const N: usize> {
  slots: [Option<T>; N],
  head: usize,
  len: usize,
}

impl<T: Copy, const N: usize> BoundedQueue<T, N> {
  /// An empty queue.
  pub(crate) const fn new() -> Self {
    Self {
      slots: [None; N],
      head: 0,
      len: 0,
    }
  }

  /// Pushes `item` to the back, returning `Err(item)` if the queue is full.
  pub(crate) fn push(&mut self, item: T) -> Result<(), T> {
    if self.len >= N {
      return Err(item);
    }
    let tail = wrap_add(self.head, self.len, N);
    if let Some(slot) = self.slots.get_mut(tail) {
      *slot = Some(item);
      self.len = self.len.saturating_add(1);
      Ok(())
    } else {
      // Unreachable: `tail < N`. Kept panic-free as a fallback.
      Err(item)
    }
  }

  /// Pops the front item, or `None` if empty.
  pub(crate) fn pop(&mut self) -> Option<T> {
    if self.len == 0 {
      return None;
    }
    let item = self.slots.get_mut(self.head).and_then(Option::take);
    self.head = wrap_add(self.head, 1, N);
    self.len = self.len.saturating_sub(1);
    item
  }

  /// Discards every queued item, leaving the queue empty. Used by the connection's
  /// fail transition to drop stale nonfatal lifecycle events the moment it becomes
  /// terminal-priority (the terminal `ConnError` then supersedes them).
  pub(crate) fn clear(&mut self) {
    for slot in &mut self.slots {
      *slot = None;
    }
    self.head = 0;
    self.len = 0;
  }
}

/// The byte capacity of a single transmit slot. A queued transmit — including a
/// DATA payload plus its frame header — must fit this; larger `send_data` calls
/// error. This is the v1 no-alloc bound.
pub(crate) const TX_CAP: usize = 2048;

/// The number of in-flight transmit slots the ring holds.
pub(crate) const TX_N: usize = 8;

/// One queued transmit: owned bytes (transmits carry owned payloads, unlike the
/// borrowed [`Transmit`]) plus the target stream and FIN flag.
#[derive(Clone, Copy)]
struct TxSlot {
  buf: [u8; TX_CAP],
  len: usize,
  kind: StreamKind,
  fin: bool,
}

/// A fixed-capacity ring of transmit slots.
///
/// Slots own their bytes, so [`poll`](TxRing::poll) lends a [`Transmit`]
/// borrowing the front slot; the borrow is valid until the next `poll`.
pub(crate) struct TxRing {
  slots: [TxSlot; TX_N],
  head: usize,
  len: usize,
}

impl TxRing {
  /// An empty transmit ring.
  pub(crate) const fn new() -> Self {
    const EMPTY: TxSlot = TxSlot {
      buf: [0u8; TX_CAP],
      len: 0,
      kind: StreamKind::OpenRequest,
      fin: false,
    };
    Self {
      slots: [EMPTY; TX_N],
      head: 0,
      len: 0,
    }
  }

  /// Whether the ring has at least `n` free slots. Used to preflight a multi-slot
  /// enqueue (the [`start`](super::Connection::start) setup writes three transmits)
  /// so it stays all-or-nothing: a sequence that cannot fit in full enqueues
  /// nothing, rather than committing a partial prefix.
  pub(crate) const fn has_capacity(&self, n: usize) -> bool {
    TX_N.saturating_sub(self.len) >= n
  }

  /// Reserves the next free slot's writable buffer and metadata, calling `fill`
  /// to write the bytes (it returns the number written). Errors if the ring is
  /// full or `fill` errors.
  ///
  /// `fill` receives the slot's full `[u8; TX_CAP]` buffer; the connection's
  /// frame writers bounds-check against it and surface a too-large error.
  pub(crate) fn enqueue<E>(
    &mut self,
    kind: StreamKind,
    fin: bool,
    fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
  ) -> Result<(), TxError<E>> {
    if self.len >= TX_N {
      return Err(TxError::Full);
    }
    let tail = wrap_add(self.head, self.len, TX_N);
    let slot = self.slots.get_mut(tail).ok_or(TxError::Full)?;
    let written = fill(&mut slot.buf).map_err(TxError::Fill)?;
    slot.len = written.min(TX_CAP);
    slot.kind = kind;
    slot.fin = fin;
    self.len = self.len.saturating_add(1);
    Ok(())
  }

  /// Lends the front transmit (borrowing its bytes) and advances past it, or
  /// `None` if empty. The borrow is valid until the next call.
  pub(crate) fn poll(&mut self) -> Option<Transmit<'_>> {
    if self.len == 0 {
      return None;
    }
    let head = self.head;
    self.head = wrap_add(self.head, 1, TX_N);
    self.len = self.len.saturating_sub(1);
    let slot = self.slots.get(head)?;
    let bytes = slot.buf.get(..slot.len)?;
    Some(Transmit::new(slot.kind, bytes, slot.fin))
  }
}

/// An error enqueuing a transmit: the ring was full, or the fill closure failed.
pub(crate) enum TxError<E> {
  /// No free transmit slot.
  Full,
  /// The fill closure (frame writer) failed.
  Fill(E),
}
