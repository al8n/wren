//! Fixed-capacity, no-alloc storage backing the connection's event queue and
//! transmit ring. Both are simple bounded rings; pushes fail (rather than
//! allocate or overwrite) when full, which the connection treats as a
//! capacity-exceeded error.

use core::{marker::PhantomData, ops::Range};

use crate::event::{Event, StreamKind, Transmit};

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

/// The number of queued lifecycle events the default event queue holds.
pub(crate) const EVENT_CAP: usize = 8;

/// Default lifecycle-event queue storage.
///
/// With `std` or `alloc`, the default connection stores this in a heap-backed
/// `Vec` so the default owned `Connection` stays small.
#[cfg(any(feature = "std", feature = "alloc"))]
pub type DefaultEventBuf<'a> = std::vec::Vec<Option<Event>>;

/// Default lifecycle-event queue storage.
///
/// With no allocator available, the default is borrowed caller-owned storage so
/// borrowed connections stay small. Construct it with
/// `Connection::with_buffers`.
#[cfg(not(any(feature = "std", feature = "alloc")))]
pub type DefaultEventBuf<'a> = &'a mut [Option<Event>];

#[cfg(any(feature = "std", feature = "alloc"))]
pub(crate) fn default_event_buf() -> DefaultEventBuf<'static> {
  std::vec![None; EVENT_CAP]
}

/// A fixed-capacity ring buffer of `Copy` items (used for queued [`Event`]s).
///
/// [`Event`]: crate::event::Event
pub(crate) struct BoundedQueue<'a, T, const N: usize, B> {
  slots: B,
  head: usize,
  len: usize,
  _item: PhantomData<T>,
  _storage: PhantomData<&'a mut ()>,
}

impl<T, const N: usize, B> BoundedQueue<'_, T, N, B> {
  /// An empty queue backed by caller-provided slot storage.
  pub(crate) fn with_buffer(slots: B) -> Self {
    Self {
      slots,
      head: 0,
      len: 0,
      _item: PhantomData,
      _storage: PhantomData,
    }
  }
}

impl<T: Copy, const N: usize, B> BoundedQueue<'_, T, N, B>
where
  B: AsMut<[Option<T>]>,
{
  /// Pushes `item` to the back, returning `Err(item)` if the queue is full.
  pub(crate) fn push(&mut self, item: T) -> Result<(), T> {
    let capacity = self.slots.as_mut().len().min(N);
    if capacity == 0 || self.len >= capacity {
      return Err(item);
    }
    let tail = wrap_add(self.head, self.len, capacity);
    if let Some(slot) = self.slots.as_mut().get_mut(tail) {
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
    let capacity = self.slots.as_mut().len().min(N);
    if capacity == 0 {
      return None;
    }
    let item = self
      .slots
      .as_mut()
      .get_mut(self.head)
      .and_then(Option::take);
    self.head = wrap_add(self.head, 1, capacity);
    self.len = self.len.saturating_sub(1);
    item
  }

  /// Discards every queued item, leaving the queue empty. Used by the connection's
  /// fail transition to drop stale nonfatal lifecycle events the moment it becomes
  /// terminal-priority (the terminal `ConnError` then supersedes them).
  pub(crate) fn clear(&mut self) {
    for slot in self.slots.as_mut().iter_mut().take(N) {
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

/// Total byte storage needed by the default transmit ring.
pub(crate) const TX_BYTES_CAP: usize = TX_CAP * TX_N;

/// Default transmit-ring byte storage.
///
/// With `std` or `alloc`, the default connection stores this in a heap-backed
/// `Vec<u8>` so the default owned `Connection` stays small.
#[cfg(any(feature = "std", feature = "alloc"))]
pub type DefaultTxBuf<'a> = std::vec::Vec<u8>;

/// Default transmit-ring byte storage.
///
/// With no allocator available, the default is borrowed caller-owned storage so
/// borrowed connections stay small. Construct it with
/// `Connection::with_buffers`.
#[cfg(not(any(feature = "std", feature = "alloc")))]
pub type DefaultTxBuf<'a> = &'a mut [u8];

#[cfg(any(feature = "std", feature = "alloc"))]
pub(crate) fn default_tx_buf() -> DefaultTxBuf<'static> {
  std::vec![0u8; TX_BYTES_CAP]
}

/// Metadata for one queued transmit slot.
#[derive(Clone, Copy)]
struct TxMeta {
  len: usize,
  kind: StreamKind,
  fin: bool,
}

const fn empty_tx_meta() -> TxMeta {
  TxMeta {
    len: 0,
    kind: StreamKind::OpenRequest,
    fin: false,
  }
}

/// A fixed-capacity ring of transmit slots.
///
/// The byte storage owns or borrows the queued bytes, so [`poll`](TxRing::poll)
/// lends a [`Transmit`] borrowing the front slot; the borrow is valid until the
/// next `poll`.
pub(crate) struct TxRing<'a, B = DefaultTxBuf<'a>> {
  bytes: B,
  slots: [TxMeta; TX_N],
  head: usize,
  len: usize,
  _storage: PhantomData<&'a mut ()>,
}

impl<B> TxRing<'_, B> {
  /// An empty transmit ring backed by caller-provided byte storage.
  pub(crate) fn with_buffer(bytes: B) -> Self {
    Self {
      bytes,
      slots: [empty_tx_meta(); TX_N],
      head: 0,
      len: 0,
      _storage: PhantomData,
    }
  }
}

/// Number of usable transmit slots in a byte buffer of `bytes_len`.
///
/// A default-sized buffer yields [`TX_N`] slots. A borrowed buffer may be smaller;
/// complete [`TX_CAP`]-sized chunks become slots and any trailing partial chunk
/// is ignored.
fn capacity_for_len(mut bytes_len: usize) -> usize {
  let mut slots = 0usize;
  while bytes_len >= TX_CAP && slots < TX_N {
    bytes_len = bytes_len.saturating_sub(TX_CAP);
    slots = slots.saturating_add(1);
  }
  slots
}

impl<B> TxRing<'_, B>
where
  B: AsRef<[u8]>,
{
  fn capacity(&self) -> usize {
    capacity_for_len(self.bytes.as_ref().len())
  }

  /// Lends the front transmit (borrowing its bytes) and advances past it, or
  /// `None` if empty. The borrow is valid until the next call.
  pub(crate) fn poll(&mut self) -> Option<Transmit<'_>> {
    if self.len == 0 {
      return None;
    }
    let capacity = self.capacity();
    if capacity == 0 {
      return None;
    }
    let head = self.head;
    self.head = wrap_add(self.head, 1, capacity);
    self.len = self.len.saturating_sub(1);
    let slot = self.slots.get(head)?;
    let range = slot_range(head, slot.len)?;
    let bytes = self.bytes.as_ref().get(range)?;
    Some(Transmit::new(slot.kind, bytes, slot.fin))
  }
}

impl<B> TxRing<'_, B>
where
  B: AsMut<[u8]>,
{
  pub(crate) fn has_capacity_mut(&mut self, n: usize) -> bool {
    capacity_for_len(self.bytes.as_mut().len()).saturating_sub(self.len) >= n
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
    let capacity = capacity_for_len(self.bytes.as_mut().len());
    if capacity == 0 || self.len >= capacity {
      return Err(TxError::Full);
    }
    let tail = wrap_add(self.head, self.len, capacity);
    let range = slot_range(tail, TX_CAP).ok_or(TxError::Full)?;
    let slot_bytes = self.bytes.as_mut().get_mut(range).ok_or(TxError::Full)?;
    let written = fill(slot_bytes).map_err(TxError::Fill)?;
    let slot = self.slots.get_mut(tail).ok_or(TxError::Full)?;
    slot.len = written.min(TX_CAP);
    slot.kind = kind;
    slot.fin = fin;
    self.len = self.len.saturating_add(1);
    Ok(())
  }
}

fn slot_range(index: usize, len: usize) -> Option<Range<usize>> {
  let start = index.checked_mul(TX_CAP)?;
  let end = start.checked_add(len)?;
  Some(start..end)
}

/// An error enqueuing a transmit: the ring was full, or the fill closure failed.
pub(crate) enum TxError<E> {
  /// No free transmit slot.
  Full,
  /// The fill closure (frame writer) failed.
  Fill(E),
}
