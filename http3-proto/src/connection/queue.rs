//! Fixed-capacity, no-alloc storage backing the connection's event queue and
//! transmit ring. Both are simple bounded rings; pushes fail (rather than
//! allocate or overwrite) when full, which the connection treats as a
//! capacity-exceeded error.

use core::{marker::PhantomData, ops::Range};

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
use crate::backend::DataBuf;
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

/// A fixed-capacity ring buffer over a generic backing store `B` of
/// `Option<T>` slots (used for queued [`Event`]s). The usable capacity is the
/// backing slice's length — the default owned `Vec` is sized [`EVENT_CAP`], and a
/// borrowed slice is the caller's length (consistent with [`TxRing`], which also
/// treats its byte buffer's length as the bound). The `Copy` bound on `T` lives
/// only on the push/pop/clear impl block, not on the type itself.
///
/// [`Event`]: crate::event::Event
pub(crate) struct BoundedQueue<'a, T, B> {
  slots: B,
  head: usize,
  len: usize,
  _item: PhantomData<T>,
  _storage: PhantomData<&'a mut ()>,
}

impl<T, B> BoundedQueue<'_, T, B> {
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

impl<T: Copy, B> BoundedQueue<'_, T, B>
where
  B: AsMut<[Option<T>]>,
{
  /// Pushes `item` to the back, returning `Err(item)` if the queue is full.
  pub(crate) fn push(&mut self, item: T) -> Result<(), T> {
    let capacity = self.slots.as_mut().len();
    if capacity == 0 || self.len >= capacity {
      return Err(item);
    }
    let tail = wrap_add(self.head, self.len, capacity);
    if let Some(slot) = self.slots.as_mut().get_mut(tail) {
      *slot = Some(item);
      self.len = self.len.saturating_add(1);
      Ok(())
    } else {
      // `tail < capacity == slots.as_mut().len()`, so `get_mut` always succeeds;
      // this `else` is a panic-free fallback.
      Err(item)
    }
  }

  /// Pops the front item, or `None` if empty.
  pub(crate) fn pop(&mut self) -> Option<T> {
    if self.len == 0 {
      return None;
    }
    let capacity = self.slots.as_mut().len();
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
    // Clear the actual backing slice: push/pop bound by `slots.len()`, so clearing
    // every slot matches that slice-is-truth capacity model.
    for slot in self.slots.as_mut().iter_mut() {
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
///
/// On the heap tiers a DATA slot is **vectored**: the byte-ring slot holds only
/// the DATA frame header (`len` bytes) and the refcounted body lives in `body`
/// (segment 1), held zero-copy via a cheap clone. Every other transmit, and
/// every transmit on the bare tier, keeps the whole framed bytes in the byte ring
/// with `body == None` (a single segment).
#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
#[derive(Clone)]
struct TxMeta {
  len: usize,
  kind: StreamKind,
  fin: bool,
  body: Option<DataBuf>,
}

/// Metadata for one queued transmit slot (bare tier: no refcounted body — the
/// whole framed transmit lives in the byte ring, always a single segment).
#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
#[derive(Clone, Copy)]
struct TxMeta {
  len: usize,
  kind: StreamKind,
  fin: bool,
}

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
fn empty_tx_meta() -> TxMeta {
  TxMeta {
    len: 0,
    kind: StreamKind::OpenRequest,
    fin: false,
    body: None,
  }
}

#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
const fn empty_tx_meta() -> TxMeta {
  TxMeta {
    len: 0,
    kind: StreamKind::OpenRequest,
    fin: false,
  }
}

/// Cursor for the transmit currently being written by the driver. The slot itself
/// stays at the ring's head (so its bytes / held body remain valid and a later
/// enqueue cannot reuse the slot); this only records how many bytes the driver has
/// already written (`consumed`) so a partial QUIC `writev` can resume from there.
///
/// `consume_seen` distinguishes "the driver re-polled without acking a partial
/// write" (treated as a full write of the previous transmit — the legacy
/// poll-advances model) from "the driver reported a partial write via
/// [`consume`](TxRing::consume)" (re-yield the remaining segments).
#[derive(Clone, Copy)]
struct TxFront {
  consumed: usize,
  consume_seen: bool,
}

/// A fixed-capacity ring of transmit slots.
///
/// The byte storage owns or borrows the queued bytes, so [`poll`](TxRing::poll)
/// lends a [`Transmit`] borrowing the front slot; the borrow is valid until the
/// next `poll`.
///
/// A polled transmit is held in `front` until fully written. The "driver re-polls"
/// model is preserved: a `poll` with no intervening [`consume`](TxRing::consume)
/// acknowledges the previously polled transmit as fully written and advances to
/// the next; a `consume(n)` records a partial write so the next `poll` re-yields
/// the remaining segments (re-sliced by `consumed`).
pub(crate) struct TxRing<'a, B = DefaultTxBuf<'a>> {
  bytes: B,
  slots: [TxMeta; TX_N],
  head: usize,
  len: usize,
  front: Option<TxFront>,
  _storage: PhantomData<&'a mut ()>,
}

impl<B> TxRing<'_, B> {
  /// An empty transmit ring backed by caller-provided byte storage.
  pub(crate) fn with_buffer(bytes: B) -> Self {
    Self {
      bytes,
      slots: core::array::from_fn(|_| empty_tx_meta()),
      head: 0,
      len: 0,
      front: None,
      _storage: PhantomData,
    }
  }
}

/// Number of usable transmit slots in a byte buffer of `bytes_len`.
///
/// A default-sized buffer yields [`TX_N`] slots. A borrowed buffer may be smaller;
/// complete [`TX_CAP`]-sized chunks become slots and any trailing partial chunk
/// is ignored.
///
/// MUST cap at [`TX_N`]: `head`/`tail` index the fixed `[TxMeta; TX_N]` slots
/// array, so a larger byte buffer must not yield more slots than that array
/// holds, or indexing would go out of range.
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

  /// Lends the front transmit (borrowing its bytes / held body), or `None` if the
  /// ring is empty. The borrow is valid until the next call.
  ///
  /// The "driver re-polls" model is preserved: a `poll` not preceded by a
  /// [`consume`](Self::consume) since the last `poll` acknowledges the previously
  /// polled transmit as fully written and advances to the next; after a *partial*
  /// `consume(n)` the same transmit is re-yielded with its already-written prefix
  /// dropped (segments re-sliced by `consumed`), so a partial QUIC `writev`
  /// resumes exactly where it left off.
  pub(crate) fn poll(&mut self) -> Option<Transmit<'_>> {
    let capacity = self.capacity();
    // `capacity_for_len` caps at `TX_N`, so `head` below stays in range of the
    // fixed `slots` array.
    debug_assert!(capacity <= TX_N);
    if capacity == 0 {
      return None;
    }
    let head = self.head;
    let consumed = match self.front {
      // A transmit is in flight. If the driver reported a partial write that has
      // not yet drained the slot, re-yield the remainder; otherwise the previous
      // poll's transmit is done — advance past it and start the next.
      Some(f) if f.consume_seen && f.consumed < self.front_total(head) => f.consumed,
      Some(_) => {
        self.advance_head(head, capacity);
        self.front = None;
        0
      }
      None => 0,
    };
    if self.front.is_none() {
      if self.len == 0 {
        return None;
      }
      self.front = Some(TxFront {
        consumed: 0,
        consume_seen: false,
      });
    }
    self.build_transmit(self.head, consumed)
  }

  /// The total byte length (header + any held body) of the slot at `index`.
  fn front_total(&self, index: usize) -> usize {
    match self.slots.get(index) {
      Some(slot) => slot_total(slot),
      None => 0,
    }
  }

  /// Drops the fully-written head slot: free any held body and advance the ring.
  fn advance_head(&mut self, head: usize, capacity: usize) {
    if let Some(slot) = self.slots.get_mut(head) {
      clear_slot_body(slot);
    }
    self.head = wrap_add(head, 1, capacity);
    self.len = self.len.saturating_sub(1);
  }

  /// Builds the lent [`Transmit`] for the head slot, skipping the first `consumed`
  /// bytes across its (header, body) segments.
  fn build_transmit(&self, head: usize, consumed: usize) -> Option<Transmit<'_>> {
    let slot = self.slots.get(head)?;
    let range = slot_range(head, slot.len)?;
    let header = self.bytes.as_ref().get(range)?;
    transmit_for_slot(slot, header, consumed)
  }
}

impl<B> TxRing<'_, B> {
  /// Reports that the driver wrote `n` bytes of the transmit last returned by
  /// [`poll`](Self::poll) (a partial QUIC `writev`). The next `poll` re-yields the
  /// remaining segments; the slot is freed once every byte is written. A `consume`
  /// with no transmit in flight is a no-op.
  pub(crate) fn consume(&mut self, n: usize) {
    if let Some(front) = self.front.as_mut() {
      let total = self.slots.get(self.head).map_or(0, slot_total);
      front.consumed = front.consumed.saturating_add(n).min(total);
      front.consume_seen = true;
    }
  }
}

impl<B> TxRing<'_, B>
where
  B: AsMut<[u8]>,
{
  /// The usable slot capacity, computed via `AsMut` (the write-side twin of the
  /// `AsRef` [`capacity`](TxRing::capacity) that backs `poll`).
  fn capacity_via_mut(&mut self) -> usize {
    capacity_for_len(self.bytes.as_mut().len())
  }

  /// Whether `n` more transmits would fit, preflighting a multi-slot enqueue so
  /// a caller's setup (e.g. [`start`]'s control + QPACK streams) stays
  /// all-or-nothing instead of half-queuing and then failing. `&mut` is needed
  /// only to reach `AsMut` for the capacity read; it queues nothing.
  ///
  /// [`start`]: crate::connection::Connection::start
  pub(crate) fn has_capacity_mut(&mut self, n: usize) -> bool {
    self.capacity_via_mut().saturating_sub(self.len) >= n
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
    let capacity = self.capacity_via_mut();
    // `capacity_for_len` caps at `TX_N`, so `tail`/`head` below stay in range of
    // the fixed `slots` array.
    debug_assert!(capacity <= TX_N);
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
    clear_slot_body(slot);
    self.len = self.len.saturating_add(1);
    Ok(())
  }
}

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
impl<B> TxRing<'_, B>
where
  B: AsMut<[u8]>,
{
  /// Enqueues a **vectored** DATA transmit: `fill` writes just the DATA frame
  /// header into the slot's byte-ring workspace (returning its length) and `body`
  /// is held zero-copy as segment 1 (a cheap clone of the caller's [`DataBuf`], not
  /// a memcpy into the ring). [`poll`](Self::poll) then yields `[header, body]`.
  ///
  /// Only the small frame header is bounded by [`TX_CAP`]; the body's size is
  /// bounded by the held [`DataBuf`], not the ring.
  pub(crate) fn enqueue_data<E>(
    &mut self,
    kind: StreamKind,
    fin: bool,
    body: DataBuf,
    fill: impl FnOnce(&mut [u8]) -> Result<usize, E>,
  ) -> Result<(), TxError<E>> {
    let capacity = self.capacity_via_mut();
    debug_assert!(capacity <= TX_N);
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
    slot.body = Some(body);
    self.len = self.len.saturating_add(1);
    Ok(())
  }
}

fn slot_range(index: usize, len: usize) -> Option<Range<usize>> {
  let start = index.checked_mul(TX_CAP)?;
  let end = start.checked_add(len)?;
  Some(start..end)
}

/// The total byte length (header in the ring + any held body) of `slot`.
fn slot_total(slot: &TxMeta) -> usize {
  slot.len.saturating_add(body_len(slot))
}

/// The length of `slot`'s held DATA body (`0` when there is none / on bare).
#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
fn body_len(slot: &TxMeta) -> usize {
  use core::ops::Deref;
  slot.body.as_ref().map_or(0, |b| b.deref().len())
}

#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
fn body_len(_slot: &TxMeta) -> usize {
  0
}

/// Drops any held DATA body, so a reused slot does not pin a stale buffer.
#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
fn clear_slot_body(slot: &mut TxMeta) {
  slot.body = None;
}

#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
fn clear_slot_body(_slot: &mut TxMeta) {}

/// Builds the lent [`Transmit`] for `slot`, with `header` its frame-header /
/// single-segment bytes from the ring, skipping the first `consumed` bytes across
/// the (header, body) segments.
///
/// On the heap tiers a DATA slot is two segments (`[header, body]`); `consumed`
/// trims the header first, then the body, so a partial write resumes mid-body
/// once the header is fully written. Every other slot is one segment trimmed by
/// `consumed`.
#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
fn transmit_for_slot<'a>(
  slot: &'a TxMeta,
  header: &'a [u8],
  consumed: usize,
) -> Option<Transmit<'a>> {
  use core::ops::Deref;
  match slot.body.as_ref() {
    Some(body) => {
      let body = body.deref();
      let hdr_rem = header.get(consumed.min(header.len())..).unwrap_or(&[]);
      let body_skip = consumed.saturating_sub(header.len());
      let body_rem = body.get(body_skip.min(body.len())..).unwrap_or(&[]);
      Some(Transmit::with_segments(
        slot.kind,
        [hdr_rem, body_rem],
        2,
        slot.fin,
      ))
    }
    None => {
      let rem = header.get(consumed.min(header.len())..).unwrap_or(&[]);
      Some(Transmit::new(slot.kind, rem, slot.fin))
    }
  }
}

#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
fn transmit_for_slot<'a>(
  slot: &'a TxMeta,
  header: &'a [u8],
  consumed: usize,
) -> Option<Transmit<'a>> {
  let rem = header.get(consumed.min(header.len())..).unwrap_or(&[]);
  Some(Transmit::new(slot.kind, rem, slot.fin))
}

/// An error enqueuing a transmit: the ring was full, or the fill closure failed.
pub(crate) enum TxError<E> {
  /// No free transmit slot.
  Full,
  /// The fill closure (frame writer) failed.
  Fill(E),
}
