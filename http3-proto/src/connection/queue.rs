//! Fixed-capacity, no-alloc storage backing the connection's event queue and
//! transmit ring. Both are simple bounded rings; pushes fail (rather than
//! allocate or overwrite) when full, which the connection treats as a
//! capacity-exceeded error.

use core::{marker::PhantomData, ops::Range};

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
use crate::backend::DataBuf;
use crate::event::{Event, StreamId, StreamKind, Transmit};

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

/// Whether a queued stream reset still needs its [`StreamStore`] slot bookkeeping
/// (free the slot + clear the tunnel-slot pointer) or only its wire `RESET_STREAM`.
///
/// [`StreamStore`]: crate::stream_store::StreamStore
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ResetKind {
  /// A carrier-deferred stream reset: the lending `Frames` carrier recorded a
  /// stream-scoped error on a tracked stream it could not reset in place. Draining
  /// it does the slot bookkeeping (remove the entry, clear `request_id` if it was the
  /// tunnel-slot pointer) AND enqueues the wire `RESET_STREAM`.
  Carrier,
  /// A wire-only reset: the stream was never inserted (the capacity backstop's
  /// overflow stream) or its slot bookkeeping already ran (a `Carrier` reset whose
  /// wire enqueue then hit a full ring and was re-queued). Draining it only enqueues
  /// the wire `RESET_STREAM`.
  WireOnly,
}

/// One queued stream reset: the stream `id`, its application error `code`, and
/// whether it still needs slot bookkeeping ([`ResetKind`]).
#[derive(Clone, Copy)]
pub(crate) struct PendingReset {
  pub(crate) id: StreamId,
  pub(crate) code: u64,
  pub(crate) kind: ResetKind,
}

/// The number of stream resets the bounded retry queue holds. Resets are rare — a
/// stream-scoped protocol error or a capacity rejection — and the queue normally
/// holds 0–1 entries (a carrier records at most one per `handle_stream`, drained at
/// the head of the next API entry). It only grows when the transmit ring is
/// persistently full and `RESET_STREAM`s cannot flush; a handful of slots is generous
/// headroom for that. Exceeding it is itself a load condition (a peer flooding streams
/// against a full ring), so it fails the connection closed ([`H3Error::ExcessiveLoad`])
/// rather than silently dropping a reset. Kept small so the inline queue does not
/// bloat the connection value (see `connection_value_is_small_*`).
///
/// [`H3Error::ExcessiveLoad`]: crate::error::H3Error::ExcessiveLoad
pub(crate) const RESET_CAP: usize = 4;

/// A small bounded FIFO of stream resets awaiting materialization, generalizing the
/// connection's former single `pending_reset` slot.
///
/// Two sources feed it (see [`ResetKind`]): the lending `Frames` carrier records a
/// stream-scoped error it cannot reset in place, and the capacity backstop records a
/// `RESET_STREAM(RequestRejected)` whose direct enqueue lost to a full transmit ring.
/// The connection drains it at the head of every `&mut self` entry that can observe
/// the effect (`handle_stream` / `poll_transmit` / the send guards), retrying the
/// wire enqueue so a backpressured reset is never lost.
///
/// A FIFO ring rather than `BoundedQueue` because draining must be able to re-queue a
/// just-popped entry (its wire enqueue lost to a still-full ring) at the FRONT, so the
/// reset is retried before any later one — `BoundedQueue` only pushes to the back.
pub(crate) struct PendingResets {
  slots: [Option<PendingReset>; RESET_CAP],
  head: usize,
  len: usize,
}

impl PendingResets {
  /// An empty reset queue.
  pub(crate) const fn new() -> Self {
    Self {
      slots: [None; RESET_CAP],
      head: 0,
      len: 0,
    }
  }

  /// Whether the queue holds no pending resets. Drives the `poll_transmit`
  /// drain-then-retry fixpoint: it keeps freeing tombstoned capacity and retrying only
  /// while resets remain.
  pub(crate) fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// Whether a reset for `id` is already queued (any [`ResetKind`]). The carrier's
  /// "first stream error wins" guard and the capacity path use this so a stream is
  /// never reset twice.
  pub(crate) fn contains(&self, id: StreamId) -> bool {
    self
      .slots
      .iter()
      .any(|s| matches!(s, Some(r) if r.id == id))
  }

  /// Pushes a reset to the BACK, returning `false` if the queue is full (the caller
  /// then fails the connection closed — `RESET_CAP` resets is already pathological).
  pub(crate) fn push_back(&mut self, reset: PendingReset) -> bool {
    if self.len >= RESET_CAP {
      return false;
    }
    let tail = wrap_add(self.head, self.len, RESET_CAP);
    if let Some(slot) = self.slots.get_mut(tail) {
      *slot = Some(reset);
      self.len = self.len.saturating_add(1);
      true
    } else {
      false
    }
  }

  /// Re-queues a just-popped reset at the FRONT (its wire enqueue lost to a full
  /// ring), so it is retried before any later reset. The slot it was popped from is
  /// free, so this never overflows after a `pop_front`.
  pub(crate) fn push_front(&mut self, reset: PendingReset) -> bool {
    if self.len >= RESET_CAP {
      return false;
    }
    // One step back from `head`, wrapping, without `-1 % cap`.
    self.head = if self.head == 0 {
      RESET_CAP.saturating_sub(1)
    } else {
      self.head.saturating_sub(1)
    };
    if let Some(slot) = self.slots.get_mut(self.head) {
      *slot = Some(reset);
      self.len = self.len.saturating_add(1);
      true
    } else {
      false
    }
  }

  /// Pops the front reset, or `None` if empty.
  pub(crate) fn pop_front(&mut self) -> Option<PendingReset> {
    if self.len == 0 {
      return None;
    }
    let item = self.slots.get_mut(self.head).and_then(Option::take);
    self.head = wrap_add(self.head, 1, RESET_CAP);
    self.len = self.len.saturating_sub(1);
    item
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
  /// A purged slot ([`purge_stream`](TxRing::purge_stream)): its held body is freed
  /// and [`poll`](TxRing::poll) skips it. Used to drop a reset stream's already-queued
  /// `Existing(id)` DATA/FIN so no ordinary same-stream transmit precedes its
  /// `RESET_STREAM`, without moving the ring's positionally-indexed bytes.
  tombstone: bool,
}

/// Metadata for one queued transmit slot (bare tier: no refcounted body — the
/// whole framed transmit lives in the byte ring, always a single segment).
#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
#[derive(Clone, Copy)]
struct TxMeta {
  len: usize,
  kind: StreamKind,
  fin: bool,
  /// See the heap-tier [`TxMeta::tombstone`].
  tombstone: bool,
}

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
fn empty_tx_meta() -> TxMeta {
  TxMeta {
    len: 0,
    kind: StreamKind::OpenRequest,
    fin: false,
    body: None,
    tombstone: false,
  }
}

#[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
const fn empty_tx_meta() -> TxMeta {
  TxMeta {
    len: 0,
    kind: StreamKind::OpenRequest,
    fin: false,
    tombstone: false,
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
      // Drop any purged (tombstoned) slots now at the head before lending the next
      // transmit, so a reset stream's superseded `Existing(id)` DATA/FIN is never
      // yielded. A still-in-flight slot (front set above) is never tombstoned —
      // `purge_stream` clears `front` when it tombstones the head — so this only
      // runs on a fresh head.
      self.drop_head_tombstones(capacity);
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

  /// Drains every leading tombstoned slot, freeing the `len` they hold WITHOUT
  /// lending a transmit. The liveness half of the reset-delivery state machine: a
  /// reset that [`purge_stream`](Self::purge_stream)d a full ring of same-stream DATA
  /// cannot fit the still-full ring at enqueue time (tombstones count against `len`
  /// until drained), so the connection must free that tombstoned capacity BEFORE it
  /// retries the reset enqueue — otherwise [`poll`](Self::poll) drains the tombstones
  /// itself, returns `None`, and a driver that stops on `None` strands the reset.
  ///
  /// Returns the number of slots freed, so the caller can re-attempt a pending reset
  /// only when capacity actually opened (a fixpoint, since purging a second reset's
  /// head DATA can create fresh leading tombstones). A no-op while a transmit is held
  /// in `front` (a partial `writev` not yet acked): that slot is live and must not be
  /// advanced past here — the next `poll` resolves the front first. `purge_stream`
  /// clears `front` whenever it tombstones the head, so a held front is never a
  /// tombstone.
  pub(crate) fn drain_leading_tombstones(&mut self) -> usize {
    if self.front.is_some() {
      return 0;
    }
    let capacity = self.capacity();
    debug_assert!(capacity <= TX_N);
    if capacity == 0 {
      return 0;
    }
    let before = self.len;
    self.drop_head_tombstones(capacity);
    before.saturating_sub(self.len)
  }

  /// Advances the head past any leading tombstoned slots (freeing each held body),
  /// so [`poll`](Self::poll) lands on the next live transmit or empties the ring.
  fn drop_head_tombstones(&mut self, capacity: usize) {
    while self.len > 0 {
      let head = self.head;
      let tombstone = self.slots.get(head).is_some_and(|s| s.tombstone);
      if !tombstone {
        return;
      }
      self.advance_head(head, capacity);
    }
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

  /// Tombstones every queued ordinary transmit targeting request stream `id`
  /// ([`StreamKind::Existing`] DATA / FIN), freeing each held [`DataBuf`] body so a
  /// reset SUPERSEDES — not queues behind — its stream's stale bytes.
  /// [`poll`](Self::poll) then skips the tombstones, so no `Existing(id)` transmit
  /// precedes the `RESET_STREAM` the caller enqueues next (RFC 9114 §4.1.2: the reset
  /// abandons the stream's data).
  ///
  /// Tombstone-and-skip rather than compaction: the byte ring is positionally indexed
  /// (slot `i`'s bytes live at `i * TX_CAP`), so removing interior slots would mean
  /// moving survivors' bytes; marking them skip-on-poll avoids that while keeping the
  /// ordering guarantee. Tombstoned slots still count against `len` until `poll` drains
  /// them, so a reset that cannot fit the (still-full) ring immediately is re-queued
  /// (never dropped) and materializes once `poll` skips a tombstone and frees a slot.
  ///
  /// Held-front edge case: if the in-flight front transmit (a partial `writev` recorded
  /// via [`consume`](Self::consume)) is `id`'s data, it is tombstoned too and `front` is
  /// cleared — the already-written prefix is on the wire, but the reset abandons the
  /// stream, so the queue must yield no further `id` bytes before the reset.
  pub(crate) fn purge_stream(&mut self, id: StreamId) {
    let capacity = self.capacity_via_mut();
    debug_assert!(capacity <= TX_N);
    let mut purged_head = false;
    for offset in 0..self.len.min(capacity) {
      let index = wrap_add(self.head, offset, capacity);
      let Some(slot) = self.slots.get_mut(index) else {
        continue;
      };
      if matches!(slot.kind, StreamKind::Existing(sid) if sid == id) {
        slot.tombstone = true;
        clear_slot_body(slot);
        if offset == 0 {
          purged_head = true;
        }
      }
    }
    // The in-flight front transmit was just tombstoned: drop its partial-write cursor so
    // the next `poll` starts fresh on the new head (and does not re-yield a freed slot).
    if purged_head {
      self.front = None;
    }
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
    slot.tombstone = false;
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
    slot.tombstone = false;
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
