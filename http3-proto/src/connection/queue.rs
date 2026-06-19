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

/// One pending stream reset: the stream `id` and its application error `code`. The
/// abort is emitted as a wire `RESET_STREAM` directly from the dedicated reset
/// channel (it is never stored in the byte [`TxRing`]).
#[derive(Clone, Copy)]
pub(crate) struct PendingReset {
  pub(crate) id: StreamId,
  pub(crate) code: u64,
}

/// The number of distinct stream resets the dedicated reset channel holds.
///
/// A stream reset is a per-stream control SIGNAL, not bytes: it is recorded here and
/// emitted as a `RESET_STREAM` directly by [`poll_transmit`], so — unlike the byte
/// [`TxRing`] — it is NEVER gated by ring slot capacity. The channel dedups by stream
/// id (at most one entry per stream, FIRST code wins), and [`poll_transmit`] drains
/// one entry per call, so it cannot hold more than the number of distinct live streams
/// reset since the last poll. A handful of slots is generous headroom; exceeding it is
/// pathological (a flood of distinct streams reset without a single intervening
/// `poll_transmit`), so the connection fails closed ([`H3Error::ExcessiveLoad`])
/// rather than silently dropping a reset. Kept small so the inline channel does not
/// bloat the connection value (see `connection_value_is_small_*`).
///
/// [`poll_transmit`]: crate::connection::Connection::poll_transmit
/// [`H3Error::ExcessiveLoad`]: crate::error::H3Error::ExcessiveLoad
pub(crate) const RESET_CAP: usize = 4;

/// A small bounded, id-keyed FIFO of stream resets — the dedicated reset
/// control-signal channel, the SOLE source of `RESET_STREAM`.
///
/// A stream reset is modeled as a per-stream SIGNAL rather than queued bytes:
/// [`poll_transmit`] emits one entry per call FIRST and unconditionally (before
/// polling the byte [`TxRing`]), so an abort can never be byte-ring-gated, dropped, or
/// stranded behind a held front transmit. Two sources feed it: the lending `Frames`
/// carrier records a stream-scoped error it cannot reset in place, and the capacity
/// backstop records a `RESET_STREAM(RequestRejected)` for an at-capacity stream.
///
/// Recording is DEDUPED by stream id ([`record`](Self::record)): at most one entry per
/// stream, the FIRST code wins (exactly-once per RFC 9114 §4.1.2). FIFO is incidental —
/// emission order among distinct streams does not matter; the queue exists only so a
/// recorded abort survives until the next `poll_transmit`.
///
/// [`poll_transmit`]: crate::connection::Connection::poll_transmit
pub(crate) struct PendingResets {
  slots: [Option<PendingReset>; RESET_CAP],
  head: usize,
  len: usize,
}

impl PendingResets {
  /// An empty reset channel.
  pub(crate) const fn new() -> Self {
    Self {
      slots: [None; RESET_CAP],
      head: 0,
      len: 0,
    }
  }

  /// Whether a reset for `id` is already recorded. The carrier's "first stream error
  /// wins" guard and the reset call sites use this so a stream is never reset twice.
  pub(crate) fn contains(&self, id: StreamId) -> bool {
    self
      .slots
      .iter()
      .any(|s| matches!(s, Some(r) if r.id == id))
  }

  /// Snapshots the ids of every recorded reset into a fixed array (trailing slots stay
  /// `None`). The reconcile (`reconcile_pending_resets`) copies the ids out FIRST and
  /// then iterates them, so it can call `&mut self` store / ring methods per id without
  /// holding a borrow of this channel across the call.
  pub(crate) fn ids(&self) -> [Option<StreamId>; RESET_CAP] {
    let mut out = [None; RESET_CAP];
    let mut n = 0usize;
    for reset in self.slots.iter().flatten() {
      if let Some(dst) = out.get_mut(n) {
        *dst = Some(reset.id);
        n = n.saturating_add(1);
      }
    }
    out
  }

  /// Records a reset for `id` with `code`, DEDUPED by id (FIRST code wins): a no-op
  /// returning `true` if `id` is already recorded. Returns `false` only when the
  /// channel is full of distinct other streams (the caller then fails the connection
  /// closed — `RESET_CAP` distinct undrained resets is pathological).
  pub(crate) fn record(&mut self, id: StreamId, code: u64) -> bool {
    if self.contains(id) {
      return true;
    }
    if self.len >= RESET_CAP {
      return false;
    }
    let tail = wrap_add(self.head, self.len, RESET_CAP);
    if let Some(slot) = self.slots.get_mut(tail) {
      *slot = Some(PendingReset { id, code });
      self.len = self.len.saturating_add(1);
      true
    } else {
      false
    }
  }

  /// Pops the front reset, or `None` if empty. Used by [`poll_transmit`] to emit one
  /// pending abort per call.
  ///
  /// [`poll_transmit`]: crate::connection::Connection::poll_transmit
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
/// `consume_seen` means "a [`consume`](TxRing::consume) happened SINCE THE LAST
/// `poll`". It distinguishes "the driver re-polled without acking a partial write"
/// (treated as a full write of the previously yielded segments — the legacy
/// poll-advances model) from "the driver reported a partial write via
/// [`consume`](TxRing::consume)" (re-yield the remaining segments). `poll` clears
/// it the moment it re-yields the remainder, so the cleared-then-re-polled state is
/// exactly the "advance" case: a partial write is re-yielded EXACTLY ONCE per
/// `consume`, never duplicated.
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
      // A transmit is in flight. If the driver reported a partial write since the
      // last poll that has not yet drained the slot, re-yield the remainder AND
      // clear `consume_seen` — the partial write has now been re-yielded, so a NEXT
      // poll without a fresh `consume` means "this remainder was fully written,
      // advance" (the poll-advances model). Without clearing it, the same remainder
      // would be re-yielded forever.
      Some(f) if f.consume_seen && f.consumed < self.front_total(head) => {
        if let Some(front) = self.front.as_mut() {
          front.consume_seen = false;
        }
        f.consumed
      }
      // Either no partial write since the last poll (the previous yield is fully
      // written) or the partial write has drained the slot — advance past it and
      // start the next.
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
  /// reset SUPERSEDES — not leaves behind — its stream's stale bytes.
  /// [`poll`](Self::poll) then skips the tombstones, so no `Existing(id)` transmit is
  /// ever yielded once the stream is reset (RFC 9114 §4.1.2: the reset abandons the
  /// stream's data).
  ///
  /// This is the DATA-purge half of a reset and is DECOUPLED from emitting the
  /// `RESET_STREAM`: the abort is emitted directly from the dedicated reset channel
  /// (never from this byte ring), so it reaches the wire regardless of whether/when
  /// these tombstones drain. The purge only guarantees no stale same-stream DATA is
  /// yielded; it does not gate, and is not gated by, the abort.
  ///
  /// Tombstone-and-skip rather than compaction: the byte ring is positionally indexed
  /// (slot `i`'s bytes live at `i * TX_CAP`), so removing interior slots would mean
  /// moving survivors' bytes; marking them skip-on-poll avoids that. Tombstoned slots
  /// count against `len` until `poll` drains them (a no-op to the driver: `poll` skips
  /// straight past them to the next live transmit or to empty).
  ///
  /// Held-front edge case: if the in-flight front transmit (a partial `writev` recorded
  /// via [`consume`](Self::consume)) is `id`'s data, it is tombstoned too and `front` is
  /// cleared — the already-written prefix is on the wire, but the reset abandons the
  /// stream, so the queue must yield no further `id` bytes.
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
