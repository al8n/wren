//! The receive state machine: incremental header assembly, policy, in-place
//! unmasking, chunked delivery.
//!
//! ## Cursor mechanics
//!
//! [`Events`] holds the input as `Option<&'a mut [u8]>` and never indexes a
//! fixed position into it. Each step splits the *front* off that slice with
//! [`slice::split_at_mut`]: header and consumed-control bytes are split off
//! and dropped, payload bytes are split off, unmasked in place, then handed
//! out as a shared reborrow while the tail is kept for the next step. All
//! offsets are therefore relative to the current tail, and yielded chunks
//! never alias the bytes still owned by the cursor — the safe replacement for
//! the unsafe reborrow the sketch warned against.
//!
//! [`Events::next`] is a **lending iterator**: each event borrows the cursor
//! and is valid only until the next `next()` call. Uncompressed chunks point
//! into the input slice with no copy (the split-off `&'a mut [u8]` reborrows
//! to a shared slice at the shorter `&mut self` lifetime); compressed chunks
//! point into the cursor's internal inflate buffer (same lifetime). Narrowing
//! both to the `&mut self` borrow lets one signature cover both without
//! copying the uncompressed path.

use super::{Connection, Lifecycle, events::*, role::Role};
use crate::{
  constants::{MAX_CONTROL_PAYLOAD, MAX_FRAME_HEADER},
  frame::{CloseCode, Decoded, FrameHeader, Opcode, decode_close_payload, mask},
  time::Instant,
  utf8::Utf8Validator,
};

/// Caller-contract errors from [`Connection::handle`] and
/// [`Connection::observe`] — two entry points over one refusal site, since
/// both are the same `feed`. Protocol violations are NOT errors — they surface
/// as a final [`Event::Closed`].
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum HandleError {
  /// The connection is terminal; feeding more input is a caller bug.
  #[error("connection is terminal")]
  Terminal,

  /// `now` is earlier than an instant this connection has already been given
  /// through any of its four `now`-taking entry points. See
  /// [`Connection::handle`] and [`Connection::observe`].
  #[error("`now` is earlier than an instant this connection has already been given")]
  ClockWentBackwards,
}

/// Where the receive machine is within the byte stream.
#[derive(Debug)]
pub(crate) enum FrameState {
  /// Accumulating a (possibly split) header.
  Header {
    buf: [u8; MAX_FRAME_HEADER],
    len: usize,
  },
  /// Streaming a data-frame payload.
  DataPayload {
    remaining: u64,
    mask: Option<[u8; 4]>,
    offset: u64,
    fin: bool,
  },
  /// Accumulating a control-frame payload (≤ 125 bytes, never split-yielded).
  ControlPayload {
    opcode: Opcode,
    remaining: u64,
    mask: Option<[u8; 4]>,
    offset: u64,
  },
}

/// An in-progress fragmented message.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum MessageState {
  /// Between messages.
  Idle,
  /// Inside a message.
  InMessage {
    kind: MessageKind,
    compressed: bool,
    received: u64,
    /// This message's payload is being SKIPPED — no unmask, no UTF-8
    /// validation, no inflate, no size accounting — and only
    /// `MessageStart`/`MessageEnd` are surfaced for it. Set at the message's
    /// start when the cursor is in observation mode
    /// ([`Connection::observe`]) or when the inbound inflate context is
    /// poisoned, and at any run a cursor skips.
    ///
    /// It is per-MESSAGE rather than per-call because the two entry points
    /// can feed one message between them: a message half of which was never
    /// decoded must not be decoded from the middle. The UTF-8 validator is
    /// the sharpest reason — its carry is seeded at `MessageStart`, so
    /// validating a tail whose head was skipped can split a multi-byte
    /// character and fail a conforming peer with 1007 — and the inflater is
    /// the same shape one layer down.
    skipped: bool,
  },
}

#[derive(Debug)]
pub(crate) struct RecvState {
  pub(crate) frame: FrameState,
  pub(crate) message: MessageState,
  pub(crate) utf8: Utf8Validator,
  /// Carry bytes of a char split across `handle` calls (len ≤ 3).
  pub(crate) text_carry: ([u8; 4], u8),
  /// Additional pongs owed when several pings arrive before `poll_transmit`
  /// drains the first. The FIRST echo does not live here — it goes in the
  /// outbound pong slot,
  /// [`SendState::pending_pong`](super::send::SendState::pending_pong), which
  /// is its own buffer beside the queued close rather than shared with it (see
  /// [`SendState`](super::send::SendState) for why one slot could not serve
  /// both). RFC 6455 §5.5.3 permits answering only the most
  /// recent ping, so on the bare (`no_alloc`) tier that one slot is the whole
  /// story and later pings coalesce into it; where a heap is available we echo
  /// every ping (Autobahn §2.10) up to [`MAX_PENDING_PONGS`] — past that, the
  /// OLDEST queued echo is shed (the §5.5.3 most-recent rule makes shedding
  /// conformant), so a ping flood cannot grow memory without bound.
  #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
  pub(crate) pong_overflow: std::collections::VecDeque<([u8; MAX_CONTROL_PAYLOAD], u8)>,
  /// Close/ping/pong payload accumulator (control frames may split across
  /// reads).
  pub(crate) control_buf: [u8; MAX_CONTROL_PAYLOAD],
  pub(crate) control_len: usize,
  /// Inbound permessage-deflate decompressor, created lazily at the first
  /// compressed message. Boxed to keep `RecvState` small (the raw inflate
  /// dictionary alone is ~32 KiB).
  #[cfg(feature = "deflate")]
  pub(crate) inflate: Option<std::boxed::Box<inflate::InflateBox>>,
  /// The inbound DEFLATE stream can no longer be decoded: a compressed
  /// message was SKIPPED (by [`Connection::observe`]) while the inbound
  /// direction kept its context, so the sliding window is missing that
  /// message's output and every later compressed message would back-reference
  /// bytes this endpoint never produced. From here on, compressed data frames
  /// are skipped the way observation skips them — `MessageStart`/`MessageEnd`
  /// and no chunks — rather than inflated into garbage or failed as 1007:
  /// the connection has already sent its Close, the application has said it
  /// is done, and a dictionary that cannot be rebuilt is not an error the
  /// peer caused. Uncompressed messages are unaffected.
  ///
  /// **Beside the `Option` rather than inside the box**, which the box could
  /// not do: the very first compressed message of a connection can be the one
  /// observation skips, and at that moment `inflate` is `None` — creating the
  /// box to hold the flag would allocate the ~32 KiB dictionary that skipping
  /// exists to avoid. Measured to cost nothing: `Connection<Nanos, Server>`
  /// stays at 600 bytes with `deflate` (it lands in existing padding), which
  /// is what [`CONNECTION_SIZE_BUDGET`](super::CONNECTION_SIZE_BUDGET)
  /// asserts.
  #[cfg(feature = "deflate")]
  pub(crate) inflate_poisoned: bool,
}

impl RecvState {
  /// How many pong echoes are queued BEHIND the outbound slot. Zero on the bare
  /// tier, which has no queue. `SendState::queue_close` needs it to size the
  /// group of pongs that precede a close.
  pub(crate) fn queued_pongs(&self) -> usize {
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    {
      self.pong_overflow.len()
    }
    #[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
    {
      0
    }
  }

  pub(crate) const fn new() -> Self {
    Self {
      frame: FrameState::Header {
        buf: [0; MAX_FRAME_HEADER],
        len: 0,
      },
      message: MessageState::Idle,
      utf8: Utf8Validator::new(),
      text_carry: ([0; 4], 0),
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      pong_overflow: std::collections::VecDeque::new(),
      control_buf: [0; MAX_CONTROL_PAYLOAD],
      control_len: 0,
      #[cfg(feature = "deflate")]
      inflate: None,
      #[cfg(feature = "deflate")]
      inflate_poisoned: false,
    }
  }
}

#[cfg(feature = "deflate")]
pub(crate) mod inflate {
  //! Inbound permessage-deflate decompression (RFC 7692 §7.2.2).
  //!
  //! Each compressed message is one continuous raw-DEFLATE stream. Per the
  //! RFC the sender strips the `00 00 FF FF` sync-flush tail before sending,
  //! so the receiver appends those four octets to the message's final frame
  //! before inflating. We feed each unmasked frame run through
  //! [`miniz_oxide`]'s streaming inflater into a reused output buffer and
  //! never use [`MZFlush::Finish`]: the stream stays open across messages so
  //! context takeover (the next message back-referencing this one's window)
  //! keeps working. Context is reset per message only when the inbound
  //! direction negotiated `no_context_takeover`.

  use miniz_oxide::{
    DataFormat, MZError, MZFlush, MZStatus,
    inflate::stream::{InflateState, inflate},
  };
  use std::{boxed::Box, vec::Vec};

  /// RFC 7692 §7.2.2: the four octets appended to the last frame's data
  /// before inflating (the deflate sync-flush boundary the sender removed).
  const SYNC_TAIL: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

  /// Output is drained from the inflater in fixed stack-sized steps.
  const INFLATE_CHUNK: usize = 4 * 1024;

  /// Why an inflate run could not complete. Both map to a close code at the
  /// call site (1007 for a corrupt stream, 1009 for an over-cap message).
  pub(crate) enum InflateFail {
    /// The DEFLATE stream is malformed (RFC: fail the connection, 1007).
    Corrupt,
    /// The inflated message exceeded `max_message_size` (1009).
    TooLarge,
  }

  /// A lazily-created inbound decompressor plus its scratch output buffer.
  /// Boxed inside `RecvState` so the large dictionary never inflates the
  /// connection's inline size.
  pub(crate) struct InflateBox {
    state: Box<InflateState>,
    /// Inflated output of the CURRENT frame run; reborrowed by the yielded
    /// chunk event and overwritten on the next run.
    buf: Vec<u8>,
    /// Inflated bytes accumulated for the in-progress message (reset when a
    /// message completes), checked against `max_message_size`.
    inflated_total: u64,
    /// The peer finished its DEFLATE stream with a final block. Set on
    /// `StreamEnd`; the next message then starts a FRESH stream (a final
    /// block ends the old one — there is nothing to take context from), and
    /// any further input for the CURRENT message is malformed.
    ended: bool,
    /// Test-only: inflated bytes across the connection's whole life, never
    /// reset. See [`inflated_ever`](Self::inflated_ever).
    ///
    /// Gated to the tier its READERS are on, not to `test` alone: the only
    /// reader is `inflated_ever`, whose only callers are in the `std`-gated
    /// test module, so on a `--no-default-features --features deflate` build
    /// a `#[cfg(test)]` field is written by `run` and read by nobody.
    #[cfg(all(test, feature = "std"))]
    inflated_ever: u64,
  }

  impl InflateBox {
    /// A fresh raw-DEFLATE decompressor. The inbound window-bits negotiation
    /// does not change decoding: `miniz_oxide`'s inflater always allocates
    /// the full 32 KiB dictionary, which correctly decodes any stream a peer
    /// produced under an equal-or-smaller window. The negotiated bits matter
    /// only on the SEND side.
    /// (Deliberate: RFC 7692 §7.1.2 places the window limit on
    /// the SENDER; no receiver-side rejection of over-distance references
    /// is required, and with a fixed 32 KiB window the cap's memory
    /// benefit is structurally absent — a violating peer is tolerated the
    /// way obs-text is, while every conforming stream decodes exactly.)
    pub(crate) fn new() -> Box<Self> {
      Box::new(Self {
        state: InflateState::new_boxed(DataFormat::Raw),
        buf: Vec::new(),
        inflated_total: 0,
        ended: false,
        #[cfg(all(test, feature = "std"))]
        inflated_ever: 0,
      })
    }

    /// The inflated output of the most recent [`run`](Self::run).
    pub(crate) fn output(&self) -> &[u8] {
      &self.buf
    }

    /// The output buffer's CAPACITY, which is its high-water mark by
    /// construction: `run` clears the buffer rather than shrinking it and
    /// `Vec` never gives capacity back, so this is the largest single run
    /// this connection has ever inflated, rounded up to the growth step.
    /// The measurement behind the observation regressions.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn buf_capacity(&self) -> usize {
      self.buf.capacity()
    }

    /// Every byte this decompressor has ever produced, across all messages.
    /// `inflated_total` is per-message and resets; this does not, which is
    /// what makes it the oracle for "how much work did a discarded message
    /// cost" — the buffer's capacity only shows the largest single frame.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn inflated_ever(&self) -> u64 {
      self.inflated_ever
    }

    /// Resets the decompressor for a new message (inbound
    /// `no_context_takeover`): drop the back-reference window so the next
    /// message decodes independently.
    pub(crate) fn reset(&mut self) {
      self.state.reset(DataFormat::Raw);
      self.ended = false;
    }

    /// Marks the start of a new message: clears the per-message inflated-byte
    /// counter. The window persists unless [`reset`](Self::reset) is called —
    /// EXCEPT after a peer's final block, which ended the DEFLATE stream
    /// outright: the next message must start a fresh stream regardless of
    /// context takeover (leaving the inflater in the ended state would
    /// silently poison every later compressed message).
    pub(crate) fn begin_message(&mut self) {
      self.inflated_total = 0;
      if self.ended {
        self.state.reset(DataFormat::Raw);
        self.ended = false;
      }
    }

    /// Inflates one frame run into `buf` (cleared first). On the message's
    /// final frame, appends the RFC sync-flush tail and drains the trailing
    /// block — unless the peer already finished the stream with a final
    /// block, which makes the tail unnecessary (and illegal to feed into an
    /// ended stream). Accumulates `inflated_total` and enforces `max`.
    pub(crate) fn run(
      &mut self,
      data: &[u8],
      final_frame: bool,
      max: u64,
    ) -> Result<(), InflateFail> {
      self.buf.clear();
      self.feed(data, max)?;
      if final_frame && !self.ended {
        self.feed(&SYNC_TAIL, max)?;
      }
      Ok(())
    }

    /// Drives the streaming inflater over `input`, appending decompressed
    /// output to `buf` until the input is consumed and no further output is
    /// produced. `MZFlush::None` keeps the stream open across calls/messages.
    fn feed(&mut self, input: &[u8], max: u64) -> Result<(), InflateFail> {
      let mut cursor = input;
      loop {
        let base = self.buf.len();
        self.buf.resize(base.saturating_add(INFLATE_CHUNK), 0);
        let Some(window) = self.buf.get_mut(base..) else {
          return Err(InflateFail::Corrupt);
        };
        let result = inflate(&mut self.state, cursor, window, MZFlush::None);
        let written = result.bytes_written;
        let consumed = result.bytes_consumed;
        // Trim the resized region back to what was actually produced.
        self.buf.truncate(base.saturating_add(written));

        self.inflated_total = self
          .inflated_total
          .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        #[cfg(all(test, feature = "std"))]
        {
          self.inflated_ever = self
            .inflated_ever
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        }
        if self.inflated_total > max {
          return Err(InflateFail::TooLarge);
        }

        cursor = cursor.get(consumed..).unwrap_or(&[]);

        match result.status {
          // Stream finished (a peer sent a final block). Anything still in
          // the cursor is bytes AFTER the stream end — RFC 7692 §7.2.2
          // requires the whole payload to be part of the message's stream,
          // so trailing bytes are malformed, not silently dropped.
          Ok(MZStatus::StreamEnd) => {
            if !cursor.is_empty() {
              return Err(InflateFail::Corrupt);
            }
            self.ended = true;
            return Ok(());
          }
          Ok(_) => {
            // Done with this input once it is drained and the last step made
            // no progress (the open-stream steady state between messages).
            if cursor.is_empty() && written == 0 && consumed == 0 {
              return Ok(());
            }
            // All input consumed and the inflater did not fill the whole
            // window — nothing is buffered waiting to come out.
            if cursor.is_empty() && written < INFLATE_CHUNK {
              return Ok(());
            }
          }
          // No progress possible. With the stream still open this just means
          // "need more input"; that is fine once our input is drained.
          Err(MZError::Buf) => {
            if cursor.is_empty() {
              return Ok(());
            }
            return Err(InflateFail::Corrupt);
          }
          Err(_) => return Err(InflateFail::Corrupt),
        }
      }
    }
  }

  impl core::fmt::Debug for InflateBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      f.debug_struct("InflateBox")
        .field("buffered", &self.buf.len())
        .field("inflated_total", &self.inflated_total)
        .finish_non_exhaustive()
    }
  }
}

/// A lending-iterator cursor over the events produced by one `handle` call.
/// Each [`next`](Events::next) event borrows the cursor and is valid only
/// until the following `next()` call; fold it into owned storage before
/// advancing. Drop the cursor (or drain it) before calling `handle` again.
///
/// Dropping the cursor EARLY is safe: `Drop` runs the unread tail through
/// the state machine so the connection never desynchronizes — control
/// frames are still answered, the close handshake still progresses, and
/// protocol violations still fail the connection. What early drop discards
/// is the borrowed DATA events themselves (the chunks the caller chose not
/// to read); a driver that needs every byte must drain with
/// `while let Some(event) = events.next()`.
// The struct-level bounds are STRUCTURAL (an exception to the
// bounds-on-methods convention): `Drop` must be implemented for exactly the
// struct's generics, and the drain it performs needs the same `Instant`/
// `Role` capabilities as `next` — a bound-free `Events` cannot exist anyway
// (`handle` is the only constructor and requires both).
#[derive(Debug)]
pub struct Events<'a, 'c, I, Ro>
where
  I: Instant,
  Ro: Role,
{
  pub(crate) conn: &'c mut Connection<I, Ro>,
  /// The unconsumed tail of the input. `None` only transiently while a step
  /// splits it; always `Some` between `next` calls.
  pub(crate) data: Option<&'a mut [u8]>,
  /// A `MessageEnd` owed after the final chunk of a message was yielded.
  pub(crate) pending_message_end: bool,
  /// A terminal `Closed` owed after a `CloseReceived` was yielded.
  pub(crate) pending_closed: Option<Closed>,
  /// This cursor is in OBSERVATION mode ([`Connection::observe`]): data
  /// payload bytes are advanced over and never decoded. A field on the
  /// CURSOR and not on the connection, because the mode is a property of the
  /// bytes being fed — where they came from — and not of the connection: a
  /// driver that has both kinds of input must not be able to leave a mode
  /// set. (It is also why the mode cannot cost a `Connection` field; that
  /// struct's size is const-asserted.)
  pub(crate) observing: bool,
}

impl<I, Ro> Drop for Events<'_, '_, I, Ro>
where
  I: Instant,
  Ro: Role,
{
  fn drop(&mut self) {
    // Regression: an early-dropped cursor that discards the unread tail
    // while the frame state has already advanced past its header leaves the
    // machine waiting forever for payload bytes the transport will never
    // resend. Draining here keeps the PROTOCOL
    // consistent on every drop path; only the data views are lost, which
    // dropping the cursor opts into. (`next` makes progress on every call
    // — it consumes input or returns `None` — so this terminates.)
    while self.next().is_some() {}
  }
}

impl<I, Ro> Connection<I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// Feeds inbound transport bytes. Payload bytes are unmasked in place; the
  /// returned [`Events`] cursor is a lending iterator over borrowed events
  /// (each valid until the next `next()` call).
  pub fn handle<'a, 'c>(
    &'c mut self,
    now: I,
    data: &'a mut [u8],
  ) -> Result<Events<'a, 'c, I, Ro>, HandleError> {
    self.feed(now, data, false)
  }

  /// Feeds inbound transport bytes as an OBSERVER: everything `handle` does,
  /// except that data payload bytes are advanced over instead of decoded.
  ///
  /// For a caller that has stopped consuming — it has sent its Close and is
  /// now only waiting to see the peer's — and must still be a conforming
  /// endpoint while it waits. Framing is unchanged in every respect: opcode
  /// and RSV validation, the mask-bit rule, fragment sequencing, the
  /// control-frame length rule, the clock check and the terminal
  /// short-circuit all apply, and a framing violation still fails the
  /// connection exactly as it would under `handle`. Control frames are
  /// processed identically — a Ping still queues its Pong into the outbound
  /// slots, a Pong still surfaces, and the peer's Close still echoes and
  /// terminates. [`Event::MessageStart`] and [`Event::MessageEnd`] are still
  /// emitted, so a caller's assembler can keep tracking message boundaries.
  ///
  /// What it does NOT do is any work on the data payload: the bytes are not
  /// unmasked, not validated as UTF-8, not inflated, and not counted against
  /// [`ConnectionConfig::max_message_size`](super::ConnectionConfig::max_message_size),
  /// and no chunk event is yielded for them. Skipping the UTF-8 check is not
  /// a relaxation of RFC 6455 §8.1 (line 2643 of `.rfc-cache/rfc6455.txt`).
  /// That obligation is conditioned on interpreting the bytes: "When an
  /// endpoint is to interpret a byte stream as UTF-8 but finds that the byte
  /// stream is not, in fact, a valid UTF-8 stream, that endpoint MUST _Fail
  /// the WebSocket Connection_." An observer is not interpreting them. The
  /// specific clause was checked rather than the general one: §5.6 (line
  /// 2098) says of a text frame that "the whole message MUST contain valid
  /// UTF-8", which is a rule on what a SENDER may put on the wire, and it
  /// routes the receiver's handling to §8.1 rather than stating a second
  /// obligation of its own.
  ///
  /// **A message is skipped whole.** The mode is per-CALL, but the fact that
  /// a message's bytes were skipped is remembered on the connection until
  /// that message's final frame: half a message must never be decoded from
  /// the middle, whether its remaining frames arrive through this method or
  /// through [`handle`](Connection::handle). Assembly resumes at the next
  /// message.
  ///
  /// # What a consumer is told, and when
  ///
  /// **Everything it needs is in the events; there is nothing to remember
  /// across calls.** Two of them carry the fact that a message's payload is
  /// not being delivered, and between them they cover both ways a message can
  /// come to be skipped:
  ///
  /// - A message that STARTS here says so in its own start:
  ///   [`MessageStart::skipped`] is set, so a folder discards to the boundary
  ///   instead of opening an accumulator.
  /// - A message already IN PROGRESS when observation begins cannot say it in
  ///   its start — that start was emitted under
  ///   [`handle`](Connection::handle), before this decision existed — so it is
  ///   said once, at the first run skipped, as
  ///   [`Event::MessageAbandoned`]: drop what you hold for it. Its
  ///   `MessageEnd` still arrives at the boundary, possibly through `handle`
  ///   long afterwards, and would otherwise seal what a folder is holding as
  ///   a complete, TRUNCATED message.
  ///
  /// That second event is why this is not a pairing obligation on the caller:
  /// **a whole `observe` call can yield NO other events at all** — an observed
  /// read whose every byte is continuation payload produces nothing else — so
  /// there is no moment a caller could have been asked to react to instead.
  /// Both assemblers in this crate act on both events in `push`.
  ///
  /// # permessage-deflate and context takeover
  ///
  /// Skipping a compressed message's bytes means the inflater never saw them.
  /// With `no_context_takeover` on the inbound direction that costs nothing —
  /// each message is its own DEFLATE stream, and the next one resets. **With
  /// context takeover it is not recoverable**: the sliding window is now
  /// missing that message's output, so every later compressed message would
  /// back-reference bytes this endpoint never produced. Observing a
  /// compressed data frame under context takeover therefore POISONS the
  /// inbound inflate context, and from then on `handle` treats compressed
  /// data frames exactly as this method does — skipped, `MessageStart` and
  /// `MessageEnd` only, no chunks, and no error. Uncompressed messages are
  /// unaffected. It is not an error because the peer did not cause it: this
  /// endpoint has sent its Close and its application has said it is done, and
  /// a dictionary that cannot be rebuilt is a consequence of that decision.
  pub fn observe<'a, 'c>(
    &'c mut self,
    now: I,
    data: &'a mut [u8],
  ) -> Result<Events<'a, 'c, I, Ro>, HandleError> {
    self.feed(now, data, true)
  }

  /// The body of both entry points; `observing` is the single difference and
  /// it is carried by the cursor.
  fn feed<'a, 'c>(
    &'c mut self,
    now: I,
    data: &'a mut [u8],
    observing: bool,
  ) -> Result<Events<'a, 'c, I, Ro>, HandleError> {
    // The clock check comes FIRST, before the state-dependent refusal below,
    // because it is a statement about this call's ARGUMENT rather than about
    // the connection: a driver validating its own timekeeping gets the same
    // answer whether or not the connection has since gone terminal. It touches
    // nothing on refusal, so `data` is unread and the cursor is never built.
    if !self.accept_now(now) {
      return Err(crate::contract::contract_violation(
        HandleError::ClockWentBackwards,
        crate::contract::CLOCK_IS_MONOTONIC,
      ));
    }
    if self.is_terminal() {
      return Err(HandleError::Terminal);
    }
    // Non-empty inbound input re-arms the keepalive timer (measures liveness).
    if !data.is_empty()
      && let Some(interval) = self.config.keepalive
    {
      self.next_keepalive = now.checked_add_duration(interval);
    }
    Ok(Events {
      conn: self,
      data: Some(data),
      pending_message_end: false,
      pending_closed: None,
      observing,
    })
  }
}

/// Test-only windows onto the inbound decompressor: what it has retained and
/// what it has done. Both are what the observation regressions assert on, and
/// neither is a public API — the crate publishes no way to ask, and should
/// not.
///
/// **The cfg is the UNION of what the CALLERS carry, not `test` plus the
/// feature the code is about.** All three are called only from
/// `tests::deflate`, a `#[cfg(feature = "deflate")]` module nested inside
/// `#[cfg(all(test, feature = "std"))] mod tests`. Gated on `deflate` alone
/// they compile with no caller at all on
/// `--no-default-features --features deflate`, and `-D warnings` fails that
/// build on `dead_code` — which is what CI's `cargo hack test --each-feature`
/// found and the local gate list did not run. Widen this only together with
/// the tests that call it.
#[cfg(all(test, feature = "std", feature = "deflate"))]
impl<I, Ro> Connection<I, Ro> {
  /// The inflate output buffer's capacity, or 0 when no decompressor was ever
  /// created. See [`InflateBox::buf_capacity`](inflate::InflateBox::buf_capacity).
  pub(crate) fn inflate_buf_capacity(&self) -> usize {
    self
      .recv
      .inflate
      .as_deref()
      .map_or(0, inflate::InflateBox::buf_capacity)
  }

  /// Every byte the decompressor has produced on this connection.
  pub(crate) fn inflated_ever(&self) -> u64 {
    self
      .recv
      .inflate
      .as_deref()
      .map_or(0, inflate::InflateBox::inflated_ever)
  }

  /// Whether the inbound inflate context has been poisoned by a skipped
  /// compressed message.
  pub(crate) fn inflate_is_poisoned(&self) -> bool {
    self.recv.inflate_poisoned
  }
}

impl<'a, I, Ro> Events<'a, '_, I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// The next event, or `None` when this input is exhausted.
  ///
  /// This is a **lending iterator**: each event borrows `self` and is only
  /// valid until the next `next()` call (or until the cursor is dropped).
  /// Uncompressed payload chunks still point directly into the input slice
  /// with no copy; compressed chunks point into the cursor's internal
  /// inflate buffer — both are reborrowed at the shorter `&mut self`
  /// lifetime so a single signature covers them. Fold each event into owned
  /// storage before calling `next()` again. The intended call shape is a
  /// `while let Some(event) = events.next()` loop.
  // A lending iterator: `Iterator` cannot express items that borrow `self`
  // (`Item` has no access to the `&mut self` lifetime of `next`), so this
  // stays an inherent method.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Option<Event<'_>> {
    if self.pending_message_end {
      self.pending_message_end = false;
      return Some(Event::MessageEnd);
    }
    if let Some(closed) = self.pending_closed.take() {
      self.conn.lifecycle = Lifecycle::Terminal;
      return Some(Event::Closed(closed));
    }

    loop {
      // Terminal also covers the peer-close case (RFC 6455 §1.4): the rest of
      // the input is ignored — no further frames are expected after a close.
      if self.conn.is_terminal() {
        return None;
      }

      match self.conn.recv.frame {
        FrameState::Header { .. } => {
          // A new frame needs at least one byte; without input we are done.
          // (A zero-length payload frame is NOT pending here — its header
          // already transitioned us into a payload state, handled below, so
          // it completes even when the input is exhausted.)
          if self.remaining() == 0 {
            return None;
          }
          if let Some(event) = self.step_header() {
            return Some(event);
          }
        }
        FrameState::DataPayload { .. } => match self.advance_data_payload() {
          // Borrow phase: build the event after the mutating `advance` borrow
          // has ended. A builder yielding `None` means this run produced no
          // visible event (e.g. an incomplete UTF-8 char folded into the
          // carry) — keep looping rather than ending the cursor.
          DataStep::YieldInput {
            chunk,
            kind,
            message_done,
          } => {
            if let Some(event) = self.build_input_event(chunk, kind, message_done) {
              return Some(event);
            }
          }
          #[cfg(feature = "deflate")]
          DataStep::YieldInflated {
            chunk,
            kind,
            message_done,
          } => match self.decide_inflated(chunk, kind, message_done) {
            // Tail return: build the event (borrows the inflate buffer) only
            // after the owned decision is in hand.
            InflateDecision::Yield(yielded) => return Some(self.build_inflated_event(yielded)),
            InflateDecision::MessageEnd => return Some(Event::MessageEnd),
            InflateDecision::Fail(code) => return Some(self.fail(code)),
            InflateDecision::Nothing => {}
          },
          // Observed (or otherwise skipped) payload: no chunk, and the
          // message's boundary still surfaces so a caller's assembler can
          // track it.
          DataStep::Skipped { message_done } => {
            if message_done {
              return Some(Event::MessageEnd);
            }
          }
          // The same, plus the one-time notice that a message already in
          // progress is being given up on.
          DataStep::Abandoned => return Some(Event::MessageAbandoned),
          DataStep::Fail(code) => return Some(self.fail(code)),
          DataStep::NeedMore => return None,
          DataStep::Continue => {}
        },
        FrameState::ControlPayload { .. } => match self.step_control_payload() {
          StepOutcome::Event(event) => return Some(event),
          StepOutcome::NeedMore => return None,
          StepOutcome::Continue => {}
        },
      }
    }
  }

  /// Length of the unconsumed tail.
  fn remaining(&self) -> usize {
    self.data.as_deref().map_or(0, <[u8]>::len)
  }

  /// Splits the first `n` bytes off the front of the tail, keeps the rest as
  /// the new tail, and returns the split-off head (empty if the tail is
  /// gone). `n` is clamped to the tail length.
  fn take_front(&mut self, n: usize) -> &'a mut [u8] {
    match self.data.take() {
      Some(buf) => {
        let at = n.min(buf.len());
        let (head, tail) = buf.split_at_mut(at);
        self.data = Some(tail);
        head
      }
      None => &mut [],
    }
  }

  /// Accumulates header bytes from the tail and, once a full header is
  /// parsed, applies policy. Returns an event to surface immediately, or
  /// `None` to keep parsing (more state or more input).
  fn step_header(&mut self) -> Option<Event<'a>> {
    let FrameState::Header { mut buf, len } = self.conn.recv.frame else {
      return None;
    };

    // Peek-copy new bytes into the accumulator without consuming them yet;
    // we only know how many the header actually needs after decoding.
    let available = self.remaining();
    let room = MAX_FRAME_HEADER.saturating_sub(len);
    let take = available.min(room);
    {
      let tail = self.data.as_deref().unwrap_or(&[]);
      let src = tail.get(..take).unwrap_or(&[]);
      let dst = buf
        .get_mut(len..len.saturating_add(take))
        .unwrap_or(&mut []);
      for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
      }
    }
    let staged = len.saturating_add(take);

    match FrameHeader::decode(buf.get(..staged).unwrap_or(&[])) {
      Err(_) => {
        // Length-grammar violation (non-canonical / oversized).
        Some(self.fail(CloseCode::ProtocolError))
      }
      Ok(Decoded::Incomplete(_)) => {
        // Consume everything we staged; the rest of the header arrives in a
        // later call.
        let _ = self.take_front(take);
        self.conn.recv.frame = FrameState::Header { buf, len: staged };
        None
      }
      Ok(Decoded::Complete(decoded)) => {
        // Consume only the header bytes that came from THIS tail; bytes
        // staged from prior calls already left the buffer, and any extra we
        // peeked are payload that must stay.
        let header_bytes = decoded.consumed();
        let new_consumed = header_bytes.saturating_sub(len);
        let _ = self.take_front(new_consumed);
        self.conn.recv.frame = FrameState::Header {
          buf: [0; MAX_FRAME_HEADER],
          len: 0,
        };
        self.on_header(decoded.header())
      }
    }
  }

  /// Header-complete policy. Returns an event to surface immediately
  /// (failure or `MessageStart`) or `None` to continue parsing.
  fn on_header(&mut self, header: FrameHeader) -> Option<Event<'a>> {
    let masked = header.mask().is_some();
    if masked != Ro::EXPECT_MASKED_INBOUND {
      return Some(self.fail(CloseCode::ProtocolError));
    }
    if header.rsv2() || header.rsv3() {
      return Some(self.fail(CloseCode::ProtocolError));
    }
    let opcode = header.opcode();
    if opcode.is_reserved() {
      return Some(self.fail(CloseCode::ProtocolError));
    }
    if header.payload_len() > self.conn.config.max_frame_payload() {
      return Some(self.fail(CloseCode::MessageTooBig));
    }

    if opcode.is_control() {
      if !header.fin() || header.payload_len() > control_cap() {
        return Some(self.fail(CloseCode::ProtocolError));
      }
      if header.rsv1() {
        return Some(self.fail(CloseCode::ProtocolError));
      }
      self.conn.recv.control_len = 0;
      self.conn.recv.frame = FrameState::ControlPayload {
        opcode,
        remaining: header.payload_len(),
        mask: header.mask(),
        offset: 0,
      };
      return None;
    }

    // Data frames.
    match (opcode, self.conn.recv.message) {
      (Opcode::Continuation, MessageState::Idle) => Some(self.fail(CloseCode::ProtocolError)),
      (Opcode::Continuation, MessageState::InMessage { .. }) => {
        if header.rsv1() {
          return Some(self.fail(CloseCode::ProtocolError));
        }
        self.begin_data_payload(header);
        None
      }
      (Opcode::Text | Opcode::Binary, MessageState::InMessage { .. }) => {
        Some(self.fail(CloseCode::ProtocolError))
      }
      (Opcode::Text | Opcode::Binary, MessageState::Idle) => {
        let compressed = if header.rsv1() {
          #[cfg(feature = "deflate")]
          {
            if self.conn.deflate.is_none() {
              return Some(self.fail(CloseCode::ProtocolError));
            }
            true
          }
          #[cfg(not(feature = "deflate"))]
          {
            return Some(self.fail(CloseCode::ProtocolError));
          }
        } else {
          false
        };
        let kind = if matches!(opcode, Opcode::Text) {
          MessageKind::Text
        } else {
          MessageKind::Binary
        };
        self.conn.recv.message = MessageState::InMessage {
          kind,
          compressed,
          received: 0,
          skipped: false,
        };
        self.conn.recv.utf8.reset();
        self.conn.recv.text_carry = ([0; 4], 0);
        // Whether this message will be decoded at all is settled HERE, once,
        // for the whole message — an observed message, and a compressed one
        // arriving after the inflate context was poisoned, are both skipped
        // to their final frame however their later frames are fed. Deciding
        // it per RUN instead would let a message be decoded from the middle,
        // which is what the `skipped` flag exists to prevent.
        let skipping = self.observing || (compressed && self.inflate_poisoned());
        if skipping {
          self.mark_message_skipped();
        }
        #[cfg(feature = "deflate")]
        if compressed && !skipping {
          // Deliberately NOT run for a skipped message: it would create the
          // ~32 KiB decompressor for bytes nobody will inflate. Nothing later
          // needs the per-message bookkeeping it does, because the next
          // message this connection actually decodes runs it again — and with
          // `no_context_takeover` that call resets the window, while with
          // takeover the context is poisoned and no such message exists.
          self.begin_inflate_message();
        }
        self.begin_data_payload(header);
        // The event carries the fact. A consumer that opens an accumulator for
        // a message whose payload is skipped delivers an EMPTY message where
        // the peer sent bytes, and no later event can tell it otherwise — the
        // only other event this message produces is its `MessageEnd`.
        Some(Event::MessageStart(MessageStart::new(
          kind, compressed, skipping,
        )))
      }
      _ => Some(self.fail(CloseCode::ProtocolError)),
    }
  }

  fn begin_data_payload(&mut self, header: FrameHeader) {
    self.conn.recv.frame = FrameState::DataPayload {
      remaining: header.payload_len(),
      mask: header.mask(),
      offset: 0,
      fin: header.fin(),
    };
  }

  /// Whether the inbound direction negotiated `no_context_takeover` — the
  /// direction the peer SENDS on: client→server for a server connection,
  /// server→client for a client connection.
  ///
  /// The negotiated parameters are the record: they are stored on the
  /// connection as `Connection::deflate` at
  /// [`Connection::new`](Connection::new) from
  /// [`Negotiated::deflate`](crate::negotiation::Negotiated::deflate), and
  /// read back through
  /// [`DeflateParams::client_no_context_takeover`](crate::negotiation::DeflateParams::client_no_context_takeover)
  /// / [`server_no_context_takeover`](crate::negotiation::DeflateParams::server_no_context_takeover).
  /// Nothing else records takeover, and nothing mutates it after the
  /// handshake.
  #[cfg(feature = "deflate")]
  fn inbound_no_context_takeover(&self) -> bool {
    self.conn.deflate.is_some_and(|params| {
      if Ro::EXPECT_MASKED_INBOUND {
        params.client_no_context_takeover()
      } else {
        params.server_no_context_takeover()
      }
    })
  }

  /// Whether the inbound inflate context has been poisoned by a skipped
  /// compressed message (see [`Connection::observe`]). Always `false` without
  /// the `deflate` feature, where no compressed message can be accepted at
  /// all.
  fn inflate_poisoned(&self) -> bool {
    #[cfg(feature = "deflate")]
    {
      self.conn.recv.inflate_poisoned
    }
    #[cfg(not(feature = "deflate"))]
    {
      false
    }
  }

  /// Records that the in-progress message's payload is NOT being decoded, and
  /// — when that message is compressed and the inbound direction kept its
  /// context — that the inflate context is now unusable.
  ///
  /// **The single writer of both facts.** Two sites decide to skip (a message
  /// that starts under observation or under a poisoned context, and a run an
  /// observing cursor walks past mid-message), and routing both through one
  /// function is what keeps "a skipped compressed message poisons the
  /// context" from being true at one of them and not the other.
  ///
  /// The poison is set for ANY skipped compressed run, including an empty
  /// one. DEFLATE is a bit stream, so what a skipped frame costs the inflater
  /// is not measured in the bytes it carried — an endpoint that resumed
  /// mid-stream would be reading at the wrong bit offset — and a rule that
  /// asked "did this frame carry payload" would be a second, weaker rule.
  fn mark_message_skipped(&mut self) {
    let MessageState::InMessage {
      kind,
      compressed,
      received,
      ..
    } = self.conn.recv.message
    else {
      return;
    };
    self.conn.recv.message = MessageState::InMessage {
      kind,
      compressed,
      received,
      skipped: true,
    };
    #[cfg(feature = "deflate")]
    if compressed && !self.inbound_no_context_takeover() {
      self.conn.recv.inflate_poisoned = true;
    }
  }

  /// Prepares the inbound decompressor for a new compressed message: create
  /// it lazily, reset its window when the inbound direction negotiated
  /// `no_context_takeover`, and clear the per-message inflated-byte counter.
  #[cfg(feature = "deflate")]
  fn begin_inflate_message(&mut self) {
    let no_takeover = self.inbound_no_context_takeover();
    let had_context = self.conn.recv.inflate.is_some();
    let inflate = self
      .conn
      .recv
      .inflate
      .get_or_insert_with(inflate::InflateBox::new);
    // Reset only an EXISTING context; a freshly created one needs none.
    if no_takeover && had_context {
      inflate.reset();
    }
    inflate.begin_message();
  }

  /// Advances the current data payload by one run: splits off the available
  /// bytes, unmasks them in place, applies the per-frame/per-message state
  /// transitions and the raw size cap, and reports what to yield. The borrow
  /// of `self` ends with this call — the returned [`DataStep`] only borrows
  /// the input (`'a`), never `self`, so the event itself is built afterward
  /// in [`next`](Self::next) (the lending-iterator split that keeps the
  /// borrow checker happy across the loop).
  fn advance_data_payload(&mut self) -> DataStep<'a> {
    let FrameState::DataPayload {
      remaining,
      mask: key,
      offset,
      fin,
    } = self.conn.recv.frame
    else {
      return DataStep::Continue;
    };

    // The message state is read BEFORE any byte is touched, because whether
    // this run is decoded decides whether the input is written to at all: an
    // observed run is not unmasked, so the caller's buffer comes back as the
    // wire had it.
    let MessageState::InMessage {
      kind,
      compressed,
      received,
      skipped,
    } = self.conn.recv.message
    else {
      return DataStep::Fail(CloseCode::ProtocolError);
    };
    let skip = self.observing || skipped;

    let available = self.remaining();
    let take = clamp_to_usize(remaining, available);
    if take == 0 && remaining > 0 {
      return DataStep::NeedMore;
    }

    let head = self.take_front(take);
    if let Some(k) = key
      && !skip
    {
      mask(head, k, offset);
    }
    // `head` borrows the input (`'a`), which is disjoint from `self`.
    let chunk: &'a [u8] = head;

    let next_remaining = remaining.saturating_sub(widen(take));
    let frame_done = next_remaining == 0;
    if frame_done {
      self.conn.recv.frame = FrameState::Header {
        buf: [0; MAX_FRAME_HEADER],
        len: 0,
      };
    } else {
      self.conn.recv.frame = FrameState::DataPayload {
        remaining: next_remaining,
        mask: key,
        offset: offset.saturating_add(widen(take)),
        fin,
      };
    }

    let message_done = frame_done && fin;

    // Skipped: the cursor has advanced over the payload and that is all it
    // does with it. No unmask (above), no UTF-8 validation, no inflate, and
    // no size accounting — `received` is deliberately left where it was,
    // because a cap on bytes this endpoint never looked at bounds nothing.
    if skip {
      // The FIRST skipped run of a message whose start said otherwise. That
      // start was emitted before this decision existed, so the fact travels
      // as its own event — once, here, and never for a message whose start
      // already carried `skipped`.
      //
      // `self.observing && !skipped` is the whole condition, and the inflate
      // poison adds no second cause: the poison is written only by
      // `mark_message_skipped`, which acts on the message in flight, and only
      // one message is ever in flight (a Text or Binary frame inside an open
      // message fails the connection in `on_header`). So the poison is set at
      // the same instant that message is marked skipped — by this branch —
      // and every LATER compressed message meets it at its own `on_header`,
      // where it is marked skipped at the start and its `MessageStart` says
      // so. A poisoned message in flight is unreachable, so there is no
      // second emission site to write and no untestable branch guarding one.
      let abandons = !skipped;
      self.mark_message_skipped();
      if message_done {
        self.conn.recv.message = MessageState::Idle;
      }
      if abandons {
        // The boundary, if this same run carried it, follows the abandon.
        self.pending_message_end = message_done;
        return DataStep::Abandoned;
      }
      return DataStep::Skipped { message_done };
    }

    #[cfg(feature = "deflate")]
    if compressed {
      // The inflated-byte cap is enforced during inflation, in `decide_inflated`.
      if message_done {
        self.conn.recv.message = MessageState::Idle;
      }
      return DataStep::YieldInflated {
        chunk,
        kind,
        message_done,
      };
    }

    // Uncompressed: cap on the bytes received here.
    let received = received.saturating_add(widen(chunk.len()));
    if received > self.conn.config.max_message_size() {
      return DataStep::Fail(CloseCode::MessageTooBig);
    }
    self.conn.recv.message = if message_done {
      MessageState::Idle
    } else {
      MessageState::InMessage {
        kind,
        compressed,
        received,
        skipped: false,
      }
    };
    DataStep::YieldInput {
      chunk,
      kind,
      message_done,
    }
  }

  /// Builds the event for an uncompressed data run (the borrow phase of the
  /// lending split). `chunk` borrows the input. Sets the pending `MessageEnd`
  /// flag when the chunk both yields and ends the message.
  fn build_input_event(
    &mut self,
    chunk: &'a [u8],
    kind: MessageKind,
    message_done: bool,
  ) -> Option<Event<'a>> {
    let event = match kind {
      MessageKind::Binary => (!chunk.is_empty()).then_some(Event::BinaryChunk(chunk)),
      MessageKind::Text => {
        match validate_text_ranges(
          &mut self.conn.recv.utf8,
          &mut self.conn.recv.text_carry,
          chunk,
          message_done,
        ) {
          Ok(y) => y.map(|y| Event::TextChunk(text_chunk(chunk, y))),
          Err(code) => return Some(self.fail(code)),
        }
      }
    };
    self.finish_data_event(event, message_done)
  }

  /// Inflates a compressed data run (RFC 7692 §7.2.2) and DECIDES what to
  /// yield, returning an OWNED [`InflateDecision`] — no borrow of `self`
  /// outlives this call. The decompressed bytes stay in the inflate buffer;
  /// [`build_inflated_event`](Self::build_inflated_event) slices them
  /// afterward. Splitting the mutation (inflate + validate + state) from the
  /// borrow (slicing the buffer) is what lets the lending iterator type-check:
  /// when this run yields nothing, `next` keeps looping with no borrow held.
  /// Text is validated post-inflation through the same UTF-8 machinery as
  /// uncompressed text. Sets the pending `MessageEnd` flag when a yielded
  /// chunk also ends the message.
  #[cfg(feature = "deflate")]
  fn decide_inflated(
    &mut self,
    chunk: &[u8],
    kind: MessageKind,
    message_done: bool,
  ) -> InflateDecision {
    use inflate::InflateFail;
    let max = self.conn.config.max_message_size();

    let recv = &mut self.conn.recv;
    let Some(inflate) = recv.inflate.as_mut() else {
      // A compressed message always created its decompressor in on_header.
      return InflateDecision::Fail(CloseCode::ProtocolError);
    };
    // The RFC 7692 §7.2.2 sync-flush tail is appended once, after the message's
    // FINAL frame — keyed on `message_done`, NOT on each frame's completion.
    match inflate.run(chunk, message_done, max) {
      Ok(()) => {}
      Err(InflateFail::Corrupt) => return InflateDecision::Fail(CloseCode::InvalidFramePayload),
      Err(InflateFail::TooLarge) => return InflateDecision::Fail(CloseCode::MessageTooBig),
    }

    // Decide what (if anything) to yield. Binary yields the whole inflated
    // run; text validates it (split borrow: the buffer is read while
    // `utf8`/`text_carry`, disjoint fields, are mutated) and yields the
    // validated body range.
    let yielded = match kind {
      MessageKind::Binary => {
        let inflated = recv.inflate.as_deref().map(inflate::InflateBox::output);
        match inflated {
          Some(bytes) if !bytes.is_empty() => Some(Yielded::Binary),
          Some(_) => None,
          None => return InflateDecision::Fail(CloseCode::ProtocolError),
        }
      }
      MessageKind::Text => {
        let Some(inflated) = recv.inflate.as_deref().map(inflate::InflateBox::output) else {
          return InflateDecision::Fail(CloseCode::ProtocolError);
        };
        match validate_text_ranges(&mut recv.utf8, &mut recv.text_carry, inflated, message_done) {
          Ok(Some(y)) => Some(Yielded::Text(y)),
          Ok(None) => None,
          Err(code) => return InflateDecision::Fail(code),
        }
      }
    };

    match yielded {
      Some(y) => {
        if message_done {
          self.pending_message_end = true;
        }
        InflateDecision::Yield(y)
      }
      None if message_done => InflateDecision::MessageEnd,
      None => InflateDecision::Nothing,
    }
  }

  /// Borrow-phase tail of [`decide_inflated`](Self::decide_inflated): slices
  /// the just-produced inflate buffer to build the yielded chunk event. Called
  /// from `next` only when the decision was [`InflateDecision::Yield`], so the
  /// `'s` borrow of `self` here is the cursor's final tail return.
  #[cfg(feature = "deflate")]
  fn build_inflated_event(&mut self, yielded: Yielded) -> Event<'_> {
    let inflated = self
      .conn
      .recv
      .inflate
      .as_deref()
      .map_or(&[][..], inflate::InflateBox::output);
    match yielded {
      Yielded::Binary => Event::BinaryChunk(inflated),
      Yielded::Text(y) => Event::TextChunk(text_chunk(inflated, y)),
    }
  }

  /// Sequences a just-built data chunk with its trailing `MessageEnd`: when
  /// the chunk yields and the message is done, stash the pending end; when the
  /// chunk is empty but the message is done, surface `MessageEnd` now.
  fn finish_data_event<'s>(
    &mut self,
    event: Option<Event<'s>>,
    message_done: bool,
  ) -> Option<Event<'s>> {
    match event {
      Some(e) => {
        if message_done {
          self.pending_message_end = true;
        }
        Some(e)
      }
      None if message_done => Some(Event::MessageEnd),
      None => None,
    }
  }

  /// Consumes (part of) the current control payload: split off the available
  /// run, unmask it in place, copy it into the accumulator, and once the
  /// frame is complete dispatch the control opcode.
  fn step_control_payload(&mut self) -> StepOutcome<'a> {
    let FrameState::ControlPayload {
      opcode,
      remaining,
      mask: key,
      offset,
    } = self.conn.recv.frame
    else {
      return StepOutcome::Continue;
    };

    let available = self.remaining();
    let take = clamp_to_usize(remaining, available);
    if take == 0 && remaining > 0 {
      return StepOutcome::NeedMore;
    }

    let at = self.conn.recv.control_len;
    let head = self.take_front(take);
    if let Some(k) = key {
      mask(head, k, offset);
    }
    if let Some(dst) = self
      .conn
      .recv
      .control_buf
      .get_mut(at..at.saturating_add(head.len()))
    {
      for (d, s) in dst.iter_mut().zip(head.iter()) {
        *d = *s;
      }
    }
    self.conn.recv.control_len = at.saturating_add(head.len());

    let next_remaining = remaining.saturating_sub(widen(take));
    if next_remaining > 0 {
      self.conn.recv.frame = FrameState::ControlPayload {
        opcode,
        remaining: next_remaining,
        mask: key,
        offset: offset.saturating_add(widen(take)),
      };
      return StepOutcome::Continue;
    }
    self.conn.recv.frame = FrameState::Header {
      buf: [0; MAX_FRAME_HEADER],
      len: 0,
    };
    match self.finish_control(opcode) {
      Ok(event) => StepOutcome::Event(event),
      Err(code) => StepOutcome::Event(self.fail(code)),
    }
  }

  /// Dispatches a fully-accumulated control frame from `control_buf`.
  fn finish_control(&mut self, opcode: Opcode) -> Result<Event<'a>, CloseCode> {
    let len = self.conn.recv.control_len.min(MAX_CONTROL_PAYLOAD);
    let mut payload_buf = [0u8; MAX_CONTROL_PAYLOAD];
    for (d, s) in payload_buf
      .iter_mut()
      .zip(self.conn.recv.control_buf.iter().take(len))
    {
      *d = *s;
    }
    let len_u8 = u8::try_from(len).unwrap_or(MAX_CONTROL_PAYLOAD_U8);
    let payload = ControlPayload::new(payload_buf, len_u8);
    self.conn.recv.control_len = 0;

    match opcode {
      Opcode::Ping => {
        self.queue_pong(payload_buf, len_u8);
        Ok(Event::Ping(payload))
      }
      Opcode::Pong => Ok(Event::Pong(payload)),
      Opcode::Close => {
        let decoded = match decode_close_payload(payload.as_slice()) {
          Ok(d) => d,
          // A malformed-UTF-8 REASON is invalid payload DATA (1007) — the
          // same failure class as invalid text, RFC 6455 §8.1 — while the
          // structural shapes (a one-byte code) stay protocol errors (1002).
          Err(crate::frame::ClosePayloadError::InvalidReasonUtf8) => {
            return Err(CloseCode::InvalidFramePayload);
          }
          Err(_) => return Err(CloseCode::ProtocolError),
        };
        let code = decoded.code();
        // An ABSENT code (empty body → synthetic NoStatusReceived) is a clean
        // close; an explicit code must be valid on the wire. 1005/1006/1015
        // are reserved signalling codes that are never valid ON the wire, so
        // sending one explicitly (e.g. `03 ED` = 1005) fails 1002 per Autobahn
        // 7.x — only the empty-body synthesis of NoStatusReceived is accepted.
        let absent = payload.as_slice().is_empty();
        if !absent && !code.is_valid_on_wire() {
          return Err(CloseCode::ProtocolError);
        }
        // Echo (RFC 6455 §5.5.1): respond with the same code (Normal when
        // none was received), unless we already sent our own close.
        let echo = if absent { CloseCode::Normal } else { code };
        if !matches!(self.conn.lifecycle, Lifecycle::CloseSent) {
          let queued_behind = self.conn.recv.queued_pongs();
          self.conn.send.queue_close(echo, "", queued_behind);
        } else if self.conn.send.close_sent {
          // Our close ALREADY LEFT, so both Close frames are now exchanged.
          // §5.5.1 (line 2023 of `.rfc-cache/rfc6455.txt`): "After both sending
          // and receiving a Close message, an endpoint considers the WebSocket
          // connection closed and MUST close the underlying TCP connection."
          // Nothing more may go out. The §5.5.2 Pong obligation was real when
          // those Pings arrived, but it cannot be discharged on a connection
          // the RFC says MUST now close — the MUST-close wins, and the echoes
          // are dropped rather than written after the handshake completed.
          self.conn.send.pending_pong = None;
          #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
          self.conn.recv.pong_overflow.clear();
          self.conn.send.pongs_before_close = 0;
        } else {
          // Our close is queued and has NOT gone out. Every pong still queued
          // was owed for a Ping that arrived before this Close (one arriving
          // after it is refused in `queue_pong`), and there is still a frame
          // ahead of them to be written — so all of them can be discharged
          // first. Promote the whole queue into the pre-close prefix; the drain
          // then yields every pong and finally the close that ends the
          // handshake. Bounded at `MAX_PENDING_PONGS + 1` pongs plus the close.
          // This is the ONE site that raises the count, and it is the epoch
          // boundary `poll_transmit`'s two-epoch bound states its second half
          // from: `lifecycle` goes Terminal just below, so
          // `queue_pong` refuses every later Ping and there is no third epoch.
          let owed = usize::from(self.conn.send.pending_pong.is_some())
            .saturating_add(self.conn.recv.queued_pongs());
          self.conn.send.pongs_before_close = u8::try_from(owed).unwrap_or(u8::MAX);
        }
        // Peer echo clears the close deadline (handshake complete).
        self.conn.close_deadline = None;
        // Terminal IMMEDIATELY (on the connection, not the cursor): a consumer
        // that handles `CloseReceived` and drops the cursor without asking for
        // the trailing `Closed` event must still observe `is_terminal()` and
        // get `HandleError::Terminal` on the next feed — otherwise the
        // connection wedges in a never-terminal limbo. The in-flight cursor
        // still delivers `Closed` because `pending_closed` is popped before
        // the terminal check in `next`.
        self.conn.lifecycle = Lifecycle::Terminal;

        let mut reason_buf = [0u8; MAX_CONTROL_PAYLOAD];
        let rbytes = decoded.reason().as_bytes();
        for (d, s) in reason_buf.iter_mut().zip(rbytes) {
          *d = *s;
        }
        let rlen = u8::try_from(rbytes.len()).unwrap_or(MAX_CONTROL_PAYLOAD_U8);
        let received = CloseReceived::new(code, ControlPayload::new(reason_buf, rlen));
        self.pending_closed = Some(Closed::new(code, true));
        Ok(Event::CloseReceived(received))
      }
      _ => Err(CloseCode::ProtocolError),
    }
  }

  /// Records the pong owed for a received ping (RFC 6455 §5.5.2).
  ///
  /// The first echo fills the single outbound control slot; later pings in the
  /// same batch go BEHIND it in the overflow queue where a heap is available,
  /// so every ping of a batch gets its own pong (Autobahn §2.10). That queue is
  /// CAPPED: once full, the oldest queued echo is shed, so a peer flooding
  /// pings faster than the application drains `poll_transmit` cannot grow
  /// memory without bound — §5.5.3 expressly allows answering "only the most
  /// recently processed Ping frame", which is what makes shedding the OLDEST
  /// conformant. On the bare tier there is no queue and the slot simply
  /// coalesces to the most recent ping, by the same clause.
  ///
  /// **The §5.5.2 question is settled HERE, where the Ping lands, not at drain
  /// time.** Line 2042 of `.rfc-cache/rfc6455.txt` reads "Upon receipt of a Ping
  /// frame, an endpoint MUST send a Pong frame in response, unless it already
  /// received a Close frame" — the exemption is a property of the moment the
  /// Ping ARRIVES. So a Ping that arrives after a Close was received owes
  /// nothing and is dropped right here; and, the other half of the same
  /// sentence, a pong owed BEFORE that Close arrived is **not** cancelled by it.
  /// Nothing in §5.5.2 says a later Close discharges an obligation that already
  /// existed, and an earlier revision of this crate read it that way and
  /// silently dropped the echo.
  ///
  /// The terminal check covers the failure path too: §7.1.7 (line 2399) has an
  /// endpoint instructed to _Fail the WebSocket Connection_ stop processing, and
  /// `fail` additionally clears what was already owed.
  ///
  /// **It is the second half of a pair, and cannot fire today.** The first half
  /// is [`Events::next`]'s opening `if self.conn.is_terminal() { return None; }`:
  /// once a Close is parsed the cursor stops consuming, so a Ping later in the
  /// same batch is never decoded and this function is never reached with a
  /// terminal connection. `handle` refuses a subsequent call outright. Which
  /// means deleting the check reds nothing that goes through `handle` — the
  /// shape this crate has twice mistaken for coverage.
  ///
  /// So the pairing is pinned rather than asserted:
  /// `tests::a_post_close_ping_owes_no_pong_even_past_the_cursor_short_circuit`
  /// bypasses the short-circuit and drives this function directly, and
  /// `tests::dropping_events_after_close_received_is_still_terminal` covers the
  /// half that is live. Keep both: the short-circuit is about ignoring the rest
  /// of the input (§1.4), this check is about §5.5.2's obligation, and a
  /// refactor that separated them would otherwise reintroduce the defect
  /// silently.
  ///
  /// A queued CLOSE is not consulted. It is a different frame in a different
  /// slot; which of the two drains first is queue-time order, decided in
  /// `poll_transmit`.
  fn queue_pong(&mut self, payload: [u8; MAX_CONTROL_PAYLOAD], len: u8) {
    if self.conn.is_terminal() {
      return;
    }
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    if self.conn.send.pending_pong.is_some() {
      if self.conn.recv.pong_overflow.len() >= MAX_PENDING_PONGS {
        self.conn.recv.pong_overflow.pop_front();
        // The shed entry is drain position 1 — the slot is 0, the overflow
        // front is 1. It lies inside the frozen pre-close prefix only when that
        // prefix reaches past the slot, i.e. `>= 2`; at exactly 1 the prefix is
        // the slot alone and what was shed was already behind the close. Unlike
        // `offer_pong`'s position 0, `saturating_sub` alone would be wrong here,
        // so the comparison is load-bearing rather than restated.
        if self.conn.send.pongs_before_close >= 2 {
          self.conn.send.pongs_before_close = self.conn.send.pongs_before_close.saturating_sub(1);
        }
      }
      self.conn.recv.pong_overflow.push_back((payload, len));
      return;
    }
    self.conn.send.offer_pong(payload, len);
  }

  /// Queues the failure close, transitions to Terminal, and produces the
  /// terminal event. Stops consuming the rest of the input.
  fn fail(&mut self, code: CloseCode) -> Event<'a> {
    // Only a close that actually went out (drained by `poll_transmit`)
    // suppresses the failure close. A close that is merely QUEUED — `close()`
    // ran but the driver has not drained yet — is superseded: the failure
    // code is what must reach the wire, or the peer would see a benign close
    // for a connection we are failing.
    // §7.1.7 (line 2399): an endpoint instructed to _Fail the WebSocket
    // Connection_ proceeds to close it and "MUST NOT continue to attempt to
    // process data". So every owed pong goes, here at §7.1.7's own entrance,
    // rather than being filtered out at drain time by a second rule.
    // The count is "pre-close pongs currently queued", and a cleared queue has
    // none — so it goes with them. F3's discard arm already does this; now every
    // site that empties the queue does.
    //
    // MEASURED to be a no-op today, and kept anyway. On the `!close_sent` path
    // below, `force_close` calls `queue_close(code, "", 0)` with the slot
    // already emptied above, so the count is recomputed to 0 there. On the
    // `close_sent` path nothing recomputes it — but a POSITIVE count with
    // `close_sent` is unreachable: the close drains only once the prefix is
    // exhausted or the slot is empty, and nothing empties the slot except
    // draining. So neither branch can leave a stale number, and deleting this
    // line reds no test. It stays because it makes the rule true AT the site
    // that empties the queue rather than by two arguments about other sites,
    // and because the second of those arguments is one line of `poll_transmit`
    // away from being false.
    self.conn.send.pending_pong = None;
    #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
    self.conn.recv.pong_overflow.clear();
    self.conn.send.pongs_before_close = 0;
    if !self.conn.send.close_sent {
      self.conn.send.force_close(code);
    }
    self.conn.lifecycle = Lifecycle::Terminal;
    self.data = None;
    Event::Closed(Closed::new(code, false))
  }
}

/// Outcome of one payload step.
enum StepOutcome<'a> {
  /// Surface this event to the caller.
  Event(Event<'a>),
  /// The current frame is not finished and the input is exhausted.
  NeedMore,
  /// Keep looping (more bytes or a new frame await in the same input).
  Continue,
}

/// What [`advance_data_payload`](Events::advance_data_payload) decided to do
/// with one payload run. Carries only input-borrowed data (`'a`), never a
/// borrow of `self`, so [`next`](Events::next) can build the actual event
/// after the mutating borrow ends — the split that makes the lending
/// iterator type-check across the `next` loop.
enum DataStep<'a> {
  /// Yield an uncompressed run (already unmasked, borrowing the input).
  YieldInput {
    chunk: &'a [u8],
    kind: MessageKind,
    message_done: bool,
  },
  /// Inflate and yield a compressed run (output lands in the inflate buffer).
  #[cfg(feature = "deflate")]
  YieldInflated {
    chunk: &'a [u8],
    kind: MessageKind,
    message_done: bool,
  },
  /// The run was advanced over and not decoded (see
  /// [`Connection::observe`]): nothing to yield but the message's `End`.
  Skipped { message_done: bool },
  /// The first run skipped of a message whose `MessageStart` said otherwise:
  /// yield [`Event::MessageAbandoned`]. A `MessageEnd` owed by the same run is
  /// left pending on the cursor and follows it.
  Abandoned,
  /// Fail the connection with this close code.
  Fail(CloseCode),
  /// The current frame is not finished and the input is exhausted.
  NeedMore,
  /// Nothing to yield from this run; keep looping.
  Continue,
}

/// What inflating one compressed run decided to do. Owned (no borrow of
/// `self`), so the buffer-slicing event build happens afterward in `next`.
#[cfg(feature = "deflate")]
enum InflateDecision {
  /// Yield a chunk built from the inflate buffer (see [`Yielded`]).
  Yield(Yielded),
  /// The run ended the message and produced no chunk: yield `MessageEnd`.
  MessageEnd,
  /// Nothing to yield from this run; keep looping.
  Nothing,
  /// Fail the connection with this close code.
  Fail(CloseCode),
}

/// Which kind of chunk an inflated run yields; the bytes live in the inflate
/// buffer and are sliced in the borrow phase.
#[cfg(feature = "deflate")]
enum Yielded {
  /// The whole inflated run, as a binary chunk.
  Binary,
  /// A validated text body (with its carry prefix) over the inflated run.
  Text(TextYield),
}

/// The §5.5 control-payload cap as a `u64` for header comparisons.
fn control_cap() -> u64 {
  widen(MAX_CONTROL_PAYLOAD)
}

const MAX_CONTROL_PAYLOAD_U8: u8 = 125;

/// Cap on the pong-echo overflow queue (heap tiers): one pending slot plus
/// this many queued echoes bounds a ping flood at ~2 KiB of retained payload
/// while still answering every ping of any realistic batch (Autobahn §2.10
/// sends ten). Past the cap the oldest echo is shed — conformant per RFC 6455
/// §5.5.3, which lets an endpoint answer only the most recent ping.
#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
const MAX_PENDING_PONGS: usize = 16;

/// Widens a `usize` to `u64` (lossless on supported targets; the saturating
/// fallback keeps the no-narrowing lint wall satisfied uniformly).
fn widen(value: usize) -> u64 {
  u64::try_from(value).unwrap_or(u64::MAX)
}

/// `min(remaining, available)` as a `usize` — `available` already bounds it,
/// so the conversion never saturates in practice.
fn clamp_to_usize(remaining: u64, available: usize) -> usize {
  usize::try_from(remaining.min(widen(available))).unwrap_or(available)
}

/// The yield of one text-chunk validation: the carried-character prefix plus
/// the byte range of the chunk that forms the body. Owned (no borrow), so the
/// validator's borrow of `utf8`/`text_carry` ends before the caller slices the
/// chunk — letting the body slice borrow a *different* `RecvState` field (the
/// inflate buffer) than the one validation mutated.
struct TextYield {
  prefix: ([u8; 4], u8),
  body: core::ops::Range<usize>,
}

/// Runs the incremental validator over a text chunk, assembling the carry
/// prefix. Returns what to yield (or `None` when the chunk is fully absorbed
/// into the carry / produced nothing), or the close code on invalid UTF-8.
///
/// Free function over the specific fields (not `&mut self`) so the caller can
/// borrow `utf8`/`text_carry` while `chunk` borrows a different field of the
/// same `RecvState` — the split borrow a `&mut self` method could not express.
fn validate_text_ranges(
  utf8: &mut Utf8Validator,
  text_carry: &mut ([u8; 4], u8),
  chunk: &[u8],
  message_done: bool,
) -> Result<Option<TextYield>, CloseCode> {
  let needed_before = usize::from(utf8.pending_needed());
  let complete = match utf8.feed(chunk) {
    Ok(c) => c,
    Err(_) => return Err(CloseCode::InvalidFramePayload),
  };
  if message_done && !utf8.is_boundary() {
    return Err(CloseCode::InvalidFramePayload);
  }

  // Prefix: finish the carried char with the first `needed_before` bytes (if
  // this chunk supplied them all — otherwise everything joins the carry and
  // nothing is yielded).
  let (mut carry_buf, carry_len) = *text_carry;
  let mut prefix = ([0u8; 4], 0u8);
  let body_start = if carry_len > 0 {
    if chunk.len() < needed_before {
      // Char still incomplete: extend the carry.
      for (i, b) in chunk.iter().enumerate() {
        if let Some(slot) = carry_buf.get_mut(usize::from(carry_len).saturating_add(i)) {
          *slot = *b;
        }
      }
      let new_len = carry_len.saturating_add(u8::try_from(chunk.len()).unwrap_or(0));
      *text_carry = (carry_buf, new_len);
      return Ok(None);
    }
    // Char completes: prefix = carry + needed_before bytes.
    let mut prefix_buf = [0u8; 4];
    let mut n = 0u8;
    for b in carry_buf.iter().take(usize::from(carry_len)) {
      if let Some(slot) = prefix_buf.get_mut(usize::from(n)) {
        *slot = *b;
        n = n.saturating_add(1);
      }
    }
    for b in chunk.iter().take(needed_before) {
      if let Some(slot) = prefix_buf.get_mut(usize::from(n)) {
        *slot = *b;
        n = n.saturating_add(1);
      }
    }
    prefix = (prefix_buf, n);
    *text_carry = ([0; 4], 0);
    needed_before
  } else {
    0
  };

  // New carry: bytes past the last char boundary in THIS chunk.
  let new_carry = chunk.get(complete..).unwrap_or(&[]);
  if !new_carry.is_empty() {
    let mut carry = [0u8; 4];
    let mut n = 0u8;
    for b in new_carry.iter().take(3) {
      if let Some(slot) = carry.get_mut(usize::from(n)) {
        *slot = *b;
        n = n.saturating_add(1);
      }
    }
    *text_carry = (carry, n);
  }

  let body = body_start.min(complete)..complete;
  if prefix.1 == 0 && body.is_empty() {
    return Ok(None);
  }
  Ok(Some(TextYield { prefix, body }))
}

/// Builds a [`TextChunk`] from a validated yield over `chunk`. The body range
/// is validated UTF-8 by construction (the validator confirmed it).
fn text_chunk<'s>(chunk: &'s [u8], y: TextYield) -> TextChunk<'s> {
  let body_bytes = chunk.get(y.body).unwrap_or(&[]);
  let body = core::str::from_utf8(body_bytes).unwrap_or("");
  TextChunk::new(y.prefix, body)
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::{
    connection::{
      Connection, ConnectionConfig,
      role::Server,
      tests::{Ev, drain, drain_observed, fold_events, server},
    },
    frame::{CloseCode, FrameHeader, Opcode, encode_close_payload, mask as apply_mask},
    negotiation::Negotiated,
    time::testing::TestInstant,
  };

  const KEY: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];

  /// Builds one masked frame (client→server direction) into a Vec.
  fn frame(opcode: Opcode, fin: bool, rsv1: bool, payload: &[u8]) -> Vec<u8> {
    let header = FrameHeader::new(opcode, payload.len() as u64)
      .with_fin(fin)
      .with_rsv1(rsv1)
      .with_mask(Some(KEY));
    let mut out = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode(&mut out).unwrap();
    out[n..].copy_from_slice(payload);
    apply_mask(&mut out[n..], KEY, 0);
    out
  }

  fn fold(events: Vec<Ev>) -> Vec<Ev> {
    fold_events(events)
  }

  #[test]
  fn single_text_message() {
    let mut conn = server();
    let bytes = frame(Opcode::Text, true, false, "Hello".as_bytes());
    let got = fold(drain(&mut conn, &bytes));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Text, false),
        Ev::Text("Hello".into()),
        Ev::End
      ]
    );
  }

  #[test]
  fn fragmented_text_with_interleaved_ping() {
    let mut conn = server();
    let mut bytes = frame(Opcode::Text, false, false, b"Hel");
    bytes.extend(frame(Opcode::Ping, true, false, b"k"));
    bytes.extend(frame(Opcode::Continuation, true, false, b"lo"));
    let got = fold(drain(&mut conn, &bytes));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Text, false),
        Ev::Text("Hel".into()),
        Ev::Ping(b"k".to_vec()),
        Ev::Text("lo".into()),
        Ev::End,
      ]
    );
  }

  #[test]
  fn split_anywhere_yields_identical_folded_events() {
    // The 4a smoke version of the invariance property (full proptest in 4b):
    // a fixed multi-frame stream cut at EVERY byte boundary.
    let mut whole = frame(Opcode::Text, false, false, "Héllo ".as_bytes());
    whole.extend(frame(
      Opcode::Continuation,
      true,
      false,
      "wörld 𐍈".as_bytes(),
    ));
    whole.extend(frame(Opcode::Binary, true, false, &[1, 2, 3]));

    let mut reference = server();
    let expected = fold(drain(&mut reference, &whole));

    for cut in 0..=whole.len() {
      let mut conn = server();
      let mut got = drain(&mut conn, &whole[..cut]);
      got.extend(drain(&mut conn, &whole[cut..]));
      assert_eq!(fold(got), expected, "cut at {cut}");
    }
  }

  #[test]
  fn unmasked_client_frame_fails_1002() {
    let mut conn = server();
    let header = FrameHeader::new(Opcode::Text, 2);
    let mut bytes = vec![0u8; 4];
    let n = header.encode(&mut bytes).unwrap();
    bytes.truncate(n);
    bytes.extend(b"hi");
    let got = drain(&mut conn, &bytes);
    assert_eq!(got, [Ev::Closed(1002, false)]);
    assert!(conn.is_terminal());
    // Feeding a terminal connection is a caller error.
    let mut more = [0u8; 1];
    assert!(matches!(
      conn.handle(TestInstant(0), &mut more).unwrap_err(),
      HandleError::Terminal
    ));
  }

  /// Regression: a close frame with a VALID two-byte code but a
  /// malformed-UTF-8 reason fails as invalid payload DATA (1007), the same
  /// class as invalid text — only the STRUCTURAL close-payload shapes (a
  /// one-byte code) are protocol errors (1002).
  #[test]
  fn invalid_utf8_close_reason_fails_1007() {
    let mut conn = server();
    // Code 1000 + invalid reason byte.
    let payload = [0x03, 0xE8, 0xFF];
    let got = drain(&mut conn, &frame(Opcode::Close, true, false, &payload));
    assert_eq!(got, [Ev::Closed(1007, false)]);

    // The one-byte structural shape stays 1002.
    let mut conn = server();
    let got = drain(&mut conn, &frame(Opcode::Close, true, false, &[0x03]));
    assert_eq!(got, [Ev::Closed(1002, false)]);
  }

  #[test]
  fn policy_violations_fail_1002() {
    // Reserved opcode.
    let mut conn = server();
    assert_eq!(
      drain(&mut conn, &frame(Opcode::Reserved(0x3), true, false, b"")),
      [Ev::Closed(1002, false)]
    );

    // RSV1 without deflate.
    let mut conn = server();
    assert_eq!(
      drain(&mut conn, &frame(Opcode::Text, true, true, b"")),
      [Ev::Closed(1002, false)]
    );

    // Fragmented control frame.
    let mut conn = server();
    assert_eq!(
      drain(&mut conn, &frame(Opcode::Ping, false, false, b"")),
      [Ev::Closed(1002, false)]
    );

    // Oversized control frame: 126-byte ping.
    let mut conn = server();
    let big = vec![0u8; 126];
    assert_eq!(
      drain(&mut conn, &frame(Opcode::Ping, true, false, &big)),
      [Ev::Closed(1002, false)]
    );

    // Continuation with no message.
    let mut conn = server();
    assert_eq!(
      drain(&mut conn, &frame(Opcode::Continuation, true, false, b"x")),
      [Ev::Closed(1002, false)]
    );

    // New data opcode mid-message.
    let mut conn = server();
    let mut bytes = frame(Opcode::Text, false, false, b"a");
    bytes.extend(frame(Opcode::Text, true, false, b"b"));
    let got = drain(&mut conn, &bytes);
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Text, false),
        Ev::Text("a".into()),
        Ev::Closed(1002, false)
      ]
    );
  }

  #[test]
  fn invalid_utf8_fails_fast_1007() {
    let mut conn = server();
    let got = drain(&mut conn, &frame(Opcode::Text, true, false, &[0xC0, 0xAF]));
    assert_eq!(
      got,
      [Ev::Start(MessageKind::Text, false), Ev::Closed(1007, false)]
    );

    // Truncated char at message end.
    let mut conn = server();
    let got = drain(&mut conn, &frame(Opcode::Text, true, false, &[0xF0, 0x9F]));
    assert_eq!(
      got,
      [Ev::Start(MessageKind::Text, false), Ev::Closed(1007, false)]
    );

    // Char split across FRAMES of one message is fine.
    let mut conn = server();
    let e = "é".as_bytes(); // C3 A9
    let mut bytes = frame(Opcode::Text, false, false, &e[..1]);
    bytes.extend(frame(Opcode::Continuation, true, false, &e[1..]));
    let got = fold(drain(&mut conn, &bytes));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Text, false),
        Ev::Text("é".into()),
        Ev::End
      ]
    );
  }

  #[test]
  fn size_limits_fail_1009() {
    let small = ConnectionConfig::new()
      .with_max_frame_payload(4)
      .with_max_message_size(6);
    let mut conn: Connection<TestInstant, Server> =
      Connection::new(&Negotiated::none(), small, Server::new(), TestInstant(0));
    assert_eq!(
      drain(&mut conn, &frame(Opcode::Binary, true, false, b"12345")),
      [Ev::Closed(1009, false)]
    );

    let mut conn: Connection<TestInstant, Server> =
      Connection::new(&Negotiated::none(), small, Server::new(), TestInstant(0));
    let mut bytes = frame(Opcode::Binary, false, false, b"1234");
    bytes.extend(frame(Opcode::Continuation, true, false, b"567"));
    let got = fold(drain(&mut conn, &bytes));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Binary, false),
        Ev::Bin(b"1234".to_vec()),
        Ev::Closed(1009, false)
      ]
    );
  }

  #[test]
  fn close_handshake_from_peer() {
    let mut conn = server();
    let mut payload = [0u8; 16];
    let n = encode_close_payload(CloseCode::Normal, "bye", &mut payload).unwrap();
    let bytes = frame(Opcode::Close, true, false, &payload[..n]);
    let got = drain(&mut conn, &bytes);
    assert_eq!(
      got,
      [Ev::CloseRecv(1000, "bye".into()), Ev::Closed(1000, true)]
    );
    assert!(conn.is_terminal());

    // Invalid close code on the wire.
    let mut conn = server();
    let bytes = frame(Opcode::Close, true, false, &[0x03, 0xED]); // 1005
    assert_eq!(drain(&mut conn, &bytes), [Ev::Closed(1002, false)]);

    // One-byte close body.
    let mut conn = server();
    let bytes = frame(Opcode::Close, true, false, &[0x03]);
    assert_eq!(drain(&mut conn, &bytes), [Ev::Closed(1002, false)]);

    // Empty close body: NoStatusReceived, clean.
    let mut conn = server();
    let bytes = frame(Opcode::Close, true, false, b"");
    assert_eq!(
      drain(&mut conn, &bytes),
      [Ev::CloseRecv(1005, "".into()), Ev::Closed(1005, true)]
    );
  }

  /// Regression: a protocol failure arriving AFTER `close()` but
  /// BEFORE the queued close drains must put the FAILURE code on the wire —
  /// only a close that actually went out suppresses the failure close.
  #[test]
  fn failure_supersedes_a_queued_but_unsent_close() {
    let mut conn = server();
    conn.close(crate::frame::CloseCode::Normal, "bye").unwrap();
    // No poll_transmit drain: the Normal close is queued, not sent.

    // A malformed inbound frame (unmasked client frame) fails the connection.
    let header = FrameHeader::new(Opcode::Text, 2);
    let mut bytes = vec![0u8; 8];
    let n = header.encode(&mut bytes).unwrap();
    bytes.truncate(n);
    bytes.extend(b"hi");
    let got = drain(&mut conn, &bytes);
    assert_eq!(got, [Ev::Closed(1002, false)]);

    // The wire close must carry 1002, not the stale queued 1000.
    let mut out = [0u8; 32];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("failure close pending");
    assert_eq!(out[0], 0x88);
    assert_eq!(
      &out[2..4],
      &[0x03, 0xEA],
      "the failure code 1002 must reach the wire"
    );
    let _ = n;
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none()
    );
  }

  /// Companion to the supersede rule: once the close has actually DRAINED,
  /// a later failure must NOT emit a second close frame.
  #[test]
  fn failure_after_a_sent_close_emits_no_second_close() {
    let mut conn = server();
    conn.close(crate::frame::CloseCode::Normal, "").unwrap();
    let mut out = [0u8; 32];
    conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("close drains");

    let header = FrameHeader::new(Opcode::Text, 1);
    let mut bytes = vec![0u8; 8];
    let n = header.encode(&mut bytes).unwrap();
    bytes.truncate(n);
    bytes.extend(b"x");
    let got = drain(&mut conn, &bytes);
    assert_eq!(got, [Ev::Closed(1002, false)]);
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none(),
      "nothing may follow a sent close"
    );
  }

  /// Regression: dropping the cursor after the FIRST event of a
  /// complete frame must not desynchronize the machine — `Drop` drains the
  /// unread tail for its protocol effects, so a ping later in the same read
  /// is still answered and the next `handle` call starts at a frame
  /// boundary instead of waiting for payload bytes the transport will never
  /// resend.
  #[test]
  fn dropping_events_mid_read_keeps_the_machine_in_sync() {
    let mut conn = server();

    // One read containing a complete masked text frame AND a masked ping.
    let mut bytes = frame(Opcode::Text, true, false, b"hello");
    bytes.extend(frame(Opcode::Ping, true, false, b"pp"));

    {
      let mut events = conn.handle(TestInstant(0), &mut bytes).unwrap();
      let first = events.next().expect("first event");
      assert!(matches!(first, Event::MessageStart { .. }));
      // Drop with the text payload, MessageEnd, AND the ping unread.
    }

    // The dropped tail was still processed: the ping got its echo queued.
    let mut out = [0u8; 32];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("pong queued by the drained tail");
    assert_eq!(out[0], 0x8A, "pong opcode");
    assert_eq!(&out[2..n], b"pp");

    // And the machine is at a frame boundary: a fresh read parses cleanly.
    let bytes = frame(Opcode::Text, true, false, b"again");
    let got = drain(&mut conn, &bytes);
    assert!(
      matches!(got.first(), Some(Ev::Start(..))),
      "next read must start a fresh message, got {got:?}"
    );
  }

  /// C2: failing the connection leaves no pong, and no count describing one.
  ///
  /// **This test pins the behaviour, not the new line.** `fail` clears the queue
  /// — §7.1.7 (line 2399 of `.rfc-cache/rfc6455.txt`) has an endpoint told to
  /// _Fail the WebSocket Connection_ stop processing — and the count reaching 0
  /// is currently guaranteed twice over: `force_close` recomputes it through
  /// `queue_close(code, "", 0)` on the `!close_sent` path, and on the
  /// `close_sent` path no reachable sequence leaves it positive. Reverting the
  /// explicit zeroing in `fail` therefore does NOT red this test — measured, not
  /// assumed — so what it holds is the observable rule: a failed connection
  /// drains its failure close first and owes nothing.
  #[test]
  fn failing_the_connection_clears_the_pre_close_count_with_the_pongs() {
    let mut conn = server();

    // One pong owed, then our own close: the prefix freezes at 1.
    let mut ping = crate::connection::tests::masked_frame(Opcode::Ping, true, b"A");
    {
      let mut ev = conn.handle(TestInstant(0), &mut ping).unwrap();
      while ev.next().is_some() {}
    }
    conn.close(CloseCode::GoingAway, "").unwrap();
    assert_eq!(
      conn.send.pongs_before_close, 1,
      "the prefix froze at the slot"
    );

    // A reserved opcode fails the connection (§5.2), reaching `fail`.
    let mut bad = frame(Opcode::Reserved(0xB), true, false, b"");
    {
      let mut ev = conn.handle(TestInstant(0), &mut bad).unwrap();
      while ev.next().is_some() {}
    }
    assert!(conn.is_terminal());
    assert_eq!(
      conn.send.pongs_before_close, 0,
      "a failed connection owes no pre-close pongs — held today by both \
       `force_close`'s recompute and `fail`'s explicit zeroing"
    );

    // And the failure close drains first, with no pong ahead of it.
    let mut out = [0u8; 32];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("the failure close");
    assert_eq!(out[0], 0x88, "poll 1 is the close, not a pong");
    let _ = n;
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none(),
      "and nothing behind it"
    );
  }

  /// F4: the public half of the post-Close-Ping rule — one batch carrying
  /// `[Close, Ping]`.
  ///
  /// `Events::next` returns `None` once the connection is terminal, so the
  /// trailing Ping is never decoded: it is not surfaced as an event and it owes
  /// no Pong. RFC 6455 §5.5.2 (line 2042 of `.rfc-cache/rfc6455.txt`) is the
  /// reason it owes nothing — "unless it already received a Close frame" — and
  /// the short-circuit is the mechanism. The helper test above proves the
  /// second-line guard; only this one protects the public behaviour, which a
  /// refactor could change without touching that helper.
  #[test]
  fn a_ping_behind_a_close_in_one_batch_is_neither_surfaced_nor_answered() {
    let mut conn = server();

    let mut payload = [0u8; 8];
    let pn = encode_close_payload(CloseCode::Normal, "", &mut payload).unwrap();
    let mut bytes = crate::connection::tests::masked_frame(Opcode::Close, true, &payload[..pn]);
    bytes.extend(crate::connection::tests::masked_frame(
      Opcode::Ping,
      true,
      b"late",
    ));

    {
      let mut ev = conn.handle(TestInstant(0), &mut bytes).unwrap();
      assert!(matches!(ev.next(), Some(Event::CloseReceived(_))));
      assert!(matches!(ev.next(), Some(Event::Closed(_))));
      assert!(
        ev.next().is_none(),
        "the Ping behind the Close is never decoded: §5.5.2 line 2042 exempts a \
         Ping that arrives after a Close was received, and `Events::next`'s \
         terminal short-circuit is what stops it being surfaced"
      );
    }
    assert!(conn.is_terminal());

    let mut out = [0u8; 64];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("the close echo");
    assert_eq!(
      &out[..n],
      &[0x88, 0x02, 0x03, 0xE8],
      "the echo, whole: FIN Close, len 2, code 1000"
    );
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none(),
      "no Pong was queued for a Ping that arrived after the Close"
    );
    assert!(conn.send.pending_pong.is_none());
  }

  /// F2: shedding an entry that lies inside the frozen pre-close prefix must
  /// shrink the prefix with it.
  ///
  /// At capacity the overflow queue evicts its front to make room. That entry
  /// is drain position 1 and — with a full queue — inside the prefix, so if the
  /// count does not shrink, the post-close pong pushed in its place inherits its
  /// place AHEAD of the close. RFC 6455 §5.5.3 (line 2064 of
  /// `.rfc-cache/rfc6455.txt`) permits dropping the older echo; it does not
  /// permit the replacement to overtake the close.
  ///
  /// The prefix here is `1 + MAX_PENDING_PONGS` — the slot plus the queue — so
  /// the close lands on poll `1 + MAX_PENDING_PONGS`, one earlier than the
  /// number of pongs queued, because A2 was shed.
  #[test]
  fn a_shed_pre_close_pong_shrinks_the_frozen_prefix() {
    use crate::frame::Decoded;
    let mut conn = server();
    let prefix = 1 + MAX_PENDING_PONGS;

    for i in 1..=prefix {
      let payload = format!("A{i}");
      let mut f = crate::connection::tests::masked_frame(Opcode::Ping, true, payload.as_bytes());
      let mut ev = conn.handle(TestInstant(0), &mut f).unwrap();
      while ev.next().is_some() {}
    }
    conn.close(CloseCode::GoingAway, "").unwrap();

    // The queue is full, so this evicts A2 — drain position 1.
    let mut b = crate::connection::tests::masked_frame(Opcode::Ping, true, b"B");
    {
      let mut ev = conn.handle(TestInstant(0), &mut b).unwrap();
      while ev.next().is_some() {}
    }

    let mut out = [0u8; 64];
    let mut got: Vec<(u8, Vec<u8>)> = Vec::new();
    while let Some(n) = conn.poll_transmit(TestInstant(0), &mut out).unwrap() {
      let decoded = match FrameHeader::decode(&out[..n]).unwrap() {
        Decoded::Complete(d) => d,
        _ => panic!("incomplete frame"),
      };
      got.push((out[0], out[decoded.consumed()..n].to_vec()));
    }

    let mut expect: Vec<(u8, Vec<u8>)> = Vec::new();
    expect.push((0x8A, b"A1".to_vec()));
    for i in 3..=prefix {
      expect.push((0x8A, format!("A{i}").into_bytes()));
    }
    expect.push((0x88, vec![0x03, 0xE9]));
    expect.push((0x8A, b"B".to_vec()));
    assert_eq!(
      got,
      expect,
      "A2 was shed from inside the frozen prefix, so the prefix must shrink to \
       {} and the close must land on poll {} — B is a POST-close pong and may \
       not inherit A2's place ahead of it",
      prefix - 1,
      prefix
    );
  }

  /// The pair of `Events::next`'s terminal short-circuit, driven past it.
  ///
  /// `queue_pong`'s own terminal refusal is unreachable through `handle`,
  /// because the cursor stops consuming once a Close is parsed — so nothing
  /// that goes through the public API can show the guard working, and deleting
  /// it would red no test. This reaches the state a refactor of `next` could
  /// reach — terminal, with a Ping still to decode — and shows the refusal.
  ///
  /// Its PARTNER is
  /// `a_ping_behind_a_close_in_one_batch_is_neither_surfaced_nor_answered`,
  /// which asserts the same outcome through the public API only. This one
  /// proves the helper's guard; that one protects `Events::next`'s behaviour,
  /// which a refactor could change while this test kept passing.
  #[test]
  fn a_post_close_ping_owes_no_pong_even_past_the_cursor_short_circuit() {
    use crate::connection::Lifecycle;
    let mut conn = server();
    let mut ping = crate::connection::tests::masked_frame(Opcode::Ping, true, b"late");
    let mut events = conn.handle(TestInstant(0), &mut ping).unwrap();

    // The state `next` refuses to walk into: a Close has been received, and a
    // Ping is still in the buffer. Set directly, because the short-circuit is
    // exactly what stops the public API from producing it.
    events.conn.lifecycle = Lifecycle::Terminal;
    events.queue_pong([b'x'; MAX_CONTROL_PAYLOAD], 4);

    assert!(
      events.conn.send.pending_pong.is_none(),
      "a Ping received after a Close owes nothing (§5.5.2, line 2043)"
    );
    assert_eq!(events.conn.recv.pong_overflow.len(), 0);
  }

  /// Regression: a consumer that handles `CloseReceived` and DROPS
  /// the cursor without asking for the trailing `Closed` event must still
  /// observe a terminal connection — the clean-close transition lives on the
  /// connection, not the cursor.
  #[test]
  fn dropping_events_after_close_received_is_still_terminal() {
    let mut conn = server();
    let mut payload = [0u8; 16];
    let n = encode_close_payload(CloseCode::Normal, "bye", &mut payload).unwrap();
    let mut bytes = frame(Opcode::Close, true, false, &payload[..n]);

    {
      let mut events = conn.handle(TestInstant(0), &mut bytes).unwrap();
      assert!(matches!(events.next(), Some(Event::CloseReceived(_))));
      // Drop WITHOUT consuming the pending `Closed`.
    }
    assert!(
      conn.is_terminal(),
      "early cursor drop must not strand the lifecycle"
    );
    assert_eq!(conn.poll_timeout(), None);

    // The close echo still drains, exactly once.
    let mut out = [0u8; 32];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("close echo pending");
    assert_eq!(out[0], 0x88, "echo is a close frame");
    let _ = n;
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none()
    );

    // Feeding a terminal connection is a caller error.
    let mut more = [0u8; 1];
    assert!(matches!(
      conn.handle(TestInstant(0), &mut more).unwrap_err(),
      HandleError::Terminal
    ));
  }

  #[test]
  fn observation_yields_boundaries_without_payload_and_still_answers_control() {
    // The whole contract of `observe` in one feed: the message's boundaries
    // are surfaced and its payload is not, while control frames are processed
    // exactly as `handle` processes them — the Ping's echo is queued and the
    // peer's Close terminates.
    let mut conn = server();
    let mut bytes = frame(Opcode::Text, false, false, b"Hel");
    bytes.extend(frame(Opcode::Ping, true, false, b"k"));
    bytes.extend(frame(Opcode::Continuation, true, false, b"lo"));
    let got = fold(drain_observed(&mut conn, &bytes));
    assert_eq!(
      got,
      [
        Ev::SkippedStart(MessageKind::Text, false),
        Ev::Ping(b"k".to_vec()),
        Ev::End
      ],
      "no chunk between Start and End, and the start says so"
    );

    // The Pong is queued, not skipped along with the payload.
    let mut out = [0u8; 64];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("the ping's echo is owed");
    assert_eq!(&out[..n], &[0x8A, 0x01, b'k'], "an unmasked pong for `k`");

    let mut payload = [0u8; MAX_CONTROL_PAYLOAD];
    let n = encode_close_payload(CloseCode::Normal, "", &mut payload).unwrap();
    let close = frame(Opcode::Close, true, false, &payload[..n]);
    let got = drain_observed(&mut conn, &close);
    assert_eq!(
      got,
      [Ev::CloseRecv(1000, String::new()), Ev::Closed(1000, true)],
      "the close handshake completes under observation"
    );
    assert!(conn.is_terminal());
  }

  #[test]
  fn observation_leaves_the_input_buffer_unmasked() {
    // Not unmasking is the point rather than an accident: an observer does no
    // work on the payload, and the caller's buffer therefore comes back as
    // the wire had it.
    let mut conn = server();
    let bytes = frame(Opcode::Binary, true, false, b"payload");
    let mut data = bytes.clone();
    drop(conn.observe(TestInstant(0), &mut data).unwrap());
    assert_eq!(data, bytes, "the observed payload was not written to");
  }

  #[test]
  fn a_framing_violation_still_fails_the_connection_under_observation() {
    // Every header-level rule is unchanged: an unmasked client frame is a
    // 1002 whether the cursor is observing or receiving.
    let mut conn = server();
    let unmasked = [0x82u8, 0x01, 0x00];
    let got = drain_observed(&mut conn, &unmasked);
    assert_eq!(got, [Ev::Closed(1002, false)]);
    assert!(conn.is_terminal());
  }

  #[test]
  fn a_message_half_observed_is_skipped_to_its_end_by_handle() {
    // The mode is per CALL; which message is being skipped is state the
    // connection keeps. Feeding the tail of an observed message through
    // `handle` must not decode it from the middle — for text that would run
    // the UTF-8 validator over a tail whose head it never saw, splitting a
    // multi-byte character and failing a CONFORMING peer with 1007.
    let mut conn = server();
    // "€" is E2 82 AC; the split lands inside it.
    let head = frame(Opcode::Text, false, false, &[0xE2]);
    let tail = frame(Opcode::Continuation, true, false, &[0x82, 0xAC]);

    let got = drain_observed(&mut conn, &head);
    assert_eq!(got, [Ev::SkippedStart(MessageKind::Text, false)]);
    let got = drain(&mut conn, &tail);
    assert_eq!(got, [Ev::End], "the tail is skipped, not validated");
    assert!(!conn.is_terminal(), "and the peer is not blamed for it");

    // The NEXT message assembles normally: skipping ends at the boundary.
    let got = fold(drain(&mut conn, &frame(Opcode::Text, true, false, b"ok")));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Text, false),
        Ev::Text("ok".into()),
        Ev::End
      ]
    );
  }

  #[test]
  fn a_message_in_flight_is_abandoned_once_when_observation_takes_over() {
    // The event the caller used to owe as an action. It fires at the FIRST run
    // skipped of a message whose `MessageStart` was already emitted saying
    // otherwise, once, and its `MessageEnd` still arrives at the boundary.
    let mut conn = server();
    let got = drain(&mut conn, &frame(Opcode::Binary, false, false, b"head"));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Binary, false),
        Ev::Bin(b"head".to_vec())
      ],
      "the message begins under `handle` and its start says nothing about skipping"
    );

    let got = drain_observed(
      &mut conn,
      &frame(Opcode::Continuation, false, false, b"one"),
    );
    assert_eq!(got, [Ev::Abandoned], "the notice, and no chunk");
    let got = drain_observed(
      &mut conn,
      &frame(Opcode::Continuation, false, false, b"two"),
    );
    assert_eq!(
      got,
      [],
      "exactly once: the second observed run says nothing"
    );

    // The boundary still arrives, and through `handle` — which is where the
    // truncation happened: a folder that had not been told would seal here.
    let got = drain(&mut conn, &frame(Opcode::Continuation, true, false, b"end"));
    assert_eq!(
      got,
      [Ev::End],
      "the boundary, with no chunk and no second notice"
    );
    assert!(!conn.is_terminal());

    // And the next message is unaffected.
    let got = fold(drain(
      &mut conn,
      &frame(Opcode::Text, true, false, b"after"),
    ));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Text, false),
        Ev::Text("after".into()),
        Ev::End
      ]
    );
  }

  #[test]
  fn a_message_observed_from_its_start_is_never_abandoned() {
    // The other half of "exactly once": a message whose start already said
    // `skipped` gets no notice, because its start carried the same fact and
    // nothing was ever accumulated for it to drop.
    let mut conn = server();
    let mut bytes = frame(Opcode::Binary, false, false, b"one");
    bytes.extend(frame(Opcode::Continuation, false, false, b"two"));
    bytes.extend(frame(Opcode::Continuation, true, false, b"three"));
    let got = drain_observed(&mut conn, &bytes);
    assert_eq!(
      got,
      [Ev::SkippedStart(MessageKind::Binary, false), Ev::End],
      "a skipped start and its boundary, and no abandon notice between them"
    );
  }

  #[test]
  fn observed_payload_is_not_counted_against_the_message_cap() {
    // No size accounting on bytes this endpoint never looked at: a cap on
    // them would bound nothing, and tripping 1009 on a discarded message
    // would blame the peer for our own decision to stop reading.
    let config = ConnectionConfig::new().with_max_message_size(8);
    let mut conn = Connection::new(&Negotiated::none(), config, Server::new(), TestInstant(0));
    let bytes = frame(Opcode::Binary, true, false, &[0xAB; 4096]);
    let got = drain_observed(&mut conn, &bytes);
    assert_eq!(got, [Ev::SkippedStart(MessageKind::Binary, false), Ev::End]);
    assert!(!conn.is_terminal(), "4 KiB observed under an 8-byte cap");
  }

  #[cfg(feature = "deflate")]
  mod deflate {
    use super::*;
    use crate::{connection::role::Server, negotiation::DeflateParams};
    use miniz_oxide::deflate::core::{
      CompressorOxide, TDEFLFlush, compress, create_comp_flags_from_zip_params,
    };

    /// A permessage-deflate reference COMPRESSOR mirroring real WebSocket peers
    /// (tungstenite, browsers): each message is emitted with a DEFLATE
    /// **sync flush** (`Z_SYNC_FLUSH`), which ends every message with the
    /// `00 00 FF FF` boundary; per RFC 7692 §7.2.1 the sender then strips that
    /// trailing boundary. The receiver re-appends it (§7.2.2) before inflating.
    /// One compressor instance models one peer with context takeover across
    /// messages; `reset` models `no_context_takeover`.
    struct RefCompressor {
      inner: CompressorOxide,
    }

    impl RefCompressor {
      fn new() -> Self {
        // Level 6, raw (window_bits = 0 → no zlib wrapper), default strategy.
        let flags = create_comp_flags_from_zip_params(6, 0, 0);
        Self {
          inner: CompressorOxide::new(flags),
        }
      }

      /// Reset the compressor context (no_context_takeover between messages).
      fn reset(&mut self) {
        self.inner.reset();
      }

      /// Compress one whole message, sync-flush, and strip the trailing
      /// `00 00 FF FF` — the bytes a real peer puts on the wire as the RSV1
      /// payload.
      fn compress(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len() + 512];
        let mut written = 0;
        let mut cursor = data;
        // Feed all input (no flush) until consumed.
        loop {
          if written + 64 > out.len() {
            out.resize(out.len() * 2, 0);
          }
          let (_s, cin, cout) = compress(
            &mut self.inner,
            cursor,
            &mut out[written..],
            TDEFLFlush::None,
          );
          written += cout;
          cursor = &cursor[cin..];
          if cursor.is_empty() {
            break;
          }
        }
        // One sync flush to terminate the message with 00 00 FF FF.
        if written + 512 > out.len() {
          out.resize(written + 512, 0);
        }
        let (_s, _cin, cout) =
          compress(&mut self.inner, &[], &mut out[written..], TDEFLFlush::Sync);
        written += cout;
        out.truncate(written);
        // Strip the trailing sync-flush boundary (RFC 7692 §7.2.1).
        if out.ends_with(&[0x00, 0x00, 0xFF, 0xFF]) {
          let n = out.len() - 4;
          out.truncate(n);
        }
        out
      }
    }

    /// A server connection that negotiated permessage-deflate with `params`.
    fn deflate_server(params: DeflateParams) -> Connection<TestInstant, Server> {
      let negotiated = Negotiated::none().with_deflate(Some(params));
      Connection::new(
        &negotiated,
        ConnectionConfig::default(),
        Server::new(),
        TestInstant(0),
      )
    }

    /// A server connection with a custom config and negotiated deflate.
    fn deflate_server_cfg(
      params: DeflateParams,
      config: ConnectionConfig,
    ) -> Connection<TestInstant, Server> {
      let negotiated = Negotiated::none().with_deflate(Some(params));
      Connection::new(&negotiated, config, Server::new(), TestInstant(0))
    }

    /// The params a default offer/accept lands on (context takeover both ways,
    /// 15-bit windows) — exactly `DeflateParams::default`.
    fn default_params() -> DeflateParams {
      DeflateParams::default()
    }

    /// REWRITE of the cycle-1 4a `rsv1_passthrough_when_deflate_negotiated`
    /// test: RSV1 payloads are now INFLATED (RFC 7692 §7.2.2), not passed
    /// through as raw DEFLATE bytes. A compressed text frame decodes to the
    /// original text.
    #[test]
    fn rsv1_inflates_when_deflate_negotiated() {
      let mut peer = RefCompressor::new();
      let payload = peer.compress(b"Hello");
      let mut conn = deflate_server(default_params());
      let bytes = frame(Opcode::Text, true, true, &payload);
      let got = fold(drain(&mut conn, &bytes));
      assert_eq!(
        got,
        [
          Ev::Start(MessageKind::Text, true),
          Ev::Text("Hello".into()),
          Ev::End
        ]
      );

      // RSV1 on a continuation still fails (RSV1 is a per-message, first-frame
      // flag — §7.2.3.1).
      let mut conn = deflate_server(default_params());
      let mut bytes = frame(Opcode::Text, false, true, b"x");
      bytes.extend(frame(Opcode::Continuation, true, true, b"y"));
      let got = drain(&mut conn, &bytes);
      assert_eq!(got.last(), Some(&Ev::Closed(1002, false)));
    }

    #[test]
    fn binary_message_round_trips_through_reference_compressor() {
      let data: Vec<u8> = (0u8..200).collect();
      let mut peer = RefCompressor::new();
      let payload = peer.compress(&data);
      let mut conn = deflate_server(default_params());
      let got = fold(drain(
        &mut conn,
        &frame(Opcode::Binary, true, true, &payload),
      ));
      assert_eq!(
        got,
        [Ev::Start(MessageKind::Binary, true), Ev::Bin(data), Ev::End]
      );
    }

    #[test]
    fn context_takeover_across_two_messages() {
      // One compressor (context takeover): the second message's stream
      // back-references the first's window. The decoder must keep its window
      // across messages to decode the second.
      let mut peer = RefCompressor::new();
      let m1 = b"the quick brown fox";
      let m2 = b"the quick brown fox jumps over"; // shares a long prefix
      let p1 = peer.compress(m1);
      let p2 = peer.compress(m2);

      let mut conn = deflate_server(default_params());
      let got1 = fold(drain(&mut conn, &frame(Opcode::Text, true, true, &p1)));
      assert_eq!(
        got1,
        [
          Ev::Start(MessageKind::Text, true),
          Ev::Text(String::from_utf8(m1.to_vec()).unwrap()),
          Ev::End
        ]
      );
      let got2 = fold(drain(&mut conn, &frame(Opcode::Text, true, true, &p2)));
      assert_eq!(
        got2,
        [
          Ev::Start(MessageKind::Text, true),
          Ev::Text(String::from_utf8(m2.to_vec()).unwrap()),
          Ev::End
        ]
      );
    }

    #[test]
    fn final_block_messages_decode_and_recover_across_messages() {
      // Regression: a peer may end a message with a FINAL
      // DEFLATE block instead of a sync flush. The message decodes — and
      // the ENDED inflater must not poison the next message under context
      // takeover: a final block terminated the stream, so the next message
      // starts a fresh one.
      let mut conn = deflate_server(default_params());
      let p1 = miniz_oxide::deflate::compress_to_vec(b"first", 6);
      let got1 = fold(drain(&mut conn, &frame(Opcode::Text, true, true, &p1)));
      assert_eq!(
        got1,
        [
          Ev::Start(MessageKind::Text, true),
          Ev::Text("first".into()),
          Ev::End
        ]
      );
      let p2 = miniz_oxide::deflate::compress_to_vec(b"second", 6);
      let got2 = fold(drain(&mut conn, &frame(Opcode::Text, true, true, &p2)));
      assert_eq!(
        got2,
        [
          Ev::Start(MessageKind::Text, true),
          Ev::Text("second".into()),
          Ev::End
        ]
      );
    }

    #[test]
    fn trailing_bytes_after_stream_end_fail_the_connection() {
      // Regression: bytes AFTER the final block are not part of
      // any DEFLATE stream — RFC 7692 §7.2.2 makes the whole payload part
      // of the message's stream, so they are malformed (1007), never
      // silently dropped.
      let mut conn = deflate_server(default_params());
      let mut payload = miniz_oxide::deflate::compress_to_vec(b"hello", 6);
      payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
      let got = fold(drain(&mut conn, &frame(Opcode::Text, true, true, &payload)));
      assert!(got.contains(&Ev::Closed(1007, false)), "{got:?}");
    }

    #[test]
    fn no_context_takeover_resets_between_messages() {
      use crate::negotiation::{ServerDeflateConfig, accept_deflate_offer};
      // Negotiate client_no_context_takeover: the inbound (client→server)
      // direction resets per message, so the peer compresses each message with
      // a fresh context and the decoder must reset to match.
      let params = match accept_deflate_offer(
        [b"permessage-deflate; client_no_context_takeover".as_slice()],
        &ServerDeflateConfig::new(),
      ) {
        Some((params, _)) => params,
        None => panic!("offer must be accepted"),
      };
      assert!(params.client_no_context_takeover());

      let mut peer = RefCompressor::new();
      let m1 = b"the quick brown fox";
      let m2 = b"the quick brown fox jumps over";
      let p1 = peer.compress(m1);
      peer.reset(); // peer resets its context per message
      let p2 = peer.compress(m2);

      let mut conn = deflate_server(params);
      let got1 = fold(drain(&mut conn, &frame(Opcode::Text, true, true, &p1)));
      assert_eq!(got1[1], Ev::Text(String::from_utf8(m1.to_vec()).unwrap()));
      let got2 = fold(drain(&mut conn, &frame(Opcode::Text, true, true, &p2)));
      assert_eq!(got2[1], Ev::Text(String::from_utf8(m2.to_vec()).unwrap()));
    }

    #[test]
    fn fragmented_compressed_message() {
      // RSV1 only on the FIRST frame; the compressed stream is split across a
      // text-start + continuation. The tail is appended only after the final
      // frame, internally.
      let data = b"aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeee";
      let mut peer = RefCompressor::new();
      let payload = peer.compress(data);
      let mid = payload.len() / 2;

      let mut conn = deflate_server(default_params());
      let mut bytes = frame(Opcode::Text, false, true, &payload[..mid]);
      bytes.extend(frame(Opcode::Continuation, true, false, &payload[mid..]));
      let got = fold(drain(&mut conn, &bytes));
      assert_eq!(
        got,
        [
          Ev::Start(MessageKind::Text, true),
          Ev::Text(String::from_utf8(data.to_vec()).unwrap()),
          Ev::End
        ]
      );
    }

    #[test]
    fn malformed_deflate_fails_1007() {
      // RSV1 set, but the payload is not a valid DEFLATE stream.
      let mut conn = deflate_server(default_params());
      let garbage = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
      let got = drain(&mut conn, &frame(Opcode::Binary, true, true, &garbage));
      assert_eq!(got.last(), Some(&Ev::Closed(1007, false)));
      assert_eq!(got.first(), Some(&Ev::Start(MessageKind::Binary, true)));
    }

    #[test]
    fn inflated_size_cap_fails_1009() {
      // A highly compressible "bomb": a few KiB compressed inflate to far more
      // than a tiny max_message_size, which must trip 1009 on inflated bytes.
      let bomb = vec![0u8; 64 * 1024];
      let mut peer = RefCompressor::new();
      let payload = peer.compress(&bomb);
      assert!(payload.len() < 1024, "bomb should compress small");

      let config = ConnectionConfig::new()
        .with_max_frame_payload(1 << 20)
        .with_max_message_size(1024);
      let mut conn = deflate_server_cfg(default_params(), config);
      let got = drain(&mut conn, &frame(Opcode::Binary, true, true, &payload));
      assert_eq!(got.last(), Some(&Ev::Closed(1009, false)));
    }

    #[test]
    fn split_anywhere_over_a_compressed_stream() {
      // Smoke version of the invariance property for a compressed message:
      // cut the wire at every byte boundary; the folded events must match.
      let mut peer = RefCompressor::new();
      let payload = peer.compress("héllo wörld 𐍈 deflate".as_bytes());
      let whole = frame(Opcode::Text, true, true, &payload);

      let mut reference = deflate_server(default_params());
      let expected = fold(drain(&mut reference, &whole));
      assert_eq!(expected.first(), Some(&Ev::Start(MessageKind::Text, true)));

      for cut in 0..=whole.len() {
        let mut conn = deflate_server(default_params());
        let mut got = drain(&mut conn, &whole[..cut]);
        got.extend(drain(&mut conn, &whole[cut..]));
        assert_eq!(fold(got), expected, "cut at {cut}");
      }
    }

    /// One compressed "bomb" message on the wire: `FRAGMENTS` frames, whose
    /// concatenated payload inflates to `BOMB_BYTES` of a repeated byte.
    /// Compressed by `peer`, so it continues that peer's DEFLATE stream.
    fn compressed_bomb(peer: &mut RefCompressor) -> Vec<u8> {
      let payload = peer.compress(&vec![b'A'; BOMB_BYTES]);
      let per_frame = payload.len().div_ceil(FRAGMENTS);
      let mut wire = Vec::new();
      let mut chunks = payload.chunks(per_frame).peekable();
      let mut first = true;
      while let Some(chunk) = chunks.next() {
        let fin = chunks.peek().is_none();
        let opcode = if first {
          Opcode::Binary
        } else {
          Opcode::Continuation
        };
        wire.extend(frame(opcode, fin, first, chunk));
        first = false;
      }
      wire
    }

    /// Hundreds of frames, each inflating to tens of KiB — the shape a peer
    /// that keeps sending after our Close can produce from one read chunk.
    #[cfg(not(miri))]
    const FRAGMENTS: usize = 256;
    #[cfg(not(miri))]
    const BOMB_BYTES: usize = 8 * 1024 * 1024;

    /// The same SHAPE at 1/512th the bytes, for the interpreter.
    ///
    /// Only one test builds a bomb under miri —
    /// `no_context_takeover_survives_an_observed_message`, whose subject is
    /// semantic (nothing is poisoned, the next message still arrives) and
    /// which those two assertions reach at any size. The one whose subject IS
    /// the magnitude is `#[cfg_attr(miri, ignore = ...)]` instead, because
    /// shrinking it would delete the thing it measures.
    ///
    /// 8 fragments still exercises the fragmented path (a first frame, a
    /// final frame and continuations between), and 16 KiB is four times
    /// `INFLATE_CHUNK` (4 KiB), so a bomb this size would still grow the
    /// output buffer several times over if it were HANDLED. That is what
    /// makes the two assertions — capacity and `inflated_ever` both unmoved —
    /// say something under the interpreter rather than pass vacuously.
    #[cfg(miri)]
    const FRAGMENTS: usize = 8;
    #[cfg(miri)]
    const BOMB_BYTES: usize = 16 * 1024;

    // MEASURED on CI at 1934.5 s inside the interpreter, against
    // `xtask miri-test`'s 3600 s per-test and 4000 s per-crate budgets — this
    // test and the one below it were 3859.8 s of the crate's 3956.6 s and the
    // wrapper killed the run. What it asserts is that observation inflates
    // NOTHING: the output buffer's capacity and `inflated_ever` are unmoved
    // across a bomb. Miri cannot make an allocation bound wrong — it runs the
    // same `Vec` growth the same way, only slower — and the bound is the
    // whole subject, so shrinking the bomb would delete what is being
    // measured rather than make it cheaper to measure.
    #[test]
    #[cfg_attr(
      miri,
      ignore = "an allocation bound over megabytes; miri cannot make it wrong"
    )]
    fn observation_skips_a_compressed_bomb_and_poisons_the_context() {
      // The finding this exists for: with `deflate`, discarding the EVENT is
      // one layer too late — the payload has already been inflated into the
      // decompressor's buffer, and one read of a fragmented bomb costs
      // megabytes of output for a message nobody will ever see.
      let mut peer = RefCompressor::new();
      let mut conn = deflate_server(default_params());

      // Baseline: one complete compressed message through `handle`, which is
      // what an ordinary receive costs.
      let baseline = peer.compress(b"the quick brown fox");
      let got = fold(drain(
        &mut conn,
        &frame(Opcode::Binary, true, true, &baseline),
      ));
      assert_eq!(
        got,
        [
          Ev::Start(MessageKind::Binary, true),
          Ev::Bin(b"the quick brown fox".to_vec()),
          Ev::End
        ]
      );
      let capacity = conn.inflate_buf_capacity();
      let inflated = conn.inflated_ever();
      assert!(capacity > 0, "the baseline created the decompressor");

      // The bomb, observed. Boundaries and nothing else.
      let bomb = compressed_bomb(&mut peer);
      let got = fold(drain_observed(&mut conn, &bomb));
      assert_eq!(
        got,
        [Ev::SkippedStart(MessageKind::Binary, true), Ev::End],
        "no chunk is yielded for {FRAGMENTS} observed frames, and the start says so"
      );
      assert_eq!(
        conn.inflate_buf_capacity(),
        capacity,
        "the inflate buffer did not grow for a message nobody reads"
      );
      assert_eq!(
        conn.inflated_ever(),
        inflated,
        "and not one byte of the {BOMB_BYTES}-byte bomb was inflated"
      );
      assert!(!conn.is_terminal(), "skipping is not a failure");

      // Context takeover was in effect, so the window is now missing that
      // message: every later compressed message is skipped too, silently.
      assert!(conn.inflate_is_poisoned());
      let after = peer.compress(b"the quick brown fox jumps over");
      let got = fold(drain(&mut conn, &frame(Opcode::Binary, true, true, &after)));
      assert_eq!(
        got,
        [Ev::SkippedStart(MessageKind::Binary, true), Ev::End],
        "a compressed message after the poison is skipped, not decoded — and its \
         MessageStart says `skipped`, so a folder discards it instead of sealing an \
         EMPTY message at the MessageEnd"
      );
      assert!(
        !conn.is_terminal(),
        "and it is not an error: the peer did not cause it"
      );
      assert_eq!(conn.inflated_ever(), inflated, "nothing more was inflated");

      // Uncompressed messages are unaffected by the poison.
      let got = fold(drain(
        &mut conn,
        &frame(Opcode::Text, true, false, b"plain"),
      ));
      assert_eq!(
        got,
        [
          Ev::Start(MessageKind::Text, false),
          Ev::Text("plain".into()),
          Ev::End
        ]
      );
    }

    #[test]
    fn no_context_takeover_survives_an_observed_message() {
      // The other half of the ruling: with `no_context_takeover` on the
      // inbound direction each message is its own DEFLATE stream, so skipping
      // one costs the next nothing and there is nothing to poison.
      use crate::negotiation::{ServerDeflateConfig, accept_deflate_offer};
      let params = match accept_deflate_offer(
        [b"permessage-deflate; client_no_context_takeover".as_slice()],
        &ServerDeflateConfig::new(),
      ) {
        Some((params, _)) => params,
        None => panic!("offer must be accepted"),
      };
      assert!(params.client_no_context_takeover());

      let mut peer = RefCompressor::new();
      let mut conn = deflate_server(params);
      let baseline = peer.compress(b"the quick brown fox");
      peer.reset();
      let got = fold(drain(
        &mut conn,
        &frame(Opcode::Binary, true, true, &baseline),
      ));
      assert_eq!(got[1], Ev::Bin(b"the quick brown fox".to_vec()));
      let capacity = conn.inflate_buf_capacity();
      let inflated = conn.inflated_ever();

      let bomb = compressed_bomb(&mut peer);
      peer.reset();
      let got = fold(drain_observed(&mut conn, &bomb));
      assert_eq!(got, [Ev::SkippedStart(MessageKind::Binary, true), Ev::End]);
      assert_eq!(conn.inflate_buf_capacity(), capacity);
      assert_eq!(conn.inflated_ever(), inflated);
      assert!(
        !conn.inflate_is_poisoned(),
        "each message resets the stream, so nothing was lost"
      );

      let after = peer.compress(b"delivered after the skipped one");
      let got = fold(drain(&mut conn, &frame(Opcode::Binary, true, true, &after)));
      assert_eq!(
        got,
        [
          Ev::Start(MessageKind::Binary, true),
          Ev::Bin(b"delivered after the skipped one".to_vec()),
          Ev::End
        ],
        "the message after an observed one is still delivered"
      );
    }

    #[test]
    fn a_compressed_message_half_observed_is_skipped_to_its_end() {
      // The per-message rule under `deflate`: a message the inflater stopped
      // following cannot be resumed from the middle of its stream. `handle`
      // finishes swallowing it, with no chunk and no 1007.
      let mut peer = RefCompressor::new();
      let mut conn = deflate_server(default_params());
      let payload = peer.compress(b"aaaaaaaaaabbbbbbbbbbcccccccccc");
      let mid = payload.len() / 2;

      let got = drain(
        &mut conn,
        &frame(Opcode::Binary, false, true, &payload[..mid]),
      );
      assert!(
        matches!(got.first(), Some(Ev::Start(MessageKind::Binary, true))),
        "{got:?}"
      );
      let observed = drain_observed(&mut conn, &frame(Opcode::Continuation, false, false, &[]));
      assert_eq!(
        observed,
        [Ev::Abandoned],
        "even an empty observed run of a message in flight yields the notice — \
         what it abandons is the message, not the bytes"
      );
      assert!(conn.inflate_is_poisoned());
      let got = drain(
        &mut conn,
        &frame(Opcode::Continuation, true, false, &payload[mid..]),
      );
      assert_eq!(got, [Ev::End], "the rest is skipped, not inflated");
      assert!(!conn.is_terminal());
    }

    #[test]
    fn empty_compressed_message_yields_empty() {
      // An empty payload, compressed, must inflate to nothing: Start then End
      // with no chunk.
      let mut peer = RefCompressor::new();
      let payload = peer.compress(b"");
      let mut conn = deflate_server(default_params());
      let got = fold(drain(
        &mut conn,
        &frame(Opcode::Binary, true, true, &payload),
      ));
      assert_eq!(got, [Ev::Start(MessageKind::Binary, true), Ev::End]);
    }
  }
}
