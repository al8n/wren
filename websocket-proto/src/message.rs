//! Message assembly over [`Connection`] events.
//!
//! Two folders turn the lending-iterator events from [`Connection::handle`]
//! into whole messages:
//!
//! - [`SliceAssembler`] reassembles into a **caller-provided buffer** and
//!   yields a borrowed [`MessageRef`]. It needs no allocator and is available
//!   on every tier, including the bare `no_std` build; the buffer length is the
//!   message-size cap.
//! - [`MessageAssembler`] (heap tiers) reassembles into **owned** [`Message`]
//!   values with cheap-clone payloads.
//!
//! Both are pure convenience layers: the same information is available
//! incrementally through the events themselves. Place a folder above the event
//! loop when your driver prefers whole messages over streaming delivery.
//!
//! [`Connection`]: crate::connection::Connection
//! [`Connection::handle`]: crate::connection::Connection::handle

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
use std::{string::String, vec::Vec};

use crate::connection::{Event, MessageKind};

/// A borrowed assembled WebSocket message, yielded by
/// [`SliceAssembler::push`]. The slices borrow the assembler's caller-provided
/// buffer and are valid until the next `push` call — the same lending shape as
/// [`Events::next`](crate::connection::Events).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageRef<'a> {
  /// A complete text message (valid UTF-8 by construction).
  Text(&'a str),
  /// A complete binary message.
  Binary(&'a [u8]),
}

impl MessageRef<'_> {
  /// The [`MessageKind`] of this message.
  pub const fn kind(&self) -> MessageKind {
    match self {
      Self::Text(_) => MessageKind::Text,
      Self::Binary(_) => MessageKind::Binary,
    }
  }

  /// Byte length of the payload.
  pub const fn len(&self) -> usize {
    match self {
      Self::Text(s) => s.len(),
      Self::Binary(b) => b.len(),
    }
  }

  /// Whether the payload is empty.
  pub const fn is_empty(&self) -> bool {
    self.len() == 0
  }
}

/// Errors from [`SliceAssembler::push`] and [`MessageAssembler::push`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssembleError {
  /// The assembled message exceeded the size cap (the buffer length for
  /// [`SliceAssembler`]; the configured `max_message_size` for
  /// [`MessageAssembler`]).
  #[error("assembled message exceeded the size cap")]
  TooLarge,

  /// A [`Event::MessageStart`] arrived while a message was already in progress
  /// (the protocol machine prevents this; this is a defensive guard).
  #[error("MessageStart received while a message was already assembling")]
  Desequenced,
}

/// Reassembly state shared by both folders: idle, or mid-message of a kind
/// with `len` bytes accumulated so far. `SliceAssembler` keeps the bytes in the
/// caller's buffer; `MessageAssembler` keeps them in an owned `String`/`Vec`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum FoldState {
  Idle,
  InText,
  InBinary,
  /// Inside a message whose payload is not being delivered, waiting for its
  /// final frame. A distinct state rather than `Idle`, because a message half
  /// of which is already gone must not start being assembled part-way through:
  /// assembly resumes at the next boundary, not at the next chunk.
  Discarding,
}

/// Folds connection events into whole messages in a **caller-provided buffer**,
/// yielding a borrowed [`MessageRef`]. Allocator-free and available on every
/// tier.
///
/// Feed events from [`Connection::handle`] into [`push`](SliceAssembler::push)
/// one at a time. When a message is complete, `push` returns
/// `Ok(Some(message))` borrowing the buffer; for all other events it returns
/// `Ok(None)`.
///
/// **Push EVERY event, terminal ones included.** `Ping` and `Pong` are
/// pass-through and a caller handles them itself, but that handling happens IN
/// ADDITION to the push, never instead of it:
/// [`Event::CloseReceived`] and [`Event::Closed`] end the connection, and this
/// folder drops the message it is holding when it sees one. A loop that
/// filters the terminal events out and never pushes them keeps its partial and
/// its non-idle state for as long as it keeps the folder. The shape is: match
/// for your own handling, then push unconditionally.
///
/// The buffer length is the message-size cap: a message whose bytes would
/// exceed it is rejected with [`AssembleError::TooLarge`]. On any error the
/// assembler resets to idle, so the next [`Event::MessageStart`] begins a fresh
/// message (the same post-error contract as [`MessageAssembler`]).
///
/// [`Connection::handle`]: crate::connection::Connection::handle
#[derive(Debug)]
pub struct SliceAssembler<'b> {
  buf: &'b mut [u8],
  len: usize,
  state: FoldState,
}

impl<'b> SliceAssembler<'b> {
  /// Creates an assembler that reassembles into `buf`. The buffer length is
  /// the message-size cap.
  pub fn new(buf: &'b mut [u8]) -> Self {
    Self {
      buf,
      len: 0,
      state: FoldState::Idle,
    }
  }

  /// Appends `bytes` to the buffer at the current offset, or fails (resetting
  /// to idle) if they would overflow the cap.
  fn append(&mut self, bytes: &[u8]) -> Result<(), AssembleError> {
    let new_len = self.len.saturating_add(bytes.len());
    let Some(dst) = self.buf.get_mut(self.len..new_len) else {
      self.state = FoldState::Idle;
      self.len = 0;
      return Err(AssembleError::TooLarge);
    };
    for (d, s) in dst.iter_mut().zip(bytes) {
      *d = *s;
    }
    self.len = new_len;
    Ok(())
  }

  /// Drops the partial in hand and discards to the message's boundary: the
  /// body of the [`Event::MessageAbandoned`] arm in [`push`](Self::push),
  /// named so the two folders read alike.
  fn abandon(&mut self) {
    self.len = 0;
    if !matches!(self.state, FoldState::Idle) {
      self.state = FoldState::Discarding;
    }
  }

  /// Forgets the message in progress: any partial is dropped and the folder
  /// returns to `Idle`.
  ///
  /// **For a fact learned OUTSIDE the event stream.** The terminal arms of
  /// [`push`](Self::push) cover every way the connection's end arrives AS an
  /// event; this covers the ways it does not. A driver learns that a
  /// connection is over from its own timer — a close-handshake budget that
  /// elapsed with no reply, so there is no peer frame to decode and no event
  /// to push — and it learns that nobody will ever read again from its own
  /// API: a `close()` that consumed the handle, or a dropped read half. In
  /// none of those does a byte arrive, so in none of them can an event say so.
  ///
  /// `Idle` and not the discarding state, for the same reason the terminal
  /// arms use `Idle`: there is no boundary left to swallow to. A folder reset
  /// this way assembles the next `MessageStart` normally, which is what makes
  /// it safe to call on a connection that turns out not to be over.
  pub fn reset(&mut self) {
    self.state = FoldState::Idle;
    self.len = 0;
  }

  /// Pushes one event into the assembler.
  ///
  /// Returns:
  /// - `Ok(Some(message))` when a complete message has been assembled; the
  ///   slices borrow this assembler's buffer until the next call.
  /// - `Ok(None)` for all other events (mid-message chunks, control frames),
  ///   and for every event of a message being discarded — one whose
  ///   [`MessageStart::skipped`] said no payload would follow, or one an
  ///   [`Event::MessageAbandoned`] gave up on. A TERMINAL event
  ///   ([`Event::CloseReceived`] or [`Event::Closed`]) drops whatever is in
  ///   progress: nothing will close it, so holding it would retain the
  ///   accumulator for the folder's whole remaining life.
  /// - `Err(AssembleError::TooLarge)` when the assembled size would exceed the
  ///   buffer length.
  /// - `Err(AssembleError::Desequenced)` when a `MessageStart` arrives while
  ///   a message is already in progress (defensive; the protocol machine
  ///   normally prevents this).
  ///
  /// [`MessageStart::skipped`]: crate::connection::MessageStart::skipped
  pub fn push(&mut self, event: &Event<'_>) -> Result<Option<MessageRef<'_>>, AssembleError> {
    match event {
      Event::MessageStart(start) => {
        if !matches!(self.state, FoldState::Idle) {
          self.state = FoldState::Idle;
          self.len = 0;
          return Err(AssembleError::Desequenced);
        }
        // A skipped message has no payload to accumulate; opening a buffer for
        // it would seal an EMPTY message at its `MessageEnd`.
        self.state = if start.skipped() {
          FoldState::Discarding
        } else {
          match start.kind() {
            MessageKind::Text => FoldState::InText,
            MessageKind::Binary => FoldState::InBinary,
          }
        };
        self.len = 0;
        Ok(None)
      }

      Event::TextChunk(chunk) => {
        if !matches!(self.state, FoldState::InText) {
          // Outside a text message — ignore (shouldn't happen via the
          // protocol machine, but be robust).
          return Ok(None);
        }
        self.append(chunk.prefix().as_bytes())?;
        self.append(chunk.body().as_bytes())?;
        Ok(None)
      }

      Event::BinaryChunk(bytes) => {
        if !matches!(self.state, FoldState::InBinary) {
          return Ok(None);
        }
        self.append(bytes)?;
        Ok(None)
      }

      Event::MessageEnd => {
        let finished = core::mem::replace(&mut self.state, FoldState::Idle);
        let len = core::mem::replace(&mut self.len, 0);
        let bytes = self.buf.get(..len).unwrap_or(&[]);
        let msg = match finished {
          // The accumulated text bytes are a concatenation of validated `str`
          // pieces, hence valid UTF-8; `unwrap_or("")` is the lint-wall
          // spelling of that invariant.
          FoldState::InText => MessageRef::Text(core::str::from_utf8(bytes).unwrap_or("")),
          FoldState::InBinary => MessageRef::Binary(bytes),
          // Nothing was accumulated, either because no message was open or
          // because this one was discarded. Both end at `Idle`, which is what
          // lets the next `MessageStart` be assembled normally.
          FoldState::Idle | FoldState::Discarding => return Ok(None),
        };
        Ok(Some(msg))
      }

      // The message in progress will not be delivered: drop what is held for
      // it and swallow the rest, so the `MessageEnd` still to come seals
      // nothing.
      Event::MessageAbandoned => {
        self.abandon();
        Ok(None)
      }

      // Terminal. The connection is over, so no `MessageEnd` will ever close
      // what is in progress and no `MessageAbandoned` was owed — a Close
      // arriving in a control-only feed skips no data run — yet a folder that
      // kept its accumulator would hold it for as long as the caller holds
      // the folder, up to the message cap. Drop it and return to `Idle`.
      //
      // BOTH terminal events, because either can be the last one a folder
      // sees. `Closed` alone is not enough: a consumer that handles
      // `CloseReceived` and stops iterating never receives the `Closed` that
      // follows it — the cursor's `Drop` drains the tail through the state
      // machine but delivers none of it. `CloseReceived` alone is not enough
      // either: a protocol failure yields `Closed` with no `CloseReceived`
      // before it. Handling both is what makes the rule total; handling one
      // twice costs nothing, since the second finds `Idle`.
      Event::CloseReceived(_) | Event::Closed(_) => {
        self.state = FoldState::Idle;
        self.len = 0;
        Ok(None)
      }

      // Control events: pass through as Ok(None).
      Event::Ping(_) | Event::Pong(_) => Ok(None),
    }
  }
}

cfg_heap! {
  /// Owned text payload: [`smol_str::SmolStr`] on the `alloc`/`std` tiers,
  /// `portable_atomic_util::Arc<str>` on `no-atomic`. O(1) clone on every tier.
  pub type TextBuf = crate::backend::TextBufInner;
  /// Owned binary payload: [`bytes::Bytes`] on the `alloc`/`std` tiers,
  /// `portable_atomic_util::Arc<[u8]>` on `no-atomic`. O(1) clone on every tier.
  pub type BinaryBuf = crate::backend::BinaryBufInner;
}

cfg_heap! {
  /// An owned assembled WebSocket message.
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum Message {
    /// A complete text message (valid UTF-8 by construction).
    Text(TextBuf),
    /// A complete binary message.
    Binary(BinaryBuf),
  }
}

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
impl Message {
  /// The [`MessageKind`] of this message.
  pub fn kind(&self) -> MessageKind {
    match self {
      Self::Text(_) => MessageKind::Text,
      Self::Binary(_) => MessageKind::Binary,
    }
  }

  /// Byte length of the payload.
  pub fn len(&self) -> usize {
    match self {
      Self::Text(s) => s.len(),
      Self::Binary(b) => b.len(),
    }
  }

  /// Whether the payload is empty.
  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }
}

cfg_heap! {
  /// Folds connection events into complete owned [`Message`] values.
  ///
  /// Feed events from [`Connection::handle`] into
  /// [`push`](MessageAssembler::push) one at a time. When a message is complete,
  /// `push` returns `Ok(Some(message))`; for all other events it returns
  /// `Ok(None)`.
  ///
  /// **Push EVERY event, terminal ones included.** `Ping` and `Pong` are
  /// pass-through and a caller handles them itself, but that handling happens
  /// IN ADDITION to the push, never instead of it: [`Event::CloseReceived`]
  /// and [`Event::Closed`] end the connection, and this folder drops the
  /// message it is holding when it sees one. A loop that filters the terminal
  /// events out and never pushes them keeps its partial — up to
  /// `max_message_size` — and its non-idle state for as long as it keeps the
  /// folder. The shape is: match for your own handling, then push
  /// unconditionally.
  ///
  /// ```
  /// use websocket_proto::{
  ///   connection::{Connection, ConnectionConfig, Event, role::Server},
  ///   message::MessageAssembler,
  ///   negotiation::Negotiated,
  /// };
  /// # fn demo<I: websocket_proto::time::Instant>(
  /// #   conn: &mut Connection<I, Server>,
  /// #   asm: &mut MessageAssembler,
  /// #   now: I,
  /// #   bytes: &mut [u8],
  /// # ) -> Result<Vec<websocket_proto::message::Message>, Box<dyn std::error::Error>> {
  /// let mut delivered = Vec::new();
  /// let mut events = conn.handle(now, bytes)?;
  /// while let Some(event) = events.next() {
  ///   // Your own handling first — and it does not replace the push.
  ///   match &event {
  ///     Event::Ping(payload) => { let _echo_is_queued_for_you = payload; }
  ///     Event::CloseReceived(close) => { let _code = close.code(); }
  ///     _ => {}
  ///   }
  ///   // Then push, unconditionally, whatever the event was.
  ///   if let Some(message) = asm.push(&event)? {
  ///     delivered.push(message);
  ///   }
  /// }
  /// # Ok(delivered)
  /// # }
  /// ```
  ///
  /// When the connection ends without an event — a close-handshake timeout on
  /// the driver's own clock, or a caller that will never read again — nothing
  /// is pushed and nothing can be. [`reset`](MessageAssembler::reset) is the
  /// action for that.
  ///
  /// On any error the assembler resets to idle, so the next
  /// [`Event::MessageStart`] begins a fresh message (the same post-error
  /// contract as [`SliceAssembler`]).
  ///
  /// A message whose [`MessageStart::skipped`] is set carries no payload —
  /// `push` discards it to its boundary rather than opening an accumulator —
  /// and a message ALREADY in progress when its payload stops being delivered
  /// says so once, as [`Event::MessageAbandoned`], which `push` acts on the
  /// same way. So a caller feeding [`Connection::observe`]'s events needs no
  /// special case and no bookkeeping of its own: `push` every event.
  ///
  /// [`Connection::handle`]: crate::connection::Connection::handle
  /// [`Connection::observe`]: crate::connection::Connection::observe
  /// [`MessageStart::skipped`]: crate::connection::MessageStart::skipped
  #[derive(Debug)]
  pub struct MessageAssembler {
    max_message_size: usize,
    state: AssemblerState,
  }
}

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
#[derive(Debug)]
enum AssemblerState {
  Idle,
  InText(String),
  InBinary(Vec<u8>),
  /// Inside a message whose data is being thrown away, waiting for its final
  /// frame. A distinct state rather than `Idle`, because a message half of
  /// which is already gone must not start being assembled part-way through:
  /// normal assembly resumes at the next boundary, not at the next chunk.
  Discarding,
}

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
impl MessageAssembler {
  /// Creates a new assembler that rejects messages larger than
  /// `max_message_size` bytes.
  pub fn new(max_message_size: usize) -> Self {
    Self {
      max_message_size,
      state: AssemblerState::Idle,
    }
  }

  /// How many payload bytes the in-progress message is holding right now.
  ///
  /// Zero between messages. A caller that has to bound what an inbound stream
  /// nobody is draining can retain needs this number: `max_message_size`
  /// answers how large ONE message may become, not how much is held at this
  /// instant, and a message that is still arriving is held entirely here.
  pub fn buffered(&self) -> usize {
    match &self.state {
      AssemblerState::Idle | AssemblerState::Discarding => 0,
      AssemblerState::InText(text) => text.len(),
      AssemblerState::InBinary(bytes) => bytes.len(),
    }
  }

  /// Drops the partial in hand and discards to the message's boundary: the
  /// body of the [`Event::MessageAbandoned`] arm in [`push`](Self::push),
  /// named so the two folders read alike.
  fn abandon(&mut self) {
    if !matches!(self.state, AssemblerState::Idle) {
      self.state = AssemblerState::Discarding;
    }
  }

  /// Forgets the message in progress: any partial is dropped and the folder
  /// returns to `Idle`.
  ///
  /// **For a fact learned OUTSIDE the event stream.** The terminal arms of
  /// [`push`](Self::push) cover every way the connection's end arrives AS an
  /// event; this covers the ways it does not. A driver learns that a
  /// connection is over from its own timer — a close-handshake budget that
  /// elapsed with no reply, so there is no peer frame to decode and no event
  /// to push — and it learns that nobody will ever read again from its own
  /// API: a `close()` that consumed the handle, or a dropped read half. In
  /// none of those does a byte arrive, so in none of them can an event say so.
  ///
  /// `Idle` and not the discarding state, for the same reason the terminal
  /// arms use `Idle`: there is no boundary left to swallow to. A folder reset
  /// this way assembles the next `MessageStart` normally, which is what makes
  /// it safe to call on a connection that turns out not to be over.
  pub fn reset(&mut self) {
    self.state = AssemblerState::Idle;
  }

  /// Pushes one event into the assembler.
  ///
  /// Returns:
  /// - `Ok(Some(message))` when a complete message has been assembled.
  /// - `Ok(None)` for all other events (mid-message chunks, control frames),
  ///   and for every data event of a message being discarded — one whose
  ///   [`MessageStart::skipped`] said no payload would follow, or one an
  ///   [`Event::MessageAbandoned`] gave up on. Half a message is never
  ///   delivered, so `push` finishes swallowing it and assembles again from
  ///   the next `MessageStart`. A TERMINAL event ([`Event::CloseReceived`] or
  ///   [`Event::Closed`]) drops whatever is in progress: nothing will close it,
  ///   so holding it would retain up to `max_message_size` for the folder's
  ///   whole remaining life.
  /// - `Err(AssembleError::TooLarge)` when the assembled size exceeds
  ///   `max_message_size`.
  /// - `Err(AssembleError::Desequenced)` when a `MessageStart` arrives while
  ///   a message is already in progress (defensive; the protocol machine
  ///   normally prevents this).
  ///
  /// [`MessageStart::skipped`]: crate::connection::MessageStart::skipped
  pub fn push(&mut self, event: &Event<'_>) -> Result<Option<Message>, AssembleError> {
    match event {
      Event::MessageStart(start) => {
        if !matches!(self.state, AssemblerState::Idle) {
          self.state = AssemblerState::Idle;
          return Err(AssembleError::Desequenced);
        }
        // A skipped message has no payload to accumulate; opening one would
        // seal an EMPTY message at its `MessageEnd` where the peer sent bytes.
        self.state = if start.skipped() {
          AssemblerState::Discarding
        } else {
          match start.kind() {
            MessageKind::Text => AssemblerState::InText(String::new()),
            MessageKind::Binary => AssemblerState::InBinary(Vec::new()),
          }
        };
        Ok(None)
      }

      Event::TextChunk(chunk) => {
        let AssemblerState::InText(ref mut buf) = self.state else {
          // Outside a text message — ignore (shouldn't happen via the
          // protocol machine, but be robust).
          return Ok(None);
        };
        let prefix = chunk.prefix();
        let body = chunk.body();
        let new_len = buf
          .len()
          .saturating_add(prefix.len())
          .saturating_add(body.len());
        if new_len > self.max_message_size {
          self.state = AssemblerState::Idle;
          return Err(AssembleError::TooLarge);
        }
        buf.push_str(prefix);
        buf.push_str(body);
        Ok(None)
      }

      Event::BinaryChunk(bytes) => {
        let AssemblerState::InBinary(ref mut buf) = self.state else {
          return Ok(None);
        };
        let new_len = buf.len().saturating_add(bytes.len());
        if new_len > self.max_message_size {
          self.state = AssemblerState::Idle;
          return Err(AssembleError::TooLarge);
        }
        buf.extend_from_slice(bytes);
        Ok(None)
      }

      Event::MessageEnd => {
        let finished = core::mem::replace(&mut self.state, AssemblerState::Idle);
        let msg = match finished {
          // Seal the owned accumulator into the cheap-clone backing: `Bytes`
          // adopts the `Vec` in O(1); `SmolStr` copies once for text past its
          // inline capacity (the no-atomic `Arc<str>` always allocates once).
          AssemblerState::InText(s) => Message::Text(crate::backend::text_from_string(s)),
          AssemblerState::InBinary(b) => Message::Binary(crate::backend::binary_from_vec(b)),
          // Nothing was accumulated, either because no message was open or
          // because this one was discarded. Both end at `Idle`, which is what
          // lets the next `MessageStart` be assembled normally.
          AssemblerState::Idle | AssemblerState::Discarding => return Ok(None),
        };
        Ok(Some(msg))
      }

      // The message in progress will not be delivered: drop what is held for
      // it and swallow the rest, so the `MessageEnd` still to come seals
      // nothing.
      Event::MessageAbandoned => {
        self.abandon();
        Ok(None)
      }

      // Terminal. The connection is over, so no `MessageEnd` will ever close
      // what is in progress and no `MessageAbandoned` was owed — a Close
      // arriving in a control-only feed skips no data run — yet a folder that
      // kept its accumulator would hold it for as long as the caller holds
      // the folder, up to the message cap. Drop it and return to `Idle`.
      //
      // BOTH terminal events, because either can be the last one a folder
      // sees. `Closed` alone is not enough: a consumer that handles
      // `CloseReceived` and stops iterating never receives the `Closed` that
      // follows it — the cursor's `Drop` drains the tail through the state
      // machine but delivers none of it. `CloseReceived` alone is not enough
      // either: a protocol failure yields `Closed` with no `CloseReceived`
      // before it. Handling both is what makes the rule total; handling one
      // twice costs nothing, since the second finds `Idle`.
      Event::CloseReceived(_) | Event::Closed(_) => {
        self.state = AssemblerState::Idle;
        Ok(None)
      }

      // Control events: pass through as Ok(None).
      Event::Ping(_) | Event::Pong(_) => Ok(None),
    }
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::{
    connection::{Connection, ConnectionConfig, Event, role::Server, tests::masked_frame},
    frame::Opcode,
    negotiation::Negotiated,
    time::testing::TestInstant,
  };

  fn server() -> Connection<TestInstant, Server> {
    Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    )
  }

  fn assembler(max: usize) -> MessageAssembler {
    MessageAssembler::new(max)
  }

  /// Build a simple masked text frame (client→server direction).
  fn text_frame(payload: &str, fin: bool) -> Vec<u8> {
    masked_frame(Opcode::Text, fin, payload.as_bytes())
  }

  /// Build a simple masked binary frame.
  fn bin_frame(payload: &[u8], fin: bool) -> Vec<u8> {
    masked_frame(Opcode::Binary, fin, payload)
  }

  /// Build a continuation frame.
  fn cont_frame(payload: &[u8], fin: bool) -> Vec<u8> {
    masked_frame(Opcode::Continuation, fin, payload)
  }

  // ── T4-1: unfragmented text assembly ──────────────────────────────────────

  #[test]
  fn assembles_whole_text_message() {
    let mut conn = server();
    let mut asm = assembler(1024);
    let mut wire = text_frame("hello world", true);
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut result = None;
    while let Some(ev) = events.next() {
      result = asm.push(&ev).unwrap();
    }
    assert_eq!(result, Some(Message::Text("hello world".into())));
  }

  // ── T4-2: unfragmented binary assembly ────────────────────────────────────

  #[test]
  fn assembles_whole_binary_message() {
    let mut conn = server();
    let mut asm = assembler(1024);
    let data = vec![1u8, 2, 3, 4, 5];
    let mut wire = bin_frame(&data, true);
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut result = None;
    while let Some(ev) = events.next() {
      result = asm.push(&ev).unwrap();
    }
    assert_eq!(result, Some(Message::Binary(data.into())));
  }

  // ── T4-3: fragmented text assembly ────────────────────────────────────────

  #[test]
  fn assembles_fragmented_text_message() {
    let mut conn = server();
    let mut asm = assembler(1024);

    let mut wire = text_frame("Hello, ", false);
    wire.extend(cont_frame(b"world", true));

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut results = Vec::new();
    while let Some(ev) = events.next() {
      if let Some(msg) = asm.push(&ev).unwrap() {
        results.push(msg);
      }
    }
    assert_eq!(results, [Message::Text("Hello, world".into())]);
  }

  // ── T4-4: fragmented binary assembly ──────────────────────────────────────

  #[test]
  fn assembles_fragmented_binary_message() {
    let mut conn = server();
    let mut asm = assembler(1024);

    let part1 = vec![10u8, 20, 30];
    let part2 = vec![40u8, 50, 60];
    let mut wire = bin_frame(&part1, false);
    wire.extend(cont_frame(&part2, true));

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut results = Vec::new();
    while let Some(ev) = events.next() {
      if let Some(msg) = asm.push(&ev).unwrap() {
        results.push(msg);
      }
    }
    let mut expected = part1.clone();
    expected.extend_from_slice(&part2);
    assert_eq!(results, [Message::Binary(expected.into())]);
  }

  // ── T4-5: size cap returns TooLarge ───────────────────────────────────────

  #[test]
  fn size_cap_returns_too_large_for_text() {
    let mut conn = server();
    let mut asm = assembler(4); // cap at 4 bytes
    let mut wire = text_frame("12345", true); // 5 bytes > 4
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut got_error = false;
    while let Some(ev) = events.next() {
      match asm.push(&ev) {
        Err(AssembleError::TooLarge) => {
          got_error = true;
          break;
        }
        Ok(_) => {}
        Err(e) => panic!("unexpected error: {e:?}"),
      }
    }
    assert!(got_error, "expected TooLarge error");
  }

  #[test]
  fn size_cap_returns_too_large_for_binary() {
    let mut conn = server();
    let mut asm = assembler(3); // cap at 3 bytes
    let data = vec![1u8, 2, 3, 4]; // 4 bytes > 3
    let mut wire = bin_frame(&data, true);
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut got_error = false;
    while let Some(ev) = events.next() {
      match asm.push(&ev) {
        Err(AssembleError::TooLarge) => {
          got_error = true;
          break;
        }
        Ok(_) => {}
        Err(e) => panic!("unexpected error: {e:?}"),
      }
    }
    assert!(got_error, "expected TooLarge error");
  }

  // ── T4-6: control events return Ok(None) ──────────────────────────────────

  #[test]
  fn control_events_are_ignored() {
    use crate::frame::{FrameHeader, mask as apply_mask};

    let mut conn = server();
    let mut asm = assembler(1024);

    // Build: text start + ping + continuation + text end.
    let key = [0x37, 0xFA, 0x21, 0x3Du8];
    let ping_hdr = FrameHeader::new(Opcode::Ping, 3).with_mask(Some(key));
    let mut ping_frame = vec![0u8; ping_hdr.header_len() + 3];
    let n = ping_hdr.encode(&mut ping_frame).unwrap();
    ping_frame[n..].copy_from_slice(b"xxx");
    apply_mask(&mut ping_frame[n..], key, 0);

    let mut wire = text_frame("foo", false);
    wire.extend_from_slice(&ping_frame);
    wire.extend(cont_frame(b"bar", true));

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut messages = Vec::new();
    let mut pings = 0usize;
    while let Some(ev) = events.next() {
      if let Event::Ping(_) = &ev {
        pings += 1;
      }
      if let Some(msg) = asm.push(&ev).unwrap() {
        messages.push(msg);
      }
    }
    assert_eq!(pings, 1, "expected one ping event");
    assert_eq!(messages, [Message::Text("foobar".into())]);
  }

  // ── T4-7: prefix+body text joins (split-mid-char) ─────────────────────────

  #[test]
  fn prefix_and_body_join_across_split_utf8_char() {
    // Build a real split-mid-char stream: "é" = [0xC3, 0xA9] — split after
    // the first byte so the second frame carries the completing byte.
    use crate::frame::{FrameHeader, mask as apply_mask};

    let e_bytes: &[u8] = "é".as_bytes(); // [0xC3, 0xA9]
    assert_eq!(e_bytes.len(), 2);

    let key = [0x37, 0xFA, 0x21, 0x3Du8];

    // Frame 1: Text, non-final, payload = [0xC3] (first byte of 'é')
    let hdr1 = FrameHeader::new(Opcode::Text, 1)
      .with_fin(false)
      .with_mask(Some(key));
    let mut frame1 = vec![0u8; hdr1.header_len() + 1];
    let n = hdr1.encode(&mut frame1).unwrap();
    frame1[n] = e_bytes[0];
    apply_mask(&mut frame1[n..], key, 0);

    // Frame 2: Continuation, final, payload = [0xA9] (second byte of 'é')
    let hdr2 = FrameHeader::new(Opcode::Continuation, 1)
      .with_fin(true)
      .with_mask(Some(key));
    let mut frame2 = vec![0u8; hdr2.header_len() + 1];
    let n = hdr2.encode(&mut frame2).unwrap();
    frame2[n] = e_bytes[1];
    apply_mask(&mut frame2[n..], key, 0);

    let mut conn = server();
    let mut asm = assembler(1024);
    let mut wire = frame1;
    wire.extend_from_slice(&frame2);

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut messages = Vec::new();
    while let Some(ev) = events.next() {
      if let Some(msg) = asm.push(&ev).unwrap() {
        messages.push(msg);
      }
    }
    assert_eq!(messages, [Message::Text("é".into())]);
  }

  // ── T4-8: Desequenced error ────────────────────────────────────────────────

  #[test]
  fn desequenced_when_start_arrives_mid_message() {
    use crate::connection::MessageStart;

    let mut asm = assembler(1024);
    // Push a MessageStart to begin assembling.
    let start1 = Event::MessageStart(MessageStart::new(MessageKind::Text, false, false));
    asm.push(&start1).unwrap();
    // Push another MessageStart while still in-progress.
    let start2 = Event::MessageStart(MessageStart::new(MessageKind::Binary, false, false));
    assert!(matches!(asm.push(&start2), Err(AssembleError::Desequenced)));
    // Post-error contract: the assembler reset to idle, so a fresh
    // MessageStart begins a clean message.
    let start3 = Event::MessageStart(MessageStart::new(MessageKind::Text, false, false));
    assert_eq!(asm.push(&start3), Ok(None));
  }

  // Post-error contract: after TooLarge the assembler resets to idle, and the
  // next message is assembled cleanly (no stale bytes from the aborted one).
  #[test]
  fn resets_to_idle_after_too_large() {
    let mut conn = server();
    let mut asm = assembler(4);

    let mut wire = text_frame("12345", true); // 5 > 4 ⇒ TooLarge
    let mut saw_too_large = false;
    {
      // Scoped: `Events` carries a `Drop` impl, so a shadowed cursor would
      // hold its `&mut conn` borrow until end of function.
      let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
      while let Some(ev) = events.next() {
        if matches!(asm.push(&ev), Err(AssembleError::TooLarge)) {
          saw_too_large = true;
        }
      }
    }
    assert!(saw_too_large);

    let mut wire = text_frame("ok", true); // 2 ≤ 4 ⇒ fine
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut got = None;
    while let Some(ev) = events.next() {
      got = asm.push(&ev).unwrap();
    }
    assert_eq!(got, Some(Message::Text("ok".into())));
  }

  // ── T4-9: closed event returns Ok(None) ───────────────────────────────────

  #[test]
  fn closed_and_close_received_return_none() {
    use crate::{
      connection::{CloseReceived, Closed, ControlPayload},
      frame::CloseCode,
    };

    let mut asm = assembler(1024);
    let payload = ControlPayload::new([0u8; 125], 0);
    let cr = CloseReceived::new(CloseCode::Normal, payload);
    let closed = Closed::new(CloseCode::Normal, true);
    assert_eq!(asm.push(&Event::CloseReceived(cr)), Ok(None));
    assert_eq!(asm.push(&Event::Closed(closed)), Ok(None));
  }

  // ── T4-10: kind and len accessors ─────────────────────────────────────────

  #[test]
  fn message_kind_and_len_accessors() {
    let t = Message::Text("hello".into());
    assert_eq!(t.kind(), MessageKind::Text);
    assert_eq!(t.len(), 5);
    assert!(!t.is_empty());

    let b = Message::Binary(vec![1, 2, 3].into());
    assert_eq!(b.kind(), MessageKind::Binary);
    assert_eq!(b.len(), 3);

    let empty = Message::Binary(Vec::new().into());
    assert!(empty.is_empty());
  }

  // ── SliceAssembler: the caller-buffer mirror of the above ─────────────────

  #[test]
  fn slice_discards_a_skipped_start_and_drops_an_abandoned_partial() {
    // The bare tier's folder reads the same flag and owes the same action:
    // without either, a skipped message is sealed as an EMPTY `MessageRef` and
    // an abandoned one as a TRUNCATED one.
    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);

    // A message that STARTS skipped: Start and End arrive, nothing is yielded.
    let mut wire = text_frame("one", true);
    let mut delivered = 0usize;
    {
      let mut events = conn.observe(TestInstant(0), &mut wire).unwrap();
      while let Some(ev) = events.next() {
        if asm.push(&ev).unwrap().is_some() {
          delivered += 1;
        }
      }
    }
    assert_eq!(delivered, 0, "a skipped message is not fabricated empty");

    // A message assembled under `handle`, then abandoned mid-way by the
    // notice: its `MessageEnd` must seal nothing.
    let mut head = text_frame("abc", false);
    {
      let mut events = conn.handle(TestInstant(0), &mut head).unwrap();
      while let Some(ev) = events.next() {
        assert!(asm.push(&ev).unwrap().is_none());
      }
    }
    let mut mid = cont_frame(b"def", false);
    let mut notices = 0usize;
    {
      let mut events = conn.observe(TestInstant(0), &mut mid).unwrap();
      while let Some(ev) = events.next() {
        if matches!(ev, Event::MessageAbandoned) {
          notices += 1;
        }
        assert!(asm.push(&ev).unwrap().is_none());
      }
    }
    assert_eq!(notices, 1, "the notice reached the folder");
    let mut tail = cont_frame(b"ghi", true);
    {
      let mut events = conn.handle(TestInstant(0), &mut tail).unwrap();
      while let Some(ev) = events.next() {
        assert!(
          asm.push(&ev).unwrap().is_none(),
          "an abandoned message is never delivered, truncated or otherwise"
        );
      }
    }

    // And the next whole message assembles normally.
    let mut after = text_frame("after", true);
    let mut owned = None;
    {
      let mut events = conn.handle(TestInstant(0), &mut after).unwrap();
      while let Some(ev) = events.next() {
        if let Some(msg) = asm.push(&ev).unwrap() {
          owned = Some(match msg {
            MessageRef::Text(s) => s.to_owned(),
            MessageRef::Binary(_) => panic!("expected text"),
          });
        }
      }
    }
    assert_eq!(owned.as_deref(), Some("after"));
  }

  #[test]
  fn slice_drops_the_partial_on_a_terminal_close() {
    // The bare tier's folder, same rule: nothing will close the message in
    // progress, so it is dropped rather than held in the caller's buffer.
    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);
    let mut head = text_frame("a partial message", false);
    {
      let mut events = conn.handle(TestInstant(0), &mut head).unwrap();
      while let Some(ev) = events.next() {
        assert!(asm.push(&ev).unwrap().is_none());
      }
    }

    let mut payload = [0u8; crate::constants::MAX_CONTROL_PAYLOAD];
    let n = crate::frame::encode_close_payload(crate::frame::CloseCode::Normal, "", &mut payload)
      .unwrap();
    let mut close = masked_frame(Opcode::Close, true, &payload[..n]);
    {
      let mut events = conn.observe(TestInstant(0), &mut close).unwrap();
      while let Some(ev) = events.next() {
        assert!(asm.push(&ev).unwrap().is_none());
      }
    }

    // Nothing is retained: a `MessageEnd` synthesised from a second
    // connection — the only way to ask this folder what it is holding — seals
    // nothing.
    let mut other = server();
    let mut wire = text_frame("x", true);
    let mut events = other.handle(TestInstant(0), &mut wire).unwrap();
    let _start = events.next();
    let mut sealed = None;
    while let Some(ev) = events.next() {
      if matches!(ev, Event::MessageEnd)
        && let Some(msg) = asm.push(&ev).unwrap()
      {
        sealed = Some(match msg {
          MessageRef::Text(t) => t.len(),
          MessageRef::Binary(b) => b.len(),
        });
      }
    }
    assert_eq!(sealed, None, "the terminal event left nothing to seal");
  }

  #[test]
  fn slice_reset_drops_the_partial() {
    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);
    let mut head = text_frame("a partial message", false);
    {
      let mut events = conn.handle(TestInstant(0), &mut head).unwrap();
      while let Some(ev) = events.next() {
        assert!(asm.push(&ev).unwrap().is_none());
      }
    }
    asm.reset();

    // Nothing is retained: the abandoned message's own tail seals nothing,
    // and the next whole message assembles normally.
    let mut tail = cont_frame(b" tail", true);
    {
      let mut events = conn.handle(TestInstant(0), &mut tail).unwrap();
      while let Some(ev) = events.next() {
        assert!(
          asm.push(&ev).unwrap().is_none(),
          "a reset folder has no message to seal"
        );
      }
    }
    let mut after = text_frame("after", true);
    let mut owned = None;
    {
      let mut events = conn.handle(TestInstant(0), &mut after).unwrap();
      while let Some(ev) = events.next() {
        if let Some(msg) = asm.push(&ev).unwrap() {
          owned = Some(match msg {
            MessageRef::Text(t) => t.to_owned(),
            MessageRef::Binary(_) => panic!("expected text"),
          });
        }
      }
    }
    assert_eq!(owned.as_deref(), Some("after"));
  }

  #[test]
  fn slice_assembles_whole_text_message() {
    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);
    let mut wire = text_frame("hello world", true);
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut owned = None;
    while let Some(ev) = events.next() {
      if let Some(msg) = asm.push(&ev).unwrap() {
        // Copy out before the borrow ends so the assertion can outlive `asm`.
        owned = Some(match msg {
          MessageRef::Text(s) => s.to_owned(),
          MessageRef::Binary(_) => panic!("expected text"),
        });
      }
    }
    assert_eq!(owned.as_deref(), Some("hello world"));
  }

  #[test]
  fn slice_assembles_whole_binary_message() {
    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);
    let data = vec![1u8, 2, 3, 4, 5];
    let mut wire = bin_frame(&data, true);
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut owned = None;
    while let Some(ev) = events.next() {
      if let Some(msg) = asm.push(&ev).unwrap() {
        owned = Some(match msg {
          MessageRef::Binary(b) => b.to_vec(),
          MessageRef::Text(_) => panic!("expected binary"),
        });
      }
    }
    assert_eq!(owned, Some(data));
  }

  #[test]
  fn slice_assembles_fragmented_text_message() {
    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);

    let mut wire = text_frame("Hello, ", false);
    wire.extend(cont_frame(b"world", true));

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut results = Vec::new();
    while let Some(ev) = events.next() {
      if let Some(MessageRef::Text(s)) = asm.push(&ev).unwrap() {
        results.push(s.to_owned());
      }
    }
    assert_eq!(results, ["Hello, world"]);
  }

  #[test]
  fn slice_assembles_fragmented_binary_message() {
    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);

    let part1 = vec![10u8, 20, 30];
    let part2 = vec![40u8, 50, 60];
    let mut wire = bin_frame(&part1, false);
    wire.extend(cont_frame(&part2, true));

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut results = Vec::new();
    while let Some(ev) = events.next() {
      if let Some(MessageRef::Binary(b)) = asm.push(&ev).unwrap() {
        results.push(b.to_vec());
      }
    }
    let mut expected = part1.clone();
    expected.extend_from_slice(&part2);
    assert_eq!(results, [expected]);
  }

  #[test]
  fn slice_prefix_and_body_join_across_split_utf8_char() {
    // The split-mid-char path: "é" = [0xC3, 0xA9] split after the first byte,
    // so the completing byte arrives via the next frame's `prefix`.
    use crate::frame::{FrameHeader, mask as apply_mask};

    let e_bytes: &[u8] = "é".as_bytes();
    assert_eq!(e_bytes.len(), 2);
    let key = [0x37, 0xFA, 0x21, 0x3Du8];

    let hdr1 = FrameHeader::new(Opcode::Text, 1)
      .with_fin(false)
      .with_mask(Some(key));
    let mut frame1 = vec![0u8; hdr1.header_len() + 1];
    let n = hdr1.encode(&mut frame1).unwrap();
    frame1[n] = e_bytes[0];
    apply_mask(&mut frame1[n..], key, 0);

    let hdr2 = FrameHeader::new(Opcode::Continuation, 1)
      .with_fin(true)
      .with_mask(Some(key));
    let mut frame2 = vec![0u8; hdr2.header_len() + 1];
    let n = hdr2.encode(&mut frame2).unwrap();
    frame2[n] = e_bytes[1];
    apply_mask(&mut frame2[n..], key, 0);

    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);
    let mut wire = frame1;
    wire.extend_from_slice(&frame2);

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut results = Vec::new();
    while let Some(ev) = events.next() {
      if let Some(MessageRef::Text(s)) = asm.push(&ev).unwrap() {
        results.push(s.to_owned());
      }
    }
    assert_eq!(results, ["é"]);
  }

  #[test]
  fn slice_control_events_are_ignored() {
    use crate::frame::{FrameHeader, mask as apply_mask};

    let mut conn = server();
    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);

    let key = [0x37, 0xFA, 0x21, 0x3Du8];
    let ping_hdr = FrameHeader::new(Opcode::Ping, 3).with_mask(Some(key));
    let mut ping_frame = vec![0u8; ping_hdr.header_len() + 3];
    let n = ping_hdr.encode(&mut ping_frame).unwrap();
    ping_frame[n..].copy_from_slice(b"xxx");
    apply_mask(&mut ping_frame[n..], key, 0);

    let mut wire = text_frame("foo", false);
    wire.extend_from_slice(&ping_frame);
    wire.extend(cont_frame(b"bar", true));

    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut messages = Vec::new();
    let mut pings = 0usize;
    while let Some(ev) = events.next() {
      if let Event::Ping(_) = &ev {
        pings += 1;
      }
      if let Some(MessageRef::Text(s)) = asm.push(&ev).unwrap() {
        messages.push(s.to_owned());
      }
    }
    assert_eq!(pings, 1);
    assert_eq!(messages, ["foobar"]);
  }

  #[test]
  fn slice_desequenced_when_start_arrives_mid_message() {
    use crate::connection::MessageStart;

    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);
    let start1 = Event::MessageStart(MessageStart::new(MessageKind::Text, false, false));
    asm.push(&start1).unwrap();
    let start2 = Event::MessageStart(MessageStart::new(MessageKind::Binary, false, false));
    assert!(matches!(asm.push(&start2), Err(AssembleError::Desequenced)));
    // Reset-to-idle: a fresh start succeeds.
    let start3 = Event::MessageStart(MessageStart::new(MessageKind::Text, false, false));
    assert_eq!(asm.push(&start3), Ok(None));
  }

  #[test]
  fn slice_closed_and_close_received_return_none() {
    use crate::{
      connection::{CloseReceived, Closed, ControlPayload},
      frame::CloseCode,
    };

    let mut buf = [0u8; 1024];
    let mut asm = SliceAssembler::new(&mut buf);
    let payload = ControlPayload::new([0u8; 125], 0);
    let cr = CloseReceived::new(CloseCode::Normal, payload);
    let closed = Closed::new(CloseCode::Normal, true);
    assert_eq!(asm.push(&Event::CloseReceived(cr)), Ok(None));
    assert_eq!(asm.push(&Event::Closed(closed)), Ok(None));
  }

  // Cap = buffer length. An exact-fit message succeeds; one byte over is
  // TooLarge; reuse after the error works (reset-to-idle contract).
  #[test]
  fn slice_cap_exact_fit_succeeds() {
    let mut conn = server();
    let mut buf = [0u8; 5];
    let mut asm = SliceAssembler::new(&mut buf);
    let mut wire = text_frame("12345", true); // exactly 5
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut owned = None;
    while let Some(ev) = events.next() {
      if let Some(MessageRef::Text(s)) = asm.push(&ev).unwrap() {
        owned = Some(s.to_owned());
      }
    }
    assert_eq!(owned.as_deref(), Some("12345"));
  }

  #[test]
  fn slice_cap_one_over_is_too_large_then_reusable() {
    let mut conn = server();
    let mut buf = [0u8; 4];
    let mut asm = SliceAssembler::new(&mut buf);

    let mut wire = text_frame("12345", true); // 5 > 4
    let mut saw_too_large = false;
    {
      // Scoped: `Events` carries a `Drop` impl, so a shadowed cursor would
      // hold its `&mut conn` borrow until end of function.
      let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
      while let Some(ev) = events.next() {
        if matches!(asm.push(&ev), Err(AssembleError::TooLarge)) {
          saw_too_large = true;
        }
      }
    }
    assert!(saw_too_large, "expected TooLarge at the cap");

    // Subsequent reuse after TooLarge: idle again, assembles cleanly.
    let mut wire = text_frame("ok", true);
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut owned = None;
    while let Some(ev) = events.next() {
      if let Some(MessageRef::Text(s)) = asm.push(&ev).unwrap() {
        owned = Some(s.to_owned());
      }
    }
    assert_eq!(owned.as_deref(), Some("ok"));
  }

  #[test]
  fn slice_cap_one_over_is_too_large_binary() {
    let mut conn = server();
    let mut buf = [0u8; 3];
    let mut asm = SliceAssembler::new(&mut buf);
    let data = vec![1u8, 2, 3, 4]; // 4 > 3
    let mut wire = bin_frame(&data, true);
    let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
    let mut saw_too_large = false;
    while let Some(ev) = events.next() {
      if matches!(asm.push(&ev), Err(AssembleError::TooLarge)) {
        saw_too_large = true;
      }
    }
    assert!(saw_too_large);
  }

  #[test]
  fn message_ref_kind_and_len_accessors() {
    let t = MessageRef::Text("hello");
    assert_eq!(t.kind(), MessageKind::Text);
    assert_eq!(t.len(), 5);
    assert!(!t.is_empty());

    let b = MessageRef::Binary(&[1, 2, 3]);
    assert_eq!(b.kind(), MessageKind::Binary);
    assert_eq!(b.len(), 3);

    let empty = MessageRef::Binary(&[]);
    assert!(empty.is_empty());
  }

  // ── skipped starts and `abandon`: the two ways a message is not assembled ──

  /// Feeds one frame's worth of wire bytes through `handle` and pushes every
  /// event it produces, answering whatever the assembler yielded.
  fn feed(
    conn: &mut Connection<TestInstant, Server>,
    asm: &mut MessageAssembler,
    wire: &mut [u8],
  ) -> Option<Message> {
    let mut events = conn.handle(TestInstant(0), wire).unwrap();
    let mut out = None;
    while let Some(ev) = events.next() {
      if let Some(got) = asm.push(&ev).unwrap() {
        out = Some(got);
      }
    }
    out
  }

  /// The same through `observe`, with NOTHING done first — the caller has no
  /// obligation left; the events carry it. Answers how many events the feed
  /// produced, because zero is a case that matters.
  fn feed_observed(
    conn: &mut Connection<TestInstant, Server>,
    asm: &mut MessageAssembler,
    wire: &mut [u8],
  ) -> (Option<Message>, usize) {
    let mut events = conn.observe(TestInstant(0), wire).unwrap();
    let mut out = None;
    let mut seen = 0usize;
    while let Some(ev) = events.next() {
      seen += 1;
      if let Some(got) = asm.push(&ev).unwrap() {
        out = Some(got);
      }
    }
    (out, seen)
  }

  #[test]
  fn an_observed_continuation_abandons_the_partial_and_swallows_the_rest() {
    let mut conn = server();
    let mut asm = assembler(1024);
    assert_eq!(
      feed(&mut conn, &mut asm, &mut text_frame("abc", false)),
      None
    );
    assert_eq!(asm.buffered(), 3, "`push` accumulates what it is given");

    // The observed feed of a message ALREADY in progress: its payload is
    // skipped, and the ONE event it produces is the notice that says so.
    let (got, events) = feed_observed(&mut conn, &mut asm, &mut cont_frame(b"def", false));
    assert_eq!(got, None);
    assert_eq!(events, 1, "exactly one event: the notice, and no chunk");
    assert_eq!(
      asm.buffered(),
      0,
      "which dropped the partial message in hand"
    );

    let (got, _) = feed_observed(&mut conn, &mut asm, &mut cont_frame(b"ghi", true));
    assert_eq!(
      got, None,
      "half a message is never delivered, so its final frame yields nothing"
    );
    assert_eq!(asm.buffered(), 0);
  }

  #[test]
  fn push_after_the_abandon_notice_keeps_discarding_to_the_boundary() {
    // The regression the cross-family review ran: the head is assembled under
    // `handle`, the continuations are observed (zero events), and the
    // `MessageEnd` arrives back under `handle` — where it must seal nothing.
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(&mut conn, &mut asm, &mut text_frame("abc", false));
    feed_observed(&mut conn, &mut asm, &mut cont_frame(b"def", false));

    assert_eq!(
      feed(&mut conn, &mut asm, &mut cont_frame(b"ghi", true)),
      None,
      "the message the notice gave up on stays discarded through `push`"
    );
    assert_eq!(
      feed(&mut conn, &mut asm, &mut text_frame("next", true)),
      Some(Message::Text("next".into())),
      "and the NEXT message assembles whole"
    );
  }

  #[test]
  fn a_terminal_close_drops_the_partial_in_hand() {
    // The retention this closes: a fragmented prefix accumulated under
    // `handle`, then a control-only feed carrying the peer's Close. No data
    // run is skipped, so no `MessageAbandoned`; the connection goes terminal,
    // so no `MessageEnd` ever arrives. Without a terminal arm the accumulator
    // survives for as long as the caller holds the assembler — up to
    // `max_message_size`.
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(
      &mut conn,
      &mut asm,
      &mut text_frame("a partial message", false),
    );
    assert_eq!(asm.buffered(), 17, "held under `handle`");

    let mut payload = [0u8; crate::constants::MAX_CONTROL_PAYLOAD];
    let n = crate::frame::encode_close_payload(crate::frame::CloseCode::Normal, "", &mut payload)
      .unwrap();
    let mut close = masked_frame(Opcode::Close, true, &payload[..n]);
    let mut saw_close_received = false;
    {
      let mut events = conn.observe(TestInstant(0), &mut close).unwrap();
      while let Some(ev) = events.next() {
        if matches!(ev, Event::CloseReceived(_)) {
          saw_close_received = true;
        }
        assert_eq!(asm.push(&ev).unwrap(), None);
      }
    }
    assert!(saw_close_received, "the peer's Close was decoded");
    assert_eq!(
      asm.buffered(),
      0,
      "a terminal event drops the message nothing will ever close"
    );

    // And the state is Idle rather than Discarding: there is no boundary left
    // to swallow to, so a fresh assembler and this one behave alike.
    assert_eq!(assembler(1024).buffered(), asm.buffered());
  }

  #[test]
  fn the_documented_event_loop_holds_nothing_after_the_close() {
    // The loop the type doc shows, written out: match for the caller's own
    // control handling, then push unconditionally. A caller that routed the
    // terminal events "separately" — the instruction that used to be there —
    // would end this test holding 17 bytes.
    let mut conn = server();
    let mut asm = assembler(1024);
    let mut wire = text_frame("a partial message", false);
    let mut payload = [0u8; crate::constants::MAX_CONTROL_PAYLOAD];
    let n = crate::frame::encode_close_payload(crate::frame::CloseCode::Normal, "", &mut payload)
      .unwrap();
    wire.extend(masked_frame(Opcode::Close, true, &payload[..n]));

    let mut delivered = Vec::new();
    let mut pings = 0usize;
    let mut close_code = None;
    {
      let mut events = conn.handle(TestInstant(0), &mut wire).unwrap();
      while let Some(event) = events.next() {
        match &event {
          Event::Ping(_) => pings += 1,
          Event::CloseReceived(close) => close_code = Some(close.code()),
          _ => {}
        }
        if let Some(message) = asm.push(&event).unwrap() {
          delivered.push(message);
        }
      }
    }
    assert_eq!(pings, 0);
    assert_eq!(close_code, Some(crate::frame::CloseCode::Normal));
    assert!(delivered.is_empty(), "the partial was never a message");
    assert_eq!(
      asm.buffered(),
      0,
      "and pushing the terminal events left nothing behind"
    );
  }

  #[test]
  fn reset_drops_the_partial_for_a_fact_no_event_carried() {
    // The action for a connection that ended without a frame to decode: a
    // driver's own close-handshake timeout, or a caller that will never read
    // again. Nothing is pushed on those paths, so nothing can be.
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(
      &mut conn,
      &mut asm,
      &mut text_frame("a partial message", false),
    );
    assert_eq!(asm.buffered(), 17);
    asm.reset();
    assert_eq!(asm.buffered(), 0);

    // To `Idle`, not to discarding: a folder reset for a connection that turns
    // out not to be over assembles the next message normally.
    assert_eq!(
      feed(&mut conn, &mut asm, &mut cont_frame(b" tail", true)),
      None,
      "the abandoned message's own tail is not resumed"
    );
    assert_eq!(
      feed(&mut conn, &mut asm, &mut text_frame("next", true)),
      Some(Message::Text("next".into())),
      "and the next whole message assembles"
    );

    asm.reset();
    assert_eq!(asm.buffered(), 0, "a reset while idle is a no-op");
  }

  #[test]
  fn a_folder_that_stops_at_close_received_still_drops_the_partial() {
    // `Closed` alone would not be enough. A consumer that handles
    // `CloseReceived` and stops iterating never receives the `Closed` that
    // follows — the cursor's `Drop` drains the tail through the state machine
    // and delivers none of it — so the LAST event that folder ever sees is
    // `CloseReceived`.
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(
      &mut conn,
      &mut asm,
      &mut text_frame("a partial message", false),
    );
    assert_eq!(asm.buffered(), 17);

    let mut payload = [0u8; crate::constants::MAX_CONTROL_PAYLOAD];
    let n = crate::frame::encode_close_payload(crate::frame::CloseCode::Normal, "", &mut payload)
      .unwrap();
    let mut close = masked_frame(Opcode::Close, true, &payload[..n]);
    {
      let mut events = conn.handle(TestInstant(0), &mut close).unwrap();
      let first = events.next().expect("CloseReceived");
      assert!(matches!(first, Event::CloseReceived(_)), "{first:?}");
      assert_eq!(asm.push(&first).unwrap(), None);
      // Stop here: the cursor is dropped without the trailing `Closed`.
    }
    assert_eq!(asm.buffered(), 0, "and the partial is gone all the same");
  }

  #[test]
  fn a_protocol_failure_drops_the_partial_with_no_close_received() {
    // The other half: `CloseReceived` alone would not be enough either, since
    // a failed connection yields `Closed` and nothing before it.
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(
      &mut conn,
      &mut asm,
      &mut text_frame("a partial message", false),
    );
    assert_eq!(asm.buffered(), 17);

    // A Text frame inside an open message is a §5.4 sequencing violation.
    let mut bad = text_frame("interleaved", true);
    let mut saw_closed = false;
    let mut saw_close_received = false;
    {
      let mut events = conn.handle(TestInstant(0), &mut bad).unwrap();
      while let Some(ev) = events.next() {
        saw_closed |= matches!(ev, Event::Closed(_));
        saw_close_received |= matches!(ev, Event::CloseReceived(_));
        assert_eq!(asm.push(&ev).unwrap(), None);
      }
    }
    assert!(saw_closed, "the connection failed");
    assert!(!saw_close_received, "with no Close from the peer");
    assert_eq!(asm.buffered(), 0);
  }

  #[test]
  fn the_abandon_notice_arrives_once_and_a_repeat_is_harmless() {
    // The protocol emits it once per message. The assembler is asked what it
    // does with a second one anyway, because "once" is the protocol's
    // guarantee and not the folder's precondition.
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(&mut conn, &mut asm, &mut text_frame("abc", false));
    assert_eq!(asm.buffered(), 3);

    let (_, events) = feed_observed(&mut conn, &mut asm, &mut cont_frame(b"def", false));
    assert_eq!(events, 1, "the notice");
    let (_, events) = feed_observed(&mut conn, &mut asm, &mut cont_frame(b"ghi", false));
    assert_eq!(events, 0, "and never again for the same message");

    assert_eq!(asm.push(&Event::MessageAbandoned).unwrap(), None);
    assert_eq!(asm.buffered(), 0, "a repeat changes nothing");
    assert_eq!(
      feed(&mut conn, &mut asm, &mut cont_frame(b"", true)),
      None,
      "still discarding to the boundary"
    );
    assert_eq!(
      feed(&mut conn, &mut asm, &mut text_frame("after", true)),
      Some(Message::Text("after".into())),
      "and the next message assembles whole"
    );

    // Idle: nothing held, nothing to drop, and the next message is unaffected.
    assert_eq!(asm.push(&Event::MessageAbandoned).unwrap(), None);
    assert_eq!(
      feed(&mut conn, &mut asm, &mut text_frame("whole", true)),
      Some(Message::Text("whole".into())),
      "a notice while idle leaves the next message assembling normally"
    );
  }

  #[test]
  fn a_skipped_start_is_discarded_rather_than_fabricated() {
    // A message that STARTS under observation says so in its own event, so
    // `push` needs no mode: it must not open an accumulator, because the
    // `MessageEnd` that follows would seal an EMPTY message where the peer
    // sent bytes.
    let mut conn = server();
    let mut asm = assembler(1024);
    let (got, events) = feed_observed(&mut conn, &mut asm, &mut text_frame("one", true));
    assert_eq!(
      got, None,
      "a skipped message is dropped, not returned empty"
    );
    assert!(events >= 2, "its Start and End still arrive: {events}");
    assert_eq!(asm.buffered(), 0);

    let (got, _) = feed_observed(&mut conn, &mut asm, &mut bin_frame(&[1, 2, 3], true));
    assert_eq!(got, None);
    assert_eq!(asm.buffered(), 0, "and nothing is retained between them");

    // The flag is on the event, so `push` alone — no `abandon`, no observed
    // feed — is enough to discard it. This is the poisoned-inflater path,
    // where a SKIPPED start arrives through `handle`.
    let mut wire = text_frame("two", true);
    let mut events = conn.observe(TestInstant(0), &mut wire).unwrap();
    let start = events.next().expect("a message start");
    assert!(
      matches!(&start, Event::MessageStart(s) if s.skipped()),
      "an observed start is marked skipped: {start:?}"
    );
    assert_eq!(asm.push(&start).unwrap(), None);
    drop(events);
    assert_eq!(asm.buffered(), 0, "discarding holds nothing");
  }

  #[test]
  fn a_skipped_start_while_discarding_is_still_desequenced() {
    // Discarding is a message in progress like any other: a second start
    // inside it is a caller error, skipped or not.
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(&mut conn, &mut asm, &mut text_frame("abc", false));
    feed_observed(&mut conn, &mut asm, &mut cont_frame(b"def", false));

    let mut other = server();
    let mut wire = text_frame("x", true);
    let mut events = other.observe(TestInstant(0), &mut wire).unwrap();
    let start = events.next().expect("a message start");
    let err = asm
      .push(&start)
      .expect_err("a start inside a message is desequenced, skipped or not");
    assert!(matches!(err, AssembleError::Desequenced), "got {err:?}");
    drop(events);
    assert_eq!(asm.buffered(), 0, "the error resets the assembler to idle");
  }

  #[test]
  fn buffered_counts_the_partial_under_push_and_nothing_under_discard() {
    let mut conn = server();
    let mut asm = assembler(1024);
    assert_eq!(asm.buffered(), 0, "nothing is held between messages");

    feed(&mut conn, &mut asm, &mut text_frame("hello", false));
    assert_eq!(asm.buffered(), 5);
    feed(&mut conn, &mut asm, &mut cont_frame(b" world", false));
    assert_eq!(asm.buffered(), 11, "`push` holds every byte of the partial");

    feed_observed(&mut conn, &mut asm, &mut cont_frame(b"!", false));
    assert_eq!(asm.buffered(), 0, "discarding holds nothing at all");
    feed(&mut conn, &mut asm, &mut cont_frame(b"", true));
    assert_eq!(asm.buffered(), 0, "and the boundary leaves it idle");
  }

  /// A second `MessageStart` before the first message ends cannot come from
  /// this crate's own parser: a Text or Binary frame received while a
  /// fragmented message is open is answered with `CloseCode::ProtocolError`
  /// (`recv.rs`, the `(Text | Binary, InMessage)` arm), and
  /// `EncodeError::FragmentSequence` is that rule's send-side mirror. So the
  /// event is synthesised from a SECOND connection, and what is pinned here is
  /// only what the assembler does when a caller hands it one anyway.
  #[test]
  fn a_message_start_while_discarding_is_desequenced() {
    let mut conn = server();
    let mut asm = assembler(1024);
    feed(&mut conn, &mut asm, &mut text_frame("abc", false));
    feed_observed(&mut conn, &mut asm, &mut cont_frame(b"def", false));

    let mut other = server();
    let mut wire = text_frame("x", true);
    let mut events = other.handle(TestInstant(0), &mut wire).unwrap();
    let start = events.next().expect("a message start");
    let err = asm
      .push(&start)
      .expect_err("a start inside a message is desequenced, discarding or not");
    assert!(matches!(err, AssembleError::Desequenced), "got {err:?}");
    drop(events);

    assert_eq!(asm.buffered(), 0, "the error resets the assembler to idle");
    assert_eq!(
      feed(&mut conn, &mut asm, &mut cont_frame(b"ghi", true)),
      None,
      "the reset is to IDLE, so the abandoned message's tail assembles nothing"
    );
    assert_eq!(
      feed(&mut conn, &mut asm, &mut text_frame("after", true)),
      Some(Message::Text("after".into())),
      "and a whole message after it is assembled normally"
    );
  }
}
