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
}

/// Folds connection events into whole messages in a **caller-provided buffer**,
/// yielding a borrowed [`MessageRef`]. Allocator-free and available on every
/// tier.
///
/// Feed events from [`Connection::handle`] into [`push`](SliceAssembler::push)
/// one at a time. When a message is complete, `push` returns
/// `Ok(Some(message))` borrowing the buffer; for all other events it returns
/// `Ok(None)`. Control events (`Ping`, `Pong`, `CloseReceived`, `Closed`) are
/// passed through as `Ok(None)` — route them separately before calling `push`.
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

  /// Pushes one event into the assembler.
  ///
  /// Returns:
  /// - `Ok(Some(message))` when a complete message has been assembled; the
  ///   slices borrow this assembler's buffer until the next call.
  /// - `Ok(None)` for all other events (mid-message chunks, control frames,
  ///   `Closed`).
  /// - `Err(AssembleError::TooLarge)` when the assembled size would exceed the
  ///   buffer length.
  /// - `Err(AssembleError::Desequenced)` when a `MessageStart` arrives while
  ///   a message is already in progress (defensive; the protocol machine
  ///   normally prevents this).
  pub fn push(&mut self, event: &Event<'_>) -> Result<Option<MessageRef<'_>>, AssembleError> {
    match event {
      Event::MessageStart(start) => {
        if !matches!(self.state, FoldState::Idle) {
          self.state = FoldState::Idle;
          self.len = 0;
          return Err(AssembleError::Desequenced);
        }
        self.state = match start.kind() {
          MessageKind::Text => FoldState::InText,
          MessageKind::Binary => FoldState::InBinary,
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
          FoldState::Idle => return Ok(None),
        };
        Ok(Some(msg))
      }

      // Control events and Closed: pass through as Ok(None).
      Event::Ping(_) | Event::Pong(_) | Event::CloseReceived(_) | Event::Closed(_) => Ok(None),
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
  /// `Ok(None)`. Control events (`Ping`, `Pong`, `CloseReceived`, `Closed`) are
  /// passed through as `Ok(None)` — route them separately before calling `push`.
  ///
  /// On any error the assembler resets to idle, so the next
  /// [`Event::MessageStart`] begins a fresh message (the same post-error
  /// contract as [`SliceAssembler`]).
  ///
  /// [`Connection::handle`]: crate::connection::Connection::handle
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

  /// Pushes one event into the assembler.
  ///
  /// Returns:
  /// - `Ok(Some(message))` when a complete message has been assembled.
  /// - `Ok(None)` for all other events (mid-message chunks, control frames,
  ///   `Closed`).
  /// - `Err(AssembleError::TooLarge)` when the assembled size exceeds
  ///   `max_message_size`.
  /// - `Err(AssembleError::Desequenced)` when a `MessageStart` arrives while
  ///   a message is already in progress (defensive; the protocol machine
  ///   normally prevents this).
  pub fn push(&mut self, event: &Event<'_>) -> Result<Option<Message>, AssembleError> {
    match event {
      Event::MessageStart(start) => {
        if !matches!(self.state, AssemblerState::Idle) {
          self.state = AssemblerState::Idle;
          return Err(AssembleError::Desequenced);
        }
        self.state = match start.kind() {
          MessageKind::Text => AssemblerState::InText(String::new()),
          MessageKind::Binary => AssemblerState::InBinary(Vec::new()),
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
          AssemblerState::Idle => return Ok(None),
        };
        Ok(Some(msg))
      }

      // Control events and Closed: pass through as Ok(None).
      Event::Ping(_) | Event::Pong(_) | Event::CloseReceived(_) | Event::Closed(_) => Ok(None),
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
    let start1 = Event::MessageStart(MessageStart::new(MessageKind::Text, false));
    asm.push(&start1).unwrap();
    // Push another MessageStart while still in-progress.
    let start2 = Event::MessageStart(MessageStart::new(MessageKind::Binary, false));
    assert!(matches!(asm.push(&start2), Err(AssembleError::Desequenced)));
    // Post-error contract: the assembler reset to idle, so a fresh
    // MessageStart begins a clean message.
    let start3 = Event::MessageStart(MessageStart::new(MessageKind::Text, false));
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
    let start1 = Event::MessageStart(MessageStart::new(MessageKind::Text, false));
    asm.push(&start1).unwrap();
    let start2 = Event::MessageStart(MessageStart::new(MessageKind::Binary, false));
    assert!(matches!(asm.push(&start2), Err(AssembleError::Desequenced)));
    // Reset-to-idle: a fresh start succeeds.
    let start3 = Event::MessageStart(MessageStart::new(MessageKind::Text, false));
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
}
