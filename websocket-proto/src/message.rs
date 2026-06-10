//! Heap-tier owned-message assembly over [`Connection`] events.
//!
//! [`MessageAssembler`] folds the lending-iterator events from
//! [`Connection::handle`] into complete owned [`Message`] values. It is a pure
//! convenience layer: the same information is available incrementally through
//! the events themselves, without any allocation. Place `MessageAssembler`
//! above the event loop when your driver prefers owned messages over streaming
//! delivery.
//!
//! [`Connection`]: crate::connection::Connection
//! [`Connection::handle`]: crate::connection::Connection::handle

#[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
use std::{string::String, vec::Vec};

use crate::connection::{Event, MessageKind};

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
  /// Errors from [`MessageAssembler::push`].
  #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
  pub enum AssembleError {
    /// The assembled message exceeded the configured `max_message_size`.
    #[error("assembled message exceeded max_message_size")]
    TooLarge,

    /// A [`Event::MessageStart`] arrived while a message was already in progress
    /// (the protocol machine prevents this; this is a defensive guard).
    #[error("MessageStart received while a message was already assembling")]
    Desequenced,
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
}
