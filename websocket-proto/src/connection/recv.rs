//! The receive state machine: incremental header assembly, policy, in-place
//! unmasking, chunked delivery.
//!
//! ## Cursor mechanics
//!
//! [`Events`] holds the input as `Option<&'a mut [u8]>` and never indexes a
//! fixed position into it. Each step splits the *front* off that slice with
//! [`slice::split_at_mut`]: header and consumed-control bytes are split off
//! and dropped, payload bytes are split off, unmasked in place, then handed
//! out as a shared `&'a [u8]` reborrow (the by-value `&mut → &` coercion
//! keeps the `'a` lifetime) while the tail is kept for the next step. All
//! offsets are therefore relative to the current tail, and yielded chunks
//! never alias the bytes still owned by the cursor — the safe replacement for
//! the unsafe reborrow the sketch warned against.

use super::{Connection, Lifecycle, events::*, role::Role};
use crate::{
  constants::{MAX_CONTROL_PAYLOAD, MAX_FRAME_HEADER},
  frame::{CloseCode, Decoded, FrameHeader, Opcode, decode_close_payload, mask},
  time::Instant,
  utf8::Utf8Validator,
};

/// Caller-contract errors from [`Connection::handle`]. Protocol violations
/// are NOT errors — they surface as a final [`Event::Closed`].
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum HandleError {
  /// The connection is terminal; feeding more input is a caller bug.
  #[error("connection is terminal")]
  Terminal,
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
  },
}

#[derive(Debug)]
pub(crate) struct RecvState {
  pub(crate) frame: FrameState,
  pub(crate) message: MessageState,
  pub(crate) utf8: Utf8Validator,
  /// Carry bytes of a char split across `handle` calls (len ≤ 3).
  pub(crate) text_carry: ([u8; 4], u8),
  /// Latest ping payload awaiting echo (drained by poll_transmit).
  pub(crate) pending_pong: Option<([u8; MAX_CONTROL_PAYLOAD], u8)>,
  /// Close/ping/pong payload accumulator (control frames may split across
  /// reads).
  pub(crate) control_buf: [u8; MAX_CONTROL_PAYLOAD],
  pub(crate) control_len: usize,
}

impl RecvState {
  pub(crate) const fn new() -> Self {
    Self {
      frame: FrameState::Header {
        buf: [0; MAX_FRAME_HEADER],
        len: 0,
      },
      message: MessageState::Idle,
      utf8: Utf8Validator::new(),
      text_carry: ([0; 4], 0),
      pending_pong: None,
      control_buf: [0; MAX_CONTROL_PAYLOAD],
      control_len: 0,
    }
  }
}

/// Iterator-like cursor over the events produced by one `handle` call.
/// Yields events borrowing the input; drop it (or drain it) before calling
/// `handle` again.
#[derive(Debug)]
pub struct Events<'a, 'c, I, Ro> {
  pub(crate) conn: &'c mut Connection<I, Ro>,
  /// The unconsumed tail of the input. `None` only transiently while a step
  /// splits it; always `Some` between `next` calls.
  pub(crate) data: Option<&'a mut [u8]>,
  /// A `MessageEnd` owed after the final chunk of a message was yielded.
  pub(crate) pending_message_end: bool,
  /// A terminal `Closed` owed after a `CloseReceived` was yielded.
  pub(crate) pending_closed: Option<Closed>,
}

impl<I, Ro> Connection<I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// Feeds inbound transport bytes. Payload bytes are unmasked in place;
  /// the returned cursor yields borrowed events. `now` is accepted for
  /// signature stability (timers land in plan 4b).
  pub fn handle<'a, 'c>(
    &'c mut self,
    now: I,
    data: &'a mut [u8],
  ) -> Result<Events<'a, 'c, I, Ro>, HandleError> {
    let _ = now;
    if self.is_terminal() {
      return Err(HandleError::Terminal);
    }
    Ok(Events {
      conn: self,
      data: Some(data),
      pending_message_end: false,
      pending_closed: None,
    })
  }
}

impl<'a, I, Ro> Events<'a, '_, I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// The next event, or `None` when this input is exhausted.
  ///
  /// (A `next(&mut self) -> Option<Event<'a>>` inherent method rather than
  /// `Iterator`: items borrow the input slice at `'a`, which outlives the
  /// cursor — that part fits `Iterator` — but keeping it inherent leaves
  /// room to evolve the signature; a `for`-loop style `while let` is the
  /// intended call shape.)
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Option<Event<'a>> {
    if self.pending_message_end {
      self.pending_message_end = false;
      return Some(Event::MessageEnd);
    }
    if let Some(closed) = self.pending_closed.take() {
      self.conn.lifecycle = Lifecycle::Terminal;
      return Some(Event::Closed(closed));
    }

    loop {
      if self.conn.is_terminal() {
        return None;
      }
      // Discard inbound data after the peer's close (RFC 6455 §1.4 — no
      // further frames are expected; anything that arrives is ignored).
      if matches!(self.conn.lifecycle, Lifecycle::PeerClosed) {
        self.data = None;
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
        FrameState::DataPayload { .. } => match self.step_data_payload() {
          StepOutcome::Event(event) => return Some(event),
          StepOutcome::NeedMore => return None,
          StepOutcome::Continue => {}
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
        };
        self.conn.recv.utf8.reset();
        self.conn.recv.text_carry = ([0; 4], 0);
        self.begin_data_payload(header);
        Some(Event::MessageStart(MessageStart::new(kind, compressed)))
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

  /// Consumes (part of) the current data payload: split off the available
  /// run, unmask it in place, account for size, and yield the chunk
  /// (text-validated or raw) followed by `MessageEnd` on the final frame.
  fn step_data_payload(&mut self) -> StepOutcome<'a> {
    let FrameState::DataPayload {
      remaining,
      mask: key,
      offset,
      fin,
    } = self.conn.recv.frame
    else {
      return StepOutcome::Continue;
    };

    let available = self.remaining();
    let take = clamp_to_usize(remaining, available);
    if take == 0 && remaining > 0 {
      return StepOutcome::NeedMore;
    }

    let head = self.take_front(take);
    if let Some(k) = key {
      mask(head, k, offset);
    }
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

    match self.emit_data_chunk(chunk, fin, frame_done) {
      Ok(Some(event)) => StepOutcome::Event(event),
      Ok(None) => StepOutcome::Continue,
      Err(code) => StepOutcome::Event(self.fail(code)),
    }
  }

  /// Emits the just-unmasked data chunk: size accounting, UTF-8 gating,
  /// chunk + `MessageEnd` sequencing.
  fn emit_data_chunk(
    &mut self,
    chunk: &'a [u8],
    fin: bool,
    frame_done: bool,
  ) -> Result<Option<Event<'a>>, CloseCode> {
    let MessageState::InMessage {
      kind,
      compressed,
      received,
    } = self.conn.recv.message
    else {
      return Err(CloseCode::ProtocolError);
    };
    let len = widen(chunk.len());
    let received = received.saturating_add(len);
    if received > self.conn.config.max_message_size() {
      return Err(CloseCode::MessageTooBig);
    }
    let message_done = frame_done && fin;
    self.conn.recv.message = if message_done {
      MessageState::Idle
    } else {
      MessageState::InMessage {
        kind,
        compressed,
        received,
      }
    };

    let event = if compressed {
      // Compressed payloads are NOT UTF-8 validated until inflation (plan 5);
      // surface the raw DEFLATE bytes as BinaryChunk runs regardless of the
      // text/binary opcode — MessageStart.compressed() tells the consumer
      // what they are.
      if chunk.is_empty() {
        None
      } else {
        Some(Event::BinaryChunk(chunk))
      }
    } else {
      match kind {
        MessageKind::Binary => {
          if chunk.is_empty() {
            None
          } else {
            Some(Event::BinaryChunk(chunk))
          }
        }
        MessageKind::Text => self
          .validate_text(chunk, message_done)?
          .map(Event::TextChunk),
      }
    };

    match event {
      Some(e) => {
        if message_done {
          // MessageEnd must still follow this chunk: stash a pending flag.
          self.pending_message_end = true;
        }
        Ok(Some(e))
      }
      None if message_done => Ok(Some(Event::MessageEnd)),
      None => Ok(None),
    }
  }

  /// Runs the incremental validator over the chunk, assembling the carry
  /// prefix. Returns the text chunk to yield (or `None` for empty), or the
  /// close code on invalid UTF-8.
  fn validate_text(
    &mut self,
    chunk: &'a [u8],
    message_done: bool,
  ) -> Result<Option<TextChunk<'a>>, CloseCode> {
    let needed_before = usize::from(self.conn.recv.utf8.pending_needed());
    let complete = match self.conn.recv.utf8.feed(chunk) {
      Ok(c) => c,
      Err(_) => return Err(CloseCode::InvalidFramePayload),
    };
    if message_done && !self.conn.recv.utf8.is_boundary() {
      return Err(CloseCode::InvalidFramePayload);
    }

    // Prefix: finish the carried char with the first `needed_before` bytes
    // (if this chunk supplied them all — otherwise everything joins the
    // carry and nothing is yielded).
    let (mut carry_buf, carry_len) = self.conn.recv.text_carry;
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
        self.conn.recv.text_carry = (carry_buf, new_len);
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
      self.conn.recv.text_carry = ([0; 4], 0);
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
      self.conn.recv.text_carry = (carry, n);
    }

    let body_bytes = chunk.get(body_start..complete).unwrap_or(&[]);
    let body = core::str::from_utf8(body_bytes).unwrap_or("");
    if prefix.1 == 0 && body.is_empty() {
      return Ok(None);
    }
    Ok(Some(TextChunk::new(prefix, body)))
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
        self.conn.recv.pending_pong = Some((payload_buf, len_u8));
        Ok(Event::Ping(payload))
      }
      Opcode::Pong => Ok(Event::Pong(payload)),
      Opcode::Close => {
        let decoded = match decode_close_payload(payload.as_slice()) {
          Ok(d) => d,
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
          self.conn.send.queue_close(echo, "");
        }
        self.conn.lifecycle = Lifecycle::PeerClosed;

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

  /// Queues the failure close, transitions to Terminal, and produces the
  /// terminal event. Stops consuming the rest of the input.
  fn fail(&mut self, code: CloseCode) -> Event<'a> {
    if !matches!(self.conn.lifecycle, Lifecycle::CloseSent) {
      self.conn.send.queue_close(code, "");
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

/// The §5.5 control-payload cap as a `u64` for header comparisons.
fn control_cap() -> u64 {
  widen(MAX_CONTROL_PAYLOAD)
}

const MAX_CONTROL_PAYLOAD_U8: u8 = 125;

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

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::{
    connection::{Connection, ConnectionConfig, role::Server},
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

  fn server() -> Connection<TestInstant, Server> {
    Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    )
  }

  /// Drains every event of one handle() call into owned summaries.
  #[derive(Debug, PartialEq, Eq)]
  enum Ev {
    Start(MessageKind, bool),
    Text(String),
    Bin(Vec<u8>),
    End,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    CloseRecv(u16, String),
    Closed(u16, bool),
  }

  fn drain(conn: &mut Connection<TestInstant, Server>, bytes: &[u8]) -> Vec<Ev> {
    let mut data = bytes.to_vec();
    let mut events = conn.handle(TestInstant(0), &mut data).unwrap();
    let mut out = Vec::new();
    while let Some(e) = events.next() {
      out.push(match e {
        Event::MessageStart(s) => Ev::Start(s.kind(), s.compressed()),
        Event::TextChunk(t) => Ev::Text(format!("{}{}", t.prefix(), t.body())),
        Event::BinaryChunk(b) => Ev::Bin(b.to_vec()),
        Event::MessageEnd => Ev::End,
        Event::Ping(p) => Ev::Ping(p.as_slice().to_vec()),
        Event::Pong(p) => Ev::Pong(p.as_slice().to_vec()),
        Event::CloseReceived(c) => Ev::CloseRecv(c.code().as_u16(), c.reason().to_string()),
        Event::Closed(c) => Ev::Closed(c.code().as_u16(), c.clean()),
      });
    }
    out
  }

  /// Text/binary chunks may split arbitrarily — fold adjacent runs for
  /// comparison.
  fn fold(events: Vec<Ev>) -> Vec<Ev> {
    let mut out: Vec<Ev> = Vec::new();
    for e in events {
      match (out.last_mut(), e) {
        (Some(Ev::Text(acc)), Ev::Text(t)) => acc.push_str(&t),
        (Some(Ev::Bin(acc)), Ev::Bin(b)) => acc.extend_from_slice(&b),
        (_, e) => out.push(e),
      }
    }
    out
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

  #[cfg(feature = "deflate")]
  #[test]
  fn rsv1_passthrough_when_deflate_negotiated() {
    use crate::negotiation::{DeflateOffer, parse_deflate_response};
    let params = parse_deflate_response("permessage-deflate", &DeflateOffer::new()).unwrap();
    let negotiated = Negotiated::none().with_deflate(Some(params));
    let mut conn: Connection<TestInstant, Server> = Connection::new(
      &negotiated,
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    );
    // RSV1 on the first frame: accepted, marked compressed, payload raw.
    let bytes = frame(Opcode::Text, true, true, &[0xAB, 0xCD]);
    let got = fold(drain(&mut conn, &bytes));
    assert_eq!(
      got,
      [
        Ev::Start(MessageKind::Text, true),
        Ev::Bin(vec![0xAB, 0xCD]),
        Ev::End
      ]
    );

    // RSV1 on a continuation still fails.
    let mut conn: Connection<TestInstant, Server> = Connection::new(
      &negotiated,
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    );
    let mut bytes = frame(Opcode::Text, false, true, b"x");
    bytes.extend(frame(Opcode::Continuation, true, true, b"y"));
    let got = drain(&mut conn, &bytes);
    assert_eq!(got.last(), Some(&Ev::Closed(1002, false)));
  }
}
