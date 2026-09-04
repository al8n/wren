//! Borrowed events yielded while feeding inbound bytes.
//!
//! Events are produced by the lending iterator [`Events::next`](super::Events):
//! every borrowed event (and the slices inside it) is valid only until the
//! next `next()` call. Uncompressed chunks borrow the input slice directly;
//! compressed chunks borrow the cursor's internal inflate buffer.

use crate::{constants::MAX_CONTROL_PAYLOAD, frame::CloseCode};

/// What kind of data message is being received.
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Display, derive_more::IsVariant)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum MessageKind {
  /// UTF-8 text (§5.6) — payload chunks arrive as validated text.
  Text,
  /// Binary — payload chunks arrive as raw bytes.
  Binary,
}

impl MessageKind {
  /// Stable lowercase name.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Text => "text",
      Self::Binary => "binary",
    }
  }
}

/// A data message began.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MessageStart {
  kind: MessageKind,
  compressed: bool,
  skipped: bool,
}

impl MessageStart {
  pub(crate) const fn new(kind: MessageKind, compressed: bool, skipped: bool) -> Self {
    Self {
      kind,
      compressed,
      skipped,
    }
  }

  /// Text or binary.
  #[inline(always)]
  pub const fn kind(&self) -> MessageKind {
    self.kind
  }

  /// RSV1 was set under a negotiated permessage-deflate (RFC 7692): the wire
  /// payload was compressed. The chunks delivered for this message are already
  /// **inflated** — text passes the incremental UTF-8 validator post-inflation
  /// and arrives as [`Event::TextChunk`], binary as [`Event::BinaryChunk`].
  /// This flag is observable but the decoding is transparent; a consumer that
  /// ignores it sees the same decoded bytes either way.
  #[inline(always)]
  pub const fn compressed(&self) -> bool {
    self.compressed
  }

  /// **No chunk will follow for this message; a consumer holds nothing for
  /// it.** Only [`Event::MessageEnd`] closes it.
  ///
  /// True when the payload is being skipped rather than decoded: this message
  /// began under [`Connection::observe`](super::Connection::observe), or it is
  /// a compressed message arriving after the inbound inflate context was
  /// poisoned (see that method). Its `MessageEnd` still arrives — what is
  /// absent is the payload.
  ///
  /// **What stays bounded, and what does not.** Framing, fragment sequencing,
  /// the control-frame rules and the per-frame
  /// [`max_frame_payload`](super::ConnectionConfig::max_frame_payload) limit
  /// all apply exactly as they do to any other message: a violation still
  /// fails the connection. The AGGREGATE
  /// [`max_message_size`](super::ConnectionConfig::max_message_size)
  /// accounting is deliberately not performed — a skipped message retains
  /// nothing, so there is nothing for that cap to bound, and counting bytes
  /// this endpoint never looked at would fail a conforming peer for a message
  /// it was never going to deliver. A skipped message can therefore exceed
  /// `max_message_size` on the wire without the 1009 an ordinary one would
  /// draw.
  ///
  /// A folder must not open an accumulator for such a message: doing so
  /// delivers an EMPTY message where the peer sent bytes. Both assemblers in
  /// this crate read this flag and discard to the boundary instead
  /// ([`SliceAssembler::push`](crate::message::SliceAssembler::push),
  /// [`MessageAssembler::push`](crate::message::MessageAssembler::push)), so a
  /// caller using either needs no special case; a caller with its own folder
  /// does.
  #[inline(always)]
  pub const fn skipped(&self) -> bool {
    self.skipped
  }
}

/// A validated text payload chunk. `prefix` carries the ≤4 bytes that
/// complete a character split across `handle` calls; `body` is a borrowed
/// run valid until the next [`Events::next`](super::Events) call. Their
/// concatenation is the payload run.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TextChunk<'a> {
  prefix: ([u8; 4], u8),
  body: &'a str,
}

impl<'a> TextChunk<'a> {
  pub(crate) const fn new(prefix: ([u8; 4], u8), body: &'a str) -> Self {
    Self { prefix, body }
  }

  /// The carried-character prefix (often empty). Valid UTF-8 by
  /// construction.
  pub fn prefix(&self) -> &str {
    let (buf, len) = &self.prefix;
    let bytes = buf.get(..usize::from(*len)).unwrap_or(&[]);
    core::str::from_utf8(bytes).unwrap_or("")
  }

  /// The borrowed remainder of the run.
  #[inline(always)]
  pub const fn body(&self) -> &'a str {
    self.body
  }
}

/// An owned-inline control payload (≤ 125 bytes), copied out of the input
/// because a control frame may straddle `handle` calls.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ControlPayload {
  buf: [u8; MAX_CONTROL_PAYLOAD],
  len: u8,
}

impl ControlPayload {
  pub(crate) const fn new(buf: [u8; MAX_CONTROL_PAYLOAD], len: u8) -> Self {
    Self { buf, len }
  }

  /// The payload bytes.
  pub fn as_slice(&self) -> &[u8] {
    self.buf.get(..usize::from(self.len)).unwrap_or(&[])
  }
}

/// The peer's close frame, decoded (reason copied inline, ≤ 123 bytes).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CloseReceived {
  code: CloseCode,
  reason: ControlPayload,
}

impl CloseReceived {
  pub(crate) const fn new(code: CloseCode, reason: ControlPayload) -> Self {
    Self { code, reason }
  }

  /// The close code ([`CloseCode::NoStatusReceived`] when absent).
  #[inline(always)]
  pub const fn code(&self) -> CloseCode {
    self.code
  }

  /// The UTF-8 close reason (empty when absent; validated at decode).
  pub fn reason(&self) -> &str {
    core::str::from_utf8(self.reason.as_slice()).unwrap_or("")
  }
}

/// Terminal event: the connection finished (cleanly or not). Drain
/// [`poll_transmit`](super::Connection::poll_transmit), then drop the
/// transport.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Closed {
  code: CloseCode,
  clean: bool,
}

impl Closed {
  pub(crate) const fn new(code: CloseCode, clean: bool) -> Self {
    Self { code, clean }
  }

  /// The governing close code (the peer's on a clean close; the failure
  /// code on a protocol failure).
  #[inline(always)]
  pub const fn code(&self) -> CloseCode {
    self.code
  }

  /// Whether the close handshake completed per §7.1.4.
  #[inline(always)]
  pub const fn clean(&self) -> bool {
    self.clean
  }
}

/// One borrowed receive event.
#[derive(Debug, Copy, Clone, PartialEq, Eq, derive_more::IsVariant)]
#[non_exhaustive]
pub enum Event<'a> {
  /// A data message began.
  MessageStart(MessageStart),
  /// A run of binary payload, valid until the next
  /// [`Events::next`](super::Events) call. Uncompressed payloads are unmasked
  /// in place and borrow the input directly; compressed payloads borrow the
  /// cursor's internal inflate buffer (see [`MessageStart::compressed`]).
  BinaryChunk(&'a [u8]),
  /// A run of validated text payload.
  TextChunk(TextChunk<'a>),
  /// The current message ended (its FIN frame completed).
  MessageEnd,
  /// **The message in progress will not be delivered: drop what you hold for
  /// it.** No further chunk follows; its [`MessageEnd`](Event::MessageEnd)
  /// still arrives at the boundary, and assembly resumes at the next
  /// [`MessageStart`](Event::MessageStart).
  ///
  /// Emitted exactly ONCE per message, at the first payload run the machine
  /// skips of a message whose `MessageStart` was already emitted saying
  /// otherwise — that is, a message that began under
  /// [`handle`](super::Connection::handle) and was still in flight when
  /// [`observe`](super::Connection::observe) took over. A message whose start
  /// already said [`MessageStart::skipped`] never gets this event: its start
  /// carried the same fact, and nothing was accumulated for it to drop.
  ///
  /// It exists because that fact cannot travel on the start — the start was
  /// emitted before the decision — and cannot be left to the caller: an
  /// observation feed can produce NO events at all (every byte of it can be
  /// continuation payload), so there is no moment a caller could reliably
  /// react to. Both assemblers in this crate act on it in `push`; a caller
  /// with its own folder must drop its partial here, or a `MessageEnd` will
  /// later seal a TRUNCATED message.
  MessageAbandoned,
  /// A ping arrived; the payload is copied inline and the pong echo is
  /// queued automatically — drain
  /// [`poll_transmit`](super::Connection::poll_transmit).
  Ping(ControlPayload),
  /// A pong arrived (payload copied inline).
  Pong(ControlPayload),
  /// The peer initiated the close handshake (echo queued automatically).
  CloseReceived(CloseReceived),
  /// Terminal.
  Closed(Closed),
}
