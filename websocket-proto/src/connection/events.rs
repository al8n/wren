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
}

impl MessageStart {
  pub(crate) const fn new(kind: MessageKind, compressed: bool) -> Self {
    Self { kind, compressed }
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
