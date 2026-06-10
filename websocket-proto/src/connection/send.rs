//! The send side: zero-queue application encodes plus the inline queue for
//! protocol-generated control frames.

use super::{Connection, Lifecycle, role::Role};
use crate::{
  constants::MAX_CONTROL_PAYLOAD,
  error::BufferTooSmallDetail,
  frame::{CloseCode, FrameHeader, Opcode, encode_close_payload, mask},
  time::Instant,
};
use derive_more::{IsVariant, TryUnwrap, Unwrap};

/// Errors from the application-send encoders.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, Unwrap, TryUnwrap, thiserror::Error)]
#[unwrap(ref)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum EncodeError {
  /// The output buffer cannot hold the frame.
  #[error("{0}")]
  BufferTooSmall(BufferTooSmallDetail),

  /// Control payloads are capped at 125 bytes (RFC 6455 §5.5).
  #[error("control payload exceeds 125 bytes")]
  ControlTooLong,

  /// A continuation was encoded with no fragmented message in progress, or
  /// a new data message started mid-fragmentation.
  #[error("fragmentation sequence violation")]
  FragmentSequence,

  /// The close handshake is underway (or done); data sends are over.
  #[error("connection is closing or closed")]
  Closing,

  /// The close code is not sendable on the wire.
  #[error("close code is not sendable")]
  InvalidCloseCode,

  /// The close reason exceeds 123 bytes.
  #[error("close reason too long")]
  ReasonTooLong,
}

/// Outbound fragmentation state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum SendMessageState {
  /// Between messages.
  Idle,
  /// Inside a message.
  InMessage,
}

#[derive(Debug)]
pub(crate) struct SendState {
  pub(crate) message: SendMessageState,
  /// Close frame queued by the protocol or the application.
  pub(crate) pending_close: Option<([u8; MAX_CONTROL_PAYLOAD], u8)>,
  pub(crate) close_sent: bool,
  /// The close code from the first `queue_close` call (for `handle_timeout`).
  pub(crate) queued_code: Option<CloseCode>,
  /// A keepalive ping is pending (empty payload).
  pub(crate) pending_ping: bool,
}

impl SendState {
  pub(crate) const fn new() -> Self {
    Self {
      message: SendMessageState::Idle,
      pending_close: None,
      close_sent: false,
      queued_code: None,
      pending_ping: false,
    }
  }

  /// Queues a close frame payload (best effort; oversized reasons are
  /// truncated at a char boundary by the caller before queueing). The first
  /// queued close wins — a later one (e.g. an echo after we already sent our
  /// own close) is dropped.
  pub(crate) fn queue_close(&mut self, code: CloseCode, reason: &str) {
    let mut buf = [0u8; MAX_CONTROL_PAYLOAD];
    let len = match encode_close_payload(code, reason, &mut buf) {
      Ok(n) => n,
      Err(_) => encode_close_payload(code, "", &mut buf).unwrap_or_default(),
    };
    if self.pending_close.is_none() {
      self.pending_close = Some((buf, u8::try_from(len).unwrap_or(0)));
      self.queued_code = Some(code);
    }
  }
}

/// The kind of data frame being encoded by [`Connection::encode_fragment`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::IsVariant)]
#[non_exhaustive]
pub enum FragmentKind {
  /// The first fragment of a text message.
  TextStart,
  /// The first fragment of a binary message.
  BinaryStart,
  /// A middle/final continuation fragment.
  Continue,
}

impl FragmentKind {
  /// The wire opcode plus whether this fragment STARTS a message.
  const fn into_parts(self) -> (Opcode, bool) {
    match self {
      Self::TextStart => (Opcode::Text, true),
      Self::BinaryStart => (Opcode::Binary, true),
      Self::Continue => (Opcode::Continuation, false),
    }
  }
}

/// A serialized frame header for vectored writes
/// (`writev([header.as_slice(), payload])`).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EncodedHeader {
  buf: [u8; crate::constants::MAX_FRAME_HEADER],
  len: u8,
}

impl EncodedHeader {
  /// The header bytes (2–14).
  pub fn as_slice(&self) -> &[u8] {
    self.buf.get(..usize::from(self.len)).unwrap_or(&self.buf)
  }
}

impl<I, Ro> Connection<I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// Encodes a whole unfragmented text message into `out`.
  pub fn encode_text(&mut self, payload: &str, out: &mut [u8]) -> Result<usize, EncodeError> {
    self.encode_data(Opcode::Text, true, true, payload.as_bytes(), out)
  }

  /// Encodes a whole unfragmented binary message into `out`.
  pub fn encode_binary(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    self.encode_data(Opcode::Binary, true, true, payload, out)
  }

  /// Encodes one fragment. Sequencing is tracked: a `*Start` requires no
  /// message in progress; `Continue` requires one; `fin` ends it.
  pub fn encode_fragment(
    &mut self,
    kind: FragmentKind,
    fin: bool,
    payload: &[u8],
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    let (opcode, starting) = kind.into_parts();
    self.encode_data(opcode, starting, fin, payload, out)
  }

  /// The vectored-write twin of [`encode_fragment`]: masks `payload` **in
  /// place** (clients; servers leave it untouched) and returns the frame
  /// header for the driver to write first —
  /// `writev([header.as_slice(), payload])`. Same lifecycle and sequencing
  /// rules.
  ///
  /// [`encode_fragment`]: Connection::encode_fragment
  pub fn prepare_fragment(
    &mut self,
    kind: FragmentKind,
    fin: bool,
    payload: &mut [u8],
  ) -> Result<EncodedHeader, EncodeError> {
    let (opcode, starting) = kind.into_parts();
    self.check_data_send(starting)?;

    let key = self.role.next_mask();
    let header = FrameHeader::new(opcode, u64::try_from(payload.len()).unwrap_or(u64::MAX))
      .with_fin(fin)
      .with_mask(key);
    let mut buf = [0u8; crate::constants::MAX_FRAME_HEADER];
    let len = match header.encode(&mut buf) {
      Ok(n) => n,
      // Unreachable: the buffer is MAX_FRAME_HEADER and the length is a
      // usize (never exceeds the §5.2 maximum).
      Err(_) => {
        return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
          crate::constants::MAX_FRAME_HEADER,
          0,
        )));
      }
    };
    if let Some(k) = key {
      mask(payload, k, 0);
    }
    self.send.message = if fin {
      SendMessageState::Idle
    } else {
      SendMessageState::InMessage
    };
    Ok(EncodedHeader {
      buf,
      len: u8::try_from(len).unwrap_or(0),
    })
  }

  /// Encodes a ping with an application payload (≤ 125 bytes).
  pub fn encode_ping(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    self.encode_control(Opcode::Ping, payload, out)
  }

  /// Encodes an unsolicited pong (§5.5.3 allows them).
  pub fn encode_pong(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    self.encode_control(Opcode::Pong, payload, out)
  }

  /// Starts the close handshake from this side: validates and queues the
  /// close frame for [`poll_transmit`](Connection::poll_transmit) and stops
  /// further data sends. The reason is capped at 123 bytes (truncate at a
  /// char boundary before calling, or it is rejected).
  pub fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), EncodeError> {
    if !matches!(self.lifecycle, Lifecycle::Open) {
      return Err(EncodeError::Closing);
    }
    if !code.is_valid_on_wire() {
      return Err(EncodeError::InvalidCloseCode);
    }
    if reason.len() > MAX_CONTROL_PAYLOAD.saturating_sub(2) {
      return Err(EncodeError::ReasonTooLong);
    }
    self.send.queue_close(code, reason);
    self.lifecycle = Lifecycle::CloseSent;
    Ok(())
  }

  /// Drains one queued protocol frame (close → pong echo → keepalive ping)
  /// into `out`. Returns the byte count, or `None` when nothing is pending.
  /// Arms `close_deadline` at the moment the close frame actually drains.
  pub fn poll_transmit(&mut self, now: I, out: &mut [u8]) -> Result<Option<usize>, EncodeError> {
    // Close first: once it goes out, nothing else ever follows (§5.5.1).
    if !self.send.close_sent {
      if let Some((payload, len)) = self.send.pending_close {
        let len = usize::from(len);
        let n = self.write_frame(
          Opcode::Close,
          true,
          false,
          payload.get(..len).unwrap_or(&[]),
          out,
        )?;
        self.send.close_sent = true;
        self.send.pending_close = None;
        // Arm the close deadline NOW (at drain time, not at close() time).
        self.close_deadline = now.checked_add_duration(self.config.close_timeout);
        return Ok(Some(n));
      }
    } else {
      return Ok(None);
    }
    if let Some((payload, len)) = self.recv.pending_pong {
      let len = usize::from(len);
      let n = self.write_frame(
        Opcode::Pong,
        true,
        false,
        payload.get(..len).unwrap_or(&[]),
        out,
      )?;
      self.recv.pending_pong = None;
      return Ok(Some(n));
    }
    // Keepalive ping (empty payload, no mask key for server; masked for client).
    if self.send.pending_ping {
      let n = self.write_frame(Opcode::Ping, true, false, &[], out)?;
      self.send.pending_ping = false;
      return Ok(Some(n));
    }
    Ok(None)
  }

  /// Shared lifecycle + fragmentation-sequencing prologue for the data
  /// encoders.
  fn check_data_send(&self, starting: bool) -> Result<(), EncodeError> {
    if !matches!(self.lifecycle, Lifecycle::Open) {
      return Err(EncodeError::Closing);
    }
    match (starting, self.send.message) {
      (true, SendMessageState::Idle) => Ok(()),
      (false, SendMessageState::InMessage) => Ok(()),
      _ => Err(EncodeError::FragmentSequence),
    }
  }

  fn encode_data(
    &mut self,
    opcode: Opcode,
    starting: bool,
    fin: bool,
    payload: &[u8],
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    self.check_data_send(starting)?;
    let n = self.write_frame(opcode, fin, false, payload, out)?;
    self.send.message = if fin {
      SendMessageState::Idle
    } else {
      SendMessageState::InMessage
    };
    Ok(n)
  }

  fn encode_control(
    &mut self,
    opcode: Opcode,
    payload: &[u8],
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    if !matches!(self.lifecycle, Lifecycle::Open) {
      return Err(EncodeError::Closing);
    }
    if payload.len() > MAX_CONTROL_PAYLOAD {
      return Err(EncodeError::ControlTooLong);
    }
    self.write_frame(opcode, true, false, payload, out)
  }

  /// Serializes one frame: header + (masked) payload copy.
  fn write_frame(
    &mut self,
    opcode: Opcode,
    fin: bool,
    rsv1: bool,
    payload: &[u8],
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    let key = self.role.next_mask();
    let header = FrameHeader::new(opcode, u64::try_from(payload.len()).unwrap_or(u64::MAX))
      .with_fin(fin)
      .with_rsv1(rsv1)
      .with_mask(key);
    let header_len = header.header_len();
    let total = header_len.saturating_add(payload.len());
    let Some(dst) = out.get_mut(..total) else {
      return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
        total,
        out.len(),
      )));
    };
    let (head, body) = dst.split_at_mut(header_len);
    match header.encode(head) {
      Ok(_) => {}
      Err(_) => {
        return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
          total,
          out.len(),
        )));
      }
    }
    for (d, s) in body.iter_mut().zip(payload) {
      *d = *s;
    }
    if let Some(k) = key {
      mask(body, k, 0);
    }
    Ok(total)
  }
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;
  use crate::{
    connection::{
      Connection, ConnectionConfig,
      role::{Client, Server},
      tests::CountingRng,
    },
    frame::{CloseCode, Decoded, FrameHeader},
    negotiation::Negotiated,
    time::testing::TestInstant,
  };

  fn client() -> Connection<TestInstant, Client<CountingRng>> {
    Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Client::new(CountingRng(0)),
      TestInstant(0),
    )
  }

  fn server() -> Connection<TestInstant, Server> {
    Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    )
  }

  #[test]
  fn server_text_is_unmasked_and_canonical() {
    let mut conn = server();
    let mut out = [0u8; 32];
    let n = conn.encode_text("Hello", &mut out).unwrap();
    assert_eq!(&out[..n], &[0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
  }

  #[test]
  fn client_frames_are_masked_with_fresh_keys() {
    let mut conn = client();
    let mut out = [0u8; 32];
    let n1 = conn.encode_text("Hi", &mut out).unwrap();
    let first = out[..n1].to_vec();
    let n2 = conn.encode_text("Hi", &mut out).unwrap();
    let second = out[..n2].to_vec();

    // Both decode as masked text frames with DIFFERENT keys.
    let d1 = match FrameHeader::decode(&first).unwrap() {
      Decoded::Complete(d) => d,
      _ => panic!(),
    };
    let d2 = match FrameHeader::decode(&second).unwrap() {
      Decoded::Complete(d) => d,
      _ => panic!(),
    };
    assert!(d1.header().mask().is_some());
    assert_ne!(d1.header().mask(), d2.header().mask());
    // Unmasking restores the payload.
    let mut payload = first[d1.consumed()..].to_vec();
    crate::frame::mask(&mut payload, d1.header().mask().unwrap(), 0);
    assert_eq!(&payload, b"Hi");
  }

  #[test]
  fn fragmentation_sequencing_is_enforced() {
    let mut conn = server();
    let mut out = [0u8; 64];

    assert!(matches!(
      conn.encode_fragment(FragmentKind::Continue, true, b"x", &mut out),
      Err(EncodeError::FragmentSequence)
    ));

    conn
      .encode_fragment(FragmentKind::TextStart, false, b"He", &mut out)
      .unwrap();
    assert!(matches!(
      conn.encode_text("nope", &mut out),
      Err(EncodeError::FragmentSequence)
    ));
    // Control frames are fine mid-message.
    conn.encode_ping(b"k", &mut out).unwrap();
    conn
      .encode_fragment(FragmentKind::Continue, true, b"y", &mut out)
      .unwrap();
    // Sequence complete: a new message may start.
    conn.encode_text("ok", &mut out).unwrap();
  }

  #[test]
  fn control_length_cap() {
    let mut conn = server();
    let mut out = [0u8; 256];
    let big = [0u8; 126];
    assert!(matches!(
      conn.encode_ping(&big, &mut out),
      Err(EncodeError::ControlTooLong)
    ));
    assert!(conn.encode_ping(&big[..125], &mut out).is_ok());
  }

  #[test]
  fn close_initiation_and_send_blocking() {
    let mut conn = server();
    let mut out = [0u8; 64];

    assert!(matches!(
      conn.close(CloseCode::NoStatusReceived, ""),
      Err(EncodeError::InvalidCloseCode)
    ));
    conn.close(CloseCode::Normal, "done").unwrap();
    assert!(matches!(
      conn.encode_text("late", &mut out),
      Err(EncodeError::Closing)
    ));
    assert!(matches!(
      conn.close(CloseCode::Normal, ""),
      Err(EncodeError::Closing)
    ));

    // poll_transmit emits exactly one close frame, then nothing.
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .unwrap();
    assert_eq!(&out[..n], &[0x88, 0x06, 0x03, 0xE8, b'd', b'o', b'n', b'e']);
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none()
    );
  }

  #[test]
  fn prepare_fragment_masks_in_place_and_returns_the_header() {
    let mut conn = client();
    let mut payload = *b"Hello";
    let header = conn
      .prepare_fragment(FragmentKind::TextStart, true, &mut payload)
      .unwrap();

    // Reassemble header ++ payload: must decode as one masked text frame
    // whose unmasked payload is the original.
    let mut wire = header.as_slice().to_vec();
    wire.extend_from_slice(&payload);
    let d = match crate::frame::FrameHeader::decode(&wire).unwrap() {
      crate::frame::Decoded::Complete(d) => d,
      _ => panic!(),
    };
    assert_eq!(d.header().opcode(), crate::frame::Opcode::Text);
    let key = d.header().mask().unwrap();
    let mut p = wire[d.consumed()..].to_vec();
    crate::frame::mask(&mut p, key, 0);
    assert_eq!(&p, b"Hello");

    // Server side: no mask, payload untouched.
    let mut conn = server();
    let mut payload = *b"Hi";
    let header = conn
      .prepare_fragment(FragmentKind::BinaryStart, true, &mut payload)
      .unwrap();
    assert_eq!(header.as_slice(), &[0x82, 0x02]);
    assert_eq!(&payload, b"Hi");

    // Sequencing shares state with encode_fragment.
    let mut conn = server();
    let mut p = *b"a";
    conn
      .prepare_fragment(FragmentKind::TextStart, false, &mut p)
      .unwrap();
    let mut out = [0u8; 16];
    assert!(matches!(
      conn.encode_text("nope", &mut out),
      Err(EncodeError::FragmentSequence)
    ));
    conn
      .prepare_fragment(FragmentKind::Continue, true, &mut p)
      .unwrap();
  }

  #[test]
  fn pong_echo_drains_after_ping() {
    use crate::{
      connection::role::Server as Srv,
      frame::{Opcode, mask as apply_mask},
    };
    let mut conn = server();
    // Receive a masked ping (client→server) with payload "abc".
    let key = [9, 9, 9, 9];
    let header = FrameHeader::new(Opcode::Ping, 3).with_mask(Some(key));
    let mut bytes = vec![0u8; header.header_len() + 3];
    let n = header.encode(&mut bytes).unwrap();
    bytes[n..].copy_from_slice(b"abc");
    apply_mask(&mut bytes[n..], key, 0);
    {
      let mut events = conn.handle(TestInstant(0), &mut bytes).unwrap();
      while events.next().is_some() {}
    }
    let mut out = [0u8; 64];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .unwrap();
    // Server pong: unmasked, opcode A, payload "abc".
    assert_eq!(&out[..n], &[0x8A, 0x03, b'a', b'b', b'c']);
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none()
    );
    let _ = Srv::new();
  }

  #[test]
  fn peer_close_echo_is_queued_and_close_first_priority() {
    use crate::frame::{Opcode, encode_close_payload, mask as apply_mask};
    let mut conn = server();
    // Peer ping then close in one buffer: pong is pending, then close
    // arrives → the close echo takes priority and the pong never goes out
    // after it (close ends the stream).
    let key = [1, 2, 3, 4];
    let mut bytes = Vec::new();
    let h = FrameHeader::new(Opcode::Ping, 1).with_mask(Some(key));
    let mut f = vec![0u8; h.header_len() + 1];
    let n = h.encode(&mut f).unwrap();
    f[n] = b'p';
    apply_mask(&mut f[n..], key, 0);
    bytes.extend(f);
    let mut payload = [0u8; 8];
    let pn = encode_close_payload(CloseCode::Normal, "", &mut payload).unwrap();
    let h =
      FrameHeader::new(Opcode::Close, u64::try_from(pn).unwrap_or(u64::MAX)).with_mask(Some(key));
    let mut f = vec![0u8; h.header_len() + pn];
    let n = h.encode(&mut f).unwrap();
    f[n..].copy_from_slice(&payload[..pn]);
    apply_mask(&mut f[n..], key, 0);
    bytes.extend(f);

    {
      let mut events = conn.handle(TestInstant(0), &mut bytes).unwrap();
      while events.next().is_some() {}
    }
    let mut out = [0u8; 64];
    // First drain: the close echo.
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .unwrap();
    assert_eq!(out[0], 0x88);
    let _ = n;
    // Nothing after a sent close — the pending pong is dropped.
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none()
    );
  }
}
