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

  /// Compressed send was requested but permessage-deflate was not negotiated,
  /// or the outbound window-bits negotiated below 15 (miniz_oxide cannot bound
  /// its 32 KiB compression window to fewer bits — RFC-legal to send plain
  /// instead).
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  #[error("permessage-deflate not negotiated or outbound window bits < 15")]
  CompressionUnavailable,
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
  /// Outbound permessage-deflate compressor, created lazily on the first
  /// compressed send. Boxed to keep `SendState` small.
  #[cfg(feature = "deflate")]
  pub(crate) deflate: Option<std::boxed::Box<compress::CompressorBox>>,
}

impl SendState {
  pub(crate) fn new() -> Self {
    Self {
      message: SendMessageState::Idle,
      pending_close: None,
      close_sent: false,
      queued_code: None,
      pending_ping: false,
      #[cfg(feature = "deflate")]
      deflate: None,
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

/// Outbound permessage-deflate compression (RFC 7692 §7.2.1).
///
/// Compress with a raw-DEFLATE sync-flush and strip the trailing `00 00 FF FF`
/// boundary before framing (RFC 7692 §7.2.1). The compressor is kept across
/// messages for context takeover; reset per message when the outbound direction
/// negotiated `no_context_takeover`.
#[cfg(feature = "deflate")]
pub(crate) mod compress {

  use miniz_oxide::deflate::core::{
    CompressorOxide, TDEFLFlush, compress, create_comp_flags_from_zip_params,
  };
  use std::{boxed::Box, vec::Vec};

  /// RFC 7692 §7.2.1: the four trailing bytes a DEFLATE sync-flush always
  /// appends; these are stripped before putting the compressed bytes on the wire.
  const SYNC_TAIL: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

  /// Outbound compressor plus its scratch output buffer. Boxed inside
  /// `SendState` so the large internal state does not inflate the struct.
  pub(crate) struct CompressorBox {
    inner: Box<CompressorOxide>,
    /// Scratch buffer reused across messages; grows as needed but never shrinks.
    buf: Vec<u8>,
  }

  impl CompressorBox {
    /// A fresh raw-DEFLATE compressor (level 6, default strategy).
    pub(crate) fn new() -> Box<Self> {
      // window_bits=0 → raw DEFLATE (no zlib wrapper); level 6, strategy 0.
      let flags = create_comp_flags_from_zip_params(6, 0, 0);
      Box::new(Self {
        inner: Box::new(CompressorOxide::new(flags)),
        buf: Vec::new(),
      })
    }

    /// Reset the compressor context for `no_context_takeover`: the next
    /// message starts with a clean window.
    pub(crate) fn reset(&mut self) {
      self.inner.reset();
    }

    /// One output window appended to `buf` per `compress` call. miniz_oxide
    /// buffers compressed output internally and only emits as much as fits in
    /// the supplied window, so each call drains at most this many bytes —
    /// `compress_message` loops until the compressor reports it is fully
    /// drained.
    const WINDOW: usize = 8 * 1024;

    /// Compress `data` with a DEFLATE sync-flush, strip the trailing
    /// `00 00 FF FF` boundary, and return a slice into the internal scratch
    /// buffer. The slice is valid until the next call to `compress_message`.
    pub(crate) fn compress_message(&mut self, data: &[u8]) -> &[u8] {
      self.buf.clear();

      // Phase 1 — feed all input (no flush). Loop until every input byte is
      // consumed AND a call leaves the output window non-full: a full window
      // means the compressor still has buffered output to hand us, so we must
      // call again even after all input is consumed.
      let mut cursor = data;
      loop {
        let (consumed, written) = self.drive(cursor, TDEFLFlush::None);
        cursor = cursor.get(consumed..).unwrap_or(&[]);
        if cursor.is_empty() && written < Self::WINDOW {
          break;
        }
      }

      // Phase 2 — sync-flush. Keep flushing until a call yields a partial (or
      // empty) window: that signals the flush is fully drained. Leaving any
      // buffered flush output behind would both truncate this frame and poison
      // the next message's stream (context takeover reuses the compressor).
      loop {
        let (_consumed, written) = self.drive(&[], TDEFLFlush::Sync);
        if written < Self::WINDOW {
          break;
        }
      }

      // Strip the sync-flush boundary (RFC 7692 §7.2.1).
      if self.buf.ends_with(&SYNC_TAIL) {
        let new_len = self.buf.len().saturating_sub(4);
        self.buf.truncate(new_len);
      }

      &self.buf
    }

    /// One `compress` call into a freshly-appended `WINDOW`-sized region of
    /// `buf`, truncated to the bytes actually written. Returns
    /// `(input_consumed, output_written)`.
    fn drive(&mut self, input: &[u8], flush: TDEFLFlush) -> (usize, usize) {
      let base = self.buf.len();
      self.buf.resize(base.saturating_add(Self::WINDOW), 0);
      let Some(window) = self.buf.get_mut(base..) else {
        self.buf.truncate(base);
        return (input.len(), 0);
      };
      let (_status, consumed, written) = compress(&mut self.inner, input, window, flush);
      self.buf.truncate(base.saturating_add(written));
      (consumed, written)
    }
  }

  impl core::fmt::Debug for CompressorBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      f.debug_struct("CompressorBox")
        .field("scratch_len", &self.buf.len())
        .finish_non_exhaustive()
    }
  }
}

impl<I, Ro> Connection<I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// Encodes a whole compressed text message (RSV1 set) into `out`.
  ///
  /// Requires permessage-deflate to have been negotiated **and** the outbound
  /// window bits to be 15 (the `miniz_oxide` compressor always uses a 32 KiB
  /// window; emitting a smaller-window stream requires clamp support that
  /// miniz_oxide does not provide — RFC-legal to send plain in that case).
  /// Returns [`EncodeError::CompressionUnavailable`] otherwise.
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub fn encode_text_compressed(
    &mut self,
    payload: &str,
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    self.encode_compressed(crate::frame::Opcode::Text, payload.as_bytes(), out)
  }

  /// Encodes a whole compressed binary message (RSV1 set) into `out`.
  ///
  /// Same availability conditions as [`encode_text_compressed`].
  ///
  /// [`encode_text_compressed`]: Connection::encode_text_compressed
  #[cfg(feature = "deflate")]
  #[cfg_attr(docsrs, doc(cfg(feature = "deflate")))]
  pub fn encode_binary_compressed(
    &mut self,
    payload: &[u8],
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    self.encode_compressed(crate::frame::Opcode::Binary, payload, out)
  }

  /// Shared implementation for compressed whole-message sends.
  #[cfg(feature = "deflate")]
  fn encode_compressed(
    &mut self,
    opcode: crate::frame::Opcode,
    payload: &[u8],
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    use crate::negotiation::DeflateParams;

    // Guard: deflate must be negotiated.
    let params: DeflateParams = match self.deflate {
      Some(p) => p,
      None => return Err(EncodeError::CompressionUnavailable),
    };

    // Guard: outbound window bits must be 15 (miniz_oxide limitation).
    let outbound_bits = if Ro::EXPECT_MASKED_INBOUND {
      // Server receives masked (i.e. client role sends outbound) — but wait:
      // EXPECT_MASKED_INBOUND is true for SERVER (it expects clients to mask).
      // So: server sends on server→client direction = server_max_window_bits.
      // client sends on client→server direction = client_max_window_bits.
      // Ro::EXPECT_MASKED_INBOUND == true means WE ARE THE SERVER.
      params.server_max_window_bits()
    } else {
      params.client_max_window_bits()
    };
    if outbound_bits < 15 {
      return Err(EncodeError::CompressionUnavailable);
    }

    // Lifecycle + sequencing check (whole message → starting=true).
    self.check_data_send(true)?;

    // Determine whether to reset the compressor for this message.
    let no_takeover = if Ro::EXPECT_MASKED_INBOUND {
      params.server_no_context_takeover()
    } else {
      params.client_no_context_takeover()
    };

    // Lazily create the compressor, then compress.
    let had_compressor = self.send.deflate.is_some();
    let compressor = self
      .send
      .deflate
      .get_or_insert_with(compress::CompressorBox::new);
    if no_takeover && had_compressor {
      compressor.reset();
    }
    let compressed = compressor.compress_message(payload);
    // Copy the compressed bytes into a temporary owned buffer so we can call
    // `write_frame` with them (avoid a double-borrow of `self`).
    let compressed_owned: std::vec::Vec<u8> = compressed.to_vec();

    let n = self.write_frame(opcode, true, true, &compressed_owned, out)?;
    self.send.message = SendMessageState::Idle;
    Ok(n)
  }
}

#[cfg(all(test, feature = "std", feature = "deflate"))]
mod deflate_tests {
  use super::*;
  use crate::{
    connection::{
      Connection, ConnectionConfig, Events,
      events::{Event, MessageKind},
      role::{Client, Server},
      tests::CountingRng,
    },
    frame::{Decoded, FrameHeader, Opcode},
    negotiation::{DeflateParams, Negotiated, ServerDeflateConfig, accept_deflate_offer},
    time::testing::TestInstant,
  };

  // ── helpers ────────────────────────────────────────────────────────────────

  fn deflate_server(params: DeflateParams) -> Connection<TestInstant, Server> {
    let negotiated = Negotiated::none().with_deflate(Some(params));
    Connection::new(
      &negotiated,
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    )
  }

  fn deflate_client(params: DeflateParams) -> Connection<TestInstant, Client<CountingRng>> {
    let negotiated = Negotiated::none().with_deflate(Some(params));
    Connection::new(
      &negotiated,
      ConnectionConfig::default(),
      Client::new(CountingRng(0)),
      TestInstant(0),
    )
  }

  fn default_params() -> DeflateParams {
    DeflateParams::default()
  }

  /// Drain all events from an Events cursor into an owned summary vec.
  fn drain_events<I, Ro>(events: &mut Events<'_, '_, I, Ro>) -> Vec<DrainEv>
  where
    I: crate::time::Instant,
    Ro: crate::connection::role::Role,
  {
    let mut out = Vec::new();
    while let Some(e) = events.next() {
      match e {
        Event::MessageStart(s) => out.push(DrainEv::Start(s.kind())),
        Event::TextChunk(t) => {
          let mut s = t.prefix().to_string();
          s.push_str(t.body());
          out.push(DrainEv::Text(s));
        }
        Event::BinaryChunk(b) => out.push(DrainEv::Bin(b.to_vec())),
        Event::MessageEnd => out.push(DrainEv::End),
        _ => {}
      }
    }
    out
  }

  /// Fold adjacent Text/Bin chunks.
  fn fold(evs: Vec<DrainEv>) -> Vec<DrainEv> {
    let mut out: Vec<DrainEv> = Vec::new();
    for e in evs {
      match (out.last_mut(), e) {
        (Some(DrainEv::Text(acc)), DrainEv::Text(t)) => acc.push_str(&t),
        (Some(DrainEv::Bin(acc)), DrainEv::Bin(b)) => acc.extend_from_slice(&b),
        (_, e) => out.push(e),
      }
    }
    out
  }

  #[derive(Debug, PartialEq, Eq)]
  enum DrainEv {
    Start(MessageKind),
    Text(String),
    Bin(Vec<u8>),
    End,
  }

  // ── tests ──────────────────────────────────────────────────────────────────

  /// T3-1: A client compresses a text message; a server connection inflates it
  /// and recovers the original text.
  #[test]
  fn compressed_text_round_trips_through_recv() {
    let params = default_params();
    let mut client = deflate_client(params);
    let mut server = deflate_server(params);

    let mut wire = vec![0u8; 4096];
    let n = client
      .encode_text_compressed("Hello, deflate!", &mut wire)
      .unwrap();
    wire.truncate(n);

    let mut events = server.handle(TestInstant(0), &mut wire).unwrap();
    let evs = fold(drain_events(&mut events));
    assert_eq!(
      evs,
      [
        DrainEv::Start(MessageKind::Text),
        DrainEv::Text("Hello, deflate!".into()),
        DrainEv::End,
      ]
    );
  }

  /// T3-2: A client compresses a binary message; a server connection inflates it
  /// and recovers the original bytes.
  #[test]
  fn compressed_binary_round_trips_through_recv() {
    let params = default_params();
    let mut client = deflate_client(params);
    let mut server = deflate_server(params);

    let data: Vec<u8> = (0u8..128).collect();
    let mut wire = vec![0u8; 4096];
    let n = client.encode_binary_compressed(&data, &mut wire).unwrap();
    wire.truncate(n);

    let mut events = server.handle(TestInstant(0), &mut wire).unwrap();
    let evs = fold(drain_events(&mut events));
    assert_eq!(
      evs,
      [
        DrainEv::Start(MessageKind::Binary),
        DrainEv::Bin(data),
        DrainEv::End,
      ]
    );
  }

  /// T3-3: The RSV1 bit must be set on a compressed send.
  #[test]
  fn compressed_send_sets_rsv1_on_the_wire() {
    let mut conn = deflate_server(default_params());
    let mut out = vec![0u8; 4096];
    let n = conn.encode_text_compressed("test", &mut out).unwrap();

    let wire = &out[..n];
    let decoded = match FrameHeader::decode(wire).unwrap() {
      Decoded::Complete(d) => d,
      _ => panic!("expected a complete frame header"),
    };
    assert!(
      decoded.header().rsv1(),
      "RSV1 must be set on a compressed frame"
    );
    assert_eq!(decoded.header().opcode(), Opcode::Text);
    assert!(decoded.header().fin());
  }

  /// T3-4: `encode_text_compressed` returns `EncodeError::CompressionUnavailable`
  /// when deflate is not negotiated.
  #[test]
  fn not_negotiated_returns_compression_unavailable() {
    let mut conn: Connection<TestInstant, Server> = Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    );
    let mut out = [0u8; 64];
    assert!(matches!(
      conn.encode_text_compressed("hello", &mut out),
      Err(EncodeError::CompressionUnavailable)
    ));
    assert!(matches!(
      conn.encode_binary_compressed(b"hi", &mut out),
      Err(EncodeError::CompressionUnavailable)
    ));
  }

  /// T3-5: When the server's outbound window bits < 15, `encode_text_compressed`
  /// returns `EncodeError::CompressionUnavailable` (miniz_oxide cannot honor the
  /// window constraint).
  #[test]
  fn outbound_bits_below_15_returns_compression_unavailable() {
    // Negotiate server_max_window_bits=10; the SERVER's outbound direction uses
    // server_max_window_bits, so bits=10 < 15 → CompressionUnavailable.
    let (params, _) = accept_deflate_offer(
      ["permessage-deflate; server_max_window_bits=10"].into_iter(),
      &ServerDeflateConfig::new(),
    )
    .expect("offer must be accepted");
    assert_eq!(params.server_max_window_bits(), 10);

    let mut server = deflate_server(params);
    let mut out = [0u8; 128];
    assert!(matches!(
      server.encode_text_compressed("hello", &mut out),
      Err(EncodeError::CompressionUnavailable)
    ));
    assert!(matches!(
      server.encode_binary_compressed(b"hi", &mut out),
      Err(EncodeError::CompressionUnavailable)
    ));
  }

  /// T3-6: With `no_context_takeover` on the send direction, two successive
  /// compressed messages are each independently decodable by a fresh-context
  /// inflater — verified by decoding both with a server that also negotiated
  /// no_context_takeover on the inbound side.
  #[test]
  fn no_context_takeover_reset_each_message_independently_decodable() {
    // Negotiate server_no_context_takeover: the server's outbound context
    // resets per message. The receiving client must also reset per message.
    let (params, _) = accept_deflate_offer(
      ["permessage-deflate; server_no_context_takeover"].into_iter(),
      &ServerDeflateConfig::new(),
    )
    .expect("offer must be accepted");
    assert!(params.server_no_context_takeover());

    let mut server = deflate_server(params);
    let mut wire1 = vec![0u8; 4096];
    let n1 = server
      .encode_text_compressed("the quick brown fox", &mut wire1)
      .unwrap();
    wire1.truncate(n1);

    let mut wire2 = vec![0u8; 4096];
    let n2 = server
      .encode_text_compressed("the quick brown fox jumps over", &mut wire2)
      .unwrap();
    wire2.truncate(n2);

    // Each message must decode independently with a client that has matching
    // no_context_takeover (each context is fresh).
    let mut client1 = deflate_client(params);
    let evs1 = fold(drain_events(
      &mut client1.handle(TestInstant(0), &mut wire1).unwrap(),
    ));
    assert_eq!(evs1[1], DrainEv::Text("the quick brown fox".into()));

    let mut client2 = deflate_client(params);
    let evs2 = fold(drain_events(
      &mut client2.handle(TestInstant(0), &mut wire2).unwrap(),
    ));
    assert_eq!(
      evs2[1],
      DrainEv::Text("the quick brown fox jumps over".into())
    );
  }

  /// Regression (Autobahn 12.1.*/13.1.*): compressed sends of LARGE,
  /// INCOMPRESSIBLE payloads must round-trip through an *independent*
  /// reference decoder, across many context-takeover messages.
  ///
  /// The original `compress_message` sized its sync-flush output window at a
  /// fixed 512 bytes and exited the feed loop the moment all input was
  /// consumed — so when the compressor still held buffered output (the common
  /// case for incompressible data), the frame was silently truncated *and* the
  /// leftover flush state poisoned every subsequent message in the takeover
  /// stream. Our own inflater agreed with the broken encoder (same bug, both
  /// sides), so this test decodes with a fresh `miniz_oxide` stream instead.
  #[test]
  fn large_incompressible_compressed_sends_round_trip_via_reference_decoder() {
    use miniz_oxide::{
      DataFormat, MZFlush,
      inflate::stream::{InflateState, inflate},
    };

    // A 16 KiB payload that DEFLATE cannot shrink (LCG-spread bytes — high
    // entropy at the byte level), matching the Autobahn 12.1.7 case size.
    let mut data = vec![0u8; 16 * 1024];
    let mut x: u32 = 0x1234_5678;
    for b in &mut data {
      x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
      *b = (x >> 24) as u8;
    }

    let mut server = deflate_server(default_params());
    // One reference inflate stream, context kept across messages (no Finish),
    // mirroring a conformant peer with permessage-deflate context takeover.
    let mut ref_state = InflateState::new_boxed(DataFormat::Raw);

    for msg in 0..8 {
      let mut wire = vec![0u8; 64 * 1024];
      let n = server
        .encode_binary_compressed(&data, &mut wire)
        .expect("compressed send");
      wire.truncate(n);

      // Pull the (unmasked, server-role) compressed payload out of the frame.
      let decoded = match FrameHeader::decode(&wire).expect("decode header") {
        Decoded::Complete(d) => d,
        _ => panic!("incomplete frame header"),
      };
      assert!(decoded.header().rsv1(), "msg {msg}: RSV1 must be set");
      let mut payload = wire[decoded.consumed()..].to_vec();
      // RFC 7692 §7.2.2: the sender stripped the sync tail; restore it.
      payload.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);

      let mut out = vec![0u8; 64 * 1024];
      let result = inflate(&mut ref_state, &payload, &mut out, MZFlush::None);
      assert_eq!(
        result.bytes_written,
        data.len(),
        "msg {msg}: reference decoder inflated {} bytes, expected {} (status {:?})",
        result.bytes_written,
        data.len(),
        result.status,
      );
      assert_eq!(
        &out[..result.bytes_written],
        &data[..],
        "msg {msg}: content"
      );
    }
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
