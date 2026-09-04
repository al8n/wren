//! The send side: zero-queue application encodes plus the inline queue for
//! protocol-generated control frames.

use super::{Connection, Lifecycle, role::Role};
use crate::{
  constants::MAX_CONTROL_PAYLOAD,
  error::BufferTooSmallDetail,
  frame::{CloseCode, FrameHeader, Opcode, encode_close_payload, mask},
  time::Instant,
};
use derive_more::{IsVariant, TryUnwrap};

/// Errors from the application-send encoders.
#[derive(Debug, Clone, Eq, PartialEq, IsVariant, TryUnwrap, thiserror::Error)]
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

  /// Outbound text payload bytes are not valid UTF-8 (RFC 6455 §8.1). A single
  /// fragment may legally end mid-codepoint (§5.6 splits a character across
  /// frames), but the assembled message must be valid: a `fin` fragment is
  /// rejected unless it lands on a character boundary. The fragmentation state
  /// is left unchanged, so the caller may retry the same fragment with
  /// corrected bytes.
  #[error("outbound text payload is not valid UTF-8")]
  InvalidUtf8,

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
///
/// Text carries the streaming UTF-8 validator (the same one the receive path
/// uses) across the fragments of one message: §5.6 lets a fragment end
/// mid-codepoint, so only the assembled message must be valid, and the
/// incremental validator is exactly the right shape — feed each fragment, and
/// require a character boundary at `fin`.
#[derive(Debug, Clone)]
pub(crate) enum SendMessageState {
  /// Between messages.
  Idle,
  /// Inside a text message, validating its payload bytes as UTF-8.
  InText(crate::utf8::Utf8Validator),
  /// Inside a binary message (arbitrary bytes; no validation).
  InBinary,
}

/// Which frame the single outbound control slot ([`SendState::pending`]) holds.
///
/// The tag is what lets one buffer stand for two, and the reason is a property
/// of [`Connection::poll_transmit`] rather than of the RFC: a queued close is
/// drained FIRST and sets `close_sent`, after which `poll_transmit` answers
/// `None` for the life of the connection. So a pong that is pending when a
/// close is queued was already never going to reach the wire, and a pong owed
/// after one is queued was never going to either. One tagged slot stores
/// exactly what two untagged slots could ever transmit — 127 bytes instead of
/// 254, per connection, empty almost always.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum PendingKind {
  /// A close frame: the last frame this side puts on the wire.
  Close,
  /// A pong echoing a received ping (RFC 6455 §5.5.2).
  Pong,
}

/// The one protocol-generated control frame awaiting
/// [`Connection::poll_transmit`], and which kind it is.
///
/// Application-sent control frames do not come through here at all —
/// `encode_ping` / `encode_pong` serialize straight into the caller's buffer.
#[derive(Debug, Copy, Clone)]
pub(crate) struct PendingControl {
  pub(crate) kind: PendingKind,
  pub(crate) payload: [u8; MAX_CONTROL_PAYLOAD],
  pub(crate) len: u8,
}

#[derive(Debug)]
pub(crate) struct SendState {
  pub(crate) message: SendMessageState,
  /// The single outbound control slot — a close queued by the protocol or the
  /// application, or a pong owed for a received ping. See [`PendingKind`] for
  /// why one slot is enough for both.
  pub(crate) pending: Option<PendingControl>,
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
      pending: None,
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
  /// own close) is dropped. A pong holding the slot IS displaced: see
  /// [`PendingKind`].
  pub(crate) fn queue_close(&mut self, code: CloseCode, reason: &str) {
    if matches!(self.pending_kind(), Some(PendingKind::Close)) {
      return;
    }
    let mut payload = [0u8; MAX_CONTROL_PAYLOAD];
    let len = match encode_close_payload(code, reason, &mut payload) {
      Ok(n) => n,
      Err(_) => encode_close_payload(code, "", &mut payload).unwrap_or_default(),
    };
    self.pending = Some(PendingControl {
      kind: PendingKind::Close,
      payload,
      len: u8::try_from(len).unwrap_or(0),
    });
    self.queued_code = Some(code);
  }

  /// Replaces whatever the slot holds — including an EARLIER close — with this
  /// failure close. The receive path's `fail` is the only caller: the failure
  /// code is what must reach the wire, or a peer would see the benign close of
  /// a connection we are failing.
  pub(crate) fn force_close(&mut self, code: CloseCode) {
    self.pending = None;
    self.queued_code = None;
    self.queue_close(code, "");
  }

  /// What the outbound control slot holds, if anything.
  pub(crate) const fn pending_kind(&self) -> Option<PendingKind> {
    match self.pending {
      Some(PendingControl { kind, .. }) => Some(kind),
      None => None,
    }
  }

  /// Offers a pong echo to the outbound slot; a pong already there is replaced.
  ///
  /// A queued CLOSE is never displaced, and the refusal lives HERE, in the only
  /// writer that can put a pong in the slot, rather than at the call site — a
  /// second caller inherits it instead of having to remember it. Displacing a
  /// close would delete a frame the peer is waiting for; queueing behind one
  /// would store bytes `poll_transmit` can no longer reach.
  pub(crate) fn offer_pong(&mut self, payload: [u8; MAX_CONTROL_PAYLOAD], len: u8) {
    if matches!(self.pending_kind(), Some(PendingKind::Close)) {
      return;
    }
    self.pending = Some(PendingControl {
      kind: PendingKind::Pong,
      payload,
      len,
    });
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
  /// Stable lowercase name.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::TextStart => "text_start",
      Self::BinaryStart => "binary_start",
      Self::Continue => "continue",
    }
  }

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
  // `#[inline]` here is load-bearing for `tests/no_panic.rs`, not a codegen
  // guess. This crate's `no-panic` step runs WITHOUT fat LTO on purpose (see
  // that file's LTO section and the `no-panic` job): its shims wrap leaves that
  // inline into the shim under the default profile, and the missing LTO is what
  // the lie-check's reason-grep stands on. The `prepare_*` shims wrap a
  // GENERIC method whose tree spans several functions, and without this
  // annotation the release link reds with `ERROR[no-panic]: detected panic in
  // function `shim_prepare_text`` and the same for `shim_prepare_binary` —
  // core's panic paths are still separate codegen units. MEASURED, by bisecting
  // the set: `plan_data_send` alone still reds both shims; `prepare_fragment` +
  // `plan_data_send` links clean; so those two are the minimum and the two
  // one-line forwarders below carry it as well, because a proof that depends on
  // the optimizer's CGU placement for a one-liner is a proof on a knife edge.
  // (`CARGO_PROFILE_RELEASE_LTO=fat` also links clean, which is how the failure
  // was identified as cross-CGU opacity rather than a real panic edge — but
  // moving this crate's step to fat LTO is exactly what its comments forbid.)
  #[inline]
  pub fn prepare_fragment(
    &mut self,
    kind: FragmentKind,
    fin: bool,
    payload: &mut [u8],
  ) -> Result<EncodedHeader, EncodeError> {
    let (opcode, starting) = kind.into_parts();
    // Validate (lifecycle, sequencing, and outbound text UTF-8) BEFORE writing
    // any header bytes or masking the payload in place: on rejection the
    // payload buffer stays byte-identical and the fragmentation state unchanged,
    // so the caller can retry the same fragment with corrected bytes.
    let next = self.plan_data_send(opcode, starting, fin, payload)?;

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
    self.send.message = next;
    Ok(EncodedHeader {
      buf,
      len: u8::try_from(len).unwrap_or(0),
    })
  }

  /// A whole unfragmented **binary** message with no payload copy: the
  /// zero-copy twin of [`encode_binary`](Connection::encode_binary).
  ///
  /// This is the path a vectored driver wants. `encode_binary` copies the
  /// payload into `out` behind the header; this masks `payload` **in place**
  /// (clients; servers leave it untouched) and hands back the header for the
  /// driver to write first — `writev([header.as_slice(), payload])`, or an
  /// `io_uring` `IORING_OP_WRITEV` over the same two iovecs. For a 64 KiB
  /// message that is 64 KiB of `memcpy` per send that does not happen.
  ///
  /// It is exactly `prepare_fragment(FragmentKind::BinaryStart, true, payload)`
  /// and exists because that spelling reads like fragmentation when what it
  /// says is "one whole message". The lifecycle and sequencing rules are
  /// [`prepare_fragment`](Connection::prepare_fragment)'s, unchanged: a whole
  /// message is a `*Start` that is also `fin`, so it requires no message in
  /// progress and leaves none.
  ///
  /// Rejection leaves `payload` byte-identical and the fragmentation state
  /// unchanged — everything fallible is checked before a byte is masked — so
  /// the same buffer can be retried.
  #[inline]
  pub fn prepare_binary(&mut self, payload: &mut [u8]) -> Result<EncodedHeader, EncodeError> {
    self.prepare_fragment(FragmentKind::BinaryStart, true, payload)
  }

  /// A whole unfragmented **text** message with no payload copy: the zero-copy
  /// twin of [`encode_text`](Connection::encode_text). See
  /// [`prepare_binary`](Connection::prepare_binary) for what "no copy" buys and
  /// how the header is written.
  ///
  /// **The payload is `&mut [u8]`, not `&str`**, and the difference is forced
  /// rather than chosen: masking rewrites the bytes in place, and a masked
  /// UTF-8 string is not UTF-8 — writing those bytes through a `&mut str` would
  /// break the type's invariant, which this crate cannot do at all
  /// (`forbid(unsafe_code)`) and should not do in any case. Validity is checked
  /// instead: the bytes must be valid UTF-8 (RFC 6455 §8.1) and the message
  /// must end on a character boundary, both BEFORE anything is masked, so a
  /// rejected send leaves the buffer byte-identical for a retry. Pass
  /// `some_string.as_bytes()` through a mutable buffer you own.
  #[inline]
  pub fn prepare_text(&mut self, payload: &mut [u8]) -> Result<EncodedHeader, EncodeError> {
    self.prepare_fragment(FragmentKind::TextStart, true, payload)
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
  ///
  /// **The queued close is the last frame this side sends.** A pong owed for a
  /// Ping received between this call and the peer's close echo is therefore not
  /// sent, and RFC 6455 does not license that: §5.5.1 forbids only further
  /// *data* frames after a Close, and §5.5.2's exemption from the Pong — "unless
  /// it already received a Close frame" — is keyed on having RECEIVED one,
  /// which this endpoint has not. It is a deliberate simplification of this
  /// crate's, recorded here so a driver that needs the pong knows to send it
  /// itself with [`encode_pong`](Connection::encode_pong) — the connection
  /// still surfaces the [`Ping`](crate::connection::Event::Ping) event, so the
  /// payload §5.5.3 requires the echo to carry is in the caller's hands.
  ///
  /// The protocol's OWN closes are not in this position: an echo answers a
  /// Close we received (§5.5.2 exempts it outright) and a failure close is
  /// §7.1.7's, which ends the connection rather than continuing it.
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
  ///
  /// Once the close drains, this answers `None` for the life of the connection.
  /// That is THIS crate's rule and not RFC 6455 §5.5.1's, which forbids only
  /// further *data* frames after a Close ("The application MUST NOT send any
  /// more data frames after sending a Close frame"). On the two paths the
  /// protocol itself queues a close it is also the RFC's: an echo answers a
  /// Close we RECEIVED, and §5.5.2 exempts an endpoint that "already received a
  /// Close frame" from the Pong it would otherwise owe; a failure close is
  /// §7.1.7's, after which the endpoint proceeds to _Close the WebSocket
  /// Connection_ and "MUST NOT continue to attempt to process data" from the
  /// peer. After a caller's own [`close`](Connection::close) it is neither —
  /// see that method.
  pub fn poll_transmit(&mut self, now: I, out: &mut [u8]) -> Result<Option<usize>, EncodeError> {
    // Close first, and then nothing: see the note above for which rule that is.
    if !self.send.close_sent {
      if let Some(pending) = self.send.pending
        && matches!(pending.kind, PendingKind::Close)
      {
        let len = usize::from(pending.len);
        let n = self.write_frame(
          Opcode::Close,
          true,
          false,
          pending.payload.get(..len).unwrap_or(&[]),
          out,
        )?;
        self.send.close_sent = true;
        self.send.pending = None;
        // Arm the close deadline NOW (at drain time, not at close() time).
        self.close_deadline = now.checked_add_duration(self.config.close_timeout);
        return Ok(Some(n));
      }
    } else {
      return Ok(None);
    }
    // The slot's other tenant. Matched on the tag rather than inferred from the
    // arm above having returned: one entrance, one condition, stated.
    if let Some(pending) = self.send.pending
      && matches!(pending.kind, PendingKind::Pong)
    {
      let len = usize::from(pending.len);
      let n = self.write_frame(
        Opcode::Pong,
        true,
        false,
        pending.payload.get(..len).unwrap_or(&[]),
        out,
      )?;
      // Refill the slot from the overflow queue so the next `poll_transmit`
      // emits the following pong (every ping answered where a heap exists).
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      {
        self.send.pending =
          self
            .recv
            .pong_overflow
            .pop_front()
            .map(|(payload, len)| PendingControl {
              kind: PendingKind::Pong,
              payload,
              len,
            });
      }
      #[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
      {
        self.send.pending = None;
      }
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

  /// Lifecycle + fragmentation-sequencing check WITHOUT payload validation.
  /// Used by the compressed-send path, whose payload bytes are a DEFLATE stream
  /// (validated post-inflation on the receive side), never raw UTF-8 — hence
  /// the gate: without `deflate` it has no caller.
  #[cfg(feature = "deflate")]
  fn check_data_send(&self, starting: bool) -> Result<(), EncodeError> {
    if !matches!(self.lifecycle, Lifecycle::Open) {
      return Err(EncodeError::Closing);
    }
    match (starting, &self.send.message) {
      (true, SendMessageState::Idle) => Ok(()),
      (false, SendMessageState::InText(_) | SendMessageState::InBinary) => Ok(()),
      _ => Err(EncodeError::FragmentSequence),
    }
  }

  /// Computes the fragmentation state to commit AFTER a (plaintext) data frame
  /// is successfully written, validating lifecycle, sequencing, and — for text
  /// — that the payload keeps the assembled message valid UTF-8 (RFC 6455
  /// §8.1). Reads state only; the caller commits the returned state once all
  /// fallible work (the write, and for `prepare_fragment` the in-place mask)
  /// has succeeded, so a rejected send leaves the fragmentation state — and the
  /// payload buffer — untouched for a retry.
  ///
  /// §5.6 allows a single fragment to split a codepoint, so a non-`fin`
  /// fragment may end mid-character; only a `fin` fragment must land on a
  /// character boundary.
  #[inline]
  fn plan_data_send(
    &self,
    opcode: Opcode,
    starting: bool,
    fin: bool,
    payload: &[u8],
  ) -> Result<SendMessageState, EncodeError> {
    if !matches!(self.lifecycle, Lifecycle::Open) {
      return Err(EncodeError::Closing);
    }
    match (starting, &self.send.message) {
      (true, SendMessageState::Idle) => {
        if matches!(opcode, Opcode::Text) {
          let mut validator = crate::utf8::Utf8Validator::new();
          Self::validate_text_fragment(&mut validator, fin, payload)?;
          Ok(if fin {
            SendMessageState::Idle
          } else {
            SendMessageState::InText(validator)
          })
        } else {
          Ok(if fin {
            SendMessageState::Idle
          } else {
            SendMessageState::InBinary
          })
        }
      }
      (false, SendMessageState::InText(validator)) => {
        let mut validator = validator.clone();
        Self::validate_text_fragment(&mut validator, fin, payload)?;
        Ok(if fin {
          SendMessageState::Idle
        } else {
          SendMessageState::InText(validator)
        })
      }
      (false, SendMessageState::InBinary) => Ok(if fin {
        SendMessageState::Idle
      } else {
        SendMessageState::InBinary
      }),
      _ => Err(EncodeError::FragmentSequence),
    }
  }

  /// Feeds one text fragment's bytes through the message's UTF-8 validator. A
  /// `fin` fragment additionally requires a character boundary (the message
  /// may not end mid-codepoint).
  fn validate_text_fragment(
    validator: &mut crate::utf8::Utf8Validator,
    fin: bool,
    payload: &[u8],
  ) -> Result<(), EncodeError> {
    if validator.feed(payload).is_err() {
      return Err(EncodeError::InvalidUtf8);
    }
    if fin && !validator.is_boundary() {
      return Err(EncodeError::InvalidUtf8);
    }
    Ok(())
  }

  fn encode_data(
    &mut self,
    opcode: Opcode,
    starting: bool,
    fin: bool,
    payload: &[u8],
    out: &mut [u8],
  ) -> Result<usize, EncodeError> {
    let next = self.plan_data_send(opcode, starting, fin, payload)?;
    let n = self.write_frame(opcode, fin, false, payload, out)?;
    self.send.message = next;
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

  /// A safe upper bound on the sync-flushed DEFLATE output for `len` input
  /// bytes. DEFLATE's worst case is stored (uncompressed) blocks: 5 bytes of
  /// header per 65 535-byte block, plus a handful of bytes for the final
  /// bit-alignment and the (stripped) sync-flush boundary. The generous
  /// per-message slack keeps this bound safe across miniz_oxide's block
  /// placement choices; the regression tests pin it against incompressible
  /// (uniformly random) payloads.
  pub(crate) const fn worst_case_len(len: usize) -> usize {
    let blocks = len.div_euclid(65_535).saturating_add(1);
    len
      .saturating_add(blocks.saturating_mul(5))
      .saturating_add(64)
  }

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

    // TRANSACTIONALITY: every fallible check must precede the compressor
    // mutation. Under context takeover the compressor's sliding window is
    // shared peer-visible state — once `compress_message` runs, the message
    // is committed to that history, and a retry after a late failure would
    // compress against bytes the peer's inflater never received. So the
    // output buffer is preflighted against the worst-case encoded size; the
    // actual frame is then guaranteed to fit and `write_frame` cannot fail.
    let needed_worst =
      crate::constants::MAX_FRAME_HEADER.saturating_add(compress::worst_case_len(payload.len()));
    if out.len() < needed_worst {
      return Err(EncodeError::BufferTooSmall(BufferTooSmallDetail::new(
        needed_worst,
        out.len(),
      )));
    }

    // Determine whether to reset the compressor for this message.
    let no_takeover = if Ro::EXPECT_MASKED_INBOUND {
      params.server_no_context_takeover()
    } else {
      params.client_no_context_takeover()
    };

    // Lazily create the compressor, then compress. The box is TAKEN out of
    // `self` for the duration of the write so the scratch slice borrows a
    // local, not `self` — `write_frame` then borrows `self` disjointly and
    // no copy of the compressed payload is needed (a `to_vec` here would
    // duplicate an unbounded buffer after the takeover history had already
    // advanced).
    let had_compressor = self.send.deflate.is_some();
    let mut compressor = self
      .send
      .deflate
      .take()
      .unwrap_or_else(compress::CompressorBox::new);
    if no_takeover && had_compressor {
      compressor.reset();
    }
    let compressed = compressor.compress_message(payload);
    let written = self.write_frame(opcode, true, true, compressed, out);
    // Restore the compressor (and its takeover history) on EVERY path
    // before surfacing the write result.
    self.send.deflate = Some(compressor);
    let n = written?;
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

  /// A client compresses a text message; a server connection inflates it
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

  /// A client compresses a binary message; a server connection inflates it
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

  /// The RSV1 bit must be set on a compressed send.
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

  /// `encode_text_compressed` returns `EncodeError::CompressionUnavailable`
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

  /// When the server's outbound window bits < 15, `encode_text_compressed`
  /// returns `EncodeError::CompressionUnavailable` (miniz_oxide cannot honor the
  /// window constraint).
  #[test]
  fn outbound_bits_below_15_returns_compression_unavailable() {
    // Our SERVER declines sub-15 server-window offers outright, so
    // server-side params can no longer carry them — but a CLIENT can
    // still end up capped below 15: its valueless client_max_window_bits
    // hint lets a remote server pick e.g. 10. The client's outbound
    // direction uses client_max_window_bits → CompressionUnavailable.
    let offer = crate::negotiation::DeflateOffer::new();
    let params = crate::negotiation::parse_deflate_response(
      [b"permessage-deflate; client_max_window_bits=10".as_slice()],
      &offer,
    )
    .expect("a remote server may pick a smaller client window");
    assert_eq!(params.client_max_window_bits(), 10);

    let mut client = deflate_client(params);
    let mut out = [0u8; 128];
    assert!(matches!(
      client.encode_text_compressed("hello", &mut out),
      Err(EncodeError::CompressionUnavailable)
    ));
    assert!(matches!(
      client.encode_binary_compressed(b"hi", &mut out),
      Err(EncodeError::CompressionUnavailable)
    ));
  }

  /// With `no_context_takeover` on the send direction, two successive
  /// compressed messages are each independently decodable by a fresh-context
  /// inflater — verified by decoding both with a server that also negotiated
  /// no_context_takeover on the inbound side.
  #[test]
  fn no_context_takeover_reset_each_message_independently_decodable() {
    // Negotiate server_no_context_takeover: the server's outbound context
    // resets per message. The receiving client must also reset per message.
    let (params, _) = accept_deflate_offer(
      [b"permessage-deflate; server_no_context_takeover".as_slice()],
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

  /// Regression: a compressed send rejected for a too-small output
  /// buffer must NOT advance the compressor's context-takeover history — the
  /// retry with an adequate buffer must produce a stream a conformant peer
  /// inflater (which never saw the failed attempt) still decodes.
  #[test]
  fn buffer_too_small_compressed_send_is_retry_safe() {
    use miniz_oxide::{
      DataFormat, MZFlush,
      inflate::stream::{InflateState, inflate},
    };

    let mut server = deflate_server(default_params());
    let mut ref_state = InflateState::new_boxed(DataFormat::Raw);

    let mut decode = |wire: &[u8], expect: &[u8], label: &str| {
      let decoded = match FrameHeader::decode(wire).expect("decode header") {
        Decoded::Complete(d) => d,
        _ => panic!("incomplete frame header"),
      };
      let mut payload = wire[decoded.consumed()..].to_vec();
      payload.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
      let mut out = vec![0u8; 4096];
      let result = inflate(&mut ref_state, &payload, &mut out, MZFlush::None);
      assert_eq!(result.bytes_written, expect.len(), "{label}: length");
      assert_eq!(&out[..result.bytes_written], expect, "{label}: content");
    };

    // Seed the takeover history with one successful message.
    let mut wire = vec![0u8; 1024];
    let n = server
      .encode_text_compressed("first message", &mut wire)
      .unwrap();
    decode(&wire[..n], b"first message", "seed");

    // Fail a send on buffer size — repeatedly, to prove no cumulative damage.
    for _ in 0..3 {
      let mut tiny = [0u8; 8];
      let err = server
        .encode_text_compressed("second message", &mut tiny)
        .unwrap_err();
      assert!(matches!(err, EncodeError::BufferTooSmall(_)));
    }

    // Retry with room: the reference inflater (which saw only the seed) must
    // decode this and a follow-up cleanly — proving the failed attempts left
    // no trace in the shared compression context.
    let n = server
      .encode_text_compressed("second message", &mut wire)
      .unwrap();
    decode(&wire[..n], b"second message", "retry");
    let n = server
      .encode_text_compressed("third message", &mut wire)
      .unwrap();
    decode(&wire[..n], b"third message", "follow-up");
  }

  /// `worst_case_len` must dominate the actual sync-flushed output for
  /// incompressible inputs at and around block boundaries.
  #[test]
  fn worst_case_len_bounds_actual_output() {
    let mut compressor = compress::CompressorBox::new();
    let mut x: u32 = 0x9E37_79B9;
    for len in [0usize, 1, 64, 4096, 65_534, 65_535, 65_536, 131_072] {
      let mut data = vec![0u8; len];
      for b in &mut data {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
      }
      compressor.reset();
      let actual = compressor.compress_message(&data).len();
      let bound = compress::worst_case_len(len);
      assert!(
        actual <= bound,
        "len {len}: actual {actual} > bound {bound}"
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

  /// The two whole-message aliases, checked against the copying encoders they
  /// are the no-copy twin of: the same bytes on the wire, and the same
  /// fragmentation state left behind.
  ///
  /// The comparison is the assertion. `prepare_binary` reading like the main
  /// path is the whole reason it exists, so what has to hold is that it IS the
  /// main path — a driver that switches `encode_binary` for it must not have
  /// changed what the peer receives.
  #[test]
  fn prepare_binary_and_text_are_the_copying_encoders_without_the_copy() {
    for text in [false, true] {
      let body: &[u8] = if text { b"Hello" } else { &[0x00, 0xFF, 0x7F] };

      // The copying encoder, into its own buffer.
      let mut copying = client();
      let mut out = [0u8; 32];
      let n = if text {
        copying.encode_text("Hello", &mut out).unwrap()
      } else {
        copying.encode_binary(body, &mut out).unwrap()
      };
      let copied = out[..n].to_vec();

      // The no-copy twin, from an identically-seeded client so the mask keys
      // match frame for frame.
      let mut preparing = client();
      let mut payload = body.to_vec();
      let header = if text {
        preparing.prepare_text(&mut payload).unwrap()
      } else {
        preparing.prepare_binary(&mut payload).unwrap()
      };
      let mut vectored = header.as_slice().to_vec();
      vectored.extend_from_slice(&payload);

      assert_eq!(vectored, copied, "text={text}");

      // Both left the connection between messages, so a second whole message
      // is accepted by either.
      preparing.encode_binary(b"next", &mut out).unwrap();
      copying.encode_binary(b"next", &mut out).unwrap();
    }
  }

  /// `prepare_text` is `encode_text`'s §8.1 gate too, and it refuses BEFORE it
  /// masks: the rejected buffer is byte-identical, so the caller may fix the
  /// bytes and retry the same allocation. That ordering is what makes the
  /// no-copy path safe to offer as the default — a driver that masked first
  /// would hand back a buffer it had already scrambled.
  #[test]
  fn prepare_text_refuses_invalid_utf8_without_touching_the_buffer() {
    let mut conn = client();
    let mut payload = [0xFFu8, 0xFE];
    assert!(matches!(
      conn.prepare_text(&mut payload),
      Err(EncodeError::InvalidUtf8)
    ));
    assert_eq!(&payload, &[0xFF, 0xFE], "a refused send masks nothing");

    // Binary takes the same bytes, since §8.1 governs text alone.
    conn
      .prepare_binary(&mut payload)
      .expect("binary accepts arbitrary bytes");

    // And the connection is still usable for a text message afterwards.
    let mut good = *b"ok";
    conn.prepare_text(&mut good).expect("text after a refusal");
  }

  /// RFC 6455 §5.6: a fragment may split a codepoint — only the assembled
  /// message must be valid UTF-8. "é" (0xC3 0xA9) sent as TextStart(0xC3,
  /// fin=false) + Continue(0xA9, fin=true) is LEGAL and must keep working.
  #[test]
  fn text_fragments_may_split_mid_codepoint() {
    let mut conn = server();
    let mut out = [0u8; 32];
    conn
      .encode_fragment(FragmentKind::TextStart, false, &[0xC3], &mut out)
      .expect("a lead byte alone is a legal non-final fragment");
    conn
      .encode_fragment(FragmentKind::Continue, true, &[0xA9], &mut out)
      .expect("the continuation completes 'é' on a boundary");

    // The message reassembles to valid UTF-8 ("é") through a peer's recv path.
    use crate::connection::tests::{Ev, drain, fold_events, masked_frame, server as ref_server};
    let mut srv = ref_server();
    let start = masked_frame(crate::frame::Opcode::Text, false, &[0xC3]);
    let cont = masked_frame(crate::frame::Opcode::Continuation, true, &[0xA9]);
    let mut evs = drain(&mut srv, &start);
    evs.extend(drain(&mut srv, &cont));
    assert_eq!(
      fold_events(evs),
      [
        Ev::Start(crate::connection::MessageKind::Text, false),
        Ev::Text("é".into()),
        Ev::End,
      ]
    );
  }

  /// Invalid UTF-8 text bytes are rejected, and the fragmentation state is left
  /// unchanged: a failed START stays Idle (a fresh start still works); a failed
  /// CONTINUE stays in the text message (a valid continue still works).
  #[test]
  fn invalid_utf8_text_fragment_is_rejected() {
    let mut out = [0u8; 32];

    // Failed START → still Idle: a following valid TextStart succeeds.
    let mut conn = server();
    assert!(matches!(
      conn.encode_fragment(FragmentKind::TextStart, true, &[0xFF], &mut out),
      Err(EncodeError::InvalidUtf8)
    ));
    conn
      .encode_text("recovered", &mut out)
      .expect("a failed start left the connection Idle");

    // Failed CONTINUE → still InText: a following valid continue succeeds and
    // closes the message cleanly.
    let mut conn = server();
    conn
      .encode_fragment(FragmentKind::TextStart, false, b"ab", &mut out)
      .unwrap();
    assert!(matches!(
      conn.encode_fragment(FragmentKind::Continue, false, &[0xFF], &mut out),
      Err(EncodeError::InvalidUtf8)
    ));
    conn
      .encode_fragment(FragmentKind::Continue, true, b"cd", &mut out)
      .expect("the failed continue left the text message in progress");
    // Message done: a new message may start.
    conn.encode_text("next", &mut out).unwrap();
  }

  /// A `fin` fragment that ends mid-codepoint is rejected (the message may not
  /// end mid-character), but the state is preserved so the remaining byte may
  /// be sent to finish the codepoint.
  #[test]
  fn fin_mid_codepoint_is_rejected() {
    let mut conn = server();
    let mut out = [0u8; 32];
    // Start "é" but stop after the lead byte.
    conn
      .encode_fragment(FragmentKind::TextStart, false, &[0xC3], &mut out)
      .unwrap();
    // fin on the lead byte alone (empty continuation) leaves a character in
    // flight → rejected.
    assert!(matches!(
      conn.encode_fragment(FragmentKind::Continue, true, &[], &mut out),
      Err(EncodeError::InvalidUtf8)
    ));
    // State preserved: supplying the trailing byte with fin completes "é".
    conn
      .encode_fragment(FragmentKind::Continue, true, &[0xA9], &mut out)
      .expect("the rejected fin left the in-flight codepoint intact");
  }

  /// `prepare_fragment` must reject invalid outbound text BEFORE it masks the
  /// payload in place: on rejection the buffer is byte-identical (unmasked).
  #[test]
  fn prepare_fragment_validates_before_masking() {
    let mut conn = client();
    let mut payload = [0xFFu8, 0x00, 0xC0];
    let before = payload;
    assert!(matches!(
      conn.prepare_fragment(FragmentKind::TextStart, true, &mut payload),
      Err(EncodeError::InvalidUtf8)
    ));
    assert_eq!(payload, before, "rejected payload must be left unmasked");

    // And the fragmentation state is untouched: a valid whole text send works.
    let mut out = [0u8; 32];
    conn
      .encode_text("ok", &mut out)
      .expect("a rejected prepare_fragment left the connection Idle");
  }

  /// Binary fragments carry arbitrary bytes — no UTF-8 constraint (§5.6 only
  /// governs text).
  #[test]
  fn binary_fragments_accept_arbitrary_bytes() {
    let mut conn = server();
    let mut out = [0u8; 32];
    conn
      .encode_fragment(FragmentKind::BinaryStart, false, &[0xFF, 0xFE], &mut out)
      .expect("binary start accepts non-UTF-8 bytes");
    conn
      .encode_fragment(FragmentKind::Continue, true, &[0x80, 0xC0], &mut out)
      .expect("binary continuation accepts non-UTF-8 bytes");

    // prepare_fragment (client) masks arbitrary binary bytes without validation.
    let mut conn = client();
    let mut payload = [0xFFu8, 0xC0];
    conn
      .prepare_fragment(FragmentKind::BinaryStart, true, &mut payload)
      .expect("binary prepare_fragment accepts non-UTF-8 bytes");
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

  /// `SendState`'s slot rules, asserted on the state directly rather than
  /// through a `Connection`, because one of them has no reachable sequence.
  ///
  /// "The first queued close wins" is guarded in `queue_close`, and every path
  /// that reaches it is ALREADY guarded elsewhere: `Connection::close` refuses
  /// unless the lifecycle is `Open`, the peer-close echo is behind
  /// `if !matches!(lifecycle, CloseSent)`, and `fail` goes through
  /// `force_close`, which clears the slot first. Deleting the guard therefore
  /// reds nothing at the `Connection` level — measured, not assumed — and an
  /// unreachable guard with no subject is one a later caller can walk past
  /// without a single test disagreeing. Naming it here is what keeps the rule
  /// stated: a fourth writer that queues a second close must not silently
  /// replace the first, because `queued_code` is what `handle_timeout` reports
  /// and the payload is what the peer reads.
  #[test]
  fn the_close_slot_takes_a_pong_s_place_and_then_keeps_its_own() {
    let mut send = SendState::new();

    // A pong owed, then a close: the close TAKES the slot. This is the
    // displacement the single-slot design turns on — the pong was already
    // unreachable, since `poll_transmit` answers `None` after a close drains.
    send.offer_pong([b'p'; MAX_CONTROL_PAYLOAD], 1);
    assert_eq!(send.pending_kind(), Some(PendingKind::Pong));
    send.queue_close(CloseCode::GoingAway, "first");
    assert_eq!(send.pending_kind(), Some(PendingKind::Close));
    assert_eq!(send.queued_code, Some(CloseCode::GoingAway));
    let first = send.pending.expect("a close is queued");
    assert_eq!(&first.payload[..usize::from(first.len)], b"\x03\xE9first");

    // A SECOND close does not replace it — neither its code nor its payload.
    send.queue_close(CloseCode::PolicyViolation, "second");
    assert_eq!(send.queued_code, Some(CloseCode::GoingAway));
    let still = send.pending.expect("the first close is still queued");
    assert_eq!(&still.payload[..usize::from(still.len)], b"\x03\xE9first");

    // Nor does a pong owed afterwards.
    send.offer_pong([b'q'; MAX_CONTROL_PAYLOAD], 1);
    assert_eq!(send.pending_kind(), Some(PendingKind::Close));
    let after = send.pending.expect("the first close is still queued");
    assert_eq!(&after.payload[..usize::from(after.len)], b"\x03\xE9first");

    // `force_close` is the one door that DOES replace a queued close: the
    // failure code is what has to reach the wire.
    send.force_close(CloseCode::ProtocolError);
    assert_eq!(send.queued_code, Some(CloseCode::ProtocolError));
    let failed = send.pending.expect("the failure close is queued");
    assert_eq!(&failed.payload[..usize::from(failed.len)], b"\x03\xEA");
  }

  /// The direction the shared outbound slot resolves in, pinned from the
  /// outside. `pending_close` and `pending_pong` used to be two fields, so
  /// neither could overwrite the other and nothing had to say which wins; they
  /// are one tagged slot now, and a pong that took it from a queued close would
  /// DELETE a close frame the peer is waiting on — a wedged handshake, not a
  /// dropped echo. The refusal lives in `SendState::offer_pong`; this is the
  /// assertion that names the frame it protects.
  ///
  /// Note what makes this test's subject its own: the sibling above drains a
  /// close that was queued while a pong was already pending, which the OLD
  /// two-field code also answered `Some(close)` then `None` to. This one queues
  /// the close FIRST and lands the ping after it, which is the sequence only
  /// the tag decides.
  #[test]
  fn a_pong_owed_after_a_queued_close_does_not_displace_it() {
    use crate::frame::{Opcode, mask as apply_mask};
    let mut conn = server();
    conn
      .close(CloseCode::GoingAway, "bye")
      .expect("close on an open connection");

    // A ping arriving AFTER our close is queued but BEFORE it drains.
    let key = [4, 4, 4, 4];
    let h = FrameHeader::new(Opcode::Ping, 1).with_mask(Some(key));
    let mut bytes = vec![0u8; h.header_len() + 1];
    let n = h.encode(&mut bytes).unwrap();
    bytes[n] = b'q';
    apply_mask(&mut bytes[n..], key, 0);
    {
      let mut events = conn.handle(TestInstant(0), &mut bytes).unwrap();
      // The Ping event is still surfaced: the caller can answer it itself.
      assert!(matches!(
        events.next(),
        Some(crate::connection::Event::Ping(_))
      ));
      assert!(events.next().is_none());
    }

    // The CLOSE drains, carrying OUR code and reason — not a pong.
    let mut out = [0u8; 64];
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("the queued close must still be there");
    assert_eq!(out[0], 0x88, "opcode must be Close, not Pong (0x8A)");
    let decoded = match FrameHeader::decode(&out[..n]).unwrap() {
      Decoded::Complete(d) => d,
      _ => panic!("incomplete close frame"),
    };
    let body = &out[decoded.consumed()..n];
    assert_eq!(&body[..2], &[0x03, 0xE9], "close code 1001 (GoingAway)");
    assert_eq!(&body[2..], b"bye");
    // And nothing behind it.
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none()
    );
  }

  /// Regression (Autobahn 2.10): several pings arriving in one `handle` batch
  /// each get their own pong (where `alloc` is available — every tier the
  /// suite runs on). The single-slot design coalesced all but the last.
  #[cfg(any(feature = "alloc", feature = "std"))]
  #[test]
  fn ping_flood_in_one_batch_pongs_every_ping_in_order() {
    use crate::frame::{Opcode, mask as apply_mask};
    let mut conn = server();

    // Ten masked pings with distinct payloads, glued into one buffer.
    let key = [9, 8, 7, 6];
    let mut bytes = Vec::new();
    let payloads: Vec<Vec<u8>> = (0..10)
      .map(|i| format!("payload-{i}").into_bytes())
      .collect();
    for p in &payloads {
      let h = FrameHeader::new(Opcode::Ping, p.len() as u64).with_mask(Some(key));
      let mut f = vec![0u8; h.header_len() + p.len()];
      let n = h.encode(&mut f).unwrap();
      f[n..].copy_from_slice(p);
      apply_mask(&mut f[n..], key, 0);
      bytes.extend(f);
    }

    {
      let mut events = conn.handle(TestInstant(0), &mut bytes).unwrap();
      while events.next().is_some() {}
    }

    // Drain every queued pong: ten frames, payloads in arrival order, unmasked.
    let mut out = [0u8; 64];
    let mut got: Vec<Vec<u8>> = Vec::new();
    while let Some(n) = conn.poll_transmit(TestInstant(0), &mut out).unwrap() {
      let decoded = match FrameHeader::decode(&out[..n]).unwrap() {
        Decoded::Complete(d) => d,
        _ => panic!("incomplete pong frame"),
      };
      assert_eq!(decoded.header().opcode(), Opcode::Pong);
      assert!(
        decoded.header().mask().is_none(),
        "server pongs are unmasked"
      );
      got.push(out[decoded.consumed()..n].to_vec());
    }
    assert_eq!(got, payloads, "every ping must be answered, in order");
  }

  /// Regression: a ping FLOOD must not grow memory without bound.
  /// Past the overflow cap the oldest queued echoes are shed (RFC 6455 §5.5.3
  /// lets an endpoint answer only the most recent ping), so draining after a
  /// 100-ping flood yields a bounded pong count whose LAST echo answers the
  /// LAST ping.
  #[cfg(any(feature = "alloc", feature = "std"))]
  #[test]
  fn ping_flood_beyond_the_cap_sheds_oldest_and_stays_bounded() {
    use crate::frame::{Opcode, mask as apply_mask};
    let mut conn = server();

    let key = [1, 3, 5, 7];
    let mut bytes = Vec::new();
    let payloads: Vec<Vec<u8>> = (0..100).map(|i| format!("p{i:03}").into_bytes()).collect();
    for p in &payloads {
      let h = FrameHeader::new(Opcode::Ping, p.len() as u64).with_mask(Some(key));
      let mut f = vec![0u8; h.header_len() + p.len()];
      let n = h.encode(&mut f).unwrap();
      f[n..].copy_from_slice(p);
      apply_mask(&mut f[n..], key, 0);
      bytes.extend(f);
    }

    {
      let mut events = conn.handle(TestInstant(0), &mut bytes).unwrap();
      while events.next().is_some() {}
    }

    let mut out = [0u8; 64];
    let mut got: Vec<Vec<u8>> = Vec::new();
    while let Some(n) = conn.poll_transmit(TestInstant(0), &mut out).unwrap() {
      let decoded = match FrameHeader::decode(&out[..n]).unwrap() {
        Decoded::Complete(d) => d,
        _ => panic!("incomplete pong frame"),
      };
      assert_eq!(decoded.header().opcode(), Opcode::Pong);
      got.push(out[decoded.consumed()..n].to_vec());
    }

    // Bounded: one pending slot + the capped overflow queue.
    assert!(
      got.len() <= 17,
      "flood must shed past the cap; drained {} pongs",
      got.len()
    );
    // The most recent ping is always answered (§5.5.3), and answered last.
    assert_eq!(
      got.last().map(Vec::as_slice),
      Some(b"p099".as_slice()),
      "the newest ping's echo must survive the shed"
    );
  }
}
