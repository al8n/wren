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

  /// `now` is earlier than an instant this connection has already been given.
  /// See [`Connection::poll_transmit`].
  #[error("`now` is earlier than an instant this connection has already been given")]
  ClockWentBackwards,

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

/// The outbound control frames awaiting [`Connection::poll_transmit`].
///
/// **Two slots, not one, and the second is a conformance requirement rather
/// than a convenience.** An earlier revision of this crate merged them, on the
/// reasoning that `poll_transmit` drained a queued close first and answered
/// `None` for ever after, so an owed pong could never reach the wire anyway.
/// That reasoning described the code and not RFC 6455: §5.5.2 (line 2042 of
/// `.rfc-cache/rfc6455.txt`) makes the Pong a MUST that runs until *this*
/// endpoint "already received a Close frame", and a close this endpoint SENT is
/// not one it received. §5.5.3 (line 2064) permits answering only the most
/// recently processed Ping; it does not permit answering none. So the machine
/// has to be able to hold a queued close and an owed pong at the same time, and
/// two slots is what that costs — 254 bytes rather than 127. A smaller
/// `Connection` does not license a nonconformance.
///
/// Application-sent control frames do not come through here at all:
/// `encode_ping` / `encode_pong` serialize straight into the caller's buffer.
#[derive(Debug)]
pub(crate) struct SendState {
  pub(crate) message: SendMessageState,
  /// The close frame queued by the protocol or the application. Ordered against
  /// [`Self::pending_pong`] by QUEUE TIME, not by priority — see
  /// [`Connection::poll_transmit`] and [`Self::pongs_before_close`].
  pub(crate) pending_close: Option<([u8; MAX_CONTROL_PAYLOAD], u8)>,
  /// The pong owed for the most recently processed ping (§5.5.3). On the heap
  /// tiers `RecvState::pong_overflow` queues the ones behind it.
  pub(crate) pending_pong: Option<([u8; MAX_CONTROL_PAYLOAD], u8)>,
  /// How many owed pongs were queued BEFORE the close was, and so drain ahead
  /// of it. Frozen by `queue_close` and only decremented from there — by drains
  /// and by shedding — so a Ping arriving after the close cannot join the group
  /// on its own, which is what bounds the close. The one exception is the
  /// epoch boundary: the peer's Close arriving with ours still queued
  /// recomputes this ONCE from the live queue and turns the connection
  /// terminal, so it cannot grow again. See [`Connection::poll_transmit`] for
  /// the ordering it implements, both epochs' bounds, and why a counter rather
  /// than a flag.
  pub(crate) pongs_before_close: u8,
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
      pending_pong: None,
      pongs_before_close: 0,
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
  ///
  /// It does not touch the pong slot. The two frames are independent
  /// obligations: §5.5.1 (line 2002) bans further *data* frames after a Close,
  /// not control frames, and §5.5.2's Pong MUST runs until a Close is
  /// RECEIVED.
  pub(crate) fn queue_close(&mut self, code: CloseCode, reason: &str, queued_behind: usize) {
    if self.pending_close.is_some() {
      return;
    }
    // Freeze the pongs already owed. They drain ahead of this close; anything a
    // later Ping owes drains behind it. `queued_behind` is what
    // `RecvState::queued_pongs` reports — zero on the bare tier, which has no
    // queue — and the slot itself is the `+1`.
    let owed = usize::from(self.pending_pong.is_some()).saturating_add(queued_behind);
    self.pongs_before_close = u8::try_from(owed).unwrap_or(u8::MAX);
    let mut payload = [0u8; MAX_CONTROL_PAYLOAD];
    let len = match encode_close_payload(code, reason, &mut payload) {
      Ok(n) => n,
      Err(_) => encode_close_payload(code, "", &mut payload).unwrap_or_default(),
    };
    self.pending_close = Some((payload, u8::try_from(len).unwrap_or(0)));
    self.queued_code = Some(code);
  }

  /// Replaces an EARLIER queued close with this failure close. The receive
  /// path's `fail` is the only caller: the failure code is what must reach the
  /// wire, or a peer would see the benign close of a connection we are failing.
  ///
  /// Nothing is left queued ahead of it: the receive path's `fail` clears the
  /// owed pongs first, because §7.1.7 (line 2399 of `.rfc-cache/rfc6455.txt`)
  /// has an endpoint instructed to _Fail the WebSocket Connection_ proceed to
  /// close it and "MUST NOT continue to attempt to process data". Passing `0`
  /// here says the same thing about the ordering group.
  pub(crate) fn force_close(&mut self, code: CloseCode) {
    self.pending_close = None;
    self.queued_code = None;
    self.queue_close(code, "", 0);
  }

  /// Records the pong owed for a received ping, replacing one already owed —
  /// §5.5.3 (line 2064) permits answering "only the most recently processed
  /// Ping frame", which is what the single slot does on the bare tier. A queued
  /// close is not consulted: it is a different frame with its own slot.
  pub(crate) fn offer_pong(&mut self, payload: [u8; MAX_CONTROL_PAYLOAD], len: u8) {
    // Replacing an occupied slot SHEDS drain position 0. If a close is queued,
    // position 0 is inside the frozen prefix whenever that prefix is non-empty,
    // so the prefix loses an entry and must shrink with it — otherwise the
    // replacement (a post-close pong by identity) inherits the departed one's
    // place ahead of the close. `saturating_sub` IS the "iff the prefix is
    // non-empty" condition; a separate `>= 1` guard would restate it and be a
    // guard with no subject.
    //
    // On the heap tiers this branch never fires: `queue_pong` reaches
    // `offer_pong` only with an empty slot. One site serves both tiers with no
    // `cfg`, and a decrement outside a close window is harmless — `queue_close`
    // recomputes the count from the live queue, and `poll_transmit` reads it
    // only while a close is waiting.
    if self.pending_pong.replace((payload, len)).is_some() {
      self.pongs_before_close = self.pongs_before_close.saturating_sub(1);
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
  /// **The close is not the last frame this side sends.** A Ping that arrives
  /// between this call and the peer's Close is still answered: §5.5.2 (line
  /// 2042 of `.rfc-cache/rfc6455.txt`) makes the Pong a MUST "unless it already
  /// received a Close frame", and a Close this endpoint SENT is not one it
  /// received. That echo drains from
  /// [`poll_transmit`](Connection::poll_transmit) **behind** this close, because
  /// it was queued behind it — a Ping arriving after `close()` cannot overtake
  /// the Close, which is what stops a peer starving it. A pong already owed when
  /// this is called goes first, for the same queue-time reason. The caller may
  /// also answer by hand with [`encode_pong`](Connection::encode_pong), which
  /// works in this state.
  ///
  /// Data sends do stop here, and that half IS §5.5.1's (line 2002): "The
  /// application MUST NOT send any more data frames after sending a Close
  /// frame."
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
    let queued_behind = self.recv.queued_pongs();
    self.send.queue_close(code, reason, queued_behind);
    self.lifecycle = Lifecycle::CloseSent;
    Ok(())
  }

  /// Drains one queued protocol frame (owed pong → close → keepalive ping) into
  /// `out`. Returns the byte count, or `None` when nothing is pending. Arms
  /// `close_deadline` at the moment the close frame actually drains.
  ///
  /// Answers [`EncodeError::ClockWentBackwards`] when `now` is EARLIER than an
  /// instant already handed to this connection; an equal instant is fine, and
  /// the refusal writes nothing and dequeues nothing. The rule, and the
  /// `assert-contracts` exception to "returns rather than panics", is on
  /// [`crate::time::Instant`].
  ///
  /// # The order, derived
  ///
  /// **Queue-time first-in-first-out between the two slots.** Whichever of the
  /// owed pong and the queued close was queued first drains first, and a Ping
  /// that arrives after `close()` cannot overtake the Close — until the peer's
  /// own Close arrives with ours still queued, which promotes every surviving
  /// echo ahead of it exactly once (see the two-epoch bound below). Neither
  /// RFC 6455 clause forbids either order — §5.5.1 (line 2002 of
  /// `.rfc-cache/rfc6455.txt`) bans only further *data* frames after a Close —
  /// so the order is chosen, and it is chosen for liveness:
  ///
  /// * §5.5.2 (line 2043) asks for the Pong "as soon as is practical", and for
  ///   a Ping received while our Close was queued but not yet on the wire, the
  ///   next frame written IS the earliest practical one. So a pre-close pong
  ///   goes first.
  /// * But **unconditional** pong priority permits unbounded Close starvation.
  ///   A driver that alternates one inbound Ping with exactly one
  ///   `poll_transmit` emits a Pong every time and never reaches its Close, so
  ///   `close_deadline` never arms. The queue cap does not help: only one pong
  ///   is outstanding at a time. This crate cannot assume a drain-to-`None`
  ///   schedule — the public API neither enforces nor can express one.
  ///
  /// # The invariant, on every tier
  ///
  /// While a close is queued and undrained, **the first `pongs_before_close`
  /// entries in drain order are exactly the surviving pongs that were queued
  /// before it.** Drain order is the slot (position 0), then `pong_overflow`
  /// front to back (positions 1..). Three things maintain it, and the third is
  /// the one an earlier revision was missing:
  ///
  /// * `queue_close` FREEZES the count from the live queue;
  /// * a drain DECREMENTS it;
  /// * and SHEDDING an entry that lies inside the prefix decrements it too —
  ///   `offer_pong` when it replaces an occupied slot (position 0, the bare
  ///   tier), and `queue_pong` when a full overflow queue evicts its front
  ///   (position 1, the heap tiers). Without that, the replacement inherits the
  ///   departed entry's place ahead of the close, and the invariant is false
  ///   exactly on the tiers capable of replacement. §5.5.3 (line 2064) permits
  ///   dropping the older echo; it does not permit the newer one to overtake
  ///   the close.
  ///
  /// # The bound, in two epochs
  ///
  /// The count is frozen at `close()` and only SHRINKS — by drains and by
  /// shedding — while ours is the only Close in play. It is NOT monotone over
  /// the connection's life, and a bound stated as if it were is false:
  /// `Events::step` RECOMPUTES it once, from the live queue, when the peer's
  /// Close arrives with our close still queued. `close(); 17 Pings; peer Close`
  /// takes it from 0 to 17 and moves the Close from poll 1 to poll 18. The
  /// promotion is deliberate — those echoes were owed for Pings that arrived
  /// before the peer's Close, §5.5.2 does not let a later Close cancel an
  /// obligation that already existed, and there is still a frame ahead of them
  /// to be written — so the bound is stated from each epoch's start instead:
  ///
  /// * **Before any peer Close:** the Close is emitted within
  ///   `pongs_before_close + 1` polls of `close()` — at most
  ///   `MAX_PENDING_PONGS + 1 + 1` = 18 on the heap tiers, at most 2 on the
  ///   bare one, and exactly 1 when nothing was owed.
  /// * **After the promotion:** within the recomputed count + 1 polls of the
  ///   peer's Close. The recomputation reads the live queue, which holds at
  ///   most `MAX_PENDING_PONGS + 1` entries (the slot plus the capped
  ///   overflow), so that is 18 again.
  ///
  /// There is no third epoch: the same branch turns the connection terminal,
  /// and `Events::queue_pong` refuses every Ping from there on, so the count
  /// cannot grow a second time. The LIFETIME bound is therefore the sum —
  /// `2 * (MAX_PENDING_PONGS + 1) + 1` = 35 polls on the heap tiers, and, the
  /// bare tier having only the slot to promote, `2 * 1 + 1` = 3.
  ///
  /// A counter rather than a flag because the heap tiers can owe several at
  /// that instant (`MAX_PENDING_PONGS` behind the slot), and all of them
  /// precede the close.
  ///
  /// # Which frames stop, and when
  ///
  /// The close drains ONCE (`close_sent`). Pongs keep draining after it, because
  /// §5.5.2's MUST is discharged only by a Close this endpoint has **received**.
  /// That question is settled where the Ping lands, in
  /// `Events::queue_pong` — a Ping received after a Close owes nothing, and a
  /// pong already owed when the Close arrives is not cancelled by it — so there
  /// is no lifecycle gate here at all.
  pub fn poll_transmit(&mut self, now: I, out: &mut [u8]) -> Result<Option<usize>, EncodeError> {
    // Before anything is written or dequeued, so a refusal leaves the queue and
    // the lifecycle exactly as they were and the call is retryable.
    if !self.accept_now(now) {
      return Err(crate::contract::contract_violation(
        EncodeError::ClockWentBackwards,
        crate::contract::CLOCK_IS_MONOTONIC,
      ));
    }
    // One pong arm, one condition: it goes now unless a close is queued and
    // undrained AND this pong was queued behind it. See "The order, derived".
    let close_waiting = !self.send.close_sent && self.send.pending_close.is_some();
    if (!close_waiting || self.send.pongs_before_close > 0)
      && let Some((payload, len)) = self.send.pending_pong
    {
      let len = usize::from(len);
      let n = self.write_frame(
        Opcode::Pong,
        true,
        false,
        payload.get(..len).unwrap_or(&[]),
        out,
      )?;
      self.send.pongs_before_close = self.send.pongs_before_close.saturating_sub(1);
      // Refill the slot from the overflow queue so the next `poll_transmit`
      // emits the following pong (every ping answered where a heap exists).
      #[cfg(any(feature = "alloc", feature = "std", feature = "no-atomic"))]
      {
        self.send.pending_pong = self.recv.pong_overflow.pop_front();
      }
      #[cfg(not(any(feature = "alloc", feature = "std", feature = "no-atomic")))]
      {
        self.send.pending_pong = None;
      }
      return Ok(Some(n));
    }
    // The close, once.
    if !self.send.close_sent
      && let Some((payload, len)) = self.send.pending_close
    {
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
    // Keepalive ping (empty payload, no mask key for server; masked for client).
    // Only while `Open`: a ping armed before `close()` must not follow the close
    // onto the wire, and there is no keepalive to keep alive once we are closing.
    if matches!(self.lifecycle, Lifecycle::Open) && self.send.pending_ping {
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
    // TERMINAL, not "not Open". A control frame after our own Close is
    // permitted — §5.5.1 (line 2002) bans further *data* frames only — and
    // refusing one in `CloseSent` made this crate's own documented workaround
    // impossible: the caller was told to answer a post-close Ping with
    // `encode_pong` and then handed `EncodeError::Closing` when it tried.
    // §5.5.2 (line 2043) keeps the Pong owed until a Close is RECEIVED, and
    // §5.5.2 (line 2047) lets an endpoint send a Ping "any time after the
    // connection is established and before the connection is closed" — which
    // §7.1.4 makes the TCP close, not our Close frame.
    if matches!(self.lifecycle, Lifecycle::Terminal) {
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

/// Bare-tier regressions — the ONLY tests `cargo test -p websocket-proto
/// --no-default-features` executes, because every other test module in this
/// crate is gated on `std`.
///
/// It has to be its own module rather than a `cfg` inside the `std` one: the
/// behaviour under test differs by tier, and on the bare tier there is no
/// allocator, so no `Vec`, no `format!`, and no `time::testing::TestInstant`
/// (which is itself `std`-gated). Everything here is fixed-size.
#[cfg(all(
  test,
  not(any(feature = "alloc", feature = "std", feature = "no-atomic"))
))]
mod bare_tests {
  use crate::{
    connection::{Connection, ConnectionConfig, role::Server},
    frame::{CloseCode, FrameHeader, Opcode, mask as apply_mask},
    negotiation::Negotiated,
    time::Instant,
  };

  /// A microsecond counter — the bare tier's stand-in for `TestInstant`.
  #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
  struct Tick(u64);

  impl Instant for Tick {
    fn checked_add_duration(self, dur: core::time::Duration) -> Option<Self> {
      u64::try_from(dur.as_micros())
        .ok()
        .and_then(|micros| self.0.checked_add(micros))
        .map(Tick)
    }

    fn checked_duration_since(self, earlier: Self) -> Option<core::time::Duration> {
      self
        .0
        .checked_sub(earlier.0)
        .map(core::time::Duration::from_micros)
    }
  }

  /// One masked client→server ping, written into a caller-owned buffer.
  fn masked_ping<'b>(buf: &'b mut [u8; 16], payload: &[u8]) -> &'b mut [u8] {
    const KEY: [u8; 4] = [3, 1, 4, 1];
    let header = FrameHeader::new(Opcode::Ping, payload.len() as u64).with_mask(Some(KEY));
    let n = header.encode(buf).unwrap();
    let end = n + payload.len();
    buf[n..end].copy_from_slice(payload);
    apply_mask(&mut buf[n..end], KEY, 0);
    &mut buf[..end]
  }

  fn server() -> Connection<Tick, Server> {
    Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      Tick(0),
    )
  }

  /// F2, bare tier: replacing the slot sheds drain position 0, so the frozen
  /// pre-close prefix must shrink and the survivor lands BEHIND the close.
  ///
  /// There is no overflow queue here, so a second ping replaces the first —
  /// RFC 6455 §5.5.3 (line 2064 of `.rfc-cache/rfc6455.txt`) permits answering
  /// "only the most recently processed Ping frame". But the survivor is
  /// post-close BY IDENTITY, so it must not inherit the departed pong's place
  /// ahead of the close. Before the fix this emitted Pong(B) then the Close.
  #[test]
  fn a_replaced_pre_close_pong_leaves_the_prefix_and_lands_behind_the_close() {
    let mut conn = server();

    let mut a_buf = [0u8; 16];
    let a = masked_ping(&mut a_buf, b"A");
    {
      let mut ev = conn.handle(Tick(0), a).unwrap();
      while ev.next().is_some() {}
    }

    conn.close(CloseCode::GoingAway, "").unwrap();

    let mut b_buf = [0u8; 16];
    let b = masked_ping(&mut b_buf, b"B");
    {
      let mut ev = conn.handle(Tick(0), b).unwrap();
      while ev.next().is_some() {}
    }

    let mut out = [0u8; 32];
    let n = conn.poll_transmit(Tick(0), &mut out).unwrap().unwrap();
    assert_eq!(
      &out[..n],
      &[0x88, 0x02, 0x03, 0xE9],
      "poll 1 must be the close: B replaced A in the slot, so the frozen prefix \
       lost its only entry and must shrink to 0"
    );
    let n = conn.poll_transmit(Tick(0), &mut out).unwrap().unwrap();
    assert_eq!(
      &out[..n],
      &[0x8A, 0x01, b'B'],
      "poll 2 is the surviving pong, behind the close it was queued after"
    );
    assert!(conn.poll_transmit(Tick(0), &mut out).unwrap().is_none());
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
  fn a_pong_owed_before_the_peer_close_still_drains_ahead_of_the_echo() {
    use crate::frame::{Opcode, encode_close_payload, mask as apply_mask};
    let mut conn = server();
    // Peer ping then close in one buffer. THIS TEST PINNED THE DEFECT: it used
    // to assert the echo was the only frame that drained, reading §5.5.2's
    // exemption (line 2043, "unless it already received a Close frame") as
    // though a later Close cancelled an obligation that already existed. It does
    // not. The exemption is a property of the moment the PING arrives, and when
    // this ping arrived no Close had been received — so the pong is owed, and it
    // is queued before the close, so queue-time order puts it first.
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
    // First drain: the owed pong.
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .unwrap();
    assert_eq!(out[0], 0x8A, "the owed pong, not the echo");
    assert_eq!(&out[..n], &[0x8A, 0x01, b'p']);
    // Then the close echo.
    let n = conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .expect("the close echo");
    assert_eq!(out[0], 0x88);
    let _ = n;
    // And nothing behind it.
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
  ///
  /// The other half is the INDEPENDENCE of the two slots, which is what the
  /// conformance fix turns on: neither erases the other, in either order.
  #[test]
  fn the_close_slot_and_the_pong_slot_do_not_erase_each_other() {
    let mut send = SendState::new();

    // A pong owed, then a close: BOTH are held. An earlier revision merged
    // these into one tagged slot, and the close displaced the pong; §5.5.2
    // (line 2042) owes that pong until a Close is RECEIVED, so displacing it
    // dropped a frame the RFC requires.
    send.offer_pong([b'p'; MAX_CONTROL_PAYLOAD], 1);
    send.queue_close(CloseCode::GoingAway, "first", 0);
    assert_eq!(send.queued_code, Some(CloseCode::GoingAway));
    // And the queue-order group is frozen at what was owed: the slot's one pong.
    assert_eq!(send.pongs_before_close, 1);
    let (close, close_len) = send.pending_close.expect("a close is queued");
    assert_eq!(&close[..usize::from(close_len)], b"\x03\xE9first");
    let (pong, pong_len) = send.pending_pong.expect("the pong is still owed");
    assert_eq!(&pong[..usize::from(pong_len)], b"p");

    // A SECOND close does not replace the first — neither its code nor its
    // payload — and does not touch the pong.
    send.queue_close(CloseCode::PolicyViolation, "second", 7);
    assert_eq!(send.queued_code, Some(CloseCode::GoingAway));
    let (still, still_len) = send.pending_close.expect("the first close is still queued");
    assert_eq!(&still[..usize::from(still_len)], b"\x03\xE9first");
    assert!(send.pending_pong.is_some());

    assert_eq!(
      send.pongs_before_close, 1,
      "a refused second close must not re-freeze the ordering group either"
    );

    // And the other direction: a pong owed AFTER the close replaces only the
    // pong (§5.5.3's most-recent rule), leaving the close alone. It does NOT
    // join the pre-close group — that is what bounds the close.
    //
    // This assertion USED TO SAY the count was unchanged, and that was the
    // defect: replacing an occupied slot sheds drain position 0, which is
    // inside the frozen prefix, so the prefix must shrink WITH it. Leaving the
    // count alone let the replacement inherit the departed entry's place ahead
    // of the close. The rule the test was reaching for holds more strongly
    // now — the later pong does not join the group, and the one it displaced
    // leaves it.
    let before = send.pongs_before_close;
    send.offer_pong([b'q'; MAX_CONTROL_PAYLOAD], 1);
    let (newer, newer_len) = send.pending_pong.expect("the newer pong is owed");
    assert_eq!(&newer[..usize::from(newer_len)], b"q");
    let (after, after_len) = send.pending_close.expect("the first close is still queued");
    assert_eq!(&after[..usize::from(after_len)], b"\x03\xE9first");
    assert_eq!(
      send.pongs_before_close,
      before - 1,
      "the replaced entry left the frozen prefix, so the prefix shrank with it"
    );

    // `force_close` is the one door that DOES replace a queued close: the
    // failure code is what has to reach the wire. It leaves the pong alone —
    // `poll_transmit`'s terminal gate is what silences that, in one place.
    send.force_close(CloseCode::ProtocolError);
    assert_eq!(send.queued_code, Some(CloseCode::ProtocolError));
    let (failed, failed_len) = send.pending_close.expect("the failure close is queued");
    assert_eq!(&failed[..usize::from(failed_len)], b"\x03\xEA");
    assert!(send.pending_pong.is_some());
  }

  /// Builds one masked client→server ping frame with `payload`.
  fn masked_ping(payload: &[u8]) -> Vec<u8> {
    use crate::frame::{Opcode, mask as apply_mask};
    const KEY: [u8; 4] = [7, 6, 5, 4];
    let h = FrameHeader::new(Opcode::Ping, payload.len() as u64).with_mask(Some(KEY));
    let mut f = vec![0u8; h.header_len() + payload.len()];
    let n = h.encode(&mut f).unwrap();
    f[n..].copy_from_slice(payload);
    apply_mask(&mut f[n..], KEY, 0);
    f
  }

  /// Drains every frame `poll_transmit` will give, as `(opcode_byte, body)`.
  fn drain_all(conn: &mut Connection<TestInstant, Server>) -> Vec<(u8, Vec<u8>)> {
    let mut out = [0u8; 64];
    let mut got = Vec::new();
    while let Some(n) = conn.poll_transmit(TestInstant(0), &mut out).unwrap() {
      let decoded = match FrameHeader::decode(&out[..n]).unwrap() {
        Decoded::Complete(d) => d,
        _ => panic!("incomplete frame"),
      };
      got.push((out[0], out[decoded.consumed()..n].to_vec()));
    }
    got
  }

  /// **Conformance regression 1: `Ping → close() → Ping → drain`.**
  ///
  /// RFC 6455 §5.5.2 (line 2042 of `.rfc-cache/rfc6455.txt`) makes a Pong a MUST
  /// "unless it already received a Close frame". A Close this endpoint SENT is
  /// not one it received, so BOTH pings are owed a pong here — the second as
  /// much as the first, since neither arrived after a received Close.
  ///
  /// **The ORDER is queue-time, and that is what this pins.** The pong owed
  /// before `close()` precedes the close; the pong owed after it follows. An
  /// earlier revision put every pong first unconditionally, which let a peer
  /// alternating Pings with single `poll_transmit` calls starve the close
  /// forever — see `a_close_cannot_be_starved_by_a_ping_per_poll`.
  ///
  /// Both echoes exist because a heap is available (Autobahn §2.10's rule); on
  /// the bare tier the single slot coalesces to the most recent by §5.5.3 (line
  /// 2064), and the close still emerges after exactly one pong.
  #[test]
  fn a_ping_before_a_local_close_precedes_it_and_one_after_follows_it() {
    let mut conn = server();

    let mut before = masked_ping(b"before");
    {
      let mut ev = conn.handle(TestInstant(0), &mut before).unwrap();
      while ev.next().is_some() {}
    }
    conn.close(CloseCode::GoingAway, "bye").unwrap();
    let mut after = masked_ping(b"after");
    {
      let mut ev = conn
        .handle(TestInstant(0), &mut after)
        .expect("input is still accepted in CloseSent");
      while ev.next().is_some() {}
    }

    let got = drain_all(&mut conn);
    let shape: Vec<(u8, &[u8])> = got.iter().map(|(op, b)| (*op, b.as_slice())).collect();
    assert_eq!(
      shape,
      vec![
        (0x8A, b"before".as_slice()),
        (0x88, b"\x03\xE9bye".as_slice()),
        (0x8A, b"after".as_slice()),
      ],
      "the pong queued before the close, then the close, then the one queued after"
    );
  }

  /// `CloseSent → Ping → peer Close`, in its four public shapes.
  ///
  /// A Ping received after our own `close()` is queued BEHIND that close by
  /// queue-time order. When the peer's Close then arrives the branch must say
  /// what becomes of it, and the answer turns on whether our close already
  /// LEFT — the same `close_sent` marker `poll_transmit` and `fail` use:
  ///
  /// * still queued → every owed pong can still be discharged ahead of it, so
  ///   they are promoted into the pre-close prefix;
  /// * already gone → both Close frames are exchanged and §5.5.1 (line 2023 of
  ///   `.rfc-cache/rfc6455.txt`) says the endpoint "MUST close the underlying
  ///   TCP connection". Nothing more goes out; the echoes are dropped.
  ///
  /// Before the fix (a) emitted the Close and then the Pong, and (b) emitted a
  /// Pong after BOTH Close frames had been exchanged.
  #[test]
  fn a_peer_close_in_close_sent_promotes_owed_pongs_or_drops_them() {
    fn peer_close(code: CloseCode) -> Vec<u8> {
      use crate::frame::{Opcode, encode_close_payload, mask as apply_mask};
      const KEY: [u8; 4] = [8, 6, 7, 5];
      let mut payload = [0u8; 8];
      let pn = encode_close_payload(code, "", &mut payload).unwrap();
      let h = FrameHeader::new(Opcode::Close, pn as u64).with_mask(Some(KEY));
      let mut f = vec![0u8; h.header_len() + pn];
      let n = h.encode(&mut f).unwrap();
      f[n..].copy_from_slice(&payload[..pn]);
      apply_mask(&mut f[n..], KEY, 0);
      f
    }
    fn feed(conn: &mut Connection<TestInstant, Server>, bytes: &mut [u8]) {
      let mut ev = conn.handle(TestInstant(0), bytes).unwrap();
      while ev.next().is_some() {}
    }
    fn shape(got: &[(u8, Vec<u8>)]) -> Vec<(u8, &[u8])> {
      got.iter().map(|(op, b)| (*op, b.as_slice())).collect()
    }

    // (a) our close still queued: the owed pong is promoted ahead of it.
    let mut conn = server();
    conn.close(CloseCode::GoingAway, "").unwrap();
    feed(&mut conn, &mut masked_ping(b"P"));
    feed(&mut conn, &mut peer_close(CloseCode::Normal));
    assert!(conn.is_terminal());
    let got = drain_all(&mut conn);
    assert_eq!(
      shape(&got),
      vec![(0x8A, b"P".as_slice()), (0x88, b"\x03\xE9".as_slice())],
      "(a) our close had not left, so the owed pong is discharged ahead of it"
    );

    // (b) our close already left: both Closes are exchanged, nothing follows.
    let mut conn = server();
    conn.close(CloseCode::GoingAway, "").unwrap();
    assert_eq!(
      drain_all(&mut conn).len(),
      1,
      "(b) the close goes out first"
    );
    feed(&mut conn, &mut masked_ping(b"P"));
    feed(&mut conn, &mut peer_close(CloseCode::Normal));
    assert!(
      drain_all(&mut conn).is_empty(),
      "(b) §5.5.1 line 2023: after both Close frames are exchanged the endpoint \
       MUST close the connection — no pong may follow"
    );

    // (c) the same ping, drained BEFORE the peer's close arrives: it goes out.
    let mut conn = server();
    conn.close(CloseCode::GoingAway, "").unwrap();
    assert_eq!(drain_all(&mut conn).len(), 1);
    feed(&mut conn, &mut masked_ping(b"P"));
    let got = drain_all(&mut conn);
    assert_eq!(
      shape(&got),
      vec![(0x8A, b"P".as_slice())],
      "(c) still owed while only OUR close has been sent"
    );
    feed(&mut conn, &mut peer_close(CloseCode::Normal));
    assert!(drain_all(&mut conn).is_empty(), "(c) and nothing after");

    // (d) mixed: one pong owed before the close, one after, then the peer's.
    let mut conn = server();
    feed(&mut conn, &mut masked_ping(b"A"));
    conn.close(CloseCode::GoingAway, "").unwrap();
    feed(&mut conn, &mut masked_ping(b"B"));
    feed(&mut conn, &mut peer_close(CloseCode::Normal));
    let got = drain_all(&mut conn);
    assert_eq!(
      shape(&got),
      vec![
        (0x8A, b"A".as_slice()),
        (0x8A, b"B".as_slice()),
        (0x88, b"\x03\xE9".as_slice()),
      ],
      "(d) both pongs promoted ahead of the close that ends the handshake"
    );
  }

  /// **The starvation bound, on the schedule that exposes it.** With
  /// unconditional pong priority a driver that alternates one inbound Ping with
  /// exactly ONE `poll_transmit` emits a Pong every time and never reaches its
  /// Close, so `close_deadline` never arms. The queue cap does not help — only
  /// one pong is outstanding at a time — and this crate cannot assume a
  /// drain-to-`None` schedule, because the public API neither enforces nor can
  /// express one.
  ///
  /// The bound queue-time order gives is exact within an epoch:
  /// `pongs_before_close` is frozen when the close is queued and only shrinks
  /// while ours is the only Close in play, so the close is emitted **within
  /// `pongs_before_close + 1` polls**. No peer Close arrives here, so this is
  /// that first epoch; the promotion that opens the second one, and the
  /// lifetime bound over both, are on `poll_transmit`. Here one pong was owed
  /// at `close()`, so the budget is **2**, and the test fails if it takes more —
  /// under the old rule it never arrived at all. `close_deadline` must arm on
  /// that drain, which is the whole reason the bound matters.
  #[test]
  fn a_close_cannot_be_starved_by_a_ping_per_poll() {
    use core::time::Duration;
    let config = ConnectionConfig::new().with_close_timeout(Duration::from_secs(3));
    let mut conn: Connection<TestInstant, Server> =
      Connection::new(&Negotiated::none(), config, Server::new(), TestInstant(0));

    // One pong owed when the close is queued: the budget is 1 + 1 = 2 polls.
    let mut first = masked_ping(b"p0");
    {
      let mut ev = conn.handle(TestInstant(0), &mut first).unwrap();
      while ev.next().is_some() {}
    }
    conn.close(CloseCode::GoingAway, "").unwrap();
    assert_eq!(conn.poll_timeout(), None, "the deadline arms on the drain");

    // The adversarial schedule: one Ping in, exactly one poll out, forever.
    let mut out = [0u8; 64];
    let mut polls = 0usize;
    let mut close_at = None;
    for round in 0..64u32 {
      let mut ping = masked_ping(format!("p{round}").as_bytes());
      {
        let mut ev = conn.handle(TestInstant(0), &mut ping).unwrap();
        while ev.next().is_some() {}
      }
      let n = conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .expect("something is always owed on this schedule");
      polls += 1;
      if out[0] == 0x88 {
        close_at = Some(polls);
        let _ = n;
        break;
      }
    }
    assert_eq!(
      close_at,
      Some(2),
      "the close must emerge within `pongs_before_close + 1` = 2 polls"
    );
    // And it armed the deadline as it went out.
    assert_eq!(conn.poll_timeout(), Some(TestInstant(3_000_000)));
  }

  /// **Conformance regression 2: `close() → drain → Ping → drain`.**
  ///
  /// The `CloseSent` path. Two things were broken here and both are §5.5.2's
  /// (line 2042) Pong MUST, which runs until a Close is RECEIVED:
  ///
  /// * the machine answered nothing after its own close had drained, because
  ///   `poll_transmit` returned `None` for the life of the connection;
  /// * and `encode_pong` — the workaround this crate's own docs pointed a
  ///   caller at — answered `EncodeError::Closing`, because `encode_control`
  ///   refused every non-`Open` lifecycle. The documented escape hatch was shut.
  ///
  /// Both are asserted, because a caller may reasonably use either.
  #[test]
  fn a_ping_after_our_close_has_drained_is_still_answered() {
    let mut conn = server();
    conn.close(CloseCode::Normal, "").unwrap();

    let drained = drain_all(&mut conn);
    assert_eq!(drained.len(), 1, "just the close");
    assert_eq!(drained[0].0, 0x88);

    let mut ping = masked_ping(b"late");
    {
      let mut ev = conn
        .handle(TestInstant(0), &mut ping)
        .expect("input is still accepted in CloseSent");
      while ev.next().is_some() {}
    }

    // (a) The machine answers it, after the close rather than before — the
    // close has already gone, so "as soon as is practical" is now.
    let got = drain_all(&mut conn);
    let shape: Vec<(u8, &[u8])> = got.iter().map(|(op, b)| (*op, b.as_slice())).collect();
    assert_eq!(shape, vec![(0x8A, b"late".as_slice())]);

    // (b) And the by-hand path works in `CloseSent` too. A Ping is legal here
    // as well: §5.5.2 (line 2047) allows one "any time after the connection is
    // established and before the connection is closed", and §7.1.4 makes that
    // the TCP close.
    let mut out = [0u8; 32];
    let n = conn
      .encode_pong(b"manual", &mut out)
      .expect("encode_pong must work while awaiting the peer's close");
    assert_eq!(&out[..n], b"\x8A\x06manual");
    conn
      .encode_ping(b"", &mut out)
      .expect("encode_ping too, by the same clause");

    // Data sends are still refused — that half IS §5.5.1 (line 2002).
    assert!(matches!(
      conn.encode_text("nope", &mut out),
      Err(EncodeError::Closing)
    ));
  }

  /// The boundary, and the SECOND thing this test used to get wrong. §5.5.2's
  /// exemption (line 2043, "unless it already received a Close frame") is a
  /// property of the moment a PING arrives, so it splits into two halves that
  /// this test now pins separately:
  ///
  /// * a pong owed BEFORE the peer's Close still drains — ahead of the echo,
  ///   by queue-time order — because a later Close does not cancel an
  ///   obligation that already existed. This test asserted the opposite;
  /// * a Ping arriving AFTER the Close owes nothing, and `encode_pong` is
  ///   refused, because by then a Close has been received.
  ///
  /// Without the second half, "keep answering pings" would have had no end.
  #[test]
  fn a_received_close_splits_the_pong_obligation_at_the_moment_of_arrival() {
    use crate::frame::{Opcode, encode_close_payload, mask as apply_mask};
    let mut conn = server();

    // One ping (pong owed), then the peer's close, in one batch.
    let mut bytes = masked_ping(b"owed");
    const KEY: [u8; 4] = [2, 4, 6, 8];
    let mut payload = [0u8; 8];
    let pn = encode_close_payload(CloseCode::Normal, "", &mut payload).unwrap();
    let h = FrameHeader::new(Opcode::Close, pn as u64).with_mask(Some(KEY));
    let mut f = vec![0u8; h.header_len() + pn];
    let n = h.encode(&mut f).unwrap();
    f[n..].copy_from_slice(&payload[..pn]);
    apply_mask(&mut f[n..], KEY, 0);
    bytes.extend(f);

    {
      let mut ev = conn.handle(TestInstant(0), &mut bytes).unwrap();
      while ev.next().is_some() {}
    }
    assert!(conn.is_terminal());

    let got = drain_all(&mut conn);
    let shape: Vec<(u8, &[u8])> = got.iter().map(|(op, b)| (*op, b.as_slice())).collect();
    assert_eq!(
      shape,
      vec![(0x8A, b"owed".as_slice()), (0x88, b"\x03\xE8".as_slice()),],
      "the pong owed before the Close arrived, then the echo"
    );

    // The other half: a Ping that arrives after a Close was received owes
    // nothing. `handle` refuses input once terminal, so the machine can never
    // even be offered one — and the by-hand path is shut for the same reason.
    let mut late = masked_ping(b"late");
    assert!(matches!(
      conn.handle(TestInstant(0), &mut late),
      Err(crate::connection::HandleError::Terminal)
    ));
    let mut out = [0u8; 32];
    assert!(matches!(
      conn.encode_pong(b"x", &mut out),
      Err(EncodeError::Closing)
    ));
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
