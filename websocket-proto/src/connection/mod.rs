//! The transport-blind WebSocket connection state machine (RFC 6455 §5–§8).
//!
//! One [`Connection`] serves any reliable byte stream — an HTTP/1.1-upgraded
//! TCP socket, an HTTP/2 stream (RFC 8441), or an HTTP/3 stream (RFC 9220) —
//! because those transports change only the opening handshake. Construct it
//! from the handshake's [`Negotiated`] plus a
//! [`ConnectionConfig`] and a [`role::Role`](crate::connection::role::Role) value.
//!
//! Receive: feed transport bytes to [`Connection::handle`]; the returned
//! [`Events`](crate::connection::Events) cursor is a lending iterator whose
//! events borrow the cursor and are valid only until the next `next()` call.
//! Uncompressed payloads are
//! unmasked **in place** and the chunks point straight into the input —
//! receive state is O(1) in message size (the inflate path under the
//! `deflate` feature is the one exception: it buffers each inflated message).
//! Send: the `encode_*` methods serialize straight into your buffer (clients
//! mask on the copy with a fresh key per frame); only protocol-generated
//! frames (pong echoes, close) are queued internally and drained via
//! [`Connection::poll_transmit`].
//!
//! Protocol violations are not `Err`s: the machine queues the prescribed
//! close frame, becomes terminal, and yields a final
//! `Closed` event with `clean == false`; keep draining
//! [`Connection::poll_transmit`] and then drop the transport.

mod events;
mod recv;
pub mod role;
mod send;

pub use events::{
  CloseReceived, Closed, ControlPayload, Event, MessageKind, MessageStart, TextChunk,
};
pub use recv::{Events, HandleError};
pub use send::{EncodeError, EncodedHeader, FragmentKind};

use crate::{negotiation::Negotiated, time::Instant};
use role::Role;

/// Connection limits and behavior knobs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
  max_frame_payload: u64,
  max_message_size: u64,
  /// Optional keepalive ping interval. `None` disables keepalive.
  keepalive: Option<core::time::Duration>,
  /// Close-handshake timeout (default 10 s).
  close_timeout: core::time::Duration,
}

impl Default for ConnectionConfig {
  fn default() -> Self {
    Self {
      max_frame_payload: 16 * 1024 * 1024,
      max_message_size: 64 * 1024 * 1024,
      keepalive: None,
      close_timeout: core::time::Duration::from_secs(10),
    }
  }
}

impl ConnectionConfig {
  /// The defaults: 16 MiB frames, 64 MiB messages, no keepalive, 10 s close timeout.
  pub fn new() -> Self {
    Self::default()
  }

  /// Caps a single frame's payload length (exceeding ⇒ close 1009).
  #[must_use]
  pub const fn with_max_frame_payload(mut self, max: u64) -> Self {
    self.max_frame_payload = max;
    self
  }

  /// Caps a whole message's accumulated size (exceeding ⇒ close 1009).
  #[must_use]
  pub const fn with_max_message_size(mut self, max: u64) -> Self {
    self.max_message_size = max;
    self
  }

  /// Sets the keepalive ping interval (`None` disables keepalive).
  #[must_use]
  pub const fn with_keepalive(mut self, interval: Option<core::time::Duration>) -> Self {
    self.keepalive = interval;
    self
  }

  /// Sets the close-handshake timeout.
  #[must_use]
  pub const fn with_close_timeout(mut self, timeout: core::time::Duration) -> Self {
    self.close_timeout = timeout;
    self
  }

  /// The frame-payload cap.
  #[inline(always)]
  pub const fn max_frame_payload(&self) -> u64 {
    self.max_frame_payload
  }

  /// The message-size cap.
  #[inline(always)]
  pub const fn max_message_size(&self) -> u64 {
    self.max_message_size
  }

  /// The keepalive interval, if configured.
  #[inline(always)]
  pub const fn keepalive(&self) -> Option<core::time::Duration> {
    self.keepalive
  }

  /// The close-handshake timeout.
  #[inline(always)]
  pub const fn close_timeout(&self) -> core::time::Duration {
    self.close_timeout
  }
}

/// The WebSocket connection state machine. `I` is the caller's monotonic
/// clock; `Ro` is the [`role`] (client or server), fixed at the type level.
#[derive(Debug)]
pub struct Connection<I, Ro> {
  pub(crate) role: Ro,
  pub(crate) config: ConnectionConfig,
  #[cfg(feature = "deflate")]
  pub(crate) deflate: Option<crate::negotiation::DeflateParams>,
  pub(crate) recv: recv::RecvState,
  pub(crate) send: send::SendState,
  pub(crate) lifecycle: Lifecycle,
  /// Deadline after which `handle_timeout` declares the close unclean
  /// (armed when the close frame drains in `poll_transmit`).
  pub(crate) close_deadline: Option<I>,
  /// Next instant at which a keepalive ping should be sent.
  pub(crate) next_keepalive: Option<I>,
  /// The latest instant any of the three `now`-taking entry points has been
  /// given. See [`Connection::accept_now`] for what it is compared against and
  /// why it is an `I` rather than an `Option<I>`.
  pub(crate) last_now: I,
  pub(crate) _clock: core::marker::PhantomData<I>,
}

/// What [`Connection::handle_timeout`] refuses.
///
/// It had no error type before the monotonicity check: every other outcome of
/// a timeout tick is an ordinary `Option<Closed>`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeoutError {
  /// `now` is earlier than an instant this connection has already been given.
  /// See [`Connection::handle_timeout`].
  #[error("`now` is earlier than an instant this connection has already been given")]
  ClockWentBackwards,
}

/// The clock the budget below is taken over: a `u64` nanosecond counter, which
/// is the shape a thread-per-core driver keeps anyway (an `io_uring` timeout is
/// a `__kernel_timespec`, not an opaque handle). Taking the bound over a clock
/// THIS crate defines is the whole point of the newtype — the size of
/// [`std::time::Instant`] is the platform's business and differs between
/// targets, so a budget written against it would move underneath this crate
/// without anything here changing, and would not exist at all on the bare tier
/// where the assertion matters most.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Nanos(u64);

impl Instant for Nanos {
  fn checked_add_duration(self, dur: core::time::Duration) -> Option<Self> {
    u64::try_from(dur.as_nanos())
      .ok()
      .and_then(|nanos| self.0.checked_add(nanos))
      .map(Self)
  }

  fn checked_duration_since(self, earlier: Self) -> Option<core::time::Duration> {
    self
      .0
      .checked_sub(earlier.0)
      .map(core::time::Duration::from_nanos)
  }
}

/// `size_of::<Connection<Nanos, Server>>()` as MEASURED, per storage tier.
///
/// A driver that keeps one `Connection` per accepted socket — a thread-per-core
/// `io_uring` server with a preallocated slab, say — multiplies this number by
/// its connection count and pays it as resident memory before a single byte
/// arrives. That makes the size a published property of the crate rather than
/// an implementation detail, and a published property with no gate is one that
/// drifts. This is the gate, and it is `const`, so it is evaluated by every
/// `cargo check` on every tier and every target rather than by a test somebody
/// has to run.
///
/// The value is the measurement and NOT a round number above it. A budget with
/// slack in it only fails once the struct has already grown past what anyone
/// measured, which is exactly the growth it exists to report; a budget equal to
/// the measurement fails on the first byte and names the field that added it.
/// Widening it is therefore a deliberate edit with a new measurement beside it,
/// which is the review this number should get.
///
/// Measured 2026-09-04 on aarch64-apple-darwin (64-bit `usize`), with a probe
/// binary outside the workspace that depends on this crate by path and prints
/// `core::mem::size_of::<Connection<Nanos, Server>>()`:
///
/// ```text
/// cargo run --quiet --no-default-features          # 536 at e42b30d → 544
/// cargo run --quiet --features std                 # 568 at e42b30d → 576
/// cargo run --quiet --features alloc               # 568 at e42b30d → 576
/// cargo run --quiet --features no-atomic           # 568 at e42b30d → 576
/// cargo run --quiet --features alloc,deflate       # 592 at e42b30d → 600
/// ```
///
/// The last column includes `SendState::pongs_before_close`, the `u8` that
/// makes the two outbound slots drain in queue-time order. MEASURED, because
/// the guess would have been wrong in both directions: it costs **nothing** on
/// the bare and heap tiers, where it lands in existing padding, and **8 bytes**
/// with `deflate`, where it does not.
///
/// **Net +8 bytes on the bare and heap tiers, +8 with `deflate`** — `last_now`
/// on the first two, and `last_now` plus the queue-order byte on the third,
/// where padding stops absorbing them. On the bare tier every one of them is
/// `last_now` — the monotonicity
/// check's stored instant, an `I` rather than an `Option<I>` precisely so it is
/// eight and not sixteen (see [`accept_now`](Connection::accept_now)). With
/// `deflate` even that lands in existing padding and the number does not move.
///
/// A middle revision of this branch was 128 bytes smaller, by merging
/// `SendState`'s close slot and `RecvState`'s pong slot into one tagged slot.
/// **That merge was a conformance defect and is reverted**: RFC 6455 §5.5.2
/// (line 2042 of `.rfc-cache/rfc6455.txt`) owes a Pong until a Close is
/// RECEIVED, so the machine has to hold a queued close and an owed pong at the
/// same time, and one slot cannot. The two buffers are back where `e42b30d` had
/// them. A smaller `Connection` does not license a nonconformance — the
/// derivation is on [`poll_transmit`](Connection::poll_transmit).
///
/// The budget caught the `last_now` growth rather than a reviewer: adding the
/// field reddened `cargo check` with `error[E0080]: evaluation panicked` before
/// a test was written, which is the gate working.
///
/// # What this bound does NOT say
///
/// It is taken at ONE instantiation: `Connection<Nanos, Server>` — an 8-byte
/// `Copy + Ord` clock and a zero-sized role. It is **not** a bound on
/// `Connection<I, Ro>` for a caller's own `I` and `Ro`, and it cannot be: the
/// struct holds three `I`-shaped fields (`close_deadline` and `next_keepalive`
/// as `Option<I>`, `last_now` as `I`) plus the role by value, so a caller
/// substituting a wider instant or a `Client<R>` whose `R` carries an RNG pays
/// for them on top and this assertion says nothing about it.
///
/// MEASURED rather than reasoned, because the reasoning was wrong the first
/// time: with a 16-byte clock newtype the bare tier is **568**, not the 448 a
/// field-by-field count predicted. The two `Option<I>` and the `I` grow by 8
/// each, and none of the 24 lands in padding.
///
/// The three tiers are three numbers because they are three structs: the heap
/// tiers add `RecvState::pong_overflow` (a `VecDeque`, 32 bytes), and `deflate`
/// adds the two boxed codec handles and the negotiated parameters on top. A
/// 32-bit target (`thumbv6m-none-eabi`) lands strictly under every one of them —
/// `control_len` and the `VecDeque`'s three fields are `usize` — so `<=` is the
/// right comparison and the bare-tier check still bites where it is checked.
#[cfg(not(any(
  feature = "alloc",
  feature = "std",
  feature = "no-atomic",
  feature = "deflate"
)))]
const CONNECTION_SIZE_BUDGET: usize = 544;

#[cfg(all(
  not(feature = "deflate"),
  any(feature = "alloc", feature = "std", feature = "no-atomic")
))]
const CONNECTION_SIZE_BUDGET: usize = 576;

#[cfg(feature = "deflate")]
const CONNECTION_SIZE_BUDGET: usize = 600;

const _: () =
  assert!(core::mem::size_of::<Connection<Nanos, role::Server>>() <= CONNECTION_SIZE_BUDGET);

/// Connection lifecycle (close handshake per RFC 6455 §7).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Lifecycle {
  /// Open for data both ways.
  Open,
  /// We sent (queued) a close; awaiting the peer's echo.
  CloseSent,
  /// Terminal: close exchange finished (the peer's close makes the
  /// connection terminal at once — the echo is queued for `poll_transmit`)
  /// or the connection failed.
  Terminal,
}

impl<I, Ro> Connection<I, Ro>
where
  I: Instant,
  Ro: Role,
{
  /// Builds a connection from a completed handshake. `now` seeds keepalive
  /// timer if configured.
  pub fn new(negotiated: &Negotiated, config: ConnectionConfig, role: Ro, now: I) -> Self {
    let next_keepalive = config.keepalive.and_then(|d| now.checked_add_duration(d));
    #[cfg(not(feature = "deflate"))]
    let _ = negotiated;
    Self {
      role,
      config,
      #[cfg(feature = "deflate")]
      deflate: negotiated.deflate(),
      recv: recv::RecvState::new(),
      send: send::SendState::new(),
      lifecycle: Lifecycle::Open,
      close_deadline: None,
      next_keepalive,
      last_now: now,
      _clock: core::marker::PhantomData,
    }
  }

  /// True once the connection is terminal (cleanly closed or failed):
  /// `handle` refuses further input and the transport can be dropped after
  /// a final [`poll_transmit`](Connection::poll_transmit) drain.
  pub const fn is_terminal(&self) -> bool {
    matches!(self.lifecycle, Lifecycle::Terminal)
  }

  /// True once this endpoint's Close frame has been handed to
  /// [`poll_transmit`](Connection::poll_transmit)'s caller.
  ///
  /// It says the Close LEFT this crate, not that it reached the wire — that
  /// second fact belongs to whoever owns the transport, and only that owner
  /// can know it. The distinction is why this is public: a driver that
  /// coalesces `poll_transmit` output into wire batches has to know which
  /// batch the Close is in, and the alternative — reading its own "a close is
  /// owed" flag — labels the NEXT batch too, because that flag is still set
  /// while the Close sits unflushed. §5.5.1 (line 2023 of
  /// `.rfc-cache/rfc6455.txt`) is what makes a wrong answer a protocol
  /// violation rather than a bookkeeping slip: after both sending and
  /// receiving a Close the connection is closed and nothing more may go out,
  /// so a batch mislabelled as the one carrying the Close is a frame written
  /// past the completed handshake.
  ///
  /// Compare [`is_terminal`](Connection::is_terminal), which answers about the
  /// close EXCHANGE: this flips when OUR Close drains, that flips when the
  /// peer's Close arrives (or the connection fails). Both true is the
  /// completed handshake; this one alone is `CloseSent` with the frame
  /// drained.
  pub const fn close_sent(&self) -> bool {
    self.send.close_sent
  }

  /// Returns the next deadline the caller must arrange to fire
  /// [`handle_timeout`](Connection::handle_timeout) at. Returns `None` when
  /// no timers are armed. It takes no `now`, so it never refuses.
  ///
  /// **The deadline it returns may be OLDER than the last instant this
  /// connection was given**, and that is not a bug in either method: a deadline
  /// is armed from the `now` of the call that armed it, while `last_now`
  /// advances on every `handle` / `poll_transmit` / `handle_timeout`. A keepalive
  /// armed at `t+5` is already stale once a `poll_transmit(t+20)` has gone by.
  ///
  /// So this value is a *when to wake up*, not a *what to pass*. Arrange the
  /// timer for it, and then call `handle_timeout` with a **fresh** reading of
  /// your clock. Handing this value straight back is a rewind, and
  /// `handle_timeout` refuses it with
  /// [`TimeoutError::ClockWentBackwards`].
  pub fn poll_timeout(&self) -> Option<I> {
    let keepalive = if matches!(self.lifecycle, Lifecycle::Open) {
      self.next_keepalive
    } else {
      None
    };
    let close = if matches!(self.lifecycle, Lifecycle::CloseSent) {
      self.close_deadline
    } else {
      None
    };
    match (keepalive, close) {
      (Some(a), Some(b)) => Some(a.min(b)),
      (Some(a), None) => Some(a),
      (None, Some(b)) => Some(b),
      (None, None) => None,
    }
  }

  /// Accepts `now` as this connection's current instant, recording it, or
  /// answers `false` because it is EARLIER than one already seen.
  ///
  /// This is the crate's whole monotonicity check, in one place, and three
  /// things about it are deliberate.
  ///
  /// **Equal is accepted.** Only a strictly earlier instant is refused. A
  /// driver that reads its clock once per wakeup and hands the same instant to
  /// `handle`, `poll_transmit` and `handle_timeout` in one batch is the shape
  /// this crate is written for, and every call in that batch must succeed.
  ///
  /// **It RETURNS by default — and panics under `assert-contracts` — with the
  /// decision in one flag rather than three call sites.** All three refusals go through
  /// [`contract_violation`](crate::contract::contract_violation), which hands
  /// the error back — or, under the `assert-contracts` feature, panics naming
  /// this contract. A clock that goes backwards is a bug in the caller's
  /// timekeeping, and whether that should kill the process or be logged and
  /// retried is the driver's; the crate's job is to make the fact reachable
  /// instead of absorbing it, which is what it did before this check —
  /// `handle(now)` with a rewound `now` simply made deadlines fire late and
  /// said nothing. Note the asymmetry that module is built on: a caller's bug
  /// may panic under a flag; a PEER's bytes never may, on any flag.
  ///
  /// **The stored instant is an `I`, not an `Option<I>`.** There is no "no
  /// clock yet" state to represent: [`Connection::new`] already takes a `now`
  /// and seeds this from it, so the first call after construction compares
  /// against a real instant. An `Option` would encode a case that cannot occur
  /// and cost eight more bytes on every connection — on a crate whose size is a
  /// `const` assertion, that is not free.
  ///
  /// Refusal touches nothing: the comparison runs before the store, so a
  /// refused call leaves the connection byte-identical and is retryable with a
  /// correct instant.
  fn accept_now(&mut self, now: I) -> bool {
    if now < self.last_now {
      return false;
    }
    self.last_now = now;
    true
  }

  /// Advances the timer state to `now`. Returns `Ok(Some(Closed))` when the
  /// close-handshake timeout fires; `Ok(None)` when nothing fired or a
  /// keepalive ping was queued (drain
  /// [`poll_transmit`](Connection::poll_transmit)).
  ///
  /// # Errors
  ///
  /// [`TimeoutError::ClockWentBackwards`] when `now` is EARLIER than an instant
  /// already handed to this connection through this method,
  /// [`handle`](Connection::handle) or
  /// [`poll_transmit`](Connection::poll_transmit). An equal instant is fine.
  /// The refusal leaves the connection untouched, so the call can be retried
  /// with a correct instant. The rule — and the `assert-contracts` exception,
  /// under which this refusal panics rather than returning — is on
  /// [`crate::time::Instant`].
  ///
  /// Pass a FRESH `now`, not the deadline
  /// [`poll_timeout`](Connection::poll_timeout) handed you: that deadline can
  /// already be older than the last instant this connection was given, and
  /// feeding it back is a rewind this method refuses.
  pub fn handle_timeout(&mut self, now: I) -> Result<Option<Closed>, TimeoutError> {
    if !self.accept_now(now) {
      return Err(crate::contract::contract_violation(
        TimeoutError::ClockWentBackwards,
        crate::contract::CLOCK_IS_MONOTONIC,
      ));
    }
    // Close deadline check (only in CloseSent).
    if matches!(self.lifecycle, Lifecycle::CloseSent)
      && let Some(deadline) = self.close_deadline
      && now >= deadline
    {
      self.lifecycle = Lifecycle::Terminal;
      let code = self
        .send
        .queued_code
        .unwrap_or(crate::frame::CloseCode::Normal);
      return Ok(Some(Closed::new(code, false)));
    }
    // Keepalive check (only in Open).
    if matches!(self.lifecycle, Lifecycle::Open)
      && let Some(deadline) = self.next_keepalive
      && now >= deadline
    {
      self.send.pending_ping = true;
      // Re-arm.
      if let Some(interval) = self.config.keepalive {
        self.next_keepalive = now.checked_add_duration(interval);
      }
    }
    Ok(None)
  }
}

#[cfg(all(test, feature = "std"))]
pub(crate) mod tests {
  use super::{
    Connection, ConnectionConfig,
    events::{Event, MessageKind},
    role::{Client, Role, Server},
  };
  use crate::{
    frame::{FrameHeader, Opcode, mask as apply_mask},
    negotiation::Negotiated,
    time::testing::TestInstant,
  };

  /// Owned summary of one event — shared by recv and property tests.
  #[derive(Debug, PartialEq, Eq, Clone)]
  pub(crate) enum Ev {
    Start(MessageKind, bool),
    Text(String),
    Bin(Vec<u8>),
    End,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    CloseRecv(u16, String),
    Closed(u16, bool),
  }

  /// Feeds `bytes` into `conn` and collects every event as owned `Ev`s.
  pub(crate) fn drain(conn: &mut Connection<TestInstant, Server>, bytes: &[u8]) -> Vec<Ev> {
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

  /// Folds adjacent Text/Bin chunks produced by split delivery.
  pub(crate) fn fold_events(events: Vec<Ev>) -> Vec<Ev> {
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

  /// A fresh server-role connection for testing.
  pub(crate) fn server() -> Connection<TestInstant, Server> {
    Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    )
  }

  /// Builds one masked frame (client→server direction) into a `Vec`.
  pub(crate) fn masked_frame(opcode: Opcode, fin: bool, payload: &[u8]) -> Vec<u8> {
    masked_frame_payload(opcode, fin, payload)
  }

  /// Builds one masked frame with the given payload bytes.
  pub(crate) fn masked_frame_payload(opcode: Opcode, fin: bool, payload: &[u8]) -> Vec<u8> {
    const KEY: [u8; 4] = [0x37, 0xFA, 0x21, 0x3D];
    let header = FrameHeader::new(opcode, u64::try_from(payload.len()).unwrap_or(u64::MAX))
      .with_fin(fin)
      .with_mask(Some(KEY));
    let mut out = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode(&mut out).unwrap();
    out[n..].copy_from_slice(payload);
    apply_mask(&mut out[n..], KEY, 0);
    out
  }

  /// Deterministic RngCore: fills with a repeating counter.
  pub(crate) struct CountingRng(pub(crate) u8);

  impl rand_core::TryRng for CountingRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
      let mut b = [0u8; 4];
      self.try_fill_bytes(&mut b)?;
      Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
      let mut b = [0u8; 8];
      self.try_fill_bytes(&mut b)?;
      Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
      for d in dest {
        *d = self.0;
        self.0 = self.0.wrapping_add(1);
      }
      Ok(())
    }
  }

  #[test]
  fn roles_declare_masking_direction() {
    const { assert!(!<Client<CountingRng> as Role>::EXPECT_MASKED_INBOUND) };
    const { assert!(<Server as Role>::EXPECT_MASKED_INBOUND) };

    let mut client = Client::new(CountingRng(0));
    assert_eq!(client.next_mask(), Some([0, 1, 2, 3]));
    assert_eq!(client.next_mask(), Some([4, 5, 6, 7]));
    assert_eq!(Server::new().next_mask(), None);
  }

  #[test]
  fn config_builders_and_defaults() {
    let c = ConnectionConfig::default();
    assert_eq!(c.max_frame_payload(), 16 * 1024 * 1024);
    assert_eq!(c.max_message_size(), 64 * 1024 * 1024);
    let c = ConnectionConfig::new()
      .with_max_frame_payload(10)
      .with_max_message_size(20);
    assert_eq!(c.max_frame_payload(), 10);
    assert_eq!(c.max_message_size(), 20);
  }

  #[test]
  fn connection_constructs_from_negotiated() {
    let conn: Connection<TestInstant, Server> = Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(0),
    );
    assert!(!conn.is_terminal());
  }

  #[test]
  fn keepalive_pings_on_inbound_silence() {
    use core::time::Duration;
    let config = ConnectionConfig::new().with_keepalive(Some(Duration::from_secs(5)));
    let mut conn: Connection<TestInstant, Server> =
      Connection::new(&Negotiated::none(), config, Server::new(), TestInstant(0));

    // Armed from construction.
    assert_eq!(conn.poll_timeout(), Some(TestInstant(5_000_000)));
    // Not yet due: nothing happens.
    assert!(
      conn
        .handle_timeout(TestInstant(4_999_999))
        .expect("a monotonic instant")
        .is_none()
    );
    let mut out = [0u8; 16];
    // This drain used to be spelled `TestInstant(0)` — a REWIND, since the tick
    // above already handed the connection 4_999_999. It was incidental rather
    // than deliberate: what the line asserts is that nothing is queued yet, and
    // no instant it could be given changes that. Spelled at the same instant the
    // tick used, it says the same thing and keeps the clock monotone.
    assert!(
      conn
        .poll_transmit(TestInstant(4_999_999), &mut out)
        .unwrap()
        .is_none()
    );
    // Due: queues an empty ping and re-arms.
    assert!(
      conn
        .handle_timeout(TestInstant(5_000_000))
        .expect("a monotonic instant")
        .is_none()
    );
    let n = conn
      .poll_transmit(TestInstant(5_000_000), &mut out)
      .unwrap()
      .unwrap();
    assert_eq!(&out[..n], &[0x89, 0x00]);
    assert_eq!(conn.poll_timeout(), Some(TestInstant(10_000_000)));

    // Inbound traffic re-arms.
    let mut ping = crate::connection::tests::masked_frame(crate::frame::Opcode::Ping, true, b"x");
    {
      let mut ev = conn.handle(TestInstant(7_000_000), &mut ping).unwrap();
      while ev.next().is_some() {}
    }
    assert_eq!(conn.poll_timeout(), Some(TestInstant(12_000_000)));
  }

  /// The monotonicity contract, at all three entry points that take a `now`.
  ///
  /// The state comparison is a `Debug` render taken before and after, which is
  /// the cheapest thing that is actually BYTE-identical rather than
  /// spot-checked: it covers the lifecycle, both deadlines, the outbound
  /// control slot, the frame and message cursors and the recorded instant at
  /// once, so a refusal that quietly advanced any one of them reds here. A
  /// handful of `assert_eq!`s on the fields somebody thought to name would not.
  #[cfg(not(feature = "assert-contracts"))]
  #[test]
  fn a_rewound_now_is_refused_everywhere_and_changes_nothing() {
    use super::{EncodeError, HandleError, TimeoutError};
    use crate::frame::Opcode;

    let mut conn: Connection<TestInstant, Server> = Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(1_000),
    );

    // Give it state worth leaving alone: a received ping owes a pong, which
    // sits in the outbound control slot.
    let mut ping = masked_frame(Opcode::Ping, true, b"abc");
    {
      let mut ev = conn.handle(TestInstant(2_000), &mut ping).expect("forward");
      while ev.next().is_some() {}
    }

    let snapshot = format!("{conn:?}");
    let mut out = [0u8; 32];
    let mut more = masked_frame(Opcode::Ping, true, b"xyz");
    let more_before = more.clone();

    // `handle`: refused, and `data` is not read.
    assert!(matches!(
      conn.handle(TestInstant(1_999), &mut more),
      Err(HandleError::ClockWentBackwards)
    ));
    assert_eq!(more, more_before, "a refused handle unmasks nothing");
    assert_eq!(format!("{conn:?}"), snapshot);

    // `poll_transmit`: refused, and nothing is written or dequeued — the pong
    // is still owed.
    assert!(matches!(
      conn.poll_transmit(TestInstant(1_999), &mut out),
      Err(EncodeError::ClockWentBackwards)
    ));
    assert_eq!(out, [0u8; 32], "a refused drain writes nothing");
    assert_eq!(format!("{conn:?}"), snapshot);

    // `handle_timeout`: refused, no timer moves.
    assert!(matches!(
      conn.handle_timeout(TestInstant(1_999)),
      Err(TimeoutError::ClockWentBackwards)
    ));
    assert_eq!(format!("{conn:?}"), snapshot);

    // EQUAL is accepted at all three, which is the shape a driver that reads
    // its clock once per wakeup and fans it across a batch depends on.
    assert!(conn.handle_timeout(TestInstant(2_000)).is_ok());
    {
      let mut ev = conn
        .handle(TestInstant(2_000), &mut more)
        .expect("an equal instant is not a rewind");
      while ev.next().is_some() {}
    }
    let n = conn
      .poll_transmit(TestInstant(2_000), &mut out)
      .expect("an equal instant is not a rewind")
      .expect("the pong the refused drain left owed");
    assert_eq!(out[0], 0x8A, "and it is still a pong");
    let _ = n;
  }

  /// The instant [`Connection::new`] was given is the first floor: the very
  /// first `now`-taking call is compared against it. That is why the recorded
  /// instant is an `I` rather than an `Option<I>` — there is no "no clock yet"
  /// state, so there is no first call that skips the check.
  #[cfg(not(feature = "assert-contracts"))]
  #[test]
  fn the_constructing_instant_is_the_first_floor() {
    use super::EncodeError;

    let mut conn: Connection<TestInstant, Server> = Connection::new(
      &Negotiated::none(),
      ConnectionConfig::default(),
      Server::new(),
      TestInstant(5_000),
    );
    let mut out = [0u8; 8];
    assert!(matches!(
      conn.poll_transmit(TestInstant(4_999), &mut out),
      Err(EncodeError::ClockWentBackwards)
    ));
    // At it, and past it.
    assert!(conn.poll_transmit(TestInstant(5_000), &mut out).is_ok());
    assert!(conn.handle_timeout(TestInstant(9_999)).is_ok());
  }

  /// The same contract under `assert-contracts`, at each of the three entry
  /// points, one panic per test because a `should_panic` test can only witness
  /// the first.
  ///
  /// These are the mirrors of the two tests above, which are gated OFF under
  /// the feature: with it on there is no returned `Err` to inspect and no
  /// surviving state to compare, because the process is going down. Splitting
  /// them is what lets `cargo test --all-features` and `cargo hack
  /// --each-feature` run a crate whose behaviour the flag genuinely changes.
  ///
  /// `expected` matches the CONTRACT's own words rather than "panicked", so a
  /// panic that arrived from somewhere else — a bounds check, an unwrap in a
  /// helper — does not pass for this one.
  #[cfg(feature = "assert-contracts")]
  mod assert_contracts {
    use super::*;
    use crate::frame::Opcode;

    fn at(now: u64) -> Connection<TestInstant, Server> {
      Connection::new(
        &Negotiated::none(),
        ConnectionConfig::default(),
        Server::new(),
        TestInstant(now),
      )
    }

    #[test]
    #[should_panic(expected = "`now` must not go backwards")]
    fn handle_panics_on_a_rewound_now() {
      let mut conn = at(1_000);
      let mut frame = masked_frame(Opcode::Ping, true, b"x");
      let _ = conn.handle(TestInstant(999), &mut frame);
    }

    #[test]
    #[should_panic(expected = "`now` must not go backwards")]
    fn poll_transmit_panics_on_a_rewound_now() {
      let mut conn = at(1_000);
      let mut out = [0u8; 16];
      let _ = conn.poll_transmit(TestInstant(999), &mut out);
    }

    #[test]
    #[should_panic(expected = "`now` must not go backwards")]
    fn handle_timeout_panics_on_a_rewound_now() {
      let mut conn = at(1_000);
      let _ = conn.handle_timeout(TestInstant(999));
    }

    /// And the feature does NOT turn every refusal into a panic: an equal
    /// instant is still accepted, so a driver batching one clock read across
    /// several calls does not trip it.
    #[test]
    fn an_equal_now_still_does_not_panic() {
      let mut conn = at(1_000);
      let mut out = [0u8; 16];
      assert!(conn.handle_timeout(TestInstant(1_000)).is_ok());
      assert!(conn.poll_transmit(TestInstant(1_000), &mut out).is_ok());
    }
  }

  #[test]
  fn close_timeout_fires_unclean() {
    use core::time::Duration;
    let config = ConnectionConfig::new().with_close_timeout(Duration::from_secs(3));
    let mut conn: Connection<TestInstant, Server> =
      Connection::new(&Negotiated::none(), config, Server::new(), TestInstant(0));

    conn.close(crate::frame::CloseCode::GoingAway, "").unwrap();
    // Deadline arms when the frame DRAINS, not at close().
    assert_eq!(conn.poll_timeout(), None);
    let mut out = [0u8; 16];
    conn
      .poll_transmit(TestInstant(1_000_000), &mut out)
      .unwrap()
      .unwrap();
    assert_eq!(conn.poll_timeout(), Some(TestInstant(4_000_000)));

    // Keepalive does not surface in CloseSent.
    // (Even if a keepalive config is present, only close deadline appears.)
    let config2 = ConnectionConfig::new()
      .with_keepalive(Some(Duration::from_secs(1)))
      .with_close_timeout(Duration::from_secs(3));
    let mut conn2: Connection<TestInstant, Server> =
      Connection::new(&Negotiated::none(), config2, Server::new(), TestInstant(0));
    conn2.close(crate::frame::CloseCode::GoingAway, "").unwrap();
    conn2
      .poll_transmit(TestInstant(1_000_000), &mut out)
      .unwrap()
      .unwrap();
    // Only the close deadline, not the keepalive.
    assert_eq!(conn2.poll_timeout(), Some(TestInstant(4_000_000)));

    // Peer never answers: terminal, unclean, our code.
    let closed = conn
      .handle_timeout(TestInstant(4_000_000))
      .expect("a monotonic instant")
      .expect("the close deadline fires");
    assert_eq!(closed.code(), crate::frame::CloseCode::GoingAway);
    assert!(!closed.clean());
    assert!(conn.is_terminal());
  }

  #[test]
  fn peer_echo_clears_the_close_deadline() {
    use core::time::Duration;
    let config = ConnectionConfig::new().with_close_timeout(Duration::from_secs(3));
    let mut conn: Connection<TestInstant, Server> =
      Connection::new(&Negotiated::none(), config, Server::new(), TestInstant(0));
    conn.close(crate::frame::CloseCode::Normal, "").unwrap();
    let mut out = [0u8; 16];
    conn
      .poll_transmit(TestInstant(0), &mut out)
      .unwrap()
      .unwrap();
    assert!(conn.poll_timeout().is_some());

    let mut payload = [0u8; 4];
    let n = crate::frame::encode_close_payload(crate::frame::CloseCode::Normal, "", &mut payload)
      .unwrap();
    let mut echo = crate::connection::tests::masked_frame_payload(
      crate::frame::Opcode::Close,
      true,
      &payload[..n],
    );
    {
      let mut ev = conn.handle(TestInstant(1_000_000), &mut echo).unwrap();
      // CloseReceived + Closed{clean: true}.
      assert!(matches!(
        ev.next(),
        Some(crate::connection::Event::CloseReceived(_))
      ));
      assert!(matches!(ev.next(), Some(crate::connection::Event::Closed(c)) if c.clean()));
      assert!(ev.next().is_none());
    }
    assert!(conn.is_terminal());
    assert_eq!(conn.poll_timeout(), None);
  }

  mod properties {
    use super::*;
    use crate::connection::role::Client;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
      Text(String),
      Binary(Vec<u8>),
      FragText(Vec<String>),
      Ping(Vec<u8>),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
      prop_oneof![
        ".{0,64}".prop_map(Op::Text),
        proptest::collection::vec(any::<u8>(), 0..64).prop_map(Op::Binary),
        proptest::collection::vec(".{0,16}", 1..4).prop_map(Op::FragText),
        proptest::collection::vec(any::<u8>(), 0..32).prop_map(Op::Ping),
      ]
    }

    fn encode_script(ops: &[Op]) -> Vec<u8> {
      use crate::connection::send::FragmentKind;
      let mut conn: Connection<TestInstant, Client<CountingRng>> = Connection::new(
        &Negotiated::none(),
        ConnectionConfig::default(),
        Client::new(CountingRng(7)),
        TestInstant(0),
      );
      let mut wire = Vec::new();
      let mut buf = vec![0u8; 1 << 12];
      for op in ops {
        match op {
          Op::Text(s) => {
            let n = conn.encode_text(s, &mut buf).unwrap();
            wire.extend_from_slice(&buf[..n]);
          }
          Op::Binary(b) => {
            let n = conn.encode_binary(b, &mut buf).unwrap();
            wire.extend_from_slice(&buf[..n]);
          }
          Op::FragText(parts) => {
            for (i, part) in parts.iter().enumerate() {
              let kind = if i == 0 {
                FragmentKind::TextStart
              } else {
                FragmentKind::Continue
              };
              let fin = i == parts.len() - 1;
              let n = conn
                .encode_fragment(kind, fin, part.as_bytes(), &mut buf)
                .unwrap();
              wire.extend_from_slice(&buf[..n]);
            }
          }
          Op::Ping(p) => {
            let p = &p[..p.len().min(125)];
            let n = conn.encode_ping(p, &mut buf).unwrap();
            wire.extend_from_slice(&buf[..n]);
          }
        }
      }
      wire
    }

    fn run(srv: &mut Connection<TestInstant, Server>, pieces: &[&[u8]]) -> Vec<Ev> {
      let mut out = Vec::new();
      for piece in pieces {
        out.extend(drain(srv, piece));
      }
      fold_events(out)
    }

    proptest! {
      #[test]
      fn split_anywhere_is_invariant(
        ops in proptest::collection::vec(op_strategy(), 0..6),
        cuts in proptest::collection::vec(any::<u16>(), 0..6),
      ) {
        let wire = encode_script(&ops);

        let mut reference = server();
        let expected = run(&mut reference, &[&wire]);

        let mut points: Vec<usize> =
          cuts.iter().map(|&c| usize::from(c) % (wire.len() + 1)).collect();
        points.sort_unstable();
        points.dedup();
        let mut pieces: Vec<&[u8]> = Vec::new();
        let mut start = 0;
        for &p in &points {
          pieces.push(&wire[start..p]);
          start = p;
        }
        pieces.push(&wire[start..]);

        let mut split_conn = server();
        let got = run(&mut split_conn, &pieces);
        prop_assert_eq!(got, expected);

        // And the content matches the script.
        let mut expected_content: Vec<Ev> = Vec::new();
        for op in &ops {
          match op {
            Op::Text(s) => {
              expected_content.push(Ev::Start(MessageKind::Text, false));
              if !s.is_empty() {
                expected_content.push(Ev::Text(s.clone()));
              }
              expected_content.push(Ev::End);
            }
            Op::FragText(parts) => {
              expected_content.push(Ev::Start(MessageKind::Text, false));
              let joined: String = parts.concat();
              if !joined.is_empty() {
                expected_content.push(Ev::Text(joined));
              }
              expected_content.push(Ev::End);
            }
            Op::Binary(b) => {
              expected_content.push(Ev::Start(MessageKind::Binary, false));
              if !b.is_empty() {
                expected_content.push(Ev::Bin(b.clone()));
              }
              expected_content.push(Ev::End);
            }
            Op::Ping(p) => {
              expected_content.push(Ev::Ping(p[..p.len().min(125)].to_vec()));
            }
          }
        }
        prop_assert_eq!(run(&mut server(), &[&wire]), expected_content);
      }
    }
  }
}
