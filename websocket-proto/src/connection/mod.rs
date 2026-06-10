//! The transport-blind WebSocket connection state machine (RFC 6455 §5–§8).
//!
//! One [`Connection`] serves any reliable byte stream — an HTTP/1.1-upgraded
//! TCP socket, an HTTP/2 stream (RFC 8441), or an HTTP/3 stream (RFC 9220) —
//! because those transports change only the opening handshake. Construct it
//! from the handshake's [`Negotiated`](crate::negotiation::Negotiated) plus a
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
  pub(crate) _clock: core::marker::PhantomData<I>,
}

/// Connection lifecycle (close handshake per RFC 6455 §7).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Lifecycle {
  /// Open for data both ways.
  Open,
  /// We sent (queued) a close; awaiting the peer's echo.
  CloseSent,
  /// Peer's close received (echo queued); inbound is drained/discarded.
  PeerClosed,
  /// Terminal: close exchange finished or the connection failed.
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
      _clock: core::marker::PhantomData,
    }
  }

  /// True once the connection is terminal (cleanly closed or failed):
  /// `handle` refuses further input and the transport can be dropped after
  /// a final [`poll_transmit`](Connection::poll_transmit) drain.
  pub const fn is_terminal(&self) -> bool {
    matches!(self.lifecycle, Lifecycle::Terminal)
  }

  /// Returns the next deadline the caller must arrange to fire
  /// [`handle_timeout`](Connection::handle_timeout) at. Returns `None` when
  /// no timers are armed.
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

  /// Advances the timer state to `now`. Returns `Some(Closed)` when the
  /// close-handshake timeout fires; returns `None` when a keepalive ping is
  /// queued (drain [`poll_transmit`](Connection::poll_transmit)).
  pub fn handle_timeout(&mut self, now: I) -> Option<Closed> {
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
      return Some(Closed::new(code, false));
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
    None
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
    assert!(conn.handle_timeout(TestInstant(4_999_999)).is_none());
    let mut out = [0u8; 16];
    assert!(
      conn
        .poll_transmit(TestInstant(0), &mut out)
        .unwrap()
        .is_none()
    );
    // Due: queues an empty ping and re-arms.
    assert!(conn.handle_timeout(TestInstant(5_000_000)).is_none());
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
    let closed = conn.handle_timeout(TestInstant(4_000_000)).unwrap();
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
