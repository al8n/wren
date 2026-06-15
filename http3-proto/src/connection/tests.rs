use std::vec::Vec;

use super::*;
use crate::event::{StreamKind, StreamRole};

/// The CONNECT request a WebSocket client sends (RFC 9220 Extended CONNECT).
const CONNECT_REQUEST: [(&str, &str); 5] = [
  (":method", "CONNECT"),
  (":scheme", "https"),
  (":path", "/chat"),
  (":authority", "example.com"),
  (":protocol", "websocket"),
];

/// The server's accepting response.
const RESPONSE: [(&str, &str); 1] = [(":status", "200")];

/// A captured transmit: owned bytes plus the routing metadata.
struct Captured {
  kind: StreamKind,
  bytes: Vec<u8>,
  fin: bool,
}

/// Pairs a client and server connection over a single shared stream-id space
/// (the same [`StreamId`] identifies a stream on both ends), routing transmits
/// between them and recording the observable outcomes.
struct Harness {
  client: Connection<Client>,
  server: Connection<Server>,
  next_id: u64,
  client_established: bool,
  server_established: bool,
  server_saw_request: bool,
  client_saw_response: bool,
  /// Bytes the server received over the tunnel (DATA frames).
  server_rx: Vec<u8>,
  /// Bytes the client received over the tunnel (DATA frames).
  client_rx: Vec<u8>,
  /// The id assigned to the bidirectional request stream, once opened.
  request_id: Option<StreamId>,
}

/// Which peer a captured transmit is being delivered to.
#[derive(Clone, Copy)]
enum Side {
  Client,
  Server,
}

impl Harness {
  fn new() -> Self {
    Self {
      client: Connection::new(),
      server: Connection::new(),
      next_id: 0,
      client_established: false,
      server_established: false,
      server_saw_request: false,
      client_saw_response: false,
      server_rx: Vec::new(),
      client_rx: Vec::new(),
      request_id: None,
    }
  }

  fn fresh_id(&mut self) -> StreamId {
    let id = StreamId::new(self.next_id);
    self.next_id = self.next_id.wrapping_add(1);
    id
  }

  /// Drains every queued transmit from `from`, assigning ids to opened streams
  /// and delivering the bytes to the other peer.
  fn flush(&mut self, from: Side) {
    loop {
      // Capture one transmit (copying its bytes so the borrow ends).
      let captured = {
        let conn_tx = match from {
          Side::Client => self.client.poll_transmit(),
          Side::Server => self.server.poll_transmit(),
        };
        match conn_tx {
          None => break,
          Some(t) => Captured {
            kind: t.kind(),
            bytes: t.bytes().to_vec(),
            fin: t.fin(),
          },
        }
      };
      self.route(from, captured);
    }
  }

  /// Routes one captured transmit: resolve/assign its stream id, register the
  /// stream on the relevant side(s), then deliver the bytes to the peer.
  fn route(&mut self, from: Side, cap: Captured) {
    let to = match from {
      Side::Client => Side::Server,
      Side::Server => Side::Client,
    };
    let id = match cap.kind {
      StreamKind::Existing(id) => id,
      StreamKind::OpenUni(role) => {
        let id = self.fresh_id();
        // The opener records its own outbound uni stream's id↔role.
        self.provide(from, role, id);
        id
      }
      StreamKind::OpenRequest => {
        let id = self.fresh_id();
        // Both ends register the bidi request stream (the driver registers the
        // inbound request when the peer opens it).
        self.provide(from, StreamRole::Request, id);
        self.provide(to, StreamRole::Request, id);
        self.request_id = Some(id);
        id
      }
    };
    // FIN carries no bytes for this harness; the request FSM models FIN via its
    // own `fin()`, which these tests do not exercise.
    let _ = cap.fin;
    self.deliver(to, id, &cap.bytes);
    self.drain_events();
  }

  fn provide(&mut self, side: Side, role: StreamRole, id: StreamId) {
    match side {
      Side::Client => self.client.provide_stream(role, id),
      Side::Server => self.server.provide_stream(role, id),
    }
  }

  /// Delivers `bytes` to `side`'s connection on stream `id`, draining the frames.
  fn deliver(&mut self, side: Side, id: StreamId, bytes: &[u8]) {
    let mut scratch = std::vec![0u8; 2048];
    match side {
      Side::Server => {
        let mut frames = self
          .server
          .handle_stream(id, bytes, &mut scratch)
          .expect("server handle_stream");
        while let Some(frame) = frames.next().expect("server frame") {
          match frame {
            Frame::Request(mut hs) => {
              self.server_saw_request = true;
              // Drain the header set so its borrow is consumed.
              while hs.next().expect("req header").is_some() {}
            }
            Frame::Response(_) => panic!("server received a Response"),
            Frame::Data(chunk) => self.server_rx.extend_from_slice(chunk),
          }
        }
      }
      Side::Client => {
        let mut frames = self
          .client
          .handle_stream(id, bytes, &mut scratch)
          .expect("client handle_stream");
        while let Some(frame) = frames.next().expect("client frame") {
          match frame {
            Frame::Response(mut hs) => {
              self.client_saw_response = true;
              while hs.next().expect("resp header").is_some() {}
            }
            Frame::Request(_) => panic!("client received a Request"),
            Frame::Data(chunk) => self.client_rx.extend_from_slice(chunk),
          }
        }
      }
    }
  }

  /// Drains both sides' event queues, recording `Established`.
  fn drain_events(&mut self) {
    while let Some(ev) = self.client.poll_event() {
      if ev.is_established() {
        self.client_established = true;
      }
    }
    while let Some(ev) = self.server.poll_event() {
      if ev.is_established() {
        self.server_established = true;
      }
    }
  }

  /// Pumps both directions once (client→server, then server→client).
  fn pump(&mut self) {
    self.flush(Side::Client);
    self.flush(Side::Server);
    self.drain_events();
  }

  /// Pumps until both peers report `Established`, accepting the request on the
  /// server when its CONNECT HEADERS arrive. Fails the test if it does not
  /// converge within a bounded number of rounds.
  fn run_until_established(&mut self) {
    self.server.start().expect("server start");
    for _ in 0..16 {
      self.pump();
      // When the server has seen the request but not yet accepted, accept it.
      if self.server_saw_request && !self.server_established {
        self.server.accept_with(&RESPONSE[..]).expect("accept_with");
      }
      if self.client_established && self.server_established {
        return;
      }
    }
    panic!(
      "did not establish: client_established={} server_established={} server_saw_request={}",
      self.client_established, self.server_established, self.server_saw_request
    );
  }
}

#[test]
fn client_server_connect_then_tunnel() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  assert!(h.client_established && h.server_established);
  assert!(h.server_saw_request);
  assert!(h.client_saw_response);
  h.client.send_data(b"ping").unwrap();
  h.pump();
  assert_eq!(h.server_rx.as_slice(), b"ping");
}

#[test]
fn send_data_before_established_errors() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  assert!(h.client.send_data(b"x").is_err());
}

#[test]
fn server_receives_connect_protocol_setting() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  // The client received the server's SETTINGS, which advertise Extended CONNECT.
  let peer = h.client.peer_settings().expect("client has peer settings");
  assert!(peer.enable_connect_protocol());
  // The server received the client's SETTINGS (client does not advertise it).
  let peer = h.server.peer_settings().expect("server has peer settings");
  assert!(!peer.enable_connect_protocol());
}

#[test]
fn bidirectional_tunnel_data() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  h.client.send_data(b"client->server").unwrap();
  h.server.send_data(b"server->client").unwrap();
  h.pump();
  assert_eq!(h.server_rx.as_slice(), b"client->server");
  assert_eq!(h.client_rx.as_slice(), b"server->client");
}

#[test]
fn close_enqueues_fin_transmit() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  h.client.close();
  // The next client transmit is an empty FIN on the request stream.
  let t = h.client.poll_transmit().expect("fin transmit");
  assert!(t.fin());
  assert!(t.bytes().is_empty());
  assert!(matches!(t.kind(), StreamKind::Existing(_)));
  // After close, further sends error.
  assert!(h.client.send_data(b"x").is_err());
}

#[test]
fn reset_enqueues_reset_event_and_closes() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  let req_id = h.request_id.expect("request id assigned");
  h.client.handle_stream_reset(req_id, 0x010c);
  let ev = h.client.poll_event().expect("reset event");
  assert!(matches!(ev, Event::Reset(0x010c)));
  assert!(h.client.send_data(b"x").is_err());
}

#[test]
fn server_accept_before_request_errors() {
  let mut s: Connection<Server> = Connection::new();
  s.start().unwrap();
  // No request stream registered yet → accept_with errors.
  assert!(s.accept_with(&RESPONSE[..]).is_err());
}

#[test]
fn data_split_across_transmits_reassembles() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  h.client.send_data(b"aa").unwrap();
  h.client.send_data(b"bb").unwrap();
  h.client.send_data(b"cc").unwrap();
  h.pump();
  assert_eq!(h.server_rx.as_slice(), b"aabbcc");
}

#[test]
fn send_data_payload_larger_than_slot_errors_not_panics() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  // A payload that, even before its frame header, cannot fit one transmit slot.
  let big = std::vec![0u8; super::queue::TX_CAP + 1];
  let err = h
    .client
    .send_data(&big)
    .expect_err("oversized send must error");
  // The too-large case is the framing/protocol error, not WouldBlock.
  assert!(matches!(err, Error::Protocol(H3Error::FrameError)));
}

#[test]
fn filling_transmit_queue_returns_would_block() {
  let mut h = Harness::new();
  h.client.open_with(&CONNECT_REQUEST[..]).unwrap();
  h.run_until_established();
  // After establishment the client's transmit ring is drained; fill it without
  // draining. The ring holds TX_N slots, so by TX_N + 1 enqueues it is full.
  let mut last = Ok(());
  for _ in 0..(super::queue::TX_N + 1) {
    last = h.client.send_data(b"x");
    if last.is_err() {
      break;
    }
  }
  assert_eq!(last, Err(Error::WouldBlock));
}

#[test]
fn grease_uni_stream_is_ignored() {
  let mut c: Connection<Client> = Connection::new();
  let id = StreamId::new(42);
  let mut scratch = std::vec![0u8; 64];
  // 0x21 is a reserved/GREASE stream type (0x1f * N + 0x21); its bytes are
  // discarded with no frames and no error (RFC 9114 §6.2 / §9).
  let mut frames = c
    .handle_stream(id, &[0x21, 0xaa, 0xbb], &mut scratch)
    .expect("grease uni stream must not error");
  assert!(frames.next().expect("no frames").is_none());
  // Subsequent bytes on the same ignored stream are still discarded cleanly.
  let mut frames = c
    .handle_stream(id, &[0xcc, 0xdd], &mut scratch)
    .expect("ignored stream stays ignored");
  assert!(frames.next().expect("no frames").is_none());
}

#[test]
fn handle_stream_fin_clean_boundary_enqueues_peer_closed() {
  let mut c: Connection<Client> = Connection::new();
  let id = StreamId::new(7);
  c.provide_stream(StreamRole::Request, id);
  // The request FSM is fresh (at a frame boundary): a FIN is a clean end.
  c.handle_stream_fin(id);
  assert_eq!(c.poll_event(), Some(Event::PeerClosed));
  assert_eq!(c.poll_event(), None);
}

#[test]
fn handle_stream_fin_mid_frame_enqueues_conn_error() {
  let mut c: Connection<Client> = Connection::new();
  let id = StreamId::new(7);
  c.provide_stream(StreamRole::Request, id);
  // Feed one byte of a frame header (0x01 = HEADERS type, length varint missing),
  // leaving the FSM mid-frame; no items are produced yet. Scope the borrow so the
  // connection is free for the FIN call below.
  let mut scratch = std::vec![0u8; 64];
  {
    let mut frames = c
      .handle_stream(id, &[0x01], &mut scratch)
      .expect("partial header must not error");
    assert!(frames.next().expect("no frames yet").is_none());
  }
  // A FIN now ends the stream mid-frame: a connection-level frame error.
  c.handle_stream_fin(id);
  assert_eq!(c.poll_event(), Some(Event::ConnError(H3Error::FrameError)));
  assert_eq!(c.poll_event(), None);
}
