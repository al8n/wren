use std::{
  string::{String, ToString},
  vec::Vec,
};

use super::*;
use crate::{
  event::{StreamKind, StreamRole},
  stream::HDR_CAP,
};

type StaticConnection<Ro> = Connection<'static, 'static, 'static, 'static, 'static, Ro>;
type StaticBorrowedConnection<Ro> =
  BorrowedConnection<'static, 'static, 'static, 'static, 'static, Ro>;

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

#[test]
fn connection_value_is_small_with_handle_backed_storage() {
  let borrowed = core::mem::size_of::<StaticBorrowedConnection<Client>>();
  let default = core::mem::size_of::<StaticConnection<Client>>();
  // The connection stores buffer *handles* and state inline — never the byte
  // buffers. On the heap tiers the transmit ring additionally holds one optional
  // refcounted DATA body (`DataBuf`) per slot so queued DATA is vectored
  // zero-copy; those are still small handles (a refcounted pointer each), but
  // `TX_N` of them widen the inline ring past the original 1 KiB bound — hence the
  // slightly larger ceiling here.
  assert!(
    borrowed < 1280,
    "borrowed connection should only store buffer handles and state, got {borrowed}"
  );
  assert!(
    default < 1280,
    "default std/alloc connection should only store buffer handles and state, got {default}"
  );
}

#[test]
fn borrowed_transmit_storage_controls_queue_capacity() {
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  let mut tx_bytes = [0u8; super::queue::TX_CAP * 3];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  let mut c = BorrowedConnection::<Client>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
  );

  assert!(c.tx.has_capacity_mut(3));
  assert!(!c.tx.has_capacity_mut(4));
  c.start().expect("three setup transmits fit");
  assert!(!c.tx.has_capacity_mut(1));

  let mut drained = 0usize;
  while c.poll_transmit().is_some() {
    drained = drained.saturating_add(1);
  }
  assert_eq!(drained, 3);
  assert!(c.tx.has_capacity_mut(3));
}

/// Fills the next free transmit slot with `n` zero bytes via `enqueue`, asserting
/// it succeeds.
fn push_tx<B: AsMut<[u8]>>(ring: &mut super::queue::TxRing<'_, B>, n: usize) {
  ring
    .enqueue(StreamKind::OpenRequest, false, |buf| {
      let take = n.min(buf.len());
      buf.get_mut(..take).map_or(Err(()), |slot| {
        slot.fill(0);
        Ok::<usize, ()>(take)
      })
    })
    .map_err(|_| ())
    .expect("slot is free");
}

#[test]
fn tx_ring_trailing_partial_chunk_is_ignored() {
  // TX_CAP*3 + 100: three whole slots plus a partial that must NOT count.
  let mut bytes = std::vec![0u8; super::queue::TX_CAP * 3 + 100];
  let mut ring = super::queue::TxRing::with_buffer(&mut bytes[..]);
  assert!(ring.has_capacity_mut(3));
  assert!(!ring.has_capacity_mut(4));
  for _ in 0..3 {
    push_tx(&mut ring, 1);
  }
  // The partial chunk yields no fourth slot.
  assert!(!ring.has_capacity_mut(1));
}

#[test]
fn tx_ring_oversized_buffer_caps_at_tx_n() {
  // A buffer far larger than the default still yields only TX_N slots, so the
  // fixed `slots` array is never indexed out of range.
  let mut bytes = std::vec![0u8; super::queue::TX_BYTES_CAP + super::queue::TX_CAP * 4];
  let mut ring = super::queue::TxRing::with_buffer(&mut bytes[..]);
  assert!(ring.has_capacity_mut(super::queue::TX_N));
  assert!(!ring.has_capacity_mut(super::queue::TX_N + 1));
  // Fill every slot and drain it: exercises enqueue/poll wrap at the TX_N cap.
  for _ in 0..super::queue::TX_N {
    push_tx(&mut ring, 1);
  }
  assert!(!ring.has_capacity_mut(1));
  let mut drained = 0usize;
  while ring.poll().is_some() {
    drained = drained.saturating_add(1);
  }
  assert_eq!(drained, super::queue::TX_N);
}

#[test]
fn bounded_queue_shorter_slice_uses_shorter_capacity() {
  // A slice SHORTER than EVENT_CAP caps the queue at the slice length.
  let short = EVENT_QUEUE_CAP - 2;
  let mut slots = std::vec![None; short];
  let mut q = super::queue::BoundedQueue::<Event, _>::with_buffer(&mut slots[..]);
  for _ in 0..short {
    q.push(Event::Established)
      .expect("fits under the shorter cap");
  }
  // Full at the shorter cap, not at EVENT_CAP.
  assert!(q.push(Event::Established).is_err());
  assert!(matches!(q.pop(), Some(Event::Established)));
  // After a clear the shorter-capacity queue is reusable to the same bound.
  q.clear();
  assert!(q.pop().is_none());
  for _ in 0..short {
    q.push(Event::Established).expect("reusable after clear");
  }
  assert!(q.push(Event::Established).is_err());
}

#[test]
fn bounded_queue_longer_slice_uses_full_capacity() {
  // The backing slice's length is the capacity: a slice LONGER than the default
  // EVENT_CAP is NOT capped — it uses its full length (consistent with `TxRing`,
  // which bounds capacity by its byte buffer's length and never caps it).
  let long = EVENT_QUEUE_CAP + 4;
  let mut slots = std::vec![None; long];
  let mut q = super::queue::BoundedQueue::<Event, _>::with_buffer(&mut slots[..]);
  for _ in 0..long {
    q.push(Event::Established)
      .expect("fits up to the full slice length");
  }
  // Full at the full slice length, NOT at EVENT_CAP.
  assert!(q.push(Event::Established).is_err());
}

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
  client: StaticConnection<Client>,
  server: StaticConnection<Server>,
  next_id: u64,
  client_established: bool,
  server_established: bool,
  server_saw_request: bool,
  client_saw_response: bool,
  /// Set once the client has sent its CONNECT request via `open_with` (after the
  /// peer's SETTINGS arrived). The request is sent exactly once.
  client_opened: bool,
  /// Bytes the server received over the tunnel (DATA frames).
  server_rx: Vec<u8>,
  /// Bytes the client received over the tunnel (DATA frames).
  client_rx: Vec<u8>,
  /// Bytes the server received per request stream id (general DATA bodies).
  server_rx_by_id: std::collections::BTreeMap<u64, Vec<u8>>,
  /// Bytes the client received per request stream id (general DATA bodies).
  client_rx_by_id: std::collections::BTreeMap<u64, Vec<u8>>,
  /// Every request stream id the server observed as a `Frame::Request`, in order.
  server_request_ids: Vec<StreamId>,
  /// Set when the server observes a `Frame::Trailers` on any request stream.
  server_saw_trailers: bool,
  /// Every client response, in observation order, tagged `(interim, headers)` where
  /// `headers` is the decoded field section as `(name, value)` pairs. Populated by
  /// [`Harness::pump_collect_client_responses`].
  client_responses: Vec<(bool, Vec<(String, String)>)>,
  /// Whether `deliver` should record full client responses into `client_responses`
  /// (only the interim-precedes-final test needs the decoded headers).
  collect_client_responses: bool,
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
      client_opened: false,
      server_rx: Vec::new(),
      client_rx: Vec::new(),
      server_rx_by_id: std::collections::BTreeMap::new(),
      client_rx_by_id: std::collections::BTreeMap::new(),
      server_request_ids: Vec::new(),
      server_saw_trailers: false,
      client_responses: Vec::new(),
      collect_client_responses: false,
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
          Some(t) => {
            // A DATA transmit is vectored (`[frame-header, body]`); concatenate the
            // segments so the receiver sees the framed DATA as on the wire. Every
            // other transmit is single-segment, so this is just its one slice.
            let mut bytes = Vec::new();
            for seg in t.segments() {
              bytes.extend_from_slice(seg);
            }
            Captured {
              kind: t.kind(),
              bytes,
              fin: t.fin(),
            }
          }
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
      StreamKind::Existing(id) => {
        // `Existing(id)` only ever targets a bidi request stream (HEADERS / DATA /
        // FIN). The general `open_request` enqueues its request HEADERS on a
        // driver-minted id without an `OpenRequest` round-trip, so the receiving
        // peer learns of the new inbound bidi stream out of band — model that here
        // by provisioning the stream on the `to` side (idempotent: a re-provide of
        // an already-registered tunnel id is a no-op).
        self.provide(to, StreamRole::Request, id);
        id
      }
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
      StreamKind::ResetStream { id, code } => {
        // A `RESET_STREAM` abort carries no bytes: the driver issues a QUIC stream
        // reset, which the peer observes as `handle_stream_reset`. Deliver that and
        // stop (there is nothing to `deliver`).
        match to {
          Side::Client => self.client.handle_stream_reset(id, code),
          Side::Server => self.server.handle_stream_reset(id, code),
        }
        self.drain_events();
        return;
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
              self.server_request_ids.push(id);
              // Drain the header set so its borrow is consumed.
              while hs.next().expect("req header").is_some() {}
            }
            Frame::Trailers(mut hs) => {
              self.server_saw_trailers = true;
              while hs.next().expect("req trailer").is_some() {}
            }
            Frame::Response { .. } => panic!("server received a Response"),
            Frame::Data(chunk) => {
              self.server_rx.extend_from_slice(chunk);
              self
                .server_rx_by_id
                .entry(id.get())
                .or_default()
                .extend_from_slice(chunk);
            }
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
            Frame::Response {
              interim,
              mut headers,
            } => {
              if !interim {
                self.client_saw_response = true;
              }
              if self.collect_client_responses {
                let mut pairs = Vec::new();
                while let Some(p) = headers.next().expect("resp header") {
                  pairs.push((p.name().to_string(), p.value().to_string()));
                }
                self.client_responses.push((interim, pairs));
              } else {
                while headers.next().expect("resp header").is_some() {}
              }
            }
            Frame::Trailers(mut hs) => while hs.next().expect("resp trailer").is_some() {},
            Frame::Request(_) => panic!("client received a Request"),
            Frame::Data(chunk) => {
              self.client_rx.extend_from_slice(chunk);
              self
                .client_rx_by_id
                .entry(id.get())
                .or_default()
                .extend_from_slice(chunk);
            }
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

  /// Drives the full new client flow to Established on both sides:
  ///
  /// 1. `start()` both roles (control + QPACK setup).
  /// 2. Pump both directions; once the client has received the peer's SETTINGS
  ///    (`peer_settings().is_some()`) advertising Extended CONNECT, call
  ///    `open_with` exactly once to send the CONNECT request.
  /// 3. When the server sees the CONNECT HEADERS, call `accept_with`.
  ///
  /// Fails the test if it does not converge within a bounded number of rounds.
  fn run_until_established(&mut self) {
    self.client.start().expect("client start");
    self.server.start().expect("server start");
    for _ in 0..16 {
      self.pump();
      // Once the peer's SETTINGS (opt-in) have arrived, send the CONNECT request.
      if !self.client_opened
        && self
          .client
          .peer_settings()
          .is_some_and(|s| s.enable_connect_protocol())
      {
        self
          .client
          .open_with(&CONNECT_REQUEST[..])
          .expect("open_with");
        self.client_opened = true;
      }
      // When the server has seen the request but not yet accepted, accept it.
      // QUIC streams are unordered, so the request can arrive before the client's
      // control-stream SETTINGS; `accept_with` then returns WouldBlock until those
      // SETTINGS are decoded. Treat WouldBlock as "retry on the next pump"; any
      // other error fails the test.
      if self.server_saw_request && !self.server_established {
        match self.server.accept_with(&RESPONSE[..]) {
          Ok(()) => {}
          Err(Error::WouldBlock) => {}
          Err(e) => panic!("accept_with failed: {e:?}"),
        }
      }
      if self.client_established && self.server_established {
        return;
      }
    }
    panic!(
      "did not establish: client_established={} server_established={} server_saw_request={} client_opened={}",
      self.client_established, self.server_established, self.server_saw_request, self.client_opened
    );
  }

  /// `start()`s both roles and pumps until BOTH have decoded the peer's SETTINGS, so
  /// either direction can send HEADERS. Unlike [`run_until_established`] this opens no
  /// stream — the general tests drive `open_request` / `send_response` themselves.
  fn exchange_settings(&mut self) {
    self.client.start().expect("client start");
    self.server.start().expect("server start");
    for _ in 0..16 {
      self.pump();
      if self.client.peer_settings().is_some() && self.server.peer_settings().is_some() {
        return;
      }
    }
    panic!("peer SETTINGS never exchanged");
  }

  /// Brings up a GENERAL (non-CONNECT) request/response exchange to its final response
  /// on `id`: exchange SETTINGS, `open_request` a GET on `id`, then `send_response` a
  /// final 200. After this both the request and the final response have been observed,
  /// so DATA bodies flow in both directions. Returns the id it opened on.
  fn establish_general_get(&mut self, id: StreamId) -> StreamId {
    self.exchange_settings();
    let get: &[(&str, &str)] = &[
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/"),
      (":authority", "x"),
    ];
    self.client.open_request(id, get).expect("open_request");
    self.pump();
    let resp: &[(&str, &str)] = &[(":status", "200")];
    self
      .server
      .send_response(id, resp, true)
      .expect("send_response final");
    self.pump();
    id
  }

  /// Pumps both directions with full client-response capture enabled, recording every
  /// `Frame::Response` the client observes into `client_responses` as
  /// `(interim, headers)`.
  fn pump_collect_client_responses(&mut self) {
    self.collect_client_responses = true;
    self.pump();
    self.collect_client_responses = false;
  }

  /// The bytes the server received on request stream `id` (general DATA body).
  fn server_rx_for(&self, id: StreamId) -> &[u8] {
    self
      .server_rx_by_id
      .get(&id.get())
      .map_or(&[][..], Vec::as_slice)
  }

  /// The bytes the client received on request stream `id` (general DATA body).
  fn client_rx_for(&self, id: StreamId) -> &[u8] {
    self
      .client_rx_by_id
      .get(&id.get())
      .map_or(&[][..], Vec::as_slice)
  }
}

#[test]
fn client_server_connect_then_tunnel() {
  let mut h = Harness::new();
  h.run_until_established();
  assert!(h.client_established && h.server_established);
  assert!(h.server_saw_request);
  assert!(h.client_saw_response);
  h.client.send_data(b"ping").unwrap();
  h.pump();
  assert_eq!(h.server_rx.as_slice(), b"ping");
}

#[test]
fn general_request_response_headers_roundtrip() {
  // Client opens a normal GET; server sees Frame::Request, sends a final 200.
  let mut h = Harness::new();
  h.client.start().expect("c start");
  h.server.start().expect("s start");
  // Exchange SETTINGS so both directions can send HEADERS.
  for _ in 0..8 {
    h.pump();
    if h.client.peer_settings().is_some() && h.server.peer_settings().is_some() {
      break;
    }
  }
  // Client opens a GET request on a driver-minted bidi id (general API).
  let id = StreamId::new(0);
  let get: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "example.com"),
  ];
  h.client.open_request(id, get).expect("open_request");
  h.pump();
  assert!(h.server_saw_request, "server must observe Frame::Request");
  // Server responds 200 final on the same id (general API).
  let resp: &[(&str, &str)] = &[(":status", "200")];
  h.server
    .send_response(id, resp, true)
    .expect("send_response");
  h.pump();
  assert!(
    h.client_saw_response,
    "client must observe Frame::Response{{interim:false}}"
  );
}

#[test]
fn request_body_and_response_body_flow_both_directions() {
  let mut h = Harness::new();
  // SETTINGS + open GET on a driver-minted id + 200 final; returns the id.
  let id = h.establish_general_get(StreamId::new(0));
  // Client sends a request body chunk AFTER the request headers.
  h.client
    .send_data_on(id, bytes::Bytes::from_static(b"ping"))
    .expect("client body");
  h.pump();
  assert_eq!(h.server_rx, b"ping");
  // Server sends a response body chunk.
  h.server
    .send_data_on(id, bytes::Bytes::from_static(b"pong"))
    .expect("server body");
  h.pump();
  assert_eq!(h.client_rx, b"pong");
}

#[test]
fn send_data_zero_copy_vectored_output() {
  let mut h = Harness::new();
  let id = h.establish_general_get(StreamId::new(0));
  // Heap tier: send_data_on takes impl Into<DataBuf> (Bytes). Zero-copy: the body
  // slice in the transmit points into the held buffer.
  let body = bytes::Bytes::from_static(b"hello world");
  h.client.send_data_on(id, body).expect("send");
  // The transmit is vectored: segment 0 = DATA frame header, segment 1 = body.
  let t = h.client.poll_transmit().expect("transmit");
  let segs = t.segments();
  assert_eq!(segs.len(), 2);
  assert!(!segs[0].is_empty(), "frame header segment");
  assert_eq!(segs[1], b"hello world", "body segment (zero-copy)");
}

#[test]
fn partial_write_resumes_from_offset() {
  let mut h = Harness::new();
  let id = h.establish_general_get(StreamId::new(0));
  h.client
    .send_data_on(id, bytes::Bytes::from_static(b"abcdef"))
    .unwrap();
  // First poll: full vector. Simulate the driver writing only 2 total bytes.
  let total = h.client.poll_transmit().expect("t").len();
  assert!(total > 2);
  h.client.consume_transmit(2);
  // Next poll resumes: the same transmit, fewer remaining bytes.
  let remaining = h.client.poll_transmit().expect("t2").len();
  assert_eq!(remaining, total - 2);
  // Finish writing it.
  h.client.consume_transmit(remaining);
  assert!(h.client.poll_transmit().is_none());
}

#[test]
fn partial_write_mid_body_yields_only_remaining_body() {
  // A partial write that has fully written the frame header resumes mid-body: the
  // next poll's header segment is empty and the body segment is the unwritten tail.
  let mut h = Harness::new();
  let id = h.establish_general_get(StreamId::new(0));
  h.client
    .send_data_on(id, bytes::Bytes::from_static(b"abcdef"))
    .unwrap();
  let first = h.client.poll_transmit().expect("t");
  let header_len = first.segments().first().map(|s| s.len()).expect("header");
  let total = first.len();
  // Consume the whole header plus the first body byte.
  h.client.consume_transmit(header_len + 1);
  let t2 = h.client.poll_transmit().expect("t2");
  assert_eq!(t2.len(), total - header_len - 1);
  let segs = t2.segments();
  assert_eq!(segs.len(), 2, "still a vectored DATA transmit");
  assert!(segs[0].is_empty(), "header fully written");
  assert_eq!(segs[1], b"bcdef", "only the unwritten body tail remains");
}

#[test]
fn bare_tier_send_data_on_copies() {
  // Bare tier path is exercised by tiers.rs; here just assert &[u8] arity on the
  // heap tier still compiles via Into<DataBuf> for a slice copy.
  // (Heap: bytes::Bytes::copy_from_slice path.)
  let mut h = Harness::new();
  let id = h.establish_general_get(StreamId::new(0));
  h.client
    .send_data_on(id, bytes::Bytes::copy_from_slice(b"x"))
    .unwrap();
  assert!(h.client.poll_transmit().is_some());
}

#[test]
fn interim_1xx_precedes_final_response() {
  let mut h = Harness::new();
  h.exchange_settings();
  let id = StreamId::new(0);
  let get: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "x"),
  ];
  h.client.open_request(id, get).unwrap();
  h.pump();
  // Server sends 103 interim (last=false), then 200 final (last=true).
  h.server
    .send_response(id, &[(":status", "103")][..], false)
    .unwrap();
  h.server
    .send_response(id, &[(":status", "200")][..], true)
    .unwrap();
  // Collect every response frame the client observes, tagging interim.
  h.pump_collect_client_responses();
  assert_eq!(
    h.client_responses,
    std::vec![
      (true, std::vec![(":status".to_string(), "103".to_string())]),
      (false, std::vec![(":status".to_string(), "200".to_string())])
    ]
  );
}

#[test]
fn trailers_after_body_both_directions() {
  let mut h = Harness::new();
  let id = h.establish_general_get(StreamId::new(0));
  h.client
    .send_data_on(id, bytes::Bytes::from_static(b"x"))
    .unwrap();
  h.client
    .send_trailers(id, &[("x-checksum", "abc")][..])
    .unwrap();
  h.pump();
  assert!(h.server_saw_trailers, "server observes Frame::Trailers");
}

#[test]
fn incomplete_message_fin_before_headers_is_error() {
  let mut s = Connection::<Server>::new();
  s.start().unwrap();
  let id = StreamId::new(0);
  s.provide_stream(StreamRole::Request, id);
  s.handle_stream_fin(id); // FIN before any HEADERS
  assert!(matches!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::RequestIncomplete))
  ));
}

#[test]
fn general_client_final_response_establishes_per_stream_without_connection_event() {
  // A GENERAL client stream's FINAL response sets up `Frame::Data` flow (the per-stream
  // entry is `established`) but emits NO connection `Event::Established` and does NOT flip
  // the connection to `Phase::Open` — events are connection-scoped only (RFC 9114 §2), and
  // a general request stream is not the connection-scoped CONNECT tunnel. (The tunnel
  // keeps `Event::Established` + `Open`; see `client_server_connect_then_tunnel`.)
  let mut h = Harness::new();
  let id = h.establish_general_get(StreamId::new(0));
  // No connection-level establish for a general stream.
  assert!(
    !h.client_established,
    "a general client final response must NOT emit Event::Established"
  );
  assert!(
    !h.client.is_established(),
    "a general stream must NOT flip the connection to Open"
  );
  // Yet the per-stream entry IS established: DATA flows both ways.
  h.client
    .send_data_on(id, bytes::Bytes::from_static(b"req-body"))
    .expect("client body");
  h.server
    .send_data_on(id, bytes::Bytes::from_static(b"resp-body"))
    .expect("server body");
  h.pump();
  assert_eq!(h.server_rx, b"req-body");
  assert_eq!(h.client_rx, b"resp-body");
}

// Two concurrent request streams (distinct driver-minted ids) exchange interleaved
// frames with per-stream body isolation — the whole point of Phase 0 (#15). The
// per-stream RESET isolation half (a non-tunnel reset is stream-scoped) lives in the
// sibling test below.
#[test]
fn two_concurrent_request_streams_are_isolated() {
  let mut h = Harness::new();
  h.exchange_settings();
  let id_a = StreamId::new(0);
  let id_b = StreamId::new(4);
  let get: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "x"),
  ];
  // Open both request streams concurrently (distinct ids => distinct slots).
  h.client.open_request(id_a, get).unwrap();
  h.client.open_request(id_b, get).unwrap();
  h.pump();
  // Server saw two independent Frame::Request streams.
  assert_eq!(h.server_request_ids, std::vec![id_a, id_b]);
  // Interleave: respond on A, respond on B, body on A, body on B, in mixed order.
  h.server
    .send_response(id_a, &[(":status", "200")][..], true)
    .unwrap();
  h.server
    .send_response(id_b, &[(":status", "200")][..], true)
    .unwrap();
  h.client
    .send_data_on(id_a, bytes::Bytes::from_static(b"a-body"))
    .unwrap();
  h.client
    .send_data_on(id_b, bytes::Bytes::from_static(b"b-body"))
    .unwrap();
  h.pump();
  assert_eq!(h.server_rx_for(id_a), b"a-body");
  assert_eq!(h.server_rx_for(id_b), b"b-body");
  // Both streams remain usable: a trailing server→client body on each lands on the
  // right stream, proving per-stream isolation of the DATA path.
  h.server
    .send_data_on(id_a, bytes::Bytes::from_static(b"a-tail"))
    .unwrap();
  h.server
    .send_data_on(id_b, bytes::Bytes::from_static(b"b-tail"))
    .unwrap();
  h.pump();
  assert_eq!(h.client_rx_for(id_a), b"a-tail");
  assert_eq!(h.client_rx_for(id_b), b"b-tail");
  // Neither stream's traffic leaked into the connection-scoped tunnel buffers as the
  // sole occupant (each id has its own per-id buffer).
  assert!(!h.client.is_failed() && !h.server.is_failed());
}

// The per-stream RESET-isolation half of the concurrent-streams scenario: a real
// per-stream `reset_stream` for a non-tunnel stream is stream-scoped (not
// connection-fatal) and frees only the reset stream's slot, leaving the connection and
// every other stream live.
#[test]
fn two_concurrent_request_streams_reset_is_isolated() {
  let mut h = Harness::new();
  h.exchange_settings();
  let id_a = StreamId::new(0);
  let id_b = StreamId::new(4);
  let get: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "x"),
  ];
  h.client.open_request(id_a, get).unwrap();
  h.client.open_request(id_b, get).unwrap();
  h.pump();
  h.server
    .send_response(id_a, &[(":status", "200")][..], true)
    .unwrap();
  h.server
    .send_response(id_b, &[(":status", "200")][..], true)
    .unwrap();
  h.pump();
  // Reset stream A only (non-tunnel => stream-scoped). The connection and stream B
  // survive: B still carries a trailing exchange end to end.
  h.client.reset_stream(id_a, 0x010c); // H3_REQUEST_CANCELLED (raw u64 code)
  h.pump();
  assert!(
    !h.client.is_failed() && !h.server.is_failed(),
    "connection survives a per-stream reset"
  );
  assert!(h.server.stream_is_gone(id_a), "reset stream A is freed");
  h.server
    .send_data_on(id_b, bytes::Bytes::from_static(b"still-ok"))
    .unwrap();
  h.pump();
  assert_eq!(
    h.client_rx_for(id_b),
    b"still-ok",
    "stream B is undisturbed by A's reset"
  );
}

// A malformed RESPONSE on a GENERAL client stream is a STREAM error (RFC 9114 §4.1.2),
// not connection-fatal: `Frames::next` surfaces the `MessageError`, the connection is
// NOT failed, a `RESET_STREAM` for that stream is enqueued, the stream's slot is freed,
// and a concurrent general stream keeps working. This is the lazy-carrier
// (`fail_or_reset` → `pending_reset` → `apply_pending_reset`) path, distinct from the
// driver-requested `reset_stream` above. The client `open_request` stream is
// unambiguously non-tunnel (vs `open_with`'s tunnel), so the scope is clear.
#[test]
fn malformed_response_on_general_client_stream_resets_alone() {
  let mut h = Harness::new();
  h.exchange_settings();
  let id_a = StreamId::new(0);
  let id_b = StreamId::new(4);
  let get: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "x"),
  ];
  h.client.open_request(id_a, get).unwrap();
  h.client.open_request(id_b, get).unwrap();
  h.pump();
  // Stream B gets a valid final 200 (established end to end).
  h.server
    .send_response(id_b, &[(":status", "200")][..], true)
    .unwrap();
  h.pump();
  // Feed a MALFORMED response on stream A straight to the client: a HEADERS section with
  // NO `:status` (it cannot be tagged interim/final) is a malformed message.
  let bad = request_headers_frame(&[("x", "y")][..]);
  let mut scratch = std::vec![0u8; 2048];
  {
    let mut frames = h
      .client
      .handle_stream(id_a, &bad, &mut scratch)
      .expect("handle_stream builds the iterator");
    // The stream-scoped error surfaces to the driver as `MessageError`...
    assert_eq!(frames.next().err(), Some(H3Error::MessageError));
    // ...and the connection is NOT failed (a stream error is not connection-fatal).
    drop(frames);
  }
  assert!(
    !h.client.is_failed(),
    "a malformed response on a general stream must NOT fail the connection"
  );
  // The pending reset materializes on the next API entry: a `RESET_STREAM` transmit for
  // A is emitted and A's slot is freed. Copy the transmit's facts out so its borrow of
  // the client ends before the `stream_is_gone` read below.
  let (kind, empty, no_fin) = {
    let t = h.client.poll_transmit().expect("a reset transmit");
    (t.kind(), t.bytes().is_empty(), !t.fin())
  };
  assert!(
    matches!(kind, StreamKind::ResetStream { id, code }
      if id == id_a && code == H3Error::MessageError.code()),
    "a RESET_STREAM(MessageError) for stream A is enqueued"
  );
  assert!(empty, "a RESET_STREAM carries no bytes");
  assert!(no_fin, "a RESET_STREAM is not a FIN");
  assert!(h.client.stream_is_gone(id_a), "reset stream A is freed");
  // Stream B is undisturbed: a trailing server body lands on it end to end.
  h.server
    .send_data_on(id_b, bytes::Bytes::from_static(b"still-ok"))
    .unwrap();
  h.pump();
  assert_eq!(
    h.client_rx_for(id_b),
    b"still-ok",
    "stream B is undisturbed by A's stream-scoped reset"
  );
}

#[test]
fn send_data_before_established_errors() {
  // A fresh client (only `start`ed, no CONNECT exchange) cannot send tunnel DATA.
  let mut h = Harness::new();
  h.client.start().unwrap();
  assert!(h.client.send_data(b"x").is_err());
}

#[test]
fn server_receives_connect_protocol_setting() {
  let mut h = Harness::new();
  h.run_until_established();
  // The client received the server's SETTINGS, which advertise Extended CONNECT.
  let peer = h.client.peer_settings().expect("client has peer settings");
  assert!(peer.enable_connect_protocol());
  // The server received the client's SETTINGS (client does not advertise it).
  let peer = h.server.peer_settings().expect("server has peer settings");
  assert!(!peer.enable_connect_protocol());
}

#[test]
fn peer_settings_exposes_max_field_section_size() {
  // The decoded peer settings are surfaced (the core also enforces the peer's
  // MAX_FIELD_SECTION_SIZE on outbound HEADERS at send time; see the open_with /
  // accept_with size tests). Our own peers never advertise the setting, so it
  // reads back as None — confirming both that the accessor works and that our
  // side omits it.
  let mut h = Harness::new();
  h.run_until_established();
  let client_view = h.client.peer_settings().expect("client has peer settings");
  assert_eq!(
    client_view.max_field_section_size(),
    None,
    "the server peer advertises no MAX_FIELD_SECTION_SIZE"
  );
  let server_view = h.server.peer_settings().expect("server has peer settings");
  assert_eq!(
    server_view.max_field_section_size(),
    None,
    "the client peer advertises no MAX_FIELD_SECTION_SIZE"
  );
}

#[test]
fn bidirectional_tunnel_data() {
  let mut h = Harness::new();
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
fn close_under_transmit_backpressure_eventually_emits_fin() {
  // If the transmit ring is full when `close()` is called, the empty FIN cannot
  // be enqueued immediately. It must NOT be dropped: once the driver drains the
  // ring via `poll_transmit`, the FIN is retried and eventually emitted (exactly
  // once) on the request stream.
  let mut h = Harness::new();
  h.run_until_established();
  let req_id = h.request_id.expect("request id assigned");
  // Fill the transmit ring completely (the ring holds TX_N slots).
  for _ in 0..super::queue::TX_N {
    h.client.send_data(b"x").expect("ring not yet full");
  }
  // The ring is now full; the next send would block.
  assert_eq!(h.client.send_data(b"x"), Err(Error::WouldBlock));
  // Close under this backpressure: the FIN cannot be enqueued right now.
  h.client.close();
  // Drain via repeated poll_transmit; a fin:true transmit on the request stream
  // must eventually appear (and exactly once).
  let mut fin_count = 0usize;
  let mut polls = 0usize;
  while let Some(t) = h.client.poll_transmit() {
    polls += 1;
    if t.fin() {
      assert!(
        matches!(t.kind(), StreamKind::Existing(id) if id == req_id),
        "FIN must target the request stream"
      );
      assert!(t.bytes().is_empty(), "the close FIN carries no payload");
      fin_count += 1;
    }
    // Guard against an infinite loop if the FIN were re-enqueued endlessly.
    assert!(polls < 100, "poll_transmit did not terminate");
  }
  assert_eq!(fin_count, 1, "the close FIN must be emitted exactly once");
}

#[test]
fn close_before_request_stream_exists_still_emits_fin() {
  // If `close()` is called before the request stream has been opened, the FIN is
  // held pending (no request id to target yet) and emitted once the stream id is
  // provided and the driver polls — never lost.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  // Close before any request stream id is assigned: the FIN cannot target a
  // stream yet, so it is held pending rather than dropped.
  c.close();
  // Draining the setup transmits now yields NO FIN (the request stream does not
  // exist yet).
  let mut saw_early_fin = false;
  while let Some(t) = c.poll_transmit() {
    saw_early_fin |= t.fin();
  }
  assert!(!saw_early_fin, "no FIN before the request stream exists");
  // The driver opens the request stream and reports its id.
  let req_id = StreamId::new(99);
  c.provide_stream(StreamRole::Request, req_id);
  // Now the deferred FIN is retried on the next poll and emitted exactly once.
  let mut fin_count = 0usize;
  while let Some(t) = c.poll_transmit() {
    if t.fin() && matches!(t.kind(), StreamKind::Existing(id) if id == req_id) {
      fin_count += 1;
    }
  }
  assert_eq!(
    fin_count, 1,
    "deferred close FIN must be emitted exactly once"
  );
}

#[test]
fn reset_enqueues_reset_event_and_closes() {
  let mut h = Harness::new();
  h.run_until_established();
  let req_id = h.request_id.expect("request id assigned");
  h.client.handle_stream_reset(req_id, 0x010c);
  let ev = h.client.poll_event().expect("reset event");
  assert!(matches!(ev, Event::Reset(0x010c)));
  assert!(h.client.send_data(b"x").is_err());
}

#[test]
fn server_accept_before_request_errors() {
  let mut s: StaticConnection<Server> = Connection::new();
  s.start().unwrap();
  // No request HEADERS decoded (and no peer SETTINGS) yet → not ready to respond,
  // so accept_with is the retriable WouldBlock, not a terminal error.
  assert_eq!(s.accept_with(&RESPONSE[..]), Err(Error::WouldBlock));
}

#[test]
fn data_split_across_transmits_reassembles() {
  let mut h = Harness::new();
  h.run_until_established();
  h.client.send_data(b"aa").unwrap();
  h.client.send_data(b"bb").unwrap();
  h.client.send_data(b"cc").unwrap();
  h.pump();
  assert_eq!(h.server_rx.as_slice(), b"aabbcc");
}

#[test]
fn send_data_body_larger_than_slot_is_zero_copy_not_an_error() {
  // On the heap tiers the DATA body is held zero-copy in the refcounted `DataBuf`,
  // so only the small frame header is bounded by a transmit slot — a body larger
  // than `TX_CAP` is no longer the v1 no-alloc error it is on the bare tier; it is
  // sent as a vectored transmit whose body segment is the whole payload.
  let mut h = Harness::new();
  h.run_until_established();
  let big = std::vec![7u8; super::queue::TX_CAP + 1];
  h.client
    .send_data(&big)
    .expect("an over-slot body is fine on heap tiers (held zero-copy)");
  let t = h.client.poll_transmit().expect("vectored DATA transmit");
  let segs = t.segments();
  assert_eq!(segs.len(), 2, "DATA is vectored: [header, body]");
  assert_eq!(
    segs[1].len(),
    big.len(),
    "body segment is the whole payload"
  );
  assert!(segs[1].iter().all(|&b| b == 7));
}

#[test]
fn filling_transmit_queue_returns_would_block() {
  let mut h = Harness::new();
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
  let mut c: StaticConnection<Client> = Connection::new();
  let id = StreamId::new(42);
  let mut scratch = std::vec![0u8; 64];
  // 0x21 is a reserved/GREASE stream type (0x1f * N + 0x21); its bytes are
  // discarded with no frames and no error (RFC 9114 §6.2 / §9).
  {
    let mut frames = c
      .handle_stream(id, &[0x21, 0xaa, 0xbb], &mut scratch)
      .expect("grease uni stream must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // Subsequent bytes on the same ignored stream are still discarded cleanly.
  {
    let mut frames = c
      .handle_stream(id, &[0xcc, 0xdd], &mut scratch)
      .expect("ignored stream stays ignored");
    assert!(frames.next().expect("no frames").is_none());
  }
}

#[test]
fn handle_stream_fin_before_headers_is_request_incomplete() {
  // The request FSM is fresh (a frame boundary, but BEFORE the mandatory CONNECT
  // HEADERS were decoded). A FIN here is an incomplete request, not a clean
  // half-close: it must enqueue ConnError(RequestIncomplete) and make the
  // connection terminal (so a peer cannot FIN the request stream before the CONNECT
  // exchange and leave the connection stuck handshaking).
  let mut c: StaticConnection<Client> = Connection::new();
  let id = StreamId::new(7);
  c.provide_stream(StreamRole::Request, id);
  c.handle_stream_fin(id);
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::RequestIncomplete))
  );
  assert_eq!(c.poll_event(), None);
  assert!(
    c.is_terminal(),
    "a FIN before the CONNECT HEADERS makes the connection terminal"
  );
}

#[test]
fn handle_stream_fin_mid_frame_enqueues_conn_error() {
  let mut c: StaticConnection<Client> = Connection::new();
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

#[test]
fn malformed_response_headers_does_not_establish_without_draining() {
  // A client receiving a response HEADERS frame whose field section is malformed
  // in a LATER field line must surface the QPACK error from the FIRST
  // `Frames::next` pull EAGERLY — without the caller draining the yielded
  // `Frame`'s header set — and must NOT mark the tunnel established. The field
  // section is validated in full before any `Response` frame is yielded.
  //
  // This lazy fatal error routes through the centralized `fail` transition: the
  // connection becomes terminal and exactly one ConnError(QpackDecompressionFailed)
  // is enqueued (and NO Established).
  let mut c = Connection::<Client>::new();
  let id = StreamId::new(7);
  c.provide_stream(StreamRole::Request, id);
  // A HEADERS frame: prefix 0x00 0x00; 0xd9 = indexed static `:status 200` (a
  // valid first field line); 0x80 = indexed line with the static (T) bit clear,
  // i.e. a dynamic-table reference this static-only decoder rejects.
  let fs = [0x00u8, 0x00, 0xd9, 0x80];
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(crate::frame::FrameType::Headers, fs.len() as u64, &mut hdr)
    .unwrap();
  let mut frame = std::vec::Vec::new();
  frame.extend_from_slice(&hdr[..hn]);
  frame.extend_from_slice(&fs);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(id, &frame, &mut sc)
      .expect("handle_stream itself only builds the iterator");
    // The FIRST frame pull is the error — the caller never drains a HeaderSet.
    assert!(matches!(
      frames.next(),
      Err(H3Error::QpackDecompressionFailed)
    ));
  }
  // The malformed response must NOT have established the tunnel ...
  assert!(
    !c.is_established(),
    "a malformed response field section must not establish the tunnel"
  );
  // ... and the lazy error routed through `fail`: the connection is now terminal
  // with exactly one ConnError(QpackDecompressionFailed), no Established.
  assert!(
    c.is_terminal(),
    "a lazy QPACK error makes the connection terminal"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::QpackDecompressionFailed)),
    "the lazy QPACK error is surfaced as the terminal ConnError"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "no Established (or duplicate) event on a malformed response"
  );
}

#[test]
fn duplicate_control_stream_is_stream_creation_error() {
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // First control stream (uni type byte 0x00) on id 10 — OK.
  let _ = c.handle_stream(StreamId::new(10), &[0x00], &mut sc);
  // Second, different id 11, also control → H3_STREAM_CREATION_ERROR.
  assert!(matches!(
    c.handle_stream(StreamId::new(11), &[0x00], &mut sc).err(),
    Some(H3Error::StreamCreation)
  ));
}

#[test]
fn reregistering_same_critical_stream_id_is_ok() {
  // Re-seeing the same id for the same critical role is a no-op, not an error.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let _ = c.handle_stream(StreamId::new(10), &[0x00], &mut sc);
  // Feeding the same id again (its type byte was already consumed; further bytes
  // route through the registered handler) must not be a stream-creation error.
  assert!(c.handle_stream(StreamId::new(10), &[], &mut sc).is_ok());
}

#[test]
fn control_stream_fin_is_closed_critical() {
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let _ = c.handle_stream(StreamId::new(10), &[0x00], &mut sc); // register control stream
  c.handle_stream_fin(StreamId::new(10));
  assert!(matches!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream))
  ));
}

// ── client sends the CONNECT request only after the peer's SETTINGS (RFC 8441) ──

/// A peer (server) control stream's bytes: the type byte 0x00 followed by a
/// SETTINGS frame whose payload is `settings_payload`.
fn peer_control_settings(settings_payload: &[u8]) -> Vec<u8> {
  let len = u8::try_from(settings_payload.len()).expect("tiny settings payload");
  let mut v = std::vec![0x00u8, 0x04, len]; // ctrl type, SETTINGS frame type, length
  v.extend_from_slice(settings_payload);
  v
}

/// Drains and discards a connection's queued transmits, returning their count.
fn drain_transmits<Ro: Role>(c: &mut StaticConnection<Ro>) -> usize {
  let mut n = 0usize;
  while c.poll_transmit().is_some() {
    n += 1;
  }
  n
}

/// Feeds a fresh client its setup transmits, then the peer's control-stream
/// SETTINGS (`settings_payload`), so `open_with` can be exercised against a known
/// peer-SETTINGS state. Leaves the transmit ring drained.
fn client_after_peer_settings(settings_payload: &[u8]) -> StaticConnection<Client> {
  let mut c = Connection::<Client>::new();
  c.start().expect("client start");
  drain_transmits(&mut c);
  let bytes = peer_control_settings(settings_payload);
  let mut sc = [0u8; 128];
  {
    let mut frames = c
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  c
}

#[test]
fn open_with_before_peer_settings_is_would_block() {
  // `open_with` must be called only AFTER the peer's SETTINGS arrive. Before then
  // there is no opt-in to check, so it returns WouldBlock — the caller pumps more
  // inbound bytes and retries. The request is NOT enqueued.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::WouldBlock),
    "open_with before peer SETTINGS must be WouldBlock"
  );
  assert!(
    c.poll_transmit().is_none(),
    "no request transmit before the peer's SETTINGS are known"
  );
  // The connection is healthy: WouldBlock is retriable, not terminal.
  assert!(!c.is_terminal());
  assert_eq!(c.poll_event(), None);
}

#[test]
fn open_with_after_opt_in_enqueues_the_request() {
  // After the peer's SETTINGS advertise ENABLE_CONNECT_PROTOCOL=1, `open_with`
  // returns Ok and enqueues the CONNECT request HEADERS as an OpenRequest.
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  assert!(
    c.peer_settings()
      .expect("peer settings stored")
      .enable_connect_protocol()
  );
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c.poll_transmit().expect("request enqueued after opt-in");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
  assert!(!t.bytes().is_empty());
  // No error event on the conformant opt-in path.
  assert_eq!(c.poll_event(), None);
}

#[test]
fn open_with_second_call_is_noop_ok() {
  // The request is sent exactly once: a second `open_with` after the first
  // succeeded is a no-op Ok and enqueues no further request transmit.
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("first open_with");
  // Drain the request transmit produced by the first call.
  assert!(drain_transmits(&mut c) >= 1);
  // The second call is Ok but produces nothing.
  c.open_with(&CONNECT_REQUEST[..])
    .expect("second open_with is a no-op Ok");
  assert!(
    c.poll_transmit().is_none(),
    "a second open_with must not enqueue another request"
  );
}

#[test]
fn open_with_when_peer_opted_out_is_extended_connect_unsupported() {
  // A peer that omits ENABLE_CONNECT_PROTOCOL (or sends value 0) is making a
  // VALID refusal to support Extended CONNECT (RFC 9220 / RFC 8441), NOT a
  // protocol violation. `open_with` returns ExtendedConnectUnsupported (synchronous
  // opt-out) without sending the request; the connection stays healthy.
  let mut c = client_after_peer_settings(&[]); // empty payload = ENABLE_CONNECT_PROTOCOL absent
  assert!(
    !c.peer_settings()
      .expect("peer settings stored")
      .enable_connect_protocol()
  );
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::ExtendedConnectUnsupported),
    "opt-out must surface as ExtendedConnectUnsupported"
  );
  // The request must NOT be sent (no transmit at all).
  assert!(
    c.poll_transmit().is_none(),
    "no request transmit when the peer does not support Extended CONNECT"
  );
  // The opt-out is not a connection error: the connection is healthy, no event.
  assert!(
    !c.is_terminal(),
    "a conformant non-Extended-CONNECT peer must not close the connection"
  );
  assert_eq!(c.poll_event(), None);
}

#[test]
fn open_with_explicit_opt_out_value_zero_is_extended_connect_unsupported() {
  // The peer explicitly sends ENABLE_CONNECT_PROTOCOL=0 (id 0x08, value 0x00):
  // still a valid opt-out, so `open_with` is ExtendedConnectUnsupported.
  let mut c = client_after_peer_settings(&[0x08, 0x00]);
  assert!(
    !c.peer_settings()
      .expect("peer settings stored")
      .enable_connect_protocol()
  );
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::ExtendedConnectUnsupported)
  );
  assert!(c.poll_transmit().is_none());
  assert!(!c.is_terminal());
}

#[test]
fn open_with_over_peer_max_field_section_size_is_field_section_too_large() {
  // The peer opts in to Extended CONNECT AND advertises a tiny
  // MAX_FIELD_SECTION_SIZE (id 0x06, value 10). A normal CONNECT request's decoded
  // field-section size (each field's name+value length + 32 overhead) far exceeds
  // 10, so `open_with` returns FieldSectionTooLarge and sends nothing.
  // Payload: ENABLE_CONNECT_PROTOCOL=1 (0x08,0x01) AND MAX_FIELD_SECTION_SIZE=10
  // (0x06,0x0a).
  let mut c = client_after_peer_settings(&[0x08, 0x01, 0x06, 0x0a]);
  let peer = c.peer_settings().expect("peer settings stored");
  assert!(peer.enable_connect_protocol());
  assert_eq!(peer.max_field_section_size(), Some(10));
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::FieldSectionTooLarge),
    "a request over the peer's MAX_FIELD_SECTION_SIZE must be rejected"
  );
  assert!(
    c.poll_transmit().is_none(),
    "no request transmit when the field section is too large"
  );
  // Field-section-too-large is a synchronous send-time refusal, not a teardown.
  assert!(!c.is_terminal());
  assert_eq!(c.poll_event(), None);
}

#[test]
fn open_with_within_peer_max_field_section_size_succeeds() {
  // With a generous MAX_FIELD_SECTION_SIZE (id 0x06, value 0x4000 = 16384, encoded
  // as the 4-byte varint 0x80 0x00 0x40 0x00) plus opt-in, a normal CONNECT request
  // fits and `open_with` succeeds.
  let mut c = client_after_peer_settings(&[0x08, 0x01, 0x06, 0x80, 0x00, 0x40, 0x00]);
  let peer = c.peer_settings().expect("peer settings stored");
  assert!(peer.enable_connect_protocol());
  assert_eq!(peer.max_field_section_size(), Some(16384));
  c.open_with(&CONNECT_REQUEST[..])
    .expect("a request within the limit must be sent");
  let t = c.poll_transmit().expect("request enqueued");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
}

#[test]
fn accept_with_over_peer_max_field_section_size_is_field_section_too_large() {
  // Server symmetry: if the peer (client) advertised a tiny MAX_FIELD_SECTION_SIZE,
  // `accept_with` rejects an oversized response with FieldSectionTooLarge. Feed the
  // server a client control stream carrying MAX_FIELD_SECTION_SIZE=10 (0x06,0x0a),
  // register the request stream, then accept a multi-field response.
  let mut s = Connection::<Server>::new();
  s.start().unwrap();
  drain_transmits(&mut s);
  let mut sc = [0u8; 128];
  let bytes = peer_control_settings(&[0x06, 0x0a]);
  {
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert_eq!(
    s.peer_settings()
      .expect("peer settings stored")
      .max_field_section_size(),
    Some(10)
  );
  s.provide_stream(StreamRole::Request, StreamId::new(0));
  // The request HEADERS must be decoded before the response is sized/sent. (This
  // inbound decode is not bounded by the peer's outbound MAX_FIELD_SECTION_SIZE.)
  deliver_connect_request(&mut s, StreamId::new(0));
  // A response whose decoded field-section size (>= 32 for one field) exceeds 10.
  let big_response: [(&str, &str); 2] = [(":status", "200"), ("sec-websocket-accept", "abc")];
  assert_eq!(
    s.accept_with(&big_response[..]),
    Err(Error::FieldSectionTooLarge),
    "an oversized response must be rejected against a peer's MAX_FIELD_SECTION_SIZE"
  );
  // Rejected synchronously without establishing or sending.
  assert!(!s.is_established());
  assert!(s.poll_transmit().is_none());
}

// ── server parity: accept_with gates on peer SETTINGS and is exactly-once ───────

/// Feeds a fresh server its setup transmits, then registers the request stream;
/// the peer's (client's) control-stream SETTINGS are NOT yet delivered, so this is
/// the pre-SETTINGS state in which `accept_with` must block. Leaves the transmit
/// ring drained.
fn server_request_registered_no_peer_settings() -> StaticConnection<Server> {
  let mut s = Connection::<Server>::new();
  s.start().expect("server start");
  drain_transmits(&mut s);
  s.provide_stream(StreamRole::Request, StreamId::new(0));
  s
}

/// A HEADERS frame carrying `fields` as its QPACK field section, ready to feed on a
/// request stream (`[frame header][field section]`).
fn request_headers_frame(fields: &[(&str, &str)]) -> Vec<u8> {
  let mut fs = [0u8; 256];
  let n = crate::qpack::encode_field_section(fields.iter().copied(), &mut fs)
    .expect("CONNECT field section encodes");
  let fs = &fs[..n];
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(crate::frame::FrameType::Headers, fs.len() as u64, &mut hdr)
    .expect("HEADERS frame header encodes");
  let mut v = Vec::new();
  v.extend_from_slice(&hdr[..hn]);
  v.extend_from_slice(fs);
  v
}

/// Delivers the peer's CONNECT request HEADERS to `s` on the request stream
/// `req_id`, asserting the server yields exactly the `Frame::Request` (which sets
/// `request_received`, the gate `accept_with` waits on). The request stream must
/// already be registered (via `provide_stream`).
fn deliver_connect_request(s: &mut StaticConnection<Server>, req_id: StreamId) {
  let frame = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut sc = std::vec![0u8; 512];
  let mut frames = s
    .handle_stream(req_id, &frame, &mut sc)
    .expect("request HEADERS decode");
  let mut saw_request = false;
  while let Some(f) = frames.next().expect("request frame") {
    match f {
      Frame::Request(mut hs) => {
        saw_request = true;
        while hs.next().expect("req header").is_some() {}
      }
      Frame::Response { .. } | Frame::Trailers(_) | Frame::Data(_) => {
        panic!("expected only the request HEADERS")
      }
    }
  }
  assert!(
    saw_request,
    "the server must yield the CONNECT request HEADERS"
  );
}

#[test]
fn accept_with_before_peer_settings_is_would_block() {
  // Server parity with `open_with`: QUIC streams are unordered, so the request
  // stream (and this call) can arrive before the client's control-stream SETTINGS.
  // Until those SETTINGS are decoded the peer's MAX_FIELD_SECTION_SIZE is unknown,
  // so `accept_with` must return WouldBlock — enqueuing NO response and NOT
  // establishing — rather than send a possibly over-limit response and commit.
  let mut s = server_request_registered_no_peer_settings();
  assert!(
    s.peer_settings().is_none(),
    "the client's SETTINGS have not arrived yet"
  );
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::WouldBlock),
    "accept_with before the peer's SETTINGS must be WouldBlock"
  );
  assert!(
    s.poll_transmit().is_none(),
    "no response transmit before the peer's SETTINGS are known"
  );
  assert!(!s.is_established(), "the tunnel must not be established");
  // WouldBlock is retriable, not a teardown.
  assert!(!s.is_terminal());
  assert_eq!(s.poll_event(), None);
}

#[test]
fn accept_with_after_peer_settings_succeeds() {
  // Once the client's control-stream SETTINGS are decoded, the same `accept_with`
  // that previously returned WouldBlock now succeeds: the response HEADERS are
  // enqueued, the tunnel is established, and Event::Established is pushed.
  let mut s = server_request_registered_no_peer_settings();
  assert_eq!(s.accept_with(&RESPONSE[..]), Err(Error::WouldBlock));
  // Deliver the client's control-stream SETTINGS (opt-in is client-irrelevant to
  // the server, but a plain SETTINGS frame still satisfies the peer-SETTINGS gate).
  let mut sc = [0u8; 128];
  let bytes = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert!(s.peer_settings().is_some(), "peer SETTINGS now decoded");
  // Peer SETTINGS alone are not enough: the request HEADERS must also be decoded
  // (the request stream id was registered when the stream opened, before HEADERS).
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::WouldBlock),
    "accept_with before the request HEADERS are decoded must be WouldBlock"
  );
  // Deliver the peer's CONNECT request HEADERS; now `request_received` is set.
  deliver_connect_request(&mut s, StreamId::new(0));
  // The retry now succeeds.
  s.accept_with(&RESPONSE[..])
    .expect("accept_with after the peer's SETTINGS and request must succeed");
  assert!(s.is_established(), "the tunnel is now established");
  let t = s.poll_transmit().expect("response HEADERS enqueued");
  assert!(matches!(t.kind(), StreamKind::Existing(_)));
  assert!(!t.bytes().is_empty());
  assert_eq!(s.poll_event(), Some(Event::Established));
}

#[test]
fn accept_with_second_call_is_noop_ok() {
  // Server parity with the client's exactly-once `request_sent` guard: a single
  // CONNECT phase carries exactly one response HEADERS, so a second `accept_with`
  // after a successful one is a no-op Ok — no second HEADERS transmit and no second
  // Event::Established.
  let mut s = server_request_registered_no_peer_settings();
  let mut sc = [0u8; 128];
  let bytes = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  deliver_connect_request(&mut s, StreamId::new(0));
  s.accept_with(&RESPONSE[..]).expect("first accept_with");
  // Drain the response HEADERS and the Established event from the first call.
  assert!(drain_transmits(&mut s) >= 1);
  assert_eq!(s.poll_event(), Some(Event::Established));
  // The second call is Ok but enqueues nothing and pushes no further event.
  s.accept_with(&RESPONSE[..])
    .expect("second accept_with is a no-op Ok");
  assert!(
    s.poll_transmit().is_none(),
    "a second accept_with must not enqueue another response HEADERS"
  );
  assert_eq!(
    s.poll_event(),
    None,
    "a second accept_with must not push another Established"
  );
}

#[test]
fn accept_with_requires_request_headers_decoded_first() {
  // `provide_stream(Request, id)` registers the request stream id the moment the
  // QUIC stream opens — BEFORE any HEADERS are decoded. `accept_with` must NOT
  // treat that registration as "the request was received": it must block until
  // `handle_stream` has actually yielded the CONNECT request as `Frame::Request`.
  // Otherwise the server could respond and flip `established` without ever decoding
  // or validating the client's CONNECT request.
  let mut s = server_request_registered_no_peer_settings();
  // Make peer SETTINGS available so the SETTINGS gate is satisfied and we isolate
  // the request-received gate.
  let mut sc = [0u8; 128];
  let bytes = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert!(s.peer_settings().is_some(), "peer SETTINGS decoded");
  // The request stream id is registered, peer SETTINGS are in — but no request
  // HEADERS have been decoded yet, so accept_with still blocks.
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::WouldBlock),
    "accept_with must block until the request HEADERS are decoded"
  );
  assert!(
    s.poll_transmit().is_none(),
    "no response before the request"
  );
  assert!(!s.is_established(), "the tunnel must not be established");
  assert!(!s.is_terminal(), "WouldBlock is retriable, not a teardown");
  // Now decode the peer's CONNECT request HEADERS (yields Frame::Request).
  deliver_connect_request(&mut s, StreamId::new(0));
  // The retry now succeeds.
  s.accept_with(&RESPONSE[..])
    .expect("accept_with after Frame::Request must succeed");
  assert!(s.is_established());
  let t = s.poll_transmit().expect("response HEADERS enqueued");
  assert!(matches!(t.kind(), StreamKind::Existing(_)));
  assert_eq!(s.poll_event(), Some(Event::Established));
}

// ── the control stream rejects forbidden frames after SETTINGS (RFC 9114 §7.2) ─

/// Feeds `frame_bytes` on the peer control stream of a fresh server, after the
/// initial SETTINGS frame, returning the `handle_stream` result.
fn feed_after_settings(frame_bytes: &[u8]) -> Result<(), H3Error> {
  let mut c = Connection::<Server>::new();
  let mut sc = [0u8; 128];
  let id = StreamId::new(3);
  // First, the control stream + a valid (empty) SETTINGS frame.
  let setup = peer_control_settings(&[]);
  c.handle_stream(id, &setup, &mut sc).map(|_| ())?;
  // Then the frame under test, on the (now registered) control stream.
  c.handle_stream(id, frame_bytes, &mut sc).map(|_| ())
}

#[test]
fn control_data_frame_after_settings_is_frame_unexpected() {
  // DATA frame (type 0x00, length 0) on the control stream after SETTINGS.
  assert_eq!(
    feed_after_settings(&[0x00, 0x00]),
    Err(H3Error::FrameUnexpected)
  );
}

#[test]
fn control_headers_frame_after_settings_is_frame_unexpected() {
  // HEADERS frame (type 0x01, length 0) on the control stream after SETTINGS.
  assert_eq!(
    feed_after_settings(&[0x01, 0x00]),
    Err(H3Error::FrameUnexpected)
  );
}

#[test]
fn duplicate_control_settings_is_frame_unexpected() {
  // A second SETTINGS frame (type 0x04, length 0) after the first.
  assert_eq!(
    feed_after_settings(&[0x04, 0x00]),
    Err(H3Error::FrameUnexpected)
  );
}

#[test]
fn unknown_control_frame_after_settings_is_ignored() {
  // A GREASE / unknown frame type (0x21) with a 2-byte payload is skipped.
  assert_eq!(feed_after_settings(&[0x21, 0x02, 0xaa, 0xbb]), Ok(()));
}

#[test]
fn reserved_control_frame_after_settings_is_frame_unexpected() {
  // An HTTP/2-reserved frame type (0x02, length 0) is forbidden on HTTP/3
  // (RFC 9114 §7.2.8): H3_FRAME_UNEXPECTED, not silently skipped.
  assert_eq!(
    feed_after_settings(&[0x02, 0x00]),
    Err(H3Error::FrameUnexpected)
  );
}

#[test]
fn goaway_control_frame_after_settings_is_ignored() {
  // GOAWAY (0x07) is a valid control-stream frame we do not model: its payload
  // (here 2 bytes) is skipped (RFC 9114 §7.2.6), not an error.
  assert_eq!(feed_after_settings(&[0x07, 0x02, 0xaa, 0xbb]), Ok(()));
}

#[test]
fn push_promise_control_frame_after_settings_is_frame_unexpected() {
  // PUSH_PROMISE (0x05) is a push frame; we never enable server push, so on the
  // control stream it is unexpected (RFC 9114 §7.2.5).
  assert_eq!(
    feed_after_settings(&[0x05, 0x00]),
    Err(H3Error::FrameUnexpected)
  );
}

#[test]
fn non_settings_first_control_frame_is_missing_settings() {
  let mut c = Connection::<Server>::new();
  let mut sc = [0u8; 128];
  // Control stream type byte 0x00, then a DATA frame (type 0x00) as the FIRST
  // frame — the first control frame must be SETTINGS (RFC 9114 §6.2.1).
  let bytes = [0x00u8, 0x00, 0x00]; // ctrl type, DATA frame type, length 0
  assert_eq!(
    c.handle_stream(StreamId::new(3), &bytes, &mut sc).err(),
    Some(H3Error::MissingSettings)
  );
}

#[test]
fn oversized_control_settings_is_excessive_load_not_panic() {
  let mut c = Connection::<Server>::new();
  let mut sc = [0u8; 128];
  // A SETTINGS frame claiming a payload larger than the generous bounded buffer
  // (CTRL_CAP = 1024): type 0x04, length 0x44 0x01 (the 2-byte varint for 1025 >
  // 1024). This is implausibly large, so it is an excessive-load policy error
  // (H3_EXCESSIVE_LOAD), NOT a malformed-frame error — and never a panic.
  let bytes = [0x00u8, 0x04, 0x44, 0x01];
  assert_eq!(
    c.handle_stream(StreamId::new(3), &bytes, &mut sc).err(),
    Some(H3Error::ExcessiveLoad)
  );
}

#[test]
fn control_settings_with_grease_over_64_bytes_decodes() {
  // A conforming peer may include unknown / GREASE extension settings (RFC 9114
  // §7.2.4.1 / §9), legitimately pushing the SETTINGS payload well past 64 bytes.
  // With the bound at CTRL_CAP = 1024, such a payload must decode successfully and
  // still apply the KNOWN settings — never be rejected just for carrying GREASE.
  let mut payload = std::vec::Vec::new();
  // A known setting we expect to read back: ENABLE_CONNECT_PROTOCOL=1.
  payload.extend_from_slice(&[0x08, 0x01]);
  // Many unknown / GREASE settings (id 0x21, value 0x00 = 2 bytes each). 40 of them
  // add 80 bytes, so the total payload is 82 bytes (> 64, < 1024).
  for _ in 0..40 {
    payload.extend_from_slice(&[0x21, 0x00]);
  }
  assert!(
    payload.len() > 64 && payload.len() < 1024,
    "the GREASE-laden payload ({}) must straddle the old/new bounds",
    payload.len()
  );
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  // Build the control bytes manually: a payload of 82 bytes needs a real varint
  // length (the single-byte `peer_control_settings` helper only encodes lengths
  // < 64). [ctrl type 0x00][SETTINGS frame header][payload].
  let mut bytes = std::vec![0x00u8];
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(
    crate::frame::FrameType::Settings,
    payload.len() as u64,
    &mut hdr,
  )
  .expect("settings frame header encodes");
  bytes.extend_from_slice(&hdr[..hn]);
  bytes.extend_from_slice(&payload);
  let mut sc = std::vec![0u8; 256];
  {
    let mut frames = c
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("a GREASE-laden SETTINGS payload over 64 bytes must decode");
    assert!(frames.next().expect("no frames").is_none());
  }
  // The known setting was applied despite the surrounding GREASE.
  let peer = c.peer_settings().expect("peer settings decoded");
  assert!(
    peer.enable_connect_protocol(),
    "the known ENABLE_CONNECT_PROTOCOL setting must survive the GREASE"
  );
  // And the now-permitted CONNECT request can be sent as a result.
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c.poll_transmit().expect("request enqueued");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
}

#[test]
fn control_settings_split_across_calls_reassembles() {
  // The SETTINGS frame and its payload arrive split across several feeds; the
  // continuous parser must reassemble and decode it.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  let id = StreamId::new(3);
  let mut sc = [0u8; 128];
  // Full peer control bytes: type byte + SETTINGS(enable_connect_protocol=1).
  let full = peer_control_settings(&[0x08, 0x01]);
  for chunk in full.chunks(1) {
    let mut frames = c.handle_stream(id, chunk, &mut sc).expect("split ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  // Once fully reassembled the peer settings are stored, so the now-permitted
  // CONNECT request can be sent.
  let peer = c.peer_settings().expect("peer settings decoded");
  assert!(peer.enable_connect_protocol());
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c.poll_transmit().expect("request enqueued");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
}

// ── inbound uni tracking: bounded, classified, never silently hidden ───────────

#[test]
fn grease_uni_continuation_is_discarded_not_reclassified() {
  // A tracked GREASE stream's continuation bytes are discarded *by lookup* — they
  // are never reinterpreted as a fresh stream-type varint (RFC 9114 §6.2/§9).
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(1000);
  // First chunk classifies id as GREASE (type 0x21 → Ignored).
  {
    let mut frames = c.handle_stream(id, &[0x21], &mut sc).expect("grease ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  // A continuation chunk that *looks* like a control stream type (0x00) followed
  // by a SETTINGS frame must NOT register a control stream: the id is already
  // tracked as Ignored, so these bytes are discarded.
  {
    let mut frames = c
      .handle_stream(id, &[0x00, 0x04, 0x00], &mut sc)
      .expect("grease continuation discarded");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert!(c.peer_settings().is_none(), "no SETTINGS were processed");
  assert_eq!(c.poll_event(), None);
}

#[test]
fn flooding_inbound_uni_streams_past_cap_is_excessive_load() {
  // A peer flooding more distinct GREASE uni streams than the tracking table
  // holds is failed with H3_EXCESSIVE_LOAD — never silently dropped (which would
  // let a later real control stream be hidden).
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // The first UNI_CAP distinct GREASE streams are tracked cleanly.
  for i in 0..(super::UNI_CAP as u64) {
    let id = StreamId::new(1000 + i);
    let mut frames = c
      .handle_stream(id, &[0x21, 0xaa, 0xbb], &mut sc)
      .expect("grease uni stream under cap must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // The table is now full; one more distinct inbound uni stream overflows it.
  let overflow = StreamId::new(9999);
  assert_eq!(
    c.handle_stream(overflow, &[0x21, 0xaa], &mut sc).err(),
    Some(H3Error::ExcessiveLoad)
  );
}

#[test]
fn control_stream_after_grease_flood_is_still_classified() {
  // Saturation-then-control must NOT hide SETTINGS: a control stream opened after
  // several GREASE streams (while still under the cap) is classified and its
  // SETTINGS processed, so the client's CONNECT request can then be sent.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  let mut sc = [0u8; 128];
  // Several GREASE uni streams first (well under UNI_CAP).
  for i in 0..(super::UNI_CAP as u64 - 4) {
    let id = StreamId::new(2000 + i);
    let mut frames = c
      .handle_stream(id, &[0x21, 0xaa, 0xbb], &mut sc)
      .expect("grease uni stream must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // Now the peer's REAL control stream (type 0x00 + SETTINGS enabling Extended
  // CONNECT). Its SETTINGS must be processed despite the preceding flood.
  let ctrl = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = c
      .handle_stream(StreamId::new(3), &ctrl, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  // SETTINGS were processed (stored + opt-in observed) ...
  let peer = c.peer_settings().expect("peer settings decoded");
  assert!(peer.enable_connect_protocol());
  // ... and the now-permitted CONNECT request can be sent as a result.
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c
    .poll_transmit()
    .expect("request enqueued after control SETTINGS");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
  assert_eq!(c.poll_event(), None);
}

#[test]
fn duplicate_control_stream_survives_when_table_has_room() {
  // The duplicate-critical check fires by role, independent of GREASE entries.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // One real control stream (id 10), then some GREASE streams.
  let _ = c.handle_stream(StreamId::new(10), &[0x00], &mut sc);
  for i in 0..3u64 {
    let _ = c.handle_stream(StreamId::new(20 + i), &[0x21], &mut sc);
  }
  // A second control stream on a different id is still a creation error.
  assert_eq!(
    c.handle_stream(StreamId::new(11), &[0x00], &mut sc).err(),
    Some(H3Error::StreamCreation)
  );
}

#[test]
fn push_uni_stream_is_id_error() {
  // An inbound push unidirectional stream (leading type byte 0x01) is a peer
  // violation: this crate never enables server push (it never sends MAX_PUSH_ID,
  // so the max push id stays 0), so receiving a push stream is H3_ID_ERROR
  // (RFC 9114 §6.2.2 / §7.2.7) — NOT a silently-ignored GREASE stream.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // 0x01 = push stream type, then some would-be push payload.
  assert_eq!(
    c.handle_stream(StreamId::new(8), &[0x01, 0xaa, 0xbb], &mut sc)
      .err(),
    Some(H3Error::IdError),
    "a push unidirectional stream must fail the connection with H3_ID_ERROR"
  );
}

#[test]
fn push_uni_stream_with_split_type_varint_is_id_error() {
  // The push type 0x01 encoded as a 2-byte varint (0x40 0x01) split across two
  // feeds must still classify to H3_ID_ERROR once the type completes — the
  // partial first byte stays Pending, then the second byte resolves to push.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(8);
  {
    let mut frames = c
      .handle_stream(id, &[0x40], &mut sc)
      .expect("partial type varint must not error yet");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert_eq!(
    c.handle_stream(id, &[0x01], &mut sc).err(),
    Some(H3Error::IdError),
    "a push type completing across feeds is still H3_ID_ERROR"
  );
}

#[test]
fn fin_on_classified_ignored_uni_stream_frees_its_slot() {
  // A cleanly FINed *classified Ignored* (GREASE / extension) uni stream must
  // free its tracking slot. Otherwise a peer could open + FIN UNI_CAP GREASE
  // streams to wedge the bounded table and have the real inbound control stream
  // rejected with H3_EXCESSIVE_LOAD — a connection kill-switch.
  //
  // Open UNI_CAP distinct GREASE streams (each a complete 1-byte type varint
  // 0x21 -> Ignored, so they are CLASSIFIED, not merely Pending), cleanly FIN all
  // of them, then open the peer's real control stream: it must classify and
  // process SETTINGS with no ExcessiveLoad, proving the FINed Ignored streams
  // released their slots.
  // An overflow is connection-fatal (ExcessiveLoad routes through `fail`), so this
  // test must NOT trip the overflow on the live connection: it proves slot-freeing
  // directly by re-tracking UNI_CAP fresh streams after the FINs. (A separate test
  // asserts that an overflow is the terminal ConnError(ExcessiveLoad).)
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  let mut sc = std::vec![0u8; 128];
  // Fill the whole table with classified-Ignored GREASE streams.
  for i in 0..(super::UNI_CAP as u64) {
    let id = StreamId::new(3000 + i);
    let mut frames = c
      .handle_stream(id, &[0x21, 0xaa, 0xbb], &mut sc)
      .expect("grease uni stream under cap must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // Cleanly FIN every GREASE stream: each closed extension stream must free its
  // slot, and FINing an Ignored stream is NOT a closed-critical-stream error.
  for i in 0..(super::UNI_CAP as u64) {
    c.handle_stream_fin(StreamId::new(3000 + i));
  }
  assert_eq!(
    c.poll_event(),
    None,
    "FINing Ignored streams produces no events"
  );
  assert!(
    !c.is_terminal(),
    "FINing Ignored streams (no overflow tripped) keeps the connection healthy"
  );
  // With the slots freed, the peer's REAL control stream (type 0x00 + SETTINGS
  // enabling Extended CONNECT) must now classify and have its SETTINGS processed
  // — no ExcessiveLoad.
  let ctrl = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = c
      .handle_stream(StreamId::new(3), &ctrl, &mut sc)
      .expect("control stream must classify after FINed GREASE streams freed slots");
    assert!(frames.next().expect("no frames").is_none());
  }
  let peer = c.peer_settings().expect("peer settings decoded");
  assert!(peer.enable_connect_protocol());
  // And the now-permitted CONNECT request can be sent as a result.
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c
    .poll_transmit()
    .expect("request enqueued after control SETTINGS");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
  assert_eq!(c.poll_event(), None);
}

// ── partial type-varint tracking shares the unified bounded table ──

#[test]
fn partial_type_varints_do_not_block_a_later_control_stream() {
  // Several inbound uni streams that each send only ONE byte of a multi-byte
  // stream-type varint (and then stop) must share the single bounded table rather
  // than a separate partial-tracking table that could be exhausted to falsely
  // reject a later real control stream. As long as the total stays under UNI_CAP,
  // the control stream is classified and its SETTINGS processed.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  let mut sc = [0u8; 128];
  // 0x40 is the first byte of a 2-byte QUIC varint (prefix 0b01); on its own it
  // is a truncated (incomplete) type varint, so each of these streams stays
  // Pending. Four such streams, all sharing the one bounded table.
  for i in 0..4u64 {
    let id = StreamId::new(500 + i);
    let mut frames = c
      .handle_stream(id, &[0x40], &mut sc)
      .expect("partial type varint must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // The peer's REAL control stream now arrives (type 0x00 + SETTINGS opt-in). It
  // must still be classified despite the four lingering partials.
  let ctrl = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = c
      .handle_stream(StreamId::new(3), &ctrl, &mut sc)
      .expect("control stream classified despite partial-varint streams");
    assert!(frames.next().expect("no frames").is_none());
  }
  let peer = c.peer_settings().expect("peer settings decoded");
  assert!(peer.enable_connect_protocol());
  // And the now-permitted CONNECT request can be sent as a result.
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c
    .poll_transmit()
    .expect("request enqueued after control SETTINGS");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
  assert_eq!(c.poll_event(), None);
}

#[test]
fn fin_on_partial_type_varint_stream_frees_its_slot() {
  // A FIN on a stream that only ever sent a partial type varint frees its slot
  // (the stream closed before declaring its type), so a later new stream can still
  // be tracked. Fill the table to its last slot with partials, FIN one of them,
  // then a fresh stream must still be accepted.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // Reserve all UNI_CAP slots as Pending (each sends one byte of a 2-byte varint).
  // (An overflow is connection-fatal, so this test proves slot-freeing directly —
  // fill to the last slot, FIN one, then a fresh stream is accepted — without
  // tripping the overflow on the live connection.)
  for i in 0..(super::UNI_CAP as u64) {
    let id = StreamId::new(700 + i);
    let mut frames = c
      .handle_stream(id, &[0x40], &mut sc)
      .expect("partial type varint under cap must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // FIN the first partial stream: closing before declaring a type frees its slot
  // and must NOT be treated as a closed critical stream (no ConnError event).
  c.handle_stream_fin(StreamId::new(700));
  assert_eq!(c.poll_event(), None, "pending-stream FIN is not critical");
  assert!(!c.is_terminal(), "a pending-stream FIN keeps it healthy");
  // With a slot freed, a fresh inbound uni stream is accepted again.
  let mut frames = c
    .handle_stream(StreamId::new(9001), &[0x21, 0xaa], &mut sc)
    .expect("a freed slot lets a new stream be tracked");
  assert!(frames.next().expect("no frames").is_none());
}

#[test]
fn flooding_partial_type_varint_streams_past_cap_is_excessive_load() {
  // Exceeding UNI_CAP with streams that are only ever Pending (partial type
  // varints) is H3_EXCESSIVE_LOAD — the SAME bound as classified streams — not a
  // StreamCreation error.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  for i in 0..(super::UNI_CAP as u64) {
    let id = StreamId::new(800 + i);
    let mut frames = c
      .handle_stream(id, &[0x40], &mut sc)
      .expect("partial uni stream under cap must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // One more distinct (still-partial) inbound uni stream overflows the table.
  assert_eq!(
    c.handle_stream(StreamId::new(8888), &[0x40], &mut sc).err(),
    Some(H3Error::ExcessiveLoad)
  );
  // The overflow is connection-fatal — it routes through `fail`, making the
  // connection terminal and enqueuing exactly one ConnError(ExcessiveLoad).
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ExcessiveLoad))
  );
  assert_eq!(
    c.poll_event(),
    None,
    "exactly one ConnError for the overflow"
  );
  assert!(c.is_terminal(), "an ExcessiveLoad overflow is terminal");
}

#[test]
fn split_type_varint_completes_then_classifies_control() {
  // A 2-byte type varint split across two calls (first byte, then the second)
  // must reassemble in the single slot and classify correctly. 0x40 0x00 is the
  // 2-byte encoding of 0 (the control stream type), followed by a SETTINGS frame.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  let mut sc = [0u8; 128];
  let id = StreamId::new(3);
  // First byte of the type varint only — stays Pending, no role yet.
  {
    let mut frames = c.handle_stream(id, &[0x40], &mut sc).expect("partial ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  // Second byte completes the type varint (= 0, control), then the SETTINGS frame
  // (type 0x04, len 2, ENABLE_CONNECT_PROTOCOL=1). All in one continuation feed.
  {
    let mut frames = c
      .handle_stream(id, &[0x00, 0x04, 0x02, 0x08, 0x01], &mut sc)
      .expect("control classified after the split type varint");
    assert!(frames.next().expect("no frames").is_none());
  }
  let peer = c.peer_settings().expect("peer settings decoded");
  assert!(peer.enable_connect_protocol());
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c.poll_transmit().expect("request enqueued");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
}

// ── outbound HEADERS are measured AND encoded in a SINGLE traversal ──────

/// A `Headers` supplier whose `for_each` emits a DIFFERENT field section on each
/// call: the first traversal yields a small section (one short field), every
/// later traversal a large one (many fields). A two-pass design (size pass then
/// encode pass) would measure the small first section, pass the limit check, then
/// encode the large second section — sending bytes that were never validated. The
/// single-pass design measures and encodes the SAME (first) traversal, so the
/// bytes sent are exactly the bytes validated.
struct ShrinkingHeaders {
  calls: core::cell::Cell<u32>,
}

impl ShrinkingHeaders {
  const fn new() -> Self {
    Self {
      calls: core::cell::Cell::new(0),
    }
  }
}

impl Headers for ShrinkingHeaders {
  fn for_each(&self, f: &mut dyn FnMut(&str, &str)) -> Result<(), Error> {
    let n = self.calls.get();
    self.calls.set(n.saturating_add(1));
    if n == 0 {
      // First traversal: a single small field (well within any sane limit).
      f(":method", "CONNECT");
    } else {
      // Any later traversal: a much larger section (would blow a tiny limit).
      for _ in 0..16 {
        f(
          "x-large-header-name",
          "a-fairly-long-header-value-component",
        );
      }
    }
    Ok(())
  }
}

#[test]
fn open_with_single_pass_sends_exactly_the_validated_field_section() {
  // With a non-replayable supplier, `open_with` must encode and size-account the
  // SAME traversal. We use a generous limit so the FIRST (small) section passes;
  // the single-pass design must then send exactly that small section — never the
  // larger section a SECOND traversal would emit.
  let mut c = client_after_peer_settings(&[0x08, 0x01, 0x06, 0x80, 0x00, 0x40, 0x00]);
  let headers = ShrinkingHeaders::new();
  c.open_with(&headers).expect("open_with within the limit");
  // Exactly ONE traversal happened (measure + encode fused).
  assert_eq!(
    headers.calls.get(),
    1,
    "the supplier must be traversed exactly once"
  );
  let t = c.poll_transmit().expect("request enqueued");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
  // Decode the transmitted HEADERS frame's field section and confirm it is the
  // FIRST (small) section — i.e. the bytes sent match what was validated.
  let bytes = t.bytes();
  let (hn, hdr) = crate::frame::decode_header(bytes).expect("frame header decodes");
  assert!(matches!(hdr.kind(), crate::frame::FrameKind::Headers));
  let fs = bytes.get(hn..).expect("field section follows the header");
  let mut scratch = std::vec![0u8; 512];
  let mut lines =
    crate::qpack::decode_field_section_into(fs, &mut scratch).expect("field section decodes");
  let first = lines.next().expect("ok").expect("one field");
  assert_eq!((first.name(), first.value()), (":method", "CONNECT"));
  assert!(
    lines.next().expect("ok").is_none(),
    "exactly the single small field was sent, not the larger second section"
  );
}

#[test]
fn open_with_single_pass_too_large_sends_nothing_and_keeps_request_unsent() {
  // When the FIRST (and only) traversal's decoded section exceeds the peer's
  // MAX_FIELD_SECTION_SIZE, `open_with` returns
  // FieldSectionTooLarge, enqueues NO request transmit, and leaves `request_sent`
  // false so a later (smaller) request can still be sent — nothing inconsistent
  // is ever committed.
  //
  // The supplier emits a single field of decoded size 7 + 7 + 32 = 46 on the
  // first call; a limit of 10 rejects it. (A two-pass design that re-traversed
  // could diverge here; the single pass cannot.)
  let mut c = client_after_peer_settings(&[0x08, 0x01, 0x06, 0x0a]);
  let headers = ShrinkingHeaders::new();
  assert_eq!(
    c.open_with(&headers),
    Err(Error::FieldSectionTooLarge),
    "the first traversal is over the limit, so the request must be refused"
  );
  // The request was NOT sent: no transmit, and `request_sent` stays false.
  assert!(
    c.poll_transmit().is_none(),
    "no request transmit on the too-large path"
  );
  assert!(
    !c.request_sent,
    "request_sent must stay false so the request can be retried"
  );
  // A synchronous refusal, not a teardown.
  assert!(!c.is_terminal());
  assert_eq!(c.poll_event(), None);
  // Because `request_sent` stayed false, `open_with` is NOT short-circuited as a
  // no-op `Ok` on a second call: it genuinely re-attempts (and, still over the
  // limit, refuses again) rather than silently succeeding. This proves the
  // too-large path left the request retriable.
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::FieldSectionTooLarge),
    "a second open_with re-attempts (not a no-op Ok), proving the request is unsent"
  );
  assert!(c.poll_transmit().is_none(), "still nothing sent");
}

// ── outbound HEADERS: the encode workspace is sized to the transmit slot (TX_CAP) ─

/// A `Headers` supplier that emits `count` copies of a fixed literal field
/// (`name` / `value`), letting a test build a field section of a chosen size. The
/// fields use literal names so each contributes its full name + value to the
/// encoded bytes (no static-table compression shrinks the wire size below the
/// scratch bound under test).
struct RepeatedHeaders {
  count: usize,
  name: &'static str,
  value: &'static str,
}

impl Headers for RepeatedHeaders {
  fn for_each(&self, f: &mut dyn FnMut(&str, &str)) -> Result<(), Error> {
    for _ in 0..self.count {
      f(self.name, self.value);
    }
    Ok(())
  }
}

#[test]
fn open_with_field_section_over_512_within_peer_limit_succeeds() {
  // A valid field section larger than 512 bytes but fitting the transmit slot
  // (TX_CAP) — and within the peer's MAX_FIELD_SECTION_SIZE — must encode and send:
  // the encode scratch spans the transmit slot, not a fixed 512-byte buffer that
  // would reject it with a QPACK buffer error.
  //
  // 20 fields of a 19-byte literal name + 28-byte value encode to roughly
  // 20 * (1 + 19 + 1 + 28) ≈ 980 bytes (> 512, < TX_CAP). Decoded size is
  // 20 * (19 + 28 + 32) = 1580; a generous peer limit (16384) admits it.
  let mut c = client_after_peer_settings(&[0x08, 0x01, 0x06, 0x80, 0x00, 0x40, 0x00]);
  assert_eq!(
    c.peer_settings()
      .expect("peer settings stored")
      .max_field_section_size(),
    Some(16384)
  );
  let headers = RepeatedHeaders {
    count: 20,
    name: "x-some-header-name-",
    value: "a-moderately-long-header-val",
  };
  c.open_with(&headers)
    .expect("a >512-byte section within the peer limit must be sent");
  let t = c.poll_transmit().expect("request enqueued");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
  // The encoded HEADERS frame's field section is genuinely larger than 512 bytes,
  // confirming the workspace spans the transmit slot.
  let bytes = t.bytes();
  let (hn, hdr) = crate::frame::decode_header(bytes).expect("frame header decodes");
  assert!(matches!(hdr.kind(), crate::frame::FrameKind::Headers));
  let fs_len = bytes.len() - hn;
  assert!(
    fs_len > 512,
    "the field section ({fs_len} bytes) must exceed the old 512-byte scratch"
  );
}

#[test]
fn open_with_no_peer_limit_field_section_over_512_succeeds() {
  // The same >512-byte valid section must also send when the peer advertises NO
  // MAX_FIELD_SECTION_SIZE (the common case for our own stack). With no limit there
  // is nothing to refuse — only the transmit slot bounds the size — so it must encode
  // successfully.
  let mut c = client_after_peer_settings(&[0x08, 0x01]); // opt-in, no field-size limit
  assert_eq!(
    c.peer_settings()
      .expect("peer settings stored")
      .max_field_section_size(),
    None
  );
  let headers = RepeatedHeaders {
    count: 20,
    name: "x-some-header-name-",
    value: "a-moderately-long-header-val",
  };
  c.open_with(&headers)
    .expect("a >512-byte section with no peer limit must be sent");
  let t = c.poll_transmit().expect("request enqueued");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
}

#[test]
fn open_with_long_over_peer_limit_section_is_field_section_too_large_not_protocol() {
  // A section that exceeds BOTH the peer's MAX_FIELD_SECTION_SIZE AND 512 bytes must
  // surface the LOCAL Error::FieldSectionTooLarge — NOT
  // Error::Protocol(QPACK_DECOMPRESSION_FAILED). The size check runs before any
  // encode-buffer pressure, so a large section maps to the local refusal rather than
  // a spurious protocol error. The request must stay unsent (request_sent false, no
  // transmit).
  //
  // Peer limit = 600 (decoded). 30 fields of (19 + 28 + 32) = 79 decoded bytes
  // each → ~2370 decoded (>> 600), and their encoded form (~1470 bytes) also exceeds
  // 512 bytes — the case that must map to FieldSectionTooLarge, not a protocol error.
  let mut c = client_after_peer_settings(&[0x08, 0x01, 0x06, 0x42, 0x58]); // MAX_FIELD_SECTION_SIZE=600
  assert_eq!(
    c.peer_settings()
      .expect("peer settings stored")
      .max_field_section_size(),
    Some(600)
  );
  let headers = RepeatedHeaders {
    count: 30,
    name: "x-some-header-name-",
    value: "a-moderately-long-header-val",
  };
  assert_eq!(
    c.open_with(&headers),
    Err(Error::FieldSectionTooLarge),
    "an over-limit long section must be the LOCAL FieldSectionTooLarge, not a protocol error"
  );
  assert!(
    c.poll_transmit().is_none(),
    "no request transmit on the too-large path"
  );
  assert!(
    !c.request_sent,
    "request_sent must stay false so a smaller request can be retried"
  );
  assert!(!c.is_terminal(), "a too-large refusal is not a teardown");
  assert_eq!(c.poll_event(), None);
}

#[test]
fn open_with_section_overflowing_workspace_is_field_section_too_large() {
  // With NO peer limit, a section so large it overflows the local TX_CAP encode
  // workspace must be refused LOCALLY as FieldSectionTooLarge (buffer exhaustion →
  // "too large for us to send"), never a peer protocol error. ~120 fields of ~47
  // encoded bytes ≈ 5640 bytes >> TX_CAP.
  let mut c = client_after_peer_settings(&[0x08, 0x01]); // opt-in, no field-size limit
  let headers = RepeatedHeaders {
    count: 120,
    name: "x-some-header-name-",
    value: "a-moderately-long-header-val",
  };
  assert_eq!(
    c.open_with(&headers),
    Err(Error::FieldSectionTooLarge),
    "a section overflowing the local workspace must be FieldSectionTooLarge"
  );
  assert!(c.poll_transmit().is_none(), "nothing sent");
  assert!(!c.request_sent, "request stays retriable");
  assert!(!c.is_terminal());
  assert_eq!(c.poll_event(), None);
}

// ── QPACK encoder/decoder stream errors use the correct codes (§6) ───────

#[test]
fn qpack_encoder_stream_instruction_is_encoder_stream_error() {
  // An instruction byte on the peer's QPACK ENCODER stream (type 0x02) is a
  // violation (we advertise QPACK_MAX_TABLE_CAPACITY=0): it must be the encoder-
  // stream code 0x0201, NOT the generic QPACK_DECOMPRESSION_FAILED.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(2);
  // Type byte 0x02 classifies the encoder stream; the trailing 0x3f is an
  // instruction byte (Set Dynamic Table Capacity), forbidden here.
  assert_eq!(
    c.handle_stream(id, &[0x02, 0x3f], &mut sc).err(),
    Some(H3Error::QpackEncoderStreamError)
  );
}

#[test]
fn qpack_decoder_stream_instruction_is_decoder_stream_error() {
  // An instruction byte on the peer's QPACK DECODER stream (type 0x03) must be
  // the decoder-stream code 0x0202.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(3);
  assert_eq!(
    c.handle_stream(id, &[0x03, 0x01], &mut sc).err(),
    Some(H3Error::QpackDecoderStreamError)
  );
}

#[test]
fn qpack_encoder_stream_instruction_split_after_type_is_encoder_stream_error() {
  // The type byte and the instruction arrive in separate feeds: the encoder
  // stream is classified first (no error on the bare type byte), then the later
  // instruction byte is the encoder-stream error.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(2);
  {
    let mut frames = c
      .handle_stream(id, &[0x02], &mut sc)
      .expect("bare QPACK encoder type byte is fine (stream stays idle)");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert_eq!(
    c.handle_stream(id, &[0x3f], &mut sc).err(),
    Some(H3Error::QpackEncoderStreamError),
    "a later instruction on the registered encoder stream is the encoder code"
  );
}

#[test]
fn qpack_encoder_stream_set_capacity_zero_is_accepted() {
  // Set Dynamic Table Capacity(0) is the single byte 0x20 and is legal even with
  // QPACK_MAX_TABLE_CAPACITY=0 (it sets the capacity to 0 — a no-op within the
  // maximum). On the peer's ENCODER stream (type 0x02) it must be accepted (no
  // error, no frames), not rejected like a dynamic-table instruction.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(2);
  {
    let mut frames = c
      .handle_stream(id, &[0x02, 0x20], &mut sc)
      .expect("Set Capacity(0) on the encoder stream must be accepted");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert_eq!(c.poll_event(), None, "Set Capacity(0) produces no events");
}

#[test]
fn qpack_encoder_stream_set_capacity_one_is_encoder_stream_error() {
  // Set Dynamic Table Capacity with value 1 (0x21) requires a non-zero dynamic
  // table, which we forbid (QPACK_MAX_TABLE_CAPACITY=0): it is the encoder-stream
  // error, NOT accepted like the value-0 special case.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(2);
  assert_eq!(
    c.handle_stream(id, &[0x02, 0x21], &mut sc).err(),
    Some(H3Error::QpackEncoderStreamError),
    "Set Capacity(1) on the encoder stream must be the encoder-stream error"
  );
}

#[test]
fn qpack_encoder_stream_insert_with_name_ref_is_encoder_stream_error() {
  // Insert With Name Reference (high bit set, here 0x80) is a dynamic-table
  // instruction, forbidden with QPACK_MAX_TABLE_CAPACITY=0: encoder-stream error.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(2);
  assert_eq!(
    c.handle_stream(id, &[0x02, 0x80], &mut sc).err(),
    Some(H3Error::QpackEncoderStreamError),
    "Insert With Name Reference on the encoder stream must be the encoder-stream error"
  );
}

#[test]
fn qpack_encoder_stream_set_capacity_zero_split_after_type_is_accepted() {
  // The type byte and the 0x20 instruction arrive in separate feeds: the bare
  // type byte classifies the encoder stream, then the later 0x20 (Set Capacity 0,
  // a complete single-byte instruction with no continuation) is accepted.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let id = StreamId::new(2);
  {
    let mut frames = c
      .handle_stream(id, &[0x02], &mut sc)
      .expect("bare QPACK encoder type byte is fine");
    assert!(frames.next().expect("no frames").is_none());
  }
  {
    let mut frames = c
      .handle_stream(id, &[0x20], &mut sc)
      .expect("a later Set Capacity(0) on the registered encoder stream is accepted");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert_eq!(c.poll_event(), None);
}

// ── role-aware control-frame handling for push / GOAWAY (§7.2) ───────────

/// Feeds `frame_bytes` on the peer control stream of a fresh CLIENT, after the
/// initial SETTINGS frame, returning the `handle_stream` result. Mirrors
/// [`feed_after_settings`] (which uses a server) for the client-only rules.
fn client_feed_after_settings(frame_bytes: &[u8]) -> Result<(), H3Error> {
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 128];
  let id = StreamId::new(3);
  let setup = peer_control_settings(&[]);
  c.handle_stream(id, &setup, &mut sc).map(|_| ())?;
  c.handle_stream(id, frame_bytes, &mut sc).map(|_| ())
}

#[test]
fn client_max_push_id_on_control_after_settings_is_frame_unexpected() {
  // MAX_PUSH_ID (0x0d) is client→server only (RFC 9114 §7.2.7); a CLIENT
  // receiving it from the server is H3_FRAME_UNEXPECTED. Payload: a 1-byte push
  // id varint (0x00).
  assert_eq!(
    client_feed_after_settings(&[0x0d, 0x01, 0x00]),
    Err(H3Error::FrameUnexpected),
    "a client must reject MAX_PUSH_ID on the control stream"
  );
}

#[test]
fn server_max_push_id_on_control_after_settings_is_skipped() {
  // A SERVER receiving MAX_PUSH_ID from the client is valid (we just never push):
  // its payload is skipped, not an error.
  assert_eq!(
    feed_after_settings(&[0x0d, 0x01, 0x00]),
    Ok(()),
    "a server accepts-and-skips MAX_PUSH_ID"
  );
}

#[test]
fn cancel_push_on_control_after_settings_is_id_error() {
  // CANCEL_PUSH (0x03): push is never enabled (no MAX_PUSH_ID is ever sent), so
  // no push id can be valid — receiving it is H3_ID_ERROR (RFC 9114 §7.2.3). Both
  // roles reject it; verify on the server path. Payload: a 1-byte push id (0x00).
  assert_eq!(
    feed_after_settings(&[0x03, 0x01, 0x00]),
    Err(H3Error::IdError),
    "CANCEL_PUSH is an id error when push was never enabled"
  );
}

#[test]
fn cancel_push_on_control_after_settings_is_id_error_for_client_too() {
  // The CANCEL_PUSH rejection is role-independent.
  assert_eq!(
    client_feed_after_settings(&[0x03, 0x01, 0x00]),
    Err(H3Error::IdError)
  );
}

#[test]
fn goaway_on_control_after_settings_is_skipped_for_client() {
  // GOAWAY (0x07) is accepted-and-ignored (v1 limitation): a client skips its
  // payload after SETTINGS. (The server case is covered by
  // `goaway_control_frame_after_settings_is_ignored`.)
  assert_eq!(
    client_feed_after_settings(&[0x07, 0x02, 0xaa, 0xbb]),
    Ok(()),
    "GOAWAY is accepted and its payload skipped"
  );
}

// ── lifecycle-guard audit: terminal / idempotency / readiness symmetry ──────────

#[test]
fn open_with_after_close_is_closed() {
  // `open_with` must honor a prior `close()`, symmetric with `accept_with`. If
  // `close()` was called while waiting for the peer's SETTINGS, a later
  // `open_with` must NOT still send the CONNECT request.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  // Close before the peer's SETTINGS arrive and before the request was sent.
  c.close();
  assert!(c.is_terminal());
  // open_with must now be terminal — not WouldBlock (SETTINGS absent) and not Ok.
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::Closed),
    "open_with after close must be Closed, mirroring accept_with"
  );
  // No request transmit was queued (only the close FIN may be pending, which has no
  // request stream to target here).
  let mut saw_request = false;
  while let Some(t) = c.poll_transmit() {
    if matches!(t.kind(), StreamKind::OpenRequest) {
      saw_request = true;
    }
  }
  assert!(
    !saw_request,
    "no OpenRequest transmit may be queued after close"
  );
  assert!(!c.request_sent, "the request must stay unsent");
}

#[test]
fn open_with_after_reset_is_closed() {
  // Audit: after a peer reset, the connection is closing, so `open_with` is
  // terminal even before the peer's SETTINGS arrive (the request stream the reset
  // targets exists; the reset makes the whole connection closing).
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  let req_id = StreamId::new(7);
  c.provide_stream(StreamRole::Request, req_id);
  c.handle_stream_reset(req_id, 0x010c);
  assert!(c.is_terminal());
  let _ = c.poll_event(); // drain the Reset event
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::Closed),
    "open_with after a reset must be terminal"
  );
}

#[test]
fn accept_with_after_close_is_closed() {
  // Audit (accept_with symmetry): a `close()` before the response is sent makes
  // accept_with terminal, taking precedence over the request-received / SETTINGS
  // readiness gates.
  let mut s = server_request_registered_no_peer_settings();
  s.close();
  assert!(s.is_terminal());
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::Closed),
    "accept_with after close must be Closed"
  );
}

#[test]
fn start_is_idempotent_no_duplicate_control_stream() {
  // Audit: `start` must enqueue the control + QPACK setup exactly once. A second
  // `start` is a no-op Ok — never a duplicate control stream (which the peer would
  // reject with H3_STREAM_CREATION_ERROR).
  let mut c = Connection::<Client>::new();
  c.start().expect("first start");
  let first = drain_transmits(&mut c);
  assert_eq!(first, 3, "start enqueues the control + 2 QPACK streams");
  c.start().expect("second start is a no-op Ok");
  assert_eq!(
    drain_transmits(&mut c),
    0,
    "a second start must enqueue nothing (no duplicate control stream)"
  );
}

#[test]
fn start_after_close_is_closed() {
  // Audit: `start` is terminal once closing — it must not set up a connection that
  // has already been closed.
  let mut c = Connection::<Client>::new();
  c.close(); // close before start: a degenerate but legal call order
  assert_eq!(
    c.start(),
    Err(Error::Closed),
    "start after close must be terminal"
  );
  assert_eq!(drain_transmits(&mut c), 0, "no setup transmits after close");
}

#[test]
fn reset_is_idempotent_single_event() {
  // Audit: a repeated reset of the request stream must enqueue Event::Reset at most
  // once (mirroring close's exactly-once FIN), and stays terminal.
  let mut h = Harness::new();
  h.run_until_established();
  let req_id = h.request_id.expect("request id assigned");
  h.client.handle_stream_reset(req_id, 0x010c);
  h.client.handle_stream_reset(req_id, 0x010c);
  assert_eq!(h.client.poll_event(), Some(Event::Reset(0x010c)));
  assert_eq!(
    h.client.poll_event(),
    None,
    "a repeated reset must not enqueue a second Reset event"
  );
  assert!(h.client.send_data(b"x").is_err(), "still terminal");
}

#[test]
fn out_of_order_calls_do_not_panic() {
  // Audit: no public method panics when called out of order. Exercise the
  // degenerate orderings the guard matrix must tolerate: send_data before
  // established, close before start, double close, FIN/reset on unknown ids, and
  // accept_with on a fresh server.
  let mut c = Connection::<Client>::new();
  assert!(c.send_data(b"x").is_err(), "send before established");
  c.close(); // close before start
  c.close(); // close twice
  c.handle_stream_fin(StreamId::new(123)); // FIN on an unknown id
  c.handle_stream_reset(StreamId::new(123), 0); // reset on an unknown id
  let mut s = Connection::<Server>::new();
  // accept_with on a fresh server that has not `start`ed is terminal `Closed` (the
  // setup streams must precede the response), no panic. (Once `start`ed but before
  // the request/SETTINGS it would be the retriable WouldBlock; see
  // `server_accept_before_request_errors`.)
  assert_eq!(s.accept_with(&RESPONSE[..]), Err(Error::Closed));
  s.handle_stream_fin(StreamId::new(1)); // FIN before any stream registered
}

// ── provide_stream must not silently rebind a role to a new id ────────

#[test]
fn provide_stream_second_request_id_coexists_and_keeps_the_tunnel_slot() {
  // A request stream is NO LONGER write-once-singular (the multi-stream core): a
  // SECOND request id gets its OWN store entry rather than failing the connection,
  // and `request_id` — the single CONNECT tunnel-slot pointer — keeps naming the
  // FIRST id (so send_data / close / accept_with still target the original tunnel).
  // Re-providing the SAME (Request, id) is an idempotent no-op (the entry is kept).
  let mut c = Connection::<Client>::new();
  let id1 = StreamId::new(4);
  let id2 = StreamId::new(8);
  c.provide_stream(StreamRole::Request, id1);
  assert_eq!(
    c.request_id,
    Some(id1),
    "first binding records the tunnel slot"
  );
  assert!(!c.is_terminal(), "the first binding is healthy");
  // A second, different request id: accepted (its own entry), not a teardown.
  c.provide_stream(StreamRole::Request, id2);
  assert!(
    !c.is_terminal(),
    "a second request id coexists rather than failing the connection"
  );
  assert_eq!(
    c.request_id,
    Some(id1),
    "the tunnel-slot pointer keeps naming the first id"
  );
  assert_eq!(c.poll_event(), None, "no duplicate-stream error: not fatal");
  // Both ids are tracked as request streams: each routes to the request path.
  assert!(c.streams.get(id1).is_some(), "id1 has its own store entry");
  assert!(c.streams.get(id2).is_some(), "id2 has its own store entry");
  // Re-providing the ORIGINAL (role, id) is an idempotent no-op: no further event.
  c.provide_stream(StreamRole::Request, id1);
  assert_eq!(
    c.poll_event(),
    None,
    "re-providing the same (Request, id1) is a no-op"
  );
  assert_eq!(c.request_id, Some(id1));
}

#[test]
fn provide_stream_rebinding_a_critical_role_to_a_different_id_is_terminal() {
  // The write-once rule generalizes to any critical role: a second control stream
  // id provided for the already-bound ControlOut role is the same
  // duplicate-critical error.
  let mut c = Connection::<Client>::new();
  c.provide_stream(StreamRole::ControlOut, StreamId::new(0));
  assert!(!c.is_terminal());
  c.provide_stream(StreamRole::ControlOut, StreamId::new(2));
  assert!(
    c.is_terminal(),
    "a different-id critical rebind is terminal"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::StreamCreation))
  );
  assert_eq!(c.poll_event(), None);
}

#[test]
fn close_before_provide_request_still_binds_first_id() {
  // `close()` before the request stream is bound leaves `request_id` UNBOUND
  // (close only sets the pending FIN), so the later FIRST
  // `provide_stream(Request, id)` is a first binding — NOT a different-id rebind —
  // and still records the id and lets the deferred FIN target it (emitted once).
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  c.close(); // request stream not yet bound; FIN is held pending
  assert!(c.is_terminal());
  assert_eq!(c.request_id, None, "close does not bind the request id");
  let req_id = StreamId::new(12);
  c.provide_stream(StreamRole::Request, req_id);
  assert_eq!(
    c.request_id,
    Some(req_id),
    "the first request binding after close still records the id"
  );
  // No spurious StreamCreation error from this first binding.
  assert_eq!(
    c.poll_event(),
    None,
    "a first binding after close is not a duplicate"
  );
  // The deferred close FIN now targets the freshly bound request stream, once.
  let mut fin_count = 0usize;
  while let Some(t) = c.poll_transmit() {
    if t.fin() && matches!(t.kind(), StreamKind::Existing(id) if id == req_id) {
      fin_count += 1;
    }
  }
  assert_eq!(fin_count, 1, "the deferred FIN is emitted exactly once");
}

// ── a connection-fatal FIN must make the connection terminal ──────────

#[test]
fn request_mid_frame_fin_is_terminal_and_signals_once() {
  // A request stream ending mid-frame enqueues ConnError(FrameError) AND
  // makes the connection terminal, so a previously-ready `open_with` / `send_data`
  // now returns Closed. A second fatal FIN must not enqueue a duplicate event.
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  let id = StreamId::new(0);
  c.provide_stream(StreamRole::Request, id);
  assert!(!c.is_terminal(), "healthy and ready to open before the FIN");
  // Feed one byte of a frame header, leaving the request FSM mid-frame.
  let mut sc = std::vec![0u8; 64];
  {
    let mut frames = c
      .handle_stream(id, &[0x01], &mut sc)
      .expect("partial header must not error");
    assert!(frames.next().expect("no frames yet").is_none());
  }
  c.handle_stream_fin(id);
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameError)),
    "a mid-frame request FIN is a frame error"
  );
  assert!(
    c.is_terminal(),
    "a mid-frame request FIN makes the connection terminal"
  );
  // The send paths are now terminal (they were ready before the FIN).
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::Closed),
    "open_with after a fatal request FIN must be Closed"
  );
  assert_eq!(
    c.send_data(b"x"),
    Err(Error::Closed),
    "send_data after a fatal request FIN must be Closed"
  );
  // A second fatal FIN must NOT enqueue a duplicate ConnError.
  c.handle_stream_fin(id);
  assert_eq!(
    c.poll_event(),
    None,
    "a repeated fatal FIN must not enqueue a second event"
  );
}

#[test]
fn critical_stream_fin_is_terminal_and_signals_once() {
  // A critical (control) stream closing enqueues ConnError(ClosedCriticalStream)
  // AND makes the connection terminal, so an
  // established tunnel's `send_data` now returns Closed. A second fatal FIN must
  // not enqueue a duplicate event.
  //
  // Drive a server to Established (so send_data would otherwise succeed), then FIN
  // the peer's inbound control stream (id 3, registered by the SETTINGS feed).
  let mut s = server_request_registered_no_peer_settings();
  let mut sc = [0u8; 128];
  let bytes = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  deliver_connect_request(&mut s, StreamId::new(0));
  s.accept_with(&RESPONSE[..]).expect("accept_with succeeds");
  assert!(s.is_established());
  assert_eq!(s.poll_event(), Some(Event::Established));
  s.send_data(b"ok")
    .expect("send_data works while established");
  drain_transmits(&mut s);
  assert!(!s.is_terminal(), "healthy before the critical-stream FIN");
  // FIN the inbound control stream: a closed critical stream.
  s.handle_stream_fin(StreamId::new(3));
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "closing a critical stream is H3_CLOSED_CRITICAL_STREAM"
  );
  assert!(
    s.is_terminal(),
    "a critical-stream FIN makes the connection terminal"
  );
  assert_eq!(
    s.send_data(b"x"),
    Err(Error::Closed),
    "send_data after a critical-stream FIN must be Closed"
  );
  // A second critical-stream FIN must NOT enqueue a duplicate event.
  s.handle_stream_fin(StreamId::new(3));
  assert_eq!(
    s.poll_event(),
    None,
    "a repeated critical-stream FIN must not enqueue a second event"
  );
}

#[test]
fn clean_request_fin_after_headers_is_peer_closed_and_not_a_teardown() {
  // A CLEAN request-stream FIN at a frame boundary AFTER the CONNECT HEADERS (the
  // FSM reached Tunnel) is the graceful PeerClosed signal, NOT a connection-fatal
  // error — the peer merely half-closed its send side of an established tunnel, so
  // the connection is not forced terminal here. (Contrast with
  // `handle_stream_fin_before_headers_is_request_incomplete`: a FIN BEFORE the
  // HEADERS is fatal.)
  //
  // A tunnel-lifecycle `PeerClosed` is gated on the tunnel being established
  // (`tunnel_established`), not merely on the FSM reaching `Tunnel` (the HEADERS
  // decoded), so the FIN must land on a genuinely ESTABLISHED tunnel for the
  // IMMEDIATE PeerClosed. `client_open_at_tunnel_boundary` establishes the client
  // (start + open_with + observed response HEADERS) and leaves the request FSM at a
  // Tunnel frame boundary — the realistic shape this boundary case exercises.
  // (The pre-establishment FIN — FSM in Tunnel but tunnel NOT established — is the
  // DEFERRED-PeerClosed case covered by the deferred-emit tests below.)
  let id = StreamId::new(7);
  let mut c = client_open_at_tunnel_boundary(id);
  // A clean FIN now lands at a frame boundary in Tunnel of an established tunnel: a
  // graceful half-close.
  c.handle_stream_fin(id);
  // Drain any non-PeerClosed events (e.g. Established) first, then assert the
  // PeerClosed and that the connection stays non-terminal.
  let mut saw_peer_closed = false;
  let mut saw_conn_error = false;
  while let Some(ev) = c.poll_event() {
    match ev {
      Event::PeerClosed => saw_peer_closed = true,
      Event::ConnError(_) => saw_conn_error = true,
      _ => {}
    }
  }
  assert!(saw_peer_closed, "a clean FIN in Tunnel is PeerClosed");
  assert!(!saw_conn_error, "a clean half-close is not a ConnError");
  assert!(
    !c.is_terminal(),
    "a clean (graceful) request FIN in Tunnel is a half-close, not a teardown"
  );
}

// ── every connection-fatal inbound H3Error routes through `fail` ───────

/// Drives a client to the `Open` phase (the tunnel established) by: feeding the
/// peer's SETTINGS, sending the CONNECT request, registering the request stream
/// `req_id`, then decoding the response HEADERS on it (which both drives the FSM
/// into Tunnel and runs the client's establish transition). Leaves the request
/// stream at a frame boundary in Tunnel, the transmit ring drained, and the
/// `Established` event drained — so a follow-on fatal inbound error is observable
/// in isolation.
fn client_open_at_tunnel_boundary(req_id: StreamId) -> StaticConnection<Client> {
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("response HEADERS decode");
    let mut saw = false;
    while let Some(f) = frames.next().expect("response frame") {
      if let Frame::Response { mut headers, .. } = f {
        saw = true;
        while headers.next().expect("resp header").is_some() {}
      }
    }
    assert!(saw, "the client yields the response HEADERS");
  }
  assert!(c.is_established(), "the tunnel is Open after the response");
  assert_eq!(c.poll_event(), Some(Event::Established));
  drain_transmits(&mut c);
  c
}

#[test]
fn lazy_second_headers_routes_through_fail_and_makes_terminal() {
  // A SECOND HEADERS frame on the request stream is a frame-placement violation
  // surfaced LAZILY by `Frames::next` (not by `handle_stream` itself). This lazy
  // error must fail the connection rather than merely propagate to the caller:
  // otherwise the connection would stay Open and a later `send_data` would be
  // accepted on a dead tunnel. Routing through the centralized `fail` makes the
  // connection terminal, enqueues exactly one ConnError(FrameUnexpected), and makes
  // `send_data` return Closed.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // The tunnel is Open: a send works right up until the fatal frame.
  c.send_data(b"pre").expect("send_data works while Open");
  drain_transmits(&mut c);
  // Feed a SECOND HEADERS frame on the request stream (the FSM is in Tunnel, so a
  // HEADERS is now H3_FRAME_UNEXPECTED). The error surfaces on the first pull.
  let second = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &second, &mut sc)
      .expect("handle_stream only builds the iterator");
    assert_eq!(
      frames.next().err(),
      Some(H3Error::FrameUnexpected),
      "a second HEADERS in Tunnel is the lazy frame-unexpected error"
    );
  }
  // The lazy error routed through `fail` → terminal + one ConnError.
  assert!(
    c.is_terminal(),
    "a lazy fatal error makes the connection terminal"
  );
  assert_eq!(
    c.send_data(b"post"),
    Err(Error::Closed),
    "send_data after a lazy fatal error must be Closed"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameUnexpected)),
    "the lazy error is surfaced as exactly one terminal ConnError"
  );
  assert_eq!(c.poll_event(), None, "exactly one ConnError is enqueued");
}

#[test]
fn lazy_qpack_error_routes_through_fail_and_makes_terminal() {
  // QPACK variant: a malformed QPACK field section on the request stream surfaces
  // lazily from `Frames::next` (the FSM validates the whole section on the first
  // pull) and must route through `fail`. The malformed FIRST HEADERS fails before
  // establishing, so the connection was `Handshaking`; the load-bearing assertions
  // are that it is now `Failed` (terminal — NOT merely un-established) with exactly
  // one ConnError(QpackDecompressionFailed), and that `send_data` returns Closed
  // afterwards.
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  let req_id = StreamId::new(0);
  c.provide_stream(StreamRole::Request, req_id);
  assert!(!c.is_terminal(), "healthy before the malformed HEADERS");
  // A HEADERS frame whose field section references the dynamic table (0x80, the
  // static (T) bit clear), which this static-only decoder rejects — a lazy QPACK
  // decompression failure surfaced on the first `Frames::next` pull.
  let fs = [0x00u8, 0x00, 0xd9, 0x80];
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(crate::frame::FrameType::Headers, fs.len() as u64, &mut hdr)
    .unwrap();
  let mut frame = std::vec::Vec::new();
  frame.extend_from_slice(&hdr[..hn]);
  frame.extend_from_slice(&fs);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("handle_stream only builds the iterator");
    assert_eq!(
      frames.next().err(),
      Some(H3Error::QpackDecompressionFailed),
      "a dynamic-table reference is a lazy QPACK decompression failure"
    );
  }
  // The lazy QPACK error routed through `fail` → terminal + one ConnError.
  assert!(
    c.is_terminal(),
    "a lazy QPACK error makes the connection terminal (not merely un-established)"
  );
  assert_eq!(
    c.send_data(b"post"),
    Err(Error::Closed),
    "send_data after a lazy QPACK error must be Closed"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::QpackDecompressionFailed))
  );
  assert_eq!(c.poll_event(), None, "exactly one ConnError");
}

// ── `Frames::next` is inert once the connection has failed (terminal-priority) ─────

/// A zero-length HEADERS frame (frame type HEADERS, length 0, empty field section).
/// On an established tunnel the request FSM is in `Tunnel`, so ANY HEADERS frame is a
/// forbidden second HEADERS → `H3Error::FrameUnexpected` — even an empty one (the FSM
/// rejects on the frame header's kind, before any field section is consumed).
fn zero_length_headers_frame() -> Vec<u8> {
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(crate::frame::FrameType::Headers, 0, &mut hdr)
    .expect("zero-length HEADERS frame header encodes");
  hdr[..hn].to_vec()
}

#[test]
fn lazy_fatal_then_second_next_yields_no_trailing_data_frames_next_is_fused() {
  // `Frames::next` must be FUSED once a lazy fatal request-FSM error has failed the
  // connection — mirroring `drain_for_errors`' `is_failed()` top guard.
  //
  // The exploit: on an established tunnel, ONE `handle_stream` read carrying
  // `[forbidden zero-length second HEADERS][DATA frame]`. The first `next()` hits
  // the forbidden HEADERS in `Tunnel` (→ `FrameUnexpected`) and routes through
  // `fail_into` (terminal `ConnError` recorded). Without the fuse the SAME iterator
  // would stay live, so a SECOND `next()` would resume parsing AFTER the bad HEADERS
  // and — because `tunnel_established` is still true — yield the following
  // `Frame::Data`, surfacing application data AFTER the connection was already
  // `Failed`, breaking terminal-priority ordering. With the fuse, the second `next()`
  // returns `Ok(None)` and the only observable event is the single terminal ConnError.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // ONE read: a forbidden zero-length second HEADERS, then a DATA frame that the
  // pre-fix iterator would resume into and surface as `Frame::Data`.
  let mut input = zero_length_headers_frame();
  input.extend_from_slice(&request_data_frame(b"smuggled"));
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &input, &mut sc)
      .expect("handle_stream only builds the iterator on an Open connection");
    // First pull: the forbidden HEADERS is the lazy frame-unexpected error.
    assert_eq!(
      frames.next().err(),
      Some(H3Error::FrameUnexpected),
      "a second (zero-length) HEADERS in Tunnel is the lazy frame-unexpected error"
    );
    // Second pull: the iterator is now fused (the connection is Failed). It MUST NOT
    // resume parsing into the trailing DATA frame and surface it as `Frame::Data`.
    assert!(
      frames
        .next()
        .expect("a fused iterator yields Ok(None), never an Err")
        .is_none(),
      "a fused Frames must not surface trailing Frame::Data after the terminal error"
    );
    // A third pull stays fused too.
    assert!(
      frames.next().expect("still fused").is_none(),
      "every subsequent next() on a fused Frames is Ok(None)"
    );
  }
  // The lazy error routed through `fail` → terminal + exactly one ConnError, and the
  // send path is now `Closed`.
  assert!(
    c.is_terminal(),
    "the lazy fatal error makes the connection terminal"
  );
  assert_eq!(
    c.send_data(b"post"),
    Err(Error::Closed),
    "send_data after the fused fatal error must be Closed"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameUnexpected)),
    "exactly the terminal ConnError(FrameUnexpected) — no Frame::Data ahead of it"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "exactly one event: the terminal ConnError, nothing from the trailing DATA"
  );
}

#[test]
fn lazy_fatal_then_drop_drain_emits_nothing_new_next_drain_parity() {
  // Drop variant — next/drain parity end-to-end: the SAME
  // `[zero-length second HEADERS][DATA]` read, but the driver pulls `next()` ONCE
  // (getting the `Err`) and then DROPS the `Frames`. The drop-drain
  // (`drain_for_errors`) must be a no-op — its own `is_failed()` top guard already
  // short-circuits a connection the yield path just failed — so it yields/emits
  // nothing new and the connection stays `Failed` with the single ConnError. This
  // confirms the yield-path fuse and the drop-path guard agree.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  let mut input = zero_length_headers_frame();
  input.extend_from_slice(&request_data_frame(b"smuggled"));
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &input, &mut sc)
      .expect("handle_stream only builds the iterator");
    assert_eq!(
      frames.next().err(),
      Some(H3Error::FrameUnexpected),
      "the forbidden HEADERS fails the connection on the first pull"
    );
    // Drop `frames` here WITHOUT pulling again: the drop-drain runs over the
    // remaining (post-error) input but is guarded by `is_failed()`, so it is a no-op.
  }
  assert!(
    c.is_terminal(),
    "the connection stays terminal after the drop"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameUnexpected)),
    "the drop-drain added nothing: exactly the single terminal ConnError"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "next/drain parity: no extra event from the dropped iterator"
  );
}

// ── an undrained request `Frames` still validates ALL supplied bytes ─────────

#[test]
fn undrained_request_frames_drop_validates_trailing_forbidden_headers_server() {
  // The OBSERVED-then-dropped path: a peer can coalesce, in ONE `handle_stream`
  // call, a valid CONNECT request HEADERS frame followed by a FORBIDDEN second
  // HEADERS frame. A server driver that pulls ONLY the first `Frame::Request` (so
  // readiness fires from that next()) and then drops the iterator (without pulling
  // far enough to surface the second HEADERS) must STILL get the trailing frame
  // validated: drain-on-drop drives the FSM over the unread bytes, hits
  // H3_FRAME_UNEXPECTED, and routes it through `fail`. The connection becomes
  // terminal even though `Frames::next` was never pulled to the error.
  // (Distinct from the unobserved-drop case: here the first HEADERS WAS observed
  // via next(), so granting readiness was correct; the trailing-fatal scan is what
  // the drop drain adds.)
  let mut s = server_request_registered_no_peer_settings();
  // Deliver the client's control-stream SETTINGS so the peer-SETTINGS gate is
  // satisfied: after the request is decoded, `accept_with` would otherwise succeed,
  // so its `Closed` below is caused specifically by the drop-drain failing the conn.
  let mut sc = [0u8; 128];
  {
    let bytes = peer_control_settings(&[0x08, 0x01]);
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  // One `handle_stream` input = [valid CONNECT request HEADERS][forbidden 2nd HEADERS].
  let mut bytes = request_headers_frame(&CONNECT_REQUEST[..]);
  bytes.extend_from_slice(&request_headers_frame(&RESPONSE[..]));
  let mut rsc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(StreamId::new(0), &bytes, &mut rsc)
      .expect("handle_stream only builds the iterator");
    // Pull ONLY the first frame (the CONNECT request), then stop and let `frames`
    // drop WITHOUT pulling the second HEADERS that follows it in the same input.
    let first = frames
      .next()
      .expect("first frame ok")
      .expect("a first frame");
    assert!(
      matches!(first, Frame::Request(_)),
      "the first yielded frame is the CONNECT request HEADERS"
    );
    // `frames` drops here: drain-on-drop validates the trailing forbidden HEADERS.
  }
  // The drop-drain failed the connection: it is now terminal, so BOTH send paths
  // report `Closed` (the request was received, so absent the drop-drain validation
  // `accept_with` would succeed here).
  assert!(
    s.is_terminal(),
    "the trailing forbidden HEADERS made the connection terminal on drop"
  );
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::Closed),
    "accept_with after the drop-drain failure must be Closed"
  );
  assert_eq!(
    s.send_data(b"x"),
    Err(Error::Closed),
    "send_data after the drop-drain failure must be Closed"
  );
  // Exactly one ConnError(FrameUnexpected) — the second HEADERS — is observable.
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::FrameUnexpected)),
    "the trailing second HEADERS surfaces as exactly one terminal ConnError"
  );
  assert_eq!(s.poll_event(), None, "exactly one ConnError is enqueued");
}

#[test]
fn undrained_request_frames_drop_validates_trailing_forbidden_frame_client() {
  // Client analog — the OBSERVED-then-dropped path: a response HEADERS frame
  // followed by a forbidden frame (a second HEADERS) in ONE `handle_stream` input.
  // The client pulls only the `Frame::Response` (observing it, which establishes the
  // tunnel from that next()) and drops without reaching the forbidden frame;
  // drain-on-drop must still fail the connection. (Distinct from the unobserved-drop
  // case: here the response WAS observed, so establishing was correct; the
  // trailing-fatal scan then supersedes it.)
  let req_id = StreamId::new(0);
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  // [valid response HEADERS][forbidden 2nd HEADERS] in a single feed.
  let mut bytes = request_headers_frame(&RESPONSE[..]);
  bytes.extend_from_slice(&request_headers_frame(&RESPONSE[..]));
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &bytes, &mut sc)
      .expect("handle_stream only builds the iterator");
    let first = frames
      .next()
      .expect("first frame ok")
      .expect("a first frame");
    assert!(
      matches!(first, Frame::Response { .. }),
      "the first yielded frame is the response HEADERS"
    );
    // Drop without pulling the trailing forbidden HEADERS.
  }
  // Pulling the response established the tunnel; the drop-drain then failed it on the
  // forbidden frame, so `Failed` supersedes `Open` and the send path is `Closed`.
  assert!(
    c.is_terminal(),
    "the trailing forbidden frame made the connection terminal on drop"
  );
  assert_eq!(
    c.send_data(b"x"),
    Err(Error::Closed),
    "send_data after the drop-drain failure must be Closed"
  );
  // The fail transition clears the pending queue, so the `Established` queued by the
  // pulled response is DISCARDED — the connection is terminal-priority and
  // `poll_event` yields EXACTLY the terminal ConnError(FrameUnexpected), then None
  // (no stale `Established` ahead of it).
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameUnexpected)),
    "the trailing second HEADERS surfaces as exactly one terminal ConnError"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "the stale Established was discarded; exactly one ConnError is delivered"
  );
}

#[test]
fn fully_drained_request_frames_drop_is_not_a_spurious_failure() {
  // The drop-drain must NOT introduce a spurious failure on the normal path. A
  // request HEADERS frame with NO trailing forbidden frame, fully
  // drained, leaves nothing for drop-drain to find — the server stays healthy,
  // `request_received` is set, and `accept_with` still succeeds exactly as before.
  let mut s = server_request_registered_no_peer_settings();
  let mut sc = [0u8; 128];
  {
    let bytes = peer_control_settings(&[0x08, 0x01]);
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  // A single well-formed CONNECT request HEADERS frame, fully drained.
  let bytes = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut rsc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(StreamId::new(0), &bytes, &mut rsc)
      .expect("request HEADERS decode");
    let mut saw = false;
    while let Some(f) = frames.next().expect("request frame") {
      match f {
        Frame::Request(mut hs) => {
          saw = true;
          while hs.next().expect("req header").is_some() {}
        }
        Frame::Response { .. } | Frame::Trailers(_) | Frame::Data(_) => {
          panic!("expected only the request HEADERS")
        }
      }
    }
    assert!(saw, "the server yields the CONNECT request HEADERS");
    // `frames` drops here after a FULL drain: drop-drain finds nothing.
  }
  assert!(
    !s.is_terminal(),
    "a fully-drained clean request must not be failed by drop-drain"
  );
  assert_eq!(s.poll_event(), None, "no spurious event from drop-drain");
  // The connection still works: `accept_with` succeeds (request received + SETTINGS).
  s.accept_with(&RESPONSE[..])
    .expect("accept_with after a clean fully-drained request still succeeds");
  assert!(s.is_established(), "the tunnel establishes normally");
}

// ── `fail` cancels a deferred graceful FIN ────────────────────────────

#[test]
fn fail_cancels_a_deferred_close_fin() {
  // A `close()` whose empty FIN was DEFERRED (the transmit ring was full) must NOT
  // later flush a graceful FIN once the connection has `fail`ed. A
  // Failed connection emits no clean close FIN; draining `poll_transmit` after the
  // failure yields the queued payloads but NO fin:true transmit, and exactly one
  // ConnError is observed.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Fill the transmit ring so a subsequent close cannot enqueue its FIN now.
  for _ in 0..super::queue::TX_N {
    c.send_data(b"x").expect("ring not yet full");
  }
  assert_eq!(c.send_data(b"x"), Err(Error::WouldBlock), "ring is full");
  // Close under backpressure: the FIN is deferred (close_pending set).
  c.close();
  assert!(c.is_terminal(), "close enters Closing");
  // A fatal condition now arrives BEFORE the deferred FIN could flush: a mid-frame
  // request FIN (feed one byte of a header to leave the FSM mid-frame, then FIN).
  let mut sc = std::vec![0u8; 64];
  {
    let mut frames = c
      .handle_stream(req_id, &[0x01], &mut sc)
      .expect("partial header ok");
    assert!(frames.next().expect("no frames yet").is_none());
  }
  c.handle_stream_fin(req_id);
  // The connection is now Failed; draining the ring must yield NO graceful FIN
  // (close_pending was cleared by `fail`, and `try_send_fin` requires Closing).
  let mut saw_fin = false;
  let mut polls = 0usize;
  while let Some(t) = c.poll_transmit() {
    saw_fin |= t.fin();
    polls += 1;
    assert!(polls < 200, "poll_transmit did not terminate");
  }
  assert!(
    !saw_fin,
    "a Failed connection must not flush a deferred graceful FIN"
  );
  // Exactly one ConnError (the fatal mid-frame FIN); the close enqueued none.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameError)),
    "the fatal condition surfaces as exactly one ConnError"
  );
  assert_eq!(c.poll_event(), None, "exactly one ConnError");
}

#[test]
fn fail_via_lazy_error_cancels_a_deferred_close_fin() {
  // When the failure arrives through the LAZY iterator path (`Frames::next` →
  // `Phase::fail_into`), `close_pending` is cleared by `fail_into` itself (it
  // carries `&mut close_pending`). The primary invariant therefore holds on the
  // lazy path, not only via the belt-and-suspenders `Phase::Closing` guard in
  // `try_send_fin`: the fatal transition clears `close_pending`, so a `Failed`
  // connection never flushes a deferred graceful FIN regardless of which path
  // produced the failure.
  // Same scenario as `fail_cancels_a_deferred_close_fin` but the fatal condition is
  // a second HEADERS (a lazy `FrameUnexpected`), not a mid-frame FIN.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  for _ in 0..super::queue::TX_N {
    c.send_data(b"x").expect("ring not yet full");
  }
  assert_eq!(c.send_data(b"x"), Err(Error::WouldBlock), "ring is full");
  c.close(); // FIN deferred (close_pending set), phase Closing
  assert!(c.is_terminal());
  assert!(
    c.is_close_pending(),
    "the deferred FIN must be pending after close() under a full ring"
  );
  // A lazy fatal error: a second HEADERS on the request stream (FSM in Tunnel).
  let second = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &second, &mut sc)
      .expect("handle_stream only builds the iterator");
    assert_eq!(frames.next().err(), Some(H3Error::FrameUnexpected));
  }
  // The lazy fail path clears close_pending directly (via fail_into's &mut bool
  // parameter), so the primary invariant holds — not just the secondary
  // belt-and-suspenders guard in try_send_fin.
  assert!(
    !c.is_close_pending(),
    "the lazy fatal path must clear close_pending (primary invariant)"
  );
  assert!(
    c.phase.is_failed(),
    "the lazy path must produce the Failed phase"
  );
  // Draining must yield NO FIN: close_pending is clear and the phase is Failed.
  let mut saw_fin = false;
  let mut polls = 0usize;
  while let Some(t) = c.poll_transmit() {
    saw_fin |= t.fin();
    polls += 1;
    assert!(polls < 200, "poll_transmit did not terminate");
  }
  assert!(
    !saw_fin,
    "a Failed connection must not flush a deferred FIN even via the lazy path"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameUnexpected))
  );
  assert_eq!(c.poll_event(), None, "exactly one ConnError");
}

// ── start is transactional; setup precedes request/data ──────────────

#[test]
fn start_on_a_near_full_ring_enqueues_no_partial_setup_and_retry_is_single() {
  // `start` is all-or-nothing. With fewer than three free transmit slots it
  // returns WouldBlock having enqueued NOTHING (no partial setup) and leaving
  // `started` false. After the ring drains, a single retry produces EXACTLY ONE
  // control stream — never the duplicate critical streams a partial-then-retry
  // path would create.
  let mut c = Connection::<Client>::new();
  // Fill the ring directly so only two slots remain (< 3 needed by start).
  for _ in 0..(super::queue::TX_N - 2) {
    assert!(
      c.tx
        .enqueue(StreamKind::OpenRequest, false, |_out| Ok::<usize, ()>(0))
        .is_ok(),
      "dummy transmit enqueues while the ring has room"
    );
  }
  assert!(
    c.tx.has_capacity_mut(2) && !c.tx.has_capacity_mut(3),
    "ring has 2 free slots"
  );
  // start cannot fit its three setup transmits: WouldBlock, nothing enqueued.
  assert_eq!(
    c.start(),
    Err(Error::WouldBlock),
    "start on a near-full ring is WouldBlock"
  );
  assert!(!c.is_started(), "a failed start leaves started false");
  // Draining yields ONLY the dummy transmits — start added no setup transmit.
  let mut setup_seen = 0usize;
  let mut total = 0usize;
  while let Some(t) = c.poll_transmit() {
    total += 1;
    if matches!(
      t.kind(),
      StreamKind::OpenUni(
        StreamRole::ControlOut | StreamRole::QpackEncOut | StreamRole::QpackDecOut
      )
    ) {
      setup_seen += 1;
    }
  }
  assert_eq!(
    total,
    super::queue::TX_N - 2,
    "only the dummy transmits were queued"
  );
  assert_eq!(setup_seen, 0, "the failed start enqueued no setup transmit");
  // The ring is now empty; the retry succeeds and emits EXACTLY ONE control stream.
  c.start().expect("retry on the drained ring succeeds");
  assert!(c.is_started());
  let mut control_streams = 0usize;
  let mut setup_total = 0usize;
  while let Some(t) = c.poll_transmit() {
    setup_total += 1;
    if matches!(t.kind(), StreamKind::OpenUni(StreamRole::ControlOut)) {
      control_streams += 1;
    }
  }
  assert_eq!(
    setup_total, 3,
    "the retry enqueues exactly the 3 setup streams"
  );
  assert_eq!(
    control_streams, 1,
    "exactly one control stream — no duplicate from a partial-then-retry"
  );
}

#[test]
fn open_with_before_start_enqueues_no_request_transmit() {
  // Request/data traffic must not precede setup. `open_with` before `start` must
  // NOT enqueue an OpenRequest (which would put the CONNECT request on the
  // wire ahead of our SETTINGS, violating RFC 8441 ordering); it returns Closed.
  let mut c = Connection::<Client>::new();
  assert!(!c.is_started());
  assert_eq!(
    c.open_with(&CONNECT_REQUEST[..]),
    Err(Error::Closed),
    "open_with before start is a terminal usage error"
  );
  assert!(
    c.poll_transmit().is_none(),
    "no request transmit may be enqueued before start"
  );
  assert!(!c.request_sent, "the request stays unsent");
}

#[test]
fn send_data_before_start_enqueues_no_data_transmit() {
  // `send_data` before `start` must NOT enqueue a DATA frame ahead of our SETTINGS;
  // it returns Closed.
  let mut c = Connection::<Client>::new();
  assert!(!c.is_started());
  assert_eq!(
    c.send_data(b"x"),
    Err(Error::Closed),
    "send_data before start is a terminal usage error"
  );
  assert!(
    c.poll_transmit().is_none(),
    "no DATA transmit may be enqueued before start"
  );
}

#[test]
fn accept_with_before_start_enqueues_no_response_transmit() {
  // Server parity: `accept_with` before `start` must NOT enqueue a response HEADERS
  // frame ahead of our SETTINGS; it returns Closed.
  let mut s = Connection::<Server>::new();
  assert!(!s.is_started());
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::Closed),
    "accept_with before start is a terminal usage error"
  );
  assert!(
    s.poll_transmit().is_none(),
    "no response transmit may be enqueued before start"
  );
  assert!(!s.is_established(), "the tunnel must not be established");
}

// ── Phase machine: explicit transition / guard coverage (refactor) ──────────────

#[test]
fn phase_progresses_created_handshaking_open_then_closing() {
  // The full client lifecycle observed through the Phase-derived predicates:
  // Created (fresh) → Handshaking (after start) → Open (after the response HEADERS
  // are decoded / Established) → Closing (after close). Each predicate is the
  // single Phase read, so this pins the linear progression end to end.
  let mut h = Harness::new();
  // Created: not started, not open, not terminal.
  assert!(!h.client.is_started() && !h.client.is_established() && !h.client.is_terminal());
  h.client.start().expect("client start");
  h.server.start().expect("server start");
  // Handshaking: started, but not yet open and not terminal.
  assert!(h.client.is_started() && !h.client.is_established() && !h.client.is_terminal());
  // Drive both ends to Established the normal way.
  h.run_until_established();
  // Open: established, started, not terminal.
  assert!(h.client.is_established() && h.client.is_started() && !h.client.is_terminal());
  assert!(h.server.is_established() && !h.server.is_terminal());
  // Closing: a local close moves Open → Closing (terminal); still "started".
  h.client.close();
  assert!(h.client.is_terminal() && h.client.is_started());
  // is_established now reports false (the phase is no longer Open).
  assert!(!h.client.is_established(), "Closing is no longer Open");
}

#[test]
fn send_data_in_handshaking_is_closed() {
  // send_data's single guard is `phase == Open`. In Handshaking (started, peer
  // SETTINGS in, request even bound — but the CONNECT exchange not yet complete)
  // it must still be Closed, never enqueuing a DATA frame ahead of establishment.
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.provide_stream(StreamRole::Request, StreamId::new(0));
  c.open_with(&CONNECT_REQUEST[..]).expect("request enqueued");
  assert!(c.is_started() && !c.is_established(), "still Handshaking");
  assert_eq!(
    c.send_data(b"x"),
    Err(Error::Closed),
    "send_data before Open must be Closed"
  );
  assert!(
    c.poll_transmit()
      .is_none_or(|t| !matches!(t.kind(), StreamKind::Existing(_))),
    "no DATA transmit may be enqueued in Handshaking"
  );
}

#[test]
fn establish_is_a_noop_after_close_response_decoded_late() {
  // `establish` (Handshaking → Open) is a no-op outside Handshaking. If the client
  // closes while still handshaking and the peer's response HEADERS are decoded
  // AFTER the close, the late response must NOT (re-)establish the tunnel: no
  // Open, no Established event — the phase stays terminal.
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  let id = StreamId::new(0);
  c.provide_stream(StreamRole::Request, id);
  c.open_with(&CONNECT_REQUEST[..]).expect("request enqueued");
  drain_transmits(&mut c);
  // Close while Handshaking: phase → Closing.
  c.close();
  assert!(c.is_terminal() && !c.is_established());
  // Now the peer's response HEADERS arrive and are fully decoded.
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(id, &frame, &mut sc)
      .expect("a late response still decodes");
    // The response frame is still surfaced (the FSM is direction-agnostic) ...
    while frames.next().expect("frame").is_some() {}
  }
  // ... but the connection did NOT (re-)establish: no Open, and no Established
  // event was enqueued by the late response.
  assert!(
    !c.is_established(),
    "a response decoded after close must not establish the tunnel"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "no Established event from a post-close response"
  );
  assert!(c.is_terminal(), "the phase stays terminal");
}

#[test]
fn fail_supersedes_closing_and_still_signals_once() {
  // `fail` transitions from ANY phase but Failed, so a fatal condition after a
  // graceful close still surfaces the terminal ConnError (Failed supersedes
  // Closing). This is the centralized-transition contract: a teardown that turns
  // out fatal is reported, exactly once.
  let mut c = Connection::<Client>::new();
  let id = StreamId::new(0);
  c.provide_stream(StreamRole::Request, id);
  // Leave the request FSM mid-frame (one byte of a header), then gracefully close.
  let mut sc = std::vec![0u8; 64];
  {
    let mut frames = c.handle_stream(id, &[0x01], &mut sc).expect("partial ok");
    assert!(frames.next().expect("no frames yet").is_none());
  }
  c.close(); // phase → Closing (no event)
  assert!(c.is_terminal());
  assert_eq!(c.poll_event(), None, "a graceful close enqueues no event");
  // A mid-frame request FIN is now fatal: it must move Closing → Failed and
  // enqueue ConnError exactly once.
  c.handle_stream_fin(id);
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameError)),
    "a fatal FIN after a graceful close still surfaces the error (Failed > Closing)"
  );
  // A second fatal FIN does not enqueue a duplicate (Failed is idempotent).
  c.handle_stream_fin(id);
  assert_eq!(c.poll_event(), None, "Failed is idempotent");
}

#[test]
fn reset_moves_to_closing_without_arming_a_fin() {
  // A peer reset enters Closing and signals `Reset`, but must NOT arm a local FIN:
  // the peer already reset the request stream, so emitting our own FIN on it would
  // be spurious. (Distinct from `close()`, which DOES send the local half-close
  // FIN.) Drain transmits first so any spurious FIN would be observable.
  let mut h = Harness::new();
  h.run_until_established();
  let req_id = h.request_id.expect("request id assigned");
  drain_transmits(&mut h.client);
  h.client.handle_stream_reset(req_id, 0x010c);
  assert!(h.client.is_terminal(), "a reset enters Closing");
  assert_eq!(h.client.poll_event(), Some(Event::Reset(0x010c)));
  // No FIN transmit is queued by the reset (close() would have queued one).
  let mut saw_fin = false;
  while let Some(t) = h.client.poll_transmit() {
    saw_fin |= t.fin();
  }
  assert!(!saw_fin, "a peer reset must not arm a local FIN");
}

#[test]
fn start_is_noop_in_open_phase() {
  // `start` is idempotent across the whole post-setup range, not just a second
  // immediate call: once the tunnel is Open, a stray `start` is still a no-op Ok
  // (no duplicate control stream).
  let mut h = Harness::new();
  h.run_until_established();
  assert!(h.client.is_established());
  h.client.start().expect("start while Open is a no-op Ok");
  // No new setup transmit (the ring was drained by run_until_established's pumping).
  let mut setup = 0usize;
  while let Some(t) = h.client.poll_transmit() {
    if matches!(
      t.kind(),
      StreamKind::OpenUni(
        StreamRole::ControlOut | StreamRole::QpackEncOut | StreamRole::QpackDecOut
      )
    ) {
      setup += 1;
    }
  }
  assert_eq!(setup, 0, "start in Open enqueues no duplicate setup");
}

// ── drain-on-drop must validate even in the Closing phase ───────────────────

#[test]
fn drain_on_drop_in_closing_with_forbidden_frame_fails_supersedes_close() {
  // The exploit: open the tunnel, fill the transmit ring so the FIN is deferred,
  // call close() (phase → Closing, close_pending set), then deliver a forbidden
  // request-stream frame (a second HEADERS in Tunnel) and drop the returned Frames
  // WITHOUT pulling from it. The drop-drain validates even while Closing, and the
  // fatal path clears close_pending directly (via fail_into's &mut bool parameter)
  // — the primary invariant, not only the belt-and-suspenders phase guard in
  // try_send_fin — so a failed connection cannot flush a deferred FIN.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Fill the transmit ring so the FIN cannot be enqueued immediately.
  for _ in 0..super::queue::TX_N {
    c.send_data(b"x").expect("ring not yet full");
  }
  assert_eq!(c.send_data(b"x"), Err(Error::WouldBlock), "ring is full");
  // Call close(): phase → Closing, close_pending is armed (FIN deferred).
  c.close();
  assert!(
    c.phase.is_closing(),
    "after close() with a full ring the phase must be Closing"
  );
  assert!(c.close_pending, "the deferred FIN is pending");
  assert!(
    c.is_close_pending(),
    "is_close_pending() accessor confirms the deferred FIN is armed"
  );
  // Deliver a forbidden request-stream frame (a second HEADERS in Tunnel) and drop
  // the Frames WITHOUT pulling — drain-on-drop must still validate.
  let second = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let _frames = c
      .handle_stream(req_id, &second, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Drop `_frames` here without any `next()` call: drain-on-drop runs.
  }
  // The connection must now be Failed (fatal supersedes Closing).
  assert!(
    c.phase.is_failed(),
    "a forbidden frame on drop in Closing must make the connection Failed"
  );
  // The drop-drain fatal path clears close_pending directly via fail_into, so the
  // primary invariant holds — the deferred FIN is cancelled by the fail transition
  // itself, not only by the try_send_fin phase guard.
  assert!(
    !c.is_close_pending(),
    "the drop-drain fatal path must clear close_pending (primary invariant)"
  );
  // Drain poll_transmit: must NOT see any fin:true transmit.
  let mut saw_fin = false;
  let mut polls = 0usize;
  while let Some(t) = c.poll_transmit() {
    saw_fin |= t.fin();
    polls += 1;
    assert!(polls < 200, "poll_transmit did not terminate");
  }
  assert!(
    !saw_fin,
    "a Failed connection must not flush a deferred graceful FIN"
  );
  // Exactly one ConnError(FrameUnexpected) — the second HEADERS — is observable.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::FrameUnexpected)),
    "the trailing forbidden frame surfaces as exactly one terminal ConnError"
  );
  assert_eq!(c.poll_event(), None, "exactly one ConnError is enqueued");
}

#[test]
fn drain_on_drop_in_closing_with_no_forbidden_frame_stays_closing() {
  // A drop in Closing with NO trailing forbidden frame must NOT spuriously fail the
  // connection. The phase stays Closing, close_pending stays
  // armed, and no ConnError is enqueued — a clean (empty) drain is a true no-op.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Fill the transmit ring so the FIN is deferred.
  for _ in 0..super::queue::TX_N {
    c.send_data(b"x").expect("ring not yet full");
  }
  assert_eq!(c.send_data(b"x"), Err(Error::WouldBlock), "ring is full");
  c.close();
  assert!(c.phase.is_closing(), "phase is Closing after close()");
  assert!(c.close_pending, "close_pending is armed");
  // Deliver a clean, fully-consumed DATA frame (no protocol violation) and drop the
  // Frames without any pull — drain-on-drop finds no error in the remaining bytes.
  let mut data_frame = std::vec::Vec::new();
  let mut hdr = [0u8; 16];
  let payload = b"ok";
  let hn = crate::frame::encode_header(
    crate::frame::FrameType::Data,
    payload.len() as u64,
    &mut hdr,
  )
  .expect("DATA frame header encodes");
  data_frame.extend_from_slice(&hdr[..hn]);
  data_frame.extend_from_slice(payload);
  let mut sc = std::vec![0u8; 512];
  {
    let _frames = c
      .handle_stream(req_id, &data_frame, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Drop without pulling: drain-on-drop finds a valid DATA chunk, no error.
  }
  // The connection must still be Closing — not spuriously Failed.
  assert!(
    c.phase.is_closing(),
    "a clean drop in Closing must not spuriously fail the connection"
  );
  assert!(
    c.close_pending,
    "close_pending must remain armed after a clean drop"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "no spurious ConnError from a clean drop in Closing"
  );
}

// ── handshake readiness is granted on OBSERVATION (next()), not the drop ──

#[test]
fn drop_request_frames_unobserved_does_not_grant_request_received_server() {
  // Readiness must be gated on the driver OBSERVING the CONNECT request, not merely
  // on the drop-drain decoding its HEADERS. A server
  // `handle_stream` delivering a VALID CONNECT request HEADERS frame, then dropping
  // `Frames` WITHOUT any `next()`, must NOT set `request_received`: the driver never
  // saw the `Frame::Request`, so it must not be able to `accept_with` a request it
  // never observed/validated. The crate contract requires observing the request
  // before responding. (Contrast `..._after_valid_headers_..._observed_then_dropped`
  // below, which pulls `next()` first and legitimately keeps readiness.)
  let mut s = server_request_registered_no_peer_settings();
  // Deliver the client's control-stream SETTINGS so the peer-SETTINGS gate is
  // satisfied; this isolates the request-OBSERVED gate as the only thing that could
  // block `accept_with` below (so its WouldBlock is specifically the unobserved
  // request, not a missing-SETTINGS WouldBlock).
  let mut sc = [0u8; 128];
  {
    let bytes = peer_control_settings(&[0x08, 0x01]);
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert!(
    !s.request_received(),
    "request_received is false before any HEADERS arrive"
  );
  // A single, well-formed CONNECT request HEADERS frame.
  let bytes = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut rsc = std::vec![0u8; 512];
  {
    let _frames = s
      .handle_stream(StreamId::new(0), &bytes, &mut rsc)
      .expect("handle_stream only builds the iterator");
    // Drop WITHOUT pulling a single frame: the drop-drain decodes + validates the
    // HEADERS (structural) but does NOT grant readiness (the driver never observed
    // the Frame::Request).
  }
  // The HEADERS was decoded by the drop-drain, but it was never OBSERVED, so
  // `request_received` stays false — the driver did not see the CONNECT request.
  assert!(
    !s.request_received(),
    "an unobserved (dropped-before-next) request must NOT set request_received"
  );
  // A valid request is not an error: the connection stays non-terminal, no event.
  assert!(!s.is_terminal(), "a valid request is not a teardown");
  assert_eq!(
    s.poll_event(),
    None,
    "no event from a clean unobserved drop"
  );
  // The core proof: `accept_with` must NOT proceed — the CONNECT was never observed,
  // so it is the retriable WouldBlock (pump/observe and retry), and the tunnel is
  // NOT established.
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::WouldBlock),
    "accept_with must NOT proceed on a request the driver never observed"
  );
  assert!(
    !s.is_established(),
    "the tunnel must not establish on an unobserved request"
  );
  assert!(!s.is_terminal(), "WouldBlock is retriable, not a teardown");
}

#[test]
fn drop_response_frames_unobserved_does_not_establish_client() {
  // A client `handle_stream` delivering a VALID response HEADERS frame, then
  // dropping `Frames` WITHOUT any `next()`, must NOT run the
  // `Handshaking → Open` establish: the driver never observed the `Frame::Response`,
  // so it never validated the response's status and must not become `Established` on
  // it. Readiness fires only on a real `next()` yield. (Contrast
  // `fully_drained_first_headers_path_is_unchanged`, which pulls first.)
  let req_id = StreamId::new(0);
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  drain_transmits(&mut c);
  assert!(!c.is_established(), "not established before the response");
  assert!(c.phase.is_handshaking(), "the client is Handshaking");
  // A single, well-formed response HEADERS frame.
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let _frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Drop WITHOUT pulling: the drop-drain decodes + validates the response HEADERS
    // (structural) but does NOT establish (the driver never observed the response).
  }
  // The HEADERS was decoded by the drop-drain, but it was never OBSERVED, so the
  // client must NOT be established and must stay in Handshaking — no Established.
  assert!(
    !c.is_established(),
    "an unobserved (dropped-before-next) response must NOT establish the tunnel"
  );
  assert!(
    c.phase.is_handshaking(),
    "the client stays Handshaking (not Open) on an unobserved response"
  );
  assert!(!c.is_terminal(), "a valid response is not a teardown");
  assert_eq!(
    c.poll_event(),
    None,
    "no Established (and no spurious event) on the unobserved-drop path"
  );
}

#[test]
fn drop_malformed_first_headers_unobserved_is_still_fatal() {
  // The structural half of the split: the drop-drain must STILL decode + validate
  // the FIRST HEADERS section even though it does not grant
  // readiness. A response HEADERS frame whose field section is malformed in a later
  // field line, dropped WITHOUT any `next()`, must make the connection terminal —
  // the structural decode runs on the drop path and a malformed section is fatal —
  // while of course NOT establishing the tunnel.
  let mut c = Connection::<Client>::new();
  let id = StreamId::new(7);
  c.provide_stream(StreamRole::Request, id);
  // Same malformed section as `malformed_response_headers_does_not_establish_*`:
  // 0xd9 = valid `:status 200`, then 0x80 = a dynamic-table reference this
  // static-only decoder rejects.
  let fs = [0x00u8, 0x00, 0xd9, 0x80];
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(crate::frame::FrameType::Headers, fs.len() as u64, &mut hdr)
    .unwrap();
  let mut frame = std::vec::Vec::new();
  frame.extend_from_slice(&hdr[..hn]);
  frame.extend_from_slice(&fs);
  let mut sc = std::vec![0u8; 512];
  {
    let _frames = c
      .handle_stream(id, &frame, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Drop WITHOUT any next(): the drop-drain's structural decode hits the bad field.
  }
  assert!(
    !c.is_established(),
    "a malformed response must not establish, observed or not"
  );
  assert!(
    c.is_terminal(),
    "the drop-drain must still fail the connection on a malformed first HEADERS"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::QpackDecompressionFailed)),
    "the malformed section surfaces as exactly one terminal ConnError on drop"
  );
  assert_eq!(c.poll_event(), None, "exactly one ConnError");
}

#[test]
fn drop_request_frames_unobserved_then_later_data_is_message_error_server() {
  // Server abandoned-stream path: dropping `Frames` before any `next()` over a VALID
  // first HEADERS frame leaves the inbound FSM in its tunnel phase (decoding the
  // first HEADERS commits that phase, and the drop-drain decodes it), marking the
  // stream `request_abandoned`. Abandonment is INERT — the driver never observes the
  // CONNECT request and so never establishes the tunnel — but it is NOT terminal, so
  // a LATER `handle_stream` is still VALIDATED. A peer that then sends DATA on this
  // never-established stream commits a premature-DATA violation (RFC 9114 §4.4): the
  // abandoned-stream validation path must surface NO `Frame::Data` (the tunnel was
  // never established) AND fail the connection with exactly one
  // `ConnError(MessageError)`. An abandoned stream is not terminal, so it must not
  // bypass the DATA gate.
  let mut s = server_request_registered_no_peer_settings();
  // Deliver the client's control-stream SETTINGS so the peer-SETTINGS gate is
  // satisfied; that isolates the request-OBSERVED gate as the only thing that could
  // block `accept_with` (so its WouldBlock is specifically the unobserved request).
  let mut sc = [0u8; 128];
  {
    let bytes = peer_control_settings(&[0x08, 0x01]);
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  // A valid CONNECT request HEADERS frame, dropped WITHOUT any next(): the drop-drain
  // decodes it (advancing the FSM into Tunnel) but marks the stream abandoned.
  let bytes = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut rsc = std::vec![0u8; 512];
  {
    let _frames = s
      .handle_stream(StreamId::new(0), &bytes, &mut rsc)
      .expect("handle_stream only builds the iterator");
    // Drop without pulling: marks `request_abandoned`.
  }
  assert!(
    !s.request_received(),
    "an unobserved (dropped-before-next) request must NOT set request_received"
  );
  assert!(!s.is_terminal(), "abandonment alone is not a teardown");
  // Now deliver a DATA frame on the SAME request stream in a SEPARATE later read. The
  // abandoned-stream validation path drives the FSM (in Tunnel) and hits the
  // establishment gate: the tunnel was never established, so this premature DATA is
  // `H3_MESSAGE_ERROR`. NO `Frame::Data` surfaces, and the connection becomes terminal.
  let data = request_data_frame(b"smuggled");
  let mut dsc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(StreamId::new(0), &data, &mut dsc)
      .expect("handle_stream on an abandoned request stream surfaces an empty iterator");
    assert!(
      frames
        .next()
        .expect("an abandoned stream surfaces no Frame::Data")
        .is_none(),
      "an abandoned (dropped-unobserved) request stream must surface NO Frame::Data"
    );
  }
  assert!(
    s.is_terminal(),
    "premature DATA on a never-established (abandoned) stream is a §4.4 violation: terminal"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "the abandoned-stream validation path fails premature DATA with H3_MESSAGE_ERROR"
  );
  assert_eq!(s.poll_event(), None, "exactly one terminal ConnError");
  // The connection is now `Failed`, so `accept_with` reports `Closed` (not the prior
  // retriable WouldBlock) and the tunnel never establishes.
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::Closed),
    "accept_with on the now-failed connection is Closed, never establishing"
  );
  assert!(
    !s.is_established(),
    "the tunnel must not establish on an abandoned-then-failed request"
  );
}

// ── tunnel DATA is yielded only once the tunnel is established ────────────────

/// A fresh server in `Handshaking` with the peer's (client's) control-stream
/// SETTINGS decoded and the request stream (id 0) registered, but NOT yet accepted.
/// This is the state in which a peer can coalesce the request HEADERS and a DATA
/// frame before the server has sent its 2xx.
fn server_handshaking_with_peer_settings() -> StaticConnection<Server> {
  let mut s = server_request_registered_no_peer_settings();
  let mut sc = [0u8; 128];
  let bytes = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert!(s.peer_settings().is_some(), "peer SETTINGS decoded");
  assert!(s.phase.is_handshaking(), "the server is Handshaking");
  s
}

#[test]
fn server_coalesced_request_then_data_before_accept_is_message_error() {
  // A peer coalesces the CONNECT request HEADERS and a DATA frame in ONE
  // `handle_stream` read, BEFORE the server has accepted (sent its 2xx). The
  // phase is still `Handshaking` — observing the HEADERS only sets `request_received`,
  // and `accept_with` cannot run while the `Frames` borrow is held — so the tunnel is
  // NOT established. The DATA is therefore premature (RFC 9114 §4.4): `Frames::next`
  // must yield the `Frame::Request` and then FAIL the DATA with `H3_MESSAGE_ERROR`,
  // routing through the centralized fail transition (terminal, one ConnError), so the
  // driver never processes pre-accept tunnel bytes.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  // request HEADERS + DATA coalesced in a single input.
  let mut input = request_headers_frame(&CONNECT_REQUEST[..]);
  input.extend_from_slice(&request_data_frame(b"smuggled"));
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(req_id, &input, &mut sc)
      .expect("handle_stream only builds the iterator");
    // First yield: the CONNECT request HEADERS.
    match frames.next().expect("the request HEADERS yield") {
      Some(Frame::Request(mut hs)) => while hs.next().expect("req header").is_some() {},
      _ => panic!("expected Frame::Request first"),
    }
    // Second yield: the premature DATA is the message error (not a `Frame::Data`).
    assert_eq!(
      frames.next().err(),
      Some(H3Error::MessageError),
      "DATA before the 2xx is H3_MESSAGE_ERROR"
    );
  }
  // The lazy error routed through `fail`: the connection is terminal with exactly one
  // ConnError(MessageError) and no Established.
  assert!(
    s.is_terminal(),
    "premature tunnel DATA makes the connection terminal"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "exactly one terminal ConnError(MessageError)"
  );
  assert_eq!(s.poll_event(), None, "exactly one event");
  // A later accept is now refused outright (terminal), not WouldBlock.
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::Closed),
    "accept_with on a failed connection returns Closed"
  );
}

#[test]
fn server_accept_then_separate_data_yields_frame_data() {
  // The normal path stays green: the request HEADERS arrive in one `handle_stream`
  // (→ `Frame::Request`), the server `accept_with`s (→ `Open`, sets
  // `tunnel_established`), THEN a SEPARATE `handle_stream` delivers a DATA frame — it
  // must yield `Frame::Data` with no error. This is the `client_server_connect_then_tunnel`
  // shape at the connection level.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  // The request HEADERS alone, observed (sets `request_received`).
  deliver_connect_request(&mut s, req_id);
  // Accept: sends the 2xx and establishes the tunnel.
  s.accept_with(&RESPONSE[..]).expect("accept_with succeeds");
  assert!(s.is_established(), "the tunnel is Open after accept_with");
  assert_eq!(s.poll_event(), Some(Event::Established));
  drain_transmits(&mut s);
  // A separate DATA frame now yields the chunk (the tunnel is established).
  let data = request_data_frame(b"payload");
  let mut sc = std::vec![0u8; 512];
  let mut got = Vec::new();
  {
    let mut frames = s
      .handle_stream(req_id, &data, &mut sc)
      .expect("handle_stream after accept");
    while let Some(f) = frames.next().expect("post-accept frame") {
      match f {
        Frame::Data(chunk) => got.extend_from_slice(chunk),
        _ => panic!("expected Frame::Data"),
      }
    }
  }
  assert_eq!(got.as_slice(), b"payload", "post-accept tunnel DATA flows");
  assert!(
    !s.is_terminal(),
    "a normal post-accept DATA is not a teardown"
  );
  assert_eq!(s.poll_event(), None, "no error event on the normal path");
}

#[test]
fn half_close_after_open_still_delivers_peer_data() {
  // The gate must NOT break a half-close: once the tunnel is established
  // (`tunnel_established` true), a local `close()` moves the phase to `Closing` but
  // leaves `tunnel_established` true — so subsequent inbound DATA in this post-`Open`
  // half-close STILL yields `Frame::Data`. (Gating on `is_open()` would wrongly drop
  // it; gating on `tunnel_established` is correct.)
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  assert!(c.is_established(), "the client tunnel is Open");
  c.close();
  assert!(c.phase.is_closing(), "close() moved the phase to Closing");
  // Inbound DATA during the half-close still surfaces as Frame::Data.
  let data = request_data_frame(b"after-close");
  let mut sc = std::vec![0u8; 512];
  let mut got = Vec::new();
  {
    let mut frames = c
      .handle_stream(req_id, &data, &mut sc)
      .expect("handle_stream during half-close");
    while let Some(f) = frames.next().expect("half-close frame") {
      match f {
        Frame::Data(chunk) => got.extend_from_slice(chunk),
        _ => panic!("expected Frame::Data"),
      }
    }
  }
  assert_eq!(
    got.as_slice(),
    b"after-close",
    "a post-Open half-close still delivers peer DATA"
  );
  assert!(
    !c.phase.is_failed(),
    "delivering DATA during a half-close must not fail the connection"
  );
}

#[test]
fn client_establish_then_data_yields_frame_data() {
  // Client positive control: the genuinely-premature client case is UNCONSTRUCTABLE
  // — the client's stream FSM requires HEADERS before DATA, so DATA
  // can never precede the response on a live stream, and observing the response
  // HEADERS runs `establish` (sets `tunnel_established`) BEFORE any same-drain DATA.
  // The only way to reach Tunnel without establishing is to drop the response
  // `Frames` unobserved, which sets `request_abandoned`: the stream surfaces no
  // `Frame::Data`, but later premature DATA is still validated and fails the connection
  // (covered by `drop_response_frames_unobserved_then_later_data_is_message_error_client`).
  // So this test instead asserts the gate does NOT misfire on the client: once the client
  // establishes on the response, `tunnel_established` is true and a subsequent DATA
  // frame still yields `Frame::Data` (no spurious MessageError).
  let req_id = StreamId::new(0);
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  drain_transmits(&mut c);
  // A valid response HEADERS, observed via next() so the FSM reaches Tunnel AND the
  // tunnel establishes.
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("response HEADERS decode");
    match frames.next().expect("response frame") {
      Some(Frame::Response { mut headers, .. }) => {
        while headers.next().expect("resp header").is_some() {}
      }
      _ => panic!("expected Frame::Response"),
    }
  }
  assert!(c.is_established(), "the client established on the response");
  drain_transmits(&mut c);
  // Establishment set `tunnel_established`, so subsequent DATA flows (no MessageError).
  let data = request_data_frame(b"client-data");
  let mut dsc = std::vec![0u8; 512];
  let mut got = Vec::new();
  {
    let mut frames = c
      .handle_stream(req_id, &data, &mut dsc)
      .expect("handle_stream after establish");
    while let Some(f) = frames.next().expect("post-establish frame") {
      match f {
        Frame::Data(chunk) => got.extend_from_slice(chunk),
        _ => panic!("expected Frame::Data"),
      }
    }
  }
  assert_eq!(got.as_slice(), b"client-data");
}

#[test]
fn drop_response_frames_unobserved_then_later_data_is_message_error_client() {
  // Client analog: dropping `Frames` before any `next()` over a VALID response
  // HEADERS frame leaves the FSM in Tunnel without establishing (readiness needs the
  // `next()` yield), marking the stream `request_abandoned`. The client never
  // observed the response, so it never establishes — but abandonment is NOT terminal,
  // so a later DATA read is still VALIDATED. That DATA
  // on a never-established tunnel is premature (RFC 9114 §4.4): NO `Frame::Data` surfaces
  // AND the connection fails with exactly one `ConnError(MessageError)`. The client must
  // not become `Established`.
  let req_id = StreamId::new(0);
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  drain_transmits(&mut c);
  assert!(c.phase.is_handshaking(), "the client is Handshaking");
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let _frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Drop without pulling: marks `request_abandoned`, FSM advanced to Tunnel.
  }
  assert!(
    !c.is_established(),
    "an unobserved response must NOT establish the tunnel"
  );
  assert!(c.phase.is_handshaking(), "the client stays Handshaking");
  // Deliver a DATA frame on the same request stream in a SEPARATE later read: the
  // abandoned-stream validation path drives the FSM (in Tunnel) and hits the
  // establishment gate. The tunnel was never established → premature → H3_MESSAGE_ERROR.
  let data = request_data_frame(b"smuggled");
  let mut dsc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &data, &mut dsc)
      .expect("handle_stream on an abandoned request stream surfaces an empty iterator");
    assert!(
      frames
        .next()
        .expect("an abandoned stream surfaces no Frame::Data")
        .is_none(),
      "an abandoned (dropped-unobserved) response stream must surface NO Frame::Data"
    );
  }
  assert!(
    !c.is_established(),
    "premature DATA on an inert stream must not establish the tunnel"
  );
  assert!(
    c.is_terminal(),
    "premature DATA on a never-established (abandoned) stream is a §4.4 violation: terminal"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "the abandoned-stream validation path fails premature DATA with H3_MESSAGE_ERROR"
  );
  assert_eq!(c.poll_event(), None, "exactly one terminal ConnError");
}

#[test]
fn drop_request_frames_unobserved_then_clean_fin_no_peer_closed_server() {
  // A clean FIN after an UNOBSERVED first HEADERS. Dropping `Frames` before any
  // `next()` over a valid CONNECT request HEADERS leaves the FSM
  // in Tunnel, so `RequestStream::fin()` returns `Ok(())` (clean half-close) and
  // `handle_stream_fin` would enqueue `Event::PeerClosed`. But the tunnel was never
  // observed/established, so the `request_abandoned` guard must make the FIN a no-op:
  // NO `PeerClosed`, and readiness never granted.
  let mut s = server_request_registered_no_peer_settings();
  let mut sc = [0u8; 128];
  {
    let bytes = peer_control_settings(&[0x08, 0x01]);
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  let bytes = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut rsc = std::vec![0u8; 512];
  {
    let _frames = s
      .handle_stream(StreamId::new(0), &bytes, &mut rsc)
      .expect("handle_stream only builds the iterator");
    // Drop without pulling: marks `request_abandoned`.
  }
  // A clean FIN at a frame boundary: the FSM (in Tunnel) would otherwise make this a
  // PeerClosed half-close, but the `request_abandoned` guard makes it a no-op.
  s.handle_stream_fin(StreamId::new(0));
  assert!(
    !s.is_terminal(),
    "a clean FIN on an inert stream is not a teardown"
  );
  assert_eq!(
    s.poll_event(),
    None,
    "an abandoned (dropped-unobserved) request stream must surface NO PeerClosed on FIN"
  );
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::WouldBlock),
    "readiness must never be granted on an abandoned request stream"
  );
  assert!(
    !s.is_established(),
    "the tunnel must not establish on an abandoned request"
  );
}

#[test]
fn drop_response_frames_unobserved_then_clean_fin_no_peer_closed_client() {
  // The client analog of the clean-FIN case. Dropping `Frames` before any `next()`
  // over a valid response HEADERS leaves the FSM in
  // Tunnel; a clean FIN must NOT surface `PeerClosed` (the tunnel was never
  // observed/established) and the client must not be `Established`.
  let req_id = StreamId::new(0);
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  drain_transmits(&mut c);
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let _frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Drop without pulling: marks `request_abandoned`.
  }
  c.handle_stream_fin(req_id);
  assert!(
    !c.is_established(),
    "a clean FIN on an inert stream must not establish the tunnel"
  );
  assert!(
    c.phase.is_handshaking(),
    "still Handshaking after the inert FIN"
  );
  assert!(
    !c.is_terminal(),
    "a clean FIN on an inert stream is not a teardown"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "an abandoned (dropped-unobserved) response stream must surface NO PeerClosed on FIN"
  );
}

#[test]
fn observe_request_frame_then_drop_grants_request_received_server() {
  // Server positive twin: when the driver DOES pull `next()` to observe the first
  // `Frame::Request` and only THEN drops the iterator (no trailing forbidden frame),
  // readiness legitimately fires from `next()` — `request_received` is set and
  // `accept_with` proceeds. This is the observed-then-dropped path that MUST keep
  // working, the mirror image of the unobserved-drop case above.
  let mut s = server_request_registered_no_peer_settings();
  let mut sc = [0u8; 128];
  {
    let bytes = peer_control_settings(&[0x08, 0x01]);
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  let bytes = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut rsc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(StreamId::new(0), &bytes, &mut rsc)
      .expect("handle_stream only builds the iterator");
    // OBSERVE the first frame (the CONNECT request) via next(), then drop the rest.
    let first = frames
      .next()
      .expect("first frame ok")
      .expect("a first frame");
    assert!(
      matches!(first, Frame::Request(_)),
      "the first yielded frame is the CONNECT request HEADERS"
    );
    // `frames` drops here AFTER observation — readiness already fired in next().
  }
  assert!(
    s.request_received(),
    "observing the Frame::Request via next() must set request_received"
  );
  assert!(
    !s.is_terminal(),
    "a valid observed request is not a teardown"
  );
  s.accept_with(&RESPONSE[..])
    .expect("accept_with must proceed once the request was observed");
  assert!(
    s.is_established(),
    "the tunnel establishes after observation"
  );
}

#[test]
fn observe_response_frame_then_drop_establishes_client() {
  // Client positive twin: when the driver pulls `next()` to observe the first
  // `Frame::Response` and only THEN drops (no trailing forbidden frame), the
  // `Handshaking → Open` establish legitimately fires from `next()`. The
  // observed-then-dropped path keeps establishing, mirroring the unobserved-drop
  // case above.
  let req_id = StreamId::new(0);
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  drain_transmits(&mut c);
  assert!(c.phase.is_handshaking(), "the client is Handshaking");
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("handle_stream only builds the iterator");
    // OBSERVE the response via next(), then drop — establish fires in next().
    let first = frames
      .next()
      .expect("first frame ok")
      .expect("a first frame");
    assert!(
      matches!(first, Frame::Response { .. }),
      "the first yielded frame is the response HEADERS"
    );
    // `frames` drops here AFTER observation — the tunnel is already established.
  }
  assert!(
    c.is_established(),
    "observing the Frame::Response via next() must establish the tunnel"
  );
  assert!(
    !c.is_terminal(),
    "a valid observed response is not a teardown"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::Established),
    "establish enqueues exactly one Established on the observed-then-dropped path"
  );
  assert_eq!(c.poll_event(), None, "no duplicate or spurious event");
}

// ── premature DATA is fatal on EVERY path and for EVERY DATA frame ────────────
//
// Every DATA-frame occurrence — empty or not, on the yield path (`Frames::next`) OR
// the drop path (`drain_for_errors`) — passes the establishment gate: the drop-drain
// fails a coalesced premature DATA item rather than discarding it, and a zero-length
// DATA frame is yielded as one empty occurrence so it reaches the gate too. Premature
// DATA is `H3_MESSAGE_ERROR`, terminal.

#[test]
fn server_coalesced_request_then_data_observed_then_dropped_is_message_error() {
  // Drop-drain path: a peer coalesces the CONNECT request HEADERS and a DATA frame in
  // ONE `handle_stream` read before `accept_with`. The driver pulls ONLY the
  // `Frame::Request` and DROPS the iterator. The drop-drain must apply the SAME gate
  // as the yield path: were the premature DATA discarded (`request_received` already
  // set), a later `accept_with` would establish a tunnel that already smuggled
  // pre-accept bytes. Instead the premature DATA fails the connection with
  // `H3_MESSAGE_ERROR`, terminal, and the later `accept_with` reports `Closed`.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  let mut input = request_headers_frame(&CONNECT_REQUEST[..]);
  input.extend_from_slice(&request_data_frame(b"smuggled"));
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(req_id, &input, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Observe ONLY the request HEADERS, then drop (leaving the premature DATA for the
    // drop-drain to detect).
    match frames.next().expect("the request HEADERS yield") {
      Some(Frame::Request(mut hs)) => while hs.next().expect("req header").is_some() {},
      _ => panic!("expected Frame::Request first"),
    }
    // `frames` drops here WITHOUT pulling the DATA: the drop-drain must fail it.
  }
  assert!(
    s.is_terminal(),
    "premature DATA left on the drop path must still make the connection terminal"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "the drop-drain routes premature DATA through fail(MessageError)"
  );
  assert_eq!(s.poll_event(), None, "exactly one terminal event");
  assert_eq!(
    s.accept_with(&RESPONSE[..]),
    Err(Error::Closed),
    "a later accept_with on the failed connection is Closed, never establishing a corrupted tunnel"
  );
}

#[test]
fn server_coalesced_request_then_data_unobserved_drop_is_message_error() {
  // Unobserved drop: the same coalesced HEADERS+DATA, but the driver drops the
  // iterator WITHOUT any next(). The drop-drain decodes the first HEADERS
  // UNOBSERVED (marking `request_abandoned`), then hits the premature DATA item — a
  // real RFC 9114 §4.4 violation by the peer that SUPERSEDES mere abandonment (exactly
  // as a trailing forbidden frame already fails an abandoned-stream drain). So the
  // connection fails with `H3_MESSAGE_ERROR` rather than going quietly inert.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  let mut input = request_headers_frame(&CONNECT_REQUEST[..]);
  input.extend_from_slice(&request_data_frame(b"smuggled"));
  let mut sc = std::vec![0u8; 512];
  {
    let _frames = s
      .handle_stream(req_id, &input, &mut sc)
      .expect("handle_stream only builds the iterator");
    // Drop WITHOUT any next(): unobserved first HEADERS, then premature DATA.
  }
  assert!(
    s.is_terminal(),
    "a peer §4.4 violation (premature DATA) supersedes abandonment and fails the connection"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "premature DATA on the unobserved-drop path is H3_MESSAGE_ERROR"
  );
  assert_eq!(s.poll_event(), None, "exactly one terminal event");
}

#[test]
fn server_zero_length_data_before_accept_is_message_error() {
  // Zero-length DATA: the FSM yields a length-0 DATA frame as one empty occurrence, so
  // it reaches the gate rather than being silently skipped. An EMPTY premature DATA
  // frame before `accept_with` is `H3_MESSAGE_ERROR` just like a non-empty one (it
  // must not yield Ok(None)). Driven via `Frames::next`.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  // request HEADERS + a length-0 DATA frame coalesced.
  let mut input = request_headers_frame(&CONNECT_REQUEST[..]);
  input.extend_from_slice(&request_data_frame(b""));
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(req_id, &input, &mut sc)
      .expect("handle_stream only builds the iterator");
    match frames.next().expect("the request HEADERS yield") {
      Some(Frame::Request(mut hs)) => while hs.next().expect("req header").is_some() {},
      _ => panic!("expected Frame::Request first"),
    }
    // The empty DATA before the 2xx is the message error (not Ok(None)).
    assert_eq!(
      frames.next().err(),
      Some(H3Error::MessageError),
      "a zero-length DATA before the 2xx is H3_MESSAGE_ERROR"
    );
  }
  assert!(
    s.is_terminal(),
    "premature empty DATA makes the connection terminal"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "exactly one terminal ConnError(MessageError)"
  );
  assert_eq!(s.poll_event(), None, "exactly one event");
}

#[test]
fn server_zero_length_data_before_accept_drop_drain_is_message_error() {
  // Drop-drain variant: the same coalesced request HEADERS + length-0 DATA, but the
  // driver pulls only `Frame::Request` and drops. The empty DATA must hit the gate on
  // the DROP path too and fail the connection.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  let mut input = request_headers_frame(&CONNECT_REQUEST[..]);
  input.extend_from_slice(&request_data_frame(b""));
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(req_id, &input, &mut sc)
      .expect("handle_stream only builds the iterator");
    match frames.next().expect("the request HEADERS yield") {
      Some(Frame::Request(mut hs)) => while hs.next().expect("req header").is_some() {},
      _ => panic!("expected Frame::Request first"),
    }
    // Drop with the empty DATA unconsumed: the drop-drain must fail it.
  }
  assert!(
    s.is_terminal(),
    "a zero-length premature DATA on the drop path is fatal too"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "the drop-drain routes the empty premature DATA through fail(MessageError)"
  );
  assert_eq!(s.poll_event(), None, "exactly one terminal event");
}

#[test]
fn server_zero_length_data_when_established_surfaces_no_frame_data() {
  // The established case must NOT misfire: once the tunnel is `Open`
  // (`tunnel_established`), a length-0 DATA frame is a legal (if empty) occurrence. It
  // passes the gate, but `Frames::next` must NOT surface an empty `Frame::Data` (the
  // driver is never handed empty chunks) — it skips it and returns Ok(None), with no
  // error and no teardown.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  deliver_connect_request(&mut s, req_id);
  s.accept_with(&RESPONSE[..]).expect("accept_with succeeds");
  assert!(s.is_established(), "the tunnel is Open after accept_with");
  assert_eq!(s.poll_event(), Some(Event::Established));
  drain_transmits(&mut s);
  // A length-0 DATA frame on the established tunnel: consumed, not surfaced.
  let data = request_data_frame(b"");
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(req_id, &data, &mut sc)
      .expect("handle_stream after accept");
    assert!(
      frames
        .next()
        .expect("no error on an established empty DATA")
        .is_none(),
      "an established zero-length DATA must NOT surface an empty Frame::Data"
    );
  }
  assert!(
    !s.is_terminal(),
    "an established empty DATA frame is not a teardown"
  );
  assert_eq!(
    s.poll_event(),
    None,
    "no event from a consumed empty DATA frame"
  );
}

#[test]
fn server_established_empty_then_nonempty_data_yields_only_nonempty() {
  // Interleaving control: a length-0 DATA frame FOLLOWED by a non-empty DATA frame,
  // coalesced in one read on an established tunnel. `Frames::next` skips the
  // empty occurrence and yields exactly the non-empty chunk — proving the skip loop
  // advances correctly past an empty frame to the next real one.
  let req_id = StreamId::new(0);
  let mut s = server_handshaking_with_peer_settings();
  deliver_connect_request(&mut s, req_id);
  s.accept_with(&RESPONSE[..]).expect("accept_with succeeds");
  assert_eq!(s.poll_event(), Some(Event::Established));
  drain_transmits(&mut s);
  let mut data = request_data_frame(b"");
  data.extend_from_slice(&request_data_frame(b"payload"));
  let mut sc = std::vec![0u8; 512];
  let mut got = Vec::new();
  {
    let mut frames = s
      .handle_stream(req_id, &data, &mut sc)
      .expect("handle_stream after accept");
    while let Some(f) = frames.next().expect("post-accept frame") {
      match f {
        Frame::Data(chunk) => got.extend_from_slice(chunk),
        _ => panic!("expected only Frame::Data"),
      }
    }
  }
  assert_eq!(
    got.as_slice(),
    b"payload",
    "the empty DATA is skipped; only the non-empty chunk surfaces"
  );
  assert!(
    !s.is_terminal(),
    "normal established DATA is not a teardown"
  );
  assert_eq!(
    s.poll_event(),
    None,
    "no error on the established interleaved path"
  );
}

// ── an abandoned (dropped-unobserved) request stream is validation-only ───────
//
// An abandoned request stream is NOT terminal — only a `Failed` connection bypasses the
// FSM/gate entirely. So the `request_abandoned` short-circuit must NOT blindly ignore
// later bytes/FINs: a peer can send a valid HEADERS (driver drops it unobserved →
// abandoned), then send DATA in a LATER read before `accept_with`, and that premature
// DATA must still reach the gate and fail the connection. An abandoned stream's later
// input runs through the same validation path (the DATA gate + FSM error checks),
// surfacing nothing but failing on the peer's protocol violations.
// (The two-read DATA cases are covered by
// `drop_request_frames_unobserved_then_later_data_is_message_error_{server,client}`.)

#[test]
fn abandoned_request_then_separate_data_before_accept_is_message_error_server() {
  // The server drops an otherwise-VALID request HEADERS iterator UNOBSERVED, then
  // receives a SEPARATE DATA frame on the same request
  // stream in a later `handle_stream`, all BEFORE `accept_with`. The abandoned stream is
  // not terminal, so this premature DATA must still hit the establishment gate (the
  // tunnel was never established) and fail the connection with `H3_MESSAGE_ERROR`. This
  // isolates the abandoned-then-separate-read path WITHOUT first delivering peer SETTINGS
  // (the §4.4 violation is independent of the peer-SETTINGS gate).
  let req_id = StreamId::new(0);
  let mut s = server_request_registered_no_peer_settings();
  // A valid CONNECT request HEADERS, dropped without any next(): abandoned, FSM → Tunnel.
  let headers = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut hsc = std::vec![0u8; 512];
  {
    let _frames = s
      .handle_stream(req_id, &headers, &mut hsc)
      .expect("handle_stream only builds the iterator");
    // Drop unobserved: marks `request_abandoned`.
  }
  assert!(!s.is_terminal(), "abandonment alone is not a teardown");
  assert!(
    !s.request_received(),
    "the unobserved request never granted readiness"
  );
  // A SEPARATE later read carrying a DATA frame: premature (tunnel never established).
  let data = request_data_frame(b"smuggled");
  let mut dsc = std::vec![0u8; 512];
  {
    let mut frames = s
      .handle_stream(req_id, &data, &mut dsc)
      .expect("the abandoned-stream validation path surfaces an empty iterator");
    assert!(
      frames
        .next()
        .expect("no Frame::Data from an abandoned stream")
        .is_none(),
      "an abandoned request stream surfaces NO Frame::Data"
    );
  }
  assert!(
    s.is_terminal(),
    "premature DATA in a separate read on an abandoned stream fails the connection"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::MessageError)),
    "the abandoned-stream DATA gate fires H3_MESSAGE_ERROR"
  );
  assert_eq!(s.poll_event(), None, "exactly one terminal ConnError");
}

#[test]
fn abandoned_request_then_midframe_fin_is_frame_error_server() {
  // FIN-consistency: a FIN on an abandoned request stream must also be VALIDATED, not
  // blindly ignored. The peer first sends a valid HEADERS frame (dropped unobserved →
  // abandoned, FSM in Tunnel), then sends ONE byte of a frame header (leaving the FSM
  // mid-frame), then FINs. A mid-frame FIN is a real framing violation (RFC 9114 §7.1),
  // so it must fail the connection with `H3_FRAME_ERROR` — even on an abandoned stream.
  // (A CLEAN FIN on an abandoned stream stays inert / non-terminal — that is the
  // `drop_request_frames_unobserved_then_clean_fin_no_peer_closed_server` invariant.)
  let req_id = StreamId::new(0);
  let mut s = server_request_registered_no_peer_settings();
  // A valid CONNECT request HEADERS, dropped unobserved: abandoned, FSM → Tunnel.
  let headers = request_headers_frame(&CONNECT_REQUEST[..]);
  let mut hsc = std::vec![0u8; 512];
  {
    let _frames = s
      .handle_stream(req_id, &headers, &mut hsc)
      .expect("handle_stream only builds the iterator");
  }
  assert!(!s.is_terminal(), "abandonment alone is not a teardown");
  // Feed one byte of a DATA frame header, leaving the (abandoned) FSM mid-frame. The
  // abandoned-stream validation path drives the FSM but surfaces nothing; one partial
  // header byte completes no item and is not itself an error.
  let mut psc = std::vec![0u8; 64];
  {
    let mut frames = s
      .handle_stream(req_id, &[0x01], &mut psc)
      .expect("a partial header on an abandoned stream is not an error");
    assert!(
      frames
        .next()
        .expect("no item from a partial header")
        .is_none(),
      "a partial header surfaces nothing"
    );
  }
  assert!(
    !s.is_terminal(),
    "a partial header alone is not yet a violation"
  );
  // Now FIN mid-frame: the abandoned-stream FIN path validates `RequestStream::fin()`,
  // which reports the mid-frame truncation as a frame error and fails the connection.
  s.handle_stream_fin(req_id);
  assert!(
    s.is_terminal(),
    "a mid-frame FIN on an abandoned stream is a framing violation: terminal"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::ConnError(H3Error::FrameError)),
    "a mid-frame FIN on an abandoned stream is H3_FRAME_ERROR (validated, not ignored)"
  );
  assert_eq!(s.poll_event(), None, "exactly one terminal ConnError");
}

#[test]
fn fully_drained_first_headers_path_is_unchanged() {
  // Positive control: the shared `on_headers_decoded` must leave the normal
  // FULLY-DRAINED path identical — the client still establishes exactly once when
  // it pulls the response, and the drop afterwards (carriers already spent) is a
  // no-op. This guards against the shared helper double-firing or shifting the
  // establish off the pulled path.
  let req_id = StreamId::new(0);
  let mut c = client_after_peer_settings(&[0x08, 0x01]);
  c.open_with(&CONNECT_REQUEST[..]).expect("open_with");
  c.provide_stream(StreamRole::Request, req_id);
  drain_transmits(&mut c);
  let frame = request_headers_frame(&RESPONSE[..]);
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &frame, &mut sc)
      .expect("response HEADERS decode");
    let mut saw = false;
    while let Some(f) = frames.next().expect("response frame") {
      if let Frame::Response { mut headers, .. } = f {
        saw = true;
        while headers.next().expect("resp header").is_some() {}
      }
    }
    assert!(
      saw,
      "the client yields the response HEADERS on the drained path"
    );
    // Pulling the response already established; the drop here is a no-op.
  }
  assert!(
    c.is_established(),
    "the drained path establishes the tunnel"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::Established),
    "exactly one Established on the drained path"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "the post-drain drop must not re-fire establish"
  );
}

// ── the terminal ConnError is non-droppable (survives a full queue) ────

/// Saturates a connection's bounded event queue (capacity 8) by pushing benign
/// `PeerClosed` events directly, so a subsequent fatal path cannot enqueue its
/// `ConnError` into the queue — proving the terminal error survives via the
/// dedicated `conn_error` slot. Returns the number pushed (the full capacity).
fn saturate_event_queue<Ro: Role>(c: &mut StaticConnection<Ro>) -> usize {
  let mut n = 0usize;
  // `push` returns Err(item) once full; stop there.
  while c.events.push(Event::PeerClosed).is_ok() {
    n += 1;
    assert!(
      n <= 64,
      "the bounded queue must fill in well under 64 pushes"
    );
  }
  assert_eq!(
    c.events.push(Event::PeerClosed),
    Err(Event::PeerClosed),
    "the queue is now saturated: a further push fails"
  );
  n
}

/// Drains `poll_event`, returning the count of terminal `ConnError`s seen and the
/// first such error. Asserts exactly one `ConnError` is delivered (the terminal
/// code), regardless of how many benign events preceded it in the queue.
fn drain_until_single_conn_error<Ro: Role>(c: &mut StaticConnection<Ro>) -> H3Error {
  let mut conn_errors = std::vec::Vec::new();
  while let Some(ev) = c.poll_event() {
    if let Event::ConnError(e) = ev {
      conn_errors.push(e);
    }
  }
  assert_eq!(
    conn_errors.len(),
    1,
    "exactly one terminal ConnError must be delivered despite the full queue"
  );
  conn_errors[0]
}

#[test]
fn terminal_conn_error_survives_saturated_queue_on_duplicate_provide_stream() {
  // `provide_stream`'s duplicate-CRITICAL-role path is a NO-RETURN-VALUE fatal path
  // — without the dedicated `conn_error` slot, a saturated event queue would swallow
  // its terminal ConnError and leave the connection Failed with NO observable error.
  // With the slot, the terminal code is delivered exactly once. (A duplicate REQUEST
  // id is no longer fatal in the multi-stream core, so a critical role is the
  // duplicate-stream trigger.)
  let mut c = Connection::<Client>::new();
  c.provide_stream(StreamRole::ControlOut, StreamId::new(0));
  assert!(!c.is_terminal(), "healthy after the first binding");
  // Saturate the event queue so a queue-only push would be lost.
  saturate_event_queue(&mut c);
  // Trigger the no-return fatal path: a different id for the already-bound critical role.
  c.provide_stream(StreamRole::ControlOut, StreamId::new(2));
  assert!(
    c.is_terminal(),
    "the duplicate critical stream makes the connection Failed even with a full queue"
  );
  // The terminal ConnError is delivered exactly once (after the benign events).
  assert_eq!(
    drain_until_single_conn_error(&mut c),
    H3Error::StreamCreation,
    "the saturated queue must not swallow the duplicate-stream terminal error"
  );
  // After it is delivered, the connection is terminal with an empty queue.
  assert_eq!(c.poll_event(), None, "the terminal error is delivered once");
  // A second fatal condition does not re-deliver or overwrite the terminal error.
  c.provide_stream(StreamRole::ControlOut, StreamId::new(6));
  assert_eq!(
    c.poll_event(),
    None,
    "a second fatal condition must not re-deliver a terminal ConnError"
  );
}

#[test]
fn terminal_conn_error_survives_saturated_queue_on_critical_stream_fin() {
  // `handle_stream_fin` on a critical stream is the other NO-RETURN fatal path. With
  // the event queue saturated, the ClosedCriticalStream terminal error must still
  // surface (via the dedicated slot), exactly once.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // Register the peer's inbound control stream (uni type 0x00) on id 10.
  {
    let _ = c
      .handle_stream(StreamId::new(10), &[0x00], &mut sc)
      .expect("control stream type byte ok");
  }
  assert!(
    !c.is_terminal(),
    "healthy after registering the control stream"
  );
  // Saturate the event queue.
  saturate_event_queue(&mut c);
  // FIN the critical (control) stream: a no-return fatal path.
  c.handle_stream_fin(StreamId::new(10));
  assert!(
    c.is_terminal(),
    "closing a critical stream is terminal even with a full queue"
  );
  assert_eq!(
    drain_until_single_conn_error(&mut c),
    H3Error::ClosedCriticalStream,
    "the saturated queue must not swallow the closed-critical-stream terminal error"
  );
  assert_eq!(c.poll_event(), None, "the terminal error is delivered once");
  // A second critical-stream FIN must not re-deliver the terminal error.
  c.handle_stream_fin(StreamId::new(10));
  assert_eq!(
    c.poll_event(),
    None,
    "a repeated critical-stream FIN must not re-deliver a ConnError"
  );
}

#[test]
fn terminal_conn_error_supersedes_queued_events() {
  // Once the connection fails it is terminal-priority. Benign lifecycle events
  // already in the queue when the
  // failure occurs are DISCARDED by the fail transition (`events.clear()`), and
  // `poll_event` yields EXACTLY the terminal ConnError (from the dedicated slot),
  // then None — no stale queued PeerClosed ahead of it.
  let mut c = Connection::<Client>::new();
  c.provide_stream(StreamRole::ControlOut, StreamId::new(0));
  // A couple of benign events (not a saturating flood) precede the failure.
  assert!(c.events.push(Event::PeerClosed).is_ok());
  assert!(c.events.push(Event::PeerClosed).is_ok());
  // No-return fatal path (a duplicate critical stream) with room still in the queue.
  c.provide_stream(StreamRole::ControlOut, StreamId::new(2));
  assert!(c.is_terminal());
  // The terminal ConnError supersedes the stale queued events: it is delivered
  // first and alone, with the previously-queued PeerClosed events suppressed.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::StreamCreation)),
    "the terminal error supersedes the stale queued events"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "the stale queued PeerClosed events were discarded by the fail"
  );
}

// ── the `Failed` terminal state is enforced on the inbound paths ─────────────

/// A request-stream DATA frame (`[DATA header][payload]`), ready to feed via
/// `handle_stream` once the request FSM is in Tunnel.
fn request_data_frame(payload: &[u8]) -> Vec<u8> {
  let mut hdr = [0u8; 16];
  let hn = crate::frame::encode_header(
    crate::frame::FrameType::Data,
    payload.len() as u64,
    &mut hdr,
  )
  .expect("DATA frame header encodes");
  let mut v = Vec::new();
  v.extend_from_slice(&hdr[..hn]);
  v.extend_from_slice(payload);
  v
}

#[test]
fn handle_stream_after_fail_yields_no_data_and_stays_failed() {
  // A `Failed` connection must not PROCESS or YIELD inbound request-stream data. The
  // exploit: establish the tunnel (request FSM in Tunnel, so a
  // DATA frame would normally yield `Frame::Data`), then fail the connection via a
  // NO-RETURN fatal path — a critical (inbound control) stream FIN. The request FSM
  // is untouched (still Tunnel), so without the guard a later DATA frame would be
  // decoded and `Frame::Data` yielded AFTER the connection-fatal error and BEFORE
  // the terminal ConnError is polled. With the guard, `handle_stream` returns an
  // empty iterator: no frame, no processing.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Sanity: while Open, a DATA frame on the request stream yields the chunk.
  {
    let data = request_data_frame(b"pre");
    let mut sc = std::vec![0u8; 512];
    let mut frames = c
      .handle_stream(req_id, &data, &mut sc)
      .expect("handle_stream while Open");
    let mut saw = Vec::new();
    while let Some(f) = frames.next().expect("frame") {
      if let Frame::Data(chunk) = f {
        saw.extend_from_slice(chunk);
      }
    }
    assert_eq!(saw.as_slice(), b"pre", "DATA flows while Open");
  }
  // Fail via a no-return fatal path: FIN the peer's inbound control stream (id 3,
  // registered when `client_after_peer_settings` fed the SETTINGS).
  c.handle_stream_fin(StreamId::new(3));
  assert!(c.phase.is_failed(), "a critical-stream FIN makes it Failed");
  // Now a request-stream DATA frame must NOT be processed or yielded.
  {
    let data = request_data_frame(b"post");
    let mut sc = std::vec![0u8; 512];
    let mut frames = c
      .handle_stream(req_id, &data, &mut sc)
      .expect("handle_stream on a Failed connection is an empty no-op iterator");
    assert!(
      frames
        .next()
        .expect("no frames on a Failed connection")
        .is_none(),
      "a Failed connection must not yield any Frame::Data"
    );
  }
  // The connection is still Failed, and the terminal ConnError is what surfaces.
  assert!(c.phase.is_failed(), "the connection stays Failed");
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "the terminal ConnError is the event delivered (no application data ahead of it)"
  );
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

#[test]
fn handle_stream_after_fail_via_duplicate_critical_yields_no_data() {
  // Another no-return path: fail via a duplicate critical stream (a SECOND inbound
  // control stream) and confirm a subsequent request-stream DATA frame is likewise
  // ignored — empty iterator. (A duplicate REQUEST id is no longer fatal in the
  // multi-stream core, so a critical stream is the duplicate-stream trigger.)
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // No-return fatal path: a second inbound control stream (id 3 already classified).
  let mut tc = [0u8; 32];
  {
    let _ = c.handle_stream(StreamId::new(11), &[0x00], &mut tc);
  }
  assert!(c.phase.is_failed(), "a duplicate critical stream fails it");
  let data = request_data_frame(b"post");
  let mut sc = std::vec![0u8; 512];
  {
    let mut frames = c
      .handle_stream(req_id, &data, &mut sc)
      .expect("Failed handle_stream is an empty no-op");
    assert!(
      frames.next().expect("no frames").is_none(),
      "no Frame::Data after a fatal duplicate critical stream"
    );
  }
  assert!(c.phase.is_failed());
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::StreamCreation)),
    "the terminal ConnError is still the delivered event"
  );
  assert_eq!(c.poll_event(), None);
}

#[test]
fn handle_stream_after_fail_ignores_control_stream_bytes() {
  // The Failed guard covers EVERY stream type, not just the request stream. After a
  // fatal error, even further control-stream bytes are ignored (no processing, no
  // second error) — the connection is terminal.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // Register the peer's inbound control stream on id 10, then fail via its FIN.
  {
    let _ = c
      .handle_stream(StreamId::new(10), &[0x00], &mut sc)
      .expect("control type byte ok");
  }
  c.handle_stream_fin(StreamId::new(10));
  assert!(c.phase.is_failed(), "the critical-stream FIN failed it");
  // A forbidden control-stream frame (a DATA frame) would normally be
  // FrameUnexpected, but on a Failed connection `handle_stream` is a no-op: it must
  // return Ok(empty), not re-error.
  {
    let frames = c
      .handle_stream(StreamId::new(10), &[0x00, 0x00], &mut sc)
      .expect("a Failed connection ignores further control bytes");
    drop(frames);
  }
  // Only the original terminal error is delivered.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream))
  );
  assert_eq!(c.poll_event(), None);
}

#[test]
fn handle_stream_fin_after_fail_emits_no_peer_closed_before_conn_error() {
  // After a no-return fatal path populated the terminal `conn_error` slot, a later
  // request-stream FIN must NOT enqueue `PeerClosed`. Since
  // `poll_event` drains the bounded queue BEFORE the terminal slot, a post-fatal
  // `PeerClosed` would be delivered ahead of the terminal ConnError — breaking
  // terminal ordering. The `Failed` guard makes the FIN a no-op, so the NEXT event
  // is the original ConnError, with nothing intervening.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Fail via a no-return fatal path: FIN the inbound control stream (id 3). The
  // request FSM stays in Tunnel, so `RequestStream::fin()` would otherwise be a
  // clean Ok(()) → PeerClosed.
  c.handle_stream_fin(StreamId::new(3));
  assert!(c.phase.is_failed(), "the critical-stream FIN failed it");
  // A request-stream FIN now: must be a no-op (no PeerClosed, no second ConnError).
  c.handle_stream_fin(req_id);
  // The NEXT event is the original terminal ConnError — nothing ahead of it.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "the original terminal ConnError, with no intervening PeerClosed"
  );
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

#[test]
fn clean_request_fin_twice_emits_at_most_one_peer_closed() {
  // Idempotency: a clean request-stream FIN at a Tunnel frame boundary is
  // `PeerClosed` (a graceful half-close). `RequestStream::fin()` is a pure read that
  // keeps returning Ok(()) at that boundary, so a SECOND clean FIN would re-push
  // `PeerClosed` without the `peer_closed` de-dup. It must be emitted exactly once.
  // Use the helper that drives a client to Open with the request FSM at a Tunnel
  // frame boundary (it also drains the Established event), so PeerClosed is the only
  // event in play.
  let id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(id);
  // First clean FIN: PeerClosed, connection stays non-terminal (half-close).
  c.handle_stream_fin(id);
  assert_eq!(
    c.poll_event(),
    Some(Event::PeerClosed),
    "first FIN is PeerClosed"
  );
  assert!(!c.is_terminal(), "a clean half-close is not a teardown");
  // Second clean FIN on the (still Tunnel) request stream: NO duplicate PeerClosed.
  c.handle_stream_fin(id);
  assert_eq!(
    c.poll_event(),
    None,
    "a second clean request FIN must not enqueue a duplicate PeerClosed"
  );
  assert!(!c.is_terminal(), "still a half-close, not terminal");
}

/// Drives a server to `Handshaking` with the peer's (client's) control-stream
/// SETTINGS decoded AND the CONNECT request HEADERS observed as `Frame::Request`
/// (so `request_received` is set, the gate `accept_with` waits on) — but WITHOUT
/// calling `accept_with`, so the tunnel is NOT yet established. This is the exact
/// pre-establishment window in which a peer can FIN its request stream after its
/// HEADERS but before the server sends the 2xx. Leaves the transmit ring drained.
fn server_request_observed_not_yet_accepted(req_id: StreamId) -> StaticConnection<Server> {
  let mut s = server_request_registered_no_peer_settings();
  // Deliver the client's control-stream SETTINGS so the peer-SETTINGS gate is met.
  let bytes = peer_control_settings(&[0x08, 0x01]);
  let mut sc = [0u8; 128];
  {
    let mut frames = s
      .handle_stream(StreamId::new(3), &bytes, &mut sc)
      .expect("control bytes ok");
    assert!(frames.next().expect("no frames").is_none());
  }
  assert!(s.peer_settings().is_some(), "peer SETTINGS decoded");
  // Observe the CONNECT request HEADERS as `Frame::Request` (sets `request_received`).
  deliver_connect_request(&mut s, req_id);
  drain_transmits(&mut s);
  assert!(
    !s.is_established(),
    "the tunnel must not be established before accept_with"
  );
  s
}

#[test]
fn pre_establishment_clean_request_fin_defers_peer_closed_until_after_established() {
  // A tunnel-lifecycle `PeerClosed` must NEVER precede `Established`. On the SERVER a
  // peer can cleanly FIN its request stream AFTER its CONNECT HEADERS but
  // BEFORE `accept_with` sends the 2xx (the establish point): the request FSM has
  // reached `Tunnel`, but the tunnel is not yet established (`tunnel_established` is
  // still false). `RequestStream::fin()` returns Ok(()) here, but emitting
  // `PeerClosed` now would surface a tunnel-lifecycle event before `Established`. So
  // the FIN is DEFERRED (`peer_fin_pending` set, nothing emitted), and `establish`
  // (which `accept_with` calls) flushes it RIGHT AFTER pushing `Established` — so the
  // observable order is `Established` then `PeerClosed`, each exactly once.
  let req_id = StreamId::new(0);
  let mut s = server_request_observed_not_yet_accepted(req_id);
  // A clean FIN at the Tunnel frame boundary, BEFORE accept_with: defer, emit nothing.
  s.handle_stream_fin(req_id);
  assert!(
    !s.is_terminal(),
    "a clean pre-establishment half-close is not a teardown"
  );
  assert_eq!(
    s.poll_event(),
    None,
    "a pre-establishment clean FIN must surface NEITHER Established NOR PeerClosed yet"
  );
  assert!(
    !s.is_established(),
    "still not established before accept_with"
  );
  // Now accept the CONNECT: this establishes the tunnel and flushes the deferred FIN.
  s.accept_with(&RESPONSE[..])
    .expect("accept_with after the request was observed succeeds");
  assert!(s.is_established(), "the tunnel is now established");
  // `Established` is enqueued strictly BEFORE the deferred `PeerClosed`.
  assert_eq!(
    s.poll_event(),
    Some(Event::Established),
    "Established must be delivered FIRST"
  );
  assert_eq!(
    s.poll_event(),
    Some(Event::PeerClosed),
    "the deferred PeerClosed must follow Established"
  );
  assert_eq!(
    s.poll_event(),
    None,
    "Established and PeerClosed are each delivered exactly once"
  );
  assert!(
    !s.is_terminal(),
    "the deferred half-close is still not a teardown"
  );
}

#[test]
fn second_fin_after_deferred_peer_closed_emits_no_duplicate() {
  // Idempotency: after a deferred pre-establishment FIN has been flushed as a single
  // `PeerClosed` (post-`accept_with`), a SECOND clean FIN on the (still
  // `Tunnel`) request stream must NOT enqueue a duplicate. `RequestStream::fin()` is
  // a pure read that keeps returning Ok(()) at the Tunnel frame boundary, but the
  // `peer_closed` flag — set by the deferred flush — de-dups it: the peer FINs its
  // send side at most once.
  let req_id = StreamId::new(0);
  let mut s = server_request_observed_not_yet_accepted(req_id);
  // Pre-establishment FIN (deferred), then accept_with flushes Established + PeerClosed.
  s.handle_stream_fin(req_id);
  s.accept_with(&RESPONSE[..]).expect("accept_with succeeds");
  assert_eq!(s.poll_event(), Some(Event::Established));
  assert_eq!(s.poll_event(), Some(Event::PeerClosed));
  assert_eq!(s.poll_event(), None);
  // A second clean FIN on the still-Tunnel request stream: no duplicate PeerClosed.
  s.handle_stream_fin(req_id);
  assert_eq!(
    s.poll_event(),
    None,
    "a second clean request FIN must not enqueue a duplicate PeerClosed"
  );
  assert!(!s.is_terminal(), "still a half-close, not terminal");
}

#[test]
fn provide_stream_after_fail_is_a_noop() {
  // `provide_stream` on a `Failed` connection is a no-op — it must not bind a new id
  // after the terminal ConnError. The exploit would be the driver opening the
  // request stream LATE on a connection that has already failed via a
  // critical-stream FIN: the late registration must not resurrect bookkeeping on a
  // terminal core.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // Register + FIN the inbound control stream (id 10): a no-return fatal path. No
  // request stream has been bound yet, so `request_id` is still None.
  {
    let _ = c
      .handle_stream(StreamId::new(10), &[0x00], &mut sc)
      .expect("control type byte ok");
  }
  c.handle_stream_fin(StreamId::new(10));
  assert!(c.phase.is_failed(), "the critical-stream FIN failed it");
  // Now the driver provides the request stream LATE. On a Failed connection this is
  // a no-op: no id bound, no FSM created.
  c.provide_stream(StreamRole::Request, StreamId::new(0));
  assert_eq!(
    c.request_id, None,
    "a Failed connection binds no request id"
  );
  // The connection stays Failed and only the original terminal error is delivered.
  assert!(c.phase.is_failed());
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream))
  );
  assert_eq!(c.poll_event(), None);
}

#[test]
fn handle_stream_reset_after_fail_emits_no_reset_event() {
  // A stream reset arriving AFTER a fatal error must NOT enqueue a `Reset` event
  // ahead of (or in addition to) the terminal ConnError. The `!is_terminal()` guard
  // covers `Failed` (Failed is terminal); this pins that behavior so a regression is
  // caught.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Fail via a no-return fatal path.
  c.handle_stream_fin(StreamId::new(3));
  assert!(c.phase.is_failed());
  // A reset on the request stream now: a no-op (no Reset event).
  c.handle_stream_reset(req_id, 0x010c);
  // Only the original terminal ConnError surfaces — no Reset ahead of it.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "no Reset event is enqueued after a fatal ConnError"
  );
  assert_eq!(c.poll_event(), None);
}

// ── the terminal ConnError supersedes a previously-queued graceful event ─

#[test]
fn terminal_conn_error_supersedes_a_previously_queued_reset() {
  // Real API paths: a graceful `Reset` queued by a peer request-stream reset (which
  // enters `Closing`) must be SUPPRESSED when a later no-return fatal path fails the
  // connection — the fail transition clears the pending queue, so `poll_event` yields
  // EXACTLY the terminal ConnError, with no intervening `Reset`. Were the queue
  // drained first, the stale `Reset` would precede the terminal error.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Queue a graceful Reset via the real reset path (enters Closing).
  c.handle_stream_reset(req_id, 0x010c);
  assert!(c.phase.is_closing(), "a peer reset enters Closing");
  // Trigger a no-return fatal path BEFORE polling: FIN the peer's inbound control
  // stream (id 3, registered by the SETTINGS feed). Failed supersedes Closing.
  c.handle_stream_fin(StreamId::new(3));
  assert!(
    c.phase.is_failed(),
    "the critical-stream FIN supersedes Closing"
  );
  // The next event is the terminal ConnError, with NO intervening Reset.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "the terminal ConnError supersedes the stale queued Reset"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "the stale Reset was discarded by the fail; exactly one event"
  );
}

#[test]
fn terminal_conn_error_supersedes_a_previously_queued_peer_closed() {
  // PeerClosed + duplicate-critical variant: a graceful `PeerClosed` queued by a clean
  // request-stream FIN (a half-close that leaves the
  // tunnel Open) must be SUPPRESSED when a later no-return fatal path — a duplicate
  // critical stream (a SECOND inbound control stream) — fails the connection. The next
  // event is EXACTLY the terminal ConnError, with no intervening PeerClosed. (A
  // duplicate REQUEST id is no longer fatal in the multi-stream core.)
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // A clean request FIN at the Tunnel boundary queues PeerClosed (stays Open).
  c.handle_stream_fin(req_id);
  assert!(!c.is_terminal(), "a clean half-close is not a teardown");
  // No-return fatal path BEFORE polling: a second inbound control stream (the peer's
  // control stream id 3 was already classified) is a duplicate critical stream.
  let mut sc = [0u8; 32];
  {
    let _ = c.handle_stream(StreamId::new(11), &[0x00], &mut sc);
  }
  assert!(c.phase.is_failed(), "a duplicate critical stream fails it");
  // EXACTLY the terminal ConnError, with NO intervening PeerClosed.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::StreamCreation)),
    "the terminal ConnError supersedes the stale queued PeerClosed"
  );
  assert_eq!(
    c.poll_event(),
    None,
    "the stale PeerClosed was discarded by the fail; exactly one event"
  );
}

// ── poll_transmit is inert once Failed (no stale outbound bytes) ────────

#[test]
fn poll_transmit_is_inert_once_failed_and_drops_queued_data() {
  // A DATA transmit queued while Open must NOT be written after a no-return fatal
  // path makes the connection terminal. Establish the tunnel, `send_data` to queue a
  // DATA transmit (do NOT poll it), then FIN the peer's inbound control stream (a
  // no-return fatal path). `poll_transmit` must now yield None — the stale DATA is
  // suppressed — and `poll_event` yields the terminal ConnError; the queued DATA must
  // not drain from the tx ring on a terminal connection.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // Queue a DATA transmit while Open, but do NOT poll it yet.
  c.send_data(b"stale").expect("send_data works while Open");
  // Fail via a no-return fatal path: FIN the inbound control stream (id 3).
  c.handle_stream_fin(StreamId::new(3));
  assert!(
    c.phase.is_failed(),
    "the critical-stream FIN makes it Failed"
  );
  // poll_transmit is inert on a Failed connection: the queued DATA is NOT written.
  assert!(
    c.poll_transmit().is_none(),
    "a Failed connection emits no transmit (the stale DATA is suppressed)"
  );
  // The terminal ConnError is the connection's last observable signal.
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "the terminal ConnError surfaces on a Failed connection"
  );
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

// ── RESET_STREAM handling mirrors the FIN matrix ──────────────────────────────
//
// `handle_stream_reset` resolves through the same matrix as `handle_stream_fin`:
// a RESET_STREAM on a peer-opened critical stream is H3_CLOSED_CRITICAL_STREAM (RFC
// 9114 §6.2.1), and a RESET_STREAM on an Ignored / Pending inbound uni stream releases
// its slot (otherwise a peer could reset UNI_CAP GREASE streams to wedge the table and
// starve a real control stream). These tests are the reset analogs of the FIN tests
// above.

#[test]
fn reset_on_inbound_control_stream_is_closed_critical() {
  // The reset analog of `control_stream_fin_is_closed_critical`: a RESET_STREAM on the
  // peer's inbound control stream (type 0x00) is H3_CLOSED_CRITICAL_STREAM, terminal.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let _ = c.handle_stream(StreamId::new(10), &[0x00], &mut sc); // register control stream
  c.handle_stream_reset(StreamId::new(10), 0x010c);
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "resetting the inbound control stream is H3_CLOSED_CRITICAL_STREAM"
  );
  assert!(c.is_terminal(), "a critical-stream reset is terminal");
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

#[test]
fn reset_on_inbound_qpack_encoder_stream_is_closed_critical() {
  // The reset analog for the peer's QPACK ENCODER stream (type 0x02): resetting a
  // classified critical inbound uni stream is H3_CLOSED_CRITICAL_STREAM, terminal.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let _ = c.handle_stream(StreamId::new(11), &[0x02], &mut sc); // classify QpackEncIn
  c.handle_stream_reset(StreamId::new(11), 0x010c);
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "resetting the inbound QPACK encoder stream is H3_CLOSED_CRITICAL_STREAM"
  );
  assert!(c.is_terminal());
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

#[test]
fn reset_on_inbound_qpack_decoder_stream_is_closed_critical() {
  // The reset analog for the peer's QPACK DECODER stream (type 0x03).
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  let _ = c.handle_stream(StreamId::new(13), &[0x03], &mut sc); // classify QpackDecIn
  c.handle_stream_reset(StreamId::new(13), 0x010c);
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "resetting the inbound QPACK decoder stream is H3_CLOSED_CRITICAL_STREAM"
  );
  assert!(c.is_terminal());
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

#[test]
fn reset_on_outbound_critical_stream_is_closed_critical() {
  // The reset analog of the outbound-critical FIN branch (resolved via `role_of`): a
  // RESET_STREAM on a critical stream WE opened (the outbound control stream) is
  // H3_CLOSED_CRITICAL_STREAM, terminal.
  let mut c = Connection::<Client>::new();
  let ctrl_id = StreamId::new(2);
  c.provide_stream(StreamRole::ControlOut, ctrl_id);
  assert!(!c.is_terminal(), "healthy before the reset");
  c.handle_stream_reset(ctrl_id, 0x010c);
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "resetting an outbound critical stream is H3_CLOSED_CRITICAL_STREAM"
  );
  assert!(c.is_terminal(), "an outbound-critical reset is terminal");
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

#[test]
fn reset_on_classified_ignored_uni_stream_frees_its_slot() {
  // The reset analog of `fin_on_classified_ignored_uni_stream_frees_its_slot`: a
  // RESET_STREAM on a classified Ignored (GREASE) uni stream must free its tracking
  // slot. Otherwise a peer could open + RESET UNI_CAP GREASE streams to wedge the
  // bounded table and have the real inbound control stream rejected with
  // H3_EXCESSIVE_LOAD — a connection kill-switch. Proof: fill the table with
  // classified-Ignored GREASE streams, reset all of them, then the peer's real
  // control stream must classify and have its SETTINGS processed (no ExcessiveLoad).
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  let mut sc = std::vec![0u8; 128];
  // Fill the whole table with classified-Ignored GREASE streams (1-byte type 0x21).
  for i in 0..(super::UNI_CAP as u64) {
    let id = StreamId::new(3000 + i);
    let mut frames = c
      .handle_stream(id, &[0x21, 0xaa, 0xbb], &mut sc)
      .expect("grease uni stream under cap must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // Reset every GREASE stream: each closed extension stream must free its slot, and
  // resetting an Ignored stream is NOT a closed-critical-stream error.
  for i in 0..(super::UNI_CAP as u64) {
    c.handle_stream_reset(StreamId::new(3000 + i), 0x010c);
  }
  assert_eq!(
    c.poll_event(),
    None,
    "resetting Ignored streams produces no events"
  );
  assert!(
    !c.is_terminal(),
    "resetting Ignored streams (no overflow tripped) keeps the connection healthy"
  );
  // With the slots freed, the peer's REAL control stream (type 0x00 + SETTINGS
  // enabling Extended CONNECT) must now classify and have its SETTINGS processed.
  let ctrl = peer_control_settings(&[0x08, 0x01]);
  {
    let mut frames = c
      .handle_stream(StreamId::new(3), &ctrl, &mut sc)
      .expect("control stream must classify after RESET GREASE streams freed slots");
    assert!(frames.next().expect("no frames").is_none());
  }
  let peer = c.peer_settings().expect("peer settings decoded");
  assert!(peer.enable_connect_protocol());
  c.open_with(&CONNECT_REQUEST[..])
    .expect("open_with after opt-in");
  let t = c
    .poll_transmit()
    .expect("request enqueued after control SETTINGS");
  assert!(matches!(t.kind(), StreamKind::OpenRequest));
  assert_eq!(c.poll_event(), None);
}

#[test]
fn reset_on_partial_type_varint_stream_frees_its_slot() {
  // The reset analog of `fin_on_partial_type_varint_stream_frees_its_slot`: a
  // RESET_STREAM on a stream that only ever sent a partial type varint frees its slot
  // (the stream closed before declaring its type), so a later new stream can still be
  // tracked. Fill the table with partials, reset one, then a fresh stream is accepted.
  let mut c = Connection::<Client>::new();
  let mut sc = [0u8; 64];
  // Reserve all UNI_CAP slots as Pending (each sends one byte of a 2-byte varint).
  for i in 0..(super::UNI_CAP as u64) {
    let id = StreamId::new(700 + i);
    let mut frames = c
      .handle_stream(id, &[0x40], &mut sc)
      .expect("partial type varint under cap must not error");
    assert!(frames.next().expect("no frames").is_none());
  }
  // Reset the first partial stream: closing before declaring a type frees its slot and
  // must NOT be treated as a closed critical stream (no ConnError event).
  c.handle_stream_reset(StreamId::new(700), 0x010c);
  assert_eq!(c.poll_event(), None, "pending-stream reset is not critical");
  assert!(!c.is_terminal(), "a pending-stream reset keeps it healthy");
  // With a slot freed, a fresh inbound uni stream is accepted again.
  let mut frames = c
    .handle_stream(StreamId::new(9001), &[0x21, 0xaa], &mut sc)
    .expect("a freed slot lets a new stream be tracked");
  assert!(frames.next().expect("no frames").is_none());
}

#[test]
fn reset_on_unknown_id_is_a_noop() {
  // The "unknown / untracked id" branch: a RESET_STREAM on an id that is neither the
  // request stream, an outbound role, nor a tracked inbound uni stream is ignored (no
  // panic, no event, not terminal). Mirrors the FIN unknown-id no-op.
  let mut c = Connection::<Client>::new();
  c.start().unwrap();
  drain_transmits(&mut c);
  c.handle_stream_reset(StreamId::new(444), 0x010c);
  assert_eq!(
    c.poll_event(),
    None,
    "an unknown-id reset enqueues no event"
  );
  assert!(!c.is_terminal(), "an unknown-id reset is not terminal");
}

#[test]
fn reset_on_critical_stream_while_closing_supersedes_the_close() {
  // A critical-stream reset must fail with ClosedCriticalStream EVEN when the
  // connection is already gracefully `Closing` (a local `close()`): the closed-
  // critical error supersedes the graceful close (it fires from `Closing`, not only
  // from a healthy phase). Mirror of the FIN behavior — `resolve_non_request_close`
  // routes through `fail`, which promotes `Closing → Failed`.
  let req_id = StreamId::new(0);
  let mut c = client_open_at_tunnel_boundary(req_id);
  // The inbound control stream (id 3) was registered by the SETTINGS feed inside
  // `client_after_peer_settings`. Begin a graceful local close first.
  c.close();
  assert!(c.phase.is_closing(), "close() enters Closing");
  // A reset of the inbound control stream now: ClosedCriticalStream supersedes Closing.
  c.handle_stream_reset(StreamId::new(3), 0x010c);
  assert!(
    c.phase.is_failed(),
    "a critical-stream reset supersedes the graceful Closing"
  );
  assert_eq!(
    c.poll_event(),
    Some(Event::ConnError(H3Error::ClosedCriticalStream)),
    "the terminal ConnError supersedes the graceful close"
  );
  assert_eq!(c.poll_event(), None, "exactly one terminal event");
}

#[test]
fn two_request_streams_coexist_in_store() {
  // Server side: register two inbound request streams; both get independent
  // store slots and independent recv FSMs.
  let mut s = Connection::<Server>::new();
  s.start().expect("start");
  s.provide_stream(StreamRole::Request, StreamId::new(0));
  s.provide_stream(StreamRole::Request, StreamId::new(4));
  // Both ids are tracked; feeding a partial HEADERS to one does not disturb the
  // other (no panic, independent FSMs). Detailed behavior is covered in Task 6.
  let mut scratch = std::vec![0u8; 1024];
  let _ = s.handle_stream(StreamId::new(0), &[0x01, 0x03], &mut scratch);
  let _ = s.handle_stream(StreamId::new(4), &[0x01, 0x03], &mut scratch);
  // No connection-fatal error from independent partial reads.
  assert!(s.poll_event().is_none());
}
