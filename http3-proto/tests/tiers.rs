//! Bare-tier smoke test: proves `http3-proto` builds and runs with
//! `--no-default-features` (no `std`, no `alloc`) and that the core contract
//! — `Connection::with_buffers`, `start`, `open_with`, `poll_transmit`,
//! `handle_stream`, `poll_event` — works without a heap.
//!
//! Run as:
//! ```sh
//! cargo test -p http3-proto --no-default-features --test tiers
//! ```

use http3_proto::{
  BorrowedConnection, Client, Connection, UniSlot,
  connection::{CTRL_CAP, EVENT_QUEUE_CAP, TX_BYTES_CAP, UNI_TRACKING_CAP},
  event::{StreamId, StreamRole},
  stream::{HDR_CAP, RequestStream},
};
// `Server` is used only by the bare multi-stream smoke; on the heap tiers (where
// `--all-features --all-targets` also compiles this file) that test is cfg'd out,
// so gate the import to match and avoid an unused-import warning under `-D warnings`.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
use http3_proto::Server;
// The bare-tier stream store is caller-provided slots; this slot type is exported
// only on the bare tier (heap tiers grow the store internally). `--all-features
// --all-targets` also compiles this test under `std`, where `BorrowedConnection`
// uses the heap store, so the slot type and its `with_buffers` arg are bare-only.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
use http3_proto::StreamSlot;

type StaticConnection<Ro> = Connection<'static, 'static, 'static, 'static, 'static, Ro>;

/// A minimal `Headers` impl backed by a static slice: the bare tier cannot use
/// `Vec`, so the `[(&str, &str)]` blanket impl on a fixed-size array is the
/// right approach.
static REQUEST_HEADERS: &[(&str, &str)] = &[
  (":method", "CONNECT"),
  (":protocol", "websocket"),
  (":scheme", "https"),
  (":path", "/"),
  (":authority", "example.com"),
];

#[test]
fn bare_tier_open_and_drain() {
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  let mut tx_bytes = [0u8; TX_BYTES_CAP];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  // The bare-tier stream store is a caller-provided fixed-capacity slice; the CONNECT
  // tunnel needs one slot. (Under `std`/`alloc`/`no-atomic` the store grows
  // internally, so `with_buffers` takes no slots there.)
  #[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
  let mut stream_slots: [StreamSlot<'_, &mut [u8]>; 1] = [StreamSlot::EMPTY];
  #[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
  let mut conn = BorrowedConnection::<Client>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
    &mut stream_slots[..],
  );
  #[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
  let mut conn = BorrowedConnection::<Client>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
  );

  // start() enqueues the control stream and two QPACK streams. The CONNECT request
  // is sent later with open_with, only after the peer's SETTINGS arrive (RFC 8441
  // §3). All of this must work without any allocator.
  conn.start().expect("start failed");

  // Drain the transmit queue into a stack scratch buffer.
  let sink = [0u8; 1024];
  let mut tx_count = 0usize;
  while let Some(t) = conn.poll_transmit() {
    // Verify the transmit carries some bytes.
    let n = t.bytes().len();
    assert!(n > 0, "expected non-empty transmit");
    // Copy into sink to prove no panic on the indexing.
    let _ = sink.get(..n); // bounds check only; we don't need the data
    tx_count = tx_count.saturating_add(1);
  }
  // We expect exactly 3 setup transmits from start: control stream open, QPACK
  // enc open, QPACK dec open. The request HEADERS are sent later via open_with.
  assert_eq!(tx_count, 3, "expected 3 setup transmits, got {tx_count}");

  // Before the peer's SETTINGS arrive, open_with is WouldBlock (no opt-in yet).
  assert!(
    conn.open_with(REQUEST_HEADERS).is_err(),
    "open_with before peer SETTINGS must error (WouldBlock)"
  );

  // Register a fake request stream id and feed the peer's control SETTINGS.
  conn.provide_stream(StreamRole::Request, StreamId::new(0));
  let mut scratch = [0u8; 512];
  // The peer control stream (new unknown id = 1): type byte 0x00, then a SETTINGS
  // frame (type=0x04, length=2) advertising ENABLE_CONNECT_PROTOCOL=1
  // (id=0x08, value=0x01). The connection routes it to classify_uni then
  // handle_control, which decodes and stores the peer's settings.
  let ctrl_bytes: &[u8] = &[0x00, 0x04, 0x02, 0x08, 0x01];
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(1), ctrl_bytes, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }

  // The peer's SETTINGS opting in have arrived, so open_with now sends the request.
  conn
    .open_with(REQUEST_HEADERS)
    .expect("open_with after peer opt-in failed");
  let req = conn
    .poll_transmit()
    .expect("request enqueued after peer opts in");
  assert!(!req.bytes().is_empty());

  // No error events on this (conformant) opt-in path.
  assert!(conn.poll_event().is_none());
}

/// Multi-slot stream storage on the bare tier: two request streams registered
/// over caller-provided `StreamSlot`s are tracked independently, and a partial
/// read on one does not panic or disturb the other.
///
/// This is a **partial-read smoke**, not a full second-stream GET. On the bare
/// tier only the single seeded tunnel stream owns a real HEADERS buffer; every
/// ADDITIONAL request stream gets an empty (`&mut []`) HEADERS buffer, so it can
/// hold multi-slot state and tolerate a partial read, but it cannot accept a
/// *full* HEADERS section (that would graceful-`FrameError` on the empty buffer).
/// Full bare multi-stream therefore needs caller-supplied per-stream HEADERS
/// buffers — a future enhancement beyond Phase 0; the CONNECT tunnel (one stream,
/// seeded buffer) is the fully-driven bare path (see `bare_tier_open_and_drain`).
/// The slab/heap tiers grow real per-stream buffers internally, so they drive
/// concurrent streams to completion (covered by `connection::tests`).
///
/// We feed only `&[0x01, 0x03]` — a HEADERS frame header (type `0x01`, length 3)
/// with no payload — so the recv FSM parses the frame header and waits for the
/// body without ever touching the empty HEADERS buffer.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
#[test]
fn bare_tier_two_streams_independent() {
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  let mut tx_bytes = [0u8; TX_BYTES_CAP];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  // Caller-provided stream storage: 2 slots (the multi-stream store capacity).
  let mut stream_slots: [StreamSlot<'_, &mut [u8]>; 2] = [StreamSlot::EMPTY; 2];
  let mut conn = BorrowedConnection::<Server>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
    &mut stream_slots[..],
  );
  conn.start().expect("start failed");
  // Two independent inbound request streams (server-side ids 0 and 4).
  conn.provide_stream(StreamRole::Request, StreamId::new(0));
  conn.provide_stream(StreamRole::Request, StreamId::new(4));

  // A partial HEADERS read on each: the frame header parses, the body is awaited;
  // neither call panics and neither disturbs the other's tracked slot.
  let mut scratch = [0u8; 1024];
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(0), &[0x01, 0x03], &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(4), &[0x01, 0x03], &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  // No frame completed and no connection-scoped event fired (a partial leading
  // section yields nothing; general streams never push `Event::Established`).
  assert!(conn.poll_event().is_none());
}

#[test]
fn bare_tier_default_connection_type_is_small() {
  let connection_size = core::mem::size_of::<StaticConnection<Client>>();
  let request_stream_size = core::mem::size_of::<RequestStream<'static>>();
  // On the bare tier the transmit ring holds no refcounted DATA body, so the
  // connection stays under 1 KiB. `--all-features --all-targets` also compiles
  // this test on the heap tiers, where the ring additionally holds one optional
  // `DataBuf` handle per slot (for vectored zero-copy DATA), widening it; allow
  // that larger ceiling there.
  #[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
  let max_connection_size = 1024;
  #[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
  let max_connection_size = 1280;
  assert!(
    connection_size < max_connection_size,
    "default Connection should store buffer handles, got {connection_size}"
  );
  assert!(
    request_stream_size < 128,
    "bare default RequestStream should store a borrowed buffer handle, got {request_stream_size}"
  );
}

#[test]
fn bare_tier_varint_roundtrip() {
  // Verify the varint codec on stack data only (no heap).
  let cases: &[(u64, &[u8])] = &[
    (0, &[0x00]),
    (63, &[0x3f]),
    (64, &[0x40, 0x40]),
    (16383, &[0x7f, 0xff]),
  ];
  for &(expected_val, wire) in cases {
    let (consumed, decoded) = http3_proto::varint::decode(wire).expect("decode");
    assert_eq!(consumed, wire.len());
    assert_eq!(decoded, expected_val);
    let mut buf = [0u8; 8];
    let n = http3_proto::varint::encode(decoded, &mut buf).expect("encode");
    assert_eq!(&buf[..n], wire);
  }
}

#[test]
fn bare_tier_frame_decode() {
  // DATA frame: type=0x00 (1 byte), length=10 (1 byte).
  let wire: &[u8] = &[0x00, 0x0a];
  let (consumed, hdr) = http3_proto::frame::decode_header(wire).expect("decode_header");
  assert_eq!(consumed, 2);
  assert_eq!(hdr.length(), 10);
  assert!(matches!(hdr.kind(), http3_proto::frame::FrameKind::Data));
}

#[test]
fn bare_tier_qpack_decode_into() {
  // Valid 2-byte prefix (RIC=0, base=0) + indexed static entry 17 = ":method: GET".
  let field_section: &[u8] = &[0x00, 0x00, 0xd1];
  let mut scratch = [0u8; 256];
  let mut lines = http3_proto::qpack::decode_field_section_into(field_section, &mut scratch)
    .expect("decode_field_section_into");
  let pair = lines.next().expect("next Ok").expect("some pair");
  assert_eq!(pair.name(), ":method");
  assert_eq!(pair.value(), "GET");
  assert!(lines.next().expect("next Ok").is_none());
}
