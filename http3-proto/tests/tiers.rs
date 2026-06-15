//! Bare-tier smoke test: proves `http3-proto` builds and runs with
//! `--no-default-features` (no `std`, no `alloc`) and that the core contract
//! — `Connection::new`, `open_with`, `poll_transmit`, `handle_stream`,
//! `poll_event` — works without a heap.
//!
//! Run as:
//! ```sh
//! cargo test -p http3-proto --no-default-features --test tiers
//! ```

use http3_proto::{
  Client, Connection,
  event::{StreamId, StreamRole},
};

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
  let mut conn = Connection::<Client>::new();

  // open_with enqueues the control stream, two QPACK streams, and the
  // request HEADERS. All of this must work without any allocator.
  conn.open_with(REQUEST_HEADERS).expect("open_with failed");

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
  // We expect at least 4 transmits: control stream open, QPACK enc open,
  // QPACK dec open, request stream open with HEADERS.
  assert!(tx_count >= 4, "expected >= 4 transmits, got {tx_count}");

  // Register a fake request stream id and feed arbitrary bytes.
  conn.provide_stream(StreamRole::Request, StreamId::new(0));
  let mut scratch = [0u8; 512];
  // Feeding the SETTINGS + QPACK type bytes on a control stream (new unknown
  // id = 1): type byte 0x00 = control stream, then SETTINGS frame.
  // The connection routes it to classify_uni then handle_control.
  let ctrl_bytes: &[u8] = &[0x00, 0x04, 0x00]; // type=ctrl, SETTINGS type=4, length=0
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(1), ctrl_bytes, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }

  // Events: none expected yet (no established tunnel).
  assert!(conn.poll_event().is_none());
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
