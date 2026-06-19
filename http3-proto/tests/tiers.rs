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
// `Server` (the bare multi-stream smoke) and `General` (the bare general-API tests) are
// used only on the bare tier; on the heap tiers (where `--all-features --all-targets` also
// compiles this file) those tests are cfg'd out, so gate the imports to match and avoid an
// unused-import warning under `-D warnings`.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
use http3_proto::{General, Server};
// The bare-tier stream store is caller-provided slots; this slot type is exported
// only on the bare tier (heap tiers grow the store internally). `--all-features
// --all-targets` also compiles this test under `std`, where `BorrowedConnection`
// uses the heap store, so the slot type and its `with_buffers` arg are bare-only.
// `H3Error` / `StreamKind` back the bare capacity-overflow reset assertion.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
use http3_proto::{H3Error, StreamKind, StreamSlot};

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

/// An at-capacity request stream is reset with `H3_REQUEST_REJECTED` and the
/// connection survives. A 1-slot stream store is filled by the first request stream, so a
/// SECOND `provide_stream(Request, ..)` overflows the store (`insert` fails). That
/// overflow stream's `StreamEntry` is never inserted, so the reset cannot go through
/// `reset_stream` (its `streams.remove` would no-op); the connection emits a `RESET_STREAM`
/// transmit DIRECTLY via `enqueue_stream_reset` so the peer learns the request was
/// rejected.
///
/// The bare tier is the natural home: its store is a caller-provided fixed-capacity slice
/// (here length 1), whereas the heap tiers' `SlabStore` is unbounded and cannot overflow.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
#[test]
fn bare_tier_capacity_overflow_resets_with_request_rejected() {
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  let mut tx_bytes = [0u8; TX_BYTES_CAP];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  // A ONE-slot stream store: the first request stream fills it, the next overflows.
  let mut stream_slots: [StreamSlot<'_, &mut [u8]>; 1] = [StreamSlot::EMPTY];
  let mut conn = BorrowedConnection::<Server>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
    &mut stream_slots[..],
  );
  conn.start().expect("start failed");
  // Drain the setup transmits so the next `poll_transmit` returns only the reset.
  while conn.poll_transmit().is_some() {}
  // First request stream (id 0): takes the single store slot (and the seeded buffer).
  conn.provide_stream(StreamRole::Request, StreamId::new(0));
  // Second request stream (id 4): the store is full, so the insert overflows. The
  // overflow stream must be reset with H3_REQUEST_REJECTED (a RESET_STREAM transmit).
  let overflow = StreamId::new(4);
  conn.provide_stream(StreamRole::Request, overflow);
  // The reset IS emitted (not silently dropped): a RESET_STREAM(RequestRejected) for the
  // overflow id, carrying no bytes. Copy the transmit's facts out so its borrow of `conn`
  // ends before the `poll_event` read below.
  let (kind, empty, no_fin) = {
    let t = conn
      .poll_transmit()
      .expect("the overflow stream is reset with a RESET_STREAM transmit");
    (t.kind(), t.bytes().is_empty(), !t.fin())
  };
  assert!(
    matches!(kind, StreamKind::ResetStream { id, code }
      if id == overflow && code == H3Error::RequestRejected.code()),
    "the overflow stream is reset with H3_REQUEST_REJECTED",
  );
  assert!(empty, "a RESET_STREAM carries no bytes");
  assert!(no_fin, "a RESET_STREAM is not a FIN");
  // The connection survives: overflow is NOT connection-fatal, so no terminal `ConnError`
  // is queued (a failed connection would surface one here) and the reset emits no
  // connection-scoped event (it is stream-scoped). `poll_event` draining empty proves
  // both — `is_failed` is a test-only accessor unavailable on the bare tier.
  assert!(
    conn.poll_event().is_none(),
    "overflow is not connection-fatal: no ConnError, no event"
  );
}

/// A CLIENT `open_request` at stream-store capacity returns `Err` and enqueues NO request
/// HEADERS for the over-capacity id (it does not both reset and write on an untracked id).
/// The connection survives, and the over-capacity stream is reset with
/// `H3_REQUEST_REJECTED`.
///
/// Bare tier: a 1-slot store, so the first `open_request` fills it (taking the seeded
/// HEADERS buffer) and the second overflows.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
#[test]
fn bare_tier_open_request_at_capacity_errs_without_headers() {
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  let mut tx_bytes = [0u8; TX_BYTES_CAP];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  // A ONE-slot stream store: the first request stream fills it, the next overflows.
  let mut stream_slots: [StreamSlot<'_, &mut [u8]>; 1] = [StreamSlot::EMPTY];
  let mut conn = BorrowedConnection::<Client, General>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
    &mut stream_slots[..],
  );
  conn.start().expect("start failed");
  // Feed the peer's control SETTINGS so `open_request` is past its readiness gate.
  let mut scratch = [0u8; 512];
  let ctrl_bytes: &[u8] = &[0x00, 0x04, 0x02, 0x08, 0x01];
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(1), ctrl_bytes, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  // Drain the setup transmits so the only later transmit is the overflow reset.
  while conn.poll_transmit().is_some() {}

  let get: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "example.com"),
  ];
  // First `open_request` takes the single store slot (and the seeded buffer) and succeeds.
  let id0 = StreamId::new(0);
  conn
    .open_request(id0, get)
    .expect("first open_request fits");
  // Its request HEADERS are enqueued on id0. Copy the facts out so the borrow ends.
  let (first_kind, first_nonempty) = {
    let first = conn
      .poll_transmit()
      .expect("first request HEADERS enqueued");
    (first.kind(), !first.bytes().is_empty())
  };
  assert!(matches!(first_kind, StreamKind::Existing(eid) if eid == id0));
  assert!(first_nonempty, "the request HEADERS carry bytes");

  // Second `open_request` overflows the 1-slot store: it must return Err and enqueue NO
  // HEADERS for the over-capacity id.
  let overflow = StreamId::new(4);
  let err = conn
    .open_request(overflow, get)
    .expect_err("at-capacity open_request must error");
  assert!(
    matches!(err, http3_proto::Error::Protocol(H3Error::RequestRejected)),
    "the over-capacity open is RequestRejected, got {err:?}"
  );
  // The ONLY transmit for the over-capacity id is its RESET_STREAM(RequestRejected) — never
  // request HEADERS (no `Existing(overflow)`). Copy each transmit's facts out so the borrow
  // ends before the next poll.
  let mut saw_reset = false;
  loop {
    let next = {
      match conn.poll_transmit() {
        None => break,
        Some(t) => (t.kind(), t.bytes().is_empty()),
      }
    };
    let (kind, empty) = next;
    match kind {
      StreamKind::ResetStream { id, code } => {
        assert_eq!(id, overflow, "the reset targets the over-capacity id");
        assert_eq!(code, H3Error::RequestRejected.code(), "H3_REQUEST_REJECTED");
        assert!(empty, "a RESET_STREAM carries no bytes");
        saw_reset = true;
      }
      StreamKind::Existing(eid) => {
        assert_ne!(eid, overflow, "NO request HEADERS for the over-capacity id");
      }
      _ => {}
    }
  }
  assert!(
    saw_reset,
    "the over-capacity stream is reset with H3_REQUEST_REJECTED"
  );
  // The connection survives: overflow is not connection-fatal, so no terminal ConnError.
  assert!(
    conn.poll_event().is_none(),
    "an at-capacity open is not connection-fatal: no ConnError"
  );
  // The rejected id is not tracked, so a send on it reads as closed (no lingering entry).
  assert!(
    matches!(
      conn.send_data_on(overflow, &b"x"[..]),
      Err(http3_proto::Error::Closed)
    ),
    "the rejected stream is untracked: a body on it is rejected (no body-before-HEADERS)"
  );
}

/// A MALFORMED `open_request` (rejected at the encode/validate step) does NOT consume the
/// construction-time recv-buffer seed, so a subsequent VALID `open_request` still gets the
/// seeded HEADERS buffer and can decode a full response section.
///
/// The bare tier is the only place this is observable: only the single SEEDED stream owns a
/// real HEADERS buffer (additional streams get `ReqBufAlloc::fresh()` == `&mut []`, which
/// graceful-`FrameError`s on a full section). `open_request` encodes+validates into the
/// preflighted tx slot BEFORE registering the stream, so a rejected open leaves the seed
/// intact for the next request.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
#[test]
fn bare_tier_malformed_open_request_preserves_seed_for_next_open() {
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  let mut tx_bytes = [0u8; TX_BYTES_CAP];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  // A single store slot: the seeded HEADERS buffer backs whichever stream registers first.
  let mut stream_slots: [StreamSlot<'_, &mut [u8]>; 1] = [StreamSlot::EMPTY];
  let mut conn = BorrowedConnection::<Client, General>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
    &mut stream_slots[..],
  );
  conn.start().expect("start failed");
  // Feed the peer's control SETTINGS so `open_request` is past its readiness gate.
  let mut scratch = [0u8; 512];
  let ctrl_bytes: &[u8] = &[0x00, 0x04, 0x02, 0x08, 0x01];
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(1), ctrl_bytes, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  while conn.poll_transmit().is_some() {}

  let id = StreamId::new(0);
  // A MALFORMED request: a forbidden connection-specific field (`connection`) fails the
  // single-pass `validate(MessageKind::Request)` with `MessageError` — the encode/validate
  // rejection path that must NOT consume the seed.
  let malformed: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "example.com"),
    ("connection", "keep-alive"),
  ];
  let err = conn
    .open_request(id, malformed)
    .expect_err("a malformed open_request must be rejected");
  assert!(
    matches!(err, http3_proto::Error::Protocol(H3Error::MessageError)),
    "the malformed request is MessageError, got {err:?}"
  );
  // The rejection enqueued nothing and registered no entry (the id is free to reuse).
  assert!(
    conn.poll_transmit().is_none(),
    "a rejected open_request enqueues no HEADERS"
  );
  // A malformed open_request is a caller refusal, not connection-fatal: no terminal ConnError.
  assert!(
    !matches!(conn.poll_event(), Some(http3_proto::Event::ConnError(_))),
    "a malformed open_request is a caller refusal, not connection-fatal"
  );

  // A VALID request on the SAME id succeeds — and, crucially, takes the SEEDED buffer
  // (the malformed open did not consume it).
  let get: &[(&str, &str)] = &[
    (":method", "GET"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "example.com"),
  ];
  conn
    .open_request(id, get)
    .expect("a valid open_request after a rejected one must succeed");
  // Drain its request HEADERS.
  while conn.poll_transmit().is_some() {}

  // The PROOF the seed survived: feed a full response HEADERS section (`:status: 200`,
  // QPACK static index 25) and require it to DECODE into a final `Frame::Response`. Without
  // the seeded buffer the stream would hold `&mut []` and this section would
  // graceful-`FrameError`.
  let response: &[u8] = &[0x01, 0x03, 0x00, 0x00, 0xd9];
  let mut decoded_final_response = false;
  let mut decode_err = None;
  {
    match conn.handle_stream(id, response, &mut scratch) {
      Ok(mut frames) => loop {
        match frames.next() {
          Ok(Some(http3_proto::Frame::Response { interim: false, .. })) => {
            decoded_final_response = true;
          }
          Ok(Some(_)) => {}
          Ok(None) => break,
          Err(e) => {
            decode_err = Some(e);
            break;
          }
        }
      },
      Err(e) => decode_err = Some(e),
    }
  }
  assert!(
    decode_err.is_none(),
    "the response HEADERS must decode (seed survived); got error {decode_err:?}"
  );
  assert!(
    decoded_final_response,
    "the seeded buffer decoded the final response — the malformed open did not consume the seed"
  );
  // The exchange left the connection live: no terminal ConnError.
  assert!(
    !matches!(conn.poll_event(), Some(http3_proto::Event::ConnError(_))),
    "the exchange left the connection live"
  );
}

/// A capacity-rejection reset is NOT lost under transmit backpressure. With the transmit
/// ring FULL at the moment a request stream overflows the store, the
/// `RESET_STREAM(RequestRejected)` cannot be enqueued directly; instead it is recorded in
/// the bounded pending-reset retry queue and materializes on a later `poll_transmit` once
/// the ring drains.
///
/// The ring is sized for EXACTLY the three setup transmits, so it is full right after
/// `start()`; the overflow reset must survive in the retry queue until the ring drains.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
#[test]
fn bare_tier_capacity_reset_survives_full_tx_ring() {
  use http3_proto::connection::TX_SLOT_CAP;
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  // Exactly three transmit slots: full immediately after the three setup transmits.
  let mut tx_bytes = [0u8; TX_SLOT_CAP * 3];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  let mut stream_slots: [StreamSlot<'_, &mut [u8]>; 1] = [StreamSlot::EMPTY];
  let mut conn = BorrowedConnection::<Server>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
    &mut stream_slots[..],
  );
  conn.start().expect("start failed");
  // The ring now holds the three setup transmits and is FULL — do NOT drain it.
  // First request stream fills the 1-slot store.
  conn.provide_stream(StreamRole::Request, StreamId::new(0));
  // Second request stream overflows the store. Its RESET_STREAM(RequestRejected) cannot be
  // enqueued (ring full), so it is recorded in the retry queue rather than dropped.
  let overflow = StreamId::new(4);
  conn.provide_stream(StreamRole::Request, overflow);

  // Drain every transmit, collecting whether the deferred reset materializes. The first
  // polls yield the setup transmits; as the ring drains, the queued reset is re-enqueued at
  // the head of `poll_transmit` and surfaces — it is NOT lost.
  let mut saw_reset = false;
  let mut total = 0usize;
  loop {
    let captured = match conn.poll_transmit() {
      None => break,
      Some(t) => (t.kind(), t.bytes().is_empty()),
    };
    total = total.saturating_add(1);
    if let (StreamKind::ResetStream { id, code }, empty) = captured {
      assert_eq!(
        id, overflow,
        "the deferred reset targets the over-capacity id"
      );
      assert_eq!(code, H3Error::RequestRejected.code(), "H3_REQUEST_REJECTED");
      assert!(empty, "a RESET_STREAM carries no bytes");
      saw_reset = true;
    }
    // Guard against a non-terminating loop if the retry logic regressed.
    assert!(total < 16, "transmit drain should terminate");
  }
  assert!(
    saw_reset,
    "the backpressured RequestRejected reset materializes once the ring drains (not lost)"
  );
  // The connection survives: a capacity rejection under backpressure is not fatal.
  assert!(
    conn.poll_event().is_none(),
    "a backpressured capacity rejection is not connection-fatal"
  );
}

/// Resetting a stream PURGES its already-queued `Existing(id)` DATA/FIN from the transmit
/// ring, so the `RESET_STREAM` supersedes — does not queue behind — the stale bytes. On the
/// bare tier the DATA payload lives entirely in the byte ring (no refcounted body), so the
/// tombstone-and-skip purge is what drops it: after the reset, `poll_transmit` yields the
/// abort with NO `Existing(id)` transmit preceding it, and nothing after.
#[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
#[test]
fn bare_tier_reset_purges_queued_same_stream_data() {
  let mut request_headers = [0u8; HDR_CAP];
  let mut control_payload = [0u8; CTRL_CAP];
  let mut tx_bytes = [0u8; TX_BYTES_CAP];
  let mut event_slots = [None; EVENT_QUEUE_CAP];
  let mut uni_slots = [UniSlot::EMPTY; UNI_TRACKING_CAP];
  let mut stream_slots: [StreamSlot<'_, &mut [u8]>; 1] = [StreamSlot::EMPTY];
  let mut conn = BorrowedConnection::<Client, General>::with_buffers(
    &mut request_headers[..],
    &mut control_payload[..],
    &mut tx_bytes[..],
    &mut event_slots[..],
    &mut uni_slots[..],
    &mut stream_slots[..],
  );
  conn.start().expect("start failed");
  // Feed the peer's control SETTINGS so `open_request` is past its readiness gate.
  let mut scratch = [0u8; 512];
  let ctrl_bytes: &[u8] = &[0x00, 0x04, 0x02, 0x08, 0x01];
  if let Ok(mut frames) = conn.handle_stream(StreamId::new(1), ctrl_bytes, &mut scratch) {
    while let Ok(Some(_)) = frames.next() {}
  }
  let id = StreamId::new(0);
  let get: &[(&str, &str)] = &[
    (":method", "POST"),
    (":scheme", "https"),
    (":path", "/"),
    (":authority", "example.com"),
  ];
  conn.open_request(id, get).expect("open_request fits");
  // Drain the setup transmits AND the request HEADERS, so the ring holds only the DATA we
  // queue next (isolating the purge assertion).
  while conn.poll_transmit().is_some() {}
  // Queue request-body DATA on `id` (a client may send body before any response). On bare
  // these bytes live in the ring.
  for _ in 0..3 {
    conn
      .send_data_on(id, &b"stale-body"[..])
      .expect("queue request body");
  }
  // Condemn the stream: purge its queued DATA and enqueue the RESET_STREAM.
  conn.reset_stream(id, H3Error::RequestRejected.code());
  // The FIRST (and only) transmit is the RESET_STREAM — NO `Existing(id)` DATA precedes it.
  let first = {
    let t = conn.poll_transmit().expect("a transmit after reset");
    (t.kind(), t.bytes().is_empty())
  };
  assert!(
    matches!(first.0, StreamKind::ResetStream { id: rid, code }
      if rid == id && code == H3Error::RequestRejected.code()),
    "the reset supersedes the queued DATA (first transmit), got {:?}",
    first.0
  );
  assert!(first.1, "a RESET_STREAM carries no bytes");
  assert!(
    conn.poll_transmit().is_none(),
    "the purged same-stream DATA is gone (only the reset remained)"
  );
}

#[test]
fn bare_tier_default_connection_type_is_small() {
  let connection_size = core::mem::size_of::<StaticConnection<Client>>();
  let request_stream_size = core::mem::size_of::<RequestStream<'static>>();
  // On the bare tier the transmit ring holds no refcounted DATA body, so the
  // connection stays under 1 KiB. `--all-features --all-targets` also compiles
  // this test on the heap tiers, where the ring additionally holds one optional
  // `DataBuf` handle per slot (for vectored zero-copy DATA), widening it; allow
  // that larger ceiling there. Both ceilings include the bounded reset-id
  // tombstone set (`RESET_CAP` ids — see `ResetTombstones`).
  #[cfg(not(any(feature = "std", feature = "alloc", feature = "no-atomic")))]
  let max_connection_size = 1024;
  #[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
  let max_connection_size = 1320;
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
