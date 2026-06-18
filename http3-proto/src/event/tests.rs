use super::*;

#[test]
fn stream_id_roundtrips() {
  assert_eq!(StreamId::new(7).get(), 7);
}

#[test]
fn transmit_accessors() {
  let t = Transmit::new(StreamKind::OpenRequest, b"hi", true);
  assert_eq!(t.kind(), StreamKind::OpenRequest);
  assert_eq!(t.bytes(), b"hi");
  assert!(t.fin());
  // A `new` transmit is single-segment: one slice, `bytes()` == segment 0.
  assert_eq!(t.segments(), &[b"hi".as_slice()]);
  assert_eq!(t.len(), 2);
  assert!(!t.is_empty());
}

#[test]
fn vectored_transmit_segments_and_len() {
  let header = b"\x00\x05";
  let body = b"hello";
  let t = Transmit::with_segments(
    StreamKind::Existing(StreamId::new(2)),
    [header.as_slice(), body.as_slice()],
    2,
    false,
  );
  let segs = t.segments();
  assert_eq!(segs.len(), 2);
  assert_eq!(segs[0], header);
  assert_eq!(segs[1], body);
  // `bytes()` stays the single-segment view (segment 0 = the frame header).
  assert_eq!(t.bytes(), header);
  assert_eq!(t.len(), header.len() + body.len());
  assert!(!t.is_empty());
}

#[test]
fn vectored_transmit_seg_count_is_clamped() {
  // An out-of-range `seg_count` cannot widen the exposed slice past the array.
  let t = Transmit::with_segments(StreamKind::OpenRequest, [b"a", b"b"], 9, false);
  assert_eq!(t.segments().len(), 2);
}

#[test]
fn empty_transmit_is_empty() {
  let t = Transmit::new(StreamKind::Existing(StreamId::new(1)), &[], true);
  assert!(t.is_empty());
  assert_eq!(t.len(), 0);
  assert!(t.fin());
}

#[test]
fn stream_role_as_str_and_predicates() {
  assert_eq!(StreamRole::Request.as_str(), "request");
  assert_eq!(StreamRole::QpackEncOut.as_str(), "qpack_enc_out");
  assert!(StreamRole::ControlOut.is_control_out());
  assert!(!StreamRole::ControlOut.is_request());
}

#[test]
fn stream_kind_and_event_predicates() {
  assert!(StreamKind::OpenRequest.is_open_request());
  assert!(StreamKind::Existing(StreamId::new(1)).is_existing());
  assert!(Event::Established.is_established());
  assert!(Event::Reset(7).is_reset());
  assert!(!Event::PeerClosed.is_established());
  assert!(Event::PeerClosed.is_peer_closed());
}

#[test]
fn reset_stream_kind_carries_id_and_code() {
  let kind = StreamKind::ResetStream {
    id: StreamId::new(4),
    code: 0x010e,
  };
  assert!(kind.is_reset_stream());
  assert!(!kind.is_existing());
  // A RESET_STREAM transmit carries no bytes and is not a FIN (the driver issues a QUIC
  // reset instead of a write).
  let t = Transmit::new(kind, &[], false);
  assert!(t.bytes().is_empty());
  assert!(!t.fin());
  assert!(matches!(
    t.kind(),
    StreamKind::ResetStream { id, code } if id == StreamId::new(4) && code == 0x010e
  ));
}

#[test]
fn transmit_without_fin() {
  let t = Transmit::new(StreamKind::Existing(StreamId::new(3)), b"data", false);
  assert!(!t.fin());
  assert_eq!(t.bytes(), b"data");
  assert!(t.kind().is_existing());
}
