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
}

#[test]
fn transmit_without_fin() {
  let t = Transmit::new(StreamKind::Existing(StreamId::new(3)), b"data", false);
  assert!(!t.fin());
  assert_eq!(t.bytes(), b"data");
  assert!(t.kind().is_existing());
}
