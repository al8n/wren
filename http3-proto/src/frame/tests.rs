use super::*;

#[test]
fn encode_decode_header() {
  // DATA frame with a 5-byte payload: type=0x00, len=0x05.
  let mut buf = [0u8; 16];
  let n = encode_header(FrameType::Data, 5, &mut buf).unwrap();
  assert_eq!(&buf[..n], &[0x00, 0x05]);
  let (consumed, hdr) = decode_header(&buf[..n]).unwrap();
  assert_eq!(consumed, 2);
  assert_eq!(hdr.kind(), FrameKind::Data);
  assert_eq!(hdr.length(), 5);
}

#[test]
fn settings_and_headers_types() {
  let mut buf = [0u8; 16];
  let n = encode_header(FrameType::Settings, 0, &mut buf).unwrap();
  assert_eq!(
    decode_header(&buf[..n]).unwrap().1.kind(),
    FrameKind::Settings
  );
  let n = encode_header(FrameType::Headers, 3, &mut buf).unwrap();
  assert_eq!(
    decode_header(&buf[..n]).unwrap().1.kind(),
    FrameKind::Headers
  );
}

#[test]
fn grease_decodes_as_unknown() {
  // GREASE type 0x21 (= 0x1f*0 + 0x21), length 0: an unknown extension.
  let (_, hdr) = decode_header(&[0x21, 0x00]).unwrap();
  assert_eq!(hdr.kind(), FrameKind::Unknown);
  assert!(hdr.kind().is_unknown());
}

#[test]
fn known_control_frames_decode_to_their_kind() {
  // CANCEL_PUSH (0x03), GOAWAY (0x07), MAX_PUSH_ID (0x0d), PUSH_PROMISE (0x05)
  // each decode to their own distinct kind rather than a shared catch-all.
  assert_eq!(
    decode_header(&[0x03, 0x00]).unwrap().1.kind(),
    FrameKind::CancelPush
  );
  assert_eq!(
    decode_header(&[0x07, 0x00]).unwrap().1.kind(),
    FrameKind::GoAway
  );
  assert_eq!(
    decode_header(&[0x0d, 0x00]).unwrap().1.kind(),
    FrameKind::MaxPushId
  );
  assert_eq!(
    decode_header(&[0x05, 0x00]).unwrap().1.kind(),
    FrameKind::PushPromise
  );
}

#[test]
fn http2_reserved_frame_types_decode_as_reserved() {
  // The HTTP/2-reserved frame types (RFC 9114 §7.2.8): 0x02, 0x06, 0x08, 0x09.
  for ty in [0x02u8, 0x06, 0x08, 0x09] {
    let (_, hdr) = decode_header(&[ty, 0x00]).unwrap();
    assert_eq!(hdr.kind(), FrameKind::Reserved, "type {ty:#x}");
    assert!(hdr.kind().is_reserved());
  }
}

#[test]
fn frame_kind_as_str() {
  assert_eq!(FrameKind::Data.as_str(), "DATA");
  assert_eq!(FrameKind::Reserved.as_str(), "RESERVED");
  assert_eq!(FrameKind::GoAway.as_str(), "GOAWAY");
  assert_eq!(FrameKind::Unknown.as_str(), "UNKNOWN");
}

#[test]
fn decode_header_truncated() {
  assert!(matches!(decode_header(&[]), Err(FrameError::Truncated(_))));
  assert!(matches!(
    decode_header(&[0x00]),
    Err(FrameError::Truncated(_))
  )); // type but no length
}

#[test]
fn multi_byte_length_roundtrips() {
  // length 16384 needs a 4-byte varint; type DATA needs 1 → 5-byte header.
  let mut buf = [0u8; 16];
  let n = encode_header(FrameType::Data, 16384, &mut buf).unwrap();
  assert_eq!(n, 5);
  let (consumed, hdr) = decode_header(&buf[..n]).unwrap();
  assert_eq!(consumed, 5);
  assert_eq!((hdr.kind(), hdr.length()), (FrameKind::Data, 16384));
}

#[test]
fn multi_byte_type_decodes_as_unknown() {
  // Type 64 encoded as a 2-byte varint [0x40, 0x40], length 0 → Unknown.
  let (consumed, hdr) = decode_header(&[0x40, 0x40, 0x00]).unwrap();
  assert_eq!(consumed, 3);
  assert_eq!(hdr.kind(), FrameKind::Unknown);
}

#[test]
fn encode_header_rejects_small_buffer() {
  // 1-byte buffer holds the type varint but not the length varint.
  let mut buf = [0u8; 1];
  assert!(matches!(
    encode_header(FrameType::Data, 5, &mut buf),
    Err(FrameError::Varint(VarintError::Buffer(_)))
  ));
}
