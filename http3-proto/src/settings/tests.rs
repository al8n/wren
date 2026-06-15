use super::*;

#[test]
fn encode_then_decode_roundtrip() {
  let ours = Settings::for_server(); // enable_connect_protocol = true
  let mut buf = [0u8; 64];
  let n = ours.encode_payload(&mut buf).unwrap();
  let got = Settings::decode_payload(&buf[..n]).unwrap();
  assert!(got.enable_connect_protocol());
  assert_eq!(got.qpack_max_table_capacity(), 0);
}

#[test]
fn client_settings_omit_connect_protocol() {
  assert!(!Settings::for_client().enable_connect_protocol());
}

#[test]
fn server_payload_contains_enable_connect_protocol() {
  let mut buf = [0u8; 64];
  let n = Settings::for_server().encode_payload(&mut buf).unwrap();
  // ENABLE_CONNECT_PROTOCOL (0x08) = 1 (0x01), both single-byte varints.
  assert!(buf[..n].windows(2).any(|w| w == [0x08, 0x01]));
}

#[test]
fn duplicate_setting_is_error() {
  // two QPACK_MAX_TABLE_CAPACITY (0x01) entries.
  assert!(matches!(
    Settings::decode_payload(&[0x01, 0x00, 0x01, 0x00]),
    Err(SettingsError::Duplicate(_))
  ));
}

#[test]
fn unknown_setting_ignored() {
  // id 0x21 (GREASE) value 0 — ignored, leaves defaults.
  let got = Settings::decode_payload(&[0x21, 0x00]).unwrap();
  assert!(!got.enable_connect_protocol());
}

#[test]
fn reserved_http2_setting_is_error() {
  // 0x02 (HTTP/2 SETTINGS_ENABLE_PUSH) is reserved in HTTP/3.
  assert!(matches!(
    Settings::decode_payload(&[0x02, 0x00]),
    Err(SettingsError::Reserved(_))
  ));
}

#[test]
fn truncated_payload_is_error() {
  // identifier present, value missing.
  assert!(matches!(
    Settings::decode_payload(&[0x01]),
    Err(SettingsError::Truncated(_))
  ));
}

#[test]
fn decodes_max_field_section_size() {
  // id 0x06, value 63 (single-byte varint 0x3f).
  let got = Settings::decode_payload(&[0x06, 0x3f]).unwrap();
  assert_eq!(got.max_field_section_size(), Some(63));
}

#[test]
fn all_reserved_http2_settings_rejected() {
  for id in [0x02u8, 0x03, 0x04, 0x05] {
    assert!(
      matches!(
        Settings::decode_payload(&[id, 0x00]),
        Err(SettingsError::Reserved(_))
      ),
      "id {id:#x} should be reserved"
    );
  }
  // Boundary: 0x01 and 0x06 are valid HTTP/3 identifiers, NOT reserved.
  assert!(Settings::decode_payload(&[0x01, 0x00]).is_ok());
  assert!(Settings::decode_payload(&[0x06, 0x00]).is_ok());
}

#[test]
fn client_payload_exact_bytes() {
  // for_client encodes exactly QPACK_MAX_TABLE_CAPACITY=0, QPACK_BLOCKED_STREAMS=0;
  // it must NOT contain ENABLE_CONNECT_PROTOCOL (0x08).
  let mut buf = [0u8; 64];
  let n = Settings::for_client().encode_payload(&mut buf).unwrap();
  assert_eq!(&buf[..n], &[0x01, 0x00, 0x07, 0x00]);
}

#[test]
fn client_roundtrip_and_connect_protocol_values() {
  let mut buf = [0u8; 64];
  let n = Settings::for_client().encode_payload(&mut buf).unwrap();
  let got = Settings::decode_payload(&buf[..n]).unwrap();
  assert!(!got.enable_connect_protocol());
  assert_eq!(got.max_field_section_size(), None);
  // Explicit enable / disable, plus the documented lenient handling of an
  // out-of-range value (RFC 8441 says 0 or 1; we treat >1 as disabled, no error).
  assert!(
    Settings::decode_payload(&[0x08, 0x01])
      .unwrap()
      .enable_connect_protocol()
  );
  assert!(
    !Settings::decode_payload(&[0x08, 0x00])
      .unwrap()
      .enable_connect_protocol()
  );
  assert!(
    !Settings::decode_payload(&[0x08, 0x02])
      .unwrap()
      .enable_connect_protocol()
  );
}

#[test]
fn encode_rejects_small_buffer() {
  assert!(
    Settings::for_server()
      .encode_payload(&mut [0u8; 1])
      .is_err()
  );
}
