/// RFC 6455 §4.2.2 — the GUID appended to `Sec-WebSocket-Key` before SHA-1
/// hashing to derive `Sec-WebSocket-Accept`.
pub const WEBSOCKET_GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// RFC 6455 §4.1 — the only WebSocket protocol version this crate implements,
/// as the header value string.
pub const WEBSOCKET_VERSION: &str = "13";

/// RFC 6455 §5.5 — the maximum payload length of a control frame
/// (close / ping / pong).
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// RFC 6455 §5.2 — the maximum encoded frame-header size: 2 fixed bytes,
/// up to 8 extended-payload-length bytes, up to 4 masking-key bytes.
pub const MAX_FRAME_HEADER: usize = 14;

/// RFC 6455 §4.1 — the length of a `Sec-WebSocket-Key` value: the base64
/// encoding of a 16-byte nonce, including padding.
pub const SEC_WEBSOCKET_KEY_LEN: usize = 24;

/// RFC 6455 §4.2.2 — the length of a `Sec-WebSocket-Accept` value: the base64
/// encoding of a 20-byte SHA-1 digest, including padding.
pub const SEC_WEBSOCKET_ACCEPT_LEN: usize = 28;

#[cfg(all(test, feature = "std"))]
mod tests {
  use super::*;

  #[test]
  fn guid_matches_rfc6455_4_2_2() {
    assert_eq!(WEBSOCKET_GUID, b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    assert_eq!(WEBSOCKET_GUID.len(), 36);
  }

  #[test]
  fn frame_limits_match_rfc6455_5() {
    assert_eq!(MAX_CONTROL_PAYLOAD, 125);
    // 2 fixed + 8 extended-length + 4 masking key.
    assert_eq!(MAX_FRAME_HEADER, 14);
  }

  #[test]
  fn handshake_lengths_match_rfc6455_4() {
    assert_eq!(WEBSOCKET_VERSION, "13");
    // base64(16 bytes) and base64(20 bytes), padded.
    assert_eq!(SEC_WEBSOCKET_KEY_LEN, 24);
    assert_eq!(SEC_WEBSOCKET_ACCEPT_LEN, 28);
  }
}
