use super::static_table::{STATIC_TABLE, find_name, find_name_value};

#[test]
fn static_table_has_99_entries() {
  assert_eq!(STATIC_TABLE.len(), 99);
}

#[test]
fn known_static_indices() {
  // Spot-check entries the CONNECT handshake uses + transcription anchors (RFC 9204 App. A).
  assert_eq!(STATIC_TABLE[0], (":authority", ""));
  assert_eq!(STATIC_TABLE[1], (":path", "/"));
  assert_eq!(STATIC_TABLE[15], (":method", "CONNECT"));
  assert_eq!(STATIC_TABLE[17], (":method", "GET"));
  assert_eq!(STATIC_TABLE[22], (":scheme", "http"));
  assert_eq!(STATIC_TABLE[23], (":scheme", "https"));
  assert_eq!(STATIC_TABLE[25], (":status", "200"));
  // End + tricky-value anchors to lock the full transcription.
  assert_eq!(
    STATIC_TABLE[73],
    ("access-control-allow-credentials", "FALSE")
  );
  assert_eq!(
    STATIC_TABLE[85],
    (
      "content-security-policy",
      "script-src 'none'; object-src 'none'; base-uri 'none'"
    )
  );
  assert_eq!(STATIC_TABLE[98], ("x-frame-options", "sameorigin"));
}

#[test]
fn lookups() {
  assert_eq!(find_name_value(":method", "CONNECT"), Some(15));
  assert_eq!(find_name(":authority"), Some(0));
  assert_eq!(find_name_value(":protocol", "websocket"), None); // not in static table
}
