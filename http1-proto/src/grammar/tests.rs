use super::*;

// RFC 9110 §5.6.2: tchar set exactness — probe boundaries.
#[test]
fn tchar_boundaries() {
  // `!#$%&'*+-.^_`|~` plus the digit/alpha range edges — spelled as a byte
  // string because every probe here is printable (clippy::byte_char_slices).
  for b in *b"!#$%&'*+-.^_`|~09azAZ" {
    assert!(is_token_byte(b), "{b:#x} must be tchar");
  }
  for b in [
    b' ', b'\t', b'"', b'(', b')', b',', b'/', b':', b';', b'<', b'=', b'>', b'?', b'@', b'[',
    b'\\', b']', b'{', b'}', 0x7F, 0x00, 0x80,
  ] {
    assert!(!is_token_byte(b), "{b:#x} must NOT be tchar");
  }
}

// RFC 9110 §5.5: obs-text (0x80-0xFF) IS valid field content; CTLs are not.
#[test]
fn field_value_accepts_obs_text_rejects_ctls() {
  assert!(validate_field_value(b"caf\xC3\xA9").is_ok()); // UTF-8 bytes
  assert!(validate_field_value(b"\xFF\x80").is_ok()); // raw obs-text
  assert!(validate_field_value(b"a b\tc").is_ok()); // interior SP/HTAB
  assert_eq!(validate_field_value(b"a\x00b"), Err(1)); // NUL
  assert_eq!(validate_field_value(b"a\x0Bb"), Err(1)); // VT
  assert_eq!(validate_field_value(b"a\rb"), Err(1)); // bare CR
  assert_eq!(validate_field_value(b"a\nb"), Err(1)); // bare LF
}

// RFC 9110 §5.6.3: OWS surrounds a field value; it is not part of the value.
#[test]
fn trim_ows_both_ends_only() {
  assert_eq!(trim_ows(b" \t v v \t "), b"v v");
  assert_eq!(trim_ows(b""), b"");
  assert_eq!(trim_ows(b" \t "), b"");
}

// RFC 9110 §5.6.1: case-insensitive token comparison (Connection/Upgrade/TE).
#[test]
fn token_list_contains_is_case_insensitive() {
  assert!(token_list_contains(b"Keep-Alive, Upgrade", "upgrade"));
  assert!(!token_list_contains(b"keep-alive-x", "keep-alive"));
}

// Ported validators keep behavior: spot-check + boundary cases.
#[test]
fn ported_target_validators() {
  assert!(is_valid_path_and_query("/chat?x=1"));
  assert!(!is_valid_path_and_query("/sp ace"));
  assert!(is_valid_authority("example.com:443"));
  assert!(is_valid_authority("[::1]:8080"));
  assert!(!is_valid_authority("bad host"));
}

/// Tests that collect into a `Vec`: gated to the tiers that have a heap, since
/// the bare `no_std` tier has neither an allocator nor the `alloc as std` alias.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
mod heap {
  use crate::grammar::*;
  use std::vec::Vec;

  // RFC 9110 §5.6.1 #-list over bytes.
  #[test]
  fn list_elements_splits_and_skips_empties() {
    let v: Vec<&[u8]> = list_elements(b" chunked ,, gzip,x ").collect();
    assert_eq!(
      v,
      [b"chunked".as_slice(), b"gzip".as_slice(), b"x".as_slice()]
    );
  }
}
