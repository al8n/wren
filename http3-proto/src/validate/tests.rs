use super::*;
use crate::qpack::{decode_field_section_into, encode_field_section_from};

/// QPACK-encodes `pairs` into a fresh section buffer (static-only encoder; literal
/// names emitted verbatim, so uppercase names survive for the validator to reject).
fn section(pairs: &[(&str, &str)]) -> std::vec::Vec<u8> {
  let mut buf = std::vec![0u8; 4096];
  let (n, _) = encode_field_section_from(pairs, buf.as_mut_slice(), None).expect("encode");
  buf.truncate(n);
  buf
}

/// Encodes, decodes, then validates `pairs` under `kind`.
fn check(kind: MessageKind, pairs: &[(&str, &str)]) -> Result<(), H3Error> {
  let bytes = section(pairs);
  let mut scratch = std::vec![0u8; 4096];
  let mut hs = decode_field_section_into(&bytes, scratch.as_mut_slice()).expect("decode");
  validate(kind, &mut hs)
}

// ── requests ────────────────────────────────────────────────────────────────

#[test]
fn valid_get_request_ok() {
  assert!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        (":authority", "x")
      ]
    )
    .is_ok()
  );
}

#[test]
fn get_request_without_authority_ok() {
  // :authority is optional for a normal method.
  assert!(
    check(
      MessageKind::Request,
      &[(":method", "GET"), (":scheme", "https"), (":path", "/")]
    )
    .is_ok()
  );
}

#[test]
fn request_missing_method_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[(":scheme", "https"), (":path", "/")]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn request_missing_scheme_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[(":method", "GET"), (":path", "/"), (":authority", "x")]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn request_missing_path_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "x")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn request_with_status_is_error() {
  // A response pseudo-header must not appear in a request.
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        (":status", "200")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn request_with_unknown_pseudo_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        (":bogus", "x")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn normal_method_with_protocol_is_error() {
  // :protocol is only valid with CONNECT (Extended CONNECT).
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        (":protocol", "websocket")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn connect_with_scheme_is_error() {
  // Plain CONNECT must NOT carry :scheme / :path.
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "CONNECT"),
        (":authority", "x"),
        (":scheme", "https")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn connect_with_path_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[(":method", "CONNECT"), (":authority", "x"), (":path", "/")]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn connect_missing_authority_is_error() {
  assert_eq!(
    check(MessageKind::Request, &[(":method", "CONNECT")]).unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn plain_connect_ok() {
  assert!(
    check(
      MessageKind::Request,
      &[(":method", "CONNECT"), (":authority", "x")]
    )
    .is_ok()
  );
}

#[test]
fn extended_connect_requires_protocol_and_scheme_path() {
  assert!(
    check(
      MessageKind::Request,
      &[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":path", "/"),
        (":authority", "x")
      ]
    )
    .is_ok()
  );
}

#[test]
fn extended_connect_missing_scheme_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":path", "/"),
        (":authority", "x")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

/// The WS tunnel's exact Extended-CONNECT handshake (mirrors `connection::tests`
/// `CONNECT_REQUEST` / `tiers::REQUEST_HEADERS`) must validate clean, or the
/// tunnel suite regresses.
#[test]
fn tunnel_extended_connect_handshake_ok() {
  assert!(
    check(
      MessageKind::Request,
      &[
        (":method", "CONNECT"),
        (":protocol", "websocket"),
        (":scheme", "https"),
        (":path", "/chat"),
        (":authority", "example.com")
      ]
    )
    .is_ok()
  );
}

#[test]
fn pseudo_after_regular_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        ("x-foo", "bar"),
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn duplicate_method_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":method", "POST"),
        (":scheme", "https"),
        (":path", "/")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn request_with_regular_field_ok() {
  // A normal lowercase regular field after the pseudo-headers is fine.
  assert!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        ("user-agent", "x")
      ]
    )
    .is_ok()
  );
}

// ── field rules (§4.2) ────────────────────────────────────────────────────────

#[test]
fn connection_specific_field_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        ("connection", "keep-alive")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn transfer_encoding_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        ("transfer-encoding", "chunked")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn te_must_be_trailers() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        ("te", "gzip")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
  assert!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        ("te", "trailers")
      ]
    )
    .is_ok()
  );
}

#[test]
fn uppercase_field_name_is_error() {
  assert_eq!(
    check(
      MessageKind::Request,
      &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/"),
        ("X-Foo", "bar")
      ]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

// ── responses ─────────────────────────────────────────────────────────────────

#[test]
fn response_requires_status() {
  assert_eq!(
    check(MessageKind::Response, &[("content-type", "text/plain")]).unwrap_err(),
    H3Error::MessageError
  );
  assert!(check(MessageKind::Response, &[(":status", "200")]).is_ok());
}

#[test]
fn response_with_regular_field_ok() {
  assert!(
    check(
      MessageKind::Response,
      &[(":status", "200"), ("sec-websocket-accept", "abc")]
    )
    .is_ok()
  );
}

#[test]
fn response_with_request_pseudo_is_error() {
  assert_eq!(
    check(
      MessageKind::Response,
      &[(":status", "200"), (":method", "GET")]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn duplicate_status_is_error() {
  assert_eq!(
    check(
      MessageKind::Response,
      &[(":status", "200"), (":status", "201")]
    )
    .unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn final_response_with_interim_status_is_error() {
  // A 1xx status in a final-response context is rejected.
  assert_eq!(
    check(MessageKind::Response, &[(":status", "100")]).unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn interim_response_ok() {
  assert!(check(MessageKind::Interim, &[(":status", "103")]).is_ok());
}

#[test]
fn interim_response_with_final_status_is_error() {
  assert_eq!(
    check(MessageKind::Interim, &[(":status", "200")]).unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn response_with_out_of_range_status_is_error() {
  assert_eq!(
    check(MessageKind::Response, &[(":status", "99")]).unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn response_with_non_numeric_status_is_error() {
  assert_eq!(
    check(MessageKind::Response, &[(":status", "ok")]).unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn strict_status_rejects_non_3xx_digit_shapes() {
  // A valid `:status` is EXACTLY three ASCII digits in `100..=599`. Everything
  // else is `MessageError`, regardless of the response context (final or interim).
  // - `999`: three digits but out of class (`> 599`).
  // - `1000`: four digits — too long, even though it parses as an integer.
  // - `0200`: a leading-zero four-char form that an integer parse would read as
  //   `200`; the three-digit shape check rejects it BEFORE any range test.
  // - `099`: three digits but `< 100` (interim class starts at `100`).
  // - `2xx`: a non-digit byte in a three-char value.
  for bad in ["999", "1000", "0200", "099", "2xx"] {
    assert_eq!(
      check(MessageKind::Response, &[(":status", bad)]).unwrap_err(),
      H3Error::MessageError,
      "final-context `:status` {bad:?} must be rejected"
    );
    assert_eq!(
      check(MessageKind::Interim, &[(":status", bad)]).unwrap_err(),
      H3Error::MessageError,
      "interim-context `:status` {bad:?} must be rejected"
    );
  }
}

#[test]
fn strict_status_accepts_exactly_3_digit_in_class() {
  // The boundary values of each class: `100`/`103` interim, `200`/`599` final.
  assert!(
    check(MessageKind::Interim, &[(":status", "100")]).is_ok(),
    "100 is the first interim status"
  );
  assert!(
    check(MessageKind::Interim, &[(":status", "103")]).is_ok(),
    "103 is a valid interim status"
  );
  assert!(
    check(MessageKind::Response, &[(":status", "200")]).is_ok(),
    "200 is the first final status"
  );
  assert!(
    check(MessageKind::Response, &[(":status", "599")]).is_ok(),
    "599 is the last in-class final status"
  );
}

#[test]
fn status_is_2xx_accepts_only_3_digit_2xx() {
  // The CONNECT-acceptance classifier: exactly three ASCII digits, leading `2`.
  for ok in ["200", "201", "204", "299"] {
    assert!(status_is_2xx(ok), "{ok} is a 2xx success code");
  }
  // Interim, other final classes, and every malformed shape are NOT 2xx.
  for bad in [
    "100", "103", // interim
    "300", "404", "500", "599", // non-2xx final
    "2", "20", "2000", // wrong length
    "02x", "2x0", "0200", "099", // non-digit / leading zero
    "",    // empty
  ] {
    assert!(!status_is_2xx(bad), "{bad:?} must not classify as 2xx");
  }
}

// ── trailers ──────────────────────────────────────────────────────────────────

#[test]
fn trailers_reject_pseudo_headers() {
  assert_eq!(
    check(MessageKind::Trailers, &[(":status", "200")]).unwrap_err(),
    H3Error::MessageError
  );
  assert!(check(MessageKind::Trailers, &[("x-checksum", "abc")]).is_ok());
}

#[test]
fn trailers_reject_connection_specific() {
  assert_eq!(
    check(MessageKind::Trailers, &[("connection", "close")]).unwrap_err(),
    H3Error::MessageError
  );
}

#[test]
fn empty_trailers_ok() {
  assert!(check(MessageKind::Trailers, &[]).is_ok());
}

// ── response_is_interim ───────────────────────────────────────────────────────

#[test]
fn interim_status_detection() {
  let bytes = section(&[(":status", "103")]);
  let mut scratch = std::vec![0u8; 4096];
  let mut hs = decode_field_section_into(&bytes, scratch.as_mut_slice()).unwrap();
  assert_eq!(response_is_interim(&mut hs).unwrap(), Some(true));
}

#[test]
fn final_status_is_not_interim() {
  let bytes = section(&[(":status", "200")]);
  let mut scratch = std::vec![0u8; 4096];
  let mut hs = decode_field_section_into(&bytes, scratch.as_mut_slice()).unwrap();
  assert_eq!(response_is_interim(&mut hs).unwrap(), Some(false));
}

#[test]
fn no_status_is_none() {
  let bytes = section(&[("content-type", "text/plain")]);
  let mut scratch = std::vec![0u8; 4096];
  let mut hs = decode_field_section_into(&bytes, scratch.as_mut_slice()).unwrap();
  assert_eq!(response_is_interim(&mut hs).unwrap(), None);
}
