//! The media surface is reachable from the crate root, and the pieces issue
//! #42 asked for compose without a caller re-reading any bytes.

use http1_proto::{MediaType, Weight, media_type, validate::parse_content_length, weight_for};

#[test]
fn a_graphql_over_http_server_can_discriminate_its_two_types() {
  let accept = b"application/graphql-response+json;q=0.9, application/json;q=0.5";
  let candidates = [
    b"application/graphql-response+json".as_slice(),
    b"application/json",
  ];
  let best = candidates
    .iter()
    .filter_map(|c| media_type(c).ok())
    .max_by_key(|m| weight_for(m, [accept.as_slice()]).unwrap_or(Weight::ZERO))
    .expect("one candidate parses");
  assert_eq!(best.subtype(), "graphql-response+json");
}

#[test]
fn content_length_is_reachable() {
  assert_eq!(parse_content_length(b"1024"), Ok(1024));
  assert!(parse_content_length(b"10 24").is_err());
}

#[test]
fn a_content_type_carries_its_charset() {
  let m: MediaType<'_> = media_type(b"text/html;charset=\"utf-8\"").expect("valid");
  let charset = m
    .params()
    .filter_map(Result::ok)
    .find(|(name, _)| name.eq_ignore_ascii_case(b"charset"))
    .map(|(_, value)| value)
    .expect("a charset");
  assert!(charset.eq_unescaped_ignore_ascii_case("UTF-8"));
}
