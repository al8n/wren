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

#[test]
fn parameterised_list_refuses_what_does_not_parse() {
  // A name that is not a token.
  assert_eq!(
    parameterised_list([b"ext@1".as_slice()])
      .next()
      .unwrap()
      .unwrap_err(),
    ListError::NotAToken
  );
  // An unterminated quoted string.
  assert_eq!(
    parameterised_list([b"ext; q=\"unterminated".as_slice()])
      .next()
      .unwrap()
      .unwrap()
      .params()
      .next()
      .unwrap()
      .unwrap_err(),
    ListError::UnterminatedQuotedString
  );
  // A parameter name that is not a token.
  assert_eq!(
    parameterised_list([b"ext; @=1".as_slice()])
      .next()
      .unwrap()
      .unwrap()
      .params()
      .next()
      .unwrap()
      .unwrap_err(),
    ListError::NotAToken
  );
}

// A quoted-string that crosses the §5.2 join and is STILL open when the last
// field line ends is `UnterminatedQuotedString`, and NOT `ValueSpansFieldLines`.
// The two are not interchangeable: `ValueSpansFieldLines` says the value is well
// formed and merely not one slice, because it closed on a later line, while this
// one closes nowhere and §5.2 has no further line to continue it with — a §5.6.4
// violation. Collapsing them reports a broken value as a borrowing limitation.
#[test]
fn a_quoted_value_that_crosses_the_join_and_never_closes_is_unterminated() {
  let lines: [&[u8]; 2] = [b"ext; q=\"a", b"b"];
  let mut members = parameterised_list(lines);
  let member = members.next().unwrap().unwrap();
  // The boundary scan did cross the join: both lines are still ONE member.
  assert_eq!(member.name(), b"ext");
  assert_eq!(
    member.params().next().unwrap().unwrap_err(),
    ListError::UnterminatedQuotedString
  );
  assert!(members.next().is_none());
}

// RFC 9110 §5.6.6: `parameters = *( OWS ";" OWS [ parameter ] )` — the
// `[ parameter ]` is optional, so a `;` with nothing behind it states no
// parameter rather than violating the production.
#[test]
fn an_empty_parameter_is_skipped_not_a_violation() {
  let member = parameterised_list([b"ext; ; q=1;".as_slice()])
    .next()
    .unwrap()
    .unwrap();
  let mut params = member.params();
  assert!(matches!(
    params.next().unwrap(),
    Ok((b"q", ParamValue::Token(b"1")))
  ));
  assert!(params.next().is_none());

  let member = parameterised_list([b"ext;;".as_slice()])
    .next()
    .unwrap()
    .unwrap();
  assert_eq!(member.name(), b"ext");
  assert!(member.params().next().is_none());
}

#[test]
fn a_supplied_predicate_admits_a_name_is_token_refuses() {
  fn solidus_ok(name: &[u8]) -> bool {
    match name.iter().position(|b| *b == b'/') {
      Some(at) => match (name.get(..at), name.get(at.saturating_add(1)..)) {
        (Some(ty), Some(sub)) => is_token(ty) && is_token(sub),
        _ => false,
      },
      None => false,
    }
  }

  // `is_token` refuses this today, which is the whole of issue #42.
  assert!(!is_token(b"application/json"));

  let mut walk =
    parameterised_list_with([b"application/json;charset=utf-8".as_slice()], solidus_ok);
  let member = walk
    .next()
    .expect("one member")
    .expect("the predicate admits it");
  assert_eq!(member.name(), b"application/json");
  let mut params = member.params();
  assert!(matches!(
    params.next().expect("one parameter").expect("well formed"),
    (b"charset", ParamValue::Token(b"utf-8"))
  ));
  assert!(params.next().is_none());
  assert!(walk.next().is_none());
}

#[test]
fn parameterised_list_still_refuses_a_non_token_name() {
  let mut walk = parameterised_list([b"application/json".as_slice()]);
  assert_eq!(
    walk.next().expect("one member").unwrap_err(),
    ListError::NotAToken
  );
}

#[test]
fn has_bare_comma_ignores_a_comma_inside_a_quoted_string() {
  assert!(!has_bare_comma(b"text/plain;boundary=\"a,b\""));
  assert!(has_bare_comma(b"text/plain, text/html"));
  assert!(has_bare_comma(b"text/plain,"));
  assert!(!has_bare_comma(b"text/plain"));
}

#[test]
fn a_token_and_a_missing_value_unescape_to_themselves() {
  assert!(
    ParamValue::Token(b"utf-8")
      .unescaped()
      .eq(b"utf-8".iter().copied())
  );
  assert_eq!(ParamValue::None.unescaped().count(), 0);
}

#[test]
fn unescape_into_writes_nothing_when_the_slice_is_short() {
  let v = ParamValue::Quoted(br#"a\"b"#);
  let mut out = [0xAAu8; 2];
  assert_eq!(
    v.unescape_into(&mut out),
    Err(BufferTooSmall { need: 3, have: 2 })
  );
  assert_eq!(out, [0xAA, 0xAA], "a failed call must not have written");

  // The EXACT fit, `need == out.len()`: the boundary between the two arms, and
  // the seat an off-by-one in a two-pass buffer API takes.
  let mut out = [0xAAu8; 3];
  assert_eq!(v.unescape_into(&mut out), Ok(3));
  assert_eq!(out, *br#"a"b"#);

  let mut out = [0u8; 8];
  assert_eq!(v.unescape_into(&mut out), Ok(3));
  assert_eq!(out.get(..3), Some(br#"a"b"#.as_slice()));
}

#[test]
fn eq_unescaped_answers_the_charset_question_without_a_buffer() {
  assert!(ParamValue::Quoted(b"UTF-8").eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(ParamValue::Quoted(br#"utf\-8"#).eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(ParamValue::Token(b"utf-8").eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(!ParamValue::Quoted(b"utf-8").eq_unescaped_ignore_ascii_case("utf-88"));
  assert!(!ParamValue::Quoted(b"utf-88").eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(ParamValue::None.eq_unescaped_ignore_ascii_case(""));
  assert!(!ParamValue::None.eq_unescaped_ignore_ascii_case("x"));
}

// RFC 9110 §7.8's `Upgrade = #protocol` asked of a SENDER, which §5.6.1.1
// makes a stricter question than the same production asked of a recipient: "In
// any production that uses the list construct, a sender MUST NOT generate empty
// list elements". The three shapes an empty element takes — leading, trailing
// and doubled — are each refused, and each of them passed while this walk took
// its elements from `list_elements`.
#[test]
fn a_sender_may_not_generate_an_empty_protocol_list_element() {
  for bad in [
    &b""[..],
    b",",
    b",websocket",
    b"websocket,",
    b"a,,b",
    b"websocket, ,h2c",
  ] {
    assert!(!is_protocol_list(bad), "{bad:?} must not be sendable");
  }
  for good in [&b"websocket"[..], b"a,b", b"websocket, h2c", b"HTTP/1.1"] {
    assert!(is_protocol_list(good), "{good:?} must be sendable");
  }
}

// The RECIPIENT half of the same production, and the asymmetry is normative:
// §5.6.1.2 has a recipient "parse and ignore a reasonable number of empty list
// elements", so the values above that a sender may not write are values a
// recipient must still read.
#[test]
fn a_recipient_reads_the_empty_elements_a_sender_may_not_write() {
  for tolerated in [&b",websocket"[..], b"websocket,", b"a,,b"] {
    assert!(
      lists_a_protocol([tolerated].into_iter()),
      "{tolerated:?} must be readable"
    );
    assert!(!is_protocol_list(tolerated), "and not writable");
  }
  // What tolerance does NOT extend to: a non-empty element that is not a
  // `protocol`, and a value that names no protocol at all.
  assert!(!lists_a_protocol([&b"web socket"[..]].into_iter()));
  assert!(!lists_a_protocol([&b","[..]].into_iter()));
}

// The comparison `ParamValue` does not derive, written the way its own doc
// directs a caller — beside `MediaType`'s and `MediaRange`'s equivalents in
// `media::tests`, and for the same reason. RFC 9110 §5.6.6: "A parameter value
// that matches the token production can be transmitted either as a token or
// within a quoted-string.  The quoted and unquoted values are equivalent." The
// derive answered `false` for exactly the spellings that sentence equates.
#[test]
fn one_parameter_value_written_two_ways_is_compared_unescaped() {
  fn value(field: &[u8]) -> ParamValue<'_> {
    parameterised_list([field])
      .next()
      .expect("one member")
      .expect("well formed")
      .params()
      .next()
      .expect("one parameter")
      .expect("well formed")
      .1
  }

  // §5.6.6's own equivalence: one value, as a `token` and inside a
  // `quoted-string`. Two variants, which is half of what the derive compared.
  let token = value(b"ext; charset=utf-8");
  let quoted = value(b"ext; charset=\"utf-8\"");
  assert!(matches!(token, ParamValue::Token(b"utf-8")));
  assert!(matches!(quoted, ParamValue::Quoted(b"utf-8")));
  assert!(token.unescaped().eq(quoted.unescaped()));

  // §5.6.4's `quoted-pair` MUST spells the same value a third way, and this
  // pair differs in the BYTES the derive compared rather than in the variant.
  let escaped = value(b"ext; charset=\"utf\\-8\"");
  assert!(matches!(escaped, ParamValue::Quoted(b"utf\\-8")));
  assert!(escaped.unescaped().eq(token.unescaped()));
  assert!(escaped.unescaped().eq(quoted.unescaped()));
}

// And the comparison `ListMember` does not derive. `params` is the untrimmed
// remainder after the member's first `;`, so the `OWS` §5.6.6's
// `parameters = *( OWS ";" OWS [ parameter ] )` puts around that `;` sat in the
// bytes the derive compared, and these two members differ in nothing else.
#[test]
fn one_list_member_written_two_ways_is_compared_by_its_pieces() {
  fn member(field: &[u8]) -> ListMember<'_> {
    parameterised_list([field])
      .next()
      .expect("one member")
      .expect("well formed")
  }

  let tight = member(b"ext;q=1");
  let spaced = member(b"ext;  q=1");
  assert!(tight.name().eq_ignore_ascii_case(spaced.name()));
  for (a, b) in tight.params().zip(spaced.params()) {
    let (a_name, a_value) = a.expect("well formed");
    let (b_name, b_value) = b.expect("well formed");
    assert!(a_name.eq_ignore_ascii_case(b_name));
    assert!(a_value.unescaped().eq(b_value.unescaped()));
  }
  assert_eq!(tight.params().count(), 1);
  assert_eq!(tight.params().count(), spaced.params().count());
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

  // RFC 6455 §9.1: extension-list is a #-list of extensions, each with
  // `token [ "=" ( token / quoted-string ) ]` parameters.
  #[test]
  fn parameterised_list_keeps_quoted_separators_inside_their_string() {
    let v = b"permessage-deflate; client_max_window_bits=10, x-private; note=\"a,b;c\"";
    let members: Vec<_> = parameterised_list([v.as_slice()])
      .map(|m| m.unwrap())
      .collect();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].name(), b"permessage-deflate");
    assert_eq!(members[1].name(), b"x-private");

    let p0: Vec<_> = members[0].params().map(|p| p.unwrap()).collect();
    assert!(matches!(
      p0[..],
      [(b"client_max_window_bits", ParamValue::Token(b"10"))]
    ));

    let p1: Vec<_> = members[1].params().map(|p| p.unwrap()).collect();
    assert!(matches!(p1[..], [(b"note", ParamValue::Quoted(b"a,b;c"))]));
  }

  // RFC 9110 §5.6.4: a backslash escapes the next character inside a
  // quoted-string.
  #[test]
  fn parameterised_list_carries_escapes_through() {
    let v = b"ext; q=\"a\\\"b\"";
    let m = parameterised_list([v.as_slice()]).next().unwrap().unwrap();
    let p: Vec<_> = m.params().map(|p| p.unwrap()).collect();
    assert!(matches!(p[..], [(b"q", ParamValue::Quoted(b"a\\\"b"))]));
  }

  // RFC 9110 §5.6.1.2: a recipient ignores empty list elements.
  #[test]
  fn parameterised_list_ignores_empty_elements() {
    let v = b", ext ,, other,";
    let names: Vec<_> = parameterised_list([v.as_slice()])
      .map(|m| m.unwrap().name().to_vec())
      .collect();
    assert_eq!(names, [b"ext".to_vec(), b"other".to_vec()]);
  }

  // RFC 6455 §9.1 permits splitting the field across lines; RFC 9110 §5.2 makes
  // them one comma-joined value.
  #[test]
  fn a_list_split_across_field_lines_is_one_list() {
    let lines: [&[u8]; 2] = [
      b"permessage-deflate; server_no_context_takeover",
      b"x-private",
    ];
    let names: Vec<_> = parameterised_list(lines)
      .map(|m| m.unwrap().name().to_vec())
      .collect();
    assert_eq!(
      names,
      [b"permessage-deflate".to_vec(), b"x-private".to_vec()]
    );
  }

  // The §5.2 join's comma is DATA inside an open quoted-string
  // (`grammar::scan_quoted_after_join`): the two lines are ONE member, and the
  // member after it is found at the right place. The spanning VALUE is not one
  // slice, so reading it is a named refusal rather than a mis-slice.
  #[test]
  fn a_quoted_value_spanning_the_join_keeps_the_boundaries_and_refuses_the_value() {
    let lines: [&[u8]; 2] = [b"ext; q=\"a", b"b\", other"];
    let members: Vec<_> = parameterised_list(lines).collect();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].as_ref().unwrap().name(), b"ext");
    assert_eq!(members[1].as_ref().unwrap().name(), b"other");
    let p = members[0].unwrap().params().next().unwrap();
    assert_eq!(p.unwrap_err(), ListError::ValueSpansFieldLines);
  }

  #[test]
  fn unescaping_removes_the_backslash_and_keeps_the_octet() {
    let v = ParamValue::Quoted(br#"a\"b\\c"#);
    let got: Vec<u8> = v.unescaped().collect();
    assert_eq!(got.as_slice(), br#"a"b\c"#);
  }
}
