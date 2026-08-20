use super::*;

#[test]
fn qvalue_accepts_exactly_what_the_abnf_spells() {
  // `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`
  assert_eq!(parse_qvalue(b"0"), Some(Weight::ZERO));
  assert_eq!(parse_qvalue(b"1"), Some(Weight::ONE));
  assert_eq!(parse_qvalue(b"0.5"), Some(Weight(500)));
  assert_eq!(parse_qvalue(b"0.05"), Some(Weight(50)));
  assert_eq!(parse_qvalue(b"0.005"), Some(Weight(5)));
  assert_eq!(parse_qvalue(b"0.001"), Some(Weight(1)));
  assert_eq!(parse_qvalue(b"1.000"), Some(Weight::ONE));
  // `[ "." 0*3DIGIT ]` admits ZERO digits after the dot.
  assert_eq!(parse_qvalue(b"0."), Some(Weight::ZERO));
  assert_eq!(parse_qvalue(b"1."), Some(Weight::ONE));
}

#[test]
fn qvalue_refuses_what_the_abnf_does_not_spell() {
  for bad in [
    b"1.001".as_slice(), // 1 admits only zeros after the dot
    b"1.5",
    b"0.5000", // 0*3DIGIT is at most three
    b".5",     // no leading digit
    b"00.5",
    b"2",
    b"",
    b"blah",
    b"0,5",
    b"-0.5",
    b"0.5 ",
  ] {
    assert_eq!(parse_qvalue(bad), None, "{:?} is not a qvalue", bad);
  }
}

#[test]
fn weight_orders_as_the_rfc_says_it_does() {
  // RFC 9110 section 12.4.2: "0.001 is the least preferred and 1 is the most
  // preferred".
  assert!(Weight::ZERO < Weight(1));
  assert!(Weight(1) < Weight(500));
  assert!(Weight(500) < Weight::ONE);
  assert_eq!(Weight::ONE.thousandths(), 1000);
  assert_eq!(Weight::ZERO.thousandths(), 0);
}

#[test]
fn a_media_type_parses_to_its_two_tokens_and_its_parameters() {
  let m = media_type(b"application/graphql-response+json;charset=utf-8").expect("valid");
  assert_eq!(m.ty(), "application");
  assert_eq!(m.subtype(), "graphql-response+json");
  let mut params = m.params();
  assert_eq!(
    params.next().expect("one").expect("well formed"),
    (b"charset".as_slice(), ParamValue::Token(b"utf-8"))
  );
  assert!(params.next().is_none());
}

#[test]
fn content_type_refuses_a_comma_outside_a_quoted_string() {
  // RFC 9110 section 8.3 warns that recovering from a doubled Content-Type by
  // taking "the last syntactically valid member of the list" causes
  // "potential interoperability and security issues"; refusal cannot diverge.
  assert_eq!(
    media_type(b"text/plain, text/html"),
    Err(MediaError::NotASingleton)
  );
  // A trailing comma too: member-counting would call this singular, because
  // section 5.6.1.2 has the walk skip empty elements.
  assert_eq!(media_type(b"text/plain,"), Err(MediaError::NotASingleton));
  // Inside a quoted-string the comma is data.
  let m = media_type(b"multipart/form-data;boundary=\"a,b\"").expect("valid");
  assert_eq!(m.subtype(), "form-data");
}

#[test]
fn a_parameter_named_q_is_ordinary_in_a_content_type() {
  // Content-Type has no weight grammar: section 12.4.2's q is a
  // content-negotiation feature and section 12.5.1's recipient SHOULD is
  // Accept's. So this is a valid media type with an oddly named parameter.
  let m = media_type(b"text/html;q=blah").expect("valid");
  assert_eq!(m.ty(), "text");
  assert_eq!(
    m.params().next().expect("one").expect("well formed"),
    (b"q".as_slice(), ParamValue::Token(b"blah"))
  );
}

#[test]
fn media_type_refuses_what_is_not_type_solidus_subtype() {
  for bad in [
    b"application".as_slice(), // no solidus
    b"/json",                  // empty type
    b"application/",           // empty subtype
    b"appli cation/json",      // space is not a tchar
    b"application/js/on",      // two solidi: the second is not a tchar
  ] {
    assert_eq!(media_type(bad), Err(MediaError::NotAMediaType), "{:?}", bad);
  }
}

#[test]
fn a_valueless_parameter_is_refused_by_the_media_grammar() {
  // The walker admits `ParamValue::None` for fields like RFC 6455's that
  // define their own parameter grammar. Section 5.6.6's `parameter` requires
  // the `=`, so for a media type it is a violation.
  assert_eq!(
    media_type(b"text/html;charset"),
    Err(MediaError::ValuelessParameter)
  );
}

#[test]
fn a_literal_asterisk_type_parses_and_matches_nothing_real() {
  // `*` is a tchar, so `*/json` reaches the grammar through the
  // `type "/" subtype` alternative with the literal type `*`.
  let m = media_type(b"*/json").expect("valid");
  assert_eq!(m.ty(), "*");
  assert_eq!(m.subtype(), "json");
}
