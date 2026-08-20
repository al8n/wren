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
    b"1.0000", // 0*3("0") is at most three, even all zero
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

#[test]
fn a_range_yields_its_shape_its_weight_and_its_parameters() {
  let mut it = accept([b"text/html;level=3;q=0.7".as_slice()]);
  let r = it.next().expect("one").expect("valid");
  assert_eq!(r.ty(), Some("text"));
  assert_eq!(r.subtype(), Some("html"));
  assert_eq!(r.weight(), Weight(700));
  let mut params = r.params();
  assert_eq!(
    params.next().expect("one").expect("well formed"),
    (b"level".as_slice(), ParamValue::Token(b"3"))
  );
  assert!(
    params.next().is_none(),
    "q is weight, not a range parameter"
  );
}

#[test]
fn a_literal_asterisk_type_matches_nothing_real_in_a_range_too() {
  // Section 12.5.1 names exactly two wildcard SHAPES -- "*/*" and "type/*"
  // (quoted in full on `MediaRange::ty`'s doc). `*` reached through the third
  // alternative, `type "/" subtype`, is an ordinary token, not a wildcard:
  // `*/json` must report `ty() == Some("*")`, never collapse to `None`. An
  // earlier draft of this design conflated the two and let `*/json` match
  // every candidate; `weight_for` (task 6) is built directly on this staying
  // false.
  let r = accept([b"*/json".as_slice()])
    .next()
    .expect("one")
    .expect("valid");
  assert_eq!(r.ty(), Some("*"));
  assert_eq!(r.subtype(), Some("json"));
}

#[test]
fn a_missing_q_defaults_to_one() {
  let r = accept([b"text/html".as_slice()])
    .next()
    .expect("one")
    .expect("valid");
  assert_eq!(r.weight(), Weight::ONE);
}

#[test]
fn two_q_parameters_are_both_weight_and_the_last_one_wins() {
  let r = accept([b"text/html;q=0.5;q=0.7".as_slice()])
    .next()
    .expect("one")
    .expect("valid");
  assert_eq!(r.weight(), Weight(700));
  assert_eq!(r.params().count(), 0, "neither q reaches params()");
}

#[test]
fn a_q_that_is_not_a_qvalue_ends_the_walk() {
  for bad in [
    b"text/html;q=blah".as_slice(),
    b"text/html;q=1.5",
    b"text/html;q=0.5000",
  ] {
    assert_eq!(
      accept([bad]).next(),
      Some(Err(MediaError::BadWeight)),
      "{:?}",
      bad
    );
  }
}

#[test]
fn the_walk_stops_at_the_first_faulting_member() {
  let mut it = accept([b"text/html, not-a-media-type, text/plain".as_slice()]);
  assert!(it.next().expect("first").is_ok());
  assert_eq!(it.next(), Some(Err(MediaError::NotAMediaType)));
  assert!(it.next().is_none(), "later members are unreachable");
}

#[test]
fn an_empty_accept_value_yields_no_ranges() {
  assert!(accept([b"".as_slice()]).next().is_none());
}

#[test]
fn a_value_spanning_the_join_is_lifted_to_its_own_variant() {
  // A quoted-string opened on one field line and closed on the next is well
  // formed (section 5.2 joins them with a comma, which is data inside the
  // string) and not one contiguous slice.
  let mut it = accept([b"text/html;boundary=\"a".as_slice(), b"b\"".as_slice()]);
  assert_eq!(it.next(), Some(Err(MediaError::ValueSpansFieldLines)));
}

#[test]
fn a_valueless_parameter_is_refused_in_a_range_too() {
  // The same refusal `media_type` makes, for the same reason: section 5.6.6's
  // `parameter` grammar requires the `=`, and a media range defines no
  // grammar of its own that admits a bare name.
  assert_eq!(
    accept([b"text/html;charset".as_slice()]).next(),
    Some(Err(MediaError::ValuelessParameter))
  );
}

#[test]
fn a_valueless_q_is_a_grammar_fault_not_a_bad_weight() {
  // A bare `q` fails section 5.6.6's `parameter` grammar outright -- there is
  // no value to be a bad `qvalue`, so the walk never reaches section 12.5.1's
  // weight question at all. This pins the ordering: the valueless check runs
  // before the `q`-name check.
  assert_eq!(
    accept([b"text/html;q".as_slice()]).next(),
    Some(Err(MediaError::ValuelessParameter))
  );
  // A valueless parameter that is NOT `q`, alongside a well-formed `q`:
  // this is "refuses valueless", not "refuses anything near a `q`".
  assert_eq!(
    accept([b"text/html;charset;q=0.5".as_slice()]).next(),
    Some(Err(MediaError::ValuelessParameter))
  );
}

/// Tests that collect into a `Vec`: gated to the tiers that have a heap, since
/// the bare `no_std` tier has neither an allocator nor the `alloc as std` alias.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
mod heap {
  use crate::media::*;
  use std::vec::Vec;

  #[test]
  fn the_two_wildcard_shapes_report_none() {
    let mut it = accept([b"*/*, text/*, text/plain".as_slice()]);
    let all = it.by_ref().map(|r| r.expect("valid")).collect::<Vec<_>>();
    assert_eq!(
      all.first().map(|r| (r.ty(), r.subtype())),
      Some((None, None))
    );
    assert_eq!(
      all.get(1).map(|r| (r.ty(), r.subtype())),
      Some((Some("text"), None))
    );
    assert_eq!(
      all.get(2).map(|r| (r.ty(), r.subtype())),
      Some((Some("text"), Some("plain")))
    );
  }

  #[test]
  fn q_is_weight_wherever_it_appears_and_in_whatever_case() {
    // RFC 9110 section 12.5.1: "Recipients SHOULD process any parameter named
    // "q" as weight, regardless of parameter ordering." Section 12.4.2 names it
    // "q" (case-insensitive).
    for line in [
      b"text/html;q=0.5;level=3".as_slice(),
      b"text/html;level=3;q=0.5",
      b"text/html;Q=0.5;level=3",
      b"text/html;level=3;q=\"0.5\"",
    ] {
      let r = accept([line]).next().expect("one").expect("valid");
      assert_eq!(r.weight(), Weight(500), "{:?}", line);
      let names = r.params().map(|p| p.expect("ok").0).collect::<Vec<_>>();
      assert_eq!(names, [b"level".as_slice()], "{:?}", line);
    }
  }
}
