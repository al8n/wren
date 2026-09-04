use super::*;

/// The `n`th item of a walk, or `None` past its end.
fn nth<'a>(
  mut walk: impl Iterator<Item = Result<Preference<'a>, NegotiationError>>,
  n: usize,
) -> Option<Result<Preference<'a>, NegotiationError>> {
  walk.nth(n)
}

/// What the `Accept-Encoding` walk yields for its `n`th member, rendered as
/// `(name, thousandths)`.
fn member<'a>(lines: &[&'a [u8]], n: usize) -> Option<(Option<&'a str>, u16)> {
  let item = nth(accept_encoding(lines.iter().copied()), n)?;
  let pref = item.expect("well formed");
  Some((pref.name(), pref.weight().thousandths()))
}

#[test]
fn a_coding_list_reads_in_wire_order_with_the_default_weight() {
  // RFC 9110 §12.5.3: "Accept-Encoding: compress, gzip" is one of that
  // section's own examples, and §12.4.2: "If no "q" parameter is present, the
  // default weight is 1."
  let lines = [b"compress, gzip".as_slice()];
  assert_eq!(member(&lines, 0), Some((Some("compress"), 1000)));
  assert_eq!(member(&lines, 1), Some((Some("gzip"), 1000)));
  assert_eq!(member(&lines, 2), None);
}

#[test]
fn the_sections_own_last_example_reads_as_it_reads() {
  // RFC 9110 §12.5.3: "Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0".
  // The `identity; q=0.5` element carries the `OWS` §12.4.2's
  // `weight = OWS ";" OWS "q=" qvalue` puts after the semicolon.
  let lines = [b"gzip;q=1.0, identity; q=0.5, *;q=0".as_slice()];
  assert_eq!(member(&lines, 0), Some((Some("gzip"), 1000)));
  assert_eq!(member(&lines, 1), Some((Some("identity"), 500)));
  assert_eq!(member(&lines, 2), Some((None, 0)));
  assert_eq!(member(&lines, 3), None);
}

#[test]
fn the_asterisk_is_the_wildcard_and_identity_is_a_name() {
  // RFC 9110 §12.5.3: "The asterisk "*" symbol in an Accept-Encoding field
  // matches any available content coding not explicitly listed in the field."
  // and "An "identity" token is used as a synonym for "no encoding" in order
  // to communicate when no encoding is preferred." — two different things, and
  // `identity` is a `token` like any other.
  let star = accept_encoding([b"*".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert!(star.is_wildcard());
  assert_eq!(star.name(), None);

  let identity = accept_encoding([b"identity".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert!(!identity.is_wildcard());
  assert_eq!(identity.name(), Some("identity"));
}

#[test]
fn a_weight_is_read_in_whatever_case_the_sender_spelled_the_q() {
  // RFC 9110 §12.4.2 names the parameter "q" (case-insensitive), and RFC 5234
  // makes the `"q="` literal in `weight = OWS ";" OWS "q=" qvalue`
  // case-insensitive on its own.
  for line in [b"gzip;q=0.5".as_slice(), b"gzip;Q=0.5"] {
    let pref = accept_encoding([line])
      .next()
      .expect("one")
      .expect("well formed");
    assert_eq!(pref.weight().thousandths(), 500, "{line:?}");
  }
}

#[test]
fn ows_stands_where_the_weight_puts_it_and_nowhere_else() {
  // `weight = OWS ";" OWS "q=" qvalue` (RFC 9110 §12.4.2) brackets white space
  // on both sides of the semicolon and writes NONE inside `"q="`.
  for line in [
    b"gzip ;q=0.5".as_slice(),
    b"gzip; q=0.5",
    b"gzip \t; \tq=0.5",
  ] {
    let pref = accept_encoding([line])
      .next()
      .expect("one")
      .expect("well formed");
    assert_eq!(pref.weight().thousandths(), 500, "{line:?}");
  }
  // The `BWS` §10.1.4's `transfer-parameter` puts around its `=` is not here,
  // and WHICH refusal each side of the literal earns is the point rather than
  // that both are refused. A space in front of the `=` means the two bytes
  // `"q="` never matched, so what follows the element is no weight at all; a
  // space behind it means they did match and the value slot then holds
  // something that is no `qvalue`.
  for line in [b"gzip;q =0.5".as_slice(), b"gzip;q = 0.5"] {
    assert_eq!(
      accept_encoding([line])
        .next()
        .expect("one")
        .expect_err("malformed"),
      NegotiationError::NotAWeight,
      "{line:?}"
    );
  }
  assert_eq!(
    accept_encoding([b"gzip;q= 0.5".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::BadWeight
  );
}

#[test]
fn a_quoted_qvalue_is_no_weight_here_and_is_one_in_accept() {
  // The whole of why RFC 9110 §12.5.1's `q` rule does not transfer, in one
  // pair. §5.6.6 says of a `parameter` that "The quoted and unquoted values
  // are equivalent.", and a `media-range` carries `parameters`; §12.4.2's
  // `weight = OWS ";" OWS "q=" qvalue` has no `quoted-string` alternative, and
  // `codings          = content-coding / "identity" / "*"` carries no
  // parameters for §5.6.6's sentence to be about.
  let accepted = crate::media::accept([b"text/plain;q=\"0.5\"".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert_eq!(accepted.weight().thousandths(), 500);

  assert_eq!(
    accept_encoding([b"gzip;q=\"0.5\"".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::BadWeight
  );
}

#[test]
fn a_second_parameter_is_no_element_of_this_field() {
  // `Accept-Encoding  = #( codings [ weight ] )` (RFC 9110 §12.5.3) brackets
  // ONE weight and nothing else, where
  // `parameters      = *( OWS ";" OWS [ parameter ] )` (§5.6.6) repeats. Each
  // line below is a `media-range` shape and no `codings [ weight ]`.
  assert_eq!(
    accept_encoding([b"gzip;p=1".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::NotAWeight
  );
  assert_eq!(
    accept_encoding([b"gzip;p=1;q=0.5".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::NotAWeight
  );
  // Here the `q` IS in the bracketed place, so the fault is the value: `0.5;p=1`
  // is no `qvalue`.
  assert_eq!(
    accept_encoding([b"gzip;q=0.5;p=1".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::BadWeight
  );
}

#[test]
fn a_bare_semicolon_is_not_a_weight() {
  for line in [b"gzip;".as_slice(), b"gzip; ", b"gzip;;q=0.5"] {
    assert_eq!(
      accept_encoding([line])
        .next()
        .expect("one")
        .expect_err("malformed"),
      NegotiationError::NotAWeight,
      "{line:?}"
    );
  }
}

#[test]
fn a_name_that_is_no_token_is_no_element() {
  // `content-coding   = token` (RFC 9110 §8.4.1), so a byte §5.6.2's `tchar`
  // forbids ends it.
  for line in [
    b"gz ip".as_slice(),
    b"gzip/1",
    b"\"gzip\"",
    b"gz\x00ip",
    b"=",
  ] {
    assert_eq!(
      accept_encoding([line])
        .next()
        .expect("one")
        .expect_err("malformed"),
      NegotiationError::NotAnElement,
      "{line:?}"
    );
  }
}

#[test]
fn an_empty_element_is_skipped_and_an_empty_field_yields_nothing() {
  // RFC 9110 §5.6.1.2 has a recipient skip empty list elements, and §12.5.3's
  // own example list includes the field with an empty value.
  let mut skipping = accept_encoding([b", gzip ,, compress,".as_slice()]);
  assert_eq!(
    skipping.next().expect("one").expect("ok").name(),
    Some("gzip")
  );
  assert_eq!(
    skipping.next().expect("two").expect("ok").name(),
    Some("compress")
  );
  assert!(skipping.next().is_none());

  assert!(accept_encoding([b"".as_slice()]).next().is_none());
  assert!(accept_encoding([b" ".as_slice(), b","]).next().is_none());
  // And an ABSENT field is the same emptiness here: which of the two §12.5.3's
  // opposite defaults applies is the caller's, since only the caller knows
  // whether it had a field to pass.
  let absent: [&[u8]; 0] = [];
  assert!(accept_encoding(absent).next().is_none());
}

#[test]
fn field_lines_walk_as_the_join_between_them_would() {
  // RFC 9110 §5.2 joins repeated field lines with a comma, and no element here
  // may hold one, so the two readings cannot part.
  let split = [b"gzip;q=0.5".as_slice(), b"compress", b"*;q=0"];
  let joined = [b"gzip;q=0.5,compress,*;q=0".as_slice()];
  for n in 0..4 {
    assert_eq!(
      nth(accept_encoding(split.iter().copied()), n).map(|item| {
        let pref = item.expect("well formed");
        (pref.name(), pref.weight().thousandths())
      }),
      nth(accept_encoding(joined.iter().copied()), n).map(|item| {
        let pref = item.expect("well formed");
        (pref.name(), pref.weight().thousandths())
      }),
      "member {n}"
    );
  }
}

#[test]
fn the_walk_latches_on_the_first_fault() {
  let mut walk = accept_encoding([b"gzip, gz ip, compress".as_slice()]);
  assert_eq!(walk.next().expect("one").expect("ok").name(), Some("gzip"));
  assert_eq!(
    walk.next().expect("two").expect_err("malformed"),
    NegotiationError::NotAnElement
  );
  assert!(walk.next().is_none());
  // Latched, not merely exhausted: an `Iterator` that answered `None` may
  // answer `Some` again, and this one must not.
  assert!(walk.next().is_none());
}

#[test]
fn a_zero_weight_is_a_weight_and_not_an_absent_one() {
  // RFC 9110 §12.4.2: "a value of 0 means "not acceptable"" — which a caller
  // can only act on if it arrives as a weight rather than as a refusal.
  let pref = accept_encoding([b"*;q=0".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert!(pref.is_wildcard());
  assert_eq!(pref.weight(), Weight::ZERO);
}

#[test]
fn every_qvalue_shape_the_abnf_spells_reaches_the_reader() {
  // `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`
  // (RFC 9110 §12.4.2), read through this field rather than directly, so the
  // element split in front of it is exercised too.
  for (line, thousandths) in [
    (b"gzip;q=0".as_slice(), 0u16),
    (b"gzip;q=1", 1000),
    (b"gzip;q=0.", 0),
    (b"gzip;q=1.", 1000),
    (b"gzip;q=0.001", 1),
    (b"gzip;q=1.000", 1000),
  ] {
    let pref = accept_encoding([line])
      .next()
      .expect("one")
      .expect("well formed");
    assert_eq!(pref.weight().thousandths(), thousandths, "{line:?}");
  }
  for line in [b"gzip;q=1.5".as_slice(), b"gzip;q=0.5000", b"gzip;q=blah"] {
    assert_eq!(
      accept_encoding([line])
        .next()
        .expect("one")
        .expect_err("malformed"),
      NegotiationError::BadWeight,
      "{line:?}"
    );
  }
}
