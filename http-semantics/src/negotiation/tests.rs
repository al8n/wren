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

// ── RFC 9110 §12.5.4's Accept-Language ───────────────────────────────────────

/// What the `Accept-Language` walk yields for its `n`th member, rendered as
/// `(name, thousandths)`.
fn language<'a>(lines: &[&'a [u8]], n: usize) -> Option<(Option<&'a str>, u16)> {
  let item = nth(accept_language(lines.iter().copied()), n)?;
  let pref = item.expect("well formed");
  Some((pref.name(), pref.weight().thousandths()))
}

#[test]
fn the_sections_own_language_example_reads_as_it_reads() {
  // RFC 9110 §12.5.4: "Accept-Language: da, en-gb;q=0.8, en;q=0.7".
  let lines = [b"da, en-gb;q=0.8, en;q=0.7".as_slice()];
  assert_eq!(language(&lines, 0), Some((Some("da"), 1000)));
  assert_eq!(language(&lines, 1), Some((Some("en-gb"), 800)));
  assert_eq!(language(&lines, 2), Some((Some("en"), 700)));
  assert_eq!(language(&lines, 3), None);
}

#[test]
fn the_wildcard_range_is_the_wildcard_and_nothing_else_can_be() {
  // RFC 4647 §2.1's `language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"`
  // has no ALPHA that `*` satisfies, so the first alternative cannot derive it
  // and the wildcard reading is the only one.
  let star = accept_language([b"*".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert!(star.is_wildcard());
  assert_eq!(star.name(), None);
  // RFC 4647 §2.2's `extended-language-range` would admit a `*` in a later
  // subtag; §12.5.4 names §2.1, which does not.
  assert_eq!(
    accept_language([b"en-*".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::NotAnElement
  );
}

#[test]
fn both_subtag_positions_are_read_as_their_own_rule() {
  // `(1*8ALPHA *("-" 1*8alphanum))` — ALPHA in front, `alphanum` behind, and
  // `alphanum         = ALPHA / DIGIT` (RFC 4647 §2.1).
  for good in [
    b"en".as_slice(),
    b"en-gb",
    b"zh-Hans-CN",
    b"en-us-1",
    b"abcdefgh",
    b"en-12345678",
    b"x-a",
  ] {
    let pref = accept_language([good])
      .next()
      .expect("one")
      .expect("well formed");
    assert!(!pref.is_wildcard(), "{good:?}");
  }
  for bad in [
    b"1-en".as_slice(), // a DIGIT in the primary subtag
    b"abcdefghi",       // nine ALPHA where 1*8 bounds it at eight
    b"en-123456789",    // nine alphanum in a later subtag
    b"en-",             // 1* admits no empty subtag
    b"-gb",
    b"en--gb",
    b"en_gb", // `_` is a tchar and no part of this rule
    b"en.gb",
  ] {
    assert_eq!(
      accept_language([bad])
        .next()
        .expect("one")
        .expect_err("malformed"),
      NegotiationError::NotAnElement,
      "{bad:?}"
    );
  }
}

#[test]
fn every_language_range_is_a_token_and_not_every_token_is_a_range() {
  // The two element rules this module carries are NESTED, which is what keeps a
  // `language-range` from ever moving an element boundary: RFC 4647 §2.1 spells
  // it out of ALPHA, DIGIT and `-`, and all three are RFC 9110 §5.6.2 `tchar`s.
  let mut narrower = 0usize;
  for sample in [
    b"*".as_slice(),
    b"en",
    b"en-gb",
    b"zh-Hans-CN",
    b"en-us-1",
    b"1-en",
    b"abcdefghi",
    b"en-",
    b"en--gb",
    b"en_gb",
    b"gzip",
    b"identity",
    b"x-a",
  ] {
    if is_language_range(sample) {
      assert!(
        crate::grammar::is_token(sample),
        "{sample:?} is a language-range and no token"
      );
    } else if crate::grammar::is_token(sample) {
      narrower += 1;
    }
  }
  // And the nesting is PROPER, so the narrower rule is doing work. Five of the
  // thirteen samples are a `token` and no `language-range` — `1-en`,
  // `abcdefghi`, `en-`, `en--gb` and `en_gb` — while `gzip` and `identity` are
  // BOTH, which is the half of this that a coding-shaped reading of the list
  // gets wrong.
  assert_eq!(narrower, 5);
}

#[test]
fn the_weight_behind_a_language_range_is_the_same_weight() {
  // One `read_weight`, so §12.5.4 gets §12.5.3's answers: no `quoted-string`
  // alternative, no `BWS` around the `"q="` literal, and one bracketed weight.
  assert_eq!(
    accept_language([b"en;q=\"0.5\"".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::BadWeight
  );
  assert_eq!(
    accept_language([b"en;q = 0.5".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::NotAWeight
  );
  assert_eq!(
    accept_language([b"en;p=1".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::NotAWeight
  );
  let zero = accept_language([b"en;Q=0".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert_eq!(zero.weight(), Weight::ZERO);
}

#[test]
fn the_language_walk_skips_empty_elements_and_latches_like_the_other() {
  let mut walk = accept_language([b", da ,, en_gb, en".as_slice()]);
  assert_eq!(walk.next().expect("one").expect("ok").name(), Some("da"));
  assert_eq!(
    walk.next().expect("two").expect_err("malformed"),
    NegotiationError::NotAnElement
  );
  assert!(walk.next().is_none());
  assert!(walk.next().is_none());
}

// ── RFC 9110 §12.5.2's Accept-Charset ────────────────────────────────────────

#[test]
fn the_sections_own_charset_example_reads_as_it_reads() {
  // RFC 9110 §12.5.2: "Accept-Charset: iso-8859-5, unicode-1-1;q=0.8".
  let mut walk = accept_charset([b"iso-8859-5, unicode-1-1;q=0.8".as_slice()]);
  let first = walk.next().expect("one").expect("well formed");
  assert_eq!(first.name(), Some("iso-8859-5"));
  assert_eq!(first.weight(), Weight::ONE);
  let second = walk.next().expect("two").expect("well formed");
  assert_eq!(second.name(), Some("unicode-1-1"));
  assert_eq!(second.weight().thousandths(), 800);
  assert!(walk.next().is_none());
}

#[test]
fn the_charset_wildcard_is_the_wildcard() {
  // RFC 9110 §12.5.2: "The special value "*", if present in the Accept-Charset
  // header field, matches every charset that is not mentioned elsewhere in the
  // field."
  let star = accept_charset([b"*;q=0".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert!(star.is_wildcard());
  assert_eq!(star.name(), None);
  assert_eq!(star.weight(), Weight::ZERO);
}

#[test]
fn the_charset_element_is_the_token_the_field_spells() {
  // `Accept-Charset = #( ( token / "*" ) [ weight ] )` (RFC 9110 §12.5.2) —
  // there is no `charset` production in RFC 9110 to read instead. §8.3.2's Note
  // says the one difference that makes: RFC 2978's `mime-charset` admits `{`
  // and `}`, which §5.6.2's `token` does not, and this field spells `token`.
  assert_eq!(
    accept_charset([b"a{b}".as_slice()])
      .next()
      .expect("one")
      .expect_err("malformed"),
    NegotiationError::NotAnElement
  );
  // Everything a `token` is, this field admits — including the shapes the other
  // two fields refuse or read differently.
  for good in [b"utf-8".as_slice(), b"UTF-8", b"x_y", b"abcdefghi", b"1-en"] {
    let pref = accept_charset([good])
      .next()
      .expect("one")
      .expect("well formed");
    assert!(!pref.is_wildcard(), "{good:?}");
  }
}

#[test]
fn charset_and_encoding_read_one_element_language() {
  // The two entry points share `Element::Token` because RFC 9110 §12.5.2's
  // `( token / "*" )` and §12.5.3's
  // `codings          = content-coding / "identity" / "*"` derive the SAME
  // strings: `content-coding   = token`, `identity` is a `token`, and `*` is a
  // `tchar`. So nothing an element may SAY tells the two fields apart, and this
  // pins that rather than leaving it as a coincidence of one implementation.
  for line in [
    b"gzip".as_slice(),
    b"identity",
    b"*",
    b"utf-8",
    b"a{b}",
    b"gz ip",
    b"gzip;q=0.5",
    b"gzip;q=\"0.5\"",
    b"gzip;p=1",
    b"",
  ] {
    let charset = accept_charset([line]).next();
    let encoding = accept_encoding([line]).next();
    match (charset, encoding) {
      (None, None) => {}
      (Some(Ok(a)), Some(Ok(b))) => {
        assert_eq!(a.name(), b.name(), "{line:?}");
        assert_eq!(a.weight(), b.weight(), "{line:?}");
      }
      (Some(Err(a)), Some(Err(b))) => assert_eq!(a, b, "{line:?}"),
      _ => panic!("the two fields parted over {line:?}"),
    }
  }
}

// ── RFC 9110 §12.5.5's Vary ──────────────────────────────────────────────────

/// The `n`th `Vary` member, rendered so a test can compare it: `None` for the
/// wildcard, `Some(name)` for a field name.
fn vary_member_at<'a>(lines: &[&'a [u8]], n: usize) -> Option<Option<&'a str>> {
  let item = vary(lines.iter().copied()).nth(n)?;
  Some(match item.expect("well formed") {
    VaryMember::Wildcard => None,
    VaryMember::FieldName(name) => Some(name),
  })
}

#[test]
fn the_sections_own_vary_example_reads_as_it_reads() {
  // RFC 9110 §12.5.5: "Vary: accept-encoding, accept-language".
  let lines = [b"accept-encoding, accept-language".as_slice()];
  assert_eq!(vary_member_at(&lines, 0), Some(Some("accept-encoding")));
  assert_eq!(vary_member_at(&lines, 1), Some(Some("accept-language")));
  assert_eq!(vary_member_at(&lines, 2), None);
}

#[test]
fn the_wildcard_is_a_member_and_not_a_state_of_the_whole_value() {
  // `Vary = #( "*" / field-name )` (RFC 9110 §12.5.5) puts the wildcard inside
  // the list construct, and that section speaks of "A list containing the
  // member "*"" — so a value may hold it beside field names.
  let lines = [b"*, accept-encoding".as_slice()];
  assert_eq!(vary_member_at(&lines, 0), Some(None));
  assert_eq!(vary_member_at(&lines, 1), Some(Some("accept-encoding")));
  assert_eq!(vary_member_at(&lines, 2), None);

  let alone = [b"*".as_slice()];
  assert_eq!(vary_member_at(&alone, 0), Some(None));
  assert_eq!(vary_member_at(&alone, 1), None);
}

#[test]
fn a_vary_member_carries_no_weight_grammar() {
  // §12.5.5 brackets no `[ weight ]`, so a `;` opens nothing at all and
  // `;` is no RFC 9110 §5.6.2 `tchar`. What `Accept-Encoding` reads as a weight
  // is a malformed member here — which is the whole of why `Vary` is not the
  // other walk.
  for line in [b"accept-encoding;q=0.5".as_slice(), b"accept-encoding;"] {
    assert_eq!(
      vary([line]).next().expect("one").expect_err("malformed"),
      VaryError::NotAFieldName,
      "{line:?}"
    );
  }
  let pref = accept_encoding([b"accept-encoding;q=0.5".as_slice()])
    .next()
    .expect("one")
    .expect("well formed");
  assert_eq!(pref.weight().thousandths(), 500);
}

#[test]
fn a_vary_member_is_a_token_and_is_not_checked_against_a_registry() {
  // `field-name     = token` (RFC 9110 §5.1), and §12.5.5: "Potential selecting
  // header fields are not limited to fields defined by this specification."
  for good in [b"X-Made-Up".as_slice(), b"a", b"*x", b"~!#$%&'^_`|"] {
    assert!(
      matches!(
        vary([good]).next().expect("one").expect("well formed"),
        VaryMember::FieldName(_)
      ),
      "{good:?}"
    );
  }
  for bad in [b"accept encoding".as_slice(), b"accept:", b"\"accept\""] {
    assert_eq!(
      vary([bad]).next().expect("one").expect_err("malformed"),
      VaryError::NotAFieldName,
      "{bad:?}"
    );
  }
}

#[test]
fn the_vary_walk_skips_empty_elements_latches_and_reads_lines_as_the_join() {
  let mut walk = vary([b", accept ,, accept encoding, accept-language".as_slice()]);
  assert!(matches!(
    walk.next().expect("one").expect("ok"),
    VaryMember::FieldName("accept")
  ));
  assert_eq!(
    walk.next().expect("two").expect_err("malformed"),
    VaryError::NotAFieldName
  );
  assert!(walk.next().is_none());
  assert!(walk.next().is_none());

  let split = [b"*".as_slice(), b"accept-encoding", b""];
  let joined = [b"*,accept-encoding,".as_slice()];
  for n in 0..3 {
    assert_eq!(vary_member_at(&split, n), vary_member_at(&joined, n), "{n}");
  }

  let absent: [&[u8]; 0] = [];
  assert!(vary(absent).next().is_none());
  assert!(vary([b"".as_slice()]).next().is_none());
}

// ── RFC 9110 §12.5.3's acceptability rules ───────────────────────────────────

/// One acceptability answer, rendered so a test can compare it without naming
/// a `Weight` this module cannot construct: `(is_acceptable, thousandths)`.
///
/// The pair separates all three states. `AcceptableByDefault` is
/// `(true, None)`, `Unmentioned` is `(false, None)`, and a `Weighed` is
/// `(_, Some(_))`.
fn acceptability(coding: Option<&[u8]>, lines: &[&[u8]]) -> (bool, Option<u16>) {
  let answer =
    encoding_acceptability(coding, lines.iter().copied()).expect("the field is well formed");
  (
    answer.is_acceptable(),
    answer.weight().map(Weight::thousandths),
  )
}

#[test]
fn rule_1_is_about_the_fields_presence_and_zero_lines_is_absent() {
  // RFC 9110 §12.5.3 rule 1: "If no Accept-Encoding header field is in the
  // request, any content coding is considered acceptable by the user agent."
  // A field is present exactly when a line names it, so no lines is rule 1's
  // subject and one empty line is not.
  assert_eq!(acceptability(Some(b"gzip"), &[]), (true, None));
  assert_eq!(acceptability(Some(b"br"), &[]), (true, None));
  assert_eq!(acceptability(None, &[]), (true, None));

  // The same question one line later is a different rule, and a different
  // answer: §12.4.3's "If no wildcard is present, values that are not
  // explicitly mentioned in the field are considered unacceptable."
  assert_eq!(acceptability(Some(b"gzip"), &[b""]), (false, None));
}

#[test]
fn rule_3_reads_the_entry_that_names_the_coding() {
  // RFC 9110 §12.5.3 rule 3: "If the representation's content coding is one of
  // the content codings listed in the Accept-Encoding field value, then it is
  // acceptable unless it is accompanied by a qvalue of 0."
  assert_eq!(
    acceptability(Some(b"gzip"), &[b"gzip, compress"]),
    (true, Some(1000))
  );
  assert_eq!(
    acceptability(Some(b"gzip"), &[b"gzip;q=0.5"]),
    (true, Some(500))
  );
  assert_eq!(
    acceptability(Some(b"gzip"), &[b"gzip;q=0"]),
    (false, Some(0))
  );
  // §8.4.1: "All content codings are case-insensitive".
  assert_eq!(
    acceptability(Some(b"GZIP"), &[b"gzip;q=0.5"]),
    (true, Some(500))
  );
  assert_eq!(
    acceptability(Some(b"gzip"), &[b"GZIP;q=0.5"]),
    (true, Some(500))
  );
}

#[test]
fn the_asterisk_stands_in_for_a_coding_the_field_does_not_list() {
  // RFC 9110 §12.5.3: "The asterisk "*" symbol in an Accept-Encoding field
  // matches any available content coding not explicitly listed in the field."
  assert_eq!(
    acceptability(Some(b"br"), &[b"gzip;q=1, *;q=0.5"]),
    (true, Some(500))
  );
  assert_eq!(
    acceptability(Some(b"br"), &[b"gzip;q=1, *;q=0"]),
    (false, Some(0))
  );
  // An entry that names it is more specific and wins wherever it stands.
  assert_eq!(
    acceptability(Some(b"br"), &[b"*;q=0, br;q=0.5"]),
    (true, Some(500))
  );
  assert_eq!(
    acceptability(Some(b"br"), &[b"br;q=0.5, *;q=0"]),
    (true, Some(500))
  );
}

#[test]
fn a_coding_the_field_never_mentions_is_its_own_state() {
  // RFC 9110 §12.4.3: "If no wildcard is present, values that are not
  // explicitly mentioned in the field are considered unacceptable." Not the
  // same answer as a weight of zero — the field said nothing, rather than
  // saying no — so a caller can report which it met.
  assert_eq!(
    acceptability(Some(b"br"), &[b"gzip, compress"]),
    (false, None)
  );
  assert_eq!(
    acceptability(Some(b"br"), &[b"gzip;q=0"]),
    (false, None),
    "another coding's zero is not this coding's"
  );
  assert_eq!(acceptability(Some(b"br"), &[b"br;q=0"]), (false, Some(0)));
}

#[test]
fn rule_2_governs_a_representation_that_has_no_coding() {
  // RFC 9110 §12.5.3 rule 2: "If the representation has no content coding,
  // then it is acceptable by default unless specifically excluded by the
  // Accept-Encoding header field stating either "identity;q=0" or "*;q=0"
  // without a more specific entry for "identity"."
  assert_eq!(acceptability(None, &[b"gzip, compress"]), (true, None));
  assert_eq!(acceptability(None, &[b"identity;q=0"]), (false, Some(0)));
  assert_eq!(acceptability(None, &[b"identity;q=0.5"]), (true, Some(500)));
  assert_eq!(acceptability(None, &[b"*;q=0"]), (false, Some(0)));
  // The clause that makes rule 2 more than two exclusions: a `*;q=0` with a
  // more specific entry for `identity` does NOT exclude.
  assert_eq!(
    acceptability(None, &[b"*;q=0, identity;q=0.5"]),
    (true, Some(500))
  );
  assert_eq!(
    acceptability(None, &[b"*;q=0, identity;q=0"]),
    (false, Some(0))
  );
  // And the direction rule 2 does NOT run in: a non-zero `*` lends no weight
  // to a representation with no coding, because rule 2 names only `*;q=0` as
  // reaching it. The answer is the default, with no weight, not `Some(500)`.
  assert_eq!(acceptability(None, &[b"*;q=0.5"]), (true, None));
  assert_eq!(acceptability(None, &[b"gzip;q=1, *;q=0.5"]), (true, None));
}

#[test]
fn the_empty_field_sentence_falls_out_of_the_other_rules() {
  // RFC 9110 §12.5.3: "An Accept-Encoding header field with a field value that
  // is empty implies that the user agent does not want any content coding in
  // response." Read as a consequence of rules 2 and 3 and §12.4.3 rather than
  // as a case of its own — so this test is what says the consequence holds,
  // and there is no branch anywhere that spells it.
  for empty in [b"".as_slice(), b" ", b",", b", ,"] {
    assert_eq!(
      acceptability(Some(b"gzip"), &[empty]),
      (false, None),
      "{empty:?}"
    );
    assert_eq!(acceptability(None, &[empty]), (true, None), "{empty:?}");
  }
}

#[test]
fn the_sections_own_example_answers_every_way_round() {
  // RFC 9110 §12.5.3: "Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0".
  let field: &[&[u8]] = &[b"gzip;q=1.0, identity; q=0.5, *;q=0"];
  assert_eq!(acceptability(Some(b"gzip"), field), (true, Some(1000)));
  assert_eq!(acceptability(Some(b"identity"), field), (true, Some(500)));
  // A representation with no coding reaches the same entry, because rule 2's
  // "more specific entry" is the one naming `identity`.
  assert_eq!(acceptability(None, field), (true, Some(500)));
  assert_eq!(acceptability(Some(b"br"), field), (false, Some(0)));
}

#[test]
fn a_repeated_entry_is_undecided_and_this_is_the_reading_taken() {
  // RFC 9110 does not settle what a field naming one coding twice with two
  // different weights means. `fold_repeated_entry` records where the rule that
  // would settle it was looked for — §12.4.2, §12.5.1's ordering sentence,
  // §5.6.1 and §5.6.1.2, §5.3 and §8.6 — and it is in none of them. This test
  // is what makes the resulting choice a decision the next reader MEETS rather
  // than a behaviour they infer.

  // The half that IS derived, from rule 3's "unless it is accompanied by a
  // qvalue of 0": a zero anywhere excludes. Asserted BOTH ways round, because
  // what makes it derived rather than chosen is that no reading of the repeat
  // can move it — two recipients reading the same field from opposite ends
  // agree here whatever rule each took.
  for field in [
    b"gzip;q=1, gzip;q=0".as_slice(),
    b"gzip;q=0, gzip;q=1",
    b"gzip;q=0, gzip;q=0.5, gzip;q=1",
  ] {
    assert_eq!(
      acceptability(Some(b"gzip"), &[field]),
      (false, Some(0)),
      "{field:?}"
    );
  }
  assert_eq!(
    acceptability(Some(b"br"), &[b"*;q=1, *;q=0"]),
    (false, Some(0))
  );
  assert_eq!(
    acceptability(Some(b"br"), &[b"*;q=0, *;q=1"]),
    (false, Some(0))
  );

  // The half that is CHOSEN. Nothing in RFC 9110 picks between the last entry,
  // the first, and the largest, so the pair below is asserted both ways round —
  // one of them alone would be satisfied by a "largest wins" reading too, and
  // the mirror is what excludes it. A future reading that takes the first entry
  // reds on the first assertion; one that takes the largest reds on the second.
  //
  // What would settle it: a sentence saying which entry a recipient reads when
  // a field names one value more than once with different weights. There is
  // none. If one is ever added, this test is what has to be re-argued rather
  // than merely re-blessed.
  //
  // Both claims above are measured, not predicted. Replacing
  // `fold_repeated_entry`'s body with `seen.unwrap_or(found)` — first in wire
  // order — reds this test, and replacing it with a zero-absorbing
  // largest-wins reds it on the mirror assertion below, naming that message.
  // Run as `cargo test -p http-semantics --lib
  // negotiation::tests::a_repeated_entry`, once per mutation, with the file
  // restored from a copy afterwards.
  assert_eq!(
    acceptability(Some(b"gzip"), &[b"gzip;q=0.25, gzip;q=0.75"]),
    (true, Some(750)),
    "last in wire order; the first-in-wire-order reading answers 250 here"
  );
  assert_eq!(
    acceptability(Some(b"gzip"), &[b"gzip;q=0.75, gzip;q=0.25"]),
    (true, Some(250)),
    "and the mirror: a largest-wins reading answers 750 here, and this pins the \
     ORDER rather than a value that happens to be the larger of the two"
  );
  // The same undecidedness reaches the wildcard entry, and takes the same
  // reading there, since one fold serves both.
  assert_eq!(
    acceptability(Some(b"br"), &[b"*;q=0.25, *;q=0.75"]),
    (true, Some(750))
  );
  assert_eq!(
    acceptability(Some(b"br"), &[b"*;q=0.75, *;q=0.25"]),
    (true, Some(250))
  );
}

#[test]
fn the_lines_are_walked_as_the_join_would_and_a_fault_is_reported() {
  // RFC 9110 §5.2's join, over the same field the example above uses.
  let split: &[&[u8]] = &[b"gzip;q=1.0", b"identity; q=0.5", b"*;q=0"];
  assert_eq!(acceptability(Some(b"gzip"), split), (true, Some(1000)));
  assert_eq!(acceptability(None, split), (true, Some(500)));
  assert_eq!(acceptability(Some(b"br"), split), (false, Some(0)));

  // A malformed field is answered with the walk's own fault rather than with a
  // verdict taken over the members in front of it.
  assert_eq!(
    encoding_acceptability(Some(b"gzip"), [b"gzip, br;p=1".as_slice()]).expect_err("malformed"),
    NegotiationError::NotAWeight
  );
  assert_eq!(
    encoding_acceptability(None, [b"identity;q=blah".as_slice()]).expect_err("malformed"),
    NegotiationError::BadWeight
  );
}
