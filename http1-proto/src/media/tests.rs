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
  // RFC 9110 §12.4.2: "0.001 is the least preferred and 1 is the most
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
  // RFC 9110 §8.3 warns that recovering from a doubled Content-Type by
  // taking "the last syntactically valid member of the list" causes
  // "potential interoperability and security issues"; refusal cannot diverge.
  assert_eq!(
    media_type(b"text/plain, text/html"),
    Err(MediaError::NotASingleton)
  );
  // A trailing comma too: member-counting would call this singular, because
  // §5.6.1.2 has the walk skip empty elements.
  assert_eq!(media_type(b"text/plain,"), Err(MediaError::NotASingleton));
  // Inside a quoted-string the comma is data.
  let m = media_type(b"multipart/form-data;boundary=\"a,b\"").expect("valid");
  assert_eq!(m.subtype(), "form-data");
}

#[test]
fn a_parameter_named_q_is_ordinary_in_a_content_type() {
  // Content-Type has no weight grammar: §12.4.2's q is a content-negotiation
  // feature and §12.5.1's recipient SHOULD is Accept's. So this is a valid
  // media type with an oddly named parameter.
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
    b"/",                      // both halves empty at once
    b"appli cation/json",      // space is not a tchar
    b"application/js/on",      // two solidi: the second is not a tchar
  ] {
    assert_eq!(media_type(bad), Err(MediaError::NotAMediaType), "{:?}", bad);
  }
}

#[test]
fn a_valueless_parameter_is_refused_by_the_media_grammar() {
  // The walker admits `ParamValue::None` for fields like RFC 6455's that
  // define their own parameter grammar. §5.6.6's `parameter` requires the `=`,
  // so for a media type it is a violation.
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
  // §12.5.1 names exactly two wildcard SHAPES — "*/*" and "type/*"
  // (quoted in full on `MediaRange::ty`'s doc). `*` reached through the third
  // alternative, `type "/" subtype`, is an ordinary token, not a wildcard:
  // `*/json` must report `ty() == Some("*")`, never collapse to `None`. An
  // earlier draft of this design conflated the two and let `*/json` match
  // every candidate; `weight_for` is built directly on this staying false.
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
fn a_fault_found_reading_the_member_stops_the_walk_too() {
  // The OTHER half of the rule above, and the half that has to be latched
  // here. The list walk stops itself only when a member's own boundaries are
  // unresolved; every fault below is found AFTER it handed over a delimited
  // member, so it is ready with the next one and would go on yielding.
  //
  // Each fixture pairs a faulting first member with a perfectly good second,
  // so a walk that failed to latch would answer `Some(Ok(text/html))` where
  // this asserts `None`.
  for (field, want) in [
    (
      b"text/plain;q=bogus, text/html".as_slice(),
      MediaError::BadWeight,
    ),
    // The `q` that decides is the LAST one (§12.5.1), so the fault can be
    // behind a `q` that already parsed.
    (
      b"text/plain;q=1;q=nope, text/html".as_slice(),
      MediaError::BadWeight,
    ),
    (
      b"text/plain;charset, text/html".as_slice(),
      MediaError::ValuelessParameter,
    ),
    // `NotAMediaType` is the one kind with no unlatched route: `accept` hands
    // the walker `is_media_name`, which already requires the solidus, so the
    // name check inside `range_from` cannot fail on a member the walker
    // admitted. It reaches a caller only as the walker's own `NotAToken`,
    // latched there — asserted here so the contract is pinned for every
    // variant `accept` documents, whichever latch answers for it.
    (
      b"text/plain;q=0.5, not-a-media-type, text/html".as_slice(),
      MediaError::NotAMediaType,
    ),
  ] {
    let mut it = accept([field]);
    let mut item = it.next();
    // Walk to the fault: the `NotAMediaType` fixture opens with a good member.
    while matches!(item, Some(Ok(_))) {
      item = it.next();
    }
    assert_eq!(item, Some(Err(want)), "{field:?}");
    assert!(
      it.next().is_none(),
      "{field:?}: later members are unreachable"
    );
    // Latched, not merely exhausted — an `Iterator` that answered `None` is
    // free to answer `Some` again, and this one must not.
    assert!(it.next().is_none(), "{field:?}: the stop is latched");
  }
}

#[test]
fn a_value_spanning_the_join_stops_the_walk_too() {
  // The fourth kind, which needs two field lines to reach. §5.2 joins them
  // with a comma that falls INSIDE the quoted-string, so the value is well
  // formed, is not one contiguous slice, and is reported by the parameter walk
  // inside `range_from` — with the list walk none the wiser.
  let mut it = accept([
    b"text/html;boundary=\"a".as_slice(),
    b"b\", text/plain".as_slice(),
  ]);
  assert_eq!(it.next(), Some(Err(MediaError::ValueSpansFieldLines)));
  assert!(it.next().is_none(), "later members are unreachable");
  assert!(it.next().is_none(), "the stop is latched");
}

#[test]
fn an_empty_accept_value_yields_no_ranges() {
  assert!(accept([b"".as_slice()]).next().is_none());
}

#[test]
fn a_value_spanning_the_join_is_lifted_to_its_own_variant() {
  // A quoted-string opened on one field line and closed on the next is well
  // formed (§5.2 joins them with a comma, which is data inside the string)
  // and not one contiguous slice.
  let mut it = accept([b"text/html;boundary=\"a".as_slice(), b"b\"".as_slice()]);
  assert_eq!(it.next(), Some(Err(MediaError::ValueSpansFieldLines)));
}

#[test]
fn a_valueless_parameter_is_refused_in_a_range_too() {
  // The same refusal `media_type` makes, for the same reason: §5.6.6's
  // `parameter` grammar requires the `=`, and a media range defines no
  // grammar of its own that admits a bare name.
  assert_eq!(
    accept([b"text/html;charset".as_slice()]).next(),
    Some(Err(MediaError::ValuelessParameter))
  );
}

#[test]
fn a_valueless_q_is_a_grammar_fault_not_a_bad_weight() {
  // A bare `q` fails §5.6.6's `parameter` grammar outright — there is no
  // value to be a bad `qvalue`, so the walk never reaches §12.5.1's weight
  // question at all. This pins the ordering: the valueless check runs before
  // the `q`-name check.
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

/// RFC 9110 §12.5.1's worked example.
const TABLE_5_FIELD: &[u8] = b"text/*;q=0.3, text/plain;q=0.7, text/plain;format=flowed, \
    text/plain;format=fixed;q=0.4, */*;q=0.5";

#[test]
fn rfc_9110_table_5() {
  // The last row is `0.3`, NOT the `0.7` §12.5.1 prints: verified erratum 7138
  // corrects it, a leftover from RFC 7231's version of the example. The
  // section's own rules give the same answer independently —
  // `text/html;level=3` matches only `text/*;q=0.3` and `*/*;q=0.5`, and
  // `text/*` is the more specific shape.
  for (candidate, expected) in [
    (b"text/plain;format=flowed".as_slice(), 1000),
    (b"text/plain", 700),
    (b"text/html", 300),
    (b"image/jpeg", 500),
    (b"text/plain;format=fixed", 400),
    (b"text/html;level=3", 300),
  ] {
    let m = media_type(candidate).expect("valid candidate");
    assert_eq!(
      weight_for(&m, [TABLE_5_FIELD]),
      Ok(Weight(expected)),
      "{:?}",
      candidate
    );
  }
}

#[test]
fn rfc_7231_table_is_reproduced_too() {
  // A second worked example, richer in parameterised ranges than RFC 9110's.
  // `text/html;level=3` is 0.7 HERE and 0.3 in RFC 9110's, because the fields
  // differ — this is the row erratum 7138 traces.
  const FIELD: &[u8] = b"text/*;q=0.3, text/html;q=0.7, text/html;level=1, \
                         text/html;level=2;q=0.4, */*;q=0.5";
  for (candidate, expected) in [
    (b"text/html;level=1".as_slice(), 1000),
    (b"text/html", 700),
    (b"text/plain", 300),
    (b"image/jpeg", 500),
    (b"text/html;level=2", 400),
    (b"text/html;level=3", 700),
  ] {
    let m = media_type(candidate).expect("valid candidate");
    assert_eq!(
      weight_for(&m, [FIELD]),
      Ok(Weight(expected)),
      "{:?}",
      candidate
    );
  }
}

#[test]
fn a_parameterised_wildcard_outranks_its_bare_form() {
  // §12.5.1: "The media-range can include media type parameters that are
  // applicable to that range." — of ANY shape. A precedence rule transcribed
  // from the section's four-item printed list gives 0.1 here; the sentence
  // that generates the list gives 0.9.
  let m = media_type(b"text/plain;format=flowed").expect("valid");
  assert_eq!(
    weight_for(&m, [b"text/*;q=0.1, text/*;format=flowed;q=0.9".as_slice()]),
    Ok(Weight(900))
  );
}

#[test]
fn a_literal_asterisk_type_is_not_a_wildcard() {
  let m = media_type(b"application/json").expect("valid");
  assert_eq!(
    weight_for(&m, [b"*/json;q=0.9, */*;q=0.1".as_slice()]),
    Ok(Weight(100)),
    "*/json is type/subtype with the literal type `*`, and matches nothing real"
  );
}

#[test]
fn shape_beats_parameter_count() {
  // A recorded READING, not an RFC answer: §12.5.1 orders this pair nowhere.
  let m = media_type(b"text/plain;format=flowed").expect("valid");
  assert_eq!(
    weight_for(
      &m,
      [b"text/*;format=flowed;q=0.9, text/plain;q=0.2".as_slice()]
    ),
    Ok(Weight(200))
  );
}

#[test]
fn the_three_shapes_compete_at_once_and_the_narrowest_wins() {
  // Every shape carrying the SAME parameter, so only shape separates them.
  // Not a row of either RFC's table: both tables' parameterised ranges are
  // `type/subtype`, so neither exercises a parameterised wildcard losing to a
  // parameterised exact type.
  let m = media_type(b"text/plain;format=flowed").expect("valid");
  for field in [
    b"*/*;format=flowed;q=0.2, text/*;format=flowed;q=0.5, text/plain;format=flowed;q=0.8"
      .as_slice(),
    // Reversed, because a key that depended on field order here would be
    // reading precedence off the wrong component.
    b"text/plain;format=flowed;q=0.8, text/*;format=flowed;q=0.5, */*;format=flowed;q=0.2",
  ] {
    assert_eq!(weight_for(&m, [field]), Ok(Weight(800)), "{:?}", field);
  }
  // And the bare forms of all three lose to the parameterised exact type,
  // wherever they sit.
  assert_eq!(
    weight_for(
      &m,
      [b"text/plain;format=flowed;q=0.9, */*;q=0.1, text/*;q=0.3, text/plain;q=0.6".as_slice()]
    ),
    Ok(Weight(900))
  );
}

#[test]
fn matched_count_outranks_field_order() {
  // Two ranges of the SAME shape differing only in how many of the candidate's
  // parameters they matched. Neither RFC table has this pair either.
  let m = media_type(b"text/html;a=1;b=2").expect("valid");
  for field in [
    b"text/html;a=1;q=0.4, text/html;a=1;b=2;q=0.7".as_slice(),
    b"text/html;a=1;b=2;q=0.7, text/html;a=1;q=0.4",
  ] {
    assert_eq!(weight_for(&m, [field]), Ok(Weight(700)), "{:?}", field);
  }
}

#[test]
fn a_residual_tie_takes_the_first_in_field_order() {
  // Also a recorded reading. The contract is that the choice is STABLE.
  let m = media_type(b"text/plain").expect("valid");
  assert_eq!(
    weight_for(&m, [b"text/plain;q=0.3, text/plain;q=0.9".as_slice()]),
    Ok(Weight(300))
  );
}

#[test]
fn an_equal_specificity_tie_is_settled_by_the_strict_comparison_alone() {
  // The precedence key carries no positional counter: two ranges that tie on
  // shape AND on matched parameter count produce EQUAL keys, and first-in-field
  // -order is what the strict `<` means. These pin that on both sides of a
  // §5.2 line join, since the walk is one list either way and a tie has to be
  // decided the same way in both places.
  let plain = media_type(b"text/plain").expect("valid");
  // Equal shape, equal parameter count (zero), within one line.
  assert_eq!(
    weight_for(&plain, [b"text/plain;q=0.3, text/plain;q=0.9".as_slice()]),
    Ok(Weight(300))
  );
  // The same tie across a line boundary.
  assert_eq!(
    weight_for(
      &plain,
      [b"text/plain;q=0.3".as_slice(), b"text/plain;q=0.9"]
    ),
    Ok(Weight(300))
  );
  // Equal shape and a nonzero equal parameter count, both ways round.
  let one = media_type(b"text/plain;a=1").expect("valid");
  assert_eq!(
    weight_for(
      &one,
      [b"text/plain;a=1;q=0.3, text/plain;a=1;q=0.9".as_slice()]
    ),
    Ok(Weight(300))
  );
  assert_eq!(
    weight_for(
      &one,
      [b"text/plain;a=1;q=0.3".as_slice(), b"text/plain;a=1;q=0.9"]
    ),
    Ok(Weight(300))
  );
  // Wildcards tie with each other too, and the first still wins.
  assert_eq!(
    weight_for(&plain, [b"*/*;q=0.2".as_slice(), b"*/*;q=0.8"]),
    Ok(Weight(200))
  );
  // A tie is not a rank: a genuinely higher-precedence range on a LATER line
  // still displaces an earlier one, so this is a tie rule and not last-loses.
  assert_eq!(
    weight_for(&plain, [b"*/*;q=0.2".as_slice(), b"text/plain;q=0.8"]),
    Ok(Weight(800))
  );
}

#[test]
fn duplicate_range_parameters_match_per_instance() {
  let one = media_type(b"text/html;a=1").expect("valid");
  let two = media_type(b"text/html;a=1;a=1").expect("valid");
  let field = [b"text/html;a=1;a=1;q=0.8, text/html;a=1;q=0.3".as_slice()];
  // The doubled range needs TWO instances and the first candidate has one.
  assert_eq!(weight_for(&one, field), Ok(Weight(300)));
  // The second candidate has both, so the doubled range earns its count.
  assert_eq!(weight_for(&two, field), Ok(Weight(800)));
}

#[test]
fn duplicate_instances_pair_up_in_any_order_and_never_inflate_precedence() {
  // Per instance means PAIRING, not positional equality: `a=2;a=1` against a
  // candidate's `a=1;a=2` spends both instances and counts two.
  let both = media_type(b"text/html;a=1;a=2").expect("valid");
  assert_eq!(
    weight_for(
      &both,
      [b"text/html;a=2;a=1;q=0.8, text/html;a=1;q=0.3".as_slice()]
    ),
    Ok(Weight(800))
  );
  // A doubled range whose second instance has no unspent counterpart matches
  // nothing, even though the NAME appears twice on both sides.
  let twice_the_same = media_type(b"text/html;a=1;a=1").expect("valid");
  assert_eq!(
    weight_for(
      &twice_the_same,
      [b"text/html;a=1;a=2;q=0.8, text/html;a=1;q=0.3".as_slice()]
    ),
    Ok(Weight(300))
  );
  // The reading's whole point: repetition may not buy precedence. Under set
  // membership the tripled range would win with 0.9, and a range that says
  // strictly less about the candidate would outrank the one that describes it
  // exactly.
  let described = media_type(b"text/html;a=1;b=2").expect("valid");
  assert_eq!(
    weight_for(
      &described,
      [b"text/html;a=1;a=1;a=1;q=0.9, text/html;a=1;b=2;q=0.2".as_slice()]
    ),
    Ok(Weight(200))
  );
}

#[test]
fn a_range_parameter_the_candidate_lacks_does_not_match() {
  let m = media_type(b"text/plain").expect("valid");
  assert_eq!(
    weight_for(
      &m,
      [b"text/plain;format=flowed;q=0.9, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(100))
  );
}

#[test]
fn a_candidate_parameter_the_range_lacks_still_matches() {
  let m = media_type(b"text/html;level=3").expect("valid");
  assert_eq!(
    weight_for(&m, [b"text/*;q=0.3".as_slice()]),
    Ok(Weight(300))
  );
}

#[test]
fn parameter_values_compare_after_unescaping_and_byte_exact() {
  let m = media_type(b"text/html;charset=utf-8").expect("valid");
  // Quoted and unquoted are the same value (§5.6.6).
  assert_eq!(
    weight_for(
      &m,
      [b"text/html;charset=\"utf-8\";q=0.6, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(600))
  );
  // Escapes are removed before comparing (§5.6.4's recipient MUST).
  assert_eq!(
    weight_for(
      &m,
      [b"text/html;charset=\"utf\\-8\";q=0.6, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(600))
  );
  // Byte-exact is the DEFAULT, not the whole rule: §8.3.1 leaves which
  // parameters fold to each registration, so a parameter RFC 9110 says nothing
  // about compares as written and a case-different range falls through to the
  // coarser match. `charset`, which RFC 9110 DOES settle, is the one exception
  // and has its own tests below.
  let boundary = media_type(b"multipart/form-data;boundary=abc").expect("valid");
  assert_eq!(
    weight_for(
      &boundary,
      [b"multipart/form-data;boundary=ABC;q=0.6, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(100))
  );
}

#[test]
fn a_charset_value_folds_case_so_a_q_zero_range_is_not_escaped() {
  // §8.3.2: "In the fields defined by this document, charset names appear
  // either in parameters (Content-Type), or, for Accept-Encoding, in the form
  // of a plain token. In both cases, charset names are matched
  // case-insensitively."
  //
  // The sharp case, and why this is not cosmetic: a field that refuses this
  // representation OUTRIGHT must not be answered with the full weight of the
  // range behind it. Comparing `charset` byte-exact makes the `q=0` range miss
  // and the bare `text/plain` range win, which tells a server to serve, at
  // weight 1, what the client just refused.
  let m = media_type(b"text/plain;charset=utf-8").expect("valid");
  assert_eq!(
    weight_for(
      &m,
      [b"text/plain;charset=UTF-8;q=0, text/plain;q=1".as_slice()]
    ),
    Ok(Weight::ZERO)
  );
  // The same fold the other way round — the candidate is the upper-case one —
  // and through a quoted-string, since §5.6.6 makes the two forms one value.
  let upper = media_type(b"text/plain;charset=UTF-8").expect("valid");
  assert_eq!(
    weight_for(
      &upper,
      [b"text/plain;charset=\"utf-8\";q=0, text/plain;q=1".as_slice()]
    ),
    Ok(Weight::ZERO)
  );
  // And it is a MATCH, not merely a refusal: the folded range wins its own
  // weight where the coarser one would otherwise have given `0.1`.
  assert_eq!(
    weight_for(
      &m,
      [b"text/plain;charset=UTF-8;q=0.6, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(600))
  );
  // §5.6.6 makes the parameter NAME case-insensitive, so the exception is
  // selected by which parameter this is rather than by how it is spelled.
  let named = media_type(b"text/plain;Charset=utf-8").expect("valid");
  assert_eq!(
    weight_for(
      &named,
      [b"text/plain;CHARSET=UTF-8;q=0, text/plain;q=1".as_slice()]
    ),
    Ok(Weight::ZERO)
  );
}

#[test]
fn a_charset_differing_in_value_still_does_not_match() {
  // The mirror of the test above, and what keeps it from being "charset always
  // matches": folding CASE is not folding the value. Two different charset
  // names are two different values, so the `q=0` range does not apply and the
  // wildcard behind it does.
  let m = media_type(b"text/plain;charset=utf-8").expect("valid");
  assert_eq!(
    weight_for(
      &m,
      [b"text/plain;charset=ISO-8859-1;q=0, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(100))
  );
  // Nor is it a prefix match, in either direction.
  assert_eq!(
    weight_for(&m, [b"text/plain;charset=UTF-88;q=0, */*;q=0.1".as_slice()]),
    Ok(Weight(100))
  );
  assert_eq!(
    weight_for(&m, [b"text/plain;charset=UTF;q=0, */*;q=0.1".as_slice()]),
    Ok(Weight(100))
  );
}

#[test]
fn a_non_charset_parameter_value_still_compares_byte_exact() {
  // The exception stays an exception. RFC 9110 gives `boundary` no case rule
  // at all, so a range whose `boundary` differs only in case does not match
  // and a `q=0` on it does not reach this candidate.
  let m = media_type(b"multipart/form-data;boundary=AbC").expect("valid");
  assert_eq!(
    weight_for(
      &m,
      [b"multipart/form-data;boundary=abc;q=0, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(100))
  );
  // The same for a parameter that merely LOOKS like the exception: the rule is
  // on the name `charset`, not on anything that contains it.
  let near = media_type(b"text/html;charsets=UTF-8").expect("valid");
  assert_eq!(
    weight_for(
      &near,
      [b"text/html;charsets=utf-8;q=0, */*;q=0.1".as_slice()]
    ),
    Ok(Weight(100))
  );
  let level = media_type(b"text/html;level=A").expect("valid");
  assert_eq!(
    weight_for(&level, [b"text/html;level=a;q=0, */*;q=0.1".as_slice()]),
    Ok(Weight(100))
  );
  // …and byte-exact still ADMITS the identical value, so those three are
  // matching failures rather than a parameter that can never match at all.
  assert_eq!(
    weight_for(&m, [b"multipart/form-data;boundary=AbC;q=0".as_slice()]),
    Ok(Weight::ZERO)
  );
  // The same answer through the policy entry point with an empty policy, which
  // is what `weight_for` passes: the two must not drift apart.
  assert_eq!(
    weight_for_with(
      &m,
      [b"multipart/form-data;boundary=abc;q=0, */*;q=0.1".as_slice()],
      NO_FOLDING
    ),
    Ok(Weight(100))
  );
}

/// A policy that adds nothing — the one `weight_for` passes.
const NO_FOLDING: fn(&[u8], &[u8], &[u8]) -> bool = |_, _, _| false;

/// RFC 9782 §6.3 registers `eat_profile` for `application/eat+cwt` with a
/// case-insensitive value. RFC 9110 settles nothing about it, so it is exactly
/// the class `weight_for_with` exists for.
const EAT_PROFILE: fn(&[u8], &[u8], &[u8]) -> bool = |ty, subtype, name| {
  ty.eq_ignore_ascii_case(b"application")
    && subtype.eq_ignore_ascii_case(b"eat+cwt")
    && name.eq_ignore_ascii_case(b"eat_profile")
};

#[test]
fn a_registered_parameter_needs_the_callers_own_rule() {
  // The reproduction, asserted on BOTH sides so it pins the hook rather than a
  // value: the default is byte-exact and misses the refusal, and the caller's
  // own rule sees it. A test asserting only the second would also pass if the
  // default had started folding everything.
  let m =
    media_type(b"application/eat+cwt;eat_profile=\"tag:evidence.example,2022\"").expect("valid");
  let field = b"application/eat+cwt;eat_profile=\"TAG:EVIDENCE.EXAMPLE,2022\";q=0, */*;q=1";

  // Byte-exact: the `q=0` range does not match, and the wildcard behind it
  // answers. This is the documented default, and the reason the doc warns that
  // a refusal can be missed.
  assert_eq!(weight_for(&m, [field.as_slice()]), Ok(Weight::ONE));
  assert_eq!(
    weight_for_with(&m, [field.as_slice()], NO_FOLDING),
    Ok(Weight::ONE)
  );

  // With the registration's rule supplied, the refusal is seen.
  assert_eq!(
    weight_for_with(&m, [field.as_slice()], EAT_PROFILE),
    Ok(Weight::ZERO)
  );

  // And folding is still not blanket matching: a different profile is a
  // different value under the same policy, so the `q=0` misses on merit.
  assert_eq!(
    weight_for_with(
      &m,
      [b"application/eat+cwt;eat_profile=\"tag:other.example,2022\";q=0, */*;q=1".as_slice()],
      EAT_PROFILE
    ),
    Ok(Weight::ONE)
  );
}

#[test]
fn the_folding_policy_is_keyed_on_the_media_type_and_not_the_name_alone() {
  // A parameter is registered PER media type, so the policy is asked about all
  // three. `EAT_PROFILE` answers only for `application/eat+cwt`; the same
  // parameter name on another type keeps comparing byte-exact.
  let other =
    media_type(b"application/eat+jwt;eat_profile=\"tag:evidence.example,2022\"").expect("valid");
  assert_eq!(
    weight_for_with(
      &other,
      [b"application/eat+jwt;eat_profile=\"TAG:EVIDENCE.EXAMPLE,2022\";q=0, */*;q=1".as_slice()],
      EAT_PROFILE
    ),
    Ok(Weight::ONE),
    "the policy names eat+cwt, not eat+jwt"
  );

  // The type handed to the policy is the CANDIDATE's, not the range's: this
  // range is `*/*` and carries no type of its own, and the parameter must still
  // fold, because the candidate is what the registration is about.
  let cwt =
    media_type(b"application/eat+cwt;eat_profile=\"tag:evidence.example,2022\"").expect("valid");
  // The trailing `*/*;q=1` MATCHES either way, so this assertion discriminates:
  // without the fold the parameterised range misses and the bare wildcard
  // answers `ONE`; with it the parameterised range outranks the bare one on
  // matched-parameter count and the `q=0` answers.
  assert_eq!(
    weight_for_with(
      &cwt,
      [b"*/*;eat_profile=\"TAG:EVIDENCE.EXAMPLE,2022\";q=0, */*;q=1".as_slice()],
      EAT_PROFILE
    ),
    Ok(Weight::ZERO)
  );
}

#[test]
fn charset_folds_even_when_the_policy_adds_nothing() {
  // §8.3.2 is RFC 9110's own rule, not a default a caller may switch off, so
  // it applies UNDER any policy. A design that made `charset` merely the
  // default argument would answer `ONE` here the moment a caller supplied a
  // policy of its own — which is a silent regression on the most common
  // parameter there is.
  let m = media_type(b"text/plain;charset=utf-8").expect("valid");
  let field = b"text/plain;charset=UTF-8;q=0, text/plain;q=1";
  assert_eq!(weight_for(&m, [field.as_slice()]), Ok(Weight::ZERO));
  assert_eq!(
    weight_for_with(&m, [field.as_slice()], NO_FOLDING),
    Ok(Weight::ZERO)
  );
  // Including under a policy that is busy with something else entirely.
  assert_eq!(
    weight_for_with(&m, [field.as_slice()], EAT_PROFILE),
    Ok(Weight::ZERO)
  );
}

#[test]
fn parameter_names_compare_case_insensitively() {
  let m = media_type(b"text/html;Charset=utf-8").expect("valid");
  assert_eq!(
    weight_for(&m, [b"text/html;charset=utf-8;q=0.6, */*;q=0.1".as_slice()]),
    Ok(Weight(600))
  );
}

#[test]
fn an_unmatched_candidate_weighs_zero() {
  // §12.4.3: "If no wildcard is present, values that are not explicitly
  // mentioned in the field are considered unacceptable."
  //
  // Row 3 of the three-way rule on `weight_for`: the field was SENT and did
  // not mention this candidate. Row 1 — no field at all — is a different input
  // with a different answer; see the absence test below before changing any of
  // these to `ONE`.
  let m = media_type(b"image/png").expect("valid");
  assert_eq!(weight_for(&m, [b"text/html".as_slice()]), Ok(Weight::ZERO));
  assert_eq!(weight_for(&m, [b"".as_slice()]), Ok(Weight::ZERO));
  // An explicit q=0 is the same answer, and the RFC draws no distinction.
  assert_eq!(weight_for(&m, [b"*/*;q=0".as_slice()]), Ok(Weight::ZERO));
}

/// No field lines at all — the natural spelling of a request that carried no
/// `Accept` header.
const NO_ACCEPT: [&[u8]; 0] = [];

#[test]
fn an_absent_accept_field_is_no_preference_not_a_refusal() {
  // §12.4.1, titled Absence: "For each of the content negotiation fields, a
  // request that does not contain the field implies that the sender has no
  // preference on that dimension of negotiation."
  //
  // Row 1 of `weight_for`'s three-way rule. No preference is not a refusal, so
  // the candidate keeps §12.4.2's default weight and no matching happens at
  // all — including for a candidate no real field would have named.
  let m = media_type(b"text/html").expect("valid");
  assert_eq!(weight_for(&m, NO_ACCEPT), Ok(Weight::ONE));
  let odd = media_type(b"application/vnd.example+json;v=3").expect("valid");
  assert_eq!(weight_for(&odd, NO_ACCEPT), Ok(Weight::ONE));

  // The CONTRAST is what this test exists for, so it is asserted here rather
  // than left to the tests either side: an answer of `ONE` for row 1 is only
  // right if rows 2 and 3 are still `ZERO`. A rule that returned `ONE`
  // whenever nothing matched would satisfy the two assertions above and be
  // wrong about every present field.
  assert_eq!(
    weight_for(&m, [b"".as_slice()]),
    Ok(Weight::ZERO),
    "row 2: a field that WAS sent, with an empty list"
  );
  assert_eq!(
    weight_for(&m, [b"image/png".as_slice()]),
    Ok(Weight::ZERO),
    "row 3: a field that WAS sent, naming something else"
  );
}

#[test]
fn a_present_but_empty_accept_field_is_not_an_absent_one() {
  // Row 2, on its own. `Accept = #( media-range [ weight ] )`, and §5.6.1.1
  // expands the construct to `#element => [ 1#element ]`, so an empty list is
  // a field the sender was entitled to write. It was SENT, it named no range,
  // and §12.4.3 makes an unmentioned value unacceptable — which is the same
  // answer as row 3 and NOT the answer to row 1.
  let m = media_type(b"text/html").expect("valid");
  for field in [
    b"".as_slice(),
    // Whitespace is OWS, not a range (§5.6.3).
    b" ",
    // §5.6.1.2: "A recipient MUST parse and ignore a reasonable number of
    // empty list elements".
    b",",
    b" , ,",
  ] {
    assert_eq!(weight_for(&m, [field]), Ok(Weight::ZERO), "{field:?}");
  }
  // Several lines that are all empty are still a field that was sent: §5.2
  // joins them into one value, and that value names no range either.
  assert_eq!(
    weight_for(&m, [b"".as_slice(), b""]),
    Ok(Weight::ZERO),
    "two empty lines are a present field, not an absent one"
  );
  // And one empty line is not a shorter way of writing no lines: the two
  // inputs differ, and so do the answers.
  assert_ne!(weight_for(&m, [b"".as_slice()]), weight_for(&m, NO_ACCEPT));
}

#[test]
fn the_absence_rule_leaves_a_present_field_alone() {
  // Reading presence off the input costs the walk its first line, which is
  // handed straight back to it. These pin that nothing was dropped or
  // reordered on the way.
  let m = media_type(b"text/html").expect("valid");
  // A matching range on the ONLY line still wins its own weight.
  assert_eq!(
    weight_for(&m, [b"text/html;q=0.4, */*;q=0.1".as_slice()]),
    Ok(Weight(400))
  );
  // A range on the FIRST line is still reachable when later lines follow it.
  assert_eq!(
    weight_for(&m, [b"text/html;q=0.4".as_slice(), b"image/png;q=0.9"]),
    Ok(Weight(400))
  );
  // An empty FIRST line is a present field whose later lines still walk: §5.2
  // joins them with a comma, and §5.6.1.2 ignores the empty element it makes.
  assert_eq!(
    weight_for(&m, [b"".as_slice(), b"text/html;q=0.4"]),
    Ok(Weight(400))
  );
  // A fault on the first line is still a fault, rather than an absence.
  assert_eq!(
    weight_for(&m, [b"text/html;q=bogus".as_slice()]),
    Err(MediaError::BadWeight)
  );
}

#[test]
fn a_malformed_accept_yields_err_not_a_weight() {
  let m = media_type(b"text/html").expect("valid");
  assert_eq!(
    weight_for(&m, [b"text/html;q=blah".as_slice()]),
    Err(MediaError::BadWeight)
  );
}

#[test]
fn a_candidate_past_the_tracking_bound_is_refused_not_mis_ranked() {
  // The two fixtures are sized off the published constant.
  assert_eq!(MAX_TRACKED_PARAMS, 16);
  const SIXTEEN: &[u8] = b"text/plain;p1=1;p2=2;p3=3;p4=4;p5=5;p6=6;p7=7;p8=8;\
                           p9=9;p10=10;p11=11;p12=12;p13=13;p14=14;p15=15;p16=16";
  const SEVENTEEN: &[u8] = b"text/plain;p1=1;p2=2;p3=3;p4=4;p5=5;p6=6;p7=7;p8=8;\
                             p9=9;p10=10;p11=11;p12=12;p13=13;p14=14;p15=15;p16=16;\
                             p17=17";
  let sixteen = media_type(SIXTEEN).expect("valid candidate");
  let seventeen = media_type(SEVENTEEN).expect("valid candidate");
  assert_eq!(sixteen.params().count(), MAX_TRACKED_PARAMS);
  assert_eq!(seventeen.params().count(), MAX_TRACKED_PARAMS + 1);
  // Every slot reachable: the range's parameter matches none of the sixteen,
  // so the walk sees all of them and still answers.
  let field = [b"text/plain;zz=1;q=0.9, */*;q=0.1".as_slice()];
  assert_eq!(weight_for(&sixteen, field), Ok(Weight(100)));
  // One instance more than the walk can record: a refusal, never a weight that
  // silently ignored the parameters it could not see.
  assert_eq!(
    weight_for(&seventeen, field),
    Err(MediaError::TooManyParameters)
  );
  // A PARAMETERLESS range spends no slot, so the bound never reaches it and the
  // same 17-parameter candidate still matches at every shape.
  for line in [
    b"*/*;q=0.4".as_slice(),
    b"text/*;q=0.4",
    b"text/plain;q=0.4",
  ] {
    assert_eq!(
      weight_for(&seventeen, [line]),
      Ok(Weight(400)),
      "{:?}",
      line
    );
  }
  // Nor is the refusal categorical: a range parameter answered before the
  // bound never needs a slot past it.
  assert_eq!(
    weight_for(&seventeen, [b"text/plain;p1=1;q=0.7".as_slice()]),
    Ok(Weight(700))
  );
}

#[test]
fn type_and_subtype_compare_case_insensitively() {
  // RFC 9110 §8.3.1: "The type and subtype tokens are case-insensitive." An RFC
  // rule rather than one of the readings §5.3's key records, and the only test
  // in this file that fails if either half of the comparison becomes `!=`.
  let upper = media_type(b"TEXT/Plain").expect("valid");
  // `text/*` exercises the type half alone — a `type/*` range never reads a
  // subtype — and `text/plain` exercises both and outranks it, so the answer
  // moves whichever half stops folding case: 0.3 if only the subtype does,
  // 0 if the type does.
  assert_eq!(
    weight_for(&upper, [b"text/*;q=0.3, text/plain;q=0.7".as_slice()]),
    Ok(Weight(700))
  );
  // The fold is symmetric, so it also holds with the cases swapped between the
  // field and the candidate.
  let lower = media_type(b"text/plain").expect("valid");
  assert_eq!(
    weight_for(&lower, [b"TEXT/*;q=0.3, TEXT/PLAIN;q=0.7".as_slice()]),
    Ok(Weight(700))
  );
  // Folding case is not folding tokens together: `html` is still not `plain`,
  // in any case.
  assert_eq!(
    weight_for(&upper, [b"TEXT/HTML;q=0.9, */*;q=0.1".as_slice()]),
    Ok(Weight(100))
  );
}

#[test]
fn a_field_split_across_lines_is_one_list_with_one_running_order() {
  // RFC 9110 §5.2 makes a repeated field one comma-joined value, and `accept`
  // walks the lines as that one list. Two consequences live only here.
  let m = media_type(b"text/plain").expect("valid");
  // First: a later line's range is reachable at all, and wins on merit.
  assert_eq!(
    weight_for(&m, [b"text/*;q=0.3".as_slice(), b"text/plain;q=0.8"]),
    Ok(Weight(800))
  );
  // Second: field order settles a residual tie ACROSS the join and not only
  // within a line. The two `text/plain` ranges tie on shape and on matched
  // parameter count, and the one on the SECOND line loses because the key
  // comparison is strict — the incumbent stands. A `<=` there would answer
  // 0.9, which is the last-wins contract rather than this one.
  assert_eq!(
    weight_for(
      &m,
      [
        b"text/html;q=0.1, text/plain;q=0.3".as_slice(),
        b"text/plain;q=0.9"
      ]
    ),
    Ok(Weight(300))
  );
}

#[test]
fn a_value_spanning_the_join_surfaces_through_weight_for() {
  // The design's one partiality: a quoted value opened on one line and closed
  // on the next is well formed and not one contiguous slice, so it is an error
  // rather than a weight — and the error has to travel out of `weight_for`,
  // not be skipped as an unmatched range.
  let m = media_type(b"text/plain").expect("valid");
  assert_eq!(
    weight_for(
      &m,
      [
        b"text/plain;boundary=\"a".as_slice(),
        b"b\";q=0.5, */*;q=0.1"
      ]
    ),
    Err(MediaError::ValueSpansFieldLines)
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
    // RFC 9110 §12.5.1: "Recipients SHOULD process any parameter named "q" as
    // weight, regardless of parameter ordering." §12.4.2 names it "q"
    // (case-insensitive).
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
