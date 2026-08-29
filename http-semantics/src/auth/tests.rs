use super::*;
use crate::grammar::{ListError, parameterised_list};

// ── RFC 9110 §11.2: the two spellings of a value ─────────────────────────────

#[test]
fn a_value_is_a_quoted_string_or_a_token() {
  let quoted = auth_param(br#"realm="x""#).unwrap();
  assert_eq!(quoted.name(), b"realm");
  assert!(matches!(quoted.value(), Ok(ParamValue::Quoted(v)) if v == b"x"));

  // RFC 9110 §11.5 says of this very parameter: "For historical reasons, a
  // sender MUST only generate the quoted-string syntax." That binds a SENDER,
  // and the sentence after it is permissive about recipients, so neither makes
  // the bare token a fault to report. §11.2's production admits it, and §11.2
  // gives the reason a generic component honours it.
  let token = auth_param(b"realm=x").unwrap();
  assert_eq!(token.name(), b"realm");
  assert!(matches!(token.value(), Ok(ParamValue::Token(v)) if v == b"x"));
}

#[test]
fn the_bws_around_the_equals_is_read_and_removed() {
  for spelling in [
    &br#"realm = "x""#[..],
    br#"realm ="x""#,
    br#"realm= "x""#,
    b"realm\t=\t\"x\"",
  ] {
    let param = auth_param(spelling).unwrap();
    assert_eq!(param.name(), b"realm", "{spelling:?}");
    assert!(
      matches!(param.value(), Ok(ParamValue::Quoted(v)) if v == b"x"),
      "{spelling:?}"
    );
  }
}

#[test]
fn a_bws_parameter_is_what_the_semicolon_walker_refuses() {
  // The module doc's claim, executed. §5.6.6's `parameter` has no BWS, so the
  // walker for it reads `realm ` as the name and refuses a token that is not
  // one; §11.2's `auth-param` has the BWS, and the same bytes are a parameter.
  let mut members = parameterised_list([&br#"m;realm = "x""#[..]]);
  let member = members.next().unwrap().unwrap();
  assert!(matches!(
    member.params().next(),
    Some(Err(ListError::NotAToken))
  ));

  assert_eq!(auth_param(br#"realm = "x""#).unwrap().name(), b"realm");
}

// ── The shapes that are not an auth-param ────────────────────────────────────

#[test]
fn a_name_with_no_equals_is_not_a_parameter() {
  assert_eq!(
    auth_param(b"realm").unwrap_err(),
    AuthError::MalformedParameter
  );
  // The name has to be a whole `token` up to the BWS, so a space inside it is
  // not BWS the production would remove.
  assert_eq!(
    auth_param(b"re alm=x").unwrap_err(),
    AuthError::MalformedParameter
  );
  // RFC 9110 §5.6.2's `token = 1*tchar` names at least one character, so there
  // is no parameter whose name is empty.
  assert_eq!(
    auth_param(b"=x").unwrap_err(),
    AuthError::MalformedParameter
  );
}

#[test]
fn a_name_with_no_value_is_not_a_parameter() {
  // At the `auth-param` level `realm=` does not parse: the production requires
  // a value behind the `=`, and there is none.
  //
  // This is NOT the last word on those bytes, and the two answers do not
  // conflict — they are given at different levels of RFC 9110 §11's grammar.
  // In `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` the choice
  // is made one level up, and §11.2's
  // `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
  // ends in a run of `=` signs that takes this one. So a credential reading
  // `Scheme foo=` as a `token68` and this parameter reading `realm=` as
  // malformed are the same grammar answering two different questions, and
  // repairing either to agree with the other would break the level it belongs
  // to.
  assert_eq!(
    auth_param(b"realm=").unwrap_err(),
    AuthError::MalformedParameter
  );
}

#[test]
fn a_value_is_one_alternative_taken_whole() {
  // `( token / quoted-string )` leaves nothing over: bytes behind a closed
  // string, or behind a token, are not part of either alternative.
  for leftover in [&br#"realm="x"y"#[..], b"realm=x y", br#"realm=x"y""#] {
    assert_eq!(
      auth_param(leftover).unwrap_err(),
      AuthError::MalformedParameter,
      "{leftover:?}"
    );
  }
}

#[test]
fn an_open_string_and_a_forbidden_byte_are_told_apart() {
  // Open where the element ends: nothing here can close it.
  assert_eq!(
    auth_param(br#"realm="x"#).unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  // %x00 is neither `qdtext` nor an octet `quoted-pair` may escape. The crate
  // keeps this apart from the open case, and so does this module: after it, a
  // walker can no longer tell a separating comma from data.
  assert_eq!(
    auth_param(b"realm=\"a\x00b\"").unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    auth_param(b"realm=\"a\\\x00b\"").unwrap_err(),
    AuthError::InvalidQuotedString
  );
}

// ── §5.6.4's escape, which an auth-param value really has ────────────────────

#[test]
fn a_quoted_pair_in_a_value_unescapes() {
  // Unlike §8.8.3's `opaque-tag`, where a backslash is content, an
  // `auth-param` value is a real quoted-string: the sender wrote three bytes.
  // §11.6.1's own worked example carries an escaped DQUOTE in exactly this
  // shape, in its `title` parameter.
  let param = auth_param(br#"realm="a\"b""#).unwrap();
  assert_eq!(param.name(), b"realm");
  let value = param.value().unwrap();
  assert!(matches!(value, ParamValue::Quoted(raw) if raw == br#"a\"b"#));
  assert!(value.unescaped().eq(br#"a"b"#.iter().copied()));
}

#[test]
fn an_empty_quoted_string_is_a_value() {
  // RFC 9110 §5.6.4's
  // `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` puts no floor on
  // the content, so this parameter's value is no bytes at all — and a reader
  // demanding one would refuse a value the grammar admits.
  let param = auth_param(br#"realm="""#).unwrap();
  assert_eq!(param.name(), b"realm");
  assert!(matches!(param.value(), Ok(ParamValue::Quoted(v)) if v.is_empty()));

  // `value()` stores nothing and re-derives from the bytes it holds, so asking
  // twice answers the same.
  assert!(matches!(param.value(), Ok(ParamValue::Quoted(v)) if v.is_empty()));
}

// ── RFC 9110 §11.2's token68, and the branch §11.3 leaves to a recipient ─────

#[test]
fn a_token68_is_a_run_of_its_own_alphabet_and_then_a_pad() {
  // RFC 9110 §11.2:
  // `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
  assert_eq!(token68_end(b"dGVzdA==", 0), Some(8));
  assert_eq!(token68_end(b"mF_9.B5f-4.1JqM", 0), Some(15));
  // `+` and `/` are the two the base64 alphabet needs. `/` is no §5.6.2
  // `tchar`, so a run this admits is not a `token` and nothing here reads it
  // as one.
  assert_eq!(token68_end(b"YWJj+ZGVm/Zw==", 0), Some(14));

  // `1*` puts a floor of one byte under the alphabet run, so a pad standing
  // on its own is not a token68 with an empty run in front of it — it is not
  // a token68.
  assert_eq!(token68_end(b"====", 0), None);
  assert_eq!(token68_end(b"", 0), None);
  assert_eq!(token68_end(b"!", 0), None);

  // The two runs go in that order and there is no way back: `a=b` ends at the
  // `b` rather than reading it as more of the alphabet.
  assert_eq!(token68_end(b"a=b", 0), Some(2));
  // A `tchar` outside this alphabet ends the run where it stands.
  assert_eq!(token68_end(b"foo!bar", 0), Some(3));
  // RFC 9110 §11.2 sized the set to hold an encoding "with or without
  // padding, but excluding whitespace", so SP is not in it and ends the run.
  assert_eq!(token68_end(b"dGVzdA== ", 0), Some(8));

  // `at` is a cursor into a whole field value, not always its first byte.
  assert_eq!(token68_end(b"Basic dGVzdA==", 6), Some(14));
  assert_eq!(token68_end(b"Basic dGVzdA==", 99), None);
}

#[test]
fn a_run_that_ends_its_element_is_read_as_token68() {
  // The first two of spec §4.2's rows. `Bearer`'s value carries no `=` at
  // all; `Basic`'s carries two, and both of them are the production's pad.
  assert_eq!(
    token68(b"Bearer mF_9.B5f-4.1JqM", 7),
    Some(&b"mF_9.B5f-4.1JqM"[..])
  );
  assert_eq!(token68(b"Basic dGVzdA==", 6), Some(&b"dGVzdA=="[..]));
}

#[test]
fn a_run_with_more_of_its_element_behind_it_is_read_as_a_parameter() {
  // `Newauth foo=bar`: the `*"="` pad has token bytes behind it, so the run
  // stops inside the element instead of ending it and the other branch is the
  // one that applies — where the same bytes are one whole `auth-param`.
  assert_eq!(token68(b"Newauth foo=bar", 8), None);
  let param = auth_param(b"foo=bar").unwrap();
  assert_eq!(param.name(), b"foo");
  assert!(matches!(param.value(), Ok(ParamValue::Token(v)) if v == b"bar"));
}

#[test]
fn a_trailing_equals_ends_a_token68_and_does_not_start_a_missing_value() {
  // Spec §4.2's deliberate resolution: `Scheme foo=` is a `token68` (`foo`,
  // then one byte of the pad) and is also an `auth-param` that never got its
  // value. Only the first is a derivation, so it is the reading taken and no
  // fault is reported.
  assert_eq!(token68(b"Scheme foo=", 7), Some(&b"foo="[..]));

  // `a_name_with_no_value_is_not_a_parameter` asserts the OPPOSITE answer
  // about these same bytes, and both tests are right — they ask different
  // levels of §11's grammar. That one asks `auth_param`, which sees one
  // element and finds no value behind the `=`; this one asks the level above,
  // where RFC 9110 §11.3's
  // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` offers a
  // branch that ends in `*"="`. Repairing either to agree with the other
  // would make it answer for a level it does not belong to.
  assert_eq!(
    auth_param(b"foo=").unwrap_err(),
    AuthError::MalformedParameter
  );

  // Spec §10's `["Basic realm=", "x"]` row rests on this reading, and this is
  // the half of it one field line holds. §5.2's join and the challenge it
  // then splits are not this task's.
  assert_eq!(token68(b"Basic realm=", 6), Some(&b"realm="[..]));
}

#[test]
fn a_comma_ends_the_run_and_the_element_with_it() {
  // `Scheme foo=,bar`: §5.6.1 puts an element boundary at the comma, so the
  // run reaches the end of its element there and `bar` is no part of it.
  assert_eq!(token68(b"Scheme foo=,bar", 7), Some(&b"foo="[..]));

  // The `OWS` RFC 9110 §5.6.1.2 hangs on that comma —
  // `#element => [ element ] *( OWS "," OWS [ element ] )` — belongs to the
  // list rather than to the run, so it does not disqualify the reading.
  assert_eq!(
    token68(b"Basic dGVzdA== , Newauth realm=\"x\"", 6),
    Some(&b"dGVzdA=="[..])
  );
  assert_eq!(token68(b"Basic dGVzdA==\t,x", 6), Some(&b"dGVzdA=="[..]));

  // A parameter-shaped element behind that comma does not reopen the one in
  // front of it. Nothing derives `Basic dGVzdA==, realm=x` — `realm=x` is no
  // challenge without `1*SP` behind its token, and `dGVzdA==` is no parameter
  // — so a walk that read the comma the other way would be choosing which
  // fault to report, not rescuing a conforming value.
  assert_eq!(
    token68(b"Basic dGVzdA==, realm=x", 6),
    Some(&b"dGVzdA=="[..])
  );

  // A field line's end and that comma are one terminator and not two: §5.2
  // joins repeated lines with a comma, so a run reaching the end of one line
  // meets the comma next and answers the same either way.
  assert_eq!(
    token68(b"Basic dGVzdA==", 6),
    token68(b"Basic dGVzdA==,x", 6)
  );
}

#[test]
fn an_element_that_is_no_run_at_all_is_read_as_a_parameter_and_fails_there() {
  // Spec §4.2's last row. `=` has nothing in front of the pad, so `1*(…)` is
  // unsatisfied and the token68 branch is not on offer.
  assert_eq!(token68(b"Scheme =", 7), None);
  // And there is no `MalformedToken68` for it to be reported as: the element
  // is re-read as the other branch, and the fault is named there.
  assert_eq!(auth_param(b"=").unwrap_err(), AuthError::MalformedParameter);
}

#[test]
fn the_two_branches_are_never_both_derivable() {
  // `token68`'s doc argues this rather than leaving it to be noticed: a run
  // that reaches the end of its element leaves nothing but `=` behind its
  // first `=`, and `auth-param` needs a `token` or a `quoted-string` there.
  // So taking the token68 branch whenever the run ends the element can never
  // steal a reading the parameter branch would have had — and an element that
  // is neither is refused by the parameter branch, which is where §11.2 has a
  // fault to name.
  let (mut runs, mut params) = (0usize, 0usize);
  for (element, is_token68, is_param) in [
    (&b"dGVzdA=="[..], true, false),
    (b"mF_9.B5f-4.1JqM", true, false),
    (b"foo=", true, false),
    (b"a==", true, false),
    (b"abc", true, false),
    (b"a/b", true, false),
    (b"foo=bar", false, true),
    (br#"realm="x""#, false, true),
    (br#"realm = "x""#, false, true),
    (b"=", false, false),
    (b"a=b=", false, false),
  ] {
    assert_eq!(token68(element, 0).is_some(), is_token68, "{element:?}");
    assert_eq!(auth_param(element).is_ok(), is_param, "{element:?}");
    assert!(!(is_token68 && is_param), "{element:?}");
    runs += usize::from(is_token68);
    params += usize::from(is_param);
  }
  // Neither column is vacuously empty.
  assert_eq!((runs, params), (6, 3));
}
