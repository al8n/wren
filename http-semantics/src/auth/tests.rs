use super::*;
use crate::grammar::{ListError, ParamSyntax, parameterised_list};

/// [`auth_param`] over an element held whole — one field line's worth, with
/// nothing behind it that RFC 9110 §5.2's join could add. A quoted-string this
/// element leaves open therefore has nothing left that could close it, which is
/// the reading every test above the cross-line block wants.
fn auth_param_alone(element: &[u8]) -> Result<AuthParam<'_>, AuthError> {
  auth_param(element, ValueTail::Ends)
}

/// The eight bytes the brute forces here run every element over.
///
/// `a` is a §5.6.2 `tchar` and one of RFC 9110 §11.2's `token68` alphabet; `/`
/// is one of §11.2's and no `tchar`; `!` is a `tchar` and none of §11.2's; `=`
/// is `token68`'s pad and `auth-param`'s own terminal; DQUOTE and `\` are what
/// §5.6.4 gives meaning to; SP and HTAB are §5.6.3's `OWS`.
///
/// A comma is deliberately absent: a comma is what ENDS a §5.6.1.2 element, so
/// no element holds one.
const ELEMENT_ALPHABET: [u8; 8] = *b"a/!=\"\\ \t";

// ── RFC 9110 §11.2: the two spellings of a value ─────────────────────────────

#[test]
fn a_value_is_a_quoted_string_or_a_token() {
  let quoted = auth_param_alone(br#"realm="x""#).unwrap();
  assert_eq!(quoted.name(), b"realm");
  assert!(matches!(quoted.value(), Ok(ParamValue::Quoted(v)) if v == b"x"));

  // RFC 9110 §11.5 says of this very parameter: "For historical reasons, a
  // sender MUST only generate the quoted-string syntax." That binds a SENDER,
  // and the sentence after it is permissive about recipients, so neither makes
  // the bare token a fault to report. §11.2's production admits it, and §11.2
  // gives the reason a generic component honours it.
  let token = auth_param_alone(b"realm=x").unwrap();
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
    let param = auth_param_alone(spelling).unwrap();
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
  let mut members = parameterised_list([&br#"m;realm = "x""#[..]], ParamSyntax::Parameter);
  let member = members.next().unwrap().unwrap();
  assert!(matches!(
    member.params().next(),
    Some(Err(ListError::NotAToken))
  ));

  assert_eq!(
    auth_param_alone(br#"realm = "x""#).unwrap().name(),
    b"realm"
  );
}

// ── The shapes that are not an auth-param ────────────────────────────────────

#[test]
fn a_name_with_no_equals_is_not_a_parameter() {
  assert_eq!(
    auth_param_alone(b"realm").unwrap_err(),
    AuthError::MalformedParameter
  );
  // The name has to be a whole `token` up to the BWS, so a space inside it is
  // not BWS the production would remove.
  assert_eq!(
    auth_param_alone(b"re alm=x").unwrap_err(),
    AuthError::MalformedParameter
  );
  // RFC 9110 §5.6.2's `token = 1*tchar` names at least one character, so there
  // is no parameter whose name is empty.
  assert_eq!(
    auth_param_alone(b"=x").unwrap_err(),
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
    auth_param_alone(b"realm=").unwrap_err(),
    AuthError::MalformedParameter
  );
}

#[test]
fn a_value_is_one_alternative_taken_whole() {
  // `( token / quoted-string )` leaves nothing over: bytes behind a closed
  // string, or behind a token, are not part of either alternative.
  for leftover in [&br#"realm="x"y"#[..], b"realm=x y", br#"realm=x"y""#] {
    assert_eq!(
      auth_param_alone(leftover).unwrap_err(),
      AuthError::MalformedParameter,
      "{leftover:?}"
    );
  }
}

#[test]
fn an_open_string_and_a_forbidden_byte_are_told_apart() {
  // Open where the element ends: nothing here can close it.
  assert_eq!(
    auth_param_alone(br#"realm="x"#).unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  // %x00 is neither `qdtext` nor an octet `quoted-pair` may escape. The crate
  // keeps this apart from the open case, and so does this module: after it, a
  // walker can no longer tell a separating comma from data.
  assert_eq!(
    auth_param_alone(b"realm=\"a\x00b\"").unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    auth_param_alone(b"realm=\"a\\\x00b\"").unwrap_err(),
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
  let param = auth_param_alone(br#"realm="a\"b""#).unwrap();
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
  let param = auth_param_alone(br#"realm="""#).unwrap();
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
  let param = auth_param_alone(b"foo=bar").unwrap();
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
    auth_param_alone(b"foo=").unwrap_err(),
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
  assert_eq!(
    auth_param_alone(b"=").unwrap_err(),
    AuthError::MalformedParameter
  );
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
    assert_eq!(auth_param_alone(element).is_ok(), is_param, "{element:?}");
    assert!(!(is_token68 && is_param), "{element:?}");
    runs += usize::from(is_token68);
    params += usize::from(is_param);
  }
  // Neither column is vacuously empty.
  assert_eq!((runs, params), (6, 3));

  // And the same claim over every element of length 1..=5 the productions give
  // a meaning to, because the whole of `Challenges::challenge`'s `token68`
  // completion and `Challenges::list_open`'s close now rest on it. A table
  // answers for its own rows; this answers for the alphabet.
  //
  // [`ELEMENT_ALPHABET`] is the eight bytes and its doc says why each is there.
  const ALPHABET: [u8; 8] = ELEMENT_ALPHABET;
  let (mut examined, mut runs, mut params) = (0usize, 0usize, 0usize);
  let mut element = [0_u8; 5];
  for len in 1..=5_usize {
    for mut index in 0..ALPHABET
      .len()
      .pow(u32::try_from(len).unwrap_or_else(|_| unreachable!("a length of five fits in a u32")))
    {
      for slot in element.iter_mut().take(len) {
        *slot = ALPHABET[index % ALPHABET.len()];
        index /= ALPHABET.len();
      }
      let element = element.get(..len).unwrap_or_default();
      let is_token68 = token68(element, 0).is_some();
      let is_param = auth_param_alone(element).is_ok();
      assert!(
        !(is_token68 && is_param),
        "both branches derive {element:?}"
      );
      examined += 1;
      runs += usize::from(is_token68);
      params += usize::from(is_param);
    }
  }
  // The counts, so a run that stopped writing elements says so rather than
  // passing an assertion nothing reaches.
  assert_eq!((examined, runs, params), (37_448, 402, 222));
}

// ── RFC 9110 §5.2: a challenge is not always one field line ──────────────────

// One challenge's seventeen lines, so the sixteen-line prefix and the whole of
// it are the same value one line apart. Every element is a parameter, so no
// reading of RFC 9110 §11.6.1's field splits it into two challenges.
const SEVENTEEN_LINES: [&[u8]; 17] = [
  b"Basic a=1",
  b"b=2",
  b"c=3",
  b"d=4",
  b"e=5",
  b"f=6",
  b"g=7",
  b"h=8",
  b"i=9",
  b"j=10",
  b"k=11",
  b"l=12",
  b"m=13",
  b"n=14",
  b"o=15",
  b"p=16",
  b"q=17",
];

#[test]
fn a_parameter_list_split_at_a_join_is_one_challenge() {
  // RFC 9110 §5.2 makes a repeated field one value: the field line values
  // "concatenated in order, with each field line value separated by a comma".
  // So these two lines are `Basic a=1,b=2`, which §11.6.1 warns is a shape a
  // parser has to be ready for — "it might contain more than one challenge,
  // and each challenge can contain a comma-separated list of authentication
  // parameters". Here it is the second: ONE challenge whose parameter list a
  // sender split at an element boundary.
  let credential = read_credential([&b"Basic a=1"[..], b"b=2"]).unwrap();
  assert_eq!(credential.scheme(), b"Basic");
  assert!(credential.token68().is_none());

  let mut params = credential.params();
  let a = params.next().unwrap();
  assert_eq!(a.name(), b"a");
  assert!(matches!(a.value(), Ok(ParamValue::Token(v)) if v == b"1"));
  let b = params.next().unwrap();
  assert_eq!(b.name(), b"b");
  assert!(matches!(b.value(), Ok(ParamValue::Token(v)) if v == b"2"));
  assert!(params.next().is_none());
}

#[test]
fn a_value_crossing_a_join_keeps_its_challenge_and_its_name() {
  // The join's comma is DATA inside an open quoted-string, so these two lines
  // are one parameter whose value is `"long,tail"` — well formed, and not one
  // contiguous slice for a borrowing reader to hand back.
  //
  // The challenge is NOT failed over it. RFC 9110 §11.4 has a user agent
  // choose among challenges by "selecting the challenge with what it considers
  // to be the most secure auth-scheme that it understands", so hiding a scheme
  // behind one unreadable value would take away the thing the choice turns on.
  let credential = read_credential([&b"Basic a=\"long"[..], b"tail\""]).unwrap();
  assert_eq!(credential.scheme(), b"Basic");

  let mut params = credential.params();
  let a = params.next().unwrap();
  assert_eq!(a.name(), b"a");
  assert_eq!(a.value().unwrap_err(), ValueSpansFieldLines);
  assert!(params.next().is_none());
}

#[test]
fn the_line_that_closes_a_value_carries_the_elements_behind_it() {
  // `tail"` begins no element of its own, and dropping it would take the
  // string's close and everything after it with it. The rule that keeps it is
  // about BYTES: a line spends an entry when it carries any that are not OWS
  // or a comma, whether or not an element starts there.
  let credential = read_credential([&b"Basic a=\"long"[..], b"tail\", b=2", b"c=3"]).unwrap();

  let mut params = credential.params();
  let a = params.next().unwrap();
  assert_eq!(a.name(), b"a");
  assert_eq!(a.value().unwrap_err(), ValueSpansFieldLines);
  let b = params.next().unwrap();
  assert_eq!(b.name(), b"b");
  assert!(matches!(b.value(), Ok(ParamValue::Token(v)) if v == b"2"));
  let c = params.next().unwrap();
  assert_eq!(c.name(), b"c");
  assert!(matches!(c.value(), Ok(ParamValue::Token(v)) if v == b"3"));
  assert!(params.next().is_none());
}

#[test]
fn every_parameter_beside_a_spanning_value_still_answers() {
  // The regression this pins: a challenge must not lose its scheme, its realm
  // and its nonce because one parameter a caller may never read is not one
  // slice.
  let credential = read_credential([
    &b"Digest realm=\"x\", opaque=\"jo"[..],
    b"in\", nonce=\"y\"",
  ])
  .unwrap();
  assert!(credential.scheme_is("digest"));

  let mut params = credential.params();
  let realm = params.next().unwrap();
  assert_eq!(realm.name(), b"realm");
  assert!(matches!(realm.value(), Ok(ParamValue::Quoted(v)) if v == b"x"));
  let opaque = params.next().unwrap();
  assert_eq!(opaque.name(), b"opaque");
  assert_eq!(opaque.value().unwrap_err(), ValueSpansFieldLines);
  let nonce = params.next().unwrap();
  assert_eq!(nonce.name(), b"nonce");
  assert!(matches!(nonce.value(), Ok(ParamValue::Quoted(v)) if v == b"y"));
  assert!(params.next().is_none());
}

#[test]
fn a_string_still_open_on_the_last_line_is_unterminated() {
  // The other half of the pair above, and the reason the two errors are
  // distinct: this string closes nowhere, so the value does not exist rather
  // than merely being non-contiguous.
  assert_eq!(
    read_credential([&b"Basic a=\"long"[..], b"tail"]).unwrap_err(),
    AuthError::UnterminatedQuotedString
  );

  // A string that DID close across the join ENDED the value, so the DQUOTE
  // behind it opens nothing and there is no second string to leave open. The
  // element is refused for what those bytes are — nothing `auth-param` derives
  // — and not for where they stop, which is the same answer the same bytes get
  // on one field line.
  assert_eq!(
    read_credential([&b"Basic a=\"x"[..], b"y\" \"z"]).unwrap_err(),
    AuthError::MalformedParameter
  );
  assert_eq!(
    credentials(b"Basic a=\"x,y\" \"z").unwrap_err(),
    AuthError::MalformedParameter
  );
}

#[test]
fn the_escape_pending_at_a_join_is_spent_on_the_join_comma() {
  // A backslash at the end of a field line escapes the comma RFC 9110 §5.2
  // joins the lines with — that comma is the next character of the string, and
  // `quoted-pair` is what the backslash makes of it. The escape is therefore
  // SPENT there, and the next line's leading DQUOTE arrives unescaped and
  // CLOSES the string: `a="x\` + `"` is the one parameter `a`, whose value
  // spans the join.
  let closed = read_credential([&b"Basic a=\"x\\"[..], b"\""]).unwrap();
  let mut params = closed.params();
  let a = params.next().unwrap();
  assert_eq!(a.name(), b"a");
  assert_eq!(a.value().unwrap_err(), ValueSpansFieldLines);
  assert!(params.next().is_none());

  // A DQUOTE first on the next line is data only when THAT line writes the
  // backslash in front of it, and then the string runs on: here it swallows
  // `, b=2` and never closes.
  //
  // The reading that says the escape carried across the join is what makes
  // such a DQUOTE data is wrong, and the two answers are one input apart:
  // `scan_quoted_after_join` feeds the join's comma THROUGH the
  // pending escape before the next line's first byte, which is the whole
  // reason that function exists. Its own doc records the defect of doing
  // otherwise — the escape handed to the wrong character read a closed value
  // as unterminated and an unterminated one as closed.
  assert_eq!(
    read_credential([&b"Basic a=\"x\\"[..], b"\\\", b=2"]).unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
}

#[test]
fn a_value_that_closed_across_a_join_has_ended_its_element() {
  // RFC 9110 §5.2 makes these two field lines one value — the field line
  // values "concatenated in order, with each field line value separated by a
  // comma" — so they are `Basic realm="x,"junk`. The quoted-string opens at
  // the first DQUOTE, takes `x` and the join's comma as `qdtext`, and closes
  // at the second; `junk` then stands behind it. §11.2's
  // `auth-param = token BWS "=" BWS ( token / quoted-string )` admits ONE
  // token or ONE quoted-string as the value and nothing after it, so those
  // four bytes are derived by nothing.
  assert_eq!(
    read_credential([&b"Basic realm=\"x"[..], b"\"junk"]).unwrap_err(),
    AuthError::MalformedParameter
  );

  // The same bytes on ONE field line, which is where the rule is anchored:
  // `auth_param` refuses a quoted-string with bytes behind its close. RFC 9110
  // §5.2's join is a way of writing the value and not a way past the rule, and
  // the pair of them is what says so — neither assertion carries it alone.
  assert_eq!(
    credentials(b"Basic realm=\"x,\"junk").unwrap_err(),
    AuthError::MalformedParameter
  );

  // What MAY stand there is the whitespace RFC 9110 §5.6.1.2 hangs on the
  // comma in front of the next element —
  // `#element => [ element ] *( OWS "," OWS [ element ] )` — and a line end,
  // where §5.2's own comma is the value's next character.
  for lines in [
    [&b"Basic a=\"long"[..], b"tail\" \t"],
    [&b"Basic a=\"long"[..], b"tail\" \t,"],
    [&b"Basic a=\"long"[..], b"tail\""],
  ] {
    let credential = read_credential(lines).unwrap();
    let mut params = credential.params();
    let a = params.next().unwrap();
    assert_eq!(a.name(), b"a", "{lines:?}");
    assert_eq!(a.value().unwrap_err(), ValueSpansFieldLines, "{lines:?}");
    assert!(params.next().is_none(), "{lines:?}");
  }
}

// gate-exempt: a="x,y" "z,w", b=2 — the one field value RFC 9110 §5.2 joins
// three lines into, shown in prose; not a production of any RFC.
#[test]
fn a_string_opened_behind_the_close_is_not_a_second_value() {
  // A DQUOTE is not `OWS` either, so a string opening BEHIND the close is
  // trailing junk like any other — and junk derives nothing, so it opens no
  // string. RFC 9110 §5.2 joins these three lines into `a="x,y" "z,w", b=2`,
  // whose first element carries what LOOKS like two quoted-strings where
  // §11.2's `( token / quoted-string )` names one; the second is `"z,w"` only
  // if a run nothing derives may still say which commas are data.
  //
  // The element therefore ENDS on the line its value closed on, and what the
  // lines behind it hold cannot change that. The three inputs below differ
  // only in that tail — none, a line that closes the junk's DQUOTE, and a line
  // that closes nothing followed by one that does — and answer alike.
  for tail in [&[][..], &[&b"w\", b=2"[..]], &[&b"w"[..], b"\", b=2"]] {
    let lines = [&b"a=\"x"[..], b"y\" \"z"]
      .into_iter()
      .chain(tail.iter().copied());
    let [first, past] = info::<2>(lines);
    assert_eq!(
      first.unwrap().unwrap_err(),
      AuthError::MalformedParameter,
      "{tail:?}"
    );
    assert!(past.is_none(), "{tail:?}");

    // Both readers carry this loop, so both are driven: the one
    // `Credential::read` spends before a credential exists, and the one
    // §11.6.3's field walks as it hands parameters out.
    let credential = [&b"Basic a=\"x"[..], b"y\" \"z"]
      .into_iter()
      .chain(tail.iter().copied());
    assert_eq!(
      read_credential(credential).unwrap_err(),
      AuthError::MalformedParameter,
      "{tail:?}"
    );
  }

  // Where the element ended is visible from outside: a challenge written on
  // the line behind the junk is REACHED, because the junk's DQUOTE did not
  // swallow the join comma in front of it.
  let [basic, digest, past] = walk::<3>([&b"Basic a=\"x"[..], b"y\" \"z", b"Digest realm=z"]);
  assert_eq!(basic.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());
}

#[test]
fn the_junk_behind_a_close_is_refused_at_every_entry_point() {
  // `rejoin` is the one place this module carries an element across RFC 9110
  // §5.2's join, and all three walks reach it. The `#challenge` walk
  // additionally has to go on: §11.4 has a user agent choose among challenges
  // by "selecting the challenge with what it considers to be the most secure
  // auth-scheme that it understands", so the boundary behind the refused
  // challenge still has to be the one a clean scan found, and `Newauth` is
  // still read.
  let [basic, newauth, past] = walk::<3>([&b"Basic a=\"x"[..], b"y\"junk, Newauth c=3"]);
  assert_eq!(basic.unwrap().unwrap_err(), AuthError::MalformedParameter);
  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(names::<2>(&newauth), [Some(&b"c"[..]), None]);
  assert!(past.is_none());

  // §11.6.3's field is a parameter list and nothing else, and one fault ends
  // that walk — so the parameter behind the junk is not handed over either.
  let [first, past] = info::<2>([&b"a=\"x"[..], b"y\"junk, b=2"]);
  assert_eq!(first.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert!(past.is_none());

  // §11.6.2's field holds ONE credential, and a fault anywhere in it refuses
  // the whole value.
  assert_eq!(
    credentials(b"Basic a=\"x,y\"junk, b=2").unwrap_err(),
    AuthError::MalformedParameter
  );
}

#[test]
fn a_refused_run_hides_no_challenge_behind_it() {
  // RFC 9110 §11.4 has a user agent select "the challenge with what it
  // considers to be the most secure auth-scheme that it understands", so a
  // challenge it cannot read must not take the readable ones behind it away.
  // Each input below is a run of bytes some production has already refused,
  // carrying one DQUOTE placed to swallow the comma in front of `Digest`.

  // Behind the close of a value §5.2's join carried onto a second field line.
  // The value of `a` closes at the DQUOTE the second line opens with, and the
  // one in `junk` is what stands behind that close.
  let [basic, broken, digest, past] = walk::<4>([
    &b"Basic realm=x, Broken a=\"q"[..],
    b"r\"junk\", Digest realm=z",
  ]);
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::MalformedParameter);
  let digest = digest.unwrap().unwrap();
  assert_eq!(digest.scheme(), b"Digest");
  assert_eq!(names::<2>(&digest), [Some(&b"realm"[..]), None]);
  assert!(past.is_none());

  // The same junk on ONE field line, which reaches the rule by the other
  // entrance: the scan that finds where an element ends on the line it began
  // on, rather than the one that carries an element across a join.
  let [broken, digest, past] = walk::<3>([&b"Basic a=\"x\"ju\"nk, Digest realm=z"[..]]);
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // And by the third: the seek that gets past a challenge already reported.
  // An element opening with `=` is neither a `challenge` nor an `auth-param`,
  // so the whole run it stands in has been refused before the seek reads a
  // byte of it — and a refused run holds no quoted-string for its DQUOTE to
  // open, nor one for a byte §5.6.4 forbids to be inside.
  for value in [
    &b"=x\"junk, Digest realm=z"[..],
    b"=x\"j\x00unk, Digest realm=z",
  ] {
    let [missing, digest, past] = walk::<3>([value]);
    assert_eq!(
      missing.unwrap().unwrap_err(),
      AuthError::MissingScheme,
      "{value:?}"
    );
    assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest", "{value:?}");
    assert!(past.is_none(), "{value:?}");
  }
}

#[test]
fn a_quote_where_no_string_may_open_hides_no_challenge() {
  // RFC 9110 §11.2's `auth-param = token BWS "=" BWS ( token / quoted-string )`
  // admits a quoted-string at ONE position, the first byte of the value; and
  // §5.6.2's `tchar`, §11.2's `token68` alphabet and §5.6.3's `BWS` each
  // exclude DQUOTE. So a DQUOTE standing anywhere else in an element is a byte
  // no production admits: it begins no string, and every comma behind it is
  // still the §5.6.1.2 separator it looks like.
  //
  // §11.4 has a user agent select "the challenge with what it considers to be
  // the most secure auth-scheme that it understands", so one DQUOTE written
  // where no value begins must not take `Digest` away. Each value below places
  // one at a different such position, and each is the same answer.
  for value in [
    // Behind a value that already took the `token` alternative.
    &b"Basic a=x\"y, Digest realm=z"[..],
    // The same, spelled with the BWS §11.2 puts around the `=`.
    b"Basic a = x\"y, Digest realm=z",
    // Behind a backslash, which is as little a `tchar` as the DQUOTE is, and
    // which escapes nothing outside a quoted-string.
    b"Basic a=x\\\"y, Digest realm=z",
    // The same backslash with no `=` in front of the DQUOTE at all. One byte
    // that is not the `=` stands between the name and the DQUOTE, which is as
    // far from §11.2's value position as a hundred would be.
    b"Basic a\\\"x, Digest realm=z",
    // Inside the name, where the element has not reached its `=` yet.
    b"Basic a\"b=1, Digest realm=z",
    // At the element's first byte, with no name token at all.
    b"Basic \"x, Digest realm=z",
    // Behind an `=` with nothing in front of it to be a name.
    b"Basic =\"x, Digest realm=z",
    // Behind a `token68` run — the other alternative §11.3 admits after a
    // scheme, and one whose alphabet holds no DQUOTE either.
    b"Basic dGVzdA==\"x, Digest realm=z",
    // And in a LATER element, once a well-formed one has been read.
    b"Basic r=1, a=x\"y, Digest realm=z",
  ] {
    let [broken, digest, past] = walk::<3>([value]);
    assert_eq!(
      broken.unwrap().unwrap_err(),
      AuthError::MalformedParameter,
      "{value:?}"
    );
    let digest = digest.unwrap().unwrap();
    assert_eq!(digest.scheme(), b"Digest", "{value:?}");
    assert_eq!(
      names::<2>(&digest),
      [Some(&b"realm"[..]), None],
      "{value:?}"
    );
    assert!(past.is_none(), "{value:?}");
  }

  // The same shape across RFC 9110 §5.2's join, where the reach is longer: a
  // string opened there would have held the element past the join comma and
  // swallowed the whole of the next field line with it.
  let [broken, digest, past] = walk::<3>([&b"Basic a=x\"y"[..], b"Digest realm=z"]);
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // All three of this module's walks find an element's end with the same scan,
  // and the two that are not the `#challenge` walk show its reach in the FAULT
  // instead of in a challenge. A %x00 behind a DQUOTE that opens nothing is
  // not inside a quoted-string, so RFC 9110 §5.6.4 has nothing there to
  // forbid: the element is refused for deriving nothing, which is what the
  // DQUOTE and the %x00 both are.
  assert_eq!(
    read_credential([&b"Basic a=x\"\x00y\""[..]]).unwrap_err(),
    AuthError::MalformedParameter
  );
  assert_eq!(
    read_credential([&b"Basic a=x\"y"[..], b"\x00\""]).unwrap_err(),
    AuthError::MalformedParameter
  );
  let [first, past] = info::<2>([&b"a=x\"\x00y\", b=2"[..]]);
  assert_eq!(first.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert!(past.is_none());
  // The `#challenge` walk goes on past that element, because it met no string:
  // a comma outside one is a boundary it can still trust.
  let [broken, newauth, past] = walk::<3>([&b"Basic a=x\"\x00y\", Newauth b=1"[..]]);
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());

  // The control, at the one position RFC 9110 §11.2 does admit a string: the
  // DQUOTE opens, the %x00 IS inside a quoted-string, and §5.6.4 forbids it —
  // in all three walks. The two that poison say so and stop; the `#challenge`
  // one refuses that challenge and reads the next, because the byte it choked
  // on is one §5.5 admits nowhere in a field value and so nothing behind the
  // fault is any value's data.
  assert_eq!(
    read_credential([&b"Basic a=\"x\x00y\""[..]]).unwrap_err(),
    AuthError::InvalidQuotedString
  );
  let [first, past] = info::<2>([&b"a=\"x\x00y\", b=2"[..]]);
  assert_eq!(first.unwrap().unwrap_err(), AuthError::InvalidQuotedString);
  assert!(past.is_none());
  let [broken, unknown, past] = walk::<3>([&b"Basic a=\"x\x00y\", Newauth b=1"[..]]);
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::InvalidQuotedString);
  // And the `#challenge` walk does NOT go on past this one, which is the pair's
  // whole point: the DQUOTE here stands where §11.2 admits a value, so a
  // reading opens a string that the %x00 keeps from ever closing, and that
  // reading holds the comma in front of `Newauth` as `a`'s own data. The
  // element above met no string at all, so its comma is a boundary every
  // reading agrees on and `Newauth` is reached there.
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // And what the rule may not cost: at that admitted position the string still
  // opens, so the comma between its DQUOTEs is data and this is ONE challenge
  // carrying ONE parameter rather than two of either. The position is reached
  // by reading RFC 9110 §11.2's `BWS` off BOTH sides of the `=`, so each
  // spelling of that whitespace has to arrive at the same DQUOTE.
  for spelling in [
    &b"Basic realm=\"a, b\""[..],
    b"Basic realm = \"a, b\"",
    b"Basic realm =\"a, b\"",
    b"Basic realm= \"a, b\"",
    b"Basic realm\t=\t\"a, b\"",
  ] {
    let credential = one([spelling]);
    assert_eq!(
      names::<2>(&credential),
      [Some(&b"realm"[..]), None],
      "{spelling:?}"
    );
    assert!(
      matches!(credential.params().next().unwrap().value(), Ok(ParamValue::Quoted(v)) if v == b"a, b"),
      "{spelling:?}"
    );
  }

  // And the shape this rule does NOT reach, which is the recovery's own.
  // `Basic ",a=", Digest realm=z` refuses at the one byte `"` that no
  // production derives — that much is this rule — and what stands behind that
  // refusal is `a="`, whose DQUOTE is at RFC 9110 §11.2's value position and so
  // is one a reading MAY open. That reading holds the comma in front of
  // `Digest`, and every byte behind it, as `a`'s data. Yielding `Digest` was
  // manufacturing a challenge out of a value's interior, which is what
  // `refused_element_end` will not do.
  let [broken, unknown, past] = walk::<3>([&b"Basic \",a=\", Digest realm=z"[..]]);
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());
  // The pair that says the answer above is about the READING and not about the
  // refusal standing in front of it: the same value with `a`'s string CLOSED
  // before the comma. The reading that opens it stands outside it there,
  // exactly as the reading that leaves it shut does, so no reading holds that
  // comma — `Digest` is a challenge whose boundary this walk knows, and
  // refusing to report it would hide a challenge for nothing.
  let [broken, digest, past] = walk::<3>([&b"Basic \",a=\"\", Digest realm=z"[..]]);
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());
  // The control, with nothing refused in front of the DQUOTE: it stands at its
  // own element's value position, so the string opens, RFC 9110 §5.6.4 makes
  // the comma in front of `Digest` data inside it, and the value ends there
  // with the string never closed. `Digest` is hidden by the GRAMMAR here, and
  // this input has always answered so.
  let [control, past] = walk::<2>([&b"Basic a=\"x, Digest realm=z"[..]]);
  assert_eq!(
    control.unwrap().unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  assert!(past.is_none());
}

/// The tail every refusal below is followed by: an element whose DQUOTE stands
/// exactly where RFC 9110 §11.2 admits a value, so it would open a string that
/// §5.6.4 runs to the end of the field — swallowing the comma in front of
/// `Digest` — if the challenge in front of it had not already been refused.
const TRAP: &[u8] = b"trap=\"open, Digest realm=z";

#[test]
fn the_control_is_that_the_trap_hides_a_challenge_on_its_own() {
  // Read as the first element of a challenge, with nothing refused in front of
  // it, `TRAP` really does take `Digest` away — and RFC 9110 §5.6.4 is why:
  // the DQUOTE is at §11.2's value position, so a quoted-string opens and
  // every comma inside one is data. Without this the test below would pass
  // over a trap that never sprang.
  let mut value = b"Basic ".to_vec();
  value.extend_from_slice(TRAP);
  let [only, past] = walk::<2>([value.as_slice()]);
  assert_eq!(
    only.unwrap().unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  assert!(past.is_none(), "the trap hides `Digest` when it is sprung");
}

/// The tail whose boundary EVERY reading of it agrees on: the string opens
/// where RFC 9110 §11.2 admits one and CLOSES in front of the comma, so the
/// reading that opened it stands outside it there exactly as the reading that
/// left it shut does. `Digest` is a challenge whose extent this walk knows,
/// whatever refusal stands in front of it.
const CERTAIN: &[u8] = b"safe=\"shut\", Digest realm=z";

/// Every fault that refuses a challenge while the walk is still deciding where
/// that challenge ends, the head that carries it, and whether the boundary
/// behind that head is one EVERY reading of it agrees on.
///
/// Driven twice — once behind [`CERTAIN`] and once behind [`TRAP`] — so that
/// the two tests below differ in the TAIL and in nothing else. A trigger added
/// to one is added to the other. The third column is read by the [`CERTAIN`]
/// test alone: behind [`TRAP`] the readings part in the tail whatever the head
/// did, and every row answers `ChallengeBoundaryUnknown`.
const REFUSED_HEADS: [(&[u8], AuthError, bool); 6] = [
  // A value that closed with bytes behind that close.
  (b"Basic a=\"x\"j", AuthError::MalformedParameter, true),
  // An element that is no `auth-param` at all: two `=` where the production
  // admits one value.
  (b"Basic a=b=c", AuthError::MalformedParameter, true),
  // A value that is neither of §11.2's alternatives taken whole.
  (b"Basic a=x y", AuthError::MalformedParameter, true),
  // A `token68` run that stops INSIDE its own element, so neither of RFC 9110
  // §11.2's alternatives derives it: the run ends at its `=` pad and `x` stands
  // behind that pad, where `auth-param = token BWS "=" BWS ( token /
  // quoted-string )` wanted a value. `Basic dGVzdA==` is NOT this shape and
  // cannot stand here — its run reaches the element's end, so `token68` derives
  // the body and the challenge completes rather than being refused.
  (b"Basic dGVzdA==x", AuthError::MalformedParameter, true),
  // §11.2's one-name-once MUST.
  (b"Basic a=1, a=2", AuthError::DuplicateParameter, true),
  // A byte §5.6.4 forbids INSIDE a string that legitimately opened, standing in
  // FRONT of the comma that ends this element — and the ONE row whose boundary
  // no recovery may take.
  //
  // This row said `true`, on the reading that a forbidden byte means no
  // `quoted-string` derives over the comma in ANY reading. It does
  // mean that, and it is not the question: the DQUOTE stands where RFC 9110
  // §11.2 admits a value, the sender wrote every byte behind it as that value's
  // data, and a string that reaches no close holds every comma left in the
  // field. `crate::grammar::Readings::absorb` had already ruled so for §5.6.6's
  // `parameters` — it calls that reading SEALED — and this module answered
  // otherwise, which is how
  // `Basic x="%x01, Digest realm=evil` handed a caller a `Digest` built out of
  // those bytes.
  (b"Basic a=\"x\x00y\"", AuthError::InvalidQuotedString, false),
];

/// `head`, a comma, and `tail`.
///
/// The return type is an `impl` rather than the owned collection's own name,
/// which is not in scope on the tier this crate builds with no features at all.
fn behind(head: &[u8], tail: &[u8]) -> impl core::ops::Deref<Target = [u8]> {
  let mut value = head.to_vec();
  value.extend_from_slice(b", ");
  value.extend_from_slice(tail);
  value
}

#[test]
fn every_way_a_challenge_is_refused_reaches_a_challenge_behind_a_certain_comma() {
  // RFC 9110 §11.4 has a user agent select "the challenge with what it
  // considers to be the most secure auth-scheme that it understands", so a
  // challenge it cannot read must not take the readable ones behind it away.
  // Each value below is a challenge refused for a different reason, then
  // `CERTAIN`, then `Digest` — and every one of them reaches `Digest`, because
  // the comma in front of it is one no reading of the bytes ahead of it holds
  // inside a §5.6.4 quoted-string.
  for (head, fault, certain) in REFUSED_HEADS {
    let value = behind(head, CERTAIN);
    let [refused, second, past] = walk::<3>([&*value]);
    assert_eq!(refused.unwrap().unwrap_err(), fault, "{head:?}");
    if certain {
      assert_eq!(
        second.unwrap().unwrap().scheme(),
        b"Digest",
        "the challenge behind {head:?}"
      );
    } else {
      // The one row where a reading of the HEAD holds every comma behind it,
      // `CERTAIN` tail or not: the string that opened at `a`'s value position
      // reaches no close, so `safe="shut"` and `Digest realm=z` are among the
      // bytes it holds. A tail whose own boundary every reading agrees on
      // cannot put that right — what is uncertain is where the head ENDS.
      assert_eq!(
        second.unwrap().unwrap_err(),
        AuthError::ChallengeBoundaryUnknown,
        "the boundary behind {head:?}"
      );
    }
    assert!(past.is_none(), "{head:?}");
  }

  // The OWS controls, which say the rule above is about WHERE the element
  // begins and not about refusing whitespace. RFC 9110 §5.6.1.2 hangs `OWS` on
  // its comma, so the element behind it is read exactly as one written with
  // none — and each of these has an opener no reading holds the probe inside.
  for continuation in [
    // A quoted `realm` that CLOSES in front of the comma.
    &b" Newauth realm=\"c\", Digest realm=z"[..],
    b"\trealm=\"c\", Digest realm=z",
    // A HTAB where `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
    // writes `1*SP`, so no challenge opens behind the whitespace either.
    b" Newauth\trealm=\"c, Digest realm=z",
    // A continuation with NO DQUOTE in it is not here and cannot be: the head's
    // own value then closes nowhere, so §5.2's value ends inside a string, the
    // walk answers `UnterminatedQuotedString` and there is no comma behind it
    // for any reading to reach. That is the asymmetry
    // `AuthError::ChallengeBoundaryUnknown` does not cover, recorded at
    // `Refusal::Unbounded`; corpus I grades its row for it `hider-excused`.
  ] {
    let [refused, digest, past] = walk::<3>([&b"Basic a=\"x"[..], continuation]);
    assert_eq!(
      refused.unwrap().unwrap_err(),
      AuthError::MalformedParameter,
      "{continuation:?}"
    );
    assert_eq!(
      digest.unwrap().unwrap().scheme(),
      b"Digest",
      "the challenge behind {continuation:?}"
    );
    assert!(past.is_none(), "{continuation:?}");
  }

  // A value that closed across §5.2's join with bytes behind that close. The
  // element began on a line this walk no longer holds, so the recovery runs
  // from the head of the line the value closed on — which is where the reading
  // that ended the element at the join comma begins. `r"junk"` opens no string
  // there: RFC 9110 §11.2 admits a value nowhere in it, since `r` is followed
  // by a DQUOTE and not by an `=`. So both readings end the element at the same
  // comma and `Digest` is reached.
  let mut tail = b"r\"junk\", ".to_vec();
  tail.extend_from_slice(CERTAIN);
  let [refused, digest, past] = walk::<3>([&b"Basic a=\"q"[..], tail.as_slice()]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // One parameter past MAX_PARAMS_PER_CREDENTIAL, which is this reader's own
  // bound rather than a fault of the sender's — and refuses the challenge just
  // the same, so the same recovery has to follow it.
  let value = behind(SEVENTEEN_CHALLENGE, CERTAIN);
  let [refused, digest, past] = walk::<3>([&*value]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::TooManyParameters);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // One field line past MAX_CHALLENGE_LINES, the other bound of this reader's,
  // met BETWEEN two elements — so the cursor stands where every reading is
  // outside a string, and the tail on the line behind it is reached.
  let mut lines = [&b""[..]; 18];
  lines[..SEVENTEEN_LINES.len()].copy_from_slice(&SEVENTEEN_LINES);
  lines[17] = CERTAIN;
  let [refused, digest, past] = walk::<3>(lines);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The forbidden byte met on the far side of §5.2's join, where the string
  // opened on one field line and the byte stands first on the next. The DQUOTE
  // that opened it is on a line this walk no longer holds, so no scan it may
  // make can even SEE the opener, let alone say the string ever closes — and it
  // does not: `Challenges::skip_element` reports `Refusal::Unbounded` for that
  // reason and the caller is told the rest is unread.
  //
  // This asserted `Digest`, the same manufactured challenge as the one-line
  // spelling's and one line further away from the DQUOTE it came out of.
  let [refused, unknown, past] = walk::<3>([&b"Basic a=\"x"[..], b"\x00, Digest realm=z"]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // A whole challenge on the continuation line, whose own quoted parameter
  // CLOSES in front of the comma. That is the reading §5.2's join admits beside
  // the one that carried `a`'s value here, and its opener stands behind
  // `auth-scheme 1*SP` — an offset no scan from the recovery cursor asks about
  // unless it is looking for it. Here the two readings agree: `realm`'s string
  // closes at `evil"`, so the comma behind it is RFC 9110 §5.6.1.2's separator
  // whichever reading is the sender's, and `Newauth` is a challenge this walk
  // knows the boundaries of. Refusing to report it would hide a challenge for
  // nothing.
  let [refused, newauth, past] = walk::<3>([
    &b"Basic a=\"x"[..],
    b"Digest realm=\"evil\", Newauth realm=z",
  ]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());

  // The same across TWO of §5.2's joins. The middle line carries no DQUOTE, so
  // the reading that opened `a`'s value is still inside it at that line's end
  // and the walk arrives at the last line with the same two readings it had at
  // the first join — which is why one line's worth of state answers for a value
  // spread over any number of them.
  let [refused, newauth, past] = walk::<3>([
    &b"Basic a=\"x"[..],
    b"nothing here closes it",
    b"Digest realm=\"evil\", Newauth realm=z",
  ]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());

  // And the element a challenge may NOT open at: the first of a challenge's own
  // `#auth-param` list, which `challenge = auth-scheme [ 1*SP ( token68 /
  // #auth-param ) ]` reaches past `1*SP` and not past a comma. RFC 9110
  // §11.6.1's ambiguity is about the elements of the OUTER list, so
  // `Digest realm="c` inside `Basic`'s body is an `auth-param` and nothing
  // else — it has no `=` behind its leading token, so §11.2 admits a value
  // nowhere in it, no reading opens a string at that DQUOTE, and the comma
  // behind `"c` is a separator in all of them.
  //
  // No recovery decides this one, and that is worth saying because it is what
  // keeps `Recovery::after_comma` false everywhere but a join:
  // `BodyCheck::element` HOLDS the first element's verdict, and the loop breaks
  // at `Newauth` because `opens_a_challenge` answers for it — so the fault is
  // `BodyCheck::finish`'s and the walk never enters `seek` at all.
  let [refused, newauth, past] = walk::<3>([&b"Basic Digest realm=\"c, Newauth realm=z"[..]]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());
}

#[test]
fn the_two_positions_a_reading_may_open_a_string_at_are_an_element_s_and_a_challenge_s() {
  // RFC 9110 §11.6.1 reads an element of the outer list two ways, and the
  // openers they name are the whole of what `opener_at` answers.
  //
  // One more `auth-param` of the list already open: the element's OWN value
  // position, which is where `trap="open`'s DQUOTE stands.
  assert_eq!(
    opener_at(b"trap=\"open, Digest realm=z", 0, true, false),
    Some(5)
  );
  // Not admitted where the refused challenge opened no list — nothing in what
  // is left of it is an `auth-param`, so nothing in it has a value position.
  assert_eq!(
    opener_at(b"trap=\"open, Digest realm=z", 0, false, false),
    None
  );

  // A whole challenge: the value position of its FIRST parameter, behind
  // `auth-scheme 1*SP`. Admitted only where a comma stands in front of the
  // element, which is what §5.2's join puts at the head of a continuation line.
  let joined = &b"Digest realm=\"evil, Newauth realm=z"[..];
  assert_eq!(opener_at(joined, 0, true, true), Some(13));
  assert_eq!(opener_at(joined, 0, true, false), None);
  // §5.6.3's `BWS` is admitted around §11.2's `=` and moves the position.
  assert_eq!(opener_at(b"Digest realm = \"evil", 0, true, true), Some(15));
  // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` writes `1*SP`,
  // and §5.6.3's HTAB is not one — so no challenge opens here in any reading.
  assert_eq!(opener_at(b"Digest\trealm=\"evil", 0, true, true), None);
  // A value position holding a `token` opens nothing: §11.2's
  // `( token / quoted-string )` is one alternative taken whole, and a scan
  // started at a `tchar` would read the rest of the run as a string's interior.
  assert_eq!(
    opener_at(b"Digest realm=z, Newauth realm=q", 0, true, true),
    None
  );
  assert_eq!(
    opener_at(b"trap=open, Digest realm=z", 0, true, false),
    None
  );

  // And never both at once, which is what keeps one scan an answer about every
  // reading: §5.6.2's `tchar` holds no `=`, so a token followed by `BWS "="` is
  // not a token followed by `1*SP` and another token. The two readings share
  // one `token`, so they are read from ONE offset — the element's own start,
  // which the OWS test below is about.
  assert_eq!(opener_at(b"a = \"x", 0, true, true), Some(4));
  assert_eq!(opener_at(b"a b=\"x", 0, true, true), Some(4));
  assert_eq!(opener_at(b"a b=\"x", 0, true, false), None);
}

#[test]
fn the_ows_a_list_hangs_on_its_comma_stands_in_front_of_both_openers() {
  // RFC 9110 §5.6.1.2 expands its list as
  // `#element => [ element ] *( OWS "," OWS [ element ] )`, so where a comma
  // stands in front of the cursor the element begins behind whatever §5.6.3
  // whitespace follows it — and BOTH of §11.6.1's readings are of the element,
  // not of the comma's far side.
  //
  // Asked at the far side instead, neither shape is found at all: §5.6.2's
  // `tchar` excludes SP and HTAB, so `token_end` answers `None` and the run
  // reads as one holding no opener. Every offset below is one byte or two off
  // the answer above it, and that is the whole of the defect.
  assert_eq!(opener_at(b" realm=\"evil", 0, true, true), Some(7));
  assert_eq!(opener_at(b"\trealm=\"evil", 0, true, true), Some(7));
  assert_eq!(opener_at(b"  realm=\"evil", 0, true, true), Some(8));
  assert_eq!(opener_at(b" \trealm=\"evil", 0, true, true), Some(8));
  // The challenge reading, whose opener stands behind `auth-scheme 1*SP` as
  // well as behind the list's `OWS`.
  assert_eq!(opener_at(b" Newauth realm=\"evil", 0, true, true), Some(15));
  assert_eq!(
    opener_at(b"\tNewauth realm=\"evil", 0, true, true),
    Some(15)
  );
  // The element reading alone, where the refused challenge opened no list: the
  // whitespace moves the position it is not admitted AT, and it stays
  // unadmitted.
  assert_eq!(opener_at(b" realm=\"evil", 0, false, true), None);
  assert_eq!(
    opener_at(b" Newauth realm=\"evil", 0, false, true),
    Some(15)
  );

  // And nothing is skipped where no comma stands in front of the cursor.
  // `Challenges::open_element` has already put the cursor on an element's first
  // byte there, so whitespace at it is the element's own and no production
  // admits a value behind it.
  assert_eq!(opener_at(b" realm=\"evil", 0, true, false), None);
}

#[test]
fn where_a_recovery_stands_says_whether_a_challenge_may_open_there() {
  // The element began and ended on the line the walk holds, so nothing this
  // scan crossed put a comma in front of it and RFC 9110 §11.6.1's challenge
  // reading is not this scan's to admit.
  let scanned = scan_element(b"Basic a=1, b=2", 6, 6, || Ok(None)).unwrap();
  assert_eq!(scanned.recovery.at(), 6);
  assert!(!scanned.recovery.after_comma());

  // §5.2's join carried the element onto the line the walk now stands on, and
  // that line's first byte is behind the join's comma.
  let mut behind = [&b"Digest realm=\"evil\", x"[..]].into_iter();
  let scanned = scan_element(b"Basic a=\"x", 6, 6, || Ok(behind.next())).unwrap();
  assert_eq!(scanned.recovery.at(), 0);
  assert_eq!(scanned.recovery.floor(), 14);
  assert!(scanned.recovery.after_comma());

  // The value ran out inside the string, so the cursor is at the last line's
  // end, where no element of any list begins.
  let mut open = [&b"nothing closes it"[..]].into_iter();
  let scanned = scan_element(b"Basic a=\"x", 6, 6, || Ok(open.next())).unwrap();
  assert_eq!(scanned.recovery.at(), 17);
  assert!(!scanned.recovery.after_comma());
}

/// And the other half of `read_challenge`'s `recover_from`: an element the walk
/// reads a challenge at that no `auth-param` begins at is one the recovery must
/// NOT take at the challenge's own first byte.
///
/// ```text
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `opens_a_challenge` answers `true` for `Newauth a="x,y"z`, so RFC 9110
/// §11.6.1 has no second reading of that element to lose and the value position
/// that decides its extent is its BODY's — `param_value_at` answered at `a`,
/// not at `Newauth`. Recovering from the scheme instead would answer
/// [`Recovery::strung`] `false` over a body a §5.6.4 quoted-string decided, so
/// the held verdict would come due at [`BodyCheck::finish`] with the comma
/// inside `"x,y"` already crossed — and the reading that leaves that DQUOTE
/// shut ends the element there.
///
/// It needs a list open IN FRONT of the challenge, because that is what
/// `recover_from`'s other half asks: `Basic p=1` opens one and `Broken;junk`
/// leaves it open behind a fault. Without it the walk is at the head of a value
/// where §11.6.1 admits no `auth-param` at all, and the two offsets answer
/// alike.
#[test]
fn a_challenge_no_parameter_begins_at_recovers_at_its_body() {
  let value: &[u8] = b"Basic p=1, Broken;junk, Newauth a=\"x,y\"z, Digest realm=z";
  let [basic, scheme, body, unknown, past] = walk::<5>([value]);
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(scheme.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(body.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown,
    "the comma inside `\"x,y\"` is one the shut reading ends the element at"
  );
  assert!(past.is_none());

  // The control that says it is about the LIST and not about the bytes: the
  // same challenge with no list open in front of it. `Broken;junk` at the head
  // of a value opens none, so §11.6.1 reads no `auth-param` at `Newauth` under
  // any reading and the recovery is the body's either way.
  let control: &[u8] = b"Broken;junk, Newauth a=\"x,y\"z, Digest realm=z";
  let [scheme, body, unknown, past] = walk::<4>([control]);
  assert_eq!(scheme.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(body.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());
}

/// The recovery over a body's FIRST element is the OUTER list's element, and
/// `element_at` is the whole of the difference.
///
/// ```text
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `x = "c, Digest realm=z` derives two ways: an `auth-scheme` `x`, §11.3's
/// `1*SP`, and a body opening at the `=` — which derives nothing, since `=` is
/// no `tchar` — or one `auth-param` whose `BWS` is that same SP and whose
/// quoted-string opens at offset 4 and never closes. The walk enters the body,
/// so `scan_element` is asked at 2; the element the OUTER `#challenge` list
/// holds begins at 0, and the value position is 4.
///
/// A scan that took the recovery at its own offset answers that no
/// quoted-string decided anything — `param_value_at` needs a `token` and `=` is
/// not one — so the held verdict came due behind a comma inside `x`'s value.
/// `Basic a=1, Broken;junk, Bearer, x = "c, Digest realm=z` is the value that
/// cost, and `auth-corpus`'s corpus O is where 54 of its shape were counted.
/// The other reading of an element a recovery CROSSES, which `auth_param`
/// cannot see.
///
/// ```text
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// `Challenges::seek` crosses an element `opens_a_challenge` answered `false`
/// for — one an `auth-param` begins at — and `sustain_the_epoch` used to ask it
/// only what §11.2 makes of it. Where §11.2's `BWS` in front of the `=` holds a
/// SP, the same bytes are also an `auth-scheme` taking §11.3's `1*SP`, whose
/// body opens AT the `=` and derives nothing. That reading has a `#auth-param`
/// list open and has stopped deriving inside it, which is what
/// `Broken<HTAB>junk, y<SP>=<SP>1, Bearer, x="open, Digest realm=z` needed and
/// did not get.
#[test]
fn a_crossed_element_may_open_a_list_the_reading_that_derives_does_not() {
  // The one SP, and every neighbouring spelling of the same production. Only
  // `1*SP` is the body's entrance, and §5.6.3's HTAB is not one of its bytes.
  assert!(opens_a_parameter_list(b"y = 1"));
  assert!(opens_a_parameter_list(b"y  = 1"));
  assert!(opens_a_parameter_list(b"y \t= 1"));
  assert!(!opens_a_parameter_list(b"y=1"));
  assert!(!opens_a_parameter_list(b"y\t=\t1"));
  assert!(!opens_a_parameter_list(b"y= 1"));

  // A challenge that takes the OTHER alternative closes no list of its own, and
  // a scheme with no body opens none.
  assert!(!opens_a_parameter_list(b"Bearer abc"));
  assert!(!opens_a_parameter_list(b"Bearer dGVzdA=="));
  assert!(!opens_a_parameter_list(b"Bearer"));
  assert!(!opens_a_parameter_list(b""));
  // And a body that is only the list's own whitespace is no body at all: the
  // optional group needs one of its two alternatives and neither derives `OWS`.
  assert!(!opens_a_parameter_list(b"Bearer "));
  // A challenge with a parameter body opens one, which is the same sentence
  // read over an element the walk would have stopped at rather than crossed.
  assert!(opens_a_parameter_list(b"Basic a=1"));

  // And the mirror of the same rule, which this fix over-corrected.
  // `y<SP>=<SP>1` is a whole `auth-param` here, because a list
  // IS open where the recovery crosses it and the span still derives — so the
  // challenge branch failing at the body's `=` is an alternative that derives
  // nothing beside one that derives, and §11.6.1 leaves a recipient no choice
  // between those. It opens no list, `Bearer` closes the epoch a receiver bound
  // opened, and the `Digest` behind `x` is one every complete derivation of the
  // value agrees on.
  let derivable: &[u8] = b"Basic p1=1, p2=2, p3=3, p4=4, p5=5, p6=6, p7=7, p8=8, \
                           p9=9, p10=10, p11=11, p12=12, p13=13, p14=14, p15=15, \
                           p16=16, p17=17, y = 1, Bearer, x=\"open, Digest realm=z";
  let [bound, bearer, scheme, digest] = walk::<4>([derivable]);
  assert_eq!(bound.unwrap().unwrap_err(), AuthError::TooManyParameters);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(scheme.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(
    digest.unwrap().unwrap().scheme(),
    b"Digest",
    "a failed alternative may not refute a span the grammar still derives"
  );

  // And the walk, over the value the two spellings part on. Both are shown at
  // `7c25761`; only the second may be, because only the first has a reading
  // that holds the probe inside `x`'s value.
  let opens: &[u8] = b"Broken\tjunk, y = 1, Bearer, x=\"open, Digest realm=z";
  let closes: &[u8] = b"Broken\tjunk, y\t=\t1, Bearer, x=\"open, Digest realm=z";
  let [_, _, _, last] = walk::<4>([opens]);
  assert_eq!(
    last.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown,
    "a span that opens a list is a list in front of the trap"
  );
  let [_, _, _, last] = walk::<4>([closes]);
  assert_eq!(
    last.unwrap().unwrap().scheme(),
    b"Digest",
    "and one that opens none leaves the boundary every reading agrees on"
  );
}

#[test]
fn a_body_s_first_element_recovers_at_the_element_the_outer_list_holds() {
  let value = b"x = \"c, Digest realm=z";
  // Where the walk enters the body: past `auth-scheme 1*SP`, at the `=`.
  assert_eq!(skip_sp(value, token_end(value, 0).unwrap()), 2);
  // The two readings, and the one value position the run holds. It is the
  // outer element's, and no scan from the body's own offset finds it.
  assert_eq!(param_value_at(value, 0), Some(4));
  assert_eq!(param_value_at(value, 2), None);

  // Asked at the body's offset for both, which is what the walk used to do.
  let scanned = scan_element(value, 2, 2, || Ok(None)).unwrap();
  assert_eq!(scanned.recovery.at(), 2);
  assert!(!scanned.recovery.strung());

  // And asked with the outer element's, which is what it does.
  let scanned = scan_element(value, 2, 0, || Ok(None)).unwrap();
  assert_eq!(scanned.element.bytes, b"= \"c");
  assert_eq!(scanned.recovery.at(), 0);
  assert_eq!(scanned.recovery.floor(), 0);
  assert!(scanned.recovery.strung());
  // The comma is the same comma either way: only `auth-scheme 1*SP` stands
  // between the two offsets, and neither a `token` nor a run of SP holds one.
  assert_eq!(raw_comma_end(value, 0), raw_comma_end(value, 2));
  // So all that moves is the question `some_reading_holds` asks, and it is the
  // difference between crossing that comma and declining it.
  assert!(some_reading_holds(
    value,
    0,
    raw_comma_end(value, 0),
    true,
    false
  ));
  assert!(!some_reading_holds(
    value,
    2,
    raw_comma_end(value, 2),
    true,
    false
  ));
}

#[test]
fn every_way_a_challenge_is_refused_invents_no_challenge_out_of_a_value() {
  // The other half of the same rule, and the defect this walk carried. `TRAP`
  // is a well-formed opener in its own right — the control above proves it
  // hides `Digest` when nothing precedes it — so a recovery that crossed the
  // comma inside `trap="open` would hand a caller a `Digest` challenge with a
  // `realm` no sender wrote, chosen by whoever controls that parameter's value.
  //
  // Behind a fault nothing forces RFC 9110 §11.2's `( token / quoted-string )`
  // on the bytes at `trap`'s value position, so the DQUOTE there is one a
  // reading may open and a reading may leave shut, and the two disagree about
  // that comma. The walk reports it: `AuthError::ChallengeBoundaryUnknown`, and
  // no further item.
  //
  // Every trigger reaches the same recovery, which is why the table above is
  // driven through both tails rather than one.
  for (head, fault, _) in REFUSED_HEADS {
    let value = behind(head, TRAP);
    let [refused, unknown, past] = walk::<3>([&*value]);
    assert_eq!(refused.unwrap().unwrap_err(), fault, "{head:?}");
    assert_eq!(
      unknown.unwrap().unwrap_err(),
      AuthError::ChallengeBoundaryUnknown,
      "the boundary behind {head:?}"
    );
    assert!(past.is_none(), "{head:?}");
  }

  // The two-field-line spelling, where the readings part inside the ELEMENT
  // rather than behind it. `Basic a="x` and `trap="open, Digest realm=z` are one
  // value: the reading that opens `a`'s value closes it at the DQUOTE behind
  // `trap=` and then runs to the comma behind `open`, and the reading that ends
  // the element at §5.2's join comma opens a string at `trap`'s own value
  // position instead and holds `Digest` inside it. So no tail is needed to
  // spring this one — the head is the trap.
  let [refused, unknown, past] = walk::<3>([&b"Basic a=\"x"[..], b"trap=\"open, Digest realm=z"]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // The same on ONE field line: `a="x,y"junk` closes its value and runs on, and
  // the reading that leaves the DQUOTE shut ends the element at the comma
  // INSIDE `"x,y"`. Two extents, and the tail behind them is not what decides
  // it — this row answers the same with a comma no reading holds behind it.
  for tail in [CERTAIN, TRAP] {
    let value = behind(b"Basic a=\"x,y\"junk", tail);
    let [refused, unknown, past] = walk::<3>([&*value]);
    assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
    assert_eq!(
      unknown.unwrap().unwrap_err(),
      AuthError::ChallengeBoundaryUnknown,
      "{tail:?}"
    );
    assert!(past.is_none(), "{tail:?}");
  }

  // And a comma the reading that CARRIED the value across the join holds,
  // which is the other half of what a recovery behind a joined element has to
  // answer. `Basic a="x` and `p, q"junk, Digest realm=z` are one value: the
  // reading that opens `a`'s value closes it at the DQUOTE behind `q` and runs
  // on to the comma behind `junk`, and the reading that ends the element at
  // §5.2's join comma begins at `p` — where the FIRST raw comma stands in
  // front of that close, inside the bytes the first reading holds. So the
  // earliest comma is one no boundary may be taken at, and a later one would
  // hide the element the second reading found.
  let [refused, unknown, past] = walk::<3>([&b"Basic a=\"x"[..], b"p, q\"junk, Digest realm=z"]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // The control that says that pair is about the RECOVERY and not about the
  // shape: the same two lines with nothing behind the close, so the element
  // derives, its value is the grammar's, and `Digest` is the second challenge.
  let [basic, digest, past] = walk::<3>([&b"Basic a=\"x"[..], b"p, q\", Digest realm=z"]);
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(names::<2>(&basic), [Some(&b"a"[..]), None]);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The parameter bound, which is #77's own trigger: RFC 9110 §11.2 bounds
  // `#auth-param` nowhere, so the input that meets it CONFORMS, and the
  // challenge invented behind it was invented on conforming input.
  let value = behind(SEVENTEEN_CHALLENGE, TRAP);
  let [refused, unknown, past] = walk::<3>([&*value]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::TooManyParameters);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // The line bound met between elements, with the trap on the line behind the
  // one that overran.
  let mut lines = [&b""[..]; 18];
  lines[..SEVENTEEN_LINES.len()].copy_from_slice(&SEVENTEEN_LINES);
  lines[17] = TRAP;
  let [refused, unknown, past] = walk::<3>(lines);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // The reading a join admits that no scan from the recovery cursor finds on
  // its own: a whole challenge beginning on the continuation line, with a
  // quoted parameter of ITS own. `Basic a="x` and
  // `Digest realm="evil, Newauth realm=z, junk", Safe realm=s` are one value
  // under RFC 9110 §5.2. One reading takes the DQUOTE behind `realm=` as the
  // CLOSE of `a`'s value and ends the element behind `evil`; the other shuts
  // `a` at the join comma and reads `Digest realm="evil, Newauth realm=z,
  // junk"` as a challenge whose `realm` holds `Newauth realm=z` as data. The
  // opener that decides it stands behind `auth-scheme 1*SP`, and a check asked
  // only at the cursor never sees it — so the comma behind `evil` was crossed
  // and `Newauth realm=z` was handed to a caller out of the middle of a realm.
  //
  // Nothing derivable is lost by refusing: the readings disagree about whether
  // `Newauth` is a challenge at all, and `Safe realm=s` stands behind a comma
  // only one of them agrees on.
  let invented_across_a_join: [&[u8]; 2] = [
    b"Basic a=\"x",
    b"Digest realm=\"evil, Newauth realm=z, junk\", Safe realm=s",
  ];
  let [refused, unknown, past] = walk::<3>(invented_across_a_join);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none(), "a challenge out of `realm`'s own data");

  // And across TWO joins, where the line the readings part on is not the line
  // the element began on OR the one behind it.
  let [refused, unknown, past] = walk::<3>([
    &b"Basic a=\"x"[..],
    b"nothing here closes it",
    b"Digest realm=\"evil, Newauth realm=z, junk\", Safe realm=s",
  ]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // The same reading with RFC 9110 §5.6.1.2's own `OWS` in front of it, which
  // is what `#element => [ element ] *( OWS "," OWS [ element ] )` hangs on
  // every comma — §5.2's join comma included. One space moves the element, and
  // both of its openers, off the offset the join left the cursor on; a check
  // asked at the cursor finds no `token` there at all, since §5.6.2's `tchar`
  // excludes SP, and crosses the comma inside `realm`'s own value.
  //
  // Both of §11.6.1's readings are spelled, and both spellings of §5.6.3's
  // `OWS`: the element's own value position (`realm="evil`) and a whole
  // challenge's first parameter (`Newauth realm="evil`).
  for continuation in [
    &b" realm=\"evil, Digest realm=z"[..],
    b"\trealm=\"evil, Digest realm=z",
    b"  realm=\"evil, Digest realm=z",
    b" Newauth realm=\"evil, Digest realm=z",
    b"\tNewauth realm=\"evil, Digest realm=z",
    b" \tNewauth realm=\"evil, Digest realm=z",
  ] {
    let [refused, unknown, past] = walk::<3>([&b"Basic a=\"x"[..], continuation]);
    assert_eq!(
      refused.unwrap().unwrap_err(),
      AuthError::MalformedParameter,
      "{continuation:?}"
    );
    assert_eq!(
      unknown.unwrap().unwrap_err(),
      AuthError::ChallengeBoundaryUnknown,
      "a challenge out of a value behind the list's own OWS: {continuation:?}"
    );
    assert!(past.is_none(), "{continuation:?}");

    // And across two joins, where one line's worth of state still answers.
    let [refused, unknown, past] =
      walk::<3>([&b"Basic a=\"x"[..], b"nothing here closes it", continuation]);
    assert_eq!(
      refused.unwrap().unwrap_err(),
      AuthError::MalformedParameter,
      "{continuation:?}"
    );
    assert_eq!(
      unknown.unwrap().unwrap_err(),
      AuthError::ChallengeBoundaryUnknown,
      "{continuation:?}"
    );
    assert!(past.is_none(), "{continuation:?}");
  }

  // The same bound, met at the crossing where the challenge's own value is
  // still OPEN across §5.2's join. `TRAP` is not the trap for this one, and no
  // tail can be: the walk stands INSIDE a string RFC 9110 §11.2 admitted at a
  // value position and §5.6.4 has closed nowhere, so every byte behind the
  // bound — the comma in front of `Digest` included — is that value's data in
  // the only reading there is. Yielding `Digest` here read a challenge out of
  // the interior of `a`'s value.
  let mut open_at_the_bound = [&b"j"[..]; 18];
  open_at_the_bound[0] = b"Basic a=\"x";
  open_at_the_bound[17] = b"p, Digest realm=z";
  let [refused, unknown, past] = walk::<3>(open_at_the_bound);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());
}

/// The exact tail al8n/wren#77 measured: an element whose value is a
/// well-formed RFC 9110 §5.6.4 quoted-string carrying a comma, a whole
/// challenge, another comma, and more of the same value.
///
/// It is the shape the parameter bound made reachable on CONFORMING input, and
/// the reason [`TRAP`] alone is not enough of a pin: the trap's string never
/// closes, so a reader could be right about it for the wrong reason — by
/// treating an unterminated run as special — and still cut this one in half.
/// Here nothing at all is wrong with the value.
const INVENTED: &[u8] = b"x=\"c, Digest realm=evil, junk\"";

/// The scheme #77's recovery manufactured, and the one no answer may carry.
fn yields_no_invented_scheme(lines: &[&[u8]], label: &[u8]) {
  for credential in challenges(lines.iter().copied()).flatten() {
    assert_ne!(
      credential.scheme(),
      b"Digest",
      "{label:?}: a scheme built out of a parameter's own data"
    );
  }
}

#[test]
fn a_value_the_grammar_admits_is_never_cut_into_a_challenge() {
  // al8n/wren#77, pinned as the input it was measured on. RFC 9110 §11.2 bounds
  // `#auth-param` nowhere, so
  //
  //     WWW-Authenticate: Basic p1=1, ..., p17=17, x="c, Digest realm=evil, junk"
  //
  // conforms: no repeated name, nothing malformed, no byte §5.5 forbids, one
  // field line. What refuses it is `MAX_PARAMS_PER_CREDENTIAL`, which is this
  // reader's own bound — and the recovery behind that refusal cut `x`'s value
  // at the comma inside it and handed the caller
  // `Ok(scheme="Digest", params=[realm="evil"])`. §11.4 has a user agent select
  // "the challenge with what it considers to be the most secure auth-scheme
  // that it understands", so the scheme and the realm it chooses were whoever
  // wrote `x`'s value.
  let mut exact = SEVENTEEN_CHALLENGE.to_vec();
  exact.extend_from_slice(b", ");
  exact.extend_from_slice(INVENTED);
  // The bound is this reader's, so the value still DERIVES — and where it does,
  // `( token / quoted-string )` is not a choice at `x`'s value position. The
  // element ends where that string closes, which is the end of the value, so
  // there is no `Digest` to invent AND no remainder to report. The notice this
  // row used to carry was an over-report of an unread stretch that does not
  // exist.
  let [refused, past] = walk::<2>([exact.as_slice()]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::TooManyParameters);
  assert!(past.is_none());
  yields_no_invented_scheme(&[exact.as_slice()], SEVENTEEN_CHALLENGE);

  // The control that says the tail is a value and not a trap: with nothing
  // refused in front of it, those same bytes are ONE challenge carrying ONE
  // parameter whose value holds the comma, the scheme and the realm as data.
  // That is what the sender wrote, and it is what makes cutting it an
  // invention rather than a recovery.
  let credential = one([&b"Basic x=\"c, Digest realm=evil, junk\""[..]]);
  assert_eq!(credential.scheme(), b"Basic");
  assert_eq!(names::<2>(&credential), [Some(&b"x"[..]), None]);
  assert!(
    matches!(
      credential.params().next().unwrap().value(),
      Ok(ParamValue::Quoted(v)) if v == b"c, Digest realm=evil, junk"
    ),
    "the whole tail is one parameter's value"
  );

  // Every trigger reaches that recovery, so every trigger is driven through the
  // same tail. The first six are the ones #77 enumerates; the two scheme faults
  // reach it as well and are here for the same reason.
  for (head, fault, _) in REFUSED_HEADS {
    let value = behind(head, INVENTED);
    if fault.is_a_receiver_bound() {
      // The value still DERIVES, so `( token / quoted-string )` is not a choice
      // at the trap's value position: the element ends where that string
      // closes, which is the end of the value. Nothing to invent, and no
      // remainder to report.
      let [refused, past] = walk::<2>([&*value]);
      assert_eq!(refused.unwrap().unwrap_err(), fault, "{head:?}");
      assert!(past.is_none(), "{head:?}");
    } else {
      // A fault of the GRAMMAR'S, so nothing derives behind it and the DQUOTE
      // at the trap's value position is a reading beside the one that leaves it
      // shut. The walk declines and says so.
      let [refused, unknown, past] = walk::<3>([&*value]);
      assert_eq!(refused.unwrap().unwrap_err(), fault, "{head:?}");
      assert_eq!(
        unknown.unwrap().unwrap_err(),
        AuthError::ChallengeBoundaryUnknown,
        "{head:?}"
      );
      assert!(past.is_none(), "{head:?}");
    }
    yields_no_invented_scheme(&[&value], head);
  }

  // The line bound, which no one-line value can reach.
  let mut lines = [&b""[..]; 18];
  lines[..SEVENTEEN_LINES.len()].copy_from_slice(&SEVENTEEN_LINES);
  lines[17] = INVENTED;
  // `MAX_CHALLENGE_LINES` is this reader's bound too, so the same rule holds:
  // the trap's string is forced, the element ends where it closes, and there is
  // nothing behind it.
  let [refused, past] = walk::<2>(lines);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert!(past.is_none());
  yields_no_invented_scheme(&lines, INVENTED);

  // And the scheme faults. They recover from where the scheme token ran out,
  // and there is no reading that hides between the element's first byte and
  // that cursor: `challenge` is entered only at an element no `auth-param` may
  // begin at. What they DO have to answer for is what stands behind them —
  // §11.6.1 lets a challenge already open take the refused element as a
  // malformed parameter of its own, and under that reading its list is still
  // open and the elements behind it may be parameters too. Both values below
  // open a list in front of the refusal, so both reach the same recovery.
  for (value, fault) in [
    (
      &b"Basic a=1, =x, x=\"c, Digest realm=evil, junk\""[..],
      AuthError::MissingScheme,
    ),
    (
      b"Basic a=1, Newauth\tq, x=\"c, Digest realm=evil, junk\"",
      AuthError::MalformedScheme,
    ),
  ] {
    let mut walk = challenges([value]).skip_while(|read| read.is_ok());
    assert_eq!(
      walk
        .next()
        .unwrap_or_else(|| panic!("{value:?}"))
        .unwrap_err(),
      fault,
      "{value:?}"
    );
    assert_eq!(
      walk
        .next()
        .unwrap_or_else(|| panic!("{value:?}"))
        .unwrap_err(),
      AuthError::ChallengeBoundaryUnknown,
      "{value:?}"
    );
    assert!(walk.next().is_none(), "{value:?}");
    yields_no_invented_scheme(&[value], value);
  }
}

/// The refusals whose recovery asks whether a `#auth-param` list is open at
/// all: the ones RFC 9110 §11.3's `challenge` takes at its `auth-scheme`, in
/// front of the `1*SP` that is the body's only entrance.
///
/// Every other refusal is inside a body, where a list is open by construction
/// and `Challenges::list_open` is not consulted.
const SCHEME_REFUSALS: [(&[u8], AuthError); 3] = [
  // `1*SP` is SP alone, so a HTAB reaching an element rather than §5.6.1.2's
  // comma opens no body.
  (b"Broken\tjunk", AuthError::MalformedScheme),
  // No leading `token` at all.
  (b"=x", AuthError::MissingScheme),
  // A byte behind the token the production admits nothing after.
  (b"Broken;junk", AuthError::MalformedScheme),
];

/// The tail those refusals are recovered past, whose DQUOTE stands at RFC 9110
/// §11.2's value position and never closes.
const OPEN_TRAP: &[u8] = b"x=\"open, Digest realm=z";

#[test]
fn a_list_lives_from_its_1_sp_to_the_challenge_that_derives_past_it() {
  // What a refusal at an `auth-scheme` inherits is the value's list state, not
  // the refused challenge's: RFC 9110 §11.6.1 lets a challenge already open
  // take the refused element as a malformed `auth-param` of its own, and under
  // that reading the elements behind it may be parameters too. So the question
  // is whether a `#auth-param` list is open HERE, and the two halves of it are
  // pinned below in opposite directions.
  //
  // ```text
  // challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // ```
  //
  // `1*SP` is the body's only entrance, and what closes a list is a challenge
  // that COMPLETES with a body §11.3's `#auth-param` alternative is not: no
  // body at all, or a `token68`. Both close it for one reason — their own
  // element derives as a challenge and derives as nothing else.
  for (prefix, reached) in [
    // No list has opened anywhere in the value.
    (&b""[..], true),
    // One has, and nothing since has closed it.
    (b"Basic a=1", false),
    // A scheme standing alone closes it. Its own element DERIVES — §11.6.1's
    // other reading of it needs `auth-param`'s `=`, and it has none — so the
    // list-still-open reading is a non-derivation beside a derivation and not
    // one of the two §11.6.1 leaves a recipient to choose between. This is the
    // shape the walk hid a `Digest` behind.
    (b"Basic a=1, Bearer", true),
    // The other spelling of the same scheme, where §5.6.1.2's `OWS` stands
    // between the token and its comma. One writer for both.
    (b"Basic a=1, Bearer\t", true),
    // And a list reopened behind that scheme is open again.
    (b"Basic a=1, Bearer, Newauth b=2", false),
    (b"Bearer, Basic a=1", false),
    // A `token68` body closes one for the SAME reason, and these are the rows
    // that say so. `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" /
    // "/" ) *"="` puts nothing but more `=` behind its first one, and
    // `auth-param = token BWS "=" BWS ( token / quoted-string )` needs a
    // `token` or a `quoted-string` there — so the `#auth-param` alternative
    // derives none of these bytes rather than deriving them badly. ABNF's `/`
    // being unordered says a recipient may try either alternative; it does not
    // make one that derives nothing into a reading. So no list is open behind
    // the challenge and the `Digest` is a challenge the sender wrote.
    (b"Bearer abc", true),
    (b"Bearer dGVzdA==", true),
    (b"Basic a=1, Bearer abc", true),
    // And a list reopened behind THAT is open again, exactly as it is behind a
    // bare scheme.
    (b"Basic a=1, Bearer abc, Newauth b=2", false),
  ] {
    for (refusal, fault) in SCHEME_REFUSALS {
      let mut value = prefix.to_vec();
      if !prefix.is_empty() {
        value.extend_from_slice(b", ");
      }
      value.extend_from_slice(refusal);
      value.extend_from_slice(b", ");
      value.extend_from_slice(OPEN_TRAP);

      let mut walk = challenges([value.as_slice()]).skip_while(|read| read.is_ok());
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_err(),
        fault,
        "{value:?}"
      );
      let last = walk.next().unwrap_or_else(|| panic!("{value:?}"));
      if reached {
        assert_eq!(
          last.unwrap_or_else(|_| panic!("{value:?}")).scheme(),
          b"Digest",
          "a list every reading closed hid a challenge: {value:?}"
        );
      } else {
        assert_eq!(
          last.unwrap_err(),
          AuthError::ChallengeBoundaryUnknown,
          "a list some reading still has open was crossed: {value:?}"
        );
        yields_no_invented_scheme(&[&value], &value);
      }
      assert!(walk.next().is_none(), "{value:?}");
    }
  }

  // The control that says the tail is a trap and the prefixes are what decides
  // it: the same values with a DQUOTE that CLOSES in front of the comma reach
  // `Digest` from every prefix, because every reading then stands outside the
  // string there.
  for prefix in [
    &b""[..],
    b"Basic a=1",
    b"Basic a=1, Bearer",
    b"Bearer abc",
    b"Basic a=1, Bearer abc",
  ] {
    for (refusal, fault) in SCHEME_REFUSALS {
      let mut value = prefix.to_vec();
      if !prefix.is_empty() {
        value.extend_from_slice(b", ");
      }
      value.extend_from_slice(refusal);
      value.extend_from_slice(b", x=\"shut\", Digest realm=z");

      let mut walk = challenges([value.as_slice()]).skip_while(|read| read.is_ok());
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_err(),
        fault,
        "{value:?}"
      );
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_or_else(|_| panic!("{value:?}"))
          .scheme(),
        b"Digest",
        "{value:?}"
      );
      assert!(walk.next().is_none(), "{value:?}");
    }
  }
}

#[test]
fn a_fault_takes_away_the_argument_a_completed_challenge_closes_a_list_with() {
  // The condition on the close, and the shape no other test here spells: a
  // challenge that completes BEHIND a fault. The argument the two closing
  // bodies share — a bare `auth-scheme` and RFC 9110 §11.2's `token68` — is
  // that every reading of the value has this element as a challenge, since
  // `auth-param = token BWS "=" BWS ( token / quoted-string )` derives none of
  // its bytes. Behind a fault that is no longer a fact about the value: nothing
  // derives there, so the readings include one in which every element since the
  // fault is garbage the open list still holds, and THAT reading has the list
  // open behind this challenge too.
  //
  // So the close is conditioned, and these are the values that condition it.
  // Each is `Basic a=1` — a list — then a fault, then a challenge that would
  // close the list if it stood in front of that fault, then the open trap. The
  // trap's DQUOTE is at a value position of `Basic`'s list under the surviving
  // reading, so the comma inside it is not a boundary and the walk says so.
  for closer in [&b"Bearer"[..], b"Bearer abc", b"Bearer dGVzdA=="] {
    for (refusal, _) in SCHEME_REFUSALS {
      let mut value = b"Basic a=1, Broken;junk, ".to_vec();
      value.extend_from_slice(closer);
      value.extend_from_slice(b", ");
      value.extend_from_slice(refusal);
      value.extend_from_slice(b", ");
      value.extend_from_slice(OPEN_TRAP);

      let last = challenges([value.as_slice()])
        .last()
        .unwrap_or_else(|| panic!("{value:?}"));
      assert_eq!(
        last.unwrap_err(),
        AuthError::ChallengeBoundaryUnknown,
        "a list a fault left open was crossed: {value:?}"
      );
      yields_no_invented_scheme(&[&value], &value);
    }
  }

  // The control in the other direction, which says the condition is the FAULT
  // and not the second challenge: the same values with the fault removed reach
  // `Digest` from every closer.
  for closer in [&b"Bearer"[..], b"Bearer abc", b"Bearer dGVzdA=="] {
    for (refusal, _) in SCHEME_REFUSALS {
      let mut value = b"Basic a=1, ".to_vec();
      value.extend_from_slice(closer);
      value.extend_from_slice(b", ");
      value.extend_from_slice(refusal);
      value.extend_from_slice(b", ");
      value.extend_from_slice(OPEN_TRAP);

      let last = challenges([value.as_slice()])
        .last()
        .unwrap_or_else(|| panic!("{value:?}"));
      assert_eq!(
        last.unwrap_or_else(|_| panic!("{value:?}")).scheme(),
        b"Digest",
        "a list every reading closed hid a challenge: {value:?}"
      );
    }
  }
}

/// The three refusals this reader sets that RFC 9110 does not, each written as
/// the field-line fragments it takes.
///
/// [`AuthError::is_a_receiver_bound`] names them, and its doc is the argument.
/// The grammar derives every byte of these values, with every element of every
/// list where §5.6.1.2 puts it; what the refusal says is that this reader will
/// not HOLD the challenge, and never that it cannot find the next one.
const RECEIVER_BOUNDS: [(&[&[u8]], AuthError); 3] = [
  // One name past `MAX_PARAMS_PER_CREDENTIAL`.
  (
    &[b"Basic p1=1, p2=2, p3=3, p4=4, p5=5, p6=6, p7=7, p8=8, p9=9, p10=10, p11=11, p12=12, p13=13, p14=14, p15=15, p16=16, p17=17"],
    AuthError::TooManyParameters,
  ),
  // RFC 9110 §11.2's one-name-once MUST, which is prose about names laid over a
  // list §5.6.1.2 has already delimited: it moves no comma.
  (&[b"Basic a=1, a=1"], AuthError::DuplicateParameter),
  // One region past `MAX_CHALLENGE_LINES`, with SIXTEEN names and not
  // seventeen: the first parameter's value crosses §5.2's join, so it spends
  // two regions on one name and this row is about the line bound alone.
  (
    &[
      b"Basic a1=\"x",
      b"y\"",
      b"a2=2",
      b"a3=3",
      b"a4=4",
      b"a5=5",
      b"a6=6",
      b"a7=7",
      b"a8=8",
      b"a9=9",
      b"a10=10",
      b"a11=11",
      b"a12=12",
      b"a13=13",
      b"a14=14",
      b"a15=15",
      b"a16=16",
    ],
    AuthError::ChallengeSpansTooManyLines,
  ),
];

/// The challenges that complete between two refusals, each of which ends a
/// `#auth-param` list the grammar still has open.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
const CLOSING_BODIES: [&[u8]; 3] = [b"Bearer", b"Bearer abc", b"Bearer dGVzdA=="];

#[test]
fn a_bound_this_reader_sets_leaves_every_boundary_where_the_grammar_put_it() {
  // This holds in both directions: a refusal is one of two things, and the
  // recovery behind it is not the same for both.
  //
  // ```text
  // #element   => [ element ] *( OWS "," OWS [ element ] )
  // challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // auth-param = token BWS "=" BWS ( token / quoted-string )
  // ```
  //
  // Behind an element RFC 9110 derives no part of, no boundary is fixed: a
  // DQUOTE at a §11.2 value position is a reading's to open or to leave shut,
  // and one reading has every element since as garbage the open list still
  // holds. Behind a bound of THIS reader's the grammar is untouched — every
  // element is where §5.6.1.2 puts it — so the first element no `auth-param`
  // derives ends the list, and `Bearer abc` is such an element.
  //
  // `Basic <seventeen parameters>, Bearer abc, x="open, Digest realm=z` is the
  // value: `MAX_PARAMS_PER_CREDENTIAL` refuses the `Basic`, recovery reaches
  // and yields the `Bearer`, and the `Digest` behind `x` is a challenge no
  // reading of these bytes holds inside a value.
  for (bound, fault) in RECEIVER_BOUNDS {
    for closer in CLOSING_BODIES {
      for opener in [&b""[..], b"Basic a=1"] {
        // A fixed shape rather than a growable one, so this reads on the
        // `no_std` tier where the name `Vec` is not in scope.
        let mut lines: [_; MAX_CHALLENGE_LINES + 1] = core::array::from_fn(|_| b"".to_vec());
        let held = bound.len();
        for (index, (line, fragment)) in lines.iter_mut().zip(bound).enumerate() {
          if index == 0 && !opener.is_empty() {
            line.extend_from_slice(opener);
            line.extend_from_slice(b", ");
          }
          line.extend_from_slice(fragment);
        }
        let tail = lines
          .get_mut(held.saturating_sub(1))
          .expect("a bound takes at least one line and at most the array's");
        tail.extend_from_slice(b", ");
        tail.extend_from_slice(closer);
        tail.extend_from_slice(b", ");
        tail.extend_from_slice(OPEN_TRAP);
        let lines = lines.get(..held).unwrap_or_default();

        let mut walk =
          challenges(lines.iter().map(|line| line.as_slice())).skip_while(|read| read.is_ok());
        assert_eq!(
          walk
            .next()
            .unwrap_or_else(|| panic!("{lines:?}"))
            .unwrap_err(),
          fault,
          "{lines:?}"
        );
        assert_eq!(
          walk
            .next()
            .unwrap_or_else(|| panic!("{lines:?}"))
            .unwrap_or_else(|_| panic!("{lines:?}"))
            .scheme(),
          closer.get(..6).unwrap_or_default(),
          "the challenge recovery reached: {lines:?}"
        );
        assert_eq!(
          walk
            .next()
            .unwrap_or_else(|| panic!("{lines:?}"))
            .unwrap_err(),
          AuthError::MalformedScheme,
          "{lines:?}"
        );
        assert_eq!(
          walk
            .next()
            .unwrap_or_else(|| panic!("{lines:?}"))
            .unwrap_or_else(|_| panic!("{lines:?}"))
            .scheme(),
          b"Digest",
          "a bound this reader sets hid a challenge behind it: {lines:?}"
        );
        assert!(walk.next().is_none(), "{lines:?}");
      }
    }
  }

  // The control in the other direction, and the whole of what separates the two
  // regimes: the same shape with a fault of the GRAMMAR in the bound's place.
  // Nothing derives behind it, so the `Bearer` closes no list and the walk says
  // the rest is unread rather than crossing a comma some reading holds inside
  // `x`'s value.
  for (refusal, fault) in SCHEME_REFUSALS {
    for closer in CLOSING_BODIES {
      let mut value = b"Basic a=1, ".to_vec();
      value.extend_from_slice(refusal);
      value.extend_from_slice(b", ");
      value.extend_from_slice(closer);
      value.extend_from_slice(b", ");
      value.extend_from_slice(OPEN_TRAP);

      let mut walk = challenges([value.as_slice()]).skip_while(|read| read.is_ok());
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_err(),
        fault,
        "{value:?}"
      );
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_or_else(|_| panic!("{value:?}"))
          .scheme(),
        closer.get(..6).unwrap_or_default(),
        "{value:?}"
      );
      assert_eq!(
        challenges([value.as_slice()])
          .last()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_err(),
        AuthError::ChallengeBoundaryUnknown,
        "a list a fault left open was crossed: {value:?}"
      );
      yields_no_invented_scheme(&[&value], &value);
    }
  }
}

#[test]
fn the_element_recovery_resumes_on_is_not_a_challenge_that_completed() {
  // `Challenges::seek` stops on an element [`opens_a_challenge`] answers `true`
  // for, and it is tempting to read that as the list having ended there. It is
  // not the same sentence.
  //
  // ```text
  // #element   => [ element ] *( OWS "," OWS [ element ] )
  // auth-param = token BWS "=" BWS ( token / quoted-string )
  // ```
  //
  // `opens_a_challenge` says no `auth-param` BEGINS at the element. Where the
  // walk goes on to refuse that same element at its `auth-scheme`, nothing
  // derives there under any reading — so the reading in which RFC 9110
  // §11.6.1's list is still running and this element is garbage inside it
  // survives, and the list has not ended after all.
  //
  // `Basic <seventeen parameters>, Broken;junk, x="open, Digest realm=z` is the
  // value. `MAX_PARAMS_PER_CREDENTIAL` refuses the `Basic`, recovery resumes on
  // `Broken;junk`, and `Broken;junk` is then refused itself — so the DQUOTE at
  // `x`'s value position still stands at a value position of `Basic`'s list and
  // the comma inside it is no boundary.
  for (bound, fault) in RECEIVER_BOUNDS {
    for tail in [&b"Broken;junk, "[..], b"y=1, Broken;junk, "] {
      let mut lines: [_; MAX_CHALLENGE_LINES + 1] = core::array::from_fn(|_| b"".to_vec());
      let held = bound.len();
      for (line, fragment) in lines.iter_mut().zip(bound) {
        line.extend_from_slice(fragment);
      }
      let last = lines
        .get_mut(held.saturating_sub(1))
        .expect("a bound takes at least one line and at most the array's");
      last.extend_from_slice(b", ");
      last.extend_from_slice(tail);
      last.extend_from_slice(OPEN_TRAP);
      let lines = lines.get(..held).unwrap_or_default();

      let mut walk =
        challenges(lines.iter().map(|line| line.as_slice())).skip_while(|read| read.is_ok());
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{lines:?}"))
          .unwrap_err(),
        fault,
        "{lines:?}"
      );
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{lines:?}"))
          .unwrap_err(),
        AuthError::MalformedScheme,
        "{lines:?}"
      );
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{lines:?}"))
          .unwrap_err(),
        AuthError::ChallengeBoundaryUnknown,
        "the element recovery resumed on closed a list it did not derive: {lines:?}"
      );
      assert!(walk.next().is_none(), "{lines:?}");
    }
  }

  // The control, and the whole of the difference: the same bound with a
  // challenge that COMPLETES where the fault stood. Its own element derives as
  // an element of the outer list and derives as nothing else, so the list has
  // ended and the probe is reached.
  for (bound, fault) in RECEIVER_BOUNDS {
    for closer in CLOSING_BODIES {
      let mut lines: [_; MAX_CHALLENGE_LINES + 1] = core::array::from_fn(|_| b"".to_vec());
      let held = bound.len();
      for (line, fragment) in lines.iter_mut().zip(bound) {
        line.extend_from_slice(fragment);
      }
      let last = lines
        .get_mut(held.saturating_sub(1))
        .expect("a bound takes at least one line and at most the array's");
      last.extend_from_slice(b", ");
      last.extend_from_slice(closer);
      last.extend_from_slice(b", ");
      last.extend_from_slice(OPEN_TRAP);
      let lines = lines.get(..held).unwrap_or_default();

      let last = challenges(lines.iter().map(|line| line.as_slice()))
        .last()
        .unwrap_or_else(|| panic!("{lines:?}"));
      assert_eq!(
        last.unwrap_or_else(|_| panic!("{lines:?}")).scheme(),
        b"Digest",
        "a list a completed challenge ended hid a challenge: {lines:?}"
      );
    }
    let _ = fault;
  }
}

#[test]
fn a_fault_reaches_past_itself_only_through_the_list_it_stood_in() {
  // A fault of RFC 9110's grammar, and then a bound THIS reader sets. The bound
  // alone would leave the readings behind it the grammar's, so the next
  // completed challenge ends the list. Whether the fault in front of it takes
  // that away is `Epoch::reaches_past_itself`, and its doc is the argument: a
  // fault changes what the bytes behind it may be read as in exactly one way —
  // the DQUOTE at a §11.2 value position becomes a choice — and §11.2 admits a
  // value position only inside a `#auth-param` list. So a fault met inside a
  // list reaches past itself and one met where none is open does not.
  //
  // ```text
  // challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // auth-param = token BWS "=" BWS ( token / quoted-string )
  // ```
  //
  // Both directions over the same shape, which is the whole of the claim.
  for (prefix, reaches) in [
    // A list is open where the fault is met, so it may still be running at the
    // trap: `Bearer abc` closes nothing and the DQUOTE behind it stands at a
    // value position of a list some reading still has open.
    (&b"Basic a=1, Broken;junk, "[..], true),
    // And none is. `Broken;junk` is the value's first element, so no reading
    // has a list at it for a string to belong to — and the `Basic` list that
    // opens behind it is one this fault never stood in. The elements behind it
    // must read exactly as they do with the prefix removed.
    (b"Broken;junk, ", false),
  ] {
    for (bound, fault) in RECEIVER_BOUNDS {
      for closer in CLOSING_BODIES {
        let mut lines: [_; MAX_CHALLENGE_LINES + 1] = core::array::from_fn(|_| b"".to_vec());
        let held = bound.len();
        for (index, (line, fragment)) in lines.iter_mut().zip(bound).enumerate() {
          if index == 0 {
            line.extend_from_slice(prefix);
          }
          line.extend_from_slice(fragment);
        }
        let last = lines
          .get_mut(held.saturating_sub(1))
          .expect("a bound takes at least one line and at most the array's");
        last.extend_from_slice(b", ");
        last.extend_from_slice(closer);
        last.extend_from_slice(b", ");
        last.extend_from_slice(OPEN_TRAP);
        let lines = lines.get(..held).unwrap_or_default();

        // The fault and the bound are reported in that order either way.
        let mut walk =
          challenges(lines.iter().map(|line| line.as_slice())).skip_while(|read| read.is_ok());
        assert_eq!(
          walk
            .next()
            .unwrap_or_else(|| panic!("{lines:?}"))
            .unwrap_err(),
          AuthError::MalformedScheme,
          "{lines:?}"
        );
        assert_eq!(
          walk
            .next()
            .unwrap_or_else(|| panic!("{lines:?}"))
            .unwrap_err(),
          fault,
          "{lines:?}"
        );

        let last = challenges(lines.iter().map(|line| line.as_slice()))
          .last()
          .unwrap_or_else(|| panic!("{lines:?}"));
        if reaches {
          assert_eq!(
            last.unwrap_err(),
            AuthError::ChallengeBoundaryUnknown,
            "a bound behind a fault with a list put the grammar back: {lines:?}"
          );
          for credential in challenges(lines.iter().map(|line| line.as_slice())).flatten() {
            assert_ne!(
              credential.scheme(),
              b"Digest",
              "a scheme built out of a parameter's own data: {lines:?}"
            );
          }
        } else {
          assert_eq!(
            last.unwrap_or_else(|_| panic!("{lines:?}")).scheme(),
            b"Digest",
            "a fault with no list reached past itself and hid a challenge: {lines:?}"
          );
        }
      }
    }
  }
}

/// The elements a recovery ABSORBS, and what RFC 9110 §11.2 says about each.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Every one of these is an element `opens_a_challenge` answers `false` for, so
/// `Challenges::seek` crosses it rather than stopping on it. The flag is
/// whether §11.2 derives it, which is the only thing an epoch's own claim turns
/// on: `BWS` is admitted on both sides of the `=` and a repeated name is
/// §11.2's own MUST rather than a fault of the grammar, so both of those must
/// SUSTAIN the claim; `( token / quoted-string )` is one alternative taken
/// whole, so the two `trailing` spellings refute it.
///
/// `y=1"x` is the one row that is not about the value's own shape: the DQUOTE
/// stands behind a `token` the value already took, so §11.2 admits no
/// quoted-string at it, it opens nothing, and what is left is a `token`
/// alternative with bytes behind it.
///
/// `y=1<SP>` is the row that says the list's own whitespace is not the
/// element's. §5.6.1.2 hangs `OWS` on BOTH sides of its comma, so the space in
/// front of one belongs to the list — an absorbed element read with it still on
/// is a `token` with a space behind it, which is neither of §11.2's
/// alternatives, and the span would be refuted by whitespace the sender was
/// entitled to write.
///
/// The last pair is the same two elements in both orders, because the claim is
/// about every element of the span and a rule that asked only the first would
/// answer one of them wrong.
const ABSORBED: [(&[u8], bool); 12] = [
  (b"y=1", true),
  (b"y=\"q\"", true),
  (b"y\t=\ta", true),
  (b"a=1", true),
  (b"y=1, z=2", true),
  (b"y=1 ", true),
  (b"y=", false),
  (b"y=1 z", false),
  (b"y=\"q\"z", false),
  (b"y=1\"x", false),
  (b"y=1, z=", false),
  (b"y=, z=1", false),
];

#[test]
fn an_epoch_is_derivable_only_while_every_element_of_its_span_still_derives() {
  // A recovery epoch opened by a bound of THIS reader's claims that the
  // bound, and not RFC 9110's grammar, is why the
  // value stopped deriving — which is what lets a challenge that completes
  // behind it end the `#auth-param` list the refusal left open.
  //
  // ```text
  // #element   => [ element ] *( OWS "," OWS [ element ] )
  // challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // auth-param = token BWS "=" BWS ( token / quoted-string )
  // ```
  //
  // That is a claim about every element between the refusal and the close: a
  // derivation of the whole value has to reach through all of them. So the
  // first one §11.2 derives nothing at falsifies it — the grammar is then a
  // reason too — and the epoch may no longer be closed.
  //
  // `Basic a=1, a=2, y=, Bearer, x="open, Digest realm=z` is the witness. `y=`
  // is skipped by `seek` because an `auth-param` BEGINS at it, `Bearer` closed
  // the epoch on the strength of a claim `y=` had already refuted, and the
  // scheme fault at `x=` then stood in front of no open list and crossed the
  // comma inside `x`'s own value — handing back a `Digest` challenge out of the
  // middle of it.
  //
  // Both directions over one shape: where the span derives, the probe is a
  // challenge and must still be shown.
  for (bound, fault) in RECEIVER_BOUNDS {
    for closer in CLOSING_BODIES {
      for (span, derives) in ABSORBED {
        let mut lines: [_; MAX_CHALLENGE_LINES + 1] = core::array::from_fn(|_| b"".to_vec());
        let held = bound.len();
        for (line, fragment) in lines.iter_mut().zip(bound) {
          line.extend_from_slice(fragment);
        }
        let last = lines
          .get_mut(held.saturating_sub(1))
          .expect("a bound takes at least one line and at most the array's");
        last.extend_from_slice(b", ");
        last.extend_from_slice(span);
        last.extend_from_slice(b", ");
        last.extend_from_slice(closer);
        last.extend_from_slice(b", ");
        last.extend_from_slice(OPEN_TRAP);
        let lines = lines.get(..held).unwrap_or_default();

        // The bound is still the first fault reported, whatever the span holds:
        // a refusal binds where it is met and the span is behind it.
        assert_eq!(
          challenges(lines.iter().map(|line| line.as_slice()))
            .find(|read| read.is_err())
            .unwrap_or_else(|| panic!("{lines:?}"))
            .unwrap_err(),
          fault,
          "{lines:?}"
        );
        // And the closer still completes, so what moves is the epoch's claim
        // and not which challenges the walk reaches.
        assert!(
          challenges(lines.iter().map(|line| line.as_slice()))
            .flatten()
            .any(|credential| credential.scheme() == b"Bearer"),
          "the challenge that closes the epoch was not read: {lines:?}"
        );

        let last = challenges(lines.iter().map(|line| line.as_slice()))
          .last()
          .unwrap_or_else(|| panic!("{lines:?}"));
        if derives {
          assert_eq!(
            last.unwrap_or_else(|_| panic!("{lines:?}")).scheme(),
            b"Digest",
            "a span the grammar derives cost a challenge: {lines:?}"
          );
        } else {
          assert_eq!(
            last.unwrap_err(),
            AuthError::ChallengeBoundaryUnknown,
            "a span the grammar derives nothing at still closed an epoch: {lines:?}"
          );
          for credential in challenges(lines.iter().map(|line| line.as_slice())).flatten() {
            assert_ne!(
              credential.scheme(),
              b"Digest",
              "a scheme built out of a parameter's own data: {lines:?}"
            );
          }
        }
      }
    }
  }
}

#[test]
fn the_element_a_refusal_leaves_the_cursor_on_is_in_the_span_it_opens() {
  // The span rule has no first-element exception, and this is the shape that
  // says why it may not. RFC 9110 §5.2 joins the field lines into one value;
  // `MAX_CHALLENGE_LINES` is met when the challenge needs a line this reader
  // may not hold, and it is met with the cursor at the HEAD of that line — on
  // an element the walk has not read and nothing has derived.
  //
  // ```text
  // #element   = [ element ] *( OWS "," OWS [ element ] )
  // challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // auth-param = token BWS "=" BWS ( token / quoted-string )
  // ```
  //
  // So the first element of the span is the first element of that line. A rule
  // that measured only the elements BEHIND the cursor was green over every
  // other shape on this branch and handed a caller the `Digest` below, read
  // out of `x`'s own value.
  // `a1` is on the first line, so the names behind it start at `a2`: a repeat
  // would be refused by RFC 9110 §11.2's one-name-once MUST before the line
  // bound this test is about is ever met. Written out because no allocator is
  // assumed here.
  const NAMES: [&[u8]; MAX_CHALLENGE_LINES] = [
    b"Basic a1=1",
    b"a2=1",
    b"a3=1",
    b"a4=1",
    b"a5=1",
    b"a6=1",
    b"a7=1",
    b"a8=1",
    b"a9=1",
    b"a10=1",
    b"a11=1",
    b"a12=1",
    b"a13=1",
    b"a14=1",
    b"a15=1",
    b"a16=1",
  ];
  for (span, derives) in ABSORBED {
    let mut lines: [_; MAX_CHALLENGE_LINES + 1] = core::array::from_fn(|_| b"".to_vec());
    for (line, name) in lines.iter_mut().zip(NAMES) {
      line.extend_from_slice(name);
    }
    let last = lines
      .last_mut()
      .expect("the array holds one line past the bound");
    last.extend_from_slice(span);
    last.extend_from_slice(b", Bearer, ");
    last.extend_from_slice(OPEN_TRAP);

    // The bound is what refused it, and the closer behind the span still
    // completes — so what moves is the epoch's claim and not the walk's reach.
    let read = lines.iter().map(|line| line.as_slice());
    assert_eq!(
      challenges(read)
        .find(|answer| answer.is_err())
        .unwrap_or_else(|| panic!("{lines:?}"))
        .unwrap_err(),
      AuthError::ChallengeSpansTooManyLines,
      "{lines:?}"
    );
    assert!(
      challenges(lines.iter().map(|line| line.as_slice()))
        .flatten()
        .any(|credential| credential.scheme() == b"Bearer"),
      "the challenge that closes the epoch was not read: {lines:?}"
    );

    let last = challenges(lines.iter().map(|line| line.as_slice()))
      .last()
      .unwrap_or_else(|| panic!("{lines:?}"));
    if derives {
      assert_eq!(
        last.unwrap_or_else(|_| panic!("{lines:?}")).scheme(),
        b"Digest",
        "a span the grammar derives cost a challenge: {lines:?}"
      );
    } else {
      assert_eq!(
        last.unwrap_err(),
        AuthError::ChallengeBoundaryUnknown,
        "the element the cursor stands on was left out of the span: {lines:?}"
      );
    }
  }
}

#[test]
fn a_bound_met_inside_a_span_refutes_nothing_the_grammar_did_not() {
  // The other direction of the same rule, and the one that says it is RFC
  // 9110's grammar being asked and not the walk's own bookkeeping. A repeated
  // name and a nineteenth parameter are refusals THIS reader makes; §11.2
  // derives every byte of the elements carrying them, with every element where
  // §5.6.1.2 puts it, so neither moves a comma and neither may refute a span.
  //
  // The `a=1` row is a real repeat: `Basic a=1, a=1` is the refused challenge,
  // so the absorbed element carries a name that challenge already used. The
  // long row is nineteen more parameters behind a bound of seventeen, which is
  // `MAX_PARAMS_PER_CREDENTIAL` exceeded twice over inside one span.
  for span in [
    &b"a=1"[..],
    b"q1=1, q2=1, q3=1, q4=1, q5=1, q6=1, q7=1, q8=1, q9=1, q10=1, q11=1, q12=1, q13=1, q14=1, q15=1, q16=1, q17=1, q18=1, q19=1",
  ] {
    let mut value = b"Basic a=1, a=1, ".to_vec();
    value.extend_from_slice(span);
    value.extend_from_slice(b", Bearer, ");
    value.extend_from_slice(OPEN_TRAP);
    let read: [&[u8]; 1] = [value.as_slice()];
    assert_eq!(
      challenges(read)
        .last()
        .unwrap_or_else(|| panic!("{value:?}"))
        .unwrap_or_else(|_| panic!("{value:?}"))
        .scheme(),
      b"Digest",
      "a bound met inside a span refuted it: {value:?}"
    );
  }
}

#[test]
fn a_list_free_fault_in_front_of_a_value_hides_none_of_its_challenges() {
  // The strongest form of the same claim: prefixing a value with a fault
  // that opens no `#auth-param` list must expose exactly the challenges it
  // exposed without the prefix, in the same order.
  //
  // `Broken;junk` is that prefix. It is an element of the outer `#challenge`
  // list that derives nothing, at the head of the value where no list is open,
  // and `Challenges::seek` settles its extent by the commas every reading ends
  // an element at. There is nothing left of it to reach forward with.
  //
  // **Challenges, not answers.** The FAULT count may fall by one, because
  // §11.6.1's ambiguity is resolved once per challenge and `seek` reads a
  // parameter-shaped element behind the refusal as part of the fault already
  // reported rather than as a second one — `Basic="q` behind this prefix is
  // absorbed that way.
  //
  // **What that costs, and the scope of the argument, which is the whole of
  // it.** THIS epoch is list-free, so two things hold together and neither is
  // a fact about absorption in general. `refused_element_end` admits no
  // opener, so every comma `seek` crosses is one every reading ends an element
  // at; and a receiver bound is only ever met inside the body RFC 9110 §11.3's
  // `1*SP` opened, so a list-free epoch is never derivable and has no claim for
  // an absorbed element to falsify. An element absorbed here can therefore cost
  // a fault report and nothing else. It is an element `opens_a_challenge`
  // answered `false` for, which
  // `an_element_that_completes_a_challenge_is_no_parameter_of_the_list_in_front_of_it`
  // proves can never complete a challenge, so nothing is hidden — and there is
  // no derivability left to lose, so nothing is invented.
  //
  // **That scope did not cover this.** Read as a claim about absorption
  // rather than about THIS epoch, it says a skipped
  // element costs only a report; and in a DERIVABLE epoch it costs the claim
  // itself, because the element the grammar derives nothing at is precisely the
  // evidence that the grammar is a reason the value stopped deriving.
  // `an_epoch_is_derivable_only_while_every_element_of_its_span_still_derives`
  // is that half, and the two are the two regimes an epoch has rather than a
  // rule and its exception.
  for tail in [
    &b"Safe, Basic a=1, a=2, Bearer abc, x=\"open, Digest realm=z"[..],
    b"Basic a=1, a=2, Bearer abc, x=\"open, Digest realm=z",
    b"Basic a=1, Bearer, x=\"open, Digest realm=z",
    b"Bearer abc, x=\"open, Digest realm=z",
    b"Basic a=1, Broken;junk, Bearer, x=\"open, Digest realm=z",
    b"Basic ;, Bearer, x=\"open, Digest realm=z",
    b"Basic=\"q, Digest realm=z",
    b"Basic p1=1, Bearer dGVzdA==, x=\"open, Digest realm=z",
  ] {
    let mut prefixed = b"Broken;junk, ".to_vec();
    prefixed.extend_from_slice(tail);

    let bare: [_; 8] = core::array::from_fn(|_| None);
    let mut bare = bare;
    for (slot, scheme) in bare.iter_mut().zip(
      challenges([tail])
        .flatten()
        .map(|credential| credential.scheme()),
    ) {
      *slot = Some(scheme);
    }
    let with: [_; 8] = core::array::from_fn(|_| None);
    let mut with = with;
    for (slot, scheme) in with.iter_mut().zip(
      challenges([prefixed.as_slice()])
        .flatten()
        .map(|credential| credential.scheme()),
    ) {
      *slot = Some(scheme);
    }
    assert_eq!(bare, with, "a list-free fault moved a challenge: {tail:?}");
    // And the prefix is reported, so the caller is not told a value it never
    // received: the fault is the walk's FIRST answer either way.
    assert_eq!(
      challenges([prefixed.as_slice()])
        .next()
        .unwrap_or_else(|| panic!("{tail:?}"))
        .unwrap_err(),
      AuthError::MalformedScheme,
      "{tail:?}"
    );
  }
}

#[test]
fn a_fault_reported_over_a_complete_extent_is_a_refusal_like_every_other() {
  // Two faults are reported with the challenge's extent ALREADY complete — a
  // body neither of RFC 9110 §11.3's alternatives derives, and the line bound
  // met on the region the challenge ends in — and previously they reached the
  // caller without the walk recording a refusal at all.
  //
  // `Basic ;` is the first of them: `;` is no §5.6.2 `tchar`, so the body is no
  // `#auth-param` list, and §11.2's `token68` alphabet does not hold it either.
  // Nothing derives from there, so nothing behind it does — and the `Bearer`
  // standing behind it closes no list. A walk that recorded nothing let it, and
  // handed a caller a `Digest` read out of the middle of `x`'s own value.
  for closer in CLOSING_BODIES {
    for opener in [&b""[..], b"Basic a=1"] {
      let mut value = b"".to_vec();
      if !opener.is_empty() {
        value.extend_from_slice(opener);
        value.extend_from_slice(b", ");
      }
      value.extend_from_slice(b"Basic ;, ");
      value.extend_from_slice(closer);
      value.extend_from_slice(b", ");
      value.extend_from_slice(OPEN_TRAP);

      let mut walk = challenges([value.as_slice()]).skip_while(|read| read.is_ok());
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_err(),
        AuthError::MalformedParameter,
        "{value:?}"
      );
      assert_eq!(
        walk
          .next()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_or_else(|_| panic!("{value:?}"))
          .scheme(),
        closer.get(..6).unwrap_or_default(),
        "{value:?}"
      );
      assert_eq!(
        challenges([value.as_slice()])
          .last()
          .unwrap_or_else(|| panic!("{value:?}"))
          .unwrap_err(),
        AuthError::ChallengeBoundaryUnknown,
        "a body no reading derives left a list the `Bearer` behind it closed: {value:?}"
      );
      yields_no_invented_scheme(&[&value], &value);
    }
  }

  // And the control that says this is the BODY and not the `Basic`: the same
  // value with a body §11.2's `#auth-param` derives leaves no fault behind it,
  // the `Bearer` closes the list it opened, and the `Digest` is reached.
  for closer in CLOSING_BODIES {
    let mut value = b"Basic a=1, ".to_vec();
    value.extend_from_slice(closer);
    value.extend_from_slice(b", ");
    value.extend_from_slice(OPEN_TRAP);
    assert_eq!(
      challenges([value.as_slice()])
        .last()
        .unwrap_or_else(|| panic!("{value:?}"))
        .unwrap_or_else(|_| panic!("{value:?}"))
        .scheme(),
      b"Digest",
      "{value:?}"
    );
  }
}

#[test]
fn an_element_that_completes_a_challenge_is_no_parameter_of_the_list_in_front_of_it() {
  // The argument `a_yielded_challenge_is_no_parameter` rests on, executed over
  // the productions rather than asserted in its doc.
  //
  // ```text
  // challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // auth-param = token BWS "=" BWS ( token / quoted-string )
  // token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  // ```
  //
  // Suppose an element is both. Some `auth-param` begins at it, so a `token`,
  // then `BWS`, then `=` stand at its head; and it completes as a challenge, so
  // `auth-scheme 1*SP` stands there too and the body opens at the first byte
  // behind the SP run. `BWS` is §5.6.3's `OWS`, and a HTAB between the scheme
  // and the `=` is refused before any body is read — so the run is SP alone and
  // the body opens AT the `=`. `#auth-param` needs a `token` at its first
  // element and `=` is no §5.6.2 `tchar`; `token68` needs one of its own base
  // alphabet, where `=` is only the trailing pad. The body derives nothing, the
  // challenge is refused rather than completed, and the two cannot both hold.
  //
  // [`ELEMENT_ALPHABET`], the same eight bytes the other brute force here runs
  // over, written once so the two answer over the same elements.
  const ALPHABET: [u8; 8] = ELEMENT_ALPHABET;
  let (mut examined, mut parameters, mut completed) = (0usize, 0usize, 0usize);
  let mut element = [0_u8; 5];
  for len in 1..=5_usize {
    for mut index in 0..ALPHABET
      .len()
      .pow(u32::try_from(len).unwrap_or_else(|_| unreachable!("a length of five fits in a u32")))
    {
      for slot in element.iter_mut().take(len) {
        *slot = ALPHABET[index % ALPHABET.len()];
        index /= ALPHABET.len();
      }
      let element = element.get(..len).unwrap_or_default();
      let a_parameter = param_value_at(element, 0).is_some();
      // The element read as a whole value, which is the element read as a
      // `#challenge` list of one: no comma is in the alphabet, so the walk
      // yields one answer and it is this element's.
      let completes = matches!(challenges([element]).next(), Some(Ok(_)));
      assert!(
        !(a_parameter && completes),
        "an element completed a challenge and admits an auth-param at its head: {element:?}"
      );
      examined += 1;
      parameters += usize::from(a_parameter);
      completed += usize::from(completes);
    }
  }
  // Neither column is vacuously empty, which is the half a `false` on either
  // side would pass without.
  assert_eq!((examined, parameters, completed), (37_448, 2_034, 990));
}

#[test]
fn a_run_that_ends_its_element_is_no_body_when_a_region_stands_behind_it() {
  // ```text
  // challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // token68   = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  // ```
  //
  // `token68` is the WHOLE body, and a run that ends its own list ELEMENT has
  // ended one element rather than the body. `Basic dGVzdA==` and `x=1` are two
  // field lines RFC 9110 §5.2 makes one value, `Basic dGVzdA==,x=1`, whose body
  // is `dGVzdA==,x=1` — and no `token68` holds a comma.
  //
  // `Credential::read` is where a body already cut is derived, so this is asked
  // of it directly: the `#challenge` walk never hands it one of these, because
  // it ends the challenge at the run's own comma before a second region can be
  // taken. That is what makes the region count a rule of `BodyCheck::finish`
  // rather than a fact about one caller.
  let mut body = BodyLines::new();
  body.push(b"dGVzdA==", 8).expect("the first region");
  body.push(b"x=1", 3).expect("the second");
  assert_eq!(body.len, 2, "two regions, which is a body §5.2 joined");
  assert_eq!(
    Credential::read(b"Basic", body).unwrap_err(),
    AuthError::MalformedParameter,
    "a run that ends its element is not a body two regions long"
  );

  // The control that says the rule is the SECOND region and not the run: the
  // same first region alone is the body, and the `token68` is taken.
  let mut body = BodyLines::new();
  body.push(b"dGVzdA==", 8).expect("the one region");
  assert_eq!(
    Credential::read(b"Basic", body).unwrap().token68(),
    Some(&b"dGVzdA=="[..])
  );
}

#[test]
fn an_empty_element_in_front_of_a_run_is_a_body_no_token68_derives() {
  // `token68` is not a list, so it has no empty elements and nothing may stand
  // in front of it inside the body:
  //
  // ```text
  // challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  // token68   = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  // ```
  //
  // RFC 9110 §5.6.1.2 admits those empty elements in the OTHER alternative —
  // "A recipient MUST parse and ignore a reasonable number of empty list
  // elements" — so a body that opens with one took `#auth-param`, whatever the
  // bytes behind it look like.
  //
  // It has to be answered at the ELEMENT rather than read off the body, because
  // `BodyLines` spends no region on one that is all `OWS` and commas: the same
  // sentence is why, and the cost is that a body whose empty elements stand on
  // the line §5.2's join left behind arrives here as the bytes behind them.
  let [fault, digest, past] = walk::<3>([&b"Basic ,"[..], b"a=, Digest realm=z"]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The one-line spelling of the same value, which is what it has to agree
  // with: RFC 9110 §5.2 makes those two lines one value,
  // `Basic ,,a=, Digest realm=z`.
  let [fault, digest, past] = walk::<3>([&b"Basic ,,a=, Digest realm=z"[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // And the control that says the rule is about the empty element and not about
  // the run: the same run with nothing in front of it IS the body.
  let credential = one([&b"Basic a="[..]]);
  assert_eq!(credential.token68(), Some(&b"a="[..]));
}

#[test]
fn a_scheme_fault_is_recovered_from_the_element_s_own_first_byte() {
  // RFC 9110 §11.6.1 gives the element two readings and they open a §5.6.4
  // quoted-string in different places. A scheme refusal is the challenge
  // reading failing; the OTHER reading is one `auth-param` whose value position
  // is `param_value_at` answered at the element's FIRST byte, and a recovery
  // that begins behind the scheme token has already walked past it.
  //
  // `Basic a=1, Broken;junk, Bearer, x="open, Digest realm=z` is the value: a
  // list `Basic` opened and the fault left open, a `Bearer` that cannot close
  // it, and then `x="open` refused at its own scheme with `x=`'s DQUOTE
  // standing at a value position of that list. Read from behind the `x`, the
  // opener is invisible and the comma inside the string is crossed.
  let value = &b"Basic a=1, Broken;junk, Bearer, x=\"open, Digest realm=z"[..];
  let [basic, broken, bearer, malformed, unknown, past] = walk::<6>([value]);
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());
  yields_no_invented_scheme(&[value], value);

  // And the control that says the origin is admitted by `Challenges::list_open`
  // rather than taken unconditionally: with no list open anywhere, the same
  // element's DQUOTE stands at no value position of any reading and the comma
  // in front of `Digest` is a boundary. `Basic="q` is that element read at its
  // own first byte, and §11.6.1 has no challenge open at the head of a
  // `#challenge` value for a parameter to belong to.
  let [malformed, digest, past] = walk::<3>([&b"Basic=\"q, Digest realm=z"[..]]);
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());
}

#[test]
fn a_forbidden_byte_is_the_one_thing_a_high_byte_is_not() {
  // The pair that says the recovery above is about the bytes RFC 9110 §5.6.4
  // forbids and not about DQUOTEs. `obs-text` IS `qdtext` — the production is
  // `qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text` — so a high byte
  // inside a value leaves that value deriving, the comma inside it data, and
  // the whole thing ONE challenge with ONE parameter. Nothing is yielded behind
  // it, because there is nothing behind it: it is all the realm.
  for high in [0x80_u8, 0xFF] {
    let mut line = b"Basic realm=\"a".to_vec();
    line.push(high);
    line.extend_from_slice(b"b, Digest realm=z\"");
    let [only, past] = walk::<2>([line.as_slice()]);
    let only = only.unwrap().unwrap();
    assert_eq!(only.scheme(), b"Basic", "{high:#04x}");
    assert_eq!(
      names::<2>(&only),
      [Some(&b"realm"[..]), None],
      "{high:#04x}"
    );
    assert!(
      past.is_none(),
      "{high:#04x} must not yield a second challenge"
    );

    // And escaped, which `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )`
    // admits for the same reason.
    let mut escaped = b"Basic realm=\"a\\".to_vec();
    escaped.push(high);
    escaped.extend_from_slice(b"b, Digest realm=z\"");
    let [only, past] = walk::<2>([escaped.as_slice()]);
    assert_eq!(
      only.unwrap().unwrap().scheme(),
      b"Basic",
      "{high:#04x} escaped"
    );
    assert!(past.is_none(), "{high:#04x} escaped");
  }

  // The control, one byte apart: a CTL is neither `qdtext` nor an octet a
  // `quoted-pair` may escape, so no `quoted-string` derives here and the
  // challenge is refused. What the sender wrote is unchanged by that — every
  // byte behind the DQUOTE is still what they typed between it and a close that
  // never comes — so the comma inside the realm is that run's data under the
  // reading that opened it, and the walk declines it rather than cross. The
  // `obs-text` rows above are never recovered from at all.
  //
  // This asserted `MalformedParameter`, which is what the walk said after
  // crossing that comma and reading `Digest realm=z"` as an element of its
  // own. One byte to the left it would have said `Digest`.
  let [refused, unknown, past] = walk::<3>([&b"Basic realm=\"a\x00b, Digest realm=z\""[..]]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());
}

#[test]
fn a_string_a_forbidden_byte_sealed_holds_every_comma_behind_its_dquote() {
  // `Basic x="%x01, Digest realm=evil` handed a caller a `Digest` with a
  // `realm` of `evil` that no origin server sent. RFC 9110 §11.2 admits a value
  // at `x`'s position, the sender opened a §5.6.4 quoted-string there, and the
  // %x01 means it reaches no close — so every comma behind that DQUOTE is among
  // the bytes the sender wrote as `x`'s data, the `Digest` included.
  //
  // Four spellings of the one shape, because the DQUOTE and the byte can stand
  // in four places relative to the walk, and the boundary is uncertifiable in
  // all four.
  for lines in [
    // The original shape, on one field line.
    &[&b"Basic x=\"\x01, Digest realm=z"[..]][..],
    // With bytes of the realm on either side of the byte, which is the shape
    // `auth-corpus`'s corpus F writes.
    &[b"Basic realm=\"a\x01b, Digest realm=z"],
    // Behind a tail whose OWN boundary every reading agrees on: it cannot put
    // right an uncertain boundary in front of it.
    &[b"Basic a=\"x\x00y\", safe=\"shut\", Digest realm=z"],
    // And with RFC 9110 §5.2's join between the DQUOTE and the byte, where the
    // opener is on a line this walk no longer holds. `Challenges::skip_element`
    // answers that one, and `Refusal::Unbounded` is how.
    &[b"Basic a=\"x", b"y\x01, Digest realm=z"],
  ] {
    let [refused, unknown, past] = walk::<3>(lines.iter().copied());
    assert_eq!(
      refused.unwrap().unwrap_err(),
      AuthError::InvalidQuotedString,
      "{lines:?}"
    );
    assert_eq!(
      unknown.unwrap().unwrap_err(),
      AuthError::ChallengeBoundaryUnknown,
      "{lines:?}"
    );
    assert!(past.is_none(), "{lines:?}");
  }

  // And the answer `crate::grammar` had already given the same question, which
  // is where this one now comes from. RFC 9110 §10.1.4's `transfer-parameter`
  // is a different production with the same DQUOTE in it: `Readings::absorb`
  // calls a string a forbidden byte sealed one that covers every comma left, so
  // that walk answers `MemberBoundaryUnknown` and hands back no `chunked` cut
  // out of `x`'s value. This module answered otherwise.
  let mut read = crate::grammar::parameterised_list(
    [&b"gzip;;x=\"a\x01, chunked, b\", br"[..]],
    crate::grammar::ParamSyntax::TransferParameter,
  );
  assert!(
    read.next().is_some_and(|read| read.is_ok()),
    "§10.1.4's walk yields the member in front of the fault"
  );
  assert!(
    matches!(
      read.next(),
      Some(Err(crate::grammar::ListError::MemberBoundaryUnknown))
    ),
    "and declines the boundary a sealed string holds"
  );
  assert!(read.next().is_none(), "and yields nothing behind it");

  // The control, one byte apart, in both walks: `obs-text` IS `qdtext`, so the
  // string closes, the commas inside it are data, and each walk hands back one
  // member whose value holds the lot. Without this the pair above would pass
  // over a rule that simply refused every DQUOTE.
  let credential = one([&b"Basic realm=\"a\xffb, Digest realm=z\""[..]]);
  assert_eq!(credential.scheme(), b"Basic");
  assert_eq!(names::<2>(&credential), [Some(&b"realm"[..]), None]);
  let mut read = crate::grammar::parameterised_list(
    [&b"gzip;;x=\"a\xff, chunked, b\", br"[..]],
    crate::grammar::ParamSyntax::TransferParameter,
  );
  assert!(read.next().is_some_and(|read| read.is_ok()));
  assert!(
    matches!(
      read.next(),
      Some(Err(crate::grammar::ListError::MemberBoundaryUnknown))
    ),
    "and the high byte leaves the empty slot's own fault, not a `chunked`"
  );
}

#[test]
fn an_element_a_join_carried_here_is_put_to_the_grammar_whole() {
  // A second, hiding-direction form of the same class. RFC 9110 §5.2 joins
  // these two field lines into
  // `Basic a=1, a="x,y", Bearer, x="open, Digest realm=z`: `a`'s value is the
  // one string `x,y`, §11.2 derives that element whole, and what refuses the
  // challenge is the repeated NAME — a bound of this reader's, which moves no
  // comma and leaves every boundary where §5.6.1.2 put it.
  //
  // So the span stays derivable, `Bearer` derives as an element of the outer
  // list and closes the epoch, the DQUOTE behind `x=` then stands at no value
  // position, and the comma in front of `Digest` is the separator it looks
  // like.
  //
  // What stood in the way was where the recovery cursor lands: at the head of
  // the continuation line, where the run is `y"` — the SUFFIX of `a`'s element
  // and no `auth-param` of its own. Slicing there and reading that suffix as a
  // whole element refuted a claim the grammar never refuted, and the genuine
  // `Digest` went behind `ChallengeBoundaryUnknown`.
  let [refused, bearer, malformed, digest, past] = walk::<5>([
    &b"Basic a=1, a=\"x"[..],
    b"y\", Bearer, x=\"open, Digest realm=z",
  ]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The pair that says the answer is about the ELEMENT and not about the join:
  // the same refusal on ONE field line, where the cursor lands on the element's
  // own first byte and the suffix never existed. `Digest` is shown there too.
  let [refused, bearer, malformed, digest, past] =
    walk::<5>([&b"Basic a=1, a=\"xy\", Bearer, x=\"open, Digest realm=z"[..]]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // And what the pair does NOT say, kept here rather than left to be found:
  // §5.2 joins the two lines above into `Basic a=1, a="x,y", Bearer, ...`, and
  // that value written on one line answers differently. It is not this rule's
  // doing. `Recovery::floor` is: on one line the recovery begins in FRONT of
  // `a`'s DQUOTE, so the earliest comma from there is the one INSIDE `a`'s own
  // value and `some_reading_holds` reports it; across the join it begins behind
  // the close, where that comma is already spent. The asymmetry is the
  // recovery's origin and not the span's claim, and the value below is where it
  // shows.
  // On ONE line the recovery now crosses it: a duplicate name leaves the value
  // deriving, so `a="x,y"` is one `auth-param` in every reading, the comma
  // inside it is that value's data in all of them, and the element ends at the
  // comma behind its close. `Bearer` then closes the list in every derivation,
  // `x="open` stands in front of none, and the `Digest` behind it is a
  // challenge whose boundary nothing disputes.
  let [refused, bearer, scheme, digest] =
    walk::<4>([&b"Basic a=1, a=\"x,y\", Bearer, x=\"open, Digest realm=z"[..]]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(scheme.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");

  // And the control that says the epoch is doing the work rather than the
  // recovery simply crossing everything: the same two lines with an element the
  // GRAMMAR derives nothing at inside the span. `y=` is no `auth-param`, so the
  // claim is refuted for the reason it exists to be refuted for, `Bearer` may
  // not close the epoch, and the `Digest` behind `x="open` is that parameter's
  // own data.
  let [refused, bearer, malformed, unknown, past] = walk::<5>([
    &b"Basic a=1, a=\"x"[..],
    b"y\", y=, Bearer, x=\"open, Digest realm=z",
  ]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());
}

#[test]
fn where_every_refusal_leaves_the_cursor() {
  // `Origin`'s enumeration, driven one entrance at a time. It was prose across
  // four doc comments, and one of the rows was wrong: the entrance that
  // recovers from the far side of RFC 9110
  // §5.2's join said it left the cursor at an element's own start, and it
  // leaves it on that element's SUFFIX.
  //
  // Each row below reaches ONE entrance and asserts what the cursor there
  // decides — which is what the walk hands the caller, since where a recovery
  // starts is the only thing that moves these answers. The tail is the same
  // everywhere: a `Newauth` whose boundary every reading agrees on, so a cursor
  // in the wrong place shows up as a different item and not as a different
  // fault.
  //
  // `Origin::Unread`, five faults and `Origin::Body`'s one, each reaching the
  // tail. The fault may not be the walk's FIRST item — some of these values
  // carry a challenge that completes in front of the refusal, which is what
  // opens the `#auth-param` list the recovery then has to reckon with — so the
  // walk is read from its first `Err`.
  for (value, fault) in [
    // `Origin::Unread`: no `auth-scheme` token at all.
    (&b"Basic a=1, =x, Newauth b=1"[..], AuthError::MissingScheme),
    // A scheme with bytes behind it RFC 9110 §11.3 admits nothing at, refused
    // at the element's own first byte and not behind the token.
    (
      b"Basic\tNewauth b=1, Newauth c=1",
      AuthError::MalformedScheme,
    ),
    // `BodyCheck::settle`'s held verdict on the element behind the cursor.
    (
      b"Basic a=x y, b=2, Newauth c=1",
      AuthError::MalformedParameter,
    ),
    // `Challenges::skip_element`'s fault with no join crossed, where the scan
    // never advanced past the element's first byte. The DQUOTE stands where
    // §11.2 admits NO value — `a`'s value took the `token` alternative — so it
    // opens nothing in any reading and the comma behind it is a separator.
    (
      b"Basic a=x\"\x00y, Newauth b=1",
      AuthError::MalformedParameter,
    ),
    // `Origin::Body`: the cursor is ON the whitespace §11.3's `1*SP` did not
    // take, which is the body position — the one row where §5.6.1.2 hangs no
    // `OWS` in front of the element, because there is no comma there to hang
    // it on.
    (b"Basic \ta, Newauth b=1", AuthError::MalformedScheme),
  ] {
    let mut read = challenges([value]).skip_while(|read| read.is_ok());
    assert_eq!(
      read
        .next()
        .unwrap_or_else(|| panic!("{value:?}"))
        .unwrap_err(),
      fault,
      "{value:?}"
    );
    let last = read
      .next()
      .unwrap_or_else(|| panic!("{value:?}: the walk stopped"));
    assert_eq!(
      last.unwrap().scheme(),
      b"Newauth",
      "the cursor behind {value:?}"
    );
    assert!(read.next().is_none(), "{value:?}");
  }

  // `Origin::Unread` with a receiver bound, which is the one row
  // `Challenges::sustain_the_epoch` ever slices a line at:
  // `Section::outgrown`'s line bound, met BETWEEN two elements with the cursor
  // on the first byte of one no scan has read. Seventeen field lines is one
  // more than `MAX_CHALLENGE_LINES` holds.
  let mut lines = [&b""[..]; 18];
  lines[..SEVENTEEN_LINES.len()].copy_from_slice(&SEVENTEEN_LINES);
  lines[17] = b"Newauth b=1";
  let [refused, newauth, past] = walk::<3>(lines);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());

  // `Origin::Scanned`, the element's own first byte, no join crossed: the run
  // at the cursor IS the element, and reading it from the line or from the
  // `Element` the walk cut gives the same bytes.
  let [refused, bearer, newauth, past] =
    walk::<4>([&b"Basic a=1, a=\"x\", Bearer, Newauth b=1"[..]]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());

  // `Origin::Scanned`, the head of the line §5.2's join left: the run at the
  // cursor is `y"`, the element is `a="x` + the join + `y"`, and only the
  // second derives. The epoch stays derivable, `Bearer` closes it, and
  // `Newauth` is a challenge rather than a parameter of a list nothing closed.
  let [refused, bearer, newauth, past] =
    walk::<4>([&b"Basic a=1, a=\"x"[..], b"y\", Bearer, Newauth b=1"]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert_eq!(bearer.unwrap().unwrap().scheme(), b"Bearer");
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());

  // `Origin::Crossed`, the head of the line §5.2's join left with a string
  // still open around the cursor. Nothing seeks from there and nothing behind
  // it is read, which is the one row whose answer is the absence of the tail.
  let [refused, unknown, past] = walk::<3>([&b"Basic a=\"x"[..], b"\x00, Newauth b=1"]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());
}

#[test]
fn where_a_forbidden_byte_is_recovered_from_is_where_the_scan_stood() {
  // What used to be a KNOWN cost here, and is not one any more: RFC 9110 §5.2
  // makes these two field line lists ONE value, and they now answer the same.
  //
  // On one line the scan never advanced past the element, so the cursor is on
  // the element's first byte, the earliest comma from there is the one inside
  // the realm, and the string RFC 9110 §11.2 admits at `realm`'s value position
  // is still OPEN at it: the bytes between the DQUOTE and that comma are
  // `qdtext`, whatever the %x00 later in the value does to the field as a
  // whole. Some reading holds that comma, so there is no boundary to cross.
  let one_line = &b"Basic realm=\"ab, Digest realm=z, \x00c\""[..];
  let [refused, unknown, past] = walk::<3>([one_line]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // Split at that same comma, the element's earlier bytes are on a field line
  // this walk no longer holds, so the cursor is on the first byte of the line
  // the scan choked on — and the DQUOTE that opened `realm`'s value is behind
  // it, on a line this walk may not read again. A walk that cannot see the
  // opener may not certify a comma behind it, whatever the bytes at the cursor
  // look like, so the refusal is `Refusal::Unbounded` and the answer is the
  // one-line spelling's.
  //
  // The note left here said making the two agree needed the OFFSET the scan
  // choked at, which `QuotedScan::Invalid` does not carry. It does not — and it
  // was never the missing thing. What the split spelling lost is the OPENER,
  // and the answer to a lost opener is to decline rather than to reconstruct
  // it. Until then this asserted `MissingScheme`, the walk having crossed to a
  // `%x00c"` the sender wrote inside a realm.
  let split: [&[u8]; 2] = [b"Basic realm=\"ab", b" Digest realm=z, \x00c\""];
  let [refused, unknown, past] = walk::<3>(split);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // Neither spelling shows a challenge at the probe's offset, and no derivation
  // of the value puts one there either — the value carries a byte RFC 9110 §5.5
  // admits nowhere in one, so `Digest realm=z` is no challenge, and the reading
  // that makes it a realm's data is the reading both spellings now stop on.
  //
  // The control that says the two spellings are otherwise one value: with the
  // forbidden byte gone, both are one challenge with one realm.
  let clean_one_line: [&[u8]; 1] = [b"Basic realm=\"ab, Digest realm=z, c\""];
  let clean_split: [&[u8]; 2] = [b"Basic realm=\"ab", b" Digest realm=z, c\""];

  // Both claims of one value, executed rather than asserted in prose. The pair
  // above says two spellings of ONE value answer differently, which says
  // nothing at all unless the two lists really do join to the same bytes.
  assert!(joined_value([one_line]).eq(joined_value(split)));
  assert!(joined_value(clean_one_line).eq(joined_value(clean_split)));

  for lines in [&clean_one_line[..], &clean_split[..]] {
    let [only, past] = walk::<2>(lines.iter().copied());
    let only = only.unwrap().unwrap();
    assert_eq!(only.scheme(), b"Basic", "{lines:?}");
    assert_eq!(names::<2>(&only), [Some(&b"realm"[..]), None], "{lines:?}");
    assert!(past.is_none(), "{lines:?}");
  }
}

#[test]
fn the_regions_a_challenge_holds_are_the_lines_it_read() {
  // The seam this closes, stated as the fact that closes it. Two walks produce
  // a credential's elements — `Challenges::skip_element` while it is still
  // deciding where the challenge ends, and `ParamWalk::element` when a caller
  // reads `params()` — and they are one function over one set of bytes rather
  // than two readings that happen to agree. That rests on `BodyLines` keeping
  // each region as the walk that took it saw it: the field line from the
  // credential's first byte on it to the LINE's end, never cut at the
  // credential's end, with `held` saying where the credential stops.
  //
  // An edit that cut the regions instead would leave `scan_element` reading
  // two different slices in the two walks, and the agreement would go back to
  // being an argument about what lies past an element's delimiter. These are
  // the assertions such an edit fails.
  let line = &b"Basic a=1, Digest realm=z"[..];
  let credential = walk::<3>([line])[0]
    .expect("a challenge")
    .expect("Basic reads");

  // The stored region is the line from the body's first byte, and it runs on
  // past this challenge into the next one.
  assert_eq!(credential.body.len, 1);
  assert_eq!(credential.body.line(0), &line[6..]);
  assert_eq!(credential.body.line(0), b"a=1, Digest realm=z");
  // What the credential HOLDS of it is where the collecting walk stopped, and
  // that is a recorded cursor rather than a second reading of the same bytes.
  assert_eq!(credential.body.held, 3);
  assert_eq!(credential.body.cut(0), b"a=1");
  assert!(credential.body.line(0).len() > credential.body.cut(0).len());
  // And the walk over the uncut region stops exactly there. Asked of the walk
  // itself as well as of `params()`, because `AuthParamIter` ends on a fault
  // without reporting one: a walk that ran past this credential would meet
  // `Digest realm=z`, refuse it as a parameter and stop anyway, so the names
  // alone cannot tell a walk that stopped from one that overran and was
  // swallowed.
  assert_eq!(names::<2>(&credential), [Some(&b"a"[..]), None]);
  let mut walk = ParamWalk::over(credential.body);
  assert!(walk.step().is_some(), "the one parameter");
  assert!(
    walk.step().is_none(),
    "the walk ends where the credential does, not at a fault behind it"
  );

  // A challenge that ends where its line does holds all of its region, so the
  // two are the same slice and `held` is the whole of it.
  let credential = one([&b"Basic a=1"[..]]);
  assert_eq!(credential.body.held, credential.body.line(0).len());
  assert_eq!(credential.body.cut(0), credential.body.line(0));
}

#[test]
fn a_walk_that_stops_on_a_fault_says_so() {
  // `Credential::params` is infallible because the list was derived once
  // already, so the ONE thing a fault can do to that walk is end it. What it
  // must not do is end it the way running out of credential does. A walk that
  // read one element too many meets the NEXT challenge's first element,
  // `auth_param` refuses it, the walk stops — and the caller is handed a
  // parameter list that looks complete with no fault reported anywhere. That is
  // the one place in this module where being wrong is silent, and `Stop` is
  // what makes the two endings two states rather than one `bool`.
  //
  // `BodyLines`'s `held` is what keeps the overrun from happening, and
  // `walks_to_its_end` asserts the ending of every credential this crate
  // builds. This is what fails if the two endings become one again.

  // The ordinary ending: the cursor reached the credential's own last byte.
  let credential = one([&b"Basic a=1, b=2"[..]]);
  let mut params = credential.params();
  assert_eq!(params.next().map(|p| p.name()), Some(&b"a"[..]));
  assert_eq!(params.next().map(|p| p.name()), Some(&b"b"[..]));
  assert!(params.next().is_none());
  assert_eq!(params.walk.stop, Some(Stop::Spent));
  assert!(params.next().is_none(), "an ended walk stays ended");

  // The fault ending, which only a body built by hand can reach: a region whose
  // bytes run PAST the credential, so the walk meets `Digest realm=z` — the
  // next challenge's first element, which no `auth-param` derives — and a
  // parameter behind THAT which a walk not stopped by the fault would hand
  // over as if it belonged here.
  let line = &b"a=1, Digest realm=z, b=2"[..];
  let mut body = BodyLines::new();
  body.push(line, line.len()).expect("one region");
  let overrun = Credential {
    scheme: b"Basic",
    body,
    token68: None,
  };
  let mut params = overrun.params();
  assert_eq!(params.next().map(|p| p.name()), Some(&b"a"[..]));
  assert!(params.next().is_none(), "`Digest realm=z` is no parameter");
  assert_eq!(
    params.walk.stop,
    Some(Stop::Fault(AuthError::MalformedParameter)),
    "the fault that ended the walk is recorded, not dropped"
  );
  assert!(
    params.next().is_none(),
    "and the walk stays ended, so `b=2` behind the fault is never handed over"
  );

  // The other fault this walk can meet, and the other place it was dropped: a
  // byte RFC 9110 §5.6.4 forbids INSIDE a quoted-string, which `scan_element`
  // reports and `ParamWalk::element` records. It reaches `AuthParamIter` as a
  // `Some(Err(_))` that yields nothing, so this is the ending the iterator
  // itself never sees — and the walk still says which one it was.
  let line = &b"a=\"\x00\""[..];
  let mut body = BodyLines::new();
  body.push(line, line.len()).expect("one region");
  let forbidden = Credential {
    scheme: b"Basic",
    body,
    token68: None,
  };
  let mut params = forbidden.params();
  assert!(params.next().is_none());
  assert_eq!(
    params.walk.stop,
    Some(Stop::Fault(AuthError::InvalidQuotedString)),
    "the scan's own fault is recorded too"
  );

  // A `token68` body is spent before its walk begins, and that is the ordinary
  // ending rather than a refusal — `Credential::params` initialises it so. Both
  // spellings yield no parameters, and the ENDING is the whole of what tells
  // them apart.
  let token = one([&b"Basic dGVzdA=="[..]]);
  assert!(token.token68().is_some());
  let mut params = token.params();
  assert!(params.next().is_none());
  assert_eq!(params.walk.stop, Some(Stop::Spent));
}

/// Tests that read a formatted value: gated to the tiers with a heap, since the
/// bare `no_std` tier has neither an allocator nor the `alloc as std` alias.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
#[test]
fn the_debug_of_a_body_prints_what_the_credential_holds() {
  // `BodyLines`'s `Debug` is hand-written, and what it is written to do is
  // print the CUT regions rather than the uncut lines they are stored as — so a
  // `Credential` in a log or a failing assertion shows the bytes that
  // credential holds and not the next challenge's behind them. A hand-written
  // formatter is a second reader of `held`, and this is what says which of the
  // two slices it reads.
  let line = &b"Basic a=1, Digest realm=z"[..];
  let credential = walk::<3>([line])[0]
    .expect("a challenge")
    .expect("Basic reads");
  assert_eq!(
    std::format!("{:?}", credential.body),
    std::format!("{:?}", [&b"a=1"[..]]),
    "the cut region, which is what this credential holds"
  );
  assert_ne!(
    std::format!("{:?}", credential.body),
    std::format!("{:?}", [credential.body.line(0)]),
    "and not the stored line, which runs on into the next challenge"
  );

  // Every region but the last is the credential's as far as its line runs, so a
  // body that crossed a join prints one whole region and one cut one.
  let spanning = walk::<3>([&b"Basic a=\"x"[..], b"y\", Digest realm=z"])[0]
    .expect("a challenge")
    .expect("Basic reads");
  assert_eq!(
    std::format!("{:?}", spanning.body),
    std::format!("{:?}", [&b"a=\"x"[..], &b"y\""[..]]),
  );
}

// Not run under miri, for the reason the two `date` brute forces are not.
// The crate is `forbid(unsafe_code)`, so there is no undefined behaviour in
// what this drives for the interpreter to find, and what it does drive is the
// most expensive thing in the crate: 181_896 field values, each derived once by
// the collecting walk and once again by `Credential::read`. Interpreted, that
// is hours — enough on its own to spend the whole `miri` job's budget and leave
// the crates behind this one unrun. Every other tier runs it in full, and a
// disagreement between the two producers is a logic error, which is what those
// tiers are the check for.
#[test]
#[cfg_attr(
  miri,
  ignore = "181_896 field values, each derived twice; no unsafe to interpret"
)]
fn the_body_a_challenge_collected_reads_the_same_alone() {
  // The two producers, compared directly. `Credential::params` hands a caller
  // the answer of the walk over the collected body for a challenge the
  // COLLECTING walk accepted, so a disagreement between them would drop a
  // parameter from a challenge that parsed and report nothing at all.
  //
  // They agree by construction — `scan_element` is the one derivation of an
  // element's boundary and `the_regions_a_challenge_holds_are_the_lines_it_read`
  // pins the bytes it is handed — and this is the check that the construction
  // still holds. It compares one producer against the other rather than either
  // against a reading of this test's own, so there is no oracle here to be
  // written in the implementation's favour: what it reports is a disagreement,
  // which is directly observable.
  //
  // Both shapes of arrival are driven, because they differ in what the two
  // walks are handed: one field line, where a region is a suffix of the line
  // the collecting walk scanned, and a value split at every interior position
  // of the payload, where every region but the first IS that line.
  const ALPHABET: [u8; 8] = *b"a=\"x, \\\t";
  let mut checked = 0usize;
  let mut accepted = 0usize;
  let mut buf = [0u8; 5];

  /// A parameter's value, in a shape two of them can be compared in:
  /// `ParamValue` carries no `PartialEq` and is `#[non_exhaustive]`.
  fn shape<'a>(param: &AuthParam<'a>) -> (u8, &'a [u8]) {
    match param.value() {
      Ok(ParamValue::Token(value)) => (0, value),
      Ok(ParamValue::Quoted(value)) => (1, value),
      Ok(_) => (2, b""),
      Err(ValueSpansFieldLines) => (3, b""),
    }
  }

  let compare = |lines: &[&[u8]], accepted: &mut usize| {
    for outcome in challenges(lines.iter().copied()) {
      let Ok(collected) = outcome else { continue };
      *accepted += 1;
      let alone = Credential::read(collected.scheme, collected.body)
        .expect("a body the walk accepted is a body that reads");
      assert_eq!(alone.token68(), collected.token68(), "{lines:?}");
      assert_eq!(names::<20>(&alone), names::<20>(&collected), "{lines:?}");
      let mine = collected.params().map(|param| shape(&param));
      let theirs = alone.params().map(|param| shape(&param));
      assert!(mine.eq(theirs), "{lines:?}");
    }
  };

  for len in 1..=5 {
    let mut idx = [0usize; 5];
    loop {
      for at in 0..len {
        buf[at] = ALPHABET[idx[at]];
      }
      let payload = &buf[..len];
      let mut value = b"Basic ".to_vec();
      value.extend_from_slice(payload);
      value.extend_from_slice(b", Digest realm=z");
      checked += 1;
      compare(&[value.as_slice()], &mut accepted);

      // The same payload split across RFC 9110 §5.2's join, at every position
      // inside it — the shape in which a credential spans more than one region.
      for at in 1..len {
        let (head, tail) = payload.split_at(at);
        let mut first = b"Basic ".to_vec();
        first.extend_from_slice(head);
        let mut second = tail.to_vec();
        second.extend_from_slice(b", Digest realm=z");
        checked += 1;
        compare(&[first.as_slice(), second.as_slice()], &mut accepted);
      }

      let mut at = len;
      let carried = loop {
        if at == 0 {
          break false;
        }
        at -= 1;
        idx[at] += 1;
        if idx[at] < ALPHABET.len() {
          break true;
        }
        idx[at] = 0;
      };
      if !carried {
        break;
      }
    }
  }
  // 37448 one-line values (8 + 64 + 512 + 4096 + 32768) and 144448 split ones
  // (1×64 + 2×512 + 3×4096 + 4×32768).
  assert_eq!(checked, 181_896);
  assert!(accepted > 150_000, "{accepted} challenges re-derived");
}

#[cfg(feature = "test-no-panic")]
#[test]
fn every_value_tail_crosses_the_forwarder_as_itself() {
  // The link proof drives `auth_param` through the `__no_panic_internals`
  // forwarder, which mirrors this crate-private enum as one a test crate can
  // name. The `match` below is exhaustive over the private enum, so a fourth
  // state added to it stops this build rather than reaching the shim as one of
  // the three already there — which is what a `u8` boundary with a fallback arm
  // could not say.
  for tail in [ValueTail::Ends, ValueTail::Continues, ValueTail::Trails] {
    let mirrored = match tail {
      ValueTail::Ends => crate::__no_panic_internals::ValueTail::Ends,
      ValueTail::Continues => crate::__no_panic_internals::ValueTail::Continues,
      ValueTail::Trails => crate::__no_panic_internals::ValueTail::Trails,
    };
    assert_eq!(
      crate::__no_panic_internals::ValueTail::from(tail),
      mirrored,
      "{tail:?}"
    );
    assert_eq!(
      crate::__no_panic_internals::auth_param(b"a=\"x", mirrored).map(|p| p.name()),
      auth_param(b"a=\"x", tail).map(|p| p.name()),
      "{tail:?}"
    );
  }
}

#[test]
fn a_field_line_carrying_no_element_bytes_spends_no_entry() {
  // RFC 9110 §5.6.1.2 opens "Empty elements do not contribute to the count of
  // elements present.", so a line that carries only OWS and commas is a run of
  // empty elements and spends nothing — and a challenge whose two parameters
  // sit either side of them is one challenge with two parameters.
  let credential = read_credential([
    &b"Basic a=1"[..],
    b"",
    b"",
    b"",
    b"",
    b" , , ",
    b"\t",
    b"b=2",
  ])
  .unwrap();

  let mut params = credential.params();
  assert_eq!(params.next().unwrap().name(), b"a");
  assert_eq!(params.next().unwrap().name(), b"b");
  assert!(params.next().is_none());
}

#[test]
fn a_flood_of_empty_field_lines_is_not_too_many_lines() {
  // The same rule where it costs something to hold: more empty lines than
  // MAX_CHALLENGE_LINES, still accepted. A slot-per-spanned-line bound would
  // refuse this, and refusing it would put a count on the empty elements
  // RFC 9110 §5.6.1.2 asks a recipient to "parse and ignore" — the position
  // `a_comma_flood_is_not_too_many_tags` already pins for this crate.
  // Every spelling of a line with no element bytes in it: nothing at all, OWS,
  // a comma, and a comma-whitespace-comma run.
  let empty: [&[u8]; 4] = [b"", b" ", b",", b" , ,\t"];
  let mut lines = [&b""[..]; MAX_CHALLENGE_LINES * 2];
  for (at, line) in lines.iter_mut().enumerate() {
    *line = empty[at % empty.len()];
  }
  lines[0] = b"Basic a=1";
  lines[MAX_CHALLENGE_LINES * 2 - 1] = b"b=2";

  let credential = read_credential(lines).unwrap();
  let mut params = credential.params();
  assert_eq!(params.next().unwrap().name(), b"a");
  assert_eq!(params.next().unwrap().name(), b"b");
  assert!(params.next().is_none());
}

#[test]
fn a_challenge_past_the_line_bound_is_refused() {
  // Sixteen lines of one challenge is the last shape a borrowing reader can
  // name at once; the seventeenth is refused rather than read in part.
  let sixteen = read_credential(SEVENTEEN_LINES.iter().take(MAX_CHALLENGE_LINES).copied()).unwrap();
  assert_eq!(sixteen.params().count(), MAX_CHALLENGE_LINES);

  assert_eq!(
    read_credential(SEVENTEEN_LINES).unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
}

#[test]
fn a_name_split_by_a_join_is_not_a_name() {
  // §5.2 joins these to `Basic real,m=x`, in which `real` is a parameter name
  // with no `=` behind it. A `token` carries no comma, so nothing a sender can
  // write makes one name out of two lines.
  assert_eq!(
    read_credential([&b"Basic real"[..], b"m=x"]).unwrap_err(),
    AuthError::MalformedParameter
  );
}

// ── RFC 9110 §11.3's production, over whatever lines it arrived on ───────────

#[test]
fn a_scheme_is_matched_case_insensitively() {
  // RFC 9110 §11.1: "It uses a case-insensitive token to identify the
  // authentication scheme". The raw bytes stay as the sender wrote them and
  // the fold is what `scheme_is` offers.
  let credential = read_credential([&b"bAsIc realm=\"x\""[..]]).unwrap();
  assert_eq!(credential.scheme(), b"bAsIc");
  assert!(credential.scheme_is("Basic"));
  assert!(credential.scheme_is("basic"));
  assert!(!credential.scheme_is("Bearer"));
  assert!(!credential.scheme_is("Basi"));
}

#[test]
fn a_token68_credential_carries_no_parameters() {
  let credential = read_credential([&b"Basic dGVzdA=="[..]]).unwrap();
  assert_eq!(credential.token68(), Some(&b"dGVzdA=="[..]));
  assert_eq!(credential.params().count(), 0);

  let bearer = read_credential([&b"Bearer mF_9.B5f-4.1JqM"[..]]).unwrap();
  assert_eq!(bearer.token68(), Some(&b"mF_9.B5f-4.1JqM"[..]));
  assert_eq!(bearer.params().count(), 0);

  // A run that ends its own element but leaves more of the CREDENTIAL behind
  // it is not the whole of `[ 1*SP ( token68 / #auth-param ) ]`, so the other
  // branch is the one read — and it fails there, which is why no
  // `MalformedToken68` exists.
  assert_eq!(
    read_credential([&b"Basic dGVzdA==,"[..]]).unwrap_err(),
    AuthError::MalformedParameter
  );
  assert_eq!(
    read_credential([&b"Basic dGVzdA=="[..], b"x"]).unwrap_err(),
    AuthError::MalformedParameter
  );
}

#[test]
fn a_scheme_reaches_its_body_only_through_1_sp() {
  // A scheme with nothing behind it is a whole challenge.
  let bare = read_credential([&b"Basic"[..]]).unwrap();
  assert_eq!(bare.scheme(), b"Basic");
  assert!(bare.token68().is_none());
  assert_eq!(bare.params().count(), 0);

  // RFC 9110 §11.3's
  // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` admits nothing
  // after the scheme without that `1*SP`, so `=1` glued to a token is a scheme
  // the grammar cannot continue from.
  assert_eq!(
    read_credential([&b"type=1"[..]]).unwrap_err(),
    AuthError::MalformedScheme
  );
  // `1*SP` is SP alone. RFC 9110 §5.6.1.2 expands a list as
  // `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs every
  // OWS it has on a comma, so a HTAB standing where the first element should
  // be is derived by nothing.
  assert_eq!(
    read_credential([&b"Basic \ta=1"[..]]).unwrap_err(),
    AuthError::MalformedScheme
  );
  assert_eq!(
    read_credential([&b"Basic\ta=1"[..]]).unwrap_err(),
    AuthError::MalformedScheme
  );
  // Two SPs are still `1*SP`, and the empty first element §5.6.1.2 admits
  // needs the comma it hangs on — which this has.
  assert_eq!(
    read_credential([&b"Basic  a=1"[..]])
      .unwrap()
      .params()
      .count(),
    1
  );
  assert_eq!(
    read_credential([&b"Basic , a=1"[..]])
      .unwrap()
      .params()
      .count(),
    1
  );

  // The join's comma is not `1*SP` either, so a scheme alone on its line does
  // not reach a body on the next one.
  assert_eq!(
    read_credential([&b"Basic"[..], b"a=1"]).unwrap_err(),
    AuthError::MalformedScheme
  );

  // An element with bytes and no leading token has no scheme to report.
  assert_eq!(
    read_credential([&b"=x"[..]]).unwrap_err(),
    AuthError::MissingScheme
  );
}

#[test]
fn a_comma_inside_a_value_is_not_a_parameter_boundary() {
  // RFC 9110 §5.6.4's `quoted-string` makes a comma between the DQUOTEs data,
  // so this is two parameters and not three. It is the same rule the join
  // rests on, one line earlier: a walk that split on a raw comma would report
  // a parameter no sender wrote.
  let credential = read_credential([&br#"Basic realm="x,y", b=2"#[..]]).unwrap();

  let mut params = credential.params();
  let realm = params.next().unwrap();
  assert_eq!(realm.name(), b"realm");
  assert!(matches!(realm.value(), Ok(ParamValue::Quoted(v)) if v == b"x,y"));
  assert_eq!(params.next().unwrap().name(), b"b");
  assert!(params.next().is_none());
}

#[test]
fn a_forbidden_byte_is_reported_wherever_the_walk_meets_it() {
  // %x00 is neither `qdtext` nor an octet `quoted-pair` may escape, and the
  // walk can meet one at three points across a join. All three are the same
  // fault, and none of them is the open-string one: after a byte RFC 9110
  // §5.6.4 forbids, a walker can no longer tell a separating comma from data.
  //
  // Before any join, while the element's own end is being found.
  assert_eq!(
    read_credential([&b"Basic a=\"x\x00y\", b=2"[..]]).unwrap_err(),
    AuthError::InvalidQuotedString
  );
  // On the far side of the join, inside the string the join carried over.
  assert_eq!(
    read_credential([&b"Basic a=\"x"[..], b"y\x00z\""]).unwrap_err(),
    AuthError::InvalidQuotedString
  );
  // And in a LATER element, once the spanning one has been handed over: the
  // walk goes on from where that element ended, on the line it ended on.
  assert_eq!(
    read_credential([&b"Basic a=\"x"[..], b"y\", b=\"\x00\""]).unwrap_err(),
    AuthError::InvalidQuotedString
  );

  // And the point at which it does NOT meet one, because there is no string
  // there to meet it in: behind the DQUOTE that closed the value. Those bytes
  // derive nothing, so the DQUOTE in front of the %x00 opens no string and the
  // %x00 is not inside one — the element is refused for being underivable,
  // which is what the same bytes on ONE field line have always answered.
  assert_eq!(
    read_credential([&b"Basic a=\"x"[..], b"y\" \"\x00\""]).unwrap_err(),
    AuthError::MalformedParameter
  );
  assert_eq!(
    credentials(b"Basic a=\"x,y\" \"\x00\"").unwrap_err(),
    AuthError::MalformedParameter
  );
}

// ── RFC 9110 §11.6.1's #challenge, and the comma that means two things ───────

/// One `#challenge` walk collected into a fixed array, `None` past its last
/// result.
///
/// `N` is written one larger than the answer a test expects, so the trailing
/// `None` is the assertion that the walk stopped where it was supposed to
/// rather than the test reading only a prefix of it.
fn walk<'a, const N: usize>(
  lines: impl IntoIterator<Item = &'a [u8]>,
) -> [Option<Result<Credential<'a>, AuthError>>; N] {
  let mut out = [None; N];
  for (slot, outcome) in out.iter_mut().zip(challenges(lines)) {
    *slot = Some(outcome);
  }
  out
}

/// One challenge's parameter names in wire order, `None` past its last.
fn names<'a, const N: usize>(credential: &Credential<'a>) -> [Option<&'a [u8]>; N] {
  let mut out = [None; N];
  for (slot, param) in out.iter_mut().zip(credential.params()) {
    *slot = Some(param.name());
  }
  out
}

/// The one value RFC 9110 §5.2 makes of a field line list, as bytes: the line
/// values "concatenated in order, with each field line value separated by a
/// comma".
///
/// Allocation-free, because this module compiles on the bare tier. Its callers
/// are the two tests that assert two spellings of ONE value answer differently
/// — a claim that is worthless if the two lists are not in fact one value, and
/// which was prose in both of them until it was this.
fn joined_value<'a>(
  lines: impl IntoIterator<Item = &'a [u8]> + 'a,
) -> impl Iterator<Item = u8> + 'a {
  lines.into_iter().enumerate().flat_map(|(index, line)| {
    (index > 0)
      .then_some(b',')
      .into_iter()
      .chain(line.iter().copied())
  })
}

/// The one challenge `lines` holds, with the walk asserted to hold nothing
/// else.
fn one<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> Credential<'a> {
  let [first, second] = walk::<2>(lines);
  assert!(
    second.is_none(),
    "a second challenge where one was expected"
  );
  first
    .expect("no challenge at all")
    .expect("challenge failed")
}

#[test]
fn the_worked_example_of_section_11_6_1() {
  // RFC 9110 §11.6.1 prints this field, wrapped across two of the document's
  // own lines and carrying a `quoted-pair` DQUOTE in its last value:
  //
  //    WWW-Authenticate: Basic realm="simple", Newauth realm="apps",
  //                     type=1, title="Login to \"apps\""
  //
  // and then says what it holds. "This header field contains two challenges",
  // one for Basic with a realm value of simple and one for Newauth with a
  // realm value of apps, and "It also contains two additional parameters".
  // Which challenge those last two belong to is the whole of §11.6.1's
  // ambiguity: the commas in front of them look exactly like the comma in
  // front of Newauth.
  let value = br#"Basic realm="simple", Newauth realm="apps", type=1, title="Login to \"apps\"""#;

  let [basic, newauth, past] = walk::<3>([&value[..]]);
  assert!(past.is_none(), "the field holds two challenges and no more");

  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert!(basic.token68().is_none());
  assert_eq!(names::<2>(&basic), [Some(&b"realm"[..]), None]);
  let realm = basic.params().next().unwrap();
  assert!(matches!(realm.value(), Ok(ParamValue::Quoted(v)) if v == b"simple"));

  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert!(newauth.token68().is_none());
  assert_eq!(
    names::<4>(&newauth),
    [Some(&b"realm"[..]), Some(b"type"), Some(b"title"), None]
  );
  let mut params = newauth.params();
  assert!(matches!(params.next().unwrap().value(), Ok(ParamValue::Quoted(v)) if v == b"apps"));
  assert!(matches!(params.next().unwrap().value(), Ok(ParamValue::Token(v)) if v == b"1"));
  // The escaped DQUOTEs are `quoted-pair`s, so the sender wrote one character
  // where the field carries two bytes.
  let title = params.next().unwrap().value().unwrap();
  assert!(matches!(title, ParamValue::Quoted(raw) if raw == br#"Login to \"apps\""#));
  assert!(title.unescaped().eq(br#"Login to "apps""#.iter().copied()));

  // The same field, split at an element boundary the way RFC 9110 §5.3 lets a
  // sender split any `#challenge` list. §5.2 joins the lines with a comma,
  // which lands beside the one already there — an empty element, and §11.6.1
  // says of exactly that shape that "In practice, this ambiguity does not
  // affect the semantics of the header field value and thus is harmless."
  let [basic, newauth, past] = walk::<3>([
    &br#"Basic realm="simple", Newauth realm="apps","#[..],
    br#"                 type=1, title="Login to \"apps\"""#,
  ]);
  assert!(past.is_none());
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(
    names::<4>(&newauth),
    [Some(&b"realm"[..]), Some(b"type"), Some(b"title"), None]
  );
}

#[test]
fn the_sentence_the_worked_example_prints() {
  // RFC 9110 §11.6.1's example is one field value, and what a walker has to
  // implement is the sentence above it: a value "might contain more than one
  // challenge, and each challenge can contain a comma-separated list of
  // authentication parameters". So the shapes below vary both counts, none of
  // them is the printed example, and every comma in them is decided by the
  // same rule.
  //
  // The generating grammar is RFC 9110 Appendix A's expansion, where both
  // levels are the same construct one inside the other:
  //
  // ```text
  // challenge = auth-scheme [ 1*SP ( token68 / [ auth-param *( OWS "," OWS auth-param ) ] ) ]
  // ```
  for (value, shape) in [
    (&b"A"[..], &[(&b"A"[..], 0usize)][..]),
    (b"A, B", &[(&b"A"[..], 0), (b"B", 0)]),
    (b"A, B, C", &[(&b"A"[..], 0), (b"B", 0), (b"C", 0)]),
    (b"A x=1", &[(&b"A"[..], 1)]),
    (b"A x=1, y=2", &[(&b"A"[..], 2)]),
    (b"A x=1, y=2, z=3", &[(&b"A"[..], 3)]),
    (b"A x=1, B", &[(&b"A"[..], 1), (b"B", 0)]),
    (b"A, B y=1", &[(&b"A"[..], 0), (b"B", 1)]),
    (b"A x=1, B y=2", &[(&b"A"[..], 1), (b"B", 1)]),
    (
      b"A x=1, y=2, B z=3, C",
      &[(&b"A"[..], 2), (b"B", 1), (b"C", 0)],
    ),
  ] {
    let [first, second, third, past] = walk::<4>([value]);
    assert!(past.is_none(), "{value:?}");
    for (read, &(scheme, count)) in [first, second, third].into_iter().zip(shape) {
      let credential = read
        .unwrap_or_else(|| panic!("{value:?}: too few challenges"))
        .unwrap_or_else(|fault| panic!("{value:?}: {fault}"));
      assert_eq!(credential.scheme(), scheme, "{value:?}");
      assert_eq!(credential.params().count(), count, "{value:?}");
    }
    assert!(
      walk::<4>([value])
        .get(shape.len())
        .is_some_and(|read| read.is_none()),
      "{value:?}: more challenges than the shape names"
    );
  }
}

#[test]
fn the_sp_after_the_scheme_is_what_admits_a_parameter_section() {
  // RFC 9110 §11.3 gives a challenge no other entrance to its parameters:
  // `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`. So the byte
  // after the scheme token decides the whole reading, and these two values
  // are one space apart.
  //
  // With the SP, the section opens on an empty first element §5.6.1.2 admits
  // and `type=1` is a parameter of `Basic`.
  let credential = one([&b"Basic , type=1"[..]]);
  assert_eq!(credential.scheme(), b"Basic");
  assert_eq!(names::<2>(&credential), [Some(&b"type"[..]), None]);

  // Without it the scheme takes no parameters at all, the comma is a
  // challenge boundary, and `type=1` has to be a challenge of its own — which
  // it is not, since the grammar admits nothing after a scheme without
  // `1*SP`.
  let [basic, malformed, past] = walk::<3>([&b"Basic, type=1"[..]]);
  assert!(past.is_none());
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(basic.params().count(), 0);
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);

  // A walker that trimmed the list's OWS before asking would have destroyed
  // the deciding byte, so the two answers are asserted to differ.
  assert_ne!(
    walk::<3>([&b"Basic , type=1"[..]]).map(|read| read.map(|r| r.is_ok())),
    walk::<3>([&b"Basic, type=1"[..]]).map(|read| read.map(|r| r.is_ok()))
  );
}

#[test]
fn an_empty_element_is_skipped_before_the_boundary_is_asked() {
  // RFC 9110 §5.6.1.2's rule comes first: "A recipient MUST parse and ignore a
  // reasonable number of empty list elements". A rule that read the empty
  // element between these two commas as an element with no leading token —
  // and therefore as a boundary — would split one challenge into two.
  let credential = one([&b"Basic a=1,,b=2"[..]]);
  assert_eq!(credential.scheme(), b"Basic");
  assert_eq!(names::<3>(&credential), [Some(&b"a"[..]), Some(b"b"), None]);

  // The same at the challenge level, and in quantity: §5.6.1.2's "Empty
  // elements do not contribute to the count of elements present.", which
  // `a_comma_flood_is_not_too_many_tags` already pins for this crate.
  let [basic, newauth, past] = walk::<3>([&b" , ,Basic a=1, ,, , Newauth b=2, ,"[..]]);
  assert!(past.is_none());
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");

  // A trailing comma is one of those empty elements, and `#challenge` has a
  // list for it to sit in.
  assert_eq!(
    one([&b"Basic dGVzdA==,"[..]]).token68(),
    Some(&b"dGVzdA=="[..])
  );
}

#[test]
fn a_challenge_reaches_its_parameters_only_through_1_sp() {
  // Spec §4.1's declined leniency, pinned so it is not quietly restored.
  // `1*SP` is SP alone, and RFC 9110 §5.6.1.2 expands a list as
  // `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs every
  // OWS it has on a comma — so a HTAB standing where the first element should
  // be is derived by nothing.
  let [fault, past] = walk::<2>([&b"Basic \ta=1"[..]]);
  assert!(past.is_none());
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedScheme);

  // The same byte glued straight to the scheme is the other shape of the same
  // error, and neither is subsumed by the other.
  let [fault, past] = walk::<2>([&b"Basic\ta=1"[..]]);
  assert!(past.is_none());
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedScheme);
}

#[test]
fn a_token68_with_no_pad_is_read_through_the_challenge_walk_too() {
  // RFC 9110 §11.2's
  // `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
  // needs no `=` at all, and the pins for that shape are otherwise reached
  // through `credentials`. The first element of a parameter section is
  // admitted by the `1*SP` in front of it, so §11.6.1's boundary question is
  // not asked of it — and a walk that asked anyway would answer "the next
  // challenge" here, since the run carries no `=` to say otherwise, and would
  // split one challenge into two.
  let credential = one([&b"Bearer mF_9.B5f-4.1JqM"[..]]);
  assert_eq!(credential.scheme(), b"Bearer");
  assert_eq!(credential.token68(), Some(&b"mF_9.B5f-4.1JqM"[..]));
  assert_eq!(credential.params().count(), 0);
}

#[test]
fn the_bws_in_front_of_an_equals_is_read_at_a_boundary_too() {
  // RFC 9110 §11.2's `auth-param = token BWS "=" BWS ( token / quoted-string )`
  // puts §5.6.3's BWS between the name and the `=`, so the byte that answers
  // §11.6.1's boundary question is the first non-BWS one behind the token
  // rather than the byte itself. A walk that read the raw byte would make the
  // second element of `Basic a=1, b = 2` the scheme of a second challenge, and
  // split a conforming value.
  let credential = one([&b"Basic a=1, b = 2"[..]]);
  assert_eq!(names::<3>(&credential), [Some(&b"a"[..]), Some(b"b"), None]);
  let mut params = credential.params();
  assert_eq!(params.next().unwrap().name(), b"a");
  assert!(matches!(params.next().unwrap().value(), Ok(ParamValue::Token(v)) if v == b"2"));
}

#[test]
fn a_line_source_that_answered_none_has_ended_the_value() {
  // RFC 9110 §5.2's value ends at the last field line, and `Iterator` does not
  // promise that a `None` is final. So the walk latches the exhaustion rather
  // than polling again: a source that yields after answering `None` cannot add
  // a line to a value that already ended, and without the latch the walk would
  // read the resurrected line as another challenge — the latch is polled a
  // second time here, because the first `None` arrives inside `Basic`'s own
  // element loop and the next `next()` asks again.
  struct Resurrects(usize);
  impl Iterator for Resurrects {
    type Item = &'static [u8];

    fn next(&mut self) -> Option<Self::Item> {
      self.0 += 1;
      match self.0 {
        1 => Some(b"Basic a=1"),
        2 => None,
        _ => Some(b"Newauth b=2"),
      }
    }
  }

  let [basic, past] = walk::<2>(Resurrects(0));
  assert!(past.is_none(), "a line arrived after the value ended");
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(names::<2>(&basic), [Some(&b"a"[..]), None]);
}

#[test]
fn a_challenge_closes_at_the_end_of_its_value() {
  // Spec §10's `["Basic realm=", "x"]` row, which only this walk can answer.
  // RFC 9110 §5.2 joins the lines to `Basic realm=,x`, and at that comma the
  // next element's leading token is `x` with no `=` behind it — a boundary.
  // So `realm=` ends the `Basic` challenge, where §11.2's
  // `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
  // is the branch that derives it, and `x` is a second challenge.
  let [basic, x, past] = walk::<3>([&b"Basic realm="[..], b"x"]);
  assert!(past.is_none());
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(basic.token68(), Some(&b"realm="[..]));
  let x = x.unwrap().unwrap();
  assert_eq!(x.scheme(), b"x");
  assert_eq!(x.params().count(), 0);

  // A challenge closes at the end of its VALUE and not at the end of the
  // element the boundary question was asked about, so the OWS §5.6.1.2 hangs
  // on the comma is no part of either challenge — and a `token68` whose run is
  // followed by that OWS still ends its credential.
  let [basic, newauth, past] = walk::<3>([&br#"Basic dGVzdA== , Newauth realm="x""#[..]]);
  assert!(past.is_none());
  assert_eq!(basic.unwrap().unwrap().token68(), Some(&b"dGVzdA=="[..]));
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
}

#[test]
fn the_ows_a_list_hangs_on_its_comma_is_no_part_of_a_parameter() {
  // RFC 9110 §5.6.1.2's `#element => [ element ] *( OWS "," OWS [ element ] )`
  // puts OWS on BOTH sides of every comma, so the space in front of one is the
  // list's and not the value's. A walker that handed it to the parameter would
  // refuse a conforming value, since `( token / quoted-string )` is one
  // alternative taken whole.
  let credential = one([&b"Basic a=1 , b=2"[..]]);
  assert_eq!(names::<3>(&credential), [Some(&b"a"[..]), Some(b"b"), None]);
  let mut params = credential.params();
  assert!(matches!(params.next().unwrap().value(), Ok(ParamValue::Token(v)) if v == b"1"));

  // The same OWS where a quoted value carries it.
  let credential = one([&br#"Basic a="1" , b=2"#[..]]);
  assert_eq!(names::<3>(&credential), [Some(&b"a"[..]), Some(b"b"), None]);

  // And the same walk reached through `credentials`, where every comma is a
  // parameter separator and no boundary question is asked at all.
  assert_eq!(
    read_credential([&b"Basic a=1 , b=2"[..]])
      .unwrap()
      .params()
      .count(),
    2
  );
}

#[test]
fn the_ows_a_list_hangs_on_a_comma_has_to_reach_it() {
  // The leading edge of the rule the test above pins at the trailing one. RFC
  // 9110 §5.6.1.2's `#element => [ element ] *( OWS "," OWS [ element ] )`
  // hangs every OWS it has ON a comma, so a HTAB is the list's whitespace when
  // the comma is really behind it and is derived by nothing when an element is
  // there instead. §5.6.3's OWS is SP or HTAB, so the run has to be walked to
  // what it reaches rather than judged one byte at a time.
  //
  // The `#challenge` list's own edge, one comma apart. `1*SP` is SP alone, so
  // neither value opens a parameter section; the first is a bare challenge
  // with the list's OWS behind it, and the second has a HTAB where the
  // production admits nothing.
  let [basic, newauth, past] = walk::<3>([&b"Basic\t, Newauth x=1"[..]]);
  assert!(past.is_none());
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(basic.params().count(), 0);
  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(names::<2>(&newauth), [Some(&b"x"[..]), None]);

  let [fault, past] = walk::<2>([&b"Basic\tNewauth x=1"[..]]);
  assert!(past.is_none());
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedScheme);

  // So the HTAB spelling reads as the comma-only spelling does and NOT as the
  // SP one, which is the pair §4.1 is written over: with the SP the section
  // opens and `type=1` is a parameter of `Basic`; with the HTAB, as with no
  // whitespace at all, `Basic` is whole and `type=1` has to be a challenge —
  // which the grammar does not derive.
  assert_eq!(
    walk::<3>([&b"Basic\t, type=1"[..]]).map(|read| read.map(|r| r.is_ok())),
    walk::<3>([&b"Basic, type=1"[..]]).map(|read| read.map(|r| r.is_ok()))
  );
  assert_ne!(
    walk::<3>([&b"Basic\t, type=1"[..]]).map(|read| read.map(|r| r.is_ok())),
    walk::<3>([&b"Basic , type=1"[..]]).map(|read| read.map(|r| r.is_ok()))
  );

  // The parameter section's opening edge, the same comma apart. Here `1*SP`
  // HAS taken its SP, so the HTAB is the OWS in front of the section's first
  // comma and the section opens on the empty first element §5.6.1.2 admits —
  // and where it reaches an element instead, that section cannot start. Spec
  // §4.1's declined leniency is the second of these and stays refused.
  assert_eq!(
    names::<2>(&one([&b"Basic \t,a=1"[..]])),
    [Some(&b"a"[..]), None]
  );
  let [fault, past] = walk::<2>([&b"Basic \ta=1"[..]]);
  assert!(past.is_none());
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_ne!(
    walk::<2>([&b"Basic \t,a=1"[..]]).map(|read| read.map(|r| r.is_ok())),
    walk::<2>([&b"Basic \ta=1"[..]]).map(|read| read.map(|r| r.is_ok()))
  );

  // A run of OWS is one run, and what ends it is what decides.
  assert_eq!(
    names::<2>(&one([&b"Basic \t \t, type=1"[..]])),
    [Some(&b"type"[..]), None]
  );
  let [fault, past] = walk::<2>([&b"Basic \t \ta=1"[..]]);
  assert!(past.is_none());
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedScheme);

  // Both edges across RFC 9110 §5.2's join, where the comma the OWS hangs on
  // is the one the join puts there rather than one the sender wrote.
  let [basic, newauth, past] = walk::<3>([&b"Basic\t"[..], b"Newauth x=1"]);
  assert!(past.is_none());
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert_eq!(
    names::<2>(&one([&b"Basic \t"[..], b"x=1"])),
    [Some(&b"x"[..]), None]
  );

  // The section's edge through the other two entry points, which reach it by
  // the same code. `credentials` is singular, so only the section's edge is
  // there to reach: the scheme's own HTAB has no list at the top of this
  // field's value to be the OWS of, and stays refused.
  assert_eq!(
    names::<2>(&credentials(b"Basic \t, type=1").unwrap()),
    [Some(&b"type"[..]), None]
  );
  assert_eq!(
    read_credential([&b"Basic \t, type=1"[..]])
      .unwrap()
      .params()
      .count(),
    1
  );
  assert_eq!(
    credentials(b"Basic \ta=1").unwrap_err(),
    AuthError::MalformedScheme
  );
  assert_eq!(
    credentials(b"Basic\t, type=1").unwrap_err(),
    AuthError::MalformedScheme
  );
}

#[test]
fn a_failed_challenge_is_reported_once() {
  // Spec §5.2's rule, and the value it is written over. The second element
  // has bytes and no leading token, so it opens a challenge that has no
  // scheme; the walk then seeks the next boundary rather than re-reading what
  // is left of that challenge as challenges of their own. `type=b` is
  // therefore part of the reported failure and not a second error.
  let [basic, missing, newauth, past] = walk::<4>([&b"Basic a=1, =x, type=b, Newauth c=1"[..]]);
  assert!(
    past.is_none(),
    "three results, and `type=b` is not a fourth"
  );

  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(names::<2>(&basic), [Some(&b"a"[..]), None]);

  assert_eq!(missing.unwrap().unwrap_err(), AuthError::MissingScheme);

  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(names::<2>(&newauth), [Some(&b"c"[..]), None]);
}

#[test]
fn the_walk_continues_while_the_commas_are_still_trustworthy() {
  // Spec §5.2's table, one row per continuable error: the boundary the walk
  // would resume at was known when the fault fired, so RFC 9110 §11.4's user
  // agent — "selecting the challenge with what it considers to be the most
  // secure auth-scheme that it understands" — still gets to see the challenge
  // behind it.
  for (value, fault) in [
    (&b"Basic a=1, =x, Newauth b=1"[..], AuthError::MissingScheme),
    (b"Basic, type=1, Newauth b=1", AuthError::MalformedScheme),
    (b"Basic a=x y, Newauth b=1", AuthError::MalformedParameter),
  ] {
    let mut walk = challenges([value]).skip_while(|read| read.is_ok());
    assert_eq!(walk.next().unwrap().unwrap_err(), fault, "{value:?}");
    let last = walk
      .next()
      .unwrap_or_else(|| panic!("{value:?}: walk stopped"));
    assert_eq!(last.unwrap().scheme(), b"Newauth", "{value:?}");
  }

  // And the row that looks like it should not continue, and does not. The
  // argument for continuing was that the byte the scan fails on is one RFC 9110
  // §5.5 admits nowhere in a field value, so there is no reading of what
  // follows for the recovery to be wrong about. There is: the DQUOTE stands
  // where §11.2 admits a value, the sender wrote every byte behind it as that
  // value's data, and a run that reaches no close holds the comma in front of
  // `Newauth` too. So this row is the walk telling the caller the rest is
  // unread, and `Newauth` is what §11.4's user agent is told it has not been
  // shown — rather than being handed a `Newauth` cut out of `a`'s own value.
  let [fault, unknown, past] = walk::<3>([&b"Basic a=\"x\x00y\", Newauth b=1"[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::InvalidQuotedString);
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // Which is a rule about the walk that READS a challenge, and there is one
  // walk it cannot be a rule about. A SEEK past an already-reported challenge
  // reads no quoted-string at all — the bytes it crosses have been refused, so
  // no production admits one there — and a scan that opens no string cannot
  // fail inside one. The %x00 below sits in a challenge already reported as
  // `MalformedScheme`, and §11.4's user agent still gets `Newauth`.
  let [basic, malformed, newauth, past] =
    walk::<4>([&b"Basic, type=1, x=\"a\x00b\", Newauth c=1"[..]]);
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());

  // The row spec §5.2's table calls end of input by construction: a string
  // that never closed consumed the rest of the value, so there is nothing
  // behind it for the walk to continue to.
  let [fault, past] = walk::<2>([&br#"Basic a="x"#[..]]);
  assert_eq!(
    fault.unwrap().unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  assert!(past.is_none());

  // A quoted-string that never closes is the benign end of the same seek: it
  // consumes the rest of the input and the walk ends.
  let [basic, malformed, past] = walk::<3>([&b"Basic, type=\"x"[..]]);
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert!(past.is_none());
}

#[test]
fn a_challenge_split_across_field_lines_is_still_one_challenge() {
  // RFC 9110 §11.6.1: the field "can occur multiple times", and §5.2 makes the
  // lines one value "concatenated in order, with each field line value
  // separated by a comma". At that comma the next element's leading token has
  // an `=` behind it, so it is a parameter of the challenge already open.
  let credential = one([&b"Basic a=1"[..], b"b=2"]);
  assert_eq!(credential.scheme(), b"Basic");
  assert_eq!(names::<3>(&credential), [Some(&b"a"[..]), Some(b"b"), None]);

  // A value that spans the join keeps its challenge and every name in it, and
  // only that one value reports it is not one slice.
  let credential = one([
    &br#"Digest realm="x", opaque="jo"#[..],
    br#"in", nonce="y""#,
  ]);
  assert!(credential.scheme_is("digest"));
  let mut params = credential.params();
  assert!(matches!(params.next().unwrap().value(), Ok(ParamValue::Quoted(v)) if v == b"x"));
  assert_eq!(
    params.next().unwrap().value().unwrap_err(),
    ValueSpansFieldLines
  );
  assert!(matches!(params.next().unwrap().value(), Ok(ParamValue::Quoted(v)) if v == b"y"));
  assert!(params.next().is_none());

  // Lines that carry no element bytes spend no entry, so a challenge whose
  // parameters sit either side of them is one challenge.
  let credential = one([&b"Basic a=1"[..], b"", b" , ,", b"\t", b"b=2"]);
  assert_eq!(names::<3>(&credential), [Some(&b"a"[..]), Some(b"b"), None]);

  // A name split by a join is not a name: RFC 9110 §5.2 joins these to
  // `Basic real,m=x`, and `real` is wholly a `token68` at that comma. So the
  // body took §11.3's `token68` alternative, `Basic real` is a whole challenge,
  // and `m=x` is the next element of the outer list — where `m` is a `token`
  // with `=` behind it and `challenge = auth-scheme [ 1*SP ( token68 /
  // #auth-param ) ]` admits nothing, so it is refused at its scheme.
  //
  // The other reading — one `#auth-param` list whose first element is `real`
  // and second is `m=x` — is not one: `auth-param` needs a value behind an `=`
  // and `real` has no `=` at all, so that alternative derives none of these
  // bytes rather than deriving them badly.
  let [basic, fault, past] = walk::<3>([&b"Basic real"[..], b"m=x"]);
  assert_eq!(basic.unwrap().unwrap().token68(), Some(&b"real"[..]));
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert!(past.is_none());

  // And a boundary is found across a join exactly as it is inside a line.
  let [basic, newauth, past] = walk::<3>([&b"Basic a=1"[..], b"Newauth b=2"]);
  assert!(past.is_none());
  assert_eq!(
    names::<2>(&basic.unwrap().unwrap()),
    [Some(&b"a"[..]), None]
  );
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
}

#[test]
fn a_challenge_past_the_line_bound_is_refused_and_the_next_one_is_read() {
  // The refusal `MAX_CHALLENGE_LINES` names, met inside a walk rather than
  // over one credential — and the walk goes on, because the boundary behind
  // the refused challenge is still a comma this scan resolved.
  let mut lines = [&b""[..]; 18];
  lines[..SEVENTEEN_LINES.len()].copy_from_slice(&SEVENTEEN_LINES);
  lines[17] = b"Newauth z=1";

  let [refused, newauth, past] = walk::<3>(lines);
  assert!(past.is_none());
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");

  // Sixteen of the same lines is the shape that fits.
  let credential = one(SEVENTEEN_LINES.iter().take(MAX_CHALLENGE_LINES).copied());
  assert_eq!(credential.params().count(), MAX_CHALLENGE_LINES);

  // The seventeenth region a challenge spends need not begin an element, and
  // the shape where it does not is the one only the LAST region can be refused
  // on. One quoted value spans every line here, so fifteen of them begin
  // nothing at all — `BodyLines` still spends an entry on each, because the
  // bytes that CLOSE the value are on the last of them — and the walk meets no
  // element on the line that overruns. Seventeen regions, one parameter.
  let mut spanning = [&b""[..]; 18];
  spanning[0] = b"Basic a=\"x";
  for line in spanning.iter_mut().take(16).skip(1) {
    *line = b"j";
  }
  spanning[16] = b"y\"";
  spanning[17] = b"Newauth z=1";
  let [refused, newauth, past] = walk::<3>(spanning);
  assert!(past.is_none());
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");

  // Sixteen regions of the same shape is what fits, and the parameter is read.
  let credential = one(spanning.iter().take(15).copied().chain([&b"y\""[..]]));
  assert_eq!(
    names::<2>(&credential),
    [Some(&b"a"[..]), None],
    "one parameter across sixteen regions"
  );

  // Where a challenge carries BOTH a fault of the sender's and this reader's
  // line bound, the walk answers with whichever it MEETS first — and it meets
  // the sender's, because every element is derived where it is read rather
  // than after the whole challenge has been walked. `SeenNames::record` orders
  // its own two answers the same way and for the same reason: a recipient's
  // limit is not what to tell a caller about a list that was already
  // underivable. Seventeen lines here, and the first element is no parameter.
  let mut both = [&b"z=1"[..]; 18];
  both[0] = b"Basic a=b=c";
  both[17] = b"Newauth q=1";
  let [refused, newauth, past] = walk::<3>(both);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
  assert!(past.is_none());
}

#[test]
fn the_region_a_challenge_ends_in_is_the_one_the_bound_is_read_at() {
  // `MAX_CHALLENGE_LINES` has two readers that answer for a crossing which
  // could not return a verdict, and they are not symmetric. `Section::outgrown`
  // answers for every region an element is read ON, asked before that element's
  // bytes are; `Section::close` answers for the LAST region — the one no
  // element is read on, because the challenge ends there — by asking for a body
  // that a refusal has taken away. A count cannot answer for that one: a
  // challenge that just fits has spent every slot too.
  //
  // The test above drives `outgrown`, and drives `close` once through a
  // seventeen-region fixture whose refusal is met while a line is being LEFT.
  // These are the other half: the refusal met inside `close`'s own `spend`,
  // where the challenge's own final region is the one that does not fit. An
  // edit that dropped either reader passes eleven of the twelve gates, so both
  // are driven here by shapes that cannot be mistaken for each other.

  // Seventeen regions and the value ends on the seventeenth. One quoted value
  // spans them all, so no element is read past the first line and `outgrown` is
  // never asked at all — the refusal exists only because `close` can hand over
  // no body once its own `spend` has refused one.
  let mut ends_there = [&b"j"[..]; 17];
  ends_there[0] = b"Basic a=\"x";
  ends_there[16] = b"y\"";
  let [refused, past] = walk::<2>(ends_there);
  assert!(past.is_none(), "the value ends with the refused challenge");
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );

  // The same seventeenth region, now carrying the NEXT challenge behind the
  // byte that closes the value. The refusal is still `close`'s, and the walk
  // goes on to read what the region holds behind this challenge.
  let mut shares_the_line = ends_there;
  shares_the_line[16] = b"y\", Newauth z=1";
  let [refused, newauth, past] = walk::<3>(shares_the_line);
  assert!(past.is_none());
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");

  // Sixteen regions of the same shape is what fits, in both spellings — the
  // control that says the refusals above are the bound and not the fixture.
  let mut fits = [&b"j"[..]; 16];
  fits[0] = b"Basic a=\"x";
  fits[15] = b"y\"";
  assert_eq!(names::<2>(&one(fits)), [Some(&b"a"[..]), None]);

  let mut fits_and_shares = fits;
  fits_and_shares[15] = b"y\", Newauth z=1";
  let [basic, newauth, past] = walk::<3>(fits_and_shares);
  assert!(past.is_none());
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(names::<2>(&basic), [Some(&b"a"[..]), None]);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
}

#[test]
fn a_value_still_open_at_the_line_bound_is_refused_before_it_reads_on() {
  // The THIRD crossing `MAX_CHALLENGE_LINES` is met at, and the only one where
  // the challenge's own element is still OPEN: a quoted value RFC 9110 §5.2's
  // join carries onto the next line takes that line with it, so a line this
  // challenge may not hold is a line this reader may not read. The refusal is
  // met at the crossing itself — and it is the one refusal in this module that
  // leaves NO boundary behind it, because the cursor stands inside a §5.6.4
  // quoted-string §11.2 admitted and nothing this walk may read can say where
  // that string closes. Every comma behind it is the value's data in the only
  // reading there is, so `AuthError::ChallengeBoundaryUnknown` follows.
  //
  // One value opens on the first line here and every continuation keeps it
  // open, so the SEVENTEENTH region is the one that does not fit — and the
  // line behind it carries a byte §5.6.4 forbids and then a challenge. The
  // fault reported is the bound and not the byte, because the bound is met at
  // the crossing and the byte stands on the line that crossing could not hold.
  let mut too_many = [&b"j"[..]; 18];
  too_many[0] = b"Basic a=\"x";
  too_many[17] = b"\x00, Digest realm=z";
  let [refused, unknown, past] = walk::<3>(too_many);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // ONE line fewer is sixteen regions, and there the byte IS read — the region
  // it stands on is one this challenge holds. The FAULT is what tells the two
  // rows apart, and it still does: this pair says the refusal above is the
  // bound being met FIRST rather than the byte being unreachable, and an edit
  // that made the bound fire a line late would answer
  // `ChallengeSpansTooManyLines` here as well.
  //
  // What follows the fault is the same either way, and that is not the bound's
  // doing: `a`'s string is open across §5.2's join in both, so the DQUOTE that
  // opened it is on a line this walk no longer holds and no comma behind it may
  // be certified. This asserted `Digest`, and that `Digest` came out of
  // `a`'s own value.
  let mut within = [&b"j"[..]; 17];
  within[0] = b"Basic a=\"x";
  within[16] = b"\x00, Digest realm=z";
  let [refused, unknown, past] = walk::<3>(within);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // And with no forbidden byte at all on the line the challenge could not
  // hold: the same answer, for the same reason. `a`'s string is still open, so
  // `Digest realm=z` is inside it whatever else that line carries, and the walk
  // says so rather than reading it.
  let mut swallowed = [&b"j"[..]; 18];
  swallowed[0] = b"Basic a=\"x";
  swallowed[17] = b"Digest realm=z";
  let [refused, unknown, past] = walk::<3>(swallowed);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // Sixteen regions of the conforming shape still parse, so the refusal above
  // is the seventeenth region and not the fixture: one value spanning every
  // line of the bound, closing on the last of them, with a challenge behind it.
  let mut fits = [&b"j"[..]; 16];
  fits[0] = b"Basic a=\"x";
  fits[15] = b"y\", Digest realm=z";
  let [basic, digest, past] = walk::<3>(fits);
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(names::<2>(&basic), [Some(&b"a"[..]), None]);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // A refusal a crossing could not RETURN still binds, and `Section::outgrown`
  // is where. `Challenges::open_element` crosses a join BETWEEN two elements,
  // where §5.2's comma may already have ended the challenge and only the
  // element behind it says so, so the region it could not hold leaves the
  // section with no body instead of a verdict. Here the element behind that
  // join is a parameter of THIS challenge — so the challenge did not end at the
  // join — and its value is a DQUOTE at the one position §11.2 admits one.
  // Reading it would open a string that swallows the comma in front of
  // `Digest`; `outgrown` answers for the missing body first, and refuses before
  // that element's bytes are read. The recovery behind that refusal is where
  // the same DQUOTE is asked about again, and the answer is the same: some
  // reading of `t="open` holds the comma in front of `Digest`, so the walk
  // reports that it cannot say where the refused challenge ends.
  let mut refused_at_the_join = [&b"j"[..]; 18];
  refused_at_the_join[0] = b"Basic a=\"x";
  refused_at_the_join[16] = b"y\"";
  refused_at_the_join[17] = b"t=\"open, Digest realm=z";
  let [refused, unknown, past] = walk::<3>(refused_at_the_join);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(
    unknown.unwrap().unwrap_err(),
    AuthError::ChallengeBoundaryUnknown
  );
  assert!(past.is_none());

  // The pair that says the answer above is the READING and not the crossing:
  // the same shape with that element's string CLOSED in front of the comma. The
  // bound is met at the same place and refuses the same challenge, and `Digest`
  // is reached, because no reading of `t="shut"` holds that comma.
  let mut certain_at_the_join = refused_at_the_join;
  certain_at_the_join[17] = b"t=\"shut\", Digest realm=z";
  let [refused, digest, past] = walk::<3>(certain_at_the_join);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The control that says that trap really springs: the same last two lines
  // with FIFTEEN regions in front of them, so nothing is refused and the walk
  // reads `t="open, Digest realm=z` as the parameter it is. §5.6.4 makes every
  // comma inside the string it opens data, and `Digest` is not reached at all.
  let mut not_refused = [&b"j"[..]; 16];
  not_refused[0] = b"Basic a=\"x";
  not_refused[14] = b"y\"";
  not_refused[15] = b"t=\"open, Digest realm=z";
  let [refused, past] = walk::<2>(not_refused);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  assert!(past.is_none());
}

#[test]
fn the_line_bound_met_inside_a_value_leaves_the_two_spellings_the_same_answer() {
  // The asymmetry this test was written to record, and no longer has. The bound
  // needs seventeen regions, so no one-line spelling of a value can meet it —
  // but RFC 9110 §5.2 makes a field line list one value by separating each line
  // value from the next with a comma, so folding a join comma into the line in
  // front of it writes the SAME value over one line fewer. The two spellings
  // used to answer with different numbers of challenges, because recovery ran
  // by raw commas from where the scan STOOD and that offset moved with the
  // sender's line breaks — which §5.2 says are no part of the value.
  //
  // They agree now, and what makes them agree is that neither has a boundary to
  // find. The bound is met with the challenge's own value still open inside a
  // §5.6.4 quoted-string, so every comma behind that DQUOTE is the value's data
  // in the only reading there is: neither `Digest realm=z` nor `Newauth q=1` is
  // a challenge under any reading of these bytes, and the walk says it cannot
  // place the boundary rather than picking one of them.

  // Nineteen field lines, one value open from the first of them to the last.
  let mut folded_late = [&b"j"[..]; 19];
  folded_late[0] = b"Basic a=\"x";
  folded_late[17] = b"Digest realm=z";
  folded_late[18] = b"Newauth q=1";

  // The same value, with the comma in front of `Digest` written INTO the line
  // ahead of it instead of made by the join. One line fewer, so a different
  // region is the one that does not fit.
  let mut folded_early = [&b"j"[..]; 18];
  folded_early[0] = b"Basic a=\"x";
  folded_early[16] = b"j,Digest realm=z";
  folded_early[17] = b"Newauth q=1";

  // The claim the pair rests on, executed: the two lists are ONE value.
  assert!(
    joined_value(folded_late).eq(joined_value(folded_early)),
    "the two spellings must be one RFC 9110 §5.2 value"
  );

  for lines in [&folded_late[..], &folded_early[..]] {
    let [refused, unknown, past] = walk::<3>(lines.iter().copied());
    assert_eq!(
      refused.unwrap().unwrap_err(),
      AuthError::ChallengeSpansTooManyLines,
      "{lines:?}"
    );
    assert_eq!(
      unknown.unwrap().unwrap_err(),
      AuthError::ChallengeBoundaryUnknown,
      "{lines:?}"
    );
    assert!(past.is_none(), "{lines:?}");
  }

  // The control that says the FOLD is not what tells them apart: the same two
  // spellings with too few lines to meet the bound answer identically. What
  // separates the pair above is the recovery point the bound leaves behind,
  // and nothing else.
  let across_four: [&[u8]; 4] = [b"Basic a=\"x", b"j", b"Digest realm=z", b"Newauth q=1"];
  let across_three: [&[u8]; 3] = [b"Basic a=\"x", b"j,Digest realm=z", b"Newauth q=1"];
  assert!(joined_value(across_four).eq(joined_value(across_three)));
  for lines in [&across_four[..], &across_three[..]] {
    let [refused, past] = walk::<2>(lines.iter().copied());
    assert_eq!(
      refused.unwrap().unwrap_err(),
      AuthError::UnterminatedQuotedString,
      "{lines:?}"
    );
    assert!(past.is_none(), "{lines:?}");
  }
}

// ── RFC 9110 §11.6.2's Authorization, which holds ONE credential ─────────────

#[test]
fn the_whole_field_value_is_one_credential() {
  // RFC 9110 §11.6.2 spells the field `Authorization = credentials` and
  // §11.7.2 spells `Proxy-Authorization = credentials`; neither is a `#`-list,
  // so no comma in the value can end a credential and start another. Every one
  // of them separates `auth-param`s of the single credential the field holds,
  // and no boundary question is asked anywhere on this path.
  let credential = credentials(b"Newauth a=1, b=\"two\", c=3").unwrap();
  assert_eq!(credential.scheme(), b"Newauth");
  assert!(credential.token68().is_none());
  assert_eq!(
    names::<4>(&credential),
    [Some(&b"a"[..]), Some(b"b"), Some(b"c"), None]
  );

  // A `token68` credential, which is the other branch of the same production.
  let basic = credentials(b"Basic dGVzdA==").unwrap();
  assert_eq!(basic.token68(), Some(&b"dGVzdA=="[..]));
  assert_eq!(basic.params().count(), 0);

  // A bare scheme is a whole credential, and an empty value has none.
  assert_eq!(credentials(b"Basic").unwrap().scheme(), b"Basic");
  assert_eq!(credentials(b"").unwrap_err(), AuthError::MissingScheme);
}

#[test]
fn a_second_credential_in_the_field_is_a_parameter_that_is_not_one() {
  // Spec §7's row. `Basic x=1, Digest y=2` is two credentials only in a field
  // that could hold two, and `Authorization` is not one — so the comma is a
  // parameter boundary and `Digest y` is read where a name and its `=` should
  // be. RFC 9110 §11.2's
  // `auth-param = token BWS "=" BWS ( token / quoted-string )` puts only
  // §5.6.3's `BWS` between the two, and a second token is not that.
  assert_eq!(
    credentials(b"Basic x=1, Digest y=2").unwrap_err(),
    AuthError::MalformedParameter
  );

  // The same bytes handed to the `#challenge` walk are two challenges, because
  // that field HAS the list this one does not. Reporting the malformed
  // credential is not the same as silently taking the first of two.
  let [basic, digest, past] = walk::<3>([&b"Basic x=1, Digest y=2"[..]]);
  assert!(past.is_none());
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
}

#[test]
fn a_scheme_reaches_its_body_only_through_1_sp_here_too() {
  // §4.1's one-byte pair, asked of the singular field. Through `challenges`
  // `Basic, type=1` is TWO challenges, the second of which nothing derives;
  // through `credentials` the comma is derived by nothing at all, since
  // `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` has no list
  // at its top level for the comma to be a separator of.
  assert_eq!(
    credentials(b"Basic, type=1").unwrap_err(),
    AuthError::MalformedScheme
  );
  let [basic, malformed, past] = walk::<3>([&b"Basic, type=1"[..]]);
  assert!(past.is_none());
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);

  // With the SP the section opens, and the empty first element §5.6.1.2 skips
  // leaves one parameter — the same answer the plural field gives.
  let credential = credentials(b"Basic , type=1").unwrap();
  assert_eq!(names::<2>(&credential), [Some(&b"type"[..]), None]);
}

#[test]
fn a_trailing_comma_needs_a_list_to_be_an_empty_element_of() {
  // Spec §7.1's three rows, and the asymmetry is the grammar's. RFC 9110
  // §11.6.1's `WWW-Authenticate = #challenge` is a list, so the comma behind a
  // whole challenge is an empty element of it — the one §5.6.1.2 asks a
  // recipient to "parse and ignore".
  assert_eq!(
    one([&b"Basic dGVzdA==,"[..]]).token68(),
    Some(&b"dGVzdA=="[..])
  );

  // `Authorization = credentials` holds no such list. Once `token68` has
  // matched `dGVzdA==` the production is complete, and `,` is not one of the
  // bytes `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" )
  // *"="` admits, so nothing derives it: the body is re-read as the other
  // alternative and fails there, which is why no `MalformedToken68` exists.
  assert_eq!(
    credentials(b"Basic dGVzdA==,").unwrap_err(),
    AuthError::MalformedParameter
  );

  // Where the credential took the `#auth-param` branch instead, the trailing
  // comma IS an empty element of that list, and is skipped in the singular
  // context exactly as in the plural one. Task 3 hand-traced this row and did
  // not test it; this is the test.
  let credential = credentials(b"Newauth realm=\"x\",").unwrap();
  assert_eq!(credential.scheme(), b"Newauth");
  assert_eq!(names::<2>(&credential), [Some(&b"realm"[..]), None]);
  assert!(matches!(
    credential.params().next().unwrap().value(),
    Ok(ParamValue::Quoted(v)) if v == b"x"
  ));

  // And the empty elements are unbounded at this level too.
  let credential = credentials(b"Newauth ,,a=1,,,b=2,,").unwrap();
  assert_eq!(names::<3>(&credential), [Some(&b"a"[..]), Some(b"b"), None]);
}

// ── RFC 9110 §11.6.3's Authentication-Info, a list and nothing else ──────────

/// One `#auth-param` walk collected into a fixed array, `None` past its last
/// result.
///
/// `N` is written one larger than the answer a test expects, so the trailing
/// `None` is the assertion that the walk stopped where it was supposed to
/// rather than the test reading only a prefix of it.
fn info<'a, const N: usize>(
  lines: impl IntoIterator<Item = &'a [u8]>,
) -> [Option<Result<AuthParam<'a>, AuthError>>; N] {
  let mut out = [None; N];
  for (slot, outcome) in out.iter_mut().zip(auth_info(lines)) {
    *slot = Some(outcome);
  }
  out
}

/// Seventeen field lines — one more than [`MAX_CHALLENGE_LINES`] — carrying
/// twelve parameters, the first of which is one value spread over six of them.
///
/// Every line has element bytes on it, so a walk that spent an entry per line
/// the way a [`Credential`] must would run out on this input. The parameter
/// count is kept well under the crate's other bound so that this pins the one
/// it is about.
const SEVENTEEN_INFO_LINES: [&[u8]; 17] = [
  b"p00=\"a", b"a", b"a", b"a", b"a", b"a\"", b"p01=1", b"p02=2", b"p03=3", b"p04=4", b"p05=5",
  b"p06=6", b"p07=7", b"p08=8", b"p09=9", b"p10=10", b"p11=11",
];

#[test]
fn the_field_is_a_parameter_list_with_no_scheme_in_front_of_it() {
  // RFC 9110 §11.6.3 spells `Authentication-Info = #auth-param` and §11.7.3
  // spells `Proxy-Authentication-Info = #auth-param`. There is no
  // `auth-scheme` in either and no `token68` behind one, and what the
  // parameters mean is not this parser's either — §11.6.3: "This specification
  // only describes the generic format; authentication schemes using
  // Authentication-Info will define the individual parameters."
  let [next, rsp, past] = info::<3>([&b"nextnonce=\"47364c23\", rspauth=6629fae4"[..]]);
  assert!(past.is_none());
  let next = next.unwrap().unwrap();
  assert_eq!(next.name(), b"nextnonce");
  assert!(matches!(next.value(), Ok(ParamValue::Quoted(v)) if v == b"47364c23"));
  let rsp = rsp.unwrap().unwrap();
  assert_eq!(rsp.name(), b"rspauth");
  assert!(matches!(rsp.value(), Ok(ParamValue::Token(v)) if v == b"6629fae4"));

  // A whole challenge is not a parameter, because this field has nothing that
  // admits a scheme: `Basic` is read as a name, and RFC 9110 §11.2's
  // `auth-param = token BWS "=" BWS ( token / quoted-string )` puts only
  // §5.6.3's `BWS` between that name and its `=`, which a second token is not.
  let [fault, past] = info::<2>([&b"Basic realm=\"x\""[..]]);
  assert!(past.is_none());
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedParameter);

  // `#auth-param` has no lower bound — RFC 9110 §5.6.1's `<n>#<m>element` is
  // written here with neither — so an empty value is an empty list and not a
  // fault.
  assert!(info::<1>([&b""[..]])[0].is_none());
  assert!(info::<1>([&b" , ,"[..]])[0].is_none());
}

#[test]
fn a_parameter_list_is_read_across_the_lines_it_arrived_on() {
  // RFC 9110 §5.2 makes repeated field lines one value, the field line values
  // "concatenated in order, with each field line value separated by a comma",
  // so a sender that split this list at an element boundary wrote the same
  // list as one that did not.
  let [first, second, third, past] = info::<4>([&b"a=1"[..], b"b=2", b"c=3"]);
  assert!(past.is_none());
  assert_eq!(first.unwrap().unwrap().name(), b"a");
  assert_eq!(second.unwrap().unwrap().name(), b"b");
  assert_eq!(third.unwrap().unwrap().name(), b"c");

  // A VALUE that crosses the join is spec §5.2's rule, and it is the same rule
  // at all three entry points: the walk keeps the parameter, `name()` still
  // answers, and the one fact that is true — this value is not one contiguous
  // slice — surfaces at `value()` and nowhere else. No error is reported here.
  let [spanning, plain, past] = info::<3>([&b"a=\"long"[..], b"tail\", b=2"]);
  assert!(past.is_none());
  let spanning = spanning.unwrap().unwrap();
  assert_eq!(spanning.name(), b"a");
  assert_eq!(spanning.value().unwrap_err(), ValueSpansFieldLines);
  let plain = plain.unwrap().unwrap();
  assert_eq!(plain.name(), b"b");
  assert!(matches!(plain.value(), Ok(ParamValue::Token(v)) if v == b"2"));

  // The escape pending at a join is spent on the join's own comma, so the next
  // line's leading DQUOTE closes the string — the same reading
  // `the_escape_pending_at_a_join_is_spent_on_the_join_comma` pins for a
  // credential, reached through this walk instead.
  let [closed, past] = info::<2>([&b"a=\"x\\"[..], b"\""]);
  assert!(past.is_none());
  let closed = closed.unwrap().unwrap();
  assert_eq!(closed.name(), b"a");
  assert_eq!(closed.value().unwrap_err(), ValueSpansFieldLines);
}

#[test]
fn a_trailer_field_line_is_read_as_any_other_field_line() {
  // RFC 9110 §11.6.3: "Authentication-Info can be sent as a trailer field
  // (Section 6.5) when the authentication scheme explicitly allows this."
  // §11.7.3 says the same of `Proxy-Authentication-Info`.
  //
  // Nothing in this module honours that sentence, because nothing in it can
  // tell. `auth_info` is handed field LINES and takes no other argument: there
  // is no section, no flag and no branch in it that a header line and a
  // trailer line could take differently, so a trailer's lines parse
  // identically BY CONSTRUCTION rather than by a check that could be got
  // wrong. Whether the scheme allows the field there at all is the caller's,
  // since this crate implements no authentication scheme.
  //
  // What is asserted is the operational half of "cannot tell": a value a
  // sender wrote as one line and the same value it wrote as two — which is
  // what a trailer section, announced field by field, tends to look like —
  // give the same parameters, because RFC 9110 §5.2 joins the second back into
  // the first and this walk is the only reader either reaches.
  let [h1, h2, h_past] = info::<3>([&b"nextnonce=\"a1b2\", rspauth=\"c3d4\""[..]]);
  let [t1, t2, t_past] = info::<3>([&b"nextnonce=\"a1b2\""[..], b"rspauth=\"c3d4\""]);
  assert!(h_past.is_none());
  assert!(t_past.is_none());

  let (h1, t1) = (h1.unwrap().unwrap(), t1.unwrap().unwrap());
  assert_eq!(h1.name(), t1.name());
  assert_eq!(h1.name(), b"nextnonce");
  assert!(matches!(t1.value(), Ok(ParamValue::Quoted(v)) if v == b"a1b2"));

  let (h2, t2) = (h2.unwrap().unwrap(), t2.unwrap().unwrap());
  assert_eq!(h2.name(), t2.name());
  assert_eq!(h2.name(), b"rspauth");
  assert!(matches!(t2.value(), Ok(ParamValue::Quoted(v)) if v == b"c3d4"));
}

#[test]
fn a_parameter_list_is_not_bounded_by_the_challenge_line_bound() {
  // `MAX_CHALLENGE_LINES` bounds what one `Credential` can NAME at once: a
  // challenge is handed over whole, so a borrowing reader has to hold every
  // region it spans and the array holding them is a fixed size. This walk
  // hands over one parameter at a time and never names more than the line that
  // parameter began on, so the bound has nothing here to bound — and a list
  // spread over more lines than it is read rather than refused.
  assert!(SEVENTEEN_INFO_LINES.len() > MAX_CHALLENGE_LINES);
  let read = auth_info(SEVENTEEN_INFO_LINES).count();
  assert_eq!(read, 12);
  assert!(auth_info(SEVENTEEN_INFO_LINES).all(|param| param.is_ok()));

  // The first parameter is the value spread over six of those lines, and it is
  // the walk's own regression against dropping the lines that begin no element
  // of their own: they carry the DQUOTE that closes it.
  let mut walk = auth_info(SEVENTEEN_INFO_LINES);
  let spanning = walk.next().unwrap().unwrap();
  assert_eq!(spanning.name(), b"p00");
  assert_eq!(spanning.value().unwrap_err(), ValueSpansFieldLines);
  assert_eq!(walk.next().unwrap().unwrap().name(), b"p01");
  assert_eq!(walk.last().unwrap().unwrap().name(), b"p11");
}

#[test]
fn one_fault_ends_the_parameter_walk() {
  // Spec §5.2 lets `challenges()` go on after a fault because §11.4 has a user
  // agent SEARCH that list for a scheme it understands, and one unreadable
  // challenge must not hide the readable one behind it. A parameter list is
  // not searched that way, and the crate's own parameter walk —
  // `crate::grammar::ParamIter` — poisons on any `Err`. This one does the
  // same: the fault is reported once and the walk ends there.
  let [good, fault, past] = info::<3>([&b"a=1, b, c=3"[..]]);
  assert_eq!(good.unwrap().unwrap().name(), b"a");
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert!(past.is_none());

  // A string still open when the LAST field line ends never closed, which is
  // the one case the join cannot rescue.
  let [fault, past] = info::<2>([&b"a=\"x"[..]]);
  assert_eq!(
    fault.unwrap().unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  assert!(past.is_none());

  // %x00 is neither `qdtext` nor an octet a `quoted-pair` may escape, and
  // after it no comma can be told from data.
  let [fault, past] = info::<2>([&b"a=\"x\x00\", b=2"[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::InvalidQuotedString);
  assert!(past.is_none());
}

#[test]
fn the_stop_at_a_fault_is_what_keeps_a_later_dquote_out_of_this_field() {
  // `AuthInfo::element` derives an element AFTER computing its extent, which
  // is an order `Challenges::challenge` may not take. It is safe here for two
  // reasons, and this drives the load-bearing one: the walk stops at the first
  // fault, so no byte behind one is ever read and no DQUOTE behind one can
  // decide where anything ends.
  //
  // The shape is the `#challenge` walk's, spelled for `#auth-param`: an element
  // that derives nothing, and a DQUOTE at §11.2's own value position in the
  // element behind it. In a `#challenge` value that DQUOTE swallows the comma
  // in front of a later challenge; here the walk never reaches it, so `b` is
  // never read at all and the fault reported is the one the SENDER committed
  // at `a`.
  let [fault, past] = info::<2>([&b"a, b=\", c=1"[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert!(past.is_none(), "nothing behind the fault is read");

  // The same across RFC 9110 §5.2's join, where the fault and the trap are on
  // different field lines.
  let [fault, past] = info::<2>([&b"a"[..], b"b=\", c=1"]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert!(past.is_none());

  // The other reason, which needs no walk to state: this field is
  // `Authentication-Info = #auth-param` and has no second level, so the most
  // an extent can decide is where the next PARAMETER begins. A trap with
  // nothing refused in front of it swallows the comma, exactly as §5.6.4 says
  // it must — the parameter is real, its value simply never closes — and that
  // is the control that says the two assertions above are the stop and not the
  // trap failing to spring.
  let [fault, past] = info::<2>([&b"b=\", c=1"[..]]);
  assert_eq!(
    fault.unwrap().unwrap_err(),
    AuthError::UnterminatedQuotedString
  );
  assert!(past.is_none());
}

#[test]
fn the_same_parameter_list_reads_the_same_through_every_entry_point() {
  // One `#auth-param` list, reached once as the body of a credential and once
  // as the whole of an `Authentication-Info` field. RFC 9110 §11.6.3 says the
  // field uses the `auth-param` syntax §11.2 defines, which is the syntax the
  // body of §11.4's `credentials` is a list of — so the two walks are over one
  // production and are asserted to agree rather than left to drift.
  // The OWS RFC 9110 §5.6.1.2 hangs on both sides of every comma is the list's
  // and not the value's, at this entry point as at the other two.
  let credential = credentials(b"Basic a=1 , b=\"x\" , c = 3").unwrap();
  let [first, second, third, past] = info::<4>([&b"a=1 , b=\"x\" , c = 3"[..]]);
  assert!(past.is_none());

  let mut params = credential.params();
  for expected in [first, second, third] {
    let expected = expected.unwrap().unwrap();
    let got = params.next().unwrap();
    assert_eq!(got.name(), expected.name());
    match (got.value(), expected.value()) {
      (Ok(ParamValue::Token(a)), Ok(ParamValue::Token(b))) => assert_eq!(a, b),
      (Ok(ParamValue::Quoted(a)), Ok(ParamValue::Quoted(b))) => assert_eq!(a, b),
      _ => panic!("the two walks read one parameter differently"),
    }
  }
  assert!(params.next().is_none());
}

#[test]
fn the_elements_behind_a_closing_line_are_reached_at_every_entry_point() {
  // `rejoin` is the one place this module carries an element across RFC 9110
  // §5.2's join, and all three walks reach it. Past the DQUOTE that closes the
  // value, the rest of that field line is ordinary list bytes: the elements
  // behind it belong to the challenge, the credential or the parameter list
  // that was open, and a walk that left its cursor at the line's END instead
  // would lose every one of them.
  //
  // `the_line_that_closes_a_value_carries_the_elements_behind_it` pins this
  // over `read_credential`. These are the other two, and the `#challenge` walk
  // additionally has to find, behind that close, the boundary §11.6.1's
  // ambiguity turns on.
  let [basic, newauth, past] = walk::<3>([&b"Basic a=\"x"[..], b"y\", b=2, Newauth c=3"]);
  assert!(past.is_none());
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(names::<3>(&basic), [Some(&b"a"[..]), Some(b"b"), None]);
  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(names::<2>(&newauth), [Some(&b"c"[..]), None]);

  let [first, second, third, past] = info::<4>([&b"a=\"x"[..], b"y\", b=2, c=3"]);
  assert!(past.is_none());
  let first = first.unwrap().unwrap();
  assert_eq!(first.name(), b"a");
  assert_eq!(first.value().unwrap_err(), ValueSpansFieldLines);
  assert_eq!(second.unwrap().unwrap().name(), b"b");
  assert_eq!(third.unwrap().unwrap().name(), b"c");
}

// ── RFC 9110 §11.2's one-name-once MUST, and the bound that checks it ────────

/// Sixteen `auth-param`s with sixteen distinct names — exactly what
/// [`MAX_PARAMS_PER_CREDENTIAL`] slots hold.
///
/// A macro rather than a `const` so the same bytes can be `concat!`ed behind an
/// `auth-scheme` and in front of a seventeenth parameter without being written
/// twice: a fixture spelled out once per entry point is a fixture that can
/// drift between them, and what these tests compare is the SAME list read three
/// ways.
macro_rules! sixteen_params {
  () => {
    "p01=1, p02=2, p03=3, p04=4, p05=5, p06=6, p07=7, p08=8, \
     p09=9, p10=10, p11=11, p12=12, p13=13, p14=14, p15=15, p16=16"
  };
}

/// Sixty-four empty list elements. RFC 9110 §5.6.1.2: "Empty elements do not
/// contribute to the count of elements present."
macro_rules! empty_elements {
  () => {
    ", , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , \
     , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , , "
  };
}

const SIXTEEN: &[u8] = sixteen_params!().as_bytes();
/// One name past the bound, and a further one behind THAT: the second is what
/// makes the walk's end assertable rather than borrowed from the input running
/// out.
const SEVENTEEN_THEN_ONE_MORE: &[u8] = concat!(sixteen_params!(), ", p17=17, p18=18").as_bytes();
const SEVENTEEN_WITH_A_REPEAT: &[u8] = concat!(sixteen_params!(), ", P01=99").as_bytes();
const FLOODED_SIXTEEN: &[u8] = concat!(empty_elements!(), sixteen_params!()).as_bytes();

const SIXTEEN_CHALLENGE: &[u8] = concat!("Basic ", sixteen_params!()).as_bytes();
const SEVENTEEN_CHALLENGE: &[u8] = concat!("Basic ", sixteen_params!(), ", p17=17").as_bytes();
const SEVENTEEN_CHALLENGE_WITH_A_REPEAT: &[u8] =
  concat!("Basic ", sixteen_params!(), ", P01=99").as_bytes();
const FLOODED_SIXTEEN_CHALLENGE: &[u8] =
  concat!("Basic ", empty_elements!(), sixteen_params!()).as_bytes();

#[test]
fn a_parameter_name_occurs_once_per_challenge() {
  // RFC 9110 §11.2: "Authentication parameters are name/value pairs, where the
  // name token is matched case-insensitively and each parameter name MUST only
  // occur once per challenge." The whole challenge is refused rather than the
  // repeat dropped: a scheme handed one of two `realm`s cannot tell which one
  // the sender meant, and answering from the first would be a guess.
  let [fault, past] = walk::<2>([&br#"Basic realm="x", realm="y""#[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert!(past.is_none());

  // Names that differ by more than case are two parameters and not a repeat.
  let credential = one([&br#"Basic realm="x", realmm="y""#[..]]);
  assert_eq!(
    names::<3>(&credential),
    [Some(&b"realm"[..]), Some(b"realmm"), None]
  );
}

#[test]
fn a_repeated_name_is_matched_case_insensitively() {
  // The fold is RFC 9110 §11.2's own sentence: the name token "is matched
  // case-insensitively", in the same breath as the MUST it governs. A reader
  // comparing the sender's bytes would call these two parameters.
  for value in [
    &br#"Basic realm="x", REALM="y""#[..],
    br#"Basic Realm="x", rEaLm="y""#,
    br#"Basic REALM="x", realm="y""#,
  ] {
    let [fault, past] = walk::<2>([value]);
    assert_eq!(
      fault.unwrap().unwrap_err(),
      AuthError::DuplicateParameter,
      "{value:?}"
    );
    assert!(past.is_none(), "{value:?}");
  }
}

#[test]
fn the_rule_is_per_list_and_not_per_field_value() {
  // "per challenge" is where RFC 9110 §11.2 DOES scope the rule, so two
  // challenges of one `WWW-Authenticate` value carrying the same name are two
  // challenges and not a repeat. §11.4 has a user agent choose among them by
  // their schemes, and a rule applied across the value would refuse the pair
  // that choice is for.
  let [basic, newauth, past] = walk::<3>([&br#"Basic realm="x", Newauth realm="y""#[..]]);
  assert!(past.is_none());
  let basic = basic.unwrap().unwrap();
  assert_eq!(basic.scheme(), b"Basic");
  assert_eq!(names::<2>(&basic), [Some(&b"realm"[..]), None]);
  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(names::<2>(&newauth), [Some(&b"realm"[..]), None]);
}

#[test]
fn the_duplicate_rule_holds_at_every_entry_point() {
  // §11.2 writes the rule for a CHALLENGE. Applying it to a `credentials`
  // value and to an `Authentication-Info` list is this module's ruling rather
  // than the RFC's wording — `AuthError::DuplicateParameter` records the
  // argument — and this is that ruling executed at all three entry points.
  let [fault, past] = walk::<2>([&b"Basic a=1, A=2"[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert!(past.is_none());

  assert_eq!(
    credentials(b"Basic a=1, A=2").unwrap_err(),
    AuthError::DuplicateParameter
  );

  // The bare `#auth-param` field has no challenge for the wording to scope the
  // rule to, and is where the extension does the most work. A parameter is
  // written BEHIND the repeat so the walk's end is asserted rather than
  // borrowed from the input running out: `one_fault_ends_the_parameter_walk`
  // is the rule, and a fault that left the walk running would hand `b=3` over
  // as though the list had been read.
  let [first, fault, past, further] = info::<4>([&b"a=1, A=2, b=3"[..]]);
  assert_eq!(first.unwrap().unwrap().name(), b"a");
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert!(past.is_none());
  assert!(further.is_none());
}

#[test]
fn a_failed_name_does_not_stop_the_challenge_walk() {
  // The boundaries either side of a repeat are still known, so §11.4's choice
  // among challenges survives one that cannot be read — the same rule every
  // fault but `InvalidQuotedString` is met with.
  let [fault, newauth, past] = walk::<3>([&br#"Basic realm="x", realm="y", Newauth c=1"#[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(names::<2>(&newauth), [Some(&b"c"[..]), None]);
  assert!(past.is_none());
}

#[test]
fn a_repeat_across_a_field_line_join_is_still_a_repeat() {
  // RFC 9110 §5.2 makes the two lines one value with a comma at the join, so
  // the second `a` is another element of the SAME list rather than the start
  // of a second one.
  let [fault, past] = walk::<2>([&b"Basic a=1"[..], b"a=2"]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert!(past.is_none());

  let [first, fault, past, further] = info::<4>([&b"a=1"[..], b"a=2, b=3"]);
  assert_eq!(first.unwrap().unwrap().name(), b"a");
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert!(past.is_none());
  assert!(further.is_none());
}

#[test]
fn exactly_the_tracked_count_fits() {
  // The fixtures are sized off the published constant.
  assert_eq!(MAX_PARAMS_PER_CREDENTIAL, 16);

  let credential = one([SIXTEEN_CHALLENGE]);
  assert_eq!(credential.params().count(), MAX_PARAMS_PER_CREDENTIAL);
  assert_eq!(credentials(SIXTEEN_CHALLENGE).unwrap().params().count(), 16);

  let mut count = 0;
  for param in auth_info([SIXTEEN]) {
    param.expect("sixteen distinct names fit");
    count += 1;
  }
  assert_eq!(count, MAX_PARAMS_PER_CREDENTIAL);
}

#[test]
fn one_parameter_past_the_bound_is_refused_and_not_left_unchecked() {
  // Nothing in this list is malformed and §11.2 bounds it nowhere, so this is
  // a refusal meeting conforming input — which `MAX_PARAMS_PER_CREDENTIAL` says in as
  // many words. The alternative it rules out is worse than a refusal: a walk
  // that stopped CHECKING at the last slot would hand back a list it never
  // established was duplicate-free.
  let [fault, past] = walk::<2>([SEVENTEEN_CHALLENGE]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::TooManyParameters);
  assert!(past.is_none());

  assert_eq!(
    credentials(SEVENTEEN_CHALLENGE).unwrap_err(),
    AuthError::TooManyParameters
  );

  // The streaming walk hands over the sixteen it recorded and then refuses,
  // ending the walk exactly as every other fault on this path does —
  // `one_fault_ends_the_parameter_walk` is that rule for the other faults and
  // this is it for these two. An eighteenth parameter stands BEHIND the
  // refusal and the loop does not break, so the walk's end is asserted rather
  // than borrowed from the input running out: a refusal that left the walk
  // running would hand `p18` over out of a list it had just declared it could
  // not check.
  let mut yielded = 0;
  let mut refusals = 0;
  let mut past = 0;
  for param in auth_info([SEVENTEEN_THEN_ONE_MORE]) {
    match param {
      Ok(_) if refusals == 0 => yielded += 1,
      Err(AuthError::TooManyParameters) if refusals == 0 => refusals += 1,
      _ => past += 1,
    }
  }
  assert_eq!(yielded, MAX_PARAMS_PER_CREDENTIAL);
  assert_eq!(refusals, 1);
  assert_eq!(past, 0, "the walk went on past its own refusal");
}

#[test]
fn a_repeat_at_the_bound_is_reported_as_the_repeat_it_is() {
  // The seventeenth name is `P01`, which folds onto the first slot. Every name
  // before it went INTO a slot — the bound refuses rather than skipping — so
  // the repeat is proven and the fault the sender committed is the one
  // reported, rather than this reader's own limit.
  let [fault, past] = walk::<2>([SEVENTEEN_CHALLENGE_WITH_A_REPEAT]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::DuplicateParameter);
  assert!(past.is_none());

  assert_eq!(
    credentials(SEVENTEEN_CHALLENGE_WITH_A_REPEAT).unwrap_err(),
    AuthError::DuplicateParameter
  );

  let mut fault = None;
  for param in auth_info([SEVENTEEN_WITH_A_REPEAT]) {
    if let Err(e) = param {
      fault = Some(e);
      break;
    }
  }
  assert_eq!(fault, Some(AuthError::DuplicateParameter));
}

#[test]
fn a_challenge_past_the_tracking_bound_is_refused_and_the_next_one_is_read() {
  // A refusal costs the challenge that earned it and nothing behind it, so
  // §11.4's choice still reaches the scheme after it.
  let [fault, newauth, past] =
    walk::<3>([SEVENTEEN_CHALLENGE, b"Newauth realm=\"r\", nonce=\"n\""]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::TooManyParameters);
  let newauth = newauth.unwrap().unwrap();
  assert_eq!(newauth.scheme(), b"Newauth");
  assert_eq!(
    names::<3>(&newauth),
    [Some(&b"realm"[..]), Some(b"nonce"), None]
  );
  assert!(past.is_none());
}

#[test]
fn a_comma_flood_is_not_too_many_parameters() {
  // The distinctive claim of the bound: the empty elements accepted here are
  // UNBOUNDED and spend no slot. RFC 9110 §5.6.1.2's "reasonable number"
  // governs EMPTY elements while `MAX_PARAMS_PER_CREDENTIAL` bounds the names a
  // duplicate check records, so a flood is refused only once it carries that
  // many real parameters, however many empties preceded them. This is the
  // position `a_comma_flood_is_not_too_many_tags` pins for the crate's other
  // bound, extended to this one — an implementation counting empties against
  // the slots passes every list above and fails here.
  let credential = one([FLOODED_SIXTEEN_CHALLENGE]);
  assert_eq!(credential.params().count(), MAX_PARAMS_PER_CREDENTIAL);

  assert_eq!(
    credentials(FLOODED_SIXTEEN_CHALLENGE)
      .unwrap()
      .params()
      .count(),
    MAX_PARAMS_PER_CREDENTIAL
  );

  let mut count = 0;
  for param in auth_info([FLOODED_SIXTEEN]) {
    param.expect("an empty element spends no slot");
    count += 1;
  }
  assert_eq!(count, MAX_PARAMS_PER_CREDENTIAL);
}

#[test]
fn a_token68_credential_spends_no_slot() {
  // §11.2's two alternatives are exclusive, so the branch that takes no list
  // records no name — which is what `MAX_PARAMS_PER_CREDENTIAL` says it does not
  // count. A `token68` long enough to have been many parameters is still one
  // value.
  let credential = credentials(b"Basic bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb==").unwrap();
  assert!(credential.token68().is_some());
  assert_eq!(credential.params().count(), 0);
}
