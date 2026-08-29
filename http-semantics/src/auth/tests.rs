use super::*;
use crate::grammar::{ListError, parameterised_list};

/// [`auth_param`] over an element held whole — one field line's worth, with
/// nothing behind it that RFC 9110 §5.2's join could add. A quoted-string this
/// element leaves open therefore has nothing left that could close it, which is
/// the reading every test above the cross-line block wants.
fn auth_param_alone(element: &[u8]) -> Result<AuthParam<'_>, AuthError> {
  auth_param(element, ValueTail::Ends)
}

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
  let mut members = parameterised_list([&br#"m;realm = "x""#[..]]);
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
  // The regression the design names: a challenge must not lose its scheme, its
  // realm and its nonce because one parameter a caller may never read is not
  // one slice.
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

  // A string that DID close across the join does not rescue the element when a
  // later one on the same line never closes. What the combined value ends
  // INSIDE is what decides, so this is unterminated too, and not a value that
  // merely spans field lines.
  assert_eq!(
    read_credential([&b"Basic a=\"x"[..], b"y\" \"z"]).unwrap_err(),
    AuthError::UnterminatedQuotedString
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
  // The design document says instead that the escape carried across the join
  // is what makes such a DQUOTE data. It is not, and the two answers are one
  // input apart: `scan_quoted_after_join` feeds the join's comma THROUGH the
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
  // On the far side of the join, past the DQUOTE that closed that string,
  // while the rest of the element is walked to the comma that ends it.
  assert_eq!(
    read_credential([&b"Basic a=\"x"[..], b"y\" \"\x00\""]).unwrap_err(),
    AuthError::InvalidQuotedString
  );
  // And in a LATER element, once the spanning one has been handed over: the
  // walk goes on from where that element ended, on the line it ended on.
  assert_eq!(
    read_credential([&b"Basic a=\"x"[..], b"y\", b=\"\x00\""]).unwrap_err(),
    AuthError::InvalidQuotedString
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

  // And the row that does not continue. Every boundary this walk finds is a
  // comma outside a quoted-string, so once a quoted-string scan has failed it
  // can no longer tell which commas were separators.
  let [fault, past] = walk::<2>([&b"Basic a=\"x\x00y\", Newauth b=1"[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::InvalidQuotedString);
  assert!(past.is_none(), "nothing behind a forbidden byte is read");

  // Including where it is the SEEK past an already-reported challenge that
  // meets it: the first fault is reported, and then the walk stops on the
  // second rather than guessing at the commas behind it.
  let [basic, malformed, invalid, past] =
    walk::<4>([&b"Basic, type=1, x=\"a\x00b\", Newauth c=1"[..]]);
  assert_eq!(basic.unwrap().unwrap().scheme(), b"Basic");
  assert_eq!(malformed.unwrap().unwrap_err(), AuthError::MalformedScheme);
  assert_eq!(
    invalid.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
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
  // `Basic real,m=x`, and at that comma `m` has an `=` behind it, so the
  // challenge goes on and `real` is a parameter name with no value.
  let [fault, past] = walk::<2>([&b"Basic real"[..], b"m=x"]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::MalformedParameter);
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
}
