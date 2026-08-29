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
/// [`MAX_TRACKED_PARAMS`] slots hold.
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
  assert_eq!(MAX_TRACKED_PARAMS, 16);

  let credential = one([SIXTEEN_CHALLENGE]);
  assert_eq!(credential.params().count(), MAX_TRACKED_PARAMS);
  assert_eq!(credentials(SIXTEEN_CHALLENGE).unwrap().params().count(), 16);

  let mut count = 0;
  for param in auth_info([SIXTEEN]) {
    param.expect("sixteen distinct names fit");
    count += 1;
  }
  assert_eq!(count, MAX_TRACKED_PARAMS);
}

#[test]
fn one_parameter_past_the_bound_is_refused_and_not_left_unchecked() {
  // Nothing in this list is malformed and §11.2 bounds it nowhere, so this is
  // a refusal meeting conforming input — which `MAX_TRACKED_PARAMS` says in as
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
  assert_eq!(yielded, MAX_TRACKED_PARAMS);
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
  // governs EMPTY elements while `MAX_TRACKED_PARAMS` bounds the names a
  // duplicate check records, so a flood is refused only once it carries that
  // many real parameters, however many empties preceded them. This is the
  // position `a_comma_flood_is_not_too_many_tags` pins for the crate's other
  // bound, extended to this one — an implementation counting empties against
  // the slots passes every list above and fails here.
  let credential = one([FLOODED_SIXTEEN_CHALLENGE]);
  assert_eq!(credential.params().count(), MAX_TRACKED_PARAMS);

  assert_eq!(
    credentials(FLOODED_SIXTEEN_CHALLENGE)
      .unwrap()
      .params()
      .count(),
    MAX_TRACKED_PARAMS
  );

  let mut count = 0;
  for param in auth_info([FLOODED_SIXTEEN]) {
    param.expect("an empty element spends no slot");
    count += 1;
  }
  assert_eq!(count, MAX_TRACKED_PARAMS);
}

#[test]
fn a_token68_credential_spends_no_slot() {
  // §11.2's two alternatives are exclusive, so the branch that takes no list
  // records no name — which is what `MAX_TRACKED_PARAMS` says it does not
  // count. A `token68` long enough to have been many parameters is still one
  // value.
  let credential = credentials(b"Basic bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb==").unwrap();
  assert!(credential.token68().is_some());
  assert_eq!(credential.params().count(), 0);
}
