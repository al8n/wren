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

  // The same bytes on ONE field line, where this has always been the answer:
  // `auth_param` refuses a quoted-string with bytes behind its close. RFC 9110
  // §5.2's join is a way of writing the value and not a way past the rule, and
  // the pair of them is the whole point of the fix.
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
  let [broken, newauth, past] = walk::<3>([&b"Basic a=\"x\x00y\", Newauth b=1"[..]]);
  assert_eq!(broken.unwrap().unwrap_err(), AuthError::InvalidQuotedString);
  assert_eq!(newauth.unwrap().unwrap().scheme(), b"Newauth");
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

  // And the shape this rule once cost, which the module doc's invariant took
  // back. `Basic ",a=", Digest realm=z` hid `Digest`: an unadmitted DQUOTE
  // stopped pairing with a later one, which left the next ADMITTED position —
  // the value of `a=` — free to open a string RFC 9110 §5.6.4 ran to the end
  // of the value. It cannot now, because the element in front of it is the one
  // byte `"` that no production derives: the challenge is refused there, and
  // everything behind that refusal is read to raw commas.
  let [broken, digest, past] = walk::<3>([&b"Basic \",a=\", Digest realm=z"[..]]);
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

#[test]
fn every_way_a_challenge_is_refused_hides_no_challenge_behind_it() {
  // The module doc's invariant, driven through every fault that refuses a
  // challenge while the walk is still deciding where that challenge ends. Each
  // value below is a challenge refused for a different reason, then `TRAP`,
  // then `Digest`. RFC 9110 §11.4 has a user agent select "the challenge with
  // what it considers to be the most secure auth-scheme that it understands",
  // so every one of them must still reach `Digest`.
  //
  // `TRAP` is a well-formed opener in its own right — the control above proves
  // it hides `Digest` when nothing precedes it — so what saves `Digest` here is
  // that the refusal in front of it takes the rest of the challenge raw.
  let trap = || {
    let mut tail = b", ".to_vec();
    tail.extend_from_slice(TRAP);
    tail
  };
  for (head, fault) in [
    // A value that closed across §5.2's join with bytes behind that close.
    // This is the reviewer's own reproducer, whose first line ends inside the
    // string and whose second closes it and then runs on.
    (&b"Basic a=\"x,y\"junk"[..], AuthError::MalformedParameter),
    // The same fault with the close and the junk on ONE line.
    (b"Basic a=\"x\"j", AuthError::MalformedParameter),
    // An element that is no `auth-param` at all: two `=` where the production
    // admits one value.
    (b"Basic a=b=c", AuthError::MalformedParameter),
    // A value that is neither of §11.2's alternatives taken whole.
    (b"Basic a=x y", AuthError::MalformedParameter),
    // A `token68` run where the body holds more than the run.
    (b"Basic dGVzdA==", AuthError::MalformedParameter),
    // §11.2's one-name-once MUST.
    (b"Basic a=1, a=2", AuthError::DuplicateParameter),
  ] {
    let mut value = head.to_vec();
    value.extend_from_slice(&trap());
    let [refused, digest, past] = walk::<3>([value.as_slice()]);
    assert_eq!(refused.unwrap().unwrap_err(), fault, "{head:?}");
    assert_eq!(
      digest.unwrap().unwrap().scheme(),
      b"Digest",
      "the challenge behind {head:?}"
    );
    assert!(past.is_none(), "{head:?}");
  }

  // The reviewer's reproducer as it was written: two field lines, the value
  // opening on the first and closing on the second with `junk` behind the
  // close. §5.2 joins them with a comma, so this is the same value as the
  // one-line spelling above and answers the same way.
  let mut tail = b"r\"junk, ".to_vec();
  tail.extend_from_slice(TRAP);
  let [refused, digest, past] = walk::<3>([&b"Basic a=\"q"[..], tail.as_slice()]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::MalformedParameter);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // One parameter past MAX_PARAMS_PER_CREDENTIAL, which is this reader's own
  // bound rather than a fault of the sender's — and refuses the challenge just
  // the same, so the same recovery has to follow it.
  let mut value = SEVENTEEN_CHALLENGE.to_vec();
  value.extend_from_slice(&trap());
  let [refused, digest, past] = walk::<3>([value.as_slice()]);
  assert_eq!(refused.unwrap().unwrap_err(), AuthError::TooManyParameters);
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // One field line past MAX_CHALLENGE_LINES, the other bound of this reader's,
  // with the trap on the line behind the one that overran.
  let mut lines = [&b""[..]; 18];
  lines[..SEVENTEEN_LINES.len()].copy_from_slice(&SEVENTEEN_LINES);
  lines[17] = TRAP;
  let [refused, digest, past] = walk::<3>(lines);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The same bound, met at the crossing where the challenge's own value is
  // still OPEN across §5.2's join. `TRAP` is not the trap for this one: the
  // walk stands INSIDE a string that its DQUOTE would close, so it would spring
  // a different case. What hides `Digest` here is the open string itself —
  // every byte behind the bound is data of it, the comma in front of `Digest`
  // included — so the line behind the bound is ordinary text and reaching
  // `Digest` at all means the walk stopped where the challenge outgrew what it
  // may hold.
  let mut open_at_the_bound = [&b"j"[..]; 18];
  open_at_the_bound[0] = b"Basic a=\"x";
  open_at_the_bound[17] = b"p, Digest realm=z";
  let [refused, digest, past] = walk::<3>(open_at_the_bound);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // And the way that used to be the exception: a byte RFC 9110 §5.6.4 forbids
  // INSIDE a string that legitimately opened. It is recovered from like every
  // other refusal now, and `TRAP` is the trap for it exactly as it is for the
  // rows above — the DQUOTE in `trap="open` swallows the comma in front of
  // `Digest` for any recovery that reads a refused run as a quoted-string, and
  // this one does not read a refused run at all.
  let mut value = b"Basic a=\"x\x00y\", ".to_vec();
  value.extend_from_slice(TRAP);
  let [refused, digest, past] = walk::<3>([value.as_slice()]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The same byte met on the far side of §5.2's join, where the string opened
  // on one field line and the forbidden byte stands first on the next.
  let [refused, digest, past] = walk::<3>([&b"Basic a=\"x"[..], b"\x00, Digest realm=z"]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
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
  // `quoted-pair` may escape, so the value derives nothing, the challenge is
  // refused, and the comma the sender wrote inside the realm ends the refused
  // run. What the recovery reaches here is a fault and not a challenge —
  // `realm=z"` is no parameter, since the DQUOTE that would have closed the
  // realm is still in the run — and the `obs-text` rows above are never
  // recovered from at all.
  let [refused, malformed, past] = walk::<3>([&b"Basic realm=\"a\x00b, Digest realm=z\""[..]]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(
    malformed.unwrap().unwrap_err(),
    AuthError::MalformedParameter
  );
  assert!(past.is_none());
}

#[test]
fn where_a_forbidden_byte_is_recovered_from_is_where_the_scan_stood() {
  // A KNOWN cost of recovering by raw commas from where the scan stands, kept
  // visible rather than left to be found: RFC 9110 §5.2 makes these two field
  // line lists ONE value, and they do not answer the same.
  //
  // On one line the scan never advanced past the element, so the cursor is on
  // the element's first byte and the first raw comma from there is the one
  // inside the realm — `Digest realm=z` stands behind it and is yielded.
  let one_line = &b"Basic realm=\"ab, Digest realm=z, \x00c\""[..];
  let [refused, digest, missing, past] = walk::<4>([one_line]);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert_eq!(missing.unwrap().unwrap_err(), AuthError::MissingScheme);
  assert!(past.is_none());

  // Split at that same comma, the element's earlier bytes are on a field line
  // this walk no longer holds, so the cursor is on the first byte of the line
  // the scan choked on — and `Digest realm=z` stands in FRONT of the first raw
  // comma there, which puts it inside the refused run.
  let split: [&[u8]; 2] = [b"Basic realm=\"ab", b" Digest realm=z, \x00c\""];
  let [refused, missing, past] = walk::<3>(split);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(missing.unwrap().unwrap_err(), AuthError::MissingScheme);
  assert!(past.is_none());

  // What makes it a cost and not a defect: the challenge the split spelling
  // does not show is one NO derivation of the value puts there either. The
  // value carries a byte RFC 9110 §5.5 admits nowhere in one, so
  // `Digest realm=z` is neither a challenge nor the data of a value. Both
  // spellings show at least what they showed before this fault refused rather
  // than ended the walk, which was nothing. Making them agree needs the OFFSET
  // the scan choked at, which `QuotedScan::Invalid` does not carry.
  //
  // The control that says the two spellings are otherwise one value: with the
  // forbidden byte gone, both are one challenge with one realm.
  let clean_one_line: [&[u8]; 1] = [b"Basic realm=\"ab, Digest realm=z, c\""];
  let clean_split: [&[u8]; 2] = [b"Basic realm=\"ab", b" Digest realm=z, c\""];
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

#[test]
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

  // And the row that used to be the one that did not continue. It does now:
  // the argument for stopping was that a failed quoted-string scan can no
  // longer tell which commas were separators, which is the premise raw-comma
  // recovery answers — and the byte it fails on is one RFC 9110 §5.5 admits
  // nowhere in a field value, so there is no reading of what follows for the
  // recovery to be wrong about.
  let [fault, newauth, past] = walk::<3>([&b"Basic a=\"x\x00y\", Newauth b=1"[..]]);
  assert_eq!(fault.unwrap().unwrap_err(), AuthError::InvalidQuotedString);
  assert_eq!(
    newauth.unwrap().unwrap().scheme(),
    b"Newauth",
    "§11.4's user agent is shown the challenge behind a forbidden byte too"
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
  // met at the crossing itself, and what is left of the challenge is found by
  // raw commas like every other refusal.
  //
  // One value opens on the first line here and every continuation keeps it
  // open, so the SEVENTEENTH region is the one that does not fit — and the
  // line behind it carries a byte §5.6.4 forbids and then a challenge. The
  // fault reported is the bound and not the byte, because the bound is met at
  // the crossing and the byte stands on the line that crossing could not hold.
  let mut too_many = [&b"j"[..]; 18];
  too_many[0] = b"Basic a=\"x";
  too_many[17] = b"\x00, Digest realm=z";
  let [refused, digest, past] = walk::<3>(too_many);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // ONE line fewer is sixteen regions, and there the byte IS read — the region
  // it stands on is one this challenge holds. Both faults refuse and recover,
  // so `Digest` survives either way and the FAULT is the whole of what tells
  // the two rows apart: this pair says the refusal above is the bound being met
  // FIRST rather than the byte being unreachable, and an edit that made the
  // bound fire a line late would answer `InvalidQuotedString` here as well.
  let mut within = [&b"j"[..]; 17];
  within[0] = b"Basic a=\"x";
  within[16] = b"\x00, Digest realm=z";
  let [refused, digest, past] = walk::<3>(within);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::InvalidQuotedString
  );
  assert_eq!(digest.unwrap().unwrap().scheme(), b"Digest");
  assert!(past.is_none());

  // The cursor stands at the FIRST byte of the line the challenge could not
  // hold, so what that line carries in front of its first raw comma is still
  // the refused challenge's. A `Digest` with no comma in front of it on that
  // line is inside the refused run and is not yielded — the cost of recovering
  // raw, and the assertion an edit that moved the cursor elsewhere fails.
  let mut swallowed = [&b"j"[..]; 18];
  swallowed[0] = b"Basic a=\"x";
  swallowed[17] = b"Digest realm=z";
  let [refused, past] = walk::<2>(swallowed);
  assert_eq!(
    refused.unwrap().unwrap_err(),
    AuthError::ChallengeSpansTooManyLines
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
  // that element's bytes are read.
  let mut refused_at_the_join = [&b"j"[..]; 18];
  refused_at_the_join[0] = b"Basic a=\"x";
  refused_at_the_join[16] = b"y\"";
  refused_at_the_join[17] = b"t=\"open, Digest realm=z";
  let [refused, digest, past] = walk::<3>(refused_at_the_join);
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
  // is the order `Challenges::challenge` was redesigned out of. It is safe
  // here for two reasons, and this drives the load-bearing one: the walk stops
  // at the first fault, so no byte behind one is ever read and no DQUOTE
  // behind one can decide where anything ends.
  //
  // The shape is round 3's, spelled for `#auth-param`: an element that derives
  // nothing, and a DQUOTE at §11.2's own value position in the element behind
  // it. In a `#challenge` value that DQUOTE swallowed the comma in front of a
  // later challenge; here the walk never reaches it, so `b` is never read at
  // all and the fault reported is the one the SENDER committed at `a`.
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
