use super::*;

// RFC 9110 §5.6.2: tchar set exactness — probe boundaries.
#[test]
fn tchar_boundaries() {
  // `!#$%&'*+-.^_`|~` plus the digit/alpha range edges — spelled as a byte
  // string because every probe here is printable (clippy::byte_char_slices).
  for b in *b"!#$%&'*+-.^_`|~09azAZ" {
    assert!(is_token_byte(b), "{b:#x} must be tchar");
  }
  for b in [
    b' ', b'\t', b'"', b'(', b')', b',', b'/', b':', b';', b'<', b'=', b'>', b'?', b'@', b'[',
    b'\\', b']', b'{', b'}', 0x7F, 0x00, 0x80,
  ] {
    assert!(!is_token_byte(b), "{b:#x} must NOT be tchar");
  }
}

// RFC 9110 §5.5: obs-text (0x80-0xFF) IS valid field content; CTLs are not.
#[test]
fn field_value_accepts_obs_text_rejects_ctls() {
  assert!(validate_field_value(b"caf\xC3\xA9").is_ok()); // UTF-8 bytes
  assert!(validate_field_value(b"\xFF\x80").is_ok()); // raw obs-text
  assert!(validate_field_value(b"a b\tc").is_ok()); // interior SP/HTAB
  assert_eq!(validate_field_value(b"a\x00b"), Err(1)); // NUL
  assert_eq!(validate_field_value(b"a\x0Bb"), Err(1)); // VT
  assert_eq!(validate_field_value(b"a\rb"), Err(1)); // bare CR
  assert_eq!(validate_field_value(b"a\nb"), Err(1)); // bare LF
}

// RFC 9110 §5.6.3: OWS surrounds a field value; it is not part of the value.
#[test]
fn trim_ows_both_ends_only() {
  assert_eq!(trim_ows(b" \t v v \t "), b"v v");
  assert_eq!(trim_ows(b""), b"");
  assert_eq!(trim_ows(b" \t "), b"");
}

// RFC 9110 §5.6.1: case-insensitive token comparison (Connection/Upgrade/TE).
#[test]
fn token_list_contains_is_case_insensitive() {
  assert!(token_list_contains(b"Keep-Alive, Upgrade", "upgrade"));
  assert!(!token_list_contains(b"keep-alive-x", "keep-alive"));
}

// Ported validators keep behavior: spot-check + boundary cases.
#[test]
fn ported_target_validators() {
  assert!(is_valid_path_and_query("/chat?x=1"));
  assert!(!is_valid_path_and_query("/sp ace"));
  assert!(is_valid_authority("example.com:443"));
  assert!(is_valid_authority("[::1]:8080"));
  assert!(!is_valid_authority("bad host"));
}

#[test]
fn parameterised_list_refuses_what_does_not_parse() {
  // A name that is not a token.
  assert_eq!(
    parameterised_list([b"ext@1".as_slice()], ParamSyntax::Parameter)
      .next()
      .unwrap()
      .unwrap_err(),
    ListError::NotAToken
  );
  // An unterminated quoted string.
  assert_eq!(
    parameterised_list(
      [b"ext; q=\"unterminated".as_slice()],
      ParamSyntax::Parameter
    )
    .next()
    .unwrap()
    .unwrap()
    .params()
    .next()
    .unwrap()
    .unwrap_err(),
    ListError::UnterminatedQuotedString
  );
  // A parameter name that is not a token.
  assert_eq!(
    parameterised_list([b"ext; @=1".as_slice()], ParamSyntax::Parameter)
      .next()
      .unwrap()
      .unwrap()
      .params()
      .next()
      .unwrap()
      .unwrap_err(),
    ListError::NotAToken
  );
}

// A quoted-string that crosses the §5.2 join and is STILL open when the last
// field line ends is `UnterminatedQuotedString`, and NOT `ValueSpansFieldLines`.
// The two are not interchangeable: `ValueSpansFieldLines` says the value is well
// formed and merely not one slice, because it closed on a later line, while this
// one closes nowhere and §5.2 has no further line to continue it with — a §5.6.4
// violation. Collapsing them reports a broken value as a borrowing limitation.
#[test]
fn a_quoted_value_that_crosses_the_join_and_never_closes_is_unterminated() {
  let lines: [&[u8]; 2] = [b"ext; q=\"a", b"b"];
  let mut members = parameterised_list(lines, ParamSyntax::Parameter);
  let member = members.next().unwrap().unwrap();
  // The boundary scan did cross the join: both lines are still ONE member.
  assert_eq!(member.name(), b"ext");
  assert_eq!(
    member.params().next().unwrap().unwrap_err(),
    ListError::UnterminatedQuotedString
  );
  assert!(members.next().is_none());
}

// RFC 9110 §5.6.6: `parameters = *( OWS ";" OWS [ parameter ] )` — the
// `[ parameter ]` is optional, so a `;` with nothing behind it states no
// parameter rather than violating the production.
#[test]
fn an_empty_parameter_is_skipped_not_a_violation() {
  let member = parameterised_list([b"ext; ; q=1;".as_slice()], ParamSyntax::Parameter)
    .next()
    .unwrap()
    .unwrap();
  let mut params = member.params();
  assert!(matches!(
    params.next().unwrap(),
    Ok((b"q", ParamValue::Token(b"1")))
  ));
  assert!(params.next().is_none());

  let member = parameterised_list([b"ext;;".as_slice()], ParamSyntax::Parameter)
    .next()
    .unwrap()
    .unwrap();
  assert_eq!(member.name(), b"ext");
  assert!(member.params().next().is_none());
}

#[test]
fn a_supplied_predicate_admits_a_name_is_token_refuses() {
  fn solidus_ok(name: &[u8]) -> bool {
    match name.iter().position(|b| *b == b'/') {
      Some(at) => match (name.get(..at), name.get(at.saturating_add(1)..)) {
        (Some(ty), Some(sub)) => is_token(ty) && is_token(sub),
        _ => false,
      },
      None => false,
    }
  }

  // `is_token` refuses this today, which is the whole of issue #42.
  assert!(!is_token(b"application/json"));

  let mut walk = parameterised_list_with(
    [b"application/json;charset=utf-8".as_slice()],
    solidus_ok,
    ParamSyntax::Parameter,
    ValuelessParameter::Reported,
  );
  let member = walk
    .next()
    .expect("one member")
    .expect("the predicate admits it");
  assert_eq!(member.name(), b"application/json");
  let mut params = member.params();
  assert!(matches!(
    params.next().expect("one parameter").expect("well formed"),
    (b"charset", ParamValue::Token(b"utf-8"))
  ));
  assert!(params.next().is_none());
  assert!(walk.next().is_none());
}

#[test]
fn parameterised_list_still_refuses_a_non_token_name() {
  let mut walk = parameterised_list([b"application/json".as_slice()], ParamSyntax::Parameter);
  assert_eq!(
    walk.next().expect("one member").unwrap_err(),
    ListError::NotAToken
  );
}

// RFC 9110 §5.6.6's `parameter-value = ( token / quoted-string )` takes ONE
// alternative WHOLE, and §5.2's join is not a way past that. These two field
// lines join to `ext;q="a,"junk`: the string closes at the second DQUOTE and
// `junk` stands behind a completed value, so the value is not derivable.
// Reporting `ValueSpansFieldLines` for it would say the opposite — that variant
// names a value that is well formed and merely not one slice to borrow — and
// the bytes behind the close were dropped without a word.
#[test]
fn a_value_that_closes_across_the_join_and_runs_on_is_malformed() {
  let lines: [&[u8]; 2] = [b"ext;q=\"a", b"\"junk"];
  let member = parameterised_list(lines, ParamSyntax::Parameter)
    .next()
    .expect("one member")
    .expect("its name is a token");
  assert_eq!(member.name(), b"ext");
  assert_eq!(
    member.params().next().expect("one parameter").unwrap_err(),
    ListError::NotAToken,
    "the same fault the walk reports when the close and the bytes behind it \
     lie on ONE field line"
  );
}

// And what those refused bytes may NOT do is decide where the member ends. The
// value of `q` closes at `r"`; `ju` stands behind it, so the remainder derives
// nothing — and a run that derives nothing holds no quoted-string, so the
// DQUOTE inside `ju"nk` opens none and the comma in front of `second` is the
// §5.6.1.2 separator it looks like. Reading that DQUOTE as an opener swallowed
// the comma, and `second` — a media type, a coding, or an extension, depending
// on the field — was never yielded at all.
#[test]
fn a_refused_remainder_does_not_swallow_the_member_behind_it() {
  let lines: [&[u8]; 2] = [b"ext;q=\"a", b"r\"ju\"nk, second"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  let member = walk
    .next()
    .expect("one member")
    .expect("its name is a token");
  assert_eq!(member.name(), b"ext");
  assert_eq!(
    member.params().next().expect("one parameter").unwrap_err(),
    ListError::NotAToken
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind the refused bytes")
      .expect("well formed")
      .name(),
    b"second"
  );
  assert!(walk.next().is_none());

  // A DQUOTE in the refused run that PAIRS with a later one is the same rule
  // again: `ju"nk` above had no partner, and `j"unk … x"y` has one. Reading the
  // two of them as a string swallows both commas at once, and `second` — a
  // member that parses on its own — is never shown to the caller.
  let lines: [&[u8]; 2] = [b"ext;q=\"a", b"\"j\"unk, second, x\"y"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  assert_eq!(
    walk
      .next()
      .expect("one member")
      .expect("its name is a token")
      .name(),
    b"ext"
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind the paired DQUOTEs")
      .expect("well formed")
      .name(),
    b"second"
  );

  // But the `;` that opens RFC 9110 §5.6.6's next repetition is read, and what
  // stands behind it decides whether there is an answer to give. `r="b` puts a
  // DQUOTE at the one position `parameter-value = ( token / quoted-string )`
  // admits one, and the string it opens never closes on the line in hand — so
  // the reading that opens it reaches no comma at all, while the raw reading
  // ends the member at the one in front of `second`. Two readings, two answers,
  // and no rule that picks between them. The walk says so rather than choosing:
  // `second` is not yielded, and the caller is told the value stopped being
  // readable rather than being left to think it ended.
  let lines: [&[u8]; 2] = [b"ext;q=\"a", b"\"junk; r=\"b, second"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  let member = walk
    .next()
    .expect("one member")
    .expect("its name is a token");
  assert_eq!(
    member.params().next().expect("one parameter").unwrap_err(),
    ListError::NotAToken
  );
  assert_eq!(
    walk
      .next()
      .expect("the walk says why it stopped")
      .unwrap_err(),
    ListError::MemberBoundaryUnknown
  );
  assert!(walk.next().is_none());
}

// RFC 9110 §5.6.6 hangs `OWS` on both sides of the `;`
// (`parameters = *( OWS ";" OWS [ parameter ] )`) and §5.6.1.2 hangs it on both
// sides of the `,`, so whitespace between a value's closing DQUOTE and either
// delimiter is the list's own. A close that treated it as bytes behind the value
// would refuse `ext;p="a" ; q=2 , other`, which violates nothing.
#[test]
fn ows_between_a_closing_dquote_and_the_next_delimiter_is_the_lists() {
  let mut walk = parameterised_list(
    [b"ext;p=\"a\" ; q=2 , other".as_slice()],
    ParamSyntax::Parameter,
  );
  let member = walk.next().expect("one member").expect("well formed");
  assert_eq!(member.name(), b"ext");
  let mut params = member.params();
  assert!(matches!(
    params.next().expect("p").expect("well formed"),
    (b"p", ParamValue::Quoted(b"a"))
  ));
  assert!(matches!(
    params.next().expect("q").expect("well formed"),
    (b"q", ParamValue::Token(b"2"))
  ));
  assert!(params.next().is_none());
  assert_eq!(
    walk
      .next()
      .expect("the member behind it")
      .expect("well formed")
      .name(),
    b"other"
  );

  // The same whitespace across RFC 9110 §5.2's join, where the verdict on those
  // bytes is the one thing the member's own slice cannot carry.
  let lines: [&[u8]; 2] = [b"ext;p=\"a", b"\" ; q=2, other"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  assert_eq!(
    walk
      .next()
      .expect("one member")
      .expect("well formed")
      .params()
      .next()
      .expect("one parameter")
      .unwrap_err(),
    ListError::ValueSpansFieldLines,
    "`p`'s value closed cleanly; only the `OWS` behind it stood in the way"
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind it")
      .expect("well formed")
      .name(),
    b"other"
  );
}

// RFC 9110 §5.6.6 admits a quoted-string at exactly ONE position — the first
// byte of a `parameter-value` — because §5.6.2's `tchar` and §5.6.3's `OWS` both
// exclude DQUOTE and this walk's member names are built out of `tchar` and `/`.
// A DQUOTE anywhere else opens no string, so it decides no boundary. Each shape
// below hid `second` while the boundary scan read every DQUOTE as an opener.
#[test]
fn a_dquote_opens_no_string_where_the_grammar_admits_none() {
  // The value already took the `token` alternative.
  let one_line: [&[u8]; 4] = [
    b"ext;q=x\"y, second",
    // Behind a value that already closed.
    b"ext;q=\"a\"\"b, second",
    // At a `parameter-name`, which §5.6.6 spells `token`.
    b"ext;q\"x, second",
    // At a `parameter-name` carrying a byte §5.6.4 would have forbidden inside
    // a string — which is no fault of §5.6.4's, since no string is open.
    b"ext;q\"\x00, second",
  ];
  for field in one_line {
    let mut walk = parameterised_list([field], ParamSyntax::Parameter);
    let member = walk
      .next()
      .expect("one member")
      .expect("its name is a token");
    assert_eq!(member.name(), b"ext", "{field:?}");
    assert_eq!(
      member.params().next().expect("one parameter").unwrap_err(),
      ListError::NotAToken,
      "{field:?}"
    );
    assert_eq!(
      walk
        .next()
        .expect("the member behind the unadmitted DQUOTE")
        .expect("well formed")
        .name(),
      b"second",
      "{field:?}"
    );
  }

  // And the same DQUOTE may not hold the member open ACROSS §5.2's join: it
  // opened no string, so there is nothing for the next field line to continue.
  let lines: [&[u8]; 2] = [b"ext;q=x\"y", b"second"];
  let names: [&[u8]; 2] = [b"ext", b"second"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  for want in names {
    assert_eq!(
      walk
        .next()
        .expect("a member")
        .expect("its name is a token")
        .name(),
      want
    );
  }
  assert!(walk.next().is_none());
}

// The rule is stated at BOTH of this grammar's delimiter levels, and this is why
// the `;` one cannot be left out. `parameters = *( OWS ";" OWS [ parameter ] )`
// repeats, so a value that closed across §5.2's join may be followed by another
// `parameter` — and THAT one admits a quoted-string of its own, commas and all.
// A join that answered `Closed` by scanning for the next raw comma would cut
// this member inside the value of `q`, inventing a member the sender never
// wrote; one that answered it with a quote-aware scan would grant string
// semantics to bytes no production admits. Only the repetition read as the
// repetition it is answers both.
#[test]
fn parameters_repeat_after_a_value_that_closed_across_the_join() {
  let lines: [&[u8]; 2] = [b"ext;p=\"a", b"\"; q=\"b, c\", second"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  let member = walk
    .next()
    .expect("one member")
    .expect("its name is a token");
  assert_eq!(member.name(), b"ext");
  assert_eq!(
    member.params().next().expect("one parameter").unwrap_err(),
    ListError::ValueSpansFieldLines,
    "`p`'s value closed cleanly across the join and is simply not one slice"
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind `q`'s quoted comma")
      .expect("well formed")
      .name(),
    b"second"
  );
  assert!(walk.next().is_none());
}

// `QuotedTail` reports the head line's OWN string and not the last one the walk
// carried across a join. Here `p`'s value closes cleanly with a `;` behind it —
// so `p` is well formed and merely not contiguous — and `q`, a parameter on a
// line this walk hands nothing out from, is the one that runs on past its close.
// `QuotedTail` still says nothing about `q`: the two are told apart by the
// member's own `joined` fault, which is where a parameter behind the join is
// answered.
//
// What the member may NOT do is read as well formed. RFC 9110 §5.6.6's
// `parameter-value = ( token / quoted-string )` takes one alternative whole, so
// `q` derives nothing — and `ListError::ValueSpansFieldLines` is this walk's
// one verdict that says the value is well formed and merely not contiguous, so
// a caller that recovers from it would accept a member §5.6.6 refuses. The
// fault is reported at the parameter the walk reached, and names the member's
// parameter section rather than that one parameter; what it may not do is
// disappear.
#[test]
fn a_later_parameters_trailing_bytes_are_reported_and_not_as_its_own() {
  let lines: [&[u8]; 3] = [b"ext;p=\"a", b"\"; q=\"b", b"\"junk, second"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  let member = walk
    .next()
    .expect("one member")
    .expect("its name is a token");
  assert_eq!(member.name(), b"ext");
  assert_eq!(
    member.params().next().expect("one parameter").unwrap_err(),
    ListError::NotAToken
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind it")
      .expect("well formed")
      .name(),
    b"second"
  );
}

// `has_bare_comma` answers through the same `member_end` the walk behind it
// uses, so the two cannot disagree about which commas are data. A DQUOTE at a
// position §5.6.6 admits no string at hides no comma from it, and a value it
// called singular while the walk yielded two members would be a `Content-Type`
// refused by neither.
#[test]
fn has_bare_comma_sees_a_comma_no_quoted_string_admits() {
  // The value of `p` already took the `token` alternative.
  assert!(has_bare_comma(
    b"text/plain;p=x\"y,z\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  // Behind a value that already closed.
  assert!(has_bare_comma(
    b"text/plain;p=\"a\"junk,z",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  // And the commas that ARE data stay data, through as many repetitions of
  // `parameters` as the member has.
  assert!(!has_bare_comma(
    b"text/plain;p=\"a,b\";q=\"c,d\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));

  // The `=` is what makes a value position a value position. `p "a,b"` reaches
  // no `parameter-value` at all, so the DQUOTE behind `p ` opens nothing.
  assert!(has_bare_comma(
    b"text/plain;p \"a,b\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));

  // And §5.6.6 puts no whitespace on either side of that `=` — "Parameters do
  // not allow whitespace (not even "bad" whitespace) around the "=" character."
  // RFC 9110 §11.2's `auth-param` DOES carry `BWS` there, and reading §11.2's
  // rule here would hide both of these commas.
  assert!(has_bare_comma(
    b"text/plain;p =\"a,b\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  assert!(has_bare_comma(
    b"text/plain;p= \"a,b\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
}

#[test]
fn has_bare_comma_ignores_a_comma_inside_a_quoted_string() {
  assert!(!has_bare_comma(
    b"text/plain;boundary=\"a,b\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  assert!(has_bare_comma(
    b"text/plain, text/html",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  assert!(has_bare_comma(
    b"text/plain,",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  assert!(!has_bare_comma(
    b"text/plain",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
}

// RFC 9110 §10.1.4 spells the OTHER `parameter` this walk serves, and the
// difference is `BWS`:
//
// ```text
// TE                 = #t-codings
// t-codings          = "trailers" / ( transfer-coding [ weight ] )
// transfer-coding    = token *( OWS ";" OWS transfer-parameter )
// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
// ```
//
// RFC 9112 §7 gives `Transfer-Encoding` the same `transfer-coding`, and RFC
// 9110 §5.6.3 makes reading that whitespace a recipient's MUST: "A recipient
// MUST parse for such bad whitespace and remove it before interpreting the
// protocol element." So `gzip;p = "a,b"` is ONE conforming coding whose
// parameter value is the quoted-string `a,b`, and the comma in it is data.
//
// Deriving the boundary from §5.6.6's narrower `parameter` cut the member at
// that comma, invented a member `b"`, and — because this walk poisons on any
// `Err` — never yielded the `chunked` written behind it. On a
// `Transfer-Encoding` that is a hidden final coding, which is a framing
// decision two recipients would then make differently.
#[test]
fn a_transfer_parameters_bws_does_not_cut_a_member_at_a_quoted_comma() {
  for field in [
    b"gzip;p = \"a,b\", chunked".as_slice(),
    // Each side of the `=` on its own, and HTAB as well as SP — §5.6.3's
    // `BWS = OWS` and `OWS = *( SP / HTAB )`.
    b"gzip;p =\"a,b\", chunked",
    b"gzip;p= \"a,b\", chunked",
    b"gzip;p\t=\t\"a,b\", chunked",
    b"gzip;p   =   \"a,b\", chunked",
  ] {
    let mut walk = parameterised_list([field], ParamSyntax::TransferParameter);
    let coding = walk
      .next()
      .expect("the first coding")
      .expect("gzip is a token");
    assert_eq!(coding.name(), b"gzip", "{field:?}");
    assert!(
      matches!(
        coding
          .params()
          .next()
          .expect("one transfer-parameter")
          .expect("`token BWS \"=\" BWS quoted-string` parses"),
        (b"p", ParamValue::Quoted(b"a,b"))
      ),
      "{field:?}"
    );
    // The one this exists for.
    assert_eq!(
      walk
        .next()
        .expect("the coding behind it")
        .expect("chunked is a token")
        .name(),
      b"chunked",
      "{field:?}"
    );
    assert!(walk.next().is_none());
  }
}

// The same bytes under RFC 9110 §5.6.6, which admits no whitespace around its
// `=` — "Parameters do not allow whitespace (not even "bad" whitespace) around
// the "=" character." — so `p ` is no `parameter-name`, the DQUOTE behind it
// opens nothing, and the comma inside `"a,b"` is the §5.6.1.2 separator it
// looks like. The member ends there, which is the cost `raw_run_end` documents
// and is kept: the value was refused by the field's OWN production before the
// cut was reached, so the caller is already being told the field is malformed.
//
// What is NOT read is `b"`. Those bytes are what is left of a member already
// refused, and the walk gets past them by raw commas rather than reading them as
// a member of their own — so `chunked`, which the sender did write, is still
// yielded. The pair of tests is the point: one walk, two productions, and the
// answer moves with the production rather than with the bytes.
#[test]
fn the_same_bytes_under_5_6_6_end_the_member_at_the_quoted_comma() {
  let mut walk = parameterised_list(
    [b"gzip;p = \"a,b\", chunked".as_slice()],
    ParamSyntax::Parameter,
  );
  let first = walk.next().expect("a member").expect("gzip is a token");
  assert_eq!(first.name(), b"gzip");
  assert_eq!(
    first.params().next().expect("one parameter").unwrap_err(),
    ListError::NotAToken
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind the refused one")
      .expect("chunked is a token")
      .name(),
    b"chunked"
  );
  assert!(walk.next().is_none());
}

// The `BWS` reading widens WHERE a string may open and nothing else. A value
// that already took `transfer-parameter`'s `token` alternative admits no string
// behind it, exactly as under §5.6.6, so the member still ends at the raw comma
// and the coding behind it is still yielded.
#[test]
fn a_transfer_parameter_admits_no_string_outside_its_value_position() {
  for field in [
    // The value took the `token` alternative.
    b"gzip;p = x\"y, chunked".as_slice(),
    // A DQUOTE at a `parameter-name`, where no `=` is ever reached.
    b"gzip;p\"x, chunked",
    // Behind a value that already closed.
    b"gzip;p = \"a\"\"b, chunked",
  ] {
    let mut walk = parameterised_list([field], ParamSyntax::TransferParameter);
    assert_eq!(
      walk.next().expect("a member").expect("gzip").name(),
      b"gzip",
      "{field:?}"
    );
    assert_eq!(
      walk
        .next()
        .expect("the coding behind it")
        .expect("chunked is a token")
        .name(),
      b"chunked",
      "{field:?}"
    );
  }
}

// RFC 9110 §5.2's join re-enters `*( OWS ";" OWS transfer-parameter )` on a
// LATER field line, and the repetition it re-enters is the caller's production
// there too. A later parameter's quoted value holds its own commas, and reading
// that one repetition with §5.6.6's narrower `parameter` would cut inside it
// and hide the coding behind the member.
#[test]
fn the_join_re_enters_the_callers_own_parameter_production() {
  let lines: [&[u8]; 2] = [b"gzip;p = \"a", b"b\" ; q = \"c,d\", chunked"];
  let mut walk = parameterised_list(lines, ParamSyntax::TransferParameter);
  let coding = walk.next().expect("a member").expect("gzip is a token");
  assert_eq!(coding.name(), b"gzip");
  // `p`'s value is well formed and simply not one contiguous slice.
  assert_eq!(
    coding.params().next().expect("p").unwrap_err(),
    ListError::ValueSpansFieldLines
  );
  assert_eq!(
    walk
      .next()
      .expect("the coding behind it")
      .expect("chunked is a token")
      .name(),
    b"chunked"
  );

  // And the mirror for a §5.6.6 caller, which is the half that says the
  // production came from the CALLER and not from the join. `p="a` opens a
  // string §5.6.6 does admit, so the member really does cross the join; behind
  // the close, `q ` is no `parameter-name` there, so nothing opens at `"c,d"`
  // and the member ends at the comma INSIDE it. Reading that one repetition
  // with the wider production instead would put the member boundary where
  // §5.6.6 has none.
  //
  // `d"` is then what is left of a member already refused, so the walk gets past
  // it by raw commas instead of reading it as a member — and `second`, which the
  // sender did write, is still yielded. A fault in one member's parameters hides
  // no member behind it under either production.
  let lines: [&[u8]; 2] = [b"m;p=\"a", b"b\" ; q = \"c,d\", second"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  let member = walk.next().expect("a member").expect("m is a token");
  assert_eq!(member.name(), b"m");
  // `p`'s own value is well formed and merely not contiguous, but the
  // repetition behind it is not a `parameter` under RFC 9110 §5.6.6 — `q ` is
  // no `parameter-name` there — so the member does not read as well formed.
  // The same bytes on one field line answer `NotAToken` too, which is the
  // point: §5.2's join is not a way past a production.
  assert_eq!(
    member.params().next().expect("p").unwrap_err(),
    ListError::NotAToken
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind the refused one")
      .expect("second is a token")
      .name(),
    b"second"
  );
  assert!(walk.next().is_none());
}

// The same question `has_bare_comma` asks for RFC 9110 §8.3's singleton rule,
// asked of both productions. It answers through `member_end`, so it moves with
// the caller's grammar exactly as the walk does — a value that is one member to
// §10.1.4 and two to §5.6.6 has to be reported as each to each, or a field
// would pass as singular and then yield two members.
#[test]
fn has_bare_comma_answers_under_the_callers_own_parameter_production() {
  assert!(!has_bare_comma(
    b"gzip;p = \"a,b\"",
    ParamSyntax::TransferParameter,
    ValuelessParameter::Refused
  ));
  assert!(has_bare_comma(
    b"gzip;p = \"a,b\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  // Where the two productions agree, so do the answers.
  assert!(!has_bare_comma(
    b"gzip;p=\"a,b\"",
    ParamSyntax::TransferParameter,
    ValuelessParameter::Refused
  ));
  assert!(!has_bare_comma(
    b"gzip;p=\"a,b\"",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  assert!(has_bare_comma(
    b"gzip, chunked",
    ParamSyntax::TransferParameter,
    ValuelessParameter::Refused
  ));

  // And the third rule a field picks moves the answer too, though not the same
  // way. Where the field READS the bare `p`, `q`'s value position is reached,
  // the string opens, the comma inside `"a,b"` is data and the one in front of
  // `x` is §5.6.1.2's separator — a bare comma, and the value is a list. Where
  // the field REFUSES it, `parameters` has failed at `p`, and behind that fault
  // the raw reading ends the member at the comma inside `"a,b"` while the
  // reading that opens `q`'s string ends it at the one in front of `x`: two
  // different commas, so this reports none, because the evidence a singleton
  // field wants is a comma the value provably has. The walk agrees by
  // construction — it yields `m` and then `ListError::MemberBoundaryUnknown`,
  // so nothing behind the fault is read as a member either.
  assert!(!has_bare_comma(
    b"m;p;q=\"a,b\", x",
    ParamSyntax::Parameter,
    ValuelessParameter::Refused
  ));
  assert!(has_bare_comma(
    b"m;p;q=\"a,b\", x",
    ParamSyntax::Parameter,
    ValuelessParameter::Reported
  ));
  let mut walk = parameterised_list_with(
    [b"m;p;q=\"a,b\", x".as_slice()],
    is_token,
    ParamSyntax::Parameter,
    ValuelessParameter::Refused,
  );
  assert_eq!(
    walk.next().expect("a member").expect("m is a token").name(),
    b"m"
  );
  assert_eq!(
    walk
      .next()
      .expect("the walk says why it stopped")
      .unwrap_err(),
    ListError::MemberBoundaryUnknown
  );
  assert!(walk.next().is_none());
}

// Validity, asked apart from extent. `m;p = x` holds no comma, so both
// productions put the member's end in the same place — and they still disagree
// about whether it holds a parameter, which is the half a caller reads.
#[test]
fn a_bws_value_parses_under_one_production_and_not_the_other() {
  let read = |syntax| {
    parameterised_list([b"m;p = x".as_slice()], syntax)
      .next()
      .expect("a member")
      .expect("m is a token")
      .params()
      .next()
      .expect("one parameter")
  };
  assert!(matches!(
    read(ParamSyntax::TransferParameter).expect("`token BWS \"=\" BWS token`"),
    (b"p", ParamValue::Token(b"x"))
  ));
  assert_eq!(
    read(ParamSyntax::Parameter).unwrap_err(),
    ListError::NotAToken
  );

  // Each side of that `=` on its own, so neither half of §5.6.6's "not even
  // "bad" whitespace" can be dropped without a red test. `p =x` reads a name
  // `p ` that is no `token`; `p= x` reads a value ` x` that is no `token`
  // either — and each is a `transfer-parameter` under RFC 9110 §10.1.4.
  for (field, value) in [
    (b"m;p =x".as_slice(), b"x".as_slice()),
    (b"m;p= x".as_slice(), b"x".as_slice()),
  ] {
    let narrow = parameterised_list([field], ParamSyntax::Parameter)
      .next()
      .expect("a member")
      .expect("m is a token")
      .params()
      .next()
      .expect("one parameter");
    assert_eq!(narrow.unwrap_err(), ListError::NotAToken, "{field:?}");
    let wide = parameterised_list([field], ParamSyntax::TransferParameter)
      .next()
      .expect("a member")
      .expect("m is a token")
      .params()
      .next()
      .expect("one parameter")
      .expect("`token BWS \"=\" BWS token`");
    assert!(
      matches!(wide, (b"p", ParamValue::Token(got)) if got == value),
      "{field:?}"
    );
  }

  // Neither production spells a bare name with no `=`, and the two entry-point
  // grammars differ over what to do about it — the third difference between
  // them, beside the `BWS` above and the empty slot.
  //
  // RFC 9110 §10.1.4 brackets neither the `=` nor the value —
  // `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` — and
  // `TE` and `Transfer-Encoding` spell no grammar of their own over it, so
  // `parameterised_list` refuses a bare name there.
  //
  // §5.6.6's `parameters` is the production other fields EXTEND, and one whose
  // own `parameter` brackets the value wants the bare name rather than a
  // refusal. So the SHAPE is what this entry point hands over, and the field
  // decides. A §5.6.6 field that refuses it says so with
  // `ValuelessParameter::Refused` instead, which is what `media` now declares.
  //
  // Either way the coding written behind it is still yielded.
  let mut walk = parameterised_list([b"gzip;p, chunked".as_slice()], ParamSyntax::Parameter);
  let coding = walk.next().expect("a member").expect("gzip");
  assert!(matches!(
    coding.params().next().expect("p").expect("a bare name"),
    (b"p", ParamValue::None)
  ));
  assert_eq!(
    walk.next().expect("chunked").expect("a token").name(),
    b"chunked"
  );

  let mut walk = parameterised_list(
    [b"gzip;p, chunked".as_slice()],
    ParamSyntax::TransferParameter,
  );
  let coding = walk.next().expect("a member").expect("gzip");
  assert_eq!(
    coding.params().next().expect("p").unwrap_err(),
    ListError::MissingParameterValue
  );
  assert_eq!(
    walk.next().expect("chunked").expect("a token").name(),
    b"chunked"
  );
}

// RFC 9110 §10.1.4 puts no brackets around its slot —
// `transfer-coding = token *( OWS ";" OWS transfer-parameter )` — so every `;`
// it writes introduces a whole `transfer-parameter`, and a `;` that introduces
// nothing is one whose leading `token` is missing. Leading, interior and
// trailing are the same fault: each is a repetition that ran and derived
// nothing.
//
// `gzip;` is the one that matters most. Dropping the `;` and storing an empty
// parameter slice makes it indistinguishable from a well-formed `gzip` through
// `name()` and `params()` — a malformed `Transfer-Encoding` reported as a
// conforming one, to a reader that then frames a body with it.
#[test]
fn an_empty_transfer_parameter_slot_is_a_fault_under_10_1_4() {
  for field in [
    b"gzip;".as_slice(),
    b"gzip;;p=x",
    b"gzip;p=x;",
    // The OWS RFC 9110 §5.6.6 and §10.1.4 both put behind the `;` does not
    // fill the slot.
    b"gzip; ",
    b"gzip; ;p=x",
    b"gzip;p=x;;q=y",
  ] {
    let mut walk = parameterised_list([field], ParamSyntax::TransferParameter);
    let coding = walk.next().expect("a member").expect("gzip is a token");
    assert_eq!(coding.name(), b"gzip", "{field:?}");
    let mut params = coding.params();
    // Whatever the sender DID complete is still reported; the fault arrives at
    // the slot holding nothing.
    let err = loop {
      match params.next().expect("the empty slot is reported") {
        Ok(_) => {}
        Err(err) => break err,
      }
    };
    assert_eq!(err, ListError::NotAToken, "{field:?}");
    // And it ends the parameter walk, so nothing behind a `;` the sender never
    // completed is handed over as though it had been.
    assert!(params.next().is_none(), "{field:?}");
  }
}

// The same slots under RFC 9110 §5.6.6, which DOES bracket its own —
// `parameters = *( OWS ";" OWS [ parameter ] )` — where each states exactly the
// parameters the sender wrote and none of them is a fault. The pair of tests is
// the point: the two grammars are pinned apart, so a walk that gave one of them
// both answers reds one test or the other.
#[test]
fn the_same_empty_slots_are_conforming_5_6_6_parameters() {
  let read = |field: &'static [u8]| {
    parameterised_list([field], ParamSyntax::Parameter)
      .next()
      .expect("a member")
      .expect("gzip is a token")
  };

  // The same bytes the test above refuses, byte for byte, so what moves
  // between the two is the production and not the input.
  for field in [b"gzip;".as_slice(), b"gzip; ", b"gzip;;", b"gzip; ; "] {
    let member = read(field);
    assert_eq!(member.name(), b"gzip", "{field:?}");
    assert!(member.params().next().is_none(), "{field:?}");
  }

  for field in [
    b"gzip;;p=x".as_slice(),
    b"gzip;p=x;",
    b"gzip; ;p=x",
    b"gzip;p=x;;",
  ] {
    let mut params = read(field).params();
    assert!(
      matches!(
        params.next().expect("p").expect("well formed"),
        (b"p", ParamValue::Token(b"x"))
      ),
      "{field:?}"
    );
    assert!(params.next().is_none(), "{field:?}");
  }
}

// A member with NO `;` and a member whose `;` introduces nothing are two
// different values. RFC 9110 §10.1.4's
// `transfer-coding = token *( OWS ";" OWS transfer-parameter )` runs its
// repetition zero times for the first — conforming — and once, deriving
// nothing, for the second. Storing both as an empty slice makes the second
// unreportable, which is why the distinction lives in the type — `params` is an
// `Option` — and not in the walk alone.
#[test]
fn a_member_with_no_semicolon_is_not_a_member_with_an_empty_slot() {
  for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
    let member = parameterised_list([b"gzip".as_slice()], syntax)
      .next()
      .expect("a member")
      .expect("gzip is a token");
    assert_eq!(member.name(), b"gzip", "{syntax:?}");
    assert!(member.params().next().is_none(), "{syntax:?}");
  }

  let with_semicolon = |syntax| {
    parameterised_list([b"gzip;".as_slice()], syntax)
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
  };
  assert!(with_semicolon(ParamSyntax::Parameter).is_none());
  assert_eq!(
    with_semicolon(ParamSyntax::TransferParameter)
      .expect("the empty slot is reported")
      .unwrap_err(),
    ListError::NotAToken
  );
}

// The same rule, at the OTHER entrance. RFC 9110 §5.2 makes the field lines one
// value "concatenated in order, with each field line value separated by a
// comma", and a quoted-string open at a line's end carries the member across
// that comma — so the rest of that member's parameters are read on a LATER
// line, by a scan whose verdict is the only one they ever get.
//
// The pair below is the whole of it: the two values differ by one `;`, the
// second states an empty `transfer-parameter` slot RFC 9110 §10.1.4 does not
// admit, and a walk that drops that verdict reads both as `gzip`, one parameter
// reported as `ValueSpansFieldLines`, then `chunked`. Indistinguishable — and
// `ValueSpansFieldLines` names a value that is WELL FORMED and merely not
// contiguous, so a caller may recover from it and go on to frame a body with a
// `Transfer-Encoding` §10.1.4 refuses.
#[test]
fn an_empty_transfer_parameter_slot_is_a_fault_behind_the_join() {
  let valid: [&[u8]; 2] = [b"gzip;p=\"a", b"\";q=x, chunked"];
  let empty_slot: [&[u8]; 2] = [b"gzip;p=\"a", b"\";;q=x, chunked"];

  let read = |lines: [&'static [u8]; 2]| {
    let mut walk = parameterised_list(lines, ParamSyntax::TransferParameter);
    let coding = walk.next().expect("a member").expect("gzip is a token");
    assert_eq!(coding.name(), b"gzip");
    let fault = coding.params().next().expect("p").unwrap_err();
    // Whatever the parameters said, the coding written BEHIND this member is
    // still reachable: a parameter fault may not hide a member.
    assert_eq!(
      walk
        .next()
        .expect("the coding behind it")
        .expect("chunked is a token")
        .name(),
      b"chunked"
    );
    assert!(walk.next().is_none());
    fault
  };

  // Well formed under §10.1.4, and not one contiguous slice.
  assert_eq!(read(valid), ListError::ValueSpansFieldLines);
  // The empty slot, refused — and so no longer the same reading as the value
  // above.
  assert_eq!(read(empty_slot), ListError::NotAToken);
  assert_ne!(read(valid), read(empty_slot));

  // Leading, interior and trailing behind the join, as in front of it.
  for lines in [
    [b"gzip;p=\"a".as_slice(), b"\";"],
    [b"gzip;p=\"a".as_slice(), b"\";, chunked"],
    [b"gzip;p=\"a".as_slice(), b"\"; ; , chunked"],
    [b"gzip;p=\"a".as_slice(), b"\";q=x;, chunked"],
    [b"gzip;p=\"a".as_slice(), b"\";q=x;;r=y, chunked"],
  ] {
    assert_eq!(
      parameterised_list(lines, ParamSyntax::TransferParameter)
        .next()
        .expect("a member")
        .expect("gzip is a token")
        .params()
        .next()
        .expect("p")
        .unwrap_err(),
      ListError::NotAToken,
      "{lines:?}"
    );
  }
}

// And the mirror, which says the production came from the CALLER and not from
// the join: RFC 9110 §5.6.6 brackets its slot —
// `parameters = *( OWS ";" OWS [ parameter ] )` — so the same bytes state
// exactly the parameters written, and the only thing there is to report about
// the member is that one value of it is not one contiguous slice.
#[test]
fn the_same_empty_slots_behind_the_join_are_conforming_5_6_6_parameters() {
  for lines in [
    [b"gzip;p=\"a".as_slice(), b"\";;q=x, chunked"],
    [b"gzip;p=\"a".as_slice(), b"\";"],
    [b"gzip;p=\"a".as_slice(), b"\"; ; , chunked"],
    [b"gzip;p=\"a".as_slice(), b"\";q=x;;r=y, chunked"],
  ] {
    assert_eq!(
      parameterised_list(lines, ParamSyntax::Parameter)
        .next()
        .expect("a member")
        .expect("gzip is a token")
        .params()
        .next()
        .expect("p")
        .unwrap_err(),
      ListError::ValueSpansFieldLines,
      "{lines:?}"
    );
  }
}

// Every OTHER rule a parameter is held to, asked behind the join and asked of
// the same bytes on one field line. RFC 9110 §5.6.6's
// `parameter-value = ( token / quoted-string )` takes one alternative WHOLE, so
// bytes behind a close derive nothing and a DQUOTE inside a token derives
// nothing; `parameter-name` is §5.6.2's `token`, which `@` is not. §5.2's join
// moves none of that — a walk that answered one way in front of it and another
// way behind it would let a sender choose which grammar it was read under by
// choosing where to break the line.
#[test]
fn the_join_is_not_a_way_past_what_a_parameter_may_be() {
  for (joined, one_line) in [
    (
      [b"gzip;p=\"a".as_slice(), b"\";q=\"b\"junk, chunked"],
      b"gzip;q=\"b\"junk, chunked".as_slice(),
    ),
    (
      [b"gzip;p=\"a".as_slice(), b"\";q=x\"y, chunked"],
      b"gzip;q=x\"y, chunked",
    ),
    (
      [b"gzip;p=\"a".as_slice(), b"\";@=x, chunked"],
      b"gzip;@=x, chunked",
    ),
  ] {
    for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
      let mut walk = parameterised_list(joined, syntax);
      let member = walk.next().expect("a member").expect("gzip is a token");
      assert_eq!(
        member.params().next().expect("a parameter").unwrap_err(),
        ListError::NotAToken,
        "{joined:?} {syntax:?}"
      );
      assert_eq!(
        walk.next().expect("chunked").expect("a token").name(),
        b"chunked",
        "{joined:?} {syntax:?}"
      );

      // The same fault the same bytes earn with no join in them.
      assert_eq!(
        parameterised_list([one_line], syntax)
          .next()
          .expect("a member")
          .expect("gzip is a token")
          .params()
          .next()
          .expect("a parameter")
          .unwrap_err(),
        ListError::NotAToken,
        "{one_line:?} {syntax:?}"
      );
    }
  }
}

// Which production reads the parameters behind the join is the MEMBER's, the
// same one that delimited it. RFC 9110 §10.1.4's
// `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` admits the
// whitespace §5.6.6 refuses in as many words, so one value here is a parameter
// to one production and no parameter at all to the other — behind the join
// exactly as in front of it.
#[test]
fn a_parameter_behind_the_join_is_read_under_the_members_own_production() {
  let lines: [&[u8]; 2] = [b"gzip;p=\"a", b"\";q = x, chunked"];

  // §10.1.4 admits the `BWS`, so nothing here is malformed and `p` is simply
  // not contiguous.
  assert_eq!(
    parameterised_list(lines, ParamSyntax::TransferParameter)
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
      .expect("p")
      .unwrap_err(),
    ListError::ValueSpansFieldLines
  );

  // §5.6.6 admits none of it, so `q ` is no `parameter-name` and the member is
  // refused rather than reported as well formed.
  assert_eq!(
    parameterised_list(lines, ParamSyntax::Parameter)
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
      .expect("p")
      .unwrap_err(),
    ListError::NotAToken
  );
}

// A member's parameters may cross MORE than one join, and each crossing is the
// same rule again. RFC 9110 §5.2 joins every pair of lines the same way, so a
// parameter on the third line is as far out of `params`'s reach as one on the
// second — and a value that closes across a LATER join and runs on past that
// close derives nothing, which is what `QuotedTail::Trails` says about the
// member's own.
#[test]
fn a_parameter_behind_the_second_join_is_held_to_the_same_rules() {
  for (lines, fault) in [
    // An empty §10.1.4 slot, opened after two crossings.
    (
      [
        b"gzip;p=\"a".as_slice(),
        b"\";q=\"b".as_slice(),
        b"\";;r=x, chunked".as_slice(),
      ],
      ListError::NotAToken,
    ),
    // A value that closed across the SECOND join and ran on past the close.
    (
      [
        b"gzip;p=\"a".as_slice(),
        b"\";q=\"b".as_slice(),
        b"\"junk;r=x, chunked".as_slice(),
      ],
      ListError::NotAToken,
    ),
  ] {
    let mut walk = parameterised_list(lines, ParamSyntax::TransferParameter);
    let coding = walk.next().expect("a member").expect("gzip is a token");
    assert_eq!(
      coding.params().next().expect("p").unwrap_err(),
      fault,
      "{lines:?}"
    );
    assert_eq!(
      walk.next().expect("chunked").expect("a token").name(),
      b"chunked",
      "{lines:?}"
    );
  }

  // The same three lines with nothing wrong in them: two crossings, one member,
  // and the only thing to report is that `p`'s value is not one slice.
  let clean: [&[u8]; 3] = [b"gzip;p=\"a", b"\";q=\"b", b"\";r=x, chunked"];
  let mut walk = parameterised_list(clean, ParamSyntax::TransferParameter);
  assert_eq!(
    walk
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
      .expect("p")
      .unwrap_err(),
    ListError::ValueSpansFieldLines
  );
  assert_eq!(
    walk.next().expect("chunked").expect("a token").name(),
    b"chunked"
  );
}

// RFC 9110 §5.6.4's string is asked of the WHOLE value, and a string a
// parameter BEHIND the join opened is no exception: when the lines run out with
// it still open, the value ends inside it. Reporting the member as merely
// non-contiguous there would call a `quoted-string` that has no closing DQUOTE
// well formed.
#[test]
fn a_string_a_later_parameter_never_closes_is_unterminated() {
  for lines in [
    &[b"gzip;p=\"a".as_slice(), b"\";q=\"b"][..],
    &[b"gzip;p=\"a".as_slice(), b"\";q=\"b", b"\";r=\"c"][..],
    // The string runs on over a line of its own and still never closes.
    &[b"gzip;p=\"a".as_slice(), b"\";q=\"b", b"still open"][..],
  ] {
    for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
      assert_eq!(
        parameterised_list(lines.iter().copied(), syntax)
          .next()
          .expect("a member")
          .expect("gzip is a token")
          .params()
          .next()
          .expect("p")
          .unwrap_err(),
        ListError::UnterminatedQuotedString,
        "{lines:?} {syntax:?}"
      );
    }
  }
}

// A bare name behind RFC 9110 §5.2's join reads as it reads in front of it,
// which is the whole of what the join may not change. WHAT it reads as belongs
// to the field, and the two entry-point productions answer differently — see
// `a_bws_value_parses_under_one_production_and_not_the_other`, where the same
// pair is asserted on one field line.
//
// The §10.1.4 half is the one the join can get past: a bare
// `transfer-parameter` behind it whose verdict is dropped leaves the member
// reading `ValueSpansFieldLines` — well formed, and merely not contiguous — for
// a value §10.1.4 does not admit. What it earns instead is the
// `MissingParameterValue` those bytes earn on one field line.
//
// The §5.6.6 half states the cost of `ValuelessParameter::
// Reported`: the walk hands no slice out from behind the join, so a SHAPE
// reported there would be a shape nobody could read, and the member keeps its
// `ValueSpansFieldLines`. A §5.6.6 field that refuses bare names says so with
// `ValuelessParameter::Refused` — `media` does — and then gets the refusal at
// this entrance too.
#[test]
fn a_bare_name_behind_the_join_reads_as_it_does_in_front_of_it() {
  let lines: [&[u8]; 2] = [b"gzip;p=\"a", b"\";q, chunked"];

  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  assert_eq!(
    walk
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
      .expect("p")
      .unwrap_err(),
    ListError::ValueSpansFieldLines
  );
  assert_eq!(
    walk.next().expect("chunked").expect("a token").name(),
    b"chunked"
  );

  let mut walk = parameterised_list(lines, ParamSyntax::TransferParameter);
  assert_eq!(
    walk
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
      .expect("p")
      .unwrap_err(),
    ListError::MissingParameterValue
  );
  assert_eq!(
    walk.next().expect("chunked").expect("a token").name(),
    b"chunked"
  );
}

// Two orderings, and the walk keeps both. A member's OWN parameters are
// reported one at a time in the order the sender wrote them, so a fault among
// them is reported where it stands and a fault behind RFC 9110 §5.2's join
// never displaces it — the member is refused either way, and the parameter the
// caller is looking at is the one it is told about. Among the parameters behind
// the join, where the walk can report only one, it is the FIRST: the same
// order, one level down.
#[test]
fn the_members_own_fault_comes_first_and_so_does_the_earliest_behind_the_join() {
  // `p=x"y` is no `parameter-value` — RFC 9110 §5.6.2's `tchar` excludes DQUOTE
  // and nothing opens a string there — so the member is refused at `p`, while
  // `r="b` behind the join is a string that never closes. The parameter the
  // walk reached is the one reported.
  let own_first: [&[u8]; 2] = [b"gzip;p=x\"y;q=\"a", b"\";r=\"b"];
  for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
    assert_eq!(
      parameterised_list(own_first, syntax)
        .next()
        .expect("a member")
        .expect("gzip is a token")
        .params()
        .next()
        .expect("p")
        .unwrap_err(),
      ListError::NotAToken,
      "{syntax:?}"
    );
  }

  // Two faults behind the join: an empty slot §10.1.4 refuses, and then a
  // string that never closes. The first is the one carried.
  let two_behind: [&[u8]; 2] = [b"gzip;p=\"a", b"\";;q=\"b"];
  assert_eq!(
    parameterised_list(two_behind, ParamSyntax::TransferParameter)
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
      .expect("p")
      .unwrap_err(),
    ListError::NotAToken
  );
  // The same bytes under RFC 9110 §5.6.6, where the empty slot is no fault at
  // all and the unterminated string is the only one there is.
  assert_eq!(
    parameterised_list(two_behind, ParamSyntax::Parameter)
      .next()
      .expect("a member")
      .expect("gzip is a token")
      .params()
      .next()
      .expect("p")
      .unwrap_err(),
    ListError::UnterminatedQuotedString
  );
}

// A parameter fault hides no member behind it, asked of the parameters behind
// the join: a fault found there is carried on the MEMBER and reported through
// its parameters, never returned from the member walk — so the outer cursor
// stays where the member really ended and everything written behind it is still
// yielded.
#[test]
fn a_fault_behind_the_join_hides_no_member_behind_it() {
  for lines in [
    [b"gzip;p=\"a".as_slice(), b"\";;q=x, chunked, br"],
    [b"gzip;p=\"a".as_slice(), b"\";q=\"b\"j, chunked, br"],
    [b"gzip;p=\"a".as_slice(), b"\";q = x, chunked, br"],
  ] {
    for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
      let mut walk = parameterised_list(lines, syntax);
      for name in [b"gzip".as_slice(), b"chunked", b"br"] {
        assert_eq!(
          walk
            .next()
            .expect("a member")
            .expect("every name here is a token")
            .name(),
          name,
          "{lines:?} {syntax:?}"
        );
      }
      assert!(walk.next().is_none(), "{lines:?} {syntax:?}");
    }
  }

  // Two members in one value, each crossing a join of its own, each faulting,
  // and the member behind both still yielded.
  let lines: [&[u8]; 3] = [b"gzip;p=\"x", b"\";;q=1, br;s=\"y", b"\";;t=2, chunked"];
  let mut walk = parameterised_list(lines, ParamSyntax::TransferParameter);
  for name in [b"gzip".as_slice(), b"br"] {
    let member = walk.next().expect("a member").expect("a token");
    assert_eq!(member.name(), name);
    assert_eq!(
      member.params().next().expect("a parameter").unwrap_err(),
      ListError::NotAToken
    );
  }
  assert_eq!(
    walk.next().expect("chunked").expect("a token").name(),
    b"chunked"
  );
  assert!(walk.next().is_none());
}

// A repetition's verdict is taken where its boundary is — and where the
// repetition BEHIND the refused one opens an RFC 9110 §5.6.4 quoted-string that
// COVERS the comma the raw reading would cut at, or never closes at all, the
// walk stops rather than pick one of the two readings.
//
// The first field line of each pair below ends inside `gzip`'s parameter `p`;
// the second closes `p`, states an empty `transfer-parameter` slot RFC 9110
// §10.1.4 does not admit, and then writes a `q=` holding `oops, chunked`.
// Reading that string takes the comma in front of `chunked` as data and hides a
// transfer coding that decides framing. Reading it raw takes the same comma as
// §5.6.1.2's separator and reports a `chunked` that may be one the sender wrote
// INSIDE a value — which on this field is the same harm the other way round.
// Neither is derivable behind a fault, and
// `ListError::MemberBoundaryUnknown` is this walk saying so. Where the string
// closes in front of that comma instead, the two readings agree and the member
// behind it is reported —
// `a_refusal_hides_no_member_the_two_readings_agree_about` is that side.
//
// What it may NOT do is end quietly. The caller is shown the malformed `gzip`,
// and then told the value stopped being readable — which is the whole of the
// difference from a walk that reads the string and returns `None`, leaving the
// caller to think the field named one coding.
//
// The one-line spellings are the same shape with no join in them, because the
// hole was never the join's.
#[test]
fn a_refused_repetition_resolves_no_boundary_behind_it() {
  for (lines, fault) in [
    (
      &[b"gzip;p=\"a".as_slice(), b"\";;q=\"oops, chunked"][..],
      ListError::NotAToken,
    ),
    (
      &[b"gzip;;q=\"oops, chunked".as_slice()][..],
      ListError::NotAToken,
    ),
    // The refusal a FIELD makes ends the derivation exactly as one the
    // production makes does, so it resolves no boundary behind it either. `TE`
    // and `Transfer-Encoding` refuse a parameter with no value, and these are
    // the same two shapes with that refusal in place of the empty slot.
    (
      &[b"gzip;p=\"a".as_slice(), b"\";q;r=\"oops, chunked"][..],
      ListError::MissingParameterValue,
    ),
    (
      &[b"gzip;q;r=\"oops, chunked".as_slice()][..],
      ListError::MissingParameterValue,
    ),
    // And the same where the string CLOSES. The `x` parameter below is a
    // conforming `transfer-parameter` on its own, so the raw reading here does
    // not merely cut early — it hands the caller a `chunked` that stood inside
    // the sender's own value, and then a `b"` that is no `token`, which ends
    // the walk and hides the `br` the sender really did write.
    (
      &[b"gzip;;x=\"a, chunked, b\", br".as_slice()][..],
      ListError::NotAToken,
    ),
    (
      &[b"gzip;p=\"z".as_slice(), b"\";;x=\"a, chunked, b\", br"][..],
      ListError::NotAToken,
    ),
    (
      &[
        b"gzip;p=\"z".as_slice(),
        b"\";q=\"y",
        b"\";;x=\"a, chunked, b\", br",
      ][..],
      ListError::NotAToken,
    ),
    // And where the string behind the fault carries a byte RFC 9110 §5.6.4
    // forbids: the quoted reading reaches no close, so it answers no comma, and
    // the walk declines the run rather than fall back on the raw reading it
    // would otherwise be left alone with.
    (
      &[b"gzip;;x=\"a\x01b\", chunked".as_slice()][..],
      ListError::NotAToken,
    ),
    // §5.6.6's `parameter` admits the empty slot, so its version of the same
    // input needs a parameter NAME that is no `token` to reach the refusal —
    // and reaches the identical answer, which says the rule is the refusal and
    // not which production made it.
    (
      &[b"gzip;q;x=\"a, chunked, b\", br".as_slice()][..],
      ListError::MissingParameterValue,
    ),
  ] {
    let mut walk = parameterised_list(lines.iter().copied(), ParamSyntax::TransferParameter);
    let coding = walk.next().expect("a member").expect("gzip is a token");
    assert_eq!(coding.name(), b"gzip", "{lines:?}");
    assert_eq!(
      coding
        .params()
        .find_map(Result::err)
        .expect("the refused repetition"),
      fault,
      "{lines:?}"
    );
    assert_eq!(
      walk
        .next()
        .expect("the walk says why it stopped")
        .unwrap_err(),
      ListError::MemberBoundaryUnknown,
      "{lines:?}"
    );
    assert!(walk.next().is_none(), "{lines:?}");
  }
}

// The property these inputs are here to pin: no `chunked` this walk yields was
// ever written inside a quoted-string.
//
// The first class is `gzip;;x="a, chunked, b", br` under RFC 9110 §10.1.4's
// production, across one field line, across §5.2's join, across two joins, and
// — with a parameter name no `token` admits, since §5.6.6 admits the empty slot
// — under §5.6.6's. One admitted string covers the earliest comma there, and
// both the raw and the greedy reading see it.
//
// The second class is `m;;a="x;b="y,chunked,z",w`, where NEITHER of those two
// readings sees it. The greedy one opens the string at `a`'s value position,
// which swallows the DQUOTE that would have opened `b`'s, so it and the raw
// reading both end the member at the comma behind `y` — and the reading that
// leaves `a` shut opens the string at `b`'s position and holds that comma, and
// the `chunked` behind it, inside a value. Only a walk over EVERY reading
// refuses it, which is `readings_at`. Both spellings appear at every entrance
// and under both productions; under §5.6.6 the fault is the `a` repetition
// itself, since that production brackets the empty slot.
//
// Every one of these holds the word `chunked` inside a value and none of them
// states a `chunked` coding, so a walk that ever yields one has manufactured a
// framing-relevant transfer coding out of a parameter value. `Transfer-Encoding`
// is the field this walk serves with `TransferParameter`, and RFC 9112 §6.1
// makes `chunked` the coding that says where the message body ends.
#[test]
fn no_member_is_manufactured_from_inside_a_quoted_value() {
  const INPUTS: &[(&[&[u8]], ParamSyntax)] = &[
    (
      &[b"gzip;;x=\"a, chunked, b\", br"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;;x=\"a", b" chunked, b\", br"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;p=\"z", b"\";;x=\"a, chunked, b\", br"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;p=\"z", b"\";q=\"y", b"\";;x=\"a, chunked, b\", br"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;p x;x=\"a, chunked, b\", br"],
      ParamSyntax::Parameter,
    ),
    (
      &[b"gzip;p x;x=\"a, chunked, b\", br"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;@=1;x=\"a, chunked, b\", br"],
      ParamSyntax::Parameter,
    ),
    (
      &[b"gzip;p=\"a\"b;x=\"a, chunked, b\", br"],
      ParamSyntax::Parameter,
    ),
    (
      &[b"gzip;;x=\"a, chunked, b\", br, deflate"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;;x=\"a, chunked, b\""],
      ParamSyntax::TransferParameter,
    ),
    // The second class: an admitted string that only the reading leaving an
    // EARLIER one shut ever opens.
    (
      &[b"m;;a=\"x;b=\"y,chunked,z\",w"],
      ParamSyntax::TransferParameter,
    ),
    (&[b"m;;a=\"x;b=\"y,chunked,z\",w"], ParamSyntax::Parameter),
    (
      &[b"gzip;;a=\"x;b=\"y, chunked, z\", w"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;;a=\"x;b=\"y, chunked, z\", w"],
      ParamSyntax::Parameter,
    ),
    (
      &[b"gzip;;a=\"x;b=\"y, chunked\", br"],
      ParamSyntax::TransferParameter,
    ),
    // Three admitted positions rather than two, so the reading that covers the
    // comma is the one that leaves the first TWO shut.
    (
      &[b"gzip;;a=\"x;b=\"y;c=\"z, chunked, q\", w"],
      ParamSyntax::TransferParameter,
    ),
    // The same tail behind each of the other faults §10.1.4 and §5.6.6 report.
    (
      &[b"gzip;p x;a=\"x;b=\"y, chunked, z\", w"],
      ParamSyntax::Parameter,
    ),
    (
      &[b"gzip;q;a=\"x;b=\"y, chunked, z\", w"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;@=1;a=\"x;b=\"y, chunked, z\", w"],
      ParamSyntax::Parameter,
    ),
    // Behind RFC 9110 §5.2's join, and behind a value that closed on a later
    // line and ran on past that close.
    (
      &[b"gzip;p=\"z", b"\";;a=\"x;b=\"y, chunked, z\", w"],
      ParamSyntax::TransferParameter,
    ),
    (
      &[b"gzip;p=\"a", b"\"junk;a=\"x;b=\"y, chunked, z\", w"],
      ParamSyntax::Parameter,
    ),
    // And at the `seek` entrance, where the tail is an ELEMENT of the refused
    // member rather than a repetition of it.
    (
      &[b"gzip;p x, y\"z;a=\"q;b=\"r, chunked, s\", second"],
      ParamSyntax::Parameter,
    ),
  ];
  for &(lines, syntax) in INPUTS {
    let mut names = 0usize;
    let mut stopped = false;
    for member in parameterised_list(lines.iter().copied(), syntax) {
      match member {
        Ok(member) => {
          assert_ne!(
            member.name(),
            b"chunked",
            "manufactured from inside a value: {lines:?} {syntax:?}"
          );
          names = names.saturating_add(1);
        }
        Err(fault) => {
          assert_eq!(
            fault,
            ListError::MemberBoundaryUnknown,
            "{lines:?} {syntax:?}"
          );
          stopped = true;
        }
      }
    }
    // The member in front of the fault is derived and is yielded; nothing
    // behind it is, and the walk says which of the two it is doing.
    assert_eq!(names, 1, "{lines:?} {syntax:?}");
    assert!(stopped, "{lines:?} {syntax:?}");
  }
}

// The other half of the same harm, and the one a candidate taken from the
// greedy extent walked straight into: a member HIDDEN rather than manufactured.
//
// `parameter_end` cuts the refused repetition's extent by OPENING the string at
// its value position — that is the one place a repetition's extent comes from,
// and `ParamIter` needs it to hand the caller the refused bytes. Where that
// string swallows a comma, the extent stands past an offset at which the
// reading that leaves the string shut already ENDED the member. Certifying a
// comma behind that offset resumes the walk past whatever the sender wrote
// between the two.
//
// `gzip;p="a, chunked;q="x", br` is the shape. The greedy extent runs to the
// DQUOTE behind `q=` and on to the comma in front of `br`, which every reading
// does stand outside — so the analysis, asked about THAT comma, answered that
// every reading agrees, and the walk resumed at `br`. The reading that never
// opens `p`'s string ends the member at the comma behind `"a` and reads
// `chunked;q="x"` as an RFC 9110 §10.1.4 `transfer-coding` of its own, which is
// a framing decision on `TE` and `Transfer-Encoding`: RFC 9112 §6.1 makes
// `chunked` the coding that says where the message body ends. Hiding one is the
// same harm as inventing one, so the boundary is not derivable and the walk
// says so.
//
// Each row pins the members that ARE derivable — the ones in front of the
// fault, whose own boundaries no reading disputes — and then the refusal.
#[test]
fn no_member_is_hidden_behind_a_greedily_cut_extent() {
  /// One input: the field's lines, the production, and every member the walk
  /// must yield before it reports the boundary unknown.
  type Hidden = (
    &'static [&'static [u8]],
    ParamSyntax,
    &'static [&'static [u8]],
  );
  const INPUTS: &[Hidden] = &[
    (
      &[b"gzip;p=\"a, chunked;q=\"x\", br"],
      ParamSyntax::TransferParameter,
      &[b"gzip"],
    ),
    (
      &[b"gzip;p=\"a, chunked;q=\"x\", br"],
      ParamSyntax::Parameter,
      &[b"gzip"],
    ),
    // More than one member behind the boundary, so the walk cannot be said to
    // have stopped one member early by luck.
    (
      &[b"gzip;p=\"a, chunked;q=\"x\", br, deflate"],
      ParamSyntax::TransferParameter,
      &[b"gzip"],
    ),
    // The refused repetition's junk standing directly behind the close, with
    // no second admitted DQUOTE in it at all.
    (
      &[b"gzip;p=\"a, b\"c, chunked"],
      ParamSyntax::TransferParameter,
      &[b"gzip"],
    ),
    (
      &[b"gzip;p=\"a, chunked\"x, br"],
      ParamSyntax::TransferParameter,
      &[b"gzip"],
    ),
    // The `BWS` RFC 9110 §10.1.4 admits around the `=`, which moves the value
    // position the string opens at and moves nothing else.
    (
      &[b"gzip;p = \"a, chunked;q = \"x\", br"],
      ParamSyntax::TransferParameter,
      &[b"gzip"],
    ),
    // A repetition the scan SETTLED in front of the faulting one, so the fault
    // is not the member's first `;`.
    (
      &[b"gzip;q=1;p=\"a, chunked;r=\"x\", br"],
      ParamSyntax::TransferParameter,
      &[b"gzip"],
    ),
    // The member begins mid-line, and on a later line, and the member in front
    // of it is untouched either way.
    (
      &[b"a, gzip;p=\"a, chunked;q=\"x\", br"],
      ParamSyntax::TransferParameter,
      &[b"a", b"gzip"],
    ),
    (
      &[b"a", b"gzip;p=\"a, chunked;q=\"x\", br"],
      ParamSyntax::TransferParameter,
      &[b"a", b"gzip"],
    ),
    // The shortest spelling of the shape over the alphabet the generated
    // corpus is built from, which is where this class was reachable all along.
    (&[b"t;t=\",\"t,t"], ParamSyntax::Parameter, &[b"t"]),
    (&[b"t;t=\",\"t,t"], ParamSyntax::TransferParameter, &[b"t"]),
  ];
  for &(lines, syntax, derivable) in INPUTS {
    let mut walk = parameterised_list(lines.iter().copied(), syntax);
    for &name in derivable {
      assert_eq!(
        walk
          .next()
          .expect("a member in front of the fault")
          .expect("its name is a token")
          .name(),
        name,
        "{lines:?} {syntax:?}"
      );
    }
    assert_eq!(
      walk
        .next()
        .expect("the walk says why it stopped")
        .unwrap_err(),
      ListError::MemberBoundaryUnknown,
      "{lines:?} {syntax:?}"
    );
    assert!(walk.next().is_none(), "{lines:?} {syntax:?}");
  }
}

// The section that shape costs a member at, spelled over the alphabet the
// generated corpus is built from and pinned on its own rather than only as a
// row of the table above. The corpus reaches it by writing a member name in
// front of a generated section, and a generator that stopped doing so would
// take the shape out of the corpus with it; this holds it whatever the
// generator does.
//
// Measured over that alphabet, ten bytes is the shortest a section can be and
// still stand in the shape, defer, AND have a member opening behind the comma a
// candidate from the extent would have certified — three sections do, and this
// is one. Deferring alone is cheaper: `t;t=","t` is eight bytes and does it,
// with nothing behind the boundary to lose.
//
// Every offset below is MEASURED. The two that matter are a pair. The comma
// taken from the fault — the `;` at offset 1, the last offset every reading
// stands outside an RFC 9110 §5.6.4 quoted-string at — is the one at offset 5,
// which the string opened at offset 4 swallows. The extent `parameter_end` cuts
// for that repetition opens the same string, so it runs past the close, takes
// the `t` behind it raw, and stops at the comma at offset 8 — which no reading
// holds inside a string. A candidate taken from the extent is certified there
// and the walk resumes at the trailing `t`; the reading that leaves the string
// at offset 4 shut ended the member at offset 5 and reads the bytes between the
// two as an element of its own. Two readings, two member sequences, and no rule
// that picks between them, so there is no boundary to hand back.
#[test]
fn the_shortest_named_section_in_the_shape_is_pinned() {
  // A member named `t`, one RFC 9110 §5.6.6 `parameter` whose `quoted-string`
  // value swallows a comma, bytes behind its close that derive nothing, and
  // then §5.6.1.2's comma and one more element.
  const VALUE: &[u8] = b"t;t=\",\"t,t";
  for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
    // The candidate from the fault, and the reading that holds it.
    assert_eq!(raw_comma_end(VALUE, 1), 5, "{syntax:?}");
    assert!(readings_at(VALUE, 1, 5, syntax).covers(), "{syntax:?}");

    // The extent, and the later comma a candidate taken from it reaches.
    let (Delim::At(cut), trails) = parameter_end(VALUE, 2, syntax) else {
      panic!("the repetition's extent is on the line in hand: {syntax:?}");
    };
    assert_eq!(cut, 8, "{syntax:?}");
    assert!(trails, "{syntax:?}");
    assert_eq!(raw_comma_end(VALUE, cut), 8, "{syntax:?}");
    assert!(!readings_at(VALUE, 1, 8, syntax).covers(), "{syntax:?}");

    // So the rule answers that there is no boundary, by the coverage question
    // and by the enumeration of where each reading ENDS alike.
    assert_eq!(refused_member_end(VALUE, 1, syntax), None, "{syntax:?}");
    assert_eq!(every_reading_ends_at(VALUE, 1, syntax), None, "{syntax:?}");

    // And the walk reaches that answer through `member_end` and
    // `scan_parameters` rather than being asked it: the member in front of the
    // fault, carrying its own repetition's verdict, and then the deferral, with
    // the trailing `t` never named as a member of the list.
    let mut walk = parameterised_list([VALUE], syntax);
    let head = walk
      .next()
      .expect("the member in front of the fault")
      .expect("its name is a token");
    assert_eq!(head.name(), b"t", "{syntax:?}");
    let mut params = head.params();
    assert_eq!(
      params.next().and_then(Result::err),
      Some(ListError::NotAToken),
      "{syntax:?}"
    );
    assert!(params.next().is_none(), "{syntax:?}");
    assert_eq!(
      walk.next().expect("the walk says why it stopped").err(),
      Some(ListError::MemberBoundaryUnknown),
      "{syntax:?}"
    );
    assert!(walk.next().is_none(), "{syntax:?}");
  }
}

// The rule itself, asked of the analysis directly. `refused_member_end` takes
// the earliest comma `raw_comma_end` reaches FROM THE FAULT and hands it back
// only where NO reading of the bytes in front of it holds that offset inside a
// quoted-string — which is `readings_at`, a subset construction over which of
// the admitted DQUOTEs a reading opens.
//
// The fault is where the candidate comes from because it is the last offset
// every reading stands outside a string at: the earliest comma from there is
// the member's end under the reading that opens nothing, and no reading ends
// the member in front of it. A candidate taken from a later offset — the
// greedy extent `parameter_end` cut for the refused repetition, which is what
// `scan_parameters` used to pass — can be a comma a reading already ended the
// member behind, and certifying it hides whatever the sender wrote between.
//
// RFC 9110 §5.6.4's `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE`
// opens at a DQUOTE and at nothing else, and the two positions either
// production puts one at are the values of
// §5.6.6's `parameter-value = ( token / quoted-string )` and of §10.1.4's
// `transfer-parameter = token BWS "=" BWS ( token / quoted-string )`. Behind a
// fault nothing forces the `quoted-string` alternative on those bytes, so each
// such DQUOTE is a reading's choice and the readings number two to the power of
// however many of them stand there.
//
// Every offset and every state below was read off the walk running over these
// bytes. The `gzip;;p = "a,b", chunked` pair is the same bytes reaching
// OPPOSITE answers because §10.1.4's `BWS` admits a string §5.6.6 admits
// nowhere; the three `m;;a="x;b="y,chunked,z",w` rows are the reading a
// comparison of the raw and the greedy scan never asked.
#[test]
fn a_refused_members_end_is_the_comma_no_reading_covers() {
  /// One question: the field line, the fault the readings open up at, and the
  /// production — then the earliest raw comma FROM THAT FAULT, the states the
  /// readings stand in there, and the answer.
  type OneQuestion = (
    &'static [u8],
    usize,
    ParamSyntax,
    usize,
    Readings,
    Option<usize>,
  );
  /// Every reading outside a string: the three flags clear.
  const OUTSIDE: Readings = Readings {
    inside: false,
    escaped: false,
    sealed: false,
  };
  /// Some reading inside one, with no `quoted-pair` pending.
  const INSIDE: Readings = Readings {
    inside: true,
    escaped: false,
    sealed: false,
  };
  const QUESTIONS: &[OneQuestion] = &[
    // No DQUOTE stands behind the fault at all, so every reading is the raw
    // one and the earliest comma is the member's end.
    (
      b"gzip;q, chunked",
      4,
      ParamSyntax::TransferParameter,
      6,
      OUTSIDE,
      Some(6),
    ),
    (
      b"gzip;;q=x, chunked",
      4,
      ParamSyntax::TransferParameter,
      9,
      OUTSIDE,
      Some(9),
    ),
    // A DQUOTE stands behind it, at a value position, and the string it opens
    // CLOSES in front of the only comma — so the reading that opened it is
    // outside there too, and the set is back to one state.
    (
      b"gzip;;x=\"a\", chunked",
      4,
      ParamSyntax::TransferParameter,
      11,
      OUTSIDE,
      Some(11),
    ),
    (
      b"gzip;;x=\"chunked\", br",
      4,
      ParamSyntax::TransferParameter,
      17,
      OUTSIDE,
      Some(17),
    ),
    // Two admitted strings, both closing in front of the comma: the walk
    // crosses the repetitions rather than stopping at the first DQUOTE.
    (
      b"gzip;;x=\"a\";y=\"b\", chunked",
      4,
      ParamSyntax::TransferParameter,
      17,
      OUTSIDE,
      Some(17),
    ),
    // And the same two where the SECOND covers the comma the first left
    // exposed.
    (
      b"gzip;;x=\"a\";y=\"b, chunked\", br",
      4,
      ParamSyntax::TransferParameter,
      16,
      INSIDE,
      None,
    ),
    // One string consuming the earliest raw comma: yielding what stands behind
    // the close would be choosing the reading that opened it.
    (
      b"gzip;;x=\"a, chunked, b\", br",
      4,
      ParamSyntax::TransferParameter,
      10,
      INSIDE,
      None,
    ),
    (
      b"gzip;;q=\"a,b\", chunked",
      4,
      ParamSyntax::TransferParameter,
      10,
      INSIDE,
      None,
    ),
    // A string that stays open across every comma left on the line and across
    // the RFC 9110 §5.2 join behind them.
    (
      b"gzip;;q=\"oops, chunked",
      4,
      ParamSyntax::TransferParameter,
      13,
      INSIDE,
      None,
    ),
    // The backslash of a `quoted-pair` standing immediately in front of the
    // comma: that reading is inside a string AND holding an escape, so the
    // comma is the pair's data. `escaped` is the state no other row reaches,
    // and dropping it from `covers` would hand this comma back.
    (
      b"gzip;;x=\"a\\, chunked",
      4,
      ParamSyntax::TransferParameter,
      11,
      Readings {
        inside: false,
        escaped: true,
        sealed: false,
      },
      None,
    ),
    // The same pair one byte along: `\"` is data, so the string does NOT close
    // there and the reading is still inside at the comma behind it.
    (
      b"gzip;;x=\"a\\\", chunked",
      4,
      ParamSyntax::TransferParameter,
      12,
      INSIDE,
      None,
    ),
    // A DQUOTE at a position RFC 9110 §5.6.6 admits NO value at — `p ` is no
    // `parameter-name` — is data in every reading, so the comma inside the
    // bytes the sender wrote as a string is the separator in all of them.
    (
      b"m;p =\"a,b\", second",
      1,
      ParamSyntax::Parameter,
      7,
      OUTSIDE,
      Some(7),
    ),
    // The same line one element along, which is where `seek` asks: `b\"` opens
    // no parameter, so its DQUOTE opens no string either.
    (
      b"m;p =\"a,b\", second",
      8,
      ParamSyntax::Parameter,
      10,
      OUTSIDE,
      Some(10),
    ),
    // One line, two productions, opposite answers. Under RFC 9110 §10.1.4 the
    // `BWS` admits the space in front of the `=`, so a reading may open a
    // string covering the comma at 12; under §5.6.6 `p ` is no name, no string
    // is admitted, and the walk is already standing on that comma.
    (
      b"gzip;;p = \"a,b\", chunked",
      4,
      ParamSyntax::TransferParameter,
      12,
      INSIDE,
      None,
    ),
    (
      b"gzip;;p = \"a,b\", chunked",
      5,
      ParamSyntax::Parameter,
      12,
      OUTSIDE,
      Some(12),
    ),
    // The `seek` entrance: an element of a refused member that opens a string
    // of its own, closing in front of the comma and covering it.
    (
      b"gzip;p x, y\"z;w=\"a\", second",
      10,
      ParamSyntax::Parameter,
      19,
      OUTSIDE,
      Some(19),
    ),
    (
      b"gzip;p x, y\"z;w=\"a, chunked, b\", second",
      10,
      ParamSyntax::Parameter,
      18,
      INSIDE,
      None,
    ),
    // A byte RFC 9110 §5.6.4 forbids inside the string means that reading
    // reaches no close at all, so it covers every comma behind it and the
    // state is `sealed`. That is MORE than §5.6.4 requires — a forbidden octet
    // derives no `quoted-string` at that position, so the grammar leaves only
    // the readings that opened nothing there. It is deliberate. The sender
    // still wrote those bytes between DQUOTEs, and
    // `gzip;;x="a\x01, chunked, b", br` cut raw hands back a `chunked` that
    // stood among them.
    (
      b"gzip;;x=\"a\x01b\", chunked",
      4,
      ParamSyntax::TransferParameter,
      13,
      Readings {
        inside: false,
        escaped: false,
        sealed: true,
      },
      None,
    ),
    // The entrance behind §5.2's join, where a value closed on a later line and
    // ran on past that close: the offset is `after_close`'s, and the question
    // asked there is this same one.
    (
      b"\"junk;q=\"b\", chunked",
      5,
      ParamSyntax::Parameter,
      11,
      OUTSIDE,
      Some(11),
    ),
    // The reading a comparison of two extremes never asked. Reading RAW, and
    // reading with every admitted string open, both end the member at 12: the
    // greedy one opens the string at `a`'s value position, which swallows the
    // DQUOTE that would have opened `b`'s. The reading that leaves `a` shut
    // opens the string at `b`'s position and holds 12 — and the `chunked`
    // behind it — inside a value, which is what `inside` records here.
    (
      b"m;;a=\"x;b=\"y,chunked,z\",w",
      1,
      ParamSyntax::TransferParameter,
      12,
      INSIDE,
      None,
    ),
    // The same bytes under RFC 9110 §5.6.6, which brackets the empty slot, so
    // the fault is the `a` repetition itself rather than the slot. The state
    // walk starts there, at 2, and not at the end `parameter_end` cut for that
    // repetition by opening its string.
    (
      b"m;;a=\"x;b=\"y,chunked,z\",w",
      2,
      ParamSyntax::Parameter,
      12,
      INSIDE,
      None,
    ),
    // And the same shape where the exposed string CLOSES in front of the
    // comma: no reading covers it, so the member behind it is knowable and is
    // not withheld.
    (
      b"gzip;;a=\"x;b=\"y\", chunked",
      4,
      ParamSyntax::TransferParameter,
      16,
      OUTSIDE,
      Some(16),
    ),
    // The comma a candidate taken from the greedy extent would have skipped
    // past. `parameter_end` opens the string at the first parameter's value
    // position and runs to the DQUOTE at the second's, so the extent it cuts
    // reaches the comma in front of the last member — an offset every reading
    // does stand outside. The candidate is this one instead, at 9, which the
    // reading that opened the first string holds inside a value while the
    // reading that left it shut ends the member there; a whole coding stands
    // between the two answers.
    (
      b"gzip;p=\"a, chunked;q=\"x\", br",
      4,
      ParamSyntax::TransferParameter,
      9,
      INSIDE,
      None,
    ),
    (
      b"gzip;p=\"a, chunked;q=\"x\", br",
      4,
      ParamSyntax::Parameter,
      9,
      INSIDE,
      None,
    ),
    // The same, with the refused repetition's junk standing directly behind a
    // close rather than behind a second admitted DQUOTE.
    (
      b"gzip;p=\"a, b\"c, chunked",
      4,
      ParamSyntax::TransferParameter,
      9,
      INSIDE,
      None,
    ),
    // And the control the rule must not cost: the same refused repetition with
    // no comma inside its string, whose extent therefore reaches no comma the
    // fault does not. The candidate is the same offset either way and the
    // member behind it is reported.
    (
      b"gzip;p=\"a\"x, chunked",
      4,
      ParamSyntax::TransferParameter,
      11,
      OUTSIDE,
      Some(11),
    ),
  ];
  for &(value, fault, syntax, raw, readings, answer) in QUESTIONS {
    assert_eq!(
      raw_comma_end(value, fault),
      raw,
      "{value:?} {fault} {syntax:?}"
    );
    assert_eq!(
      readings_at(value, fault, raw, syntax),
      readings,
      "{value:?} {fault} {syntax:?}"
    );
    assert_eq!(
      refused_member_end(value, fault, syntax),
      answer,
      "{value:?} {fault} {syntax:?}"
    );
    // The answer is that comma where no reading covers it and nothing else,
    // which is what makes this a proof over the readings rather than a sample
    // of some of them.
    assert_eq!(
      answer,
      (!readings.covers()).then_some(raw),
      "{value:?} {fault} {syntax:?}"
    );
  }
}

// One question, three entrances, and the guard against them drifting apart.
//
// `refused_member_end` is asked from `scan_parameters`, from the arm of
// `member` that handles a value which closed on a later field line and ran on
// past that close, and from `seek`. Each row below is one TAIL — the bytes
// standing behind a refused repetition — spelled at all three entrances and
// read under both productions, and the walk must reach the same verdict at
// every one: the member the tail names, or RFC 9110 §5.6.1.2's boundary left
// unknown where some reading of that tail holds its earliest comma inside a
// quoted-string. An edit that moved one entrance's answer and not the others'
// reds this test and no other.
//
// The entrances do not stand at the same offset, which is why this is asserted
// rather than argued: `scan_parameters` passes the `;` that opened the refused
// repetition, `seek` passes the first byte of an element of the refused member,
// and the arm behind the join passes what `after_close` left it on. The last
// row is the one that caught them apart — `scan_parameters` took its candidate
// comma from the greedy extent `parameter_end` cut rather than from the fault,
// so it certified a comma the other two refused.
#[test]
fn the_three_entrances_reach_one_verdict() {
  /// One tail, spelled so the refusal is found by `scan_parameters`, by the
  /// close handler behind the join, and by `seek` — then the member that must
  /// stand behind it, or `None` where the boundary is not derivable.
  type Lockstep = (
    &'static [&'static [u8]],
    &'static [&'static [u8]],
    &'static [&'static [u8]],
    Option<&'static [u8]>,
  );
  const ROWS: &[Lockstep] = &[
    // The string closes in front of the comma.
    (
      &[b"gzip;p x;x=\"a\", chunked"],
      &[b"gzip;p=\"a", b"\"junk;x=\"a\", chunked"],
      &[b"gzip;p x, y\"z;x=\"a\", chunked"],
      Some(b"chunked"),
    ),
    // It consumes it.
    (
      &[b"gzip;p x;x=\"a, chunked, b\", br"],
      &[b"gzip;p=\"a", b"\"junk;x=\"a, chunked, b\", br"],
      &[b"gzip;p x, y\"z;x=\"a, chunked, b\", br"],
      None,
    ),
    // No string is admitted in front of it at all.
    (
      &[b"gzip;p x;q=x, chunked"],
      &[b"gzip;p=\"a", b"\"junk;q=x, chunked"],
      &[b"gzip;p x, y\"z;q=x, chunked"],
      Some(b"chunked"),
    ),
    // It is still open when the line runs out.
    (
      &[b"gzip;p x;q=\"oops, chunked"],
      &[b"gzip;p=\"a", b"\"junk;q=\"oops, chunked"],
      &[b"gzip;p x, y\"z;q=\"oops, chunked"],
      None,
    ),
    // The mixed reading: a string a reading opens only by leaving an EARLIER
    // admitted one shut, covering the comma neither extreme covers.
    (
      &[b"gzip;p x;a=\"q;b=\"r, chunked, s\", w"],
      &[b"gzip;p=\"a", b"\"junk;a=\"q;b=\"r, chunked, s\", w"],
      &[b"gzip;p x, y\"z;a=\"q;b=\"r, chunked, s\", w"],
      None,
    ),
    // The same shape where that exposed string CLOSES in front of the comma,
    // so no reading covers it and the member behind it is still reported.
    (
      &[b"gzip;p x;a=\"q;b=\"r\", chunked"],
      &[b"gzip;p=\"a", b"\"junk;a=\"q;b=\"r\", chunked"],
      &[b"gzip;p x, y\"z;a=\"q;b=\"r\", chunked"],
      Some(b"chunked"),
    ),
    // The REFUSED repetition opens a string of its own, and the extent
    // `parameter_end` cuts for it runs past a comma. Here the `scan` spelling
    // is the tail itself, since that entrance is the only one whose fault is a
    // repetition with an extent: the string at the first parameter's value
    // position closes at the DQUOTE at the second's, so the extent reaches the
    // comma in front of the last member — while the reading that leaves that
    // string shut ended the member at the comma behind the first opener and
    // reads the coding behind it as a member of its own. The other two
    // entrances stand on the `;` and refused it all along.
    (
      &[b"gzip;p=\"a, chunked;q=\"x\", br"],
      &[b"gzip;z=\"a", b"\"junk;p=\"a, chunked;q=\"x\", br"],
      &[b"gzip;p x, y\"z;p=\"a, chunked;q=\"x\", br"],
      None,
    ),
  ];
  for &(scan, close, seek, behind) in ROWS {
    for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
      for lines in [scan, close, seek] {
        let mut walk = parameterised_list(lines.iter().copied(), syntax);
        let refused = walk
          .next()
          .expect("the refused member")
          .expect("its name is a token");
        assert!(
          refused.params().any(|param| param.is_err()),
          "{lines:?} {syntax:?}"
        );
        match behind {
          Some(name) => assert_eq!(
            walk
              .next()
              .expect("the member the refusal must not hide")
              .expect("its name is a token")
              .name(),
            name,
            "{lines:?} {syntax:?}"
          ),
          None => {
            assert_eq!(
              walk
                .next()
                .expect("the walk says why it stopped")
                .unwrap_err(),
              ListError::MemberBoundaryUnknown,
              "{lines:?} {syntax:?}"
            );
            assert!(walk.next().is_none(), "{lines:?} {syntax:?}");
          }
        }
      }
    }
  }
}

// The other side of the same line, and what keeps the rule from costing a
// member. Where NO reading of the bytes behind the refusal holds the earliest
// comma inside a quoted-string, that comma is RFC 9110 §5.6.1.2's separator
// whichever reading is the sender's, and the member behind it has boundaries
// this walk KNOWS. Refusing to report it would hide a transfer coding for
// nothing.
//
// Two things put a comma on this side. No DQUOTE stands in front of it that
// `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` could open a string
// at — RFC 9110 §5.6.6 admits one at the first byte of a `parameter-value` and
// nowhere else — or one does and every string that MAY open closes in front of
// that comma. The second half is the one a rule keyed on the DQUOTE's position
// got wrong: `gzip;;x="a", chunked` puts a DQUOTE at an admitted position and
// still ends the member at the same comma in every reading. So does
// `gzip;;a="x;b="y", chunked`, where the readings differ about WHICH strings
// open and agree about where the member ends anyway.
#[test]
fn a_refusal_hides_no_member_no_reading_holds_inside_a_string() {
  /// One input: the field's lines, the production to read them with, and the
  /// member name the refusal must not hide.
  type Recoverable = (&'static [&'static [u8]], ParamSyntax, &'static [u8]);
  const INPUTS: &[Recoverable] = &[
    // A bare `transfer-parameter`, which §10.1.4 brackets nowhere.
    (
      &[b"gzip;q, chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;q, chunked, br"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    // The empty slot §10.1.4 does not admit, with a `token` value behind it.
    (
      &[b"gzip;;q=x, chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;q=1;;r=2, chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    // A parameter name that is no `token`, under either production.
    (&[b"gzip;p x, chunked"], ParamSyntax::Parameter, b"chunked"),
    (&[b"gzip;@=1, chunked"], ParamSyntax::Parameter, b"chunked"),
    // And where the cut falls inside bytes the sender wrote as a string that
    // §5.6.6 admits at NO position: `p ` is no `parameter-name`, so the DQUOTE
    // opens nothing under that production and the comma inside `"a,b"` is the
    // separator under every reading of it.
    (
      &[b"m;p =\"a,b\", second"],
      ParamSyntax::Parameter,
      b"second",
    ),
    (
      &[b"gzip;p = \"a,b\", chunked, br"],
      ParamSyntax::Parameter,
      b"chunked",
    ),
    (
      &[b"gzip;p=\"a", b"\";q = \"b,c\", chunked"],
      ParamSyntax::Parameter,
      b"chunked",
    ),
    // A DQUOTE at the position RFC 9110 §10.1.4's
    // `transfer-parameter = token BWS "=" BWS ( token / quoted-string )`
    // admits one, whose string CLOSES in front of the only comma. Both readings
    // end the member at that comma, so `chunked` is knowable — at every
    // entrance, and under both productions.
    (
      &[b"gzip;;x=\"a\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;;x=\"a\", chunked, br"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;p=\"z", b"\";;x=\"a\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;p=\"z", b"\";q=\"y", b"\";;x=\"a\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;p x;x=\"a\", chunked"],
      ParamSyntax::Parameter,
      b"chunked",
    ),
    (
      &[b"gzip;p x;x=\"a\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;q;x=\"a\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    // A second admitted string behind the first, also closing in front of the
    // comma: the comparison walks the repetitions rather than stopping at the
    // first DQUOTE it sees.
    (
      &[b"gzip;;x=\"a\";y=\"b\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    // Bytes standing behind the close derive nothing, and `after_close` takes
    // them raw — but they hold no DQUOTE, so the comma behind them is the same
    // one under both readings.
    (
      &[b"gzip;;x=\"a\"junk, chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    // §10.1.4's `BWS` is what admits this string and §5.6.6 admits none here,
    // so the two productions reach the same answer by opposite routes.
    (
      &[b"gzip;;p = \"a\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;;p = \"a\", chunked"],
      ParamSyntax::Parameter,
      b"chunked",
    ),
    // A DQUOTE at an admitted position the greedy reading never reaches,
    // because the string an earlier one opens swallows it. That is the shape
    // that manufactures a member where the exposed string COVERS the comma; it
    // costs nothing where the exposed string closes in front of it, and this is
    // that half.
    (
      &[b"gzip;;a=\"x;b=\"y\", chunked"],
      ParamSyntax::TransferParameter,
      b"chunked",
    ),
    (
      &[b"gzip;;a=\"x;b=\"y\", chunked"],
      ParamSyntax::Parameter,
      b"chunked",
    ),
    (
      &[b"gzip;p x, y\"z;a=\"q;b=\"r\", second"],
      ParamSyntax::Parameter,
      b"second",
    ),
  ];
  for &(lines, syntax, behind) in INPUTS {
    let mut walk = parameterised_list(lines.iter().copied(), syntax);
    let first = walk.next().expect("a member").expect("its name is a token");
    assert!(
      first.params().any(|param| param.is_err()),
      "{lines:?} {syntax:?}"
    );
    assert_eq!(
      walk
        .next()
        .expect("the member the refusal must not hide")
        .expect("its name is a token")
        .name(),
      behind,
      "{lines:?} {syntax:?}"
    );
  }

  // The same input entered MID-LINE and at offset 0 of a LATER field line. The
  // member in front of the fault is yielded as itself, the refused one carries
  // its fault, and the one behind it is still reported — the cursor the
  // comparison is asked from moves with the entrance and the answer does not.
  for lines in [
    &[b"a, gzip;;x=\"a\", chunked".as_slice()][..],
    &[b"a".as_slice(), b"gzip;;x=\"a\", chunked"][..],
  ] {
    let mut walk = parameterised_list(lines.iter().copied(), ParamSyntax::TransferParameter);
    assert_eq!(
      walk.next().expect("a").expect("a token").name(),
      b"a",
      "{lines:?}"
    );
    let coding = walk.next().expect("gzip").expect("a token");
    assert!(coding.params().any(|param| param.is_err()), "{lines:?}");
    assert_eq!(
      walk.next().expect("chunked").expect("a token").name(),
      b"chunked",
      "{lines:?}"
    );
    assert!(walk.next().is_none(), "{lines:?}");
  }
}

// The other half of the same rule, and what keeps it from costing a member.
//
// A repetition whose own extent was cut by a RAW scan can be cut INSIDE bytes
// the sender wrote as a quoted-string, and that cut stands: under RFC 9110
// §5.6.6's `parameter` a `p ` is no `parameter-name`, so no `parameter-value`
// begins behind it and the DQUOTE opens nothing at all — no reading of that
// production puts a string over the comma. What is LEFT of the member is then
// got past by a raw scan rather than read as members of its own: `b"` and `x"y`
// below are the tail of a string a refused member wrote and are no `token`, so
// the walk crosses them and resumes at the member the sender really did write.
// Reading those remains would have reported a member the sender never named and
// ended the walk on it — which is the same harm one level along.
#[test]
fn what_is_left_of_a_refused_member_is_got_past_and_not_read() {
  for (lines, syntax, behind) in [
    (
      &[b"m;p =\"a,b\", second".as_slice()][..],
      ParamSyntax::Parameter,
      b"second".as_slice(),
    ),
    (
      &[b"m;p =\"a,b\", second, third".as_slice()][..],
      ParamSyntax::Parameter,
      b"second".as_slice(),
    ),
    (
      &[b"gzip;p = \"a,b\", chunked".as_slice()][..],
      ParamSyntax::Parameter,
      b"chunked".as_slice(),
    ),
    (
      &[b"gzip;p=\"a".as_slice(), b"\";q = \"b,c\", chunked"][..],
      ParamSyntax::Parameter,
      b"chunked".as_slice(),
    ),
  ] {
    let mut walk = parameterised_list(lines.iter().copied(), syntax);
    let member = walk.next().expect("a member").expect("its name is a token");
    assert!(member.params().any(|p| p.is_err()), "{lines:?} {syntax:?}");
    assert_eq!(
      walk
        .next()
        .expect("the member behind the refused one")
        .expect("its name is a token")
        .name(),
      behind,
      "{lines:?} {syntax:?}"
    );
  }

  // The same where the refusal is the member's OWN value running on past a close
  // that happened on a later field line. RFC 9110 §5.6.6's
  // `parameter-value = ( token / quoted-string )` takes one alternative whole,
  // so `ju"nk` derives nothing and `after_close` has already taken the rest of
  // that REPETITION raw — and `x"y`, which is what is left of the member behind
  // the comma, is no `token` and is crossed rather than read.
  let lines: [&[u8]; 2] = [b"m;p=\"a", b"r\"ju\"nk, x\"y, second"];
  let mut walk = parameterised_list(lines, ParamSyntax::Parameter);
  let member = walk.next().expect("a member").expect("m is a token");
  assert_eq!(member.name(), b"m");
  assert_eq!(
    member.params().next().expect("p").unwrap_err(),
    ListError::NotAToken
  );
  assert_eq!(
    walk
      .next()
      .expect("the member behind the refused one")
      .expect("second is a token")
      .name(),
    b"second"
  );
  assert!(walk.next().is_none());

  // And an element of the refused member that opens a string of its own is not
  // crossed at all. The `w` parameter below puts a DQUOTE at the one position
  // RFC 9110 §5.6.6 admits one, so a raw scan across `y"z;w="a, chunked, b"`
  // would resume wherever that string's commas fall and hand back a `chunked`
  // that stood inside it — the same manufacture one level out, and the same
  // refusal to guess.
  let mut walk = parameterised_list(
    [b"gzip;p x, y\"z;w=\"a, chunked, b\", second".as_slice()],
    ParamSyntax::Parameter,
  );
  assert_eq!(
    walk.next().expect("a member").expect("a token").name(),
    b"gzip"
  );
  assert_eq!(
    walk
      .next()
      .expect("the walk says why it stopped")
      .unwrap_err(),
    ListError::MemberBoundaryUnknown
  );
  assert!(walk.next().is_none());
}

// The two levels, kept apart. RFC 9110 §5.6.1.2 makes an empty LIST element a
// recipient's obligation to ignore — "A recipient MUST parse and ignore a
// reasonable number of empty list elements" — and that holds under both
// productions, because it is the `#`-list's rule and neither `parameters` nor
// `transfer-coding` says anything about it. An empty PARAMETER slot is a
// different question with a different answer, and reading §5.6.1.2 as though it
// settled the second is exactly what let `gzip;` pass.
#[test]
fn an_empty_list_element_is_ignored_under_both_productions() {
  for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
    let mut walk = parameterised_list([b", gzip ,, chunked,".as_slice()], syntax);
    assert_eq!(
      walk.next().expect("gzip").expect("a token").name(),
      b"gzip",
      "{syntax:?}"
    );
    assert_eq!(
      walk.next().expect("chunked").expect("a token").name(),
      b"chunked",
      "{syntax:?}"
    );
    assert!(walk.next().is_none(), "{syntax:?}");
  }
}

// The third difference between the two productions, and the one this walk
// carries in `name_ok` rather than in `ParamSyntax`. RFC 9110 §10.1.4 writes
// `transfer-coding = token *( OWS ";" OWS transfer-parameter )`, so the head
// token is INSIDE the rule that carries the parameters and a `TE` or
// `Transfer-Encoding` member name is §5.6.2's `token` and nothing else — while
// §5.6.6's `parameters` has no head of its own and `media` supplies §8.3.1's
// `type "/" subtype` for one. `parameterised_list` is the only entry point that
// can select `TransferParameter`, and it supplies `is_token`, which is that
// pairing.
#[test]
fn the_head_token_belongs_to_10_1_4s_own_rule() {
  for field in [
    // §8.3.1's member name, which §10.1.4 does not spell.
    b"application/json;charset=utf-8".as_slice(),
    // No head at all: `token = 1*tchar` names at least one character.
    b";p=x",
    // Whitespace inside the head is no part of a token either.
    b"gzip x;p=1",
  ] {
    assert_eq!(
      parameterised_list([field], ParamSyntax::TransferParameter)
        .next()
        .expect("a member")
        .unwrap_err(),
      ListError::NotAToken,
      "{field:?}"
    );
  }
  // And the head §10.1.4 does spell, with the repetition run zero times: the
  // `t-codings` member that is the literal `trailers` walks as the token it is.
  assert_eq!(
    parameterised_list([b"trailers".as_slice()], ParamSyntax::TransferParameter)
      .next()
      .expect("a member")
      .expect("a token")
      .name(),
    b"trailers"
  );
}

#[test]
fn a_token_and_a_missing_value_unescape_to_themselves() {
  assert!(
    ParamValue::Token(b"utf-8")
      .unescaped()
      .eq(b"utf-8".iter().copied())
  );
  assert_eq!(ParamValue::None.unescaped().count(), 0);
}

#[test]
fn unescape_into_writes_nothing_when_the_slice_is_short() {
  let v = ParamValue::Quoted(br#"a\"b"#);
  let mut out = [0xAAu8; 2];
  assert_eq!(
    v.unescape_into(&mut out),
    Err(BufferTooSmall { need: 3, have: 2 })
  );
  assert_eq!(out, [0xAA, 0xAA], "a failed call must not have written");

  // The EXACT fit, `need == out.len()`: the boundary between the two arms, and
  // the seat an off-by-one in a two-pass buffer API takes.
  let mut out = [0xAAu8; 3];
  assert_eq!(v.unescape_into(&mut out), Ok(3));
  assert_eq!(out, *br#"a"b"#);

  let mut out = [0u8; 8];
  assert_eq!(v.unescape_into(&mut out), Ok(3));
  assert_eq!(out.get(..3), Some(br#"a"b"#.as_slice()));
}

#[test]
fn eq_unescaped_answers_the_charset_question_without_a_buffer() {
  assert!(ParamValue::Quoted(b"UTF-8").eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(ParamValue::Quoted(br#"utf\-8"#).eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(ParamValue::Token(b"utf-8").eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(!ParamValue::Quoted(b"utf-8").eq_unescaped_ignore_ascii_case("utf-88"));
  assert!(!ParamValue::Quoted(b"utf-88").eq_unescaped_ignore_ascii_case("utf-8"));
  assert!(ParamValue::None.eq_unescaped_ignore_ascii_case(""));
  assert!(!ParamValue::None.eq_unescaped_ignore_ascii_case("x"));
}

// RFC 9110 §7.8's `Upgrade = #protocol` asked of a SENDER, which §5.6.1.1
// makes a stricter question than the same production asked of a recipient: "In
// any production that uses the list construct, a sender MUST NOT generate empty
// list elements". The three shapes an empty element takes — leading, trailing
// and doubled — are each refused, and each of them passed while this walk took
// its elements from `list_elements`.
#[test]
fn a_sender_may_not_generate_an_empty_protocol_list_element() {
  for bad in [
    &b""[..],
    b",",
    b",websocket",
    b"websocket,",
    b"a,,b",
    b"websocket, ,h2c",
  ] {
    assert!(!is_protocol_list(bad), "{bad:?} must not be sendable");
  }
  for good in [&b"websocket"[..], b"a,b", b"websocket, h2c", b"HTTP/1.1"] {
    assert!(is_protocol_list(good), "{good:?} must be sendable");
  }
}

// The RECIPIENT half of the same production, and the asymmetry is normative:
// §5.6.1.2 has a recipient "parse and ignore a reasonable number of empty list
// elements", so the values above that a sender may not write are values a
// recipient must still read.
#[test]
fn a_recipient_reads_the_empty_elements_a_sender_may_not_write() {
  for tolerated in [&b",websocket"[..], b"websocket,", b"a,,b"] {
    assert!(
      lists_a_protocol([tolerated].into_iter()),
      "{tolerated:?} must be readable"
    );
    assert!(!is_protocol_list(tolerated), "and not writable");
  }
  // What tolerance does NOT extend to: a non-empty element that is not a
  // `protocol`, and a value that names no protocol at all.
  assert!(!lists_a_protocol([&b"web socket"[..]].into_iter()));
  assert!(!lists_a_protocol([&b","[..]].into_iter()));
}

// A §5.6.4 quoted-string is admitted at a POSITION, and the two lists
// `sender_list_shape` is asked about admit one nowhere. RFC 9110 §7.6.1's
// `Connection = #connection-option` with `connection-option = token`, and
// §7.8's `Upgrade = #protocol` built out of `protocol-name` and
// `protocol-version`, are `token`s throughout, and §5.6.2's `tchar` excludes
// DQUOTE. So every comma in such a value is §5.6.1's separator, and every
// element those commas delimit is counted.
//
// Each `buried` value below answered `Sendable` while this walk read a DQUOTE
// as an opener: a phantom string spanned the commas, and the empty element
// §5.6.1.1 forbids a sender to generate went uncounted in a value this core was
// being asked to write.
#[test]
fn a_dquote_opens_no_string_in_a_list_of_tokens() {
  for buried in [
    &b"a\",,\""[..],
    b"a\",,\",b",
    b"keep-alive\",,\", close",
    b"\"a,,b\"",
    // The OWS §5.6.1.2 puts on both sides of the comma is not content, so an
    // element that is nothing but OWS is empty however it is quoted.
    b"a\", ,\"b",
    b"close, ,close",
    // A trailing comma, hidden the same way: the string that would have
    // swallowed it never opens.
    b"a\",",
    b"a\",,",
  ] {
    assert!(
      sender_list_shape(buried) == ListShape::EmptyElement,
      "{buried:?} states an empty element §5.6.1.1 forbids"
    );
  }

  // The other half of the same rule: an unpaired DQUOTE ends no list. It is one
  // byte of the element it fell in, that element is no `token`, and the SHAPE
  // question is still answerable — which is what lets the field's own grammar
  // report the fault the sender's bytes actually have, instead of this reporting
  // a value that is not a list at all.
  for shaped in [
    &b"a\""[..],
    b"keep-alive\"x, close",
    b"a\\\"",
    b"\"",
    b"a\",b",
    b"websocket\"x, h2c",
    b"a\"\"b",
    b"\"a,b\"",
  ] {
    assert!(
      sender_list_shape(shaped) == ListShape::Sendable,
      "{shaped:?} is a list, and no element of it is empty"
    );
    assert!(
      !is_sender_token_list(shaped) && !is_protocol_list(shaped),
      "{shaped:?} is refused by the element grammar, which is where a DQUOTE fails"
    );
  }

  // The unquoted answers, unmoved: this rule is about which bytes delimit, and a
  // value with no DQUOTE in it was always delimited this way.
  assert!(sender_list_shape(b"close") == ListShape::Sendable);
  assert!(sender_list_shape(b"close, keep-alive") == ListShape::Sendable);
  assert!(sender_list_shape(b"close,") == ListShape::EmptyElement);
  assert!(sender_list_shape(b",close") == ListShape::EmptyElement);
  assert!(sender_list_shape(b"a,,b") == ListShape::EmptyElement);
  assert!(sender_list_shape(b"") == ListShape::EmptyElement);

  // The comma is the ONLY delimiter either of these lists has, which is what
  // separates them from §5.6.6's `parameters`. Neither §7.6.1's
  // `connection-option` nor §7.8's `protocol` admits a `;`, so a `;` is one more
  // byte of its element — not the opening of a repetition — and the element it
  // fell in is no `token`.
  assert!(
    !is_protocol_list(b"websocket;h2c"),
    "`;` delimits nothing here: `websocket;h2c` is ONE element and no `protocol`"
  );
  assert!(!is_sender_token_list(b"close;q=1"));
  assert!(
    sender_list_shape(b"a;") == ListShape::Sendable,
    "`a;` is one non-empty element, not one element and an empty one"
  );
}

// The comparison `ParamValue` does not derive, written the way its own doc
// directs a caller — beside `MediaType`'s and `MediaRange`'s equivalents in
// `media::tests`, and for the same reason. RFC 9110 §5.6.6: "A parameter value
// that matches the token production can be transmitted either as a token or
// within a quoted-string.  The quoted and unquoted values are equivalent." The
// derive answered `false` for exactly the spellings that sentence equates.
#[test]
fn one_parameter_value_written_two_ways_is_compared_unescaped() {
  fn value(field: &[u8]) -> ParamValue<'_> {
    parameterised_list([field], ParamSyntax::Parameter)
      .next()
      .expect("one member")
      .expect("well formed")
      .params()
      .next()
      .expect("one parameter")
      .expect("well formed")
      .1
  }

  // §5.6.6's own equivalence: one value, as a `token` and inside a
  // `quoted-string`. Two variants, which is half of what the derive compared.
  let token = value(b"ext; charset=utf-8");
  let quoted = value(b"ext; charset=\"utf-8\"");
  assert!(matches!(token, ParamValue::Token(b"utf-8")));
  assert!(matches!(quoted, ParamValue::Quoted(b"utf-8")));
  assert!(token.unescaped().eq(quoted.unescaped()));

  // §5.6.4's `quoted-pair` MUST spells the same value a third way, and this
  // pair differs in the BYTES the derive compared rather than in the variant.
  let escaped = value(b"ext; charset=\"utf\\-8\"");
  assert!(matches!(escaped, ParamValue::Quoted(b"utf\\-8")));
  assert!(escaped.unescaped().eq(token.unescaped()));
  assert!(escaped.unescaped().eq(quoted.unescaped()));
}

// And the comparison `ListMember` does not derive. `params` is the untrimmed
// remainder after the member's first `;`, so the `OWS` §5.6.6's
// `parameters = *( OWS ";" OWS [ parameter ] )` puts around that `;` sat in the
// bytes the derive compared, and these two members differ in nothing else.
#[test]
fn one_list_member_written_two_ways_is_compared_by_its_pieces() {
  fn member(field: &[u8]) -> ListMember<'_> {
    parameterised_list([field], ParamSyntax::Parameter)
      .next()
      .expect("one member")
      .expect("well formed")
  }

  let tight = member(b"ext;q=1");
  let spaced = member(b"ext;  q=1");
  assert!(tight.name().eq_ignore_ascii_case(spaced.name()));
  for (a, b) in tight.params().zip(spaced.params()) {
    let (a_name, a_value) = a.expect("well formed");
    let (b_name, b_value) = b.expect("well formed");
    assert!(a_name.eq_ignore_ascii_case(b_name));
    assert!(a_value.unescaped().eq(b_value.unescaped()));
  }
  assert_eq!(tight.params().count(), 1);
  assert_eq!(tight.params().count(), spaced.params().count());
}

/// Tests that collect into a `Vec`: gated to the tiers that have a heap, since
/// the bare `no_std` tier has neither an allocator nor the `alloc as std` alias.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
mod heap {
  use crate::grammar::*;
  use std::vec::Vec;

  // RFC 9110 §5.6.1 #-list over bytes.
  #[test]
  fn list_elements_splits_and_skips_empties() {
    let v: Vec<&[u8]> = list_elements(b" chunked ,, gzip,x ").collect();
    assert_eq!(
      v,
      [b"chunked".as_slice(), b"gzip".as_slice(), b"x".as_slice()]
    );
  }

  // RFC 6455 §9.1: extension-list is a #-list of extensions, each with
  // `token [ "=" ( token / quoted-string ) ]` parameters.
  #[test]
  fn parameterised_list_keeps_quoted_separators_inside_their_string() {
    let v = b"permessage-deflate; client_max_window_bits=10, x-private; note=\"a,b;c\"";
    let members: Vec<_> = parameterised_list([v.as_slice()], ParamSyntax::Parameter)
      .map(|m| m.unwrap())
      .collect();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].name(), b"permessage-deflate");
    assert_eq!(members[1].name(), b"x-private");

    let p0: Vec<_> = members[0].params().map(|p| p.unwrap()).collect();
    assert!(matches!(
      p0[..],
      [(b"client_max_window_bits", ParamValue::Token(b"10"))]
    ));

    let p1: Vec<_> = members[1].params().map(|p| p.unwrap()).collect();
    assert!(matches!(p1[..], [(b"note", ParamValue::Quoted(b"a,b;c"))]));
  }

  // RFC 9110 §5.6.4: a backslash escapes the next character inside a
  // quoted-string.
  #[test]
  fn parameterised_list_carries_escapes_through() {
    let v = b"ext; q=\"a\\\"b\"";
    let m = parameterised_list([v.as_slice()], ParamSyntax::Parameter)
      .next()
      .unwrap()
      .unwrap();
    let p: Vec<_> = m.params().map(|p| p.unwrap()).collect();
    assert!(matches!(p[..], [(b"q", ParamValue::Quoted(b"a\\\"b"))]));
  }

  // RFC 9110 §5.6.1.2: a recipient ignores empty list elements.
  #[test]
  fn parameterised_list_ignores_empty_elements() {
    let v = b", ext ,, other,";
    let names: Vec<_> = parameterised_list([v.as_slice()], ParamSyntax::Parameter)
      .map(|m| m.unwrap().name().to_vec())
      .collect();
    assert_eq!(names, [b"ext".to_vec(), b"other".to_vec()]);
  }

  // RFC 6455 §9.1 permits splitting the field across lines; RFC 9110 §5.2 makes
  // them one comma-joined value.
  #[test]
  fn a_list_split_across_field_lines_is_one_list() {
    let lines: [&[u8]; 2] = [
      b"permessage-deflate; server_no_context_takeover",
      b"x-private",
    ];
    let names: Vec<_> = parameterised_list(lines, ParamSyntax::Parameter)
      .map(|m| m.unwrap().name().to_vec())
      .collect();
    assert_eq!(
      names,
      [b"permessage-deflate".to_vec(), b"x-private".to_vec()]
    );
  }

  // The §5.2 join's comma is DATA inside an open quoted-string
  // (`grammar::scan_quoted_after_join`): the two lines are ONE member, and the
  // member after it is found at the right place. The spanning VALUE is not one
  // slice, so reading it is a named refusal rather than a mis-slice.
  #[test]
  fn a_quoted_value_spanning_the_join_keeps_the_boundaries_and_refuses_the_value() {
    let lines: [&[u8]; 2] = [b"ext; q=\"a", b"b\", other"];
    let members: Vec<_> = parameterised_list(lines, ParamSyntax::Parameter).collect();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].as_ref().unwrap().name(), b"ext");
    assert_eq!(members[1].as_ref().unwrap().name(), b"other");
    let p = members[0].unwrap().params().next().unwrap();
    assert_eq!(p.unwrap_err(), ListError::ValueSpansFieldLines);
  }

  #[test]
  fn unescaping_removes_the_backslash_and_keeps_the_octet() {
    let v = ParamValue::Quoted(br#"a\"b\\c"#);
    let got: Vec<u8> = v.unescaped().collect();
    assert_eq!(got.as_slice(), br#"a"b\c"#);
  }
}

// The all-readings question answered by ENUMERATION rather than by a state
// set: whether some reading of `value`, standing outside every RFC 9110 §5.6.4
// quoted-string at `from`, holds `target` inside one.
//
// Written as the definition reads. At each position an admitted DQUOTE offers,
// the reading either opens the string — followed WHOLE by `scan_quoted`, and
// covering `target` when its close lies behind it — or leaves it shut, which is
// the loop continuing. A string that never closes covers everything left. It is
// exponential in the number of admitted positions and that is the point: it is
// what `readings_at` must agree with, and it shares nothing with it but
// `param_value_at`, which answers where a string may open at all and is pinned
// by its own tests.
fn some_reading_covers(value: &[u8], from: usize, target: usize, syntax: ParamSyntax) -> bool {
  let mut at = from;
  let mut opener = None;
  while at < target {
    if value[at] == b';' {
      opener = param_value_at(value, skip_ows(value, at + 1), syntax)
        .filter(|&value_at| value.get(value_at) == Some(&b'"'));
    }
    if opener == Some(at) {
      match scan_quoted(value, at + 1, false) {
        // Inside for every offset behind the DQUOTE and in front of the close.
        QuotedScan::Closed(close) if close > target => return true,
        // Outside again at the close, and reading on from there.
        QuotedScan::Closed(close) => {
          if some_reading_covers(value, close, target, syntax) {
            return true;
          }
        }
        // No close at all, so this reading is inside at every offset left.
        QuotedScan::Open { .. } | QuotedScan::Invalid => return true,
      }
    }
    at += 1;
  }
  false
}

// Where the readings of `value` from `from` END the member, answered by
// ENUMERATION rather than by asking about one offset: `Some(end)` where every
// reading ends the member at `end`, and `None` where any two of them differ.
//
// This is the whole of what `refused_member_end` claims, and it is the half a
// coverage question alone does not state. Asking whether some reading holds ONE
// comma inside a string proves that comma is a separator in every reading; it
// does not prove that no reading had ended the member at an EARLIER comma, and
// a reading that did is one in which the bytes between the two are a member of
// their own.
//
// A reading ends the member at the first comma it stands outside an RFC 9110
// §5.6.4 quoted-string at. Where a string it opened never closes it ends the
// member nowhere on this line — not even at the end of it, which §5.2's join
// makes a comma inside that string — and `usize::MAX` stands for that and
// agrees with no finite end. The reading that opens nothing always ends at a
// finite offset, so a disagreement is always a real one.
fn every_reading_ends_at(value: &[u8], from: usize, syntax: ParamSyntax) -> Option<usize> {
  let mut at = from;
  let mut opener = None;
  while at < value.len() {
    if value[at] == b',' {
      return Some(at);
    }
    if value[at] == b';' {
      opener = param_value_at(value, skip_ows(value, at + 1), syntax)
        .filter(|&value_at| value.get(value_at) == Some(&b'"'));
    }
    if opener == Some(at) {
      let opened = match scan_quoted(value, at + 1, false) {
        QuotedScan::Closed(close) => every_reading_ends_at(value, close, syntax),
        QuotedScan::Open { .. } | QuotedScan::Invalid => Some(usize::MAX),
      };
      let shut = every_reading_ends_at(value, at + 1, syntax);
      return match (opened, shut) {
        (Some(opened), Some(shut)) if opened == shut => Some(opened),
        _ => None,
      };
    }
    at += 1;
  }
  Some(value.len())
}

// A deterministic 64-bit xorshift, so the pseudorandom half of the corpus is
// the same corpus on every machine and every run.
fn xorshift(state: &mut u64) -> u64 {
  *state ^= *state << 13;
  *state ^= *state >> 7;
  *state ^= *state << 17;
  *state
}

// One question of the corpus: the subset construction must reach the same
// answer the enumeration does, the boundary the walk certifies must be the one
// EVERY reading ends the member at, and no member the WALK yields over these
// bytes may begin at an offset some reading holds inside a string.
//
// Returns how many of the two answers were REFUSALS, how many members the two
// walks yielded, and how many of them stood in the shape a candidate taken from
// the greedily cut extent gets wrong — so the corpus can be shown to reach both
// sides of the rule, and to reach that shape, rather than to be asserted about
// vacuously.
fn check_one(value: &[u8]) -> (u64, u64, u64) {
  let mut refused = 0u64;
  let mut members = 0u64;
  let mut shaped = 0u64;
  for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
    // Every entrance stands ON the fault, which is the last offset each reading
    // is known to be outside a string at: `seek` and the arm behind RFC 9110
    // §5.2's join on an element of the refused member — the bare half of the
    // corpus — and `scan_parameters` on the `;` that opened the refused
    // repetition, which is offset 0 of the `;`-led half.
    {
      let end = raw_comma_end(value, 0);
      let enumerated = some_reading_covers(value, 0, end, syntax);
      assert_eq!(
        readings_at(value, 0, end, syntax).covers(),
        enumerated,
        "{value:?} {syntax:?}"
      );
      // A boundary some reading holds inside a string is never taken: where
      // this hands back an offset, the enumeration says every reading stands
      // outside there. And a boundary every reading agrees about is never
      // withheld: where the enumeration says none covers it, it is handed
      // back.
      assert_eq!(
        refused_member_end(value, 0, syntax),
        (!enumerated).then_some(end),
        "{value:?} {syntax:?}"
      );
      // The same answer against an enumeration that computes each reading's
      // OWN member end rather than asking about one offset. This is the half
      // that says no reading terminated in front of the comma being certified,
      // and a candidate taken from anywhere behind the fault fails it.
      assert_eq!(
        refused_member_end(value, 0, syntax),
        every_reading_ends_at(value, 0, syntax),
        "{value:?} {syntax:?}"
      );
      refused += u64::from(enumerated);
      // The shape: a refused repetition whose extent `parameter_end` cut by
      // opening its string runs PAST this comma, to a later one no reading
      // holds inside a string. A candidate taken from that extent would be
      // certified; the reading that leaves the string shut ended the member
      // here, so the answer is that there is no boundary to give.
      if value.first() == Some(&b';')
        && let (Delim::At(cut), _) = parameter_end(value, 1, syntax)
        && let greedy = raw_comma_end(value, cut)
        && greedy != end
        && !readings_at(value, 0, greedy, syntax).covers()
      {
        shaped += 1;
        assert_eq!(
          refused_member_end(value, 0, syntax),
          None,
          "{value:?} {syntax:?}"
        );
      }
    }
    // The boundary property, carried through to what the caller is handed. A
    // member begins where the walk resumed, and the walk resumes only at an
    // offset `refused_member_end` vouched for — so an offset some reading holds
    // inside a quoted-string is one no member may begin at. This asserts that
    // conclusion rather than the induction behind it: the head member begins at
    // 0 and is skipped, and every other one was found behind a boundary.
    for member in parameterised_list([value], syntax).flatten() {
      members += 1;
      let at = member.name().as_ptr() as usize - value.as_ptr() as usize;
      assert!(
        at == 0 || !some_reading_covers(value, 0, at, syntax),
        "member from inside a value: {value:?} {at} {syntax:?}"
      );
    }
  }
  (refused, members, shaped)
}

// Why the walk carries the same guard twice, asserted rather than argued.
//
// `ParameterisedList::member` reaches `after_close` where a parameter's value
// closed on a LATER field line than the member began on and bytes that derive
// nothing stand behind that close. It asks `refused_member_end` there, and
// where the answer is `None` it leaves the walk unresolved rather than
// recovering. `ParameterisedList::seek` carries the same guard one step later.
// Dropping the first of the two moves no answer, which is a thing to be able to
// SAY rather than to discover: the two overlap, and a reader with only the code
// in front of them cannot tell an overlap from a guard that is dead.
//
// The reason is a fact about where `after_close` can leave the cursor. Behind a
// close whose trailing bytes derive nothing it takes the rest of that
// repetition raw, with `raw_run_end`, and that run has exactly three ends: the
// `;` RFC 9110 §5.6.6 opens the next repetition with, §5.6.1.2's `,`, and the
// end of the field line. At the `,` and at the end there is nothing in front
// of the candidate comma for a string to open in, so a boundary is always
// derivable there and the `None` branch is unreachable. That leaves the `;`,
// and no member opens on one: this walk reads a member name to the first `;`
// or `,`, and RFC 9110 §5.6.2 spells a `token` `1*tchar` while §8.3.1 spells a
// media type `type "/" subtype`, so the empty element a `;` leaves in front of
// it is a name under neither. `next` therefore reaches `seek` and not
// `member`, at that same offset, and asks `refused_member_end` the identical
// question.
//
// `ext;q="a` + `"junk; r="b, second` in
// `a_refused_remainder_does_not_swallow_the_member_behind_it` is that path
// walked end to end; this is the rule underneath it, over every string family
// A's alphabet spells to seven bytes and at every offset a close could stand
// at.
#[test]
fn a_joined_refusal_leaves_the_cursor_where_no_member_opens() {
  const ALPHA: &[u8] = b"t;=\",";
  const LONGEST: usize = 7;

  let mut buffer = [0u8; LONGEST];
  // How many times the `None` branch was reached at all. A sweep that never
  // reached it would assert nothing and pass.
  let mut landed = 0u64;
  let base = ALPHA.len() as u64;
  for len in 0..=LONGEST {
    let count = base.pow(len as u32);
    for mut index in 0..count {
      for slot in buffer.iter_mut().take(len) {
        *slot = ALPHA[(index % base) as usize];
        index /= base;
      }
      let value = &buffer[..len];
      for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
        for end in 0..=len {
          let (at, trails) = after_close(value, end);
          if !trails || refused_member_end(value, at, syntax).is_some() {
            continue;
          }
          landed += 1;
          // The only one of the three ends at which a boundary can fail to be
          // derivable.
          assert_eq!(value.get(at), Some(&b';'), "{value:?} {end} {syntax:?}");
          // And the element standing there is empty, so no name grammar this
          // walk is entered with admits it: the cursor is one `seek` is asked
          // about next, and `seek` asks the question just asked.
          let element = trim_ows(value.get(at..raw_run_end(value, at)).unwrap_or_default());
          assert!(element.is_empty(), "{value:?} {end} {syntax:?}");
          assert!(!is_token(element), "{value:?} {end} {syntax:?}");
        }
      }
    }
  }
  assert_eq!(landed, 858);
}

// The same corpus section, walked END TO END with a member NAME in front of it.
//
// `check_one` spells each section bare and behind a leading `;`, and neither
// spelling reaches the shape it counts through the WALK. A `;`-led section's
// member name is empty, so `ParameterisedList` refuses it before `member_end`
// has handed `scan_parameters` a `;` to stand on, and the shape is put to
// `refused_member_end` directly and to nothing else. One `tchar` in front of
// that `;` is the whole difference: `member_end` reads it as the name RFC 9110
// §5.6.6 concatenates `parameters` behind, `scan_parameters` finds the fault at
// the repetition, and the deferral comes back out of the walk as
// `ListError::MemberBoundaryUnknown`. `t;t=","t,t` is one such section, and
// `the_shortest_named_section_in_the_shape_is_pinned` holds it on its own.
//
// The predicate question is deliberately NOT re-asked here, and what this
// counts is only the walk's. The bytes from that entrance are the `;`-led
// section's own, so `refused_member_end(t;X, 1)` is `refused_member_end(;X, 0)`
// shifted by one — one question asked twice, so re-introducing it here would
// buy no evidence and cost the refusal count its meaning.
//
// Returns the members the two walks yielded — each checked to begin where no
// reading holds a quoted-string open — how many of the two stood in the shape,
// and how many of those the walk deferred on. The shape is geometry and says
// nothing about whether the repetition DERIVES: `t;t=","` stands in it and is a
// conforming `parameter`, so the two counts are not the same count and the
// second is a proper part of the first.
fn walk_one(value: &[u8]) -> (u64, u64, u64) {
  let mut members = 0u64;
  let mut in_shape = 0u64;
  let mut deferred = 0u64;
  for syntax in [ParamSyntax::Parameter, ParamSyntax::TransferParameter] {
    // Walked once, with no collection to hold it in: the bare `no_std` tier
    // has no allocator and this test runs there too.
    let mut head = None;
    let mut deferring = false;
    for item in parameterised_list([value], syntax) {
      match item {
        Ok(member) => {
          members += 1;
          let at = member.name().as_ptr() as usize - value.as_ptr() as usize;
          assert!(
            at == 0 || !some_reading_covers(value, 0, at, syntax),
            "member from inside a value: {value:?} {at} {syntax:?}"
          );
          head = head.or(Some(member.name()));
          deferring = false;
        }
        Err(fault) => deferring = fault == ListError::MemberBoundaryUnknown,
      }
    }
    // The shape, at the entrance the walk itself stands on: the extent
    // `parameter_end` cuts for the first repetition — by opening that
    // repetition's own string — runs past the comma taken from the `;` to a
    // later one no reading holds inside a string. That later comma is where a
    // candidate taken from the extent would have been certified, and the walk
    // would have resumed behind whatever the sender wrote between the two.
    let shaped = matches!(
      parameter_end(value, 2, syntax),
      (Delim::At(cut), _)
        if raw_comma_end(value, cut) != raw_comma_end(value, 1)
          && !readings_at(value, 1, raw_comma_end(value, cut), syntax).covers()
    );
    if !shaped {
      continue;
    }
    in_shape += 1;
    if deferring {
      deferred += 1;
      // The member in front of the fault is still reported, so the deferral
      // costs the caller nothing that was derivable, and the walk's last word
      // is that the value stopped being readable — nothing standing behind a
      // boundary it cannot place is named as a member of the list.
      assert_eq!(head, Some(&b"t"[..]), "{value:?} {syntax:?}");
    }
  }
  (members, in_shape, deferred)
}

// The property, proved over a generated corpus rather than sampled.
//
// `refused_member_end` hands back the earliest comma FROM THE FAULT exactly
// where NO reading of the bytes in front of it holds that offset inside an RFC
// 9110 §5.6.4 quoted-string. `readings_at` decides that with a set of three
// flags carried one byte at a time; `some_reading_covers` decides it by walking
// every choice. Over every input below the two must agree, which is both halves
// of the property at once: a boundary some reading holds inside a string is
// never taken, and a boundary every reading agrees about is never withheld. The
// walk itself is then run over the same bytes, and no member it yields may
// begin at an offset the enumeration says a reading covers.
//
// `every_reading_ends_at` is the third question, and it is the one a coverage
// oracle cannot ask: whether every reading ends the member at the offset being
// certified, rather than merely standing outside a string at it. A reading that
// ended the member at an EARLIER comma reads the bytes between the two as a
// member of its own, and certifying the later offset hides it.
//
// The corpus is exhaustive where the shapes that matter are short. The class a
// comparison of two readings misses needs a string that swallows the DQUOTE of
// a LATER admitted value position, and the shortest of those is nine bytes —
// `;t=";t=",` — so the `;`-prefixed half of family A reaches it. The class an
// earlier-ending reading misses needs a repetition whose string swallows a
// comma and whose junk stands behind its close, and the shortest of those is
// seven — `;t=","t` — so that half reaches it too; `shaped` counts them. Family
// B adds the backslash of a `quoted-pair`, the SP that RFC 9110 §10.1.4's `BWS`
// admits, and an octet §5.6.4 forbids. Family C is pseudorandom and long, and
// exists because the exhaustive families stop before three admitted positions
// fit.
//
// Every section is spelled a THIRD way, with a `tchar` written in front of the
// `;`, and that spelling is `walk_one`'s. The other two reach the shape only
// through the analysis asked directly: a `;`-led section's member name is empty
// and `ParameterisedList` refuses it before `scan_parameters` is entered, so
// `shaped` counts sections at which the WALK never arrives. `walked_shaped` is
// the same shape counted where it does arrive, and `deferred` the ones it
// arrives at and stops on.
#[test]
#[cfg_attr(
  miri,
  ignore = "a few million walks: seconds natively, hours under miri, and it \
            exercises no unsafe code for miri to have an opinion about"
)]
fn every_reading_is_carried_over_a_generated_corpus() {
  /// `t` stands for any `tchar`, and the other four are the bytes the
  /// productions give meaning to.
  const ALPHA_A: &[u8] = b"t;=\",";
  /// The same plus a `quoted-pair` backslash, §10.1.4's `BWS`, and an octet
  /// §5.6.4's `qdtext` excludes.
  const ALPHA_B: &[u8] = b"t;=\", \\\x01";
  /// Two `tchar`s, so a name and a value can differ, plus a byte no production
  /// gives meaning to.
  const ALPHA_C: &[u8] = b"tu;=\", \\\x01@";
  /// Long enough for family A's nine-byte witness with its `;` prefix, and for
  /// family C's longest sample with the `t;` of the named spelling in front of
  /// it.
  const CAP: usize = 26;

  let mut buffer = [0u8; CAP];
  let mut checked = 0u64;
  let mut refused = 0u64;
  let mut members = 0u64;
  let mut shaped = 0u64;
  let mut walked = 0u64;
  let mut walked_members = 0u64;
  let mut walked_shaped = 0u64;
  let mut deferred = 0u64;

  // Families A and B, exhaustive: every string over the alphabet up to the
  // length shown, each spelled bare — the `seek` entrance, where the cursor
  // stands on an element — and behind a leading `;`, which is where
  // `scan_parameters` and the arm behind the join stand.
  for &(alphabet, longest) in &[(ALPHA_A, 8usize), (ALPHA_B, 5usize)] {
    let base = alphabet.len() as u64;
    for len in 0..=longest {
      let count = base.pow(len as u32);
      for mut index in 0..count {
        for slot in buffer.iter_mut().take(len) {
          *slot = alphabet[(index % base) as usize];
          index /= base;
        }
        let (bare_refused, bare_members, bare_shaped) = check_one(&buffer[..len]);
        buffer.copy_within(..len, 1);
        buffer[0] = b';';
        let (led_refused, led_members, led_shaped) = check_one(&buffer[..len + 1]);
        // And the same section once more with a member NAME in front of that
        // `;`, which is the only one of the three the walk reaches the shape
        // through.
        buffer.copy_within(..len + 1, 1);
        buffer[0] = b't';
        let (named_members, named_shaped, named_deferred) = walk_one(&buffer[..len + 2]);
        refused += bare_refused + led_refused;
        members += bare_members + led_members;
        shaped += bare_shaped + led_shaped;
        walked_members += named_members;
        walked_shaped += named_shaped;
        deferred += named_deferred;
        checked += 2;
        walked += 1;
      }
    }
  }

  // Family C, pseudorandom and longer.
  let mut state = 0x2026_0901_9110_5664u64;
  for _ in 0..60_000 {
    let len = 6 + (xorshift(&mut state) % 19) as usize;
    for slot in buffer.iter_mut().take(len) {
      *slot = ALPHA_C[(xorshift(&mut state) % ALPHA_C.len() as u64) as usize];
    }
    let (one_refused, one_members, one_shaped) = check_one(&buffer[..len]);
    buffer.copy_within(..len, 2);
    buffer[0] = b't';
    buffer[1] = b';';
    let (named_members, named_shaped, named_deferred) = walk_one(&buffer[..len + 2]);
    refused += one_refused;
    members += one_members;
    shaped += one_shaped;
    walked_members += named_members;
    walked_shaped += named_shaped;
    deferred += named_deferred;
    checked += 1;
    walked += 1;
  }

  // The corpus is what the argument rests on, so its size is asserted rather
  // than assumed: a generator that silently produced nothing would leave every
  // assertion above unreached and this test green. So is the number of the
  // twice-that answers that were REFUSALS — an analysis that covered nothing,
  // or covered everything, would agree with an enumeration that did the same
  // and prove neither half of the property.
  //
  // `shaped` is the count of sections in which the extent `parameter_end` cuts
  // for a refused repetition runs past the comma this rule certifies, to a
  // later one no reading covers. Those are the sections at which a candidate
  // taken from the extent rather than from the fault hides a member, and the
  // count is asserted because the corpus held them all along: the question was
  // never asked of them, and the coverage oracle above would have agreed with
  // the wrong answer if it had been.
  //
  // `walked` is the same sections again with a member name in front and
  // `walked_members` is what those walks yielded — the subjects of the
  // begins-nowhere-inside-a-value assertion, which a walk yielding nothing
  // would leave without any. `walked_shaped` is how many of those walks the
  // shape stood in front of and `deferred` how many of THOSE the walk stopped
  // on, the rest being sections whose repetition derives — the shape is
  // geometry, and `t;t=","` stands in it with a conforming `parameter`.
  //
  // `deferred` is what closes the gap the other four counts leave open.
  // `shaped` is a tally of a question put to `refused_member_end` directly, at
  // sections whose walk dies on an empty member name before `scan_parameters`
  // is entered; this is a tally of the same shape arrived at through
  // `member_end` and `scan_parameters`, and answered by the walk.
  assert_eq!(checked, 1_111_460);
  assert_eq!(refused, 14_538);
  assert_eq!(members, 150_209);
  assert_eq!(shaped, 2_039);
  assert_eq!(walked, 585_730);
  assert_eq!(walked_members, 1_325_881);
  assert_eq!(walked_shaped, 1_831);
  assert_eq!(deferred, 775);
}
