use super::*;
use crate::date::parse_http_date;

/// 2025-11-26T00:00:00Z, an arbitrary fixed clock. Only an `rfc850-date` reads
/// differently against a different one.
const NOW: i64 = 1_764_115_200;

fn push_all<'a>(fields: &[(&[u8], &'a [u8])]) -> Preconditions<'a> {
  let mut p = Preconditions::new(NOW);
  for (name, value) in fields {
    p.push(name, value);
  }
  p
}

// ── RFC 9110 §5.1: a field name is a case-insensitive token ──────────────────

#[test]
fn field_names_are_matched_case_insensitively() {
  let p = push_all(&[(b"if-match", br#""a""#), (b"IF-NONE-MATCH", br#""b""#)]);
  assert!(p.refusal().is_none());
  assert!(p.if_match().is_some());
  assert!(p.if_none_match().is_some());
}

#[test]
fn an_unrecognised_field_is_ignored() {
  let p = push_all(&[(b"user-agent", b"x")]);
  assert!(p.refusal().is_none());
  assert!(p.if_match().is_none());
}

// A value the field grammar admits and no tag fills: RFC 9110 Appendix A spells
// `If-Match` as `"*" / [ entity-tag *( OWS "," OWS entity-tag ) ]`, whose second
// alternative admits nothing at all. Present with no tags is not absent, and a
// caller reading `if_match()` sees the difference.
#[test]
fn an_empty_list_is_present_rather_than_absent() {
  let p = push_all(&[(b"If-Match", b"")]);
  assert!(p.refusal().is_none());
  let list = p.if_match().expect("an empty list is still a list");
  assert!(list.is_empty());
  assert!(!list.is_star());
}

// ── RFC 9110 §13.1.5: the two If-Range forms ─────────────────────────────────

// RFC 9110 §13.1.5: "A valid entity-tag can be distinguished from a valid
// HTTP-date by examining the first three characters for a DQUOTE."
#[test]
fn if_range_is_split_by_the_rfcs_own_rule() {
  let tag = push_all(&[(b"If-Range", br#"W/"xyzzy""#)]);
  assert!(tag.if_range_tag().is_some());
  assert!(tag.if_range_date().is_none());

  let date = push_all(&[(b"If-Range", b"Sun, 06 Nov 1994 08:49:37 GMT")]);
  assert!(date.if_range_date().is_some());
  assert!(date.if_range_tag().is_none());
}

// THREE characters, not one. `W/"xyzzy"` puts its DQUOTE third, and a test that
// only looked at the first byte would send it down the date path and report an
// If-Range the client sent as unusable.
#[test]
fn the_dquote_is_looked_for_in_all_three_leading_characters() {
  let weak = push_all(&[(b"If-Range", br#"W/"xyzzy""#)]);
  let strong = push_all(&[(b"If-Range", br#""xyzzy""#)]);
  let weak = weak.if_range_tag().expect("the weak form is a tag");
  let strong = strong.if_range_tag().expect("the strong form too");
  assert!(weak.is_weak());
  assert!(!strong.is_weak());

  // And no further than three: an `HTTP-date` carries a DQUOTE nowhere, so the
  // date form is never diverted by one appearing later in some other value.
  let p = push_all(&[(b"If-Range", b"Sun, 06 Nov 1994 08:49:37 GMT")]);
  assert!(p.if_range_tag().is_none());
}

// RFC 9110 §13.1.5's "A client MUST NOT generate an If-Range header field
// containing an entity tag that is marked as weak" is the SENDER's rule. The
// evaluation answers a weak tag with §8.8.3.2's strong comparison, which it
// fails, so the condition is false and the Range is ignored — refusing it here
// would answer with the 412 this field exists to avoid.
#[test]
fn a_weak_if_range_tag_is_read_rather_than_refused() {
  let p = push_all(&[(b"If-Range", br#"W/"xyzzy""#)]);
  assert!(p.refusal().is_none());
  let tag = p.if_range_tag().expect("read, not refused");
  assert!(tag.is_weak());
  assert_eq!(tag.opaque_tag(), b"xyzzy");
}

// An unparseable If-Range evaluates FALSE rather than refusing. RFC 9110
// §13.1.5 makes it the opposite of a lost-update guard: a mismatch transfers
// the new selected representation in place of the 412 the other conditionals
// answer with, which is the sentence the module doc quotes whole.
#[test]
fn an_unparseable_if_range_does_not_refuse() {
  let p = push_all(&[(b"If-Range", b"\"unterminated")]);
  assert!(p.refusal().is_none());
  assert!(p.if_range_tag().is_none());
  assert!(p.if_range_date().is_none());
}

// The two accessors cannot tell those two apart, and RFC 9110 §13.2.2's step 5
// must: with no If-Range the step does not run and a Range survives it, while
// an If-Range whose condition is false makes the recipient ignore the Range. So
// the state is kept rather than collapsed into the accessors' `None`.
#[test]
fn an_unusable_if_range_is_not_the_state_an_absent_one_is() {
  let absent = push_all(&[]);
  let unusable = push_all(&[(b"If-Range", b"\"unterminated")]);
  assert!(matches!(absent.if_range, IfRangeSlot::Absent));
  assert!(matches!(unusable.if_range, IfRangeSlot::PresentUnusable));
  assert!(absent.if_range_tag().is_none() && absent.if_range_date().is_none());
  assert!(unusable.if_range_tag().is_none() && unusable.if_range_date().is_none());
}

// ── RFC 9110 §13.1.3 and §13.1.4: the date fields ────────────────────────────

// The parse-time half of §13.1.3's and §13.1.4's MUST-ignore rules: a value that
// is not a valid HTTP-date is present-but-unusable, which is not the same as
// absent and not the same as false.
#[test]
fn an_unparseable_date_is_present_but_unusable() {
  let p = push_all(&[(b"If-Modified-Since", b"not a date")]);
  assert!(p.refusal().is_none(), "ignoring, not refusing");
  assert_eq!(p.if_modified_since(), DateField::PresentUnusable);

  let p = push_all(&[(
    b"If-Unmodified-Since",
    b"Sun, 06 Nov 1994 08:49:37 GMT, Mon, 07 Nov 1994 08:49:37 GMT",
  )]);
  assert_eq!(
    p.if_unmodified_since(),
    DateField::PresentUnusable,
    "§13.1.4 says including when the field value appears to be a list of dates"
  );
}

#[test]
fn an_absent_date_field_is_absent_and_not_unusable() {
  let p = push_all(&[(b"If-Match", br#""a""#)]);
  assert_eq!(p.if_modified_since(), DateField::Absent);
  assert_eq!(p.if_unmodified_since(), DateField::Absent);
}

#[test]
fn both_date_fields_read_an_imf_fixdate() {
  let p = push_all(&[
    (b"If-Modified-Since", b"Sat, 29 Oct 1994 19:43:31 GMT"),
    (b"If-Unmodified-Since", b"Sat, 29 Oct 1994 19:43:31 GMT"),
  ]);
  let DateField::Usable(since) = p.if_modified_since() else {
    panic!("§13.1.3's own example must parse")
  };
  let DateField::Usable(until) = p.if_unmodified_since() else {
    panic!("§13.1.4's own example must parse")
  };
  assert_eq!(since, until);
  assert_eq!(since.year(), 1994);
}

// The clock reaches the date parser. RFC 9110 §5.6.7's fifty-year rule measures
// against the recipient's instant, and the crate's own entry point takes it as
// an argument (`parse_http_date_from`).
#[test]
fn a_two_digit_year_is_read_against_the_supplied_clock() {
  let value = b"Sunday, 06-Nov-94 08:49:37 GMT";
  let p = push_all(&[(b"If-Modified-Since", value)]);
  let DateField::Usable(at) = p.if_modified_since() else {
    panic!("must parse")
  };
  assert_eq!(at.year(), 1994);

  // The same two digits against a clock a century on: §5.6.7's window moves
  // with the recipient, so the argument is doing work rather than being carried.
  let mut later = Preconditions::new(NOW + 100 * 365 * 24 * 60 * 60);
  later.push(b"If-Range", value);
  let at = later.if_range_date().expect("the date form of If-Range");
  assert_eq!(at.year(), 2094);
}

// ── RFC 9110 §13.1.1 and §13.1.2: the two lists that refuse ──────────────────

// The two tag lists refuse rather than ignore, because they guard against lost
// updates and a silently dropped guard is the failure they exist to prevent.
#[test]
fn a_malformed_tag_list_refuses() {
  let p = push_all(&[(b"If-Match", b"not-a-tag")]);
  assert_eq!(
    p.refusal(),
    Some(PreconditionRefusal::Malformed {
      field: TagField::IfMatch
    })
  );
  assert!(p.if_match().is_none(), "refused is not readable");
}

#[test]
fn a_malformed_if_none_match_refuses_under_its_own_name() {
  let p = push_all(&[(b"If-None-Match", b"not-a-tag")]);
  assert_eq!(
    p.refusal(),
    Some(PreconditionRefusal::Malformed {
      field: TagField::IfNoneMatch
    })
  );
}

// §13.1.1's and §13.1.2's closing note makes `*` beside another value
// syntactically invalid. That is a fault in the value, so it must arrive as
// `Malformed` and not as `TooManyTags`, which is a complaint about size.
#[test]
fn a_star_beside_another_value_is_malformed_and_not_a_size_complaint() {
  let p = push_all(&[(b"If-None-Match", br#"*, "a""#)]);
  assert_eq!(
    p.refusal(),
    Some(PreconditionRefusal::Malformed {
      field: TagField::IfNoneMatch
    })
  );
}

// The size complaint is its own cause, because it suggests a different status:
// RFC 6585 §5's 431 says the value was too large, which for a short, ill-formed
// one would be false.
#[test]
fn more_tags_than_slots_is_its_own_cause() {
  use crate::validator::MAX_TAGS;

  // `"a"` followed by `,"a"` once per slot: one tag more than `MAX_TAGS` holds,
  // which is where `TagList::parse` refuses.
  let mut value = [0u8; 3 + 4 * MAX_TAGS];
  let (first, rest) = value.split_at_mut(3);
  first.copy_from_slice(br#""a""#);
  for chunk in rest.chunks_mut(4) {
    chunk.copy_from_slice(br#","a""#);
  }
  let p = push_all(&[(b"If-Match", value.as_slice())]);
  assert_eq!(
    p.refusal(),
    Some(PreconditionRefusal::TooManyTags {
      field: TagField::IfMatch
    })
  );
}

// §13.2.2 evaluates If-Match first, so when both refuse the accessor reports
// its failure. The accessor is recipient-blind and needs one deterministic
// pick; at the origin server this is also the failure the caller acts on.
#[test]
fn if_match_wins_the_refusal_report() {
  let p = push_all(&[(b"If-Match", b"bad"), (b"If-None-Match", b"also bad")]);
  assert_eq!(
    p.refusal(),
    Some(PreconditionRefusal::Malformed {
      field: TagField::IfMatch
    })
  );
}

// And the one that lost the report is still recorded. §13.2.2 gates steps 1 and
// 2 on the recipient being the origin server, so a cache never reaches If-Match
// — it does reach If-None-Match, and a refusal it could not see would be the
// silently dropped guard this design refuses.
#[test]
fn the_refusal_that_lost_the_report_is_still_kept() {
  let p = push_all(&[(b"If-Match", b"bad"), (b"If-None-Match", b"also bad")]);
  assert!(matches!(
    p.if_none_match,
    TagSlot::Refused(PreconditionRefusal::Malformed {
      field: TagField::IfNoneMatch
    })
  ));
}

// ── RFC 9110 §14.2: Range ────────────────────────────────────────────────────

// §14.2 sanctions ignoring an unusable Range; the accessor pair says which
// happened without changing any verdict.
#[test]
fn an_unusable_range_is_ignored_and_says_so() {
  let p = push_all(&[(b"Range", b"bytes=900-800")]);
  assert!(p.range().is_none());
  assert!(p.range_ignored());

  let p = push_all(&[(b"Range", b"bytes=0-499")]);
  assert!(p.range().is_some());
  assert!(!p.range_ignored());

  let p = push_all(&[]);
  assert!(p.range().is_none());
  assert!(!p.range_ignored(), "absent is not ignored");
}

// The parse is handed back whole, so a caller that has to answer §14.2's
// would-be-200 question itself does not re-read the field to do it.
#[test]
fn the_range_reads_back_as_the_specifier_it_parsed() {
  let p = push_all(&[(b"Range", b"bytes=0-999, 4500-5499, -1000")]);
  let range = p.range().expect("§14.1.1's own example");
  assert_eq!(range.unit(), b"bytes");
  assert_eq!(range.len(), 3);
  assert!(range.is_satisfiable(10_000));
}

// ── One value per field ──────────────────────────────────────────────────────

// A second field line of a name already pushed is a value this was not given
// whole. No field picks one of the two: the lists refuse, the dates become
// unusable, and the Range is ignored.
#[test]
fn a_repeated_field_is_answered_without_choosing_between_the_two() {
  let p = push_all(&[(b"If-Match", br#""a""#), (b"If-Match", br#""b""#)]);
  assert_eq!(
    p.refusal(),
    Some(PreconditionRefusal::Malformed {
      field: TagField::IfMatch
    })
  );
  assert!(p.if_match().is_none(), "neither line, not one of them");

  let p = push_all(&[
    (b"If-Modified-Since", b"Sat, 29 Oct 1994 19:43:31 GMT"),
    (b"If-Modified-Since", b"Sat, 29 Oct 1994 19:43:31 GMT"),
  ]);
  assert_eq!(
    p.if_modified_since(),
    DateField::PresentUnusable,
    "§13.1.3 MUST-ignores a value with more than one member"
  );

  let p = push_all(&[(b"If-Range", br#""a""#), (b"If-Range", br#""b""#)]);
  assert!(p.if_range_tag().is_none());
  assert!(p.if_range_date().is_none());

  let p = push_all(&[(b"Range", b"bytes=0-499"), (b"Range", b"bytes=500-999")]);
  assert!(p.range().is_none());
  assert!(p.range_ignored());
}

// ── What the accumulator costs a caller ──────────────────────────────────────

// The two `const _`s beside `Preconditions` are what ENFORCE its size, on every
// tier including the one with no test harness. This is where the figure can be
// READ: a pinned `const _` that holds prints nothing, and one that fails names
// neither number.
//
// What it asserts is a claim neither `const _` makes — that the cost IS the
// three parse-constants, and that the accumulator's own five fields add less
// than a slot of either array to them. A field added here without a second
// thought reds this before it reds the pinned figures, and says which of the
// two it was.
#[cfg(feature = "std")]
#[test]
fn the_accumulator_costs_its_two_lists_and_its_specifier() {
  use crate::{range::RangesSpecifier, validator::TagList};

  let whole = core::mem::size_of::<Preconditions<'_>>();
  let parse_constants =
    2 * core::mem::size_of::<TagList<'_>>() + core::mem::size_of::<RangesSpecifier<'_>>();
  std::eprintln!(
    "size_of::<Preconditions>() == {whole}, of which {parse_constants} is MAX_TAGS twice and \
     MAX_RANGE_SPECS once"
  );
  assert!(parse_constants < whole);
  // The remainder is the clock, the two date slots, the `If-Range` slot, the
  // `Range` flag and the padding between them: 56 bytes on a 64-bit target and
  // 48 on a 32-bit one, measured.
  assert!(whole - parse_constants <= 64);
}

// RFC 9110 §13.2.2's step 5 keys on `If-Range` being PRESENT, and the two form
// accessors answer `None` for an absent field and for an unreadable one alike.
// The two are different answers — an absent `If-Range` leaves a `Range` live,
// while an unreadable one makes §13.1.5's condition false and the `Range` is
// ignored — so a caller re-deriving step 5 needs the difference.
#[test]
fn if_range_presence_is_readable_apart_from_its_two_forms() {
  let absent = push_all(&[(b"Range", b"bytes=0-499")]);
  assert!(!absent.if_range_present());
  assert!(absent.if_range_tag().is_none());
  assert!(absent.if_range_date().is_none());

  // Neither form reads this: no DQUOTE in the first three characters, so it
  // goes down the date path, and it is not an `HTTP-date` either.
  let unusable = push_all(&[(b"Range", b"bytes=0-499"), (b"If-Range", b"not-a-date")]);
  assert!(unusable.if_range_present());
  assert!(unusable.if_range_tag().is_none());
  assert!(unusable.if_range_date().is_none());

  // And both readable forms are present too, so the accessor is not merely
  // reporting the unusable state.
  let tag = push_all(&[(b"If-Range", br#""xyzzy""#)]);
  assert!(tag.if_range_present());
  let date = push_all(&[(b"If-Range", b"Sun, 06 Nov 1994 08:49:37 GMT")]);
  assert!(date.if_range_present());

  // The difference the accessor exists for, read off `evaluate`: the same
  // `Range` survives one and is ignored under the other.
  assert!(matches!(
    absent.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
  assert!(matches!(
    unusable.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      ..
    }
  ));
}

// ── The refusal's own vocabulary ─────────────────────────────────────────────

#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
#[test]
fn a_refusal_names_the_field_it_is_about() {
  let too_many = PreconditionRefusal::TooManyTags {
    field: TagField::IfMatch,
  };
  let malformed = PreconditionRefusal::Malformed {
    field: TagField::IfNoneMatch,
  };
  assert!(std::format!("{too_many}").contains("if-match"));
  assert!(std::format!("{malformed}").contains("if-none-match"));
}

// ── RFC 9110 §13.2.2's algorithm, behind §13.2.1's gates ─────────────────────

fn strong(tag: &'static [u8]) -> EntityTag<'static> {
  EntityTag::parse(tag).expect("a well-formed entity-tag")
}

/// The representation every step below is evaluated against: it exists, its
/// entity tag is §13.1.1's own example, its `Last-Modified` is §5.6.7's own
/// example and strong, and it is 10 000 octets long — §14.1.2's own example
/// length.
fn rep() -> Selected<'static> {
  Selected::present()
    .with_etag(strong(br#""xyzzy""#))
    .with_strong_last_modified(parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").expect("§5.6.7"))
    .with_complete_length(10_000)
    .build()
}

// ── Kind 1: each step alone, varying its condition axes ──────────────────────

// Step 1 opens "When recipient is the origin server and If-Match is present",
// so the recipient is the axis; §13.1.1 makes its 412 a MAY beside an escape,
// which is what `EscapablePrecondition` names.
#[test]
fn step_1_if_match_is_origin_only_and_its_412_escapes() {
  let p = push_all(&[(b"If-Match", br#""other""#)]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::PreconditionFailed {
      failed: EscapablePrecondition::IfMatch,
      ..
    }
  ));

  // A cache never reaches step 1.
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::Cache),
    Verdict::Proceed
  ));
}

// Step 3 opens "When If-None-Match is present" and names no recipient, so the
// method is the axis. RFC 9110 §13.1.2: "the origin server MUST respond with
// either a) the 304 (Not Modified) status code if the request method is GET or
// HEAD or b) the 412 (Precondition Failed) status code for all other request
// methods." Both halves are MUSTs, which is why neither carries the escape.
//
// The last cell is a question RFC 9111 §4.3.2 says a cache MUST NOT ASK, and
// the assertion stands as written because `evaluate` is not the rule that
// forbids it. §4.3.2: "A cache MUST NOT evaluate conditional header fields that
// only apply to an origin server, occur in a request with semantics that cannot
// be satisfied with a cached response, or occur in a request with a target
// resource for which it has no stored responses" — and `Method::Other` is by
// this crate's own vocabulary a method that MODIFIES a selected representation,
// so no stored response satisfies it. That MUST NOT binds the caller before the
// call, it is a delegation on `Preconditions::evaluate` and a paragraph on
// `Recipient::Cache`, and neither `Method` nor `Recipient` can express its two
// remaining disjuncts — they are facts about a store this crate never sees.
// What this cell pins is that step 3 has no recipient gate: the verdict is the
// one §13.2.2 gives for the question asked, whoever asked it.
#[test]
fn step_3_if_none_match_is_gated_on_nothing_and_its_412_does_not_escape() {
  let p = push_all(&[(b"If-None-Match", br#""xyzzy""#)]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::NotModified { .. }
  ));
  assert!(matches!(
    p.evaluate(&rep(), Method::Head, Recipient::Cache),
    Verdict::NotModified { .. }
  ));
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::Cache),
    Verdict::PreconditionFailedFinal { .. }
  ));
}

// One status code, two rules of different strength, and the verdict says which.
// Step 3's 304 is RFC 9110 §13.1.2's MUST; step 4's is §13.1.3's SHOULD. A
// `NotModified` carrying only the status is the same value for both, so a
// caller deviating where §13.1.3 permits it would be deviating from a MUST half
// the time. Both cells are GET at an origin server, so the method and the
// recipient are held fixed and the field is the only axis.
#[test]
fn the_two_304s_name_the_precondition_that_produced_them() {
  let step_3 = push_all(&[(b"If-None-Match", br#""xyzzy""#)]);
  assert!(matches!(
    step_3.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::NotModified {
      failed: NotModifiedPrecondition::IfNoneMatch,
      status: Status::NotModified,
    }
  ));

  let step_4 = push_all(&[(b"If-Modified-Since", b"Sun, 06 Nov 1994 08:49:37 GMT")]);
  assert!(matches!(
    step_4.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::NotModified {
      failed: NotModifiedPrecondition::IfModifiedSince,
      status: Status::NotModified,
    }
  ));

  // And §13.1.3's own first MUST-ignore rule is what keeps the two apart when
  // both fields arrive: "A recipient MUST ignore If-Modified-Since if the
  // request contains an If-None-Match header field". So this is step 3's, and
  // an implementation that ran step 4 first would answer the same status under
  // the other name.
  let both = push_all(&[
    (b"If-None-Match", br#""xyzzy""#),
    (b"If-Modified-Since", b"Sun, 06 Nov 1994 08:49:37 GMT"),
  ]);
  assert!(matches!(
    both.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::NotModified {
      failed: NotModifiedPrecondition::IfNoneMatch,
      ..
    }
  ));
}

// RFC 9110 §13.2.1's two reachable gates answer DIFFERENTLY, and a test that
// only asserted "not a 412" would pass on either.
#[test]
fn the_two_gates_answer_differently() {
  let p = push_all(&[
    (b"If-Match", br#""other""#),
    (b"If-None-Match", br#""xyzzy""#),
  ]);

  // The method rule says IGNORE — act as if the fields were absent, which is
  // step 6.
  assert!(matches!(
    p.evaluate(&rep(), Method::NoRepresentation, Recipient::OriginServer),
    Verdict::Proceed
  ));

  // The recipient rule says MUST NOT evaluate and MUST forward.
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::Forwarding),
    Verdict::NotEvaluated
  ));
}

// The six crossings where three separately-total rules meet. Each of the three
// reads as unconditional on its own, and one input satisfies all three.
//
// Every "measured" claim below was re-derived against the CURRENT dispatch,
// where each refusal is answered inside the step that consults its field. Six
// candidate wirings were built and run, and the cell sets are what those runs
// said:
//
//   A  a recipient-blind `refusal()` ahead of both gates ........ cells 1,2,4,6
//   B  a recipient-blind `refusal()` between the gates and step 1 ..... cell 4
//   C  each field's refusal between the gates and step 1, each gated as its own
//      step is ................................................... no cell at all
//   D  step 3's refusal gated origin-only, mirroring step 1's gate ..... cell 5
//   E  step 3 picking the field via `refusal()` rather than its own slot . cell 4
//   F  both step-local checks hoisted ahead of the two gates, each keeping its
//      own step's recipient gate ...................................... cell 1
//
// C is the one these six cells are blind to, which is the finding: a refusal
// dispatched between the gates and the steps crosses no gate and reds nothing
// here. `a_refusal_at_step_3_does_not_displace_the_step_that_terminated_first`
// is the cell that was missing, and it is the sole witness against C.
#[test]
fn the_gates_against_each_other_and_against_a_standing_refusal() {
  let clean = push_all(&[(b"If-Match", br#""other""#)]);
  let refused = push_all(&[(b"If-Match", b"not-a-tag")]);
  let refused_inm = push_all(&[(b"If-None-Match", b"not-a-tag")]);
  assert!(refused.refusal().is_some());

  // 1. NoRepresentation at an OriginServer with a malformed If-Match ->
  //    Proceed. A field RFC 9110 §13.2.1 orders ignored is not a guard this
  //    crate dropped.
  assert!(matches!(
    refused.evaluate(&rep(), Method::NoRepresentation, Recipient::OriginServer),
    Verdict::Proceed
  ));

  // 2. Forwarding with a malformed If-Match -> NotEvaluated.
  assert!(matches!(
    refused.evaluate(&rep(), Method::Get, Recipient::Forwarding),
    Verdict::NotEvaluated
  ));

  // 3. NoRepresentation AT a Forwarding recipient -> NotEvaluated. The forward
  //    MUST is method-unconditional and Proceed promises no forwarding.
  assert!(matches!(
    clean.evaluate(&rep(), Method::NoRepresentation, Recipient::Forwarding),
    Verdict::NotEvaluated
  ));

  // 4. A malformed If-Match at a Cache -> NOT Refused: steps 1 and 2 are
  //    origin-only, so the cache never consults the field.
  assert!(matches!(
    refused.evaluate(&rep(), Method::Other, Recipient::Cache),
    Verdict::Proceed
  ));

  // 5. A malformed If-None-Match at a Cache -> Refused: step 3 is gated on
  //    nothing, so a cache DOES refuse over this field. Cell 4's positive
  //    half, and nothing more than that — it does NOT pin that step 3 reads
  //    its own slot rather than `refusal()`, because `refused_inm` has only
  //    `If-None-Match` refused and the recipient-blind accessor answers the
  //    same field. Measured under E, exactly two tests red — cell 4 and
  //    `a_cache_refuses_under_the_field_it_actually_consults` — and this cell
  //    stays green. What it does discriminate is D, step 3's refusal gated
  //    origin-only. Measured, D reds THREE tests: this cell, that same test,
  //    and `a_refusal_carries_the_status_its_cause_suggests`, whose two cases
  //    both refuse an `If-None-Match` at a `Cache` and so lose their refusal
  //    with it. So this cell is not the sole witness against D. It is the only
  //    one of the three that is ABOUT the gate: the third checks which status a
  //    cause suggests and would red as a side effect, naming nothing about
  //    which recipient consults which field.
  assert!(matches!(
    refused_inm.evaluate(&rep(), Method::Other, Recipient::Cache),
    Verdict::Refused { .. }
  ));

  // 6. The triple where all three rules apply at once. DEFENSIVE, not
  //    discriminating: measured, no wiring reds this cell alone. F reds cell 1
  //    and leaves this one green, because at a `Forwarding` recipient neither
  //    hoisted check fires — step 1's keeps its origin gate and there is no
  //    `If-None-Match` here. The wiring that does red it, A, reds cells 1, 2
  //    and 4 with it. Kept anyway: it is the one input on which all three rules
  //    apply at once, and the five cells above assert the order only pairwise.
  assert!(matches!(
    refused.evaluate(&rep(), Method::NoRepresentation, Recipient::Forwarding),
    Verdict::NotEvaluated
  ));
}

// The losing refusal is the one a cache acts on, so `evaluate` must read the
// slot and not the accessor. With both fields refused at a cache, `refusal()`
// reports If-Match's and `evaluate` must answer over If-None-Match's.
#[test]
fn a_cache_refuses_under_the_field_it_actually_consults() {
  let p = push_all(&[
    (b"If-Match", b"not-a-tag"),
    (b"If-None-Match", b"also-not-a-tag"),
  ]);
  assert_eq!(
    p.refusal(),
    Some(PreconditionRefusal::Malformed {
      field: TagField::IfMatch
    })
  );
  let Verdict::Refused { refusal, .. } = p.evaluate(&rep(), Method::Other, Recipient::Cache) else {
    panic!("step 3 is gated on nothing, so the cache does consult If-None-Match")
  };
  assert_eq!(
    refusal,
    PreconditionRefusal::Malformed {
      field: TagField::IfNoneMatch
    }
  );
}

// A recipient gate is one way a field goes unconsulted and RFC 9110 §13.2.2's
// own control flow is the other, and only the first was ever asserted. A step
// that terminates ends the algorithm, so every field a later step would have
// read is one this evaluation never reached — and a refusal over such a field
// must not displace the verdict the earlier step owes.
//
// Each pair below is the same request with and without the malformed
// `If-None-Match`, so what is pinned is that adding it changes nothing.
#[test]
fn a_refusal_at_step_3_does_not_displace_the_step_that_terminated_first() {
  // Step 1's 412: an `If-Match` no tag matches, at the one recipient that
  // consults the field.
  let alone = push_all(&[(b"If-Match", br#""other""#)]);
  let with_refusal = push_all(&[
    (b"If-Match", br#""other""#),
    (b"If-None-Match", b"not-a-tag"),
  ]);
  for p in [&alone, &with_refusal] {
    assert!(matches!(
      p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
      Verdict::PreconditionFailed {
        failed: EscapablePrecondition::IfMatch,
        status: Status::PreconditionFailed,
      }
    ));
  }

  // Step 2's, one step further down: `If-Match` absent so the step runs, and a
  // modification date later than the one the field allows.
  let alone = push_all(&[(b"If-Unmodified-Since", b"Sun, 06 Nov 1994 08:49:36 GMT")]);
  let with_refusal = push_all(&[
    (b"If-Unmodified-Since", b"Sun, 06 Nov 1994 08:49:36 GMT"),
    (b"If-None-Match", b"not-a-tag"),
  ]);
  for p in [&alone, &with_refusal] {
    assert!(matches!(
      p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
      Verdict::PreconditionFailed {
        failed: EscapablePrecondition::IfUnmodifiedSince,
        status: Status::PreconditionFailed,
      }
    ));
  }
}

// The positive half of the test above, and what keeps it from being satisfied
// by an `If-None-Match` refusal that was simply switched off: with the earlier
// steps passing, step 3 IS reached and the same malformed value refuses.
//
// The first case differs from the first pair above in its entity-tag alone —
// `"other"` becomes `"xyzzy"`, the tag `rep()` carries — so step 1 runs over
// the same field and its condition is now true. The second differs in its date
// alone, one second later than the representation's `Last-Modified`, so step 2
// runs and its condition is now true.
#[test]
fn the_same_refusal_answers_once_step_3_is_reached() {
  let p = push_all(&[
    (b"If-Match", br#""xyzzy""#),
    (b"If-None-Match", b"not-a-tag"),
  ]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::Refused {
      refusal: PreconditionRefusal::Malformed {
        field: TagField::IfNoneMatch
      },
      ..
    }
  ));

  // And step 2's pair, with a date the representation satisfies.
  let p = push_all(&[
    (b"If-Unmodified-Since", b"Sun, 06 Nov 1994 08:49:38 GMT"),
    (b"If-None-Match", b"not-a-tag"),
  ]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::Refused {
      refusal: PreconditionRefusal::Malformed {
        field: TagField::IfNoneMatch
      },
      ..
    }
  ));
}

// The same rule for step 1's own field: a refused `If-Match` is answered by the
// step that consults it. The refusal is INSIDE step 1, and this is what says it
// is not lost by moving the dispatch ahead of the steps.
//
// The positive case only. The two recipients that never reach step 1 are cells
// 4 and 2 of the crossing test above, asserted there rather than twice.
#[test]
fn step_1_answers_its_own_fields_refusal() {
  let p = push_all(&[(b"If-Match", b"not-a-tag")]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::Refused {
      refusal: PreconditionRefusal::Malformed {
        field: TagField::IfMatch
      },
      status: Status::BadRequest,
    }
  ));
}

// The two causes suggest different statuses, and the verdict carries the one
// each cause suggests rather than one status for both.
#[test]
fn a_refusal_carries_the_status_its_cause_suggests() {
  let malformed = push_all(&[(b"If-None-Match", b"not-a-tag")]);
  assert!(matches!(
    malformed.evaluate(&rep(), Method::Other, Recipient::Cache),
    Verdict::Refused {
      status: Status::BadRequest,
      ..
    }
  ));

  use crate::validator::MAX_TAGS;

  let mut value = [0u8; 3 + 4 * MAX_TAGS];
  let (first, rest) = value.split_at_mut(3);
  first.copy_from_slice(br#""a""#);
  for chunk in rest.chunks_mut(4) {
    chunk.copy_from_slice(br#","a""#);
  }
  let too_many = push_all(&[(b"If-None-Match", value.as_slice())]);
  assert!(matches!(
    too_many.evaluate(&rep(), Method::Other, Recipient::Cache),
    Verdict::Refused {
      status: Status::FieldsTooLarge,
      ..
    }
  ));
}

// ── Kind 2: the intra-class suppressions, and the comparison assignment ──────

#[test]
fn if_match_suppresses_step_2_and_if_none_match_suppresses_step_4() {
  // Step 2 runs only when If-Match is NOT present. A true If-Match with a false
  // If-Unmodified-Since must not answer 412.
  let p = push_all(&[
    (b"If-Match", br#""xyzzy""#),
    (b"If-Unmodified-Since", b"Sun, 06 Nov 1994 08:49:36 GMT"),
  ]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::Proceed
  ));

  // Step 4 runs only when If-None-Match is NOT present. A true If-None-Match
  // with an If-Modified-Since that would answer 304 must not answer 304.
  let p = push_all(&[
    (b"If-None-Match", br#""other""#),
    (b"If-Modified-Since", b"Sun, 06 Nov 1994 08:49:37 GMT"),
  ]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
}

// The same two suppressions, with the suppressor removed, so the assertions
// above are pinned to the gate rather than to a date that was never false.
#[test]
fn the_suppressed_steps_do_answer_when_their_gate_is_open() {
  let p = push_all(&[(b"If-Unmodified-Since", b"Sun, 06 Nov 1994 08:49:36 GMT")]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::PreconditionFailed {
      failed: EscapablePrecondition::IfUnmodifiedSince,
      ..
    }
  ));

  let p = push_all(&[(b"If-Modified-Since", b"Sun, 06 Nov 1994 08:49:37 GMT")]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::NotModified { .. }
  ));
}

// RFC 9110 §13.1.1's strong, §13.1.2's weak, §13.1.5's strong — three MUSTs,
// and two correct functions wired to the wrong steps pass every Table 3
// assertion. The assignment is therefore asserted through `evaluate`.
#[test]
fn each_step_uses_the_comparison_function_the_rfc_names() {
  let weak_rep = Selected::present()
    .with_etag(EntityTag::parse(br#"W/"xyzzy""#).expect("a weak entity-tag"))
    .with_complete_length(10_000)
    .build();

  // A weak-tag pair that matches must FAIL If-Match (strong comparison).
  let p = push_all(&[(b"If-Match", br#"W/"xyzzy""#)]);
  assert!(matches!(
    p.evaluate(&weak_rep, Method::Other, Recipient::OriginServer),
    Verdict::PreconditionFailed { .. }
  ));

  // And SUCCEED against If-None-Match (weak comparison), giving a 304 on GET.
  let p = push_all(&[(b"If-None-Match", br#"W/"xyzzy""#)]);
  assert!(matches!(
    p.evaluate(&weak_rep, Method::Get, Recipient::OriginServer),
    Verdict::NotModified { .. }
  ));

  // And §13.1.5's tag form is strong too, so the same pair makes If-Range
  // false and the Range is ignored rather than applied.
  let p = push_all(&[(b"Range", b"bytes=0-499"), (b"If-Range", br#"W/"xyzzy""#)]);
  assert!(matches!(
    p.evaluate(&weak_rep, Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      ..
    }
  ));
}

// ── Kind 3: the inter-class orderings, which kinds 1 and 2 cannot see ────────

#[test]
fn lost_update_guards_precede_cache_validators() {
  // A false If-Unmodified-Since AND a false If-None-Match on a GET must answer
  // 412, not 304 — step 2 precedes step 3. An implementation that ran cache
  // validators first passes both other kinds.
  let p = push_all(&[
    (b"If-Unmodified-Since", b"Sun, 06 Nov 1994 08:49:36 GMT"),
    (b"If-None-Match", br#""xyzzy""#),
  ]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::PreconditionFailed {
      failed: EscapablePrecondition::IfUnmodifiedSince,
      ..
    }
  ));
}

// RFC 9110 §14.2: "In other words, Range is ignored when a conditional GET
// would result in a 304 (Not Modified) response." A false If-None-Match on a
// GET with Range and a true If-Range must answer 304, never 206.
#[test]
fn a_304_beats_a_206() {
  let p = push_all(&[
    (b"If-None-Match", br#""xyzzy""#),
    (b"Range", b"bytes=0-499"),
    (b"If-Range", br#""xyzzy""#),
  ]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::NotModified { .. }
  ));
}

// ── Step 5, and the two input classes this crate cannot decide ───────────────

#[test]
fn step_5_needs_both_fields_and_the_get_method() {
  let both = push_all(&[(b"Range", b"bytes=0-499"), (b"If-Range", br#""xyzzy""#)]);
  assert!(matches!(
    both.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::RangeApplies {
      status: Status::PartialContent
    }
  ));

  // Range without If-Range is the ordinary range request: step 5 never runs and
  // the caller answers from `range()` and `resolve`.
  let range_only = push_all(&[(b"Range", b"bytes=0-499")]);
  assert!(matches!(
    range_only.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
  assert!(range_only.range().is_some());

  // If-Range without Range is the other half, and RFC 9110 §13.1.5 MUST-ignores
  // it: "A server MUST ignore an If-Range header field received in a request
  // that does not contain a Range header field."
  let if_range_only = push_all(&[(b"If-Range", br#""xyzzy""#)]);
  assert!(matches!(
    if_range_only.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));

  // Step 5 says GET, where steps 3 and 4 say GET or HEAD, so HEAD is the axis
  // that separates them.
  assert!(matches!(
    both.evaluate(&rep(), Method::Head, Recipient::OriginServer),
    Verdict::Proceed
  ));
  assert!(matches!(
    both.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::Proceed
  ));
}

#[test]
fn a_false_if_range_ignores_the_range() {
  let p = push_all(&[(b"Range", b"bytes=0-499"), (b"If-Range", br#""other""#)]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      status: Status::Ok
    }
  ));

  // An If-Range neither form reads is the same false, not a refusal: §13.1.5
  // makes this field the opposite of a lost-update guard.
  let p = push_all(&[(b"Range", b"bytes=0-499"), (b"If-Range", b"\"unterminated")]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      ..
    }
  ));
}

// RFC 9110 §13.1.5's first date-form step: "If the HTTP-date validator provided
// is not a strong validator in the sense defined by Section 8.8.2.2, the
// condition is false."
#[test]
fn a_weak_date_if_range_is_false() {
  let at = parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").expect("§5.6.7's own example");
  let weakly_dated = Selected::present()
    .with_last_modified(at)
    .with_complete_length(10_000)
    .build();
  let p = push_all(&[
    (b"Range", b"bytes=0-499"),
    (b"If-Range", b"Sun, 06 Nov 1994 08:49:37 GMT"),
  ]);
  assert!(matches!(
    p.evaluate(&weakly_dated, Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      ..
    }
  ));

  // The same date, asserted strong, is §13.1.5's step 2 — an exact match.
  let strongly_dated = Selected::present()
    .with_strong_last_modified(at)
    .with_complete_length(10_000)
    .build();
  assert!(matches!(
    p.evaluate(&strongly_dated, Method::Get, Recipient::OriginServer),
    Verdict::RangeApplies { .. }
  ));

  // And the comparison is exact rather than earlier-or-equal: §13.1.5 says "the
  // If-Range comparison is by exact match, including when the validator is an
  // HTTP-date, and so it differs from the "earlier than or equal to" comparison
  // used when evaluating an If-Unmodified-Since conditional."
  let later = Selected::present()
    .with_strong_last_modified(parse_http_date(b"Sun, 06 Nov 1994 08:49:36 GMT").expect("§5.6.7"))
    .with_complete_length(10_000)
    .build();
  assert!(matches!(
    p.evaluate(&later, Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      ..
    }
  ));
}

#[test]
fn the_two_undecidable_step_5_inputs() {
  // A unit other than `bytes`: §14.1.1 makes satisfiability unit-defined.
  let p = push_all(&[
    (b"Range", b"exampleunit=1.2-4.3"),
    (b"If-Range", br#""xyzzy""#),
  ]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::RangeUndecidable {
      reason: Undecidable::UnitNotBytes,
      status: Status::Ok
    }
  ));

  // No complete length: an int-range's satisfiability has nothing to compare
  // against.
  let no_length = Selected::present().with_etag(strong(br#""xyzzy""#)).build();
  let p = push_all(&[(b"Range", b"bytes=0-499"), (b"If-Range", br#""xyzzy""#)]);
  assert!(matches!(
    p.evaluate(&no_length, Method::Get, Recipient::OriginServer),
    Verdict::RangeUndecidable {
      reason: Undecidable::LengthUnknown,
      status: Status::Ok
    }
  ));
}

#[test]
fn an_unsatisfiable_range_answers_416_with_a_content_range() {
  let p = push_all(&[(b"Range", b"bytes=99999-"), (b"If-Range", br#""xyzzy""#)]);
  let Verdict::RangeNotSatisfiable {
    content_range,
    status,
  } = p.evaluate(&rep(), Method::Get, Recipient::OriginServer)
  else {
    panic!("expected 416")
  };
  assert_eq!(status, Status::RangeNotSatisfiable);
  let cr = content_range.expect("§14.4's unsatisfied-range, since the length is known");
  assert!(cr.is_unsatisfied());
  assert_eq!(cr.complete_length(), Some(10_000));
}

// The same 416, pinned as a CHOICE rather than as a derivation — because a
// reader of `evaluate` who is not told meets an unargued status code, and this
// one sits against a literal reading of the algorithm the crate is
// implementing.
//
// RFC 9110 §13.2.2's step 5 has two bullets and no third: "if true and the
// Range is applicable to the selected representation, respond 206 (Partial
// Content)", and "otherwise, ignore the Range header field and respond 200
// (OK)". A true `If-Range` over an all-unsatisfiable range fails the first
// bullet's second conjunct, so read literally it lands in the *otherwise* and
// answers 200.
//
// §14.2 answers 416 for the same request, and every conjunct of its SHOULD is
// met here: "If all of the preconditions are true, the server supports the
// Range header field for the target resource, the received Range field-value
// contains a valid ranges-specifier, and either the range-unit is not supported
// for that target resource or the ranges-specifier is unsatisfiable with
// respect to the selected representation, the server SHOULD send a 416 (Range
// Not Satisfiable) response."
//
// This design answers 416, on §13.1.5's "Otherwise, the recipient SHOULD process
// the Range header field as requested" — processing an unsatisfiable specifier
// as requested is what §14.2 then spells out. The other reading is defensible,
// there is no erratum, and this is an open errata target. The argument in full
// is at `step_5`'s `RangeNotSatisfiable` arm; this test is the assertion that
// the answer does not drift without that paragraph moving with it.
#[test]
fn the_step_5_416_is_the_choice_this_design_made_and_not_an_oversight() {
  // Every gate of step 5 passed: the method is GET, both fields are present,
  // the `If-Range` entity-tag matches the selected representation strongly, the
  // unit is `bytes`, and the complete length is known.
  let p = push_all(&[(b"Range", b"bytes=99999-"), (b"If-Range", br#""xyzzy""#)]);
  let verdict = p.evaluate(&rep(), Method::Get, Recipient::OriginServer);

  // §14.2's SHOULD-416, and NOT step 5's *otherwise*, which would be
  // `IgnoreRange` at `Status::Ok`.
  assert!(
    matches!(
      verdict,
      Verdict::RangeNotSatisfiable {
        status: Status::RangeNotSatisfiable,
        ..
      }
    ),
    "the design's answer is 416; step 5's own *otherwise* reads 200"
  );
  assert!(
    !matches!(verdict, Verdict::IgnoreRange { .. }),
    "and the 200 reading is the one this design did not take"
  );

  // The If-Range being TRUE is what puts this request in the tension at all:
  // with a false condition, step 5's *otherwise* and §13.1.5's MUST-ignore
  // agree, and 200 is the answer here too. So the assertion above is about the
  // conflict rather than about the branch.
  let stale = push_all(&[(b"Range", b"bytes=99999-"), (b"If-Range", br#""other""#)]);
  assert!(matches!(
    stale.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      status: Status::Ok
    }
  ));
}

// RFC 9110 §14.1.2 leaves a non-zero suffix-range satisfiable against a
// zero-length representation, so this is NOT a 416 — §14.2's 416 is for an
// unsatisfiable specifier. The exit is §14.2's own: "A server that supports
// range requests MAY ignore a Range header field when the selected
// representation has no content (i.e., the selected representation's data is of
// zero length)."
#[test]
fn a_zero_length_representation_ignores_the_range() {
  let empty = Selected::present()
    .with_etag(strong(br#""xyzzy""#))
    .with_complete_length(0)
    .build();
  let p = push_all(&[(b"Range", b"bytes=-5"), (b"If-Range", br#""xyzzy""#)]);
  assert!(matches!(
    p.evaluate(&empty, Method::Get, Recipient::OriginServer),
    Verdict::IgnoreRange {
      reason: RangeIgnored::EmptyRepresentation,
      status: Status::Ok
    }
  ));

  // Every other form is unsatisfiable at that length, and there a 416 IS the
  // answer — so the variant above is the zero-length case and not the
  // zero-length REPRESENTATION.
  let p = push_all(&[(b"Range", b"bytes=0-4"), (b"If-Range", br#""xyzzy""#)]);
  assert!(matches!(
    p.evaluate(&empty, Method::Get, Recipient::OriginServer),
    Verdict::RangeNotSatisfiable { .. }
  ));
}

// RFC 9110 §14.2 grants the 416 only for a request whose "field-value contains
// a valid ranges-specifier": a value `RangesSpecifier::parse` refused is not
// one, and §14.2's blanket "A server MAY ignore the Range header field" already
// took that exit inside `push`. So step 5 has no Range to apply and the
// algorithm reaches step 6, with `range_ignored` reporting what happened.
#[test]
fn a_range_the_parser_refused_never_reaches_a_416() {
  let invalid = push_all(&[(b"Range", b"bytes=900-800"), (b"If-Range", br#""xyzzy""#)]);
  assert!(invalid.range().is_none() && invalid.range_ignored());
  assert!(matches!(
    invalid.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));

  // The other refusal `RangesSpecifier::parse` makes, over the slot bound
  // rather than over the grammar, reaches the same exit.
  use crate::range::MAX_RANGE_SPECS;

  let mut value = [0u8; 5 + 4 * (MAX_RANGE_SPECS + 1)];
  let (unit, rest) = value.split_at_mut(5);
  unit.copy_from_slice(b"bytes");
  for (index, chunk) in rest.chunks_mut(4).enumerate() {
    chunk.copy_from_slice(if index == 0 { b"=0-1" } else { b",0-1" });
  }
  let too_many = push_all(&[(b"Range", value.as_slice()), (b"If-Range", br#""xyzzy""#)]);
  assert!(too_many.range().is_none() && too_many.range_ignored());
  assert!(matches!(
    too_many.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
}

// RFC 9110 §13.1.1's and §13.1.2's `*` forms, against a representation that
// does not exist.
#[test]
fn the_star_forms_against_an_absent_representation() {
  let absent = Selected::absent();

  let p = push_all(&[(b"If-Match", b"*")]);
  assert!(matches!(
    p.evaluate(&absent, Method::Other, Recipient::OriginServer),
    Verdict::PreconditionFailed { .. }
  ));
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::Proceed
  ));

  let p = push_all(&[(b"If-None-Match", b"*")]);
  assert!(matches!(
    p.evaluate(&absent, Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::NotModified { .. }
  ));
}

// §13.1.3's and §13.1.4's last MUST-ignore rule is a fact about the RESOURCE,
// not about the value, so it can only be applied here. Ignoring and failing are
// different answers: with no modification date to compare against, the step is
// skipped and the request carries on.
#[test]
fn a_date_field_with_no_modification_date_to_compare_is_ignored_rather_than_failed() {
  let no_date = Selected::present()
    .with_etag(strong(br#""xyzzy""#))
    .with_complete_length(10_000)
    .build();

  let p = push_all(&[(b"If-Unmodified-Since", b"Sun, 06 Nov 1994 08:49:36 GMT")]);
  assert!(matches!(
    p.evaluate(&no_date, Method::Other, Recipient::OriginServer),
    Verdict::Proceed
  ));

  let p = push_all(&[(b"If-Modified-Since", b"Sun, 06 Nov 1994 08:49:37 GMT")]);
  assert!(matches!(
    p.evaluate(&no_date, Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
}

// The other MUST-ignore rule this accumulator settled in `push`: a date field
// that is present and unusable is skipped, exactly as an absent one is.
#[test]
fn an_unusable_date_field_is_skipped_rather_than_failed() {
  let p = push_all(&[(b"If-Unmodified-Since", b"not a date")]);
  assert_eq!(p.if_unmodified_since(), DateField::PresentUnusable);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::Proceed
  ));
}

// Step 2 and step 4 read the SAME two dates in opposite directions, and RFC
// 9110 states each as its own sentence. §13.1.4: earlier than or equal to the
// field value is TRUE. §13.1.3: earlier or equal is FALSE.
#[test]
fn the_two_date_steps_compare_in_opposite_directions() {
  let earlier = b"Sun, 06 Nov 1994 08:49:36 GMT";
  let equal = b"Sun, 06 Nov 1994 08:49:37 GMT";
  let later = b"Sun, 06 Nov 1994 08:49:38 GMT";

  // If-Unmodified-Since: true (proceed) at equal and later, false (412) at
  // earlier.
  for value in [equal.as_slice(), later.as_slice()] {
    let p = push_all(&[(b"If-Unmodified-Since", value)]);
    assert!(matches!(
      p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
      Verdict::Proceed
    ));
  }
  let p = push_all(&[(b"If-Unmodified-Since", earlier.as_slice())]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Other, Recipient::OriginServer),
    Verdict::PreconditionFailed { .. }
  ));

  // If-Modified-Since: false (304) at equal and later, true (proceed) at
  // earlier.
  for value in [equal.as_slice(), later.as_slice()] {
    let p = push_all(&[(b"If-Modified-Since", value)]);
    assert!(matches!(
      p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
      Verdict::NotModified { .. }
    ));
  }
  let p = push_all(&[(b"If-Modified-Since", earlier.as_slice())]);
  assert!(matches!(
    p.evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
}

// Step 6 is the answer to an empty header section, and it is the same answer a
// request whose every precondition is true gets.
#[test]
fn no_precondition_at_all_proceeds() {
  assert!(matches!(
    push_all(&[]).evaluate(&rep(), Method::Get, Recipient::OriginServer),
    Verdict::Proceed
  ));
  assert!(matches!(
    push_all(&[]).evaluate(&Selected::absent(), Method::Other, Recipient::Cache),
    Verdict::Proceed
  ));
}
