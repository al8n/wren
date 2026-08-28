use super::*;
use crate::grammar::ParamValue;

/// Whether `got` is `want`'s variant holding `want`'s exact mechanism bytes.
///
/// [`multipart::PartEncoding`] derives no equality, because RFC 2045 §6.1 makes
/// a mechanism name case-insensitive while the variant keeps the sender's
/// spelling — a `==` over those bytes called `BASE64` and `base64` different
/// mechanisms. What these tests are pinning is narrower and is the reader's to
/// answer: which variant the field sorted into, and which bytes it captured. So
/// they compare the accessors the type directs a caller to rather than the
/// values, and `Absent` is told from `Identity` by its `None` mechanism.
///
/// **Three accessors, not two**, and the third is not decoration:
/// `is_identity` alone cannot tell `Undecoded(b"x-a")` from
/// `Unrecognised(b"x-a")` — both are non-identity and both hold the same span —
/// so a helper written from the first two would call every assertion about the
/// encoding classification green whichever variant the reader produced.
/// `is_octet_stream_fallback` is what separates them, and it is the accessor a
/// caller acts on.
fn same_spelling(got: multipart::PartEncoding<'_>, want: multipart::PartEncoding<'_>) -> bool {
  got.is_identity() == want.is_identity()
    && got.is_octet_stream_fallback() == want.is_octet_stream_fallback()
    && got.mechanism() == want.mechanism()
}

/// Whether `got` is `want`'s variant holding `want`'s exact bytes.
///
/// [`ParamValue`] derives no equality for a reason of its own: RFC 9110 §5.6.6
/// makes a `token` and a `quoted-string` spelling of one value equivalent, and
/// leaves the case question to the parameter's own name. What these tests pin is
/// again the narrower thing the two parsers answer for — which production the
/// value came out of, and which bytes it captured — since the difference
/// between the grammars is exactly what several of them measure.
fn same_param(got: ParamValue<'_>, want: ParamValue<'_>) -> bool {
  match (got, want) {
    (ParamValue::None, ParamValue::None) => true,
    (ParamValue::Token(got), ParamValue::Token(want))
    | (ParamValue::Quoted(got), ParamValue::Quoted(want)) => got == want,
    _ => false,
  }
}

// ── §14.1.1: the grammar, and erratum 7306's OWS ─────────────────────────────

#[test]
fn parses_the_rfcs_own_example_including_its_space() {
  // Erratum 7306 (Verified) corrects §14.1.1 to `range-unit "=" OWS range-set`.
  let spec = RangesSpecifier::parse(b"bytes= 0-999, 4500-5499, -1000").unwrap();
  assert_eq!(spec.unit(), b"bytes");
  assert_eq!(spec.len(), 3);
}

// RFC 9110 §14.1 says "All range unit names are case-insensitive". Matching the
// token exactly would send `BYTES=0-499` to the not-bytes path and answer 200
// where a 206 was waiting.
#[test]
fn the_unit_is_matched_case_insensitively_and_returned_verbatim() {
  let spec = RangesSpecifier::parse(b"BYTES=0-499").unwrap();
  assert_eq!(spec.unit(), b"BYTES", "returned as the sender wrote it");
  assert!(spec.other_range_set().is_none(), "but recognised as bytes");
  assert_eq!(spec.resolve(0, 1000), Some(Resolved::Range(0, 499)));
}

#[test]
fn a_non_bytes_unit_keeps_its_range_set_verbatim() {
  // §14.6's own example uses positions `1*DIGIT` does not admit.
  let spec = RangesSpecifier::parse(b"exampleunit=1.2-4.3").unwrap();
  assert_eq!(spec.unit(), b"exampleunit");
  assert_eq!(spec.other_range_set(), Some(&b"1.2-4.3"[..]));
  assert_eq!(spec.spec(0), None, "no bytes range-specs to hand back");
}

// RFC 9110 §14.1.1: "A ranges-specifier is invalid if it contains any
// range-spec that is invalid or undefined for the indicated range-unit." One
// bad spec fails the whole set; `parse` does not skip the offender and
// continue.
#[test]
fn one_bad_spec_fails_the_whole_set() {
  for bad in [
    &b"bytes=0-499,900-800"[..], // §14.1.1: last-pos below first-pos
    b"bytes=abc",                // other-range shape, undefined for `bytes`
    b"bytes=0-499,abc",          // and it poisons a set whose first spec is fine
    b"bytes=",                   // `1#` needs one member
    b"bytes",                    // no `=`
    // `suffix-length = 1*DIGIT` names at least one digit, so a bare `-` is a
    // malformed spec rather than a zero-length suffix. The difference is not
    // cosmetic: §14.2 grants a 416 only for a VALID ranges-specifier that is
    // unsatisfiable, so reading this as `Suffix { length: 0 }` would move it
    // from a server's choice — §14.2 lets one "ignore or reject" an invalid
    // ranges-specifier, and names no status for either branch — to SHOULD-416.
    b"bytes=-",
    // `first-pos` is `1*DIGIT` too, and neither position admits a second
    // hyphen.
    b"bytes=--1",
    b"bytes=1-2-3",
  ] {
    assert!(
      RangesSpecifier::parse(bad).is_err(),
      "{bad:?} must not parse"
    );
  }
}

// `range-unit = token` (§14.1), so a value whose unit is not one is not a
// ranges-specifier at all, whatever its range-set says.
#[test]
fn the_range_unit_must_be_a_token() {
  for bad in [
    &b"=0-499"[..],   // `token = 1*tchar` admits no empty run
    b"by tes=0-499",  // SP is not a tchar
    b"by\"tes=0-499", // nor is DQUOTE
  ] {
    assert!(
      RangesSpecifier::parse(bad).is_err(),
      "{bad:?} must not parse"
    );
  }
}

// §14.1.1's `range-set = 1#range-spec` belongs to the GENERIC grammar — the
// section leaves each unit to say which range-spec FORMS it admits, not whether
// there is one — so the at-least-one holds under a unit whose elements this
// crate cannot read.
#[test]
fn a_range_set_needs_a_member_under_every_unit() {
  assert!(RangesSpecifier::parse(b"exampleunit=").is_err());
  assert!(RangesSpecifier::parse(b"exampleunit=,,").is_err());

  // What is required is a MEMBER, not a tidy value: the range-set still comes
  // back whole, empty elements and all, because only that unit can read it.
  let spec = RangesSpecifier::parse(b"exampleunit=,1.2-4.3,").unwrap();
  assert_eq!(spec.other_range_set(), Some(&b",1.2-4.3,"[..]));
}

// RFC 9110 §14.1.1 hands the range unit which range-spec FORMS it admits and
// what they mean — "The range unit name determines what kinds of range-spec are
// applicable to its own specifiers" — and hands over none of the octets. All
// three forms are spelled out of `other-range = 1*( %x21-2B / %x2D-7E )`:
// `int-range` and `suffix-range` are `1*DIGIT` and `-`, both inside that set.
// So every element of a range-set under every unit is that set, and one
// carrying anything else is `MalformedSpecifier` rather than an opaque span
// some other unit might understand.
#[test]
fn a_non_bytes_range_set_is_still_held_to_the_generic_octet_rule() {
  // A SP and a control byte, neither of which any of the three forms admits.
  assert!(matches!(
    RangesSpecifier::parse(b"exampleunit=a b"),
    Err(RangeError::MalformedSpecifier)
  ));
  assert!(matches!(
    RangesSpecifier::parse(b"exampleunit=a\0b"),
    Err(RangeError::MalformedSpecifier)
  ));
  // The same rule catching the shape that matters most, from the request side:
  // a CRLF inside a field value is a field line nobody sent.
  assert!(matches!(
    RangesSpecifier::parse(b"exampleunit=a\r\nX-Evil:y"),
    Err(RangeError::MalformedSpecifier)
  ));

  // A comma is NOT such a byte, and this is the case the rule must not refuse:
  // `range-set = 1#range-spec` makes it the LIST's delimiter, so it is not
  // inside any element, and `a` and `b` are each a whole `other-range`. The
  // span handed back is the whole set, so that delimiter and the §5.6.3 OWS
  // around it come back with it.
  let spec = RangesSpecifier::parse(b"exampleunit=a,b").unwrap();
  assert_eq!(spec.other_range_set(), Some(&b"a,b"[..]));
  let spec = RangesSpecifier::parse(b"exampleunit=a , b").unwrap();
  assert_eq!(spec.other_range_set(), Some(&b"a , b"[..]));
}

// The fence posts of `1*( %x21-2B / %x2D-7E )`, a byte either side of each end
// of both runs. `%x2C` is the gap between them and is tested by the comma case
// above, where it splits the set rather than failing it.
#[test]
fn the_other_range_octet_set_is_the_one_the_abnf_prints() {
  for (byte, admitted) in [
    (0x00u8, false),
    (0x09, false), // HTAB: OWS between elements, never inside one
    (0x1f, false),
    (0x20, false), // SP, for the same reason
    (0x21, true),
    (0x2b, true),
    (0x2d, true),
    (0x7e, true),
    (0x7f, false), // DEL is not a VCHAR
    (0x80, false), // and `other-range` admits no `obs-text`
    (0xff, false),
  ] {
    let mut value = *b"exampleunit=aXb";
    value[13] = byte;
    assert_eq!(
      RangesSpecifier::parse(&value).is_ok(),
      admitted,
      "{byte:#04x} in a range-set element"
    );
  }
}

// Erratum 7306 puts the `OWS` between the `=` and the range-set, so it belongs
// to neither and must not reappear in the span handed back.
#[test]
fn the_ows_after_the_equals_is_not_part_of_the_range_set() {
  let spec = RangesSpecifier::parse(b"exampleunit= \t1.2-4.3").unwrap();
  assert_eq!(spec.other_range_set(), Some(&b"1.2-4.3"[..]));
}

// §5.6.1.2 again: `range-set = 1#range-spec` is a list like any other, and an
// empty element is not a bad spec.
#[test]
fn empty_elements_are_parsed_and_ignored() {
  let spec = RangesSpecifier::parse(b"bytes=0-499,,500-999").unwrap();
  assert_eq!(spec.len(), 2, "two range-specs, not an invalid specifier");
  assert_eq!(spec.resolve(0, 2000), Some(Resolved::Range(0, 499)));
  assert_eq!(spec.resolve(1, 2000), Some(Resolved::Range(500, 999)));
}

// ── §14.1.2: satisfiability and normalisation ────────────────────────────────

#[test]
fn satisfiability_and_normalisation() {
  let len = 10_000u64;
  let cases: [(&[u8], Resolved); 8] = [
    // int-range with a first-pos below the length
    (b"bytes=0-499", Resolved::Range(0, 499)),
    // absent last-pos becomes `length - 1`
    (b"bytes=9500-", Resolved::Range(9500, 9999)),
    // last-pos PAST the end becomes `length - 1`
    (b"bytes=9500-99999", Resolved::Range(9500, 9999)),
    // and both sides of the fence post the sentence turns on. RFC 9110 §14.1.2
    // normalises a last-pos "greater than or equal to the current length of the
    // representation data", so `length` itself normalises and `length - 1` is
    // kept as written. An implementation that read the condition as strictly
    // greater answers `Range(0, 10000)` for the first of these — one byte past
    // the end — and answers every other case here correctly.
    (b"bytes=0-10000", Resolved::Range(0, 9999)),
    (b"bytes=0-9999", Resolved::Range(0, 9999)),
    // suffix-range: the last N bytes
    (b"bytes=-500", Resolved::Range(9500, 9999)),
    // a suffix longer than the representation takes the whole of it
    (b"bytes=-99999", Resolved::Range(0, 9999)),
    // first-pos at or past the end is unsatisfiable
    (b"bytes=10000-", Resolved::Unsatisfiable),
  ];
  for (value, expected) in cases {
    let spec = RangesSpecifier::parse(value).unwrap();
    assert_eq!(spec.resolve(0, len), Some(expected), "{value:?}");
  }
}

// RFC 9110 §14.1.2: "When a selected representation has zero length, the only
// satisfiable form of range-spec in a GET request is a suffix-range with a
// non-zero suffix-length." It is satisfiable and yet has NO inclusive positions
// — `length - 1` underflows and §14.4 can express no Content-Range for it.
// §14.2's zero-length MAY-ignore is the exit.
#[test]
fn a_zero_length_representation_has_a_named_answer_not_an_underflow() {
  let suffix = RangesSpecifier::parse(b"bytes=-5").unwrap();
  assert_eq!(suffix.resolve(0, 0), Some(Resolved::EmptyRepresentation));
  assert!(suffix.is_satisfiable(0), "§14.1.2 says it is satisfiable");

  for value in [&b"bytes=0-99"[..], b"bytes=0-", b"bytes=-0"] {
    let spec = RangesSpecifier::parse(value).unwrap();
    assert_eq!(
      spec.resolve(0, 0),
      Some(Resolved::Unsatisfiable),
      "{value:?}"
    );
    assert!(!spec.is_satisfiable(0), "{value:?}");
  }
}

// §14.1.1's set level: satisfiable when at least one range-spec is.
#[test]
fn the_set_level_needs_only_one() {
  let spec = RangesSpecifier::parse(b"bytes=99999-,0-499").unwrap();
  assert!(spec.is_satisfiable(1000));
  assert_eq!(spec.resolve(0, 1000), Some(Resolved::Unsatisfiable));
  assert_eq!(spec.resolve(1, 1000), Some(Resolved::Range(0, 499)));

  let none = RangesSpecifier::parse(b"bytes=99999-,88888-").unwrap();
  assert!(!none.is_satisfiable(1000));
}

// `resolve` and `spec` are both partial; `Resolved`'s three variants all
// describe a range-spec that EXISTS, so an out-of-range index gets `None`
// rather than one of them.
#[test]
fn both_index_accessors_are_partial() {
  let spec = RangesSpecifier::parse(b"bytes=0-499").unwrap();
  assert!(spec.resolve(1, 1000).is_none());
  assert!(spec.spec(1).is_none());
}

// ── RFC 9110 §14.1.2's overflow MUST: "recipients MUST anticipate potentially
// large decimal numerals and prevent parsing errors due to integer conversion
// overflows." The rule is met by NEVER CONVERTING.

#[test]
fn validity_compares_the_numerals_as_digit_strings() {
  // Both numerals are over u64::MAX = 18446744073709551615, so neither can be
  // compared as an integer — and last-pos is the smaller, so the spec is
  // invalid.
  assert!(RangesSpecifier::parse(b"bytes=18446744073709551620-18446744073709551618").is_err());

  // The same two numerals the other way round are valid, and unsatisfiable.
  let spec = RangesSpecifier::parse(b"bytes=18446744073709551618-18446744073709551620").unwrap();
  assert_eq!(spec.resolve(0, 1000), Some(Resolved::Unsatisfiable));

  // Leading zeros do not change a numeral's value.
  assert!(RangesSpecifier::parse(b"bytes=000000000000000000000000000005-4").is_err());
  let spec = RangesSpecifier::parse(b"bytes=0000000000000000000000000004-5").unwrap();
  assert_eq!(spec.resolve(0, 1000), Some(Resolved::Range(4, 5)));
}

// `Pos` is public because a caller with no complete length still needs the
// range-spec as written, and the boundary between its two variants is exactly
// `u64::MAX` — one numeral either side of it, so a fence-post there is visible.
#[test]
fn the_boundary_between_exact_and_beyond_is_u64_max() {
  let spec = RangesSpecifier::parse(b"bytes=18446744073709551615-").unwrap();
  assert_eq!(
    spec.spec(0),
    Some(RangeSpec::Int {
      first: Pos::Exact(u64::MAX),
      last: None
    }),
    "u64::MAX itself is Exact"
  );

  let spec = RangesSpecifier::parse(b"bytes=18446744073709551616-").unwrap();
  assert_eq!(
    spec.spec(0),
    Some(RangeSpec::Int {
      first: Pos::Beyond,
      last: None
    }),
    "one more is Beyond"
  );

  // A numeral that overflows and is then followed by a non-digit is MALFORMED,
  // not very large: the walk reads every byte rather than stopping once the
  // value stopped fitting.
  assert!(RangesSpecifier::parse(b"bytes=18446744073709551616x-").is_err());
}

// ── §14.4: `Content-Range`, in both directions ───────────────────────────────

// §14.4 prints seven Content-Range values across the section. Each parses, and
// each round-trips through `encode`.
#[test]
fn the_seven_printed_examples_round_trip() {
  // Extracted, not remembered — grepping the whole RFC returns thirteen,
  // because §15.3.7.1 and §15.3.7.2 print more:
  //   s=$(grep -n '^14\.4\.' .rfc-cache/rfc9110.txt | head -1 | cut -d: -f1)
  //   e=$(grep -n '^14\.5\.' .rfc-cache/rfc9110.txt | head -1 | cut -d: -f1)
  //   sed -n "${s},${e}p" .rfc-cache/rfc9110.txt | grep -c 'Content-Range: '   # 7
  let examples: [&[u8]; 7] = [
    b"bytes 42-1233/1234",
    b"bytes 42-1233/*",
    b"bytes */1234",
    b"bytes 0-499/1234",
    b"bytes 500-999/1234",
    b"bytes 500-1233/1234",
    b"bytes 734-1233/1234",
  ];
  let mut out = [0u8; 64];
  for value in examples {
    let parsed = ContentRange::parse(value).unwrap_or_else(|e| panic!("{value:?}: {e}"));
    let n = parsed.encode(&mut out).unwrap();
    assert_eq!(&out[..n], value, "round trip");
  }
}

#[test]
fn both_validity_rules_are_enforced_in_both_directions() {
  // RFC 9110 §14.4: "A Content-Range field value is invalid if it contains a
  // range-resp that has a last-pos value less than its first-pos value, or a
  // complete-length value less than or equal to its last-pos value."
  assert!(ContentRange::parse(b"bytes 500-499/1000").is_err());
  assert!(ContentRange::parse(b"bytes 0-999/999").is_err());
  assert!(ContentRange::parse(b"bytes 0-999/1000").is_ok());

  // And the constructor refuses the same two, so a value this crate writes can
  // never be one this crate would refuse to read.
  assert!(ContentRange::bytes(500, 499, Some(1000)).is_err());
  assert!(ContentRange::bytes(0, 999, Some(999)).is_err());
  assert!(ContentRange::bytes(0, 999, Some(1000)).is_ok());
  assert!(
    ContentRange::bytes(0, 999, None).is_ok(),
    "`*` for an unknown total"
  );

  // Both rules are fence posts, and each is stated with an EQUALITY in it —
  // one that admits and one that refuses. `last == first` is a one-octet range
  // and legal; `complete == last` is the half of "less than or equal to" that
  // an implementation testing only `<` would let through, and it describes
  // content that ends before the range it encloses.
  assert!(ContentRange::bytes(500, 500, Some(1000)).is_ok());
  assert!(ContentRange::parse(b"bytes 500-500/1000").is_ok());
  assert!(
    ContentRange::bytes(0, 999, Some(1000)).is_ok(),
    "one more octet"
  );
  assert!(
    ContentRange::bytes(0, 999, Some(999)).is_err(),
    "exactly as many"
  );

  // Which fault is reported is part of the answer: RFC 9110 §14.4 names these
  // two values INVALID, and an invalid value is not a malformed one — the
  // recipient of the first "MUST NOT attempt to recombine", while the second
  // was never a `Content-Range` at all.
  assert!(matches!(
    ContentRange::parse(b"bytes 0-999/999"),
    Err(RangeError::InconsistentContentRange)
  ));
  assert!(matches!(
    ContentRange::parse(b"bytes 0-x/999"),
    Err(RangeError::MalformedContentRange)
  ));
}

// The zero-length representation, from the response side: every complete-length
// of 0 is at or below every last-pos, so §14.4 can express no `range-resp` for
// it. That is `Resolved::EmptyRepresentation` seen from the other direction.
#[test]
fn a_zero_length_representation_has_no_range_resp() {
  assert!(ContentRange::bytes(0, 0, Some(0)).is_err());
  assert!(ContentRange::parse(b"bytes 0-0/0").is_err());
  // The 416 form still carries it, because it names no positions to contradict.
  assert_eq!(ContentRange::unsatisfied(0).complete_length(), Some(0));
}

#[test]
fn the_unsatisfied_form_is_its_own_shape() {
  let cr = ContentRange::unsatisfied(1234);
  assert!(cr.is_unsatisfied());
  assert_eq!(cr.complete_length(), Some(1234));
  assert!(cr.incl_range().is_none());
  assert!(cr.other_range_resp().is_none());

  let mut out = [0u8; 32];
  let n = cr.encode(&mut out).unwrap();
  assert_eq!(&out[..n], b"bytes */1234");

  // `complete-length = 1*DIGIT`, so the asterisk that stands for an unknown
  // total in a `range-resp` is not a form this one has.
  assert!(ContentRange::parse(b"bytes */*").is_err());
  assert!(ContentRange::parse(b"bytes */").is_err());
}

// RFC 9110 §14.4 prints `unsatisfied-range = "*/" complete-length` with no unit
// in it, so the form is unit-independent — and this test used to assert the
// opposite, that the shape was "recognised under `bytes` alone". That
// assertion was manufactured to agree with a defect: the generic walk behind
// `parse` DID recognise the shape, its caller dropped the arm, and the value
// went into storage as an undifferentiated opaque span. What the specification
// leaves to the range unit is §14.1.1's "The range unit name determines what
// kinds of range-spec are applicable to its own specifiers" — the MEANING of a
// specifier — and this form specifies none.
//
// So the classification crosses every unit and the SPAN still does not: the
// bytes are handed back whole, no `complete-length` is read out of them, and
// `encode` writes the sender's own back. That split is what this now pins,
// because it is the one the fix makes.
#[test]
fn the_unsatisfied_form_is_recognised_under_every_unit() {
  let cr = ContentRange::parse(b"exampleunit */25").unwrap();
  assert_eq!(cr.unit(), b"exampleunit");
  assert!(
    cr.is_unsatisfied(),
    "§14.4 attaches no unit condition to this form"
  );
  assert_eq!(
    cr.other_range_resp(),
    Some(&b"*/25"[..]),
    "and the span is still opaque: recognising a shape is not reading a value"
  );
  assert_eq!(
    cr.complete_length(),
    None,
    "no length is read out, because what `25` counts is the unit's question"
  );
  assert!(
    cr.incl_range().is_none(),
    "it names no positions under any unit"
  );
  let mut out = [0u8; 32];
  let n = cr.encode(&mut out).unwrap();
  assert_eq!(&out[..n], b"exampleunit */25", "written back verbatim");

  // The same span under `bytes` is read as well as recognised, which is the one
  // thing the unit still decides.
  let cr = ContentRange::parse(b"bytes */25").unwrap();
  assert!(cr.is_unsatisfied());
  assert_eq!(cr.complete_length(), Some(25));
  assert!(cr.other_range_resp().is_none());

  // A span that is not that shape is not classified as it, under any unit — the
  // recognition is the grammar's and not a property of being unread.
  for ordinary in [
    &b"exampleunit 1.2-4.3/25"[..],
    b"exampleunit 0-9/25",
    b"exampleunit */",
  ] {
    let cr = ContentRange::parse(ordinary).unwrap();
    assert!(!cr.is_unsatisfied(), "{ordinary:?}");
    assert!(cr.other_range_resp().is_some(), "{ordinary:?}");
  }
}

// `range-unit = token` (§14.1), so a value whose unit is not one is no
// `Content-Range` at all, whatever follows the `SP` — the rule
// `the_range_unit_must_be_a_token` pins on the request side.
#[test]
fn the_content_range_unit_must_be_a_token() {
  for bad in [
    &b"by,tes 0-499/1234"[..], // comma is not a `tchar` (§5.6.2)
    b"\"bytes\" 0-499/1234",   // nor is DQUOTE
    b" 0-499/1234",            // and `token = 1*tchar` admits no empty run
  ] {
    assert!(
      matches!(
        ContentRange::parse(bad),
        Err(RangeError::MalformedContentRange)
      ),
      "{bad:?} must not parse"
    );
  }
}

// `range-resp = incl-range "/" ( complete-length / "*" )`: only the literal
// asterisk is the unknown total, and an asterisk with anything behind it is
// neither branch. A reader that tested the leading byte instead would call
// `bytes 0-499/*1234` an unknown total and drop the digits the sender sent.
#[test]
fn only_the_bare_asterisk_is_an_unknown_complete_length() {
  let cr = ContentRange::parse(b"bytes 0-499/*").unwrap();
  assert_eq!(cr.complete_length(), None, "the bare asterisk");

  for bad in [
    &b"bytes 0-499/*1234"[..],
    b"bytes 0-499/**",
    b"bytes 0-499/*/1234",
  ] {
    assert!(
      matches!(
        ContentRange::parse(bad),
        Err(RangeError::MalformedContentRange)
      ),
      "{bad:?} must not parse"
    );
  }
}

#[test]
fn a_non_bytes_unit_is_an_opaque_span() {
  // §14.6's own example. §14.4's grammar makes every position `1*DIGIT`, which
  // these are not — the specification contradicts its own example, and the
  // reader has to survive the example.
  let cr = ContentRange::parse(b"exampleunit 1.2-4.3/25").unwrap();
  assert_eq!(cr.unit(), b"exampleunit");
  assert_eq!(cr.other_range_resp(), Some(&b"1.2-4.3/25"[..]));
  assert!(cr.incl_range().is_none());
  assert!(cr.complete_length().is_none());
  assert!(!cr.is_unsatisfied());

  // Opaque, and therefore round-tripped byte for byte rather than re-spelled.
  let mut out = [0u8; 32];
  let n = cr.encode(&mut out).unwrap();
  assert_eq!(&out[..n], b"exampleunit 1.2-4.3/25");

  // The same span under `bytes` is not opaque, it is malformed: §14.1.2 defines
  // that unit's positions and `1.2` is not one.
  assert!(ContentRange::parse(b"bytes 1.2-4.3/25").is_err());

  // A unit this crate does not read is still a unit — `range-unit = token`
  // (§14.1) — and a value with no `SP` is no `Content-Range` under any unit.
  assert!(ContentRange::parse(b"example unit 1.2-4.3/25").is_err());
  assert!(ContentRange::parse(b"bytes").is_err());
  assert!(ContentRange::parse(b"exampleunit ").is_err());
}

// Opaque was doing two jobs, and only one of them was §14.1.1's. That section
// gives the range unit "what kinds of range-spec are applicable to its own
// specifiers" — a rule about MEANING. §14.4's invalidity sentence is not about
// meaning and carries no unit condition at all: "A Content-Range field value is
// invalid if it contains a range-resp that has a last-pos value less than its
// first-pos value, or a complete-length value less than or equal to its
// last-pos value." It is stated over `range-resp`, whose `incl-range` and
// `complete-length` are `1*DIGIT`, so a value that matches that shape has to
// satisfy it whatever its unit names.
#[test]
fn the_generic_range_resp_shape_is_held_to_section_14_4s_two_clauses() {
  // The two verified inputs, which used to parse and re-encode.
  for invalid in [
    // "a last-pos value less than its first-pos value"
    &b"widgets 9-1/25"[..],
    // "or a complete-length value less than or equal to its last-pos value"
    b"widgets 0-9/9",
    // The equality half of the second clause, spelled apart from the `<` half.
    b"widgets 0-9/8",
    // And with the unknown total, where only the first clause can bite.
    b"widgets 9-1/*",
  ] {
    assert!(
      matches!(
        ContentRange::parse(invalid),
        Err(RangeError::InconsistentContentRange)
      ),
      "{invalid:?}"
    );
    // The same span under `bytes` gets the same answer, which is the point:
    // one rule, and the unit is not one of its conjuncts.
    let mut buf = [0u8; 64];
    let under_bytes = joined(&mut buf, &[b"bytes", &invalid[b"widgets".len()..]]);
    assert!(
      matches!(
        ContentRange::parse(under_bytes),
        Err(RangeError::InconsistentContentRange)
      ),
      "{under_bytes:?}"
    );
  }

  // A value that matches the shape and satisfies both clauses is still OPAQUE.
  // §14.1.1 has not been taken over: the span comes back whole, `incl_range` is
  // still `None`, and `encode` still writes the sender's own digits rather than
  // this crate's spelling of them.
  let cr = ContentRange::parse(b"widgets 007-9/25").unwrap();
  assert_eq!(cr.unit(), b"widgets");
  assert_eq!(cr.other_range_resp(), Some(&b"007-9/25"[..]));
  assert!(cr.incl_range().is_none());
  assert!(cr.complete_length().is_none());
  assert!(!cr.is_unsatisfied());
  let mut out = [0u8; 32];
  let n = cr.encode(&mut out).unwrap();
  assert_eq!(&out[..n], b"widgets 007-9/25");

  // Leading zeros are digits like any other on this path too, so `007` is 7 and
  // the clause is decided on the value rather than on the spelling.
  assert!(matches!(
    ContentRange::parse(b"widgets 007-9/0009"),
    Err(RangeError::InconsistentContentRange)
  ));
  assert!(ContentRange::parse(b"widgets 007-9/0010").is_ok());

  // A numeral no `u64` holds is compared as digits rather than converted, which
  // is what lets the clause be answered at all up there: under `bytes` the same
  // numeral is refused whole, and under another unit refusing it would throw
  // away a value whose positions are not octets and need not fit an octet
  // count. Both of these are past `u64::MAX` (18446744073709551615).
  assert!(matches!(
    ContentRange::parse(b"widgets 0-18446744073709551616/18446744073709551615"),
    Err(RangeError::InconsistentContentRange)
  ));
  let cr = ContentRange::parse(b"widgets 0-18446744073709551616/18446744073709551617").unwrap();
  assert_eq!(
    cr.other_range_resp(),
    Some(&b"0-18446744073709551616/18446744073709551617"[..])
  );
  assert!(matches!(
    ContentRange::parse(b"bytes 0-18446744073709551616/18446744073709551617"),
    Err(RangeError::MalformedContentRange)
  ));

  // What does NOT match the numeric shape stays opaque, and §14.6's own example
  // is the case that matters: `1.2` is not `1*DIGIT`, so neither clause has a
  // pair of numerals and the specification's own printed value still reads.
  for opaque in [
    &b"exampleunit 1.2-4.3/25"[..],
    // Descending, and still not `1*DIGIT`: the recognition is the shape and not
    // a search for a `-` between two things.
    b"exampleunit 4.3-1.2/25",
    // A second `/`, a second `-`, and an asterisk with a tail: each is a shape
    // the `bytes` path refuses outright and this path simply does not claim.
    b"widgets 0-9/1/2",
    b"widgets 0-9-8/25",
    b"widgets 0-9/*x",
  ] {
    let cr = ContentRange::parse(opaque).unwrap_or_else(|_| panic!("{opaque:?}"));
    assert!(cr.other_range_resp().is_some(), "{opaque:?}");
  }

  // §14.4's `unsatisfied-range` is recognised for any unit too, and neither
  // clause says anything about it: it names no `last-pos`, so there is nothing
  // to compare a `complete-length` against. `widgets */0` is therefore a value,
  // where `widgets 0-9/0` is not.
  let cr = ContentRange::parse(b"widgets */0").unwrap();
  assert_eq!(cr.other_range_resp(), Some(&b"*/0"[..]));
  // This assertion used to read `!cr.is_unsatisfied()`, on the reasoning that
  // recognising a shape must not reclassify a span. Half of that is right — the
  // span is still opaque, which the line above pins — and the other half was the
  // finding: the classification was computed here and thrown away, so
  // `encode_part_header` wrote `widgets */0` into a body part while refusing
  // `bytes */0`. §14.4 attaches no unit condition to the form, so neither does
  // this answer. `the_unsatisfied_form_is_recognised_under_every_unit` is where
  // the pair of facts is stated together.
  assert!(
    cr.is_unsatisfied(),
    "the shape is §14.4's under every unit, and the span is still opaque"
  );
  assert!(matches!(
    ContentRange::parse(b"widgets 0-9/0"),
    Err(RangeError::InconsistentContentRange)
  ));
}

// The response side of the same rule as `a_non_bytes_range_set_is_still_held_to
// _the_generic_octet_rule`, and the side whose span reaches an encoder. §14.4
// defers what the tail MEANS to the range unit; §5.5 still says what a field
// value is made of — `field-value = *field-content`, `field-content =
// field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]`, `field-vchar =
// VCHAR / obs-text` — and §14.4's own production accounts for the single SP the
// split consumed. What is left for the tail is `1*field-vchar`.
#[test]
fn a_non_bytes_content_range_tail_is_held_to_the_field_value_rule() {
  // The injection the rule exists for: this parsed, and then `encode` and
  // `multipart::encode_part_header` wrote `X-Evil:y` back out as a header line
  // of a body this crate framed.
  assert!(matches!(
    ContentRange::parse(b"exampleunit x\r\nX-Evil:y"),
    Err(RangeError::MalformedContentRange)
  ));
  // Either line-break octet on its own, since a recipient that accepts a bare
  // LF needs no CR to be misled.
  assert!(ContentRange::parse(b"exampleunit x\rY").is_err());
  assert!(ContentRange::parse(b"exampleunit x\nY").is_err());

  // `obs-text` is admitted, and is the reason the bound is §5.5's `field-vchar`
  // rather than plain `VCHAR`: §5.5 tells a recipient to "treat other allowed
  // octets in field content (i.e., obs-text) as opaque data", which is exactly
  // what this span is. It round-trips byte for byte like any other.
  let cr = ContentRange::parse(b"exampleunit \xff\x80").unwrap();
  assert_eq!(cr.other_range_resp(), Some(&b"\xff\x80"[..]));
  let mut out = [0u8; 32];
  let n = cr.encode(&mut out).unwrap();
  assert_eq!(&out[..n], b"exampleunit \xff\x80");
}

// The fence posts of `1*field-vchar`, and the two whitespace octets §5.5 would
// admit inside some other field's value but §14.4 leaves no room for: its
// `Content-Range = range-unit SP ( range-resp / unsatisfied-range )` holds one
// whitespace character, the split has consumed it, and neither alternative
// behind it holds another.
#[test]
fn the_opaque_tail_octet_set_is_field_vchar_and_nothing_else() {
  for (byte, admitted) in [
    (0x00u8, false),
    (0x09, false), // HTAB
    (0x0a, false), // LF
    (0x0d, false), // CR
    (0x1f, false),
    (0x20, false), // a second SP
    (0x21, true),
    (0x7e, true),
    (0x7f, false), // DEL is a CTL, not a VCHAR
    (0x80, true),  // `obs-text` begins
    (0xff, true),  // and ends
  ] {
    let mut value = *b"exampleunit aXb";
    value[13] = byte;
    assert_eq!(
      ContentRange::parse(&value).is_ok(),
      admitted,
      "{byte:#04x} in an opaque range-resp"
    );
  }
}

// Where the span GOES afterwards, which is the half the octet rule exists for.
// `ContentRange::parse` is the only constructor of the opaque form, so a tail it
// refuses is one no encoder can be handed — there is no second way to build the
// value `encode` and `encode_part_header` write back verbatim.
#[test]
fn nothing_this_crate_can_encode_carries_a_line_break() {
  for smuggled in [
    &b"exampleunit x\r\nX-Evil:y"[..],
    b"exampleunit 1.2-4.3/25\r\nX-Evil:y",
    b"exampleunit \r\n",
    b"exampleunit \n",
  ] {
    assert!(
      ContentRange::parse(smuggled).is_err(),
      "{smuggled:?} must not become an encodable value"
    );
  }

  // And a well-formed opaque tail is still written into a part header byte for
  // byte, which is the behaviour the refusal above must not have cost.
  let cr = ContentRange::parse(b"exampleunit 1.2-4.3/25").unwrap();
  let mut out = [0u8; 64];
  let n =
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"SEP", &mut out)
      .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--SEP\r\nContent-Range: exampleunit 1.2-4.3/25\r\n\r\n"[..]
  );
}

// RFC 9110 §14.1 says "All range unit names are case-insensitive". Matching the
// token exactly would read `BYTES 0-499/1234` as an opaque span and deny a
// recombiner the positions it needs.
#[test]
fn the_content_range_unit_is_matched_case_insensitively_and_returned_verbatim() {
  let cr = ContentRange::parse(b"BYTES 0-499/1234").unwrap();
  assert_eq!(cr.unit(), b"BYTES", "returned as the sender wrote it");
  assert!(cr.other_range_resp().is_none(), "but recognised as bytes");
  assert_eq!(cr.incl_range(), Some((0, 499)));
  assert_eq!(cr.complete_length(), Some(1234));

  // And the sender's spelling survives the round trip, since normalising it
  // would lose what was received.
  let mut out = [0u8; 32];
  let n = cr.encode(&mut out).unwrap();
  assert_eq!(&out[..n], b"BYTES 0-499/1234");
}

// RFC 9110 §14.1.2: "recipients MUST anticipate potentially large decimal
// numerals and prevent parsing errors due to integer conversion overflows."
// Nothing here converts one: a numeral past `u64::MAX` is refused whole rather
// than truncated, and `u64::MAX` itself is not.
#[test]
fn a_numeral_no_u64_holds_is_refused_rather_than_truncated() {
  let cr = ContentRange::parse(b"bytes 0-18446744073709551614/18446744073709551615").unwrap();
  assert_eq!(cr.incl_range(), Some((0, 18_446_744_073_709_551_614)));
  assert_eq!(cr.complete_length(), Some(u64::MAX));

  for over in [
    &b"bytes 0-18446744073709551616/*"[..],
    b"bytes 18446744073709551616-18446744073709551617/*",
    b"bytes 0-499/18446744073709551616",
    b"bytes */18446744073709551616",
  ] {
    assert!(
      matches!(
        ContentRange::parse(over),
        Err(RangeError::MalformedContentRange)
      ),
      "{over:?}"
    );
  }

  // Leading zeros are digits like any other, and `encode` writes the value
  // rather than the spelling.
  let cr = ContentRange::parse(b"bytes 007-0499/01234").unwrap();
  assert_eq!(cr.incl_range(), Some((7, 499)));
  let mut out = [0u8; 32];
  let n = cr.encode(&mut out).unwrap();
  assert_eq!(&out[..n], b"bytes 7-499/1234");
}

#[test]
fn encode_reports_a_small_buffer_rather_than_truncating() {
  let cr = ContentRange::bytes(0, 999, Some(1000)).unwrap();
  let mut tiny = [0u8; 4];
  assert!(matches!(
    cr.encode(&mut tiny),
    Err(RangeError::BufferTooSmall)
  ));
  assert_eq!(tiny, [0u8; 4], "a failed call must not have written");

  // The EXACT fit, the boundary between the two arms and the seat an off-by-one
  // in a measure-then-write encoder takes.
  let mut exact = [0xAAu8; 16];
  assert_eq!(cr.encode(&mut exact), Ok(16));
  assert_eq!(&exact[..], b"bytes 0-999/1000");

  // One byte short of it, and one byte over.
  let mut short = [0xAAu8; 15];
  assert!(matches!(
    cr.encode(&mut short),
    Err(RangeError::BufferTooSmall)
  ));
  assert_eq!(short, [0xAAu8; 15], "and still must not have written");
  let mut roomy = [0xAAu8; 17];
  assert_eq!(cr.encode(&mut roomy), Ok(16));
  assert_eq!(roomy[16], 0xAA, "nothing past the value it wrote");
}

// ── §14.6 and RFC 2046 §5.1.1: the `multipart/byteranges` writer ─────────────

#[test]
fn a_part_header_carries_its_content_range() {
  let cr = ContentRange::bytes(500, 999, Some(8000)).unwrap();
  let ct = crate::media::media_type(b"application/pdf").unwrap();
  let mut out = [0u8; 128];
  let n = multipart::encode_part_header(
    &cr,
    Some(&ct),
    multipart::PartEncoding::Absent,
    b"THIS_STRING_SEPARATES",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    b"\r\n--THIS_STRING_SEPARATES\r\nContent-Type: application/pdf\r\nContent-Range: bytes 500-999/8000\r\n\r\n"
  );
}

// §15.3.7.2 makes the per-part Content-Type a SHOULD conditional on the 200
// response having carried one, so it is optional. The Content-Range is not.
#[test]
fn the_content_type_is_optional_and_the_content_range_is_not() {
  let cr = ContentRange::bytes(0, 9, Some(10)).unwrap();
  let mut out = [0u8; 128];
  let n = multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut out)
    .unwrap();
  assert_eq!(&out[..n], b"\r\n--B\r\nContent-Range: bytes 0-9/10\r\n\r\n");
}

// RFC 9110 §15.3.7.2: the per-part field MUST correspond "to the range being
// enclosed in that body part", and `bytes */1234` encloses nothing. It passes
// §14.4's two validity rules, so only `is_unsatisfied` catches it — and this
// crate refuses what it can check.
#[test]
fn a_part_header_refuses_the_unsatisfied_form() {
  let cr = ContentRange::unsatisfied(1234);
  let mut out = [0u8; 128];
  assert!(
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut out)
      .is_err()
  );

  // And it is refused for the reason above rather than for the boundary, the
  // buffer, or a media type it could not spell back — all three of which are
  // fine here, and the last of which shared this refusal's variant until the
  // two were told apart.
  assert!(matches!(
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut out),
    Err(RangeError::UnsatisfiedPartRange)
  ));
  assert_eq!(out, [0u8; 128], "a refused call must not have written");
}

// The other side of that refusal, and it used to pin the DEFECT. This test was
// written as `a_part_header_writes_the_unsatisfied_shape_under_another_unit`
// and asserted that `exampleunit */25` was written into a part header —
// manufactured to agree with the answer `is_unsatisfied` was giving, on the
// reading that §14.1.1's delegation of a specifier's MEANING also delegates
// whether §14.4's second alternative was written at all. It does not: §14.4
// prints `unsatisfied-range = "*/" complete-length` inside one grammar with one
// `range-unit` slot and no unit condition on either half, so a value of that
// shape names no positions whatever the unit counts, and §15.3.7.2's "Within
// the header area of each body part in the multipart content, the server MUST
// generate a Content-Range header field corresponding to the range being
// enclosed in that body part" reaches it under every unit.
//
// So the refusal has no boundary at the unit, and what is pinned here is that
// the two spellings get one answer.
#[test]
fn a_part_header_refuses_the_unsatisfied_shape_under_every_unit() {
  let mut out = [0u8; 128];
  for unsatisfied in [&b"exampleunit */25"[..], b"bytes */25", b"widgets */0"] {
    let cr = ContentRange::parse(unsatisfied).unwrap();
    assert!(cr.is_unsatisfied(), "{unsatisfied:?}");
    assert!(
      matches!(
        multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut out),
        Err(RangeError::UnsatisfiedPartRange)
      ),
      "{unsatisfied:?}"
    );
    assert_eq!(out, [0u8; 128], "{unsatisfied:?}: refused before writing");
  }

  // The delegation that DOES stand: a span under a unit this crate cannot read
  // still heads a part, because §14.1.1 leaves what its positions mean to that
  // unit and §15.3.7.2's correspondence is then the caller's to hold. Only the
  // form that encloses nothing under every reading is refused.
  let cr = ContentRange::parse(b"exampleunit 1.2-4.3/25").unwrap();
  let n = multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut out)
    .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--B\r\nContent-Range: exampleunit 1.2-4.3/25\r\n\r\n"[..]
  );
}

#[test]
fn the_final_boundary_closes_with_two_hyphens() {
  let mut out = [0u8; 32];
  let n = multipart::encode_final_boundary(b"B", &mut out).unwrap();
  assert_eq!(&out[..n], b"\r\n--B--\r\n");
}

// RFC 2046 §5.1.1: `boundary := 0*69<bchars> bcharsnospace`, so 1 to 70
// characters from a restricted set, not ending in a space.
#[test]
fn boundary_validity_is_this_crates_to_check() {
  let mut out = [0u8; 128];
  let mut ok = |b: &[u8]| multipart::encode_final_boundary(b, &mut out).is_ok();
  assert!(ok(b"a"));
  assert!(ok(&[b'a'; 70]));
  assert!(!ok(b""), "at least one character");
  assert!(!ok(&[b'a'; 71]), "at most seventy");
  assert!(!ok(b"a "), "must not end with a space");
  assert!(ok(b"a b"), "but a space inside is a bchar");
  assert!(!ok(b"a\tb"), "tab is not");
  assert!(!ok(b"a\"b"), "nor is a DQUOTE");
}

#[test]
fn a_short_buffer_is_reported_not_truncated() {
  let cr = ContentRange::bytes(0, 9, Some(10)).unwrap();
  let mut tiny = [0u8; 8];
  assert!(matches!(
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut tiny),
    Err(RangeError::BufferTooSmall)
  ));
  assert_eq!(tiny, [0u8; 8], "a failed call must not have written");
}

// The fence post a measure-then-write encoder puts an off-by-one in: the exact
// fit, one byte short of it, and one byte over.
#[test]
fn a_part_header_fits_exactly_or_is_refused() {
  let cr = ContentRange::bytes(0, 9, Some(10)).unwrap();
  let exact = b"\r\n--B\r\nContent-Range: bytes 0-9/10\r\n\r\n".len();

  let mut room = [0xAAu8; 38];
  assert_eq!(room.len(), exact);
  assert_eq!(
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut room),
    Ok(exact)
  );

  let mut short = [0xAAu8; 37];
  assert!(matches!(
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut short),
    Err(RangeError::BufferTooSmall)
  ));
  assert_eq!(short, [0xAAu8; 37], "and still must not have written");

  let mut roomy = [0xAAu8; 39];
  assert_eq!(
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"B", &mut roomy),
    Ok(exact)
  );
  assert_eq!(roomy[exact], 0xAA, "nothing past the header it wrote");

  // The close-delimiter measures itself the same way.
  let mut close = [0xAAu8; 8];
  assert!(matches!(
    multipart::encode_final_boundary(b"B", &mut close),
    Err(RangeError::BufferTooSmall)
  ));
  assert_eq!(close, [0xAAu8; 8], "and it writes nothing either");
}

// Both entry points refuse the same boundary, with the same fault: a body whose
// parts and whose close-delimiter could disagree about it is one no reader finds
// the end of.
#[test]
fn both_writers_refuse_the_same_boundary() {
  let cr = ContentRange::bytes(0, 9, Some(10)).unwrap();
  let mut out = [0u8; 128];
  for bad in [&b""[..], b"a ", b"a\"b", &[b'a'; 71]] {
    assert!(
      matches!(
        multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, bad, &mut out),
        Err(RangeError::MalformedBoundary)
      ),
      "{bad:?} must not head a part"
    );
    assert!(
      matches!(
        multipart::encode_final_boundary(bad, &mut out),
        Err(RangeError::MalformedBoundary)
      ),
      "{bad:?} must not close a body"
    );
  }
}

// `bcharsnospace` is narrower than a `tchar` and is not a subset of one, so
// neither check stands in for the other. Every character §5.1.1 prints, and the
// `tchar`s it leaves out.
#[test]
fn the_boundary_set_is_the_one_rfc_2046_prints() {
  let mut out = [0u8; 128];
  let mut ok = |b: &[u8]| multipart::encode_final_boundary(b, &mut out).is_ok();

  // DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," / "-" / "." /
  // "/" / ":" / "=" / "?"
  for byte in b"0189azAZ'()+_,-./:=?" {
    assert!(ok(&[*byte]), "{:?} is a bcharsnospace", *byte as char);
  }

  // §5.6.2 `tchar`s that this set does not hold — the direction that says the
  // two grammars are not nested.
  for byte in b"!#$%&*^`|~" {
    assert!(
      !ok(&[*byte]),
      "{:?} is a tchar and not a bchar",
      *byte as char
    );
  }

  // And a `bcharsnospace` that is not a `tchar`, the other direction.
  assert!(ok(b"("), "( heads no token");
  assert!(!crate::grammar::is_token(b"("));
}

// §15.3.7.2's own printed example, rebuilt from this writer and the content a
// caller would put between the pieces.
#[test]
fn the_printed_example_is_what_this_writer_produces() {
  fn append(body: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    body[at..at + bytes.len()].copy_from_slice(bytes);
    at + bytes.len()
  }

  let boundary = b"THIS_STRING_SEPARATES";
  let pdf = crate::media::media_type(b"application/pdf").unwrap();
  let first = ContentRange::bytes(500, 999, Some(8000)).unwrap();
  let second = ContentRange::bytes(7000, 7999, Some(8000)).unwrap();

  let mut body = [0u8; 512];
  let mut at = 0;
  at += multipart::encode_part_header(
    &first,
    Some(&pdf),
    multipart::PartEncoding::Absent,
    boundary,
    &mut body[at..],
  )
  .unwrap();
  at = append(&mut body, at, b"...the first range...");
  at += multipart::encode_part_header(
    &second,
    Some(&pdf),
    multipart::PartEncoding::Absent,
    boundary,
    &mut body[at..],
  )
  .unwrap();
  at = append(&mut body, at, b"...the second range");
  at += multipart::encode_final_boundary(boundary, &mut body[at..]).unwrap();

  // The section prints the body with no CRLF before its first dash-boundary,
  // because there is no preamble. This writer emits the `delimiter` form every
  // time, so the difference is one leading CRLF — `[preamble CRLF]` with the
  // preamble empty, which is also §14.6's first implementation note read from
  // the writer's side.
  assert_eq!(
    &body[..at],
    &b"\r\n\
       --THIS_STRING_SEPARATES\r\n\
       Content-Type: application/pdf\r\n\
       Content-Range: bytes 500-999/8000\r\n\
       \r\n\
       ...the first range...\r\n\
       --THIS_STRING_SEPARATES\r\n\
       Content-Type: application/pdf\r\n\
       Content-Range: bytes 7000-7999/8000\r\n\
       \r\n\
       ...the second range\r\n\
       --THIS_STRING_SEPARATES--\r\n"[..]
  );
}

// RFC 9110 §14.6: "Despite the name, the "multipart/byteranges" media type is
// not limited to byte ranges." The section's own example uses a unit whose
// positions §14.4's `1*DIGIT` does not admit, and a part header carries such a
// value unread.
#[test]
fn a_part_header_carries_a_unit_this_crate_does_not_read() {
  let cr = ContentRange::parse(b"exampleunit 1.2-4.3/25").unwrap();
  let ct = crate::media::media_type(b"video/example").unwrap();
  let mut out = [0u8; 128];
  let n = multipart::encode_part_header(
    &cr,
    Some(&ct),
    multipart::PartEncoding::Absent,
    b"THIS_STRING_SEPARATES",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--THIS_STRING_SEPARATES\r\n\
       Content-Type: video/example\r\n\
       Content-Range: exampleunit 1.2-4.3/25\r\n\r\n"[..]
  );
}

// A media type is written back whole, parameters and all: RFC 9110 §15.3.7.2
// asks for "that same Content-Type header field", not for its name half.
#[test]
fn a_content_types_parameters_survive_the_part_header() {
  let cr = ContentRange::bytes(0, 9, Some(10)).unwrap();
  let mut out = [0u8; 128];

  let ct = crate::media::media_type(b"text/plain;charset=utf-8").unwrap();
  let n = multipart::encode_part_header(
    &cr,
    Some(&ct),
    multipart::PartEncoding::Absent,
    b"B",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--B\r\nContent-Type: text/plain;charset=utf-8\r\n\
       Content-Range: bytes 0-9/10\r\n\r\n"[..]
  );

  // A quoted-string value keeps its DQUOTEs, since §5.6.4's escapes come back
  // untouched and only the marks around them were taken off.
  let ct = crate::media::media_type(b"text/plain; charset=\"utf-8\"").unwrap();
  let n = multipart::encode_part_header(
    &cr,
    Some(&ct),
    multipart::PartEncoding::Absent,
    b"B",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--B\r\nContent-Type: text/plain;charset=\"utf-8\"\r\n\
       Content-Range: bytes 0-9/10\r\n\r\n"[..]
  );

  // The OWS §5.6.6 admits around the semicolon is not written back: §8.3.1
  // prints four equivalent spellings of one media type and says the tight one
  // "is preferred for consistency", so two values differing only in that
  // whitespace write the same field.
  let spaced = crate::media::media_type(b"text/plain ; charset=utf-8").unwrap();
  let n = multipart::encode_part_header(
    &cr,
    Some(&spaced),
    multipart::PartEncoding::Absent,
    b"B",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--B\r\nContent-Type: text/plain;charset=utf-8\r\n\
       Content-Range: bytes 0-9/10\r\n\r\n"[..]
  );
}

// The other span this writer copies out of a parsed value, and the one the
// sweep found already correct. What `encode_part_header` writes for a
// `Content-Type` is the media type's own bytes: its two tokens, each
// parameter's name, and each value either as a token or as a `quoted-string`
// interior with §5.6.4's escapes untouched. Every one of those is checked
// before a `MediaType` can exist — §5.6.2's `token` for the names and the
// unquoted values, and §5.6.4's `qdtext`/`quoted-pair` for the interior, which
// admits HTAB, SP and `field-vchar` and nothing else. So no CR, LF or CTL
// reaches this writer through a parameter. Asserted here rather than assumed,
// because this module is where such a byte would be written into the header
// area of a body this crate framed.
#[test]
fn no_content_type_this_writer_accepts_carries_a_line_break() {
  for smuggled in [
    &b"text/plain;charset=\"a\r\nX-Evil: y\""[..],
    b"text/plain;charset=\"a\rb\"",
    b"text/plain;charset=\"a\nb\"",
    b"text/plain;charset=\"a\x00b\"",
  ] {
    assert!(
      crate::media::media_type(smuggled).is_err(),
      "{smuggled:?} must not become a MediaType this writer would spell back"
    );
  }

  // And the interior that IS admitted still round-trips through the writer with
  // its escapes as the sender wrote them.
  let cr = ContentRange::bytes(0, 9, Some(10)).unwrap();
  let ct = crate::media::media_type(b"text/plain;charset=\"a\\\"b\"").unwrap();
  let mut out = [0u8; 128];
  let n = multipart::encode_part_header(
    &cr,
    Some(&ct),
    multipart::PartEncoding::Absent,
    b"B",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--B\r\nContent-Type: text/plain;charset=\"a\\\"b\"\r\n\
       Content-Range: bytes 0-9/10\r\n\r\n"[..]
  );
}

// The DESTINATION's grammar rather than the source's, which is the half the
// sweep above did not ask. RFC 9110 §5.5 admits `obs-text` in a field value and
// `ContentRange::parse` keeps it, because an `obs-text` tail is a legal HTTP
// field value and a caller who never writes a multipart body is entitled to it.
// RFC 2046 §5.1.1 admits no such octet where this writer would put it:
// "However, in no event are headers (either message headers or body part
// headers) allowed to contain anything other than US-ASCII characters." §14.6
// is what puts this writer's output under that rule, so the refusal sits at the
// encoder that crosses into MIME and not at the parse.
//
// The comment on `no_content_type_this_writer_accepts_carries_a_line_break`
// calls the `Content-Type` span already correct, and it is — for the grammar
// that sweep asked about, which was CR, LF and CTL. US-ASCII is the one it did
// not ask, and `obs-text` is admitted by both §5.5 and §5.6.4's
// `quoted-string`.
#[test]
fn a_part_header_this_writer_would_not_write_in_us_ascii_is_refused() {
  let tail = ContentRange::parse(b"exampleunit \x80").unwrap();
  assert_eq!(
    tail.other_range_resp(),
    Some(&b"\x80"[..]),
    "the parse is not narrowed: this is a legal HTTP field value"
  );
  let mut field = [0u8; 32];
  let n = tail.encode(&mut field).unwrap();
  assert_eq!(
    &field[..n],
    b"exampleunit \x80",
    "and the FIELD encoder still writes it, since §5.5 is its destination too"
  );

  let mut out = [0u8; 128];
  assert_eq!(
    multipart::encode_part_header(
      &tail,
      None,
      multipart::PartEncoding::Absent,
      b"SEP",
      &mut out
    ),
    Err(RangeError::NonAsciiPartHeader),
    "the MIME encoder is the one that refuses"
  );
  assert!(
    out.iter().all(|byte| *byte == 0),
    "and it refuses before writing a byte, as every other refusal here does"
  );

  // The other span that can carry one: §5.6.4's `quoted-string` admits
  // `obs-text`, so a `Content-Type` parameter reaches the same refusal.
  let cr = ContentRange::bytes(0, 1, Some(2)).unwrap();
  let quoted = crate::media::media_type(b"text/plain;charset=\"\x80\"").unwrap();
  assert_eq!(
    multipart::encode_part_header(
      &cr,
      Some(&quoted),
      multipart::PartEncoding::Absent,
      b"SEP",
      &mut out
    ),
    Err(RangeError::NonAsciiPartHeader)
  );
  // Including one behind a `quoted-pair`, which is written back out escaped and
  // is still the octet RFC 2046 keeps out.
  let escaped = crate::media::media_type(b"text/plain;charset=\"a\\\x80b\"").unwrap();
  assert_eq!(
    multipart::encode_part_header(
      &cr,
      Some(&escaped),
      multipart::PartEncoding::Absent,
      b"SEP",
      &mut out
    ),
    Err(RangeError::NonAsciiPartHeader)
  );

  // The same two shapes with every octet inside US-ASCII are written, so the
  // refusal is the byte and not the shape.
  let ascii_tail = ContentRange::parse(b"exampleunit 1.2-4.3/25").unwrap();
  assert!(
    multipart::encode_part_header(
      &ascii_tail,
      None,
      multipart::PartEncoding::Absent,
      b"SEP",
      &mut out
    )
    .is_ok()
  );
  let ascii_type = crate::media::media_type(b"text/plain;charset=\"utf-8\"").unwrap();
  assert!(
    multipart::encode_part_header(
      &cr,
      Some(&ascii_type),
      multipart::PartEncoding::Absent,
      b"SEP",
      &mut out
    )
    .is_ok()
  );
}

// `part_header_is_ascii` enumerates the spans this writer copies and argues the
// rest is ASCII by construction. This asks the ARTIFACT the same question: for
// every pair below, either the call was refused or the bytes it produced are
// US-ASCII. A span added to the writer and forgotten in that enumeration fails
// here with the header it wrote rather than in a review comment.
#[test]
fn the_part_header_writer_only_ever_writes_us_ascii() {
  let ranges = [
    ContentRange::bytes(0, 9, Some(10)).unwrap(),
    ContentRange::bytes(0, u64::MAX, None).unwrap(),
    ContentRange::parse(b"BYTES 500-999/8000").unwrap(),
    ContentRange::parse(b"exampleunit 1.2-4.3/25").unwrap(),
    ContentRange::parse(b"exampleunit \x80").unwrap(),
    ContentRange::parse(b"exampleunit \xff\x81").unwrap(),
  ];
  let types = [
    None,
    Some(crate::media::media_type(b"application/pdf").unwrap()),
    Some(crate::media::media_type(b"text/plain;charset=\"utf-8\"").unwrap()),
    Some(crate::media::media_type(b"text/plain;charset=\"\x80\"").unwrap()),
    Some(crate::media::media_type(b"text/plain;charset=\"a\\\x80b\"").unwrap()),
  ];
  let mut out = [0u8; 256];
  let (mut written, mut refused) = (0usize, 0usize);
  for range in &ranges {
    for content_type in &types {
      match multipart::encode_part_header(
        range,
        content_type.as_ref(),
        multipart::PartEncoding::Absent,
        b"SEP",
        &mut out,
      ) {
        Ok(n) => {
          written = written.saturating_add(1);
          let header = &out[..n];
          assert!(
            header.is_ascii(),
            "wrote a body part header RFC 2046 §5.1.1 does not admit: {header:?}"
          );
        }
        Err(err) => {
          refused = refused.saturating_add(1);
          assert_eq!(
            err,
            RangeError::NonAsciiPartHeader,
            "{range:?} / {content_type:?}"
          );
        }
      }
    }
  }
  // Neither arm is vacuous: a writer that refused all thirty would satisfy the
  // assertion above without producing a byte, and one that accepted all thirty
  // would be the defect this test exists for.
  assert_eq!((written, refused), (12, 18));
}

// ── §14.6 and RFC 2046 §5.1.1: the `multipart/byteranges` reader ─────────────

// §15.3.7.2's printed example, with §5.1.1's preamble and epilogue around it.
//
// The POSITIONS are narrowed from the example's, and the narrowing is the
// example's own elision rather than a liberty taken here. §15.3.7.2 prints
// `bytes 500-999/8000` over a body part whose content it writes as
// `...the first range...` — twenty-one characters standing in for the five
// hundred octets that range encloses, which is also what its own
// `Content-Length: 1741` counts. Transcribed literally, the part declares a
// range five hundred octets wide and carries twenty-one, and that is exactly
// the §15.3.7.2 correspondence `RangeError::PartRangeMismatch` refuses. So each
// range here is narrowed to the width of the placeholder the RFC printed inside
// it, and every other byte of the example — the boundary, the field order, the
// per-part `Content-Type`, the 8000-octet complete-length — is as printed.
const BODY: &[u8] = b"\
This is the preamble. It is to be ignored.\r\n\
--SEP\r\n\
Content-Type: application/pdf\r\n\
Content-Range: bytes 500-520/8000\r\n\
\r\n\
...the first range...\r\n\
--SEP\r\n\
Content-Range: bytes 7000-7021/8000\r\n\
\r\n\
...the second range...\r\n\
--SEP--\r\n\
This is the epilogue. It is to be ignored.";

#[test]
fn reads_both_parts_and_ignores_the_preamble_and_epilogue() {
  let mut reader = multipart::ByteRangesReader::new(b"SEP", BODY).unwrap();

  let first = reader.next().unwrap().unwrap();
  assert_eq!(first.content_range().incl_range(), Some((500, 520)));
  let ct = first.content_type().unwrap();
  assert_eq!((ct.ty(), ct.subtype()), ("application", "pdf"));
  assert_eq!(first.content(), b"...the first range...");

  let second = reader.next().unwrap().unwrap();
  assert_eq!(second.content_range().incl_range(), Some((7000, 7021)));
  assert!(second.content_type().is_none());
  assert_eq!(second.content(), b"...the second range...");

  assert!(
    reader.next().unwrap().is_none(),
    "the close-delimiter ends it"
  );
  assert!(reader.next().unwrap().is_none(), "and stays ended");
}

// RFC 2046 §5.1.1's `transport-padding := *LWSP-char` follows the boundary on
// every delimiter line, and the comment on that rule splits the two sides:
// composers must not generate any, and receivers must handle what a message
// transport added. Stated here rather than quoted, because that comment is one
// `;` per line in the RFC's own text and no contiguous quotation of it exists.
#[test]
fn transport_padding_is_tolerated() {
  let body = b"--SEP \t\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--   \r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"ab");
  assert!(reader.next().unwrap().is_none());
}

// RFC 2046 §5.1: "The only header fields that have defined meaning for body
// parts are those the names of which begin with "Content-". All other header
// fields may be ignored in body parts."
#[test]
fn unknown_part_header_fields_are_skipped() {
  let body =
    b"--SEP\r\nX-Trace: abc\r\nContent-Range: bytes 0-1/2\r\nX-Other: d\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), Some((0, 1)));
  assert_eq!(part.content(), b"ab");
}

// RFC 2046 §5.1.1: "Boundary string comparisons must compare the boundary value
// with the beginning of each candidate line. An exact match of the entire
// candidate line is not required; it is sufficient that the boundary appear in
// its entirety following the CRLF."
//
// The note settles which lines are CANDIDATES and nothing else. What may then
// stand on such a line is §5.1.1's own `transport-padding := *LWSP-char`, so a
// line the prefix test recognises and the padding production does not admit is
// no delimiter — and INSIDE A PART, which is where this test puts it, that is a
// refusal rather than a tail to skip.
//
// The region is half the rule and the test below is the other half: before the
// body's first delimiter line the same bytes are preamble, which §5.1.1 says to
// ignore.
//
// **This test must not assert the skip.** Reading `ab` back out of the body
// below and calling the answer correct makes a body RFC 2046 refuses twice
// over — §5.1 forbids the line, §5.1.1 admits nothing but LWSP behind a
// boundary — indistinguishable from a conformant one. The citation above is
// right; an answer that skips is not.
#[test]
fn the_matcher_is_a_prefix_test() {
  // A body-part line beginning with the dash-boundary is malformed input by
  // RFC 2046's own rule — §5.1: "The boundary delimiter MUST NOT appear inside
  // any of the encapsulated parts, on a line by itself or as the prefix of any
  // line." The prefix reading is what §5.1.1 names for it, and under that
  // reading `--SEPARATOR-JUNK` is a delimiter line carrying `ARATOR-JUNK`
  // where only `*LWSP-char` may stand.
  let body = b"--SEP\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEPARATOR-JUNK\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert!(
    matches!(reader.next(), Err(RangeError::MalformedMultipart)),
    "a delimiter line whose tail is not transport-padding"
  );

  // And the refusal is EVIDENCE of the prefix test rather than of anything
  // else, because the two readings answer this body differently. Under the
  // exact-match reading the note rejects, `--SEPARATOR-JUNK` is not a
  // delimiter at all: it is content, the part runs on to `--SEP--`, and the
  // call succeeds with those bytes inside it. Nothing above is that answer.
  //
  // The same line with a `transport-padding` tail is the other half — the
  // prefix test recognises `--SEP \t` as readily, and there the grammar admits
  // what follows the boundary, so the part is read and closed. Both halves are
  // the one rule: a prefix match makes the line a delimiter, and being a
  // delimiter is what holds its tail to §5.1.1.
  let padded = b"--SEP\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP \t\r\n\
                 Content-Range: bytes 2-3/4\r\n\r\ncd\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", padded).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"ab");
  assert_eq!(reader.next().unwrap().unwrap().content(), b"cd");
  assert!(reader.next().unwrap().is_none());
}

// One predicate, two regions, two opposite rules — and RFC 2046 writes both of
// them down.
//
// §5.1.1: "implementations must ignore anything that appears before the first
// boundary delimiter line or after the last one."
//
// §5.1: "The boundary delimiter MUST NOT appear inside any of the encapsulated
// parts, on a line by itself or as the prefix of any line."
//
// A line beginning with the dash-boundary whose tail makes it neither of
// §5.1.1's two delimiters is therefore `discard-text` in the preamble and a
// fault inside a part. The bytes are identical; only the region differs, which
// is why the reader takes the region as an argument.
//
// Leaving the first rule unapplied fails the whole body over `--SEPARATOR`
// standing above the real `--SEP` — a refusal over the one region §5.1.1 names
// as the place to ignore whatever is there. Applying it must not undo the
// delimiter-tail rule, so the loops below assert the preamble half AND both
// halves of the `body-part` production against the same three lines.
#[test]
fn a_prefix_like_line_is_preamble_before_the_first_delimiter_and_a_fault_inside_a_part() {
  // Neither delimiter production admits any of these: `--SEPARATOR` has
  // `ARATOR` where only `*LWSP-char` may stand, `--SEP TRAIL` has `TRAIL`
  // behind its padding, and `--SEP--JUNK` has `JUNK` where a close-delimiter
  // takes padding and then the end of the body or the CRLF of an epilogue.
  // Thirteen bytes each, deliberately, so that one `Content-Range` states the
  // width the CONTENT loop's alternative reading would produce. The last
  // preamble row is several such lines with ordinary preamble text between
  // them, since §5.1.1's `preamble := discard-text` is `*(*text CRLF) *text`
  // and puts no bound on how much there is.
  const CANDIDATES: [&[u8]; 3] = [b"--SEPARATOR\r\n", b"--SEP TRAIL\r\n", b"--SEP--JUNK\r\n"];
  for preamble in [
    CANDIDATES[0],
    CANDIDATES[1],
    CANDIDATES[2],
    b"This is the preamble. It is to be ignored.\r\n",
    b"--SEPARATOR\r\nnoise\r\n--SEP-ALSO-NOT\r\n",
  ] {
    let mut buf = [0u8; 160];
    let body = joined(
      &mut buf,
      &[
        preamble,
        b"--SEP\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert_eq!(
      reader.next().unwrap().unwrap().content(),
      b"ab",
      "{preamble:?} stands before the first boundary delimiter line"
    );
    assert!(reader.next().unwrap().is_none(), "{preamble:?}");
  }

  // The same three lines in a part's CONTENT, where §5.1 forbids the prefix
  // outright. `body-part := MIME-part-headers [CRLF *OCTET]` is the production,
  // and this is its second half.
  //
  // `bytes 0-18/20` is the width of `ab\r\n<line>cd` under the reading this
  // refusal denies: nineteen octets, which is what the part would enclose if a
  // boundary-prefixed line inside it were ordinary content. So a reader that
  // walked past the line would answer `Ok`, not `PartRangeMismatch` — the
  // refusal below is evidence of the prefix rule rather than of a width that
  // failed to add up.
  for interior in CANDIDATES {
    let mut buf = [0u8; 160];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: bytes 0-18/20\r\n\r\nab\r\n",
        interior,
        b"cd\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{interior:?} inside a part's content"
    );
  }

  // And in a part's HEADER BLOCK, which is the first half of that same
  // production and the third site that census reaches. Asked with a colon
  // behind the line, because a line with no colon is malformed whatever it
  // starts with and would pin nothing: what these two rows discriminate is the
  // dash-boundary rule against RFC 2046 §5.1's "All other header fields may be
  // ignored in body parts", which is what walks past a field this reader does
  // not know.
  //
  // `--SEP TRAIL: x` is left out for the mirror-image reason. RFC 822's
  // `field-name` is "1*<any CHAR, excluding CTLs, SPACE, and ":">", so that
  // line is refused by the field-name rule and would pin nothing either.
  // `a_boundary_line_in_a_header_block_is_still_a_boundary_line` carries this
  // region's own differential, one byte short of the boundary in four ways.
  for header in [&b"--SEPARATOR: x"[..], b"--SEP--JUNK: x"] {
    let mut buf = [0u8; 160];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: bytes 0-1/2\r\n",
        header,
        b"\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{header:?} in a part's header block"
    );
  }

  // The differential for the content loop: thirteen bytes again and the same
  // `Content-Range`, one byte short of the dash-boundary at the front. So what
  // that loop pins is the prefix and not the hyphens, and the width the loop
  // could not reach is reached here and agrees.
  let near = b"--SEP\r\nContent-Range: bytes 0-18/20\r\n\r\nab\r\n-SEPARATOR-\r\ncd\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", near).unwrap();
  assert_eq!(
    reader.next().unwrap().unwrap().content(),
    b"ab\r\n-SEPARATOR-\r\ncd"
  );
  assert!(reader.next().unwrap().is_none());
}

// RFC 2046 §5.1.1 spells what may stand on a boundary delimiter line behind the
// boundary, and it is one production in both of the line's forms:
//
//   delimiter         := CRLF dash-boundary
//   close-delimiter   := delimiter "--"
//   transport-padding := *LWSP-char
//   encapsulation     := delimiter transport-padding CRLF body-part
//   multipart-body    := [preamble CRLF] dash-boundary transport-padding CRLF
//                        body-part *encapsulation close-delimiter
//                        transport-padding [CRLF epilogue]
//
// `*LWSP-char` before an ordinary delimiter's CRLF, and `*LWSP-char` after a
// close-delimiter before the `[CRLF epilogue]` that is optional. RFC 822 §3.3
// makes that alphabet two bytes: `LWSP-char = SPACE / HTAB`.
//
// The close-delimiter half. Reading the line to its hyphens alone ends a body
// on `--SEP--JUNK` exactly as on `--SEP--`: `Ok(None)`, the same answer a clean
// close gets, with `JUNK` dropped in silence. A body whose TERMINATION the
// grammar refuses comes back as one that ended where it said it would — the
// same shape as a body with no part at all answering `Ok(None)`.
#[test]
fn a_body_that_ends_wrongly_has_not_ended_well() {
  // The verified input: one part, then a close-delimiter with a tail no reading
  // of `transport-padding` or `[CRLF epilogue]` admits. Without the tail rule it
  // answers `Ok(Some("a"))` and then `Ok(None)` — the second of those being the
  // answer a body that ended where it said it would gets.
  //
  // The fault now arrives on the FIRST call, not the second, and that is the
  // reader's existing shape rather than a new one: the line refused here is
  // the line that ENDS the part, and `next` has always found that line before
  // handing the part over. A body with no close-delimiter at all
  // (`a_body_that_ends_before_its_close_delimiter_is_refused`) has always
  // faulted on the first call for the same reason. What changed is what counts
  // as having found it.
  let junk = b"--SEP\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--SEP--JUNK\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", junk).unwrap();
  assert!(
    matches!(reader.next(), Err(RangeError::MalformedMultipart)),
    "and NOT a part followed by Ok(None)"
  );
  // The cursor did not move, so the fault is re-reported rather than becoming
  // a clean close on the call after it.
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));

  // `transport-padding` then the end of the body: `[CRLF epilogue]` is
  // bracketed, so a close-delimiter is entitled to be the last thing in the
  // body, with or without white space a gateway added behind it.
  for tail in [&b""[..], b" ", b"\t", b" \t \t"] {
    let mut buf = [0u8; 96];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--SEP--",
        tail,
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert_eq!(reader.next().unwrap().unwrap().content(), b"a");
    assert!(reader.next().unwrap().is_none(), "{tail:?}");
  }

  // And `transport-padding` then the CRLF that opens an epilogue, whose
  // content is nobody's business here — §5.1.1: "implementations must ignore
  // anything that appears before the first boundary delimiter line or after
  // the last one." So the bytes that are refused above are read past without
  // a glance when a CRLF stands in front of them.
  for tail in [
    &b"\r\n"[..],
    b"\r\nJUNK",
    b"  \r\nJUNK\r\nmore\r\n",
    b"\t\r\n--SEP--\r\n",
  ] {
    let mut buf = [0u8; 96];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--SEP--",
        tail,
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert_eq!(reader.next().unwrap().unwrap().content(), b"a");
    assert!(reader.next().unwrap().is_none(), "{tail:?}");
  }

  // A tail that is neither: not the padding's alphabet, and not a CRLF that
  // would make an epilogue of it. A lone CR is in the list because it is the
  // near miss of the CRLF — `epilogue := discard-text` is built out of `text`,
  // which RFC 822 §3.3 defines as any CHAR "excluding CR", so a CR that no LF
  // follows opens nothing.
  for tail in [
    &b"JUNK"[..],
    b"-",
    b"\r",
    b" JUNK\r\n",
    b"\rJUNK\r\n",
    b"\nJUNK\r\n",
    b"--\r\n",
  ] {
    let mut buf = [0u8; 96];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--SEP--",
        tail,
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{tail:?}"
    );
  }

  // The ORDINARY delimiter is the same sentence one production over, and it has
  // the same hole: skipping from the end of the boundary to wherever the line's
  // CRLF is. §5.1.1's prose says it a second time — "The
  // boundary may be followed by zero or more characters of linear whitespace.
  // It is then terminated by either another CRLF and the header fields for the
  // next part, or by two CRLFs, in which case there are no header fields for
  // the next part."
  for tail in [
    &b"JUNK"[..],
    b"-",
    b" JUNK",
    b"\tJUNK",
    b"J UNK",
    b"\t\t\tx",
  ] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP",
        tail,
        b"\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{tail:?}"
    );
  }

  // The differential for that loop: the identical body with a tail the
  // production DOES admit is read, so what the loop pins is the alphabet and
  // not the mere presence of bytes after the boundary.
  for tail in [&b""[..], b" ", b"\t", b" \t \t"] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP",
        tail,
        b"\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert_eq!(reader.next().unwrap().unwrap().content(), b"a", "{tail:?}");
    assert!(reader.next().unwrap().is_none(), "{tail:?}");
  }

  // The delimiter that ENDS a part goes through the same reading, which is
  // what makes this one rule rather than two: a part is not handed back framed
  // by a line the grammar refuses, and only then faulted on. Here the fault is
  // on the FIRST call, because the line carrying it is the one that ends the
  // first part.
  let mid = b"--SEP\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--SEP JUNK\r\n\
              Content-Range: bytes 1-1/2\r\n\r\nb\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", mid).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));
}

// The census that came with the fix above found one more exit reporting success
// over input RFC 2046 refuses, and it is the same sentence in the other half of
// the same production. §5.1.1 writes it under `body-part`:
//
//   body-part := MIME-part-headers [CRLF *OCTET]
//                ; Lines in a body-part must not start
//                ; with the specified dash-boundary and
//                ; the delimiter must not appear anywhere
//                ; in the body part.
//
// `MIME-part-headers` is the first half of that production, and the reader
// looked for boundary lines only in the second. RFC 822's `field-name` is
// "1*<any CHAR, excluding CTLs, SPACE, and ":">", which `--SEP` satisfies — so
// `--SEP: x` was a well-formed field line, walked past under §5.1's "All other
// header fields may be ignored in body parts", and the part behind it was
// reported as ordinary input.
#[test]
fn a_boundary_line_in_a_header_block_is_still_a_boundary_line() {
  // The verified inputs, both of which used to come back as a part.
  for header in [
    &b"--SEP: x"[..],
    b"--SEP--: x",
    b"--SEPARATOR: x",
    b"--SEP",
    b"--SEP--",
  ] {
    let mut buf = [0u8; 160];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: bytes 0-1/2\r\n",
        header,
        b"\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{header:?}"
    );
  }

  // The differential: the same field line one byte short of the boundary is a
  // field this reader ignores, exactly as §5.1 says it may. So what the loop
  // above pins is the dash-boundary and not the two hyphens, nor the colon.
  for header in [&b"--SE: x"[..], b"--: x", b"-SEP: x", b"X-SEP: x"] {
    let mut buf = [0u8; 160];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: bytes 0-1/2\r\n",
        header,
        b"\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert_eq!(
      reader
        .next()
        .unwrap()
        .expect("a field this reader ignores")
        .content(),
      b"ab",
      "{header:?}"
    );
  }

  // Such a line is refused rather than read as the delimiter it resembles, and
  // the grammar rather than convenience is why: each field of
  // `MIME-part-headers` carries its own CRLF, and `delimiter := CRLF
  // dash-boundary` needs one more in front of the hyphens. A body that spells
  // a delimiter with no blank line before it therefore has no CRLF left to
  // build one out of — it was refused before this rule existed and is refused
  // now, and the answer would be wrong if the rule had been written as "end
  // the header block here".
  let no_blank_line = b"--SEP\r\nContent-Range: bytes */25\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", no_blank_line).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));

  // With the blank line, the same part IS read: `[CRLF *OCTET]` is absent, the
  // blank line's CRLF is the close-delimiter's own, and the part encloses
  // nothing. That is the shape this refusal must not have taken away.
  let with_blank_line = b"--SEP\r\nContent-Range: bytes */25\r\n\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", with_blank_line).unwrap();
  let part = reader.next().unwrap().expect("a part enclosing nothing");
  assert_eq!(part.content(), b"");
  assert!(part.content_range().is_unsatisfied());
  assert!(reader.next().unwrap().is_none());
}

// §14.6's own example uses a non-bytes unit whose positions are not `1*DIGIT`.
// The reader reports it as an opaque span rather than refusing the message.
#[test]
fn a_non_bytes_part_is_an_opaque_span() {
  let body = b"--SEP\r\nContent-Range: exampleunit 1.2-4.3/25\r\n\r\nxx\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(
    part.content_range().other_range_resp(),
    Some(&b"1.2-4.3/25"[..])
  );
  assert_eq!(part.content(), b"xx");
}

// §15.3.7.2 makes the per-part Content-Range a MUST on the sender, so its
// absence is a parse error rather than a `None`.
#[test]
fn a_part_without_a_content_range_is_a_parse_error() {
  let body = b"--SEP\r\nContent-Type: text/plain\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert!(reader.next().is_err());
}

#[test]
fn the_boundary_is_validated_at_construction() {
  assert!(multipart::ByteRangesReader::new(b"", BODY).is_err());
  assert!(multipart::ByteRangesReader::new(&[b'a'; 71], BODY).is_err());
  assert!(multipart::ByteRangesReader::new(b"a ", BODY).is_err());
}

// The decision the writer left this reader, pinned on both sides. RFC 9110
// §15.3.7.2's "the server MUST generate a Content-Range header field
// corresponding to the range being enclosed in that body part" is addressed to
// the SENDER, so the writer
// refuses `bytes */1234` and the reader reports it: refusing here would discard
// every other part over a fault local to one, and would be inventing a
// recipient behaviour §15.3.7.2 does not state.
#[test]
fn a_part_whose_range_encloses_nothing_is_reported_not_refused() {
  let body = b"--SEP\r\nContent-Range: bytes */1234\r\n\r\nx\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().unwrap();

  // And it is handed over as a value no caller can mistake for a range.
  assert!(part.content_range().is_unsatisfied());
  assert_eq!(part.content_range().incl_range(), None);
  assert_eq!(part.content_range().complete_length(), Some(1234));
  assert_eq!(part.content(), b"x");

  // The asymmetry is deliberate: what this reads back, that writer will not
  // write.
  let mut out = [0u8; 64];
  assert!(matches!(
    multipart::encode_part_header(
      part.content_range(),
      None,
      multipart::PartEncoding::Absent,
      b"SEP",
      &mut out
    ),
    Err(RangeError::UnsatisfiedPartRange)
  ));
}

// RFC 9110 §15.3.7.2's correspondence, read from the side that can check it:
// "the server MUST generate a Content-Range header field corresponding to the
// range being enclosed in that body part". Under §14.1.2's unit an `incl-range`
// from `first-pos` to `last-pos` encloses `last - first + 1` octets, and the
// delimiter that ends the part has already said how many there are. A reader
// that parses both and never relates them hands back a part whose two halves
// state different widths.
#[test]
fn a_parts_content_must_be_the_width_its_content_range_encloses() {
  // Ten positions, ten octets.
  let exact = b"--SEP\r\nContent-Range: bytes 0-9/10\r\n\r\nabcdefghij\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", exact).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"abcdefghij");

  for wrong in [
    // Too few — the verified report's own case.
    &b"--SEP\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n"[..],
    // Too many, which is the same fault and not a truncation.
    b"--SEP\r\nContent-Range: bytes 0-9/10\r\n\r\nabcdefghijk\r\n--SEP--\r\n",
    // And none at all: no `incl-range` encloses zero octets, since `0-0`
    // encloses one.
    b"--SEP\r\nContent-Range: bytes 0-0/1\r\n\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", wrong).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::PartRangeMismatch)),
      "{wrong:?} states two widths"
    );
    assert!(
      matches!(reader.next(), Err(RangeError::PartRangeMismatch)),
      "and the cursor did not move, so the second call reports the same fault"
    );
  }

  // The refusal is by the WIDTH and not by the positions: the same content
  // under a range that starts elsewhere in the representation is fine.
  let elsewhere = b"--SEP\r\nContent-Range: bytes 90-99/100\r\n\r\nabcdefghij\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", elsewhere).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"abcdefghij");
}

// The two shapes the width rule does not reach, and one reason for both: there
// is no `incl-range` to take a width from, which is what
// `ContentRange::incl_range` returning `None` says. Asserted as its own test
// rather than left to the opaque-span tests above, because those would pass
// whether the exemption was reasoned or accidental.
#[test]
fn the_width_rule_reaches_only_an_incl_range() {
  // §14.4's `unsatisfied-range` encloses no range at all, and this reader
  // reports it rather than refusing it — see
  // `a_part_whose_range_encloses_nothing_is_reported_not_refused`.
  let unsatisfied = b"--SEP\r\nContent-Range: bytes */1234\r\n\r\nx\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", unsatisfied).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), None);
  assert_eq!(part.content(), b"x");

  // And a unit whose positions §14.1.1 leaves to that unit: `1.2-4.3` names a
  // width only `exampleunit` can compute, so this crate computes none.
  let other = b"--SEP\r\nContent-Range: exampleunit 1.2-4.3/25\r\n\r\nxx\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", other).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), None);
  assert_eq!(part.content(), b"xx");
}

// RFC 2046 §5.1.1's `multipart-body` puts `body-part` between the opening
// `dash-boundary` and the `close-delimiter` with no brackets around it, and
// RFC 9110 §14.6 says the same in prose: the media type "includes one or more
// body parts, each with its own Content-Type and Content-Range fields". A body
// whose first delimiter line is already the close-delimiter has none — and used
// to answer `Ok(None)`, exactly as a body whose parts had all been read, which
// left a truncated 206 indistinguishable from a complete one.
#[test]
fn a_close_delimiter_before_any_part_is_not_a_whole_body() {
  for empty in [
    &b"--SEP--\r\n"[..],
    b"This is a preamble. It is to be ignored.\r\n--SEP--\r\n",
    // §14.6's first implementation note is that "Additional CRLFs might precede
    // the first boundary string in the body"; an empty preamble is still no
    // body part.
    b"\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", empty).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{empty:?} carries no body part"
    );
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "and the cursor did not move, so the second call reports the same fault"
    );
  }

  // The distinction that answer restores: the same close-delimiter AFTER a part
  // is `Ok(None)`, the body having ended where it said it would.
  let whole = b"--SEP\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", whole).unwrap();
  assert!(reader.next().unwrap().is_some());
  assert!(reader.next().unwrap().is_none());
  assert!(reader.next().unwrap().is_none(), "and stays ended");
}

// `Ok(None)` means the close-delimiter was read. A body that merely runs out is
// a different fact about the message and gets a different answer.
#[test]
fn a_body_that_ends_before_its_close_delimiter_is_refused() {
  for truncated in [
    &b"--SEP\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n"[..], // no close-delimiter
    b"--SEP\r\nContent-Range: bytes 0-1/2\r\n",                // no empty line
    b"This is a preamble with no boundary after it\r\n",       // no delimiter at all
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", truncated).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{truncated:?} is not a whole multipart body"
    );
  }
}

// The cursor moves only on `Ok(Some)`, so a second call reports the same fault
// over the same bytes rather than a different one further in. The third part is
// what makes that testable: it fails for a DIFFERENT reason, so a cursor that
// advanced past the second would answer `MalformedContentRange` here.
#[test]
fn an_error_leaves_the_cursor_where_it_was() {
  let body = b"--SEP\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n\
               --SEP\r\nContent-Type: text/plain\r\n\r\ncd\r\n\
               --SEP\r\nContent-Range: nonsense\r\n\r\nef\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"ab");

  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));
  assert!(
    matches!(reader.next(), Err(RangeError::MalformedMultipart)),
    "the same fault again, not the next part's"
  );
}

// RFC 9110 §5.3: "a sender MUST NOT generate multiple field lines with the same
// name in a message (whether in the headers or trailers) or append a field line when a
// field line of the same name already exists in the message, unless that
// field's definition allows multiple field line values to be recombined as a
// comma-separated list". Neither of these two fields does, and §8.3's reason
// for refusing rather than choosing is that the choice is what diverges.
#[test]
fn a_repeated_singleton_field_in_a_part_is_refused() {
  for repeated in [
    &b"--SEP\r\nContent-Range: bytes 0-1/2\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n"[..],
    b"--SEP\r\nContent-Type: text/plain\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", repeated).unwrap();
    assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));
  }
}

// A `Content-Type` this crate cannot read is a field it recognises and cannot
// use, which is not the same as one it was told to ignore: reporting `None`
// would say the part carried no type when it carried one.
#[test]
fn a_part_content_type_that_is_not_a_media_type_is_refused() {
  // The same body with a readable type, so the refusal below is the field's.
  let good =
    b"--SEP\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", good).unwrap();
  assert!(reader.next().unwrap().unwrap().content_type().is_some());

  // §8.3 makes `Content-Type` a singleton, so a list is a malformed field.
  let listed = b"--SEP\r\nContent-Type: text/plain, text/html\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", listed).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));
}

// One structural thing, found three separate ways: a MIME part header is not an
// HTTP field line, and handing the whole value to the HTTP parser keeps
// producing defects. The fold is one, the transfer-encoding comments another,
// this the third.
//
// RFC 2045 §1: "all of these header fields except for Content-Disposition can
// include RFC 822 comments, which have no semantic content and should be
// ignored during MIME processing." §5.1 prints the case and calls the two
// spellings equivalent:
//
//     Content-type: text/plain; charset=us-ascii (Plain text)
//     Content-type: text/plain; charset="us-ascii"
//
// `media_type` is RFC 9110's parser and stays strict, because §8.3.1's
// `media-type` has no comment production and a trailing `(Plain text)` in an
// HTTP field section IS part of the value. The comment comes off in the MIME
// context, ahead of the delegation.
#[test]
fn a_part_content_type_may_carry_rfc_822_comments() {
  // The verified input: §5.1's own printed example, which a §8.3.1 parser
  // refuses.
  let commented = b"--SEP\r\nContent-Type: text/plain; charset=us-ascii (Plain text)\r\n\
                    Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", commented).unwrap();
  let part = reader.next().unwrap().expect("§5.1's own printed example");
  let ct = part.content_type().expect("a media type");
  assert_eq!((ct.ty(), ct.subtype()), ("text", "plain"));
  let (name, value) = ct.params().next().expect("one").expect("well formed");
  assert_eq!(name, b"charset");
  assert!(same_param(value, ParamValue::Token(b"us-ascii")));

  // And §5.1's other spelling of the same value, so the equivalence the RFC
  // asserts is what this measures rather than one half of it.
  let quoted = b"--SEP\r\nContent-Type: text/plain; charset=\"us-ascii\"\r\n\
                 Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", quoted).unwrap();
  let part = reader.next().unwrap().expect("a part");
  let ct = part.content_type().expect("a media type");
  let (name, value) = ct.params().next().expect("one").expect("well formed");
  assert_eq!(name, b"charset");
  assert!(same_param(value, ParamValue::Quoted(b"us-ascii")));

  // Leading, trailing, both, abutting, nested, and a `)` behind a quoted-pair —
  // every one a comment this reader shortens the borrow past.
  for outside in [
    &b"(Plain text) text/plain"[..],
    b"text/plain (Plain text)",
    b"(a) text/plain (b)",
    b"text/plain(Plain text)",
    b"text/plain (outer (inner) still outer)",
    b"text/plain (a \\) still the comment)",
    b"  \t text/plain \t ",
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        outside,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader
      .next()
      .unwrap_or_else(|_| panic!("{outside:?}"))
      .expect("a part");
    let ct = part.content_type().expect("a media type");
    assert_eq!((ct.ty(), ct.subtype()), ("text", "plain"), "{outside:?}");
  }

  // A `(` inside a quoted-string is text, not a comment: reading it as one
  // would walk off looking for a `)` and refuse a conforming value.
  let in_quotes = b"--SEP\r\nContent-Type: text/plain; charset=\"a(b\"\r\n\
                    Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", in_quotes).unwrap();
  let part = reader.next().unwrap().expect("a part");
  let ct = part.content_type().expect("a media type");
  let (name, value) = ct.params().next().expect("one").expect("well formed");
  assert_eq!(name, b"charset");
  assert!(same_param(value, ParamValue::Quoted(b"a(b")));

  // **An INTERIOR comment is not `PartValueNotContiguous`, and this block must
  // not assert that it is.** That answer is true of a PARSER and not of the
  // construct: strip the comments so that RFC 9110 §8.3.1's parser can read
  // what is left, and one between two of the value's lexical tokens leaves two
  // spans with nowhere to join them. RFC 5322 §3.2.2 says where a comment sits —
  // "Runs of FWS, comment, or CFWS that occur between lexical tokens in a
  // structured header field are semantically interpreted as a single space
  // character" — so every token on either side of one is contiguous and there is
  // nothing to join. Reading them in place is what `mime_content_type` does.
  for interior in [
    &b"text/plain; (c) charset=us-ascii"[..],
    b"text (c) /plain",
    b"text/plain;charset=(c)us-ascii",
    b"text/plain; charset=us-ascii (c) ; lang=en",
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        interior,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader
      .next()
      .unwrap_or_else(|e| panic!("{interior:?}: {e:?}"))
      .expect("a part");
    let ct = part.content_type().expect("a media type");
    assert_eq!((ct.ty(), ct.subtype()), ("text", "plain"), "{interior:?}");
  }

  // A comment that appears to split a single TOKEN is not a comment position at
  // all, and now gets the verdict rather than the limit: RFC 5322 §3.2.3 spells
  // `atom = [CFWS] 1*atext [CFWS]`, which puts the comment outside the token and
  // never inside it. Telling this apart from the block above took a lexer of the
  // destination grammar, which is what the round that reported both as the limit
  // did not have.
  for split_token in [
    &b"text/plain;charset=a(c)b"[..],
    b"te(c)xt/plain",
    b"text/pl(c)ain",
    b"text/plain;char(c)set=a",
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        split_token,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{split_token:?}"
    );
  }

  // A comment or a quoted-string the value ends inside of is not RFC 822 syntax
  // at all, so it keeps the fault word rather than borrowing the limit's.
  for malformed in [
    &b"text/plain (never closed"[..],
    b"text/plain; charset=\"never closed",
    // Nothing but a comment: no media type is left, and `media_type` is what
    // says so rather than the walk that removed it.
    b"(only a comment)",
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        malformed,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{malformed:?}"
    );
  }

  // The HTTP parser was NOT narrowed: the same value in an HTTP field section
  // still reads the comment as part of the parameter, which is what §8.3.1's
  // grammar says it is. The MIME context is the whole of what differs.
  assert_eq!(
    crate::media::media_type(b"text/plain; charset=us-ascii (Plain text)").unwrap_err(),
    crate::media::MediaError::Parameters(crate::grammar::ListError::NotAToken),
    "media_type must not have learned about comments: in an HTTP field section \
     `us-ascii (Plain text)` is one parameter value, and it is not a token"
  );

  // And `Content-Range` is untouched, because RFC 2045 §1's allowance is for
  // the fields THAT document defines. §14.4's is RFC 9110's, and its grammar
  // has no comment in it.
  let ranged = b"--SEP\r\nContent-Range: bytes 0-1/2 (the first two)\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", ranged).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::MalformedContentRange)
  ));
}

// The fourth defect on one line, and the one that ends the class: handing a
// body part's `Content-Type` to RFC 9110 §8.3.1's parser after a comment-strip
// reads it in a grammar that is not the grammar of the place that field is.
// RFC 9110 §14.6 frames the body by RFC 2046, RFC 2046 §5.1 gives a part its
// own header fields, and RFC 2045 §5.1 gives that field its own grammar.
// Narrowing the VALUE before delegating answers one construct at a time; only
// ending the delegation answers all of them.
//
// Both verified inputs are conforming MIME a narrowing parser refuses, and both
// converses are non-conforming MIME it accepts. Each row asserts
// the MIME side here AND the HTTP side through `media_type`, because the point
// is not that one parser got wider — it is that there are two grammars and each
// is right where it is.
#[test]
fn a_part_content_type_is_read_in_mimes_grammar_and_not_in_https() {
  // What MIME accepts and HTTP does not.
  //
  // RFC 5322 §3.2.2: "Runs of FWS, comment, or CFWS that occur between lexical
  // tokens in a structured header field are semantically interpreted as a single
  // space character." So white space and comments may surround every symbol —
  // the `/`, the `;`, the `=` — and RFC 2045 §5.1 is what makes those three
  // symbols rather than token bytes: "Note that the definition of "tspecials" is
  // the same as the RFC 822 definition of "specials" with the addition of the
  // three characters "/", "?", and "=", and the removal of "."."
  for (value, want) in [
    // The first verified input.
    (&b"text / plain"[..], ("text", "plain", None)),
    // The second, with its parameter.
    (
      b"text/plain; charset = us-ascii",
      (
        "text",
        "plain",
        Some((&b"charset"[..], ParamValue::Token(b"us-ascii"))),
      ),
    ),
    // Every symbol at once, white space and comments together.
    (
      b" (a) text (b) / (c) plain (d) ; (e) charset (f) = (g) us-ascii (h) ",
      (
        "text",
        "plain",
        Some((&b"charset"[..], ParamValue::Token(b"us-ascii"))),
      ),
    ),
    // A quoted value with the same white space around its `=`. §5.1: "Note that
    // the value of a quoted string parameter does not include the quotes."
    (
      b"text/plain ;\tcharset\t=\t\"us-ascii\"",
      (
        "text",
        "plain",
        Some((&b"charset"[..], ParamValue::Quoted(b"us-ascii"))),
      ),
    ),
    // The two `token` alphabets, which differ INSIDE a lexical token rather
    // than between two of them: RFC 2045 §5.1's `tspecials` does not hold `{`
    // or `}` and RFC 9110 §5.6.2's `tchar` does not admit either.
    (b"application/x-{foo}", ("application", "x-{foo}", None)),
    (
      b"text/plain;charset={utf-8}",
      (
        "text",
        "plain",
        Some((&b"charset"[..], ParamValue::Token(b"{utf-8}"))),
      ),
    ),
  ] {
    let mut buf = [0u8; 256];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        value,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader
      .next()
      .unwrap_or_else(|e| panic!("{value:?}: {e:?}"))
      .expect("a part");
    let ct = part.content_type().expect("a media type");
    let (ty, subtype, param) = want;
    assert_eq!((ct.ty(), ct.subtype()), (ty, subtype), "{value:?}");
    let got = ct.params().next().transpose().expect("well formed");
    assert!(
      match (got, param) {
        (None, None) => true,
        (Some((got_name, got_value)), Some((want_name, want_value))) =>
          got_name == want_name && same_param(got_value, want_value),
        _ => false,
      },
      "{value:?}"
    );

    // And the HTTP parser did NOT learn any of it. Every one of these is a
    // value §8.3.1 is right to refuse in a field section, which is why the
    // difference is a second parser rather than a widened one.
    assert!(
      crate::media::media_type(value).is_err(),
      "{value:?} must stay outside RFC 9110 §8.3.1's media-type"
    );
  }

  // What HTTP accepts and MIME does not: the empty parameter element. §5.6.6
  // spells `parameters = *( OWS ";" OWS [ parameter ] )` with the parameter
  // BRACKETED; RFC 2045 §5.1's `*(";" parameter)` brackets nothing, so a `;`
  // with no parameter behind it is not that grammar. A §5.6.6 reader accepts
  // it, being HTTP's.
  for value in [
    &b"text/plain;"[..],
    b"text/plain;;charset=utf-8",
    b"text/plain; ; charset=utf-8",
    b"text/plain;charset=utf-8;",
    b"text/plain; (c) ",
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        value,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{value:?}"
    );
  }
  // The same value in an HTTP field section is a media type with no parameters,
  // and stays one.
  let http = crate::media::media_type(b"text/plain;").expect("§5.6.6 brackets its parameter");
  assert_eq!((http.ty(), http.subtype()), ("text", "plain"));
  assert_eq!(http.params().count(), 0);

  // §5.1's other requirements, each its own refusal here and each a value
  // §8.3.1 also refuses — the two grammars agree about all of these.
  //
  // "Note also that a subtype specification is MANDATORY -- it may not be
  // omitted from a Content-Type header field.  As such, there are no default
  // subtypes."
  for malformed in [
    &b"text"[..],
    b"text/",
    b"/plain",
    b"text//plain",
    b"text/plain/html",
    // `parameter := attribute "=" value` has no alternative without the `=`.
    b"text/plain;charset",
    b"text/plain;charset=",
    b"text/plain;=utf-8",
    // A second token where only a `;` or the end may stand.
    b"text/plain utf-8",
    // A comment or a quoted-string the value ends inside of.
    b"text/plain (never closed",
    b"text/plain;charset=\"never closed",
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        malformed,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{malformed:?}"
    );
  }
}

// The other half of the fix: what a MIME-read value does at the WRITER. RFC 9110
// §8.3.1 prints four equivalent spellings of one media type and calls the tight
// one preferred "for consistency", so re-framing a part normalises the white
// space and drops the comments — the same media type and not the same bytes,
// which `Part::content_type` has said since the round that added comments.
#[test]
fn a_mime_read_content_type_re_frames_through_the_writer() {
  let body = b"--SEP\r\nContent-Type: text (c) / plain ; charset = \"us-ascii\"\r\n\
               Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().expect("a part");
  let mut out = [0u8; 128];
  let n = multipart::encode_part_header(
    part.content_range(),
    part.content_type(),
    part.content_transfer_encoding(),
    b"SEP",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--SEP\r\nContent-Type: text/plain;charset=\"us-ascii\"\r\n\
       Content-Range: bytes 0-1/2\r\n\r\n"[..]
  );

  // And what comes back out of THAT is the same media type again, so the two
  // halves of this module agree about a value that entered through the MIME
  // grammar and left through the writer.
  let mut round = [0u8; 192];
  let framed = joined(&mut round, &[&out[..n], b"ab\r\n--SEP--\r\n"]);
  let mut reader = multipart::ByteRangesReader::new(b"SEP", framed).unwrap();
  let part = reader.next().unwrap().expect("a part");
  let ct = part.content_type().expect("a media type");
  assert_eq!((ct.ty(), ct.subtype()), ("text", "plain"));
  let (name, value) = ct.params().next().expect("one").expect("well formed");
  assert_eq!(name, b"charset");
  assert!(same_param(value, ParamValue::Quoted(b"us-ascii")));

  // A `{` in a token survives the writer too, which is where the two alphabets
  // stop being an abstraction: this header is a legal MIME part header and is
  // not a legal HTTP `Content-Type`, and the writer's destination is the first.
  let body = b"--SEP\r\nContent-Type: application/x-{foo}\r\n\
               Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().expect("a part");
  let n = multipart::encode_part_header(
    part.content_range(),
    part.content_type(),
    part.content_transfer_encoding(),
    b"SEP",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--SEP\r\nContent-Type: application/x-{foo}\r\n\
       Content-Range: bytes 0-1/2\r\n\r\n"[..]
  );
}

// RFC 2045 §6.4, over the PAIR of fields — which is why validating each of them
// on its own reached it in neither direction. "Certain Content-Transfer-Encoding
// values may only be used on certain media types.  In particular, it is
// EXPRESSLY FORBIDDEN to use any encodings other than "7bit", "8bit", or
// "binary" with any composite media type, i.e. one that recursively includes
// other Content-Type fields.  Currently the only composite media types are
// "multipart" and "message"."
//
// §6.4 gives its own reason, and it is about the message rather than about a
// recipient's storage: "Though the prohibition against using
// content-transfer-encodings on composite body data may seem overly
// restrictive, it is necessary to prevent nested encodings, in which data are
// passed through an encoding algorithm multiple times, and must be decoded
// multiple times in order to be properly viewed."
#[test]
fn a_composite_part_may_not_carry_a_nested_encoding() {
  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let mut out = [0u8; 192];

  // The verified input, and the header a pair-blind writer produces. The variant
  // travels with the mechanism, because §6.4's prohibition is about the pair
  // and not about which of the two non-identity classifications the name falls
  // in — `x-anything` is a mechanism this crate cannot name, and it is
  // forbidden on a composite part exactly as `base64` is.
  for (ty, mechanism, encoding) in [
    (
      &b"multipart/mixed"[..],
      &b"base64"[..],
      multipart::PartEncoding::Undecoded(b"base64"),
    ),
    (
      b"multipart/byteranges",
      b"quoted-printable",
      multipart::PartEncoding::Undecoded(b"quoted-printable"),
    ),
    (
      b"message/rfc822",
      b"base64",
      multipart::PartEncoding::Undecoded(b"base64"),
    ),
    (
      b"message/external-body",
      b"x-anything",
      multipart::PartEncoding::Unrecognised(b"x-anything"),
    ),
    // Case is folded on both halves: §5.1 "The type, subtype, and parameter
    // names are not case sensitive", §6.1 "These values are not case sensitive
    // -- Base64 and BASE64 and bAsE64 are all equivalent."
    (
      b"MULTIPART/Mixed",
      b"BASE64",
      multipart::PartEncoding::Undecoded(b"BASE64"),
    ),
  ] {
    let ct = crate::media::media_type(ty).expect("a media type");
    assert_eq!(
      multipart::encode_part_header(&cr, Some(&ct), encoding, b"SEP", &mut out),
      Err(RangeError::CompositePartEncoding),
      "{ty:?} + {mechanism:?}"
    );
    assert_eq!(out, [0u8; 192], "{ty:?}: refused before writing");

    // And the reader refuses the same pair, which is the half that makes this a
    // cross-check rather than one more writer rule.
    let mut buf = [0u8; 256];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        ty,
        b"\r\nContent-Transfer-Encoding: ",
        mechanism,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::CompositePartEncoding)),
      "{ty:?} + {mechanism:?}"
    );
  }

  // The three §6.4 names are permitted on a composite part, so the refusal is
  // about the pair and not about the type: "If an entity is of type "multipart"
  // the Content-Transfer-Encoding is not permitted to have any value other than
  // "7bit", "8bit" or "binary"."
  for mechanism in [&b"7bit"[..], b"8bit", b"binary", b"BINARY"] {
    let ct = crate::media::media_type(b"multipart/mixed").expect("a media type");
    assert!(
      multipart::encode_part_header(
        &cr,
        Some(&ct),
        multipart::PartEncoding::Identity(mechanism),
        b"SEP",
        &mut out
      )
      .is_ok(),
      "{mechanism:?}"
    );
  }
  // As is a composite part with no such field at all — RFC 2045 §6.1 makes an
  // absent field `7bit`.
  let ct = crate::media::media_type(b"multipart/mixed").expect("a media type");
  assert!(
    multipart::encode_part_header(
      &cr,
      Some(&ct),
      multipart::PartEncoding::Absent,
      b"SEP",
      &mut out
    )
    .is_ok()
  );

  // And a part that is NOT composite keeps the report §6.4 does not touch: RFC
  // 2046 §5.1 gives each body part its own encoding, so `text/plain` under
  // `base64` is conformant input, is handed over undecoded, and has the width
  // test skipped rather than being refused.
  let body = b"--SEP\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\
               Content-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().expect("a part");
  assert!(same_spelling(
    part.content_transfer_encoding(),
    multipart::PartEncoding::Undecoded(b"base64")
  ));
  assert_eq!(part.content(), b"YWJj");
  assert_eq!(part.top_level_type(), multipart::TopLevelType::Discrete);

  // A part with a composite type and no `Content-Type` field to say so is not
  // caught, and cannot be: §5.2 makes an absent field `text/plain`, which is
  // not composite.
  let body = b"--SEP\r\nContent-Transfer-Encoding: base64\r\n\
               Content-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert!(reader.next().unwrap().is_some());

  // The `Content-Type` may follow the `Content-Transfer-Encoding`, so the pair
  // is not settled until the empty line that ends the block. Read in that order
  // it must answer the same way.
  let body = b"--SEP\r\nContent-Transfer-Encoding: base64\r\nContent-Type: multipart/mixed\r\n\
               Content-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::CompositePartEncoding)
  ));
}

// §6.4's guard is keyed on a top-level type, and two of RFC 2046's rules are
// keyed on a SUBTYPE — so they sit exactly where that guard cannot see them.
// §5.2.2, of `message/partial`: "the use of a content- transfer-encoding of
// "8bit" or "binary" is explicitly prohibited for MIME entities of type
// "message/partial"." §5.2.3, of `message/external-body`: "MUST have a
// content-transfer-encoding of 7bit (the default)." and, in the same words as
// its sibling, "the use of a content- transfer-encoding of "8bit" or "binary"
// is explicitly prohibited for entities of type "message/external-body"."
// (The space inside "content- transfer-encoding" is RFC 2046's own, kept so
// the quotations can be searched for.)
//
// These are not the composite rule reaching a subtype it missed. §6.4 already
// refuses `base64` on both, because both are `message`. What §5.2.2 and §5.2.3
// take away is two of the three mechanisms §6.4 PERMITS — so the identity
// shortcut at the top of the guard, `if encoding.is_identity() { return false }`,
// was the whole of the hole, and no test on a top-level type could have closed
// it.
#[test]
fn two_message_subtypes_are_seven_bit_only() {
  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let mut out = [0u8; 192];

  // The verified inputs: both subtypes, both prohibited mechanisms, both
  // directions. Case is folded on all three of type, subtype and mechanism —
  // §5.1 "The type, subtype, and parameter names are not case sensitive." and
  // §6.1 "These values are not case sensitive -- Base64 and BASE64 and bAsE64
  // are all equivalent."
  for ty in [
    &b"message/partial"[..],
    b"message/external-body",
    b"MESSAGE/Partial",
    b"Message/External-Body",
  ] {
    for mechanism in [&b"8bit"[..], b"binary", b"8BIT", b"Binary"] {
      let ct = crate::media::media_type(ty).expect("a media type");
      let mut untouched = [0u8; 192];
      assert_eq!(
        multipart::encode_part_header(
          &cr,
          Some(&ct),
          multipart::PartEncoding::Identity(mechanism),
          b"SEP",
          &mut untouched
        ),
        Err(RangeError::NonSevenBitPartEncoding),
        "{ty:?} + {mechanism:?}"
      );
      assert_eq!(untouched, [0u8; 192], "{ty:?}: refused before writing");

      let mut buf = [0u8; 256];
      let body = joined(
        &mut buf,
        &[
          b"--SEP\r\nContent-Type: ",
          ty,
          b"\r\nContent-Transfer-Encoding: ",
          mechanism,
          b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
        ],
      );
      let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
      assert!(
        matches!(reader.next(), Err(RangeError::NonSevenBitPartEncoding)),
        "{ty:?} + {mechanism:?}"
      );
    }

    // And what the two sections DO permit: `7bit`, and the absent field that
    // §6.1 makes the same thing — "This is the default value -- that is,
    // "Content-Transfer-Encoding: 7BIT" is assumed if the
    // Content-Transfer-Encoding header field is not present."
    for mechanism in [&b"7bit"[..], b"7BIT"] {
      let ct = crate::media::media_type(ty).expect("a media type");
      assert!(
        multipart::encode_part_header(
          &cr,
          Some(&ct),
          multipart::PartEncoding::Identity(mechanism),
          b"SEP",
          &mut out
        )
        .is_ok(),
        "{ty:?} + {mechanism:?}"
      );

      let mut buf = [0u8; 256];
      let body = joined(
        &mut buf,
        &[
          b"--SEP\r\nContent-Type: ",
          ty,
          b"\r\nContent-Transfer-Encoding: ",
          mechanism,
          b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
        ],
      );
      let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
      let part = reader.next().unwrap().expect("7bit is what they require");
      assert!(same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Identity(mechanism)
      ));
      assert_eq!(part.content(), b"abc");
    }

    let ct = crate::media::media_type(ty).expect("a media type");
    assert!(
      multipart::encode_part_header(
        &cr,
        Some(&ct),
        multipart::PartEncoding::Absent,
        b"SEP",
        &mut out
      )
      .is_ok(),
      "{ty:?} with no field at all"
    );

    let mut buf = [0u8; 256];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        ty,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("the default is 7bit");
    assert!(same_spelling(
      part.content_transfer_encoding(),
      multipart::PartEncoding::Absent
    ));

    // A mechanism §6.4 forbids on any composite type keeps §6.4's answer, so
    // the newer rule adds cases rather than reclassifying them — and the
    // reason a refusal gives stays the reason the specification gives.
    let ct = crate::media::media_type(ty).expect("a media type");
    assert_eq!(
      multipart::encode_part_header(
        &cr,
        Some(&ct),
        multipart::PartEncoding::Undecoded(b"base64"),
        b"SEP",
        &mut out
      ),
      Err(RangeError::CompositePartEncoding),
      "{ty:?} + base64"
    );

    // An unrecognised mechanism is not 7bit either. §6.4's
    // `application/octet-stream` fallback says how to READ such an entity; it
    // does not make the sender's mechanism the one these two sections require.
    // It reaches §6.4's own refusal first, being a non-identity mechanism on a
    // composite type.
    assert_eq!(
      multipart::encode_part_header(
        &cr,
        Some(&ct),
        multipart::PartEncoding::Unrecognised(b"x-anything"),
        b"SEP",
        &mut out
      ),
      Err(RangeError::CompositePartEncoding),
      "{ty:?} + x-anything"
    );
  }

  // The differential that makes this a rule about two subtypes rather than
  // about `message`: every OTHER subtype of `message` keeps §6.4's three, and
  // `8bit` on one of them is conformant input that is read and written.
  // §5.2.1 says so of `message/rfc822` in as many words — "No encoding other
  // than "7bit", "8bit", or "binary" is permitted for the body of a
  // "message/rfc822" entity." — which is §6.4 restated for that subtype and
  // not a third rule.
  for ty in [
    &b"message/rfc822"[..],
    b"message/news",
    b"multipart/mixed",
    b"multipart/partial",
    b"text/partial",
    b"message/partiality",
    b"message/external-bodyx",
  ] {
    for mechanism in [&b"8bit"[..], b"binary"] {
      let ct = crate::media::media_type(ty).expect("a media type");
      assert!(
        multipart::encode_part_header(
          &cr,
          Some(&ct),
          multipart::PartEncoding::Identity(mechanism),
          b"SEP",
          &mut out
        )
        .is_ok(),
        "{ty:?} + {mechanism:?}"
      );

      let mut buf = [0u8; 256];
      let body = joined(
        &mut buf,
        &[
          b"--SEP\r\nContent-Type: ",
          ty,
          b"\r\nContent-Transfer-Encoding: ",
          mechanism,
          b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
        ],
      );
      let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
      let part = reader.next().unwrap().expect("§6.4's three, unnarrowed");
      assert!(same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Identity(mechanism)
      ));
    }
  }

  // The `Content-Type` may follow the `Content-Transfer-Encoding`, so the pair
  // is not settled until the empty line that ends the block — the same order
  // the composite rule is tested in, because it is the same call site.
  let reordered = b"--SEP\r\nContent-Transfer-Encoding: binary\r\n\
                    Content-Type: message/partial\r\n\
                    Content-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", reordered).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::NonSevenBitPartEncoding)
  ));

  // And a part with no `Content-Type` at all is not caught, for the reason the
  // composite rule is not: RFC 2045 §5.2 gives an absent field the default
  // "Content-type: text/plain; charset=US-ASCII", which is neither of these
  // two subtypes.
  let none = b"--SEP\r\nContent-Transfer-Encoding: binary\r\n\
               Content-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", none).unwrap();
  assert!(reader.next().unwrap().is_some());
}

// RFC 2045 §6.4 states its prohibition over a CLASS — "any composite media
// type, i.e. one that recursively includes other Content-Type fields" — and the
// guard tested two literals, `multipart` and `message`. §5.1 puts
// `extension-token` in BOTH halves of `type := discrete-type / composite-type`,
// so `X-bundle/foo` is a well-formed `discrete-type` and a well-formed
// `composite-type` at once, and it walked past a guard that exists for it.
//
// §6.4's own "Currently the only composite media types are "multipart" and
// "message"" dates itself in its first word and does not narrow the sentence
// before it.
//
// This crate cannot know whether a private top-level type is composite, so it
// does what it does with every other fact it does not hold: carries the third
// state and names the obligation. `TopLevelType::Unknown` is the report;
// refusing instead would refuse every private DISCRETE type under `base64`,
// which is conformant input.
#[test]
fn a_private_top_level_type_may_be_composite_and_this_crate_cannot_say() {
  // The verified input, both directions. `X-bundle/foo` + `base64` is handed
  // over and is written, with the classification saying why.
  let body = b"--SEP\r\nContent-Type: X-bundle/foo\r\nContent-Transfer-Encoding: base64\r\n\
               Content-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader
    .next()
    .unwrap()
    .expect("§6.4's condition is undecidable");
  assert_eq!(
    part.top_level_type(),
    multipart::TopLevelType::Unknown,
    "the fact this crate does not hold, reported rather than guessed"
  );
  assert!(same_spelling(
    part.content_transfer_encoding(),
    multipart::PartEncoding::Undecoded(b"base64")
  ));

  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let mut out = [0u8; 192];
  let ct = crate::media::media_type(b"X-bundle/foo").expect("a media type");
  assert!(
    multipart::encode_part_header(
      &cr,
      Some(&ct),
      multipart::PartEncoding::Undecoded(b"base64"),
      b"SEP",
      &mut out
    )
    .is_ok(),
    "written, with the obligation on the caller who knows what X-bundle is"
  );

  // The classification itself, over §5.1's seven names and then past them. The
  // subtype is never consulted: every subtype of a composite type is composite.
  for (ty, want) in [
    (&b"text/plain"[..], multipart::TopLevelType::Discrete),
    (b"image/png", multipart::TopLevelType::Discrete),
    (b"audio/basic", multipart::TopLevelType::Discrete),
    (b"video/mp4", multipart::TopLevelType::Discrete),
    (b"application/json", multipart::TopLevelType::Discrete),
    (b"multipart/mixed", multipart::TopLevelType::Composite),
    (b"message/rfc822", multipart::TopLevelType::Composite),
    // Case-folded on the type half, §5.1: "The type, subtype, and parameter
    // names are not case sensitive."
    (b"MESSAGE/rfc822", multipart::TopLevelType::Composite),
    (b"Multipart/anything", multipart::TopLevelType::Composite),
    // And the third state, in both of §5.1's `extension-token` shapes: an
    // `x-token`, and a bare token that would be an `ietf-token`.
    (b"X-bundle/foo", multipart::TopLevelType::Unknown),
    (b"x-bundle/foo", multipart::TopLevelType::Unknown),
    (b"example/foo", multipart::TopLevelType::Unknown),
    // A near-miss of each literal, so the comparison is the whole name.
    (b"texts/plain", multipart::TopLevelType::Unknown),
    (b"multiparty/mixed", multipart::TopLevelType::Unknown),
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        ty,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("a part");
    assert_eq!(part.top_level_type(), want, "{ty:?}");
  }

  // A part with NO `Content-Type` is `Discrete` and not `Unknown`: §5.2 gives
  // an absent field the default "Content-type: text/plain; charset=US-ASCII",
  // which is a type this crate knows.
  let none = b"--SEP\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", none).unwrap();
  let part = reader.next().unwrap().expect("a part");
  assert_eq!(part.top_level_type(), multipart::TopLevelType::Discrete);
  assert!(part.content_type().is_none());

  // And the two names §6.4 does decide are still refused, which is what keeps
  // the third state from having widened the guard rather than completed it.
  let forbidden =
    b"--SEP\r\nContent-Type: multipart/mixed\r\nContent-Transfer-Encoding: base64\r\n\
                    Content-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", forbidden).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::CompositePartEncoding)
  ));
}

// The unsatisfied form crosses the reader/writer asymmetry unchanged, and the
// asymmetry is `Part::content_range`'s: §15.3.7.2 binds the SENDER, so the
// writer refuses a part that encloses nothing while the reader hands one over
// as a value the caller cannot mistake for a range. Now that the refusal covers
// every unit, so does the report.
#[test]
fn the_reader_still_reports_the_unsatisfied_form_the_writer_refuses() {
  for unsatisfied in [&b"bytes */25"[..], b"exampleunit */25"] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Range: ",
        unsatisfied,
        b"\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader
      .next()
      .unwrap_or_else(|e| panic!("{unsatisfied:?}: {e:?}"))
      .expect("a part");
    let cr = part.content_range();
    assert!(cr.is_unsatisfied(), "{unsatisfied:?}");
    assert!(
      cr.incl_range().is_none(),
      "{unsatisfied:?}: it names no positions, so the width test does not run"
    );
    assert_eq!(part.content(), b"ab", "{unsatisfied:?}");

    // And handing that same value straight back to this crate's writer is the
    // refusal, which is the asymmetry stated as a round trip.
    let mut out = [0u8; 128];
    assert_eq!(
      multipart::encode_part_header(cr, None, multipart::PartEncoding::Absent, b"SEP", &mut out),
      Err(RangeError::UnsatisfiedPartRange),
      "{unsatisfied:?}"
    );
  }
}

// The one construct RFC 2046 admits that this refuses: an RFC 822 folded field.
// Skipping the continuation would report `text/plain` for a value whose second
// line carried its `charset`, and joining it is what a reader handing back
// borrowed slices cannot do.
//
// **The refusal is `PartValueNotContiguous`, not `MalformedMultipart`**, and
// the assertions below are what pin that apart. This body IS a
// `multipart/byteranges` body — the first case unfolds the very same value and
// reads it — so the variant that says it is not one stated something false
// about a conforming message. What is true is this reader's own limit, which
// the crate already names on the field side as
// `media::MediaError::ValueSpansFieldLines`. READING the continuation instead
// needs either caller-supplied scratch storage or a segment-aware `MediaType`
// and `ContentRange` — a redesign of two public types for a construct the
// enclosing protocol deprecates. That is declined; the WORD was what was wrong,
// not the refusal.
#[test]
fn a_folded_recognised_part_header_names_this_readers_own_limit() {
  // Unfolded first, so the refusal below is the CONTINUATION's rather than
  // something the first line was going to fail on anyway.
  let whole = b"--SEP\r\nContent-Type: text/plain;charset=utf-8\r\n\
                Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", whole).unwrap();
  let part = reader.next().unwrap().unwrap();
  let ct = part.content_type().unwrap();
  assert_eq!((ct.ty(), ct.subtype()), ("text", "plain"));

  // The same value, folded — where skipping the continuation would have
  // reported `text/plain` and lost the `charset` the sender wrote.
  let folded = b"--SEP\r\nContent-Type: text/plain\r\n ;charset=utf-8\r\n\
                 Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", folded).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::PartValueNotContiguous)
  ));

  // The input that shows the old word was false:
  // `us-ascii` rather than `utf-8`, so the unfolded value is a media type with
  // nothing about it even arguably unusual. Read whole, it parses; folded, the
  // refusal is about this reader.
  let conforming = b"--SEP\r\nContent-Type: text/plain\r\n ;charset=us-ascii\r\n\
                     Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", conforming).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::PartValueNotContiguous)
  ));
  let unfolded = b"--SEP\r\nContent-Type: text/plain ;charset=us-ascii\r\n\
                   Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", unfolded).unwrap();
  let part = reader.next().unwrap().unwrap();
  let ct = part.content_type().unwrap();
  assert_eq!((ct.ty(), ct.subtype()), ("text", "plain"));

  // A continuation carrying a colon of its own — which is why the leading SP is
  // the test and the missing `:` is not. RFC 2046 §5.2.3 folds a
  // `message/external-body` content type in four of its own examples: one
  // across three lines and three across four. A colon on a continuation is not
  // a shape this test had to invent for the occasion — three of those four end
  // on the continuation `expiration="Fri, 14 Jun 1991 19:13:14 -0400 (EDT)"`,
  // which carries two colons on a line that is not a field line. A reader keyed
  // on the colon reads the second line below as a field line named
  // ` ;URL="ftp`, does not recognise it, and skips it — reporting
  // `message/external-body` with one parameter for a value that carried two.
  let with_colon =
    b"--SEP\r\nContent-Type: message/external-body;access-type=URL\r\n ;URL=\"ftp://x/y\"\r\n\
                     Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", with_colon).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::PartValueNotContiguous)
  ));

  // RFC 9112 §5.2 names both continuation bytes, a space and a horizontal tab,
  // so the same colon-carrying value folded with the HTAB is refused too. Each
  // byte of the test is pinned by a case that carries a colon, which is the
  // only shape the field-line rule would otherwise have let through.
  let with_htab =
    b"--SEP\r\nContent-Type: message/external-body;access-type=URL\r\n\t;URL=\"ftp://x/y\"\r\n\
                    Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", with_htab).unwrap();
  assert!(matches!(
    reader.next(),
    Err(RangeError::PartValueNotContiguous)
  ));
}

// Every value the test above folds is already a value of its own on its first
// line — `text/plain` is a media type before the `;charset=` arrives — so the
// refusal it pins was reachable however early the reading happened. That is
// exactly what the loops below are NOT.
//
// `Content-Type: text/` is no `media-type`. `Content-Range: bytes 0-` is no
// `content-range`. `Content-Transfer-Encoding: x-` is no `mechanism`, §5.1's
// `x-token` having a `token` for its tail and a `token` being `1*<…>`. Read on
// the line each stands on, every one of them fails its own grammar and the
// answer is a verdict about the MESSAGE. Read one line later, the continuation
// beneath says what they really are: a conforming value written across an
// RFC 822 fold, which is this reader's own limit and `PartValueNotContiguous`.
//
// So `PartValueNotContiguous`, which names exactly this input, is unreachable
// for any field read on its own line, and reachable only for one held until the
// following line. All three are held that way, and the two loops below are the
// same six values told apart in both directions.
#[test]
fn a_recognised_value_is_classified_only_once_the_next_line_has_been_read() {
  // Folded, where the line beneath is what says the value continues. Each fold
  // is placed where RFC 9112 §5.2's unfold — "replace each received obs-fold
  // with one or more SP octets prior to interpreting the field value" — leaves
  // a value the destination grammar admits, since the SP the continuation
  // begins with survives the join.
  for folded in [
    &b"--SEP\r\nContent-Range: bytes 0-1/2\r\nContent-Type: text/\r\n plain\r\n\r\nab\r\n--SEP--\r\n"[..],
    b"--SEP\r\nContent-Range: bytes\r\n 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
    b"--SEP\r\nContent-Range: bytes 0-1/2\r\nContent-Transfer-Encoding: x-\r\n token\r\n\r\nab\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", folded).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::PartValueNotContiguous)),
      "{folded:?}"
    );
  }

  // The same three half-values UNFOLDED, where the line beneath is the empty
  // line that ends the block and so says the value was all of it. Each is then
  // a fault about the message, and each keeps the variant its own grammar
  // answers with: `Content-Range` has parse errors of its own that
  // `ByteRangesReader::next` propagates, while a `Content-Type` or a
  // `Content-Transfer-Encoding` this reader cannot read at all is
  // `MalformedMultipart`.
  //
  // The two loops differ on every row, which is what makes the pair a
  // measurement rather than a restatement — and on the third row they differ
  // over bytes that are malformed BOTH ways, since RFC 2045 §6.1's `mechanism`
  // is one token and no fold of a token unfolds back into one. What that row
  // pins is which verdict the reader reaches FIRST, and it must be the fold:
  // the value has two halves and the join is what this reader cannot do,
  // whatever the joined value would have turned out to be.
  for (unfolded, want) in [
    (
      &b"--SEP\r\nContent-Range: bytes 0-1/2\r\nContent-Type: text/\r\n\r\nab\r\n--SEP--\r\n"[..],
      RangeError::MalformedMultipart,
    ),
    (
      b"--SEP\r\nContent-Range: bytes\r\n\r\nab\r\n--SEP--\r\n",
      RangeError::MalformedContentRange,
    ),
    (
      b"--SEP\r\nContent-Range: bytes 0-1/2\r\nContent-Transfer-Encoding: x-\r\n\r\nab\r\n--SEP--\r\n",
      RangeError::MalformedMultipart,
    ),
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", unfolded).unwrap();
    assert_eq!(reader.next().unwrap_err(), want, "{unfolded:?}");
  }

  // And the first two folds are faults only while they are two spans. Joined
  // the way §5.2 prescribes, `text/` + ` plain` is `text/ plain` and `bytes` +
  // ` 0-1/2` is `bytes 0-1/2` — both read here without complaint, the first
  // because RFC 2045 §5.1's field is structured and this crate's MIME parser
  // takes the white space between its lexical tokens, the second because
  // RFC 9110 §14.4 puts an SP in exactly that position. So the refusal above is
  // about the two spans and not about the values, which is the whole of what
  // `PartValueNotContiguous` claims.
  let joined =
    b"--SEP\r\nContent-Range: bytes 0-1/2\r\nContent-Type: text/ plain\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", joined).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), Some((0, 1)));
  let ct = part.content_type().unwrap();
  assert_eq!((ct.ty(), ct.subtype()), ("text", "plain"));
}

// Every sentence of the refusal above turns on the JOIN: the value has two
// halves, a borrowing reader cannot make them one slice, and reporting the
// first half alone reports a value the sender did not write. None of that is
// true of a field nothing here collects. RFC 2046 §5.1 licenses walking past
// one — "All other header fields may be ignored in body parts" — and ignoring
// a field means ignoring both lines of a folded one, so a fold there is skipped
// rather than failing the whole message.
#[test]
fn a_fold_in_a_field_this_reader_ignores_is_skipped() {
  let folded =
    b"--SEP\r\nX-Note: alpha\r\n beta\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", folded).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), Some((0, 2)));
  assert_eq!(part.content(), b"abc");
  assert!(reader.next().unwrap().is_none());

  // The same message with the fold taken out, so the answer above is the
  // CONTINUATION being skipped rather than the body being read some other way.
  let plain = b"--SEP\r\nX-Note: alpha\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", plain).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"abc");

  for ignored in [
    // The HTAB continuation, which RFC 9112 §5.2 names beside the space.
    &b"--SEP\r\nX-Note: alpha\r\n\tbeta\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n"[..],
    // A continuation carrying a colon of its own — the shape a reader keyed on
    // the `:` would read as a field line with an unrecognised name. Skipped
    // here for a different reason: the field above it is ignored.
    b"--SEP\r\nX-Note: a\r\n ;URL=\"ftp://x/y\"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    // Several continuation lines under one ignored field.
    b"--SEP\r\nX-Note: a\r\n b\r\n c\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    // A `Content-` field is not thereby recognised: the reader's own note that
    // a per-part `Content-Length` is read as neither a field nor framing.
    b"--SEP\r\nContent-Length:\r\n 3\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", ignored).unwrap();
    assert_eq!(
      reader.next().unwrap().unwrap().content(),
      b"abc",
      "{ignored:?}"
    );
  }

  // A continuation with NO field line above it is MALFORMED, and it is the one
  // of the three cases that still says so: RFC 822 gives it nothing to
  // continue, so there is no conformant construct here being declined. It used
  // to share the recognised case's answer, and while it did, this assertion
  // could not tell the two apart.
  let first = b"--SEP\r\n alpha\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", first).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));

  // And the recognised half is still refused, which is what makes the skip
  // above a narrowing rather than a removal — under its own name now, because
  // that body IS a multipart body and this reader is the thing that cannot
  // represent it. One case per collected field, each with a first line that
  // parses on its own — otherwise the value's own fault is reported before the
  // continuation is reached, and the case would pass without the fold rule
  // existing at all.
  for recognised in [
    &b"--SEP\r\nContent-Range: bytes 0-2/3\r\n ; extra\r\n\r\nabc\r\n--SEP--\r\n"[..],
    b"--SEP\r\nContent-Type: text/plain\r\n ;charset=utf-8\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    b"--SEP\r\nContent-Transfer-Encoding:\r\n 7bit\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", recognised).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::PartValueNotContiguous)),
      "{recognised:?}"
    );
  }
}

// This records a REFUTED reading whose refutation was WRONG, so that the
// refusal it produced does not get restored.
//
// RFC 2046 §5.1's rule that a body part carries its own encoding — "data
// within the body parts can be encoded on a part-by-part basis, with
// Content-Transfer-Encoding fields for each appropriate body part" — means a
// part's wire length may differ from the length its `Content-Range` encloses,
// so a width test applied unconditionally rejects a conforming 206. The
// counter-argument is RFC 9110 §14.6's registration form, whose encoding
// considerations are only "7bit", "8bit", or "binary", read as though it
// narrowed what a PART may carry. It does not. The very sentence the
// three names come from in RFC 2046 §5.1 says which entity they bind — "no
// encoding other than "7bit", "8bit", or "binary" is permitted for entities of
// type "multipart"" — and then, in the same breath, hands the parts inside it
// the freedom quoted above. The registration form describes the outer
// `multipart/byteranges` entity; each part is a separate entity with its own
// encoding.
//
// So a base64 part is CONFORMANT input. It is accepted, its mechanism is
// visible on the `Part`, and the width test is not applied to it — the wire
// span is four octets for every three the range encloses, and this crate is
// no-alloc and cannot decode. What refusing the part got right is the half
// underneath it: a reader that walks past `Content-Transfer-Encoding` in
// silence reports a base64 spelling as the range's octets through `content()`,
// with nothing saying otherwise.
#[test]
fn a_base64_body_part_is_accepted_with_its_encoding_visible() {
  // `YWJj` is base64 for `abc`: four octets on the wire for the three the range
  // encloses. Under a refusal this is `UnsupportedPartEncoding`; under an
  // unconditional width test, `PartRangeMismatch`. Both are faults invented out
  // of a conforming message.
  let counted =
    b"--SEP\r\nContent-Transfer-Encoding: base64\r\nContent-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", counted).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert!(
    same_spelling(
      part.content_transfer_encoding(),
      multipart::PartEncoding::Undecoded(b"base64")
    ),
    "the mechanism is reported, not refused"
  );
  assert!(!part.content_transfer_encoding().is_identity());
  assert_eq!(
    part.content_transfer_encoding().mechanism(),
    Some(&b"base64"[..])
  );
  assert_eq!(
    part.content(),
    b"YWJj",
    "the wire span, which the caller decodes; this crate has nowhere to put it"
  );
  assert_eq!(
    part.content_range().incl_range(),
    Some((0, 2)),
    "and the range is still the range, four wire octets notwithstanding"
  );
  assert!(reader.next().unwrap().is_none());

  // The same part under a unit this crate does not read, where there was never
  // a width test to fire in the first place.
  let uncounted = b"--SEP\r\nContent-Transfer-Encoding: base64\r\n\
                    Content-Range: exampleunit 1.2-4.3/25\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", uncounted).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content(), b"YWJj");
  assert!(!part.content_transfer_encoding().is_identity());

  // `quoted-printable` is the other mechanism this crate RECOGNISES, and the
  // two of them are the whole of that set; see
  // `only_a_known_mechanism_may_disable_the_width_invariant`.
  let qp = b"--SEP\r\nContent-Transfer-Encoding: quoted-printable\r\n\
             Content-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", qp).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert!(same_spelling(
    part.content_transfer_encoding(),
    multipart::PartEncoding::Undecoded(b"quoted-printable")
  ));
  assert!(!part.is_octet_stream_fallback());

  // `x-uuencode` and `7bits` are reported too, and NOT as the same thing: an
  // `x-token` is a syntax this crate can decide and a name it cannot read, and
  // `7bits` is the near-miss a case-folded comparison against `7bit` must tell
  // apart. Both are mechanisms this crate cannot name, so both carry RFC 2045
  // §6.4's fallback — which is the answer that separates them from the two
  // above. The wrong answers for `7bits` are `Undecoded(b"7bits")` and
  // `MalformedMultipart`, and this pins neither.
  for mechanism in [&b"x-uuencode"[..], b"7bits"] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        mechanism,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().unwrap();
    assert!(
      same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Unrecognised(mechanism)
      ),
      "{mechanism:?}"
    );
    assert!(part.is_octet_stream_fallback(), "{mechanism:?}");
  }

  // The three identity mechanisms come back as such, in whatever case, and an
  // absent field is its own answer rather than a `7bit` this crate invented for
  // a sender that wrote nothing.
  for (body, expected) in [
    (
      &b"--SEP\r\nContent-Transfer-Encoding: 7bit\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n"[..],
      multipart::PartEncoding::Identity(b"7bit"),
    ),
    (
      b"--SEP\r\nContent-Transfer-Encoding: 8bit\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      multipart::PartEncoding::Identity(b"8bit"),
    ),
    (
      b"--SEP\r\nContent-Transfer-Encoding: binary\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      multipart::PartEncoding::Identity(b"binary"),
    ),
    (
      b"--SEP\r\nContent-Transfer-Encoding: 7BIT\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      multipart::PartEncoding::Identity(b"7BIT"),
    ),
    (
      b"--SEP\r\ncontent-transfer-encoding:\tBinary\t\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      multipart::PartEncoding::Identity(b"Binary"),
    ),
    (
      b"--SEP\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      multipart::PartEncoding::Absent,
    ),
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().unwrap();
    assert_eq!(part.content(), b"abc", "{body:?}");
    assert!(
      same_spelling(part.content_transfer_encoding(), expected),
      "{body:?}"
    );
    assert!(part.content_transfer_encoding().is_identity(), "{body:?}");
  }

  // Repeated, it is refused as the other two collected fields are — refusing
  // rather than choosing, since a reader that took the first would read `7bit`
  // out of a part that also said `base64`.
  let repeated =
    b"--SEP\r\nContent-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: base64\r\n\
                   Content-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", repeated).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));
}

// The comparison `PartEncoding` does not derive, written the way its doc
// directs a caller — beside `MediaType`'s and `MediaRange`'s equivalents in
// `media::tests`, and for the same reason.
#[test]
fn one_mechanism_written_two_ways_is_compared_by_its_pieces() {
  // RFC 2045 §6.1: "These values are not case sensitive -- Base64 and BASE64
  // and bAsE64 are all equivalent." Two spellings of one mechanism, which the
  // removed derive called two mechanisms.
  let lower =
    b"--SEP\r\nContent-Transfer-Encoding: base64\r\nContent-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let upper =
    b"--SEP\r\nContent-Transfer-Encoding: BASE64\r\nContent-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let one = multipart::ByteRangesReader::new(b"SEP", lower)
    .unwrap()
    .next()
    .unwrap()
    .expect("a part")
    .content_transfer_encoding();
  let other = multipart::ByteRangesReader::new(b"SEP", upper)
    .unwrap()
    .next()
    .unwrap()
    .expect("a part")
    .content_transfer_encoding();

  // The bytes a derive would compare differ, so this is the case such a derive
  // answers `false` for.
  assert!(!same_spelling(one, other));

  // And the two pieces the type exposes agree, which is the answer §6.1 gives.
  assert_eq!(one.is_identity(), other.is_identity());
  let one = one.mechanism().expect("a mechanism");
  let other = other.mechanism().expect("a mechanism");
  assert!(one.eq_ignore_ascii_case(other));
  assert_ne!(one, other);
}

// The width test is the wire span against the range, so an identity mechanism
// is half its condition — and the OTHER half of the same fact is that a
// non-identity part is not thereby unchecked-in-general, only unchecked HERE.
#[test]
fn the_width_test_runs_only_where_the_wire_octets_are_the_enclosed_octets() {
  // Identical bodies but for the mechanism: three wire octets against a range
  // that encloses four. Under `7bit` that is `PartRangeMismatch`; under
  // `base64` it is a comparison this crate has no business making.
  let identity =
    b"--SEP\r\nContent-Transfer-Encoding: 7bit\r\nContent-Range: bytes 0-3/8\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", identity).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::PartRangeMismatch)));

  let encoded =
    b"--SEP\r\nContent-Transfer-Encoding: base64\r\nContent-Range: bytes 0-3/8\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", encoded).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content(), b"abc");
  assert_eq!(part.content_range().incl_range(), Some((0, 3)));

  // An absent field is the identity answer, so the test still fires: the
  // default RFC 2045 §6.1 supplies is a mechanism, not an absence of one.
  let absent = b"--SEP\r\nContent-Range: bytes 0-3/8\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", absent).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::PartRangeMismatch)));
}

// Joins `pieces` into `out` and hands back what was written.
//
// Spelled out rather than reached for through `format!` or `Vec` because this
// suite runs on the crate's bare tier, where there is no allocator — the same
// constraint the code under test is written to.
fn joined<'b>(out: &'b mut [u8], pieces: &[&[u8]]) -> &'b [u8] {
  let mut at = 0;
  for piece in pieces {
    out[at..at + piece.len()].copy_from_slice(piece);
    at += piece.len();
  }
  &out[..at]
}

// RFC 2045 §6.1 defines `Content-Transfer-Encoding` as a structured field, so
// RFC 822 comments and white space may sit around the mechanism.
// `Content-Transfer-Encoding: 7bit (relay)` is a conforming spelling of `7bit`,
// and a comparison run against the raw value read it as a mechanism it did not
// know. The comment grammar itself is RFC 5322 §3.2.2's.
#[test]
fn rfc_822_comments_around_the_mechanism_are_not_part_of_it() {
  for spelled in [
    &b"7bit (relay)"[..],
    b"(added by a gateway) 7bit",
    b"(a)7bit(b)",
    // The OWS §5.5 keeps out of a field value, which is trimmed before the
    // comment walk ever sees it.
    b"  \t 7bit \t ",
    // Comments nest, and an escaped `)` inside one does not close it.
    b"7bit (outer (inner) still)",
    br"7bit (a \) not the end)",
    // A comment may hold anything ASCII, the empty comment included.
    b"()7bit()",
  ] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        spelled,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().unwrap();
    assert!(
      same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Identity(b"7bit")
      ),
      "{spelled:?}"
    );
  }

  // A comment does not turn a non-identity mechanism into one either: the
  // stripping is of the FIELD, and what is left is still graded.
  let commented = b"--SEP\r\nContent-Transfer-Encoding: (x) base64 (y)\r\n\
                    Content-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", commented).unwrap();
  assert_eq!(
    reader
      .next()
      .unwrap()
      .unwrap()
      .content_transfer_encoding()
      .mechanism(),
    Some(&b"base64"[..])
  );

  // What is NOT one mechanism is a fault about the FIELD, and it gets the
  // answer a `Content-Type` that is not a `media-type` gets. Reporting it as
  // an encoding this crate does not decode would hand a sender an exemption
  // from the width test for a field nobody can read.
  for unreadable in [
    // No mechanism at all, and the same with only a comment in the value.
    &b""[..],
    b"(only a comment)",
    b"   ",
    // Two of them.
    b"7bit 8bit",
    b"7bit (c) base64",
    // A comment that never closes, and a stray close with no opener.
    b"7bit (unterminated",
    b"7bit )",
    // The escape eats the `)`, so this one never closes either.
    br"7bit (a \)",
  ] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        unreadable,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{unreadable:?}"
    );
  }
}

// The comment leniency above became a way PAST the width check the round before
// it added, and this is that hole with a test standing in it.
//
// `one_mechanism` stopped the capture at SP, HTAB or `(` — which finds where a
// token ends and establishes nothing about what came before it. So `7bit)` was
// captured whole, matched none of the three identity names, and was reported as
// `Undecoded`: the classification `ByteRangesReader::next` skips its width test
// for. One unbalanced parenthesis bought a part an exemption from
// §15.3.7.2's correspondence rule.
//
// RFC 2045 §6.1 is what settles it: "The Content-Transfer-Encoding field's
// value is a single token specifying the type of encoding", and §5.1's `token`
// admits no `tspecials`. A capture carrying one is a malformed FIELD, not a
// mechanism this crate declines to decode — and the two answers are not
// interchangeable, because only one of them skips a check.
#[test]
fn a_mechanism_is_a_token_or_the_field_is_malformed() {
  // The verified input, and its differential partner. `bytes 0-9/10` encloses
  // ten octets over content of three; the ONLY difference between the two
  // bodies is the `)`, so the second line is what the first one's refusal is
  // measured against.
  let with_paren = b"--SEP\r\nContent-Transfer-Encoding: 7bit)\r\n\
                     Content-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", with_paren).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));

  let plain = b"--SEP\r\nContent-Transfer-Encoding: 7bit\r\n\
                Content-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", plain).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::PartRangeMismatch)));

  // And the refusal is about the FIELD rather than about the width, which a
  // body whose width agrees is what says: `7bit)` is still malformed with
  // nothing at all for the width test to find fault with.
  let agreeing = b"--SEP\r\nContent-Transfer-Encoding: 7bit)\r\n\
                   Content-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", agreeing).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));

  // Every one of §5.1's fifteen `tspecials` appended to an otherwise identity
  // mechanism, and then three CTLs — so the rule is pinned by the sentence that
  // generates it rather than by the one character the finding happened to use.
  // SPACE is the production's fourth exclusion and is not spelled here: a
  // trailing one is trimmed as OWS before this reader sees the value, and an
  // interior one is `7bit 8bit`'s second-token refusal in the test above.
  for tspecial in *b"()<>@,;:\\\"/[]?=" {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: 7bit",
        &[tspecial],
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{tspecial:?}"
    );
  }
  for ctl in [0x01u8, 0x1f, 0x7f] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: 7bit",
        &[ctl],
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{ctl:?}"
    );
  }

  // The set is RFC 2045's and not RFC 9110 §5.6.2's, and the first case is
  // where the two differ: `{` and `}` are not `tchar`, and are ordinary `token`
  // characters here because `tspecials` does not hold them. The other three
  // bytes are tokens under either grammar and are here so the case is not one
  // byte wide. A mechanism spelled out of any of them is one this crate cannot
  // name — reported as `Unrecognised`, not refused — which is the answer every
  // well-formed unknown token gets.
  for admitted in [&b"x-{weird}"[..], b"x-a|b", b"x-a.b", b"x-a~b"] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        admitted,
        b"\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("a part");
    assert!(
      same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Unrecognised(admitted)
      ),
      "{admitted:?}"
    );
    // And the width test really is skipped for it, which is what makes the
    // refusals above matter: this body's content is three octets under a range
    // enclosing ten, and it comes back rather than failing.
    assert_eq!(part.content(), b"abc");
  }

  // A comment still terminates the token, which is the leniency this fix had to
  // keep: `(` is a `tspecials` too, and refusing on it would put back the
  // reading `7bit (relay)` was added to remove.
  let commented = b"--SEP\r\nContent-Transfer-Encoding: 7bit(relay)\r\n\
                    Content-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", commented).unwrap();
  assert!(same_spelling(
    reader.next().unwrap().unwrap().content_transfer_encoding(),
    multipart::PartEncoding::Identity(b"7bit")
  ));
}

// The same hole again, one level up: the round above closed the ALPHABET and
// left the PRODUCTION open. `x-` is a `token` — no `tspecials`, no CTL, not
// empty — and it is not an `x-token`, because RFC 2045 §5.1 spells that as "The
// two characters "X-" or "x-" followed, with no intervening white space, by any
// token" and `token` is `1*<…>`. It is not an `ietf-token` either: §6.3 reserves
// "all content-transfer-encoding namespace except that beginning with "X-"" to
// the IETF, so the one namespace an `X-` name is NOT in is that one. `x-`
// matches no alternative of `mechanism`, and a value matching no alternative
// must not be classified as a mechanism this crate declines to decode — that
// classification is what skips §15.3.7.2's width test.
#[test]
fn a_mechanism_is_the_whole_production_and_not_only_its_alphabet() {
  // The verified input: `x-` with `bytes 0-9/10` over three octets, which used
  // to come back `Ok` with the width test skipped.
  let bare = b"--SEP\r\nContent-Transfer-Encoding: x-\r\n\
               Content-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", bare).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));

  // Its differential partner: one more byte, and the value becomes an
  // `x-token`. The width test is then skipped on purpose and the same
  // three-octet content under the same ten-octet range comes back.
  let with_tail = b"--SEP\r\nContent-Transfer-Encoding: x-a\r\n\
                    Content-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", with_tail).unwrap();
  let part = reader.next().unwrap().expect("an x-token is a mechanism");
  assert!(same_spelling(
    part.content_transfer_encoding(),
    multipart::PartEncoding::Unrecognised(b"x-a")
  ));
  assert_eq!(part.content(), b"abc");

  // And the refusal is about the FIELD rather than about the width: `x-` is
  // still malformed over a range the content agrees with.
  let agreeing = b"--SEP\r\nContent-Transfer-Encoding: x-\r\n\
                   Content-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", agreeing).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));

  // Both spellings §5.1 gives, and the comment leniency around each, so the
  // refusal is the production's rather than one capitalisation's — and so that
  // stripping a comment cannot leave an empty `x-token` looking like a
  // longer one.
  for empty_x_token in [
    &b"X-"[..],
    b"x-",
    b"x- (relay)",
    b"(relay) X-",
    b"x-(relay)",
  ] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        empty_x_token,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{empty_x_token:?}"
    );
  }

  // The five literals, each still sorted the way §6.1 sorts it: three identity
  // transformations, two encodings this crate does not decode. The `x-` rule
  // must not have narrowed the alternatives beside it.
  for (mechanism, identity) in [
    (&b"7bit"[..], true),
    (b"8bit", true),
    (b"binary", true),
    (b"quoted-printable", false),
    (b"base64", false),
  ] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        mechanism,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("a literal is a mechanism");
    assert_eq!(
      part.content_transfer_encoding().is_identity(),
      identity,
      "{mechanism:?}"
    );
  }

  // The `x-` prefix test is pinned to BOTH of its characters rather than to the
  // first alone. `x` and `xy` are the two neighbours that are not
  // `X-`-prefixed, and they take the OTHER arm: outside the `X-` namespace a
  // token is an `ietf-token` as far as bytes can tell, so they are mechanisms
  // this crate cannot name rather than malformed fields. The differential is
  // therefore between two ANSWERS and not between a refusal and itself — `x-`
  // is refused, `x` and `xy` are reported — which is what pins the arm the
  // prefix selects.
  for neighbour in [&b"x"[..], b"xy"] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        neighbour,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader
      .next()
      .unwrap()
      .expect("a token this crate cannot name");
    assert!(
      same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Unrecognised(neighbour)
      ),
      "{neighbour:?}"
    );
  }
}

// The same rule, at the two productions the test above does not visit. RFC 2045
// §5.1 offers `x-token` THREE times — `type` and `subtype` reach it through
// `extension-token`, and §6.1's `mechanism` names it directly — so an answer
// written into `mechanism` alone, in a copy of its own, leaves the other two
// admitting a bare `x-`:
//
//   Content-Type: x-/plain        -> part returned Ok
//   Content-Type: text/x-         -> part returned Ok
//
// and the first was additionally reported as `TopLevelType::Unknown`, whose
// meaning is: an `extension-token`, and this crate cannot say which class it is
// in. `x-` is in no class — a value that is not a media type at all was being
// carried as one, and `encode_part_header` would spell it back into a body part.
//
// `x-` is a `token` — no `tspecials`, no CTL, not empty — and it is not an
// `x-token`, because §5.1 spells that as "The two characters "X-" or "x-"
// followed, with no intervening white space, by any token" and `token` is
// `1*<…>`. It is neither registry alternative either, since both are closed to
// this namespace; RFC 2046 §6: "publicly specified values shall never begin with
// "X-"".
#[test]
fn the_x_token_rule_holds_at_the_type_and_the_subtype_as_well() {
  // The two verified inputs and both of §5.1's spellings of the prefix, read.
  for spelled in [&b"x-/plain"[..], b"X-/plain", b"text/x-", b"text/X-"] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        spelled,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{spelled:?}"
    );
  }

  // The differential partner of each: one byte more, and the value is an
  // `x-token` in that position. `Unknown` is then the right answer rather than
  // a misclassification — §5.1 admits an `extension-token` as a `discrete-type`
  // and as a `composite-type` alike — and a subtype never moves the answer at
  // all, which is why `text/x-a` stays `Discrete`.
  for (spelled, want) in [
    (&b"x-a/plain"[..], multipart::TopLevelType::Unknown),
    (b"text/x-a", multipart::TopLevelType::Discrete),
  ] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        spelled,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader
      .next()
      .unwrap()
      .expect("an x-token is an extension-token");
    assert_eq!(part.top_level_type(), want, "{spelled:?}");
    assert_eq!(part.content(), b"abc", "{spelled:?}");
  }

  // And the WRITER refuses what the reader refuses, which is why the rule is
  // asked here and not only at the parser. `media_type` reads RFC 9110 §8.3.1,
  // where `type` and `subtype` are each a bare `token` and `x-` is one, so this
  // is a `MediaType` a caller really can hold and hand over — and a body part is
  // where RFC 2045 §5.1 governs instead.
  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let mut out = [0u8; 192];
  for spelled in [&b"x-/plain"[..], b"X-/plain", b"text/x-", b"text/X-"] {
    let ct = crate::media::media_type(spelled).expect("§8.3.1 spells both halves `token`");
    assert!(
      matches!(
        multipart::encode_part_header(
          &cr,
          Some(&ct),
          multipart::PartEncoding::Absent,
          b"SEP",
          &mut out
        ),
        Err(RangeError::MalformedMultipart)
      ),
      "{spelled:?}"
    );
  }

  // The writer's own differential, so its refusal is the production's and not a
  // refusal of every private name: the same call with an `x-token` in each
  // position writes the header.
  for spelled in [&b"x-a/plain"[..], b"text/x-a"] {
    let ct = crate::media::media_type(spelled).expect("a media type");
    assert!(
      multipart::encode_part_header(
        &cr,
        Some(&ct),
        multipart::PartEncoding::Absent,
        b"SEP",
        &mut out
      )
      .is_ok(),
      "{spelled:?}"
    );
  }

  // The prefix is BOTH characters here too. `x` and `xy` are outside the
  // namespace, so each position takes the other alternative and the part is
  // read — the differential is between two answers rather than between a
  // refusal and itself.
  for spelled in [&b"x/plain"[..], b"xy/plain", b"text/x", b"text/xy"] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: ",
        spelled,
        b"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      reader.next().unwrap().is_some(),
      "a token outside the X- namespace: {spelled:?}"
    );
  }
}

// The same hole a THIRD time, and the case that stops the predicate being
// narrowed again. Grown into RFC 2045 §6.1's production, `is_mechanism` reads
// its `ietf-token` alternative as any token that is not `X-`-prefixed — but
// §5.1 defines that alternative by REFERENCE and not by syntax:
//
//   ietf-token := <An extension token defined by a
//                  standards-track RFC and registered
//                  with IANA.>
//
// "registered with IANA" is a lookup, so reading it as a syntax accepts the
// registry as "anything". The verified input is `Content-Transfer-Encoding:
// bogus` over three octets under a ten-octet range: `Ok`, width test skipped,
// while `7bit` on the same body is `PartRangeMismatch`.
//
// What this test pins is the RECOGNISED set: `PartEncoding::Undecoded` claims
// this crate can name the transformation a part asked for, and only §6.1's two
// non-identity literals may wear it. Refusing every other token is the opposite
// error and is answered one test below — it turns a future registration into
// `MalformedMultipart` — so the differential here is not refusal-versus-report
// but `Undecoded`-versus-`Unrecognised`, two answers that both skip the width
// test and are told apart in the value.
#[test]
fn only_a_known_mechanism_may_disable_the_width_invariant() {
  // The verified input, at the classification rather than at the verdict.
  // Three octets, a ten-octet range, and a token registered nowhere: the part
  // comes back, and it comes back as a mechanism this crate CANNOT NAME.
  let verified = b"--SEP\r\nContent-Transfer-Encoding: bogus\r\n\
                   Content-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", verified).unwrap();
  let part = reader.next().unwrap().expect("a mechanism, unrecognised");
  assert!(same_spelling(
    part.content_transfer_encoding(),
    multipart::PartEncoding::Unrecognised(b"bogus")
  ));
  assert!(
    !part.content_transfer_encoding().is_identity(),
    "so the width test was skipped"
  );
  assert!(
    part.is_octet_stream_fallback(),
    "and the skip is not silent: §6.4 says the declared type does not govern"
  );

  // Every shape of token that a syntax-only test passes as an `ietf-token` and
  // a name-only test refuses as a malformed field. `x` and `xy` are the
  // neighbours of the `x-` case that are not `X-`-prefixed; `-` is a one-byte
  // token; `7bits` is the near-miss a case-folded comparison against `7bit`
  // must still tell apart; `some-future-encoding` is what a registration would
  // plausibly look like.
  // Each is a mechanism this crate cannot name, and NONE of them is
  // `Undecoded`, which is the property this test exists for.
  for unrecognised in [
    &b"bogus"[..],
    b"x",
    b"xy",
    b"-",
    b"7bits",
    b"base-64",
    b"some-future-encoding",
  ] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        unrecognised,
        b"\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("a mechanism");
    assert!(
      same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Unrecognised(unrecognised)
      ),
      "{unrecognised:?}"
    );
    // The half that would go quiet if `Unrecognised` were folded back into
    // `Undecoded`: the two variants differ in exactly this answer, and a caller
    // acts on it.
    assert!(part.is_octet_stream_fallback(), "{unrecognised:?}");
  }

  // A value that is no `mechanism` at all is still refused, and the two arms of
  // `is_mechanism_syntax` are one case each: `7bit)` is not a `token`, and `x-`
  // is a token that is not an `x-token` and cannot be an `ietf-token` either,
  // §6.3 having reserved every other name to the IETF.
  for malformed in [&b"7bit)"[..], b"x-", b"X-"] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        malformed,
        b"\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{malformed:?}"
    );
  }

  // The closed set, measured by the WIDTH TEST rather than by the variant
  // alone, since the test is what the classification decides. Three octets
  // under a ten-octet range is `PartRangeMismatch` exactly when the test runs,
  // so §6.1's three identity names fire it...
  for identity in [&b"7bit"[..], b"8bit", b"binary", b"BINARY"] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        identity,
        b"\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::PartRangeMismatch)),
      "{identity:?}"
    );
  }

  // ...and its two non-identity names skip it. These two are the WHOLE of
  // `Undecoded`: an `x-token` is a syntax this crate can decide and not a name
  // it can read, so `x-custom` is `Unrecognised` beside `bogus` rather than
  // beside `base64`, and §6.3's private namespace buys no entry to a set whose
  // members this crate claims to know.
  for undecoded in [
    &b"quoted-printable"[..],
    b"base64",
    b"BASE64",
    b"Quoted-Printable",
  ] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        undecoded,
        b"\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("a known mechanism");
    assert!(
      same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Undecoded(undecoded)
      ),
      "{undecoded:?}"
    );
    assert!(
      !part.is_octet_stream_fallback(),
      "a named mechanism does not displace the declared type: {undecoded:?}"
    );
    assert_eq!(part.content(), b"abc", "{undecoded:?}");
  }
  for unrecognised in [&b"x-custom"[..], b"X-CUSTOM"] {
    let mut buf = [0u8; 128];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Transfer-Encoding: ",
        unrecognised,
        b"\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("an x-token is a mechanism");
    assert!(
      same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Unrecognised(unrecognised)
      ),
      "{unrecognised:?}"
    );
    assert_eq!(part.content(), b"abc", "{unrecognised:?}");
  }

  // The writer's domain moved with the reader's range, which is the half that
  // keeps the two from disagreeing about one part: a `PartEncoding` a caller
  // built by hand out of a token this crate cannot name is not an `Undecoded`,
  // and claiming so is refused before anything is written.
  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let mut out = [0u8; 128];
  for bad in [
    &b"bogus"[..],
    b"some-future-encoding",
    b"7bits",
    b"x-custom",
  ] {
    assert!(
      matches!(
        multipart::encode_part_header(
          &cr,
          None,
          multipart::PartEncoding::Undecoded(bad),
          b"SEP",
          &mut out
        ),
        Err(RangeError::MalformedMultipart)
      ),
      "{bad:?}"
    );
  }
}

// The set of values that may disable the width test is closed, and it can be
// closed TOO FAR. Send everything outside §6.1's five names and the `X-`
// namespace to `RangeError::MalformedMultipart` and a future IANA registration
// refuses the whole body and takes every LATER part down with it — while an
// `x-token`, whose algorithm this crate has no more access to, lands in
// `Undecoded`, the variant that claims this crate KNOWS the transformation.
//
// RFC 2045 §6.4 states the receiver behaviour for exactly that value, and it is
// not rejection: "Any entity with an unrecognized Content-Transfer-Encoding
// must be treated as if it has a Content-Type of "application/octet-stream",
// regardless of what the Content-Type header field actually says."
//
// So there are four states and not two. The width test runs only for an
// identity mechanism; the skip is never silent; and a mechanism this crate
// cannot NAME is reported — token preserved, fallback stated — rather than
// called a malformed body.
#[test]
fn an_encoding_this_crate_does_not_know_is_not_a_malformed_body() {
  // The verified input, in both shapes the finding names: a future
  // registration and a private `x-` extension. Each reaches a readable part,
  // over a `Content-Range` its wire width does not agree with — the width test
  // is skipped, which is what makes the part readable at all.
  for mechanism in [&b"some-future-encoding"[..], b"x-acme-squeeze"] {
    let mut buf = [0u8; 192];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: ",
        mechanism,
        b"\r\nContent-Range: bytes 0-9/10\r\n\r\nabc\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("§6.4 says how to read this");

    // The token, as the sender spelled it.
    assert_eq!(
      part.content_transfer_encoding().mechanism(),
      Some(mechanism),
      "{mechanism:?}"
    );
    // The width test skipped, and skipped VISIBLY rather than in silence.
    assert!(
      !part.content_transfer_encoding().is_identity(),
      "{mechanism:?}"
    );
    assert_eq!(part.content(), b"abc", "{mechanism:?}");
    // §6.4's fallback, reported: the declared `text/plain` does not govern.
    assert!(part.is_octet_stream_fallback(), "{mechanism:?}");
    assert!(part.content_type().is_some(), "{mechanism:?}");
    assert_eq!(
      part.content_type().expect("declared").ty(),
      "text",
      "the field is still reported as written: {mechanism:?}"
    );
    // And it is NOT the answer a mechanism this crate can name gets, which is
    // the differential the classification is worth anything for.
    assert!(
      !same_spelling(
        part.content_transfer_encoding(),
        multipart::PartEncoding::Undecoded(mechanism)
      ),
      "{mechanism:?}"
    );
  }

  // The blast radius, which is what this is about. Refusing a body whose FIRST
  // part names an unknown mechanism takes the whole body with it; the second
  // part is an ordinary `7bit` one, and it must still be reachable.
  let two_parts = b"--SEP\r\nContent-Transfer-Encoding: some-future-encoding\r\n\
                    Content-Range: bytes 0-9/10\r\n\r\nabc\r\n\
                    --SEP\r\nContent-Range: bytes 10-12/13\r\n\r\ndef\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", two_parts).unwrap();
  let first = reader
    .next()
    .unwrap()
    .expect("the unreadable-encoding part");
  assert!(first.is_octet_stream_fallback());
  let second = reader.next().unwrap().expect("and the part behind it");
  assert!(second.content_transfer_encoding().is_identity());
  assert_eq!(second.content(), b"def");
  assert_eq!(second.content_range().incl_range(), Some((10, 12)));
  assert!(reader.next().unwrap().is_none());

  // The writer half, so the two do not part company: a caller re-framing the
  // part it just read writes the same field back, and it reads back the same
  // way. `Unrecognised` is a variant `encode_part_header` accepts, unlike the
  // round in which such a value was not a `PartEncoding` at all.
  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let mut out = [0u8; 192];
  let n = multipart::encode_part_header(
    &cr,
    None,
    multipart::PartEncoding::Unrecognised(b"some-future-encoding"),
    b"SEP",
    &mut out,
  )
  .expect("a mechanism §6.1's production admits");
  assert_eq!(
    &out[..n],
    &b"\r\n--SEP\r\nContent-Range: bytes 0-2/3\r\n\
       Content-Transfer-Encoding: some-future-encoding\r\n\r\n"[..]
  );

  // And the variant is still a claim with evidence behind it: a recognised name
  // in `Unrecognised` would publish a §6.4 fallback over `base64`, which §6.1
  // defines, so the writer refuses it exactly as it refuses the mirror error.
  for contradiction in [
    multipart::PartEncoding::Unrecognised(b"base64"),
    multipart::PartEncoding::Unrecognised(b"7bit"),
    multipart::PartEncoding::Unrecognised(b"x-"),
  ] {
    assert!(
      matches!(
        multipart::encode_part_header(&cr, None, contradiction, b"SEP", &mut out),
        Err(RangeError::MalformedMultipart)
      ),
      "{contradiction:?}"
    );
  }
}

// RFC 2046 §5.1.1: "However, in no event are headers (either message headers or
// body part headers) allowed to contain anything other than US-ASCII
// characters." A reader that locates a colon and accepts whatever else is on
// the line hands back a `Part` carrying metadata this crate's own writer
// refuses — one crate, two answers about the same bytes. The last assertion in
// each pair is that split closed: the reader's refusal and the writer's are the
// same refusal.
#[test]
fn a_part_header_line_outside_us_ascii_is_refused_by_the_reader_too() {
  for body in [
    // A `Content-Type` parameter's `quoted-string`, which RFC 9110 §5.6.4
    // admits `obs-text` in — the exact span `encode_part_header` refuses.
    &b"--SEP\r\nContent-Type: text/plain;charset=\"\x80\"\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n"[..],
    // A `Content-Range` tail under a unit this crate does not read, bounded by
    // §5.5's `field-vchar`, which admits `obs-text` too.
    b"--SEP\r\nContent-Range: exampleunit \x80\r\n\r\nabc\r\n--SEP--\r\n",
    // A field this reader IGNORES: §5.1.1's sentence is about headers, not
    // about the fields one reader happens to collect.
    b"--SEP\r\nX-Note: caf\xc3\xa9\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    // And a CONTINUATION line of one, which is a header line like any other.
    b"--SEP\r\nX-Note: a\r\n \x80\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    // The field name itself.
    b"--SEP\r\nX-\x80: a\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::NonAsciiPartHeader)),
      "{body:?}"
    );
  }

  // The same two values are still what the standalone HTTP parsers accept,
  // which is the half that did NOT change: each is a legal field value, and a
  // caller reading one outside a multipart body is entitled to it.
  assert_eq!(
    ContentRange::parse(b"exampleunit \x80")
      .unwrap()
      .other_range_resp(),
    Some(&b"\x80"[..]),
    "the standalone parse stays permissive; the MIME context is the strict one"
  );
  assert!(crate::media::media_type(b"text/plain;charset=\"\x80\"").is_ok());

  // And the CONTENT is untouched by any of this: `body-part := MIME-part-headers
  // [CRLF *OCTET]`, so an octet outside US-ASCII below the empty line is a part
  // that read back exactly as it arrived.
  let content = b"--SEP\r\nContent-Range: bytes 0-2/3\r\n\r\n\x80\xff\x00\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", content).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"\x80\xff\x00");
}

// RFC 822's `field-name` is one or more printable US-ASCII characters other
// than the colon, which RFC 5322 §3.6.8 restates as `field-name = 1*ftext`. The
// reader located a colon and called whatever preceded it a name, so an empty
// name and a name holding a control byte both reached a returned `Part`.
#[test]
fn a_part_header_field_name_is_held_to_rfc_822s_grammar() {
  for malformed in [
    // Empty: `1*ftext` names at least one character.
    &b"--SEP\r\n: a\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n"[..],
    // A control byte, which `ftext` starts above.
    b"--SEP\r\nX\x01Note: a\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    // DEL, which it stops below.
    b"--SEP\r\nX\x7fNote: a\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    // The SP an obsolete `field-name *WSP ":"` would leave in front of the
    // colon; RFC 9112 §5.1 forbids it in HTTP outright: "No whitespace is
    // allowed between the field name and colon."
    b"--SEP\r\nX-Note : a\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
    // Including on a field this reader would otherwise collect. The part
    // carries a WELL-FORMED `Content-Range` as well, so the refusal cannot be
    // the missing-field one: without this rule `Content-Range ` is simply a
    // name the reader does not recognise, and the part reads back fine.
    b"--SEP\r\nContent-Range : bytes 0-2/3\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n",
  ] {
    let mut reader = multipart::ByteRangesReader::new(b"SEP", malformed).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{malformed:?}"
    );
  }

  // `ftext` is wider than RFC 9110 §5.6.2's `token`, and deliberately: a name
  // outside `token` is still a field this reader walks past rather than a
  // reason to fail the part. Each of these is a `bcharsnospace`-ish byte that
  // `tchar` does not admit.
  let wide = b"--SEP\r\nX-(a),/b=c?: v\r\nContent-Range: bytes 0-2/3\r\n\r\nabc\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", wide).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"abc");
}

// The reader's own `A per-part Content-Length is not framing`: the field begins
// with `Content-`, so RFC 2046 §5.1's "All other header fields may be ignored in
// body parts" does not reach it, and this reader ignores it anyway — as a field
// it does not recognise, never as a second opinion about where the part ends.
// A length that disagrees with the boundary is what tells the two apart.
#[test]
fn a_per_part_content_length_is_neither_read_nor_framing() {
  let body = b"--SEP\r\nContent-Range: bytes 0-3/4\r\nContent-Length: 2\r\n\r\nabcd\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), Some((0, 3)));
  assert_eq!(
    part.content(),
    b"abcd",
    "the delimiter frames the part; the length is not a second opinion"
  );
  assert!(reader.next().unwrap().is_none());
}

// `Part` borrows the BODY `ByteRangesReader::new` was given, not the reader, so
// several are alive at once and each stays readable after the cursor has moved
// past it. Every other test in this file reads one part before asking for the
// next, which a `Part` borrowing the reader would also pass — this one holds
// both across the second `next()` and so would not compile against that shape.
#[test]
fn two_parts_are_held_and_read_after_the_second_next() {
  let body = b"--SEP\r\nContent-Range: bytes 0-1/4\r\n\r\nab\r\n\
               --SEP\r\nContent-Range: bytes 2-3/4\r\n\r\ncd\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let first = reader.next().unwrap().unwrap();
  let second = reader.next().unwrap().unwrap();
  assert_eq!(first.content(), b"ab");
  assert_eq!(second.content(), b"cd");
  assert_eq!(first.content_range().incl_range(), Some((0, 1)));
  assert_eq!(second.content_range().incl_range(), Some((2, 3)));
}

// RFC 2046 §5.1.1 spells its framing in CRLF throughout, so a body framed with
// bare LFs is refused rather than read some other way.
#[test]
fn bare_lf_is_not_a_line_break_in_this_framing() {
  let crlf = b"--SEP\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", crlf).unwrap();
  assert_eq!(reader.next().unwrap().unwrap().content(), b"ab");

  // The same bytes with every CRLF cut down to its LF.
  let lf = b"--SEP\nContent-Range: bytes 0-1/2\n\nab\n--SEP--\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", lf).unwrap();
  assert!(matches!(reader.next(), Err(RangeError::MalformedMultipart)));
}

// ── The MIME quoted-string is RFC 822's, and RFC 822's is not RFC 9110's ─────

// The lexical classes a MIME `quoted-string` is built from are RFC 822's, and
// they are wider than RFC 9110 §5.6.4's in the direction that matters here.
// RFC 822's `qtext` takes three characters out of `CHAR` — the DQUOTE, the
// backslash and the CR — and its `quoted-pair` puts no set at all on the
// character behind the backslash. §5.6.4's
// `qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text` excludes every CTL
// and DEL, and its `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )` excludes
// every CTL but HTAB.
//
// Read with §5.6.4's scanner, a conforming part carrying `charset="a<DEL>b"` was
// `MalformedMultipart` — which is not a fault of that part alone: `next` refuses
// the whole body, so one legal octet in one parameter cost every part behind it
// too. That last clause is what the second half of this test measures.
#[test]
fn a_mime_quoted_string_admits_the_ctls_rfc_822_admits() {
  for (interior, want) in [
    // DEL, the verified input. A `CHAR` (RFC 822's is US-ASCII 0-127), and none
    // of qtext's three exclusions.
    (&b"a\x7fb"[..], &b"a\x7fb"[..]),
    // A bare control character, admitted by the same three-exclusion rule.
    (b"a\x01b", b"a\x01b"),
    // An ESCAPED control character: `quoted-pair = "\" CHAR` puts no set on the
    // character behind the backslash, where §5.6.4's names four. The interior
    // comes back with the escape untouched, as the HTTP walk's does.
    (b"a\\\x01b", b"a\\\x01b"),
    // An escaped DEL, and an escaped DQUOTE beside it so the string's own
    // delimiter is reached through `quoted-pair` rather than through `qtext`.
    (b"a\\\x7f\\\"b", b"a\\\x7f\\\"b"),
  ] {
    let mut buf = [0u8; 256];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\nContent-Type: text/plain;charset=\"",
        interior,
        b"\"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    let part = reader.next().unwrap().expect("a conforming MIME part");
    let media = part.content_type().expect("a Content-Type");
    assert_eq!((media.ty(), media.subtype()), ("text", "plain"));
    let (name, value) = media.params().next().unwrap().unwrap();
    assert_eq!(name, b"charset", "{interior:?}");
    assert!(same_param(value, ParamValue::Quoted(want)), "{interior:?}");

    // The same value spelled back out. Nothing here is non-ASCII, so RFC 2046
    // §5.1.1's rule is satisfied and the writer copies the interior verbatim
    // between the DQUOTEs it took them from.
    let mut out = [0u8; 128];
    let n = multipart::encode_part_header(
      part.content_range(),
      part.content_type(),
      part.content_transfer_encoding(),
      b"SEP",
      &mut out,
    )
    .unwrap();
    let mut want_header = [0u8; 128];
    let expected = joined(
      &mut want_header,
      &[
        b"\r\n--SEP\r\nContent-Type: text/plain;charset=\"",
        want,
        b"\"\r\nContent-Range: bytes 0-1/2\r\n\r\n",
      ],
    );
    assert_eq!(&out[..n], expected, "{interior:?}");
  }

  // And the cost of the old refusal, which was never one part's. A body whose
  // FIRST part carries the DEL and whose second is unremarkable: under §5.6.4's
  // scanner the first `next` answered `MalformedMultipart`, and
  // `an_error_leaves_the_cursor_where_it_was` is why the second part was then
  // unreachable.
  let body = b"--SEP\r\nContent-Type: text/plain;charset=\"a\x7fb\"\r\n\
               Content-Range: bytes 0-1/4\r\n\r\nab\r\n\
               --SEP\r\nContent-Range: bytes 2-3/4\r\n\r\ncd\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert_eq!(reader.next().unwrap().expect("first").content(), b"ab");
  assert_eq!(reader.next().unwrap().expect("second").content(), b"cd");
  assert!(reader.next().unwrap().is_none(), "the body ends");
}

// The HTTP field section is NOT widened, which is the separation this pair of
// grammars is for: §5.6.4 is right where an HTTP field value is being read, and
// DEL is no `qdtext`.
#[test]
fn the_http_parser_keeps_its_own_quoted_string_alphabet() {
  assert_eq!(
    crate::media::media_type(b"text/plain;charset=\"a\x7fb\"").unwrap_err(),
    crate::media::MediaError::Parameters(crate::grammar::ListError::InvalidQuotedByte),
    "DEL is a `CHAR` and is not `qdtext`; §5.6.4 governs an HTTP field section"
  );
  // The escaped form is refused by the other half of §5.6.4's rule.
  assert_eq!(
    crate::media::media_type(b"text/plain;charset=\"a\\\x01b\"").unwrap_err(),
    crate::media::MediaError::Parameters(crate::grammar::ListError::InvalidQuotedByte),
  );
}

// What this pins is the FIELD grammar, and not the quoted-string's — the two are
// independent rules that land on the same octet, and this is the outer one.
// RFC 822's `field = field-name ":" [ field-body ] CRLF` ends a field at the
// CRLF this reader splits on, and `field-body = field-body-contents [CRLF
// LWSP-char field-body]` admits a CR or an LF inside a body only as the CRLF of
// a fold. So a line-break octet left INSIDE one line belongs to no `field`, and
// the CRLF split leaves that possible: the reader looks for the first CRLF, so a
// CR with no LF behind it, or an LF with no CR in front, sits in the middle of
// the line it was written into.
//
// The lexis has its own answer for the CR — `qtext` and `ctext` both exclude it
// by name — and its own SILENCE about the LF, which is a `CHAR` neither
// production names. This rule fires first for both, and that is why
// `the_mime_lexis_is_rfc_822s_and_not_rfc_9110s` over in `media`'s tests drives
// the productions directly rather than by way of a body part: a test that
// reached them only from here would pin whichever refusal came first and say
// nothing at all about the other.
#[test]
fn a_bare_line_break_octet_belongs_to_no_rfc_822_field() {
  for line in [
    // A bare CR inside a comment: `ctext` excludes it by name.
    &b"Content-Type: text/plain (a\rb)"[..],
    // Inside a quoted-string, where `qtext` excludes it by the same name.
    b"Content-Type: text/plain;charset=\"a\rb\"",
    // Behind a backslash, where `quoted-pair` would admit it — a CR is a `CHAR`
    // — so the refusal here is the FIELD grammar's and not the quoted-string's:
    // RFC 822's `field-body` admits a CR only as the CRLF of a fold, and this
    // reader has already split at every CRLF there is.
    b"Content-Type: text/plain;charset=\"a\\\rb\"",
    // A bare LF, which is the case RFC 822's `qtext` does NOT exclude and the
    // `field` production does: it is a `CHAR` and is none of the three, so
    // nothing in the quoted-string's own lexis would stop it reaching a
    // parameter value, a `Part`, and `encode_part_header`'s verbatim copy.
    b"Content-Type: text/plain;charset=\"a\nb\"",
    // The same octet in a field this reader collects nothing from, to show the
    // rule is the whole line's rather than one parser's.
    b"X-Ignored: a\nb",
    // And in one it ignores, with a CR.
    b"X-Ignored: a\rb",
  ] {
    let mut buf = [0u8; 256];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\n",
        line,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{line:?}"
    );
  }

  // The control that keeps the rule from being read as "no CR anywhere": the
  // CRLFs of the framing itself are exactly where a CR belongs, and the same
  // header without the stray octet is a part.
  let body = b"--SEP\r\nContent-Type: text/plain (a b)\r\n\
               Content-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  assert_eq!(reader.next().unwrap().expect("a part").content(), b"ab");
}

// Every refusal the MIME walk can make arrives here as one `MalformedMultipart`,
// which is the whole of what `mime_content_type`'s `Option` promises. The rows
// are the lexis's own refusals — an unclosed comment, a dangling `quoted-pair`,
// an unterminated `quoted-string` — and each is chosen to REACH that walk: the
// reader's own two line rules, the US-ASCII one and the line-break one, answer
// before it for every octet they cover, so a row carrying one of those would
// pin the wrong refusal.
#[test]
fn every_mime_lexis_refusal_reaches_the_reader_as_one_answer() {
  for line in [
    &b"Content-Type: text/plain (unclosed"[..],
    b"Content-Type: text/plain;charset=\"a\\",
    b"Content-Type: text/plain;charset=\"unterminated",
  ] {
    let mut buf = [0u8; 256];
    let body = joined(
      &mut buf,
      &[
        b"--SEP\r\n",
        line,
        b"\r\nContent-Range: bytes 0-1/2\r\n\r\nab\r\n--SEP--\r\n",
      ],
    );
    let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
    assert!(
      matches!(reader.next(), Err(RangeError::MalformedMultipart)),
      "{line:?}"
    );
  }
}

// A part that enclosed nothing is an empty slice, not an absent one — and the
// header block's own empty line supplies the CRLF the next delimiter would
// otherwise have taken off the content.
//
// The Content-Range is §14.4's `unsatisfied-range` and NOT `bytes 0-0/1`. Under
// §14.1.2's unit an `incl-range` encloses `last - first + 1` octets and `0-0`
// encloses one, so `bytes 0-0/1` over an EMPTY part is a §15.3.7.2
// correspondence violation — the very shape `RangeError::PartRangeMismatch`
// refuses, which this test would then be asserting as an `Ok`. No `incl-range`
// encloses zero octets, so the framing case this test exists for has no
// `range-resp` that can carry it; `bytes */1234` is the `bytes` shape that
// names no positions at all, and it leaves the subject — an empty content
// slice, and the CRLF accounting behind it — exactly where it was.
#[test]
fn an_empty_part_reads_back_as_an_empty_slice() {
  let body = b"--SEP\r\nContent-Range: bytes */1234\r\n\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content(), b"");
  assert_eq!(part.content_range().incl_range(), None);
  assert!(part.content_range().is_unsatisfied());
  assert!(reader.next().unwrap().is_none());
}

// The two halves against each other: what `encode_part_header` and
// `encode_final_boundary` write is what this reads, leading CRLF and all. The
// writer's `[preamble CRLF]` with an empty preamble is a preamble like any
// other from this side.
//
// The positions are the placeholder contents' widths for `BODY`'s reason, and
// here they carry a second one: this test is the round trip, so it is where the
// two halves' one deliberate disagreement would show. `encode_part_header` does
// not check the content's width against the field — it never sees the content —
// and `ByteRangesReader::next` does. A body written from ranges wider than the
// bytes appended behind them is one this writer emits happily and this reader
// refuses, which is stated on both functions and is why the ranges below are
// the widths of what `append` actually writes.
#[test]
fn the_writers_body_reads_back_part_for_part() {
  fn append(body: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    body[at..at + bytes.len()].copy_from_slice(bytes);
    at + bytes.len()
  }

  let boundary = b"THIS_STRING_SEPARATES";
  let pdf = crate::media::media_type(b"application/pdf").unwrap();
  let first = ContentRange::bytes(500, 520, Some(8000)).unwrap();
  let second = ContentRange::bytes(7000, 7018, Some(8000)).unwrap();

  let mut body = [0u8; 512];
  let mut at = 0;
  at += multipart::encode_part_header(
    &first,
    Some(&pdf),
    multipart::PartEncoding::Absent,
    boundary,
    &mut body[at..],
  )
  .unwrap();
  at = append(&mut body, at, b"...the first range...");
  at += multipart::encode_part_header(
    &second,
    None,
    multipart::PartEncoding::Absent,
    boundary,
    &mut body[at..],
  )
  .unwrap();
  at = append(&mut body, at, b"...the second range");
  at += multipart::encode_final_boundary(boundary, &mut body[at..]).unwrap();

  let mut reader = multipart::ByteRangesReader::new(boundary, &body[..at]).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), Some((500, 520)));
  let ct = part.content_type().unwrap();
  assert_eq!((ct.ty(), ct.subtype()), ("application", "pdf"));
  assert_eq!(part.content(), b"...the first range...");

  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().incl_range(), Some((7000, 7018)));
  assert!(part.content_type().is_none());
  assert_eq!(part.content(), b"...the second range");

  assert!(reader.next().unwrap().is_none());
}

// The reader reported an encoding the writer could not emit, so reframing a
// part dropped its declaration — and RFC 2045 §6.1 gives an absent field a
// meaning rather than none: "This is the default value -- that is,
// "Content-Transfer-Encoding: 7BIT" is assumed if the Content-Transfer-Encoding
// header field is not present." A `base64` part rewritten without its field
// therefore came back as `7bit`, whose octets ARE the enclosed octets, so the
// width test applied to four wire octets over a three-octet range and this
// crate refused a body it had just written.
#[test]
fn an_encoding_the_reader_reports_is_one_the_writer_can_write_back() {
  // Read, then rewrite from the three accessors alone, then read again.
  let original =
    b"--SEP\r\nContent-Transfer-Encoding: base64\r\nContent-Range: bytes 0-2/3\r\n\r\nYWJj\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", original).unwrap();
  let part = reader.next().unwrap().expect("a base64 part");

  let mut body = [0u8; 256];
  let mut at = multipart::encode_part_header(
    part.content_range(),
    part.content_type(),
    part.content_transfer_encoding(),
    b"SEP",
    &mut body,
  )
  .unwrap();
  body[at..at + part.content().len()].copy_from_slice(part.content());
  at += part.content().len();
  at += multipart::encode_final_boundary(b"SEP", &mut body[at..]).unwrap();

  let mut reader = multipart::ByteRangesReader::new(b"SEP", &body[..at]).unwrap();
  let again = reader.next().unwrap().expect("and it reads back");
  assert!(
    same_spelling(
      again.content_transfer_encoding(),
      multipart::PartEncoding::Undecoded(b"base64")
    ),
    "the declaration survived the round trip"
  );
  assert_eq!(again.content(), b"YWJj");
  assert_eq!(again.content_range().incl_range(), Some((0, 2)));
  assert!(reader.next().unwrap().is_none());

  // What the field looks like, and where it sits: last of the three, in front
  // of the empty line that ends the block.
  assert_eq!(
    &body[..at],
    &b"\r\n--SEP\r\nContent-Range: bytes 0-2/3\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj\r\n--SEP--\r\n"[..]
  );

  // `Absent` stays absent, and that is not the same as writing `7bit`: the two
  // are the same MEANING and different bytes, and a caller re-framing a part
  // that carried no field must not be made to look like one that did.
  let mut out = [0u8; 128];
  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let n =
    multipart::encode_part_header(&cr, None, multipart::PartEncoding::Absent, b"SEP", &mut out)
      .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--SEP\r\nContent-Range: bytes 0-2/3\r\n\r\n"[..]
  );

  // And the three identity names come back through the writer unchanged, case
  // included: §6.1 makes the comparison case-insensitive and the SPELLING is
  // still the sender's.
  let n = multipart::encode_part_header(
    &cr,
    None,
    multipart::PartEncoding::Identity(b"7BIT"),
    b"SEP",
    &mut out,
  )
  .unwrap();
  assert_eq!(
    &out[..n],
    &b"\r\n--SEP\r\nContent-Range: bytes 0-2/3\r\nContent-Transfer-Encoding: 7BIT\r\n\r\n"[..]
  );
}

// The writer's domain is what the reader's range is. `PartEncoding`'s variants
// are public, so these three are reachable by hand and by nothing else, and
// each would put the written header at odds with the claim the variant makes.
#[test]
fn the_writer_refuses_a_part_encoding_no_read_produces() {
  let cr = ContentRange::bytes(0, 2, Some(3)).unwrap();
  let mut out = [0u8; 128];
  for bad in [
    // Not a `mechanism` at all: `is_mechanism_syntax`'s two arms, one each.
    multipart::PartEncoding::Undecoded(b"7bit)"),
    multipart::PartEncoding::Unrecognised(b"7bit)"),
    multipart::PartEncoding::Undecoded(b"x-"),
    multipart::PartEncoding::Unrecognised(b"x-"),
    // A `mechanism`, in the variant that contradicts it. `Identity` claims the
    // content is the enclosed octets and `base64` says it is not; `Undecoded`
    // claims this crate will not vouch for the width and `7bit` says it can.
    multipart::PartEncoding::Identity(b"base64"),
    multipart::PartEncoding::Undecoded(b"7bit"),
    // And the pair that straddles the `Undecoded`/`Unrecognised` boundary,
    // which is the same rule again: `Undecoded` claims this crate can NAME the
    // transformation, which is false of an `x-token`; `Unrecognised` claims it
    // cannot, and publishes RFC 2045 §6.4's `application/octet-stream` fallback
    // on the strength of that — over a name §6.1 defines, if it were admitted
    // here.
    multipart::PartEncoding::Undecoded(b"x-custom"),
    multipart::PartEncoding::Unrecognised(b"base64"),
    multipart::PartEncoding::Unrecognised(b"7bit"),
  ] {
    assert!(
      matches!(
        multipart::encode_part_header(&cr, None, bad, b"SEP", &mut out),
        Err(RangeError::MalformedMultipart)
      ),
      "{bad:?}"
    );
  }

  // The refusal is answered before anything is written, like every other one
  // here: a buffer too small for the header still reports the encoding rather
  // than the size, because the encoding is checked first.
  let mut tiny = [0u8; 1];
  assert!(matches!(
    multipart::encode_part_header(
      &cr,
      None,
      multipart::PartEncoding::Identity(b"base64"),
      b"SEP",
      &mut tiny
    ),
    Err(RangeError::MalformedMultipart)
  ));
}

// RFC 9110 §14.6: the "media type is not limited to byte ranges", and a part
// under a unit this crate does not read is one §14.4 forbids recombining from.
// The reader
// reports the condition rather than deciding it.
#[test]
fn a_unit_this_crate_cannot_read_is_reported_as_the_condition_it_is() {
  let body = b"--SEP\r\nContent-Type: video/example\r\nContent-Range: exampleunit 1.2-4.3/25\r\n\r\nxx\r\n--SEP--\r\n";
  let mut reader = multipart::ByteRangesReader::new(b"SEP", body).unwrap();
  let part = reader.next().unwrap().unwrap();
  assert_eq!(part.content_range().unit(), b"exampleunit");
  assert!(
    part.content_range().other_range_resp().is_some(),
    "which is §14.4's own condition for the recombination MUST NOT"
  );
  assert_eq!(part.content_range().incl_range(), None);
}

/// Tests whose input is built on the heap: gated to the tiers that have one,
/// since the bare `no_std` tier has neither an allocator nor the `alloc as std`
/// alias.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
mod heap {
  use crate::range::*;
  use std::string::String;

  #[test]
  fn every_over_u64_position_gets_the_answer_the_rfc_defines() {
    let huge = "99999999999999999999999999";
    let len = 1000u64;

    // first-pos over u64, last-pos absent: valid, and unsatisfiable — no
    // representable length exceeds it.
    let v = std::format!("bytes={huge}-");
    let spec = RangesSpecifier::parse(v.as_bytes()).unwrap();
    assert_eq!(spec.resolve(0, len), Some(Resolved::Unsatisfiable));

    // first-pos over u64 with a representable last-pos: INVALID — a
    // representable last-pos is necessarily below it.
    let v = std::format!("bytes={huge}-500");
    assert!(RangesSpecifier::parse(v.as_bytes()).is_err());

    // last-pos over u64 with a representable first-pos: valid AND satisfiable —
    // a last-pos at or past the end normalises to `length - 1`, an ordinary
    // from-here-to-the-end request.
    let v = std::format!("bytes=0-{huge}");
    let spec = RangesSpecifier::parse(v.as_bytes()).unwrap();
    assert_eq!(spec.resolve(0, len), Some(Resolved::Range(0, 999)));

    // suffix-length over u64: valid and satisfiable — a suffix longer than the
    // representation takes the whole of it.
    let v = std::format!("bytes=-{huge}");
    let spec = RangesSpecifier::parse(v.as_bytes()).unwrap();
    assert_eq!(spec.resolve(0, len), Some(Resolved::Range(0, 999)));
  }

  #[test]
  fn more_range_specs_than_slots_is_refused() {
    let mut value = String::from("bytes=");
    for i in 0..=MAX_RANGE_SPECS {
      if i > 0 {
        value.push(',');
      }
      value.push_str("0-1");
    }
    assert!(matches!(
      RangesSpecifier::parse(value.as_bytes()),
      Err(RangeError::TooManySpecs)
    ));
  }

  // The other side of the same bound, and the one that says the refusal is a
  // fence-post rather than an off-by-one: exactly the slot count fits, and every
  // slot is reachable.
  #[test]
  fn exactly_the_slot_count_fits() {
    let mut value = String::from("bytes=");
    for i in 0..MAX_RANGE_SPECS {
      if i > 0 {
        value.push(',');
      }
      value.push_str("0-1");
    }
    let spec = RangesSpecifier::parse(value.as_bytes()).expect("MAX_RANGE_SPECS specs fit");
    assert_eq!(spec.len(), MAX_RANGE_SPECS);
    assert!(spec.spec(MAX_RANGE_SPECS.saturating_sub(1)).is_some());
    assert!(spec.spec(MAX_RANGE_SPECS).is_none());
  }

  // §5.6.1.2's empty elements arrive through `grammar::list_elements`, which
  // drops them before a slot is ever asked for — so a comma flood is refused
  // only once it carries MAX_RANGE_SPECS real specs, however many empties came
  // with it.
  // gate-exempt: grammar::list_elements — what `RangesSpecifier::parse` routes the
  // range-set through, one call below this test rather than in its own body; the
  // test exists to say that routing happened, which is why the walker is named
  #[test]
  fn a_comma_flood_is_not_too_many_specs() {
    let mut value = String::from("bytes=");
    for _ in 0..(MAX_RANGE_SPECS.saturating_mul(4)) {
      value.push_str(", ");
    }
    value.push_str("0-1");
    let spec =
      RangesSpecifier::parse(value.as_bytes()).expect("empty elements must not exhaust the slots");
    assert_eq!(spec.len(), 1);
  }
}
