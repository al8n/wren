use super::*;
use crate::date::parse_http_date;

// ── RFC 9110 §8.8.3: the grammar ─────────────────────────────────────────────

#[test]
fn parses_the_two_forms_and_the_empty_tag() {
  let strong = EntityTag::parse(br#""xyzzy""#).unwrap();
  assert!(!strong.is_weak());
  assert_eq!(strong.opaque_tag(), b"xyzzy");

  let weak = EntityTag::parse(br#"W/"xyzzy""#).unwrap();
  assert!(weak.is_weak());
  assert_eq!(weak.opaque_tag(), b"xyzzy");

  // §8.8.3 prints `ETag: ""` among its own examples. A parser requiring one
  // byte refuses the RFC's own example.
  let empty = EntityTag::parse(br#""""#).unwrap();
  assert!(!empty.is_weak());
  assert_eq!(empty.opaque_tag(), b"");
}

#[test]
fn etagc_admits_backslash_comma_and_obs_text() {
  // `opaque-tag` has NO quoted-pair (§8.8.3's own note names backslash
  // unescaping as the legacy recipient bug), so a trailing backslash is content
  // and the tag is two bytes long.
  let tag = EntityTag::parse(br#""a\""#).unwrap();
  assert_eq!(tag.opaque_tag(), br"a\");

  // `%x2C` is inside `%x23-7E`, which is why `grammar::list_elements` cannot
  // walk a tag list: it splits on raw commas.
  let tag = EntityTag::parse(br#""a,b""#).unwrap();
  assert_eq!(tag.opaque_tag(), b"a,b");

  // `obs-text` = `%x80-FF`. §8.8.3 admits it; Appendix A's collected grammar
  // drops it. This follows §8.8.3.
  let tag = EntityTag::parse(b"\"a\xC3\xA9\"").unwrap();
  assert_eq!(tag.opaque_tag(), b"a\xC3\xA9");
}

#[test]
fn refuses_what_the_grammar_refuses() {
  for bad in [
    &b"xyzzy"[..],   // no DQUOTEs
    br#""xyzzy"#,    // unterminated
    br#"w/"xyzzy""#, // `weak = %s"W/"` is case-SENSITIVE
    b"\"a\x7F\"",    // %x7F is outside %x23-7E and is not obs-text
    b"\"a\tb\"",     // %x09 likewise
    br#""a""b""#,    // trailing junk
    b"",             // not even a DQUOTE
    b"\"",           // one DQUOTE is not two
    b"W/",           // a weakness marker with no opaque-tag
  ] {
    assert!(EntityTag::parse(bad).is_err(), "{bad:?} must not parse");
  }
}

// `parse` is a `const fn`, so a tag literal folds at compile time — and what it
// folds to is checked, not merely that it folded.
const CONST_TAG: EntityTag<'static> = match EntityTag::parse(br#"W/"x""#) {
  Ok(tag) => tag,
  Err(_) => panic!("the RFC's own weak example is an entity-tag"),
};

#[test]
fn parse_is_usable_in_a_const_context() {
  assert!(CONST_TAG.is_weak());
  assert_eq!(CONST_TAG.opaque_tag(), b"x");
}

// ── RFC 9110 §8.8.3.2: comparison ────────────────────────────────────────────
//
// The oracle is the two DEFINITIONS, over all eight pairs. Table 3 prints four
// of them, and those four cannot see a `strong_eq` that never compares the
// opaque-tags at all.

#[test]
fn comparison_over_all_eight_pairs() {
  let w1 = EntityTag::parse(br#"W/"1""#).unwrap();
  let w2 = EntityTag::parse(br#"W/"2""#).unwrap();
  let s1 = EntityTag::parse(br#""1""#).unwrap();
  let s2 = EntityTag::parse(br#""2""#).unwrap();

  // (left, right, strong, weak)
  let pairs = [
    (w1, w1, false, true),  // Table 3 row 1
    (w1, w2, false, false), // Table 3 row 2
    (w1, s1, false, true),  // Table 3 row 3
    (s1, s1, true, true),   // Table 3 row 4
    (w1, s2, false, false), // not printed
    (s1, w1, false, true),  // not printed — symmetry
    (s1, w2, false, false), // not printed
    (s1, s2, false, false), // NOT PRINTED, and the one that matters:
                            // `!a.is_weak() && !b.is_weak()` passes all four
                            // printed rows and fails only here.
  ];
  for (a, b, strong, weak) in pairs {
    assert_eq!(a.strong_eq(&b), strong, "strong {a:?} vs {b:?}");
    assert_eq!(a.weak_eq(&b), weak, "weak {a:?} vs {b:?}");
  }
}

#[test]
fn comparison_is_case_sensitive_and_byte_exact() {
  // §8.8.3.1: "Since the value is opaque, there is no need for the client to be
  // aware of how each entity tag is constructed." Two opaque-tags differing in
  // case are two different tags, so `grammar::eq_ignore_ascii` is the wrong
  // equality here.
  let lower = EntityTag::parse(br#""a""#).unwrap();
  let upper = EntityTag::parse(br#""A""#).unwrap();
  assert!(!lower.strong_eq(&upper));
  assert!(!lower.weak_eq(&upper));

  // A prefix is not a match: the lengths are compared before the bytes.
  let short = EntityTag::parse(br#""ab""#).unwrap();
  let long = EntityTag::parse(br#""abc""#).unwrap();
  assert!(!short.strong_eq(&long));
  assert!(!long.weak_eq(&short));

  // The empty tag matches only the empty tag.
  let empty = EntityTag::parse(br#""""#).unwrap();
  assert!(empty.strong_eq(&empty));
  assert!(!empty.weak_eq(&short));
}

// ── The list walker ──────────────────────────────────────────────────────────

#[test]
fn a_tag_list_splits_on_commas_outside_the_quotes() {
  let list = TagList::parse(br#""a,b", W/"c", """#).unwrap();
  assert!(!list.is_star());
  assert_eq!(list.len(), 3);
  assert!(!list.is_empty());
  assert_eq!(list.get(0).unwrap().opaque_tag(), b"a,b");
  assert!(list.get(1).unwrap().is_weak());
  assert_eq!(list.get(2).unwrap().opaque_tag(), b"");
  assert!(list.get(3).is_none());
}

#[test]
fn a_backslash_before_a_dquote_closes_the_tag_rather_than_escaping_it() {
  // The case §8.8.3's note is about, in a list: a quoted-string walker reads
  // `\"` as an escaped DQUOTE and runs off the end of the value. `opaque-tag`
  // has no quoted-pair, so the third byte closes the first tag and the comma
  // after it splits.
  let list = TagList::parse(br#""a\", "b""#).unwrap();
  assert_eq!(list.len(), 2);
  assert_eq!(list.get(0).unwrap().opaque_tag(), br"a\");
  assert_eq!(list.get(1).unwrap().opaque_tag(), b"b");

  // And the converse: a comma between the DQUOTEs does not split, so an
  // unterminated span swallows the rest of the value rather than yielding two
  // elements that each happen to parse.
  assert!(matches!(
    TagList::parse(br#""a, "b""#),
    Err(TagError::Malformed)
  ));
}

#[test]
fn ows_around_an_element_is_not_part_of_the_tag() {
  // `#element` is `[ element ] *( OWS "," OWS [ element ] )`, and §5.5 keeps OWS
  // out of the value.
  let list = TagList::parse(b"  \"a\" ,\tW/\"b\"  ").unwrap();
  assert_eq!(list.len(), 2);
  assert_eq!(list.get(0).unwrap().opaque_tag(), b"a");
  assert!(list.get(1).unwrap().is_weak());
}

#[test]
fn star_is_a_list_of_its_own() {
  let list = TagList::parse(b"*").unwrap();
  assert!(list.is_star());
  assert_eq!(list.len(), 0);
  assert!(list.is_empty());
  assert!(list.get(0).is_none());

  // OWS around it is still OWS.
  assert!(TagList::parse(b"  *  ").unwrap().is_star());
}

// RFC 9110 §13.1.1 and §13.1.2 both close by naming this syntactically invalid:
// a field value containing `*` alongside other values, INCLUDING other
// instances of `*`.
#[test]
fn star_alongside_anything_is_invalid() {
  for bad in [&br#"*, "x""#[..], br#""x", *"#, b"*, *"] {
    assert!(
      matches!(TagList::parse(bad), Err(TagError::StarInList)),
      "{bad:?}"
    );
  }
}

#[test]
fn an_empty_field_value_is_an_empty_list() {
  // Appendix A expands `#entity-tag` to
  // `[ entity-tag *( OWS "," OWS entity-tag ) ]` for both fields, so a value
  // carrying no tag at all is grammatical and is not `*`.
  let list = TagList::parse(b"").unwrap();
  assert!(!list.is_star());
  assert!(list.is_empty());
  assert_eq!(list.len(), 0);
}

// RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable number of
// empty list elements". The crate holds this rule at one entrance,
// `grammar::list_elements`, for every RECIPIENT list whose elements that split
// can delimit. This walker is one of the exceptions, so it carries the rule across
// explicitly — and this is the test that says it did.
// gate-exempt: grammar::list_elements — named for contrast: the entrance this
// walker cannot route through, which is why the rule is re-stated here.
#[test]
fn empty_elements_are_parsed_and_ignored() {
  let list = TagList::parse(br#"W/"a", , W/"b""#).unwrap();
  assert_eq!(
    list.len(),
    2,
    "the empty element does not contribute to the count"
  );
  assert_eq!(list.get(0).unwrap().opaque_tag(), b"a");
  assert_eq!(list.get(1).unwrap().opaque_tag(), b"b");

  // The recipient form is `#element => [ element ] *( OWS "," OWS [ element ] )`,
  // so leading and trailing commas are conformant too.
  let list = TagList::parse(br#", W/"a","#).unwrap();
  assert_eq!(list.len(), 1);

  // An element of nothing but OWS is empty once §5.5's OWS is off it.
  let list = TagList::parse(b"\"a\" , \t , \"b\"").unwrap();
  assert_eq!(list.len(), 2);

  // A value of nothing but empty elements is an empty list, not a fault.
  let list = TagList::parse(b" , , ").unwrap();
  assert!(list.is_empty());
  assert!(!list.is_star());
}

#[test]
fn a_malformed_element_refuses_the_whole_list() {
  // Judging from the tags that DID parse would answer over a value the sender
  // did not send.
  assert!(matches!(
    TagList::parse(br#""a", not-a-tag"#),
    Err(TagError::Malformed)
  ));
  assert!(matches!(
    TagList::parse(br#""a", w/"b""#),
    Err(TagError::Malformed)
  ));
}

/// Tests whose input is built on the heap: gated to the tiers that have one,
/// since the bare `no_std` tier has neither an allocator nor the `alloc as std`
/// alias.
#[cfg(any(feature = "std", feature = "alloc", feature = "no-atomic"))]
mod heap {
  use crate::validator::*;
  use std::vec::Vec;

  /// `n` copies of the entity tag `"t"`, comma-separated.
  fn tags(n: usize) -> Vec<u8> {
    let mut value = Vec::new();
    for i in 0..n {
      if i > 0 {
        value.extend_from_slice(b", ");
      }
      value.extend_from_slice(b"\"t\"");
    }
    value
  }

  // The distinctive claim of the bound: the empty elements accepted here are
  // UNBOUNDED, and they spend no slot. §5.6.1.2's "reasonable number" governs
  // EMPTY elements while `MAX_TAGS` bounds REAL tags, so the slot count is not
  // what answers that sentence — a comma flood is refused only once it carries
  // `MAX_TAGS` real tags, however many empties preceded them. What makes the
  // unboundedness safe is not a count: an empty element costs no slot and no
  // byte, over a field value the transport layer has already bounded. An
  // implementation counting empties against the slots passes
  // `empty_elements_are_parsed_and_ignored` (three elements fit any plausible
  // array) and fails this.
  #[test]
  fn a_comma_flood_is_not_too_many_tags() {
    let mut value = Vec::new();
    for _ in 0..(MAX_TAGS * 4) {
      value.extend_from_slice(b", ");
    }
    value.extend_from_slice(br#""a", "b""#);

    let list = TagList::parse(&value).expect("empty elements must not exhaust the slots");
    assert_eq!(list.len(), 2);
  }

  #[test]
  fn exactly_the_slot_count_fits() {
    let value = tags(MAX_TAGS);
    let list = TagList::parse(&value).expect("MAX_TAGS tags fit");
    assert_eq!(list.len(), MAX_TAGS);
    assert_eq!(list.get(MAX_TAGS - 1).unwrap().opaque_tag(), b"t");
    assert!(list.get(MAX_TAGS).is_none());
  }

  #[test]
  fn more_real_tags_than_slots_is_refused() {
    assert!(matches!(
      TagList::parse(&tags(MAX_TAGS + 1)),
      Err(TagError::TooMany)
    ));
  }
}

// ── The selected representation ──────────────────────────────────────────────

#[test]
fn an_absent_representation_carries_nothing() {
  let absent = Selected::absent();
  assert!(!absent.exists());
  assert!(absent.etag().is_none());
  assert!(absent.last_modified().is_none());
  assert!(absent.complete_length().is_none());
}

// The split is the point: every validator lives on `Present`, so
// `Selected::absent()` has no method that could attach one. This test documents
// the shape; the guarantee is the type's, not the test's — the code in the
// comment must not compile.
#[test]
fn validators_live_on_present() {
  // Selected::absent().with_etag(tag)  // <- no such method, by construction
  let tag = EntityTag::parse(br#""xyzzy""#).unwrap();
  let selected = Selected::present().with_etag(tag).build();
  assert!(selected.exists());
  assert_eq!(selected.etag().unwrap().opaque_tag(), b"xyzzy");
}

#[test]
fn last_modified_strength_is_asserted_not_deduced() {
  let at = parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").unwrap();

  // §8.8.2.2 makes a Last-Modified implicitly weak. The default constructor
  // says so, and the safe half is the default: a false If-Range costs a 200,
  // an incorrectly true one costs correctness.
  let weak = Selected::present().with_last_modified(at).build();
  assert_eq!(weak.last_modified(), Some(at));
  assert!(!weak.last_modified_is_strong());

  let strong = Selected::present().with_strong_last_modified(at).build();
  assert_eq!(strong.last_modified(), Some(at));
  assert!(strong.last_modified_is_strong());
}

#[test]
fn the_last_call_wins() {
  let a = parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
  let b = parse_http_date(b"Sun, 06 Nov 1994 08:49:38 GMT").unwrap();
  let selected = Selected::present()
    .with_strong_last_modified(a)
    .with_last_modified(b)
    .build();
  assert_eq!(selected.last_modified(), Some(b));
  assert!(
    !selected.last_modified_is_strong(),
    "the second call replaced both fields"
  );
}

// The class question asked of this module's own opaque span: `opaque-tag` is
// handed back verbatim by `EntityTag::opaque_tag`, so what may be inside it?
// RFC 9110 §8.8.3's `etagc = %x21 / %x23-7E / obs-text` is the answer, and
// `parse` walks every byte against it — nothing here is unread. `refuses_what_
// the_grammar_refuses` already pins %x09 and %x7F from that predicate; the two
// line-break octets are pinned here because they are the ones a stored span
// could smuggle into a field section, and because a reader of this file should
// not have to derive them from a range that names neither.
#[test]
fn an_opaque_tag_cannot_carry_a_line_break() {
  for bad in [
    &b"\"a\rb\""[..],
    b"\"a\nb\"",
    b"\"a\r\nX-Evil: y\"",
    b"\"a\x00b\"",
  ] {
    assert!(EntityTag::parse(bad).is_err(), "{bad:?} must not parse");
  }
}
