//! Test fixture: every way one logical list-field value can be spelled on the
//! wire.
//!
//! RFC 9110 §5.2 makes the several lines of one field a single comma-joined
//! value and §5.3 lets a sender split a list across them; RFC 6455 §9.1 says so
//! again in its own words ("this header field MAY be split or combined across
//! multiple lines") and works the example. RFC 2616 §2.1's `#rule` — the ABNF
//! RFC 6455 states its grammars in, and RFC 822 §2.7's wording verbatim — adds
//! that "null elements are allowed, but do not contribute to the count of
//! elements present", which RFC 9110 §5.6.1.2
//! restates as a recipient MUST "parse and ignore a reasonable number of empty
//! list elements".
//!
//! So every group below is ONE value written several ways, and a reader that
//! gives two members of a group different verdicts is reading a distinction the
//! grammar does not make. That is the defect class these fixtures exist to
//! pin, in each of the three shapes it takes — a grammar disagreement, a
//! line-count disagreement, and a presence disagreement — always between a
//! gate and a reader that resolved the same field separately.
//!
//! The verdict a transport reaches is compared as a whole rather than
//! field-by-field, so a divergence anywhere in the outcome fails the test.

use std::{string::String, vec, vec::Vec};

/// Every spelling of the one-element list `a`.
pub(crate) fn one(a: &str) -> Vec<Vec<String>> {
  vec![
    vec![a.into()],
    // The implied *LWS around an element (RFC 2616 §2.1, imported by §9.1).
    vec![format!("  {a}\t")],
    // Null elements before, after, and on both sides of the real one.
    vec![format!(",{a}")],
    vec![format!("{a},")],
    vec![format!(" , {a} , ")],
    // The same nulls as separate field lines, which the join turns into the
    // spellings above.
    vec![String::new(), a.into()],
    vec![a.into(), String::new()],
    vec![String::new(), String::new(), a.into(), String::new()],
    vec![",".into(), a.into(), " , ".into()],
  ]
}

/// Every spelling of the two-element list `a, b`, in that order.
pub(crate) fn two(a: &str, b: &str) -> Vec<Vec<String>> {
  vec![
    vec![format!("{a}, {b}")],
    vec![format!("{a},{b}")],
    vec![format!("  {a} ,\t{b}  ")],
    // RFC 6455 §9.1's own worked example: one line each.
    vec![a.into(), b.into()],
    vec![format!("{a},"), b.into()],
    vec![String::new(), format!("{a}, {b}")],
    vec![format!("{a}, {b}"), String::new()],
    vec![format!(" , {a} , , {b} , ")],
    vec![
      String::new(),
      a.into(),
      String::new(),
      b.into(),
      String::new(),
    ],
  ]
}

/// Every spelling of a field that is PRESENT and names nothing.
///
/// A different logical value from an absent field and from any list above:
/// RFC 2616 §2.1 — RFC 822 §2.7's `#rule`, verbatim — requires "at least one
/// non-null element" wherever a `1#`
/// appears, and RFC 9110 §5.6.1.2 gives `""`, `","` and `",   ,"` as its own
/// examples of values that do not satisfy one.
pub(crate) fn nothing() -> Vec<Vec<String>> {
  vec![
    vec![String::new()],
    vec![" ".into()],
    vec!["\t".into()],
    vec![",".into()],
    vec![" , ".into()],
    vec![",,,".into()],
    vec![String::new(), String::new()],
    vec![String::new(), ",".into(), " ".into()],
  ]
}

/// Asserts that every spelling in `group` reaches the identical verdict, and
/// reports the two that disagreed when one does not.
pub(crate) fn agree<F>(what: &str, group: &[Vec<String>], verdict: F) -> String
where
  F: Fn(&[&str]) -> String,
{
  let mut answers: Vec<(Vec<String>, String)> = Vec::new();
  for spelling in group {
    let borrowed: Vec<&str> = spelling.iter().map(String::as_str).collect();
    answers.push((spelling.clone(), verdict(&borrowed)));
  }
  let Some((first_spelling, first)) = answers.first() else {
    panic!("{what}: no spellings to compare")
  };
  for (spelling, answer) in &answers {
    assert_eq!(
      answer, first,
      "{what}: {spelling:?} and {first_spelling:?} are the same field value, \
       but the transport answered {answer:?} and {first:?}"
    );
  }
  first.clone()
}
