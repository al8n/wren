//! RFC 9110 §8.8's validators, and the representation they describe.
//!
//! §8.8 defines two kinds of validator. The modification date is
//! [`crate::date::HttpDate`]; the entity tag is [`EntityTag`], with both of
//! §8.8.3.2's comparison functions beside it and the `"*" / #entity-tag` list
//! [`TagList`] reads for §13.1.1's `If-Match` and §13.1.2's `If-None-Match`.
//!
//! Which comparison a field takes is a MUST rather than a preference, and the
//! two are not interchangeable: §13.1.1 puts the strong function on `If-Match`,
//! §13.1.2 the weak one on `If-None-Match`, and §13.1.5 the strong one again on
//! `If-Range`'s tag form. Both are supplied here and each says which fields it
//! is for; wiring a field to the wrong one is a defect this module cannot see,
//! which is why the rule is written down at both ends.
//!
//! [`Selected`] is the other half: the representation those validators belong
//! to, as a precondition sees it. It is built through [`Selected::absent`] or
//! [`Selected::present`], and every validator lives on [`Present`] — so a
//! representation that does not exist has no method that could attach one. §8.8
//! decides what a validator IS; §13 decides what a precondition does with it,
//! and the value it does that to is assembled here.
//!
//! # Why this walks its own list
//!
//! The crate has two list walkers already, and `#entity-tag` can use neither.
//!
//! [`crate::grammar::list_elements`] splits on raw commas, and `etagc` admits
//! one between the DQUOTEs (`%x2C` is inside `%x23-7E`), so it reads the single
//! tag `"a,b"` as two elements that are each malformed.
//!
//! [`crate::grammar::parameterised_list`] is quote-aware in the wrong sense: it
//! implements §5.6.4's `quoted-string`, which has `quoted-pair`, and §8.8.3's
//! `opaque-tag` has none. A backslash is an ordinary `etagc`, so `"a\"` is one
//! valid tag whose content is `a\` — and a `quoted-string` reader takes that
//! DQUOTE for escaped data and runs off the end of the value, refusing a live
//! lost-update guard as malformed. §8.8.3's own note names backslash unescaping
//! as what some recipients inherited from RFC 2616, so reproducing it here would
//! be building the legacy bug on purpose. Its members also open with a token
//! name, and an `entity-tag` opens with a DQUOTE or with `W/`.
//!
//! The walk here therefore splits on a comma outside the DQUOTEs and processes
//! no escape between them: a different grammar, not a configuration of an
//! existing walker. What does not come along with it is §5.6.1.2's
//! empty-element MUST, which [`crate::grammar::list_elements`] holds for the
//! RECIPIENT list consumers whose elements it can delimit. [`TagList::parse`]
//! carries that rule across explicitly and is tested for it here. What bounds the
//! *reasonable number* the same sentence asks for is not [`MAX_TAGS`], which is
//! a different bound answering a different question — that constant says which.
// gate-exempt: crate::grammar::list_elements — named for contrast twice over: the
// walker this module cannot route through, and the entrance the crate holds
// §5.6.1.2's empty-element rule at for every RECIPIENT list it can delimit,
// which is why that rule is carried across here rather than inherited.
// gate-exempt: crate::grammar::parameterised_list — named for contrast: the other
// walker this module cannot route through, because it reads §5.6.4's
// `quoted-string` and `opaque-tag` has no `quoted-pair`.

use crate::{date::HttpDate, grammar::trim_ows};

/// How many entity tags a [`TagList`] holds.
///
/// RFC 9110 §5.6.1.2 opens: "Empty elements do not contribute to the count of
/// elements present." — so an empty element spends no slot here either, and this
/// bounds the real tags alone.
///
/// It is NOT what supplies the *reasonable number* the next sentence of
/// §5.6.1.2 asks for; the two clauses answer different questions. That sentence
/// governs EMPTY elements — a recipient is to accept enough of them to handle
/// the senders that merge values, but "not so much that they could be used as a
/// denial-of-service mechanism" — while this bounds real tags, refusing past
/// them with [`TagError::TooMany`]. The empty elements accepted here are
/// **unbounded**, which is exactly what `a_comma_flood_is_not_too_many_tags`
/// pins. What holds that cost down is not a count: an empty element spends no
/// slot and no byte, the walk is linear over a field value the transport layer
/// has already bounded, and this crate holds no buffer of its own — a Sans-I/O
/// core cannot be flooded by a value someone else already decided to keep.
///
/// Sixteen, and the measurement behind the number is the storage: a slot is an
/// `Option<EntityTag>`, 24 bytes on a 64-bit target, so the array is 384 of a
/// [`TagList`]'s 400 bytes — the size the assertions below pin, since it is
/// what a caller holding one on the stack pays. The fields it bounds are a
/// client's list of the validators it already holds for one resource; a browser
/// sends one, and a cache revalidating several stored variants sends a handful,
/// so sixteen is far above the shapes that occur and still small enough to keep
/// the value out of the heap this crate does not have.
///
/// Overflow is a refusal rather than a truncation, and that is the whole reason
/// there is a bound rather than a cap: judging a precondition from the tags that
/// fit could find no match, answer as though the client sent none of the others,
/// and silently void the guard.
///
/// A parse-constant rather than a caller-set knob: the storage is in the binary,
/// so a caller cannot raise it.
pub const MAX_TAGS: usize = 16;

// What the slot count costs, checked at module scope so that every `cargo
// check` on every tier enforces it. A `#[test]` would assert it only where a
// test harness runs, which is every tier EXCEPT `thumbv6m-none-eabi` — the one
// this number is written down for, where 400 bytes of stack is most of the
// budget. (`http1-proto`'s `Connection` assertion is written against the same
// argument.)
//
// The figures are the compiler's own, and these assertions are the command that
// takes them:
//
//   cargo check -p http-semantics --all-features
//   cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi
//
// On a 64-bit target a slot is a `bool` and a fat pointer, with `Option`'s
// discriminant in the pointer's null niche: 24 bytes, so the array is 384 and
// `len` plus `star` round `TagList` to the 400 `MAX_TAGS` states. On a 32-bit
// one, 12 and 200. Both widths are pinned rather than bounded, because a bound
// set well above a value asserts nothing about it.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Option<EntityTag<'_>>>() == 24);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<TagList<'_>>() == 400);

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<Option<EntityTag<'_>>>() == 12);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<TagList<'_>>() == 200);

/// Why an entity tag, or a list of them, could not be read.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TagError {
  /// Not RFC 9110 §8.8.3's `entity-tag = [ weak ] opaque-tag`: no DQUOTEs, an
  /// unterminated one, a byte `etagc` excludes, a lowercase `w/`, or anything
  /// left over behind the closing DQUOTE.
  #[error("not a valid entity-tag")]
  Malformed,
  /// `*` arrived alongside another value. RFC 9110 §13.1.1 and §13.1.2 close
  /// with the same note: "a list value containing `*` and other values
  /// (including other instances of `*`) is syntactically invalid".
  #[error("`*` alongside other values is syntactically invalid")]
  StarInList,
  /// More entity tags than [`MAX_TAGS`], which is a refusal and not a cap — see
  /// that constant for why the list is not simply truncated.
  #[error("more entity tags than this recipient holds")]
  TooMany,
}

/// RFC 9110 §8.8.3's `entity-tag = [ weak ] opaque-tag`.
///
/// Not `PartialEq`, deliberately. §8.8.3.2 defines TWO equivalences over this
/// type, a derived `==` would be a third one that is neither, and the choice
/// between them is a MUST at every site that compares tags. A caller picks
/// [`strong_eq`](Self::strong_eq) or [`weak_eq`](Self::weak_eq) and says which
/// section put it there.
#[derive(Debug, Copy, Clone)]
pub struct EntityTag<'a> {
  /// Whether `weak = %s"W/"` prefixed the `opaque-tag`.
  weak: bool,
  /// The `*etagc` between the DQUOTEs, verbatim.
  opaque: &'a [u8],
}

impl<'a> EntityTag<'a> {
  /// Reads RFC 9110 §8.8.3's `entity-tag` from one whole list member.
  ///
  /// `value` must already have §5.6.3's OWS off it and must be the entire tag: a
  /// byte behind the closing DQUOTE is a fault rather than a tail to ignore.
  /// [`TagList::parse`] trims each element before calling this.
  ///
  /// `*etagc` admits ZERO bytes, so the empty tag parses — `ETag: ""` is one of
  /// §8.8.3's own printed examples, and a parser demanding one byte refuses it.
  ///
  /// # Errors
  ///
  /// [`TagError::Malformed`] when `value` is not `[ weak ] opaque-tag`.
  pub const fn parse(value: &'a [u8]) -> Result<Self, TagError> {
    // `weak = %s"W/"`. RFC 5234 §2.3 makes a bare string literal
    // case-INsensitive and RFC 7405's `%s` prefix is what turns that off, and
    // §8.8.3 says the same thing again in prose: the origin server "MUST mark the
    // entity tag as weak by prefixing its opaque value with `W/`
    // (case-sensitive)." So a lowercase `w/` is not a weakness marker, and it
    // leaves a value that is not an `entity-tag` at all.
    let (weak, rest) = match value {
      [b'W', b'/', rest @ ..] => (true, rest),
      other => (false, other),
    };
    // `opaque-tag = DQUOTE *etagc DQUOTE`. The pattern needs two bytes, so a
    // lone DQUOTE does not match it, and `""` yields an empty `inner`.
    let [b'"', inner @ .., b'"'] = rest else {
      return Err(TagError::Malformed);
    };
    let mut tail = inner;
    while let Some((&byte, rest)) = tail.split_first() {
      if !is_etagc(byte) {
        return Err(TagError::Malformed);
      }
      tail = rest;
    }
    Ok(Self {
      weak,
      opaque: inner,
    })
  }

  /// Whether the tag arrived with §8.8.3's `weak` marker.
  #[inline]
  pub const fn is_weak(&self) -> bool {
    self.weak
  }

  /// The `*etagc` between the DQUOTEs, verbatim — never unescaped.
  ///
  /// `opaque-tag` has no `quoted-pair`, so there is nothing to unescape: a
  /// backslash is an ordinary `etagc` and belongs to the value. §8.8.3's note
  /// names backslash unescaping as what recipients carried over from RFC 2616's
  /// `quoted-string` definition, and a recipient that did it here would compare
  /// a tag the sender never sent.
  #[inline]
  pub const fn opaque_tag(&self) -> &'a [u8] {
    self.opaque
  }

  /// RFC 9110 §8.8.3.2's strong comparison: "two entity tags are equivalent if
  /// both are not weak and their opaque-tags match character-by-character."
  ///
  /// The function §13.1.1 requires of an origin server for `If-Match`, and
  /// §13.1.5 for `If-Range`'s entity-tag form.
  #[inline]
  pub const fn strong_eq(&self, other: &Self) -> bool {
    !self.weak && !other.weak && same_opaque_tag(self.opaque, other.opaque)
  }

  /// RFC 9110 §8.8.3.2's weak comparison: "two entity tags are equivalent if
  /// their opaque-tags match character-by-character, regardless of either or
  /// both being tagged as `weak`."
  ///
  /// The function §13.1.2 requires of a recipient for `If-None-Match`.
  #[inline]
  pub const fn weak_eq(&self, other: &Self) -> bool {
    same_opaque_tag(self.opaque, other.opaque)
  }
}

/// The `"*" / #entity-tag` value RFC 9110 §13.1.1's `If-Match` and §13.1.2's
/// `If-None-Match` carry, read into [`MAX_TAGS`] slots.
///
/// `*` and the tags are exclusive alternatives, so [`is_star`](Self::is_star)
/// and a non-empty list never both hold: a value carrying both is refused as
/// [`TagError::StarInList`].
#[derive(Debug, Copy, Clone)]
pub struct TagList<'a> {
  /// The tags, in the order the value listed them, `None` past [`Self::len`].
  tags: [Option<EntityTag<'a>>; MAX_TAGS],
  /// How many of `tags` are `Some`.
  len: usize,
  /// Whether the value was `*`.
  star: bool,
}

impl<'a> TagList<'a> {
  /// Reads a whole `If-Match` or `If-None-Match` field value.
  ///
  /// Elements are split on a comma OUTSIDE the DQUOTEs — a comma between them is
  /// `etagc` and belongs to the tag — with no escape processing inside, and each
  /// element is OWS-trimmed before [`EntityTag::parse`] reads it.
  ///
  /// Empty elements are parsed and ignored, spending no slot, per RFC 9110
  /// §5.6.1.2's recipient form `#element => [ element ] *( OWS "," OWS
  /// [ element ] )`. That form also admits a list of no elements at all, which
  /// Appendix A spells out for both fields as
  /// `"*" / [ entity-tag *( OWS "," OWS entity-tag ) ]`, so an empty value is an
  /// empty list rather than a fault.
  ///
  /// # Errors
  ///
  /// [`TagError::Malformed`] when an element is not an `entity-tag`,
  /// [`TagError::StarInList`] when `*` appears beside any other value, and
  /// [`TagError::TooMany`] past [`MAX_TAGS`] tags. A fault anywhere refuses the
  /// whole value: answering a precondition from the elements that did parse
  /// would answer over a value the client did not send.
  pub fn parse(value: &'a [u8]) -> Result<Self, TagError> {
    let mut list = Self {
      tags: [None; MAX_TAGS],
      len: 0,
      star: false,
    };
    let mut at = 0;
    loop {
      let (element, next) = next_element(value, at);
      if !element.is_empty() {
        list.push(element)?;
      }
      match next {
        Some(after_comma) => at = after_comma,
        None => return Ok(list),
      }
    }
  }

  /// Whether the value was `*` rather than a list of tags.
  #[inline]
  pub const fn is_star(&self) -> bool {
    self.star
  }

  /// How many entity tags the value carried.
  ///
  /// `*` is not one of them and neither is an empty list element, so this is
  /// zero for both `*` and an empty value.
  #[inline]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Whether the value carried no entity tag — true for `*` and for the empty
  /// value Appendix A's `[ entity-tag *( OWS "," OWS entity-tag ) ]` admits.
  #[inline]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// The `index`th entity tag in the order the value listed them, or `None`
  /// past the last one.
  #[inline]
  pub fn get(&self, index: usize) -> Option<EntityTag<'a>> {
    self.tags.get(index).copied().flatten()
  }

  /// Records one non-empty element.
  fn push(&mut self, element: &'a [u8]) -> Result<(), TagError> {
    // RFC 9110 §13.1.1 and §13.1.2 both close by naming a value that carries `*`
    // beside other values syntactically invalid, INCLUDING other instances of
    // `*`. The check precedes the parse in both directions because `*` is not an
    // `entity-tag`, so a star behind a tag would otherwise be reported as merely
    // malformed and the caller would never learn which fault it was.
    if matches!(element, [b'*']) {
      if self.star || !self.is_empty() {
        return Err(TagError::StarInList);
      }
      self.star = true;
      return Ok(());
    }
    if self.star {
      return Err(TagError::StarInList);
    }
    let tag = EntityTag::parse(element)?;
    // The slot lookup IS the bound: `None` means this tag is the
    // `MAX_TAGS + 1`th, which is the refusal that constant documents.
    let Some(slot) = self.tags.get_mut(self.len) else {
      return Err(TagError::TooMany);
    };
    *slot = Some(tag);
    self.len = self.len.saturating_add(1);
    Ok(())
  }
}

/// RFC 9110 §8.8.3's `etagc = %x21 / %x23-7E / obs-text`: what may sit between
/// an `opaque-tag`'s DQUOTEs.
///
/// `%x22` is the one VCHAR left out, and leaving it out is what lets the tag end
/// without an escape mechanism — which is why there is no `quoted-pair` to
/// process and why a backslash is content.
///
/// `obs-text` (`%x80-FF`) is admitted on §8.8.3's authority. Appendix A's
/// collected grammar spells the same rule `etagc = "!" / %x23-7E` and drops
/// `obs-text`; no erratum settles the disagreement, so the body text governs.
/// A recipient refusing a byte the sender was allowed to send would refuse the
/// guard the tag exists to carry. (`%x21` and `"!"` are the same character; that
/// half of the difference is only spelling.)
#[inline]
const fn is_etagc(byte: u8) -> bool {
  matches!(byte, 0x21 | 0x23..=0x7E | 0x80..=0xFF)
}

/// Whether two `opaque-tag`s match RFC 9110 §8.8.3.2's way: character-by-
/// character, and so case-SENSITIVELY.
///
/// [`crate::grammar::eq_ignore_ascii`] is the crate's other byte-string equality
/// and is the wrong one here, because it folds ASCII case. §8.8.3.1: "Since the
/// value is opaque, there is no need for the client to be aware of how each
/// entity tag is constructed." — nothing licenses a recipient to decide that two
/// spellings of an opaque octet sequence are one validator.
#[inline]
const fn same_opaque_tag(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  let (mut a, mut b) = (a, b);
  while let (Some((&x, a_rest)), Some((&y, b_rest))) = (a.split_first(), b.split_first()) {
    if x != y {
      return false;
    }
    a = a_rest;
    b = b_rest;
  }
  true
}

/// The list element beginning at `at`, OWS-trimmed, and where the element after
/// its comma begins — `None` when this element ran to the end of the value.
///
/// The split is on a comma outside the DQUOTEs. Inside them every byte is
/// content until the next DQUOTE, with no escape processing: `opaque-tag` has no
/// `quoted-pair`, so nothing suppresses a DQUOTE and a backslash before one is
/// ordinary `etagc`. An unterminated span therefore swallows the rest of the
/// value, which [`EntityTag::parse`] then refuses as one malformed element —
/// the alternative, resynchronising on the next comma, would invent elements the
/// sender did not delimit.
fn next_element(value: &[u8], at: usize) -> (&[u8], Option<usize>) {
  let mut end = at;
  let mut quoted = false;
  loop {
    let Some(&byte) = value.get(end) else {
      return (trimmed_element(value, at, end), None);
    };
    match byte {
      b'"' => quoted = !quoted,
      b',' if !quoted => {
        return (trimmed_element(value, at, end), Some(end.saturating_add(1)));
      }
      _ => {}
    }
    end = end.saturating_add(1);
  }
}

/// `value[at..end]` with RFC 9110 §5.6.3's OWS off both ends, and empty if that
/// is not a range of `value` — which cannot happen, since both ends come from a
/// walk of `value` itself.
#[inline]
fn trimmed_element(value: &[u8], at: usize, end: usize) -> &[u8] {
  trim_ows(value.get(at..end).unwrap_or_default())
}

/// The selected representation a precondition is evaluated against.
///
/// Built through [`Selected::absent`] or [`Selected::present`]. Every validator
/// lives on [`Present`], so a representation that does not exist has no method
/// that could attach one: RFC 9110 §13.1.1's `*` form is "true if the origin
/// server has a current representation for the target resource", and a resource
/// that has none has no entity tag and no `Last-Modified` for it either.
///
/// The rule is the type's rather than this paragraph's. A plain struct carrying
/// the same constructors would still let `Selected::absent()` be handed a
/// validator, and a rule stated only in prose about a type that admits its own
/// violation is a rule someone has to remember.
#[derive(Debug, Copy, Clone)]
pub struct Selected<'a> {
  /// Whether the target resource has a current representation at all — the one
  /// fact §13.1.1's and §13.1.2's `*` forms ask about.
  exists: bool,
  /// §8.8.3's entity tag for it, when the application holds one.
  etag: Option<EntityTag<'a>>,
  /// §8.8.2's `Last-Modified` for it, when the application holds one.
  last_modified: Option<HttpDate>,
  /// Whether the application asserts that `last_modified` is strong per
  /// §8.8.2.2. Written by the same call that writes `last_modified`, never on
  /// its own, so the pair cannot drift apart.
  last_modified_strong: bool,
  /// The complete length of the representation data, when the application
  /// holds it — what §14.1.2's satisfiability and normalisation rules measure
  /// a byte range against.
  complete_length: Option<u64>,
}

impl<'a> Selected<'a> {
  /// No current representation. `If-Match: *` is false, `If-None-Match: *` is
  /// true.
  ///
  /// The one constructor with no validators to attach, because there is nothing
  /// for a validator to describe.
  #[must_use]
  pub const fn absent() -> Self {
    Self {
      exists: false,
      etag: None,
      last_modified: None,
      last_modified_strong: false,
      complete_length: None,
    }
  }

  /// Begins describing a representation that exists.
  ///
  /// The validators attach to the returned [`Present`], and
  /// [`Present::build`] finishes.
  #[must_use]
  pub const fn present() -> Present<'a> {
    Present {
      inner: Self {
        exists: true,
        etag: None,
        last_modified: None,
        last_modified_strong: false,
        complete_length: None,
      },
    }
  }

  /// Whether the target resource has a current representation.
  ///
  /// §13.1.1's `*` form is true exactly when this is, and §13.1.2's is its
  /// negation: false if the origin server has a current representation.
  #[must_use]
  pub const fn exists(&self) -> bool {
    self.exists
  }

  /// The representation's entity tag, or `None` when the application supplied
  /// none.
  ///
  /// Which of §8.8.3.2's two comparisons to make against it is the comparing
  /// FIELD's rule, not this value's — [`EntityTag::strong_eq`] and
  /// [`EntityTag::weak_eq`] each say which sections put them where.
  #[must_use]
  pub const fn etag(&self) -> Option<EntityTag<'a>> {
    self.etag
  }

  /// The representation's `Last-Modified`, or `None` when the application
  /// supplied none.
  #[must_use]
  pub const fn last_modified(&self) -> Option<HttpDate> {
    self.last_modified
  }

  /// Whether the application asserted that [`Self::last_modified`] is strong in
  /// §8.8.2.2's sense.
  ///
  /// False when there is no `Last-Modified` at all, and false for one attached
  /// through [`Present::with_last_modified`] — §8.8.2.2 makes the value
  /// implicitly weak, and no deduction this crate can perform promotes it. The
  /// reader is §13.1.5's date-form `If-Range`, whose condition is false when
  /// the validator it was given is not a strong one.
  #[must_use]
  pub const fn last_modified_is_strong(&self) -> bool {
    self.last_modified_strong
  }

  /// The complete length of the representation data, or `None` when the
  /// application supplied none.
  ///
  /// Absent is not zero: a zero length is a representation with no content, and
  /// §14.1.2 answers a byte range against it differently from one it cannot
  /// measure at all.
  #[must_use]
  pub const fn complete_length(&self) -> Option<u64> {
    self.complete_length
  }
}

/// A representation that exists, under construction.
///
/// Every validator lives here. Each `with_*` replaces what a previous call set
/// — the last one wins, and there is no accumulation to reason about.
#[derive(Debug, Copy, Clone)]
pub struct Present<'a> {
  /// The value being described, with `exists` already true.
  inner: Selected<'a>,
}

impl<'a> Present<'a> {
  /// The representation's RFC 9110 §8.8.3 entity tag.
  ///
  /// One tag, not a [`TagList`]: §8.8.3 gives the selected representation a
  /// single current entity tag, and the list form is what a REQUEST carries.
  #[must_use]
  pub const fn with_etag(mut self, etag: EntityTag<'a>) -> Self {
    self.inner.etag = Some(etag);
    self
  }

  /// A `Last-Modified` the origin server has **not** determined to be strong.
  ///
  /// RFC 9110 §8.8.2.2 makes a `Last-Modified` used as a request validator
  /// "implicitly weak unless it is possible to deduce that it is strong", and
  /// it gives three ways to deduce it, not one:
  ///
  /// 1. an origin server comparing the validator against the current one, which
  ///    "reliably knows that the associated representation did not change twice
  ///    during the second covered by the presented validator";
  /// 2. a client about to use it in an `If-Modified-Since`,
  ///    `If-Unmodified-Since`, or `If-Range` field, whose cache entry for the
  ///    representation "includes a Date value which is at least one second
  ///    after the Last-Modified value" and which has reason to believe one
  ///    clock generated both, or that the gap is wide enough to "make clock
  ///    synchronization issues unlikely";
  /// 3. an intermediate cache comparing the validator against its own cache
  ///    entry, under that same Date arithmetic and that same belief.
  ///
  /// The first is a fact only the application holds. The other two are half
  /// arithmetic — `Date` at least a second after `Last-Modified`, which this
  /// crate could compute if it were handed a `Date` — and half judgement, which
  /// it could not. There is no `Date`-taking constructor on purpose: computing
  /// the arithmetic half would read as having checked the rule, and the
  /// judgement half is the half that makes the deduction sound. So strength
  /// arrives asserted — see [`Present::with_strong_last_modified`].
  ///
  /// Weak is the default because it is the safe half: a false `If-Range` costs
  /// a 200 response, an incorrectly true one costs correctness.
  #[must_use]
  pub const fn with_last_modified(mut self, at: HttpDate) -> Self {
    self.inner.last_modified = Some(at);
    self.inner.last_modified_strong = false;
    self
  }

  /// A `Last-Modified` the origin server asserts is strong per RFC 9110
  /// §8.8.2.2.
  ///
  /// The assertion is the application's, under whichever of §8.8.2.2's three
  /// rules it holds the facts for — [`Present::with_last_modified`] lists them,
  /// and the first and third are the two a recipient evaluating a precondition
  /// can be in a position to use. This crate records the assertion and checks
  /// none of it: the first rule is knowledge only the origin server has, and
  /// the other two turn on a belief about clocks that a Sans-I/O core has no
  /// way to form.
  #[must_use]
  pub const fn with_strong_last_modified(mut self, at: HttpDate) -> Self {
    self.inner.last_modified = Some(at);
    self.inner.last_modified_strong = true;
    self
  }

  /// The complete length of the selected representation.
  ///
  /// RFC 9110 §14.1.2 calculates every byte range with respect to the bytes as
  /// sent: if the representation data has a content coding applied, "each byte
  /// range is calculated with respect to the encoded sequence of bytes, not the
  /// sequence of underlying bytes that would be obtained after decoding". So
  /// this is the length of the representation data as §8.1 defines it — after
  /// any `Content-Encoding`, not the length of the underlying resource.
  #[must_use]
  pub const fn with_complete_length(mut self, len: u64) -> Self {
    self.inner.complete_length = Some(len);
    self
  }

  /// Finishes the description.
  #[must_use]
  pub const fn build(self) -> Selected<'a> {
    self.inner
  }
}

#[cfg(test)]
mod tests;
