//! RFC 9110 §14.1's `ranges-specifier`, and the three derivations §14.1.2
//! settles over one.

use super::RangeError;
use crate::grammar::{eq_ignore_ascii, is_token, list_elements, skip_ows};

/// How many `range-spec`s a [`RangesSpecifier`] holds.
///
/// RFC 9110 bounds `range-set = 1#range-spec` nowhere, so this is a bound of the
/// STORAGE rather than of the grammar: the specs live in a fixed array, and a
/// value carrying more yields [`RangeError::TooManySpecs`] rather than the ones
/// that fit.
///
/// **Overflow here is an ignore, and that is why the number is small.** §14.2
/// says outright that "A server MAY ignore the Range header field", so a
/// recipient that cannot hold the set answers 200 with the whole
/// representation — a sanctioned response, and the one the client would have
/// got had it never sent the field. Contrast [`crate::validator::MAX_TAGS`],
/// where overflow would void a precondition the client sent and no status the
/// RFC names fits; that bound has to be generous, and this one does not.
///
/// Eight, and the shapes it holds are the ones that occur: §14.1.2's own
/// largest printed example asks for three (`bytes= 0-999, 4500-5499, -1000`),
/// resuming an interrupted transfer asks for one, and §14.2 tells a client it
/// "SHOULD NOT request multiple ranges that are inherently less efficient to
/// process and transfer than a single range that encompasses the same data".
/// The shape this deliberately does not hold is the one §14.2 names as an
/// attack — "a set of many small ranges that are not listed in ascending
/// order" — and refusing to hold it is the point.
///
/// Empty elements spend no slot: §5.6.1.2 makes a recipient ignore them, and
/// [`crate::grammar::list_elements`] drops them before this array is reached.
/// So this bounds real `range-spec`s alone, and the empties are unbounded for
/// the reason [`crate::validator::MAX_TAGS`] gives at length — an empty costs
/// no slot and no byte, over a field value the transport layer has already
/// bounded.
///
/// A parse-constant rather than a caller-set knob: the storage is in the
/// binary, so a caller cannot raise it.
pub const MAX_RANGE_SPECS: usize = 8;

// What the slot count costs, checked at module scope so that every `cargo
// check` on every tier enforces it — a `#[test]` would assert it only where a
// test harness runs, which is every tier EXCEPT `thumbv6m-none-eabi`, the one
// this number is written down for. (`crate::validator`'s `TagList` assertions
// are written against the same argument.)
//
// The figures are the compiler's own, and these assertions are the command that
// takes them:
//
//   cargo check -p http-semantics --all-features
//   cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi
//
// A `Pos` is a discriminant beside a `u64`: 16 bytes on either width, with the
// discriminant's remaining values a niche, so `Option<Pos>` is 16 too. A
// `RangeSpec` is its larger variant, `Int`'s `Pos` beside an `Option<Pos>` — 32
// — with `Suffix` and then `Option`'s own `None` folded into the niche that
// `Option<Pos>` still leaves. So a slot is 32 bytes rather than the 40 a
// separate discriminant would cost, and eight of them are 256. The unit slice,
// the `other_range_set` slice and `len` round `RangesSpecifier` to 296 on a
// 64-bit target and 280 on a 32-bit one. Both widths are pinned rather than
// bounded, because a bound set well above a value asserts nothing about it.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Option<Pos>>() == 16);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Option<RangeSpec>>() == 32);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<RangesSpecifier<'_>>() == 296);

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<Option<Pos>>() == 16);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<Option<RangeSpec>>() == 32);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<RangesSpecifier<'_>>() == 280);

/// A `first-pos`, `last-pos` or `suffix-length` as written.
///
/// `Beyond` is a numeral no `u64` holds. RFC 9110 §14.1.2 closes with a MUST:
/// "recipients MUST anticipate potentially large decimal numerals and prevent
/// parsing errors due to integer conversion overflows". This design meets it by
/// never performing the conversion, which leaves every §14.1.2 rule total: a
/// `Beyond` first-pos is at or above every possible length, so the int-range is
/// unsatisfiable; a `Beyond` last-pos is "greater than or equal to the current
/// length of the representation data", which is already §14.1.2's own
/// normalisation condition; and a `Beyond` suffix-length exceeds every
/// representation, so it takes the whole of it.
///
/// **Validity is not decided from this type.** §14.1.1's "An int-range is
/// invalid if the last-pos value is present and less than the first-pos" is
/// settled at [`RangesSpecifier::parse`], by comparing the two numerals as
/// digit strings while the digits are still in hand — `Beyond` deliberately
/// keeps none.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Pos {
  /// A numeral a `u64` holds.
  Exact(u64),
  /// A numeral larger than any `u64`.
  Beyond,
}

/// One `range-spec`, unresolved.
///
/// The two forms RFC 9110 §14.1.2 defines for the `bytes` unit; the third the
/// generic grammar admits is `other-range`, and §14.1.2 says "Byte ranges do not
/// use the other-range specifier", so a `bytes` range-set carrying one is
/// invalid rather than opaque. A range-set under any other unit is kept whole by
/// [`RangesSpecifier::other_range_set`] and never reaches this type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RangeSpec {
  /// `int-range = first-pos "-" [ last-pos ]`.
  Int {
    /// The `first-pos`.
    first: Pos,
    /// The `last-pos`, absent when the range runs to the end.
    last: Option<Pos>,
  },
  /// `suffix-range = "-" suffix-length`.
  Suffix {
    /// The `suffix-length`.
    length: Pos,
  },
}

/// What a `range-spec` resolves to against a complete length.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Resolved {
  /// The inclusive first and last byte positions to send.
  Range(u64, u64),
  /// RFC 9110 §14.1.2: this range-spec is unsatisfiable against this length.
  Unsatisfiable,
  /// Satisfiable, and yet there are no positions.
  ///
  /// RFC 9110 §14.1.2 leaves a non-zero suffix-range satisfiable against a
  /// zero-length representation, and the whole of an empty representation has
  /// no inclusive positions — §14.4 can express no `Content-Range` for it
  /// either, since its own validity rule refuses a `complete-length` less than
  /// or equal to the `last-pos`. §14.2's "server that supports range requests
  /// MAY ignore a Range header field when the selected representation has no
  /// content (i.e., the selected representation's data is of zero length)" is
  /// the sanctioned exit.
  EmptyRepresentation,
}

/// RFC 9110 §14.1.1's `ranges-specifier`, the whole value of a `Range` field.
///
/// ```text
/// ranges-specifier = range-unit "=" range-set
/// range-set        = 1#range-spec
/// range-spec       = int-range
///                  / suffix-range
///                  / other-range
/// int-range     = first-pos "-" [ last-pos ]
/// first-pos     = 1*DIGIT
/// last-pos      = 1*DIGIT
/// suffix-range  = "-" suffix-length
/// suffix-length = 1*DIGIT
/// other-range   = 1*( %x21-2B / %x2D-7E )
///               ; 1*(VCHAR excluding comma)
/// ```
///
/// **The production this parses is the corrected one.** RFC 9110 erratum 7306,
/// Verified, makes it `ranges-specifier = range-unit "=" OWS range-set`; the
/// reporter's note is that the `OWS` was lost when the grammar was converted
/// away from implied linear whitespace. §14.1.2's own printed example
/// `bytes= 0-999, 4500-5499, -1000` carries that space, so under the printed
/// production the RFC's own example is malformed and under the corrected one it
/// is grammar.
// gate-exempt: ranges-specifier = range-unit "=" OWS range-set — erratum 7306's corrected production, which by construction is not the one RFC 9110 prints
///
/// **Validity is settled here and satisfiability is not.** §14.1.1: "A
/// ranges-specifier is invalid if it contains any range-spec that is invalid or
/// undefined for the indicated range-unit." That is a property of the value
/// alone, so it is decided at [`parse`](Self::parse) and one bad spec fails the
/// whole set. Satisfiability and both normalisations need the complete length of
/// the selected representation, which arrives at
/// [`resolve`](Self::resolve) instead.
///
/// **No `PartialEq`, and the omission is the design.** The exposure is
/// [`ContentRange`](super::ContentRange)'s, on the request side: a derive would
/// compare [`unit`](Self::unit) byte for byte, and §14.1's "All range unit names
/// are case-insensitive" makes `bytes=0-499` and `BYTES=0-499` one value — which
/// this type stores as two, on purpose, because normalising the unit would lose
/// what was received. A hand-written one would then have to answer for the span
/// [`other_range_set`](Self::other_range_set) hands back, and there it would be
/// guessing: §14.1.1 says "The range unit name determines what kinds of
/// range-spec are applicable to its own specifiers", so whether two range-sets
/// under a unit this crate does not implement denote the same ranges is that
/// unit's question and not this crate's. [`RangeSpec`] does derive it, since its
/// own contents are §14.1.2's positions and nothing else. A caller that needs
/// equality over the whole value compares [`unit`](Self::unit) with
/// `eq_ignore_ascii_case` and then the accessors it cares about.
#[derive(Debug, Copy, Clone)]
pub struct RangesSpecifier<'a> {
  /// The `range-unit` exactly as the sender wrote it.
  unit: &'a [u8],
  /// The `bytes` range-specs in the order the value listed them, `None` past
  /// [`Self::len`]. Empty for a unit other than `bytes`.
  specs: [Option<RangeSpec>; MAX_RANGE_SPECS],
  /// How many of `specs` are `Some`.
  len: usize,
  /// The whole range-set, verbatim, when the unit is not `bytes`.
  other: Option<&'a [u8]>,
}

impl<'a> RangesSpecifier<'a> {
  /// Reads a whole `Range` field value.
  ///
  /// The `range-unit` is matched against `bytes` with ASCII case-insensitivity,
  /// because RFC 9110 §14.1 says "All range unit names are case-insensitive" —
  /// matching the token exactly would send `Range: BYTES=0-499` to the
  /// not-bytes path and answer 200 where a 206 was waiting.
  /// [`unit`](Self::unit) still returns the sender's own bytes, since
  /// normalising them would lose what was received.
  ///
  /// A unit other than `bytes` is read as an opaque span: §14.1.1 makes it the
  /// range unit that "determines what kinds of range-spec are applicable to its
  /// own specifiers", and only that unit's own specification can say. The
  /// range-set is kept whole by [`other_range_set`](Self::other_range_set) and
  /// no `range-spec` is derived from it.
  ///
  /// **Opaque to this crate is not unconstrained.** What §14.1.1 delegates is
  /// which `range-spec` FORMS a unit admits and what they mean; the octets a
  /// `range-spec` may be written in are the generic grammar's, and the same
  /// section prints them. `other-range = 1*( %x21-2B / %x2D-7E )` is the widest
  /// of the three forms — `int-range` and `suffix-range` are `1*DIGIT` and `-`,
  /// both inside that set — so every element of a range-set under every unit is
  /// `1*( %x21-2B / %x2D-7E )`, and this walk checks each one. §14.1.1 says
  /// itself that this is the extension point rather than a licence: "To provide
  /// for extensibility, the other-range rule is a mostly unconstrained grammar
  /// that allows application-specific or future range units to define
  /// additional range specifiers." Mostly, and the residue is what is enforced
  /// here — a range-set carrying a SP, a control byte or an `obs-text` octet is
  /// `MalformedSpecifier` rather than an opaque span some other unit might
  /// understand.
  ///
  /// The range-set is split by [`crate::grammar::list_elements`], the entrance
  /// the crate holds §5.6.1.2's "A recipient MUST parse and ignore a reasonable
  /// number of empty list elements" at for every RECIPIENT list whose elements
  /// that split can delimit. `range-set` is one of them, and provably so under
  /// every unit rather than only under `bytes`:
  /// `other-range = 1*( %x21-2B / %x2D-7E )` excludes `%x2C` by its own ABNF,
  /// and §14.1.2 adds that "Byte ranges do not use the other-range specifier",
  /// leaving `bytes` with two forms made of digits and hyphens. So no range-set
  /// element can hide a comma, and `bytes=0-499,,500-999` is two range-specs
  /// rather than an invalid specifier.
  ///
  /// # Errors
  ///
  /// [`RangeError::MalformedSpecifier`] when the value is not a
  /// `ranges-specifier`: no `=`, a `range-unit` that is not a §5.6.2 `token`, a
  /// range-set with no non-empty element (`1#range-spec` requires one, and that
  /// half of §14.1.1's grammar is generic rather than unit-defined), an element
  /// carrying an octet no `range-spec` is spelled in, or — under `bytes` — any
  /// element that is not an `int-range` or a `suffix-range`,
  /// `other-range`-shaped ones such as `bytes=abc` included. §14.1.1 makes the
  /// whole set invalid when any one spec is, so this does not skip the offender
  /// and carry on with the rest.
  ///
  /// [`RangeError::TooManySpecs`] past [`MAX_RANGE_SPECS`] real specs. A set
  /// that is both over-limit and invalid reports whichever fault the walk
  /// reaches first; §14.2 sanctions ignoring the field either way, so nothing
  /// downstream turns on which.
  pub fn parse(value: &'a [u8]) -> Result<Self, RangeError> {
    let Some(eq) = value.iter().position(|&b| b == b'=') else {
      return Err(RangeError::MalformedSpecifier);
    };
    let (Some(unit), Some(after_eq)) = (value.get(..eq), value.get(eq.saturating_add(1)..)) else {
      return Err(RangeError::MalformedSpecifier);
    };
    if !is_token(unit) {
      return Err(RangeError::MalformedSpecifier);
    }
    // Erratum 7306's `OWS`, which sits between the `=` and the range-set and so
    // belongs to neither. `list_elements` trims each element's own OWS, which
    // covers every later separator; this first one is ahead of the walk, and it
    // is also what would otherwise be handed back verbatim as part of a
    // non-`bytes` range-set.
    let set = after_eq.get(skip_ows(after_eq, 0)..).unwrap_or_default();

    let mut out = Self {
      unit,
      specs: [None; MAX_RANGE_SPECS],
      len: 0,
      other: None,
    };

    if !eq_ignore_ascii(unit, "bytes") {
      // Both halves of the generic grammar, over one walk. `1#range-spec` is
      // the generic grammar's, not the unit's: §14.1.1 leaves each unit to say
      // which range-spec FORMS it admits, and says itself that there is at
      // least one of them. `list_elements` has already dropped the empty
      // elements §5.6.1.2 makes a recipient ignore, so a walk that yields
      // nothing is a range-set with no member. And each element it does yield
      // is `1*( %x21-2B / %x2D-7E )` whatever form the unit reads it as, which
      // is the octet rule this walk is here to apply — see the section on it in
      // this function's own documentation.
      let mut member = false;
      for element in list_elements(set) {
        if !is_other_range(element) {
          return Err(RangeError::MalformedSpecifier);
        }
        member = true;
      }
      if !member {
        return Err(RangeError::MalformedSpecifier);
      }
      out.other = Some(set);
      return Ok(out);
    }

    for element in list_elements(set) {
      let spec = parse_range_spec(element)?;
      // The slot lookup IS the bound: `None` means this spec is the
      // `MAX_RANGE_SPECS + 1`th, which is the refusal that constant documents.
      let Some(slot) = out.specs.get_mut(out.len) else {
        return Err(RangeError::TooManySpecs);
      };
      *slot = Some(spec);
      out.len = out.len.saturating_add(1);
    }
    // Same `1#range-spec` rule, over the walk that has just run: every non-empty
    // element became a spec, so no specs means no non-empty element, and
    // `bytes=` and `bytes=,,` are invalid specifiers rather than empty sets.
    if out.len == 0 {
      return Err(RangeError::MalformedSpecifier);
    }
    Ok(out)
  }

  /// The `range-unit`, exactly as the sender wrote it.
  #[inline]
  pub const fn unit(&self) -> &'a [u8] {
    self.unit
  }

  /// The range-set verbatim, for a unit other than `bytes`, and `None` for
  /// `bytes` itself.
  ///
  /// A non-`bytes` unit's positions need not be digits — §14.6's own example
  /// carries `exampleunit 1.2-4.3`, which `1*DIGIT` does not admit — so the
  /// bytes are handed back unread rather than forced through a grammar that is
  /// not theirs.
  ///
  /// # What the span is guaranteed to hold
  ///
  /// The whole SET, which is `1#range-spec` and so may carry the list's own
  /// commas and the §5.6.3 OWS around them: `exampleunit=a, b` hands back
  /// `a, b`, two `range-spec`s and not one. Every byte outside a comma and that
  /// OWS is inside some element, and [`parse`](Self::parse) has checked each
  /// element against §14.1.1's `1*( %x21-2B / %x2D-7E )`. So the span as a
  /// whole is a §5.5 `field-value` — it can be written back into a `Range`
  /// field without smuggling a line break — while carrying two octets an
  /// individual `range-spec` may not, both of them §5.6.1's list punctuation.
  ///
  /// What it is NOT is a decision about the unit. §14.1.1 leaves which forms a
  /// unit admits, and what its specifiers denote, to that unit's own
  /// specification; all this promises is the octets.
  #[inline]
  pub const fn other_range_set(&self) -> Option<&'a [u8]> {
    self.other
  }

  /// How many `bytes` `range-spec`s the value carried.
  ///
  /// Zero for a unit other than `bytes`, and zero for no other reason: an empty
  /// range-set is [`RangeError::MalformedSpecifier`], not an empty list.
  #[inline]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Whether the value carried no `bytes` `range-spec` — true exactly when
  /// [`other_range_set`](Self::other_range_set) is `Some`.
  #[inline]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// The `index`th `bytes` `range-spec`, unresolved, or `None` past the last
  /// one.
  ///
  /// The path for a caller that does not know the complete length of the
  /// selected representation and so has nothing to resolve against.
  #[inline]
  pub fn spec(&self, index: usize) -> Option<RangeSpec> {
    self.specs.get(index).copied().flatten()
  }

  /// The `index`th `bytes` `range-spec` resolved against `complete_length`, or
  /// `None` past the last one.
  ///
  /// One call, so the order cannot be got wrong: §14.1.2's satisfiability is
  /// decided before either normalisation, and a spec that fails it is never
  /// normalised. `None` is reserved for an index past the end — all three
  /// [`Resolved`] variants describe a `range-spec` that exists.
  ///
  /// Indexed by the received order on purpose. §15.3.7.2: "A server that
  /// generates a multipart response SHOULD send the parts in the same order
  /// that the corresponding range-spec appeared in the received Range header
  /// field, excluding those ranges that were deemed unsatisfiable or that were
  /// coalesced into other ranges." Walking `0..len()` and skipping every
  /// [`Resolved::Unsatisfiable`] honours that by construction.
  ///
  /// `complete_length` is the caller's fact, and a caller that passes two
  /// different values to two calls gets two different answers — exactly what it
  /// asked for.
  ///
  /// # The method this crate never sees
  ///
  /// RFC 9110 §14.2: "A server MUST ignore a Range header field received with a
  /// request method that is unrecognized or for which range handling is not
  /// defined.  For this specification, GET is the only method for which range
  /// handling is defined." This function takes no method and cannot check it. A
  /// caller resolving a specifier for any other method is violating that MUST —
  /// unless a later specification has defined range handling for the method in
  /// hand.
  pub fn resolve(&self, index: usize, complete_length: u64) -> Option<Resolved> {
    let resolved = match self.spec(index)? {
      RangeSpec::Int { first, last } => {
        // RFC 9110 §14.1.2's satisfiable int-range is one "with a first-pos
        // that is less than the current length of the selected representation",
        // so a zero-length representation satisfies none of them — and zero is
        // also the one length that has no "value that is one less than the
        // current length" for a last-pos to normalise to. One `checked_sub`
        // answers both, which is why there is no separate zero test above it.
        let Some(end) = complete_length.checked_sub(1) else {
          return Some(Resolved::Unsatisfiable);
        };
        // A `Beyond` first-pos is at or above every length a `u64` can express,
        // so it is below none of them.
        let Pos::Exact(first) = first else {
          return Some(Resolved::Unsatisfiable);
        };
        if first >= complete_length {
          return Some(Resolved::Unsatisfiable);
        }
        // RFC 9110 §14.1.2: "If the last-pos value is absent, or if the value
        // is greater than or equal to the current length of the representation
        // data, the byte range is interpreted as the remainder of the
        // representation". `Beyond` meets that condition for every length, so
        // it takes the same arm an absent last-pos does.
        let last = match last {
          None | Some(Pos::Beyond) => end,
          Some(Pos::Exact(last)) if last >= complete_length => end,
          Some(Pos::Exact(last)) => last,
        };
        Resolved::Range(first, last)
      }
      // Read as a pair so that every case is an arm rather than a guard: the
      // suffix-length decides satisfiability and the length decides whether
      // there are positions to name.
      RangeSpec::Suffix { length } => match (length, complete_length.checked_sub(1)) {
        // RFC 9110 §14.1.2's satisfiable suffix-range is "a suffix-range with a
        // non-zero suffix-length", so a zero one is unsatisfiable against every
        // length, the zero-length representation included.
        (Pos::Exact(0), _) => Resolved::Unsatisfiable,
        // A zero length, where §14.1.2 leaves this form satisfiable and the
        // whole of an empty representation still has no inclusive positions.
        (_, None) => Resolved::EmptyRepresentation,
        // RFC 9110 §14.1.2: "If the selected representation is shorter than the
        // specified suffix-length, the entire representation is used." `Beyond`
        // is longer than every representation, and for an exact suffix the
        // subtraction having no answer IS that condition.
        (Pos::Beyond, Some(end)) => Resolved::Range(0, end),
        (Pos::Exact(length), Some(end)) => match complete_length.checked_sub(length) {
          Some(first) => Resolved::Range(first, end),
          None => Resolved::Range(0, end),
        },
      },
    };
    Some(resolved)
  }

  /// RFC 9110 §14.1.1's set level: whether at least one `range-spec` is
  /// satisfiable against `complete_length`.
  ///
  /// [`Resolved::EmptyRepresentation`] counts as satisfiable, because §14.1.2
  /// says it is: "When a selected representation has zero length, the only
  /// satisfiable form of range-spec in a GET request is a suffix-range with a
  /// non-zero suffix-length."
  ///
  /// False for a unit other than `bytes`, and that is a report rather than a
  /// verdict: §14.1.1 makes satisfiability "as defined by the indicated
  /// range-unit", this crate defines it only for `bytes`, and there are no
  /// `bytes` range-specs to answer over. §14.2 gives such a recipient its own
  /// instruction — "An origin server MUST ignore a Range header field that
  /// contains a range unit it does not understand" — which is a decision taken
  /// before this question is worth asking.
  pub fn is_satisfiable(&self, complete_length: u64) -> bool {
    (0..self.len).any(|index| {
      !matches!(
        self.resolve(index, complete_length),
        None | Some(Resolved::Unsatisfiable)
      )
    })
  }
}

/// RFC 9110 §14.1.1's `other-range = 1*( %x21-2B / %x2D-7E )` — the octet set
/// EVERY `range-spec` is spelled out of, whatever unit reads it.
///
/// The widest of the three forms, and the other two are inside it:
/// `int-range = first-pos "-" [ last-pos ]` and `suffix-range = "-"
/// suffix-length` are spelled in `1*DIGIT` (`%x30-39`) and `-` (`%x2D`), both
/// of which this set holds. So it is `range-spec`'s octet rule rather than one
/// alternative's, which is what lets [`RangesSpecifier::parse`] apply it to a
/// set whose unit it cannot read.
///
/// The ABNF's own comment reads `1*(VCHAR excluding comma)`, and the exclusion
/// is what [`RangesSpecifier::parse`] relies on to split the set at all: a
/// comma inside a `range-spec` would make `1#range-spec` undelimitable. `%x20`
/// is excluded too, so the OWS §5.6.1 puts around a list's commas is the only
/// whitespace a range-set may carry.
fn is_other_range(element: &[u8]) -> bool {
  !element.is_empty()
    && element
      .iter()
      .all(|byte| matches!(*byte, 0x21..=0x2B | 0x2D..=0x7E))
}

/// One element of a `bytes` range-set, OWS already trimmed by the walk.
///
/// §14.1.2 defines two forms for this unit and excludes the third, so anything
/// that is not an `int-range` or a `suffix-range` is invalid rather than opaque.
fn parse_range_spec(element: &[u8]) -> Result<RangeSpec, RangeError> {
  if let Some(suffix_length) = element.strip_prefix(b"-") {
    let Some(length) = numeral(suffix_length) else {
      return Err(RangeError::MalformedSpecifier);
    };
    return Ok(RangeSpec::Suffix { length });
  }
  let Some(hyphen) = element.iter().position(|&b| b == b'-') else {
    return Err(RangeError::MalformedSpecifier);
  };
  let (Some(first_digits), Some(last_digits)) = (
    element.get(..hyphen),
    element.get(hyphen.saturating_add(1)..),
  ) else {
    return Err(RangeError::MalformedSpecifier);
  };
  let Some(first) = numeral(first_digits) else {
    return Err(RangeError::MalformedSpecifier);
  };
  if last_digits.is_empty() {
    return Ok(RangeSpec::Int { first, last: None });
  }
  let Some(last) = numeral(last_digits) else {
    return Err(RangeError::MalformedSpecifier);
  };
  // RFC 9110 §14.1.1: "An int-range is invalid if the last-pos value is present
  // and less than the first-pos." Decided from the DIGITS, here, because
  // `Pos::Beyond` keeps none of them and nothing downstream could ask the
  // question again.
  if numeral_lt(last_digits, first_digits) {
    return Err(RangeError::MalformedSpecifier);
  }
  Ok(RangeSpec::Int {
    first,
    last: Some(last),
  })
}

/// A `1*DIGIT` numeral's value, or [`Pos::Beyond`] when no `u64` holds it, and
/// `None` when the bytes are not `1*DIGIT`.
///
/// The digits are walked to the end even once the value has overflowed, so that
/// a numeral with a non-digit behind it is reported as malformed rather than as
/// a very large number.
fn numeral(digits: &[u8]) -> Option<Pos> {
  if digits.is_empty() {
    return None;
  }
  let mut value = Some(0u64);
  for &byte in digits {
    // One step answers both questions `1*DIGIT` asks of a byte: `checked_sub`
    // rejects everything below `0` and the filter everything above `9`.
    let digit = byte.checked_sub(b'0').filter(|digit| *digit < 10)?;
    value = value
      .and_then(|value| value.checked_mul(10))
      .and_then(|value| value.checked_add(u64::from(digit)));
  }
  Some(match value {
    Some(value) => Pos::Exact(value),
    None => Pos::Beyond,
  })
}

/// Whether the numeral `a` is strictly less than the numeral `b`, both
/// `1*DIGIT`, compared as digit strings.
///
/// Exact for numerals of any length, which is what lets §14.1.1's validity rule
/// be settled without the conversion §14.1.2's closing MUST warns about — two
/// positions both larger than `u64::MAX` are still decided against each other.
/// Leading zeros do not change a numeral's value, so they come off first; what
/// is left is longer-wins, then a byte comparison, which over equal-length runs
/// of ASCII digits IS numeric order.
///
/// Visible to the whole `range` module because §14.4 asks the same question of
/// the same shape: [`ContentRange::parse`](super::ContentRange::parse) applies
/// that section's two validity clauses to a `range-resp` under a unit it does
/// not read, where the numerals are likewise still digits in hand and may
/// likewise exceed a `u64`. One comparison, so the two sections cannot come to
/// disagree about which of two numerals is the larger.
pub(super) fn numeral_lt(a: &[u8], b: &[u8]) -> bool {
  let (a, b) = (significant(a), significant(b));
  if a.len() != b.len() {
    return a.len() < b.len();
  }
  a < b
}

/// A numeral's digits with every leading zero removed.
///
/// A numeral of nothing but zeros becomes empty, which is the right answer for
/// [`numeral_lt`]'s length comparison: zero is the only value shorter than one
/// significant digit, and every spelling of it lands on the same empty run.
fn significant(digits: &[u8]) -> &[u8] {
  let mut out = digits;
  while let Some((&b'0', rest)) = out.split_first() {
    out = rest;
  }
  out
}
