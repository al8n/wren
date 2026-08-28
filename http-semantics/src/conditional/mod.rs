//! RFC 9110 §13's conditional request fields, read into one accumulator.
//!
//! [`Preconditions`] is fed one field at a time by
//! [`push`](Preconditions::push) and settles nothing about the request until
//! the whole header section has been. That order is §13.2.2's rather than a
//! preference: `If-Match` being present is what decides whether its step runs
//! at all, and `If-None-Match` being present is what decides whether its own
//! does, so no field's contribution can be committed while another may still
//! arrive. [`crate::grammar::Expectations`] states the same doctrine for a
//! different field, and it is the same reason.
//!
//! # What a value can settle, and what it cannot
//!
//! §13.1.3 and §13.1.4 each MUST-ignore their date field for several reasons,
//! and they do not agree on how many: §13.1.3 has four and §13.1.4 has three,
//! because only `If-Modified-Since` carries a rule about the request method.
//! That clause is the WHOLE of the difference: the other three reasons are
//! shared — the sibling entity-tag field being present, the value not being a
//! valid `HTTP-date`, and the resource having no modification date available —
//! and exactly one of them is a fact about the VALUE, that it is not a valid
//! `HTTP-date`. The sibling entity-tag field, the request method, and whether
//! the resource has a modification date at all belong to the evaluation, and
//! this accumulator is not told any of them.
//!
//! Each date field therefore reads back as a [`DateField`]: usable, present and
//! unusable, or absent. Three states rather than two, because ignoring and
//! failing are different answers — with `If-Unmodified-Since` present and no
//! modification date to compare it against, the recipient skips that step and
//! carries on rather than answering 412.
//!
//! # Which fields refuse
//!
//! The two entity-tag lists do, through [`Preconditions::refusal`]. They guard
//! against lost updates, and a guard the recipient quietly dropped is the
//! failure they exist to prevent, so a value neither list can read stops the
//! request rather than being judged from the part that parsed. That is a
//! departure from RFC 9110 and not a gap in it: §13.1.1's and §13.1.2's
//! evaluation lists each close with a total step, so the RFC does have an
//! answer for an unreadable value, and this crate declines it.
//!
//! `If-Range` does not, and §13.1.5 is why: "The `If-Range` header field
//! provides a special conditional request mechanism that is similar to the
//! If-Match and If-Unmodified-Since header fields but that instructs the
//! recipient to ignore the Range header field if the validator doesn't match,
//! resulting in transfer of the new selected representation instead of a 412
//! (Precondition Failed) response." A value neither of its two forms reads
//! makes the condition false, which costs a full 200 — the field's own designed
//! degraded mode. Refusing would answer with the status the field exists to
//! avoid.
//!
//! `Range` does not either: §14.2 says outright that "A server MAY ignore the
//! Range header field", so a value [`RangesSpecifier`] will not read is dropped
//! and [`Preconditions::range_ignored`] says it was.
//!
//! [`RangesSpecifier`]: crate::range::RangesSpecifier

use crate::{
  date::{HttpDate, parse_http_date_from},
  grammar::eq_ignore_ascii,
  range::{ContentRange, RangesSpecifier, Resolved},
  status::Status,
  validator::{EntityTag, Selected, TagError, TagList},
};

/// RFC 9110 §13.1.1's field name, matched case-insensitively.
///
/// §5.1 makes every field name a case-insensitive `token`, which is why these
/// six are compared with [`eq_ignore_ascii`] rather than with `==`.
const IF_MATCH: &str = "if-match";

/// RFC 9110 §13.1.2's field name.
const IF_NONE_MATCH: &str = "if-none-match";

/// RFC 9110 §13.1.3's field name.
const IF_MODIFIED_SINCE: &str = "if-modified-since";

/// RFC 9110 §13.1.4's field name.
const IF_UNMODIFIED_SINCE: &str = "if-unmodified-since";

/// RFC 9110 §13.1.5's field name.
const IF_RANGE: &str = "if-range";

/// RFC 9110 §14.2's field name.
const RANGE: &str = "range";

/// Which of the two entity-tag list fields a [`PreconditionRefusal`] is about.
///
/// Only these two refuse. RFC 9110 §13.1.3, §13.1.4 and §13.1.5 answer an
/// unreadable value by ignoring the field, so no date field and no `If-Range`
/// can name itself here.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TagField {
  /// RFC 9110 §13.1.1's `If-Match = "*" / #entity-tag`.
  IfMatch,
  /// RFC 9110 §13.1.2's `If-None-Match = "*" / #entity-tag`.
  IfNoneMatch,
}

/// Why an entity-tag list field stops the request instead of being evaluated.
///
/// A cause rather than a status: the two causes suggest different answers and
/// neither is RFC 9110's, so the choice is left where the facts are. A caller
/// answering [`TooManyTags`](Self::TooManyTags) with anything but a complaint
/// about size would be answering the wrong question, and one answering
/// [`Malformed`](Self::Malformed) with 431 would call a short, ill-formed value
/// too large.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PreconditionRefusal {
  /// More entity tags than [`MAX_TAGS`](crate::validator::MAX_TAGS) holds.
  ///
  /// [`Status::FieldsTooLarge`] — RFC 6585 §5's 431 — is the suggestion, and it is this crate's own: what
  /// happened is that the value was too large for the recipient, which is the
  /// complaint that status makes. RFC 9110 names no status for it.
  #[error("more entity tags than this recipient holds in {field}")]
  TooManyTags {
    /// The field whose value was over the limit.
    field: TagField,
  },
  /// A value that is not a valid `If-Match` or `If-None-Match` field value.
  ///
  /// [`Status::BadRequest`] is the suggestion. Three shapes reach here and they are one fault, not three: an
  /// element that is not an `entity-tag`, a `*` beside any other value, and a
  /// second field line of the same name that [`Preconditions::push`] cannot
  /// join to the first.
  ///
  /// The `*` case is deliberate rather than incidental.
  /// [`TagError::StarInList`] is RFC 9110 §13.1.1's and §13.1.2's closing note
  /// — "Note that an If-Match header field with a list value containing `*` and
  /// other values (including other instances of `*`) is syntactically invalid
  /// (therefore not allowed to be generated) and furthermore is unlikely to be
  /// interoperable" — and a syntactically invalid value is a malformed one. It
  /// is not a size complaint, so it must not arrive as
  /// [`TooManyTags`](Self::TooManyTags), and it must not be dropped either: `*`
  /// is the broadest guard a client can send, and evaluating the rest of the
  /// list without it answers over a value the client did not send.
  #[error("not a valid {field} field value")]
  Malformed {
    /// The field whose value could not be read.
    field: TagField,
  },
}

// Written out lowercase, as `Preconditions::push` matches it, so an error
// message names a field the caller can find in its own header section.
impl core::fmt::Display for TagField {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(match self {
      Self::IfMatch => IF_MATCH,
      Self::IfNoneMatch => IF_NONE_MATCH,
    })
  }
}

/// What one of RFC 9110's three `HTTP-date` conditional fields parsed into.
///
/// The two states either side of [`Usable`](Self::Usable) lead to the same
/// next step and are still not the same answer, which is why there are three.
/// §13.1.3's and §13.1.4's MUST-ignore rules produce
/// [`PresentUnusable`](Self::PresentUnusable): the step is skipped and the
/// request carries on, exactly as it would for [`Absent`](Self::Absent). What
/// the distinction is for is the recipient that wants to know whether the
/// client asked at all — a conditional request whose condition was ignored is
/// not an unconditional one.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DateField {
  /// No field of this name was pushed.
  Absent,
  /// A field was pushed and its value is not a valid `HTTP-date`, so RFC 9110
  /// §13.1.3 and §13.1.4 MUST-ignore it.
  ///
  /// A value with more than one date in it lands here too, and by the same
  /// rule rather than by a separate one: §13.1.4 spells that out — "A recipient
  /// MUST ignore the If-Unmodified-Since header field if the received field
  /// value is not a valid HTTP-date (including when the field value appears to
  /// be a list of dates)." No separate list test is needed to reach this state,
  /// because none of §5.6.7's three formats can absorb the extra bytes: two of
  /// them are a constant length, and `rfc850-date` is NOT — its `day-name-l`
  /// runs from six letters to nine — so [`parse_http_date_from`] reads that
  /// name first and then holds the value to the length that name implies. A
  /// comma-joined pair of dates overruns all three.
  PresentUnusable,
  /// A field was pushed and its value is an RFC 9110 §5.6.7 `HTTP-date`.
  ///
  /// Usable is not the same as true, and not even the same as evaluated: the
  /// MUST-ignore rules this accumulator cannot decide are still ahead of it —
  /// the sibling entity-tag field, whether the resource has a modification date
  /// at all, and, for `If-Modified-Since` alone, the request method.
  Usable(HttpDate),
}

/// One entity-tag list field's slot.
///
/// Private, and an enum rather than a pair of `Option`s, because the pair
/// admits a state that cannot happen: a field is never both read and refused.
// `large_enum_variant` asks for the big variant to be boxed, and there is
// nothing here to box it with: the bare tier of this crate has no allocator,
// `forbid(unsafe_code)` rules out an untagged union, and a `TagList` is
// `MAX_TAGS` inline slots on purpose — a caller cannot raise that bound because
// the storage is in the binary. The discriminant lands in a niche `TagList`
// already has, so this enum measures exactly as wide as the variant the lint is
// complaining about — 400 bytes on a 64-bit target, the same figure `MAX_TAGS`
// pins — while the pair of `Option`s the lint would leave alone admits the
// impossible state this enum exists to close. The repair costs correctness and
// saves nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Copy, Clone)]
enum TagSlot<'a> {
  /// No field of this name was pushed.
  Absent,
  /// A field was pushed and its value stops the request.
  Refused(PreconditionRefusal),
  /// A field was pushed and its value is a `"*" / #entity-tag`.
  Read(TagList<'a>),
}

/// RFC 9110 §13.1.5's `If-Range = entity-tag / HTTP-date`, once the two forms
/// have been told apart.
///
/// Private, and four states rather than the two the accessors expose, because
/// [`PresentUnusable`](Self::PresentUnusable) and [`Absent`](Self::Absent) are
/// different answers to §13.2.2's step 5: with no `If-Range` at all the step
/// does not run and a `Range` survives it, while §13.1.5 says of the other that
/// "A recipient of an If-Range header field MUST ignore the Range header field
/// if the If-Range condition evaluates to false." Both accessors answer `None`
/// for either state, so the distinction is kept here and read by the evaluation
/// rather than by a caller.
#[derive(Debug, Copy, Clone)]
enum IfRangeSlot<'a> {
  /// No `If-Range` was pushed.
  Absent,
  /// An `If-Range` was pushed and neither form reads its value, so §13.1.5's
  /// condition is false over it.
  PresentUnusable,
  /// §13.1.5's `entity-tag` form.
  Tag(EntityTag<'a>),
  /// §13.1.5's `HTTP-date` form.
  Date(HttpDate),
}

// What the accumulator costs a caller, checked at module scope so that every
// `cargo check` on every tier enforces it — a `#[test]` would assert it only
// where a test harness runs, which is every tier EXCEPT `thumbv6m-none-eabi`,
// the one this number is written down for. (`crate::validator::MAX_TAGS` and
// `crate::range::MAX_RANGE_SPECS` make the same argument for the two arrays
// almost all of this figure is.)
//
// The figures are the compiler's own, and these assertions are the command that
// takes them:
//
//   cargo check -p http-semantics --all-features
//   cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi
//
// This is the largest value this crate asks a caller to hold, and the three
// parse-constants are almost the whole of it: two `TagSlot`s at `MAX_TAGS`
// slots each — 400 bytes on a 64-bit target, 200 on a 32-bit one, the figures
// `TagList` itself pins — and one `RangesSpecifier` at `MAX_RANGE_SPECS`, 296
// and 280. The `Option` around the specifier costs nothing, since the `unit`
// slice's null niche carries its discriminant. What this type adds of its own is
// small and the same on both widths but for the `If-Range` slot: an `i64`
// clock, two `DateField`s at 10 each, an `IfRangeSlot` at 24 and 12, and a
// `bool`. 800 + 296 + 8 + 20 + 24 + 1 = 1149, rounded up to the `i64`'s
// alignment: 1152. On a 32-bit target 400 + 280 + 8 + 20 + 12 + 1 = 721, and
// 728.
//
// Both widths are PINNED rather than bounded, for the reason the two
// assertions named above give — they are in `crate::validator` and
// `crate::range::specifier`, not in this file: a bound set well above a value
// asserts nothing about it, and an ungated bound is vacuous on the smaller
// tier, which is the tier that has the least room for this. On `thumbv6m-none-eabi` a
// caller holds this on a stack measured in kilobytes, so a slot count raised
// without thinking should red the build rather than the device.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Preconditions<'_>>() == 1152);

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<Preconditions<'_>>() == 728);

/// The five RFC 9110 §13.1 conditional fields and §14.2's `Range`, accumulated
/// before any verdict is asked for.
///
/// Every value pushed is borrowed, never copied, so the field values must
/// outlive this. Nothing here allocates, and the only bounds it has are the
/// ones its parts brought with them: [`MAX_TAGS`](crate::validator::MAX_TAGS)
/// slots in each of the two [`TagList`]s, and
/// [`MAX_RANGE_SPECS`](crate::range::MAX_RANGE_SPECS) in the
/// [`RangesSpecifier`]. All three are in the binary, so a caller cannot raise
/// them.
#[derive(Debug, Clone)]
pub struct Preconditions<'a> {
  /// The recipient's instant, for RFC 9110 §5.6.7's fifty-year rule. Reaches
  /// only the three date-valued fields, and within them only an `rfc850-date`.
  now_unix_seconds: i64,
  /// §13.1.1's `If-Match`.
  if_match: TagSlot<'a>,
  /// §13.1.2's `If-None-Match`.
  if_none_match: TagSlot<'a>,
  /// §13.1.3's `If-Modified-Since`.
  if_modified_since: DateField,
  /// §13.1.4's `If-Unmodified-Since`.
  if_unmodified_since: DateField,
  /// §13.1.5's `If-Range`, already split into its two forms.
  if_range: IfRangeSlot<'a>,
  /// §14.2's `Range`, when it parsed. `None` covers both an absent field and an
  /// ignored one, which is what `range_ignored` is beside it for.
  range: Option<RangesSpecifier<'a>>,
  /// A `Range` was pushed and is not usable.
  range_ignored: bool,
}

impl<'a> Preconditions<'a> {
  /// An empty accumulator reading dates against `now_unix_seconds`.
  ///
  /// # The clock is an argument
  ///
  /// Three of the five conditional fields carry an `HTTP-date` —
  /// `If-Modified-Since`, `If-Unmodified-Since`, and `If-Range`'s date form —
  /// and any of them may legally arrive as an `rfc850-date`, whose year is two
  /// digits. RFC 9110 §5.6.7 resolves those two digits against the RECIPIENT's
  /// instant: "Recipients of a timestamp value in rfc850-date format, which
  /// uses a two-digit year, MUST interpret a timestamp that appears to be more
  /// than 50 years in the future as representing the most recent year in the
  /// past that had the same last two digits."
  ///
  /// So the instant is an input to the parse, not a detail of it, and this
  /// crate's own reading half already takes it that way:
  /// [`parse_http_date_from`] is the entry point and the fixed-anchor
  /// [`parse_http_date`](crate::date::parse_http_date) beside it documents its
  /// degradation as a cost. A `Preconditions` with no clock would have to pick
  /// the degraded one for every caller, silently.
  ///
  /// The value is seconds since the POSIX epoch, which is what a clock answers
  /// — and what [`HttpDate::unix_seconds`] answers, so a `Date` field this
  /// crate has already read is itself a usable instant. Every [`i64`] denotes
  /// one, so this argument has no malformed value and adds no refusal.
  #[inline]
  pub const fn new(now_unix_seconds: i64) -> Self {
    Self {
      now_unix_seconds,
      if_match: TagSlot::Absent,
      if_none_match: TagSlot::Absent,
      if_modified_since: DateField::Absent,
      if_unmodified_since: DateField::Absent,
      if_range: IfRangeSlot::Absent,
      range: None,
      range_ignored: false,
    }
  }

  /// Reads one field into its slot, and answers nothing.
  ///
  /// `name` is matched case-insensitively against the six this type reads —
  /// `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`,
  /// `If-Range` and `Range` — and any other field is ignored, since a request
  /// carries many and none of the others is a precondition.
  ///
  /// **Nothing is reported here, deliberately.** A walk over a header section
  /// should not branch per line, so an over-limit list or a value that will not
  /// parse is read back afterwards through [`refusal`](Self::refusal),
  /// [`range_ignored`](Self::range_ignored) or a [`DateField`], never returned
  /// from this call. [`crate::grammar::Expectations::push`] has the same
  /// signature for the same reason.
  ///
  /// `value` is the field's, with the whitespace around it already gone. RFC
  /// 9110 §5.5 puts that on whoever read the field rather than on this: "A
  /// field value does not include leading or trailing whitespace. When a
  /// specific version of HTTP allows such whitespace to appear in a message, a
  /// field parsing implementation MUST exclude such whitespace prior to
  /// evaluating the field value."
  ///
  /// # One value per field
  ///
  /// `value` is the field's WHOLE value, already recombined if the message
  /// carried it on several lines. RFC 9110 §5.3 defines that recombination —
  /// "This means that, aside from the well-known exception noted below, a
  /// sender MUST NOT generate multiple field lines with the same name in a
  /// message (whether in the headers or trailers) or append a field line when a
  /// field line of the same name already exists in the message, unless that
  /// field's definition allows multiple field line values to be recombined as a
  /// comma-separated list (i.e., at least one alternative of the field's
  /// definition allows a comma-separated list, such as an ABNF rule of
  /// #(values) defined in Section 5.6.1)." — and it belongs to the reader one
  /// layer below this.
  ///
  /// A second push of a name already pushed is therefore a value this was not
  /// given whole, and every field answers it without choosing between the two:
  ///
  /// - The two entity-tag lists refuse, as
  ///   [`PreconditionRefusal::Malformed`]. They are `#entity-tag` lists, so
  ///   §5.3 does license two field lines — but joining them means a third
  ///   buffer to hold `first "," second`, and every tag this type hands back is
  ///   borrowed out of the caller's bytes. Judging the guard from one of the
  ///   two lines is the silent void [`TagList::parse`] already refuses within a
  ///   single value.
  /// - The two date fields become [`DateField::PresentUnusable`], and a
  ///   repeated `If-Range` reaches the matching state of its own private slot,
  ///   after which [`if_range_tag`](Self::if_range_tag) and
  ///   [`if_range_date`](Self::if_range_date) both answer `None`. §5.3 above is
  ///   the whole of the reason for all three, and it needs no help from any
  ///   field-specific MUST-ignore rule: what arrived is not one field value,
  ///   and none of these three refuses. Which is why the state holds whatever
  ///   the two lines carried — two entity-tags in an `If-Range` land in it
  ///   exactly as two dates do.
  /// - `Range` is ignored, on §14.2's "A server MAY ignore the Range header
  ///   field".
  ///
  /// [`crate::grammar::Expectations`] accumulates across field lines instead,
  /// and the difference is not a preference: every fact it keeps is a `bool`,
  /// so it needs no buffer to join two lines with.
  pub fn push(&mut self, name: &[u8], value: &'a [u8]) {
    let now = self.now_unix_seconds;
    if eq_ignore_ascii(name, IF_MATCH) {
      self.if_match = read_tag_field(&self.if_match, value, TagField::IfMatch);
    } else if eq_ignore_ascii(name, IF_NONE_MATCH) {
      self.if_none_match = read_tag_field(&self.if_none_match, value, TagField::IfNoneMatch);
    } else if eq_ignore_ascii(name, IF_MODIFIED_SINCE) {
      self.if_modified_since = read_date_field(self.if_modified_since, value, now);
    } else if eq_ignore_ascii(name, IF_UNMODIFIED_SINCE) {
      self.if_unmodified_since = read_date_field(self.if_unmodified_since, value, now);
    } else if eq_ignore_ascii(name, IF_RANGE) {
      self.if_range = read_if_range(&self.if_range, value, now);
    } else if eq_ignore_ascii(name, RANGE) {
      self.read_range(value);
    }
  }

  /// §14.2's `Range = ranges-specifier`, or the ignore that stands in for it.
  fn read_range(&mut self, value: &'a [u8]) {
    if self.range.is_some() || self.range_ignored {
      self.range = None;
      self.range_ignored = true;
      return;
    }
    match RangesSpecifier::parse(value) {
      Ok(spec) => self.range = Some(spec),
      Err(_) => self.range_ignored = true,
    }
  }

  /// Why an entity-tag list field stops this request, if one does.
  ///
  /// This is what the VALUE was, for any recipient. Which fields a particular
  /// evaluation would have consulted is that evaluation's question and not this
  /// one's, so the two may disagree in both of the ways a field goes
  /// unconsulted: a cache never reaches `If-Match` at all, and an
  /// `If-None-Match` sitting behind an RFC 9110 §13.2.2 step that already
  /// answered is never reached either. This accessor reports a malformed value
  /// in both cases, because a value is what it is whoever reads it.
  ///
  /// # When both refuse, this reports `If-Match`'s
  ///
  /// The accessor is recipient-blind, so it needs one deterministic pick, and
  /// RFC 9110 §13.2.2 supplies it by evaluating `If-Match` first: at the origin
  /// server — the one recipient that consults both — this is also the failure
  /// the caller acts on. At a cache it is not, which is the disagreement above
  /// seen from the other side.
  #[inline]
  pub const fn refusal(&self) -> Option<PreconditionRefusal> {
    if let TagSlot::Refused(why) = &self.if_match {
      Some(*why)
    } else if let TagSlot::Refused(why) = &self.if_none_match {
      Some(*why)
    } else {
      None
    }
  }

  /// RFC 9110 §13.1.1's `If-Match`, when its value parsed.
  ///
  /// `None` for a field that was never pushed AND for one whose value was
  /// refused; [`refusal`](Self::refusal) is what tells those two apart.
  ///
  /// By reference: a [`TagList`] is [`MAX_TAGS`](crate::validator::MAX_TAGS)
  /// slots wide and this type holds two of them.
  #[inline]
  pub const fn if_match(&self) -> Option<&TagList<'a>> {
    match &self.if_match {
      TagSlot::Read(list) => Some(list),
      TagSlot::Absent | TagSlot::Refused(_) => None,
    }
  }

  /// RFC 9110 §13.1.2's `If-None-Match`, when its value parsed.
  ///
  /// `None` for a field that was never pushed AND for one whose value was
  /// refused, exactly as [`if_match`](Self::if_match) is.
  #[inline]
  pub const fn if_none_match(&self) -> Option<&TagList<'a>> {
    match &self.if_none_match {
      TagSlot::Read(list) => Some(list),
      TagSlot::Absent | TagSlot::Refused(_) => None,
    }
  }

  /// RFC 9110 §13.1.3's `If-Modified-Since = HTTP-date`, in its three states.
  ///
  /// Only one of §13.1.3's four MUST-ignore rules is settled here, and it is
  /// the only one that is a fact about the value: "A recipient MUST ignore the
  /// If-Modified-Since header field if the received field value is not a valid
  /// HTTP-date, the field value has more than one member, or if the request
  /// method is neither GET nor HEAD." The method half of that sentence, the
  /// presence of `If-None-Match`, and whether the resource has a modification
  /// date at all are the evaluation's.
  #[inline]
  pub const fn if_modified_since(&self) -> DateField {
    self.if_modified_since
  }

  /// RFC 9110 §13.1.4's `If-Unmodified-Since = HTTP-date`, in its three states.
  ///
  /// §13.1.4 has THREE MUST-ignore rules where §13.1.3 has four, and the
  /// difference is real rather than an omission: no rule here turns on the
  /// request method. Its own value rule is "A recipient MUST ignore the
  /// If-Unmodified-Since header field if the received field value is not a
  /// valid HTTP-date (including when the field value appears to be a list of
  /// dates)", and that is the one settled here. The presence of `If-Match` and
  /// the resource's modification date are the evaluation's.
  #[inline]
  pub const fn if_unmodified_since(&self) -> DateField {
    self.if_unmodified_since
  }

  /// RFC 9110 §13.1.5's `If-Range` when it carried the `entity-tag` form.
  ///
  /// # Visibility is not permission
  ///
  /// §13.1.5 attaches a MUST to this field's mere PRESENCE, one about the
  /// company the field keeps rather than about its value: "A server MUST ignore
  /// an If-Range header field received in a request that does not contain a
  /// Range header field." Nothing here applies it, so a caller reading this
  /// accessor alone can be holding a validator it MUST ignore.
  ///
  /// The fact that settles it is in this same accumulator, since `Range` is
  /// pushed here too — but no one accessor answers it, because the MUST turns
  /// on the field not being RECEIVED and [`range`](Self::range) is `None` for
  /// an ignored `Range` as well as for an absent one. The test is
  /// `range().is_none() && !range_ignored()`.
  ///
  /// The sentence after it in §13.1.5 is not this crate's and cannot be: "An
  /// origin server MUST ignore an If-Range header field received in a request
  /// for a target resource that does not support Range requests." Whether the
  /// resource supports range requests is the caller's fact, exactly as the
  /// method is in [`range`](Self::range).
  ///
  /// # The two forms are told apart by §13.1.5's own rule
  ///
  /// "A valid entity-tag can be distinguished from a valid HTTP-date by
  /// examining the first three characters for a DQUOTE." That is the test this
  /// runs, rather than an equivalent one of its own devising: `W/"xyzzy"`
  /// carries its DQUOTE third and `Sun, 06 Nov 1994 08:49:37 GMT` carries none
  /// in the first three, and the rule is the RFC's to state.
  ///
  /// A weak tag reaches here rather than being turned back. §13.1.5's "A client
  /// MUST NOT generate an If-Range header field containing an entity tag that
  /// is marked as weak" is addressed to the sender, and the evaluation's own
  /// step already answers a weak one: it compares with §8.8.3.2's strong
  /// function, which no weak tag satisfies, so the condition is false and the
  /// `Range` is ignored. Refusing it here would answer a client's mistake with
  /// the 412 §13.1.5 exists to avoid.
  ///
  /// `None` when the field was absent, when it carried the date form, and when
  /// neither form read its value — the last of those is a condition that
  /// evaluates FALSE rather than a refusal, since §13.1.5 makes this field the
  /// opposite of a lost-update guard.
  ///
  /// The first and the last of those three are not the same answer, and
  /// [`if_range_present`](Self::if_range_present) is what tells them apart.
  #[inline]
  pub const fn if_range_tag(&self) -> Option<EntityTag<'a>> {
    match &self.if_range {
      IfRangeSlot::Tag(tag) => Some(*tag),
      IfRangeSlot::Absent | IfRangeSlot::PresentUnusable | IfRangeSlot::Date(_) => None,
    }
  }

  /// RFC 9110 §13.1.5's `If-Range` when it carried the `HTTP-date` form.
  ///
  /// The same DQUOTE rule [`if_range_tag`](Self::if_range_tag) states picks
  /// between them, and the same three cases answer `None` here — including the
  /// two [`if_range_present`](Self::if_range_present) separates.
  ///
  /// # Visibility is not permission
  ///
  /// §13.1.5's presence MUST governs this form exactly as it governs the tag
  /// form: "A server MUST ignore an If-Range header field received in a request
  /// that does not contain a Range header field." Nothing here applies it
  /// either, so the same test comes first —
  /// `range().is_none() && !range_ignored()` is a request that carried no
  /// `Range`, and this date is then a validator the recipient MUST ignore.
  /// [`if_range_tag`](Self::if_range_tag) carries the rest of the reasoning,
  /// including the companion MUST about a resource that does not support range
  /// requests.
  ///
  /// Whether this date is a strong validator is not asked here and cannot be:
  /// §13.1.5's first evaluation step turns on §8.8.2.2's deduction, which the
  /// selected representation carries and this accumulator has never seen.
  #[inline]
  pub const fn if_range_date(&self) -> Option<HttpDate> {
    match &self.if_range {
      IfRangeSlot::Date(at) => Some(*at),
      IfRangeSlot::Absent | IfRangeSlot::PresentUnusable | IfRangeSlot::Tag(_) => None,
    }
  }

  /// Whether an `If-Range` was pushed at all, whichever form it carried and
  /// whether or not either form read it.
  ///
  /// RFC 9110 §13.2.2's step 5 opens "When the method is GET and both Range and
  /// If-Range are present", so PRESENCE is a conjunct of the step rather than a
  /// detail of the value — and neither
  /// [`if_range_tag`](Self::if_range_tag) nor
  /// [`if_range_date`](Self::if_range_date) can supply it: both answer `None`
  /// for a field that never arrived AND for one neither form could read.
  ///
  /// Those two are different answers, and this is the accessor that tells them
  /// apart. With no `If-Range` at all the step does not run and a `Range`
  /// survives it, reaching step 6 and the caller's ordinary range handling.
  /// With an `If-Range` present and unreadable, §13.1.5's condition is FALSE
  /// over it — "A recipient of an If-Range header field MUST ignore the Range
  /// header field if the If-Range condition evaluates to false" — so the
  /// `Range` is dropped and the answer is a 200. A caller re-deriving step 5
  /// from the two accessors alone cannot see that difference and takes the
  /// wrong branch of it.
  ///
  /// [`evaluate`](Self::evaluate) does not need this: it reads the slot itself.
  /// This exists for the caller that answers §14.2's ordinary range request on
  /// its own, and it is the same observability
  /// [`range_ignored`](Self::range_ignored) provides for the field beside it.
  ///
  /// **The third state has no accessor of its own**, deliberately: `present and
  /// neither form` is this returning `true` with both of the others `None`, and
  /// a fourth accessor would spell one combination of the three that already
  /// exist.
  #[inline]
  pub const fn if_range_present(&self) -> bool {
    !matches!(self.if_range, IfRangeSlot::Absent)
  }

  /// RFC 9110 §14.2's `Range = ranges-specifier`, when it parsed.
  ///
  /// Reading the specifier back out is what keeps a caller from parsing the
  /// field twice: §13.2.2's step 5 runs only when both `Range` and `If-Range`
  /// are present, so an ordinary range request leaves the field unevaluated by
  /// the algorithm and still governed by §14.2.
  ///
  /// # The method this crate never sees
  ///
  /// Two paths reach a live `Range` without a range verdict, and §14.2 answers
  /// them differently.
  ///
  /// A **GET with `Range` and no `If-Range`** is the ordinary range request:
  /// step 5 needs both fields, so the algorithm never reaches the range
  /// verdicts, and §14.2 makes the rest the caller's — "The Range header field
  /// is evaluated after evaluating the precondition header fields defined in
  /// Section 13.1, and only if the result in absence of the Range header field
  /// would be a 200 (OK) response", a fact only the caller holds. It reads this
  /// accessor, calls [`RangesSpecifier::resolve`], and answers 206 or 416
  /// itself.
  ///
  /// **Any other method** is a MUST, not a choice: "A server MUST ignore a
  /// Range header field received with a request method that is unrecognized or
  /// for which range handling is not defined. For this specification, GET is
  /// the only method for which range handling is defined." This accessor still
  /// returns the parse, because visibility is not permission — it is there for
  /// logging, and for a future specification that defines range handling for
  /// some other method.
  ///
  /// [`RangesSpecifier::resolve`]: crate::range::RangesSpecifier::resolve
  #[inline]
  pub const fn range(&self) -> Option<&RangesSpecifier<'a>> {
    self.range.as_ref()
  }

  /// A `Range` was pushed and is not usable.
  ///
  /// True for a value [`RangesSpecifier::parse`] refused — an invalid
  /// `ranges-specifier`, or one carrying more `range-spec`s than
  /// [`MAX_RANGE_SPECS`](crate::range::MAX_RANGE_SPECS) — and for a second
  /// `Range` field pushed after a first. False when no `Range` was pushed at
  /// all, because an absent field was never ignored.
  ///
  /// **Observability, not protocol.** An ignored `Range` produces exactly what
  /// an absent one produces, a 200 carrying the whole representation, and
  /// [`range`](Self::range) answering `None` after a `Range` was pushed already
  /// IS the ignore. This only lets a caller log the difference between a client
  /// that asked for no range and one whose ask was dropped, which is why it
  /// changes no verdict and is a `bool` rather than a variant of something.
  ///
  // gate-exempt: bytes=0-18446744073709551616 — a concrete Range field value
  // this accessor's answer was measured over, not RFC 9110 grammar
  /// **A numeral larger than a [`u64`] is not one of these**, and not because
  /// such a value is tolerated: `bytes=0-18446744073709551616` parses,
  /// [`range`](Self::range) answers `Some`, and this answers `false`. A
  /// position no `u64` holds becomes [`Pos::Beyond`](crate::range::Pos::Beyond)
  /// rather than a truncation or a refusal, and every §14.1.2 rule has an
  /// answer for one — a `Beyond` `first-pos` is at or above every possible
  /// length, a `Beyond` `last-pos` is already that section's own normalisation
  /// condition, and a `Beyond` `suffix-length` exceeds every representation —
  /// so [`RangesSpecifier::resolve`] stays total over such a specifier and
  /// nothing is silently narrowed.
  ///
  /// The whole-value refusal belongs to the sibling type,
  /// [`ContentRange::parse`], and it is the opposite decision taken
  /// deliberately — on DEFINEDNESS rather than on cost. §14.1.2's rules each
  /// have a total answer for a `Beyond` position, as above; §14.4's validity
  /// clauses compare the numerals against EACH OTHER, and `Beyond` against
  /// `Beyond` decides neither of them.
  ///
  /// [`RangesSpecifier::parse`]: crate::range::RangesSpecifier::parse
  /// [`RangesSpecifier::resolve`]: crate::range::RangesSpecifier::resolve
  /// [`ContentRange::parse`]: crate::range::ContentRange::parse
  #[inline]
  pub const fn range_ignored(&self) -> bool {
    self.range_ignored
  }

  /// RFC 9110 §13.2.2's six steps, behind the two of §13.2.1's gates a
  /// recipient can decide from what it holds.
  ///
  /// `selected` is the representation the preconditions are evaluated against,
  /// and `method` and `recipient` are the two facts §13.2.1 and §13.2.2 branch
  /// on. Every outcome the algorithm names has a [`Verdict`] variant, so a
  /// caller matches rather than re-deriving.
  ///
  /// # What the caller settles first, and what it settles after
  ///
  /// §13.2.1's remaining gate cannot be decided here: "A server MUST ignore all
  /// received preconditions if its response to the same request without those
  /// conditions, prior to processing the request content, would have been a
  /// status code other than a 2xx (Successful) or 412 (Precondition Failed)."
  /// This crate never sees that response. A caller that has already settled on
  /// a redirect or a failure must not call this at all — calling it and acting
  /// on the answer is how that MUST gets violated.
  ///
  /// Three more facts stay the caller's, and each is named where it bites:
  ///
  /// - Whether a state-changing request **has already succeeded**. §13.1.1 and
  ///   §13.1.4 each let an origin server answer 2xx in place of the 412, and
  ///   [`Verdict::PreconditionFailed`] is the only variant that carries that
  ///   escape — [`Verdict::PreconditionFailedFinal`] is §13.1.2's MUST and has
  ///   none.
  /// - Whether this resource **supports range requests**, and in which units.
  ///   [`Verdict::RangeApplies`] is this crate's half of a 206 rather than the
  ///   whole of one, because §14.2's SHOULD-206 and SHOULD-416 each carry that
  ///   conjunct. §13.1.5 attaches the same fact to `If-Range`: "An origin
  ///   server MUST ignore an If-Range header field received in a request for a
  ///   target resource that does not support Range requests."
  /// - What an unrecognised range unit means for it, when the answer is
  ///   [`Verdict::RangeUndecidable`] — [`Undecidable`] states each route.
  ///
  /// # Two facts more, at a [`Recipient::Cache`], and they are RFC 9111's
  ///
  /// §13.1.2 and §13.1.3 each CLOSE by handing their cache rules to another
  /// document — "Requirements on cache handling of a received If-None-Match
  /// header field are defined in Section 4.3.2 of \[CACHING\]", and the same
  /// sentence again for `If-Modified-Since` — and \[CACHING\] is RFC 9111,
  /// which §19.1 lists as a NORMATIVE reference. Its §4.3.2 binds whoever passes
  /// [`Recipient::Cache`] here, and neither of its two rules is one this crate
  /// can apply for them.
  ///
  /// - Whether this request's semantics **can be satisfied from a stored
  ///   response**, and whether it holds any stored response for the target.
  ///   RFC 9111 §4.3.2: "A cache MUST NOT evaluate conditional header fields
  ///   that only apply to an origin server, occur in a request with semantics
  ///   that cannot be satisfied with a cached response, or occur in a request
  ///   with a target resource for which it has no stored responses; such
  ///   preconditions are likely intended for some other (inbound) server."
  ///   Three disjuncts, and only the first is applied here — as §13.2.2's
  ///   origin gate on steps 1 and 2, which is [`Recipient::Cache`]'s own
  ///   documentation read from the other side. The other two are facts about
  ///   the cache's store, which this call is never told. A cache that cannot
  ///   satisfy the request from a stored response must not call this at all;
  ///   calling it and acting on the answer is how that MUST NOT gets violated,
  ///   which is the shape of §13.2.1's remaining gate above, one RFC over.
  /// - The stored response's **`Date`, when it holds no `Last-Modified`**. RFC
  ///   9111 §4.3.2: "If a request contains an If-Modified-Since header field
  ///   and the Last-Modified header field is not present in a stored response,
  ///   a cache SHOULD use the stored response's Date field value" to evaluate
  ///   the conditional. [`Selected`] takes ONE modification date and does not
  ///   ask where it came from, so a cache in that position supplies its `Date`
  ///   as that date. Nothing here can substitute a field it was never handed:
  ///   with no `Last-Modified` and no stand-in, step 4 is skipped and that
  ///   SHOULD goes unapplied without anything saying so.
  ///
  /// # The order between the two gates and a standing refusal
  ///
  /// Three rules each read as unconditional, and one request satisfies all
  /// three at once: a malformed `If-Match` on an OPTIONS request at a proxy.
  /// The order is stated because the answer is not derivable from any two of
  /// them.
  ///
  /// 1. **[`Recipient::Forwarding`] first**, answering
  ///    [`Verdict::NotEvaluated`]. §13.2.1 states the forward rule first and
  ///    unconditionally — "A server that is not the origin server for the
  ///    target resource and cannot act as a cache for requests on the target
  ///    resource MUST NOT evaluate the conditional request header fields
  ///    defined by this specification, and it MUST forward them if the request
  ///    is forwarded, since the generating client intends that they be
  ///    evaluated by a server that can provide a current representation." —
  ///    and only then attaches the method rule with *Likewise*. So the forward
  ///    MUST binds whatever the method is, while [`Verdict::Proceed`] promises
  ///    no forwarding at all: answering `Proceed` here would license a proxy to
  ///    drop fields it MUST forward.
  /// 2. **Then [`Method::NoRepresentation`]**, answering [`Verdict::Proceed`].
  ///    §13.2.1: "Likewise, a server MUST ignore the conditional request header
  ///    fields defined by this specification when received with a request
  ///    method that does not involve the selection or modification of a
  ///    selected representation, such as CONNECT, OPTIONS, or TRACE." To ignore
  ///    a field is to act as if it were absent, which is step 6 — and it is not
  ///    an instruction to forward anything, which is why this is a different
  ///    answer from the one above.
  /// 3. **Then a refusal, at the step that reads the refused field.** A refusal
  ///    ranks below both gates because it is this crate's own departure from
  ///    RFC 9110 rather than one of its rules — [`refusal`](Self::refusal) says
  ///    why the departure is taken — and a departure cannot displace a MUST.
  ///
  ///    It is not dispatched ahead of the algorithm at all. `If-Match`'s
  ///    refusal is answered inside step 1 and `If-None-Match`'s inside step 3,
  ///    so each is reachable only when its own step is.
  ///
  ///    **Two different things stop a step, and only one of them is a gate.**
  ///    §13.2.2 gates steps 1 and 2 on the recipient being the origin server,
  ///    so a [`Recipient::Cache`] never reaches `If-Match`. But §13.2.2's steps
  ///    are also a control flow: step 1 answering 412 for a false `If-Match`
  ///    ENDS the algorithm, and step 3 sits downstream of that answer, so a
  ///    malformed `If-None-Match` beside a false `If-Match` is a field this
  ///    evaluation never read either. Dispatching the refusal ahead of the
  ///    steps saw only the gates: it let a refusal displace the verdict of a
  ///    step the algorithm reaches first — the 412 step 1 owes for a false
  ///    `If-Match`, and, one step down, the 412 step 2 owes for a false
  ///    `If-Unmodified-Since`.
  ///
  ///    Each step reads its own field's slot and NOT
  ///    [`refusal`](Self::refusal), which is recipient-blind and reports
  ///    `If-Match`'s when both fields refuse.
  ///
  /// # Where a step's own MUST-ignore rules are applied
  ///
  /// §13.1.3's and §13.1.4's remaining rules are settled here rather than in
  /// [`push`](Self::push), because each turns on a fact only this call is told:
  /// the sibling entity-tag field is step 2's and step 4's own gate, the
  /// request method is step 4's, and a resource with no modification date leaves
  /// nothing to compare against, so the step is SKIPPED. Skipping is not
  /// failing — an `If-Unmodified-Since` against a representation with no
  /// `Last-Modified` reaches step 3, never a 412.
  ///
  /// §13.1.5's presence rule is settled here too: step 5 needs a `Range` this
  /// crate could read, so an `If-Range` arriving without one is ignored, as "A
  /// server MUST ignore an If-Range header field received in a request that
  /// does not contain a Range header field" requires.
  ///
  /// # The Range this crate ignored is not a Range step 5 can apply
  ///
  /// §14.2 grants the 416 only over a value it has already called valid, in a
  /// sentence that names every conjunct: "If all of the preconditions are true,
  /// the server supports the Range header field for the target resource, the
  /// received Range field-value contains a valid ranges-specifier, and either
  /// the range-unit is not supported for that target resource or the
  /// ranges-specifier is unsatisfiable with respect to the selected
  /// representation, the server SHOULD send a 416 (Range Not Satisfiable)
  /// response." A value
  /// [`RangesSpecifier::parse`](crate::range::RangesSpecifier::parse) refused is
  /// not a valid one, and §14.2's blanket permission — "A server MAY ignore the
  /// Range header field." — was already taken over it in [`push`](Self::push).
  /// Step 5 therefore has no `Range` to apply, the algorithm reaches step 6,
  /// and [`range_ignored`](Self::range_ignored) is what says the field was
  /// there.
  #[must_use]
  pub fn evaluate(&self, selected: &Selected<'_>, method: Method, recipient: Recipient) -> Verdict {
    // §13.2.1's forward MUST, ahead of everything: it is the one rule whose
    // answer says something about the request's onward journey.
    if matches!(recipient, Recipient::Forwarding) {
      return Verdict::NotEvaluated;
    }
    // §13.2.1's method MUST. Ignoring every conditional field is step 6.
    if matches!(method, Method::NoRepresentation) {
      return Verdict::Proceed;
    }

    // Step 1. "When recipient is the origin server and If-Match is present,
    // evaluate the If-Match precondition". A true condition continues to step
    // 3, which is step 2's own gate below rather than a jump.
    //
    // The refusal is answered HERE, under step 1's own recipient gate, because
    // this is the step that consults the field: a `Cache` never reaches it, and
    // an origin server that does reach it cannot evaluate a value neither list
    // could read.
    if matches!(recipient, Recipient::OriginServer) {
      if let TagSlot::Refused(why) = self.if_match {
        return refused(why);
      }
      if let TagSlot::Read(list) = &self.if_match
        && !if_match_condition(list, selected)
      {
        return Verdict::PreconditionFailed {
          failed: EscapablePrecondition::IfMatch,
          status: Status::PreconditionFailed,
        };
      }
    }

    // Step 2. "When recipient is the origin server, If-Match is not present,
    // and If-Unmodified-Since is present". A `TagSlot::Absent` is exactly *not
    // present*: a refused field WAS present, and at this recipient a refused
    // `If-Match` has already returned above.
    if matches!(recipient, Recipient::OriginServer)
      && matches!(self.if_match, TagSlot::Absent)
      && let DateField::Usable(until) = self.if_unmodified_since
      // §13.1.4's third MUST-ignore rule: no modification date, no comparison,
      // so the step is skipped rather than failed.
      && let Some(modified) = selected.last_modified()
      // §13.1.4: "If the selected representation's last modification date is
      // earlier than or equal to the date provided in the field value, the
      // condition is true."
      && modified > until
    {
      return Verdict::PreconditionFailed {
        failed: EscapablePrecondition::IfUnmodifiedSince,
        status: Status::PreconditionFailed,
      };
    }

    // Step 3. "When If-None-Match is present, evaluate the If-None-Match
    // precondition" — no recipient gate at all, which is why a cache reaches
    // this and not the two above.
    //
    // Reaching this line is the whole of what entitles the refusal below to an
    // answer. Steps 1 and 2 each return when their condition is false, so a
    // malformed `If-None-Match` behind either of them is a field this
    // evaluation never consulted.
    if let TagSlot::Refused(why) = self.if_none_match {
      return refused(why);
    }
    if let TagSlot::Read(list) = &self.if_none_match
      && !if_none_match_condition(list, selected)
    {
      // §13.1.2 states both outcomes as MUSTs, so neither carries §13.1.1's and
      // §13.1.4's already-succeeded escape.
      return match method {
        Method::Get | Method::Head => Verdict::NotModified {
          failed: NotModifiedPrecondition::IfNoneMatch,
          status: Status::NotModified,
        },
        Method::Other | Method::NoRepresentation => Verdict::PreconditionFailedFinal {
          status: Status::PreconditionFailed,
        },
      };
    }

    // Step 4. "When the method is GET or HEAD, If-None-Match is not present,
    // and If-Modified-Since is present". The first two conjuncts are also
    // §13.1.3's own two MUST-ignore rules that this call is the first to hold.
    if matches!(method, Method::Get | Method::Head)
      && matches!(self.if_none_match, TagSlot::Absent)
      && let DateField::Usable(since) = self.if_modified_since
      && let Some(modified) = selected.last_modified()
      // §13.1.3: "If the selected representation's last modification date is
      // earlier or equal to the date provided in the field value, the condition
      // is false." The opposite direction from step 2's, over the same pair.
      && modified <= since
    {
      return Verdict::NotModified {
        failed: NotModifiedPrecondition::IfModifiedSince,
        status: Status::NotModified,
      };
    }

    // Step 5. "When the method is GET and both Range and If-Range are present,
    // evaluate the If-Range precondition" — GET alone, where steps 3 and 4 say
    // GET or HEAD.
    if matches!(method, Method::Get)
      && let Some(range) = &self.range
      && !matches!(self.if_range, IfRangeSlot::Absent)
    {
      return step_5(range, &self.if_range, selected);
    }

    // Step 6.
    Verdict::Proceed
  }
}

/// The request method, in the four classes RFC 9110 §13.2.1 and §13.2.2 divide
/// every method into.
///
/// Four coarse classes rather than a method vocabulary: §13.2.2 branches on
/// GET, on HEAD beside it, and on everything else, and §13.2.1 splits one class
/// off from all three. A general method type would carry §9.2's properties as
/// well, which nothing in this crate reads.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Method {
  /// `GET`. The only method §13.2.2's step 5 admits, which RFC 9110 §14.2
  /// matches: "For this specification, GET is the only method for which range
  /// handling is defined."
  Get,
  /// `HEAD`. Steps 3 and 4 treat it as GET; step 5 does not.
  Head,
  /// Any other method that involves the selection or modification of a selected
  /// representation.
  ///
  /// The class §13.1.2's step-3 412 is for — that sentence is quoted whole on
  /// [`Verdict::PreconditionFailedFinal`] — and the class the state-changing
  /// method of §13.1.1's and §13.1.4's escape belongs to.
  Other,
  /// A method that does NOT involve the selection or modification of a selected
  /// representation.
  ///
  /// §13.2.1 gives CONNECT, OPTIONS and TRACE as examples, and the criterion
  /// rather than the list is the rule — a method defined elsewhere that meets it
  /// belongs here too. [`Preconditions::evaluate`] answers
  /// [`Verdict::Proceed`] for it, because to ignore every conditional field is
  /// to act as if none arrived.
  NoRepresentation,
}

/// Which of RFC 9110 §13.2.1's three recipients is evaluating.
///
/// §13.2.1 divides recipients by a two-part test — being the origin server for
/// the target resource, and being able to act as a cache for requests on it —
/// and the two conjuncts have different consequences, so a two-variant split
/// cannot carry them. See [`Forwarding`](Self::Forwarding).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Recipient {
  /// The origin server for the target resource.
  ///
  /// The one recipient §13.2.2 lets reach steps 1 and 2, which is also what
  /// §13.1.1's "A cache or intermediary MAY ignore If-Match because its
  /// interoperability features are only necessary for an origin server" says
  /// from the other side.
  OriginServer,
  /// Not the origin server, and able to act as a cache for requests on the
  /// target resource.
  ///
  /// §13.2.2's step 3 is gated on nothing, so this recipient evaluates
  /// `If-None-Match` and — through step 4 — `If-Modified-Since`, and never
  /// reaches `If-Match` or `If-Unmodified-Since`.
  ///
  /// RFC 9111 §4.3.2 states the same rule in its own words, and states it as a
  /// summary of the whole precedence rather than as a consequence of one
  /// section's gate: "In summary, the If-Match and If-Unmodified-Since
  /// conditional header fields are not applicable to a cache, and If-None-Match
  /// takes precedence over If-Modified-Since." Two specifications reaching one
  /// answer, and the second of them is the one addressed to the recipient this
  /// variant names.
  ///
  /// **Naming this variant is a claim about the REQUEST as well.** §4.3.2 also
  /// carries a MUST NOT that no argument to [`Preconditions::evaluate`] can
  /// express — a cache must not evaluate preconditions in a request whose
  /// semantics a stored response cannot satisfy, or for a target resource it
  /// holds no stored response for. That rule is a delegation on
  /// [`evaluate`](Preconditions::evaluate), where it is quoted whole, and it is
  /// why passing this variant with a state-changing method is ANSWERED rather
  /// than refused: the answer is what §13.2.2 says for the question asked, and
  /// asking it is what RFC 9111 forbids.
  Cache,
  /// Neither the origin server for the target resource nor able to act as a
  /// cache for requests on it.
  ///
  /// The only class §13.2.1 tells to forward, which is why it has its own
  /// verdict: [`Verdict::NotEvaluated`].
  Forwarding,
}

/// What RFC 9110 §13.2.2's algorithm answered.
///
/// Every outcome the six steps and the two gates name has a variant, and the
/// `status` each carries is the code that step reaches — so a caller matches
/// once rather than reading a cause and re-deriving a code from prose.
///
/// **Which precondition failed is data rather than prose.** §13.1.1's and
/// §13.1.4's 412 comes with an escape and §13.1.2's does not, so the two are
/// separate variants and the escapable one names its field through
/// [`EscapablePrecondition`]. A single variant carrying a five-member field
/// would let §13.1.2's case be spelled with an escape it does not have.
///
/// [`NotModified`](Self::NotModified) is the same doctrine over the 304 pair,
/// and it needs no second variant: both 304s are the same answer, and what
/// differs is the STRENGTH of the rule that produced it — §13.1.2's MUST at
/// step 3, §13.1.3's SHOULD at step 4. So it is one variant naming its
/// precondition through [`NotModifiedPrecondition`].
///
/// **No `PartialEq`.** [`RangeNotSatisfiable`](Self::RangeNotSatisfiable)
/// carries a [`ContentRange`], which does not derive it and states why in its
/// own documentation.
///
/// Exhaustively matchable on purpose: RFC 9110 §13.2.2's algorithm is closed,
/// and a caller that must answer a request cannot have a fallback arm that
/// means anything.
#[derive(Debug, Copy, Clone)]
pub enum Verdict {
  /// 412, with the escape §13.1.1 and §13.1.4 attach to it.
  ///
  /// **The rule this verdict carries is a prohibition, and it is not a MAY.**
  /// §13.1.1: "An origin server that evaluates an If-Match condition MUST NOT
  /// perform the requested method if the condition evaluates to false." §13.1.4
  /// states the same sentence for `If-Unmodified-Since`. Everything below is an
  /// alternative WITHIN that MUST NOT rather than an alternative TO it: a
  /// caller reading only that the 412 is a MAY has been told what it may choose
  /// between and not the one thing it may not do, which is to carry on and
  /// perform the method.
  ///
  /// Both sections then state the 412 as a MAY and set a second MAY beside it,
  /// in the same two sentences: "Instead, the origin server MAY indicate that the
  /// conditional request failed by responding with a 412 (Precondition Failed)
  /// status code. Alternatively, if the request is a state-changing operation
  /// that appears to have already been applied to the selected representation,
  /// the origin server MAY respond with a 2xx (Successful) status code (i.e.,
  /// the change requested by the user agent has already succeeded, but the user
  /// agent might not be aware of it, perhaps because the prior response was
  /// lost or an equivalent change was made by some other user agent)." Whether
  /// it has already been applied is the caller's fact, so the choice is left
  /// where the facts are.
  ///
  /// That 2xx is an escape from the STATUS and never from the prohibition. It
  /// is available exactly when the change "appears to have already been
  /// applied", which is to say when performing the method is not what the 2xx
  /// would be reporting.
  PreconditionFailed {
    /// Which of the two escapable preconditions failed.
    failed: EscapablePrecondition,
    /// [`Status::PreconditionFailed`].
    status: Status,
  },
  /// 412 with no escape — §13.1.2's, for a method other than GET or HEAD.
  ///
  /// §13.1.2 states the prohibition and both of step 3's outcomes in one
  /// sentence, and all three are MUSTs: "An origin server that evaluates an
  /// If-None-Match condition MUST NOT perform the requested method if the
  /// condition evaluates to false; instead, the origin server MUST respond with
  /// either a) the 304 (Not Modified) status code if the request method is GET
  /// or HEAD or b) the 412 (Precondition Failed) status code for all other
  /// request methods." A caller applying §13.1.1's escape here would answer 2xx
  /// to exactly the retried-PUT case that rule exists for — and would perform
  /// the method while doing it, which is the half no status can repair.
  PreconditionFailedFinal {
    /// [`Status::PreconditionFailed`].
    status: Status,
  },
  /// 304, from step 3's GET-or-HEAD half or from step 4.
  ///
  /// **Two rules of different strength reach this one variant, and `failed` is
  /// which.** Step 3's is §13.1.2's MUST — quoted whole on
  /// [`PreconditionFailedFinal`](Self::PreconditionFailedFinal), since one
  /// sentence there carries both of that step's outcomes. Step 4's is §13.1.3's
  /// SHOULD, prohibition and answer alike: "An origin server that evaluates an
  /// If-Modified-Since condition SHOULD NOT perform the requested method if the
  /// condition evaluates to false; instead, the origin server SHOULD generate a
  /// 304 (Not Modified) response, including only those metadata that are useful
  /// for identifying or updating a previously cached response."
  ///
  /// A recipient with a reason to deviate may deviate from the second and may
  /// not from the first, so a variant carrying neither leaves any deviation
  /// policy applied to both halves at once. That is the miscut
  /// [`PreconditionFailed`](Self::PreconditionFailed) and
  /// [`PreconditionFailedFinal`](Self::PreconditionFailedFinal) exist to avoid,
  /// one status code over — and here the step that fired is a fact
  /// [`Preconditions::evaluate`] already HOLDS, so naming it costs nothing and
  /// discarding it was the whole of the loss.
  ///
  /// §13.1.3's "including only those metadata that are useful for identifying
  /// or updating a previously cached response" is the caller's to apply: this
  /// crate settles which status the request reaches and writes no response.
  NotModified {
    /// Which precondition's condition evaluated false, and with it whether the
    /// 304 is a MUST or a SHOULD.
    failed: NotModifiedPrecondition,
    /// [`Status::NotModified`].
    status: Status,
  },
  /// Step 5's `If-Range` is true and the `Range` is satisfiable.
  ///
  /// **This crate's half of a 206, not the whole of one.** §14.2's SHOULD-206
  /// is a conjunction of five, and two of them are facts this crate does not
  /// hold: "If all of the preconditions are true, the server supports the Range
  /// header field for the target resource, the received Range field-value
  /// contains a valid ranges-specifier with a range-unit supported for that
  /// target resource, and that ranges-specifier is satisfiable with respect to
  /// the selected representation, the server SHOULD send a 206 (Partial
  /// Content) response with content containing one or more partial
  /// representations that correspond to the satisfiable range-spec(s)
  /// requested." No positions are carried either: the caller reads them back
  /// through [`Preconditions::range`] and
  /// [`RangesSpecifier::resolve`](crate::range::RangesSpecifier::resolve), so
  /// the byte offsets have exactly one source.
  RangeApplies {
    /// [`Status::PartialContent`].
    status: Status,
  },
  /// A valid `bytes` ranges-specifier that no `range-spec` satisfies.
  ///
  /// **Answering 416 here is a choice this design records rather than a
  /// derivation.** RFC 9110 §13.2.2's step 5 sends a true `If-Range` over a
  /// Range that is not applicable to its own *otherwise* — "otherwise, ignore
  /// the Range header field and respond 200 (OK)" — while §14.2 makes the same
  /// request a SHOULD-416, and every conjunct of that SHOULD is met. This crate
  /// follows §14.2, on §13.1.5's "Otherwise, the recipient SHOULD process the
  /// Range header field as requested". The argument, both texts whole, and the
  /// reading this design did not take, are at the `step_5` arm that builds this
  /// variant.
  ///
  /// `content_range` is §14.4's `unsatisfied-range`, `"*/" complete-length`,
  /// which cannot be written at all without a complete length — hence the
  /// option. [`Preconditions::evaluate`] reaches this variant only when the
  /// length is known, because an unknown one is
  /// [`Undecidable::LengthUnknown`], so it always fills the field in. §14.4
  /// makes sending the field a SHOULD rather than a requirement.
  RangeNotSatisfiable {
    /// [`Status::RangeNotSatisfiable`].
    status: Status,
    /// §14.4's `unsatisfied-range` for the complete length that was known.
    content_range: Option<ContentRange<'static>>,
  },
  /// Step 5's *otherwise*: ignore the `Range` header field and respond 200.
  IgnoreRange {
    /// Which of the two sentences sanctions the ignore.
    reason: RangeIgnored,
    /// [`Status::Ok`].
    status: Status,
  },
  /// Step 5 was reached and this crate cannot decide it.
  ///
  /// Not an outcome RFC 9110 names, because the RFC assumes a recipient knows
  /// its own units and its own lengths; this crate may hold neither, and saying
  /// so beats picking one of the answers the caller's missing fact would have
  /// chosen between. The `status` is [`Status::Ok`] — the code both of §14.2's
  /// routes for an unusable unit reach when the caller has nothing further —
  /// so the field never carries a code no rule produced.
  RangeUndecidable {
    /// Which fact was missing.
    reason: Undecidable,
    /// [`Status::Ok`].
    status: Status,
  },
  /// A field this crate refuses to answer from.
  ///
  /// Returned in place of a verdict so that a caller who never reads
  /// [`Preconditions::refusal`] cannot receive [`Proceed`](Self::Proceed) over
  /// a lost-update guard that was dropped. The `status` is the one the cause
  /// suggests, which is the same suggestion [`PreconditionRefusal`]'s own
  /// variants document.
  ///
  /// **Only over a field the evaluation reached.**
  /// [`Preconditions::evaluate`] answers each refusal inside the step that
  /// consults its field, so this variant never displaces the verdict of a step
  /// RFC 9110 §13.2.2 reaches first: a malformed `If-None-Match` beside an
  /// `If-Match` that fails at step 1 leaves the 412 standing, because step 3 is
  /// never reached. The guarantee above survives that, and is what it was
  /// always about — no step of the algorithm runs on a value this crate refused
  /// to read, and no `Proceed` is answered over one.
  Refused {
    /// Why the field was refused.
    refusal: PreconditionRefusal,
    /// [`Status::BadRequest`] for
    /// [`PreconditionRefusal::Malformed`], [`Status::FieldsTooLarge`] for
    /// [`PreconditionRefusal::TooManyTags`].
    status: Status,
  },
  /// Step 6: "perform the requested method and respond according to its success
  /// or failure."
  ///
  /// Carries no status, because the status is the method's own and no
  /// precondition had a hand in it. §13.2.1's method rule reaches this too, by
  /// ignoring every conditional field.
  Proceed,
  /// §13.2.1: this recipient is neither the origin server nor able to cache, so
  /// it MUST NOT evaluate these fields and MUST forward them if it forwards the
  /// request.
  ///
  /// Distinct from [`Proceed`](Self::Proceed), which promises no forwarding: a
  /// caller acting on `Proceed` here would drop fields it MUST pass on.
  NotEvaluated,
}

/// The two preconditions whose 412 carries RFC 9110 §13.1.1's and §13.1.4's
/// already-succeeded escape.
///
/// Its own closed type so that §13.1.2's case cannot be spelled here. A general
/// five-member precondition vocabulary would let
/// [`Verdict::PreconditionFailed`] name `If-None-Match`, and the escape it
/// documents is one §13.1.2 does not grant.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EscapablePrecondition {
  /// RFC 9110 §13.1.1's `If-Match`, evaluated at step 1.
  IfMatch,
  /// RFC 9110 §13.1.4's `If-Unmodified-Since`, evaluated at step 2.
  IfUnmodifiedSince,
}

/// Which precondition's condition evaluated false, for a
/// [`Verdict::NotModified`].
///
/// Its own closed type for the reason [`EscapablePrecondition`] is one, and not
/// that same type: no precondition belongs to both lists. §13.1.1's and
/// §13.1.4's reach a 412 and never a 304, §13.1.3's reaches a 304 and never a
/// 412, and §13.1.2's is the only one that reaches either — where which of the
/// two it reaches is settled by the request method rather than by the field.
///
/// What this carries that the status code cannot is the STRENGTH of the rule
/// behind the 304, so a caller reads it here instead of re-deriving it from the
/// [`Method`] it passed in.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NotModifiedPrecondition {
  /// RFC 9110 §13.1.2's `If-None-Match`, evaluated at step 3, where the 304 is
  /// a **MUST** for a GET or a HEAD.
  ///
  /// The same sentence makes the 412 a MUST for every other method, which is
  /// [`Verdict::PreconditionFailedFinal`]; both halves are quoted there.
  IfNoneMatch,
  /// RFC 9110 §13.1.3's `If-Modified-Since`, evaluated at step 4, where the 304
  /// is a **SHOULD**.
  ///
  /// §13.1.3 is a SHOULD throughout, the evaluation included: "When an origin
  /// server receives a request that selects a representation and that request
  /// includes an If-Modified-Since header field without an If-None-Match header
  /// field, the origin server SHOULD evaluate the If-Modified-Since condition
  /// per Section 13.2 prior to performing the method." §13.1.1, §13.1.2 and
  /// §13.1.4 all say MUST in the matching sentence.
  IfModifiedSince,
}

/// Why a `Range` was ignored and a 200 answered in place of a 206.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RangeIgnored {
  /// RFC 9110 §13.2.2's step 5 *otherwise*: the `If-Range` condition is false.
  ///
  /// §13.1.5 states it as its own MUST as well: "A recipient of an If-Range
  /// header field MUST ignore the Range header field if the If-Range condition
  /// evaluates to false."
  IfRangeFalse,
  /// The selected representation has zero length.
  ///
  /// RFC 9110 §14.1.2 leaves one form satisfiable there — a suffix-range with a
  /// non-zero suffix-length — and the whole of an empty representation has no
  /// inclusive positions to name, so a 206 has no content to carry and §14.4
  /// can express no `Content-Range` for it. A 416 would contradict §14.1.2,
  /// which called the specifier satisfiable. §14.2 supplies the exit: "A server
  /// that supports range requests MAY ignore a Range header field when the
  /// selected representation has no content (i.e., the selected
  /// representation's data is of zero length)."
  EmptyRepresentation,
}

/// A fact RFC 9110 §13.2.2's step 5 needs that this crate does not hold.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Undecidable {
  /// The `range-unit` is not `bytes`.
  ///
  /// RFC 9110 §14.1.1 makes satisfiability "as defined by the indicated
  /// range-unit" and §14.1.2's rules are `bytes`-only, so neither satisfiability
  /// nor unit support is this crate's to answer. The value is readable through
  /// [`Preconditions::range`], and §14.2 splits what the caller does with it
  /// three ways: an origin server that does not understand the unit MUST ignore
  /// the field, a proxy MAY discard it, and a recipient that does understand it
  /// applies that unit's own satisfiability rule.
  UnitNotBytes,
  /// The [`Selected`] representation carries no complete length.
  ///
  /// An int-range's satisfiability is "an int-range with a first-pos that is
  /// less than the current length of the selected representation" (RFC 9110
  /// §14.1.2), and with no length there is nothing to compare against. The
  /// specifier is still readable through [`Preconditions::range`], and
  /// [`RangesSpecifier::spec`](crate::range::RangesSpecifier::spec) hands back
  /// each `range-spec` unresolved.
  ///
  /// **A non-zero suffix-range reaches here too**, and satisfiability is not
  /// why. §14.1.2's satisfiability list puts no length condition on that form —
  /// "a suffix-range with a non-zero suffix-length" is the whole of the entry —
  /// and the section keeps it satisfiable at every length, zero included: "When
  /// a selected representation has zero length, the only satisfiable form of
  /// range-spec in a GET request is a suffix-range with a non-zero
  /// suffix-length." So the question is not WHETHER such a specifier is
  /// satisfiable but WHICH satisfiable verdict applies, and only the length
  /// separates them: [`Verdict::RangeApplies`] above zero, and
  /// [`Verdict::IgnoreRange`] carrying
  /// [`RangeIgnored::EmptyRepresentation`] at zero — the exit §14.2 supplies
  /// where a 206 would have no content to carry. With no length this crate
  /// cannot pick between the two, which is what this variant says.
  LengthUnknown,
}

/// RFC 9110 §13.2.2's step 5, once both its fields are known to be present and
/// the method is GET.
///
/// The `If-Range` condition is evaluated FIRST and alone, because step 5 makes
/// applicability the second half of a conjunction: "if true and the Range is
/// applicable to the selected representation, respond 206 (Partial Content) …
/// otherwise, ignore the Range header field and respond 200 (OK)". A false
/// condition is answered without asking anything about the unit or the length.
fn step_5(
  range: &RangesSpecifier<'_>,
  if_range: &IfRangeSlot<'_>,
  selected: &Selected<'_>,
) -> Verdict {
  if !if_range_condition(if_range, selected) {
    return Verdict::IgnoreRange {
      reason: RangeIgnored::IfRangeFalse,
      status: Status::Ok,
    };
  }
  // `is_empty` is true exactly when the unit is not `bytes`, which is also the
  // one case `other_range_set` answers `Some` for.
  if range.other_range_set().is_some() {
    return Verdict::RangeUndecidable {
      reason: Undecidable::UnitNotBytes,
      status: Status::Ok,
    };
  }
  let Some(complete_length) = selected.complete_length() else {
    return Verdict::RangeUndecidable {
      reason: Undecidable::LengthUnknown,
      status: Status::Ok,
    };
  };
  // §14.1.1's set level: one satisfiable range-spec makes the set satisfiable.
  // The walk is a `resolve` per index rather than `is_satisfiable`, because the
  // two satisfiable answers lead to different verdicts and that predicate
  // collapses them — §14.1.2 makes `EmptyRepresentation` satisfiable, and it
  // reaches a 200 rather than a 206.
  let mut empty = false;
  for index in 0..range.len() {
    match range.resolve(index, complete_length) {
      Some(Resolved::Range(_, _)) => {
        return Verdict::RangeApplies {
          status: Status::PartialContent,
        };
      }
      Some(Resolved::EmptyRepresentation) => empty = true,
      Some(Resolved::Unsatisfiable) | None => {}
    }
  }
  if empty {
    return Verdict::IgnoreRange {
      reason: RangeIgnored::EmptyRepresentation,
      status: Status::Ok,
    };
  }
  // ── A CHOICE, not an oversight: 416 where step 5's own *otherwise* reads 200 ─
  //
  // Nothing above this line satisfied step 5's first bullet, so a literal
  // reading of §13.2.2 lands in its second and answers 200. Both texts, whole:
  //
  //   5.  When the method is GET and both Range and If-Range are present,
  //       evaluate the If-Range precondition:
  //
  //       *  "if true and the Range is applicable to the selected
  //          representation, respond 206 (Partial Content)"
  //
  //       *  "otherwise, ignore the Range header field and respond 200 (OK)"
  //
  // and §14.2, whose subject is this exact request: "If all of the
  // preconditions are true, the server supports the Range header field for the
  // target resource, the received Range field-value contains a valid
  // ranges-specifier, and either the range-unit is not supported for that
  // target resource or the ranges-specifier is unsatisfiable with respect to
  // the selected representation, the server SHOULD send a 416 (Range Not
  // Satisfiable) response."
  //
  // Every conjunct of that SHOULD is met on this path: the preconditions are
  // true (steps 1-4 passed and the `If-Range` condition evaluated true above),
  // the specifier parsed, the unit is `bytes`, and the loop above resolved no
  // `range-spec`. So §13.2.2 routes a 200 and §14.2 routes a 416, over one
  // request, and the two sections do not resolve it between them.
  //
  // **This design answers 416.** §13.1.5 is the third text and it is what tips
  // the reading: "A recipient of an If-Range header field MUST ignore the Range
  // header field if the If-Range condition evaluates to false.  Otherwise, the
  // recipient SHOULD process the Range header field as requested." A true
  // `If-Range` means processing the Range as requested, and processing an
  // unsatisfiable ranges-specifier as requested is what §14.2 spells out one
  // section later. Step 5's *otherwise* then reads as the exit for a FALSE
  // condition — which is the branch at the top of this function — rather than
  // as a second answer for a true one. Deployed servers answer 416 here.
  //
  // **The other reading is defensible, and a reader who prefers it is not
  // making a mistake.** §13.2.2's step 5 is an algorithm with two bullets and
  // no third, its *otherwise* is unqualified, and §14.2's is a SHOULD against
  // an algorithm the same document tells a server to run. The crate's banner is
  // *the derivations RFC 9110 settles*, and this is one it does not settle
  // cleanly, so the choice is recorded here rather than presented as a
  // derivation. It is an open errata target: the errata check has been run and
  // there is NO erratum, so 416 stands as a choice and not as a correction. If
  // a later erratum settles it the other way, this comment is the paragraph
  // that has to move, and the change is `status`, `content_range` and the
  // variant on the two lines below.
  Verdict::RangeNotSatisfiable {
    status: Status::RangeNotSatisfiable,
    content_range: Some(ContentRange::unsatisfied(complete_length)),
  }
}

/// RFC 9110 §13.1.1's three evaluation steps for `If-Match`, each stated whole:
///
/// 1. "If the field value is "*", the condition is true if the origin server
///    has a current representation for the target resource."
/// 2. "If the field value is a list of entity tags, the condition is true if
///    any of the listed tags match the entity tag of the selected
///    representation." The comparison is §8.8.3.2's STRONG one: "An origin
///    server MUST use the strong comparison function when comparing entity tags
///    for If-Match (Section 8.8.3.2), since the client intends this
///    precondition to prevent the method from being applied if there have been
///    any changes to the representation data."
/// 3. "Otherwise, the condition is false." That is where a representation with
///    no entity tag lands: no tag can match one that is not there.
fn if_match_condition(list: &TagList<'_>, selected: &Selected<'_>) -> bool {
  if list.is_star() {
    return selected.exists();
  }
  let Some(etag) = selected.etag() else {
    return false;
  };
  (0..list.len()).any(|index| list.get(index).is_some_and(|tag| tag.strong_eq(&etag)))
}

/// RFC 9110 §13.1.2's three evaluation steps for `If-None-Match`, which mirror
/// §13.1.1's rather than negating them:
///
/// 1. "If the field value is "*", the condition is false if the origin server
///    has a current representation for the target resource."
/// 2. "If the field value is a list of entity tags, the condition is false if
///    one of the listed tags matches the entity tag of the selected
///    representation." The comparison is §8.8.3.2's WEAK one: "A recipient MUST
///    use the weak comparison function when comparing entity tags for
///    If-None-Match (Section 8.8.3.2), since weak entity tags can be used for
///    cache validation even if there have been changes to the representation
///    data."
/// 3. "Otherwise, the condition is true." That is where a representation with
///    no entity tag lands — the opposite answer §13.1.1's own step 3 gives.
fn if_none_match_condition(list: &TagList<'_>, selected: &Selected<'_>) -> bool {
  if list.is_star() {
    return !selected.exists();
  }
  let Some(etag) = selected.etag() else {
    return true;
  };
  !(0..list.len()).any(|index| list.get(index).is_some_and(|tag| tag.weak_eq(&etag)))
}

/// RFC 9110 §13.1.5's two evaluation lists, one per form.
///
/// The date form is three steps: not a strong validator is false, an exact match
/// with the selected representation's `Last-Modified` is true, otherwise false.
/// Exact, not earlier-or-equal — §13.1.5 says so itself: "Note that the If-Range
/// comparison is by exact match, including when the validator is an HTTP-date,
/// and so it differs from the "earlier than or equal to" comparison used when
/// evaluating an If-Unmodified-Since conditional."
///
/// The entity-tag form is two: an exact match under §8.8.3.2's strong comparison
/// is true, otherwise false. So a weak tag on either side is false, which is the
/// evaluation-side answer to §13.1.5's "A client MUST NOT generate an If-Range
/// header field containing an entity tag that is marked as weak".
///
/// [`IfRangeSlot::PresentUnusable`] is false rather than a refusal, for the
/// reason the module doc gives, and [`IfRangeSlot::Absent`] cannot arrive:
/// [`Preconditions::evaluate`] reaches step 5 only when the field is present.
/// False is still its answer, so this function is total over the slot.
fn if_range_condition(slot: &IfRangeSlot<'_>, selected: &Selected<'_>) -> bool {
  match slot {
    IfRangeSlot::Absent | IfRangeSlot::PresentUnusable => false,
    IfRangeSlot::Tag(tag) => selected.etag().is_some_and(|etag| tag.strong_eq(&etag)),
    IfRangeSlot::Date(at) => {
      selected.last_modified_is_strong()
        && matches!(selected.last_modified(), Some(seen) if seen == *at)
    }
  }
}

/// [`Verdict::Refused`] for a cause, built in the one place so that the two
/// steps that can answer it cannot come to pair a cause with different statuses.
///
/// Called from inside RFC 9110 §13.2.2's step 1 and step 3 rather than ahead of
/// them, which is [`Preconditions::evaluate`]'s precedence section: reaching the
/// call is what says this evaluation consulted the field.
const fn refused(refusal: PreconditionRefusal) -> Verdict {
  Verdict::Refused {
    refusal,
    status: refusal_status(refusal),
  }
}

/// The status each refusal cause suggests, as [`PreconditionRefusal`]'s own
/// variants document it.
///
/// Neither is RFC 9110's: the section names no status for either fault, and the
/// two suggest different ones, so the mapping lives here rather than being left
/// to a caller that would have to re-derive it.
const fn refusal_status(refusal: PreconditionRefusal) -> Status {
  match refusal {
    PreconditionRefusal::TooManyTags { .. } => Status::FieldsTooLarge,
    PreconditionRefusal::Malformed { .. } => Status::BadRequest,
  }
}

/// One `If-Match` or `If-None-Match` value into its slot.
///
/// A field already pushed refuses rather than replacing what it read; see
/// [`Preconditions::push`] for why a second field line cannot be joined to the
/// first here.
fn read_tag_field<'a>(slot: &TagSlot<'a>, value: &'a [u8], field: TagField) -> TagSlot<'a> {
  if !matches!(slot, TagSlot::Absent) {
    return TagSlot::Refused(PreconditionRefusal::Malformed { field });
  }
  match TagList::parse(value) {
    Ok(list) => TagSlot::Read(list),
    // The two causes are kept apart because they suggest different statuses,
    // and `StarInList` joins `Malformed` on purpose: a `*` beside another value
    // is syntactically invalid by RFC 9110 §13.1.1's and §13.1.2's own note,
    // which is a fault in the value and not a complaint about its size.
    Err(TagError::TooMany) => TagSlot::Refused(PreconditionRefusal::TooManyTags { field }),
    Err(TagError::Malformed | TagError::StarInList) => {
      TagSlot::Refused(PreconditionRefusal::Malformed { field })
    }
  }
}

/// One `If-Modified-Since` or `If-Unmodified-Since` value into its slot.
///
/// The clock reaches [`parse_http_date_from`] and no further: RFC 9110 §5.6.7's
/// fifty-year rule is the only thing in this crate that consults it, and only
/// an `rfc850-date` reaches that rule.
fn read_date_field(slot: DateField, value: &[u8], now_unix_seconds: i64) -> DateField {
  if !matches!(slot, DateField::Absent) {
    return DateField::PresentUnusable;
  }
  match parse_http_date_from(value, now_unix_seconds) {
    Ok(at) => DateField::Usable(at),
    // Every refusal the date reader can make is the same fact here: RFC 9110
    // §13.1.3 and §13.1.4 MUST-ignore the field when its value is not a valid
    // `HTTP-date`, and they draw no distinction between the ways it can fail
    // to be one.
    Err(_) => DateField::PresentUnusable,
  }
}

/// One `If-Range` value into its slot, split by RFC 9110 §13.1.5's own rule.
///
/// "A valid entity-tag can be distinguished from a valid HTTP-date by examining
/// the first three characters for a DQUOTE." Three, not one: the `entity-tag`
/// form's optional `weak = %s"W/"` prefix puts the DQUOTE third.
fn read_if_range<'a>(
  slot: &IfRangeSlot<'a>,
  value: &'a [u8],
  now_unix_seconds: i64,
) -> IfRangeSlot<'a> {
  if !matches!(slot, IfRangeSlot::Absent) {
    return IfRangeSlot::PresentUnusable;
  }
  if value.iter().take(3).any(|byte| *byte == b'"') {
    match EntityTag::parse(value) {
      Ok(tag) => IfRangeSlot::Tag(tag),
      Err(_) => IfRangeSlot::PresentUnusable,
    }
  } else {
    match parse_http_date_from(value, now_unix_seconds) {
      Ok(at) => IfRangeSlot::Date(at),
      Err(_) => IfRangeSlot::PresentUnusable,
    }
  }
}

#[cfg(test)]
mod tests;
