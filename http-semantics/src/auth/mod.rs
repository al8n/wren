//! RFC 9110 §11.2's two forms of authentication data: the `auth-param` every
//! authentication field in §11 is built out of, and the `token68` a credential
//! may carry in place of a whole list of them.
//!
//! ```text
//! token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
//! auth-param = token BWS "=" BWS ( token / quoted-string )
//! ```
//!
//! §11.2 says in prose which of the two follows a scheme: "either a
//! comma-separated list of parameters or a single sequence of characters
//! capable of holding base64-encoded information". Nothing in
//! `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` orders the
//! alternatives, so a recipient is the one that decides. This module writes
//! that decision down in its own `token68` reading and reports the answer at
//! [`Credential::token68`].
//!
//! Removing the `BWS` is this module's own work rather than a courtesy to the
//! sender. §5.6.3: "A recipient MUST parse for such bad whitespace and remove
//! it before interpreting the protocol element." So `realm = "x"` and
//! `realm="x"` are one parameter spelled two ways, and both are read.
//!
//! # Why this walks its own parameter grammar
//!
//! The crate already has a §5.6.6 `parameter` walker, and an `auth-param` is
//! not one of those. Two differences, either alone enough to settle it:
//!
//! - **The whitespace.** `parameter = parameter-name "=" parameter-value` admits
//!   none, and §5.6.6's closing note says so outright: "Parameters do not allow
//!   whitespace" around the `=`, bad whitespace included. `auth-param` puts
//!   `BWS` on both sides of its own.
//! - **The separator.** `parameters = *( OWS ";" OWS [ parameter ] )` hangs a
//!   member's parameters off semicolons, while §11.2 spells its lists
//!   `#auth-param` — §5.6.1's comma-separated construct.
//!
//! [`crate::grammar::parameterised_list`] would therefore refuse `realm = "x"`,
//! which §11.2 requires be accepted, and
//! `a_bws_parameter_is_what_the_semicolon_walker_refuses` is that sentence made
//! executable rather than merely written down.
//!
//! What is NOT rewritten here is anything below the parameter. An
//! `auth-param`'s value is a real §5.6.4 quoted-string, `quoted-pair` included
//! — unlike §8.8.3's `opaque-tag`, the case that forced [`crate::validator`] to
//! carry a walk of its own — so §5.6.4's scanner, §5.6.2's `token`, §5.6.3's
//! whitespace skip and [`crate::grammar::ParamValue`] are the ones this crate
//! already holds.
//!
//! # A challenge is not always one field line
//!
//! §11.3's `challenge` and §11.4's `credentials` are one production, and
//! [`Credential`] is it. What makes it more than a pair of slices is §5.2: a
//! repeated field is one value, its field line values "concatenated in order,
//! with each field line value separated by a comma", so a sender may split one
//! challenge's parameter list at any element boundary in it and the pieces
//! arrive as separate lines. [`Credential`] therefore names a region per line,
//! [`MAX_CHALLENGE_LINES`] bounds how many, and [`AuthParamIter`] reads the
//! boundary between two of them as the comma §5.2 put there.
//!
//! # One name, once
//!
//! RFC 9110 §11.2 puts a MUST on the names in a parameter list, and all three
//! entry points here check it. [`AuthError::DuplicateParameter`] carries the
//! rule, the case fold it is compared under, and the ruling that decides which
//! lists it is applied to; [`MAX_PARAMS_PER_CREDENTIAL`] carries the bound that
//! checking it needs, and what happens at that bound.
//!
//! # What may decide a boundary
//!
//! Reading these fields asks two questions of the same bytes — where an element
//! or a challenge ENDS, and what it DERIVES — and this module answers them in
//! one pass, because answering them in two is how a malformed challenge hides a
//! well-formed one. RFC 9110 §11.4 has a user agent choose among challenges by
//! "selecting the challenge with what it considers to be the most secure
//! auth-scheme that it understands", which it cannot do over a challenge it was
//! never shown.
//!
//! **Only bytes some production still admits may decide where anything ends.**
//! One rule, at two scopes:
//!
//! - **Within an element.** A DQUOTE opens a §5.6.4 quoted-string only at the
//!   one position §11.2 admits a value, which is what `param_value_at` answers;
//!   and the string that opens there closes the last thing the element may
//!   hold, since `( token / quoted-string )` is one alternative taken WHOLE,
//!   which is what `after_close` answers. Anywhere else a DQUOTE is one more
//!   byte of a run nothing derives, and such a run ends at the first RAW comma
//!   — `raw_comma_end`.
//! - **Within a `#challenge` value.** The moment an element of a challenge
//!   derives nothing, repeats a name, fills the last slot there is, or takes
//!   the challenge past [`MAX_CHALLENGE_LINES`], **that challenge is refused,
//!   and the rest of its extent is found by raw commas alone** — `seek` — with
//!   the latched fault returned. No DQUOTE behind the first definitive fault may
//!   steer where the refused challenge ends.
//!
//! Keeping the second scope true is a requirement on the WALK rather than on
//! any one function: **a challenge's elements are derived in the order they
//! arrive, and each verdict is in hand before the next element's bytes are
//! read.** The `#challenge` walk is the only one that has to hold it — the
//! reader for a field carrying one credential is handed a body whose extent is
//! already settled — and it holds it by feeding every element to `BodyCheck` as
//! it finds one. A change that moves any part of that derivation behind the
//! boundary scan re-opens this, whatever else it fixes; three rounds of review
//! found the same harm through three different such moves.
//!
//! The first element's verdict is the one thing held back, and only until a
//! SECOND element exists: §11.2's `token68` alternative derives an element no
//! `auth-param` does, so a body of exactly one element cannot be judged as a
//! parameter list at all. `BodyCheck` carries that argument, and holding a
//! verdict for an element that no later element's bytes are read past costs the
//! invariant nothing.
//!
//! One fault ends the walk instead of recovering from it.
//! [`AuthError::InvalidQuotedString`] is met INSIDE a string that legitimately
//! opened, so where that string ends is unknown and every comma behind it is a
//! guess; [`challenges`] says so where it says what follows an error.
//!
//! # Where a boundary is derived, and how many times
//!
//! Once, in `scan_element`, and every walk in this module gets its elements
//! from there: the `#challenge` walk while it is still cutting a body, the
//! `#auth-param` walk a caller reaches through [`Credential::params`], and
//! §11.6.3's bare list. A rule that is right at one entrance and absent at a
//! second is how each of the three rounds above got in, and a boundary derived
//! in three places is three entrances.
//!
//! The two walks over a CREDENTIAL are the pair that must agree, because one
//! of them decides that the challenge parses and the other is what a caller
//! then reads its parameters through — so a disagreement drops a parameter and
//! reports nothing. They agree by construction and not by measurement: it is
//! one function, and `BodyLines` hands it the same bytes both times by keeping
//! each region uncut to the end of its field line, which is what the collecting
//! walk read. `scan_element` reads its line from the cursor forward only, so
//! two slices that agree from the cursor on cannot give different answers.
//!
//! Where the credential STOPS is not derived twice either. It is
//! `BodyLines::held` — the collecting walk's own cursor, recorded — so a reader
//! of the body stops where the walk that took it stopped rather than at a
//! second opinion about the same bytes.
//!
//! Names in the two sections above are plain code spans rather than intra-doc
//! links: the functions and types the rule lives in are private, and a link to
//! one from a public module's own documentation is what
//! `rustdoc::private_intra_doc_links` refuses under `-D warnings`. Each is
//! documented where it is defined.
// gate-exempt: realm = "x" — one field value shown in prose, carrying the BWS
// this module accepts; not a production of any RFC.
// gate-exempt: crate::validator — named for contrast: §8.8.3's `opaque-tag` is
// what forced a walk of its own there, and an `auth-param` value having a real
// `quoted-pair` is why none is forced here.

use crate::grammar::{
  Delim, ParamValue, QuotedScan, eq_ignore_ascii, scan_quoted, scan_quoted_after_join, skip_ows,
  token_end,
};

/// How many field lines one [`Credential`]'s body may be spread over.
///
/// RFC 9110 §5.2 makes a repeated field one value — the field line values
/// "concatenated in order, with each field line value separated by a comma" —
/// and §5.3 is what lets a sender write it that way in the first place: it
/// forbids repeating a field name "unless that field's definition allows
/// multiple field line values to be recombined as a comma-separated list",
/// which `#challenge` is. One challenge's parameter list may therefore arrive
/// split at any element boundary in it, and a reader that borrows rather than
/// joining has to name every line it landed on at once.
///
/// Sixteen, and the measurement behind the number is the storage: an entry is
/// a `&[u8]`, 16 bytes on a 64-bit target, so the array is 256 of a
/// [`Credential`]'s bytes — what a caller holding one on the stack pays. It
/// sits well above the shapes that occur: the largest challenge in wide use is
/// a Digest one at roughly nine parameters, which a sender writing one
/// parameter per line spreads over ten.
///
/// # A refusal, and not a cap
///
/// A sender that splits one challenge across seventeen field lines has written
/// something the grammar allows and this recipient will not read, and
/// [`AuthError::ChallengeSpansTooManyLines`] says so rather than reading the
/// first sixteen. A challenge is chosen by its scheme and answered with its
/// parameters, so part of one is not a smaller answer but a wrong one — the
/// trade [`MAX_TAGS`](crate::validator::MAX_TAGS) already made in this crate,
/// and named there in the same words.
///
/// # What it does not count
///
/// A field line carrying no element BYTES — only `OWS`, commas, and the empty
/// elements between them — spends no entry, so this bounds a challenge's
/// content rather than the number of lines a sender merged around it. RFC 9110
/// §5.6.1.2 opens "Empty elements do not contribute to the count of elements
/// present.", and a slot-per-spanned-line rule would count them anyway.
///
/// A parse-constant rather than a caller-set knob: the storage is in the
/// binary, so a caller cannot raise it.
pub const MAX_CHALLENGE_LINES: usize = 16;

/// How many `auth-param` names one parameter list may carry while RFC 9110
/// §11.2's one-name-once MUST is checked over it.
///
/// That MUST is checked against the names already read — "each parameter name
/// MUST only occur once per challenge" is a statement about the list so far —
/// and a reader that borrows its input and allocates nothing holds those names
/// in a fixed array of this many slots. §11.2 puts no bound on `#auth-param`,
/// so this is a bound of the WALK and not of the grammar.
///
/// Sixteen, and the measurement behind the number is the storage: a slot is a
/// `&[u8]`, 16 bytes on a 64-bit target, so the record is 256 bytes — on the
/// stack while a [`Credential`] is validated, and inside the walk
/// [`auth_info`] hands back for as long as its caller holds it. It sits above
/// the parameter lists that occur: the largest in wide use are Digest's,
/// roughly nine parameters in a challenge and a dozen in the credential that
/// answers one.
///
/// # A refusal, and not a cap
///
/// One parameter past this many is [`AuthError::TooManyParameters`], and the
/// list is refused rather than read with the MUST left unchecked past the last
/// name that fit. Nothing about such a list is malformed — §11.2 bounds it
/// nowhere — so **this is a refusal that can meet conforming input**: a sender
/// that writes seventeen distinct parameters has written something the grammar
/// allows and this recipient will not read. The alternative is worse than a
/// refusal rather than merely different, which is why the bound is drawn here
/// at all: a walk that stopped CHECKING at the last slot would hand back a
/// list it never established was duplicate-free, and a repeat sitting past
/// that slot would be a MUST silently un-enforced. That is the trade
/// [`MAX_TAGS`](crate::validator::MAX_TAGS) already made in this crate, in the
/// same words, and [`MAX_CHALLENGE_LINES`] makes again a line at a time.
///
/// # What it does not count
///
/// Empty list elements spend no slot. RFC 9110 §5.6.1.2 opens "Empty elements
/// do not contribute to the count of elements present.", so a comma flood is
/// refused only once it carries this many real parameters, however many empty
/// elements arrived beside them — `a_comma_flood_is_not_too_many_parameters`
/// is that sentence made executable, in the position
/// `a_comma_flood_is_not_too_many_tags` already pins for the crate's other
/// bound.
///
/// Nor does it count a credential whose body took §11.2's other alternative. A
/// `token68` is not a list and holds no name to repeat, so
/// [`Credential::params`] is empty for one and no slot is ever spent.
///
/// A parse-constant rather than a caller-set knob: the storage is in the
/// binary, so a caller cannot raise it.
pub const MAX_PARAMS_PER_CREDENTIAL: usize = 16;

// What the slot counts cost, checked at module scope so that every `cargo
// check` on every tier enforces it. A `#[test]` would assert it only where a
// test harness runs, which is every tier EXCEPT `thumbv6m-none-eabi` — the one
// these numbers are written down for, where a 304-byte `Credential` is a real
// share of the stack budget. (`crate::validator`'s `TagList` assertions and
// `crate::range`'s `RangesSpecifier` ones are written against the same
// argument.)
//
// The figures are the compiler's own, and these assertions are the command that
// takes them:
//
//   cargo check -p http-semantics --all-features
//   cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi
//
// A `Credential`'s size is `MAX_CHALLENGE_LINES`'s, and the derivation names
// that constant rather than a bare number a reader has to take on trust: the
// body is a `[&[u8]; MAX_CHALLENGE_LINES]`, so raising the constant raises this
// by one slice per line it admits. On a 64-bit target a slice is a fat pointer,
// 16 bytes, so the array is 256 and the two `usize`s beside it — `len`, and the
// `held` that says where the credential stops in its last region — make
// `BodyLines` 272; the scheme slice and the `Option<&[u8]>` holding the
// `token68` reading — 16 too, with `None` in the pointer's null niche rather
// than a discriminant of its own — round `Credential` to 304. On a 32-bit one a
// slice is 8, so the array is 128, `BodyLines` is 136, and `Credential` is 152.
//
// `MAX_PARAMS_PER_CREDENTIAL` is the same 16 and buys that array a second time in
// `SeenNames`, which is NOT in these figures: that record is spent inside
// `Credential::read`, and the copy `auth_info`'s walk carries lives there
// rather than in any `Credential`. The two constants being equal is why the
// one number reads like the other's, and the storage is separate: neither of
// these figures follows from `MAX_PARAMS_PER_CREDENTIAL`.
//
// An `AuthParam` is two slices and nothing else: 32 on a 64-bit target, 16 on a
// 32-bit one. An `AuthError` is eight fieldless variants, so one byte holds the
// discriminant and there is nothing width-dependent to guard.
//
// Both widths are pinned rather than bounded, because a bound set well above a
// value asserts nothing about it.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Credential<'_>>() == 304);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<AuthParam<'_>>() == 32);

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<Credential<'_>>() == 152);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<AuthParam<'_>>() == 16);

const _: () = assert!(core::mem::size_of::<AuthError>() == 1);

/// Why an RFC 9110 §11 authentication field could not be read.
///
/// One type for all six of them. §11.3's `challenge` and §11.4's `credentials`
/// are the same production written twice, and §11.6.3's field is the
/// `#auth-param` list both of those end in, so the faults a recipient can meet
/// are one set rather than three — the shape [`RangeError`](crate::range::RangeError)
/// already takes across four roles.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
  /// A list element that has bytes and does not open with a `token`, so
  /// nothing in it can be the `auth-scheme` a challenge starts with.
  ///
  /// An EMPTY element is not this. RFC 9110 §5.6.1.2: "A recipient MUST parse
  /// and ignore a reasonable number of empty list elements", so an element with
  /// no bytes in it is skipped rather than reported.
  #[error("a challenge element carries no auth-scheme")]
  MissingScheme,
  /// A leading `token` that the challenge grammar cannot continue from.
  ///
  /// Two shapes, and the general one does not subsume the named one:
  ///
  /// - The token is followed by neither `1*SP` nor the end of its element.
  ///   RFC 9110 §11.3 spells the field's grammar
  ///   `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, which
  ///   admits nothing after the scheme without that `1*SP`, so an element
  ///   reading `type=1` is a scheme with an `=` glued to it, not a parameter.
  ///   The element's END is where §5.6.1.2's `OWS` has already been walked
  ///   over: `Basic<HTAB>, Newauth x=1` is two challenges, the first of them
  ///   bare, because that `OWS` hangs on the comma and not on the scheme.
  /// - The token IS followed by `1*SP`, and what fails is the section behind
  ///   it. `1*SP` is SP alone; §5.6.1.2 expands a list as
  ///   `#element => [ element ] *( OWS "," OWS [ element ] )`, which attaches
  ///   every `OWS` it has to a comma, so a HTAB reaching an ELEMENT is derived
  ///   by nothing and the section cannot start — `Basic<SP><HTAB>a=1`. A HTAB
  ///   reaching the comma is that `OWS` and the section starts on the empty
  ///   first element in front of it, exactly as `Basic<SP>, type=1` does.
  #[error("an auth-scheme is followed by something the challenge grammar does not admit")]
  MalformedScheme,
  /// A `token BWS "=" BWS ( token / quoted-string )` that does not complete: no
  /// leading token, no `=`, no value behind it, or a value that is neither a
  /// whole `token` nor a whole `quoted-string`.
  ///
  /// Whole is whole across §5.2's join as well. A quoted value that opened on
  /// one field line and closed on a later one has ended its element there, so
  /// only the `OWS` §5.6.1.2 hangs on the next comma may follow that close:
  /// `Basic realm="x` and `"junk` are joined into `Basic realm="x,"junk`,
  /// whose value is the quoted-string `"x,"` with four bytes behind it, and
  /// this is what that is.
  #[error("not a valid auth-param")]
  MalformedParameter,
  /// A §5.6.4 quoted-string still open when the LAST field line ended, so it
  /// never closed.
  ///
  /// A string open at a JOIN is not this. §5.2 makes repeated field lines one
  /// comma-joined value and a comma inside a quoted-string is data, so such a
  /// string continues onto the next line — and the pending escape goes to that
  /// comma, which is the next character of the string, rather than to the next
  /// line's first byte. A DQUOTE arriving first on that line therefore CLOSES
  /// the string; one that is data has the backslash escaping it on its own
  /// line. `the_escape_pending_at_a_join_is_spent_on_the_join_comma` is that
  /// pair, and an earlier revision of this doc had it the other way round.
  #[error("quoted-string is never closed")]
  UnterminatedQuotedString,
  /// A byte RFC 9110 §5.6.4's `qdtext` / `quoted-pair` grammar forbids appeared
  /// inside a quoted-string.
  ///
  /// Kept apart from
  /// [`UnterminatedQuotedString`](Self::UnterminatedQuotedString) because the
  /// two say different things about what may follow. An open string is the end
  /// of the input and nothing follows it; a forbidden byte leaves a walker
  /// unable to tell a separating comma from data, and every boundary behind it
  /// is a guess.
  #[error("byte forbidden inside a quoted-string")]
  InvalidQuotedString,
  /// One challenge's bytes are spread over more than [`MAX_CHALLENGE_LINES`]
  /// field lines, which is more than a borrowing, non-allocating reader can
  /// name at once.
  ///
  /// §5.3 lets a sender split a `#challenge` list at any element boundary and
  /// §5.2 joins the lines back into one value, so a challenge legally spans as
  /// many lines as the sender chose to use. This is therefore a refusal that
  /// can meet conforming input, and it is the honest answer where reading part
  /// of a challenge is not one. That constant carries the bound's own
  /// argument, including which lines it declines to count.
  #[error("a challenge spans more field lines than this recipient can name")]
  ChallengeSpansTooManyLines,
  /// RFC 9110 §11.2's MUST, reported at the second occurrence: "Authentication
  /// parameters are name/value pairs, where the name token is matched
  /// case-insensitively and each parameter name MUST only occur once per
  /// challenge."
  ///
  /// The fold is that sentence's own: the name is a `token`, the same sentence
  /// matches it case-insensitively, and so `realm` repeated as `Realm` is the
  /// repeat this reports rather than a second parameter.
  ///
  /// # Which lists the rule is applied to, which is this module's ruling
  ///
  /// §11.2 writes it "per challenge", and that WORDING covers one of the three
  /// parameter lists §11 defines. Extending it to the other two is this
  /// module's decision and not the RFC's text, and it is recorded here rather
  /// than left to look like a quotation:
  ///
  /// - A [`credentials`] value is `auth-scheme [ 1*SP ( token68 / #auth-param ) ]`,
  ///   the same production §11.3 names a challenge, written for a request. A
  ///   scheme that cannot make sense of one name twice in a 401 cannot make
  ///   sense of it twice in the `Authorization` answering that 401.
  /// - An [`auth_info`] value is a bare `#auth-param` with no challenge around
  ///   it for the wording to scope the rule to. Reading the sentence as
  ///   literally as its words allow would leave that field's repeats
  ///   unreported, which is a narrower green than "one name, once" — so the
  ///   rule is applied to each of its lists as it is to a challenge's.
  ///
  /// What it is NOT applied across is two lists. Two challenges of one
  /// `WWW-Authenticate` value each carrying `realm` are two challenges and not
  /// a repeat, because "per challenge" is where §11.2 does scope the rule and
  /// §11.4 has a user agent choose between challenges by their schemes.
  #[error("a parameter name occurs more than once")]
  DuplicateParameter,
  /// More parameters in one list than the [`MAX_PARAMS_PER_CREDENTIAL`] names a
  /// duplicate check can hold, so the list is refused rather than left
  /// unchecked past the last one it could record.
  ///
  /// Nothing here is malformed — RFC 9110 §11.2 bounds the list nowhere — so
  /// this names a limit of a no-alloc reader rather than a fault the sender
  /// committed. That constant carries the storage the number is measured from,
  /// and says in its own words that it is a refusal and not a cap.
  #[error("more parameters than this recipient can track")]
  TooManyParameters,
}

/// An [`AuthParam`]'s value crosses an RFC 9110 §5.2 field-line join, so it is
/// well formed and is not one contiguous slice.
///
/// Deliberately NOT an [`AuthError`] variant. §5.2's join is a fact about this
/// walk rather than about the field: the parameter's boundaries are still
/// correct, so are every other parameter's beside it, and so is the scheme in
/// front of them. §11.4 has a user agent choose among challenges by their
/// schemes, and failing a whole challenge over one value a caller may never
/// read would hide the scheme that choice turns on. The fact surfaces where it
/// is true instead — at [`AuthParam::value`], with [`AuthParam::name`] still
/// answering.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[error("the parameter's value spans a field-line join and is not one contiguous slice")]
pub struct ValueSpansFieldLines;

/// One RFC 9110 §11.2 `auth-param`: a name, and the value written after its
/// `=`.
///
/// # There is no `PartialEq`
///
/// This type derives neither `PartialEq` nor `Eq`, and there are three ways a
/// derive would answer `false` about bytes the specification calls the same.
/// §11.2 matches the name token case-insensitively; §5.6.6 makes a
/// `token` value and the same value written as a `quoted-string` equivalent;
/// and the value below keeps its `quoted-pair` escapes exactly as the sender
/// spelled them. A caller compares [`name`](Self::name) with
/// [`crate::grammar::eq_ignore_ascii`] and the value as [`ParamValue`]'s own
/// doc directs.
#[derive(Debug, Copy, Clone)]
pub struct AuthParam<'a> {
  /// The `token` in front of the `=`.
  name: &'a [u8],
  /// The value exactly as written — a bare `token`, or a `quoted-string` with
  /// its DQUOTEs still on — over the bytes of ONE field line.
  /// [`value`](Self::value) re-derives everything else from these, so nothing
  /// about the walk that produced them is stored beside them.
  value: &'a [u8],
}

impl<'a> AuthParam<'a> {
  /// The parameter's name, as the sender wrote it.
  ///
  /// Infallible, and it stays infallible for a parameter whose VALUE could not
  /// be handed over: what §5.2's join can break is a value's contiguity, not
  /// the boundaries either side of the name.
  ///
  /// RFC 9110 §11.2: "Authentication parameters are name/value pairs, where
  /// the name token is matched case-insensitively and each parameter name MUST
  /// only occur once per challenge." The fold is the caller's to apply, over
  /// the sender's own bytes; [`crate::grammar::eq_ignore_ascii`] is the
  /// comparison this crate offers for it.
  #[inline]
  pub const fn name(&self) -> &'a [u8] {
    self.name
  }

  /// The parameter's value, in whichever of §11.2's two alternatives the
  /// sender took.
  ///
  /// Never [`ParamValue::None`]. That variant is for the fields that define a
  /// bare-name parameter of their own — RFC 6455 §9.1 is one — and
  /// `auth-param` requires the `=` and a value behind it, so this parser
  /// produces one alternative or refuses the parameter. It is said here rather
  /// than modelled away, because [`ParamValue`] is the crate's one parameter
  /// value and keeps one shape for every field spelling a value this way.
  ///
  /// Both spellings are read, and RFC 9110 §11.2 gives the reason in its own
  /// words: "Authentication scheme definitions need to accept both notations,
  /// both for senders and recipients, to allow recipients to use generic
  /// parsing components regardless of the authentication scheme." A generic
  /// parsing component is exactly what this is, so `realm=x` is read as
  /// `realm="x"` is.
  ///
  /// # Errors
  ///
  /// [`ValueSpansFieldLines`] when the value is a quoted-string whose closing
  /// DQUOTE is not among the bytes this parameter holds. §5.2 joins repeated
  /// field lines into one value with a comma, and a comma inside a
  /// quoted-string is data, so a value may legally open on one line and close
  /// on the next — which a borrowing reader cannot hand back as one slice.
  pub fn value(&self) -> Result<ParamValue<'a>, ValueSpansFieldLines> {
    if self.value.first() != Some(&b'"') {
      return Ok(ParamValue::Token(self.value));
    }
    match scan_quoted(self.value, 1, false) {
      QuotedScan::Closed(end) if end == self.value.len() => Ok(ParamValue::Quoted(
        self.value.get(1..end.saturating_sub(1)).unwrap_or_default(),
      )),
      // The close is not among these bytes, and for a parameter this module
      // produced that leaves one shape: a value §5.2's join split over two
      // field lines, which is what this error names. The other two arms cannot
      // arrive — `auth_param` refuses a string that ends open, one carrying a
      // byte §5.6.4 forbids, and one with bytes behind its close — and are
      // answered here rather than asserted away.
      QuotedScan::Closed(_) | QuotedScan::Open { .. } | QuotedScan::Invalid => {
        Err(ValueSpansFieldLines)
      }
    }
  }
}

/// What became of a §5.6.4 quoted-string still open when the field line an
/// `auth-param` began on ran out.
///
/// The parameter's own bytes cannot answer it: RFC 9110 §5.2 joins the lines
/// of one field with a comma, that comma is data inside an open string, and
/// the close may therefore be on a line this parameter does not hold. Only the
/// walk that crossed the join knows, so it says. [`crate::grammar::ParamIter`]
/// carries the same fact for a §5.6.6 `parameter`, under its own name.
///
/// Three answers rather than two, because closing is not ending. RFC 9110
/// §11.2's `auth-param = token BWS "=" BWS ( token / quoted-string )` takes one
/// alternative WHOLE, so what stands behind the close decides as much as the
/// close does — and those bytes are on a line the parameter does not hold
/// either.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum ValueTail {
  /// Nothing was open where the line ended, or what was open never closed on
  /// any later one. Either way the parameter's bytes are all there is of it.
  Ends,
  /// It closed on a later field line, across §5.2's join, and the element
  /// ended there — so the value is real, and is not one contiguous slice.
  Continues,
  /// It closed on a later field line and the element did NOT end there: bytes
  /// other than the `OWS` RFC 9110 §5.6.1.2 hangs on the next comma stand
  /// behind that close.
  ///
  /// One token or one quoted-string is the whole of a value, so nothing
  /// derives those bytes and the parameter is
  /// [`AuthError::MalformedParameter`]. [`auth_param`]'s `QuotedScan::Closed`
  /// arm is the same fault spelled on one field line, and this is what keeps
  /// §5.2's join from being a way past it.
  Trails,
}

/// One RFC 9110 §5.6.1.2 list element as a walk found it: the bytes it occupies
/// on the field line it began on, with the list's own `OWS` off both ends, and
/// what §5.2's join did with a quoted value it left open there.
///
/// The pair is what [`auth_param`] needs, and neither half answers alone — a
/// borrowing walk can hand back only the one line's bytes, and [`ValueTail`] is
/// what says whether a later line closed the value, ran on past that close, or
/// never arrived.
///
/// Producing this is where a walk's work over an element ENDS. What the element
/// DERIVES is [`auth_param`]'s question, and what a list of them derives is
/// [`BodyCheck`]'s — so a walk that is still deciding where a challenge stops
/// hands an element over and is told the verdict before it reads another
/// element's bytes.
#[derive(Debug, Copy, Clone)]
struct Element<'a> {
  /// The element's bytes on the line it began on.
  bytes: &'a [u8],
  /// What became of a quoted-string still open where that line ran out.
  tail: ValueTail,
}

/// What [`scan_element`] found: the element, and where the walk now stands.
#[derive(Debug, Copy, Clone)]
struct Scanned<'a> {
  /// The element.
  element: Element<'a>,
  /// Where it ended on the field line the walk stands on when this is returned
  /// — a LATER line than the element began on whenever a value crossed RFC
  /// 9110 §5.2's join. The caller's own cursor takes it.
  at: usize,
}

/// Walks the one RFC 9110 §5.6.1.2 list element that begins at `at` on `head`,
/// crossing §5.2's joins for as long as a §5.6.4 quoted-string holds it open.
///
/// **The one place an element's boundary is derived.** Three walks in this
/// module ask for one — the `#challenge` walk while it is still cutting a body
/// ([`Challenges::skip_element`]), the `#auth-param` walk re-reading a body
/// already cut ([`ParamWalk::element`]), and §11.6.3's bare list
/// ([`AuthInfo::element`]) — and a boundary derived in three places is three
/// answers a later edit can move apart. The first two produce the elements of
/// ONE credential, one of them while deciding where that credential ends and
/// the other when a caller asks for its parameters, so a disagreement between
/// them would drop a parameter from a challenge that parsed and report
/// nothing. There is nothing for them to disagree about while this is where
/// both of them get the answer.
///
/// `next` hands over the field line behind the join, or `None` where the value
/// runs out, and is where a caller does whatever crossing a line costs it —
/// taking the region left behind, in the case of a walk collecting one.
///
/// # What it reads, and why two callers may hold different slices
///
/// `head` is read from `at` FORWARD, as far as the delimiter that ends the
/// element and no further; [`trim_ows_end`] then walks back over the list's own
/// `OWS`, which stands within the element's own span. Nothing here reads a byte
/// before `at`.
///
/// Two slices that agree from `at` to their end therefore give the same
/// element, and the END of a slice is read as the comma §5.2 puts at every
/// join — which [`raw_comma_end`], [`after_close`], [`ends_element`] and
/// [`param_value_at`] each answer for the byte they inspect. That is what lets
/// [`Challenges`] scan a whole field line while [`ParamWalk`] scans the SAME
/// line from the credential's first byte on it and get the same answer:
/// [`BodyLines`] keeps its regions uncut for exactly that reason, and says so.
///
/// # Errors
///
/// [`AuthError::InvalidQuotedString`] for a byte §5.6.4 forbids inside a
/// quoted-string, and nothing else. Every OTHER fault an element carries is
/// [`auth_param`]'s to report over the [`Element`] this returns, because a
/// boundary a walk has not yet found must not be decided by bytes behind a
/// fault — and a walk cannot be handed a verdict before it has the element the
/// verdict is about.
fn scan_element<'a, N>(head: &'a [u8], at: usize, mut next: N) -> Result<Scanned<'a>, AuthError>
where
  N: FnMut() -> Option<&'a [u8]>,
{
  // What the element occupies on the line it began on — all a borrowing walk
  // can hand back — plus, when a quoted-string held it open at that line's
  // end, the escape state to continue that string with.
  let (head_end, mut open) = match element_end(head, at) {
    // The element ends here, so the `OWS` RFC 9110 §5.6.1.2 hangs on the comma
    // in front of it belongs to the list rather than to the value.
    Delim::At(end) => (trim_ows_end(head, end), None),
    Delim::Open(escape) => (head.len(), Some(escape)),
    Delim::Invalid => return Err(AuthError::InvalidQuotedString),
  };
  let mut cursor = head_end;

  // A quoted-string still open where a field line ends does NOT end the
  // element: RFC 9110 §5.2 joins the lines with a comma and §5.6.4 makes that
  // comma data inside one, so the element runs on and ends wherever the string
  // closes. `scan_quoted_after_join` is this crate's one implementation of that
  // rule, and it feeds the join's comma THROUGH any pending escape before the
  // next line's first byte — so the escape is spent on the comma, and a DQUOTE
  // arriving first on that line closes the string.
  let mut tail = ValueTail::Ends;
  while let Some(escape) = open.take() {
    let Some(line) = next() else {
      // Nothing left to close the string on, so the combined value ends inside
      // it. Whatever closed on an earlier line does not change that: what is
      // still open is what the element ends in, and `auth_param` reports it
      // over these same bytes.
      tail = ValueTail::Ends;
      break;
    };
    cursor = line.len();
    match rejoin(line, escape) {
      // Past the string, the rest of that line is the element's like any
      // other, up to the comma that ends it — and only the list's own `OWS`
      // may stand in between, which is what `trails` answers. A line that
      // closed the value ENDS the element, so this is read once and there is
      // no verdict from an earlier line to carry into it.
      Rejoin::Ends { at: end, trails } => {
        tail = if trails {
          ValueTail::Trails
        } else {
          ValueTail::Continues
        };
        cursor = end;
      }
      Rejoin::Open { escape } => open = Some(escape),
      Rejoin::Invalid => return Err(AuthError::InvalidQuotedString),
    }
  }

  Ok(Scanned {
    element: Element {
      bytes: head.get(at..head_end).unwrap_or_default(),
      tail,
    },
    at: cursor,
  })
}

/// Reads one RFC 9110 §11.2 `auth-param` out of `element`.
///
/// `element` is one list element with §5.6.1's `OWS` already off both ends: the
/// whitespace that separates elements belongs to the list, and the `BWS` read
/// here belongs to the production. All of `element` must be the parameter —
/// bytes left over behind the value are a parameter that does not parse, since
/// `( token / quoted-string )` is one alternative taken whole.
///
/// `tail` says what a §5.2 join did with a quoted value this element leaves
/// open, and it is the caller's to supply for the reason [`ValueTail`] gives.
///
/// # Errors
///
/// [`AuthError::MalformedParameter`] when `element` is not
/// `token BWS "=" BWS ( token / quoted-string )`, and for the one shape only
/// `tail` can report — a quoted value that closed across the join with bytes
/// behind that close; [`AuthError::UnterminatedQuotedString`] when a quoted
/// value is still open where `element` ends and `tail` says nothing closed it;
/// [`AuthError::InvalidQuotedString`] when one carries a byte §5.6.4 forbids.
// `pub(crate)` for one caller outside this module and no other: the
// `__no_panic_internals` forwarder the link proof's shim over it reaches it
// through. Every other caller is in this file.
pub(crate) fn auth_param(element: &[u8], tail: ValueTail) -> Result<AuthParam<'_>, AuthError> {
  let Some(name_end) = token_end(element, 0) else {
    return Err(AuthError::MalformedParameter);
  };
  let eq = skip_ows(element, name_end);
  if element.get(eq) != Some(&b'=') {
    return Err(AuthError::MalformedParameter);
  }
  let name = element.get(..name_end).unwrap_or_default();
  let at = skip_ows(element, eq.saturating_add(1));
  let value = element.get(at..).unwrap_or_default();
  match value.first() {
    // `auth-param` has no bare-name form: the production names a value, and
    // the `=` is not one.
    None => Err(AuthError::MalformedParameter),
    Some(&b'"') => match scan_quoted(value, 1, false) {
      QuotedScan::Closed(end) if end == value.len() => Ok(AuthParam { name, value }),
      QuotedScan::Closed(_) => Err(AuthError::MalformedParameter),
      QuotedScan::Open { .. } => match tail {
        // The string closed on a later field line, so the value exists and is
        // well formed — it is simply not one slice to hand back, which is what
        // [`AuthParam::value`] reports over these same bytes.
        ValueTail::Continues => Ok(AuthParam { name, value }),
        // It closed there and the element ran on past that close, which the
        // arm above this `match` already refuses when both lie on one field
        // line. One rule, and RFC 9110 §5.2's join is not a way past it.
        ValueTail::Trails => Err(AuthError::MalformedParameter),
        ValueTail::Ends => Err(AuthError::UnterminatedQuotedString),
      },
      QuotedScan::Invalid => Err(AuthError::InvalidQuotedString),
    },
    Some(_) => match token_end(value, 0) {
      Some(end) if end == value.len() => Ok(AuthParam { name, value }),
      _ => Err(AuthError::MalformedParameter),
    },
  }
}

/// RFC 9110 §11.2's `token68` alphabet: one byte of the run its production
/// opens with.
///
/// ALPHA, DIGIT and `-`, `.`, `_`, `~` are RFC 3986's 66 unreserved URI
/// characters; `+` and `/` are the two behind them, and §11.2 gives the reason
/// in as many words — the syntax is sized "so that it can hold a base64,
/// base64url (URL and filename safe alphabet), base32, or base16 (hex)
/// encoding, with or without padding, but excluding whitespace".
///
/// Neither this set nor §5.6.2's `tchar` contains the other, so a run of these
/// bytes is not thereby a `token` and a `token` is not thereby one of these:
/// `/` is here and is no `tchar`, while `!`, `#`, `$`, `%`, `&`, `'`, `*`, `^`,
/// `` ` `` and `|` are `tchar`s and are not here.
#[inline]
const fn is_token68_byte(b: u8) -> bool {
  matches!(b,
    b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// The end of the RFC 9110 §11.2 `token68` starting at `at`, or `None` when
/// there is not one.
///
/// ```text
/// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
///
/// Two runs, in that order, with no way back to the first: the alphabet's,
/// which `1*` gives a floor of one byte, and the `=` pad, which `*` lets be
/// empty. So `====` is not a token68 whose run happens to be empty — it is not
/// a token68 — and `a=b` ends at the `b` rather than reading it as more of the
/// alphabet.
///
/// This is the RUN, and not the reading. Whether the bytes it names are taken
/// as a `token68` at all is [`token68`]'s question, and the answer is `no` for
/// every run that stops short of its element's end.
// `pub(crate)` for one caller outside this module and no other: the
// `__no_panic_internals` forwarder the link proof's shim over it reaches it
// through. Every other caller is in this file.
pub(crate) fn token68_end(value: &[u8], at: usize) -> Option<usize> {
  let mut end = at;
  while value.get(end).copied().is_some_and(is_token68_byte) {
    end = end.saturating_add(1);
  }
  if end == at {
    return None;
  }
  while value.get(end) == Some(&b'=') {
    end = end.saturating_add(1);
  }
  Some(end)
}

/// Which of RFC 9110 §11.2's two forms the credential body at `at` takes,
/// answered as the `token68` when that is the one and `None` when the bytes are
/// to be read as `#auth-param` instead.
///
/// `at` is the first byte after a scheme's `1*SP`. §11.2 puts the choice in
/// prose — the scheme is followed by "either a comma-separated list of
/// parameters or a single sequence of characters capable of holding
/// base64-encoded information" — and §11.3 puts it in the grammar as
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, which §11.4
/// writes again as `credentials`. ABNF's `/` is an unordered choice, so nothing
/// there orders the two and a recipient decides.
///
/// # The rule
///
/// The `token68` is taken when its run reaches the end of its own list element:
/// the end of `value`, or the comma §5.6.1 puts between elements, with the
/// `OWS` that comma may carry skipped on the way. Anything else is the other
/// form. `dGVzdA==` and `mF_9.B5f-4.1JqM` are `token68`s by that rule, and
/// `foo=bar` is not — its pad has token bytes behind it, so the run stops
/// inside the element instead of ending it.
///
/// The end of `value` and that comma are one terminator rather than two: §5.2
/// joins repeated field lines into one value with a comma, so a run that
/// reaches the end of ONE line meets the comma next and is read the same way
/// either way.
///
/// At that comma the element is closed and nothing reopens it. A `#challenge`
/// walk tells a parameter of the CURRENT challenge from the scheme of the next
/// one by looking past the comma, and asking that question here instead could
/// change the answer only for an element both forms refuse: `Basic dGVzdA==,
/// realm=x` has no derivation either way, since `realm=x` is no challenge
/// without `1*SP` behind its token and `dGVzdA==` is no parameter. What such a
/// walk is left deciding is therefore which fault to report, never whether a
/// conforming value is read.
///
/// # Why taking it greedily steals nothing
///
/// No element this returns `Some` for is an `auth-param`, so answering the run
/// first can take no reading away from the other form. A run that reaches the
/// end of its element leaves nothing but `=` behind its first `=`, and
/// `auth-param = token BWS "=" BWS ( token / quoted-string )` needs a `token`
/// or a `quoted-string` there: `=` is neither, and the production names a value
/// rather than admitting nothing at all. `the_two_branches_are_never_both_derivable`
/// is that argument executed.
///
/// The shape worth saying it out loud for is `Scheme foo=`, which reads like a
/// parameter whose value went missing. It is not one — only the `token68`
/// derives it — so this answers `foo=` and no fault is reported. An element
/// that is NEITHER form is left to the parameter reading and refused there,
/// which is why no `MalformedToken68` exists to report.
///
/// One element is all this decides. Whether the element it ends also ends the
/// whole credential is [`Credential`]'s question, and the answer is `no` for a
/// value with more of its body behind that comma — where the other branch is
/// then the reading, and reports the fault.
fn token68(value: &[u8], at: usize) -> Option<&[u8]> {
  let end = token68_end(value, at)?;
  // Nothing behind the run inside its own element, so the run IS the element
  // and the first form is the one taken. `ends_element` is where that test
  // lives: the scheme's own edges ask the same question of the same OWS.
  if ends_element(value, end) {
    value.get(at..end)
  } else {
    None
  }
}

/// One RFC 9110 §11.3 `challenge`, which §11.4 spells again as `credentials`.
///
/// ```text
/// challenge   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// One production written twice, so one type reads both and each entry point
/// names which field it is for — the shape
/// [`RangeError`](crate::range::RangeError) already takes across four roles.
///
/// # Why the bytes are an array
///
/// A challenge is not always one field line. RFC 9110 §5.2 makes a repeated
/// field one value, the field line values "concatenated in order, with each
/// field line value separated by a comma", so `Basic a=1` followed by `b=2` is
/// `Basic a=1,b=2` — ONE challenge whose parameter list a sender split at an
/// element boundary. §11.6.1 says a parser has to be ready for both readings
/// of such a comma: "it might contain more than one challenge, and each
/// challenge can contain a comma-separated list of authentication parameters".
///
/// A borrowing reader cannot hand that back as one slice and this crate
/// allocates nothing, so the bytes are held as the regions they occupy on each
/// line, in wire order, with the boundary between two of them standing for the
/// comma §5.2 puts there. [`MAX_CHALLENGE_LINES`] is how many, and carries the
/// argument for the number.
///
/// A field line that carries no element BYTES spends no entry — only `OWS`,
/// commas, and the empty elements between them. The rule is written on bytes
/// rather than on elements because a line can begin no element and still be
/// load-bearing: given `Basic a="long` and `tail"`, the second line starts
/// nothing, yet it holds the DQUOTE that closes the value and every element
/// behind it. Dropping it would lose them.
///
/// # There is no `PartialEq`
///
/// Three ways a derive would answer `false` about bytes the specification
/// calls the same. §11.1 identifies a scheme with "a case-insensitive token";
/// §11.2 matches a parameter name case-insensitively; and a value written as a
/// `token` is the same value written as a `quoted-string`. A `Credential` also
/// holds the `BWS` spans no rule makes significant, and which line each region
/// came from — a property of how the value arrived rather than of what the
/// sender said. [`scheme_is`](Self::scheme_is) is the scheme comparison this
/// type offers, and [`AuthParam`] says what to do with a parameter.
#[derive(Debug, Copy, Clone)]
pub struct Credential<'a> {
  /// The `auth-scheme` token, always on the credential's first line: a `token`
  /// carries no comma, so nothing can hold a scheme open across §5.2's join.
  scheme: &'a [u8],
  /// What follows the `1*SP`, per field line.
  body: BodyLines<'a>,
  /// The `token68` reading, when that is the one §11.2's choice takes.
  token68: Option<&'a [u8]>,
}

impl<'a> Credential<'a> {
  /// Reads §11.3's production over a scheme and the body regions BEHIND it,
  /// which is the reading a field carrying one credential gets.
  ///
  /// The body's extent is settled before this is called and nothing here can
  /// move it, so this walks the whole of it and hands every element to
  /// [`BodyCheck`], which is where the production is decided and where a
  /// `Credential` is built.
  ///
  /// The `#challenge` walk does NOT come here. There the body's extent is the
  /// question, and a verdict reached after that extent was found is a verdict
  /// the bytes behind a fault helped decide — so that walk feeds its own
  /// [`BodyCheck`] element by element as it discovers them, and
  /// [`Challenges::challenge`] is where that is written.
  ///
  /// # Errors
  ///
  /// Whatever the parameter list carries: [`AuthError::MalformedParameter`],
  /// [`AuthError::UnterminatedQuotedString`],
  /// [`AuthError::InvalidQuotedString`], [`AuthError::DuplicateParameter`] for
  /// RFC 9110 §11.2's one-name-once MUST, and
  /// [`AuthError::TooManyParameters`] past [`MAX_PARAMS_PER_CREDENTIAL`] names.
  fn read(scheme: &'a [u8], body: BodyLines<'a>) -> Result<Self, AuthError> {
    let mut check = BodyCheck::new();
    let mut walk = ParamWalk::over(body);
    while let Some(element) = walk.step() {
      check.settle()?;
      check.element(element?)?;
    }
    check.finish(scheme, body)
  }

  /// The `auth-scheme` token, exactly as the sender wrote it.
  ///
  /// RFC 9110 §11.1: "It uses a case-insensitive token to identify the
  /// authentication scheme". The bytes are kept as they arrived and
  /// [`scheme_is`](Self::scheme_is) is the fold.
  #[inline]
  pub const fn scheme(&self) -> &'a [u8] {
    self.scheme
  }

  /// Whether the scheme is `name`, compared as §11.1's case-insensitive token.
  #[inline]
  pub fn scheme_is(&self, name: &str) -> bool {
    eq_ignore_ascii(self.scheme, name)
  }

  /// The RFC 9110 §11.2 `token68` this credential carries, or `None` when its
  /// body is a `#auth-param` list instead.
  ///
  /// ```text
  /// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  /// ```
  ///
  /// §11.2 puts the choice in prose — the scheme is followed by "either a
  /// comma-separated list of parameters or a single sequence of characters
  /// capable of holding base64-encoded information" — and the grammar's `/`
  /// does not order the two, so a recipient decides. This is `Some` exactly
  /// when the run is the whole body; [`params`](Self::params) is then empty,
  /// and the two are never both non-empty.
  #[inline]
  pub const fn token68(&self) -> Option<&'a [u8]> {
    self.token68
  }

  /// The credential's `#auth-param` list, in the order the sender wrote it.
  ///
  /// Infallible: every parameter was read once already, when this value was
  /// built. Empty when [`token68`](Self::token68) is `Some`, since §11.2's two
  /// alternatives are exclusive.
  ///
  /// The walk crosses each §5.2 field-line join, so a list split across lines
  /// yields the same parameters as the same list written on one. What a join
  /// can still take away is one VALUE's contiguity, and
  /// [`AuthParam::value`] is where that is reported.
  #[inline]
  pub const fn params(&self) -> AuthParamIter<'a> {
    AuthParamIter {
      walk: ParamWalk {
        body: self.body,
        line: 0,
        at: 0,
        // A `token68` body is spent before this walk begins: §11.2's two
        // alternatives are exclusive and no element a `token68` was taken from
        // is an `auth-param`, which `the_two_branches_are_never_both_derivable`
        // is the argument for. A walk started over that body instead would find
        // the one element it holds, be refused there, and stop on
        // `Stop::Fault`. Both spellings yield no parameters and only the ENDING
        // tells them apart, which is what
        // `a_walk_that_stops_on_a_fault_says_so` asserts of this initialiser.
        stop: match self.token68 {
          Some(_) => Some(Stop::Spent),
          None => None,
        },
      },
    }
  }
}

/// The field-line regions one credential's body occupies, in wire order.
///
/// Each entry runs from the credential's first byte on that line to the END of
/// the line, and is NOT cut where the credential stops. The boundary between
/// two entries is the comma RFC 9110 §5.2 joins field lines with.
///
/// # Why the last region is not cut, and what says where it stops
///
/// Two walks produce this body's elements: [`Challenges::skip_element`] while
/// it is still deciding where the challenge ends, and [`ParamWalk::element`]
/// when a caller reads [`Credential::params`]. They are one walk —
/// [`scan_element`] — and it reads its line only from the cursor forward, so
/// the two agree on every element as long as they are handed the same bytes
/// from that cursor on. An entry left uncut IS the same bytes: the field line
/// the collecting walk scanned, offset by the credential's own start on it.
/// Cutting it at the credential's end would leave the two reading slices of
/// different lengths and the agreement resting on an argument about what lies
/// past an element's delimiter.
///
/// [`held`](Self::held) is where the credential stops in the last entry, and it
/// is the collecting walk's OWN cursor, recorded rather than derived a second
/// time — so nothing about this body is decided twice. [`cut`](Self::cut) is
/// how the bytes a credential holds are asked for, and the only reader of an
/// entry past it is the walk that stops there.
#[derive(Copy, Clone)]
struct BodyLines<'a> {
  /// Empty past `len`.
  lines: [&'a [u8]; MAX_CHALLENGE_LINES],
  /// How many entries the credential spent.
  len: usize,
  /// How many bytes of the LAST entry belong to the credential.
  ///
  /// One number and not one per entry, because only the last entry can stop
  /// short. A walk takes an entry as it LEAVES the line, and leaving a line is
  /// reaching its end — so every earlier entry was read to its end by the walk
  /// that took it, and is read to its end here. The last entry is the only one
  /// that walk stopped inside of, and so the only one that can hold the
  /// challenge behind this one.
  held: usize,
}

impl core::fmt::Debug for BodyLines<'_> {
  /// The credential's own bytes, entry by entry — the same regions a reader of
  /// this body sees, rather than the uncut lines they are stored as.
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_list()
      .entries((0..self.len).map(|at| self.cut(at)))
      .finish()
  }
}

impl<'a> BodyLines<'a> {
  /// An empty body: a challenge that is a bare `auth-scheme` has one.
  const fn new() -> Self {
    Self {
      lines: [&[]; MAX_CHALLENGE_LINES],
      len: 0,
      held: 0,
    }
  }

  /// Takes what one field line contributes to this credential: `region` from
  /// the credential's first byte on that line to the line's end, of which the
  /// first `held` bytes are the credential's own.
  ///
  /// A region of nothing but `OWS` and commas spends no entry, and that is
  /// checked BEFORE the bound: RFC 9110 §5.6.1.2 says "Empty elements do not
  /// contribute to the count of elements present.", so a sender that merged a
  /// run of empty lines into the middle of one challenge has not made it
  /// longer. Counting them would put a number on the empty elements the same
  /// paragraph asks a recipient to "parse and ignore".
  ///
  /// The test is on the bytes the credential HOLDS — `held` of them — and not
  /// on the rest of the line, which may be the next challenge and is no part
  /// of this one's length. A line that begins no element still spends an entry
  /// when it holds any other byte, because those bytes may be the ones that
  /// close a quoted value, and every element behind it is reached through them.
  ///
  /// # Errors
  ///
  /// [`AuthError::ChallengeSpansTooManyLines`] past [`MAX_CHALLENGE_LINES`]
  /// entries, which is a refusal and not a cap; that constant says why.
  fn push(&mut self, region: &'a [u8], held: usize) -> Result<(), AuthError> {
    // A `held` past the region's end is not reachable — it is a cursor into
    // this same line — and taking the whole region for one is the direction
    // that spends an entry rather than silently dropping the line's bytes.
    let mine = region.get(..held).unwrap_or(region);
    if mine
      .iter()
      .all(|&byte| byte == b' ' || byte == b'\t' || byte == b',')
    {
      return Ok(());
    }
    let Some(slot) = self.lines.get_mut(self.len) else {
      return Err(AuthError::ChallengeSpansTooManyLines);
    };
    *slot = region;
    self.len = self.len.saturating_add(1);
    self.held = held;
    Ok(())
  }

  /// The region at `at` as it was stored — to the end of its field line — or
  /// no bytes when there is not one.
  ///
  /// This is what a walk over the body reads, because it is what the walk that
  /// collected the body read. [`cut`](Self::cut) is what the credential HOLDS
  /// of it.
  fn line(&self, at: usize) -> &'a [u8] {
    self.lines.get(at).copied().unwrap_or_default()
  }

  /// The bytes of region `at` that belong to this credential.
  ///
  /// Every region but the last is the credential's as far as its line runs;
  /// the last stops at [`held`](Self::held).
  fn cut(&self, at: usize) -> &'a [u8] {
    let region = self.line(at);
    if at.saturating_add(1) >= self.len {
      return region.get(..self.held).unwrap_or(region);
    }
    region
  }
}

/// The `auth-param` names one parameter list has used, as far as the walk over
/// it has read.
///
/// RFC 9110 §11.2: "Authentication parameters are name/value pairs, where the
/// name token is matched case-insensitively and each parameter name MUST only
/// occur once per challenge." Answering that needs the names already seen, a
/// reader that allocates nothing holds them in [`MAX_PARAMS_PER_CREDENTIAL`] slots,
/// and that is the whole reason the bound exists — see the constant for what
/// happens at it.
///
/// One record per list. A [`Credential`]'s is built and spent inside
/// [`Credential::read`]; [`auth_info`]'s walk carries its own across the
/// parameters it hands out one at a time.
#[derive(Debug, Clone)]
struct SeenNames<'a> {
  /// Empty past `len`.
  names: [&'a [u8]; MAX_PARAMS_PER_CREDENTIAL],
  /// How many slots the list has spent.
  len: usize,
}

impl<'a> SeenNames<'a> {
  /// A record of no names: where every parameter list starts.
  const fn new() -> Self {
    Self {
      names: [&[]; MAX_PARAMS_PER_CREDENTIAL],
      len: 0,
    }
  }

  /// Takes one parameter's name, reporting the second occurrence of one.
  ///
  /// # Errors
  ///
  /// [`AuthError::DuplicateParameter`] when `name` is one already recorded,
  /// folded as RFC 9110 §11.2 matches it; [`AuthError::TooManyParameters`]
  /// when it is not one and there is no slot left to record it in.
  ///
  /// **The duplicate is asked first**, so a list one past the bound whose next
  /// name repeats a recorded one is answered with the fault the SENDER
  /// committed rather than with this reader's own limit. The repeat is proven
  /// and not guessed at when that happens: the bound refuses rather than
  /// skipping, so every name before it went into a slot and the record the
  /// comparison runs over is the whole list so far. The crate's other
  /// two-fault record orders its own the same way and for the same reason —
  /// a `TagList` asks about `*` before it asks whether an element parses,
  /// lest the caller be told which fault it was by whichever check ran first.
  fn record(&mut self, name: &'a [u8]) -> Result<(), AuthError> {
    // The slots past `len` hold no name rather than an empty one — a `token`
    // has at least one byte, so nothing a caller can send matches them — and
    // the prefix is taken to say that rather than to make it true.
    let used = self.names.get(..self.len).unwrap_or_default();
    if used.iter().any(|seen| seen.eq_ignore_ascii_case(name)) {
      return Err(AuthError::DuplicateParameter);
    }
    // The slot lookup IS the bound: `None` means this name is the
    // `MAX_PARAMS_PER_CREDENTIAL + 1`th, which is the refusal that constant
    // documents.
    let Some(slot) = self.names.get_mut(self.len) else {
      return Err(AuthError::TooManyParameters);
    };
    *slot = name;
    self.len = self.len.saturating_add(1);
    Ok(())
  }
}

/// RFC 9110 §11.3's `[ 1*SP ( token68 / #auth-param ) ]` decided over the
/// elements of one credential body, and the one place a [`Credential`] is
/// built.
///
/// ```text
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Two walks produce those elements — [`Credential::read`] over a body already
/// cut, and [`Challenges::challenge`] as it cuts one — and the verdict on them
/// is written once, here, so the two cannot drift apart on what a body derives.
///
/// # Why the FIRST element's verdict is held
///
/// §11.2's two alternatives are exclusive: an element a `token68` derives is
/// one no `auth-param` does, which
/// `the_two_branches_are_never_both_derivable` is the argument for. So the
/// first element of a body that turns out to BE a `token68` is refused as an
/// `auth-param` and must not be reported, and whether the body is one is not
/// known until its extent is.
///
/// Held for exactly one element and no longer. A SECOND element ends the
/// `token68` reading — that alternative is a single run and takes the whole
/// body — so the held verdict comes due the moment one appears, which is what
/// [`settle`](Self::settle) is and why a walk still finding a boundary calls it
/// BEFORE it reads that second element's bytes.
struct BodyCheck<'a> {
  /// The names the list has used, for RFC 9110 §11.2's one-name-once MUST.
  seen: SeenNames<'a>,
  /// The verdict on the first element, held while the `token68` reading is
  /// still live.
  held: Option<AuthError>,
  /// Whether an element has been taken at all.
  opened: bool,
}

impl<'a> BodyCheck<'a> {
  /// A check over no elements: where every credential body starts.
  const fn new() -> Self {
    Self {
      seen: SeenNames::new(),
      held: None,
      opened: false,
    }
  }

  /// Takes one element of the body, in wire order.
  ///
  /// # Errors
  ///
  /// Whatever [`auth_param`] makes of the element, and
  /// [`AuthError::DuplicateParameter`] or [`AuthError::TooManyParameters`]
  /// from the record of names — except for the FIRST element, whose verdict is
  /// held for the reason this type carries and is reported by
  /// [`settle`](Self::settle) or [`finish`](Self::finish) instead.
  fn element(&mut self, element: Element<'a>) -> Result<(), AuthError> {
    let verdict = match auth_param(element.bytes, element.tail) {
      Ok(param) => self.seen.record(param.name()),
      Err(fault) => Err(fault),
    };
    if self.opened {
      return verdict;
    }
    self.opened = true;
    self.held = verdict.err();
    Ok(())
  }

  /// Reports the held verdict on the first element, which a second element
  /// makes due.
  ///
  /// Called before another element's BYTES are read, never after. A walk that
  /// is still deciding where a challenge ends would otherwise let those bytes
  /// choose the extent of a challenge already refused, which is the one thing
  /// the module doc's invariant forbids.
  ///
  /// # Errors
  ///
  /// The first element's, once; nothing on any later call.
  fn settle(&mut self) -> Result<(), AuthError> {
    match self.held.take() {
      Some(fault) => Err(fault),
      None => Ok(()),
    }
  }

  /// The credential these elements are of, once the body's extent is known.
  ///
  /// The `token68` is taken only when it is the WHOLE body. `token68` answers
  /// for one element, where a comma is a terminator; a credential is complete
  /// at the end of its body, so a run that ends its element with more of the
  /// body behind it has left bytes
  /// `auth-scheme [ 1*SP ( token68 / #auth-param ) ]` does not derive. Those
  /// bytes are then read as the other alternative and refused there, which is
  /// where §11.2 has a fault to name.
  ///
  /// # Errors
  ///
  /// The first element's held verdict, where the body took the `#auth-param`
  /// alternative and that element is no parameter.
  fn finish(mut self, scheme: &'a [u8], body: BodyLines<'a>) -> Result<Credential<'a>, AuthError> {
    // The credential's own bytes on its one region, and not the rest of the
    // line behind them: a `token68` is the WHOLE body, so what the challenge
    // behind this one wrote is not part of the question.
    let only = body.cut(0);
    let token = match body.len {
      1 => match token68(only, 0) {
        Some(run) if skip_ows(only, run.len()) == only.len() => Some(run),
        _ => None,
      },
      _ => None,
    };
    if token.is_none() {
      self.settle()?;
    }
    let credential = Credential {
      scheme,
      body,
      token68: token,
    };
    walks_to_its_end(&credential);
    Ok(credential)
  }
}

/// The `#auth-param` list of one [`Credential`], walked across the field lines
/// it arrived on.
///
/// Yields an [`AuthParam`] rather than a `Result`, because the list was
/// validated when the [`Credential`] was built — see
/// [`Credential::params`]. A caller therefore reads a parameter list without
/// deciding what to do about a fault that has already been reported once.
#[derive(Debug, Clone)]
pub struct AuthParamIter<'a> {
  walk: ParamWalk<'a>,
}

impl<'a> Iterator for AuthParamIter<'a> {
  type Item = AuthParam<'a>;

  fn next(&mut self) -> Option<Self::Item> {
    // Both faults this can meet are unreachable over a `Credential` that
    // exists: every element of its body was read and derived once before that
    // value was built, and every fault either could carry was returned there
    // instead. Ending the walk is the answer a fault deserves anyway — a
    // walker that met one can no longer say which of the commas behind it were
    // separators — but ending is not ALL that happens to it. Neither fault is
    // dropped: `ParamWalk::element` recorded the first and this records the
    // second, so a walk that ran past its credential and was refused on the
    // next challenge's first element is not the same state as one that reached
    // the credential's last byte. `Stop` is why that distinction is the one
    // thing here a mistake would otherwise be silent about.
    let element = match self.walk.step()? {
      Ok(element) => element,
      // `ParamWalk::element` recorded it. There is nothing to add.
      Err(_) => return None,
    };
    match auth_param(element.bytes, element.tail) {
      Ok(param) => Some(param),
      Err(fault) => {
        self.walk.stop = Some(Stop::Fault(fault));
        None
      }
    }
  }
}

// Every `None` this iterator answers is a `Stop` written down, and nothing
// clears one — so the walk is over for good, which is what `FusedIterator`
// promises. Declaring the promise is what makes those writes load-bearing
// rather than lines only their own comment argues for:
// `a_walk_that_stops_on_a_fault_says_so` calls `next` again past both endings.
impl core::iter::FusedIterator for AuthParamIter<'_> {}

/// Why a walk over a credential's `#auth-param` list has no next element.
///
/// Two endings, and they are not one fact. A walk that reached the credential's
/// own last byte has read every element there was. A walk that stopped on a
/// fault read an element no production derives — and over a [`Credential`] that
/// exists there is no such element, since every one of them was derived once
/// before that value was built.
///
/// So [`Fault`](Self::Fault) is unreachable, and it carries the fault rather
/// than folding into [`Spent`](Self::Spent) for exactly that reason: it is the
/// one ending here a mistake could reach in silence. A walk that read one
/// element too many meets the NEXT challenge's first element, [`auth_param`]
/// refuses it, and the walk ends — leaving a parameter list that looks complete
/// and a fault nobody was told about. [`BodyLines`]'s `held` is what stops the
/// walk before it can happen; recording WHICH ending occurred is what keeps the
/// two apart for a test and for a later edit, and [`walks_to_its_end`] is what
/// asserts it of every credential this crate builds.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Stop {
  /// The cursor reached the credential's own last byte: [`BodyLines`]'s `held`
  /// on the last region, or the end of the regions it holds.
  Spent,
  /// An element the walk read derives nothing, and the fault it carried.
  Fault(AuthError),
}

/// Asserts that a walk over `credential`'s own parameter list ends where the
/// credential does.
///
/// The invariant [`Stop`] exists for, checked where every [`Credential`] this
/// crate builds is built rather than only where one test looks. Each element of
/// a body was derived once as the value was assembled — by
/// [`BodyCheck::element`], over the elements the collecting walk produced — so
/// re-deriving them through [`Credential::params`] reads the same elements and
/// must reach [`Stop::Spent`]. Reaching [`Stop::Fault`] instead is a walk that
/// read an element PAST the credential, which is the one way being wrong here
/// is silent: the caller is handed a parameter list that looks complete and no
/// fault is reported anywhere.
///
/// `the_body_a_challenge_collected_reads_the_same_alone` measures that
/// agreement over a brute force of its own. This asserts it of every credential
/// every fixture in the suite builds, and of every credential a debug build of
/// a caller's own program builds.
///
/// Compiled away where `debug_assertions` are off, so the release build the
/// no-panic link proof is taken over carries neither the walk nor the
/// assertion, and neither does any other release build. A debug build carries
/// it the way it carries every other debug assertion, on every tier.
#[cfg(debug_assertions)]
fn walks_to_its_end(credential: &Credential<'_>) {
  let mut params = credential.params();
  while params.next().is_some() {}
  debug_assert!(
    params.walk.stop == Some(Stop::Spent),
    "a credential's own parameter list stopped on a fault rather than at its end"
  );
}

/// The same check where `debug_assertions` are off, which is nothing at all.
#[cfg(not(debug_assertions))]
#[inline]
const fn walks_to_its_end(_credential: &Credential<'_>) {}

/// One walk of a credential's `#auth-param` list, as far as the next element.
///
/// Yields the ELEMENTS a body holds and says nothing about what they derive:
/// that is [`auth_param`]'s, over the pair an [`Element`] carries. The same
/// steps are read twice — once to derive the credential and once to hand its
/// parameters over — and writing them once is what keeps the two readings from
/// disagreeing.
#[derive(Debug, Clone)]
struct ParamWalk<'a> {
  body: BodyLines<'a>,
  /// Which region the cursor is in.
  line: usize,
  /// Where in that region.
  at: usize,
  /// Why the walk has no next element, or `None` while it still has one.
  stop: Option<Stop>,
}

impl<'a> ParamWalk<'a> {
  /// A walk of `body` from its first byte.
  const fn over(body: BodyLines<'a>) -> Self {
    Self {
      body,
      line: 0,
      at: 0,
      stop: None,
    }
  }

  /// The next element of the list, or `None` at the end of it.
  fn step(&mut self) -> Option<Result<Element<'a>, AuthError>> {
    loop {
      if self.stop.is_some() {
        return None;
      }
      let line = self.body.line(self.line);
      // Where the credential stops on its last region, which is the one thing
      // about this body that is not read from its bytes: `held` is the cursor
      // of the walk that collected it, recorded there rather than derived
      // again here. Asked before the `OWS` skip, so the byte it stops on is
      // the one that walk stopped on.
      if self.line.saturating_add(1) >= self.body.len && self.at >= self.body.held {
        self.stop = Some(Stop::Spent);
        return None;
      }
      self.at = skip_ows(line, self.at);
      match line.get(self.at) {
        // This region is spent OUTSIDE a quoted-string, so RFC 9110 §5.2's
        // join comma is the separator it looks like and the next region opens
        // a new element.
        None => {
          if self.line.saturating_add(1) >= self.body.len {
            self.stop = Some(Stop::Spent);
            return None;
          }
          self.line = self.line.saturating_add(1);
          self.at = 0;
        }
        // RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable
        // number of empty list elements".
        Some(&b',') => self.at = self.at.saturating_add(1),
        Some(_) => return Some(self.element()),
      }
    }
  }

  /// Takes the element at the cursor, leaving the cursor on whatever ended it
  /// — which may be in a LATER region than the element began in.
  ///
  /// [`scan_element`] is the whole of it, over the region the cursor stands in
  /// and the regions behind it. Those are the field lines the walk that
  /// collected this body scanned, from the credential's own first byte on each
  /// — [`BodyLines`] says why they are stored uncut — so this reads the same
  /// bytes from the same cursor and produces the same element.
  fn element(&mut self) -> Result<Element<'a>, AuthError> {
    let head = self.body.line(self.line);
    let start = self.at;
    let scanned = {
      let walk = &mut *self;
      scan_element(head, start, || {
        let next = walk.line.saturating_add(1);
        if next >= walk.body.len {
          return None;
        }
        walk.line = next;
        Some(walk.body.line(next))
      })
    };
    match scanned {
      Ok(scanned) => {
        self.at = scanned.at;
        Ok(scanned.element)
      }
      Err(fault) => {
        self.stop = Some(Stop::Fault(fault));
        Err(fault)
      }
    }
  }
}

/// What the field line behind an RFC 9110 §5.2 join does to an element left
/// open inside a §5.6.4 quoted-string where the line before it ended.
///
/// Three walks over this module's elements ask exactly this at exactly this
/// point — a credential's parameter list, a `#challenge` value, and §11.6.3's
/// bare list — so [`rejoin`] answers it once and this is what it answers with.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Rejoin {
  /// The string closed and the element ends on the new line.
  Ends {
    /// Where on that line it ends.
    at: usize,
    /// Whether anything other than the `OWS` RFC 9110 §5.6.1.2 hangs on a
    /// comma stood between the close and `at`. Nothing else is derivable
    /// there, so this is [`ValueTail::Trails`] on its way to the one function
    /// that decides the production.
    trails: bool,
  },
  /// A quoted-string is open again where the new line ends.
  ///
  /// Only ever the value's OWN string, still open: a line that closed it ends
  /// the element on that same line, because nothing behind the close opens a
  /// string of its own. [`after_close`] is where that is decided.
  Open {
    /// The state RFC 9110 §5.2's NEXT join comma is to be fed through.
    escape: bool,
  },
  /// A byte §5.6.4 forbids appeared inside a quoted-string.
  Invalid,
}

/// Carries an element across RFC 9110 §5.2's join and says where it got to.
///
/// `escape` is the state the line before this one ended in.
/// [`crate::grammar::scan_quoted_after_join`] is this crate's one
/// implementation of the join rule — it feeds the join's comma THROUGH the
/// open string first, so a pending escape is spent on the comma and a DQUOTE
/// arriving first on `next` CLOSES the string. What lies behind that close is
/// [`after_close`]'s, which is the same rule [`element_end`] applies on the
/// line an element began on: one rule, and §5.2's join is neither a way past
/// it nor a second spelling of it.
fn rejoin(next: &[u8], escape: bool) -> Rejoin {
  match scan_quoted_after_join(next, escape) {
    QuotedScan::Closed(end) => {
      let (at, trails) = after_close(next, end);
      Rejoin::Ends { at, trails }
    }
    QuotedScan::Open { escape } => Rejoin::Open { escape },
    QuotedScan::Invalid => Rejoin::Invalid,
  }
}

/// Where the RFC 9110 §5.6.1.2 element that a §5.6.4 quoted-string just CLOSED
/// at `end` ends, and whether anything underivable stood between the two.
///
/// # A close is not an end
///
/// Past the close only whitespace is derivable. RFC 9110 §11.2's
/// `auth-param = token BWS "=" BWS ( token / quoted-string )` takes one
/// alternative WHOLE, and §5.6.1.2 expands the list around it as
/// `#element => [ element ] *( OWS "," OWS [ element ] )` — so between a value
/// that closed here and the comma that ends its element there is room for that
/// `OWS` and for nothing else. Reaching the comma, or the end of `value`, the
/// element is what it looked like and `trails` is false; the end of a line
/// counts as that comma, since §5.2 puts one at every join and the value ends
/// where the lines run out.
///
/// # What a proven-malformed remainder may not decide
///
/// Reaching anything ELSE, the remainder of the line derives nothing — and a
/// run that derives nothing contains no quoted-string, so a DQUOTE in it opens
/// none. [`raw_comma_end`] therefore takes the rest RAW, and this reports
/// `trails` for the element.
///
/// Granting those bytes quoted-string semantics is what an earlier revision
/// did, and it is how a malformed challenge hid a well-formed one:
/// `Basic realm=x, Broken a="q` and `r"junk", Digest realm=z` are two field
/// lines that §5.2 joins into one value, the value of `a` closes at `r"`, and
/// the DQUOTE in `junk"` then opened a string that swallowed the comma in
/// front of `Digest`. RFC 9110 §11.4 has a user agent select "the challenge
/// with what it considers to be the most secure auth-scheme that it
/// understands", which it cannot do over a challenge it was never shown.
fn after_close(value: &[u8], end: usize) -> (usize, bool) {
  let at = skip_ows(value, end);
  match value.get(at) {
    None | Some(&b',') => (at, false),
    Some(_) => (raw_comma_end(value, at), true),
  }
}

/// Where the run at `at` ends when no RFC 9110 §5.6.4 quoted-string is
/// ADMITTED anywhere in it: the first comma, read raw, or the end of `value`.
///
/// A quoted-string is something a production admits at a POSITION. Where none
/// does, a DQUOTE is one more byte of the run — it opens nothing — so every
/// comma in the run is the §5.6.1.2 separator it looks like, and the first of
/// them is where the run stops.
///
/// Two kinds of run are read this way, and each caller says which one it holds.
/// [`after_close`] and [`Challenges::seek`] hold bytes some production has
/// already REFUSED, where nothing at all is admitted. [`element_end`] holds an
/// element whose grammar puts no quoted-string in it: one that is no
/// `auth-param`, or one whose value took §11.2's `token` alternative.
///
/// Stopping at the end of the line rather than crossing §5.2's join is the
/// same answer: the join IS a comma, so the run ends there either way.
///
/// The direction this errs in is the one §11.4 needs. A run cut too EARLY
/// shows the caller more elements than the sender wrote, each answered on its
/// own; one cut too LATE hides them, and a hidden challenge is a challenge the
/// caller cannot select.
fn raw_comma_end(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while !matches!(value.get(at), None | Some(&b',')) {
    at = at.saturating_add(1);
  }
  at
}

/// Where RFC 9110 §11.2's `auth-param` admits the VALUE of the element that
/// begins at `at`, or `None` for an element that is no `auth-param` and so
/// admits a value nowhere in itself.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Three terminals stand in front of that value and all three are read here:
/// the name `token`, the `=`, and the `BWS` RFC 9110 §5.6.3 defines as `OWS`'s
/// own bytes, on either side of it. None of them can hold a comma, so the
/// question is settled inside ONE list element; and none can hold one across a
/// §5.2 join either, since a `token` carries no comma and §5.2 puts one at
/// every join, so an element that has not reached its `=` on the line it began
/// on never will. [`opens_a_challenge`] asks these same two questions of the
/// same bytes for its own reason, and asks them by calling this: it IS this
/// question answered `None`, rather than a second spelling of it.
///
/// `Some` is no claim that the element parses. What stands at the offset may be
/// neither of §11.2's two alternatives, and [`auth_param`] is the one place
/// that is decided. This answers about POSITION alone, which is all a boundary
/// scan may take from it.
fn param_value_at(value: &[u8], at: usize) -> Option<usize> {
  let name_end = token_end(value, at)?;
  let eq = skip_ows(value, name_end);
  if value.get(eq) != Some(&b'=') {
    return None;
  }
  Some(skip_ows(value, eq.saturating_add(1)))
}

/// Whether the RFC 9110 §5.6.1.2 element at `at` is the `auth-scheme` of the
/// NEXT challenge rather than another `auth-param` of the one already open.
///
/// RFC 9110 §11.6.1's ambiguity — the value "might contain more than one
/// challenge, and each challenge can contain a comma-separated list of
/// authentication parameters" — decided by the two terminals `auth-param` opens
/// with. That is
/// the same pair [`param_value_at`] reads, over the same bytes, so it IS that
/// question asked the other way round and is written as one rather than as two
/// spellings that could drift: an element §11.2 admits no value position in is
/// an element no `auth-param` derives, which is exactly what makes it a scheme.
/// [`auth_param`] refuses such an element on the same two checks, so what this
/// answers `true` for is what that would call
/// [`AuthError::MalformedParameter`].
///
/// An element with no leading token is not a parameter either, and this
/// answers `true` for it: it opens a challenge, where
/// [`AuthError::MissingScheme`] names what is wrong with it. Reporting a
/// malformed parameter instead would blame a production the element was never
/// being read by.
///
/// The `=` is looked for on THIS element's line, because a `token` carries no
/// comma and RFC 9110 §5.2 puts one at every join — so an element that has not
/// reached its `=` on the line it began on never will.
fn opens_a_challenge(value: &[u8], at: usize) -> bool {
  param_value_at(value, at).is_none()
}

/// Where the RFC 9110 §5.6.1.2 element starting at `at` ends — the comma that
/// separates it from the next, or the end of `value`.
///
/// [`crate::grammar::scan_quoted`] is this crate's one implementation of what
/// a quoted-string IS, and the answer here is taken from it, so a comma inside
/// one is data here exactly as it is everywhere else in the crate.
///
/// # A DQUOTE opens nothing where no string may begin
///
/// What a quoted-string is, is not where one may START, and the productions an
/// `auth-scheme` may be followed by leave exactly one such position:
///
/// ```text
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
///
/// RFC 9110 §5.6.2's `tchar` excludes DQUOTE, `token68`'s alphabet excludes it,
/// and §5.6.3's `BWS` is SP and HTAB — so the first byte of an `auth-param`
/// value is the only place any of these admits one. [`param_value_at`] is that
/// position. Anywhere else a DQUOTE is a byte no production admits: it opens
/// no string, and the element ends at the first RAW comma like any other run
/// that holds none, which is what [`raw_comma_end`] answers.
///
/// Reading a DQUOTE as an opener wherever it fell is how a malformed challenge
/// hid a well-formed one. In `Basic a=x"y, Digest realm=z` the value of `a`
/// already took the `token` alternative, so the DQUOTE behind it begins
/// nothing — yet it opened a string that swallowed the comma in front of
/// `Digest`, and RFC 9110 §11.4 has a user agent select "the challenge with
/// what it considers to be the most secure auth-scheme that it understands",
/// which it cannot do over a challenge it was never shown.
///
/// # And a close is not an end
///
/// [`after_close`]'s rule, for the one string that may open here: an
/// `auth-param` value is one alternative taken WHOLE, so the string that closes
/// closes the last thing the element may hold, and the scan does not go on
/// hunting delimiters behind it.
///
/// # What the rule costs
///
/// An unadmitted DQUOTE no longer pairs with a later one, so a DQUOTE that
/// used to CLOSE a refused run now leaves the next admitted position free to
/// OPEN. `Basic ",a=", Digest realm=z` reached `Digest` while its first DQUOTE
/// swallowed its second, and hides it now that the value of `a` is the
/// quoted-string §11.2 says it is, with nothing to close it. That is not this
/// rule erring: a string opened where one IS admitted runs to wherever it
/// closes and §5.6.4 makes every comma inside it data, which is why
/// `Basic a="x, Digest realm=z` has always answered the same way.
fn element_end(value: &[u8], at: usize) -> Delim {
  let opens = param_value_at(value, at).filter(|&value_at| value.get(value_at) == Some(&b'"'));
  let Some(quote) = opens else {
    return Delim::At(raw_comma_end(value, at));
  };
  match scan_quoted(value, quote.saturating_add(1), false) {
    QuotedScan::Closed(end) => Delim::At(after_close(value, end).0),
    QuotedScan::Open { escape } => Delim::Open(escape),
    QuotedScan::Invalid => Delim::Invalid,
  }
}

/// Where `value` ends once the RFC 9110 §5.6.1.2 `OWS` behind its last byte is
/// off it.
///
/// `#element => [ element ] *( OWS "," OWS [ element ] )` puts `OWS` on BOTH
/// sides of every comma, so the whitespace in front of one belongs to the list
/// and not to the element it follows. [`auth_param`] is handed an element with
/// that whitespace already off both ends, and a walk that left the trailing
/// half on would refuse `Basic a=1 , b=2` — §11.2's
/// `( token / quoted-string )` is one alternative taken whole, and a token
/// with a space behind it is neither.
///
/// Only ever called where the element ENDED on this line. A line that runs out
/// inside a §5.6.4 quoted-string ends no element, and a space there is data the
/// string carries rather than the list's.
fn trim_ows_end(value: &[u8], end: usize) -> usize {
  let mut end = end;
  while end > 0 && matches!(value.get(end.saturating_sub(1)), Some(b' ' | b'\t')) {
    end = end.saturating_sub(1);
  }
  end
}

/// Whether the RFC 9110 §5.6.1.2 list element being read ends at `at`.
///
/// The leading edge of the question [`trim_ows_end`] answers at the trailing
/// one. `#element => [ element ] *( OWS "," OWS [ element ] )` hangs every
/// `OWS` it has on a comma, so whitespace at `at` is the list's rather than
/// the element's in front of it — and it closes that element only when the
/// comma it hangs on is really behind it. §5.6.3's `OWS` is SP or HTAB, so one
/// byte cannot answer this: the run has to be walked to what it reaches.
///
/// The end of `value` counts as that comma. RFC 9110 §5.2 joins repeated field
/// lines into one value with a comma between them, so a run reaching the end
/// of ONE line meets the comma next; and where no line follows, the value ends
/// and no element stands behind the whitespace either way. That is the
/// terminator [`token68`] already reads, and this is the one place it is
/// written.
fn ends_element(value: &[u8], at: usize) -> bool {
  matches!(value.get(skip_ows(value, at)), None | Some(&b','))
}

/// Skips RFC 9110 §11.3's `1*SP` from `at`.
///
/// SP alone, which is why §5.6.3's `OWS` skip is the wrong one here:
/// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` writes `1*SP`
/// and no `OWS`, and the two differ by HTAB.
fn skip_sp(value: &[u8], at: usize) -> usize {
  let mut at = at;
  while value.get(at) == Some(&b' ') {
    at = at.saturating_add(1);
  }
  at
}

/// Reads one whole credential out of the field lines carrying it, with no
/// challenge-boundary lookahead: every comma outside a quoted-string separates
/// `auth-param`s, and the whole value is one credential.
///
/// That is RFC 9110 §11.4's reading, which §11.6.2 gives `Authorization`:
/// `Authorization = credentials` is singular, so no comma in it can end a
/// credential and start another. §11.6.1's `WWW-Authenticate = #challenge` is
/// the field where a comma has two possible meanings, and telling them apart
/// is that walk's own work — it finds each challenge's regions and this reads
/// what they hold.
///
/// `lines` are the field's lines in wire order (§5.2). An EMPTY first line is
/// [`AuthError::MissingScheme`] rather than an element to skip: `credentials`
/// is one production and not a list, so a leading comma is derived by nothing.
///
/// # Errors
///
/// [`AuthError::MissingScheme`] with no leading `token`;
/// [`AuthError::MalformedScheme`] where the scheme is followed by neither
/// `1*SP` nor the end of the credential, or where `1*SP` is followed by a HTAB
/// that reaches an element rather than the comma RFC 9110 §5.6.1.2 hangs its
/// `OWS` on; [`AuthError::ChallengeSpansTooManyLines`] past
/// [`MAX_CHALLENGE_LINES`]; and whatever the parameter list carries.
fn read_credential<'a, I>(lines: I) -> Result<Credential<'a>, AuthError>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  let mut lines = lines.into_iter();
  let head = lines.next().unwrap_or_default();
  let Some(scheme_end) = token_end(head, 0) else {
    return Err(AuthError::MissingScheme);
  };
  let scheme = head.get(..scheme_end).unwrap_or_default();
  // The byte after the scheme is decisive and is read before anything is
  // trimmed: `[ 1*SP ( token68 / #auth-param ) ]` has no other entrance, so a
  // scheme not followed by SP takes no body at all.
  let (body_at, section) = match head.get(scheme_end) {
    Some(&b' ') => {
      let at = skip_sp(head, scheme_end);
      // `1*SP` has taken every SP there was, so a HTAB here is whitespace the
      // parameter list owns rather than whitespace the scheme does. RFC 9110
      // §5.6.1.2 expands a list as
      // `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs
      // every OWS it has on a comma: reaching that comma, the HTAB is the OWS
      // in front of it and the section opens on the empty first element the
      // expansion admits; reaching an element instead, nothing derives it and
      // the section cannot start at all.
      if head.get(at) == Some(&b'\t') && !ends_element(head, at) {
        return Err(AuthError::MalformedScheme);
      }
      (at, true)
    }
    // The scheme ends its line. It is a whole credential when it ends the
    // value too, which the loop below is what settles.
    None => (head.len(), false),
    Some(_) => return Err(AuthError::MalformedScheme),
  };
  let mut body = BodyLines::new();
  // Every byte of every line is this credential's: the field holds ONE of them
  // and there is no boundary in the value for a region to stop at, which is
  // what the entry point above this says at length.
  let first = head.get(body_at..).unwrap_or_default();
  body.push(first, first.len())?;
  for line in lines {
    if !section {
      // §5.2 joins this line on with a comma, and a comma is not `1*SP`.
      return Err(AuthError::MalformedScheme);
    }
    body.push(line, line.len())?;
  }
  Credential::read(scheme, body)
}

/// Reads RFC 9110 §11.6.2's `Authorization` and §11.7.2's
/// `Proxy-Authorization` — the two authentication fields whose value is one
/// credential rather than a list of challenges.
///
/// ```text
/// Authorization = credentials
/// Proxy-Authorization = credentials
/// credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// `value` is the field's value, and §11.6.2 says what is in it: "Its value
/// consists of credentials containing the authentication information of the
/// user agent for the realm of the resource being requested." §11.7.2 says
/// the same of the proxy's field, for its own client. The reader beneath this
/// takes field LINES, because a [`Credential`] is the one production
/// [`challenges`] also finds across §5.2's joins; this field carries one
/// value, and this hands it the one it was given.
///
/// # The comma that cannot end a credential
///
/// `credentials` is singular. Neither field is a `#`-list, so there is no list
/// at the top of either value for a comma to be a separator of, and every
/// comma in one belongs to the `#auth-param` list the production ends in. The
/// question [`challenges`] has to answer at each comma — another `auth-param`
/// of the challenge already open, or the `auth-scheme` of the next one — has
/// no second reading to choose between here, and this path asks it nowhere.
///
/// A sender that writes two credentials into one value is therefore read as
/// the field is defined rather than as it was meant. `Basic x=1, Digest y=2`
/// puts `Digest y` where a parameter's name and its `=` belong, and RFC 9110
/// §11.2's `auth-param = token BWS "=" BWS ( token / quoted-string )` admits
/// only §5.6.3's `BWS` between those two, so a second token there is derived
/// by nothing. [`AuthError::MalformedParameter`] is the answer and it is the
/// right one: the field admits one credential, and reporting a malformed one
/// is not the same as silently taking the first of two.
///
/// # A trailing comma, which needs a list to be an empty element of
///
/// `Basic dGVzdA==,` is a valid `WWW-Authenticate` and is not a valid
/// `Authorization`, and the asymmetry is the grammar's rather than this
/// module's. There the comma is an empty element of `#challenge`, and RFC 9110
/// §5.6.1.2 is what skips it: "A recipient MUST parse and ignore a reasonable
/// number of empty list elements". Here `token68` has matched `dGVzdA==`, the
/// production is complete, and no list is left for an empty element to sit in
/// — nor is `,` one of the bytes `token68` is made of, so nothing derives it
/// at all. The body is then read as the other alternative and refused there,
/// which is where §11.2 has a fault to name.
///
/// Where the credential took the `#auth-param` branch instead —
/// `Newauth realm="x",` — the trailing comma IS an empty element of that list,
/// and is skipped in this singular field exactly as in the plural one.
///
/// # Errors
///
/// [`AuthError::MissingScheme`] for a value with no leading `token`;
/// [`AuthError::MalformedScheme`] where the scheme is followed by neither
/// `1*SP` nor the end of the value, or where `1*SP` is followed by a HTAB that
/// reaches an element rather than the comma RFC 9110 §5.6.1.2 hangs its `OWS`
/// on; and whatever the body carries —
/// [`AuthError::MalformedParameter`],
/// [`AuthError::UnterminatedQuotedString`],
/// [`AuthError::InvalidQuotedString`], [`AuthError::DuplicateParameter`] for
/// RFC 9110 §11.2's one-name-once MUST, applied to this field's list for the
/// reason that variant records, and [`AuthError::TooManyParameters`] past
/// [`MAX_PARAMS_PER_CREDENTIAL`] names. One `Result` and nothing behind it: there is
/// one credential in the field, so there is nothing to continue to, and a
/// fault anywhere in it refuses the whole value rather than a part of it.
///
/// Not [`AuthError::ChallengeSpansTooManyLines`], which needs a second field
/// line to be reachable at all: this field's value is one, and the reader
/// beneath is handed exactly that one.
#[inline]
pub fn credentials(value: &[u8]) -> Result<Credential<'_>, AuthError> {
  read_credential([value])
}

/// Reads RFC 9110 §11.6.1's `WWW-Authenticate` and §11.7.1's
/// `Proxy-Authenticate` — the two authentication fields whose value is a list
/// of challenges rather than one credential.
///
/// ```text
/// WWW-Authenticate = #challenge
/// Proxy-Authenticate = #challenge
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// `lines` are the field's lines in wire order. §11.6.1 says the field "can
/// occur multiple times", and §5.2 makes those lines one value with a comma at
/// each join, so a challenge and even one of its values may cross a line the
/// way [`Credential`] describes.
///
/// # The comma that ends a challenge, and the one that does not
///
/// §11.6.1 states the problem this walk exists for: the value "might contain
/// more than one challenge, and each challenge can contain a comma-separated
/// list of authentication parameters". Both levels are the same §5.6.1
/// construct, one inside the other — Appendix A writes the nesting out as
/// `challenge = auth-scheme [ 1*SP ( token68 / [ auth-param *( OWS "," OWS auth-param ) ] ) ]`
/// — so at a comma the next element is either another `auth-param` of the
/// challenge already open or the `auth-scheme` of the next one. Three rules
/// decide it, in this order, and the order is the substance.
///
/// **The SP after the scheme token is what admits a parameter section at
/// all**, and it is read before anything is trimmed. `1*SP` is the only
/// entrance the production has, so a scheme not followed by SP takes no
/// parameters and the comma behind it is a boundary: `Basic , type=1` is ONE
/// challenge with one parameter, and `Basic, type=1` is TWO, the second of
/// which nothing derives. The two values differ by one byte, and a walker that
/// split on commas with the `OWS` §5.6.1.2 hangs on them already trimmed off
/// would have destroyed the byte that separates them. What is asked of that
/// byte is whether it is SP, and what is asked of a HTAB is where its `OWS`
/// run gets to: `Basic<HTAB>, Newauth x=1` is two challenges, because the
/// scheme is followed by the list's own whitespace and then the comma that
/// ends its element.
///
/// **At a comma an empty element is skipped first.** §5.6.1.2: "A recipient
/// MUST parse and ignore a reasonable number of empty list elements". The skip
/// comes before the boundary question because `Basic a=1,,b=2` is one
/// challenge with two parameters, and a rule that read the empty element as an
/// element with no leading token — and therefore as a boundary — would split
/// it.
///
/// **Then the next element's leading `token` and the first non-`BWS` byte
/// behind it decide.** `auth-param = token BWS "=" BWS ( token / quoted-string )`
/// opens with exactly those two, so an `=` there makes the element a parameter
/// of the CURRENT challenge and anything else — a different byte, the
/// element's end, or no leading token at all — makes it the scheme of the
/// next.
///
/// A challenge then closes at the end of its last VALUE, not at the end of the
/// element that question was asked about, so nothing of the next challenge is
/// ever inside the one before it.
///
/// # What follows an error
///
/// One `Result` per challenge, and the walk continues exactly while the comma
/// structure is still trustworthy. Every boundary it finds is a comma OUTSIDE
/// a quoted-string, so [`AuthError::InvalidQuotedString`] ends it: once a
/// quoted-string scan has failed, no later comma can be told from data. Every
/// other fault leaves the boundaries known and the walk goes on, because
/// §11.4 has a user agent choose among challenges by "selecting the challenge
/// with what it considers to be the most secure auth-scheme that it
/// understands" — and one unreadable challenge must not hide the readable one
/// behind it. That is a deliberate divergence from
/// [`crate::grammar::parameterised_list`], which poisons on any `Err`: a
/// parameter list is not a list a caller searches.
///
/// A failed challenge is reported ONCE. The walk then seeks the next boundary
/// over the same clean scan and does not re-read what is left of the failed
/// challenge as challenges of its own, so in `Basic a=1, =x, type=b, Newauth
/// c=1` the `type=b` is part of the failure already reported rather than a
/// second one. A `QuotedScan::Invalid` met during that seek reports
/// [`AuthError::InvalidQuotedString`] and stops the walk, exactly as it does
/// anywhere else; one that never closes consumes the rest of the input, and
/// the walk ends there.
///
/// # How many faults one malformed value yields
///
/// Once per refused challenge, and a value can hold more refused challenges
/// than a sender wrote. Getting past a refusal is done by RAW commas — no
/// DQUOTE behind a fault opens a string, for the reason the section above
/// gives — so a comma that a quote-aware recovery would have swallowed as data
/// ends the refused run here instead, and what stands behind it is read as a
/// challenge of its own and refused in its turn.
/// `Basic<HTAB>Newauth realm="a, b"` is one such value: the scheme is refused,
/// and the comma inside `"a, b"` — data to a recovery that reads that run as a
/// quoted-string, a separator to this one, which does not read a refused run at
/// all — ends the refused challenge, so what stands behind it is refused in its
/// turn. Two [`AuthError::MalformedScheme`]s here, where such a recovery
/// reports one.
///
/// This is the safe direction and the only one §11.4 admits: a run cut too
/// EARLY shows a caller more elements than the sender wrote, each answered on
/// its own, and a run cut too LATE hides them. No challenge is ever lost by it,
/// and every `Ok` is the same `Ok`. But a caller that COUNTS the `Err`s of a
/// malformed value rather than reading them is counting something this reader
/// decides and not something the sender wrote, and will see a different number
/// than a quote-aware recovery gives. Read the faults; do not total them.
///
/// Validation is eager — a challenge is walked to its end before it is yielded
/// — which is what lets [`Credential::params`] be infallible and what lets one
/// walk go on after a fault at all.
///
/// # Errors
///
/// A yielded `Err` is [`AuthError::MissingScheme`] for an element with bytes
/// and no leading `token`; [`AuthError::MalformedScheme`] for one whose token
/// the challenge grammar cannot continue from;
/// [`AuthError::ChallengeSpansTooManyLines`] past [`MAX_CHALLENGE_LINES`];
/// [`AuthError::DuplicateParameter`] for RFC 9110 §11.2's one-name-once MUST,
/// which is per challenge here and so is NOT reported of two challenges that
/// carry the same name; [`AuthError::TooManyParameters`] past
/// [`MAX_PARAMS_PER_CREDENTIAL`] names in one of them; and whatever else that
/// challenge's parameter list carries —
/// [`AuthError::MalformedParameter`], [`AuthError::UnterminatedQuotedString`]
/// or [`AuthError::InvalidQuotedString`]. One per challenge, and the section
/// above says which of them the walk continues past.
#[inline]
pub fn challenges<'a, I>(lines: I) -> impl Iterator<Item = Result<Credential<'a>, AuthError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  Challenges {
    lines: lines.into_iter(),
    // The walk starts with no line in hand, which is the same position as a
    // line that has been spent: the next element comes from the next one.
    line: &[],
    at: 0,
    exhausted: false,
    done: false,
    seeking: false,
  }
}

/// Where a `#challenge` walk stands once it has been moved to the next element
/// of the value RFC 9110 §5.2 joined the field lines into.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Step {
  /// The cursor is on the element's first byte.
  Element {
    /// Whether a comma — one the sender wrote, or the one §5.2 puts at a join
    /// — was crossed to reach it, which is what makes §11.6.1's boundary
    /// question apply at all. The FIRST element of a parameter section is
    /// admitted by the `1*SP` in front of it and is asked nothing.
    after_comma: bool,
  },
  /// The value has no more elements.
  End,
}

/// One challenge's body as it is collected, across the field lines RFC 9110
/// §5.2 joined into one value.
struct Section<'a> {
  /// The regions taken so far.
  body: BodyLines<'a>,
  /// Where the current line's region begins.
  start: usize,
  /// Where the challenge ends in the current line: the end of the last element
  /// read there. A region is cut HERE rather than at the line's end, because
  /// what lies behind it is the next challenge and the commas and `OWS`
  /// §5.6.1.2 puts between elements — and the boundary between two regions
  /// already stands for the one comma §5.2 put there.
  end: usize,
  /// A region did not fit in [`MAX_CHALLENGE_LINES`].
  ///
  /// Recorded rather than returned, because a region is taken where a line is
  /// left behind and that is not a place a verdict can be returned from. What
  /// was collected is no longer the whole challenge, so
  /// [`AuthError::ChallengeSpansTooManyLines`] is the answer rather than
  /// whatever a partial body happens to parse as.
  ///
  /// Read at ONE place: the final region, after the challenge has ended. Every
  /// earlier one is caught before an element is read on it, by
  /// [`outgrown`](Self::outgrown), which is what keeps a challenge already past
  /// the bound from letting its remaining elements choose their own extent.
  overrun: bool,
}

impl<'a> Section<'a> {
  /// A body that begins at `at` on the line its scheme was read from.
  const fn opening_at(at: usize) -> Self {
    Self {
      body: BodyLines::new(),
      start: at,
      end: at,
      overrun: false,
    }
  }

  /// Whether this body has outgrown [`MAX_CHALLENGE_LINES`] by the time an
  /// element is read on the line the cursor stands on.
  ///
  /// A region is taken as the walk LEAVES the line it is on, so the cursor's
  /// own line is never among the ones already spent — and an element read there
  /// puts bytes into its region, which is what spends an entry. Every slot
  /// full therefore means this element's region cannot be held. Asked BEFORE
  /// that element is read, so the refusal is met where the challenge outgrew
  /// the bound rather than at the end of a walk whose later elements would by
  /// then have chosen their own extent.
  ///
  /// `overrun` is deliberately NOT part of this. A region is refused only where
  /// there is no slot left for it, so that flag is never true with fewer than
  /// [`MAX_CHALLENGE_LINES`] regions spent and the count below already holds
  /// wherever it is — a disjunct on it survives the suite, which is what
  /// leaving it out says instead. The flag is read where it is not redundant:
  /// on the LAST region, where a count that has reached the bound cannot tell a
  /// challenge that just fits from one that did not.
  const fn outgrown(&self) -> bool {
    self.body.len >= MAX_CHALLENGE_LINES
  }

  /// Takes what the line being left behind contributes — the challenge's bytes
  /// on it reaching as far as `end` — and opens a region at the start of the
  /// next one.
  ///
  /// The region taken is the line from this challenge's first byte on it to
  /// the line's END, and `end` says how much of that the challenge holds.
  /// [`BodyLines`] carries why the two are not the same slice: a region a later
  /// walk reads has to be the bytes the walk that took it read, or the two
  /// walks are deciding an element's boundary over different inputs.
  fn spend(&mut self, line: &'a [u8], end: usize) {
    let region = line.get(self.start..).unwrap_or_default();
    if self
      .body
      .push(region, end.saturating_sub(self.start))
      .is_err()
    {
      self.overrun = true;
    }
    self.start = 0;
    self.end = 0;
  }

  /// Takes the region the challenge ENDS in, and hands over the body.
  ///
  /// The one reader of [`overrun`](Self::overrun), paired with the last
  /// [`spend`](Self::spend) by consuming the section — so a walk cannot take
  /// the final region and then hand over a body that is missing one. Every
  /// EARLIER region is answered by [`outgrown`](Self::outgrown) instead,
  /// before an element is read on it, and that method carries why the two
  /// readers are not one.
  ///
  /// # Errors
  ///
  /// [`AuthError::ChallengeSpansTooManyLines`] where any region of this
  /// challenge did not fit. It is reported with no seeking behind it: the
  /// challenge's extent is complete by the time this is called, so the cursor
  /// already stands on the next challenge's first byte and there is nothing
  /// left of this one to get past.
  fn close(mut self, line: &'a [u8], end: usize) -> Result<BodyLines<'a>, AuthError> {
    self.spend(line, end);
    if self.overrun {
      return Err(AuthError::ChallengeSpansTooManyLines);
    }
    Ok(self.body)
  }
}

/// The walk [`challenges`] hands out: the field lines still to come, the one
/// being walked, and where in it the next element starts.
struct Challenges<'a, I> {
  lines: I,
  line: &'a [u8],
  at: usize,
  /// `lines` answered `None` once. An `Iterator` is not required to keep doing
  /// so, and RFC 9110 §5.2's value ends at the last line either way.
  exhausted: bool,
  done: bool,
  /// A challenge was REFUSED with the cursor still inside it, so where it ends
  /// has to be found — by raw commas alone — before another challenge can be
  /// read there. Written only by [`Challenges::refuse`] and run only by
  /// [`Challenges::seek`].
  seeking: bool,
}

impl<'a, I> Iterator for Challenges<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  type Item = Result<Credential<'a>, AuthError>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    if self.seeking {
      self.seeking = false;
      self.seek();
    }
    match self.open_element(None) {
      Step::End => {
        self.done = true;
        None
      }
      Step::Element { .. } => {
        let read = self.challenge();
        // Every boundary this walk finds is a comma outside a quoted-string,
        // so a scan that failed inside one leaves every comma behind it a
        // guess. Nothing further is read.
        if matches!(read, Err(AuthError::InvalidQuotedString)) {
          self.done = true;
        }
        Some(read)
      }
    }
  }
}

impl<'a, I> Challenges<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  /// The next field line of the value, or `None` once there are none left.
  fn next_line(&mut self) -> Option<&'a [u8]> {
    if self.exhausted {
      return None;
    }
    let next = self.lines.next();
    if next.is_none() {
      self.exhausted = true;
    }
    next
  }

  /// Moves the cursor to the first byte of the next element of the value,
  /// skipping the empty ones and crossing RFC 9110 §5.2's joins.
  ///
  /// `region` is the body being collected, when there is one; a walk that is
  /// only looking for a boundary passes `None` and takes nothing.
  fn open_element(&mut self, mut region: Option<&mut Section<'a>>) -> Step {
    let mut after_comma = false;
    loop {
      self.at = skip_ows(self.line, self.at);
      match self.line.get(self.at) {
        // RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable
        // number of empty list elements".
        Some(&b',') => {
          self.at = self.at.saturating_add(1);
          after_comma = true;
        }
        // This line is spent OUTSIDE a quoted-string, so §5.2's join comma is
        // the separator it looks like and the next line opens a new element.
        None => {
          let Some(next) = self.next_line() else {
            return Step::End;
          };
          let spent = self.line;
          self.line = next;
          self.at = 0;
          after_comma = true;
          if let Some(section) = region.as_deref_mut() {
            // The cursor moves BEFORE the region is taken, so a body that
            // cannot hold this one leaves the walk standing on the new line
            // rather than losing it with the error.
            let end = section.end;
            section.spend(spent, end);
          }
        }
        Some(_) => return Step::Element { after_comma },
      }
    }
  }

  /// Takes the element at the cursor, leaving the cursor on the comma that
  /// ended it or at the end of the line the value ran out on — and hands the
  /// element back for [`BodyCheck`] to derive BEFORE another one is read.
  ///
  /// A field line's end does not end the element when a RFC 9110 §5.6.4
  /// quoted-string is still open there: §5.2's join comma is data inside one,
  /// so the element runs on to wherever the string closes.
  /// `scan_quoted_after_join` is this crate's one implementation of that rule
  /// and feeds the join's comma THROUGH any pending escape, so the escape is
  /// spent on the comma and a DQUOTE arriving first on the next line closes
  /// the string.
  ///
  /// `region` is the body being collected. Every byte this crosses lands in it,
  /// and the same bytes are what [`AuthParamIter`] hands a caller later.
  ///
  /// # Errors
  ///
  /// [`AuthError::InvalidQuotedString`] for a byte §5.6.4 forbids inside a
  /// quoted-string — the one fault that leaves the commas behind it unreadable
  /// and so is the one this walk cannot continue past. Every OTHER fault the
  /// element carries is in the [`Element`] this returns, because a boundary
  /// this walk has not yet found must not be decided by bytes behind one.
  fn skip_element(&mut self, region: &mut Section<'a>) -> Result<Element<'a>, AuthError> {
    let head = self.line;
    let start = self.at;
    let scanned = {
      let walk = &mut *self;
      let section = &mut *region;
      scan_element(head, start, || {
        let next = walk.next_line()?;
        let spent = walk.line;
        walk.line = next;
        // The element is still open here, so ALL of the line being left is the
        // challenge's — including the bytes that begin no element of their own
        // but carry the close of this one.
        section.spend(spent, spent.len());
        Some(next)
      })?
    };
    self.at = scanned.at;
    region.end = self.at;
    Ok(scanned.element)
  }

  /// Reads the challenge at the cursor, leaving the cursor on the first byte
  /// of the next one — or at the end of the value.
  ///
  /// Eager, and eager in one pass: each element is derived the moment its own
  /// bytes have been read and BEFORE the next element's are. That is what lets
  /// [`Credential::params`] be infallible, what lets this walk report one fault
  /// per challenge and still go on to the next, and — the reason the two are
  /// one loop rather than two — what keeps the bytes of a challenge already
  /// refused from deciding where it ends.
  ///
  /// # A refusal is final, and its extent is raw from there on
  ///
  /// The module doc's invariant, and this is the walk it is about. The moment
  /// an element of this challenge derives nothing, or repeats a name, or fills
  /// the last slot there is, or overruns [`MAX_CHALLENGE_LINES`], the challenge
  /// is refused — and the rest of it is handed to [`Challenges::seek`], which
  /// finds the next challenge by raw commas alone. Nothing behind that first
  /// fault opens a quoted-string, so nothing behind it can swallow the comma in
  /// front of the next challenge.
  ///
  /// # Errors
  ///
  /// [`AuthError::MissingScheme`] and [`AuthError::MalformedScheme`], and every
  /// fault a parameter list carries, leave the cursor INSIDE the challenge that
  /// failed, so [`refuse`](Self::refuse) sets `seeking` and the next boundary
  /// is found there by raw commas. [`AuthError::InvalidQuotedString`] does not:
  /// it leaves every comma behind it a guess, so the WALK ends rather than
  /// recovering, which [`Challenges::next`] is where.
  ///
  /// Two faults are reported with no seeking behind them, and both fire with
  /// the challenge's extent already complete: a body of exactly one element
  /// that no `auth-param` derives and no `token68` takes, and a
  /// [`AuthError::ChallengeSpansTooManyLines`] met on the region the challenge
  /// ENDS in. The cursor is on the next challenge's first byte in both, so
  /// there is nothing left of this one to get past.
  fn challenge(&mut self) -> Result<Credential<'a>, AuthError> {
    let head = self.line;
    let Some(scheme_end) = token_end(head, self.at) else {
      return Err(self.refuse(AuthError::MissingScheme));
    };
    let scheme = head.get(self.at..scheme_end).unwrap_or_default();
    self.at = scheme_end;
    // The byte after the scheme is decisive and is read before anything is
    // trimmed: `[ 1*SP ( token68 / #auth-param ) ]` has no other entrance, so
    // a scheme not followed by SP takes no body at all.
    let body_at = match head.get(scheme_end) {
      Some(&b' ') => {
        let at = skip_sp(head, scheme_end);
        self.at = at;
        // `1*SP` has taken every SP there was, so a HTAB here is whitespace
        // the parameter list owns rather than whitespace the scheme does. RFC
        // 9110 §5.6.1.2 expands a list as
        // `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs
        // every OWS it has on a comma: reaching that comma, the HTAB is the
        // OWS in front of it and the section opens on the empty first element
        // the expansion admits; reaching an element instead, nothing derives
        // it and the section cannot start at all.
        if head.get(at) == Some(&b'\t') && !ends_element(head, at) {
          return Err(self.refuse(AuthError::MalformedScheme));
        }
        at
      }
      // The scheme ends its element — on a comma, or at a line end where
      // §5.2's join comma is the next character of the value. Either way it is
      // a whole challenge that took no parameters.
      None | Some(&b',') => return Credential::read(scheme, BodyLines::new()),
      // And it still ends its element with only whitespace between it and that
      // comma. `1*SP` is SP alone, so a HTAB opens no parameter section; and
      // RFC 9110 §5.6.1.2 expands the `#challenge` list the scheme sits in as
      // `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs
      // that OWS on the comma behind it. The scheme is a whole challenge and
      // what follows the comma is the next one.
      Some(&b'\t') if ends_element(head, scheme_end) => {
        return Credential::read(scheme, BodyLines::new());
      }
      // Anything else behind the token: the production admits nothing there
      // without `1*SP`, and a HTAB reaching this arm reached an element rather
      // than the comma the arm above needs.
      Some(_) => return Err(self.refuse(AuthError::MalformedScheme)),
    };

    let mut section = Section::opening_at(body_at);
    let mut check = BodyCheck::new();
    loop {
      match self.open_element(Some(&mut section)) {
        Step::End => break,
        Step::Element { after_comma } => {
          if after_comma && opens_a_challenge(self.line, self.at) {
            break;
          }
          // This element belongs to the challenge, so everything the challenge
          // already holds has to be answered BEFORE this element's bytes are
          // read. Both checks stand here for that one reason: a boundary found
          // past a fault is a boundary the bytes behind the fault decided.
          if section.outgrown() {
            return Err(self.refuse(AuthError::ChallengeSpansTooManyLines));
          }
          if let Err(fault) = check.settle() {
            return Err(self.refuse(fault));
          }
          let element = self.skip_element(&mut section)?;
          if let Err(fault) = check.element(element) {
            return Err(self.refuse(fault));
          }
        }
      }
    }
    // The challenge closes at the end of its last element, and that is where
    // the region it is in stops holding it: the bytes behind it are the next
    // challenge's, or the empty elements between the two.
    let (line, end) = (self.line, section.end);
    check.finish(scheme, section.close(line, end)?)
  }

  /// Refuses the challenge the cursor stands inside, and says so by leaving
  /// `seeking` set.
  ///
  /// The one writer of that flag, so the pairing cannot be forgotten at a new
  /// fault: a refusal reported without it would leave the cursor in the middle
  /// of a challenge and the elements behind the fault would be read as
  /// challenges of their own. [`Challenges::seek`] is what the flag runs, and
  /// what makes those elements' extent raw.
  fn refuse(&mut self, fault: AuthError) -> AuthError {
    self.seeking = true;
    fault
  }

  /// Finds where a challenge already refused ends, without reading what is left
  /// of it as challenges of its own.
  ///
  /// At each comma the next element's leading `token` and the byte behind it
  /// say whether it still belongs to the refused challenge. RFC 9110 §11.6.1's
  /// ambiguity is resolved once per challenge, so `type=b` in
  /// `Basic a=1, =x, type=b, Newauth c=1` is part of the fault already
  /// reported rather than a second one.
  ///
  /// # A refused challenge decides no boundary
  ///
  /// The module doc's invariant, and this is the whole of its recovery. The
  /// commas are found by [`raw_comma_end`] and not by the element walk
  /// [`Challenges::skip_element`] runs, and that is the difference between
  /// reading a challenge and getting past one. Every byte this crosses belongs
  /// to a challenge already refused, and nothing this walk crosses is ever
  /// derived. Letting those bytes say where a quoted-string begins would let
  /// them say which commas separate elements, and so where the refused
  /// challenge ends and the next one may start.
  ///
  /// That is not a hypothetical ordering: RFC 9110 §11.4 has a user agent
  /// select "the challenge with what it considers to be the most secure
  /// auth-scheme that it understands", and a sender who writes one DQUOTE into
  /// a challenge this walk is recovering from would otherwise swallow every
  /// comma behind it — hiding a stronger challenge inside the fault already
  /// reported for a weaker one.
  ///
  /// Every refusal comes here, and not only the scheme's. [`refuse`](Self::refuse)
  /// is the one writer of the flag that runs it, and its doc says why there is
  /// exactly one.
  ///
  /// So no fault is reported from here, because none can be: a run this walk
  /// takes raw has no quoted-string in it to carry a byte §5.6.4 forbids, and
  /// a §5.6.1.2 comma or the end of the value is all it ever stops at.
  fn seek(&mut self) {
    loop {
      self.at = raw_comma_end(self.line, self.at);
      match self.open_element(None) {
        Step::End => return,
        // A comma was crossed by construction: the element just skipped ended
        // on one, or at the line end RFC 9110 §5.2 puts one at.
        Step::Element { .. } => {
          if opens_a_challenge(self.line, self.at) {
            return;
          }
        }
      }
    }
  }
}

/// Reads RFC 9110 §11.6.3's `Authentication-Info` and §11.7.3's
/// `Proxy-Authentication-Info` — the two authentication fields that are a
/// parameter list and nothing else.
///
/// ```text
/// Authentication-Info = #auth-param
/// Proxy-Authentication-Info = #auth-param
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// No `auth-scheme` stands in front of these and no `token68` behind one, so
/// there is no [`Credential`] here to hold them and no boundary question to
/// ask: every comma outside a quoted-string separates one `auth-param` from
/// the next, and each is yielded on its own. What the parameters MEAN is not
/// this parser's either — RFC 9110 §11.6.3: "This specification only describes
/// the generic format; authentication schemes using Authentication-Info will
/// define the individual parameters." §11.6.3 also frees the field of any
/// other context: "The Authentication-Info field can be used in any HTTP
/// response, independently of request method and status code."
///
/// `lines` are the field's lines in wire order. §5.2 makes a repeated field
/// one value, its field line values "concatenated in order, with each field
/// line value separated by a comma", so a sender that split this list at an
/// element boundary wrote the same list as one that did not — and a value may
/// legally open on one line and close on the next, which the walk crosses.
///
/// `#auth-param` carries neither bound of §5.6.1's `<n>#<m>element`, so an
/// empty field value is an empty list rather than a fault.
///
/// # What a join can still take away
///
/// One VALUE's contiguity, and nothing else. A parameter whose quoted-string
/// crosses a join keeps its boundaries and its name, so the walk yields it and
/// [`AuthParam::name`] answers; [`AuthParam::value`] is where
/// [`ValueSpansFieldLines`] is reported, exactly as it is for a parameter
/// reached through [`Credential::params`]. The rule is one rule at all three
/// entry points, and §11.6.3's field is not the place it changes.
///
/// # No line bound
///
/// [`MAX_CHALLENGE_LINES`] bounds what one [`Credential`] can NAME at once,
/// because a challenge is handed over whole and a borrowing reader has to hold
/// every region it spans. This walk hands over one parameter at a time and
/// never names more than the line that parameter began on, so nothing here is
/// bounded by it: a list spread over more lines than a challenge may occupy is
/// read rather than refused.
///
/// A bound on the PARAMETERS is a different question and this walk does carry
/// one: [`MAX_PARAMS_PER_CREDENTIAL`], for the record RFC 9110 §11.2's one-name-once
/// MUST is checked against. Lines are unbounded here and names are not.
///
/// # A trailer's lines, which are field lines
///
/// RFC 9110 §11.6.3: "Authentication-Info can be sent as a trailer field
/// (Section 6.5) when the authentication scheme explicitly allows this."
/// §11.7.3 writes the same sentence for the proxy's field.
///
/// Nothing here honours that, because nothing here can tell. This reader takes
/// field lines and takes nothing else: no section reaches it, so no branch in
/// it can turn on one, and a trailer section's lines are read identically to a
/// header section's BY CONSTRUCTION rather than by a check that could be got
/// wrong. §6.5 is what makes that sound rather than lucky — a trailer field is
/// a §5 field that happens to be located in a trailer section, with the same
/// syntax it would have had in a header one. Whether the scheme allows the
/// field there at all is the caller's, since this crate implements no
/// authentication scheme.
///
/// # What follows a fault
///
/// One, and then the walk ends. A `#challenge` value is a list a caller
/// SEARCHES — §11.4 has a user agent choose "the challenge with what it
/// considers to be the most secure auth-scheme that it understands" — so
/// [`challenges`] reports a fault and goes on, lest one unreadable challenge
/// hide the readable one behind it. A parameter list is not searched that way,
/// and this crate's other parameter walk,
/// [`crate::grammar::parameterised_list`], poisons on any `Err`. This one does
/// the same, so a caller reading a fault knows the rest of the list was not
/// silently dropped one parameter at a time.
///
/// # Errors
///
/// [`AuthError::MalformedParameter`] for an element that is not
/// `token BWS "=" BWS ( token / quoted-string )` — which is what an
/// `auth-scheme` and its parameters are, read as one element of this field;
/// [`AuthError::UnterminatedQuotedString`] for a string still open when the
/// last field line ended; [`AuthError::InvalidQuotedString`] for a byte §5.6.4
/// forbids inside one; [`AuthError::DuplicateParameter`] for RFC 9110 §11.2's
/// one-name-once MUST, applied to this field's list for the reason that
/// variant records; and [`AuthError::TooManyParameters`] past
/// [`MAX_PARAMS_PER_CREDENTIAL`] names.
///
/// The last two are reported AT the parameter that broke the rule, which is
/// where this walk differs from the other two entry points rather than in the
/// rule it applies. A [`Credential`] is validated whole before it exists, so a
/// repeat anywhere in it refuses the whole credential; here the parameters in
/// front of the repeat were already handed over, and what the fault says is
/// that the walk ends there — the same thing every other fault on this path
/// says, and the reason none of them is silently dropped.
#[inline]
pub fn auth_info<'a, I>(lines: I) -> impl Iterator<Item = Result<AuthParam<'a>, AuthError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  AuthInfo {
    lines: lines.into_iter(),
    // The walk starts with no line in hand, which is the same position as a
    // line that has been spent: the next element comes from the next one.
    line: &[],
    at: 0,
    exhausted: false,
    done: false,
    seen: SeenNames::new(),
  }
}

/// The walk [`auth_info`] hands out: the field lines still to come, the one
/// being walked, and where in it the next element starts.
struct AuthInfo<'a, I> {
  lines: I,
  line: &'a [u8],
  at: usize,
  /// `lines` answered `None` once. An `Iterator` is not required to keep doing
  /// so, and RFC 9110 §5.2's value ends at the last line either way.
  exhausted: bool,
  /// A fault was reported, or the value ran out. Either way there is no
  /// further parameter to hand over.
  done: bool,
  /// The names this field's list has already used, for RFC 9110 §11.2's
  /// one-name-once MUST. [`MAX_PARAMS_PER_CREDENTIAL`] slots, which is the bulk of
  /// this walk's size and is paid by whoever holds the iterator; that constant
  /// carries the measurement.
  seen: SeenNames<'a>,
}

impl<'a, I> Iterator for AuthInfo<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  type Item = Result<AuthParam<'a>, AuthError>;

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      if self.done {
        return None;
      }
      self.at = skip_ows(self.line, self.at);
      match self.line.get(self.at) {
        // RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable
        // number of empty list elements".
        Some(&b',') => self.at = self.at.saturating_add(1),
        // This line is spent OUTSIDE a quoted-string, so §5.2's join comma is
        // the separator it looks like and the next line opens a new element.
        None => {
          let Some(next) = self.next_line() else {
            self.done = true;
            return None;
          };
          self.line = next;
          self.at = 0;
        }
        Some(_) => return Some(self.element()),
      }
    }
  }
}

impl<'a, I> AuthInfo<'a, I>
where
  I: Iterator<Item = &'a [u8]>,
{
  /// The next field line of the value, or `None` once there are none left.
  fn next_line(&mut self) -> Option<&'a [u8]> {
    if self.exhausted {
      return None;
    }
    let next = self.lines.next();
    if next.is_none() {
      self.exhausted = true;
    }
    next
  }

  /// Takes the element at the cursor, leaving the cursor on whatever ended it
  /// — which may be on a LATER field line than the element began on.
  ///
  /// The parameter is named over the bytes of the line it STARTED on, which is
  /// all a borrowing reader can hand back. When RFC 9110 §5.2's join carried a
  /// quoted value onto a further line, [`ValueTail::Continues`] is what says
  /// so, and [`AuthParam::value`] reports it over those same bytes.
  ///
  /// # Why this may derive an element after finding its extent
  ///
  /// [`Challenges::challenge`] may not, and the module doc says why: a verdict
  /// reached after the extent was found is a verdict the bytes behind a fault
  /// helped decide, and in a `#challenge` value those bytes can steer the
  /// boundary past a whole challenge. This walk is the same shape and is safe,
  /// and it is safe for two reasons rather than by luck — both of which a
  /// change here has to keep true.
  ///
  /// - **`Authentication-Info = #auth-param` has one level.** There is no
  ///   production nested inside this list for a boundary to be moved past, so
  ///   the most an element's extent can decide is where the NEXT `auth-param`
  ///   of the same list begins. There is no §11.4 choice to be denied here,
  ///   because there is no challenge to hide: the harm the `#challenge` rule
  ///   exists against has nothing in this field to happen to.
  /// - **The walk STOPS at the first fault**, so no byte behind one is ever
  ///   read at all. [`refuse`](Self::refuse) is the one writer of `done` on a
  ///   fault and every fault site goes through it, and
  ///   `one_fault_ends_the_parameter_walk` is that stop pinned.
  ///
  /// The second premise is the load-bearing one. A change that let this walk
  /// CONTINUE past a fault — a caller wanting the parameters behind a bad one
  /// — would put bytes a production has already refused in front of the next
  /// element's extent, which is round 3's shape arriving in this field. Such a
  /// change has to bring [`Challenges::challenge`]'s discipline with it: derive
  /// each element before the next element's bytes are read, and find the rest
  /// of a refused run by raw commas. It is not enough to keep this function and
  /// drop the `done`.
  ///
  /// # Errors
  ///
  /// [`AuthError::InvalidQuotedString`] for a byte §5.6.4 forbids inside a
  /// quoted-string, whatever [`auth_param`] makes of the element, and
  /// [`AuthError::DuplicateParameter`] or [`AuthError::TooManyParameters`]
  /// from the record of names this field's list has already used. Any of them
  /// ends the walk.
  fn element(&mut self) -> Result<AuthParam<'a>, AuthError> {
    let head = self.line;
    let start = self.at;
    let scanned = {
      let walk = &mut *self;
      scan_element(head, start, || {
        let next = walk.next_line()?;
        walk.line = next;
        Some(next)
      })
    };
    let scanned = match scanned {
      Ok(scanned) => scanned,
      Err(fault) => return Err(self.refuse(fault)),
    };
    self.at = scanned.at;

    let read = auth_param(scanned.element.bytes, scanned.element.tail).and_then(|param| {
      // RFC 9110 §11.2's one-name-once MUST, over the list this field IS. The
      // record is the walk's rather than the element's, because the rule is
      // about the list and a single element cannot see one.
      self.seen.record(param.name())?;
      Ok(param)
    });
    match read {
      Ok(param) => Ok(param),
      Err(fault) => Err(self.refuse(fault)),
    }
  }

  /// Ends the walk, and hands the fault that ended it back.
  ///
  /// The one writer of `done` on a fault, so the pairing cannot be forgotten at
  /// a new fault site: this walk derives each element after finding its extent,
  /// and [`element`](Self::element) records that stopping here is what makes
  /// that order safe.
  fn refuse(&mut self, fault: AuthError) -> AuthError {
    self.done = true;
    fault
  }
}

#[cfg(test)]
mod tests;
