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
//! # Every question this module and [`crate::grammar`] both decide
//!
//! Enumerated because one of them was answered twice, differently: whether a
//! run a byte §5.6.4 forbids sealed still holds the commas
//! behind it. `crate::grammar::Readings::absorb` said yes and
//! `some_reading_holds` said no, and the second answer handed a caller a
//! `Digest` built out of somebody's realm. Nothing had ever listed the
//! questions, so nothing could notice.
//!
//! **Shared, so there is one answer by construction** — this module imports it:
//! what a §5.6.4 `quoted-string` is ([`crate::grammar::scan_quoted`]), what
//! §5.2's join does to one still open
//! ([`crate::grammar::scan_quoted_after_join`]), §5.6.3's `OWS`
//! ([`crate::grammar::skip_ows`]), §5.6.2's `token`
//! ([`crate::grammar::token_end`]), §5.5's `field-vchar` (through
//! `scan_quoted`), the value a parameter hands back
//! ([`crate::grammar::ParamValue`]), and now **whether a scan's state leaves a
//! reading holding an offset** (`crate::grammar::Readings`).
//!
//! **Answered here as well, and the two agree**:
//!
//! | question | here | [`crate::grammar`] |
//! |---|---|---|
//! | where a run with no string admitted in it ends | `raw_comma_end` | `raw_comma_end` |
//! | that a close is not an END, and what may stand behind one | `after_close` | `after_close` |
//! | that a DQUOTE opens nothing where no production admits a value | `element_end` | `parameter_end`, over `raw_run_end` |
//! | where a REFUSED element's end is, or that there is none | `refused_element_end` | `refused_member_end` |
//! | what a caller is told when there is none | [`AuthError::ChallengeBoundaryUnknown`] | `ListError::MemberBoundaryUnknown` |
//! | that `( token / quoted-string )` is one alternative taken WHOLE | `auth_param` | `parse_param` |
//! | that a value may close on a later field line | `ValueTail` | `QuotedTail` |
//!
//! **Answered here as well, and the two differ — because the PRODUCTIONS do**:
//!
//! | question | here | [`crate::grammar`] |
//! |---|---|---|
//! | where a value position is | `token BWS "=" BWS`, `param_value_at` | `parameter-name "=" ` with no whitespace, or §10.1.4's own `BWS` |
//! | what ends one element | §5.6.1's comma | that comma or §5.6.6's `;`, which is why `raw_run_end` is a second scan |
//! | whether an empty slot is a fault | §5.6.1.2's empty element is skipped | §10.1.4 refuses one, §5.6.6 reports it |
//! | whether a repeated name is a fault | §11.2's one-name-once MUST | §5.6.6 has no such MUST and no check |
//! | what a fault does to the rest of the list | one per challenge, and the walk goes on, because §11.4 has a user agent SEARCH the list | `parameterised_list` poisons at the first `Err` |
//!
//! Where a row DIFFERS, the difference is a production and not a judgement, and
//! the doc of each half names the other. Where a row AGREES, it agrees because
//! one of the two is written and the other cites it — which is what the top
//! group makes unnecessary and what a future row should join instead.
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
//!   derives nothing, repeats a name, fills the last slot there is, carries a
//!   byte §5.6.4 forbids inside a quoted-string, or takes the challenge past
//!   [`MAX_CHALLENGE_LINES`], **that challenge is refused, and the rest of its
//!   extent is crossed only at the commas EVERY reading of those bytes ends an
//!   element at** — `seek`, over `refused_element_end` — with the latched fault
//!   returned. No DQUOTE behind the first definitive fault may steer where the
//!   refused challenge ends, and no raw comma may either: behind a fault
//!   nothing forces §11.2's `( token / quoted-string )` on the bytes at a value
//!   position, so a DQUOTE there is one a reading may open and a reading may
//!   leave shut, and where the two disagree about the next comma the walk
//!   reports [`AuthError::ChallengeBoundaryUnknown`] and stops. Cutting there
//!   instead is how `Basic p1=1, ..., p17=17, x="c, Digest realm=evil, junk"`
//!   handed a caller a `Digest` challenge with a `realm` of `evil` that no
//!   origin server sent — on one field line, with no repeated name, nothing
//!   malformed, no byte §5.5 forbids, and a parameter list §11.2 bounds
//!   nowhere.
//! - **And WHICH value position, which §11.6.1 answers twice.** An element the
//!   recovery stands on is one more `auth-param` of the challenge already open,
//!   or the `auth-scheme` of the next one — §11.6.1's value "might contain more
//!   than one challenge, and each challenge can contain a comma-separated list
//!   of authentication parameters" — and the two put their DQUOTE in different
//!   places: at the element's own value position, or behind `auth-scheme 1*SP`
//!   at the first parameter of the challenge opening there. `opener_at` reads
//!   both, and the second is admitted only where a comma stands in front of the
//!   cursor, which §5.2's join is what puts there. `Basic a="x` and
//!   `Digest realm="evil, Newauth realm=z, junk", Safe realm=s` are the two
//!   field lines that needed it: a check asked only at the cursor crossed the
//!   comma behind `evil` and handed a caller a `Newauth` challenge out of the
//!   middle of a realm.
//!
//! A refusal BINDS where it is met, and is never a fact left for a later reader
//! to remember. The four faults an element carries are returned by the check
//! that found them, one element at a time. The fifth — the forbidden byte — is
//! returned by the scan that met it, before that element is derived at all. The
//! sixth — the line bound — is met at three crossings and binds at each: before
//! an element is read on a line whose region cannot be held
//! (`Section::outgrown`), at the crossing an element still OPEN makes, where the
//! refusal IS the absence of a line so the scan cannot read one byte more
//! (`Section::spend`), and on the region the challenge ends in
//! (`Section::close`). A section that has refused holds no body at all, so a
//! reader that went on regardless has nothing to be handed.
//!
//! Keeping the second scope true is a requirement on the WALK rather than on
//! any one function: **a challenge's elements are derived in the order they
//! arrive, and each verdict is in hand before the next element's bytes are
//! read.** The `#challenge` walk is the only one that has to hold it — the
//! reader for a field carrying one credential is handed a body whose extent is
//! already settled — and it holds it by feeding every element to `BodyCheck` as
//! it finds one. A change that moves any part of that derivation behind the
//! boundary scan re-opens this, whatever else it fixes, and the same harm has
//! been reached through three different such moves.
//!
//! The first element's verdict is the one thing held back, and only until a
//! SECOND element exists: §11.2's `token68` alternative derives an element no
//! `auth-param` does, so a body of exactly one element cannot be judged as a
//! parameter list at all. `BodyCheck` carries that argument, and holding a
//! verdict for an element that no later element's bytes are read past costs the
//! invariant nothing.
//!
//! No fault ends the walk, and [`AuthError::InvalidQuotedString`] is not the
//! exception it looks like. The argument for carving it out — that a scan which
//! failed inside a quoted-string can no longer tell a separating comma from
//! data — states the premise of this invariant and then declines its
//! conclusion, since raw-comma recovery is what a walk that cannot trust a
//! comma DOES. The recovery it enters is the same one every other refusal
//! enters, and it certifies as few commas: a DQUOTE at §11.2's value position
//! opens a run whatever byte comes next, and a forbidden one means that run
//! reaches no close and so holds every comma behind it. That variant's own
//! documentation carries the rest.
//!
//! And THREE of the refusals are this reader's rather than RFC 9110's, which is
//! the difference that decides what recovery may say behind one.
//! [`MAX_CHALLENGE_LINES`], [`MAX_PARAMS_PER_CREDENTIAL`] and §11.2's
//! one-name-once MUST refuse a value whose every element is exactly where
//! §5.6.1.2 puts it: the grammar derives these bytes from end to end, and what
//! the refusal says is that this reader will not HOLD the challenge. Behind a
//! fault of the grammar no boundary is fixed at all, and the two regimes are
//! not the same one. `AuthError::is_a_receiver_bound` is where that is decided
//! once, `Epoch` is what carries it, and
//! `Basic p1=1, ..., p17=17, Bearer abc, x="open, Digest realm=z` is the value
//! that separates them — the `Bearer` is §11.2's `token68`, no `auth-param`
//! derives it, so the refused list has ended at it under every reading and the
//! `Digest` behind `x` is a challenge rather than that parameter's data.
//!
//! One of the three can still fire on a value some derivation admits AND leave
//! the reader unable to see where it ends: a quoted value that would have
//! closed on a field line this reader may not hold. Recovering raw from there
//! can show a caller a challenge those bytes were the data of, so that one is
//! [`AuthError::ChallengeBoundaryUnknown`] rather than a guess.
//! [`MAX_CHALLENGE_LINES`] carries that trade and which half of it is safe.
//!
//! # Where a boundary is derived, and how many times
//!
//! Once, in `scan_element`, and every walk in this module gets its elements
//! from there: the `#challenge` walk while it is still cutting a body, the
//! `#auth-param` walk a caller reaches through [`Credential::params`], and
//! §11.6.3's bare list. A rule that is right at one entrance and absent at a
//! second is how each of the three moves above got in, and a boundary derived
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
// gate-exempt: x="c", Digest realm=evil — one field value shown in prose, whose
// quoted-string CLOSES in front of the comma; not a production of any RFC.
// gate-exempt: trap="open, Digest realm=z — the pair to it, whose string does
// not close, so that comma is inside a value. Not a production of any RFC.
// gate-exempt: crate::validator — named for contrast: §8.8.3's `opaque-tag` is
// what forced a walk of its own there, and an `auth-param` value having a real
// `quoted-pair` is why none is forced here.

use crate::grammar::{
  Delim, ParamValue, QuotedScan, Readings, eq_ignore_ascii, scan_quoted, scan_quoted_after_join,
  skip_ows, token_end,
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
/// # What refusing here costs, and why it is the safe half
///
/// This is the one refusal in the `#challenge` walk that is the RECIPIENT's
/// rather than the sender's, so it is the only one that can fire on a value
/// some derivation still admits — a §5.6.4 quoted-string that would have closed
/// on a line past the bound. The rest of such a challenge is then found by raw
/// commas like every other refusal (`Challenges::seek`), and a comma the sender
/// wrote INSIDE that value is read as the separator it is not: a caller can be
/// shown a challenge those bytes were the data of.
///
/// The alternative was to end the walk, and it is the worse half — which is
/// measured rather than argued: a value this reader cannot hold may carry a
/// byte §5.6.4 forbids past the bound, and ending the walk there hid every
/// challenge behind it for a string that never was one. That is the same
/// argument [`AuthError::InvalidQuotedString`] now carries for itself, and no
/// fault in this walk ends it any more. RFC 9110 §11.4
/// has a user agent select "the challenge with what it considers to be the most
/// secure auth-scheme that it understands", which it cannot do over a challenge
/// it was never shown; being shown one too many is the error a caller can see
/// and answer, since the refusal is reported in front of it. `challenges` says
/// what a caller does with a fault it is handed.
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
  /// pair, and the reading that puts the escape on the next line's first byte
  /// instead answers both halves backwards.
  #[error("quoted-string is never closed")]
  UnterminatedQuotedString,
  /// A byte RFC 9110 §5.6.4's `qdtext` / `quoted-pair` grammar forbids appeared
  /// inside a quoted-string.
  ///
  /// Kept apart from
  /// [`UnterminatedQuotedString`](Self::UnterminatedQuotedString) because the
  /// two say different things about the value. An open string is the end of the
  /// input, and the value it holds may be perfectly well formed as far as the
  /// input goes; a forbidden byte means no derivation of that string exists at
  /// all.
  ///
  /// # What the byte is, and why the field value is already lost
  ///
  /// Every byte that reaches this is a CTL other than HTAB — RFC 9110 §5.6.4's
  /// `qdtext` admits HTAB, SP, `%x21`, `%x23-5B`, `%x5D-7E` and `obs-text`, and
  /// its `quoted-pair` escapes HTAB, SP, VCHAR and `obs-text`, so nothing else
  /// is left to forbid. §5.5's `field-vchar = VCHAR / obs-text` admits none of
  /// them ANYWHERE in a field value, and it names the three worst: "a recipient
  /// of CR, LF, or NUL within a field value MUST either reject the message or
  /// replace each of those characters with SP before further processing or
  /// forwarding of that message." Of the rest it says "Field values containing
  /// other CTL characters are also invalid; however, recipients MAY retain such
  /// characters for the sake of robustness when they appear within a safe
  /// context (e.g., an application-specific quoted string that will not be
  /// processed by any downstream HTTP parser)." This IS a downstream HTTP
  /// parser, so that exception is not this reader's to take.
  ///
  /// **So this fault refuses the challenge and the walk goes on**, like every
  /// other refusal, and the rest of that challenge's extent is looked for the
  /// way every other refusal's is — by `Challenges::seek`, which certifies
  /// only the commas no reading of the bytes in front of them holds inside a
  /// string.
  ///
  /// # What "derives nothing" does not buy
  ///
  /// It is tempting to read the paragraph above as licence to cross those
  /// commas raw: a field value carrying one of these bytes derives nothing at
  /// §5.5 before §11 is reached at all, so there is no derivation for the bytes
  /// behind the fault to belong to. True, and beside the point. The question a
  /// recovery asks is not what DERIVES but what the sender WROTE: §11.2 admits
  /// a `quoted-string` at the value position, the sender opened one there, and
  /// a run that reaches no close holds every comma behind its DQUOTE. Cutting
  /// at one of them hands a caller a challenge assembled out of somebody's
  /// realm — `Basic x="%x01, Digest realm=evil` is that challenge, and §11.4
  /// has a user agent SELECT among the challenges it is shown.
  ///
  /// `crate::grammar::Readings::absorb` calls such a reading SEALED and has
  /// answered this way for RFC 9110 §5.6.6's `parameters` since
  /// `gzip;;x="a%x01, chunked, b", br` cut raw handed a caller a `chunked` that
  /// stood among those bytes. This module answered the other way;
  /// `some_reading_holds` is where the two are now one answer.
  ///
  /// `obs-text` is the pair to this and is deliberately not here — a high byte
  /// IS `qdtext`, so a value carrying one stays one value, its commas stay
  /// data, and what changes is whether the value DERIVES rather than what a
  /// recovery may certify.
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
  /// A challenge was refused, and where it ENDS is not derivable — so
  /// everything behind it is left unread rather than cut at a comma some
  /// reading of the sender's own bytes holds inside a value.
  ///
  /// This is [`challenges`]'s LAST item. RFC 9110 §11.2 admits a §5.6.4
  /// quoted-string at the first byte of every `auth-param` value —
  /// `auth-param = token BWS "=" BWS ( token / quoted-string )` — and behind a
  /// refusal nothing forces that alternative on those bytes, so an element
  /// standing there has a reading that opens the string and a reading that
  /// leaves it shut. Where the two disagree about the next comma, the bytes
  /// behind it are that value's data under one and a whole challenge under the
  /// other, and neither offset is this walk's to pick.
  ///
  /// # Why the walk stops rather than cutting at the comma
  ///
  /// Because inventing a challenge and hiding one are the same harm, and RFC
  /// 9110 §11.4 makes the first the worse. A user agent answers by "selecting
  /// the challenge with what it considers to be the most secure auth-scheme
  /// that it understands", so a scheme and realm cut out of a parameter's data
  /// arrive indistinguishable from ones the origin server wrote — and whoever
  /// controls that parameter's value chooses them.
  /// `Basic p1=1, ..., p17=17, x="c, Digest realm=evil, junk"` is that input:
  /// one field line, no repeated name, nothing malformed, no byte §5.5 forbids.
  ///
  /// A caller that receives this knows exactly what it holds: the challenges
  /// yielded in front of it, and no claim at all about the rest of the value.
  #[error("a refused challenge ends where this recipient cannot derive, so the rest is unread")]
  ChallengeBoundaryUnknown,
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
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Element<'a> {
  /// The element's bytes on the line it began on.
  bytes: &'a [u8],
  /// What became of a quoted-string still open where that line ran out.
  tail: ValueTail,
}

/// What [`scan_element`] found: the element, where the walk now stands, and
/// where a recovery behind this element would have to begin.
#[derive(Debug, Copy, Clone)]
struct Scanned<'a> {
  /// The element.
  element: Element<'a>,
  /// Where it ended on the field line the walk stands on when this is returned
  /// — a LATER line than the element began on whenever a value crossed RFC
  /// 9110 §5.2's join. The caller's own cursor takes it.
  at: usize,
  /// Where a walk that REFUSES this element must look for the challenge's end.
  recovery: Recovery,
}

/// Where the end of a challenge holding an element already refused is looked
/// for, on the field line the walk stands on.
///
/// An element this walk cut is one whose extent it derived by OPENING the
/// RFC 9110 §5.6.4 quoted-string §11.2 admits at its value position. Where the
/// element then derives NOTHING, that string was no longer forced on those
/// bytes — a reading may leave it shut and end the element at the first comma
/// instead — so the extent this scan produced is one reading's and not every
/// reading's, and a recovery beginning behind it would never see the other one.
/// `Basic a="x` and `trap="open, Digest realm=z` are two field lines §5.2 joins
/// into one value, whose open reading closes `a` at `trap="` and whose shut
/// reading makes `trap="open, Digest realm=z` one element with the probe inside
/// its value.
///
/// # Two states, and why they are every reading however many lines were crossed
///
/// The walk holds ONE field line when it recovers, and the fields below are the
/// RFC 9110 §5.6.4 states the readings of the value stand in at that line's
/// head: inside the string this element opened, which closes at `floor`, and
/// outside every string, which is where the reading that left the DQUOTE shut
/// has been since the join it shut at. Nothing else is in the set, and the
/// reason is a fact about the lines already crossed rather than a limit of what
/// is stored.
///
/// A reading that shut this element's DQUOTE begins a fresh element at the next
/// comma, and to be INSIDE a string here it would have to have opened one on a
/// line behind this one. It cannot have: for the open reading to have carried
/// its string across those lines, [`scan_quoted`] must have closed on none of
/// them, so every DQUOTE on them stood behind the backslash of a §5.6.4
/// `quoted-pair`. [`param_value_at`]'s answer is `skip_ows` past an `=`, and
/// neither §5.6.3's `BWS` nor that `=` is a backslash — so no DQUOTE on a
/// crossed line stands at a value position, and no shut reading opens a string
/// on one. Every such reading arrives here outside every string, which is the
/// state the set already holds.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Recovery {
  /// Where the element the walk refused stands on the line it NOW holds: the
  /// element's own first byte where it never left that line, and the head of
  /// the line otherwise — the far side of the comma RFC 9110 §5.2's join put
  /// there, which is where the reading that ended the element at that comma
  /// begins.
  ///
  /// The element is the OUTER `#challenge` list's, which is not always the one
  /// [`scan_element`] read: `auth-scheme 1*SP` is no §5.6.1.2 separator, so the
  /// first element of a body §11.3's `1*SP` opened is a SUFFIX of an element
  /// that began at the scheme. `scan_element`'s `element_at` is where that
  /// element begins and this is taken from it.
  ///
  /// The far side of a comma is not an element's first byte. §5.6.1.2 expands
  /// its list as `#element => [ element ] *( OWS "," OWS [ element ] )`, so a
  /// sender may write §5.6.3 whitespace between the two, and [`opener_at`] is
  /// where it is skipped rather than here: the commas [`floor`](Self::floor)
  /// answers about are counted from this offset, and moving it would move which
  /// of them the value carried across the join still holds.
  at: usize,
  /// The offset in front of which no comma on this line is a boundary, because
  /// the reading that opened this element's value holds every one of them: the
  /// close of that value where it crossed a join, and `at` itself where it did
  /// not.
  floor: usize,
  /// Whether RFC 9110 §5.6.1.2's comma — §5.2's join comma included — stands in
  /// front of `at`, so that §11.6.1 admits a whole `challenge` there and not
  /// only one more `auth-param` of the challenge already open, and so that the
  /// `OWS` that comma may carry stands between `at` and the element both of
  /// those readings are of.
  ///
  /// The other half of what a join leaves behind, of which `floor` is the
  /// first. `floor` answers for the reading that CARRIED this element's value
  /// onto this line; this one admits the reading that shut that value AT the
  /// join, under which the continuation line opens an element of the outer
  /// `#challenge` list — a scheme, its `1*SP` and its parameters — whose own
  /// quoted value stands at an offset no scan from `at` would ask about.
  /// [`opener_at`] is where the two readings name their openers, and its doc
  /// carries why they can never name two at once.
  ///
  /// Set where a join carried this element onto the line the walk now stands
  /// on, and there alone. The other two constructions below stand where no
  /// challenge may open: the element's own start on the line it began on, which
  /// [`Challenges::challenge`] reaches only past an `opens_a_challenge` already
  /// answered `false` or as the first element of a body, and the end of a value
  /// that ran out inside a string, which begins no element at all.
  after_comma: bool,
  /// Whether a §5.6.4 quoted-string decided the extent of the element
  /// [`at`](Self::at) begins at — which is the OUTER list's element and not
  /// always the one [`scan_element`] read.
  ///
  /// Where it did not, that element ran to the first comma read raw and every
  /// reading of it ends there, so a refusal over it needs none of the above.
  /// Asked at [`at`](Self::at) for exactly that reason: the run holds ONE value
  /// position however it is read — [`opener_at`]'s exclusion argument — and
  /// where the two offsets part it is the outer element's, so a scan from the
  /// body's own would answer `false` over a string the sender opened.
  /// `Basic a=1, Broken;junk, Bearer, x ="open, Digest realm=z` is the value
  /// that says what that costs, and one SP is the whole of the difference from
  /// `x="open`: §11.2's `BWS` lets the SP §11.3's `1*SP` needs stand in front
  /// of the `=` too, so the walk enters a body at the `=`, no value position
  /// stands THERE, and the held verdict came due at
  /// [`BodyCheck::finish`](BodyCheck::finish) with the comma inside `x`'s own
  /// value already crossed.
  ///
  /// Where it did, RFC 9110 §11.2's `token68` alternative is dead — its
  /// alphabet holds no DQUOTE — which is what lets [`BodyCheck`]'s held verdict
  /// on a FIRST element come due here rather than at
  /// [`BodyCheck::finish`](BodyCheck::finish), before this element's own string
  /// has chosen the boundary the next one is read behind.
  strung: bool,
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
/// # `at` is where the element is READ from, `element_at` where a recovery
/// behind it begins
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// The two are one offset everywhere but the FIRST element of a body RFC 9110
/// §11.3's `1*SP` opened. `auth-scheme 1*SP` is no §5.6.1.2 separator, so the
/// element the OUTER `#challenge` list holds began at the scheme and this
/// scan's element is a SUFFIX of it — and [`Recovery`] is about the outer
/// list's element, because a recovery gets past an element of the outer list.
/// [`Challenges::read_challenge`] is the one caller that ever parts them, and
/// its `recover_from` carries when and why.
///
/// So the ELEMENT is read from `at`, which is the body's question and
/// [`BodyCheck`]'s; the RECOVERY is taken from `element_at`, which is
/// §11.6.1's. `element_at <= at`, and only `auth-scheme 1*SP` ever stands
/// between them — a token and a run of SP, neither of which holds a comma, so
/// [`raw_comma_end`] answers alike from either and only
/// [`some_reading_holds`]'s question moves.
///
/// `next` hands over the field line behind the join, `Ok(None)` where the value
/// runs out, or the fault that crossing this one costs more than the caller may
/// pay. It is where a caller does whatever crossing a line costs it — taking
/// the region left behind, in the case of a walk collecting one — and the two
/// are one operation for a reason: a caller that could not take the region has
/// no line to hand back, so this scan cannot read one more byte of a challenge
/// its collector has just refused. The two walks that re-read a body already
/// collected pay nothing to cross and never answer with a fault.
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
/// quoted-string — the only fault this raises of its own — and whatever `next`
/// refuses to cross a join with. Every OTHER fault an element carries is
/// [`auth_param`]'s to report over the [`Element`] this returns, because a
/// boundary a walk has not yet found must not be decided by bytes behind a
/// fault — and a walk cannot be handed a verdict before it has the element the
/// verdict is about.
fn scan_element<'a, N>(
  head: &'a [u8],
  at: usize,
  element_at: usize,
  mut next: N,
) -> Result<Scanned<'a>, AuthError>
where
  N: FnMut() -> Result<Option<&'a [u8]>, AuthError>,
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
  // Until a join is crossed the element the OUTER list holds is all on the line
  // it began on, so a recovery behind it begins at `element_at` and no reading
  // of it holds a comma the raw scan from there would find. Whether a string
  // decided the extent at all is `param_value_at` answered at that same offset:
  // the run holds ONE value position however it is read, and where the two
  // offsets differ it is `element_at`'s, which is what `opener_at`'s exclusion
  // argument says.
  let mut recovery = Recovery {
    at: element_at,
    floor: element_at,
    // No join has been crossed, so what stands in front of the outer list's
    // element is whatever the caller reached it past, and
    // `Recovery::after_comma` says why no reading opens a challenge at it
    // either way.
    after_comma: false,
    strung: param_value_at(head, element_at)
      .is_some_and(|value_at| head.get(value_at) == Some(&b'"')),
  };

  // A quoted-string still open where a field line ends does NOT end the
  // element: RFC 9110 §5.2 joins the lines with a comma and §5.6.4 makes that
  // comma data inside one, so the element runs on and ends wherever the string
  // closes. `scan_quoted_after_join` is this crate's one implementation of that
  // rule, and it feeds the join's comma THROUGH any pending escape before the
  // next line's first byte — so the escape is spent on the comma, and a DQUOTE
  // arriving first on that line closes the string.
  let mut tail = ValueTail::Ends;
  while let Some(escape) = open.take() {
    let Some(line) = next()? else {
      // Nothing left to close the string on, so the combined value ends inside
      // it. Whatever closed on an earlier line does not change that: what is
      // still open is what the element ends in, and `auth_param` reports it
      // over these same bytes.
      tail = ValueTail::Ends;
      // And this element is the last of its challenge, whose extent is
      // therefore complete: a string RFC 9110 §5.6.4 never closes holds every
      // byte behind its DQUOTE, so there is nothing behind this element for a
      // recovery to look for and no comma left to certify.
      recovery = Recovery {
        at: cursor,
        floor: cursor,
        // The value ran out here, so no element of any list begins at this
        // offset and neither of §11.6.1's two readings has an opener to name.
        after_comma: false,
        strung: recovery.strung,
      };
      break;
    };
    cursor = line.len();
    match rejoin(line, escape) {
      // Past the string, the rest of that line is the element's like any
      // other, up to the comma that ends it — and only the list's own `OWS`
      // may stand in between, which is what `trails` answers. A line that
      // closed the value ENDS the element, so this is read once and there is
      // no verdict from an earlier line to carry into it.
      Rejoin::Ends {
        close,
        at: end,
        trails,
      } => {
        tail = if trails {
          ValueTail::Trails
        } else {
          ValueTail::Continues
        };
        cursor = end;
        // The element's own bytes are no longer all on a line this walk holds,
        // so the reading that ended it at §5.2's join comma begins at the head
        // of THIS line — and the reading that carried the value here holds
        // every comma in front of its close.
        recovery = Recovery {
          at: 0,
          floor: close,
          // RFC 9110 §5.2's join put a comma in front of this line's first
          // byte, so the reading that left this element's value SHUT ended the
          // element on it — and what opens here is an element of the outer
          // `#challenge` list, which §11.6.1 lets be a whole challenge.
          after_comma: true,
          strung: true,
        };
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
    recovery,
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
    while let Some((after_comma, element)) = walk.step() {
      check.settle()?;
      // Honest rather than load-bearing here, and the difference is worth
      // saying: this walk is handed regions that begin at the body's own first
      // byte, so an empty element in front of a run is IN `BodyLines::cut`'s
      // answer and `finish` sees it either way. The collecting walk is where
      // the flag decides something — there a region of nothing but `OWS` and
      // commas spends no entry, so those elements are gone by the time `finish`
      // reads the body. A mutation that makes this a constant therefore
      // survives, and what would kill it is a caller handed a body cut past its
      // own beginning.
      check.element(element?, !after_comma)?;
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
  /// Whether the FIRST element is wholly RFC 9110 §11.2's `token68`.
  ///
  /// ```text
  /// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  /// token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  /// auth-param = token BWS "=" BWS ( token / quoted-string )
  /// ```
  ///
  /// Written for that element and no other, and it is the only element this
  /// could be true of: a `token68` is ONE run, and a second element needs the
  /// comma §5.6.1.2 separates with, which no byte of that run or of the `=`
  /// pad behind it is. So while the body is still one element long this is the
  /// BODY's answer as well, which is the moment
  /// [`token68_taken`](Self::token68_taken) is asked and the whole of why it
  /// may be asked at all.
  token68: bool,
}

impl<'a> BodyCheck<'a> {
  /// A check over no elements: where every credential body starts.
  const fn new() -> Self {
    Self {
      seen: SeenNames::new(),
      held: None,
      opened: false,
      token68: false,
    }
  }

  /// Takes one element of the body, in wire order.
  ///
  /// `opens_the_body` says this element begins where the body does, with no RFC
  /// 9110 §5.6.1.2 comma in front of it —
  /// `#element => [ element ] *( OWS "," OWS [ element ] )` puts none in front
  /// of the first element and one in front of every other. It is what
  /// [`token68`](Self::token68) needs beyond the element's own bytes: a
  /// `token68` is the WHOLE body, so an empty element or §5.2's join standing
  /// in front of the run leaves bytes the run does not reach and the body is
  /// the other alternative whatever the run looks like. `Basic<SP>,a=` is that
  /// value — its body is `,a=`, which no `token68` derives.
  ///
  /// # Errors
  ///
  /// Whatever [`auth_param`] makes of the element, and
  /// [`AuthError::DuplicateParameter`] or [`AuthError::TooManyParameters`]
  /// from the record of names — except for the FIRST element, whose verdict is
  /// held for the reason this type carries and is reported by
  /// [`settle`](Self::settle) or [`finish`](Self::finish) instead.
  fn element(&mut self, element: Element<'a>, opens_the_body: bool) -> Result<(), AuthError> {
    let verdict = match auth_param(element.bytes, element.tail) {
      Ok(param) => self.seen.record(param.name()),
      Err(fault) => Err(fault),
    };
    if self.opened {
      return verdict;
    }
    self.opened = true;
    self.held = verdict.err();
    // The other of RFC 9110 §11.3's two alternatives, asked of the same bytes.
    // [`token68`] answers for ONE list element with §5.6.1.2's own `OWS`
    // already off it, which is exactly what an [`Element`] carries — so this is
    // that question asked where the element is, and not a second spelling of
    // it.
    self.token68 = opens_the_body && token68(element.bytes, 0).is_some();
    Ok(())
  }

  /// Whether the body is already RFC 9110 §11.3's `token68`, so a walk that has
  /// found another element has found the end of this challenge rather than more
  /// of it.
  ///
  /// ```text
  /// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  /// auth-param = token BWS "=" BWS ( token / quoted-string )
  /// ```
  ///
  /// The first element being wholly a `token68` settles §11.3's choice, because
  /// the alternatives never derive one element between them: a run that reaches
  /// the end of its element leaves nothing but more `=` and §5.6.3's `OWS`
  /// behind its first `=`, and `auth-param` needs a `token` or a
  /// `quoted-string` there — `the_two_branches_are_never_both_derivable` is
  /// that argument executed over the productions. ABNF's `/` is unordered and
  /// nothing here orders it; what is being said is that ONE alternative derives
  /// these bytes and the other does not derive them at all, which is not a
  /// choice a recipient has.
  ///
  /// So the challenge is complete at that element's delimiter, and the element
  /// behind the delimiter belongs to the outer `#challenge` list whatever it
  /// turns out to be. Its bytes decide nothing here, which is why the one
  /// caller asks this BEFORE reading them.
  const fn token68_taken(&self) -> bool {
    self.token68
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
    // Three conditions and each rules out a different body. `token68` is the
    // FIRST element's answer and is what makes this one the body's: RFC 9110
    // §5.6.1.2's "Empty elements do not contribute to the count of elements
    // present." is why [`BodyLines`] spends no region on one that is all `OWS`
    // and commas, so a body opening with the empty elements that sentence
    // admits arrives here as the bytes BEHIND them — and a run reading as the
    // whole of what arrived never began the body. `Basic<SP>,` on one field
    // line and `a=` opening the next are the two that showed it: §5.2 joins
    // them into a body of `,,a=`, which no `token68` derives. One region,
    // because a body §5.2's
    // join spread over two is longer than the run that ends on the first. And
    // the `OWS` skip, because a run that ends its own ELEMENT with more of the
    // body behind that element's comma has left bytes
    // `auth-scheme [ 1*SP ( token68 / #auth-param ) ]` does not derive, which
    // is what `Basic dGVzdA==, x=1` read as one credential is.
    //
    // The region count is the one of the three no input reaches today, and the
    // mutation that drops it survives for that reason rather than because it
    // says nothing. `token68` and `auth_param` never derive one element between
    // them, so a first element this run reaches the end of always leaves a
    // verdict held — and `settle` reports a held verdict the moment a SECOND
    // element appears, which is what a second region needs. It is written here
    // all the same: this is where a body's extent is turned into a reading, and
    // a rule that holds only because of what a caller does two functions away
    // is a rule the next caller does not inherit.
    // `a_run_that_ends_its_element_is_no_body_when_a_region_stands_behind_it`
    // asks `Credential::read` for that body directly.
    let token = match body.len {
      1 if self.token68 => match token68(only, 0) {
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
      // Which side of §5.6.1.2's comma this element stands on is
      // `BodyCheck`'s question and not one a caller reading a list that has
      // already derived has anything to do with.
      (_, Ok(element)) => element,
      // `ParamWalk::element` recorded it. There is nothing to add.
      (_, Err(_)) => return None,
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

/// Asserts a consistency this branch argued for: **a challenge that is
/// yielded may not simultaneously be treated as possibly inside an earlier
/// list.**
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// # The argument
///
/// RFC 9110 §11.6.1 leaves a recipient two readings of an element behind a
/// comma: one more `auth-param` of the challenge already open, or the
/// `auth-scheme` of the next challenge. Handing the element back as a challenge
/// is taking the second. Believing, at the same moment, that an `auth-param`
/// may begin at that element is holding the first. A walk that does both has
/// not chosen, and every answer it goes on to give rests on whichever half the
/// next line of code happens to read.
///
/// `inside_a_list` is what the walk holds — [`Challenges::inside_a_list`], the
/// list a challenge left open together with the list an [`Epoch`] does — and
/// `at` is the first byte of the element the challenge was read at.
/// [`opens_a_challenge`] is the other half, and it is the same question
/// [`refused_element_end`] asks of the same bytes rather than a second spelling
/// of it.
///
/// # Why it cannot fire, twice over
///
/// **From the walk.** A challenge is read at an element the walk reached one of
/// three ways, and a list can be open at only the first two.
/// [`Challenges::seek`] resumes on an element [`opens_a_challenge`] answered
/// `true` for, and the body loop of [`Challenges::read_challenge`] breaks on
/// one for the same reason — that is what makes the element the OUTER list's.
/// The third is the break [`BodyCheck::token68_taken`] takes, which leaves the
/// cursor on an element nothing has asked, and a `token68` body closes the list
/// in front of it, so `inside_a_list` is false unless an [`Epoch`] holds one.
///
/// **From the productions**, which is the half that holds however the walk is
/// rearranged. Suppose both: some `auth-param` begins at the element, so a
/// `token`, then `BWS`, then `=` stand at its head; and the element completes
/// as a challenge, so `auth-scheme 1*SP` stands there too and the body begins
/// at the first byte behind the SP run. `BWS` is §5.6.3's `OWS`, so between the
/// token and the `=` stand only SP and HTAB — and a HTAB there is one
/// [`Challenges::read_challenge`] refuses before any body is read, so the run
/// is SP alone and the body begins AT the `=`. A body of `#auth-param` needs a
/// `token` at its first element and `=` is no `tchar`; §11.2's `token68` needs
/// one of its own alphabet and `=` is only its trailing pad. So the body
/// derives nothing, the challenge is refused rather than completed, and the two
/// suppositions cannot both hold. `an_element_that_completes_a_challenge_is_no
/// _parameter_of_the_list_in_front_of_it` runs that argument over the
/// productions.
///
/// Compiled away where `debug_assertions` are off, exactly as
/// [`walks_to_its_end`] is, so no release build carries the check or the scan
/// it makes.
#[cfg(debug_assertions)]
fn a_yielded_challenge_is_no_parameter(value: &[u8], at: usize, inside_a_list: bool) {
  debug_assert!(
    !inside_a_list || opens_a_challenge(value, at),
    "a challenge was yielded at an element the walk still reads as an auth-param"
  );
}

/// The same check where `debug_assertions` are off, which is nothing at all.
#[cfg(not(debug_assertions))]
#[inline]
const fn a_yielded_challenge_is_no_parameter(_value: &[u8], _at: usize, _inside_a_list: bool) {}

/// What [`Challenges::sustain_the_epoch`] hands [`auth_param`] rests on an
/// argument rather than on a branch, and this is that argument checked.
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// The element it puts to RFC 9110 §11.2 is one whose value cannot still be
/// OPEN where the element ends, so [`ValueTail`] has nothing left to decide and
/// `Ends` is the whole of it. Two facts hold that, and they are about different
/// epochs: where a `#auth-param` list is open, a string still open at the comma
/// is one [`some_reading_holds`] reports and [`refused_element_end`] answers
/// `None` for, so the walk stops instead of absorbing anything; and where no
/// list is open the epoch is not derivable at all, because a receiver bound is
/// only ever met inside the body §11.3's `1*SP` opened.
///
/// So this asserts the half of it that decides an ANSWER: while the epoch is
/// still derivable, the tail is a choice with one outcome. It is checked rather
/// than argued because an argument that has stopped holding leaves a doc that
/// still reads correctly.
///
/// Compiled away where `debug_assertions` are off, exactly as
/// [`a_yielded_challenge_is_no_parameter`] is.
#[cfg(debug_assertions)]
fn a_derivable_span_admits_one_tail(element: &[u8], derivable: bool) {
  debug_assert!(
    !derivable
      || auth_param(element, ValueTail::Ends).is_ok()
        == auth_param(element, ValueTail::Continues).is_ok(),
    "a derivable span absorbed an element whose value is still open where it ends"
  );
}

/// The same check where `debug_assertions` are off, which is nothing at all.
#[cfg(not(debug_assertions))]
#[inline]
const fn a_derivable_span_admits_one_tail(_element: &[u8], _derivable: bool) {}

/// [`Origin`]'s enumeration, checked at every refusal that makes one.
///
/// ```text
/// #element => [ element ] *( OWS "," OWS [ element ] )
/// ```
///
/// # What each row claims, and which half a walk can check for itself
///
/// [`Origin::Unread`] says the cursor is on the first byte of an element on
/// this line — so RFC 9110 §5.6.1.2's `OWS` is off the front of it and the
/// comma that separated it from the element behind is already crossed. Both
/// are checkable here, and both are what
/// [`Challenges::sustain_the_epoch`] slices from when no element is carried:
/// a cursor left on whitespace or on a comma would put the list's own bytes
/// inside the element it puts to §11.2. The end of the value is the one other
/// offset that row admits, where a walk that read every line has nothing left
/// to stand on.
///
/// [`Origin::Body`] says the cursor is on the body position RFC 9110 §11.3's
/// `1*SP` opened, which is checkable the same way: an SP stands in front of it,
/// and §5.6.2's `tchar` excludes SP so the scheme token really did end there.
/// The whitespace this row stands ON is why it is not [`Origin::Unread`] — a
/// body's first element has no comma in front of it for §5.6.1.2 to hang `OWS`
/// on.
///
/// [`Origin::Scanned`] and [`Origin::Crossed`] are checked by the entrances
/// themselves and not here: the first carries the element the walk cut, which
/// is a fact no offset can confirm, and the second stands on the far side of
/// §5.2's join wherever that join fell. What a walk CAN say about them is that
/// they are the only two rows a cursor a join moved may take — which is what
/// `where_every_refusal_leaves_the_cursor` drives every entrance to show.
///
/// Compiled away where `debug_assertions` are off, exactly as
/// [`a_derivable_span_admits_one_tail`] is.
#[cfg(debug_assertions)]
fn a_refusal_leaves_the_cursor_where_its_span_begins(line: &[u8], at: usize, origin: Origin<'_>) {
  match origin {
    Origin::Unread => debug_assert!(
      at >= line.len() || (skip_ows(line, at) == at && line.get(at) != Some(&b',')),
      "a refusal left the cursor on the list's own bytes and called it an element's first"
    ),
    Origin::Body => debug_assert!(
      at > 0 && line.get(at.saturating_sub(1)) == Some(&b' '),
      "a refusal named a body position with no `1*SP` in front of it"
    ),
    Origin::Scanned { .. } | Origin::Crossed => {}
  }
}

/// The same check where `debug_assertions` are off, which is nothing at all.
#[cfg(not(debug_assertions))]
#[inline]
const fn a_refusal_leaves_the_cursor_where_its_span_begins(
  _line: &[u8],
  _at: usize,
  _origin: Origin<'_>,
) {
}

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

  /// The next element of the list, or `None` at the end of it — with whether
  /// RFC 9110 §5.6.1.2's comma stood in front of it.
  ///
  /// `#element => [ element ] *( OWS "," OWS [ element ] )` puts no comma in
  /// front of the FIRST element, so the answer `false` names the element the
  /// body opens with and `true` names one an empty element or §5.2's join
  /// stands in front of. [`BodyCheck::element`] is the one caller that reads
  /// it, and its `opens_the_body` carries why.
  fn step(&mut self) -> Option<(bool, Result<Element<'a>, AuthError>)> {
    let mut after_comma = false;
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
          // RFC 9110 §5.2 puts a comma at the join, so the element behind it
          // is one the expansion above has a comma in front of.
          after_comma = true;
        }
        // RFC 9110 §5.6.1.2: "A recipient MUST parse and ignore a reasonable
        // number of empty list elements".
        Some(&b',') => {
          self.at = self.at.saturating_add(1);
          after_comma = true;
        }
        Some(_) => return Some((after_comma, self.element())),
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
      scan_element(head, start, start, || {
        let next = walk.line.saturating_add(1);
        if next >= walk.body.len {
          return Ok(None);
        }
        walk.line = next;
        Ok(Some(walk.body.line(next)))
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
    /// Where on that line the string CLOSED — one past its DQUOTE.
    ///
    /// Not where the element ends, and the two differ exactly when `trails` is
    /// set. It is the offset the reading that OPENED this value stands outside
    /// its string from, which is what a recovery behind a refused element needs
    /// in order to know which commas on this line that reading still holds.
    close: usize,
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
      Rejoin::Ends {
        close: end,
        at,
        trails,
      }
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
/// Granting those bytes quoted-string semantics is how a malformed challenge
/// hides a well-formed one:
/// `Basic realm=x, Broken a="q` and `r"junk", Digest realm=z` are two field
/// lines that §5.2 joins into one value, the value of `a` closes at `r"`, and
/// a DQUOTE in `junk"` read as an opener swallows the comma in
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

/// Whether RFC 9110 §11.6.1's OTHER reading of `element` — a whole `challenge`
/// rather than one more `auth-param` — leaves a `#auth-param` list OPEN behind
/// it.
///
/// ```text
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
///
/// `element` is one §5.6.1.2 element with the list's own `OWS` off both ends,
/// which is what an [`Element`] carries. The question is §11.3's and is asked
/// of it whole: an `auth-scheme`, the `1*SP` that is the body's only entrance,
/// and a body the `token68` alternative does not take. `Complete::opens_a_list`
/// asks the same question of a challenge this walk READ; this asks it of one it
/// did not.
///
/// # A list opens at the `1*SP`, whatever the body derives
///
/// `[ 1*SP ( token68 / #auth-param ) ]` puts the list's first element at the
/// first byte behind the SP run, so the list is open from there — and where
/// nothing derives AT that element the readings are free from it, inside the
/// list it stands in. That is the same sentence [`Epoch`] carries about a fault
/// met inside a body, one element up: `Basic<SP><HTAB>a, a=", Digest realm=z`
/// is a body whose first element derives nothing and whose list is open all the
/// same.
///
/// So the `token68` alternative is the only thing that closes it. §11.2's
/// alphabet holds no DQUOTE and no `=` but the trailing pad, and [`token68`]
/// answers `Some` only where the run IS the whole body — which is what makes
/// `Bearer abc` a challenge that opens nothing.
///
/// # Why the two readings can BOTH be about the same element
///
/// [`opener_at`]'s exclusion is about where a §5.6.4 quoted-string may OPEN,
/// and it holds: at most one of the two readings puts a value position in the
/// run. This is a different question. `y<SP>=<SP>1` is one `auth-param` under
/// the reading the walk takes, and under the other it is an `auth-scheme` whose
/// body opens AT the `=` and derives nothing — a non-derivation, but one that
/// has already opened a list, which is exactly the state freedom starts in.
/// `Broken<HTAB>junk, y<SP>=<SP>1, Bearer, x="open, Digest realm=z` is the
/// value that needs it: `Challenges::seek` crosses `y<SP>=<SP>1` because
/// [`opens_a_challenge`] answers `false` for it, and the list that reading
/// opened is the one `x`'s DQUOTE stands at a value position of.
fn opens_a_parameter_list(element: &[u8]) -> bool {
  let Some(scheme_end) = token_end(element, 0) else {
    return false;
  };
  // `1*SP` is the body's only entrance, so a scheme with anything else behind
  // it — §5.6.3's HTAB included — takes no body and opens no list.
  if element.get(scheme_end) != Some(&b' ') {
    return false;
  }
  let body = skip_sp(element, scheme_end);
  // A body that is only the list's own `OWS` is no body at all: the optional
  // group needs one of its two alternatives, and neither derives whitespace.
  !ends_element(element, body) && token68(element, body).is_none()
}

/// Where a reading of the run at `at` may OPEN the RFC 9110 §5.6.4
/// quoted-string a production admits there, or `None` where no production
/// admits one anywhere in the run.
///
/// `at` is an offset every reading in hand stands OUTSIDE a string at, and the
/// run ends at the first comma read raw. [`some_reading_holds`] is the one
/// caller and asks this at exactly that offset.
///
/// # RFC 9110 §11.6.1 gives the element two readings, and they open in
/// different places
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
///
/// RFC 9110 §11.6.1 states the ambiguity: the value "might contain more than
/// one challenge, and each challenge can contain a comma-separated list of
/// authentication parameters". So an element of the OUTER list is either one
/// more `auth-param` of the challenge already open, whose value position is
/// [`param_value_at`] answered AT `at`; or the `auth-scheme` of a whole new
/// challenge, whose first `auth-param` begins behind `auth-scheme 1*SP` and
/// whose value position is [`param_value_at`] answered THERE. `parameters`
/// admits the first and `after_comma` the second, and each is a fact about
/// where the cursor stands rather than about these bytes:
///
/// - `parameters` is false where the refused challenge was refused at its own
///   `auth-scheme` or at the `1*SP` behind it, with no earlier challenge having
///   opened a list. Nothing in what is left of it is an `auth-param`, so no
///   DQUOTE in it stands at a value position.
///   `Basic, type=1, x="a, Digest realm=z` is that value.
/// - `after_comma` is false where no comma stands in front of `at` — the first
///   element of a challenge's own `#auth-param` list, which
///   `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` puts no
///   second challenge at. `Basic Digest realm="c, Newauth realm=z` is that
///   value: `Digest realm="c` is inside `Basic`'s body, the DQUOTE behind it is
///   at no value position of any reading, and `Newauth realm=z` stands behind a
///   comma every reading of these bytes is outside a string at.
///
/// # The element does not begin at the comma, and both readings are of where it
/// does
///
/// RFC 9110 §5.6.1.2 hangs `OWS` on BOTH sides of its comma —
/// `#element => [ element ] *( OWS "," OWS [ element ] )` — so where one stands
/// in front of `at`, what `at` names is the far side of that comma and the
/// element begins behind whatever §5.6.3 whitespace the sender wrote there.
/// Both readings are of the element, so both are read from THAT offset. A check
/// asked at the comma's own far side instead finds neither shape: a SP is no
/// `tchar`, so [`token_end`] answers `None` and the run looks like one holding
/// no opener at all — which is how `Basic a="x` and
/// `<SP>realm="evil, Digest realm=z` crossed a comma standing inside `realm`'s
/// own value. The `<SP>` is the sender's one space, written visibly here
/// because that is the whole of the input.
///
/// Only [`some_reading_holds`]'s question moves. [`Recovery::at`] keeps the
/// unskipped offset, because [`Recovery::floor`] answers about the commas on
/// this LINE — where the value the join carried here closes — and an origin
/// moved off the line's head would move which of them that value still holds.
///
/// # And never both at once, which is what keeps this ONE position
///
/// The two shapes exclude each other, and the argument is about the bytes at
/// the element's own start: it is one `token` the two readings share, so they
/// have to be read from the same offset for there to be anything to share.
/// Behind that `token`, [`param_value_at`] needs RFC 9110 §5.6.3's `BWS` and
/// then `=`, and the challenge needs `1*SP` and then the `token` an
/// `auth-param` opens with. Take the SPs those two share: what follows is
/// either a HTAB, which is `BWS` and is no `tchar`, so no `token` begins there
/// and the challenge shape fails; or it is the byte both must now agree on, and
/// §5.6.2's `tchar` holds no `=`. So at most one of the two is a shape at all,
/// whichever bytes the sender wrote.
///
/// A SECOND opener of either kind needs a second element, a second element
/// needs the comma §5.6.1.2 separates with, and the run ends at the first one.
/// So the run holds one opener or none however it is read, and the choice at it
/// — open the string, or leave it shut — is the only choice there is.
///
/// That is what lets [`some_reading_holds`] answer about EVERY reading with one
/// scan. The [`crate::grammar`] walk asks the same question of RFC 9110
/// §5.6.6's `parameters`, where a member's own `;` puts many openers in one run
/// and a subset construction over their states is what answers; an `auth-param`
/// is one whole element with nothing repeating inside it, so the construction
/// collapses to a scan from the one position this names.
fn opener_at(value: &[u8], at: usize, parameters: bool, after_comma: bool) -> Option<usize> {
  // Where the element ACTUALLY begins. RFC 9110 §5.6.1.2 puts `OWS` behind the
  // comma `after_comma` reports, and the two readings below are both of the
  // element that whitespace stands in front of. Where no comma stands in front
  // of `at`, `Challenges::open_element` has already left the cursor on an
  // element's first byte and there is nothing to skip.
  let start = if after_comma { skip_ows(value, at) } else { at };
  // The element read as one more `auth-param` of the list already open.
  if parameters
    && let Some(quote) =
      param_value_at(value, start).filter(|&value_at| value.get(value_at) == Some(&b'"'))
  {
    return Some(quote);
  }
  // And read as a whole `challenge` of the outer list, which RFC 9110 §11.6.1
  // admits only where a comma stands in front of it.
  if !after_comma {
    return None;
  }
  let scheme_end = token_end(value, start)?;
  if value.get(scheme_end) != Some(&b' ') {
    return None;
  }
  let body = skip_sp(value, scheme_end);
  param_value_at(value, body).filter(|&value_at| value.get(value_at) == Some(&b'"'))
}

/// Whether the run a reading of the bytes at `at` may open with the RFC 9110
/// §5.6.4 DQUOTE standing in it still HOLDS `end`, so that a reading of these
/// bytes has the comma there as that run's data rather than as §5.6.1.2's
/// separator.
///
/// `at` is an offset every reading of the value stands OUTSIDE a string at, and
/// `end` is [`raw_comma_end`]'s answer from it — the earliest comma, read raw.
/// [`opener_at`] names the one position a reading may open at, `parameters` and
/// `after_comma` are its two admissions, and its doc carries what each rules
/// out and why there is never more than one position to scan from.
///
/// # The reading that leaves it shut ends the element at `end`
///
/// And no reading ends it earlier: an open string only ever HIDES a comma from
/// a scan, never reveals one. So `end` is where every reading ends the element
/// exactly when this answers `false`, and there is no earlier boundary for a
/// certified `end` to be hiding.
///
/// # The three states the scan can be in, and the two that hold the comma
///
/// The scan is taken over `value` cut at `end`, so what it reports is the state
/// the string is in AT the comma and not what becomes of it later:
///
/// - Still open there — [`QuotedScan::Open`], escape pending or not — and the
///   comma is inside it. The string need not ever close for that: RFC 9110
///   §5.6.4 makes every byte behind an opening DQUOTE that value's data, and a
///   sender whose line was truncated wrote them as data all the same.
/// - Closed in front of it, and that reading stands outside the string at the
///   comma exactly as the shut reading does. `Basic a=1, a=2, x="p", Digest realm=z`
///   is that shape, and refusing to report `Digest` would hide a challenge for
///   nothing.
/// - [`QuotedScan::Invalid`], and the reading that opened the string holds the
///   comma too. A byte §5.6.4 forbids means the string reaches NO close — so
///   that reading runs to the end of the value and every comma behind the
///   DQUOTE is among the bytes the sender wrote as its data. It is not a
///   `quoted-string`, and nothing here says it is: what the reading holds is a
///   run the sender opened with a DQUOTE and never shut, which is exactly what
///   [`crate::grammar::Readings::absorb`] calls SEALED and has ruled for RFC
///   9110 §5.6.6's `parameters` since `gzip;;x="a%x01, chunked, b", br` cut raw
///   handed a caller a `chunked` that stood among those bytes.
///
///   This module used to answer the other way, and the difference is the whole
///   of what [`Readings::of`] is here for: three states read as a boolean lost
///   the third, `refused_element_end` certified the raw comma, and
///   `Basic x="%x01, Digest realm=evil` handed a caller a `Digest` built out of
///   bytes behind an admitted opening DQUOTE that never closed. A forbidden
///   byte standing BEHIND the comma is still not in front of it and decides
///   nothing here: what the sender wrote between the DQUOTE and the comma is
///   `qdtext` either way.
///
/// # Why the answer is taken from `grammar` and not spelled again
///
/// Because it is one question and this crate had two answers to it. The set a
/// scan leaves is [`crate::grammar::Readings`], its [`covers`](Readings::covers)
/// asks the very question this function is named for, and [`Readings::of`] is
/// that set for a caller with ONE admitted opener — which [`opener_at`]'s doc
/// is what makes this one. So the three states become readings in one place
/// for both walks, and no later check can find them disagreeing again.
fn some_reading_holds(
  value: &[u8],
  at: usize,
  end: usize,
  parameters: bool,
  after_comma: bool,
) -> bool {
  let Some(quote) = opener_at(value, at, parameters, after_comma) else {
    return false;
  };
  Readings::of(scan_quoted(
    value.get(..end).unwrap_or_default(),
    quote.saturating_add(1),
    false,
  ))
  .covers()
}

/// Where the RFC 9110 §5.6.1.2 element at `at` ends when the challenge holding
/// it has ALREADY been refused, or `None` where no reading of these bytes
/// settles that.
///
/// `at` is the last offset at which every reading of the value still stands
/// outside a §5.6.4 quoted-string. [`Challenges::seek`] is the one caller and
/// its doc names the positions that hold: the comma an element ended on, the
/// first byte of an element none of whose bytes have been derived, and the end
/// of a field line.
///
/// # A refused challenge decides no boundary, and a manufactured one is the cost
///
/// Behind the first fault nothing derives, so the `quoted-string` alternative
/// §11.2 offers at a value position is no longer forced on the bytes there — it
/// is a reading, beside the reading that leaves the DQUOTE shut.
/// [`some_reading_holds`] is where the two are compared, and this reports the
/// comma only where they agree.
///
/// Where they do not, the answer is `None` and
/// [`AuthError::ChallengeBoundaryUnknown`] is what the walk tells the caller.
/// Cutting at the comma there is how
/// `Basic p1=1, ..., p17=17, x="c, Digest realm=evil, junk"` — one field line,
/// no repeated name, nothing malformed, and a value RFC 9110 §11.2 bounds
/// nowhere — handed a caller a `Digest` challenge with a `realm` of `evil` that
/// no origin server sent. The trigger was [`MAX_PARAMS_PER_CREDENTIAL`], which
/// is this reader's own refusal and not the grammar's, so the input that
/// reaches it conforms.
///
/// # A join carries a second reading here, and `after_comma` is it
///
/// `after_comma` says RFC 9110 §5.6.1.2's comma stands in front of `at`, which
/// is the whole of what §11.6.1 needs to read a `challenge` there rather than
/// one more `auth-param`. It is set where §5.2's join carried a refused element
/// onto the line the walk now stands on: the reading that shut that element's
/// value AT the join opens an element of the outer list at this line's head,
/// and a challenge is what that element may be. `Basic a="x` and
/// `Digest realm="evil, Newauth realm=z, junk", Safe realm=s` are the two field
/// lines that showed it — one reading takes the DQUOTE behind `realm=` as the
/// CLOSE of `a`'s value, and the other takes it as the OPEN of a `realm` whose
/// data runs `evil, Newauth realm=z, junk`. The comma behind `evil` is that
/// realm's own byte in the second reading, and crossing it handed a caller a
/// `Newauth` challenge out of the middle of a value the sender wrote whole.
/// [`opener_at`] is where the reading is admitted, [`Recovery::after_comma`]
/// where it is carried, and [`Recovery::floor`] answers for the OTHER reading
/// of the same join — the one that carried the value onto this line.
fn refused_element_end(
  value: &[u8],
  at: usize,
  parameters: bool,
  after_comma: bool,
  forced: bool,
  floor: usize,
) -> Option<usize> {
  // Asked FIRST, because a comma in front of the carried value's close is not
  // a comma this element ends at under any reading and `some_reading_holds` is
  // a question about the readings admitted AT THE CURSOR — which no longer
  // include the one that carried that value here. The span still derives, so
  // `( token / quoted-string )` is not a choice at its value position: the
  // element ends at the close, and `floor` is that close, an offset ON this
  // line because [`scan_element`] stops crossing joins the moment a string
  // closes. A byte behind the close would have made this `ValueTail::Trails`,
  // which [`auth_param`] refuses — so a span that reaches here with `forced`
  // true has only §5.6.1.2's own `OWS` between the close and the comma.
  if forced && floor > at {
    return Some(raw_comma_end(value, floor));
  }
  let end = raw_comma_end(value, at);
  if !some_reading_holds(value, at, end, parameters, after_comma) {
    return Some(end);
  }
  if !forced {
    return None;
  }
  // The span still DERIVES, so `( token / quoted-string )` is not a choice
  // here: §5.6.2's `tchar` excludes DQUOTE, so a reading that leaves this one
  // shut derives no value at all, and an element that derives nothing is no
  // element of a `#challenge` any reading of the value has. The string is the
  // only reading, `end` is inside it in ALL of them, and the element ends where
  // the string closes.
  let quote = opener_at(value, at, parameters, after_comma)?;
  match scan_quoted(value, quote.saturating_add(1), false) {
    // Behind the close, only §5.6.1.2's own `OWS` may stand: `( token /
    // quoted-string )` is one alternative taken WHOLE, so a byte behind that
    // DQUOTE leaves the element deriving nothing — and an element that derives
    // nothing is where the freedom this span had claimed to be free of BEGINS.
    // `ends_element` is that test, and it is what tells `a="x,p,q"` — whose
    // string closes inside its own element — from `y="q, Bearer, x="`, whose
    // does not: the close there is another element's opener, `open` stands
    // behind it, and nothing derives.
    QuotedScan::Closed(close) if ends_element(value, close) => Some(raw_comma_end(value, close)),
    QuotedScan::Closed(_) => None,
    // It closes nowhere on this line, so every byte behind the DQUOTE is that
    // value's data and there is no boundary to find. The caller is told.
    QuotedScan::Open { .. } | QuotedScan::Invalid => None,
  }
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
/// An unadmitted DQUOTE pairs with no later one, so a DQUOTE that a
/// pair-anywhere reading would have used to CLOSE a refused run leaves the
/// next admitted position free to OPEN instead. `Basic ",a=", Digest realm=z`
/// reaches `Digest` under that reading, its first DQUOTE swallowing its
/// second, and hides it under this one, where the value of `a` is the
/// quoted-string §11.2 says it is with nothing to close it. That is not this
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
/// One `Result` per challenge, and **a fault ends the walk only where the
/// refused challenge's own END is not derivable**. Every fault refuses the
/// challenge it was met in, and the walk then looks for where that challenge
/// stops, because §11.4 has a user agent choose among challenges by "selecting
/// the challenge with what it considers to be the most secure auth-scheme that
/// it understands" — and one unreadable challenge must not hide the readable
/// one behind it. That is a deliberate divergence from
/// [`crate::grammar::parameterised_list`], which poisons on any `Err`: a
/// parameter list is not a list a caller searches.
///
/// **What it may not do instead is invent one.** Behind the fault nothing
/// derives, so §11.2's `( token / quoted-string )` is no longer forced on the
/// bytes at a value position: an element standing there has a reading that
/// opens the string and a reading that leaves it shut, and where the two
/// disagree about the next comma the bytes behind it are that value's data
/// under one reading and a whole challenge under the other. The walk crosses
/// only the commas EVERY reading ends an element at — `refused_element_end` —
/// and where none can be vouched for it reports
/// [`AuthError::ChallengeBoundaryUnknown`] and stops, which is the last item it
/// yields. `Basic p1=1, ..., p17=17, x="c, Digest realm=evil, junk"` is why:
/// one field line, no repeated name, nothing malformed, and a `Digest` with a
/// `realm` of `evil` that no origin server sent, chosen by whoever wrote that
/// parameter's value.
///
/// [`AuthError::InvalidQuotedString`] is the one that looks like an exception
/// and is not — a refusal like every other, recovered from like every other. A
/// byte that fault fires on is one RFC 9110 §5.5 admits nowhere in a field
/// value, so no `quoted-string` DERIVES over it; what the sender wrote is
/// unchanged by that. The DQUOTE stands where §11.2 admits a value, and a run
/// opened there that reaches no close holds every comma behind it, so
/// `some_reading_holds` reports it and no boundary is certified.
/// `crate::grammar::Readings::absorb` calls that reading SEALED and is where
/// the ruling lives, for this walk and for §5.6.6's alike. A forbidden byte
/// standing BEHIND the candidate comma still decides nothing: the bytes between
/// the DQUOTE and the comma are `qdtext` either way.
///
/// A failed challenge is reported ONCE. The walk does not re-read what is left
/// of it as challenges of its own, so in
/// `Basic a=1, =x, type=b, Newauth c=1` the `type=b` is part of the failure
/// already reported rather than a second one. That seek reports no fault of its
/// own except the boundary it could not derive.
///
/// # How many faults one malformed value yields
///
/// Once per refused challenge, and a value can hold more refused challenges
/// than a sender wrote. Getting past a refusal crosses only commas no reading
/// of the bytes in front of them holds inside a §5.6.4 quoted-string, and an
/// element whose grammar admits no string at all offers no reading to hold one
/// — so such a comma ends the refused run here, and what stands behind it is
/// read as a challenge of its own and refused in its turn.
/// `Basic<HTAB>Newauth realm="a, b"` is one such value: the scheme is refused,
/// and `Newauth realm="a, b"` is an element no `auth-param` derives — it has no
/// `=` behind its leading token — so nothing opens a string over the comma
/// inside `"a, b"`, and what stands behind that comma is refused in its turn.
/// Two [`AuthError::MalformedScheme`]s here, where a quote-anywhere recovery
/// reports one.
///
/// A run cut this way shows a caller more elements than the sender wrote, each
/// answered on its own, and never fewer — the cut is at a comma every reading
/// agrees on. What a caller can still be shown that the sender did not write is
/// two cases and two only, and they are not the same kind of thing.
/// [`MAX_CHALLENGE_LINES`] is this READER's refusal rather than a fault of the
/// sender's, so it can refuse a value some derivation still admits; that
/// constant carries the trade. [`AuthError::InvalidQuotedString`] can do the
/// same arithmetic on a value NO derivation admits — the field value carries a
/// byte §5.5 forbids anywhere in one — so what a caller is shown there is built
/// out of bytes that were never a value to begin with. But a caller that COUNTS
/// the `Err`s of a malformed value rather than reading them is counting
/// something this reader decides and not something the sender wrote, and will
/// see a different number than a quote-aware recovery gives. Read the faults;
/// do not total them.
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
/// or [`AuthError::InvalidQuotedString`]. One per challenge, and the walk
/// continues past every one of them.
///
/// And, as the walk's last item, [`AuthError::ChallengeBoundaryUnknown`] where
/// the refused challenge's end is not derivable — the one fault this walk
/// raises about itself rather than about a challenge, and the one that ends it.
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
    unresolved: false,
    list_open: false,
    epoch: None,
  }
}

impl AuthError {
  /// Whether this fault is a bound THIS recipient sets rather than one RFC
  /// 9110's grammar has, which is what decides whether the readings behind it
  /// are still the grammar's.
  ///
  /// RFC 9110 §11.6.1's ambiguity is about where one element of a list ends and
  /// the next begins. Behind an element §5.6.1.2 and §11.2 derive nothing at,
  /// no boundary is fixed any more: a DQUOTE at a value position may open a
  /// §5.6.4 quoted-string and may be left shut, and the elements behind it are
  /// wherever the reading puts them. That is the regime a recovery
  /// [`Epoch`] is about, and only a fault of the GRAMMAR opens one.
  ///
  /// A bound moves no boundary. [`MAX_PARAMS_PER_CREDENTIAL`] and
  /// [`MAX_CHALLENGE_LINES`] are this reader's own — the module doc says so
  /// where each is defined, and neither is written anywhere in RFC 9110 — so
  /// the value they refuse is one the grammar still derives from end to end,
  /// with every element exactly where §5.6.1.2 puts it. What the refusal says
  /// is that this recipient will not HOLD the challenge, and never that it
  /// cannot find the next one.
  ///
  /// [`AuthError::DuplicateParameter`] is the third and it is a bound of the
  /// same kind, which is the one classification here that is not obvious. RFC
  /// 9110 §11.2's "each parameter name MUST only occur once per challenge" is
  /// prose about NAMES laid over a list §5.6.1.2 has already delimited: a
  /// repeat makes the challenge one no conforming sender wrote, and it moves no
  /// comma. `Basic a=1, a=2, Bearer abc, x="open, Digest realm=z` is where that
  /// decides an answer — `Bearer abc` is RFC 9110 §11.2's `token68` and no
  /// `auth-param` derives it, so the `Basic` list has ended under every reading
  /// the grammar admits, the DQUOTE behind it stands at no value position, and
  /// the `Digest` is a challenge rather than that value's data.
  const fn is_a_receiver_bound(self) -> bool {
    match self {
      // This reader's three, none of them RFC 9110's.
      Self::ChallengeSpansTooManyLines | Self::TooManyParameters | Self::DuplicateParameter => true,
      // And the grammar's, each of them an element RFC 9110 derives no part
      // of: no `auth-scheme` token, a scheme the production admits nothing
      // after, an element that is neither of §11.2's two alternatives, a
      // §5.6.4 quoted-string that never closes or that carries a byte §5.5
      // admits nowhere in a field value.
      Self::MissingScheme
      | Self::MalformedScheme
      | Self::MalformedParameter
      | Self::UnterminatedQuotedString
      | Self::InvalidQuotedString => false,
      // Not a fault of a challenge at all: it is what a walk ANSWERS once a
      // boundary has turned out not to be derivable, and it is never handed to
      // [`Challenges::refuse`]. Classified all the same, because an arm this
      // match does not carry is a variant added later without deciding which
      // regime stands behind it.
      Self::ChallengeBoundaryUnknown => false,
    }
  }
}

/// A challenge that COMPLETED, and the one thing about it a walk standing
/// behind it still has to know.
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// [`Credential`] answers which of §11.3's two bodies the challenge took —
/// [`Credential::token68`] is `Some` for the one and `None` for the other — but
/// it cannot answer whether there was a body at all: a bare `auth-scheme` and
/// one whose `1*SP` is followed by nothing carry the same empty
/// [`BodyLines`], and only the second of them opened a `#auth-param` list.
/// `Basic` and `Basic<SP>` are those two values, and
/// `Basic<SP>, Broken<HTAB>junk, x="open, Digest realm=z` is where telling them
/// apart decides whether a challenge is hidden.
///
/// So the `1*SP` is carried here rather than re-derived from bytes the
/// credential no longer holds, and [`Challenges::challenge`] is the one reader.
struct Complete<'a> {
  /// The challenge.
  credential: Credential<'a>,
  /// Whether RFC 9110 §11.3's `1*SP` was taken, which is the body's only
  /// entrance.
  entered: bool,
}

impl Complete<'_> {
  /// Whether a `#auth-param` list of THIS challenge is open behind it.
  ///
  /// ```text
  /// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  /// ```
  ///
  /// The `1*SP` is the body's only entrance, so a challenge that did not take
  /// it opened no list whatever its bytes are. RFC 9110 §11.2 puts the rest in
  /// prose — a scheme is followed by "either a comma-separated list of
  /// parameters or a single sequence of characters capable of holding
  /// base64-encoded information" — and only the first of those two is a list,
  /// so a body that took `token68` opened none either.
  const fn opens_a_list(&self) -> bool {
    self.entered && self.credential.token68.is_none()
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

/// A challenge refused with the cursor still inside it, and what the walk that
/// refused it can still say about where that challenge ENDS.
///
/// The fault is the same either way. What differs is whether
/// [`Challenges::seek`] may look for the boundary from where the cursor stands,
/// and [`Challenges::refuse`] is where that is turned into the two flags.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Refusal {
  /// The challenge was refused at its `auth-scheme`, at an element of the OUTER
  /// `#challenge` list that entered no body, so it opened no `#auth-param` list
  /// of its own and whether one is open here at all is the VALUE's question.
  /// Where no list of an earlier challenge is open either, no `auth-param`
  /// begins in what is left of the refused challenge, no DQUOTE in it opens an
  /// RFC 9110 §5.6.4 quoted-string in any reading, and the boundary is every
  /// raw comma.
  ///
  /// The one variant whose `inside_a_list` is not settled by where the cursor
  /// stands, and [`Challenges::refuse`] is where the value answers for it.
  Scheme(AuthError),
  /// The cursor stands inside a body RFC 9110 §11.3's `1*SP` opened, at an
  /// offset every reading of the value has OUTSIDE a §5.6.4 quoted-string — so
  /// the list the fault stands in is open by construction and the boundary is
  /// [`refused_element_end`]'s to find from here. Every fault a parameter list
  /// carries, and the `1*SP` whose body opens on whitespace no production
  /// admits there.
  ///
  /// "Outside a string" is a claim about the CURSOR and not about the fault:
  /// [`AuthError::InvalidQuotedString`] is `Bounded` where the DQUOTE it
  /// choked behind is still in front of the cursor, and
  /// [`Unbounded`](Self::Unbounded) where §5.2's join left that DQUOTE on a
  /// line this walk no longer holds.
  Bounded(AuthError),
  /// The cursor stands INSIDE a §5.6.4 quoted-string a reading of the value
  /// opened, on the far side of a §5.2 join, with the DQUOTE that opened it on
  /// a line the challenge may not read again. Every comma behind that DQUOTE is
  /// that run's data under the reading that opened it, and no scan this walk
  /// may make can even see the opener — so nothing behind it may be read at
  /// all, which is what [`AuthError::ChallengeBoundaryUnknown`] tells the
  /// caller.
  ///
  /// Two faults arrive this way and the string is open for a different reason
  /// in each: the line bound leaves it open on a line the challenge may not
  /// hold, and a byte §5.6.4 forbids leaves it open on a run that reaches no
  /// close at all. [`Challenges::skip_element`] is the one entrance and its doc
  /// tells the two apart.
  Unbounded(AuthError),
  /// The challenge's extent is already COMPLETE and the fault is reported over
  /// the whole of it, so the cursor is on the next challenge's first byte and
  /// there is nothing left of this one to get past.
  ///
  /// Two faults arrive this way — a body no reading of RFC 9110 §11.3's two
  /// alternatives derives, and a challenge whose last region will not fit in
  /// [`MAX_CHALLENGE_LINES`] — and both are refusals like every other. The
  /// arrangement in which they reached the caller WITHOUT passing through
  /// [`Challenges::refuse`] is what let `Basic ;, Bearer, x="open, Digest
  /// realm=z` hand back a `Digest` read out of the middle of `x`'s value: the
  /// body of `;` derives nothing, so nothing behind it does either, and a walk
  /// that recorded no fault let the `Bearer` behind it close a list the grammar
  /// never closed.
  Ended(AuthError),
}

impl Refusal {
  /// The fault, whichever of the four this is.
  const fn fault(self) -> AuthError {
    match self {
      Self::Scheme(fault) | Self::Bounded(fault) | Self::Unbounded(fault) | Self::Ended(fault) => {
        fault
      }
    }
  }
}

/// Where a refusal leaves the cursor, named by the entrance that made it.
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// # Why this is a type and not a sentence
///
/// Because it was a sentence, spread over the docs of four entrances, and one
/// of the four was wrong. [`Challenges::sustain_the_epoch`] rests on it — the
/// span's claim is put to the element at the cursor — and the entrance that
/// leaves the cursor on the far side of RFC 9110 §5.2's join leaves it on a
/// SUFFIX of that element rather than on the element. Nothing checked the
/// enumeration, so nothing said so, and `Basic a=1, a="x` and
/// `y", Bearer, x="open, Digest realm=z` hid a `Digest` behind a claim the
/// grammar never refuted.
///
/// So every entrance names its own, [`Challenges::refuse`] is the one reader,
/// and a fault added later cannot decline to say where it left the walk.
/// [`a_refusal_leaves_the_cursor_where_its_span_begins`] is what checks the
/// part of each row a walk can check for itself.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Origin<'a> {
  /// The first byte of an element on the line the walk holds, with RFC 9110
  /// §5.6.1.2's `OWS` already off the front of it and no scan of this walk's
  /// having read it.
  ///
  /// Seven entrances, and they agree about the cursor because
  /// [`Challenges::open_element`] is the only thing that placed it: no
  /// `auth-scheme` token at all; a scheme with bytes behind it that RFC 9110
  /// §11.3 admits nothing at; [`Section::outgrown`]'s line bound met between
  /// two elements; [`BodyCheck::settle`]'s held verdict on the element behind
  /// the cursor; the fault [`Challenges::skip_element`] raises with nothing
  /// crossed, where the scan never advanced past the element's first byte; and
  /// the two [`Refusal::Ended`] carries, on the next challenge's own first byte
  /// or at the end of a value whose lines the walk read to the last.
  ///
  /// Only [`Section::outgrown`]'s and [`BodyCheck::settle`]'s are reached by a
  /// receiver bound, so they are the only two
  /// [`Challenges::sustain_the_epoch`] ever slices a line at. The
  /// [`Refusal::Ended`] pair never seeks at all.
  Unread,
  /// The body position RFC 9110 §11.3's `1*SP` opened, which is the first
  /// element of this challenge's own `#auth-param` list.
  ///
  /// One entrance: the `1*SP` whose body opens on a HTAB. It is told apart from
  /// [`Unread`](Self::Unread) because §5.6.1.2 hangs a list's `OWS` on its
  /// COMMAS and there is no comma in front of a body's first element — so the
  /// whitespace standing here is derived by nothing, and the cursor is on it
  /// rather than past it. `Basic<SP><HTAB>a, a=", Digest realm=z` is the value,
  /// and [`opener_at`] reads the first parameter's value position from exactly
  /// this offset.
  ///
  /// No receiver bound reaches it — [`AuthError::MalformedScheme`] is a fault
  /// of the grammar's — so no span is ever sliced from here.
  Body,
  /// The element the walk has just scanned, which is the element the refusal is
  /// OVER.
  ///
  /// [`Challenges::refuse_element`]'s two entrances, and the cursor is
  /// [`Recovery::at`]: the element's own first byte where it never left the
  /// line it began on, and the head of the line otherwise — the far side of the
  /// comma §5.2's join put there, where the run standing at the cursor is this
  /// element's SUFFIX and no element of its own.
  Scanned {
    /// The element, as [`Challenges::skip_element`] cut it.
    element: Element<'a>,
    /// [`Recovery::after_comma`], which is also what says a join was crossed.
    after_comma: bool,
    /// [`Recovery::floor`] — where the value RFC 9110 §5.2's join carried onto
    /// this line CLOSES, which is an offset on the line the walk holds and
    /// never one on a line it dropped.
    floor: usize,
  },
  /// The head of the line RFC 9110 §5.2's join left, with a §5.6.4
  /// quoted-string a reading of the value opened still open around the cursor
  /// and its DQUOTE on a line this walk no longer holds.
  ///
  /// [`Challenges::skip_element`]'s two faults, which is the one entrance that
  /// leaves the cursor inside a string. Nothing seeks from here — the refusal
  /// is [`Refusal::Unbounded`] and
  /// [`AuthError::ChallengeBoundaryUnknown`] is what the caller is told — so
  /// there is no element to name and none is named.
  Crossed,
}

/// The stretch of a field value one refusal's ambiguity covers.
///
/// ```text
/// #element   => [ element ] *( OWS "," OWS [ element ] )
/// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// # What it is for
///
/// A `#auth-param` list that is open where a challenge is refused is one the
/// elements BEHIND that refusal may still be inside, and
/// [`refused_element_end`] has to know it to say whether a comma is a boundary
/// or a byte of some parameter's value. That fact was found stored as a flag
/// on the walk and outliving the bytes it was about, in three places, one
/// after another — first monotone over the whole value, then cleared on one
/// completion path out of three, then held past a completion by a second flag
/// that was monotone itself. Each fix made the expiry a little more total and
/// left one entrance open; each of those entrances is what the next fix had
/// to close.
///
/// So the fact is not a flag here. It belongs to the refusal it came from, it
/// lives exactly as long as the walk is still inside the stretch of value that
/// refusal is about, and it dies whole rather than being cleared by whichever
/// path remembers to.
///
/// **And the same class then moved onto the epoch's own
/// [`derivable`](Self::derivable).** It was learned once, from the opening
/// refusal, and never re-examined, so it too outlived the bytes that proved it
/// — `Basic a=1, a=2, y=, Bearer, x="open, Digest realm=evil, junk"` closed an
/// epoch on a claim the `y=` inside its own span had already falsified. A
/// fifth entrance, and the fix is not a sixth flag: derivability is a claim
/// about the whole span, put to every element in it by
/// [`Challenges::sustain_the_epoch`].
///
/// # What opens one
///
/// Every refusal, at [`Challenges::refuse`], which is the only place one is
/// made.
///
/// # What closes one
///
/// The first position no reading this epoch admits places inside the list it
/// holds open — and whether such a position exists at all is
/// [`derivable`](Self::derivable)'s.
///
/// - **Where the grammar still derives the value**, the readings behind the
///   refusal are §5.6.1.2's own and nothing else's, so the first challenge that
///   COMPLETES ends the list: its own element derives as an element of the
///   outer `#challenge` list and derives as nothing else. That is the one
///   position, and [`Challenges::close_the_epoch`] carries why the element
///   [`Challenges::seek`] resumes on is not a second one. Whether the grammar
///   still derives the value is a question about the whole SPAN and not only
///   about the refusal that opened it — [`derivable`](Self::derivable) is that
///   claim and [`Challenges::sustain_the_epoch`] is what every element in the
///   span is put to.
/// - **Where it does not**, no position does. Behind an element that derives
///   nothing, one reading has every element since as garbage the open list
///   still holds, and that reading has the list open behind a bare
///   `auth-scheme` and behind a `token68` too. Such an epoch is closed by
///   nothing, and `Basic a=1, Broken<HTAB>junk, Bearer, x="open, Digest
///   realm=z` is the value that says so: without it the `Digest` behind `x` is
///   read out of the middle of that parameter's own value.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Epoch<'a> {
  /// Whether a `#auth-param` list may be open at the offset recovery starts
  /// from.
  ///
  /// Settled by where the refusal was met: a fault inside a body is a fault
  /// inside the list RFC 9110 §11.3's `1*SP` opened, whatever stands in front
  /// of the challenge, and `Basic<SP><HTAB>a, a=", Digest realm=z` is the value
  /// that tells that apart from a fault standing in front of a list that never
  /// opened. Only [`Refusal::Scheme`] leaves the question to the value, and
  /// only there is the answer carried from anywhere.
  inside_a_list: bool,
  /// Whether a derivation of the whole value still reaches the cursor, which is
  /// whether this epoch can be closed at all.
  ///
  /// # A claim about the SPAN, not about the refusal
  ///
  /// It says that THIS recipient's own limit, and not RFC 9110's grammar, is
  /// why the value stopped being read — so a derivation of the whole value
  /// reaches through every element between the refusal and the position the
  /// epoch may close at, and the claim is about all of them. Three things
  /// carry it, and the first element the grammar derives nothing at refutes it
  /// whichever of the three that element reaches:
  ///
  /// - **The refusal that opened the epoch.**
  ///   [`AuthError::is_a_receiver_bound`] is that test and its doc is the
  ///   argument.
  /// - **Every element [`Challenges::seek`] crosses behind it**, the one the
  ///   refusal left the cursor on included.
  ///   [`Challenges::sustain_the_epoch`] is that test and its doc is the
  ///   argument. `Basic a=1, a=2, y=, Bearer, x="open, Digest realm=evil,
  ///   junk"` is the value that needs it: `y=` is an element the grammar
  ///   derives nothing at, standing in a span a duplicate name opened.
  /// - **The epoch this one was opened behind.**
  ///   [`Epoch::reaches_past_itself`] is that test and its doc is the argument.
  ///   An epoch opened behind one whose ambiguity can still be about these
  ///   bytes cannot be closed either.
  ///
  /// The refutation is permanent in all three, for one reason: what makes the
  /// readings free is the FIRST element the grammar derives nothing at, and no
  /// later bound of this reader's puts it back.
  derivable: bool,
  /// Whether RFC 9110 §5.6.1.2's comma stands in front of the offset the
  /// refused challenge is recovered from, so that §11.6.1 admits a whole
  /// `challenge` there and [`opener_at`] must look for the value position of
  /// ITS first parameter as well.
  ///
  /// True only where §5.2's join carried the refused element onto the line the
  /// walk now stands on, which is [`Recovery::after_comma`] and the one thing
  /// that writes it. It lives HERE rather than on the walk because that is what
  /// makes it unforgettable: an epoch is built whole at
  /// [`Challenges::refuse`], so a refusal that has no join to report writes the
  /// `false` as part of building one and cannot omit it, and the answer dies
  /// with the epoch it was taken over rather than waiting for a later refusal
  /// to overwrite it.
  ///
  /// [`Challenges::seek`] takes it on its FIRST run and leaves it false,
  /// because every later cursor that loop reaches is one `open_element` left on
  /// an element's own first byte and [`opens_a_challenge`] has already answered
  /// `false` for — so neither the challenge reading nor the `OWS` skip it
  /// carries has anything left to do there.
  after_comma: bool,
  /// Where the value RFC 9110 §5.2's join carried onto this line CLOSES, or the
  /// cursor where no join carried one.
  ///
  /// [`Recovery::floor`] is what it is and where it comes from. It is read by
  /// [`Challenges::seek`] and only while [`derivable`](Self::derivable) holds:
  /// a span that still derives has ONE reading of its value position, so the
  /// element ends at that close and the commas in front of it are that value's
  /// data in every reading rather than in some of them. Where the span does not
  /// derive there are two readings and no offset either of them agrees to
  /// resume at, which is what `AuthError::ChallengeBoundaryUnknown` tells the
  /// caller.
  floor: usize,
  /// The element this refusal was made OVER, where the walk had already scanned
  /// one — which is not always the run standing at the cursor.
  ///
  /// # What it is for
  ///
  /// [`Challenges::sustain_the_epoch`] puts the span's every element to RFC
  /// 9110 §11.2, and it needs the ELEMENT. Where §5.2's join carried the
  /// refused element onto the line the walk now stands on,
  /// [`Recovery::at`] is the head of that line and the run standing there is a
  /// SUFFIX of the element — the bytes behind the close of a value that began
  /// on a line this walk no longer holds. Slicing at the cursor and reading
  /// that suffix as a whole `auth-param` refutes the span's claim over an
  /// element the grammar derived: `Basic a=1, a="x` and
  /// `y", Bearer, x="open, Digest realm=z` are the two field lines that say so
  /// — `a`'s value is `x,y`, §11.2 derives the element whole, and the duplicate
  /// name that refused it is a bound of this reader's and moves no comma. The
  /// suffix `y"` derives nothing, so the epoch was refuted, `Bearer` could not
  /// close it, and the genuine `Digest` was hidden behind
  /// [`AuthError::ChallengeBoundaryUnknown`].
  ///
  /// So the element is carried rather than reconstructed. It is the pair
  /// [`Element`] holds — the bytes ON the line it began on, and the
  /// [`ValueTail`] saying what §5.2's join did with a value it left open there
  /// — which is exactly what [`auth_param`] is asked over everywhere else in
  /// this module.
  ///
  /// # Why it may be absent
  ///
  /// Because two of the entrances that open a derivable epoch refuse at an
  /// element the walk has NOT read: [`Section::outgrown`]'s line bound and
  /// [`BodyCheck::settle`]'s held verdict are both met between elements, with
  /// the cursor on the first byte of one no scan has touched. There is no
  /// scanned element to carry there, the run at the cursor is a whole element
  /// because no join carried one onto this line in front of it, and
  /// [`Challenges::sustain_the_epoch`] reads it from the line.
  /// [`a_refusal_leaves_the_cursor_where_its_span_begins`] is that enumeration
  /// asserted rather than left to this doc.
  ///
  /// # Why it lives here
  ///
  /// [`after_comma`](Self::after_comma)'s reason, unchanged: an epoch is built
  /// whole at [`Challenges::refuse`], so a refusal with no scanned element to
  /// report writes the `None` as part of building one and cannot omit it, and
  /// the answer dies with the epoch it was taken over rather than waiting for a
  /// later refusal to overwrite it. [`Challenges::seek`] takes it on its FIRST
  /// run and leaves it `None`, because every later element that loop reaches is
  /// one `open_element` left the cursor on, and `open_element` crosses a join
  /// only where the line it left was spent OUTSIDE a string — so no element
  /// behind the first is a continuation of anything.
  scanned: Option<Element<'a>>,
}

impl Epoch<'_> {
  /// Whether this epoch reaches PAST the challenge it refused — whether the
  /// elements behind it are ones its own ambiguity can still be about.
  ///
  /// ```text
  /// #element   => [ element ] *( OWS "," OWS [ element ] )
  /// challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  /// auth-param = token BWS "=" BWS ( token / quoted-string )
  /// ```
  ///
  /// # The channel, which is the whole of the answer
  ///
  /// A fault changes what the elements BEHIND it may be read as in exactly one
  /// way: at an element RFC 9110 §11.2 admits a value position in, the DQUOTE
  /// standing there is one a reading may open and a reading may leave shut, so
  /// the commas behind it are that value's data under one reading and
  /// §5.6.1.2's separators under another. That is the only thing being behind a
  /// fault buys, and so the only harm a fault can do at a distance.
  ///
  /// §11.2 admits a value position only inside a `#auth-param` list —
  /// `auth-param` is the production that names one, and a list is the only
  /// place one occurs. So **an epoch with no list has no such position, no
  /// DQUOTE any reading may choose, and nothing it can make the bytes behind it
  /// mean that the grammar does not already make them mean.** Its fault is a
  /// fact about its own challenge's extent — which [`Challenges::seek`] settles
  /// by the commas every reading ends an element at — and about nothing else.
  ///
  /// `Basic a=1, Broken;junk, Bearer, x="open, Digest realm=z` is the value
  /// with a channel: `Basic`'s list is open where the fault is met, so it may
  /// still be running at `x`, and the comma inside `x`'s value is one the
  /// readings disagree about. `Broken;junk, Safe, Basic a=1, a=2, Bearer abc,
  /// x="open, Digest realm=z` is the value with none: no list is open at
  /// `Broken;junk` for a string to belong to, so `Safe` and everything behind
  /// it is read exactly as it is with the prefix removed — and the `Basic` list
  /// that opens three elements later is a list this fault never stood in.
  ///
  /// # What reads it
  ///
  /// [`Challenges::refuse`], and nothing else: whether a NEW epoch inherits
  /// this one's non-derivability is the only question anyone asks about a fault
  /// at a distance. [`inside_a_list`](Self::inside_a_list) is asked at the
  /// refusal it belongs to, and [`derivable`](Self::derivable) about this
  /// epoch's own closing.
  const fn reaches_past_itself(&self) -> bool {
    self.inside_a_list && !self.derivable
  }
}

/// One challenge's body as it is collected, across the field lines RFC 9110
/// §5.2 joined into one value.
struct Section<'a> {
  /// The regions taken so far, or the refusal that a region of this challenge
  /// did not fit in [`MAX_CHALLENGE_LINES`].
  ///
  /// A `Result` and not a body beside a flag, because a flag is a fact someone
  /// has to remember to read and this is a body that is no longer there. What
  /// was collected past the bound is not the whole challenge, so
  /// [`AuthError::ChallengeSpansTooManyLines`] is the answer rather than
  /// whatever a partial body happens to parse as — and with the body GONE,
  /// [`close`](Self::close) can produce one only through `?` and
  /// [`outgrown`](Self::outgrown) answers `true` for a section that has none.
  /// There is no state in which a refused section still hands bytes over.
  ///
  /// [`spend`](Self::spend) RETURNS the refusal at every crossing but one, and
  /// [`leave`](Self::leave) is that one — the crossing between two elements,
  /// where RFC 9110 §5.2's join comma may already have ended the refused
  /// challenge and only the element behind it says so. That method carries why
  /// no verdict can be returned there, and which two readers answer for it.
  body: Result<BodyLines<'a>, AuthError>,
  /// Where the current line's region begins.
  start: usize,
  /// Where the challenge ends in the current line: the end of the last element
  /// read there. A region is cut HERE rather than at the line's end, because
  /// what lies behind it is the next challenge and the commas and `OWS`
  /// §5.6.1.2 puts between elements — and the boundary between two regions
  /// already stands for the one comma §5.2 put there.
  end: usize,
}

impl<'a> Section<'a> {
  /// A body that begins at `at` on the line its scheme was read from.
  const fn opening_at(at: usize) -> Self {
    Self {
      body: Ok(BodyLines::new()),
      start: at,
      end: at,
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
  /// A section whose body is already gone answers `true` here as well, and not
  /// by a disjunct on a flag: a region is refused only where there is no slot
  /// left for it, so the count below is at the bound wherever that has
  /// happened. The refusal reaches this method through the missing body rather
  /// than beside it, which is what leaving the disjunct out says.
  ///
  /// The count cannot answer for the LAST region, where a challenge that just
  /// fits has spent every slot too — [`close`](Self::close) is what answers
  /// there, and it does so by asking for a body that a refusal has taken away.
  const fn outgrown(&self) -> bool {
    match &self.body {
      Ok(body) => body.len >= MAX_CHALLENGE_LINES,
      Err(_) => true,
    }
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
  ///
  /// # Errors
  ///
  /// [`AuthError::ChallengeSpansTooManyLines`] where this region did not fit,
  /// or where an earlier one did not. The body is gone either way, so a caller
  /// that goes on regardless has nothing left to collect INTO — which is the
  /// point: a walk still inside an element crosses a join by asking for this,
  /// and a walk that may not take the region may not have the line.
  fn spend(&mut self, line: &'a [u8], end: usize) -> Result<(), AuthError> {
    let region = line.get(self.start..).unwrap_or_default();
    let held = end.saturating_sub(self.start);
    self.start = 0;
    self.end = 0;
    let taken = match &mut self.body {
      Ok(body) => body.push(region, held),
      Err(fault) => Err(*fault),
    };
    if let Err(fault) = taken {
      self.body = Err(fault);
      return Err(fault);
    }
    Ok(())
  }

  /// Takes the line being left BETWEEN two elements, where no verdict can be
  /// returned.
  ///
  /// The one crossing of the three that may not refuse on the spot. RFC 9110
  /// §5.2's join comma is a §5.6.1.2 separator here, so it may already have
  /// ended a challenge this region overran — and only the element behind it
  /// says which: an element that opens a challenge of its own ends this one's
  /// extent, and an element that does not belongs to it. Refusing before that
  /// is read would put the cursor inside a run that is no longer the refused
  /// challenge's, and hand the element behind the join to
  /// [`Challenges::seek`]'s raw-comma scan to swallow.
  ///
  /// The refusal is not dropped for that: [`spend`](Self::spend) leaves this
  /// section with NO body, and both readers of it bind. Which one depends on
  /// that same element — [`outgrown`](Self::outgrown) where it belongs to this
  /// challenge, asked before its bytes are read, and [`close`](Self::close)
  /// where it opens the next one and this challenge's extent is complete.
  /// Neither can be handed a partial body instead.
  fn leave(&mut self, line: &'a [u8], end: usize) {
    let _kept = self.spend(line, end);
  }

  /// Takes the region the challenge ENDS in, and hands over the body.
  ///
  /// Paired with the last [`spend`](Self::spend) by consuming the section — so
  /// a walk cannot take the final region and then hand over a body that is
  /// missing one — and it can hand over nothing at all where a region did not
  /// fit, because a refused section holds no body to hand over.
  ///
  /// # Errors
  ///
  /// [`AuthError::ChallengeSpansTooManyLines`] where any region of this
  /// challenge did not fit. It is reported with no seeking behind it: the
  /// challenge's extent is complete by the time this is called, so the cursor
  /// already stands on the next challenge's first byte and there is nothing
  /// left of this one to get past.
  fn close(mut self, line: &'a [u8], end: usize) -> Result<BodyLines<'a>, AuthError> {
    self.spend(line, end)?;
    self.body
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
  /// has to be found — by the commas every reading of those bytes ends an
  /// element at — before another challenge can be read there. Written only by
  /// [`Challenges::refuse`] and run only by [`Challenges::seek`].
  seeking: bool,
  /// A challenge was refused and where it ENDS is not derivable, so nothing
  /// behind it may be read at all.
  ///
  /// [`AuthError::ChallengeBoundaryUnknown`] is what the walk answers with, and
  /// it is the last item: everything behind an unresolved boundary is unread,
  /// and there is nothing left for a further `next` to be about. Written only
  /// by [`Challenges::refuse`], which is the one writer of all four flags.
  unresolved: bool,
  /// Whether the challenge that just COMPLETED left a `#auth-param` list of
  /// `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` open where
  /// the next element begins.
  ///
  /// That challenge's own shape and nothing else's.
  /// [`Complete::opens_a_list`] is the whole of it, it is written at the ONE
  /// point every completion passes through — [`Challenges::challenge`] — and
  /// no completion path can leave a value an earlier challenge wrote, because
  /// none of them writes this at all.
  ///
  /// # What it is NOT
  ///
  /// Whether a list is open where the WALK stands, which is a different
  /// question and the one that was found stored here. Behind a refusal the
  /// answer is the refusal's rather than any challenge's, and [`Epoch`] is
  /// where it lives. [`Challenges::inside_a_list`] is the two of them together
  /// and is what a refusal asks; nothing asks this on its own.
  ///
  /// # Why a challenge that completes closes a list in front of it
  ///
  /// Its own element DERIVES as a challenge, and RFC 9110 §11.6.1's other
  /// reading of that element — one more `auth-param` of the open list — does
  /// not derive it at all, since
  /// `auth-param = token BWS "=" BWS ( token / quoted-string )` needs a value
  /// behind an `=` that neither a bare scheme nor a `token68` puts there. A
  /// non-derivation beside a derivation is not one of the two readings §11.6.1
  /// leaves a recipient to choose between. ABNF's `/` being unordered says a
  /// recipient may TRY either alternative; it does not make an alternative that
  /// derives none of these bytes into a reading of them.
  /// `Basic a=1, Bearer, x="open, Digest realm=z` and
  /// `Bearer abc, x="open, Digest realm=z` are the two values that need the
  /// close: without it `x` reads as a parameter of a list the challenge in front
  /// of it ended, and the `Digest` behind it is hidden for nothing.
  ///
  /// A challenge that took RFC 9110 §11.3's `1*SP` and a `#auth-param` body
  /// leaves one open instead, and that is the same sentence the other way
  /// round.
  list_open: bool,
  /// The recovery epoch the walk stands in, or `None` where no refusal is still
  /// about the bytes at the cursor.
  ///
  /// [`Epoch`]'s doc carries what one is, what opens it and what closes it.
  /// Written only by [`Challenges::refuse`] and by
  /// [`Challenges::close_the_epoch`], which is called from the two positions an
  /// epoch can end at.
  epoch: Option<Epoch<'a>>,
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
    // Asked after the seek, because that is where a boundary can turn out not
    // to be derivable, and before anything is read, because what stands behind
    // an unresolved boundary is bytes this walk may not read at all.
    if self.unresolved {
      self.done = true;
      return Some(Err(AuthError::ChallengeBoundaryUnknown));
    }
    match self.open_element(None) {
      Step::End => {
        self.done = true;
        None
      }
      // Every refusal is recovered from the same way, so there is no fault to
      // test for here: `challenge` hands each one to `refuse`, and the next
      // step seeks the refused challenge's end by raw commas. A walk that
      // ended on one of them would be deciding, from bytes it has already
      // refused, that no challenge stands behind them.
      Step::Element { .. } => Some(self.challenge()),
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
            // rather than losing it with the error. `leave` and not `spend`
            // because this is the crossing where the comma already passed may
            // have ended the refused challenge, and the element behind it has
            // not been read yet; that method names the two readers that bind
            // instead.
            let end = section.end;
            section.leave(spent, end);
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
  /// and the same bytes are what [`AuthParamIter`] hands a caller later — so a
  /// line this challenge may not hold is a line this scan may not read, and
  /// taking the region and asking for the line are ONE operation for that
  /// reason.
  ///
  /// # Errors
  ///
  /// [`AuthError::InvalidQuotedString`] for a byte §5.6.4 forbids inside a
  /// quoted-string, and [`AuthError::ChallengeSpansTooManyLines`] where the
  /// line this element is still open on cannot be held. Both leave the cursor
  /// INSIDE the challenge they refuse and both are refused by the caller, at
  /// the one place every fault this can raise passes through — so what is left
  /// of that challenge is got past like every other refusal, rather than
  /// scanned on as a quoted-string whose every later byte would decide a
  /// boundary for a challenge already refused.
  ///
  /// The two do not carry the same [`Refusal`], and what tells them apart is
  /// not the fault but WHERE the cursor is left — which is decided by whether
  /// RFC 9110 §5.2's join was crossed with the element's string still open.
  ///
  /// - **Nothing crossed.** The scan never advanced past the element, so the
  ///   cursor is on the ELEMENT's own first byte, an offset every reading of
  ///   the value stands outside a string at: the DQUOTE §11.2 admits is still
  ///   in front of the cursor, where [`some_reading_holds`] scans it for
  ///   itself. Only [`AuthError::InvalidQuotedString`] arrives this way.
  ///   [`Refusal::Bounded`].
  /// - **A join crossed.** The cursor is on the first byte of the line just
  ///   fetched, and the DQUOTE that opened this element's value is on a line
  ///   this walk no longer holds — so no scan it may make can see the opener,
  ///   let alone say where the string closes. A reading of the value is INSIDE
  ///   that string here, whichever of the two faults stopped the scan:
  ///   [`AuthError::ChallengeSpansTooManyLines`] leaves it open on a line the
  ///   challenge may not hold, and [`AuthError::InvalidQuotedString`] leaves it
  ///   open on a run that reaches no close at all — which
  ///   [`crate::grammar::Readings::absorb`] calls SEALED and
  ///   [`some_reading_holds`] would report if the opener were in reach.
  ///   [`Refusal::Unbounded`].
  ///
  /// So this is the one entrance a `Refusal::Unbounded` has: the line bound met
  /// at [`Section::outgrown`] is met BETWEEN elements and the one met at
  /// [`Section::close`] is met with the extent already complete, and neither
  /// stands inside a string.
  ///
  /// **This is where the two spellings of one value were made to agree.** A
  /// forbidden byte met on the head line and the same byte met past a join used
  /// to recover from different points and yield different numbers of
  /// challenges, and the note left here said making them agree needed the
  /// OFFSET the scan choked at, which `QuotedScan::Invalid` does not carry. It
  /// does not — and it is not needed: what the split spelling lost is not the
  /// offset but the OPENER, and a walk that cannot see the opener may not
  /// certify a comma behind it. `Basic realm="ab, Digest realm=z, %x00c"` and
  /// the same value split at its first comma both answer
  /// [`AuthError::ChallengeBoundaryUnknown`] for that reason, where the split
  /// one crossed to a `%x00c"` the sender wrote inside a realm.
  ///
  /// Every OTHER fault the element carries is in the [`Element`] this returns,
  /// because a boundary this walk has not yet found must not be decided by
  /// bytes behind one.
  fn skip_element(
    &mut self,
    region: &mut Section<'a>,
    element_at: usize,
  ) -> Result<(Element<'a>, Recovery), (Refusal, Origin<'a>)> {
    let head = self.line;
    let start = self.at;
    // Set where RFC 9110 §5.2's join was crossed with this element's
    // quoted-string still OPEN, which is the whole of what tells the two
    // refusals apart. The closure below runs at that crossing and NOWHERE else
    // — `scan_element` calls it only while a string holds the element open —
    // so every fault raised past it is raised with a string open around the
    // cursor, and every fault raised without it is raised on the line the
    // element began on with the cursor still on the element's first byte.
    //
    // Read here rather than inferred from the fault's name, because the name
    // does not carry it either way: two other entrances raise
    // `ChallengeSpansTooManyLines` between elements, and
    // `AuthError::InvalidQuotedString` is raised BOTH on the head line, where
    // the DQUOTE is still in front of the cursor, and past a join, where it is
    // on a line this walk no longer holds.
    let mut crossed_a_join = false;
    let scanned = {
      let walk = &mut *self;
      let section = &mut *region;
      let open = &mut crossed_a_join;
      scan_element(head, start, element_at, || {
        let Some(next) = walk.next_line() else {
          return Ok(None);
        };
        *open = true;
        let spent = walk.line;
        walk.line = next;
        // The cursor moves to the head of the line just fetched BEFORE the
        // region is taken, so a refusal below leaves the walk standing where
        // the challenge it refuses could not be held — and `seek` starts from
        // a byte rather than from the middle of a line it never read.
        walk.at = 0;
        // The element is still open here, so ALL of the line being left is the
        // challenge's — including the bytes that begin no element of their own
        // but carry the close of this one. A region that does not fit refuses
        // the challenge on the spot: there is no line to hand back, which is
        // what keeps this scan from reading one more byte of it. The refusal
        // itself is `challenge`'s, at the one place every fault this function
        // can raise passes through.
        section.spend(spent, spent.len())?;
        Ok(Some(next))
      })
    };
    let scanned = match scanned {
      Ok(scanned) => scanned,
      // One fact, answering twice: a join crossed with the string open is both
      // what leaves the cursor inside one and what makes the boundary
      // underivable. Reading the `Refusal` back off the `Origin` at the caller
      // would be telling the two apart by something that is not the difference.
      Err(fault) if crossed_a_join => {
        return Err((Refusal::Unbounded(fault), Origin::Crossed));
      }
      // Nothing crossed, so the element the OUTER list holds is on this line
      // and the cursor goes to where it begins — the scan's own offset, except
      // where `auth-scheme 1*SP` stands in front of it and `element_at` is the
      // scheme's. The same offset [`Recovery::at`] would carry had the scan
      // produced one, and for the same reason.
      Err(fault) => {
        self.at = element_at;
        return Err((Refusal::Bounded(fault), Origin::Unread));
      }
    };
    self.at = scanned.at;
    region.end = self.at;
    Ok((scanned.element, scanned.recovery))
  }

  /// Reads the challenge at the cursor and says what it leaves behind it for
  /// the walk that goes on.
  ///
  /// The ONE place [`list_open`](Self::list_open) is written, and it is here
  /// rather than on the completion paths themselves because there are three of
  /// those and a fourth would inherit whatever the last one wrote. Every
  /// completion passes through this `Ok`, so the state behind a challenge is
  /// that challenge's own shape at the point it completes and is never a fact
  /// left over from an earlier one.
  ///
  /// It is also one of the two positions a recovery [`Epoch`] can end at: a
  /// challenge that completes is an element of the outer `#challenge` list, so
  /// wherever the grammar still derives the value, a list open in front of this
  /// challenge has ended at it. [`Epoch`]'s doc carries the other position and
  /// why an epoch behind a fault reaches neither.
  ///
  /// # Errors
  ///
  /// [`read_challenge`](Self::read_challenge)'s, unchanged. A refusal is not a
  /// completion and writes nothing here: what a refusal leaves behind it is the
  /// epoch [`refuse`](Self::refuse) opens, including the list its own fault
  /// stands in.
  fn challenge(&mut self) -> Result<Credential<'a>, AuthError> {
    let complete = self.read_challenge()?;
    self.list_open = complete.opens_a_list();
    self.close_the_epoch();
    Ok(complete.credential)
  }

  /// Whether a `#auth-param` list may be open where the walk stands, which is
  /// the two answers there are taken together.
  ///
  /// The list the challenge in front of the cursor left open is
  /// [`list_open`](Self::list_open)'s and is a fact about that challenge; the
  /// list a refusal left open is [`Epoch`]'s and is a fact about that fault.
  /// Neither is the other, and a refusal at an `auth-scheme` has to ask both.
  fn inside_a_list(&self) -> bool {
    self.list_open || self.epoch.is_some_and(|epoch| epoch.inside_a_list)
  }

  /// Ends the recovery epoch, at the one position no reading it admits places
  /// inside the list it holds open.
  ///
  /// Called from [`Challenges::challenge`] and from nowhere else, because a
  /// challenge that COMPLETES is the only such position there is. Its own
  /// element derives as an element of the outer `#challenge` list and derives
  /// as nothing else, so wherever the grammar still reaches the cursor, a list
  /// open in front of this challenge has ended at it.
  ///
  /// **The element [`Challenges::seek`] resumes on is not another one**, and
  /// the difference is the whole of what this function may be called from.
  /// [`opens_a_challenge`] says no `auth-param` BEGINS at that element; it does
  /// not say a challenge derives there. Where the walk then refuses it, nothing
  /// derives at that element under any reading, so the reading in which the
  /// list is still running and the element is garbage inside it survives —
  /// `Basic p1=1, ..., p17=17, y=1, Broken;junk, x="open, Digest realm=z` is
  /// the value, and closing an epoch at the resume crosses the comma inside
  /// `x`'s own value.
  ///
  /// An epoch behind a fault answers `false` to
  /// [`derivable`](Epoch::derivable) and outlives even a completion, because
  /// behind an element that derives nothing that argument is not available: the
  /// readings include one in which every element since is garbage the open list
  /// still holds. [`Epoch`]'s doc is that argument and the value that needs it.
  fn close_the_epoch(&mut self) {
    if self.epoch.is_some_and(|epoch| epoch.derivable) {
      self.epoch = None;
    }
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
  /// # A refusal is final, and its extent is not the refused bytes' to decide
  ///
  /// The module doc's invariant, and this is the walk it is about. The moment
  /// an element of this challenge derives nothing, or repeats a name, or fills
  /// the last slot there is, or carries a byte §5.6.4 forbids inside a
  /// quoted-string, or overruns [`MAX_CHALLENGE_LINES`], the challenge is
  /// refused — and the rest of it is handed to [`Challenges::seek`], which
  /// crosses only the commas EVERY reading of those bytes ends an element at.
  /// A DQUOTE behind that first fault opens a string in some readings and not
  /// in others, so the comma in front of the next challenge is that value's
  /// data under one of them, and neither offset is this walk's to pick.
  ///
  /// # Errors
  ///
  /// [`AuthError::MissingScheme`] and [`AuthError::MalformedScheme`], every
  /// fault a parameter list carries, the [`AuthError::InvalidQuotedString`] a
  /// scan raises, and the [`AuthError::ChallengeSpansTooManyLines`] met while
  /// an element is still open across a join, all leave the cursor INSIDE the
  /// challenge that failed, so [`refuse`](Self::refuse) records it and the next
  /// boundary is looked for there.
  ///
  /// The scheme faults are refused from the ELEMENT's own first byte, which is
  /// where §11.6.1's two readings of it part: read as one more `auth-param` of
  /// a list still open, its value position is [`param_value_at`] answered
  /// THERE, and a boundary scan starting behind the scheme token cannot find
  /// it. `Basic a=1, Broken<HTAB>junk, Bearer, x="open, Digest realm=z` is the
  /// value that shows the difference — `x=`'s DQUOTE stands at a value position
  /// of a list `Basic` opened and a fault has left open, and a scan from behind
  /// the `x` crossed the comma inside it. Whether that reading is admitted at
  /// all is [`inside_a_list`](Self::inside_a_list)'s, carried into
  /// [`opener_at`] as `parameters`: `Basic="q, Digest realm=z"` is the shape
  /// where it is not, since no list is open at the head of a `#challenge` value
  /// and so nothing in that element stands at a value position.
  ///
  /// Two faults are reported with the challenge's extent ALREADY COMPLETE: a
  /// body of exactly one element that no `auth-param` derives and no `token68`
  /// takes, and a [`AuthError::ChallengeSpansTooManyLines`] met on the region
  /// the challenge ENDS in. The cursor is on the next challenge's first byte in
  /// both, so there is nothing left of this one to get past — which is
  /// [`Refusal::Ended`], and is all that is different about them.
  fn read_challenge(&mut self) -> Result<Complete<'a>, AuthError> {
    let head = self.line;
    // Where this element begins, kept because a scheme fault is recovered from
    // it and not from wherever inside the element the fault was met. RFC 9110
    // §11.6.1's other reading of the element is one `auth-param` whose value
    // position is `param_value_at` answered at THIS offset, and an origin
    // behind the scheme token has already lost it.
    let start = self.at;
    // And where a refusal met INSIDE this challenge's body is recovered from,
    // for the same reason one element up.
    //
    // ```text
    // challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
    // auth-param = token BWS "=" BWS ( token / quoted-string )
    // ```
    //
    // §11.2's `BWS` is §5.6.3's `OWS`, so the `1*SP` §11.3 needs in front of a
    // body may be the SAME whitespace an `auth-param` writes in front of its
    // `=`. Where it is, this element derives two ways and the walk is about to
    // take one of them — and the value position the OTHER admits stands at the
    // element's own first byte, behind everything the challenge reading
    // crosses. `opens_a_challenge` is that question, asked of the element the
    // walk is reading a challenge at rather than of the ones it skips: nothing
    // asks it HERE, because at the top of a value or behind a completed
    // challenge no list is open and there is no second reading to lose.
    //
    // So the two conditions are the two halves of "the other reading exists".
    // Where they hold, every refusal met before the body's first element has
    // ENDED is a refusal over the element that began at `start` — no §5.6.1.2
    // comma has been crossed, so the outer list's element has not ended — and
    // the recovery begins there, exactly as a scheme fault's does.
    // `Basic a=1, Broken;junk, Bearer, x ="open, Digest realm=z` is the value:
    // the body opens AT the `=`, no value position stands there, and a recovery
    // from it certified the comma inside `x`'s own value and handed a caller a
    // `Digest` with a `realm` under the sender's control.
    let recover_from = (!opens_a_challenge(head, start) && self.inside_a_list()).then_some(start);
    let Some(scheme_end) = token_end(head, self.at) else {
      return Err(self.refuse(Refusal::Scheme(AuthError::MissingScheme), Origin::Unread));
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
        // [`Refusal::Bounded`] and not [`Refusal::Scheme`]: RFC 9110 §11.3's
        // `[ 1*SP ( token68 / #auth-param ) ]` has been ENTERED, so the cursor
        // stands at the body position and the list this fault is met inside is
        // this challenge's own — whatever stands in front of it, and whether or
        // not any of it derives. `Basic<SP><HTAB>a, a=", Digest realm=z` is the
        // value that tells that apart from a fault standing in front of a list
        // that never opened, and it is the whole of what the `1*SP` used to buy
        // by writing a flag that then outlived the challenge. The offset is the
        // body's own, so `opener_at` reads the first parameter's value position
        // from where §5.6.1.2 puts it — unless `recover_from` says the element
        // this body opened in has a reading of its own, in which case that
        // reading's value position is at the element's first byte and the body
        // position has already lost it. `x<SP><HTAB>="open, Digest realm=z`
        // behind a fault is the value, and it is the SP-and-HTAB spelling of
        // the `BWS` `x<SP>="open` writes with one SP.
        if head.get(at) == Some(&b'\t') && !ends_element(head, at) {
          let fault = Refusal::Bounded(AuthError::MalformedScheme);
          return Err(match recover_from {
            Some(element_at) => {
              self.at = element_at;
              self.refuse(fault, Origin::Unread)
            }
            None => self.refuse(fault, Origin::Body),
          });
        }
        at
      }
      // The scheme ends its element — on a comma, or at a line end where
      // §5.2's join comma is the next character of the value. Either way it is
      // a whole challenge that took no parameters.
      None | Some(&b',') => return self.scheme_alone(head, start, scheme),
      // And it still ends its element with only whitespace between it and that
      // comma. `1*SP` is SP alone, so a HTAB opens no parameter section; and
      // RFC 9110 §5.6.1.2 expands the `#challenge` list the scheme sits in as
      // `#element => [ element ] *( OWS "," OWS [ element ] )`, which hangs
      // that OWS on the comma behind it. The scheme is a whole challenge and
      // what follows the comma is the next one.
      Some(&b'\t') if ends_element(head, scheme_end) => {
        return self.scheme_alone(head, start, scheme);
      }
      // Anything else behind the token: the production admits nothing there
      // without `1*SP`, and a HTAB reaching this arm reached an element rather
      // than the comma the arm above needs. Recovered from the element's own
      // first byte, because the element the scheme reading fails on is the one
      // §11.6.1's other reading opens an `auth-param` at.
      Some(_) => {
        self.at = start;
        return Err(self.refuse(Refusal::Scheme(AuthError::MalformedScheme), Origin::Unread));
      }
    };

    let mut section = Section::opening_at(body_at);
    let mut check = BodyCheck::new();
    loop {
      match self.open_element(Some(&mut section)) {
        Step::End => break,
        Step::Element { after_comma } => {
          // RFC 9110 §11.3's choice is already made where the body's first
          // element is wholly a `token68`, so this element is the next one of
          // the OUTER list and not more of this challenge. Asked FIRST, before
          // anything about this element is read: a challenge whose extent the
          // grammar has already fixed is one no later byte may reopen, and
          // `Bearer abc, x="open, Digest realm=z` is the value that shows the
          // difference — `x` is parameter-shaped, so the break below does not
          // fire, and `settle` would refuse a `Bearer` that derives.
          if check.token68_taken() {
            break;
          }
          if after_comma && opens_a_challenge(self.line, self.at) {
            break;
          }
          // This element belongs to the challenge, so everything the challenge
          // already holds has to be answered BEFORE this element's bytes are
          // read. Both checks stand here for that one reason: a boundary found
          // past a fault is a boundary the bytes behind the fault decided.
          // Met BETWEEN elements, with the previous one ended at a boundary
          // the grammar itself fixed, so the cursor is where every reading
          // stands outside a string.
          if section.outgrown() {
            return Err(self.refuse(
              Refusal::Bounded(AuthError::ChallengeSpansTooManyLines),
              Origin::Unread,
            ));
          }
          if let Err(fault) = check.settle() {
            return Err(self.refuse(Refusal::Bounded(fault), Origin::Unread));
          }
          // Where the element the OUTER `#challenge` list holds begins on this
          // line. `after_comma` is false at the body's first element and there
          // alone — every later turn of this loop reached its element past a
          // §5.6.1.2 comma or §5.2's join, and both END the outer list's
          // element — so this is the one turn at which the two can part, and
          // `recover_from` is whether they do.
          //
          // No mutation kills the filter, and the reason is an argument rather
          // than dead code: `recover_from` is `Some` only where
          // `param_value_at` reads a value position at the element's own first
          // byte, which puts the body at the `=` or at the `BWS` in front of
          // one. A body opening at a HTAB is refused above; a body opening at
          // the `=` derives nothing at its first element and is no `token68`,
          // so [`BodyCheck::settle`] refuses at the TOP of this loop's second
          // turn and no later turn reaches this line at all. The filter states
          // the rule the walk relies on instead of leaving it to that chain.
          let element_at = recover_from.filter(|_| !after_comma).unwrap_or(self.at);
          // Both faults the scan can raise leave the cursor INSIDE the
          // challenge they refuse — on the line the bound was met at, or on
          // the element the forbidden byte stands in — so both are refused
          // here and neither ends the walk. Which of the two the boundary
          // survives is the scan's to say, and it says so in the `Refusal`.
          let (element, recovery) = match self.skip_element(&mut section, element_at) {
            Ok(scanned) => scanned,
            Err((refusal, origin)) => return Err(self.refuse(refusal, origin)),
          };
          if let Err(fault) = check.element(element, !after_comma) {
            return Err(self.refuse_element(element, recovery, fault));
          }
          // RFC 9110 §11.2's `token68` alphabet holds no DQUOTE, so an element
          // whose extent a §5.6.4 quoted-string decided is not one — and the
          // verdict `BodyCheck` holds for that reading is due HERE, before
          // `open_element` crosses a boundary this element's own string chose.
          // Left to `finish` it would be reported with the cursor already past
          // that boundary, and `Basic a="x` + `trap="open, Digest realm=z`
          // handed a caller a `Digest` standing inside `trap`'s value.
          if recovery.strung
            && let Err(fault) = check.settle()
          {
            return Err(self.refuse_element(element, recovery, fault));
          }
        }
      }
    }
    // The challenge closes at the end of its last element, and that is where
    // the region it is in stops holding it: the bytes behind it are the next
    // challenge's, or the empty elements between the two.
    let (line, end) = (self.line, section.end);
    // Both faults reported over an extent already complete, and both refused
    // like every other. `?` here instead — which is what stood here — reported
    // them with no epoch opened at all, so a body RFC 9110 §11.3 derives no
    // reading of left the walk believing the value still derived:
    // `Basic ;, Bearer, x="open, Digest realm=z` handed a caller a `Digest`
    // read out of the middle of `x`'s own value, because the `Bearer` behind
    // the fault closed a list no reading of these bytes closes.
    // [`Refusal::Ended`] carries what is different about them, which is only
    // that there is nothing left to seek.
    let body = match section.close(line, end) {
      Ok(body) => body,
      Err(fault) => return Err(self.refuse(Refusal::Ended(fault), Origin::Unread)),
    };
    let credential = match check.finish(scheme, body) {
      Ok(credential) => credential,
      Err(fault) => return Err(self.refuse(Refusal::Ended(fault), Origin::Unread)),
    };
    // RFC 9110 §11.6.1's two readings of this element, and the one thing that
    // may not be true of both at once.
    a_yielded_challenge_is_no_parameter(head, start, self.inside_a_list());
    Ok(Complete {
      credential,
      entered: true,
    })
  }

  /// The challenge whose `auth-scheme` is the whole of it.
  ///
  /// ```text
  /// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
  /// ```
  ///
  /// RFC 9110 §11.3's `1*SP` is the body's only entrance, so a scheme with
  /// nothing but §5.6.1.2's own `OWS` and its comma behind it took no body
  /// under ANY reading of these bytes and opened no list of its own —
  /// [`Complete::entered`] is `false` here for that reason and for no other.
  /// What that then does to a list an earlier challenge left open is
  /// [`Challenges::challenge`]'s, at the one point every completion passes
  /// through, and [`Challenges::list_open`]'s doc carries the argument.
  ///
  /// A challenge is handed back here, so
  /// [`a_yielded_challenge_is_no_parameter`] is checked here too — the other of
  /// the two places one completes.
  ///
  /// # Errors
  ///
  /// Nothing this call can raise. [`Credential::read`] is handed a body with no
  /// elements, so the walk it makes yields none and there is no verdict for
  /// [`BodyCheck`] to hold — but it answers a `Result` for every body, and this
  /// is that `Result` unchanged rather than a second reading of an empty one.
  fn scheme_alone(
    &mut self,
    head: &'a [u8],
    start: usize,
    scheme: &'a [u8],
  ) -> Result<Complete<'a>, AuthError> {
    let credential = Credential::read(scheme, BodyLines::new())?;
    // The same check the other completion path makes, at the other place a
    // challenge is handed back.
    a_yielded_challenge_is_no_parameter(head, start, self.inside_a_list());
    Ok(Complete {
      credential,
      entered: false,
    })
  }

  /// Refuses the challenge over an element that derives nothing, from the
  /// offset at which the readings of that element part.
  ///
  /// The extent [`skip_element`](Self::skip_element) cut was derived by OPENING
  /// the RFC 9110 §5.6.4 quoted-string §11.2 admits at the element's value
  /// position. Where the element then derives nothing that string is no longer
  /// forced on those bytes, so the extent is one reading's, and a boundary scan
  /// starting behind it would never see the reading that leaves the DQUOTE
  /// shut. [`Recovery`] carries where that reading begins and which commas the
  /// reading that opened the string still holds; a candidate in front of the
  /// second is one that reading is inside a value at, so no comma on this line
  /// is a boundary and there is nothing to recover to.
  ///
  /// [`Recovery::after_comma`] is the same join's other half and is carried to
  /// [`seek`](Self::seek) rather than answered here: it admits the reading in
  /// which a whole challenge — RFC 9110 §11.6.1's other reading of an element —
  /// begins on the continuation line, whose own quoted parameter may hold a
  /// comma the `floor` test knows nothing about. This is the one writer of that
  /// flag, and it writes it at every refusal it makes, so no later refusal can
  /// inherit an answer taken over other bytes.
  fn refuse_element(
    &mut self,
    element: Element<'a>,
    recovery: Recovery,
    fault: AuthError,
  ) -> AuthError {
    self.at = recovery.at;
    // A comma in front of the carried value's close is one the reading that
    // opened that value holds — so it is no boundary, and where the readings
    // are FREE there is nothing behind it this walk may resume at either.
    //
    // Where the fault is a bound of this reader's the readings are not free:
    // the value still derives, `( token / quoted-string )` is not a choice at
    // its value position, and the element ends where the string closes. That
    // close is [`Recovery::floor`] and it is on THIS line —
    // [`scan_element`] stops crossing joins the moment the string closes, so a
    // close is never left on a line the walk dropped. So there IS a boundary
    // to find and [`Challenges::seek`] is where it is found.
    // [`Challenges::refuse`] re-derives the whole claim, and a span this
    // predicate calls derivable that its own test does not degrades to
    // [`refused_element_end`]'s decline rather than to a crossing.
    let bounded =
      raw_comma_end(self.line, recovery.at) >= recovery.floor || fault.is_a_receiver_bound();
    self.refuse(
      if bounded {
        Refusal::Bounded(fault)
      } else {
        Refusal::Unbounded(fault)
      },
      Origin::Scanned {
        element,
        after_comma: recovery.after_comma,
        floor: recovery.floor,
      },
    )
  }

  /// Refuses the challenge the cursor stands inside — or the one whose extent
  /// is already complete — and opens the recovery [`Epoch`] that refusal leaves
  /// behind it.
  ///
  /// The one place a refusal is made and the one writer of everything one
  /// implies, so no pairing can be forgotten at a new fault. A refusal reported
  /// without `seeking` would leave the cursor in the middle of a challenge and
  /// the elements behind the fault would be read as challenges of their own. A
  /// refusal reported without `unresolved` where the cursor is inside a
  /// quoted-string the grammar opened would leave the walk standing at an
  /// offset it cannot vouch for, reading whatever that string happens to hold
  /// as challenges of the value. And one reported without an epoch would let a
  /// challenge completing behind it close a list on the strength of an argument
  /// only a value that still derives has — [`Epoch`]'s doc is that argument,
  /// and `Basic ;, Bearer, x="open, Digest realm=z` is the value that had no
  /// epoch at all until the two faults with a complete extent were routed
  /// through here.
  fn refuse(&mut self, refusal: Refusal, origin: Origin<'a>) -> AuthError {
    a_refusal_leaves_the_cursor_where_its_span_begins(self.line, self.at, origin);
    // Where the refusal was met, which settles the list for three of the four
    // variants: a fault inside a body is a fault inside the list RFC 9110
    // §11.3's `1*SP` opened. Only a fault at an `auth-scheme` opened none of
    // its own, and only there is the question the VALUE's — the list the
    // challenge in front of the cursor left open, or one an epoch still holds.
    let inside_a_list = !matches!(refusal, Refusal::Scheme(_)) || self.inside_a_list();
    self.epoch = Some(Epoch {
      inside_a_list,
      // Whether a derivation of the whole value still reaches the cursor.
      // `AuthError::is_a_receiver_bound`'s doc is the argument for this
      // refusal's own half, and `Epoch::reaches_past_itself` for the half an
      // older epoch has: an epoch opened behind one whose ambiguity can still
      // be ABOUT these bytes cannot be closed either, because what makes the
      // readings free is the first element the grammar derives nothing at and
      // no later bound of this reader's puts it back. An older epoch whose
      // ambiguity cannot reach here says nothing about this one, and that is a
      // fact about the CHANNEL rather than about which of the two came first.
      derivable: refusal.fault().is_a_receiver_bound()
        && self.epoch.is_none_or(|epoch| !epoch.reaches_past_itself()),
      // The join's half and the element's, both of them `Origin`'s to answer.
      // An epoch is built WHOLE here — there is no second write to forget and
      // no earlier refusal's answer to inherit — and the entrance that has
      // neither says so by naming a variant that carries neither.
      after_comma: matches!(
        origin,
        Origin::Scanned {
          after_comma: true,
          ..
        }
      ),
      // Where the value a join carried onto this line closes, which is the one
      // offset a recovery over a span that still DERIVES may resume at. Every
      // other entrance stands where no value was carried here, and the cursor
      // itself is that offset.
      floor: match origin {
        Origin::Scanned { floor, .. } => floor,
        Origin::Unread | Origin::Body | Origin::Crossed => self.at,
      },
      scanned: match origin {
        Origin::Scanned { element, .. } => Some(element),
        Origin::Unread | Origin::Body | Origin::Crossed => None,
      },
    });
    match refusal {
      Refusal::Scheme(fault) | Refusal::Bounded(fault) => {
        self.seeking = true;
        fault
      }
      Refusal::Unbounded(fault) => {
        self.unresolved = true;
        fault
      }
      // Nothing to seek and nothing unread: the extent is complete and the
      // cursor is on the next challenge's first byte.
      Refusal::Ended(fault) => fault,
    }
  }

  /// Finds where a challenge already refused ends, without reading what is left
  /// of it as challenges of its own — or gives up, where
  /// [`refused_element_end`] can vouch for no comma.
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
  /// commas are found by [`refused_element_end`] and not by the element walk
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
  /// # An element of a refused challenge may still OPEN a quoted-string
  ///
  /// So crossing one RAW is the other half of the same harm, and the half this
  /// walk committed. RFC 9110 §11.2 names a value position in every element and
  /// admits a §5.6.4 quoted-string at it; behind a fault the production no
  /// longer forces that alternative, so the DQUOTE there is one a reading may
  /// open and a reading may leave shut. Cutting at the first raw comma resumes
  /// the walk wherever the sender's own value happens to hold one — which is
  /// how `Basic p1=1, ..., p17=17, x="c, Digest realm=evil, junk"` handed a
  /// caller a `Digest` challenge with a `realm` of `evil`, out of the middle of
  /// `x`'s value and on input RFC 9110 §11.2 bounds nowhere.
  ///
  /// # And RFC 9110 §11.6.1 names that position twice
  ///
  /// The element the cursor stands on may be a whole `challenge` rather than
  /// one more `auth-param`, and then the DQUOTE that matters is its FIRST
  /// parameter's, behind `auth-scheme 1*SP`. And where a comma stands in front
  /// of the cursor, the element itself stands behind the `OWS` §5.6.1.2 hangs
  /// on that comma, so neither DQUOTE is at the offset the join left.
  /// [`opener_at`] reads both openers from the element's real start, and the
  /// second is admitted only where a comma stands in front of the cursor —
  /// which is exactly what §5.2's join puts there, and which is why this loop
  /// takes `after_comma` from [`refuse_element`](Self::refuse_element) on its
  /// first run and never again: every later cursor is one `opens_a_challenge`
  /// has already answered `false` for.
  ///
  /// So this asks [`refused_element_end`]: whether ANY reading of these bytes
  /// holds the earliest comma inside a string. Where none does, that comma is a
  /// separator whichever reading is the sender's and this crosses to it —
  /// `x="c", Digest realm=evil` is the same element with a string that CLOSES
  /// in front of the comma, and `Digest` is reported. Where one does, the walk
  /// stops rather than resume somewhere it cannot justify, and
  /// [`AuthError::ChallengeBoundaryUnknown`] is what the caller is told.
  ///
  /// Every refusal comes here, and not only the scheme's. [`refuse`](Self::refuse)
  /// is the one writer of the flags, and its doc says why there is exactly one.
  ///
  /// # The line's end is §5.2's comma only where a line follows it
  ///
  /// A string still open where the line runs out holds §5.2's join comma, so
  /// the reading that opened it and the reading that left it shut disagree —
  /// unless the value ends there, where both end the element at the same
  /// offset and there is no comma for them to disagree about. That is what the
  /// `next_line` below asks, and asking it is what keeps `Basic, type="x` from
  /// reporting an unread remainder that does not exist.
  ///
  /// No other fault is reported from here, because none can be: a comma this
  /// crosses is one no reading holds inside a string, and a §5.6.1.2 comma or
  /// the end of the value is all it ever stops at.
  fn seek(&mut self) {
    // Where the value RFC 9110 §5.2's join carried onto the line the refusal was
    // made on CLOSES. It is an offset on THAT line, so it means nothing once
    // this loop has crossed a join of its own — `crossed` is what says so, and
    // a stale one would have this walk resume at a byte of a line it is no
    // longer reading.
    let floor = self.epoch.map(|epoch| epoch.floor);
    let mut crossed = false;
    loop {
      // Taken rather than read: RFC 9110 §11.6.1's challenge reading is
      // admitted at the offset a join left the cursor on and at no other, since
      // every cursor the rest of this loop reaches is one `opens_a_challenge`
      // has already answered `false` for — and an element that opens no
      // challenge admits a value position of its own instead, which is the
      // exclusion `opener_at` derives.
      let after_comma = self
        .epoch
        .as_mut()
        .is_some_and(|epoch| core::mem::take(&mut epoch.after_comma));
      // Taken on the same terms and for the same reason: the element the
      // refusal was made over is the one the cursor stands on now, and every
      // later element this loop reaches is one `open_element` left the cursor
      // on the first byte of. `Epoch::scanned`'s doc carries what a suffix read
      // as a whole element cost.
      let scanned = self.epoch.as_mut().and_then(|epoch| epoch.scanned.take());
      let parameters = self.inside_a_list();
      // Whether a derivation of the whole value still reaches the cursor, which
      // is what says §11.2's `quoted-string` alternative is still FORCED at a
      // value position rather than one of two readings. Read at every turn
      // because `sustain_the_epoch` can refute it at any element this crosses.
      let forced = self.epoch.is_some_and(|epoch| epoch.derivable);
      let resume = floor.filter(|_| !crossed).unwrap_or(self.at);
      let Some(end) =
        refused_element_end(self.line, self.at, parameters, after_comma, forced, resume)
      else {
        // No boundary. The cursor still moves to the end of the run — the walk
        // stands past the bytes it read rather than in front of them — and
        // then the one question left is whether anything is unread at all. A
        // comma some reading holds inside a value leaves the rest of the value
        // unread; the end of a field LINE is that comma only where a line
        // follows it, and where none does the value ends inside the string,
        // every reading ends the element there, and nothing stands behind it.
        self.at = raw_comma_end(self.line, self.at);
        if self.at < self.line.len() || self.next_line().is_some() {
          self.unresolved = true;
        }
        return;
      };
      // The boundary is certified now and not before, so this is where the
      // element behind the cursor becomes one every reading of these bytes
      // ends HERE — and so an element the epoch's own claim is about. Asked
      // any earlier, the question would be about an element some reading holds
      // inside a value, which is no element at all.
      self.sustain_the_epoch(end, scanned);
      self.at = end;
      let held = self.line.len();
      match self.open_element(None) {
        Step::End => return,
        // A comma was crossed by construction: the element just skipped ended
        // on one, or at the line end RFC 9110 §5.2 puts one at.
        Step::Element { .. } => {
          crossed = crossed || self.line.len() != held || self.at < floor.unwrap_or(0);
          // The epoch does NOT end here, and the element this stops on is why:
          // [`opens_a_challenge`] says no `auth-param` begins at it, which is
          // not the same as saying a list ended in front of it. An element that
          // derives nothing derives no challenge either, so the reading in
          // which the list is still running and this element is garbage inside
          // it survives — and `Basic p1=1, ..., p17=17, y=1, Broken;junk,
          // x="open, Digest realm=z` is the value that says so: `Broken;junk`
          // is where the walk resumes AND the next thing it refuses, and a list
          // closed here crosses the comma inside `x`'s own value. Only a
          // challenge that COMPLETES ends an epoch, and
          // [`Challenges::challenge`] is where that is done.
          if opens_a_challenge(self.line, self.at) {
            return;
          }
        }
      }
    }
  }

  /// Puts the element the recovery has just got past to the epoch's claim,
  /// which that element either sustains or refutes.
  ///
  /// ```text
  /// auth-param = token BWS "=" BWS ( token / quoted-string )
  /// ```
  ///
  /// # What the claim is
  ///
  /// [`Epoch::derivable`] says a derivation of the whole value still reaches
  /// the cursor — that THIS recipient's own limit, and not RFC 9110's grammar,
  /// is why the value stopped being read.
  /// [`AuthError::is_a_receiver_bound`] is what the opening refusal
  /// contributes to that, and the refusal is only the span's first element: a
  /// derivation of the whole value has to reach through every element between
  /// it and the position the epoch may close at, so the claim is about all of
  /// them.
  ///
  /// The first of them the grammar derives nothing at falsifies it. The
  /// grammar is then a reason the value stopped deriving too, and "not the
  /// grammar" is false. The refutation is permanent for the same reason a
  /// fault's own is: what makes the readings free is the FIRST element the
  /// grammar derives nothing at, and no later bound of this reader's puts it
  /// back.
  ///
  /// # Why every element it crosses has to be asked
  ///
  /// [`Challenges::seek`] crosses the span without deriving anything in it,
  /// and [`opens_a_challenge`] is the only question it asks of an element it
  /// crosses. That question is about POSITION — whether an `auth-param` BEGINS
  /// here — and `y=` begins one and derives none. Crossing such an element
  /// silently discards the one fact that refutes the claim, and
  /// `Basic a=1, a=2, y=, Bearer, x="open, Digest realm=evil, junk"` is the
  /// value that says what that costs: the duplicate opens a derivable epoch,
  /// `y=` is skipped, `Bearer` closes the epoch on a claim `y=` had already
  /// falsified, and the scheme fault at `x=` then stands in front of no open
  /// list and crosses the comma inside `x`'s own value — handing a caller a
  /// `Digest` challenge with a `realm` of `evil` that no origin server sent.
  ///
  /// # Including the element the refusal left the cursor ON
  ///
  /// Which is the whole span and not the span less its first element, because
  /// that element is not always one the refused challenge derived.
  /// `Basic a1=1` through `a16=16` on sixteen field lines, and a seventeenth
  /// opening with the element `y=` in front of `Bearer` and a trap whose string
  /// never closes, is a value whose span begins at an element §11.2 derives
  /// nothing at — and whose `Digest` was invented out of that trap's own data
  /// while this rule skipped the span's first element. So there is no
  /// first-element exception.
  ///
  /// # And taking it from the walk where the walk has it
  ///
  /// `scanned` is that element where the refusal was made over one the walk had
  /// already read, and the difference is not cosmetic. Where RFC 9110 §5.2's
  /// join carried that element onto the line the walk now stands on, the cursor
  /// is at the HEAD of this line and the run standing there is the element's
  /// own SUFFIX — the bytes behind the close of a value that began on a line
  /// this walk no longer holds. Read as a whole `auth-param` it derives
  /// nothing, and the span's claim is refuted over an element the grammar
  /// derived: `Basic a=1, a="x` and `y", Bearer, x="open, Digest realm=z` hid a
  /// `Digest` for exactly that. [`Epoch::scanned`] is where the element is
  /// carried and why it may be absent.
  ///
  /// Where it is absent the run at the cursor IS a whole element, because the
  /// two entrances that leave a derivable epoch with no scanned element —
  /// [`Section::outgrown`]'s line bound and [`BodyCheck::settle`]'s held
  /// verdict — are met between elements, on a line no join carried an element
  /// onto in front of the cursor.
  /// [`a_refusal_leaves_the_cursor_where_its_span_begins`] is that enumeration
  /// checked rather than argued.
  ///
  /// # And RFC 9110 §5.6.1.2's leading `OWS` is not skipped here
  ///
  /// It was, and the skip is gone with the reason for it. A cursor standing
  /// behind that `OWS` is a cursor §5.2's join left at a line head, and such a
  /// cursor now arrives as a `scanned` element instead — so the skip was a
  /// second, weaker answer to the question [`Epoch::scanned`] answers, and it
  /// could not be killed by any mutation for exactly that reason: the only
  /// remaining cursor it moved was [`Origin::Body`]'s, whose fault is the
  /// grammar's and whose epoch is therefore never derivable.
  ///
  /// What replaces it is a claim rather than a skip:
  /// [`Origin::Unread`] says the cursor is on an element's first byte, and
  /// `a_refusal_leaves_the_cursor_where_its_span_begins` is where that is
  /// checked at every refusal that makes one.
  ///
  /// # A bound met inside the span is no refutation
  ///
  /// [`auth_param`] is RFC 9110's grammar and nothing else, so a repeated name
  /// and a seventeenth parameter pass here exactly as they pass anywhere: they
  /// move no comma, which is the whole of what
  /// [`AuthError::is_a_receiver_bound`] records. The claim is about what
  /// DERIVES, and only the grammar refutes it.
  ///
  /// # The element's extent
  ///
  /// [`Challenges::open_element`] left the cursor on the element's first byte
  /// with RFC 9110 §5.6.1.2's leading `OWS` already off it, and `end` is the
  /// boundary [`refused_element_end`] has just CERTIFIED for it — the offset
  /// every reading of these bytes ends the element at — with [`trim_ows_end`]
  /// taking the list's own trailing whitespace off the far end. That is why
  /// the caller asks this a turn later than it meets the element: asked at the
  /// meeting, the question would be about an element some reading holds inside
  /// a value, which is no element at all, and `Basic a1="x` and
  /// `y", Bearer, x="c` is the pair of field lines that says so.
  ///
  /// [`ValueTail::Ends`] is the tail of an element read FROM THE LINE, and it
  /// is the only one that can matter there. Where a `#auth-param` list is open,
  /// a string still open at that comma is one [`some_reading_holds`] reports
  /// and [`refused_element_end`] answers `None` for, so the walk stops rather
  /// than arrive here; and where none is open the epoch is already underivable,
  /// since a receiver bound is only ever met inside the body §11.3's `1*SP`
  /// opened. That is an argument rather than a branch, so
  /// [`a_derivable_span_admits_one_tail`] is what checks it instead of leaving
  /// it to this doc. A `scanned` element brings its own tail and is asked with
  /// it: that one crossed a join by construction, and what the join did with
  /// its value is the whole of what [`ValueTail`] exists to say.
  ///
  /// So this only ever CLEARS the flag, and an epoch already carrying a fault
  /// is one it leaves exactly as it found it.
  fn sustain_the_epoch(&mut self, end: usize, scanned: Option<Element<'a>>) {
    let element = scanned.unwrap_or_else(|| {
      let bytes = self
        .line
        .get(self.at..trim_ows_end(self.line, end))
        .unwrap_or_default();
      if let Some(epoch) = self.epoch.as_ref() {
        a_derivable_span_admits_one_tail(bytes, epoch.derivable);
      }
      Element {
        bytes,
        tail: ValueTail::Ends,
      }
    });
    let derives = auth_param(element.bytes, element.tail).is_ok();
    if let Some(epoch) = self.epoch.as_mut() {
      // RFC 9110 §11.6.1's OTHER reading of the same element, which
      // [`auth_param`] cannot see: where the element takes §11.3's `1*SP`, that
      // reading opened a `#auth-param` list and its body derives nothing —
      // every element this loop crosses is one [`opens_a_challenge`] answered
      // `false` for, so its body begins at an `=` or at the `BWS` in front of
      // one and §11.2 derives neither.
      //
      // **It is a reading only where this element does not derive.** An
      // alternative that derives nothing is not one of the two §11.6.1 leaves a
      // recipient to choose between — the rule `Challenges::list_open` carries
      // for a completed challenge, read here for a crossed element — so where
      // the span still derives AND §11.2 derives this element, the challenge
      // branch failing at the body's `=` says nothing at all.
      // `Basic p1=1, …, p17=17, y = 1, Bearer, x="open, Digest realm=z` is the
      // value that cost: `TooManyParameters` opens a derivable epoch, `y = 1`
      // is a whole `auth-param`, and letting its failed challenge branch refute
      // the span kept `Bearer` from closing the epoch and hid a `Digest` every
      // complete derivation of the value agrees on.
      let opens = !(epoch.derivable && derives) && opens_a_parameter_list(element.bytes);
      // Only §11.2's reading — the one that DERIVES — answers the span's claim.
      epoch.derivable = epoch.derivable && derives;
      // And where the challenge branch is the reading, the list it opened is
      // open behind this element whatever was open in front.
      epoch.inside_a_list = epoch.inside_a_list || opens;
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
  /// element's extent, which is the `#challenge` walk's own harm arriving in
  /// this field. Such a
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
      scan_element(head, start, start, || {
        let Some(next) = walk.next_line() else {
          return Ok(None);
        };
        walk.line = next;
        Ok(Some(next))
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
