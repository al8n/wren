//! The RFC 9110 §12.5 content negotiation fields whose element carries no
//! parameters: §12.5.2's `Accept-Charset`, §12.5.3's `Accept-Encoding`,
//! §12.5.4's `Accept-Language` and §12.5.5's `Vary`.
//!
//! One walk serves the first three. Each is a §5.6.1 list of a bare name with
//! RFC 9110 §12.4.2's weight optionally hung off it, and the only thing that
//! separates one from another is which names its element production admits:
//!
//! ```text
//! Accept-Charset = #( ( token / "*" ) [ weight ] )
//! Accept-Encoding  = #( codings [ weight ] )
//! codings          = content-coding / "identity" / "*"
//! content-coding   = token
//! Accept-Language = #( language-range [ weight ] )
//! language-range  = <language-range, see [RFC4647], Section 2.1>
//! weight = OWS ";" OWS "q=" qvalue
//! ```
//!
//! [`vary`] is in this module and is NOT that walk, because §12.5.5 is not that
//! shape:
//!
//! ```text
//! Vary = #( "*" / field-name )
//! field-name     = token
//! ```
//!
//! It carries no `[ weight ]` bracket, so there is nothing for §12.4.2 to
//! rank, and its `"*"` is an alternative of the ELEMENT rather than a name a
//! `token` alternative happens to also derive. It shares the §5.6.1 list split
//! with the three above and nothing else, and it answers in a type of its own
//! rather than in a [`Preference`] whose weight would always be
//! [`Weight::ONE`] and mean nothing. It is here because §12.5 is where its
//! subject is: it names the request fields a response's content was selected
//! from.
//!
//! §12.5.4's element is the one RFC 9110 does not spell. That `prose-val` sends
//! a reader to RFC 4647 §2.1, whose rule is transcribed at
//! [`Element::LanguageRange`] and whose text this workspace now fetches — a
//! comment quoting a spec `quote-check` has never loaded is graded against
//! nothing.
//!
//! # §12.5.1's `Accept` is not here, and this is not where it belongs
//!
//! `Accept = #( media-range [ weight ] )` has the shape above and none of the
//! machinery. Its element is a media range, which is `type "/" subtype` and
//! then §5.6.6's `parameters` — so reading one is reading a media type, and
//! [`accept`](crate::media::accept) sits in [`crate::media`] beside the
//! [`media_type`](crate::media::media_type) walk it shares every byte of. The
//! elements here share nothing with that walk except the `[ weight ]` bracket,
//! and the section below is about what the difference costs.
//!
//! # §12.5.1's `q` rule does not transfer, and does not need to
//!
//! RFC 9110 §12.5.1 tells a recipient this: "Recipients SHOULD process any
//! parameter named "q" as weight, regardless of parameter ordering." It is a
//! rule an `Accept` reader needs because a `media-range` CARRIES parameters —
//! `text/plain;charset=utf-8;q=0.5;level=1` is one element with three of them,
//! the weight is whichever is named `q`, and where it sits among the others is
//! the sender's choice.
//!
//! An element here carries none. `codings` is `content-coding / "identity" /
//! "*"` and `content-coding` is `token`; §12.5.2's is `( token / "*" )`; RFC
//! 4647 §2.1's `language-range` is ALPHA, DIGIT and `-`, and no other byte at
//! all. Each is a name, and then the ABNF is out of alternatives. So the only production a `;` inside such an
//! element can open is `[ weight ]`, there is at most one of them, and ORDER is
//! not a question anybody can ask — there is nothing for the weight to be
//! ordered against. §12.5.1's rule is not inherited here and not re-implemented
//! here; over this grammar it has no work to do.
//!
//! **Importing `Accept`'s parameter handling would not be harmless, which is
//! why this is a refusal rather than a note.** §5.6.6's `parameter` admits
//! three things §12.4.2's `weight` does not, and each changes an answer:
//!
//! - **A quoted value.** §5.6.6 says of a parameter that "The quoted and
//!   unquoted values are equivalent.", so `Accept: text/plain;q="0.5"` weighs
//!   0.5. `weight` spells its value `qvalue` with no `quoted-string`
//!   alternative at all, so `Accept-Encoding: gzip;q="0.5"` is no
//!   `Accept-Encoding`, and this module answers
//!   [`NegotiationError::BadWeight`].
//! - **A repetition.** `parameters = *( OWS ";" OWS [ parameter ] )` repeats,
//!   and `[ weight ]` brackets exactly one. `gzip;q=0.5;p=1` is a media range's
//!   shape and is no element of any field here.
//! - **A comma inside a value.** This is the one that moves a BOUNDARY rather
//!   than a verdict. A quoted parameter value may hold the comma §5.6.1 uses
//!   as its separator, which is why [`accept`](crate::media::accept) takes a
//!   field's LINES and resolves member ends itself. No production reachable
//!   from an element here admits a DQUOTE, so every comma in these fields is
//!   the separator, and the elements are exactly what
//!   [`list_elements`](crate::grammar::list_elements) splits.
//!
//! # What a line boundary does here, which is nothing
//!
//! These entry points still take a field's lines rather than one value,
//! because RFC 9110 §5.2 lets a sender spread a list field over several of
//! them and a caller should not have to join them. What the join cannot do
//! here is hide anything: it inserts a comma between two lines, no element may
//! hold one, so walking the lines in order and walking the joined value give
//! the same members at the same extents.
//!
//! # `coding-corpus` grades none of these productions
//!
//! Stated rather than left to be inferred from a differential nobody wired.
//! That harness exists because several readers of ONE production, each tested
//! from the reading that produced it, is how al8n/wren#76 happened, so a new
//! reader owes an answer to whether it is a second reader of something already
//! graded there. This one is not, on either half of the question:
//!
//! - **No element production here is in it.** It grades RFC 9110 §10.1.4's
//!   `transfer-coding`, §5.6.6's `parameters`, §5.6.1.1's empty-element
//!   question and §10.1.4's `t-codings`. `content-coding` is none of those and
//!   is not `transfer-coding` under another name: §8.4.1 writes
//!   `content-coding   = token` where §10.1.4 writes
//!   `transfer-coding    = token *( OWS ";" OWS transfer-parameter )`, so
//!   `chunked;p=1` — a value that corpus is built to exercise — is a
//!   `transfer-coding` and is no `codings`. RFC 4647's `language-range` is not
//!   in it either, and is not in RFC 9110 at all. §12.5.2's element is §5.6.2's
//!   `token`, which that corpus's `oracle` derives from the RFC and which no
//!   PAIR there grades — its own summary says every reader in it reaches one
//!   `tchar` table, so no pair parts on that layer.
//! - **This module adds no second READING of anything shared.** The three
//!   productions it does share with existing readers are reached by CALLING
//!   the one implementation of each rather than by writing another:
//!   §5.6.1's list split is [`list_elements`](crate::grammar::list_elements),
//!   whose own doc makes that route the rule; §5.6.2's `token` is
//!   [`is_token`](crate::grammar::is_token); and §12.4.2's `qvalue` is
//!   `media::parse_qvalue`, the function `Accept`'s weight already comes out
//!   of. A production with one implementation has no two readings to diverge.
//!
//! What that leaves ungraded is what this module does write for itself: where
//! an element ends and its `[ weight ]` begins. Nothing else reads that, so
//! there is nothing to differ with.

use crate::{
  grammar::{is_token, list_elements, skip_ows, trim_ows},
  media::{Weight, ascii, parse_qvalue},
};

/// RFC 9110 §12.4.3's wildcard, spelled once.
const WILDCARD: &[u8] = b"*";

/// RFC 9110 §12.5.3's synonym for no encoding, spelled once.
///
/// "An "identity" token is used as a synonym for "no encoding" in order to
/// communicate when no encoding is preferred."
const IDENTITY: &[u8] = b"identity";

/// The longest subtag RFC 4647 §2.1's
/// `language-range   = (1*8ALPHA *("-" 1*8alphanum))` admits, in either
/// position.
const MAX_SUBTAG: usize = 8;

/// Why a content negotiation walk stopped.
///
/// Every variant is a fault of the SENDER's: none of these fields bounds
/// anything this crate has to bound for it, so there is no limit-of-the-walk
/// variant here of the kind [`MediaError::TooManyParameters`] is.
///
/// [`MediaError::TooManyParameters`]: crate::media::MediaError::TooManyParameters
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum NegotiationError {
  /// The element is not the production its field spells — for
  /// [`accept_encoding`], not RFC 9110 §12.5.3's
  /// `codings          = content-coding / "identity" / "*"`.
  #[error("not an element of this negotiation field")]
  NotAnElement,
  /// Something follows the element that RFC 9110 §12.4.2's
  /// `weight = OWS ";" OWS "q=" qvalue` does not spell: a parameter by another
  /// name, a second one behind the first, or the `BWS` that production writes
  /// nowhere.
  ///
  /// Separate from [`BadWeight`](Self::BadWeight) because the two are
  /// different sender mistakes. This one is a field whose element grammar the
  /// sender took for `Accept`'s; that one is a `q` in the right place whose
  /// value is not a `qvalue`.
  #[error("what follows the element is not a weight")]
  NotAWeight,
  /// A `q` in the place RFC 9110 §12.4.2's `weight` puts one, whose value is
  /// not that section's
  /// `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
  #[error("the weight's value is not a qvalue")]
  BadWeight,
}

/// Which names an element may be, per the field being read.
///
/// A field's own value rather than a `fn(&[u8]) -> bool` the walk is handed.
/// `tests/no_panic.rs` records what a function POINTER costs a link-time proof
/// over a generic walk — two shims reaching one instantiation with two
/// different pointer values leave the indirect call un-devirtualized and empty
/// both proofs at once — and an enum matched inside the walk has no indirect
/// call to leave behind. It is also the shape `ParamSyntax` already has for the
/// same reason on the same kind of walk.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Element {
  /// RFC 9110 §5.6.2's `token          = 1*tchar`, which is the whole of what
  /// §12.5.3's `codings` admits and the whole of what §12.5.2's element does.
  ///
  /// `codings = content-coding / "identity" / "*"` names three alternatives
  /// and derives one language. `content-coding   = token` is the first;
  /// `identity` is eight `tchar`s and so is a `token` too; and `*` is a
  /// `tchar`, so the third is as well. §12.5.2 writes
  /// `Accept-Charset = #( ( token / "*" ) [ weight ] )`, whose two alternatives
  /// collapse the same way. So the two fields share this arm because their
  /// element productions DERIVE THE SAME STRINGS, which is a fact about the
  /// grammar rather than a convenience: nothing an element of either may SAY
  /// separates them.
  ///
  /// What separates them is what each section says a name MEANS — §12.5.3's
  /// `identity` and each field's `*` — and that is the caller's to read off
  /// [`Preference::name`] and [`Preference::is_wildcard`].
  Token,
  /// RFC 4647 §2.1's basic language range, which RFC 9110 §12.5.4's
  /// `language-range  = <language-range, see [RFC4647], Section 2.1>` hands out
  /// to that spec rather than spelling:
  ///
  /// ```text
  /// language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"
  /// alphanum         = ALPHA / DIGIT
  /// ```
  ///
  /// Narrower than [`Token`](Self::Token) and inside it: ALPHA, DIGIT and `-`
  /// are all §5.6.2 `tchar`s, so every `language-range` is a `token` and no
  /// `language-range` can hold a byte that would move an element boundary. The
  /// narrowing is real all the same — `x_y` and `verylongsubtag` are `token`s
  /// and are no basic language range — and it is checked rather than widened to
  /// `token` for convenience, because RFC 4647 §2.1 says what an ill-formed
  /// range is worth: "Such ill-formed ranges will probably not match anything."
  ///
  /// The `*` alternative is unambiguous here in a way it is not for a `token`
  /// element: `*` is no ALPHA, so `(1*8ALPHA *("-" 1*8alphanum))` cannot derive
  /// it and the wildcard is the only reading.
  ///
  /// This is §2.1's BASIC range and not §2.2's `extended-language-range`, which
  /// admits a `*` in any subtag position. §12.5.4's `prose-val` names §2.1, and
  /// widening to §2.2 would admit `en-*-GB` in a field whose own spec does not.
  LanguageRange,
}

impl Element {
  /// Whether `name` is a name this element admits.
  #[inline]
  fn admits(self, name: &[u8]) -> bool {
    match self {
      Self::Token => is_token(name),
      Self::LanguageRange => is_language_range(name),
    }
  }
}

/// Whether `name` is RFC 4647 §2.1's
/// `language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"`, over
/// `alphanum         = ALPHA / DIGIT`.
///
/// Read as the rule GENERATES, not off the examples RFC 9110 §12.5.4 shows.
/// `da`, `en-gb` and `en` are three shapes it derives and are not the whole of
/// it, and the two subtag positions are NOT the same rule: the primary one is
/// `1*8ALPHA` and every later one is `1*8alphanum`, so `en-us-1` is a
/// `language-range` and `1-en` is not.
///
/// A subtag of zero characters is refused at both positions, since `1*` is the
/// repetition on both sides of the hyphen: `en-`, `-gb` and `en--gb` derive
/// nothing. So is one of nine characters, at either position — the bound is
/// [`MAX_SUBTAG`] and not only the first subtag's.
///
/// The DIGIT in the later position is RFC 4647's correction to the rule it
/// replaced, and reading the replaced one instead would refuse values this
/// field carries. RFC 4647 §2.1, of RFC 2616's version: "is incorrect, since it
/// disallows the use of digits anywhere in the 'language-range'".
fn is_language_range(name: &[u8]) -> bool {
  if name == WILDCARD {
    return true;
  }
  let mut subtags = name.split(|&b| b == b'-');
  // A `split` over any slice yields a first part, so the primary subtag is
  // always there; the default is what makes that an argument rather than an
  // `unwrap`, and an empty `name` arrives as one empty part and fails below.
  let primary = subtags.next().unwrap_or_default();
  if primary.is_empty() || primary.len() > MAX_SUBTAG {
    return false;
  }
  if !primary.iter().all(u8::is_ascii_alphabetic) {
    return false;
  }
  subtags.all(|subtag| {
    !subtag.is_empty() && subtag.len() <= MAX_SUBTAG && subtag.iter().all(u8::is_ascii_alphanumeric)
  })
}

/// One member of a content negotiation list: a name, and the RFC 9110 §12.4.2
/// weight the sender hung off it.
///
/// Borrows the field lines it was parsed from.
///
/// # No `PartialEq`
///
/// For the reason [`MediaRange`] carries none, and it is the same reason
/// spelled by a different section for each field this type serves. A derive
/// here would compare the bytes as WRITTEN, and every name it can hold is
/// matched case-insensitively by the section that defines it — RFC 9110 §8.4.1
/// for a content coding: "All content codings are case-insensitive"; RFC 4647
/// §2.1 for a language range: "Matching of language tags to language ranges
/// MUST be done in a case-insensitive manner." So `gzip` and `GZIP` would
/// compare unequal while naming one coding, and `en-GB` and `en-gb` unequal
/// while naming one range. A caller compares [`name`](Self::name) with
/// `str::eq_ignore_ascii_case`.
///
/// [`MediaRange`]: crate::media::MediaRange
#[derive(Debug, Copy, Clone)]
pub struct Preference<'a> {
  name: Option<&'a [u8]>,
  weight: Weight,
}

impl<'a> Preference<'a> {
  /// The element's name, or `None` for the wildcard `*`.
  ///
  /// RFC 9110 §12.5.3: "The asterisk "*" symbol in an Accept-Encoding field
  /// matches any available content coding not explicitly listed in the field."
  /// That is a different thing from a coding whose name happens to be one
  /// character, so it is a different answer rather than a `Some("*")` every
  /// caller would have to remember to test for. Each field's own section says
  /// what its wildcard matches — §12.5.2 for a charset, §12.5.3 for a coding,
  /// and §12.4.3 over all of them — and this reports only that the sender wrote
  /// one.
  ///
  /// A name that MEANS something is still a name. `identity` reports
  /// `Some("identity")` and is not the wildcard, though RFC 9110 §12.5.3 gives
  /// it a meaning of its own: "An "identity" token is used as a synonym for "no
  /// encoding" in order to communicate when no encoding is preferred." What a
  /// name means is the caller's to act on; what this answers is which name the
  /// sender wrote.
  #[inline]
  pub const fn name(&self) -> Option<&'a str> {
    match self.name {
      Some(bytes) => Some(ascii(bytes)),
      None => None,
    }
  }

  /// Whether this member is the wildcard `*` — the complement of
  /// [`name`](Self::name) being `Some`.
  #[inline]
  pub const fn is_wildcard(&self) -> bool {
    self.name.is_none()
  }

  /// The weight, defaulting to [`Weight::ONE`].
  ///
  /// RFC 9110 §12.4.2: "If no "q" parameter is present, the default weight is
  /// 1."
  #[inline]
  pub const fn weight(&self) -> Weight {
    self.weight
  }
}

/// Reads one already-delimited element as a name and an optional weight.
///
/// The split is on the FIRST `;`, and one split is enough for the whole of
/// RFC 9110 §12.4.2's `weight = OWS ";" OWS "q=" qvalue`: `;` is no §5.6.2
/// `tchar`, so no element name reaches one, and a second `;` lands inside what
/// has to be a `qvalue` and is refused there.
fn preference_from(member: &[u8], element: Element) -> Result<Preference<'_>, NegotiationError> {
  let mut halves = member.splitn(2, |&b| b == b';');
  // `splitn` over a non-empty slice always yields a first part, and
  // `list_elements` hands out no empty member; the default is what makes that
  // an argument rather than an `unwrap`.
  let name = trim_ows(halves.next().unwrap_or_default());
  if !element.admits(name) {
    return Err(NegotiationError::NotAnElement);
  }
  let weight = match halves.next() {
    None => Weight::ONE,
    Some(tail) => read_weight(tail)?,
  };
  Ok(Preference {
    name: if name == WILDCARD { None } else { Some(name) },
    weight,
  })
}

/// Reads RFC 9110 §12.4.2's `weight = OWS ";" OWS "q=" qvalue` from just past
/// its `;`.
///
/// `"q="` is one `char-val`, so nothing may stand between the `q` and the `=`:
/// `gzip;q = 0.5` is [`NegotiationError::NotAWeight`], where §10.1.4's
/// `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` would
/// have admitted it. RFC 5234 §2.3 makes a `char-val` case-insensitive and
/// §12.4.2 says so in words as well — the parameter is "named "q"
/// (case-insensitive)" — so `Q=` is the same literal.
///
/// The trailing `OWS` an element may carry was taken by
/// `grammar::list_elements` before this ever runs, so a `qvalue` here reaches
/// the element's end.
fn read_weight(tail: &[u8]) -> Result<Weight, NegotiationError> {
  let after_ows = tail.get(skip_ows(tail, 0)..).unwrap_or_default();
  let (q, rest) = after_ows
    .split_first()
    .ok_or(NegotiationError::NotAWeight)?;
  if !q.eq_ignore_ascii_case(&b'q') {
    return Err(NegotiationError::NotAWeight);
  }
  let (eq, digits) = rest.split_first().ok_or(NegotiationError::NotAWeight)?;
  if *eq != b'=' {
    return Err(NegotiationError::NotAWeight);
  }
  parse_qvalue(digits).ok_or(NegotiationError::BadWeight)
}

/// Walks a field's elements, latching on the first fault.
///
/// The latch is not the one [`accept`](crate::media::accept) carries, and the
/// difference is worth having in one place. That walk latches because a member
/// it could not delimit leaves it unable to say where the NEXT one starts.
/// Here every boundary is known whatever else is wrong — no element admits a
/// DQUOTE, so every comma is the separator — and the walk stops anyway, for
/// the other half of that entry point's argument: a recipient that acts on the
/// well-formed suffix of a malformed field is the second of two recipients
/// disagreeing about a hostile one. A caller that wants the suffix has the
/// members in front of the fault and the fault itself, and decides for itself.
fn preferences<'a, I>(
  lines: I,
  element: Element,
) -> impl Iterator<Item = Result<Preference<'a>, NegotiationError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  lines
    .into_iter()
    .flat_map(list_elements)
    .map(move |member| preference_from(member, element))
    .scan(false, |done, item| {
      if *done {
        return None;
      }
      *done = item.is_err();
      Some(item)
    })
}

/// Walks an `Accept-Encoding` field's codings (RFC 9110 §12.5.3).
///
/// `Accept-Encoding  = #( codings [ weight ] )`, over
/// `codings          = content-coding / "identity" / "*"`. Takes the field's
/// LINES for the reason this module's own summary gives, and yields one
/// [`Preference`] per element in wire order.
///
/// # An empty field is not an absent one, and only the caller can tell
///
/// RFC 9110 §12.5.3: "An Accept-Encoding header field with a field value that
/// is empty implies that the user agent does not want any content coding in
/// response." — while rule 1 of the same section says that with no such field
/// "any content coding is considered acceptable by the user agent". Those are
/// opposite defaults, and this walk yields no member in either case: §5.6.1.2
/// has an empty element skipped, so an empty value has nothing to yield.
/// Whether the field was THERE is not a fact about the bytes, so it stays with
/// the caller, who is the one holding the lines.
///
/// # Errors
///
/// Each item is a [`NegotiationError`]:
/// [`NotAnElement`](NegotiationError::NotAnElement),
/// [`NotAWeight`](NegotiationError::NotAWeight) or
/// [`BadWeight`](NegotiationError::BadWeight). The walk yields nothing after
/// the first.
#[inline]
pub fn accept_encoding<'a, I>(
  lines: I,
) -> impl Iterator<Item = Result<Preference<'a>, NegotiationError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  preferences(lines, Element::Token)
}

/// What RFC 9110 §12.5.3 says about one content coding, for one
/// `Accept-Encoding` field.
///
/// Three states, because that section reaches its verdict through three
/// different sentences and collapsing them would report one where the reader
/// needs the other. [`is_acceptable`](Self::is_acceptable) is the verdict
/// §12.5.3 asks for; [`weight`](Self::weight) is the number §12.4.2 assigns,
/// when the field assigns one at all.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Acceptability {
  /// Acceptable, with NO weight named for it.
  ///
  /// Two of §12.5.3's rules land here, and neither states a weight. Rule 1:
  /// "If no Accept-Encoding header field is in the request, any content coding
  /// is considered acceptable by the user agent." Rule 2's default, for a
  /// representation with no content coding that the field does not
  /// specifically exclude.
  ///
  /// [`weight`](Self::weight) is `None` here rather than [`Weight::ONE`],
  /// because §12.4.2's default of 1 is what an ABSENT `q` on a PRESENT member
  /// means, and there is no member in either of these cases. Inventing a
  /// number would put a rank on a coding the field never ranked.
  AcceptableByDefault,
  /// The field named this weight for the coding — through an entry that names
  /// it, through the `"*"` entry that stands in for one, or through rule 2's
  /// `*;q=0`.
  ///
  /// Acceptable iff the weight is not [`Weight::ZERO`]. RFC 9110 §12.4.2: "a
  /// value of 0 means "not acceptable"".
  Weighed(Weight),
  /// Unacceptable because the field mentions it nowhere and carries no
  /// wildcard to stand in.
  ///
  /// RFC 9110 §12.4.3: "If no wildcard is present, values that are not
  /// explicitly mentioned in the field are considered unacceptable." A
  /// separate state from `Weighed(Weight::ZERO)` because the field said
  /// NOTHING here, where that one says zero: a caller reporting why it refused
  /// a coding can tell "you excluded it" from "you never mentioned it", and
  /// the two come from different sections.
  Unmentioned,
}

impl Acceptability {
  /// The verdict RFC 9110 §12.5.3 asks for: "A server tests whether a content
  /// coding for a given representation is acceptable using these rules".
  #[inline]
  pub const fn is_acceptable(self) -> bool {
    match self {
      Self::AcceptableByDefault => true,
      Self::Weighed(weight) => weight.thousandths() != Weight::ZERO.thousandths(),
      Self::Unmentioned => false,
    }
  }

  /// The weight the field named, or `None` where it named none.
  ///
  /// `None` is not "zero": [`Unmentioned`](Self::Unmentioned) is unacceptable
  /// with no weight, and [`AcceptableByDefault`](Self::AcceptableByDefault) is
  /// acceptable with no weight. Ranking is what this is for, and RFC 9110
  /// §12.5.3 ranks only among codings the field weighed: "When selecting
  /// between multiple content codings that have the same purpose, the
  /// acceptable content coding with the highest non-zero qvalue is preferred."
  #[inline]
  pub const fn weight(self) -> Option<Weight> {
    match self {
      Self::Weighed(weight) => Some(weight),
      Self::AcceptableByDefault | Self::Unmentioned => None,
    }
  }
}

/// Whether one content coding is acceptable to an `Accept-Encoding` field
/// (RFC 9110 §12.5.3).
///
/// `coding` is the representation's content coding, or `None` where the
/// representation HAS none — which is rule 2's subject and not a missing
/// argument. `lines` is the field's lines, and NO lines is an absent field,
/// which is rule 1's subject: a field is present exactly when at least one
/// field line names it, so `Accept-Encoding:` arrives as one line whose value
/// is empty and an absent field arrives as none at all.
///
/// Bytes rather than `&str` for the coding because a caller holds a scanned
/// `Content-Encoding` value, and because §8.4.1 settles the comparison: "All
/// content codings are case-insensitive".
///
/// # Every rule §12.5.3 states about acceptability, and where it is read
///
/// The section's three numbered rules do not close the question on their own —
/// they say nothing about a coding the field neither lists nor covers with
/// `"*"` — so two more sentences are read, and both are named here rather than
/// left inside the code.
///
/// 1. **Rule 1**, "If no Accept-Encoding header field is in the request, any
///    content coding is considered acceptable by the user agent." — no lines,
///    so [`Acceptability::AcceptableByDefault`], whatever `coding` is.
/// 2. **Rule 2**, "If the representation has no content coding, then it is
///    acceptable by default unless specifically excluded by the Accept-Encoding
///    header field stating either `identity;q=0` or `*;q=0` without a more
///    specific entry for `identity`." — `coding` is `None`. An entry naming
///    `identity` is that "more specific entry" and governs, weight and all; a
///    `*;q=0` with no such entry excludes; anything else is the default.
///    Note what this does NOT do: a `*;q=0.5` does not weigh a representation
///    that has no coding, because rule 2 names only `*;q=0` as reaching it.
/// 3. **Rule 3**, "If the representation's content coding is one of the content
///    codings listed in the Accept-Encoding field value, then it is acceptable
///    unless it is accompanied by a qvalue of 0." — an entry naming `coding`
///    governs.
/// 4. **§12.5.3's asterisk sentence**, "The asterisk "*" symbol in an
///    Accept-Encoding field matches any available content coding not explicitly
///    listed in the field." — a listed coding with no entry of its own takes
///    the `"*"` entry's weight.
/// 5. **§12.4.3**, "If no wildcard is present, values that are not explicitly
///    mentioned in the field are considered unacceptable." —
///    [`Acceptability::Unmentioned`]. This is the sentence that makes the
///    answer total; without it rules 1 to 3 leave a case with no verdict.
/// 6. **§12.5.3's empty-field sentence**, "An Accept-Encoding header field with
///    a field value that is empty implies that the user agent does not want any
///    content coding in response." — read as a CONSEQUENCE of 2, 3 and 5 rather
///    than as a case of its own: a field with no members mentions nothing and
///    carries no wildcard, so every coding is `Unmentioned` and a representation
///    with none is acceptable by default. That is what the sentence says, and a
///    special case for it would be a second answer to a question already
///    answered.
/// 7. **§12.5.3's response direction**, "The field value is evaluated the same
///    way as in a request." — so this one function serves both, and the
///    direction is not an argument.
///
/// # Two rules of §12.5.3 that this deliberately does not answer
///
/// Neither is an acceptability rule, and each needs an input that is not this
/// field and not this coding — the set of representations the responder holds.
///
/// - "When selecting between multiple content codings that have the same
///   purpose, the acceptable content coding with the highest non-zero qvalue is
///   preferred." That is a choice among alternatives, and it also needs to know
///   which codings have the same PURPOSE, which is in no field. What it ranks
///   by is [`Acceptability::weight`], asked once per candidate.
/// - "If a non-empty Accept-Encoding header field is present in a request and
///   none of the available representations for the response have a content
///   coding that is listed as acceptable, the origin server SHOULD send a
///   response without any content coding unless the identity coding is
///   indicated as unacceptable." That is how to build a response, over the
///   available representations.
///
/// Nothing here generates an `Accept-Encoding` either, so §12.5.3's own sender
/// rule is stated and not enforced, exactly as §12.5.5's is at
/// [`VaryMember::Wildcard`]: "servers that fail a request with a 415 status for
/// reasons unrelated to content codings MUST NOT include the Accept-Encoding
/// header field".
///
/// # A coding the field names twice
///
/// RFC 9110 settles no rule for a repeated entry, so this takes one and says
/// so. A zero ANYWHERE among the entries naming a coding makes it
/// `Weighed(Weight::ZERO)`, which is rule 3's own wording read plainly — a
/// coding listed twice, once with `q=0`, is a coding "accompanied by a qvalue
/// of 0" — and it is the reading that does not depend on order, so two
/// recipients cannot disagree by reading the same field from different ends.
/// Where no entry is zero, the LAST in wire order gives the weight, which is
/// the rule this crate already applies to a repeated `q` inside one member.
///
/// # Errors
///
/// [`NegotiationError`], from the walk beneath this: the field must parse
/// before it can be asked anything. The walk latches, so this reports the first
/// fault and nothing after it.
pub fn encoding_acceptability<'a, I>(
  coding: Option<&[u8]>,
  lines: I,
) -> Result<Acceptability, NegotiationError>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  // Rule 2's "more specific entry" is an entry naming `identity`, so a
  // representation with no coding is matched against that name. RFC 9110
  // §12.5.3: "An "identity" token is used as a synonym for "no encoding" in
  // order to communicate when no encoding is preferred."
  let wanted = coding.unwrap_or(IDENTITY);
  let mut lines_seen = 0usize;
  let mut named: Option<Weight> = None;
  let mut wildcard: Option<Weight> = None;
  for member in accept_encoding(
    lines
      .into_iter()
      .inspect(|_| lines_seen = lines_seen.saturating_add(1)),
  ) {
    let preference = member?;
    match preference.name() {
      None => wildcard = Some(absorbing_zero(wildcard, preference.weight())),
      Some(name) if name.as_bytes().eq_ignore_ascii_case(wanted) => {
        named = Some(absorbing_zero(named, preference.weight()));
      }
      Some(_) => {}
    }
  }
  if lines_seen == 0 {
    // Rule 1. Asked before anything else, because it is about the field's
    // presence and not about its content.
    return Ok(Acceptability::AcceptableByDefault);
  }
  Ok(match (coding, named, wildcard) {
    // Rules 2 and 3: an entry that names it governs, whatever it says.
    (_, Some(weight), _) => Acceptability::Weighed(weight),
    // Rule 2, the `*;q=0` half: it is the only weight a wildcard entry lends a
    // representation that has no coding at all.
    (None, None, Some(weight)) if weight == Weight::ZERO => Acceptability::Weighed(Weight::ZERO),
    // Rule 2's default, reached with no `identity` entry and no `*;q=0`.
    (None, None, _) => Acceptability::AcceptableByDefault,
    // §12.5.3's asterisk sentence: `*` stands in for a coding not listed.
    (Some(_), None, Some(weight)) => Acceptability::Weighed(weight),
    // §12.4.3: nothing mentions it and there is no wildcard.
    (Some(_), None, None) => Acceptability::Unmentioned,
  })
}

/// Folds a second weight for one name onto the first, with zero absorbing.
///
/// See [`encoding_acceptability`]'s own doc for why a repeat is resolved this
/// way and what RFC 9110 does and does not settle about it.
fn absorbing_zero(seen: Option<Weight>, found: Weight) -> Weight {
  match seen {
    Some(previous) if previous == Weight::ZERO => previous,
    _ => found,
  }
}

/// Walks an `Accept-Language` field's ranges (RFC 9110 §12.5.4).
///
/// `Accept-Language = #( language-range [ weight ] )`, over the basic language
/// range RFC 9110 hands out to RFC 4647 §2.1 — see
/// [`Element::LanguageRange`] for the rule and for which of RFC 4647's two
/// ranges it is. Yields one [`Preference`] per element in wire order, and
/// [`Preference::name`] is `None` for the wildcard `*`.
///
/// # Wire order is not priority, and this hands over the order it read
///
/// RFC 9110 §12.5.4: "Note that some recipients treat the order in which
/// language tags are listed as an indication of descending priority,
/// particularly for tags that are assigned equal quality values (no value is
/// the same as q=1). However, this behavior cannot be relied upon." So the
/// order is a fact about the field rather than a ranking this crate may apply,
/// and the walk yields elements in the order the sender wrote them without
/// deriving anything from it. Ranking is [`Preference::weight`]'s, which is the
/// derivation §12.4.2 settles.
///
/// # Matching is not here
///
/// RFC 9110 §12.5.4: "For matching, Section 3 of \[RFC4647\] defines several
/// matching schemes. Implementations can offer the most appropriate matching
/// scheme for their requirements." Which scheme is appropriate is not a
/// function of the field's bytes — it depends on the representations a
/// responder holds — so it is the caller's, exactly as choosing a
/// representation from an `Accept` weight is.
///
/// That sentence is why there is no `Accept-Language` counterpart to
/// [`encoding_acceptability`]. §12.5.3 states its acceptability rules itself
/// and they are answerable from a coding and a field; §12.5.4 states none and
/// hands the question to RFC 4647 §3's several schemes, so a function here
/// would be picking one of them on the caller's behalf.
///
/// # Errors
///
/// Each item is a [`NegotiationError`]:
/// [`NotAnElement`](NegotiationError::NotAnElement),
/// [`NotAWeight`](NegotiationError::NotAWeight) or
/// [`BadWeight`](NegotiationError::BadWeight). The walk yields nothing after
/// the first.
#[inline]
pub fn accept_language<'a, I>(
  lines: I,
) -> impl Iterator<Item = Result<Preference<'a>, NegotiationError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  preferences(lines, Element::LanguageRange)
}

/// Walks an `Accept-Charset` field's charsets (RFC 9110 §12.5.2).
///
/// `Accept-Charset = #( ( token / "*" ) [ weight ] )`. Yields one
/// [`Preference`] per element in wire order, with [`Preference::name`] `None`
/// for the wildcard: §12.5.2 says "The special value "*", if present in the
/// Accept-Charset header field, matches every charset that is not mentioned
/// elsewhere in the field."
///
/// # This field is deprecated, and what is deprecated is SENDING it
///
/// RFC 9110 §12.5.2's Note: "Accept-Charset is deprecated because UTF-8 has
/// become nearly ubiquitous and sending a detailed list of user-preferred
/// charsets wastes bandwidth, increases latency, and makes passive
/// fingerprinting far too easy". Every clause of that is about a sender —
/// "Most general-purpose user agents do not send Accept-Charset unless
/// specifically configured to do so." — and this crate is on the other side of
/// the wire. A recipient still meets the field, because a deprecation does not
/// unsend what is already deployed, and a recipient that cannot read it has no
/// way to honour or to ignore it deliberately.
///
/// So the Note is the reason this reader EXISTS, and it is also the reason
/// nothing in this crate writes an `Accept-Charset`. There is no encoder here
/// and none is owed: a caller that generates one is doing the deprecated half,
/// and that decision is not this crate's to make for it.
///
/// # The element is `token` — the RFC spells no `charset` rule
///
/// RFC 9110 §12.5.2's ABNF writes `( token / "*" )` and not a `charset`
/// production, and §8.3.2 defines charset names in prose instead. Its Note
/// says where the difference falls: "In theory, charset names are defined by
/// the "mime-charset" ABNF rule defined in Section 2.3 of \[RFC2978\] (as
/// corrected in \[Err1912\]). That rule allows two characters that are not
/// included in "token" ("{" and "}"), but no charset name registered at the
/// time of this writing includes braces". This reader implements the rule the
/// FIELD spells — §5.6.2's `token` — so `a{b}` is refused here, which is what
/// §12.5.2's own grammar says of it whatever a registry might one day hold.
///
/// # Errors
///
/// Each item is a [`NegotiationError`]:
/// [`NotAnElement`](NegotiationError::NotAnElement),
/// [`NotAWeight`](NegotiationError::NotAWeight) or
/// [`BadWeight`](NegotiationError::BadWeight). The walk yields nothing after
/// the first.
#[inline]
pub fn accept_charset<'a, I>(
  lines: I,
) -> impl Iterator<Item = Result<Preference<'a>, NegotiationError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  preferences(lines, Element::Token)
}

/// One member of a `Vary` field: RFC 9110 §12.5.5's `"*" / field-name`.
///
/// Borrows the field lines it was parsed from.
///
/// # No `PartialEq`
///
/// For the reason [`Preference`] carries none, on RFC 9110 §5.1's sentence
/// rather than §8.4.1's: "Field names are case-insensitive", so a derive would
/// call `Accept-Encoding` and `accept-encoding` two members while they name one
/// field. A caller compares with `str::eq_ignore_ascii_case`, or with
/// [`eq_ignore_ascii`](crate::grammar::eq_ignore_ascii) against a name it
/// knows.
#[derive(Debug, Copy, Clone)]
pub enum VaryMember<'a> {
  /// The `"*"` alternative.
  ///
  /// RFC 9110 §12.5.5: "A list containing the member "*" signals that other
  /// aspects of the request might have played a role in selecting the response
  /// representation, possibly including aspects outside the message syntax
  /// (e.g., the client's network address)." §12.4.3 puts it in one sentence:
  /// "Within Vary, the wildcard value means that the variance is unlimited."
  ///
  /// It is a MEMBER and not a whole value, which is why it is a variant of an
  /// item rather than a state of the walk: §12.5.5 writes
  /// `Vary = #( "*" / field-name )`, so `*, accept-encoding` is one list of two
  /// members and this is the first of them.
  ///
  /// # The §12.5.5 rule this crate does not enforce, and what would enforce it
  ///
  /// RFC 9110 §12.5.5: "A proxy MUST NOT generate "*" in a Vary field value."
  /// It is STATED here and nothing checks it, and both halves of that are
  /// deliberate.
  ///
  /// It binds a GENERATOR that is a proxy. This crate generates no `Vary` at
  /// all — there is no encoder for this field here — so there is no site the
  /// rule could be applied at, and adding one to have something to check would
  /// be inventing the machinery the rule governs rather than obeying it. What
  /// enforcement needs is a `Vary` writer plus the knowledge that the caller is
  /// an intermediary, and the second of those is not a fact about any bytes
  /// this crate reads.
  ///
  /// Whether this workspace serves an intermediary at all is an open ruling in
  /// al8n/wren#70 — the same absence that leaves §7.6.2's `Max-Forwards` and
  /// §7.6.3's `Via` unfiled — so the rule is unenforced pending a decision that
  /// is recorded elsewhere rather than by oversight here.
  ///
  /// What a proxy that DOES generate a `Vary` needs in order to obey it is the
  /// fact that this variant is: a caller re-emitting the members it read knows
  /// from the variant alone which one it may not write.
  Wildcard,
  /// The `field-name` alternative — RFC 9110 §5.1's
  /// `field-name     = token`.
  ///
  /// A member that is exactly `*` is [`Wildcard`](Self::Wildcard) and never
  /// this, though `*` is a §5.6.2 `tchar` and so a `token` the second
  /// alternative would also derive. §12.5.5 settles which reading applies: "A
  /// Vary field value is either the wildcard member "*" or a list of request
  /// field names, known as the selecting header fields, that might have had a
  /// role in selecting the representation for this response."
  ///
  /// Not checked against any registry. RFC 9110 §12.5.5: "Potential selecting
  /// header fields are not limited to fields defined by this specification."
  FieldName(&'a str),
}

/// Why a [`vary`] walk stopped.
///
/// One variant, and no weight variants: RFC 9110 §12.5.5's
/// `Vary = #( "*" / field-name )` brackets no `[ weight ]`, so
/// [`NegotiationError`]'s other two conditions cannot arise here and a shared
/// error type would give this walk's `Result` two states it can never hold.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum VaryError {
  /// The member is neither `"*"` nor RFC 9110 §5.1's `field-name     = token`.
  #[error("not a field name")]
  NotAFieldName,
}

/// Walks a `Vary` field's members (RFC 9110 §12.5.5).
///
/// `Vary = #( "*" / field-name )`. Takes the field's LINES like the ranked
/// readers above, and for the same reason: §5.2 may spread the list over
/// several of them, and no member can hold the comma the join inserts.
///
/// RFC 9110 §12.5.5: "The "Vary" header field in a response describes what
/// parts of a request message, aside from the method and target URI, might
/// have influenced the origin server's process for selecting the content of
/// this response."
///
/// # What this answers and what it does not
///
/// It answers which members the field named, in wire order, and which of them
/// is §12.5.5's wildcard. It answers nothing about what a recipient should DO
/// with them: §12.5.5's two purposes are a cache's rule, which RFC 9111 §4.1
/// owns, and a user agent's, and both need state that is not in this field's
/// bytes. The one consequence stated here rather than derived is
/// [`VaryMember::Wildcard`]'s: "A recipient will not be able to determine
/// whether this response is appropriate for a later request without forwarding
/// the request to the origin server."
///
/// Like the ranked walks, this one latches: nothing is yielded after the first
/// fault.
///
/// # Errors
///
/// Each item is [`VaryError::NotAFieldName`].
pub fn vary<'a, I>(lines: I) -> impl Iterator<Item = Result<VaryMember<'a>, VaryError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  lines
    .into_iter()
    .flat_map(list_elements)
    .map(vary_member)
    .scan(false, |done, item| {
      if *done {
        return None;
      }
      *done = item.is_err();
      Some(item)
    })
}

/// Reads one already-delimited `Vary` element.
fn vary_member(member: &[u8]) -> Result<VaryMember<'_>, VaryError> {
  if member == WILDCARD {
    return Ok(VaryMember::Wildcard);
  }
  if is_token(member) {
    Ok(VaryMember::FieldName(ascii(member)))
  } else {
    Err(VaryError::NotAFieldName)
  }
}

#[cfg(test)]
mod tests;
