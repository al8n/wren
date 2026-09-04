//! The RFC 9110 §12.5 content negotiation fields whose element carries no
//! parameters: §12.5.2's `Accept-Charset`, §12.5.3's `Accept-Encoding` and
//! §12.5.4's `Accept-Language`.
//!
//! One walk serves them. Each is a §5.6.1 list of a bare name with RFC 9110
//! §12.4.2's weight optionally hung off it, and the only thing that separates
//! one from another is which names its element production admits:
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
/// production, and §8.3.2 defines charset names in prose instead — in theory
/// out of RFC 2978 §2.3's `mime-charset` rule, of which §8.3.2's Note says:
/// "That rule allows two characters that are not included in "token" ("{" and
/// "}"), but no charset name registered at the time of this writing includes
/// braces". This reader implements the rule the FIELD spells — §5.6.2's
/// `token` — so `a{b}` is refused here, which is what §12.5.2's own grammar
/// says of it whatever a registry might one day hold.
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

#[cfg(test)]
mod tests;
