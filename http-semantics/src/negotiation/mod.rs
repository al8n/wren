//! The RFC 9110 §12.5 content negotiation fields whose element carries no
//! parameters: §12.5.2's `Accept-Charset`, §12.5.3's `Accept-Encoding`,
//! §12.5.4's `Accept-Language` and §12.5.5's `Vary`. One walk serves the first
//! three — each is a §5.6.1 list of a bare name with RFC 9110 §12.4.2's weight
//! optionally hung off it, and only the element production separates them.
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
//! [`vary`] is here and is NOT that walk, because §12.5.5 is not that shape:
//!
//! ```text
//! Vary = #( "*" / field-name )
//! field-name     = token
//! ```
//!
//! No `[ weight ]` bracket, so nothing for §12.4.2 to rank, and its `"*"` is an
//! alternative of the ELEMENT rather than a name the `token` alternative also
//! derives; it shares the §5.6.1 list split and nothing else. §12.5.4's element
//! is the one RFC 9110 does not spell — that `prose-val` sends a reader to RFC
//! 4647 §2.1, transcribed at [`accept_language`] — and §12.5.1's `Accept` is
//! elsewhere, since its element is a media range that
//! [`accept`](crate::media::accept) reads in [`crate::media`].
//!
//! # §12.5.1's `q` rule does not transfer, and does not need to
//!
//! RFC 9110 §12.5.1 tells a recipient this: "Recipients SHOULD process any
//! parameter named "q" as weight, regardless of parameter ordering." An
//! `Accept` reader needs it because a `media-range` CARRIES parameters, so where
//! among them the weight sits is the sender's choice. An element here carries
//! none — `codings` and §12.5.2's `( token / "*" )` are `token`s, and RFC 4647
//! §2.1's `language-range` is ALPHA, DIGIT, `-` and `*` and no other byte — so
//! the only production a `;` inside one can open is `[ weight ]`, there is at
//! most one, and ORDER is not a question anybody can ask.
//!
//! **Importing `Accept`'s parameter handling would not be harmless**: §5.6.6's
//! `parameter` admits three things §12.4.2's `weight` does not, and each changes
//! an answer. A quoted value — §5.6.6 says "The quoted and unquoted values are
//! equivalent." and `weight` spells `qvalue` with no `quoted-string`
//! alternative, so `gzip;q="0.5"` is [`NegotiationError::BadWeight`]. A
//! repetition — `parameters = *( OWS ";" OWS [ parameter ] )` repeats and
//! `[ weight ]` brackets one. And a comma inside a value, the one that moves a
//! BOUNDARY rather than a verdict and why [`accept`](crate::media::accept)
//! resolves member ends itself: no production reachable from an element here
//! admits a DQUOTE, so every comma is the separator, [`list_elements`] splits
//! the elements, and a line boundary does nothing either — RFC 9110 §5.2's join
//! inserts a comma no element may hold.
//!
//! # `coding-corpus` grades none of these productions
//!
//! Asked because that harness exists for several readers of ONE production each
//! tested from the reading that produced it, which is how al8n/wren#76 happened.
//! No element production here is in it — §8.4.1 writes
//! `content-coding   = token` where §10.1.4 writes
//! `transfer-coding    = token *( OWS ";" OWS transfer-parameter )`, and RFC
//! 4647's `language-range` is in no RFC 9110 rule — and nothing shared is read a
//! second time: §5.6.1's list split, §5.6.2's `token` and §12.4.2's `qvalue` each
//! have one implementation, which this calls.

use crate::{
  grammar::{is_token, list_elements, skip_ows, trim_ows},
  media::{Weight, ascii, parse_qvalue},
};

/// RFC 9110 §12.4.3's wildcard, spelled once.
const WILDCARD: &[u8] = b"*";

/// RFC 9110 §12.5.3's synonym for no encoding, spelled once.
const IDENTITY: &[u8] = b"identity";

/// The longest subtag RFC 4647 §2.1's `language-range` admits, in either
/// position.
const MAX_SUBTAG: usize = 8;

/// Why a content negotiation walk stopped. Every variant is a fault of the
/// SENDER's: none of these fields bounds anything this crate has to bound for
/// it, so there is no limit-of-the-walk variant of the kind
/// `media::MediaError::TooManyParameters` is.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum NegotiationError {
  /// The element is not the production its field spells — for
  /// [`accept_encoding`], not RFC 9110 §12.5.3's
  /// `codings          = content-coding / "identity" / "*"`.
  #[error("not an element of this negotiation field")]
  NotAnElement,
  /// The `"q="` literal in RFC 9110 §12.4.2's
  /// `weight = OWS ";" OWS "q=" qvalue` did not match at the start of what
  /// follows the element's `;`: a parameter by another name, a `q` with the
  /// `BWS` in front of the `=` that this production writes nowhere, or nothing
  /// behind the `;` at all. A SECOND `;q=` is NOT this, and the production says
  /// so — `#( codings [ weight ] )` brackets one weight, so once the literal
  /// has matched, everything to the element's end is the `qvalue` slot. Measured,
  /// `gzip;q=0.5;q=0.7`, `gzip;q=0.5;p=1` and `gzip;q=0.5;` all answer
  /// [`BadWeight`](Self::BadWeight), and
  /// `what_follows_a_matched_q_is_the_qvalue_slot` pins the partition.
  #[error("what follows the element is not a weight")]
  NotAWeight,
  /// A `q` in the place RFC 9110 §12.4.2's `weight` puts one, whose value is
  /// not that section's
  /// `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
  #[error("the weight's value is not a qvalue")]
  BadWeight,
}

/// Which names an element may be, per the field being read — a field's own
/// value rather than a `fn(&[u8]) -> bool` the walk is handed, because two
/// shims reaching one instantiation through two pointer values leave the
/// indirect call un-devirtualized and empty both `no-panic` proofs at once,
/// which `tests/no_panic.rs` records.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Element {
  /// RFC 9110 §5.6.2's `token          = 1*tchar`, the whole of what §12.5.3's
  /// `codings` admits and of what §12.5.2's element does: `content-coding
  /// = token`, and `identity` and `*` are `token`s, so `codings` and §12.5.2's
  /// `( token / "*" )` derive ONE language. The two fields share this arm for
  /// that reason and not for convenience, which
  /// `charset_and_encoding_read_one_element_language` pins over both entry
  /// points; what each section says a name MEANS is [`Preference::name`]'s.
  Token,
  /// RFC 4647 §2.1's basic language range, which RFC 9110 §12.5.4 hands out to
  /// that spec rather than spelling; transcribed at [`accept_language`], where
  /// a reader of the public API meets it. It is inside [`Token`](Self::Token),
  /// so the choice between these two arms narrows what an element may be and
  /// can never move where one ENDS.
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
/// `alphanum         = ALPHA / DIGIT`. Read as the rule GENERATES, not off the
/// examples RFC 9110 §12.5.4 shows: the two subtag positions are NOT the same
/// rule, so `en-us-1` is a `language-range` and `1-en` is not, and [`MAX_SUBTAG`]
/// bounds every position. That DIGIT is RFC 4647 §2.1's correction
/// to RFC 2616's version, which "is incorrect, since it disallows the use of
/// digits anywhere in the 'language-range'".
fn is_language_range(name: &[u8]) -> bool {
  if name == WILDCARD {
    return true;
  }
  let mut subtags = name.split(|&b| b == b'-');
  // A `split` yields a first part over any slice, so the default is an argument
  // rather than an `unwrap`; an empty `name` is one empty part and fails below.
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
/// weight the sender hung off it. Borrows the field lines it was parsed from.
///
/// # No `PartialEq`
///
/// For the reason `media::MediaRange` carries none: a derive compares bytes as
/// WRITTEN, and each name this can hold is matched case-insensitively — RFC
/// 9110 §8.4.1: "All content codings are case-insensitive"; RFC 4647 §2:
/// "Matching of language tags to language ranges MUST be done in a
/// case-insensitive manner." Compare [`name`](Self::name) with
/// `str::eq_ignore_ascii_case`.
#[derive(Debug, Copy, Clone)]
pub struct Preference<'a> {
  name: Option<&'a [u8]>,
  weight: Weight,
}

impl<'a> Preference<'a> {
  /// The element's name, or `None` for the wildcard `*` — a different answer
  /// rather than a `Some("*")` every caller would have to remember to test for.
  /// A name that MEANS something is still a name, so `identity` reports
  /// `Some("identity")` and is not the wildcard.
  #[inline]
  pub const fn name(&self) -> Option<&'a str> {
    match self.name {
      Some(bytes) => Some(ascii(bytes)),
      None => None,
    }
  }

  /// Whether this member is the wildcard `*`.
  #[inline]
  pub const fn is_wildcard(&self) -> bool {
    self.name.is_none()
  }

  /// The weight. RFC 9110 §12.4.2: "If no "q" parameter is present, the default
  /// weight is 1."
  #[inline]
  pub const fn weight(&self) -> Weight {
    self.weight
  }
}

/// Reads one already-delimited element as a name and an optional weight, split
/// on the FIRST `;` — enough for RFC 9110 §12.4.2's
/// `weight = OWS ";" OWS "q=" qvalue`, since `;` is no §5.6.2 `tchar`: no
/// element name reaches one and a second `;` lands inside a `qvalue`.
fn preference_from(member: &[u8], element: Element) -> Result<Preference<'_>, NegotiationError> {
  let mut halves = member.splitn(2, |&b| b == b';');
  // `splitn` yields a first part over any slice and `list_elements` hands out
  // no empty member, so the default is an argument rather than an `unwrap`.
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
/// its `;`. `"q="` is one `char-val`, so nothing may stand between `q` and `=`:
/// `gzip;q = 0.5` is [`NegotiationError::NotAWeight`], where §10.1.4's
/// `transfer-parameter = token BWS "=" BWS ( token / quoted-string )` would have
/// admitted it. §12.4.2 makes the parameter "named "q" (case-insensitive)", so
/// `Q=` is the same literal.
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

/// Walks a field's elements, latching on the first fault — not for the reason
/// [`accept`](crate::media::accept) latches, since every boundary here is known
/// whatever else is wrong, but for the other half of that entry point's
/// argument: a recipient acting on the well-formed suffix of a malformed field
/// is the second of two disagreeing about a hostile one.
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

/// Walks an `Accept-Encoding` field's codings (RFC 9110 §12.5.3):
/// `Accept-Encoding  = #( codings [ weight ] )`, over
/// `codings          = content-coding / "identity" / "*"`. Takes the field's
/// LINES for the reason this module's own summary gives, and yields one
/// [`Preference`] per element in wire order. An EMPTY field is not an absent
/// one, and this walk yields no member for either, while §12.5.3 gives them
/// opposite defaults — its rules 1 and 6 at [`encoding_acceptability`]. Which
/// one it was is no fact about the bytes and stays with the caller.
///
/// # Errors
///
/// Each item is a [`NegotiationError`]; nothing is yielded after the first.
#[inline]
pub fn accept_encoding<'a, I>(
  lines: I,
) -> impl Iterator<Item = Result<Preference<'a>, NegotiationError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  preferences(lines, Element::Token)
}

/// Which message an `Accept-Encoding` field was read from.
///
/// RFC 9110 §12.5.3 gives the field a job in each direction and writes one of
/// its rules for one direction only, which is why this is an argument rather
/// than something [`encoding_acceptability`] could infer. Only the ABSENT field
/// parts the two: rule 7 has a field that is there read alike whichever message
/// carried it, "The field value is evaluated the same way as in a request."
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Direction {
  /// The field was in a request, the direction RFC 9110 §12.5.3's rule 1 is
  /// written about: "If no Accept-Encoding header field is in the request, any
  /// content coding is considered acceptable by the user agent."
  Request,
  /// The field was in a response, where §12.5.3 gives an ABSENT field no meaning
  /// at all: it speaks of one that is there — "When the Accept-Encoding header
  /// field is present in a response, it indicates what content codings the
  /// resource was willing to accept in the associated request." See
  /// [`Acceptability::NotAdvertised`].
  Response,
}

/// What RFC 9110 §12.5.3 says about one content coding, for one
/// `Accept-Encoding` field. Separate states because that section reaches each
/// through a different sentence, and collapsing them would report one where a
/// reader needs the other.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Acceptability {
  /// Acceptable, with NO weight named for it: §12.5.3's rule 1 and rule 2's
  /// default, neither of which states one. So [`weight`](Self::weight) is `None`
  /// rather than [`Weight::ONE`] — §12.4.2's default of 1 is what an ABSENT `q`
  /// on a PRESENT member means.
  AcceptableByDefault,
  /// The field named this weight — through an entry that names the coding, or
  /// through the `"*"` entry that stands in for one. Acceptable iff the weight
  /// is not [`Weight::ZERO`]. RFC 9110 §12.4.2: "a value of 0 means "not
  /// acceptable"". A representation with no content coding reaches this through
  /// an entry naming `identity`, and through exactly one wildcard, rule 2's
  /// `*;q=0`; see [`encoding_acceptability`]'s derivation for why no other does.
  Weighed(Weight),
  /// Unacceptable because the field mentions it nowhere and carries no wildcard
  /// to stand in. RFC 9110 §12.4.3: "If no wildcard is present, values that are
  /// not explicitly mentioned in the field are considered unacceptable."
  /// Separate from `Weighed(Weight::ZERO)`: the field said NOTHING here where
  /// that one says zero, and the two come from different sections.
  Unmentioned,
  /// [`Direction::Response`] with no field at all: RFC 9110 §12.5.3 says
  /// nothing about this case, so neither does this. **Not a verdict, which is
  /// why [`is_acceptable`](Self::is_acceptable) answers `None` here.** §12.5.3's
  /// absence rule is written about the request and gives a response's field
  /// meaning only when it is PRESENT — both sentences are at [`Direction`].
  /// Answering [`AcceptableByDefault`](Self::AcceptableByDefault) instead
  /// extends rule 1 across the direction it names, telling a client that a
  /// server which said nothing accepts everything — which the client can act on
  /// by encoding its next request.
  NotAdvertised,
}

impl Acceptability {
  /// The verdict RFC 9110 §12.5.3 asks for: "A server tests whether a content
  /// coding for a given representation is acceptable using these rules".
  /// `None` where the section reaches no verdict, which is
  /// [`NotAdvertised`](Self::NotAdvertised) and nothing else: both bools would
  /// be wrong there, since `true` says a server that advertised nothing accepts
  /// this coding and `false` says it refuses one it may well accept.
  #[inline]
  pub const fn is_acceptable(self) -> Option<bool> {
    match self {
      Self::AcceptableByDefault => Some(true),
      Self::Weighed(weight) => Some(weight.thousandths() != Weight::ZERO.thousandths()),
      Self::Unmentioned => Some(false),
      Self::NotAdvertised => None,
    }
  }

  /// The weight the field named, or `None` where it named none — which is not
  /// "zero", since [`Unmentioned`](Self::Unmentioned) is unacceptable with no
  /// weight. RFC 9110 §12.5.3 ranks only among codings the field weighed: "When
  /// selecting between multiple content codings that have the same purpose, the
  /// acceptable content coding with the highest non-zero qvalue is preferred."
  #[inline]
  pub const fn weight(self) -> Option<Weight> {
    match self {
      Self::Weighed(weight) => Some(weight),
      Self::AcceptableByDefault | Self::Unmentioned | Self::NotAdvertised => None,
    }
  }
}

/// Whether one content coding is acceptable to an `Accept-Encoding` field
/// (RFC 9110 §12.5.3).
///
/// `coding` is the representation's content coding, or `None` where it HAS
/// none, which is rule 2's subject and not a missing argument. NO lines is an
/// absent field: a field is present exactly when a field line names it, so
/// `Accept-Encoding:` arrives as one line whose value is empty and an absent
/// field as none. Bytes rather than `&str` because §8.4.1 settles the
/// comparison: "All content codings are case-insensitive".
///
/// # Every rule §12.5.3 states about acceptability, and where it is read
///
/// Its three numbered rules say nothing about a coding the field neither lists
/// nor covers with `"*"`, so two more sentences are read.
///
/// 1. **Rule 1**, "If no Accept-Encoding header field is in the request, any
///    content coding is considered acceptable by the user agent." — no lines
///    AND [`Direction::Request`], so [`Acceptability::AcceptableByDefault`]
///    whatever `coding` is. The rule names its direction, so no lines on a
///    RESPONSE answers [`Acceptability::NotAdvertised`] instead.
/// 2. **Rule 2**, "If the representation has no content coding, then it is
///    acceptable by default unless specifically excluded by the Accept-Encoding
///    header field stating either `identity;q=0` or `*;q=0` without a more
///    specific entry for `identity`." — `coding` is `None`, or names `identity`,
///    which is the same state; see the section below. An entry naming
///    `identity` is that "more specific entry" and governs; failing that a
///    `*;q=0`, and only a zero one, excludes; failing both, the DEFAULT, which
///    is the one place the no-coding case parts from a named one.
/// 3. **Rule 3**, "If the representation's content coding is one of the content
///    codings listed in the Accept-Encoding field value, then it is acceptable
///    unless it is accompanied by a qvalue of 0." — an entry naming `coding`
///    governs.
/// 4. **§12.5.3's asterisk sentence**, "The asterisk "*" symbol in an
///    Accept-Encoding field matches any available content coding not explicitly
///    listed in the field." — a coding with no entry of its own takes the `"*"`
///    entry's weight.
/// 5. **§12.4.3**, "If no wildcard is present, values that are not explicitly
///    mentioned in the field are considered unacceptable." —
///    [`Acceptability::Unmentioned`], and the sentence that makes the answer
///    total; without it rules 1 to 3 leave a case with no verdict.
/// 6. **§12.5.3's empty-field sentence**, "An Accept-Encoding header field with
///    a field value that is empty implies that the user agent does not want any
///    content coding in response." — a CONSEQUENCE of 2, 3 and 5 and not a case
///    of its own: a field with no members mentions nothing and carries no
///    wildcard, so every coding is `Unmentioned` and a representation with none
///    is acceptable by default.
/// 7. **§12.5.3's response direction**, "When the Accept-Encoding header field
///    is present in a response, it indicates what content codings the resource
///    was willing to accept in the associated request. The field value is
///    evaluated the same way as in a request." — a PRESENT response field, read
///    by 2 to 6 exactly as a request's is, so `direction` decides only that.
///
/// # `identity` and no coding at all are one state, and `"*"` reaches it only
/// at zero
///
/// Two independent derivations; getting either wrong makes one representation
/// get two answers depending on how a caller spells it. **A representation does
/// not HAVE the coding `identity`.** RFC 9110 §12.5.3: "An "identity" token is
/// used as a synonym for "no encoding" in order to
/// communicate when no encoding is preferred." §8.4 makes that exclusive:
/// "Note that the coding named "identity" is reserved for its special role in
/// Accept-Encoding and thus SHOULD NOT be included." — in a `Content-Encoding` —
/// and §18.6's registry gives the name the description `Reserved`. So `None` and
/// `Some(b"identity")` name one representation state, normalised onto one path
/// case-insensitively per §8.4.1's "All content codings are case-insensitive".
/// **A `"*"` entry reaches that state only at zero, and rule 2 is the whole of
/// why it reaches it at all.** Either `"*"` matches this state like any other
/// and lends it whatever weight it carries, or it does not and rule 2 separately
/// names `*;q=0` as an excluder. This module derived it each way in successive
/// rounds; what settled it was asking which reading leaves rule 2's own sentence
/// work to do, rather than arguing from what the section does not say.
///
/// - **Rule 2's `*;q=0` clause is load-bearing under one reading and decorative
///   under the other.** If `"*"` matched this state generally, the clause would
///   follow from the asterisk sentence plus §12.4.2's "a value of 0 means "not
///   acceptable"", and so would `identity;q=0`, and so would "without a more
///   specific entry for `identity`": everything after "acceptable by default"
///   would restate machinery stated elsewhere. If `"*"` does not match it, rule
///   2 is the only source of that exclusion and its precedence sub-clause keeps
///   an explicit `identity` entry ahead of it. The section marks its
///   restatements where it makes one — rule 3 carries "As defined in Section
///   12.4.2, a qvalue of 0 means "not acceptable"." in a parenthesis, rule 2
///   none.
/// - **The asterisk sentence is quantified over something this state is not.**
///   It matches "any available content coding not explicitly listed in the
///   field", and §8.4 has a representation's codings listed in
///   `Content-Encoding` with `identity` reserved out, so this state has none.
/// - **The grammar separates the two.** `codings = content-coding / "identity" /
///   "*"` gives `identity` an alternative of its own, so a rule quantified over
///   a `content-coding` does not reach it — a SEMANTIC separation, since the
///   three alternatives derive one language and one element rule reads them.
///
/// §12.5.3's own example is NEUTRAL and is reported as such rather than pressed
/// into service: `Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0` pairs an
/// explicit `identity` entry with `*;q=0`, and both readings answer it alike.
/// What the REJECTED reading costs is the opposite of how it looked: over
/// `Accept-Encoding: *;q=0.001, gzip;q=0.5` it hands the uncoded representation
/// `Weighed(1)`, ranking it below `gzip` and turning a status rule 2 states
/// unconditionally into a near-refusal the field never wrote.
///
/// # The domain: ONE coding, and a present field
///
/// Two narrowings, neither visible from the signature. **One coding, where a
/// representation may carry several:** RFC 9110 §12.5.3 says "A representation
/// could be encoded with multiple content codings.", but its rules are stated
/// over one — "A server tests whether a content coding for a given
/// representation is acceptable using these rules" — so a caller holding two
/// asks twice. **A field that is there:** rule 7's response direction is written
/// for a PRESENT field and rule 1's absence case for the REQUEST, so an absent
/// response field answers [`Acceptability::NotAdvertised`] rather than extending
/// rule 1 across the direction it names.
///
/// # Two rules of §12.5.3 that this deliberately does not answer
///
/// Neither is an acceptability rule, and each needs the set of representations
/// the responder holds: the ranking among codings that "have the same purpose",
/// at [`Acceptability::weight`], and what to send when nothing listed is
/// acceptable — "If a non-empty Accept-Encoding header field is present in a
/// request and none of the available representations for the response have a
/// content coding that is listed as acceptable, the origin server SHOULD send a
/// response without any content coding unless the identity coding is indicated
/// as unacceptable." Nothing here generates an `Accept-Encoding`, so §12.5.3's
/// own sender rule is stated and not enforced, as §12.5.5's is at
/// [`VaryMember::Wildcard`]: "servers that fail a request with a 415 status for
/// reasons unrelated to content codings MUST NOT include the Accept-Encoding
/// header field".
///
/// # One walk per coding asked about, deliberately
///
/// A caller ranking five candidates walks the field five times: one pass would
/// mean a weight per candidate, which is storage this crate has no way to grow
/// and would have to bound the way `crate::media::MAX_TRACKED_PARAMS` does.
///
/// # A coding the field names twice: one half is derived, the other is chosen
///
/// RFC 9110 settles nothing here, and the halves do not have the same standing;
/// `fold_repeated_entry` records where the settling sentence was looked for and
/// is not. **Derived:** a zero among the entries naming a coding excludes it,
/// which is rule 3's "unless it is accompanied by a qvalue of 0" read plainly.
/// **Chosen:** where no entry is zero the FIRST in field order gives the weight,
/// because [`weight_for`](crate::media::weight_for) already resolves the same
/// open tie the same way for `Accept`.
/// `a_repeated_entry_is_undecided_and_this_is_the_reading_taken` asserts the
/// non-zero pair BOTH ways round, so a last-wins or largest-wins reading reds.
///
/// # Errors
///
/// [`NegotiationError`], from the walk beneath: the field must parse before it
/// can be asked anything, and only the first fault is reported.
pub fn encoding_acceptability<'a, I>(
  direction: Direction,
  coding: Option<&[u8]>,
  lines: I,
) -> Result<Acceptability, NegotiationError>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  // The two spellings of one state, normalised onto one path before anything
  // is read; rule 2's "more specific entry" is then an entry naming `identity`,
  // which is what this state is matched against.
  let coding = match coding {
    Some(name) if !name.eq_ignore_ascii_case(IDENTITY) => Some(name),
    _ => None,
  };
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
      None => wildcard = Some(fold_repeated_entry(wildcard, preference.weight())),
      Some(name) if name.as_bytes().eq_ignore_ascii_case(wanted) => {
        named = Some(fold_repeated_entry(named, preference.weight()));
      }
      Some(_) => {}
    }
  }
  if lines_seen == 0 {
    // The one place the direction parts the two: rule 1 is written for the
    // request, and a response carrying no such field is a case §12.5.3 does
    // not rule on.
    return Ok(match direction {
      Direction::Request => Acceptability::AcceptableByDefault,
      Direction::Response => Acceptability::NotAdvertised,
    });
  }
  Ok(match (coding, named, wildcard) {
    // Rules 2 and 3: an entry that names it governs, whatever it says. For the
    // no-coding state that entry is rule 2's "more specific entry".
    (_, Some(weight), _) => Acceptability::Weighed(weight),
    // Rule 2's second named exclusion, and the ONLY way a wildcard reaches the
    // no-coding state — the asterisk sentence ranges over an available content
    // coding, which this state has none of.
    (None, None, Some(weight)) if weight == Weight::ZERO => Acceptability::Weighed(Weight::ZERO),
    // Rule 2's default. A non-zero wildcard lands here rather than lending its
    // weight, which is the whole of the reading the doc above derives.
    (None, None, _) => Acceptability::AcceptableByDefault,
    // §12.5.3's asterisk sentence, for a coding the representation actually
    // HAS and the field does not list.
    (Some(_), None, Some(weight)) => Acceptability::Weighed(weight),
    // §12.4.3: nothing mentions it and there is no wildcard.
    (Some(_), None, None) => Acceptability::Unmentioned,
  })
}

/// Folds a second entry naming one coding onto the first, under two rules that
/// do not have the same standing — which is why this is no longer named for the
/// derived one alone. A zero absorbs, which rule 3's words give; otherwise the
/// FIRST in field order wins, which RFC 9110 does not give.
///
/// # `media` decided the undecided half first, and this follows it
///
/// The search below establishes that RFC 9110 leaves the tie open. That does not
/// license each reader here to break it its own way, and one had already broken
/// it: [`weight_for`](crate::media::weight_for) resolves a media range the field
/// names twice by FIELD ORDER, first standing, and its own comment records that
/// relaxing its `<` to `<=` would send every tie to the last range instead.
/// §12.5.1 gets the same silence §12.5.3 does, so a second reader picking the
/// other end would make one crate answer one unsettled question two ways.
/// Measured before this was aligned:
/// `weight_for(text/plain, ["text/plain;q=0.25, text/plain;q=0.75"])` is 250 and
/// `encoding_acceptability(Some(b"gzip"), ["gzip;q=0.25, gzip;q=0.75"])` was
/// 750.
///
/// The derived half stays, and the difference it makes is licensed rather than
/// chosen: `weight_for` absorbs no zero — measured,
/// `weight_for(text/plain, ["text/plain;q=1, text/plain;q=0"])` is 1000 — and
/// should not, since §12.5.1 has no counterpart to §12.5.3 rule 3's "unless it
/// is accompanied by a qvalue of 0". The two agree wherever the RFC is silent
/// and part only where it speaks to one.
///
/// # Where the rule that would settle this was looked for, and is not
///
/// Searched over the cached spec text:
///
/// - **§12.4.2**, defining `weight` and `qvalue`, says nothing about a repeat.
/// - **§12.5.1's only ordering sentence** is about a parameter's position
///   INSIDE one member, not a member repeated in a list: "Senders using weights
///   SHOULD send "q" last (after all media-range parameters)."
/// - **§5.6.1 and §5.6.1.2**, the list construct, bound cardinality and empty
///   elements — "Empty elements do not contribute to the count of elements
///   present." — and say nothing about a repeated one.
/// - **§5.3** says order matters and does not say which end: "The order in
///   which field lines with the same name are received is therefore significant
///   to the interpretation of the field value". That makes a positional rule
///   ADMISSIBLE rather than obviously wrong, and does not choose one.
/// - **§8.6** is the one place RFC 9110 rules on a repeat, and it rules for one
///   field on the case where the repeats are IDENTICAL: "a recipient of a
///   Content-Length header field value consisting of the same decimal value
///   repeated as a comma-separated list (e.g, `Content-Length: 42, 42`) MAY
///   either reject the message as invalid or replace that invalid field value
///   with a single instance of the decimal value". Two entries with DIFFERENT
///   weights are the case it does not reach.
///
/// What would settle it is a sentence naming which entry a recipient reads when
/// a field names one value twice with different weights. There is none.
fn fold_repeated_entry(seen: Option<Weight>, found: Weight) -> Weight {
  match seen {
    // Derived, from rule 3, and order-independent in both directions — which
    // is what makes it the derived half rather than a second choice.
    Some(previous) if previous == Weight::ZERO => previous,
    _ if found == Weight::ZERO => found,
    // Chosen, following `media`: the first entry stands.
    Some(previous) => previous,
    None => found,
  }
}

/// Walks an `Accept-Language` field's ranges (RFC 9110 §12.5.4), yielding one
/// [`Preference`] per element in wire order:
/// `Accept-Language = #( language-range [ weight ] )`, over the basic language
/// range RFC 9110 hands out to RFC 4647 §2.1 rather than spelling —
/// `language-range  = <language-range, see \[RFC4647\], Section 2.1>` is a
/// `prose-val`.
///
/// # The element, transcribed from the spec that owns it
///
/// RFC 4647 §2.1:
///
/// ```text
/// language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"
/// alphanum         = ALPHA / DIGIT
/// ```
///
/// The two subtag positions are different productions — `1*8ALPHA` in front and
/// `1*8alphanum` behind — so `en-us-1` is a range and `1-en` is not, and the
/// eight-character bound holds at every position. The rule is inside RFC 9110
/// §5.6.2's `token`, so no `language-range` can move an element boundary; the
/// narrowing is checked rather than widened to `token` for convenience, because
/// §2.1 says what an ill-formed range is worth: "Such ill-formed ranges will
/// probably not match anything." `*` is no ALPHA, so the first alternative
/// cannot derive it and the wildcard is its only reading — unlike §12.5.2's and
/// §12.5.3's elements, where `*` is also a `token`. And this is §2.1's BASIC
/// range, not §2.2's `extended-language-range`, which would admit `en-*-GB`.
///
/// # Wire order is not priority, and matching is not here
///
/// RFC 9110 §12.5.4: "Note that some recipients treat the order in which
/// language tags are listed as an indication of descending priority,
/// particularly for tags that are assigned equal quality values (no value is the
/// same as q=1). However, this behavior cannot be relied upon." So nothing is
/// derived from the order; ranking is [`Preference::weight`]'s. §12.5.4 hands
/// matching out too: "For matching, Section 3 of \[RFC4647\] defines several
/// matching schemes. Implementations can offer the most appropriate matching
/// scheme for their requirements." Which is appropriate depends on the
/// representations a responder holds, so it is the caller's — and that is why
/// §12.5.4 gets no counterpart to [`encoding_acceptability`].
///
/// # Errors
///
/// Each item is a [`NegotiationError`]; nothing is yielded after the first.
#[inline]
pub fn accept_language<'a, I>(
  lines: I,
) -> impl Iterator<Item = Result<Preference<'a>, NegotiationError>>
where
  I: IntoIterator<Item = &'a [u8]>,
{
  preferences(lines, Element::LanguageRange)
}

/// Walks an `Accept-Charset` field's charsets (RFC 9110 §12.5.2), yielding one
/// [`Preference`] per element in wire order:
/// `Accept-Charset = #( ( token / "*" ) [ weight ] )`, whose wildcard §12.5.2
/// describes as "The special value "*", if present in the Accept-Charset header
/// field, matches every charset that is not mentioned elsewhere in the field."
///
/// # Deprecated to SEND, and this is the receiving side
///
/// RFC 9110 §12.5.2's Note: "Accept-Charset is deprecated because UTF-8 has
/// become nearly ubiquitous and sending a detailed list of user-preferred
/// charsets wastes bandwidth, increases latency, and makes passive
/// fingerprinting far too easy". Every clause of that is about a SENDER, and a
/// deprecation does not unsend what is deployed. So the Note is why this reader
/// EXISTS and why nothing here writes an `Accept-Charset`.
///
/// # The element is `token` — the RFC spells no `charset` rule
///
/// RFC 9110 §12.5.2's ABNF writes `( token / "*" )` and not a `charset`
/// production; §8.3.2 defines charset names in prose, and its Note says where
/// the difference falls: "In theory, charset names are defined by
/// the "mime-charset" ABNF rule defined in Section 2.3 of \[RFC2978\] (as
/// corrected in \[Err1912\]). That rule allows two characters that are not
/// included in "token" ("{" and "}"), but no charset name registered at the
/// time of this writing includes braces". This reader implements the rule the
/// FIELD spells, so `a{b}` is refused.
///
/// # Errors
///
/// Each item is a [`NegotiationError`]; nothing is yielded after the first.
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
/// Borrows the field lines it was parsed from.
///
/// # No `PartialEq`
///
/// For the reason [`Preference`] carries none, on RFC 9110 §5.1's sentence
/// rather than §8.4.1's: "Field names are case-insensitive". Compare with
/// [`eq_ignore_ascii`](crate::grammar::eq_ignore_ascii).
#[derive(Debug, Copy, Clone)]
pub enum VaryMember<'a> {
  /// The `"*"` alternative.
  ///
  /// RFC 9110 §12.5.5: "A list containing the member "*" signals that other
  /// aspects of the request might have played a role in selecting the response
  /// representation, possibly including aspects outside the message syntax
  /// (e.g., the client's network address)." §12.4.3 puts it in one sentence:
  /// "Within Vary, the wildcard value means that the variance is unlimited." It
  /// is a MEMBER and not a whole value, which is why it is a variant of an item
  /// rather than a state of the walk: `*, accept-encoding` is one list of two
  /// members and this is the first.
  ///
  /// # The §12.5.5 rule this crate states and does not enforce
  ///
  /// RFC 9110 §12.5.5: "A proxy MUST NOT generate "*" in a Vary field value."
  /// It is STATED here and nothing checks it, and that is a DECISION rather than
  /// an omission: the README's `Which HTTP roles it serves` rules an intermediary
  /// out of scope, so a MUST that binds one is stated where a caller meets the
  /// value it governs rather than enforced. That section also carries why
  /// enforcing this one would be worse than stating it — a single prohibition
  /// beside no `Vary` writer, no `Via` and no `Max-Forwards` is a floor that is
  /// not there. What this crate owes such a caller is the fact it needs in order
  /// to obey the rule, and that fact is this variant.
  Wildcard,
  /// The `field-name` alternative — RFC 9110 §5.1's `field-name     = token`.
  ///
  /// A member that is exactly `*` is [`Wildcard`](Self::Wildcard) and never
  /// this, though `*` is a §5.6.2 `tchar` and so a `token` this alternative
  /// would also derive; §12.5.5 settles which reading applies: "A Vary field
  /// value is either the wildcard member "*" or a list of request field names,
  /// known as the selecting header fields, that might have had a role in
  /// selecting the representation for this response." Not checked against any
  /// registry: "Potential selecting header fields are not limited to fields
  /// defined by this specification."
  FieldName(&'a str),
}

/// Why a [`vary`] walk stopped. One variant, and no weight variants: RFC 9110
/// §12.5.5's `Vary = #( "*" / field-name )` brackets no `[ weight ]`, so a
/// shared [`NegotiationError`] would give this walk's `Result` two states it can
/// never hold.
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
/// readers above and for the same reason, and latches as they do. RFC 9110
/// §12.5.5: "The "Vary" header field in a response describes what
/// parts of a request message, aside from the method and target URI, might
/// have influenced the origin server's process for selecting the content of
/// this response." It answers which members the field named, in wire order, and
/// which is the wildcard — and nothing about what a recipient should DO with
/// them: §12.5.5's two purposes are a cache's rule, which RFC 9111 §4.1 owns,
/// and a user agent's, and both need state not in these bytes.
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
