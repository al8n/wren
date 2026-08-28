//! Range requests: RFC 9110 §14.
//!
//! [`RangesSpecifier`] reads the request's `Range` field and settles §14.1.1's
//! validity, §14.1.2's satisfiability and its two normalisations. It is the
//! reader for one direction of a field pair whose other halves — the response's
//! [`ContentRange`] and the `multipart/byteranges` body a multi-range 206
//! carries — share [`RangeError`] with it. §14.4's half goes BOTH ways, since a
//! `Content-Range` is written by the server that answers a range request and
//! read by the client that recombines the answer.
//!
//! **Facts that arrive as arguments, not as state.** The complete length of the
//! selected representation, and — because §14.1.1 makes satisfiability
//! unit-defined and §14.1.2's rules are `bytes`-only — everything about a unit
//! other than `bytes`.
//!
//! # Every span handed back unread is still constrained
//!
//! This module is the crate's only source of spans it does not interpret, and
//! there are exactly two: [`RangesSpecifier::other_range_set`] and
//! [`ContentRange::other_range_resp`]. RFC 9110 §14.1.1 is why they exist —
//! "The range unit name determines what kinds of range-spec are applicable to
//! its own specifiers", so what a specifier under `exampleunit` MEANS is that
//! unit's question and not this crate's.
//!
//! Not interpreting a span is not the same as not constraining it, and the two
//! were run together once. §14.1.1 hands the range unit its specifiers'
//! MEANING; it hands over none of the grammar that is generic, and the generic
//! grammar reaches every byte of both spans:
//!
//! - A `range-set` is `1#range-spec`, and all three `range-spec` forms are
//!   spelled out of `other-range`'s octets, `1*( %x21-2B / %x2D-7E )` —
//!   `int-range` and `suffix-range` are digits and `-`, which that set holds.
//!   So each element of a range-set under ANY unit is that set of octets: no
//!   SP, no comma, no control byte. [`RangesSpecifier::parse`] enforces it per
//!   element.
//! - A `Content-Range`'s tail is whatever §14.4's `range-unit SP` leaves, and
//!   whatever that is, it is still a FIELD VALUE. RFC 9110 §5.5 bounds one to
//!   `field-vchar` / SP / HTAB, and §14.4 puts exactly one SP in the whole
//!   value — the one the split consumed. So the tail is `1*field-vchar`, which
//!   admits `obs-text` (§5.5: "A recipient SHOULD treat other allowed octets in
//!   field content (i.e., obs-text) as opaque data") and admits neither CR nor
//!   LF. [`ContentRange::parse`] enforces it over the whole tail.
//!
//! The second is load-bearing rather than tidy: [`ContentRange::encode`] and
//! [`multipart::encode_part_header`] write that tail back out verbatim, the
//! second of them into a header line of a body this crate frames. A tail
//! carrying a CRLF is a second field line in that body, written by this crate,
//! and no gate between the parse and the write would have caught it — the
//! bytes never pass through [`crate::grammar::validate_field_value`], because
//! these encoders measure and copy rather than emitting a field section.
//!
//! # The outermost grammar is the one at the DESTINATION
//!
//! The second bullet bounds the tail by §5.5 because the tail ARRIVES as an
//! HTTP field value, and that is the right bound for the value this module
//! stores: `obs-text` in a `Content-Range` is a legal HTTP field value, and a
//! caller who never writes a multipart body is entitled to it. It is not the
//! right bound for everywhere the value is written BACK OUT.
//!
//! [`multipart::encode_part_header`] copies that tail into a header line of a
//! MIME body part, and RFC 9110 §14.6 delegates that framing to RFC 2046,
//! whose §5.1.1 admits no such octet there: "However, in no event are headers
//! (either message headers or body part headers) allowed to contain anything
//! other than US-ASCII characters." A span legal in an HTTP field value is
//! therefore not thereby legal in a MIME header this crate builds out of it,
//! and the narrower rule is carried at the ENCODER that crosses into that
//! grammar — [`RangeError::NonAsciiPartHeader`] — rather than at the parse,
//! which would take from a caller a value its own field admits.
//!
//! **The rule has a READING side too.** A reader handing back a `Part` whose
//! `Content-Type` parameter carries `%x80` — the very metadata
//! [`multipart::encode_part_header`] refuses to write — is one crate giving
//! two answers about the same bytes. The narrower grammar belongs to the CONTEXT
//! and not to the direction: a part's header block is RFC 2046's whichever way
//! it is travelling, so the reader holds every line of one to §5.1.1's
//! US-ASCII and every field name to RFC 822's `field-name`, and answers the
//! same [`RangeError::NonAsciiPartHeader`] the writer does.
//!
//! What does NOT move is [`ContentRange::parse`], which stays exactly as
//! permissive as §5.5 lets it be. A caller reading a standalone
//! `Content-Range` is entitled to what its own field admits; what it may not do
//! is take a span out of that permissive parse and put it where RFC 2046
//! governs, in either direction.
//!
//! Asking a stored span what it may contain, and where it goes afterwards, is
//! therefore the rule here rather than an observation about these two: a third
//! opaque span added to this module answers both questions at its own parse,
//! and every encoder that copies one out — and every reader that lifts one out
//! of a grammar not its own — answers what the grammar at that boundary admits.
//!
//! **What that rule covers today**, so that a writer added later is a visible
//! gap rather than a silent one. This crate has five writers, and exactly one
//! of them crosses a grammar boundary. [`ContentRange::encode`] and
//! [`crate::date::format_imf_fixdate`] write an HTTP field value, which is the
//! grammar their inputs were validated under; [`multipart::encode_final_boundary`]
//! copies only a boundary already held to RFC 2046's `bchars`;
//! [`crate::grammar::ParamValue::unescape_into`] writes into the caller's own
//! buffer rather than into a wire grammar, and states the obligation that
//! leaves with the caller. [`multipart::encode_part_header`] is the crossing,
//! and [`RangeError::NonAsciiPartHeader`] is what it answers with.
//!
//! # The destination's grammar can be WIDER, and the same rule applies
//!
//! §5.1.1's US-ASCII rule is narrower than HTTP's, and every paragraph above
//! reads as if narrowing were the direction. It is not the direction; it is
//! this instance. RFC 2045 §1 gives the fields it defines the whole of RFC
//! 822's structured-field syntax — "In particular, all of these header fields
//! except for Content-Disposition can include RFC 822 comments, which have no
//! semantic content and should be ignored during MIME processing" — and RFC
//! 9110 §8.3.1's `media-type` has no comment production at all. So a body
//! part's `Content-Type` may carry a construct the HTTP parser is right to
//! refuse, and handing that value to [`crate::media::media_type`] unchanged
//! refuses a message RFC 2045 §5.1 prints as an example.
//!
//! [`multipart::ByteRangesReader`] is therefore held to RFC 2045's own grammar
//! for that field, and `media_type` is left strict for the HTTP field sections
//! it is for. **Do not repair this by narrowing the value before handing it to
//! the HTTP parser.** Four constructs reach that one line — the fold, the
//! `Content-Transfer-Encoding` comments, the `Content-Type` comments, and the
//! white space around a symbol together with the two `token` alphabets — and
//! removing them one at a time removes constructs from a grammar the parser was
//! never reading. Ending the delegation is what answers all four.
//! [`multipart`]'s own summary tabulates every place the two part company.
//!
//! It is the same sentence as the section above with the inequality the other
//! way round: **the grammar that governs is the CONTEXT's**, and a difference in
//! either direction is answered where the two contexts meet rather than by
//! moving one of them.
// gate-exempt: crate::grammar::validate_field_value — named for contrast, and
// the contrast is the finding: nothing in this module calls it. It is the
// crate's §5.5 rule, and it sits on the http1 field-section encoder, which is
// not on the path a `Content-Range` tail takes out of here.
// gate-exempt: crate::date::format_imf_fixdate — named by the writer census, as
// one of the crate's writers this module does not call and does not go through.
// gate-exempt: multipart::encode_final_boundary — named by the writer census,
// which enumerates what each writer writes; this module declares it and calls it
// nowhere.
// gate-exempt: multipart::encode_part_header — named by the writer census as the
// one writer that crosses into RFC 2046's grammar; this module declares it and
// calls it nowhere.

mod content_range;
pub mod multipart;
mod specifier;

pub use content_range::ContentRange;
pub use specifier::{MAX_RANGE_SPECS, Pos, RangeSpec, RangesSpecifier, Resolved};

/// Why a Range field, a `Content-Range`, or a `multipart/byteranges` body could
/// not be read or written.
///
/// One type across four roles — the ranges-specifier parse, `Content-Range`'s
/// validity and encoding, output-space failures, and `multipart` framing. They
/// share a caller and a module, and this crate's precedent is one
/// `#[non_exhaustive]` enum per module rather than one per function.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RangeError {
  /// Not a valid `ranges-specifier` (RFC 9110 §14.1.1).
  #[error("not a valid ranges-specifier")]
  MalformedSpecifier,
  /// More `range-spec`s than [`MAX_RANGE_SPECS`].
  #[error("more range-specs than this recipient holds")]
  TooManySpecs,
  /// Not a valid `Content-Range` (RFC 9110 §14.4).
  #[error("not a valid Content-Range")]
  MalformedContentRange,
  /// A `Content-Range` whose `last-pos` is below its `first-pos`, or whose
  /// `complete-length` is less than or equal to its `last-pos`. RFC 9110 §14.4
  /// names both invalid and states the consequence: the "recipient of an
  /// invalid Content-Range MUST NOT attempt to recombine the received content
  /// with a stored representation".
  #[error("Content-Range positions are inconsistent")]
  InconsistentContentRange,
  /// Not a valid `multipart/byteranges` body (RFC 9110 §14.6, RFC 2046 §5.1.1).
  #[error("not a valid multipart/byteranges body")]
  MalformedMultipart,
  /// A `Content-Range` that cannot head a body part, because it encloses no
  /// range: §14.4's `unsatisfied-range`, under any unit.
  ///
  /// **Under any unit**, because §14.4 prints
  /// `unsatisfied-range = "*/" complete-length` inside one grammar with one
  /// `range-unit` slot and attaches no unit condition to either half. What
  /// §14.1.1 makes the range unit's own is what a `range-spec` MEANS — "The
  /// range unit name determines what kinds of range-spec are applicable to its
  /// own specifiers" — and this form specifies none: it names no `first-pos` and
  /// no `last-pos` for any unit to interpret. So `exampleunit */25` heads no body
  /// part for the reason `bytes */25` heads none, and
  /// [`ContentRange::is_unsatisfied`] answers `true` for both.
  ///
  /// The trap here is a discarded answer rather than a missing rule: the generic
  /// walk behind [`ContentRange::parse`] recognises the shape, and a caller that
  /// drops that arm stores the value as an undifferentiated opaque span, after
  /// which [`multipart::encode_part_header`] writes it into a part header — one
  /// crate refusing one spelling of a value while writing another spelling of
  /// the same one.
  ///
  /// Its own refusal rather than [`MalformedMultipart`](Self::MalformedMultipart),
  /// because nothing about it is malformed. The value passes both of §14.4's
  /// validity rules and this crate writes it happily as a top-level
  /// `Content-Range` on a 416; what it cannot be is a PART's. RFC 9110
  /// §15.3.7.2: "Within the header area of each body part in the multipart
  /// content, the server MUST generate a Content-Range header field
  /// corresponding to the range being enclosed in that body part." So this
  /// names a policy of §15.3.7.2's over a well-formed value, which is a
  /// different fact about a message from the one
  /// [`MalformedMultipart`](Self::MalformedMultipart) states — and only a
  /// reason-assertion that can tell the two apart says which one a refusal was.
  #[error("a body part's Content-Range encloses no range")]
  UnsatisfiedPartRange,
  /// A body part whose content is not as wide as its own `Content-Range` says,
  /// under `bytes`.
  ///
  /// The sibling of [`UnsatisfiedPartRange`](Self::UnsatisfiedPartRange), on
  /// the same sentence and on the other side of the wire. RFC 9110 §15.3.7.2:
  /// "Within the header area of each body part in the multipart content, the
  /// server MUST generate a Content-Range header field corresponding to the
  /// range being enclosed in that body part." An `incl-range` of `first-pos`
  /// through `last-pos` encloses `last - first + 1` octets under §14.1.2's
  /// unit, so a part declaring `bytes 0-9/10` over three octets of content
  /// corresponds to no range at all — its two halves state different things
  /// about the same part.
  ///
  /// Its own refusal rather than
  /// [`MalformedMultipart`](Self::MalformedMultipart), for the reason that
  /// variant gives: RFC 2046's framing is intact, every field parses, and what
  /// fails is §15.3.7.2's correspondence over a well-formed body. Refused
  /// rather than reported, unlike the unsatisfied form
  /// [`crate::range::multipart::Part::content_range`] hands over, because there
  /// the reader can give the caller a value it cannot mistake for a range —
  /// [`ContentRange::incl_range`] is `None` — and here it cannot: both halves
  /// look usable, and §15.3.7.3's recombination is performed AT the positions
  /// one of them names.
  ///
  /// **The comparison is between the WIRE octets and the range**, so it is
  /// asked only of a part whose wire octets are its enclosed octets:
  /// [`crate::range::multipart::PartEncoding::is_identity`]. RFC 2046 §5.1 lets
  /// each body part carry a `Content-Transfer-Encoding` of its own, and a part
  /// spelled in `base64` is four octets wide for every three the range encloses
  /// — a difference this crate cannot undo, being no-alloc, and so one it must
  /// not read as a fault. Such a part is handed over with its mechanism
  /// visible and this test not applied.
  #[error("a body part's content is not the width its Content-Range encloses")]
  PartRangeMismatch,
  /// A body part whose `Content-Type` is composite — a `multipart` or a
  /// `message` — carrying a `Content-Transfer-Encoding` that is not one of
  /// `7bit`, `8bit` or `binary`.
  ///
  /// RFC 2045 §6.4 states the prohibition twice and in the strongest words that
  /// document uses. Once over the entity's own type: "If an entity is of type
  /// "multipart" the Content-Transfer-Encoding is not permitted to have any
  /// value other than "7bit", "8bit" or "binary"." And once over the class,
  /// which is the sentence this refusal is spelled from: "Certain
  /// Content-Transfer-Encoding values may only be used on certain media types.
  /// In particular, it is EXPRESSLY FORBIDDEN to use any encodings other than
  /// "7bit", "8bit", or "binary" with any composite media type, i.e. one that
  /// recursively includes other Content-Type fields.  Currently the only
  /// composite media types are "multipart" and "message"."
  ///
  /// It reaches a BODY PART because §6.4's first sentence says which headers it
  /// is about: "If a Content-Transfer-Encoding header field appears as part of
  /// an entity's headers, it applies only to the body of that entity." RFC 2046
  /// §5.1 makes each body part such an entity — "data within the body parts can
  /// be encoded on a part-by-part basis, with Content-Transfer-Encoding fields
  /// for each appropriate body part" — so a part is exactly the entity §6.4
  /// binds, and the two fields that decide it are the two the part carries.
  ///
  /// # Not [`MalformedMultipart`](Self::MalformedMultipart), and not a limit
  ///
  /// Both fields parse; the framing is intact; the body is a
  /// `multipart/byteranges` body. What fails is a rule about the PAIR, which
  /// neither field can break on its own — the same shape as
  /// [`UnsatisfiedPartRange`](Self::UnsatisfiedPartRange) and
  /// [`PartRangeMismatch`](Self::PartRangeMismatch), and the reason those two
  /// have variants of their own. And it is not
  /// [`PartValueNotContiguous`](Self::PartValueNotContiguous)'s kind of answer
  /// either: nothing here is a limit of this reader, since decoding is not what
  /// §6.4 requires. §6.4 gives its own reason, and it is about the message
  /// rather than about any recipient's storage: "Though the prohibition against
  /// using content-transfer-encodings on composite body data may seem overly
  /// restrictive, it is necessary to prevent nested encodings, in which data are
  /// passed through an encoding algorithm multiple times, and must be decoded
  /// multiple times in order to be properly viewed."
  ///
  /// So the prohibition is about what a message says about its own structure,
  /// not about what a reader can afford — which is why refusing is right here
  /// even though this crate's inability to decode is a separate fact.
  ///
  /// # Both directions, and the same rule in each
  ///
  /// Nested encodings are the harm §6.4 names, and a composite body part is
  /// exactly where one would be nested. Both halves of this module answer for
  /// it: [`multipart::encode_part_header`] refuses to WRITE the combination and
  /// [`multipart::ByteRangesReader::next`] refuses to hand one back, so a body
  /// this crate would not write is not one it reports as ordinary input. Two
  /// independent per-field checks would admit every pairing of a valid type
  /// with a valid mechanism instead.
  ///
  /// A part whose type is NOT composite keeps [`PartEncoding`](multipart::PartEncoding)'s
  /// report unchanged: `text/plain` with `base64` is conformant input, is handed
  /// over undecoded, and has §15.3.7.2's width test skipped rather than being
  /// refused.
  ///
  /// # A third case, which is neither, and which this crate cannot decide
  ///
  /// §6.4's condition is "any composite media type" — a CLASS — and RFC 2045
  /// §5.1's `type := discrete-type / composite-type` puts `extension-token` in
  /// both halves of it. So `X-bundle/foo` is a well-formed member of either
  /// class, and whether §6.4 forbids it under `base64` lives in a registration
  /// or a private definition this crate does not hold. §6.4's own "Currently
  /// the only composite media types are "multipart" and "message"" dates itself
  /// in its first word and does not narrow the sentence before it — reading it
  /// as the rule lets such a pair past this refusal.
  ///
  /// This variant is NOT the answer there. The part is handed over and the
  /// header is written, with
  /// [`Part::top_level_type`](multipart::Part::top_level_type) reporting
  /// [`TopLevelType::Unknown`](multipart::TopLevelType::Unknown) and naming
  /// what the caller then owes: whoever defined a private top-level type is the
  /// party that knows whether it is composite. Refusing instead would refuse
  /// every private DISCRETE type under a non-identity mechanism, which is
  /// conformant input, to catch a violation this crate cannot demonstrate.
  #[error("a composite body part may not carry a non-identity Content-Transfer-Encoding")]
  CompositePartEncoding,
  /// A body part of a subtype RFC 2046 restricts to `7bit`, carrying anything
  /// else — written or read.
  ///
  /// Two subtypes, and the rule is stated at each of them rather than over
  /// their type. RFC 2046 §5.2.2 says of `message/partial` that "the use of a
  /// content- transfer-encoding of "8bit" or "binary" is explicitly prohibited
  /// for MIME entities of type "message/partial"." RFC 2046 §5.2.3 says of
  /// `message/external-body` that "the use of a content- transfer-encoding of
  /// "8bit" or "binary" is explicitly prohibited for entities of type
  /// "message/external-body"." §5.2.3 states the positive form as a MUST —
  /// such an entity "MUST have a content-transfer-encoding of 7bit (the
  /// default)." — and §5.2.2 requires the same of its own subtype, in lower
  /// case, in the sentence before the one quoted. (The space inside "content-
  /// transfer-encoding" is RFC 2046's own, kept here so the quotation can be
  /// searched for.)
  ///
  /// # Why the composite refusal does not already answer it
  ///
  /// Both subtypes are `message`, so both are composite, and §6.4's
  /// prohibition already refuses `base64` and `quoted-printable` on them. What
  /// §6.4 PERMITS on a composite type is its three identity mechanisms —
  /// "any encodings other than "7bit", "8bit", or "binary"" is what it forbids
  /// — and it is exactly those permissions that §5.2.2 and §5.2.3 withdraw for
  /// these two subtypes. So the two rules do not overlap where it matters:
  /// §6.4 is about a CLASS and cannot see a subtype, and a guard written from
  /// it alone lets `message/partial` + `8bit` through, which §5.2.2 calls
  /// explicitly prohibited.
  ///
  /// The variants stay distinct because the sentences do. A part refused here
  /// may carry a mechanism §6.4 has no objection to at all, so answering
  /// [`CompositePartEncoding`](Self::CompositePartEncoding) would tell a caller
  /// that a composite body part may not carry a non-identity
  /// `Content-Transfer-Encoding` — its own message, in its own words — over a
  /// part whose encoding IS an identity mechanism. A true refusal with a false
  /// reason.
  ///
  /// # What is allowed
  ///
  /// An explicit `7bit`, compared without regard to case (§6.1: "These values
  /// are not case sensitive -- Base64 and BASE64 and bAsE64 are all
  /// equivalent."), and no `Content-Transfer-Encoding` field at all — which is
  /// the same thing, since RFC 2045 §6.1 makes 7bit the default and both
  /// sections name it as such in their own parentheses. Every other mechanism
  /// is refused, including one this crate cannot name: §6.4's
  /// `application/octet-stream` fallback for an unrecognised mechanism is a
  /// rule about how to READ such an entity, and it does not make the entity's
  /// encoding 7bit.
  ///
  /// # Both directions, and the same rule in each
  ///
  /// [`multipart::encode_part_header`] refuses to write the pair and
  /// [`multipart::ByteRangesReader::next`] refuses to hand it back, from one
  /// function, exactly as the composite rule beside it is asked.
  #[error("a message/partial or message/external-body body part must be 7bit")]
  NonSevenBitPartEncoding,
  /// A boundary outside RFC 2046 §5.1.1's `1*70<bchars>` with no trailing space.
  #[error("not a valid multipart boundary")]
  MalformedBoundary,
  /// A body part header with an octet RFC 2046 does not admit in one — written
  /// or read.
  ///
  /// The one place this module's two grammars meet, and it is the same place on
  /// both sides of the wire. A `Content-Range` tail under a unit this crate
  /// does not read is held to RFC 9110 §5.5, which admits `obs-text`; a
  /// `Content-Type` parameter's `quoted-string` admits it too. Both are legal
  /// HTTP field values, and [`ContentRange::parse`] keeps them. Neither is
  /// legal in a MIME body part header: RFC 9110 §14.6 frames a body part by
  /// RFC 2046, whose §5.1.1 says that "in no event are headers (either message
  /// headers or body part headers) allowed to contain anything other than
  /// US-ASCII characters."
  ///
  /// So the value is not narrowed at the parse — a caller reading or writing an
  /// ordinary field is entitled to it — and the two functions that cross into
  /// MIME carry the narrower rule instead:
  /// [`multipart::encode_part_header`] refuses rather than writing a part
  /// header a conforming recipient rejects, and
  /// [`multipart::ByteRangesReader::next`] refuses rather than lifting such a
  /// header out of a body part into a value the caller could hand straight back
  /// to that writer.
  ///
  /// **A reader that did not answer this would be a defect rather than a
  /// symmetry**: a `Content-Type` parameter carrying `%x80` coming back out of a
  /// `Part` this crate's own writer would refuse is one crate giving two answers
  /// about the same bytes. The reader's rule is the whole
  /// header BLOCK — a continuation line and a field it ignores included — since
  /// §5.1.1's sentence is about headers and not about the two fields this crate
  /// reads out of them.
  #[error("a body part header would not be US-ASCII")]
  NonAsciiPartHeader,
  /// One of the three fields [`multipart::ByteRangesReader`] collects is
  /// written so that its value is not one contiguous run of octets, and this
  /// reader has nowhere to join the pieces.
  ///
  /// **This names a limit of the reader, not a fault in the message**, which is
  /// exactly why it is not
  /// [`MalformedMultipart`](Self::MalformedMultipart): that variant says the
  /// bytes are not a `multipart/byteranges` body, and here they may well be. A
  /// [`Part`](multipart::Part) borrows spans out of the one buffer
  /// [`multipart::ByteRangesReader::new`] was handed, so a value it hands back
  /// has to BE one such span. Joining two of them needs somewhere to put the
  /// join, and a no-alloc reader has nowhere to put one. The crate already
  /// names this same limit on the field side —
  /// [`MediaError::ValueSpansFieldLines`](crate::media::MediaError::ValueSpansFieldLines),
  /// whose own words are `quoted value spans a field-line join and is not one
  /// contiguous slice` — and this is that statement made about a body part's
  /// header block. One condition, one voice.
  ///
  /// # Reachable only where the value has not already been read
  ///
  /// All three fields are held unparsed until the line beneath them settles
  /// whether they were folded, and that order is what makes this variant's own
  /// account true of all three. Parsing a part's `Content-Range` or
  /// `Content-Type` on the physical line each was written on fails a folded one
  /// against its own grammar half-read — `Content-Type: text/` continued by
  /// ` plain` answers [`MalformedMultipart`](Self::MalformedMultipart), a
  /// verdict about the message, over the very input this variant exists to
  /// describe. The shape of that defect is general — an answer produced before
  /// the evidence that would have changed it — which is why the rule is stated
  /// at the reader rather than only here.
  ///
  /// # The one way a value arrives in pieces
  ///
  /// **An RFC 822 line fold**, where the value continues on a second line. The
  /// input is CONFORMING: a body part's header block is RFC 822's and folding
  /// is a construct that grammar admits, so `Content-Type: text/plain` folded
  /// onto a second line carrying `;charset=us-ascii` unfolds to a media type
  /// this crate reads happily. What a caller who needs the value does instead
  /// is unfold before this reader ever sees the body: copy it into storage of
  /// its own with each continuation joined onto the line above — RFC 9112 §5.2
  /// prescribes the join HTTP's own readers make, "replace each received
  /// obs-fold with one or more SP octets prior to interpreting the field
  /// value" — and hand the unfolded copy to
  /// [`multipart::ByteRangesReader::new`], which then sees an ordinary part.
  ///
  /// # An RFC 822 comment is not this, and must not be made into it
  ///
  /// A comment reaches this variant only through the parser, never through the
  /// construct. STRIPPING comments off the value so that RFC 9110 §8.3.1's
  /// parser can read what remains is what puts it there: a leading or trailing
  /// one comes off by shortening the borrowed slice, and one between two of the
  /// value's lexical tokens leaves two spans with nowhere to join them, so a
  /// conforming value (RFC 2045 §1: "all of these header fields except for
  /// Content-Disposition can include RFC 822 comments, which have no semantic
  /// content and should be ignored during MIME processing") is reported as one
  /// this reader cannot represent.
  ///
  /// It never is. RFC 5322 §3.2.2: "Runs of FWS, comment, or CFWS that occur
  /// between lexical tokens in a structured header field are semantically
  /// interpreted as a single space character." BETWEEN lexical tokens, so every
  /// token on either side of a comment is still one contiguous span and there is
  /// nothing to join. The MIME parser in `multipart` takes them in place, and
  /// `text/plain; (c) charset=us-ascii` is a media type.
  ///
  /// What remains where a comment appears to split a single TOKEN —
  /// `charset=a(c)b` — is [`MalformedMultipart`](Self::MalformedMultipart), and
  /// that is a verdict this crate can now establish rather than decline:
  /// RFC 5322 §3.2.3 spells `atom = [CFWS] 1*atext [CFWS]`, which puts the
  /// comment position outside the token and never inside it, so the value is
  /// malformed. Reporting the limit there would state something true of neither
  /// case; telling the two apart needs a lexer of the destination grammar, and
  /// `multipart` has one.
  ///
  /// # Only a field this reader COLLECTS
  ///
  /// A continuation of a field it walks past is skipped and not reported,
  /// because there is no join to perform: RFC 2046 §5.1's "All other header
  /// fields may be ignored in body parts" licenses ignoring the whole field,
  /// continuation lines included. A continuation with no field line above it at all stays
  /// [`MalformedMultipart`](Self::MalformedMultipart): RFC 822 gives it nothing
  /// to continue, so it is malformed input rather than a construct this reader
  /// declines to join.
  ///
  /// Taking scratch storage here instead of refusing is a SECOND constructor
  /// rather than a hidden mode, and it stays deferred rather than being
  /// smuggled in behind this one.
  #[error("a body part's field value is not one contiguous slice and this reader cannot join it")]
  PartValueNotContiguous,
  /// The output slice was too small.
  #[error("output buffer too small")]
  BufferTooSmall,
}

#[cfg(test)]
mod tests;
