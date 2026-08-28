//! RFC 9110 §14.6's `multipart/byteranges`, written and read.
//!
//! §14.6 sends the several ranges of a 206 as body parts "in a multipart
//! message body (\[RFC2046\], Section 5.1)", so the framing around each part is
//! RFC 2046's and the two fields inside it are RFC 9110's. This module writes
//! the framing and nothing else: [`encode_part_header`] writes one part's
//! delimiter and header block, the caller writes that part's content behind it,
//! and [`encode_final_boundary`] closes the body. That is `http1-proto`'s
//! chunked encoder's shape, for its reason — the content is the caller's, and
//! no buffer this crate could take is large enough to hold it.
//!
//! **The boundary is an argument, never generated here.** §14.6 calls it "The
//! required boundary parameter", so a caller writing the message's own
//! `Content-Type` is already holding one. Generating a boundary would need
//! entropy, which is state this crate would create rather than receive.
//!
//! **Reading is the asymmetric half.** [`ByteRangesReader`] takes the WHOLE body
//! at construction and hands back a [`Part`] at a time, each borrowing out of
//! that one slice — because a no-alloc parser cannot hold the body, and a
//! reader that took a fresh slice per call could be handed a different one. So
//! the two directions are shaped by the same fact from opposite sides: the
//! writer never sees the content because the caller holds it, and the reader
//! sees all of it at once because nothing here can store it.
//!
//! # Which grammar a part's `Content-Type` is read in, and where that lives
//!
//! A body part's `Content-Type` is not an HTTP field: RFC 9110 §14.6 hands the
//! framing of a `multipart/byteranges` body to RFC 2046, RFC 2046 §5.1 gives a
//! body part its own header fields, and RFC 2045 §5.1 gives that field its own
//! grammar — RFC 822's structured-field lexing over RFC 2045's `token` — which
//! is not RFC 9110 §8.3.1's. That parser is `media`'s, beside §8.3.1's own, and
//! [`media`](crate::media)'s summary tabulates every place the two part
//! company. This module supplies the CONTEXT and reads the field name; what the
//! value behind the colon means is a media-type question and is answered there.
//!
//! Both parsers produce one [`MediaType`], so a caller meets one type and
//! [`encode_part_header`] takes one argument. What that writer spells back is
//! §8.3.1's preferred tight form either way — `text / plain` re-frames as
//! `text/plain` — which is the same media type and not the same bytes, exactly
//! as a parameter's `OWS` has always been.

use super::{ContentRange, RangeError, content_range::put};
use crate::{
  grammar::{ParamValue, eq_ignore_ascii, trim_ows},
  media::{MediaType, is_mime_token_char, keeps_x_token, mime_content_type, skip_cfws},
};

/// The line break every piece of this framing is separated by.
const CRLF: &[u8] = b"\r\n";

/// RFC 2046 §5.1.1's `dash-boundary := "--" boundary`, without the boundary.
///
/// Also the two the close-delimiter adds: §5.1.1 says the last delimiter line
/// "is identical to the previous delimiter lines, with the addition of two more
/// hyphens after the boundary parameter value".
const DASHES: &[u8] = b"--";

/// The per-part `Content-Type` field name and its `SP`.
const CONTENT_TYPE: &[u8] = b"Content-Type: ";

/// The per-part `Content-Range` field name and its `SP`.
const CONTENT_RANGE: &[u8] = b"Content-Range: ";

/// The per-part `Content-Transfer-Encoding` field name and its `SP`.
///
/// RFC 2045 §6.1's `encoding := "Content-Transfer-Encoding" ":" mechanism`; the
/// `SP` after the colon is §5.5's optional `OWS` written the way every other
/// field this module composes writes it.
const CONTENT_TRANSFER_ENCODING: &[u8] = b"Content-Transfer-Encoding: ";

/// The longest boundary RFC 2046 §5.1.1 admits: "Boundary delimiters must not
/// appear within the encapsulated material, and must be no longer than 70
/// characters, not counting the two leading hyphens."
const MAX_BOUNDARY: usize = 70;

/// Writes one body part's delimiter and header block, returning how many bytes
/// it took.
///
/// What it writes is RFC 2046 §5.1.1's `delimiter transport-padding CRLF`
/// followed by the part's header fields and the empty line that ends them:
///
/// ```text
/// CRLF "--" boundary CRLF
/// [ "Content-Type: " media-type CRLF ]
/// "Content-Range: " content-range CRLF
/// [ "Content-Transfer-Encoding: " mechanism CRLF ]
/// CRLF
/// ```
///
/// with no `transport-padding`, because §5.1.1's own comment on that rule makes
/// zero length a MUST for composers and leaves handling a transport's padding
/// to receivers. The caller writes the part's content immediately behind these
/// bytes and then calls this again for the next part, or
/// [`encode_final_boundary`] to close the body.
///
/// # Always the delimiter form, first part included
///
/// §5.1.1 spells the body `[preamble CRLF] dash-boundary transport-padding CRLF
/// body-part *encapsulation close-delimiter transport-padding [CRLF epilogue]`,
/// where `encapsulation := delimiter transport-padding CRLF body-part` and
/// `delimiter := CRLF dash-boundary`. So the first `dash-boundary` carries no
/// CRLF of its own and every later one does. This function writes the later
/// form every time, which puts a `CRLF` in front of the first part too.
///
/// That is grammar rather than a lenience: an empty `preamble` is a
/// `discard-text` like any other, so a body opening `CRLF "--" boundary` is
/// `[preamble CRLF]` with nothing in the preamble — and §14.6's first
/// implementation note says the same thing from the reader's side, that
/// "Additional CRLFs might precede the first boundary string in the body". The
/// alternative was to make the first call different from the rest, which needs
/// to know WHICH call is the first: state this crate would have to hold or the
/// caller would have to pass, over a function that otherwise holds none. A
/// caller with a real preamble writes it before the first call and the CRLF
/// written here terminates it, which is the same bytes either way.
///
/// # What the caller must know
///
/// **That the boundary does not occur inside any part.** RFC 2046 §5.1.1:
/// "Boundary delimiters must not appear within the encapsulated material, and
/// must be no longer than 70 characters, not counting the two leading hyphens."
/// The length half this function checks; the occurrence half it cannot, because
/// it never sees the content. §5.1.1 also says why the choice is not a
/// formality: "Because boundary delimiters must not appear in the body parts
/// being encapsulated, a user agent must exercise care to choose a unique
/// boundary parameter value."
///
/// **How many ranges the request asked for.** RFC 9110 §15.3.7.2: "A server
/// MUST NOT generate a multipart response to a request for a single range,
/// since a client that does not request multiple parts might not support
/// multipart responses. However, a server MAY generate a "multipart/byteranges"
/// response with only a single body part if multiple ranges were requested and
/// only one range was found to be satisfiable or only one range remained after
/// coalescing." This function writes one part at a time and never sees the
/// count. The tail of that sentence is the half worth keeping: a one-part
/// multipart response is legitimate precisely when the request asked for
/// several and only one survived resolving or coalescing.
///
/// **That the content written behind this header is as wide as the field
/// says.** RFC 9110 §15.3.7.2: "Within the header area of each body part in the
/// multipart content, the server MUST generate a Content-Range header field
/// corresponding to the range being enclosed in that body part." Under `bytes`
/// an `incl-range` of `first-pos` through `last-pos` encloses
/// `last - first + 1` octets, and this function writes the header and stops —
/// the content is the caller's, for the reason this module's own summary gives,
/// so nothing here can count it.
///
/// This is the one place the two halves of this module deliberately do not
/// agree, and it is stated on both. [`ByteRangesReader::next`] DOES check the
/// width, because by then the content is in front of it, and answers
/// [`RangeError::PartRangeMismatch`] when it is wrong — so a caller that writes
/// `bytes 0-9/10` and then three octets produces a body this crate's own reader
/// refuses. The asymmetry is which side can see the fact, not which side the
/// rule binds: §15.3.7.2 binds the SENDER, and the sender here is the caller
/// holding the content. [`Part::content_range`] says the same thing from the
/// reader's side.
///
/// **That the positions a range names are positions its own unit defines.**
/// This is what the refusal below does NOT reach, and stating the boundary is
/// the point. §14.1.1: "The range unit name determines what kinds of range-spec
/// are applicable to its own specifiers." So whether `exampleunit 1.2-4.3`
/// names anything, and how much content it encloses, is that unit's question and
/// not this crate's — [`ContentRange::incl_range`] is `None` for it, no width can
/// be derived, and the caller holding the unit's specification is the one who
/// can hold §15.3.7.2's correspondence rule over it.
///
/// What that delegation does not cover is the value that names no positions AT
/// ALL, however easily it reads as covering it. §14.4's
/// `unsatisfied-range = "*/" complete-length` is printed inside one grammar with
/// one `range-unit` slot and no unit condition on either half, so a value of that
/// shape encloses nothing whatever unit heads it — a fact about the grammar, not
/// about the unit. [`ContentRange::is_unsatisfied`] therefore answers `true` for
/// `exampleunit */25` as for `bytes */25`, and the refusal below is on that
/// answer rather than on the unit.
///
/// **That the message's own header section is the other shape.** §15.3.7.2:
/// "To avoid confusion with single-part responses, a server MUST NOT generate a
/// Content-Range header field in the HTTP header section of a multiple part
/// response (this field will be sent in each part instead)." The fields this
/// writes are the ones that sentence sends instead;
/// [`ContentRange::encode`] states the pair from the other side.
///
/// # Errors
///
/// [`RangeError::MalformedBoundary`] when `boundary` is outside RFC 2046
/// §5.1.1's `boundary := 0*69<bchars> bcharsnospace` — empty, past 70
/// characters, ending in a space, or carrying a byte that set does not hold.
///
/// [`RangeError::UnsatisfiedPartRange`] when `range` is §14.4's
/// `unsatisfied-range`, **under every unit**. §15.3.7.2 requires the per-part
/// field to correspond "to the range being enclosed in that body part", and
/// `*/1234` encloses nothing — yet it satisfies both of §14.4's validity rules,
/// so [`ContentRange::is_unsatisfied`] is the only thing that catches it. That
/// accessor is the whole of the test, and it is unit-blind because §14.4's
/// printed production is: the form carries no unit condition, so neither does
/// this refusal. A unit-keyed test writes `exampleunit */25` into a part header
/// while refusing `bytes */25` — one rule, two answers, from a classification
/// the generic parse has already made and discarded.
///
/// [`RangeError::CompositePartEncoding`] when `content_type` is a `multipart`
/// or a `message` and `encoding` is not one of RFC 2045 §6.1's three identity
/// mechanisms. §6.4: "it is EXPRESSLY FORBIDDEN to use any encodings other than
/// "7bit", "8bit", or "binary" with any composite media type, i.e. one that
/// recursively includes other Content-Type fields.  Currently the only composite
/// media types are "multipart" and "message"." That rule binds the pair, so
/// neither the `content_type` check nor the `encoding` check above can reach it
/// — validated independently, both say yes to `multipart/mixed` + `base64`, and
/// a writer built out of them writes it. [`ByteRangesReader::next`] refuses the
/// same combination on the same sentence, so the two halves of this module agree
/// about which bodies exist.
///
/// **A caller obligation sits beside that refusal, and it is not one this crate
/// can discharge.** §6.4's condition is "any composite media type", and §5.1
/// puts `extension-token` in `discrete-type` and `composite-type` alike — so a
/// `content_type` whose top-level type is neither of the seven §5.1 names is a
/// [`TopLevelType::Unknown`], and whether §6.4 forbids the pair depends on a
/// registration or a private definition this crate does not hold. Such a pair
/// is WRITTEN. A caller passing `X-bundle/foo` with a non-identity `encoding`
/// is asserting that `X-bundle` is discrete; if it is not, the message this
/// writes is the one §6.4 calls EXPRESSLY FORBIDDEN, and the fault is the
/// caller's. Refusing instead would refuse every private DISCRETE type under
/// `base64`, which is conformant input — `forbidden_part_encoding` argues the
/// choice, and [`Part::top_level_type`] is where the reader reports the same
/// fact.
///
/// [`RangeError::NonSevenBitPartEncoding`] when `content_type` is
/// `message/partial` or `message/external-body` and `encoding` is neither
/// [`PartEncoding::Absent`] nor an `Identity` holding `7bit`. RFC 2046 §5.2.2
/// and §5.2.3 state that rule at each of those two subtypes — "the use of a
/// content- transfer-encoding of "8bit" or "binary" is explicitly prohibited
/// for MIME entities of type "message/partial"." and, of the other,
/// "MUST have a content-transfer-encoding of 7bit (the default)." Both
/// subtypes are composite, so the refusal above already covered `base64` and
/// `quoted-printable` on them; what these two sections withdraw is two of the
/// three mechanisms §6.4 PERMITS, which no test on a top-level type can
/// express. `is_seven_bit_only` argues the pair and
/// [`ByteRangesReader::next`] refuses the same combinations.
///
/// [`RangeError::MalformedMultipart`] for a `content_type` whose parameters
/// this crate cannot spell back. No value from
/// [`media_type`](crate::media::media_type) or from `mime_content_type` beside
/// it — the two constructors of a [`MediaType`], each of which walks every
/// parameter before handing the value over — is such a value, so this reports a
/// state this crate does not produce rather than panicking on one.
///
/// The same word for a `content_type` whose `type` or `subtype` is in the `X-`
/// namespace without being RFC 2045 §5.1's `x-token` — `x-/plain`, `text/x-`.
/// That one IS a state a caller can reach, and by no mistake of its own:
/// [`media_type`](crate::media::media_type) reads RFC 9110 §8.3.1, where both
/// halves are spelled `token` and `x-` is one, while §5.1 offers the `X-`
/// namespace through `x-token` alone and requires a `1*<…>` tail behind it. A
/// body part is where §5.1 governs, so the value is refused HERE rather than at
/// the parser that read it, exactly as the ASCII rule below is —
/// `is_readable_media_type` states the direction, and `ByteRangesReader::next`
/// refuses the same two spellings on the same production.
///
/// The same word, and the same argument, for an `encoding` no read of any body
/// produces: [`PartEncoding`]'s variants are public, so a caller can build
/// `Identity(b"7bit)")`, `Undecoded(b"base64")` or `Unrecognised(b"base64")` by
/// hand, and none of those is a state [`ByteRangesReader::next`] hands back.
/// What is accepted here is exactly what that reader emits — a mechanism that
/// satisfies RFC 2045 §6.1's production by `is_mechanism_syntax`, sitting in the
/// variant `is_identity_mechanism` and `is_recognised_mechanism` sort it into.
/// The variant is a CLAIM about the octets below the header
/// ([`PartEncoding::is_identity`]) and about the type that governs them
/// ([`PartEncoding::is_octet_stream_fallback`]), so writing a header whose field
/// name contradicts the claim the caller just made would put this crate's two
/// halves into disagreement about one part, which is the same split
/// [`RangeError::NonAsciiPartHeader`] below closes.
///
/// [`RangeError::NonAsciiPartHeader`] when `range`'s or `content_type`'s bytes
/// are not US-ASCII, which is the one rule here that comes from the DESTINATION
/// rather than from the value. Those two arrive validated as HTTP field values,
/// and RFC 9110 §5.5's `field-vchar` admits `obs-text` — so a `Content-Range`
/// tail under a unit this crate does not read, and a `Content-Type` parameter's
/// `quoted-string`, may each carry `%x80-FF` and still be a legal field value.
/// What they may not be is a MIME header: §14.6 frames a body part by RFC 2046,
/// whose §5.1.1 says that "in no event are headers (either message headers or
/// body part headers) allowed to contain anything other than US-ASCII
/// characters." The refusal sits here rather than at
/// [`ContentRange::parse`] because a caller who never writes a multipart body is
/// entitled to the value its own field admits; what it may not do is have this
/// function put that value where RFC 2046 governs.
///
/// `encoding` is not among the two, and its absence is not a gap: RFC 2045
/// §5.1's `token` is `%x21-7E`, so the `mechanism` test above is already the
/// narrower of the two rules and a value that passed it is US-ASCII already —
/// including a [`PartEncoding::Unrecognised`], whose span `is_mechanism_syntax`
/// holds to that same alphabet.
///
/// [`RangeError::BufferTooSmall`] when `out` is shorter than the header. The
/// length is measured before anything is written, so a call that cannot fit
/// leaves `out` untouched rather than handing a caller who reuses its buffer the
/// head of one part over the tail of another. Every refusal above is answered
/// before the first byte is written, for the same reason.
pub fn encode_part_header(
  range: &ContentRange<'_>,
  content_type: Option<&MediaType<'_>>,
  encoding: PartEncoding<'_>,
  boundary: &[u8],
  out: &mut [u8],
) -> Result<usize, RangeError> {
  if !is_boundary(boundary) {
    return Err(RangeError::MalformedBoundary);
  }
  if range.is_unsatisfied() {
    return Err(RangeError::UnsatisfiedPartRange);
  }
  if !is_readable_encoding(encoding) {
    return Err(RangeError::MalformedMultipart);
  }
  // RFC 2045 §5.1's `type` and `subtype`, which are not RFC 9110 §8.3.1's two
  // `token`s: `x-/plain` is a media type in a field section and is one in
  // neither half of a body part's. `is_readable_media_type` argues the rule and
  // the direction; the refusal is here so that nothing this crate writes is a
  // value `ByteRangesReader::next` would refuse to read back.
  if let Some(content_type) = content_type
    && !is_readable_media_type(content_type)
  {
    return Err(RangeError::MalformedMultipart);
  }
  // RFC 2045 §6.4's prohibition and RFC 2046 §5.2.2's and §5.2.3's, both of
  // which are rules about the PAIR and so cannot be reached by validating
  // either field on its own. `is_readable_encoding` above asks whether the
  // mechanism is a `mechanism`, and `media_type_len` below asks whether the
  // media type can be spelled back; both answer `yes` for `multipart/mixed`
  // + `base64`, which §6.4 calls EXPRESSLY FORBIDDEN, and both answer `yes`
  // for `message/partial` + `8bit`, which §5.2.2 calls explicitly prohibited.
  if let Some(error) = forbidden_part_encoding(content_type, encoding) {
    return Err(error);
  }
  let Some(len) = part_header_len(range, content_type, encoding, boundary) else {
    return Err(RangeError::MalformedMultipart);
  };
  // After the measurement, so the two answers `part_header_is_ascii` can give
  // do not have to be told apart here: `None` is the same parameter walk the
  // line above has already reported `MalformedMultipart` for, and only
  // `Some(false)` — a span that really does carry a non-ASCII octet — is left
  // to reach this refusal.
  if part_header_is_ascii(range, content_type) != Some(true) {
    return Err(RangeError::NonAsciiPartHeader);
  }
  let Some(room) = out.get_mut(..len) else {
    return Err(RangeError::BufferTooSmall);
  };
  match write_part_header(range, content_type, encoding, boundary, room) {
    Some(()) => Ok(len),
    // The same measurement asked of the writer rather than of the measure:
    // `write_part_header` fills `room` exactly, and this arm is what it answers
    // if it ever measured differently from `part_header_len`. A refusal is then
    // the report, since a part header written from two disagreeing sizes is one
    // no reader can find the next delimiter behind.
    None => Err(RangeError::BufferTooSmall),
  }
}

/// Writes the close-delimiter that ends the body, returning how many bytes it
/// took.
///
/// RFC 2046 §5.1.1: `close-delimiter := delimiter "--"`, and in prose, "The
/// boundary delimiter line following the last body part is a distinguished
/// delimiter that indicates that no further body parts will follow. Such a
/// delimiter line is identical to the previous delimiter lines, with the
/// addition of two more hyphens after the boundary parameter value." So this
/// writes `CRLF "--" boundary "--" CRLF`: the leading CRLF is the delimiter's,
/// closing the last part exactly as [`encode_part_header`]'s opens the next
/// one, and the trailing CRLF is `[CRLF epilogue]`'s with the epilogue empty —
/// the shape §15.3.7.2's printed example ends with, and one §5.1.1 tells a
/// reader to ignore whatever follows it: "implementations must ignore anything
/// that appears before the first boundary delimiter line or after the last one".
///
/// # Errors
///
/// [`RangeError::MalformedBoundary`] for a boundary
/// [`encode_part_header`] would refuse, on the same rule; a body whose parts
/// and whose close-delimiter could disagree about the boundary is one no reader
/// finds the end of.
///
/// [`RangeError::BufferTooSmall`] when `out` is shorter than the
/// close-delimiter, measured before anything is written.
pub fn encode_final_boundary(boundary: &[u8], out: &mut [u8]) -> Result<usize, RangeError> {
  if !is_boundary(boundary) {
    return Err(RangeError::MalformedBoundary);
  }
  let len = delimiter_len(boundary)
    .saturating_add(DASHES.len())
    .saturating_add(CRLF.len());
  let Some(room) = out.get_mut(..len) else {
    return Err(RangeError::BufferTooSmall);
  };
  match write_final_boundary(boundary, room) {
    Some(()) => Ok(len),
    None => Err(RangeError::BufferTooSmall),
  }
}

/// RFC 2046 §5.1.1's `boundary := 0*69<bchars> bcharsnospace`.
///
/// One to seventy characters, which §5.1.1's prose states in words as well:
/// the boundary parameter "consists of 1 to 70 characters from a set of
/// characters known to be very robust through mail gateways, and NOT ending
/// with white space". The production is where the asymmetry lives — every
/// character but the last may be a `bchars`, which admits `SP`, and the last
/// may not.
fn is_boundary(boundary: &[u8]) -> bool {
  let Some((last, head)) = boundary.split_last() else {
    // `0*69<bchars> bcharsnospace` names the last character unconditionally, so
    // the empty boundary is not one.
    return false;
  };
  head.len() <= MAX_BOUNDARY.saturating_sub(1)
    && head.iter().all(|byte| is_bchar(*byte))
    && is_bcharsnospace(*last)
}

/// RFC 2046 §5.1.1's `bchars := bcharsnospace / " "`.
const fn is_bchar(byte: u8) -> bool {
  is_bcharsnospace(byte) || byte == b' '
}

/// RFC 2046 §5.1.1's `bcharsnospace`, transcribed rule for rule:
///
/// ```text
/// bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" /
///                  "+" / "_" / "," / "-" / "." /
///                  "/" / ":" / "=" / "?"
/// ```
///
/// Neither this set nor RFC 9110 §5.6.2's `tchar` contains the other: `(`,
/// `)`, `,`, `/`, `:`, `=` and `?` are `bcharsnospace` and not `tchar`, while
/// `!`, `#`, `$`, `%`, `&`, `*`, `^`, `` ` ``, `|` and `~` are `tchar` and not
/// `bcharsnospace`. So neither check stands in for the other, however many
/// strings satisfy both. §5.1.1's reason for its own set is the transport
/// rather than the grammar — "characters known to be very robust through mail
/// gateways".
const fn is_bcharsnospace(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
    )
}

/// How many bytes `delimiter := CRLF dash-boundary` takes.
fn delimiter_len(boundary: &[u8]) -> usize {
  CRLF
    .len()
    .saturating_add(DASHES.len())
    .saturating_add(boundary.len())
}

/// How many bytes [`encode_part_header`] writes, or `None` for a
/// `content_type` whose parameters this crate cannot spell back.
///
/// Saturating, so a length no `usize` holds becomes one no buffer satisfies —
/// which is [`RangeError::BufferTooSmall`], the answer such a call has anyway.
/// `None` is therefore the parameter case and only that case.
fn part_header_len(
  range: &ContentRange<'_>,
  content_type: Option<&MediaType<'_>>,
  encoding: PartEncoding<'_>,
  boundary: &[u8],
) -> Option<usize> {
  // `delimiter transport-padding CRLF`, with no padding.
  let mut len = delimiter_len(boundary).saturating_add(CRLF.len());
  if let Some(content_type) = content_type {
    len = len
      .saturating_add(CONTENT_TYPE.len())
      .saturating_add(media_type_len(content_type)?)
      .saturating_add(CRLF.len());
  }
  len = len
    .saturating_add(CONTENT_RANGE.len())
    .saturating_add(range.encoded_len())
    .saturating_add(CRLF.len());
  if let Some(mechanism) = encoding.mechanism() {
    len = len
      .saturating_add(CONTENT_TRANSFER_ENCODING.len())
      .saturating_add(mechanism.len())
      .saturating_add(CRLF.len());
  }
  // The empty line that ends the part's header fields.
  Some(len.saturating_add(CRLF.len()))
}

/// How many bytes [`write_media_type`] writes, or `None` for a parameter walk
/// that does not finish.
///
/// The walk can only fail over a value that never came from
/// [`crate::media::media_type`], which is the one constructor of a
/// [`MediaType`] and which walks every parameter itself before handing one
/// back. `None` is reported rather than panicked because this crate's leaves
/// are proved panic-free at link time, and it is reported rather than ignored
/// because a `Content-Type` written from a walk that stopped early is a
/// different media type from the one the caller passed.
fn media_type_len(media_type: &MediaType<'_>) -> Option<usize> {
  // `media-type = type "/" subtype parameters` (RFC 9110 §8.3.1).
  let mut len = media_type
    .ty()
    .len()
    .saturating_add(1)
    .saturating_add(media_type.subtype().len());
  for param in media_type.params() {
    let (name, value) = param.ok()?;
    // RFC 9110 §5.6.6: "Each parameter is usually delimited by an immediately
    // preceding semicolon." Immediately, and with no OWS after it: §8.3.1
    // prints four equivalent spellings of one media type and says the first,
    // `text/html;charset=utf-8`, "is preferred for consistency".
    len = len.saturating_add(1).saturating_add(name.len());
    len = match value {
      ParamValue::None => len,
      // The `=`.
      ParamValue::Token(token) => len.saturating_add(1).saturating_add(token.len()),
      // The `=` and the two DQUOTEs the interior was read out from between.
      ParamValue::Quoted(quoted) => len.saturating_add(3).saturating_add(quoted.len()),
    };
  }
  Some(len)
}

/// Whether every byte [`write_part_header`] would write is US-ASCII, or `None`
/// for the parameter walk [`media_type_len`] describes.
///
/// RFC 2046 §5.1.1 is the rule: "However, in no event are headers (either
/// message headers or body part headers) allowed to contain anything other than
/// US-ASCII characters." It reaches these two fields because RFC 9110 §14.6
/// hands the framing around them to RFC 2046, and it reaches them ONLY here —
/// as HTTP field values both are bounded by §5.5's `field-vchar`, which admits
/// `obs-text`, and that is the bound [`ContentRange::parse`] keeps.
///
/// The question is asked of the SPANS the writer copies rather than of the
/// bytes it produced, because a second buffer to produce them into is the thing
/// this crate does not have. The two are the same question only because
/// everything else the writer emits is ASCII by construction, so what that
/// covers is enumerated here and a span added to the writer with no line here
/// is a visible omission rather than a silent one:
///
/// - [`CRLF`], [`DASHES`], [`CONTENT_TYPE`], [`CONTENT_RANGE`],
///   [`CONTENT_TRANSFER_ENCODING`], and the `/`, `;`, `=` and DQUOTE
///   [`write_media_type`] puts between a media type's pieces — ASCII literals
///   in this file.
/// - `boundary`, already held to RFC 2046 §5.1.1's `bchars` by
///   [`is_boundary`]: alphanumerics and thirteen ASCII punctuation marks.
/// - The decimal digits [`ContentRange::encode`] writes for a `bytes` value,
///   and the `-`, `/` and `*` it puts between them.
/// - The `mechanism` [`write_part_header`] copies out of a [`PartEncoding`],
///   already held to RFC 2045 §6.1's production by [`is_readable_encoding`],
///   whichever of the three named variants it sits in:
///   §5.1's `token` is `CHAR` minus the CTLs minus SPACE minus `tspecials`,
///   which is `%x21-7E`, so every byte of it is US-ASCII by that test alone.
///   This is the one span in the writer that is checked for the ASCII rule
///   somewhere ELSE, and it is listed here rather than walked because the
///   grammar test is strictly narrower than [`u8::is_ascii`] — a value that
///   passed the first cannot fail the second.
///
/// What is left is the four BORROWED spans, and they are what this walks: the
/// `range-unit`, the opaque tail under a unit this crate does not read, the
/// media type's own bytes, and each parameter's name and value. Two of those
/// four can really carry `%x80-FF` — the tail, by §5.5, and a parameter's
/// `quoted-string`, by §5.6.4 — and the other two are checked with them rather
/// than argued about.
///
/// `the_part_header_writer_only_ever_writes_us_ascii` asks the same question of
/// the ARTIFACT, over the bytes a successful call actually produced, so the
/// enumeration above is measured against the writer instead of only asserted
/// beside it.
fn part_header_is_ascii(
  range: &ContentRange<'_>,
  content_type: Option<&MediaType<'_>>,
) -> Option<bool> {
  if !range.unit().is_ascii() {
    return Some(false);
  }
  if let Some(tail) = range.other_range_resp()
    && !tail.is_ascii()
  {
    return Some(false);
  }
  let Some(content_type) = content_type else {
    return Some(true);
  };
  if !content_type.ty().is_ascii() || !content_type.subtype().is_ascii() {
    return Some(false);
  }
  for param in content_type.params() {
    let (name, value) = param.ok()?;
    if !name.is_ascii() {
      return Some(false);
    }
    let value_is_ascii = match value {
      ParamValue::None => true,
      ParamValue::Token(token) => token.is_ascii(),
      // The interior as the sender wrote it, escapes and all — which is what
      // `write_media_type` puts back between the DQUOTEs, so it is what has to
      // be ASCII.
      ParamValue::Quoted(quoted) => quoted.is_ascii(),
    };
    if !value_is_ascii {
      return Some(false);
    }
  }
  Some(true)
}

/// Fills `out` — which is exactly [`part_header_len`] long — with the part
/// header, or answers `None` without finishing if it is not.
fn write_part_header(
  range: &ContentRange<'_>,
  content_type: Option<&MediaType<'_>>,
  encoding: PartEncoding<'_>,
  boundary: &[u8],
  out: &mut [u8],
) -> Option<()> {
  let out = write_delimiter(boundary, out)?;
  let out = put(out, CRLF)?;
  let out = match content_type {
    Some(content_type) => {
      let out = put(out, CONTENT_TYPE)?;
      let out = write_media_type(content_type, out)?;
      put(out, CRLF)?
    }
    None => out,
  };
  let out = put(out, CONTENT_RANGE)?;
  let (field, out) = out.split_at_mut_checked(range.encoded_len())?;
  // `field` is exactly what `ContentRange::encode` measures, so its own
  // buffer test cannot fail here; `ok()?` is what stands in for the `unwrap`
  // this crate's lint wall forbids.
  range.encode(field).ok()?;
  let out = put(out, CRLF)?;
  // RFC 2045 §6.1's field, last of the three and still inside the header block:
  // `PartEncoding::Absent` writes nothing, which is the state §6.1 gives the
  // same meaning as `7bit` — "This is the default value -- that is,
  // "Content-Transfer-Encoding: 7BIT" is assumed if the
  // Content-Transfer-Encoding header field is not present."
  let out = match encoding.mechanism() {
    Some(mechanism) => {
      let out = put(out, CONTENT_TRANSFER_ENCODING)?;
      let out = put(out, mechanism)?;
      put(out, CRLF)?
    }
    None => out,
  };
  let out = put(out, CRLF)?;
  out.is_empty().then_some(())
}

/// Fills `out` — which is exactly the close-delimiter's length — or answers
/// `None` without finishing if it is not.
fn write_final_boundary(boundary: &[u8], out: &mut [u8]) -> Option<()> {
  let out = write_delimiter(boundary, out)?;
  let out = put(out, DASHES)?;
  let out = put(out, CRLF)?;
  out.is_empty().then_some(())
}

/// Writes `delimiter := CRLF dash-boundary` and hands back what is left of
/// `out`.
fn write_delimiter<'o>(boundary: &[u8], out: &'o mut [u8]) -> Option<&'o mut [u8]> {
  let out = put(out, CRLF)?;
  let out = put(out, DASHES)?;
  put(out, boundary)
}

/// Writes RFC 9110 §8.3.1's `media-type = type "/" subtype parameters` and
/// hands back what is left of `out`, or `None` for the parameter walk
/// [`media_type_len`] describes.
fn write_media_type<'o>(media_type: &MediaType<'_>, out: &'o mut [u8]) -> Option<&'o mut [u8]> {
  let out = put(out, media_type.ty().as_bytes())?;
  let out = put(out, b"/")?;
  let mut out = put(out, media_type.subtype().as_bytes())?;
  for param in media_type.params() {
    let (name, value) = param.ok()?;
    out = put(out, b";")?;
    out = put(out, name)?;
    out = match value {
      ParamValue::None => out,
      ParamValue::Token(token) => {
        let out = put(out, b"=")?;
        put(out, token)?
      }
      // The interior comes back with its §5.6.4 escapes untouched, so putting
      // the DQUOTEs back reproduces the `quoted-string` the sender wrote.
      ParamValue::Quoted(quoted) => {
        let out = put(out, b"=\"")?;
        let out = put(out, quoted)?;
        put(out, b"\"")?
      }
    };
  }
  Some(out)
}

/// The `Content-Range` field name, as a part header carries it.
///
/// The `SP` [`CONTENT_RANGE`] holds is the writer's; a reader splits at the
/// `:` and trims the OWS §5.6.3 admits on either side of the value, whatever
/// the sender wrote.
const CONTENT_RANGE_NAME: &str = "content-range";

/// The `Content-Type` field name, read the same way.
const CONTENT_TYPE_NAME: &str = "content-type";

/// The `Content-Transfer-Encoding` field name, read the same way.
///
/// Matched without regard to case like the other two, and RFC 2046 spells this
/// one both ways in its own examples — `Content-transfer-encoding` in §5.2.2.2's
/// and `Content-Transfer-Encoding` in §5.2.3's.
const CONTENT_TRANSFER_ENCODING_NAME: &str = "content-transfer-encoding";

/// What a body part's `Content-Transfer-Encoding` says about the octets between
/// its header block and the delimiter that ends it.
///
/// **A body part is its own entity**, and that is the whole reason this type
/// exists rather than a refusal. RFC 2046 §5.1's sentence on this field binds
/// the entity of type `multipart` — the body [`ByteRangesReader::new`] was
/// handed — and then says the opposite about what is inside it: "data within
/// the body parts can be encoded on a part-by-part basis, with
/// Content-Transfer-Encoding fields for each appropriate body part". RFC 9110
/// §14.6's registration form gives this media type's encoding considerations as
/// only "7bit", "8bit", or "binary", and it is registering that OUTER entity.
/// So a part carrying `base64` is conformant input, and reading the outer rule
/// onto the inner one is what refuses it.
///
/// What the mechanism decides here is not whether the part is acceptable but
/// whether the octets on the wire are the octets the `Content-Range` encloses —
/// which is the question [`ByteRangesReader::next`]'s width test is asking, and
/// the reason that test is skipped for a part this cannot answer `true` for.
///
/// # There is no `PartialEq`
///
/// This type derives neither `PartialEq` nor `Eq`. A derive over the mechanism
/// bytes as written contradicts the clause [`mechanism`](Self::mechanism) two
/// screens below quotes — RFC 2045 §6.1: "These values are not case sensitive
/// -- Base64 and BASE64 and bAsE64 are all equivalent." Under one,
/// `Undecoded(b"BASE64") == Undecoded(b"base64")` is `false`, and
/// `Identity(b"7BIT") == Identity(b"7bit")` with it: two spellings of one
/// mechanism, and §6.1 is the clause that says so.
///
/// The precedent for removing rather than repairing is in this crate three
/// times over, each for a case-insensitivity its own section states:
/// [`MediaType`] for RFC 9110 §8.3.1's `type` and `subtype` tokens,
/// [`ContentRange`] for RFC 9110 §14.1's `range-unit`, and
/// [`MediaRange`](crate::media::MediaRange) for both at once.
///
/// **And a case-folding `PartialEq` is not the fix**, even though §6.1's case
/// rule is unconditional where RFC 9110 §5.6.6's parameter-value rule is not.
/// It would still owe an answer this crate does not have: §6.1 makes an absent
/// field `7bit`, so [`Absent`](Self::Absent) and `Identity(b"7bit")` are one
/// encoding and two messages — and [`Absent`](Self::Absent) exists precisely to
/// keep them apart, because a caller re-framing the part has to know whether the
/// sender wrote the field. A caller compares the two things this type exposes:
/// [`is_identity`](Self::is_identity) for which side of the width test the value
/// falls on, and [`mechanism`](Self::mechanism) with
/// `<[u8]>::eq_ignore_ascii_case` or [`eq_ignore_ascii`].
///
/// # Open, and what would close it
///
/// `#[non_exhaustive]`, and the reason is not that RFC 2045's vocabulary is
/// open — §6.1's five mechanism names are a closed list, and
/// [`Undecoded`](Self::Undecoded) quotes §6.2 saying so in as many words. This
/// type is not that list. It is the set of distinct READINGS a receiver owes a
/// part's `Content-Transfer-Encoding`, and this crate has learned a new one
/// twice already: [`Undecoded`](Self::Undecoded), when a mechanism this crate
/// can name but does not perform stopped being a malformed body, and
/// [`Unrecognised`](Self::Unrecognised), when §6.4's
/// `application/octet-stream` fallback stopped being a refusal. Each was a
/// reading this type had been folding into another, and each would have broken
/// a downstream exhaustive `match` on what is otherwise a bug-fix release.
///
/// What would close it is a tracked VOCABULARY, not a decision taken here, and
/// RFC 2045 §6.3 leaves that vocabulary open at both ends. Standardised names
/// keep arriving — "Additional standardized Content-Transfer-Encoding values
/// must be specified by a standards-track RFC", since
/// "all content-transfer-encoding namespace except that beginning with "X-" is
/// explicitly reserved to the IETF for future use". Private ones need nobody's
/// permission at all: "Implementors may, if necessary, define private
/// Content-Transfer-Encoding values, but must use an x-token". So while
/// [`Unrecognised`](Self::Unrecognised) can hold a name this crate has never
/// seen, what a reader may have to SAY about such a name is open too. Pin this
/// type to a snapshot of that vocabulary which this crate tracks and updates —
/// every mechanism named, every one classified — and the attribute comes off
/// with that snapshot as its warrant.
///
/// It binds a DOWNSTREAM `match` only, which is why adding it changed no code
/// in this crate: the two `match`es over this type here — `is_readable_encoding`'s
/// four arms and [`mechanism`](Self::mechanism)'s two — stay exhaustive with no
/// wildcard, and the two `matches!` predicates never needed one. Construction is
/// untouched: the variants remain public, which is what lets a caller build the
/// value [`encode_part_header`] writes.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum PartEncoding<'a> {
  /// The part carried no `Content-Transfer-Encoding` field.
  ///
  /// RFC 2045 §6.1 makes an absent field `7bit`, so this is an identity answer
  /// like [`Identity`](Self::Identity) and is kept apart from it for one
  /// reason: a caller re-framing this part has to know whether the sender wrote
  /// the field, and a span cannot say "there was none".
  Absent,
  /// One of the three mechanisms that leave the octets alone — `7bit`, `8bit`
  /// or `binary` — as the sender spelled it, with RFC 822's comments and white
  /// space taken off either end.
  ///
  /// Under all three, [`Part::content`] is the enclosed content itself, so the
  /// width test applies and its answer means what §15.3.7.2 says it means.
  Identity(&'a [u8]),
  /// One of RFC 2045 §6.1's two non-identity mechanisms — `quoted-printable` or
  /// `base64` — as the sender spelled it.
  ///
  /// **That list is closed**, and closed by design rather than by whatever some
  /// predicate happens to admit. §6.1 enumerates five mechanisms; three of them
  /// are the identity transformations [`Identity`](Self::Identity) holds, and
  /// these are the other two. §6.2 calls that enumeration "The five values
  /// defined for the Content-Transfer-Encoding field" in as many words, and
  /// `is_recognised_mechanism` is the whole of it.
  ///
  /// **A name outside those five is not this variant, and is not a refusal
  /// either.** This variant claims the crate can NAME the transformation the
  /// sender asked for, which is a claim it must not make about a value it has
  /// never heard of. A syntactically valid `mechanism` it cannot name is
  /// [`Unrecognised`](Self::Unrecognised), which RFC 2045 §6.4 gives a defined
  /// reading; only a value that is no `mechanism` at all is
  /// [`RangeError::MalformedMultipart`], and `is_mechanism_syntax` is where
  /// that line is drawn.
  ///
  /// **This crate does not decode it.** That is the whole of what this variant
  /// claims, and it is deliberately not a claim about the message: the
  /// ENCLOSING media type does not forbid the mechanism — RFC 2046 §5.1 gives a
  /// body part its own encoding and `multipart/byteranges` inherits that — so
  /// the fact being reported is a limit of this crate, which is no-alloc and has
  /// nowhere to put a decoded copy.
  ///
  /// The part's OWN media type can forbid it, which is a different sentence in a
  /// different document and is not this variant's business either: RFC 2045
  /// §6.4's composite prohibition is checked before a [`Part`] exists, so a
  /// value of this variant sitting beside a `multipart` or `message`
  /// `Content-Type` is not one [`ByteRangesReader::next`] produces. See
  /// [`RangeError::CompositePartEncoding`].
  ///
  /// What follows from it is local: [`Part::content`] is the WIRE span, its
  /// width is the encoded width, and [`ByteRangesReader::next`]'s width test is
  /// not applied, because comparing an encoded width against a range's would be
  /// comparing two different quantities. A caller that wants the octets decodes
  /// them itself.
  ///
  /// # What that width test is, and what it is not
  ///
  /// It is **not a security control**, and skipping it here is not a hole in
  /// one. The test compares two things the same sender wrote — the positions in
  /// the part's `Content-Range` against the octets its delimiters enclose — so
  /// it catches a message that contradicts itself and nothing else. A sender
  /// that lies about its encoding gets no privilege out of the skip: it gets a
  /// part whose content the caller cannot use, with
  /// [`is_identity`](Self::is_identity) answering `false` and
  /// [`mechanism`](Self::mechanism) showing exactly what was claimed. Anything
  /// a caller trusts on the strength of a `Content-Transfer-Encoding` is
  /// trusting the sender, and this type's job is to make that visible rather
  /// than to decide it.
  ///
  /// What WOULD matter is a silent skip. This crate must never let a value it
  /// does not recognise disable the test while it reports success, because then
  /// one `Ok(Some(part))` means two different things and nothing in the answer
  /// says which. That is the whole reason an unknown mechanism is
  /// [`Unrecognised`](Self::Unrecognised) rather than this variant: both skip
  /// the test, and the ANSWER says which of the two is being held, so one
  /// `Ok(Some(part))` never means two things at once. What may not happen is a
  /// value reaching THIS variant on the strength of having parsed, because this
  /// variant's claim would then be false about it.
  Undecoded(&'a [u8]),
  /// A `mechanism` this crate does not recognise, as the sender spelled it: a
  /// name registered with IANA after this crate was written, or one of the
  /// `x-token`s RFC 2045 §6.3 reserves to implementors and whose algorithm is
  /// therefore its definer's rather than this crate's.
  ///
  /// # §6.4 says what a receiver does with one, and it is not refusal
  ///
  /// RFC 2045 §6.4, in the paragraph after the composite prohibition: "Any
  /// entity with an unrecognized Content-Transfer-Encoding must be treated as
  /// if it has a Content-Type of "application/octet-stream", regardless of what
  /// the Content-Type header field actually says." That is a receiver rule, it
  /// is a MUST, and it is written for exactly the value this variant holds. So
  /// an unrecognised mechanism has a DEFINED reading, and a reader that answers
  /// [`RangeError::MalformedMultipart`] for every such name outside the `X-`
  /// namespace refuses a message the specification has told it how to interpret
  /// and takes every later part of that body down with it. Admitting the names
  /// INSIDE that namespace instead fares no better: sorted into
  /// [`Undecoded`](Self::Undecoded), whose claim is that this crate knows the
  /// transformation, they claim a private definition it has never seen.
  ///
  /// Three things follow, and this variant carries all three:
  ///
  /// - **the token is preserved verbatim**, through
  ///   [`mechanism`](Self::mechanism), because a caller may know a name this
  ///   crate does not — a private `x-` scheme is known to whoever defined it,
  ///   and a future registration is known to anyone holding the RFC;
  /// - **[`ByteRangesReader::next`]'s width test is skipped**, since nothing
  ///   here can say the wire octets are the enclosed octets;
  /// - **the declared `Content-Type` does not govern**, which is §6.4's own
  ///   sentence, reported by
  ///   [`is_octet_stream_fallback`](Self::is_octet_stream_fallback).
  ///
  /// # The skip is licensed by §6.4's rule, not by "whatever parses"
  ///
  /// Three separate values have reached the width test and disabled it because
  /// a predicate admitted them: `7bit)` on no test at all, `x-` on an alphabet,
  /// `bogus` on a production whose `ietf-token` alternative is a registry lookup
  /// rather than a syntax. That is why this is a variant of its own rather than
  /// a widening of [`Undecoded`](Self::Undecoded): **a value may not disable a
  /// check merely by parsing.**
  ///
  /// What licenses the skip here is not that the bytes parsed. It is that the
  /// specification states a rule about this exact case, and the rule makes the
  /// content an opaque `application/octet-stream` — under which no claim
  /// survives that the wire span is the enclosed span. The cost is carried IN
  /// the answer rather than swallowed by it: this variant says the mechanism is
  /// one this crate cannot name, the width was not compared, and the declared
  /// type is not the type that governs.
  ///
  /// **The rule is the module's and not this variant's**, and every other
  /// classification here whose effect is to SKIP a check is earned the same
  /// way, so a skip added later is a visible gap rather than a silent one.
  /// [`ContentRange`]'s opaque body — a unit other than `bytes`, which makes
  /// [`ContentRange::incl_range`] `None` and so skips the width test on read
  /// and the [`RangeError::UnsatisfiedPartRange`] refusal on write — is
  /// reachable only past a `token` test and an exact case-insensitive `bytes`
  /// comparison, and [`RangesSpecifier`](crate::range::RangesSpecifier) guards
  /// its own opaque span the same way. §14.4's `unsatisfied-range` skips the
  /// width test because there is no width to compare, and the writer refuses
  /// that shape outright. `Above::Ignored` skips the fold refusal, and
  /// `is_field_name` is what stops a recognised field with a stray SP before
  /// its colon from reaching it. [`Absent`](Self::Absent) errs the other way:
  /// an absent field reads as `7bit`, so the width test APPLIES.
  ///
  /// A SILENT skip is still forbidden, and refusing the whole body is the wrong
  /// way to keep it: §6.4 has already said what to do instead.
  ///
  /// # The fallback does not disarm §6.4's own prohibition
  ///
  /// §6.4 holds two rules, and they are not one rule read twice. The
  /// prohibition is about which PAIRS a sender may compose: "it is EXPRESSLY
  /// FORBIDDEN to use any encodings other than "7bit", "8bit", or "binary" with
  /// any composite media type, i.e. one that recursively includes other
  /// Content-Type fields." The fallback above is about how a receiver INTERPRETS
  /// an entity it is holding. A pair the prohibition forbids is not one this
  /// module hands back at all — [`RangeError::CompositePartEncoding`], in both
  /// directions — so the question the fallback answers is never reached for it.
  /// Reading the fallback as a licence for the forbidden pair would let a sender
  /// clear §6.4 by naming an encoding nobody knows, which is the opposite of
  /// what §6.4 is for.
  Unrecognised(&'a [u8]),
}

impl<'a> PartEncoding<'a> {
  /// Whether the octets between the delimiters ARE the octets the part's
  /// `Content-Range` encloses.
  ///
  /// True for [`Absent`](Self::Absent) and [`Identity`](Self::Identity), and it
  /// is the exact condition [`ByteRangesReader::next`]'s width test runs under.
  /// A caller that needs [`Part::content`] to be the representation's own bytes
  /// — recombining under §15.3.7.3, say — asks this first.
  ///
  /// **`false` is two different facts**, and the answer keeps them apart:
  /// [`Undecoded`](Self::Undecoded) is a transformation this crate can name and
  /// does not perform, while [`Unrecognised`](Self::Unrecognised) is one it
  /// cannot name at all. Both skip the width test; only the second brings RFC
  /// 2045 §6.4's `application/octet-stream` fallback with it, which is what
  /// [`is_octet_stream_fallback`](Self::is_octet_stream_fallback) reports.
  #[inline]
  pub const fn is_identity(&self) -> bool {
    matches!(*self, Self::Absent | Self::Identity(_))
  }

  /// Whether RFC 2045 §6.4 replaces the part's declared `Content-Type` with
  /// `application/octet-stream`.
  ///
  /// True for [`Unrecognised`](Self::Unrecognised) alone, on §6.4's own
  /// sentence: "Any entity with an unrecognized Content-Transfer-Encoding must
  /// be treated as if it has a Content-Type of "application/octet-stream",
  /// regardless of what the Content-Type header field actually says."
  ///
  /// A caller reading [`Part::content_type`] asks this first, because that
  /// accessor reports the field the sender WROTE and this reports whether that
  /// field governs. The two are different questions, and only one of them is
  /// answered by the header block.
  #[inline]
  pub const fn is_octet_stream_fallback(&self) -> bool {
    matches!(*self, Self::Unrecognised(_))
  }

  /// The mechanism the part named, as the sender spelled it, or `None` where it
  /// named none.
  ///
  /// Case is the sender's: RFC 2045 §6.1 makes mechanism names
  /// case-insensitive, so the comparison that sorted this value into its
  /// variant folded case and this accessor does not.
  #[inline]
  pub const fn mechanism(&self) -> Option<&'a [u8]> {
    match *self {
      Self::Absent => None,
      Self::Identity(mechanism) | Self::Undecoded(mechanism) | Self::Unrecognised(mechanism) => {
        Some(mechanism)
      }
    }
  }
}

/// One body part of a `multipart/byteranges` body: its two RFC 9110 fields and
/// the content between them and the next delimiter.
///
/// Borrows out of the body [`ByteRangesReader::new`] was given, not out of the
/// reader, so parts outlive no cursor and several may be held at once.
#[derive(Debug, Copy, Clone)]
pub struct Part<'a> {
  /// §15.3.7.2's per-part `Content-Range`, which that section makes a MUST.
  content_range: ContentRange<'a>,
  /// §15.3.7.2's per-part `Content-Type`, which it makes a conditional SHOULD.
  content_type: Option<MediaType<'a>>,
  /// RFC 2045 §6.1's `Content-Transfer-Encoding`, sorted by whether this crate
  /// can promise the content below is the enclosed octets.
  content_transfer_encoding: PartEncoding<'a>,
  /// Everything between the part's header block and the delimiter that ends it.
  content: &'a [u8],
}

impl<'a> Part<'a> {
  /// The part's `Content-Range`.
  ///
  /// Not an `Option`: RFC 9110 §15.3.7.2 says that within each body part's
  /// header area "the server MUST generate a Content-Range header field
  /// corresponding to the range being enclosed in that body part", so a part
  /// without one is a body [`ByteRangesReader::next`] refuses rather than a part
  /// with a missing field. §15.3.7.2 puts the matching obligation on the reader
  /// in the same subsection: "A client that receives a multipart response MUST
  /// inspect the Content-Range header field present in each body part in order
  /// to determine which range is contained in that body part; a client cannot
  /// rely on receiving the same ranges that it requested, nor the same order
  /// that it requested."
  ///
  /// # What the caller must know
  ///
  /// **A unit this crate cannot read is one it cannot recombine from.**
  /// RFC 9110 §14.4: "If a 206 (Partial Content) response contains a
  /// Content-Range header field with a range unit (Section 14.1) that the
  /// recipient does not understand, the recipient MUST NOT attempt to recombine
  /// it with a stored representation. A proxy that receives such a message
  /// SHOULD forward it downstream." This crate hands a unit it cannot read back
  /// as an opaque span — [`ContentRange::other_range_resp`] is `Some` — and
  /// cannot know whether the caller understands it. §14.6's own example is such
  /// a message: "Despite the name, the `multipart/byteranges` media type is not
  /// limited to byte ranges", and the example that follows carries positions
  /// §14.4's `1*DIGIT` does not admit.
  ///
  /// **A part whose range encloses nothing is reported, not refused.** §14.4's
  /// `unsatisfied-range` — `bytes */1234` — heads no range, so §15.3.7.2's
  /// "corresponding to the range being enclosed in that body part" makes
  /// sending one a violation, and [`encode_part_header`] will not write one.
  /// This reader still hands it over, and the reason is not that a recipient
  /// should be liberal: it is that §15.3.7.2's rule is addressed to the SENDER,
  /// and the only thing §14.4 asks of a recipient over a `Content-Range` it
  /// cannot use is to decline to recombine — "The recipient of an invalid
  /// Content-Range MUST NOT attempt to recombine the received content with a
  /// stored representation" — which this value does not even trigger, being
  /// valid by both of §14.4's rules. Refusing it would also throw away the
  /// other parts of the message over a fault local to one, and would be this
  /// crate inventing a recipient behaviour §15.3.7.2 does not state. What the
  /// caller gets instead is a value it cannot mistake for a range:
  /// [`ContentRange::is_unsatisfied`] is true and
  /// [`ContentRange::incl_range`] is `None`, so the part's content corresponds
  /// to no range and must not be recombined into one.
  ///
  /// **A part whose range encloses the WRONG NUMBER of octets is refused**, and
  /// the paragraph above is why the two answers differ rather than why they
  /// should be the same. Both break §15.3.7.2's correspondence; only one can be
  /// handed over as a value the caller cannot misread. `bytes */1234` says
  /// plainly that it names no positions, and every accessor on it agrees.
  /// `bytes 0-9/10` over three octets of content says the opposite — it names
  /// ten positions, [`ContentRange::incl_range`] reports them, and
  /// [`content`](Self::content) reports three octets — with nothing in the
  /// value marking which half is wrong. §15.3.7.3's recombination is performed
  /// AT the positions the field names, so a caller doing what §15.3.7.2 tells
  /// it to do ("A client that receives a multipart response MUST inspect the
  /// Content-Range header field present in each body part in order to determine
  /// which range is contained in that body part") reads ten octets' worth of
  /// range out of three octets of content. That is the case a report cannot
  /// carry, and [`RangeError::PartRangeMismatch`] is what
  /// [`ByteRangesReader::next`] answers instead.
  #[inline]
  pub const fn content_range(&self) -> &ContentRange<'a> {
    &self.content_range
  }

  /// The part's `Content-Type`, where it carried one.
  ///
  /// An `Option` because RFC 9110 §15.3.7.2 makes it a SHOULD conditional on the
  /// 200 having carried one: "If the selected representation would have had a
  /// Content-Type header field in a 200 (OK) response, the server SHOULD
  /// generate that same Content-Type header field in the header area of each
  /// body part." `None` therefore says the part carried no `Content-Type`, not
  /// that its content has no type: the type of a part that carries none is the
  /// one the 200 would have given, which is a fact about the resource this crate
  /// never sees.
  ///
  /// **An RFC 822 comment the sender wrote is not here**, and cannot be: RFC
  /// 2045 §1 says such a comment has "no semantic content and should be ignored
  /// during MIME processing", and this value is the `media-type` that remains
  /// once a leading or trailing one is taken off. So a part re-framed through
  /// [`encode_part_header`] carries the same media type and not the same bytes
  /// — which is already true of its parameters, since that writer spells them
  /// in RFC 9110 §8.3.1's preferred form rather than in the sender's.
  ///
  /// **This is the field, not necessarily the type that governs.** RFC 2045
  /// §6.4: "Any entity with an unrecognized Content-Transfer-Encoding must be
  /// treated as if it has a Content-Type of "application/octet-stream",
  /// regardless of what the Content-Type header field actually says." So a
  /// caller asks [`is_octet_stream_fallback`](Self::is_octet_stream_fallback)
  /// beside this one; where that is true, this value is what the sender wrote
  /// and `application/octet-stream` is what the content is.
  #[inline]
  pub const fn content_type(&self) -> Option<&MediaType<'a>> {
    self.content_type.as_ref()
  }

  /// Whether RFC 2045 §6.4 displaces this part's declared
  /// [`content_type`](Self::content_type) with `application/octet-stream`.
  ///
  /// True exactly when [`content_transfer_encoding`](Self::content_transfer_encoding)
  /// is [`PartEncoding::Unrecognised`] — a mechanism this crate cannot name — and
  /// §6.4 is unconditional about what a receiver does then: "Any entity with an
  /// unrecognized Content-Transfer-Encoding must be treated as if it has a
  /// Content-Type of "application/octet-stream", regardless of what the
  /// Content-Type header field actually says."
  ///
  /// Asked of the PART rather than only of the encoding because §6.4's sentence
  /// is about an entity, and RFC 2046 §5.1 makes each body part one: "data
  /// within the body parts can be encoded on a part-by-part basis, with
  /// Content-Transfer-Encoding fields for each appropriate body part." It
  /// delegates to [`PartEncoding::is_octet_stream_fallback`], which is where the
  /// decision is made and argued.
  #[inline]
  pub const fn is_octet_stream_fallback(&self) -> bool {
    self.content_transfer_encoding.is_octet_stream_fallback()
  }

  /// RFC 2045 §5.1's classification of this part's top-level type, which is what
  /// §6.4's composite prohibition is stated over.
  ///
  /// A part with no `Content-Type` is [`TopLevelType::Discrete`], because §5.2
  /// gives an absent field the default "Content-type: text/plain;
  /// charset=US-ASCII".
  ///
  /// # What the caller owes, where this is `Unknown`
  ///
  /// [`TopLevelType::Unknown`] and a non-identity
  /// [`content_transfer_encoding`](Self::content_transfer_encoding) is the one
  /// pairing where §6.4's rule — "it is EXPRESSLY FORBIDDEN to use any encodings
  /// other than "7bit", "8bit", or "binary" with any composite media type, i.e.
  /// one that recursively includes other Content-Type fields" — may be broken by
  /// a part this reader hands over. §5.1's `extension-token` is admitted by
  /// `discrete-type` and by `composite-type` alike, so `X-bundle/foo` is either,
  /// and nothing in the message says which.
  ///
  /// **A caller that knows its own private type is composite owes §6.4 the
  /// refusal this crate could not make.** It is stated as an obligation rather
  /// than performed as a guess because the alternative refuses every private
  /// DISCRETE type under `base64` — conformant input — to catch a violation
  /// this crate cannot demonstrate. `forbidden_part_encoding` argues the choice
  /// where it is made.
  #[inline]
  pub fn top_level_type(&self) -> TopLevelType {
    match self.content_type {
      Some(ref content_type) => top_level_type(content_type.ty()),
      None => TopLevelType::Discrete,
    }
  }

  /// The part's `Content-Transfer-Encoding`, sorted into the one question this
  /// crate can answer about it.
  ///
  /// Reported and not refused, and that is a correction rather than a
  /// tolerance. RFC 2046 §5.1 restricts the OUTER entity's encoding and then
  /// hands each part its own: "data within the body parts can be encoded on a
  /// part-by-part basis, with Content-Transfer-Encoding fields for each
  /// appropriate body part". Reading RFC 9110 §14.6's registration form — whose
  /// encoding considerations name those same three mechanisms — as a rule about
  /// the PARTS refuses a conforming 206; [`PartEncoding`] carries the reasoning
  /// and its own account of it.
  ///
  /// **The one exception is the part's OWN type**, which is not §14.6's rule
  /// coming back but RFC 2045 §6.4's: "it is EXPRESSLY FORBIDDEN to use any
  /// encodings other than "7bit", "8bit", or "binary" with any composite media
  /// type, i.e. one that recursively includes other Content-Type fields."
  /// A part whose [`content_type`](Self::content_type) is a `multipart` or a
  /// `message` and whose mechanism is not one of the three is
  /// [`RangeError::CompositePartEncoding`], so no value of this type ever
  /// reports that combination.
  ///
  /// **Two subtypes keep only the first of the three**, and that rule is
  /// RFC 2046's rather than §6.4's: §5.2.2 and §5.2.3 restrict
  /// `message/partial` and `message/external-body` to `7bit`, so a `Part`
  /// pairing either of them with `8bit` or `binary` is
  /// [`RangeError::NonSevenBitPartEncoding`] and is likewise never reported.
  /// See [`RangeError::NonSevenBitPartEncoding`] for why the two refusals stay
  /// separate.
  ///
  /// **Where the top-level type is neither**, §5.1 admits an `extension-token`
  /// as a `discrete-type` and as a `composite-type` alike, so §6.4's condition
  /// turns on a fact this crate does not hold and the pair is reported rather
  /// than refused. [`top_level_type`](Self::top_level_type) is that report, and
  /// names what the caller then owes.
  ///
  /// What the answer decides is [`content`](Self::content)'s guarantee, not the
  /// part's admissibility: [`PartEncoding::is_identity`] false means the octets
  /// are a spelling of the enclosed content and the width test was not applied.
  ///
  /// # What the caller must know
  ///
  /// **This crate does not decode, and its writer does not re-emit.** A caller
  /// that re-frames this part with [`encode_part_header`] gets the two fields
  /// §15.3.7.2 names and no third one, so a part whose mechanism is not
  /// identity must have that field written by the caller or the body it lands
  /// in will say the octets are the content when they are not.
  #[inline]
  pub const fn content_transfer_encoding(&self) -> PartEncoding<'a> {
    self.content_transfer_encoding
  }

  /// The part's content: everything between its header block and the delimiter
  /// line that ends it, with the delimiter's own leading CRLF removed.
  ///
  /// That CRLF is framing rather than content — RFC 2046 §5.1.1 spells
  /// `delimiter := CRLF dash-boundary`, so the line break in front of a
  /// boundary belongs to the boundary. A part whose content is empty gives back
  /// an empty slice, which is a part that enclosed nothing rather than a part
  /// that was not there.
  ///
  /// # What the span is guaranteed to hold
  ///
  /// Any octet, and that is RFC 2046's own answer rather than a gap:
  /// `body-part := MIME-part-headers [CRLF *OCTET]`, where `OCTET := <any 0-255
  /// octet value>`. Nothing about a part's content is a field value, so no
  /// §5.5 rule reaches it, and this crate never writes one back — the writer
  /// half of this module frames parts and leaves the content to the caller,
  /// which is why [`encode_part_header`] takes none.
  ///
  /// What IS guaranteed is the WIDTH, and only under `bytes` **and an identity
  /// transfer encoding**: it is exactly `last - first + 1` octets for the
  /// positions [`content_range`](Self::content_range) reports, because
  /// [`ByteRangesReader::next`] refuses the part otherwise. Under the
  /// unsatisfied form or a unit this crate does not read there is no such
  /// guarantee, because there is no `incl-range` to take it from.
  ///
  /// The transfer encoding is the other half of that condition, and
  /// [`content_transfer_encoding`](Self::content_transfer_encoding) is where a
  /// caller reads it. These octets are the sender's content rather than a
  /// SPELLING of it exactly when [`PartEncoding::is_identity`] is true: RFC 2046
  /// §5.1 gives each body part its own encoding — "data within the body parts
  /// can be encoded on a part-by-part basis, with Content-Transfer-Encoding
  /// fields for each appropriate body part" — so a part naming `base64` is
  /// conformant input whose wire span is four octets for every three the range
  /// encloses. This crate does not decode it and does not refuse it; it reports
  /// it, and withholds the width guarantee with the same breath. A caller that
  /// wants the representation's octets decodes this slice itself.
  #[inline]
  pub const fn content(&self) -> &'a [u8] {
    self.content
  }
}

/// A cursor over one `multipart/byteranges` body (RFC 9110 §14.6), handing back
/// a [`Part`] at a time.
///
/// §14.6: the media type "includes one or more body parts, each with its own
/// Content-Type and Content-Range fields." The framing around those parts is
/// RFC 2046 §5.1.1's, and this reader carries five of its rules. **The first
/// four are rules a strict reader would fail conformant input on**; the fifth
/// is last because it is the exception, changing the answer only for input that
/// is already malformed.
///
/// 1. **`transport-padding` after every boundary.** §5.1.1 puts
///    `transport-padding := *LWSP-char` after the `dash-boundary`, after every
///    `delimiter` and after the `close-delimiter`, and the comment on that rule
///    is a MUST on this side of the wire: a composer must not generate padding
///    of non-zero length, and a receiver must be able to handle padding a
///    message transport added. So this reader does not require a boundary
///    delimiter line to end at the boundary.
///
///    **It is `*LWSP-char` that is skipped, and nothing else.** Reading such a
///    line to its CRLF from wherever the boundary happened to end makes
///    `--SEP--JUNK` a close-delimiter, so a body the grammar refuses ends
///    through `Ok(None)` exactly as a clean one does.
///    `delimiter_line` is the one place either form is read, and it holds both
///    tails to this production.
/// 2. **White space a gateway added.** §5.1.1: "If a boundary delimiter line
///    appears to end with white space, the white space must be presumed to have
///    been added by a gateway, and must be deleted." That white space is inside
///    rule 1's alphabet, so the two rules are one behaviour here.
/// 3. **A preamble and an epilogue of arbitrary text.** §5.1.1 opens the body
///    `[preamble CRLF]` and ends it `[CRLF epilogue]`, both `discard-text`, and
///    says what to do with them: "implementations must ignore anything that
///    appears before the first boundary delimiter line or after the last one."
///    So [`next`](Self::next) skips forward to the first boundary delimiter
///    LINE — a `dash-boundary` whose tail makes it one of §5.1.1's two
///    delimiters, rule 5 being where a candidate that is neither is settled —
///    and stops at the close-delimiter, never reporting the epilogue. That
///    subsumes §14.6's first implementation note — "Additional CRLFs might
///    precede the first boundary string in the body" — since blank lines are a
///    preamble like any other text.
/// 4. **Part header fields outside `Content-`.** §5.1: "The only header fields
///    that have defined meaning for body parts are those the names of which
///    begin with "Content-". All other header fields may be ignored in body
///    parts." And, of those others, "Such other fields are permitted to appear
///    in body parts but must not be depended on." A part carrying an `X-` field
///    is conformant input, so [`next`](Self::next) skips every field it does not
///    recognise instead of refusing the message — and skips a folded one's
///    CONTINUATION with it, since ignoring a field means ignoring both of its
///    lines. `# Errors` on [`next`](Self::next) is where that parts company with
///    the fold this reader does refuse.
/// 5. **Boundary comparison is a prefix test.** §5.1.1's note to implementors:
///    "Boundary string comparisons must compare the boundary value with the
///    beginning of each candidate line. An exact match of the entire candidate
///    line is not required; it is sufficient that the boundary appear in its
///    entirety following the CRLF." On conformant input a prefix test and a
///    line-equality test agree, because §5.1 forbids the divergence in as many
///    words: "The boundary delimiter MUST NOT appear inside any of the
///    encapsulated parts, on a line by itself or as the prefix of any line."
///    They differ only on input that already broke that rule, and the prefix
///    reading is the one RFC 2046 names for it.
///
///    The note settles which lines are CANDIDATES and nothing else. What may
///    then stand on such a line is rule 1's `transport-padding`, so
///    `--SEPARATOR` under the boundary `SEP` is a candidate whose tail makes
///    it neither of §5.1.1's two delimiters — and what THAT means depends on
///    where the line stands.
///
///    **The same bytes mean different things before the first delimiter
///    line.** §5.1.1: "implementations must ignore anything that appears
///    before the first boundary delimiter line or after the last one." A
///    preamble is `discard-text`, so `--SEPARATOR` standing there is text to
///    walk past and the search continues to the real `--SEP` beneath it.
///    §5.1: "The boundary delimiter MUST NOT appear inside any of the
///    encapsulated parts, on a line by itself or as the prefix of any line."
///    Inside a part the same line is a fault, and this reader refuses. `Scan`
///    is where those two sentences are carried and it is an argument to the
///    scan, because a reader that applies either rule everywhere is wrong
///    somewhere: applying §5.1's everywhere fails a conformant body over its
///    preamble.
///
///    So this rule is still the exception it is listed as. Inside a part it
///    changes the answer only for input §5.1 already forbids, and it changes
///    it to a refusal rather than to a part cut short at a line that is not a
///    delimiter; before the first delimiter line it changes nothing at all,
///    §5.1.1 having said to ignore whatever is there.
///
///    And the comparison is made at EVERY line of a body part. §5.1.1's
///    comment under `body-part` says the rule once and says it over the whole
///    production: a line of a body part must not start with the specified
///    dash-boundary, and the delimiter must not appear anywhere in the body
///    part. Stated here rather than quoted, because that comment is one `;`
///    per line in the RFC's own text and no contiguous quotation of it
///    exists. `body-part := MIME-part-headers [CRLF *OCTET]`, so a part's
///    HEADER BLOCK is inside it too — `read_part_headers` holds that half,
///    and [`next`](Self::next)'s `# Errors` says what the two halves each
///    answer. A preamble is not inside that production, which is exactly why
///    the sentence does not reach it.
///
/// # A part's header block is held to MIME's grammar, not to HTTP's
///
/// The five rules above are lenience; this one is the opposite, and it belongs
/// beside them because it comes out of the same §5.1.1. That section says what
/// a part's headers may hold — "However, in no event are headers (either
/// message headers or body part headers) allowed to contain anything other
/// than US-ASCII characters." — and §5.1 says it a second time from the
/// multipart type's own side: the "boundary delimiters and header fields are
/// always represented as 7bit US-ASCII in any case". So every line of a part's
/// header block is required to be US-ASCII, a continuation line and a field
/// this reader IGNORES included, and every field name is required to be
/// RFC 822's `field-name` — one or more printable US-ASCII characters other
/// than the colon, which RFC 5322 §3.6.8 restates as `field-name = 1*ftext`.
/// [`RangeError::NonAsciiPartHeader`] is the first refusal and
/// [`RangeError::MalformedMultipart`] the second.
///
/// **[`ContentRange::parse`] stays permissive**, and that is the rule rather
/// than an exception to it. It is entitled to accept what RFC 9110 §5.5 admits
/// in a field value, `obs-text` included, because a caller reading a standalone
/// HTTP field is entitled to what its own field admits. The narrower grammar
/// belongs to the DESTINATION, and here the destination is a MIME body part —
/// which is why the rule sits in this function rather than in that parser,
/// exactly as it sits in [`encode_part_header`] rather than in
/// [`ContentRange::encode`] on the writing side.
///
/// The per-part `Content-Type` reaches the same conclusion from the other
/// direction, and `mime_content_type` is where it lands: MIME's grammar for
/// that field is WIDER than HTTP's in places and narrower in none, so this
/// reader neither narrows nor widens
/// [`media_type`](crate::media::media_type) — it reads the field in the grammar
/// of the place the field is.
///
/// Without that, one crate gives two answers about the same bytes: a
/// `Content-Type` whose parameter carries `%x80`, or a `Content-Range` tail
/// under an unread unit that does, comes back inside a [`Part`] — and handing
/// that `Part`'s two fields straight to [`encode_part_header`] gets
/// `NonAsciiPartHeader` from the writer over metadata the reader has just
/// called well formed.
///
/// # A per-part `Content-Length` is not framing
///
/// It begins with `Content-`, so §5.1 does not license ignoring it, and this
/// reader ignores it anyway — as a field it does not recognise, never as a
/// second opinion about where the part ends. RFC 2046 frames a body part by its
/// delimiters and §14.6 adds no other framing, so honouring a length inside a
/// part would let one sender's arithmetic disagree with the boundary the same
/// sender wrote.
#[derive(Debug, Clone)]
pub struct ByteRangesReader<'a> {
  /// The boundary parameter's value, without the `dash-boundary`'s hyphens.
  boundary: &'a [u8],
  /// The whole body, given once at [`ByteRangesReader::new`].
  body: &'a [u8],
  /// Where the next scan starts, always the beginning of a line: 0, or the
  /// start of the boundary delimiter line that ended the last part.
  ///
  /// **And there is no second field saying the body ended.** A flag would be
  /// state nothing could disagree with: [`ByteRangesReader::next`] moves this
  /// only when it hands a part back, so once the close-delimiter has been read
  /// this still points at that line's own first hyphen and every later call
  /// re-reads it to the same answer. The terminal answer therefore has one
  /// entrance — the `--` test in `next` — rather than a test and a flag that
  /// could come to disagree about which bodies have ended.
  at: usize,
  /// Whether any part has been handed back yet.
  ///
  /// **Not the flag the field above refuses**, and the difference is which
  /// question it answers. That one would have said the body HAS ENDED, which
  /// the `--` test already decides from the bytes; this one records what the
  /// bytes no longer show — that a `body-part` was read before the
  /// close-delimiter line the cursor is now on. RFC 2046 §5.1.1's
  /// `multipart-body` requires one:
  ///
  /// ```text
  /// multipart-body := [preamble CRLF]
  ///                   dash-boundary transport-padding CRLF
  ///                   body-part *encapsulation
  ///                   close-delimiter transport-padding
  ///                   [CRLF epilogue]
  /// ```
  ///
  /// with `body-part` unbracketed between the opening `dash-boundary` and the
  /// `close-delimiter`, and RFC 9110 §14.6 says the same in prose: "The
  /// "multipart/byteranges" media type includes one or more body parts, each
  /// with its own Content-Type and Content-Range fields." So a body whose first
  /// delimiter line is already the close-delimiter is not one, and without this
  /// field nothing in the reader could tell it from a body whose parts were all
  /// read — a truncated 206 answering exactly as a complete one does.
  ///
  /// It cannot come to disagree with the `--` test, because it is not a second
  /// opinion about the same fact: `next` sets it in the one place it moves the
  /// cursor, on the statement immediately after, and reads it only on the arm
  /// the `--` test has already taken.
  emitted: bool,
}

impl<'a> ByteRangesReader<'a> {
  /// Opens a reader over one whole `multipart/byteranges` body.
  ///
  /// # The body arrives here, not at [`ByteRangesReader::next`]
  ///
  /// Every [`Part`] borrows from this slice and the reader is a cursor over it.
  /// Taking the body once makes a caller feeding a different or extended slice
  /// between calls unrepresentable rather than merely discouraged. Incremental
  /// feeding needs a resumable state the parts' borrows would outlive — a second
  /// constructor, not a hidden mode — and this crate does not have one.
  ///
  /// # The boundary arrives here too, and unquoted
  ///
  /// It is the value of the message `Content-Type`'s `boundary` parameter, which
  /// a caller reading that field with [`media_type`](crate::media::media_type)
  /// already holds — that field is in the message's own HTTP header section, so
  /// HTTP's parser is the right one for it, unlike the per-part `Content-Type`
  /// `mime_content_type` reads. A quoted
  /// one arrives through [`ParamValue::Quoted`] with its DQUOTEs already off,
  /// which is the shape this wants — RFC 9110 §14.6's second implementation
  /// note is that "Although \[RFC2046\] permits the boundary string to be
  /// quoted, some existing implementations handle a quoted boundary string
  /// incorrectly", and a boundary passed here with its quotes still on is one
  /// of those implementations. RFC 2046 §5.1.1's `bcharsnospace` holds no
  /// DQUOTE, so such a boundary is refused rather than silently matching
  /// nothing.
  ///
  /// The media type's NAME is not taken, and that is what makes §14.6's third
  /// implementation note a caller's decision rather than this crate's: a body
  /// sent as the legacy `multipart/x-byteranges` parses identically here,
  /// because the only thing this reader is told is the boundary.
  ///
  /// # Errors
  ///
  /// [`RangeError::MalformedBoundary`] when `boundary` is outside RFC 2046
  /// §5.1.1's `boundary := 0*69<bchars> bcharsnospace`, which is the same rule
  /// [`encode_part_header`] refuses on. Nothing about `body` is checked here:
  /// whether it is a multipart body at all is [`next`](Self::next)'s answer, and
  /// answering it would mean walking the body twice.
  pub fn new(boundary: &'a [u8], body: &'a [u8]) -> Result<Self, RangeError> {
    if !is_boundary(boundary) {
      return Err(RangeError::MalformedBoundary);
    }
    Ok(Self {
      boundary,
      body,
      at: 0,
      emitted: false,
    })
  }

  /// The next body part, or `Ok(None)` at the close-delimiter.
  ///
  /// `Ok(None)` is a positive answer rather than an exhaustion: it means the
  /// close-delimiter `--boundary--` was read **after at least one part**, so
  /// the body ended where it said it would. A body that simply runs out is
  /// [`RangeError::MalformedMultipart`] instead, and so is one that reaches its
  /// close-delimiter having produced no part — RFC 2046 §5.1.1's
  /// `multipart-body` puts `body-part` between the opening `dash-boundary` and
  /// the `close-delimiter` with no brackets around it, and RFC 9110 §14.6 says
  /// the same in prose: "The "multipart/byteranges" media type includes one or
  /// more body parts, each with its own Content-Type and Content-Range fields."
  /// Without that, `--SEP--` on its own would answer exactly as a body whose
  /// parts had all been read, and a truncated 206 would be indistinguishable
  /// from a complete one. Once the close-delimiter is read every later call
  /// answers `Ok(None)` again — the cursor is still on that line, so the call
  /// re-reads it — and anything after it, §5.1.1's `[CRLF epilogue]`, is never
  /// looked at.
  ///
  /// **The close-delimiter is read to its end, not to its hyphens.** §5.1.1
  /// gives it `close-delimiter transport-padding [CRLF epilogue]`, so what may
  /// follow is `*LWSP-char` and then either the end of the body or the CRLF
  /// that opens an epilogue. Reading it to its hyphens alone answers `Ok(None)`
  /// for `--SEP--JUNK` too: a body whose TERMINATION the grammar refuses comes
  /// back as one that ended where it said it would, with the junk dropped in
  /// silence. `delimiter_line` holds both of §5.1.1's delimiters to their
  /// tails, and the answer for such a body is
  /// [`RangeError::MalformedMultipart`].
  ///
  /// # The cursor moves only on `Ok(Some)`
  ///
  /// An `Err` leaves it exactly where the failing call found it, so calling
  /// again reports the same fault over the same bytes rather than a second,
  /// different one further in. There is no recovery mode: a body whose framing
  /// this cannot follow has no next part to resynchronise to, since the thing
  /// that would locate one is the framing that failed.
  ///
  /// # Errors
  ///
  /// [`RangeError::MalformedMultipart`] when the bytes are not a
  /// `multipart/byteranges` body: no boundary delimiter line at all, a body that
  /// ends before its close-delimiter, a body whose close-delimiter arrives
  /// before any part, a boundary delimiter line carrying anything but
  /// `transport-padding` behind its boundary, a part header block with no empty
  /// line closing it or with a line of its own beginning with the
  /// `dash-boundary`, a part
  /// header line that is not `field-name ":" field-value` or that continues a
  /// line that is not there at all, a field name outside RFC 822's
  /// `field-name`, a repeated `Content-Range`, `Content-Type` or
  /// `Content-Transfer-Encoding`, a `Content-Type` that is not RFC 9110
  /// §8.3.1's `media-type`, a `Content-Transfer-Encoding` that is not one
  /// RFC 2045 §6.1 mechanism token, or a part with no `Content-Range`.
  ///
  /// The delimiter-line refusal is asked of the line that ENDS a part as well
  /// as of the one that begins it, and asked before the part is handed back.
  /// This reader never hands over a part whose terminating delimiter it has not
  /// already found, and what counts as having found one is the whole LINE
  /// rather than the hyphens it opens with. So a body whose second delimiter
  /// line is `--SEP JUNK` faults on the FIRST call rather than on the second,
  /// which is how a body that runs out mid-part has always answered.
  ///
  /// The header-block half of that refusal is §5.1.1's same comment read over
  /// the rest of its own production — a line of a body part must not start
  /// with the specified dash-boundary — and `body-part := MIME-part-headers
  /// [CRLF *OCTET]` puts the header block inside it. `--SEP: x` is a
  /// well-formed RFC 822 field line, so without that rule it is walked past as
  /// a field this reader does not recognise and the part behind it comes back
  /// as ordinary input. `read_part_headers` carries the argument, including why
  /// such a line is refused rather than read as the delimiter it resembles.
  ///
  /// That last one is §15.3.7.2's MUST read from this side — "the server MUST
  /// generate a Content-Range header field corresponding to the range being
  /// enclosed in that body part" — and it is why [`Part::content_range`] is not
  /// an `Option`. A part missing it is a part whose content names no range, and
  /// §15.3.7.2 tells the client to determine the range FROM that field, so there
  /// is nothing to hand back.
  ///
  /// The repeated-field refusal is §5.3's: "a sender MUST NOT generate multiple
  /// field lines with the same name in a message (whether in the headers or
  /// trailers) or append a field line when a field line of the same name already
  /// exists in the message, unless that field's definition allows multiple field
  /// line values to be recombined as a comma-separated list". Neither of these
  /// two fields does. Refusing rather than choosing is §8.3's own reason for
  /// refusing a `Content-Type` list: "Recipients often attempt to handle this
  /// error by using the last syntactically valid member of the list, leading to
  /// potential interoperability and security issues if different implementations
  /// have different error handling behaviors."
  ///
  /// [`RangeError::PartValueNotContiguous`] is **this reader's own limit rather
  /// than a fault in the message**, and two constructs reach it. The first is
  /// RFC 822 line folding of a field this reader RECOGNISES —
  /// `Content-Range`, `Content-Type` or `Content-Transfer-Encoding`. A
  /// continuation is identified by what makes it one — the leading SP or HTAB —
  /// and not by the absence of a `:`, because a folded value's second line may
  /// carry a colon of its own: a URL inside a parameter is the ordinary case.
  /// Testing for the colon would read that line as a field line with an
  /// unrecognised name and skip it, which is the misreport this refusal exists
  /// to prevent rather than an escape from it. Joining a folded value is
  /// exactly what a reader handing back borrowed slices cannot do — the same
  /// limit this crate names as
  /// [`MediaError::ValueSpansFieldLines`](crate::media::MediaError::ValueSpansFieldLines)
  /// — and the alternative is worse than a refusal: skipping the continuation
  /// would report `Content-Type: text/plain` for a value whose second line
  /// carried its `charset`, which is a different media type reported as if it
  /// were the sender's.
  ///
  /// **All three fields, and the order is what makes it all three.** The
  /// refusal is reachable at all only where the value has not already been
  /// interpreted, so a `Content-Range` or a `Content-Type` parsed on its own
  /// physical line fails a folded value against its own grammar half-read
  /// before the continuation beneath it can say what it was:
  /// `Content-Type: text/` folded onto ` plain` answers
  /// [`RangeError::MalformedMultipart`], and this variant — which names exactly
  /// that input — is unreachable for both of those two. All three fields are
  /// held unparsed until the next line settles the question;
  /// `read_part_headers` and `Above` carry the order that makes it so.
  ///
  /// **It has its own variant because the refusal is this reader's and not the
  /// sender's fault.** [`RangeError::MalformedMultipart`] here states that the
  /// bytes are not a `multipart/byteranges` body, of a body that demonstrably is
  /// one. `Content-Type: text/plain` folded over a second line reading
  /// `;charset=us-ascii` unfolds to a `media-type` this crate parses without
  /// complaint; what it cannot do is hand back a value that is two spans. That
  /// variant's own documentation carries the whole account, the unfold a caller
  /// who needs the value performs for itself included. RFC 9112 §5.2 has
  /// deprecated the construct in HTTP, where "Historically, HTTP/1.x field
  /// values could be extended over multiple lines by preceding each extra line
  /// with at least one space or horizontal tab" — deprecated in the enclosing
  /// message's own field lines, that is, which is a fact about how rarely this
  /// arrives and not a rule the body part broke.
  ///
  /// **A comment is not one of them, and stripping one is what makes it look
  /// like one.** Strip comments off a value before handing it to HTTP's parser
  /// and a leading or trailing one comes off by shortening the borrowed slice
  /// while an interior one cannot, so a value with a comment between two of its
  /// lexical tokens is reported as a value this reader cannot represent. It
  /// never is: RFC 5322 §3.2.2 puts comments and white space "between lexical
  /// tokens in a structured header field", so every token on either side of one
  /// is still a contiguous span and nothing has to be joined.
  /// `mime_content_type` reads the comments in place, and
  /// `text/plain; (c) charset=us-ascii` is a media type here.
  ///
  /// What is left where a comment appears to split a TOKEN — `charset=a(c)b` —
  /// is [`RangeError::MalformedMultipart`], because RFC 5322 §3.2.3's
  /// `atom = [CFWS] 1*atext [CFWS]` puts the comment position outside the token
  /// and never inside it, so that value is not a comment case at all. Reporting
  /// the limit there would state something true of neither half.
  ///
  /// [`RangeError::MalformedMultipart`] as well for a `Content-Type` whose
  /// `type` or `subtype` is in the `X-` namespace without being RFC 2045
  /// §5.1's `x-token` — `x-/plain`, `text/x-`. A `token` in each position is
  /// the alphabet and not the production: §5.1 reaches the namespace through
  /// `x-token` alone, whose tail is a `token` and therefore `1*<…>`, while
  /// RFC 2046 §6 keeps the registries out of it — "publicly specified values
  /// shall never begin with "X-"". So `x-` matches no alternative of either
  /// half, and a value that is no media type must not leave here as one:
  /// [`Part`] would carry it, [`Part::top_level_type`] would report it as an
  /// [`extension-token`](TopLevelType::Unknown), and [`encode_part_header`]
  /// would spell it back into a body part. §6.1's `mechanism` decides the same
  /// namespace by the same rule, one production above.
  ///
  /// **A continuation of a field this reader IGNORES is skipped, not refused**,
  /// and the paragraph above is why the two differ rather than why they should
  /// be the same. Every sentence of it turns on the JOIN: the value has two
  /// halves, this reader cannot make them one slice, and reporting the first
  /// half alone would report a value the sender did not write. None of that is
  /// true of a field nothing here collects. RFC 2046 §5.1 licenses walking past
  /// it — "All other header fields may be ignored in body parts" — and ignoring
  /// a field means ignoring all of it, so there is no value to join, no half to
  /// report, and nothing the skip can misstate. Refusing there would fail a
  /// whole conformant 206 over a fold in a field this reader was never going to
  /// look at — a rule written for the hard case and applied to both.
  ///
  /// A continuation with NO field line above it — the first line of a part's
  /// header block — is [`RangeError::MalformedMultipart`], which is the one
  /// answer of the three it has always deserved. RFC 822 gives it nothing to
  /// continue, so it is malformed input rather than a conformant construct
  /// declined. Sharing the recognised case's refusal would hide that
  /// difference, one of the two being about the sender's bytes and the other
  /// about this reader.
  ///
  /// **A part's `Content-Transfer-Encoding` is REPORTED rather than refused,
  /// except where its own `Content-Type` forbids it.** RFC 2046 §5.1 gives each
  /// body part its own encoding: "data within the body parts can be encoded on a
  /// part-by-part basis, with Content-Transfer-Encoding fields for each
  /// appropriate body part". So a `text/plain` part naming `base64` is
  /// conformant input and comes back with [`Part::content_transfer_encoding`]
  /// saying so. Refusing every such part takes RFC 9110 §14.6's registration
  /// form — whose encoding considerations are the three identity mechanisms —
  /// for a rule about the parts inside the entity it registers.
  /// [`PartEncoding`] carries the reasoning, and what the mechanism decides is
  /// the width test below rather than the verdict.
  ///
  /// [`RangeError::CompositePartEncoding`] is the one pairing that stays a
  /// refusal, and it is RFC 2045 §6.4's rather than §14.6's: "it is EXPRESSLY
  /// FORBIDDEN to use any encodings other than "7bit", "8bit", or "binary" with
  /// any composite media type, i.e. one that recursively includes other
  /// Content-Type fields.  Currently the only composite media types are
  /// "multipart" and "message"." Which is a rule about the PAIR, so it cannot be
  /// read out of either field alone — `multipart/mixed` is a media type this
  /// reader accepts and `base64` is a mechanism it accepts, and the combination
  /// is what §6.4 names. [`encode_part_header`] refuses to write it on the same
  /// sentence.
  ///
  /// [`RangeError::NonSevenBitPartEncoding`] is the second such pairing, and it
  /// is RFC 2046's own rather than RFC 2045's: §5.2.2 and §5.2.3 restrict
  /// `message/partial` and `message/external-body` to `7bit`, the default, and
  /// say so of `8bit` and `binary` by name — "the use of a content-
  /// transfer-encoding of "8bit" or "binary" is explicitly prohibited for MIME
  /// entities of type "message/partial"." Those are two of the three
  /// mechanisms the refusal above leaves alone, so nothing keyed on a
  /// top-level type can catch them: `message/partial` + `8bit` clears §6.4's
  /// test because `8bit` IS one of the three §6.4 permits.
  /// `is_seven_bit_only` argues the pair, and [`encode_part_header`] refuses
  /// to write it.
  ///
  /// [`RangeError::MalformedMultipart`] does still cover a
  /// `Content-Transfer-Encoding` that is no `mechanism` at all: a value that is
  /// not exactly one token once RFC 822's comments and white space are taken off
  /// either end, or a capture RFC 2045 §6.1's production does not admit — `7bit)`
  /// is not a `token`, and `x-` is not an `x-token`, §5.1's tail being `1*<…>`.
  /// That is the answer a `Content-Type` which is not a `media-type` already
  /// gets, for the same reason: a recognised field whose value this reader
  /// cannot read at all is a fault about the message.
  ///
  /// **A token this crate does not RECOGNISE is not that case.** RFC 2045 §6.4
  /// gives an unrecognised mechanism a receiver behaviour of its own — "Any
  /// entity with an unrecognized Content-Transfer-Encoding must be treated as
  /// if it has a Content-Type of "application/octet-stream", regardless of what
  /// the Content-Type header field actually says" — so a future IANA
  /// registration and a private `x-` scheme come back as
  /// [`PartEncoding::Unrecognised`] with the token preserved, the width test
  /// skipped, and [`Part::is_octet_stream_fallback`] saying the declared type
  /// does not govern. Refusing the first makes every LATER part of such a body
  /// unreachable over a fault the specification does not call one, and
  /// admitting the second as a mechanism this crate RECOGNISES is a claim about
  /// a definition it has never seen.
  ///
  /// What the two answers have in common is the rule neither of them breaks:
  /// nothing may disable the width test in silence. The values that skip it are
  /// [`PartEncoding::Undecoded`]'s closed pair and
  /// [`PartEncoding::Unrecognised`], and the answer says which — see the four
  /// states on `is_mechanism_syntax`.
  ///
  /// [`RangeError::NonAsciiPartHeader`] when any line of a part's header block
  /// carries an octet outside US-ASCII, and
  /// [`RangeError::MalformedMultipart`] when a field name is not RFC 822's
  /// `field-name`. Both are RFC 2046's grammar for the place these bytes are,
  /// and the reader's own section above says why the two standalone HTTP
  /// parsers behind them stay permissive while this does not.
  ///
  /// [`RangeError::MalformedMultipart`] again for a bare CR or a bare LF left
  /// INSIDE one of those lines, which is RFC 822's `field` rather than
  /// RFC 2046's alphabet: `field = field-name ":" [ field-body ] CRLF` ends a
  /// field at the CRLF this reader has already split on, and `field-body` takes
  /// another only as the CRLF of a fold — the construct refused just above as
  /// [`RangeError::PartValueNotContiguous`]. Asked of the whole line for the
  /// same reason the US-ASCII rule is, and asked at all because the lexis a
  /// part's `Content-Type` is read in does not settle it: RFC 822's `qtext` and
  /// `ctext` exclude the CR by name and say nothing about the LF, so without
  /// this a line break could reach a parameter's span, leave in a [`Part`], and
  /// come back through [`encode_part_header`], which copies such a span into a
  /// header block verbatim.
  ///
  /// [`RangeError::PartRangeMismatch`] when a `bytes` part's content is not
  /// `last - first + 1` octets wide. §15.3.7.2's per-part field must correspond
  /// "to the range being enclosed in that body part", and the delimiter that
  /// ends the part has already said how wide the content is; a part where the
  /// two disagree is refused rather than handed over with both facts and no
  /// verdict. The check does not reach §14.4's `unsatisfied-range`, which
  /// encloses no range, nor a unit other than `bytes`, whose positions §14.1.1
  /// leaves to that unit — [`ContentRange::incl_range`] is `None` for both, and
  /// that is half the condition.
  ///
  /// The other half is [`PartEncoding::is_identity`], because the width being
  /// compared is the WIRE width. Only an identity mechanism makes the wire
  /// octets the enclosed octets; a `base64` part is four octets wide for every
  /// three the range names, and comparing those two numbers reports a fault the
  /// sender did not commit. So the test is skipped there and the guarantee is
  /// withdrawn with it — [`Part::content`] states both sides of that, and
  /// [`PartEncoding::Undecoded`] and [`PartEncoding::Unrecognised`] each carry
  /// the licence for their own skip, since a sender-chosen field selecting the
  /// branch that omits a check may not be answerable by "whatever parses".
  ///
  /// [`RangeError::MalformedContentRange`] or
  /// [`RangeError::InconsistentContentRange`] straight from
  /// [`ContentRange::parse`], which is the whole of the per-part field's reading
  /// — including that a unit other than `bytes` comes back as an opaque span
  /// rather than being forced through a grammar that is not its unit's, and
  /// including the octet rule that span is held to.
  // Not `Iterator`: its `next` would have to answer
  // `Option<Result<Part<'a>, RangeError>>`, which puts a fault of the whole BODY
  // inside the sequence of its parts, and lets `while let Some(Ok(part))` treat a
  // body that was cut off mid-part exactly like one that reached its
  // close-delimiter. The two are the distinction this signature exists to keep.
  // `http1-proto`'s `Item` pump carries the same allow for the same shape of
  // reason; `http3-proto`'s `Frames::next` carries it for a different one that
  // does NOT apply here, since a `Part` borrows the body rather than the reader.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Result<Option<Part<'a>>, RangeError> {
    let body = self.body;
    // WHICH region this scan crosses, because a line that begins with the
    // `dash-boundary` and is no delimiter means opposite things in the two —
    // §5.1.1 says to ignore it before the first delimiter line and §5.1 forbids
    // it inside a part. `Scan` carries both sentences.
    //
    // The cursor is 0 for exactly the call that crosses §5.1.1's `[preamble
    // CRLF]`: `new` sets it to 0 and `next` moves it only to a delimiter's own
    // offset, which stands behind a part's content and so is never 0. On every
    // later call it is already ON the line the previous call's `Scan::BodyPart`
    // scan found and classified, so this asks the same question over the same
    // bytes under the same rule.
    let scan = if self.at == 0 {
      Scan::Preamble
    } else {
      Scan::BodyPart
    };
    // The whole LINE, not the hyphens it opens with: `delimiter_line` is the
    // one place a boundary delimiter is read, and it reads to the end of the
    // line the grammar gives that line. Both of this function's delimiters go
    // through it, so the line that ENDS a part is held to the same production
    // as the line that begins one.
    let (_, delimiter) = delimiter_line(body, self.boundary, self.at, scan)?;
    let Delimiter::Ordinary { body_part: mut at } = delimiter else {
      // RFC 2046 §5.1.1's `multipart-body` puts `body-part` between the opening
      // `dash-boundary` and the `close-delimiter`, unbracketed, so a body that
      // reaches this line having produced none is not a multipart body. Read
      // off the cursor's own history rather than off the bytes, because the
      // bytes no longer say: this line looks the same whether it is the first
      // delimiter in the body or the seventh.
      if !self.emitted {
        return Err(RangeError::MalformedMultipart);
      }
      return Ok(None);
    };
    let headers = read_part_headers(body, self.boundary, &mut at)?;
    let Some(content_range) = headers.content_range else {
      return Err(RangeError::MalformedMultipart);
    };
    // WHICH of the two delimiters ends this part is not asked here — either
    // one ends it, and the next call re-reads this same line to find out
    // whether another part follows. That it is a delimiter AT ALL is asked,
    // and it is asked now: a part framed by a line the grammar does not admit
    // is not one this reader hands over and faults on afterwards.
    //
    // `Scan::BodyPart`, because this scan crosses the part's own content:
    // RFC 2046 §5.1's "The boundary delimiter MUST NOT appear inside any of the
    // encapsulated parts, on a line by itself or as the prefix of any line."
    // makes a boundary-prefixed line in there a fault whatever its tail, so
    // there is nothing here to walk past.
    let (end, _) = delimiter_line(body, self.boundary, at, Scan::BodyPart)?;
    // The delimiter's own CRLF is framing, not content — except where the part
    // enclosed nothing, in which case the header block's empty line supplied it
    // and there is no second CRLF to take off.
    let content_end = if end == at {
      at
    } else {
      end.saturating_sub(CRLF.len())
    };
    let Some(content) = body.get(at..content_end) else {
      return Err(RangeError::MalformedMultipart);
    };
    // The two things this call has read, related to each other. RFC 9110
    // §15.3.7.2 requires the per-part field to correspond "to the range being
    // enclosed in that body part", and under `bytes` — §14.1.2's unit, where a
    // position is an octet offset and "the byte positions specified are
    // inclusive" — the range `first-pos` through `last-pos` encloses
    // `last - first + 1` octets. The delimiter has just said how many there
    // are. A part where the two disagree states one width in its header and
    // another in its framing, and §15.3.7.3's recombination happens AT the
    // positions the header names.
    //
    // `incl_range` is `Some` for exactly the shape this can be asked of: `None`
    // covers both §14.4's `unsatisfied-range`, which encloses no range and is
    // reported rather than refused (see `Part::content_range`), and a unit
    // other than `bytes`, whose positions §14.1.1 leaves to that unit — under
    // `exampleunit 1.2-4.3` there is no arithmetic this crate may perform.
    //
    // And it is a WIRE width, so the comparison is asked only of a part whose
    // wire octets are its enclosed octets. RFC 2046 §5.1 lets each body part
    // carry a `Content-Transfer-Encoding` of its own; under one that is not an
    // identity mechanism the two numbers count different things — `YWJj` is
    // four octets for the three `bytes 0-2/3` encloses — and this crate cannot
    // close the gap, being no-alloc. Skipped rather than refused, with
    // `Part::content_transfer_encoding` telling the caller which of the two
    // answers it is holding.
    //
    // The skip is a branch a SENDER selects, so it may never be selected by
    // "whatever parses". TWO classifications reach it and they are licensed
    // differently. `PartEncoding::Undecoded` is one of the two non-identity
    // mechanisms §6.1 defines, a closed set `is_recognised_mechanism` names in
    // full. `PartEncoding::Unrecognised` is a mechanism this crate cannot name
    // at all, and what licenses ITS skip is a rule RFC 2045 §6.4 writes for
    // exactly that case: "Any entity with an unrecognized
    // Content-Transfer-Encoding must be treated as if it has a Content-Type of
    // "application/octet-stream", regardless of what the Content-Type header
    // field actually says." Under that rule the content is an opaque octet
    // stream, so there is no claim left that the wire span is the enclosed
    // span — and a message using a future registration is READ rather than
    // refused whole, which a closed set of names would cost it.
    //
    // Either way the skip is visible in the answer rather than silent: the
    // variant says which of the two it is, `mechanism` gives the token the
    // sender wrote, and `Part::is_octet_stream_fallback` says whether the
    // declared `Content-Type` still governs. `PartEncoding::Unrecognised`
    // carries the argument, and `is_mechanism_syntax` the four states.
    //
    // Checked throughout, and the conversion with it, so the rule is total on
    // every tier: `last >= first` is already `ContentRange::parse`'s guarantee,
    // and a width no `usize` holds is a width no slice on this target can have.
    if headers.encoding.is_identity()
      && let Some((first, last)) = content_range.incl_range()
    {
      let Some(width) = last.checked_sub(first).and_then(|span| span.checked_add(1)) else {
        return Err(RangeError::PartRangeMismatch);
      };
      let Ok(width) = usize::try_from(width) else {
        return Err(RangeError::PartRangeMismatch);
      };
      if content.len() != width {
        return Err(RangeError::PartRangeMismatch);
      }
    }
    self.at = end;
    self.emitted = true;
    Ok(Some(Part {
      content_range,
      content_type: headers.content_type,
      content_transfer_encoding: headers.encoding,
      content,
    }))
  }
}

/// Which field the line above belonged to, and — for one this reader collects —
/// what that line said.
///
/// TWO jobs, because one line's answer settles both. Which field the line above
/// was is what tells a fold this reader must refuse from one it may skip; and
/// whether the line BELOW turns out to be a continuation is what says the value
/// on the line above was all of it. So a recognised field's value rides here,
/// on the record of the line that wrote it, until the next line answers the
/// second question — and it is read out of that record and never off its own
/// line.
///
/// # Nothing is interpreted before the line that would reclassify it
///
/// `Content-Range`, `Content-Type` and `Content-Transfer-Encoding` are parsed
/// where [`read_part_headers`] flushes this — at the first line proving the
/// value was not folded, or at the empty line that ends the block. Parsing one
/// on its own line answers before that evidence arrives: `Content-Type: text/`
/// continued by ` plain` is a `media-type` written across a fold, and reading
/// `text/` alone called it [`RangeError::MalformedMultipart`], which is that
/// variant's own claim that the bytes are no `multipart/byteranges` body — said
/// of a body that is one, carrying a value this reader's own limit is what
/// cannot represent. What that costs is
/// [`RangeError::PartValueNotContiguous`] itself, which names exactly this
/// input and is unreachable for any field decided one line too early.
///
/// The rule is one sentence and it holds for all three fields, not for the one
/// it happens to be stated of.
///
/// # Which fold is refused, and why the others are not
///
/// A folded value's two halves are not one contiguous slice, and JOINING is
/// what a borrowing reader cannot do.
///
/// Such a value has no single span to hand back — the same limit this crate
/// names as
/// [`MediaError::ValueSpansFieldLines`](crate::media::MediaError::ValueSpansFieldLines),
/// and which [`RangeError::PartValueNotContiguous`] says in that same voice on
/// this side. It is the ONE cause: an RFC 822 comment is not a second, because
/// [`mime_content_type`] reads comments in place rather than stripping them.
/// And it is a reason to refuse only where the join was going to be PERFORMED.
/// A continuation of a field this reader does not collect needs
/// no join, because the whole field is already being walked past: RFC 2046 §5.1
/// is what licenses that walk — "All other header fields may be ignored in body
/// parts" — and ignoring a field means ignoring all of it, both of its lines
/// included.
///
/// [`Nothing`](Self::Nothing) is NEITHER case, and it is the one that stays
/// [`RangeError::MalformedMultipart`]: a header block whose FIRST line is a
/// continuation has no field above it to continue, which is malformed input
/// rather than a conformant construct this reader declines to join. Sharing the
/// recognised case's answer hides the distinction this enum exists to draw —
/// one of those two refusals is about the sender's bytes and the other is about
/// this reader.
#[derive(Debug, Copy, Clone)]
enum Above<'a> {
  /// No field line has been read in this part's header block yet.
  Nothing,
  /// The line above was RFC 9110 §15.3.7.2's `Content-Range`.
  ContentRange(
    /// What that line spelled behind the colon, trimmed of §5.5's OWS and not
    /// yet read as a `Content-Range`.
    &'a [u8],
  ),
  /// The line above was RFC 9110 §15.3.7.2's `Content-Type`.
  ContentType(
    /// What that line spelled behind the colon, trimmed of §5.5's OWS and not
    /// yet read as a `media-type`.
    &'a [u8],
  ),
  /// The line above was RFC 2045 §6.1's `Content-Transfer-Encoding`.
  TransferEncoding(
    /// What that line spelled behind the colon, trimmed of §5.5's OWS and not
    /// yet read as a `mechanism`.
    &'a [u8],
  ),
  /// The line above was a field this reader walks past, whose continuation is
  /// walked past with it.
  Ignored,
}

/// Whether `mechanism` is one of the three that leave the octets on the wire
/// exactly as the sender's content.
///
/// `7bit`, `8bit` and `binary`, the three RFC 2045 §6.1 defines as identity
/// transformations. What this decides is [`PartEncoding`]'s variant, and
/// through it whether [`ByteRangesReader::next`]'s width test may compare a
/// wire span against a range — NOT whether the part is acceptable. The other
/// two mechanisms [`is_recognised_mechanism`] names are accepted and reported
/// as [`PartEncoding::Undecoded`], and every further `mechanism`
/// [`is_mechanism_syntax`] admits as [`PartEncoding::Unrecognised`]; see those
/// two variants for the claim this crate makes about each and the claim it
/// withdrew.
///
/// **Compared without regard to case**, which RFC 2045 §6.1 makes the right
/// comparison in as many words: "These values are not case sensitive -- Base64
/// and BASE64 and bAsE64 are all equivalent." Folding case reads `7BIT` as the
/// identity mechanism it is, instead of treating a part whose octets are the
/// sender's content as one this crate cannot vouch for.
fn is_identity_mechanism(mechanism: &[u8]) -> bool {
  eq_ignore_ascii(mechanism, "7bit")
    || eq_ignore_ascii(mechanism, "8bit")
    || eq_ignore_ascii(mechanism, "binary")
}

/// The one mechanism token in a `Content-Transfer-Encoding` value, or `None`
/// when the value does not hold exactly one.
///
/// RFC 2045 §6.1 defines this field as structured, so RFC 822 comments and
/// white space may sit on either side of the mechanism and
/// `Content-Transfer-Encoding: 7bit (relay)` is a conforming spelling of
/// `7bit`. A comparison run against the raw value reads that as a mechanism it
/// does not know; the whole of this function is stripping what RFC 5322 §3.2.2
/// calls `CFWS` off both ends and requiring one token between them.
///
/// The value arrives on ONE line — a folded `Content-Transfer-Encoding` is
/// refused before it reaches here, as [`ByteRangesReader::next`]'s `# Errors`
/// sets out — so `FWS` degenerates to the SP and HTAB [`skip_cfws`] takes, and
/// no `CRLF` can appear inside a comment this walks.
///
/// `None` is a refusal of the FIELD and not of the mechanism: it means this
/// reader could not read one mechanism out of the value, which
/// [`read_part_headers`] answers with [`RangeError::MalformedMultipart`]. It is
/// deliberately not reported as [`PartEncoding::Undecoded`] — that variant says
/// a named mechanism will not be decoded here, and letting an unreadable value
/// wear it would hand a sender an exemption from the width test for a field
/// nobody can read.
///
/// **What is captured is then held to [`is_mechanism_syntax`]**, and the
/// capture alone does not stand in for it. Stopping the capture at SP, HTAB or
/// `(` finds where a token ENDS; it does not establish that what came before is
/// a `mechanism`. Without the second half, `7bit)` is captured whole, matches
/// none of the three identity names, and is reported as a mechanism this crate
/// does not decode — which is the classification
/// [`ByteRangesReader::next`]'s width test is SKIPPED for, so one unbalanced
/// parenthesis buys a part an exemption from that check.
///
/// **The alphabet alone does not close it either.** `x-` is a `token` and is
/// not an `x-token`, so a bare [`is_mime_token`] test lets
/// `Content-Transfer-Encoding: x-` back out as [`PartEncoding::Undecoded`],
/// skipping the width check exactly as `7bit)` does.
///
/// **The refusal this function performs is a SYNTACTIC one.**
/// [`is_mechanism_syntax`] answers whether a value is a
/// `mechanism` §6.1's production could have produced; what it is NOT allowed to
/// answer is whether this crate knows the name, because RFC 2045 §6.4 gives an
/// unrecognised mechanism a defined receiver behaviour and that behaviour is not
/// rejection. Sorting the survivors — which of them this crate can name — is
/// [`read_part_headers`]'s job, through [`is_identity_mechanism`] and
/// [`is_recognised_mechanism`], and it produces a variant rather than an error.
///
/// The rule underneath all of that is why the sort is a sort: a classification
/// whose effect is to skip a check has to be earned by something this crate can
/// state — either a name out of a set it enumerates, or a rule the
/// specification writes for the case. It may never be earned by
/// "the bytes parsed", which is what [`PartEncoding::Unrecognised`] carries the
/// argument for.
fn one_mechanism(value: &[u8]) -> Option<&[u8]> {
  let rest = skip_cfws(value)?;
  // Where a token ENDS: at the SP, HTAB or `(` that RFC 5322 §3.2.2's `CFWS`
  // can begin with, or at the end of the value.
  let end = rest
    .iter()
    .position(|byte| matches!(*byte, b' ' | b'\t' | b'('))
    .unwrap_or(rest.len());
  let (mechanism, tail) = rest.split_at_checked(end)?;
  // And that what came before it IS one. A capture matching no alternative of
  // §6.1's production is a malformed FIELD; a capture matching one this crate
  // cannot name is a mechanism it reports rather than an error, and the sort
  // between the two happens in `read_part_headers` rather than here.
  if !is_mechanism_syntax(mechanism) {
    return None;
  }
  // Exactly one: anything left after the trailing `CFWS` is a second token.
  skip_cfws(tail)?.is_empty().then_some(mechanism)
}

/// Which rule, if any, forbids this pair of part header fields — a
/// `Content-Type` and the `Content-Transfer-Encoding` beside it.
///
/// TWO rules, and one function, because they are one question asked of one
/// pair. `None` is the pair being admissible under both; a `Some` names the
/// section it came from, which is the whole reason the two answers are
/// different variants.
///
/// 1. [`RangeError::CompositePartEncoding`] — RFC 2045 §6.4, over the CLASS of
///    composite media types, refusing every mechanism that is not one of
///    §6.1's three identity transformations.
/// 2. [`RangeError::NonSevenBitPartEncoding`] — RFC 2046 §5.2.2 and §5.2.3,
///    over two SUBTYPES, withdrawing two of the three §6.4 leaves. See
///    [`is_seven_bit_only`], where that half is argued; the rest of this block
///    is the first rule.
///
/// The order is fixed and it is load-bearing: a pair both rules refuse comes
/// back as the first, so `message/partial` + `base64` keeps the answer §6.4
/// has always given it and the newer rule adds cases rather than
/// reclassifying them.
///
/// §6.4 states its rule over the class rather than over one media type: "Certain
/// Content-Transfer-Encoding values may only be used on certain media types.
/// In particular, it is EXPRESSLY FORBIDDEN to use any encodings other than
/// "7bit", "8bit", or "binary" with any composite media type, i.e. one that
/// recursively includes other Content-Type fields.  Currently the only composite
/// media types are "multipart" and "message"." So THIS test is on the TYPE half
/// of `type "/" subtype` and never on the subtype: every subtype of either is
/// composite, and §6.4 names no exception — which is why the rule beneath it
/// had to be written separately rather than folded in here. §5.2.2 and §5.2.3
/// are not exceptions to what §6.4 forbids; they are exceptions to what it
/// allows, and a test that consulted a subtype HERE would be answering §6.4
/// with a fact §6.4 does not use. And the rule reaches a body part
/// because §6.4 says which headers it is about — "If a Content-Transfer-Encoding
/// header field appears as part of an entity's headers, it applies only to the
/// body of that entity" — while RFC 2046 §5.1 makes each body part an entity of
/// its own: "data within the body parts can be encoded on a part-by-part basis,
/// with Content-Transfer-Encoding fields for each appropriate body part."
///
/// **One function, both directions.** [`encode_part_header`] asks it of the pair
/// a caller passed and [`read_part_headers`] asks it of the pair it just read,
/// so a combination this crate refuses to write is one it also refuses to hand
/// back. Two copies of this test could come to disagree — and a level down, so
/// can two per-field checks: validating the media type and the mechanism
/// separately leaves a rule binding only the PAIR to fall between them.
///
/// Case is folded on both halves. RFC 2045 §5.1: "The type, subtype, and
/// parameter names are not case sensitive.  For example, TEXT, Text, and TeXt
/// are all equivalent top-level media types." §6.1 says the same of a mechanism
/// — "These values are not case sensitive -- Base64 and BASE64 and bAsE64 are
/// all equivalent" — which is [`is_identity_mechanism`]'s own comparison.
///
/// A part with NO `Content-Type` is not caught, and cannot be: RFC 2045 §5.2
/// gives an absent field the default "Content-type: text/plain; charset=US-ASCII",
/// which is not composite. RFC 9110 §15.3.7.2 makes the field a SHOULD
/// conditional on the 200 having carried one, so what a part without it really
/// is depends on a representation this crate never sees — and every reading of
/// that leaves the part non-composite here.
///
/// # The class is not two names, and the third answer is not a refusal
///
/// §6.4's condition is "any composite media type", a CLASS, and its
/// "Currently the only composite media types are "multipart" and "message""
/// dates itself in its first word. The class is §5.1's, and §5.1 puts
/// `extension-token` in BOTH halves of `type := discrete-type / composite-type`
/// — so `X-bundle/foo` is a well-formed `discrete-type` and a well-formed
/// `composite-type`, and which one it is lives in a registration or a private
/// definition this crate does not hold. Testing the two literals alone lets
/// `X-bundle/foo` + `base64` through a guard §6.4 states over the class, which
/// is what this arm answers.
///
/// [`TopLevelType`] is that third answer, carried rather than guessed, and the
/// guard here fires on [`TopLevelType::Composite`] alone. An
/// [`Unknown`](TopLevelType::Unknown) top-level type under a non-identity
/// mechanism is **reported and handed over**, with the obligation named on
/// [`Part::top_level_type`] and on [`encode_part_header`]: a caller that knows
/// its own private type is composite is the one holding §6.4's fact, and it
/// applies §6.4 itself.
///
/// Refusing instead is the other available answer, and it is rejected for the
/// reason its sibling one line up is. It would turn every private
/// DISCRETE type under `base64` — conformant input, and the common case, since
/// §6.3 makes composite extensions rare — into a refusal of the whole body, to
/// catch a violation this crate cannot demonstrate. **This module refuses what
/// it knows to be forbidden and reports every fact it does not hold**, which is
/// the same sentence [`PartEncoding::Unrecognised`] is written from.
fn forbidden_part_encoding(
  content_type: Option<&MediaType<'_>>,
  encoding: PartEncoding<'_>,
) -> Option<RangeError> {
  let content_type = content_type?;
  // §6.4 first, and not only because it is the older rule: it is the one whose
  // condition is the wider of the two, so `message/partial` + `base64` keeps
  // the answer it has always had rather than being reclassified by the rule
  // added beneath it. Each fault names the sentence it comes from, and a pair
  // both sentences refuse is reported by the class rule, which is the one that
  // would refuse it under any subtype.
  if !encoding.is_identity() && matches!(top_level_type(content_type.ty()), TopLevelType::Composite)
  {
    return Some(RangeError::CompositePartEncoding);
  }
  // And then §5.2.2's and §5.2.3's, which withdraw two of the three identity
  // mechanisms §6.4 permits — for two subtypes, so the test above cannot see
  // it: `top_level_type` never consults a subtype, because every subtype of a
  // composite type is composite and §6.4 names no exception. These two
  // sections are the exception, and they are an exception to what §6.4 ALLOWS
  // rather than to what it forbids.
  if is_seven_bit_only(content_type) && !is_seven_bit(encoding) {
    return Some(RangeError::NonSevenBitPartEncoding);
  }
  None
}

/// Whether RFC 2046 restricts `content_type`'s subtype to `7bit`.
///
/// Two subtypes of `message`, and each states the rule for itself. §5.2.2:
/// "the use of a content- transfer-encoding of "8bit" or "binary" is
/// explicitly prohibited for MIME entities of type "message/partial"." §5.2.3
/// says it of the other in the same words — "the use of a content-
/// transfer-encoding of "8bit" or "binary" is explicitly prohibited for
/// entities of type "message/external-body"." — after stating the positive
/// form as a MUST: "MUST have a content-transfer-encoding of 7bit (the
/// default)." (The space inside "content- transfer-encoding" is RFC 2046's
/// own; the quotations keep it so they can be searched for.)
///
/// # Why this is a separate question from [`top_level_type`]
///
/// That classification never consults a subtype, and is right not to: RFC 2045
/// §6.4's prohibition is over "any composite media type", so every subtype of
/// `message` and of `multipart` is inside it and none is outside. These two
/// rules run the other way. They do not extend §6.4's refusal to a subtype it
/// missed — §6.4 already refuses `base64` on both of these — they withdraw two
/// of the three mechanisms §6.4 PERMITS, and a guard that can only see a
/// top-level type cannot express that. `message/partial` + `8bit` walks past
/// the composite rule for exactly that reason.
///
/// # The pair is closed, and it is closed by the specification
///
/// §5.2.4 leaves the door open in the other direction — "Future subtypes of
/// "message" intended for use with email should be restricted to "7bit"
/// encoding." — but that is a SHOULD addressed to whoever registers such a
/// subtype, and it is about what a future registration ought to say rather
/// than about a subtype this crate could name today. A receiver applying it to
/// every unregistered `message/*` would refuse conformant input on a rule
/// nobody has written yet, which is the outcome [`TopLevelType::Unknown`]
/// exists to avoid. So this is the two RFC 2046 names, and a future one
/// arrives when its own RFC does.
///
/// Case is folded on both halves, RFC 2045 §5.1: "The type, subtype, and
/// parameter names are not case sensitive.  For example, TEXT, Text, and TeXt
/// are all equivalent top-level media types."
fn is_seven_bit_only(content_type: &MediaType<'_>) -> bool {
  content_type.ty().eq_ignore_ascii_case("message")
    && (content_type.subtype().eq_ignore_ascii_case("partial")
      || content_type.subtype().eq_ignore_ascii_case("external-body"))
}

/// Whether `encoding` is RFC 2045 §6.1's `7bit`, counting the absent field as
/// the `7bit` §6.1 makes it.
///
/// §6.1 makes the two the same fact about the body: "This is the default value
/// -- that is, "Content-Transfer-Encoding: 7BIT" is assumed if the
/// Content-Transfer-Encoding header field is not present." That is why both
/// sections quoted on [`is_seven_bit_only`] write "7bit (the default)" — the
/// parenthesis is not an aside, it is the other half of what they permit.
///
/// Compared without regard to case, §6.1: "These values are not case sensitive
/// -- Base64 and BASE64 and bAsE64 are all equivalent."
///
/// **Narrower than [`PartEncoding::is_identity`], and that is the point.**
/// That predicate answers §6.1's three identity transformations, which is the
/// right question for §6.4 and for the width test; here two of those three are
/// exactly what is forbidden. Sharing the predicate is what lets `8bit` reach
/// `message/partial`.
///
/// [`PartEncoding::Unrecognised`] is not 7bit either. RFC 2045 §6.4 gives such
/// an entity a receiver behaviour — read it as `application/octet-stream` —
/// and that says how to treat the body, not that the sender's mechanism was
/// the one these two sections require.
fn is_seven_bit(encoding: PartEncoding<'_>) -> bool {
  match encoding {
    PartEncoding::Absent => true,
    PartEncoding::Identity(mechanism) => eq_ignore_ascii(mechanism, "7bit"),
    PartEncoding::Undecoded(_) | PartEncoding::Unrecognised(_) => false,
  }
}

/// RFC 2045 §5.1's `type`, as far as a crate that does not hold the media-type
/// registry can decide it.
///
/// ```text
/// type := discrete-type / composite-type
///
/// discrete-type := "text" / "image" / "audio" / "video" /
///                  "application" / extension-token
///
/// composite-type := "message" / "multipart" / extension-token
///
/// extension-token := ietf-token / x-token
/// ```
///
/// Seven names are decidable and everything else is not. `extension-token`
/// appears in BOTH alternatives, so a top-level type outside those seven is a
/// well-formed member of either class, and which class it is in lives in the
/// standards-track RFC that registered it or in the private definition behind an
/// `x-` name — neither of which this crate holds.
///
/// # Why the distinction is load-bearing here
///
/// RFC 2045 §6.4 states its prohibition over the class: "it is EXPRESSLY
/// FORBIDDEN to use any encodings other than "7bit", "8bit", or "binary" with
/// any composite media type, i.e. one that recursively includes other
/// Content-Type fields.  Currently the only composite media types are
/// "multipart" and "message"." The second sentence is a statement of fact at
/// the time of writing — "Currently" — and not a narrowing of the first, whose
/// subject is every composite media type there is. A guard written from the
/// second sentence alone tests two literals where the rule names a class, and
/// `X-bundle/foo` under `base64` walks past it.
///
/// This crate cannot close that by knowing more, so it reports instead:
/// [`Unknown`](Self::Unknown) is exactly the case where §6.4's condition turns
/// on a fact the caller may hold and this crate does not. It is the same shape
/// as [`Undecidable`](crate::conditional::Undecidable) on the conditional side
/// and as `weight_for_with`'s `fold` in [`media`](crate::media): a rule this
/// crate applies as far as its own knowledge reaches, and names where that
/// stops.
///
/// # The two halves of `extension-token`, treated on purpose rather than by
/// accident
///
/// `extension-token := ietf-token / x-token` puts one decidable alternative
/// beside one undecidable one, and §6.1's `mechanism` offers the same pair. The
/// two productions are read the same way, and the reason is one sentence: a
/// crate holds the syntax and does not hold the registry.
///
/// | alternative | what decides it | `type` / `subtype` | `mechanism` |
/// | --- | --- | --- | --- |
/// | `x-token` | bytes: `X-` and a `1*<…>` tail | admitted; a bare `x-` is [`RangeError::MalformedMultipart`] | admitted; a bare `x-` is [`RangeError::MalformedMultipart`] |
/// | `ietf-token` / `iana-token` | a registry lookup | admitted, and an unregistered one is [`Unknown`](Self::Unknown) | admitted, and an unrecognised one is [`PartEncoding::Unrecognised`] |
///
/// §5.1 defines the second row by reference — `ietf-token` is "An extension
/// token defined by a standards-track RFC and registered with IANA." and
/// `iana-token` is "A publicly-defined extension token. Tokens of this form must
/// be registered with IANA as specified in RFC 2048." — so `example/foo` and a
/// media type IANA registers tomorrow are the same bytes here, and refusing
/// either would refuse a conforming message on a lookup this crate never
/// performs. Both productions therefore admit it and report what they could not
/// decide; the reports differ only because the specification gives them
/// different work to do. §6.4 hands an unrecognised MECHANISM a receiver
/// behaviour outright — read the entity as `application/octet-stream` — so
/// `PartEncoding::Unrecognised` is an instruction this crate can carry out. It
/// gives an unregistered top-level TYPE no such default, and the fact §6.4 needs
/// about it is exactly the one nobody here holds, so [`Unknown`](Self::Unknown)
/// is an obligation handed on instead. Same admission, same refusal, different
/// consequence.
///
/// So this classification never sees a value in the `X-` namespace that is not
/// an `x-token`. Both entrances refuse one: `mime_content_type`, the only
/// constructor of a [`Part`]'s `Content-Type`, and [`encode_part_header`], the
/// only writer of one. That matters because there is no fourth variant to put
/// such a value in — carried as [`Unknown`](Self::Unknown) it would be a
/// non-media-type reported as a media type, and re-emitted as one.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TopLevelType {
  /// One of §5.1's five `discrete-type` literals: `text`, `image`, `audio`,
  /// `video` or `application`.
  ///
  /// RFC 2045 §6.4's composite prohibition does not reach a part with one of
  /// these, whatever its `Content-Transfer-Encoding` — which is why
  /// `text/plain` under `base64` is conformant input this reader hands over.
  Discrete,
  /// One of §5.1's two `composite-type` literals: `message` or `multipart`.
  ///
  /// §6.4's prohibition reaches these, and a part pairing one with a
  /// non-identity mechanism is [`RangeError::CompositePartEncoding`] rather
  /// than a [`Part`] — in both directions, since [`encode_part_header`] refuses
  /// to write what [`ByteRangesReader::next`] refuses to report.
  Composite,
  /// An `extension-token`, which §5.1's grammar admits as either.
  ///
  /// **§6.4's prohibition may or may not reach this part, and this crate cannot
  /// tell.** The part is handed over with its mechanism and this classification
  /// both visible; a caller that knows what its own private top-level type is —
  /// and whoever defined an `x-` type does know — owes §6.4 the check this crate
  /// could not perform. See [`Part::top_level_type`].
  Unknown,
}

/// [`TopLevelType`] for the `type` half of a `type "/" subtype`.
///
/// The subtype is never consulted, and that is §5.1's own shape: `type` is where
/// `discrete-type` and `composite-type` are decided, and every subtype of a
/// composite type is composite. Case is folded because §5.1 says to: "The type,
/// subtype, and parameter names are not case sensitive.  For example, TEXT,
/// Text, and TeXt are all equivalent top-level media types."
///
/// **`ty` is a `type`, and this function does not check that it is.** It has no
/// answer for a value that is none — the third variant means "an
/// `extension-token`, and this crate cannot say which class", not "not a media
/// type" — so the check is a precondition rather than an arm, and
/// `keeps_x_token` in the `media` module is where it is kept. See
/// [`TopLevelType`] for the entrances that keep it and for why there is no
/// fourth variant.
fn top_level_type(ty: &str) -> TopLevelType {
  if ty.eq_ignore_ascii_case("multipart") || ty.eq_ignore_ascii_case("message") {
    TopLevelType::Composite
  } else if ty.eq_ignore_ascii_case("text")
    || ty.eq_ignore_ascii_case("image")
    || ty.eq_ignore_ascii_case("audio")
    || ty.eq_ignore_ascii_case("video")
    || ty.eq_ignore_ascii_case("application")
  {
    TopLevelType::Discrete
  } else {
    TopLevelType::Unknown
  }
}

/// Whether `encoding` is a [`PartEncoding`] some read of some body could have
/// produced, which is the writer's domain.
///
/// The variants are public, so a caller can build any pair of variant and span
/// it likes; [`read_part_headers`] builds only three shapes, and those three are
/// what [`encode_part_header`] will write:
///
/// - [`PartEncoding::Absent`], which writes no field at all;
/// - [`PartEncoding::Identity`] holding one of the three names
///   [`is_identity_mechanism`] answers `true` for;
/// - [`PartEncoding::Undecoded`] holding one of the two names
///   [`is_recognised_mechanism`] adds to those three;
/// - [`PartEncoding::Unrecognised`] holding a value that is a `mechanism` by
///   [`is_mechanism_syntax`] and is none of those five.
///
/// The last two are checked as a PAIR of conditions each, because each variant
/// makes a claim its span has to bear out: `Undecoded` says this crate can name
/// the transformation, `Unrecognised` says it cannot, and a hand-built
/// `Unrecognised(b"base64")` would publish a §6.4 fallback over a mechanism §6.1
/// defines.
///
/// **The variant is a claim, and the field name is the evidence for it.**
/// [`PartEncoding::is_identity`] tells a caller that [`Part::content`] is the
/// octets the `Content-Range` encloses, and [`ByteRangesReader::next`] runs or
/// skips §15.3.7.2's width test on exactly that answer. Writing
/// `Content-Transfer-Encoding: base64` out of an `Identity` would publish a
/// header saying the opposite of the claim the caller just made, and the body
/// would read back with the width test skipped — this crate's two halves
/// disagreeing about one part, which is the same split
/// [`RangeError::NonAsciiPartHeader`] closes.
fn is_readable_encoding(encoding: PartEncoding<'_>) -> bool {
  match encoding {
    PartEncoding::Absent => true,
    PartEncoding::Identity(mechanism) => is_identity_mechanism(mechanism),
    PartEncoding::Undecoded(mechanism) => {
      is_recognised_mechanism(mechanism) && !is_identity_mechanism(mechanism)
    }
    PartEncoding::Unrecognised(mechanism) => {
      is_mechanism_syntax(mechanism) && !is_recognised_mechanism(mechanism)
    }
  }
}

/// Whether `content_type` is a media type some read of some body part could
/// have produced, which is the same question [`is_readable_encoding`] asks of
/// the field beside it.
///
/// A [`MediaType`] reaches [`encode_part_header`] from either of this crate's
/// two parsers, and only one of them read RFC 2045 §5.1's grammar.
/// [`media_type`](crate::media::media_type) reads RFC 9110 §8.3.1's, where
/// `type` and `subtype` are each spelled `token` outright and `x-/plain` is a
/// media type — while §5.1 builds a `type` out of `discrete-type /
/// composite-type` and a `subtype` out of `extension-token / iana-token`, whose
/// only `X-` alternative is `x-token` and whose tail is `1*<…>`. So `x-` is a
/// `type` and a `subtype` in the field section and in neither position of a
/// body part, and `mime_content_type` refuses it there.
///
/// **This is the same rule as [`RangeError::NonAsciiPartHeader`]'s and it is
/// here for the same reason**: a caller who never writes a multipart body is
/// entitled to the value its own field admits, and what it may not do is have
/// this crate put that value where RFC 2046 governs. Without this the writer
/// would emit `Content-Type: x-/plain` into a body part that
/// [`ByteRangesReader::next`] then refuses to read — the two halves disagreeing
/// about one part, which is the split that refusal closes.
///
/// `media::keeps_x_token` is the one place the `x-token` rule is spelled, and
/// this asks it of both halves. The subtype is asked as well as the type, and
/// not because anything downstream classifies it: [`top_level_type`] never
/// consults a subtype, so `text/x-` would pass every other test here and go out
/// as a `Content-Type` no reader of §5.1's grammar accepts.
fn is_readable_media_type(content_type: &MediaType<'_>) -> bool {
  keeps_x_token(content_type.ty().as_bytes()) && keeps_x_token(content_type.subtype().as_bytes())
}

/// Whether `bytes` is a `mechanism` RFC 2045 §6.1's production could have
/// produced, as far as bytes alone can decide it.
///
/// ```text
/// mechanism := "7bit" / "8bit" / "binary" /
///              "quoted-printable" / "base64" /
///              ietf-token / x-token
/// ```
///
/// This is the SYNTAX half of the field, and the only half [`one_mechanism`]
/// may refuse on. Whether this crate can NAME the transformation is
/// [`is_recognised_mechanism`]'s question, asked afterwards, and its answer is a
/// [`PartEncoding`] variant rather than an error.
///
/// # `ietf-token` names a registry, and a registry is not a syntax
///
/// §5.1 defines that alternative by reference:
///
/// ```text
/// ietf-token := <An extension token defined by a
///                standards-track RFC and registered
///                with IANA.>
/// ```
///
/// The membership test it names is "registered with IANA", a lookup no
/// predicate over `bytes` performs. So `bogus` and a mechanism IANA registers
/// tomorrow are the same bytes to this function, and it admits both: a `token`
/// that is not in the `X-` namespace is a well-formed `ietf-token` as far as
/// anything here can see, and §6.4 tells a receiver what to do with one it does
/// not know.
///
/// # The `X-` namespace is decidable, and the rule for it is not this
/// function's
///
/// §5.1 spells `x-token` as "The two characters "X-" or "x-" followed, with no
/// intervening white space, by any token", whose tail is `token` and therefore
/// `1*<…>` — NON-EMPTY. And §6.3 puts the rest of the space out of reach of an
/// `X-` name: "all content-transfer-encoding namespace except that beginning
/// with "X-" is explicitly reserved to the IETF for future use". So a bare `x-`
/// matches no alternative at all — not `x-token`, for want of the tail, and not
/// `ietf-token`, because it is in the one namespace an `ietf-token` may not
/// come from — and it stays [`RangeError::MalformedMultipart`].
///
/// **That reasoning is not about `mechanism`.** §5.1 offers `x-token` at three
/// productions — `type` and `subtype` through `extension-token`, and this one —
/// so an answer written here in a copy of its own leaves `x-/plain` and
/// `text/x-` read as media types. The rule lives once, in
/// `media::keeps_x_token`, which this calls and which the two media-type
/// positions call: a bare `x-` is refused at all three or at none. What is left
/// here is the alphabet, and §6.1's five literals and an `ietf-token` are one
/// [`is_mime_token`] test over the whole value — the alternative that could tell
/// those apart is a registry, and `x-` is a `token` like any other, which is why
/// the namespace half cannot be folded into this one.
///
/// # The four states, and which of them this decides
///
/// | value | this | [`is_recognised_mechanism`] | outcome |
/// | --- | --- | --- | --- |
/// | absent | — | — | [`PartEncoding::Absent`], width test runs |
/// | `7bit`, `8bit`, `binary` | yes | yes | [`PartEncoding::Identity`], width test runs |
/// | `quoted-printable`, `base64` | yes | yes | [`PartEncoding::Undecoded`], width test skipped |
/// | `some-future-encoding`, `x-custom` | yes | no | [`PartEncoding::Unrecognised`], width test skipped, §6.4 fallback |
/// | `7bit)`, `x-` | no | — | [`RangeError::MalformedMultipart`] |
///
/// **Do not split the fourth row.** Sending its `x-token`s into the THIRD,
/// claimed as mechanisms this crate recognises, and every other name in it into
/// the fifth, refused, is wrong in both halves. An `x-token` is a syntax this
/// crate can decide and a NAME it cannot read, so calling one recognised is a
/// claim about a private definition it has never seen; and refusing the rest
/// turns a future IANA registration into a malformed body — every later part of
/// that body unreachable with it — against a section that says to read such an
/// entity as `application/octet-stream`.
///
/// What the third row does say, and must keep saying: the set of values that
/// may disable the width test **on the strength of a name** is closed and
/// enumerable. The fourth row's skip is licensed by something else entirely,
/// and [`PartEncoding::Unrecognised`] argues it in full.
fn is_mechanism_syntax(bytes: &[u8]) -> bool {
  is_mime_token(bytes) && keeps_x_token(bytes)
}

/// Whether `bytes` names a `mechanism` this crate RECOGNISES: one of the five
/// RFC 2045 §6.1 enumerates, by name.
///
/// ```text
/// mechanism := "7bit" / "8bit" / "binary" /
///              "quoted-printable" / "base64" /
///              ietf-token / x-token
/// ```
///
/// Five of the seven alternatives are literals and this is those five. The
/// other two are open — `x-token` by design and `ietf-token` by reference to a
/// registry — so nothing here answers `true` for a value out of either, and
/// that is deliberate rather than a limit waiting to be lifted: **the set of
/// mechanisms this crate can name has to be one it can enumerate.** §6.2 calls
/// §6.1's list "The five values defined for the Content-Transfer-Encoding
/// field" in as many words.
///
/// # What a `false` answer is, and what it is NOT
///
/// It is not a refusal. [`is_mechanism_syntax`] has already decided whether the
/// value is a `mechanism` at all; this only sorts the ones that are, into
/// [`PartEncoding::Undecoded`] — a transformation this crate can name — and
/// [`PartEncoding::Unrecognised`], one it cannot. Both skip
/// [`ByteRangesReader::next`]'s width test, and the answer says which is which,
/// so no value disables that test while reporting the same thing a recognised
/// one would.
///
/// **This list plus every `x-token`, with a `false` answer as a REFUSAL, is the
/// shape to avoid.** Closing the recognised set is right, and closing it is
/// what this function is: `7bit)`, `x-` and `bogus` each reach the width-test
/// skip on a predicate one narrowing too wide. Refusing everything OUTSIDE the
/// set is the other half, and RFC 2045 §6.4 is the sentence against it: "Any
/// entity with an unrecognized Content-Transfer-Encoding must be treated as if
/// it has a Content-Type of "application/octet-stream", regardless of what the
/// Content-Type header field actually says." An unrecognised mechanism has a
/// defined receiver behaviour; a `MalformedMultipart` over the whole body —
/// every later part with it — is not that behaviour, and it is what a future
/// IANA registration and every private `x-` scheme would get.
///
/// The five comparisons fold case because §6.1 makes these values
/// case-insensitive outright: "These values are not case sensitive -- Base64 and
/// BASE64 and bAsE64 are all equivalent."
fn is_recognised_mechanism(bytes: &[u8]) -> bool {
  // `is_identity_mechanism` holds three of the five and these are the other
  // two; each is a `token` by inspection, so no alphabet test is owed here —
  // `is_mechanism_syntax` has asked it already, and asks it of every value.
  is_identity_mechanism(bytes)
    || eq_ignore_ascii(bytes, "quoted-printable")
    || eq_ignore_ascii(bytes, "base64")
}

/// Whether `bytes` is RFC 2045 §5.1's `token`, the alphabet §6.1's `mechanism`
/// is spelled out of.
///
/// ```text
/// mechanism := "7bit" / "8bit" / "binary" /
///              "quoted-printable" / "base64" /
///              ietf-token / x-token
///
/// token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
///             or tspecials>
///
/// tspecials :=  "(" / ")" / "<" / ">" / "@" /
///               "," / ";" / ":" / "\" / <">
///               "/" / "[" / "]" / "?" / "="
/// ```
///
/// §6.1 opens by saying it of the whole field — "The Content-Transfer-Encoding
/// field's value is a single token specifying the type of encoding" — and the
/// production bears it out: the five literal alternatives are tokens, and so is
/// every name the two open ones admit. §5.1, where both are defined, spells
/// `x-token` as "The two characters "X-" or "x-" followed, with no intervening
/// white space, by any token".
///
/// The byte set is that grammar arithmetic done once. RFC 822's `CHAR` is
/// US-ASCII 0-127 and its `CTL` is 0-31 and 127, so `CHAR` minus the CTLs minus
/// SPACE is `%x21-7E`, and `tspecials` removes fifteen of those.
///
/// **A token is not a `mechanism`, and this is not the test that decides one.**
/// It is the ALPHABET, one of the two things §6.1's production says;
/// [`is_mechanism_syntax`] is the production, and it is this function's only
/// caller. The other thing that production says is WHERE the token has to sit,
/// and that is not asked here: in the `X-` namespace the token is the TAIL,
/// since §5.1's `x-token` is "The two characters "X-" or "x-" followed, with no
/// intervening white space, by any token" and `token` is `1*<…>`, so the whole
/// of `x-` passes this test and is no `mechanism`. `keeps_x_token`, in the
/// `media` module, is that half — asked beside this one by the same caller, and
/// asked by the two media-type positions §5.1 offers `x-token` at, which is why
/// it does not live here.
///
/// **And a token is not a mechanism this crate can NAME.** That is
/// [`is_recognised_mechanism`]'s five literals, and nothing may call this in its
/// place: a value passing here is a `mechanism` for RFC 2045's purposes and may
/// still be one no reader has heard of, which is [`PartEncoding::Unrecognised`]
/// and not [`PartEncoding::Undecoded`]. Three values — `7bit)`, `x-` and
/// `bogus` — reach [`ByteRangesReader::next`]'s width-test skip on a test
/// weaker than the production; the four states on [`is_mechanism_syntax`] are
/// what answers them.
fn is_mime_token(bytes: &[u8]) -> bool {
  !bytes.is_empty() && bytes.iter().all(|byte| is_mime_token_char(*byte))
}

/// Whether `name` is RFC 822's `field-name`, which RFC 5322 §3.6.8 restates as
/// `field-name = 1*ftext`: one or more printable US-ASCII characters other than
/// the colon.
///
/// A part's header block is RFC 2046's, not RFC 9110's, so the name is NOT held
/// to §5.6.2's `token` — RFC 822 admits bytes a `token` does not, and refusing
/// one would fail a whole part over a field this reader was going to ignore.
/// What it is held to is the grammar of the place it actually sits, which
/// admits neither an empty name, nor the SP an obsolete `field-name *WSP ":"`
/// would leave in front of the colon, nor a control byte.
///
/// The colon is excluded by [`read_part_headers`]'s split before it is excluded
/// here, since the name is what sits before the FIRST one; the exclusion is
/// written anyway, because a rule that holds only because of where it is called
/// stops holding when it is called somewhere else.
fn is_field_name(name: &[u8]) -> bool {
  !name.is_empty()
    && name
      .iter()
      .all(|byte| matches!(*byte, 0x21..=0x39 | 0x3B..=0x7E))
}

/// One body part's header block, as [`read_part_headers`] read it.
///
/// A struct rather than a tuple because two of the three are `Option`s of
/// different types, and a caller unpacking `(Some(a), None, e)` has nothing but
/// position telling it which field is which.
struct PartHeaders<'a> {
  /// §15.3.7.2's per-part `Content-Range`.
  ///
  /// Optional HERE and required by the caller: a part missing it is refused in
  /// [`ByteRangesReader::next`], beside that part's other framing faults,
  /// rather than in the middle of a header walk.
  content_range: Option<ContentRange<'a>>,
  /// §15.3.7.2's per-part `Content-Type`, a conditional SHOULD, so `None` is a
  /// part that carried none rather than a fault.
  content_type: Option<MediaType<'a>>,
  /// RFC 2045 §6.1's `Content-Transfer-Encoding`, already sorted by
  /// [`is_identity_mechanism`] and [`is_recognised_mechanism`].
  encoding: PartEncoding<'a>,
}

/// Reads one body part's header block, leaving `at` on the first byte of the
/// part's content.
///
/// The two fields RFC 9110 §15.3.7.2 names come back; RFC 2046 §5.1's "All other
/// header fields may be ignored in body parts" is why everything else is walked
/// past rather than collected, and why an unrecognised field cannot fail this.
///
/// THREE field names are recognised, though. The third,
/// `Content-Transfer-Encoding`, comes back as a [`PartEncoding`] — read to be
/// REPORTED, since RFC 2046 §5.1 gives a body part its own encoding.
///
/// A line opening with SP or HTAB is not a field line at all but RFC 822's
/// continuation of the one above it, and it is recognised by that leading byte
/// rather than by having no `:` — a continuation may carry one, and reading it
/// as a field with an unrecognised name is the silent misreport
/// [`ByteRangesReader::next`]'s `# Errors` refuses. What is then DONE with it
/// depends on the field it continues, which [`Above`] carries.
///
/// # No recognised value is read on the line that writes it
///
/// All three are held in [`Above`] and parsed one line later, at the first line
/// that proves the value was not folded — or at the empty line, which proves
/// the same thing about the last field in the block. Reading one where it
/// stands answers before that evidence: `Content-Type: text/` folded onto
/// ` plain` becomes [`RangeError::MalformedMultipart`], a verdict about the
/// message, over a conforming value this reader's own limit is what cannot
/// represent — and it makes [`RangeError::PartValueNotContiguous`] unreachable
/// for every field decided that way. The rule is one rule and it holds for all
/// three fields, not for the one it happens to be stated of.
///
/// The order inside the loop is what carries it: the continuation test comes
/// first, the flush behind it, and every reading of a `Content-Range`, a
/// `media-type` or a `mechanism` behind that.
///
/// **This is where the MIME grammar is enforced**, over every line and not only
/// over the three fields read out of them: RFC 2046 §5.1.1 admits nothing
/// outside US-ASCII in a body part's headers, and RFC 822 bounds a field name.
/// [`ByteRangesReader`]'s own section says why the two HTTP parsers this calls
/// stay permissive while this does not.
///
/// # The boundary is passed in because a header block is part of the body part
///
/// §5.1.1 writes the rule as the comment under
/// `body-part := MIME-part-headers [CRLF *OCTET]`, and writes it over the
/// whole production: a line of a body part must not start with the specified
/// dash-boundary, and the delimiter must not appear anywhere in the body part.
/// (Stated rather than quoted: that comment is one `;` per line in the RFC's
/// own text, so no contiguous quotation of it exists.) `MIME-part-headers` is
/// the first half of that production, so a header line beginning with the
/// `dash-boundary` is inside the rule, and it is
/// [`RangeError::MalformedMultipart`] here.
///
/// It has to be refused HERE because nothing else can see it. RFC 822's
/// `field-name` is "1*<any CHAR, excluding CTLs, SPACE, and ":">", which
/// `--SEP` satisfies — so `--SEP: x` is a well-formed field line that
/// [`ByteRangesReader::next`] would otherwise walk past as a field it does not
/// recognise, reporting the part that followed as ordinary input. The same
/// shape appears one production over, on the delimiter's own tail; this is the
/// header block's half of it, and [`delimiter_line`] is the content's. Between
/// them §5.1.1's sentence covers every line of a `body-part`.
///
/// A line so refused is NOT read as the delimiter it looks like, and the
/// grammar is why rather than convenience: each field of `MIME-part-headers`
/// carries its own CRLF, and `delimiter := CRLF dash-boundary` needs one more
/// in front of the hyphens. A `dash-boundary` reached with no blank line
/// before it therefore has no CRLF left to be a `delimiter` with — which is
/// also why `--SEP\r\nContent-Range: bytes */25\r\n--SEP--\r\n` is refused by
/// the grammar alone, with this rule or without it.
fn read_part_headers<'a>(
  body: &'a [u8],
  boundary: &[u8],
  at: &mut usize,
) -> Result<PartHeaders<'a>, RangeError> {
  // The three parsed values, each written exactly once — where `above` is
  // flushed — and each doubling as the record that its field has been seen, so
  // the repeated-field refusal below reads one state rather than two.
  // `PartEncoding::Absent` is that state for the third, since the flush answers
  // one of the other three variants for every value it admits.
  let mut content_range = None;
  let mut content_type = None;
  let mut encoding = PartEncoding::Absent;
  // Held rather than read on the spot, for the reason `Above`'s own doc gives:
  // a value folded onto a second line must reach the continuation refusal as a
  // FOLD, which it cannot if the first line's half-value has already been read
  // as a `Content-Range`, a `media-type` or a `mechanism`.
  let mut above = Above::Nothing;
  loop {
    let Some(rest) = body.get(*at..) else {
      return Err(RangeError::MalformedMultipart);
    };
    let Some(past) = past_crlf(body, *at) else {
      // A header block with no empty line to close it: the body ran out inside
      // the part's fields.
      return Err(RangeError::MalformedMultipart);
    };
    let Some(line) = rest.get(..past.saturating_sub(*at).saturating_sub(CRLF.len())) else {
      return Err(RangeError::MalformedMultipart);
    };
    *at = past;
    // RFC 2046 §5.1.1: "However, in no event are headers (either message
    // headers or body part headers) allowed to contain anything other than
    // US-ASCII characters." Asked of the whole LINE, before anything reads a
    // field out of it, so a continuation and a field this reader ignores are
    // covered by the same statement the rule is — and so that no span reaching
    // a `Part` can carry an octet `encode_part_header` would refuse to write.
    if !line.is_ascii() {
      return Err(RangeError::NonAsciiPartHeader);
    }
    // And that no line-break octet survives INSIDE a line. RFC 822's
    // `field = field-name ":" [ field-body ] CRLF` terminates a field with the
    // CRLF this loop has already split at, and its
    // `field-body = field-body-contents [CRLF LWSP-char field-body]` admits a
    // CR or an LF inside a field body only as the CRLF of a fold — which is the
    // continuation this reader recognises below and refuses. So a CR or an LF
    // left over here belongs to no `field` at all.
    //
    // Asked of the whole LINE for the reason the rule above is: the same
    // sentence covers a continuation and a field this reader ignores. And it is
    // asked at ALL because RFC 822's `qtext` and `ctext` exclude the CR and not
    // the LF — literally, a bare LF is a `CHAR` neither production names — so
    // the lexis this crate now reads a `Content-Type` in would otherwise let one
    // through into a parameter value, out of a `Part`, and back into
    // `encode_part_header`, which copies that span into a header block verbatim.
    // A reader that admits what its own writer must not emit is the split
    // `NonAsciiPartHeader` closes.
    if line.iter().any(|byte| matches!(*byte, b'\r' | b'\n')) {
      return Err(RangeError::MalformedMultipart);
    }
    // And that no line of the header block is a boundary delimiter line.
    // §5.1.1 states that rule over the whole `body-part` — a line of one must
    // not start with the specified dash-boundary — and `MIME-part-headers` is
    // inside it. Asked with the same prefix comparison
    // `dash_boundary_from` uses, so the two halves of the body part answer one
    // rule; see this function's own section for why such a line is refused
    // rather than read as the delimiter it resembles.
    if let Some(after) = line.strip_prefix(DASHES)
      && after.starts_with(boundary)
    {
      return Err(RangeError::MalformedMultipart);
    }
    // A continuation line, recognised before anything reads it as a field.
    // RFC 9112 §5.2's deprecated fold is defined by the space or horizontal tab
    // that opens the extra line, so that leading byte is what makes a line a
    // continuation; the absence of a `:` is not, and a continuation may carry
    // one. See `ByteRangesReader::next`'s `# Errors` for the misreport that
    // rule prevents, and `Above` for why a continuation of an IGNORED field is
    // skipped instead — there is no value to join, because the whole field is
    // being walked past.
    //
    // THREE answers, because the three cases are three different facts about
    // the message. A continuation of a collected field is a conformant body
    // this reader cannot represent — `PartValueNotContiguous` — while a
    // continuation with nothing above it continues no field at all, which is
    // malformed input.
    //
    // Asked BEFORE the empty-line test and before anything parses a held
    // value, which is the whole of the order: an empty line is not
    // `[SP / HTAB, ...]`, so putting this first costs that test nothing and
    // buys the guarantee that no recognised value is read until this line has
    // said it is not the rest of one.
    if matches!(line, [b' ' | b'\t', ..]) {
      match above {
        Above::Ignored => continue,
        Above::ContentRange(_) | Above::ContentType(_) | Above::TransferEncoding(_) => {
          return Err(RangeError::PartValueNotContiguous);
        }
        Above::Nothing => return Err(RangeError::MalformedMultipart),
      }
    }
    // Past that test the line above is COMPLETE — whatever this line turns out
    // to be, it is not the rest of it — so this is where a recognised field's
    // value is INTERPRETED, and the one place any of the three is. Parsing one
    // on its own line answers before the evidence that would have changed the
    // answer has been read; `Above` carries what that costs and which variant it
    // makes unreachable.
    //
    // Every refusal below is therefore reached only by a value that is WHOLE
    // and still not what its field's grammar admits, which is a fault about the
    // message rather than this reader's limit.
    match above {
      Above::Nothing | Above::Ignored => {}
      Above::ContentRange(value) => content_range = Some(ContentRange::parse(value)?),
      Above::ContentType(value) => {
        // RFC 2045 §5.1's grammar, not RFC 9110 §8.3.1's, because this is a MIME
        // body part's header block and not an HTTP field section. The `media`
        // module holds both parsers and its summary says what they disagree
        // about; every fault of that one is this refusal, which is why it answers
        // `Option` rather than an error nothing here would tell apart.
        let Some(parsed) = mime_content_type(value) else {
          return Err(RangeError::MalformedMultipart);
        };
        content_type = Some(parsed);
      }
      Above::TransferEncoding(value) => {
        let Some(mechanism) = one_mechanism(value) else {
          return Err(RangeError::MalformedMultipart);
        };
        // Three answers, because there are three facts. `one_mechanism` has
        // already refused everything that is not a `mechanism` at all, so
        // what is left is sorted by what this crate can say about it: an
        // identity transformation, a non-identity one it can name, or a name
        // it has never heard of — which RFC 2045 §6.4 hands a receiver rule
        // for rather than a refusal. See `PartEncoding::Unrecognised`.
        encoding = if is_identity_mechanism(mechanism) {
          PartEncoding::Identity(mechanism)
        } else if is_recognised_mechanism(mechanism) {
          PartEncoding::Undecoded(mechanism)
        } else {
          PartEncoding::Unrecognised(mechanism)
        };
      }
    }
    // Nothing resets `above` here, and nothing has to: every path below either
    // returns or assigns it, so no held value can be parsed twice.
    //
    // The empty line that ends `MIME-part-headers`; the content begins behind
    // its CRLF.
    if line.is_empty() {
      // RFC 2045 §6.4 and RFC 2046 §5.2.2 and §5.2.3, asked here because here
      // is where both fields are final: a part's `Content-Type` may follow its
      // `Content-Transfer-Encoding`, so the pair is not known until the empty
      // line that ends the block — and the flush above has just made the last
      // of them final. The same function answers both rules for
      // `encode_part_header`, which is what keeps this reader from reporting a
      // body that writer would not write.
      if let Some(error) = forbidden_part_encoding(content_type.as_ref(), encoding) {
        return Err(error);
      }
      return Ok(PartHeaders {
        content_range,
        content_type,
        encoding,
      });
    }
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
      return Err(RangeError::MalformedMultipart);
    };
    let (Some(name), Some(value)) = (line.get(..colon), line.get(colon.saturating_add(1)..)) else {
      return Err(RangeError::MalformedMultipart);
    };
    // RFC 822's `field-name`, which is the grammar of the place these bytes are
    // — not §5.6.2's `token`, whose set is narrower than RFC 822's and would
    // fail a part over a field this reader was going to ignore anyway. What it
    // does exclude is the empty name, the SP an obsolete `field-name *WSP ":"`
    // would leave, and every control byte.
    if !is_field_name(name) {
      return Err(RangeError::MalformedMultipart);
    }
    // §5.5: the OWS around a field value is not part of the value.
    let value = trim_ows(value);
    // The repeated-field test reads the PARSED slot, and reads it correctly
    // because the flush above has already moved whatever an earlier line held
    // into that slot. So a second `Content-Range` is refused whether the first
    // was one line up or ten, and there is no second record of "this field was
    // seen" to fall out of step with the first.
    if eq_ignore_ascii(name, CONTENT_RANGE_NAME) {
      if content_range.is_some() {
        return Err(RangeError::MalformedMultipart);
      }
      above = Above::ContentRange(value);
    } else if eq_ignore_ascii(name, CONTENT_TYPE_NAME) {
      if content_type.is_some() {
        return Err(RangeError::MalformedMultipart);
      }
      above = Above::ContentType(value);
    } else if eq_ignore_ascii(name, CONTENT_TRANSFER_ENCODING_NAME) {
      if !matches!(encoding, PartEncoding::Absent) {
        return Err(RangeError::MalformedMultipart);
      }
      above = Above::TransferEncoding(value);
    } else {
      above = Above::Ignored;
    }
  }
}

/// Which of RFC 2046 §5.1.1's two boundary delimiter lines a candidate line is.
///
/// ```text
/// multipart-body := [preamble CRLF]
///                   dash-boundary transport-padding CRLF
///                   body-part *encapsulation
///                   close-delimiter transport-padding
///                   [CRLF epilogue]
///
/// encapsulation := delimiter transport-padding
///                  CRLF body-part
///
/// delimiter := CRLF dash-boundary
///
/// close-delimiter := delimiter "--"
///
/// transport-padding := *LWSP-char
/// ```
///
/// The two are the same bytes up to the boundary and part company at the first
/// byte after it, which is why this is one answer rather than a `bool` and a
/// separate offset. An ordinary delimiter is `transport-padding` and then a
/// CRLF the grammar requires, because a `body-part` follows it. A
/// close-delimiter is `"--"`, `transport-padding`, and then the end of the
/// body or the CRLF of an `[CRLF epilogue]` that is optional — nothing
/// follows it that this reader may read.
///
/// Only [`Ordinary`](Self::Ordinary) carries an offset, and that is the
/// distinction: it is where the `body-part` begins. There is nowhere for
/// [`Close`](Self::Close) to point, since §5.1.1 says of the epilogue that
/// "implementations must ignore anything that appears before the first
/// boundary delimiter line or after the last one".
#[derive(Debug, Copy, Clone)]
enum Delimiter {
  /// `dash-boundary transport-padding CRLF`, or the `delimiter
  /// transport-padding CRLF` an `encapsulation` opens with.
  Ordinary {
    /// The first byte behind the line's CRLF, which is the `body-part`'s
    /// first byte.
    body_part: usize,
  },
  /// `close-delimiter transport-padding [CRLF epilogue]`.
  Close,
}

/// Which of RFC 2046's two rules a line that BEGINS with the `dash-boundary`
/// and is no delimiter falls under.
///
/// One predicate, two contexts, two opposite answers — and RFC 2046 writes a
/// rule for each, which is why this is an argument rather than a constant.
///
/// **Before the body's first boundary delimiter line, such a line is text.**
/// §5.1.1: "implementations must ignore anything that appears before the first
/// boundary delimiter line or after the last one." §5.1.1 spells `preamble :=
/// discard-text`, so a line there that satisfies neither of that section's two
/// delimiter productions is nothing but `*text` — skipped, and the search for
/// the real opening delimiter goes on behind it.
///
/// **Inside a `body-part`, the same line is a fault.** §5.1: "The boundary
/// delimiter MUST NOT appear inside any of the encapsulated parts, on a line by
/// itself or as the prefix of any line." Every dash-boundary prefix is
/// prohibited in there, so a line carrying one is refused whether or not its
/// tail makes it a delimiter, and no search continues past it.
///
/// The two sentences are about different regions of one body, so a reader that
/// applies either everywhere is wrong somewhere. Applying the second one
/// everywhere fails a body over `--SEPARATOR` on the line above the real
/// `--SEP`, whose preamble §5.1.1 says to ignore. Applying
/// the FIRST one everywhere would be the worse half of the same mistake — a
/// part cut short at a line §5.1 forbids, with the bytes behind it silently
/// rejoined to the next part.
///
/// [`read_part_headers`] holds §5.1's sentence over a part's header block,
/// which `body-part := MIME-part-headers [CRLF *OCTET]` puts inside the same
/// production, and stays a refusal for the reason [`BodyPart`](Self::BodyPart)
/// is one.
#[derive(Debug, Copy, Clone)]
enum Scan {
  /// Across §5.1.1's `[preamble CRLF]`, where a prefix candidate that is no
  /// delimiter is `discard-text` to skip.
  Preamble,
  /// Across a `body-part`, where §5.1 forbids the prefix outright and a
  /// candidate that is no delimiter ends the read.
  BodyPart,
}

/// The boundary delimiter line at or after `from`, read to the end the grammar
/// gives it.
///
/// The answer is that line's own first hyphen — [`dash_boundary_from`] finds
/// the candidates and [`delimiter_at`] settles which of §5.1.1's two delimiters
/// a candidate is, if either.
///
/// # A candidate that is no delimiter, and the two rules about one
///
/// The scan crosses one of two regions, and what a boundary-prefixed line that
/// classifies as neither delimiter MEANS depends on which. [`Scan`] is that
/// context and carries both of RFC 2046's sentences: across §5.1.1's
/// `[preamble CRLF]` the line is `discard-text` and the search resumes behind
/// its CRLF, while across a `body-part` §5.1 prohibits the prefix outright and
/// the read ends. Which is why the search is a LOOP here rather than one probe
/// at [`dash_boundary_from`]'s first answer.
///
/// # The line does not end at the boundary, and what follows it is not free
///
/// RFC 2046 §5.1.1 admits exactly `transport-padding := *LWSP-char` between a
/// delimiter and its CRLF, and RFC 822 §3.3 spells `LWSP-char = SPACE / HTAB`.
/// §5.1.1 says the same in prose from the other side: "The boundary may be followed
/// by zero or more characters of linear whitespace. It is then terminated by
/// either another CRLF and the header fields for the next part, or by two
/// CRLFs, in which case there are no header fields for the next part." So a
/// delimiter line carrying anything else before its CRLF is
/// [`RangeError::MalformedMultipart`], and this is where that is decided for
/// both of [`ByteRangesReader::next`]'s delimiters.
///
/// The tail has to be READ, and the CLOSE-delimiter is where that bites first:
/// without it `--SEP--JUNK` ends a body exactly as `--SEP--` does, so a body
/// whose termination the grammar refuses comes back through `Ok(None)` — the
/// same answer a clean close gets, with the junk silently dropped. §5.1.1's
/// `close-delimiter transport-padding [CRLF epilogue]` puts `*LWSP-char` there
/// and then an epilogue that an optional CRLF has to introduce; `JUNK` is
/// neither, and neither is a lone CR. The ordinary delimiter has the same hole
/// one production over — skipping to the line's CRLF from wherever the boundary
/// ended — and both are closed here, by one function, because they are one
/// sentence of the grammar read in two places.
///
/// # An epilogue is still never looked at
///
/// [`Close`](Delimiter::Close) is answered for a body that ends on the padding
/// and for one that carries a CRLF and then anything at all. That is
/// §5.1.1's `[CRLF epilogue]` exactly: the CRLF is what makes an epilogue
/// possible and `epilogue := discard-text` is what makes its content nobody's
/// business. What is refused is a tail that is an epilogue under NO reading,
/// having neither the padding's alphabet nor the CRLF that would open one.
///
/// # Errors
///
/// [`RangeError::MalformedMultipart`] when there is no boundary delimiter line
/// at or after `from`, and — under [`Scan::BodyPart`] — when a line found there
/// carries something the production above does not admit behind its boundary.
/// Under [`Scan::Preamble`] such a line is not an error but text to walk past,
/// so the refusal there is the first one: the body held no delimiter line at
/// all.
fn delimiter_line(
  body: &[u8],
  boundary: &[u8],
  from: usize,
  scan: Scan,
) -> Result<(usize, Delimiter), RangeError> {
  let mut at = from;
  loop {
    let Some(start) = dash_boundary_from(body, boundary, at) else {
      return Err(RangeError::MalformedMultipart);
    };
    if let Some(delimiter) = delimiter_at(body, boundary, start) {
      return Ok((start, delimiter));
    }
    // A line that begins like a delimiter and is none. WHICH of RFC 2046's two
    // rules that breaks is the whole of what `scan` says; both sentences are on
    // that enum.
    match scan {
      Scan::BodyPart => return Err(RangeError::MalformedMultipart),
      Scan::Preamble => {
        // `preamble := discard-text` and `discard-text := *(*text CRLF)
        // *text`, so this line ends at its CRLF and the search resumes behind
        // it. `past_crlf` answers strictly past `start`, which is what makes
        // the loop finite; `None` is a preamble running to the end of the body,
        // and such a body has no boundary delimiter line anywhere.
        let Some(next) = past_crlf(body, start) else {
          return Err(RangeError::MalformedMultipart);
        };
        at = next;
      }
    }
  }
}

/// Which of §5.1.1's two delimiters the line at `start` is, or `None` when it
/// only BEGINS like one.
///
/// `start` is a line's first byte and that line already opens with the
/// `dash-boundary` — [`dash_boundary_from`] is what establishes both, and
/// [`delimiter_line`] is the only caller of either. The split is what lets the
/// CONTEXT decide what a `None` means: this function reads the tail and reports
/// what it found, [`Scan`] carries the two rules about the answer, and neither
/// half has to know the other's.
///
/// The productions are quoted on [`delimiter_line`] and [`Delimiter`], which is
/// where the tail rules and the epilogue argument live.
fn delimiter_at(body: &[u8], boundary: &[u8], start: usize) -> Option<Delimiter> {
  let after = start
    .checked_add(DASHES.len())
    .and_then(|at| at.checked_add(boundary.len()))?;
  let rest = body.get(after..)?;
  // `close-delimiter := delimiter "--"`, and the two hyphens come immediately
  // after the boundary — `transport-padding` follows them, not the boundary.
  if let Some(closing) = rest.strip_prefix(DASHES) {
    let tail = past_padding(closing)?;
    // `close-delimiter transport-padding [CRLF epilogue]`: the body may end on
    // the padding, and past a CRLF it may hold anything, that being an
    // epilogue. A tail that is neither is a body that did not end the way it
    // said it did.
    if !(tail.is_empty() || tail.starts_with(CRLF)) {
      return None;
    }
    return Some(Delimiter::Close);
  }
  // An ordinary `delimiter`, whose CRLF is not optional the way the
  // close-delimiter's is: a `body-part` follows, and it begins behind that
  // CRLF.
  let tail = past_padding(rest)?;
  if !tail.starts_with(CRLF) {
    return None;
  }
  // `tail` is a suffix of `body`, so the difference of the two lengths is its
  // offset — arithmetic that needs no bound of its own, and is checked anyway
  // because every other offset in this module is.
  let body_part = body
    .len()
    .checked_sub(tail.len())
    .and_then(|at| at.checked_add(CRLF.len()))?;
  Some(Delimiter::Ordinary { body_part })
}

/// What is left of `rest` once RFC 2046 §5.1.1's `transport-padding` is off
/// its front.
///
/// `transport-padding := *LWSP-char`, and RFC 822 §3.3 defines
/// `LWSP-char = SPACE / HTAB` — two bytes, and neither of them is the CR this
/// scan therefore stops on. `*` means the answer may be `rest` itself.
///
/// The padding is DISCARDED rather than reported, which is two of
/// [`ByteRangesReader`]'s rules at once: the comment §5.1.1 writes under the
/// production makes handling it a receiver's obligation while forbidding a
/// composer to emit any, and §5.1.1 says of the same bytes that "If a boundary
/// delimiter line appears to end with white space, the white space must be
/// presumed to have been added by a gateway, and must be deleted."
fn past_padding(rest: &[u8]) -> Option<&[u8]> {
  let end = rest
    .iter()
    .position(|byte| !matches!(*byte, b' ' | b'\t'))
    .unwrap_or(rest.len());
  rest.get(end..)
}

/// Where the next line at or after `from` that begins with the `dash-boundary`
/// starts, or `None` if there is none.
///
/// `from` must be the start of a line, which is what makes this RFC 2046
/// §5.1.1's comparison rather than a search for the boundary anywhere: only a
/// line's own beginning is a candidate, and the answer is the offset of that
/// line's first hyphen. The test is a PREFIX one, so `--SEPARATOR` is a
/// candidate under the boundary `SEP` — see [`ByteRangesReader`]'s fifth rule
/// for why that is the reading, and for the §5.1 sentence that keeps it from
/// mattering on conformant input.
///
/// **Finding a CANDIDATE is all this does**, and it is a third of one answer:
/// [`delimiter_line`] is the only caller, [`delimiter_at`] holds the rest of
/// the line to the grammar, and [`Scan`] says what a candidate that fails there
/// means where it stands. So `--SEPARATOR` is found here and then either
/// skipped as preamble text or refused as a line inside a `body-part`,
/// depending on which of RFC 2046's two rules covers the region it is in — a
/// distinction the answer here deliberately does not make.
fn dash_boundary_from(body: &[u8], boundary: &[u8], from: usize) -> Option<usize> {
  let mut at = from;
  loop {
    let line = body.get(at..)?;
    if let Some(after) = line.strip_prefix(DASHES)
      && after.starts_with(boundary)
    {
      return Some(at);
    }
    at = past_crlf(body, at)?;
  }
}

/// The offset just past the first CRLF at or after `from`, or `None` when there
/// is none left in `body`.
///
/// Only CRLF: RFC 2046 §5.1.1's framing is spelled in it throughout —
/// `delimiter := CRLF dash-boundary`, `discard-text := *(*text CRLF) *text` —
/// and a bare LF is not a line break in it. So a body framed with bare LFs has
/// no line this can end and no candidate line after its first: it is
/// [`RangeError::MalformedMultipart`] rather than a silently different parse of
/// the same bytes.
fn past_crlf(body: &[u8], from: usize) -> Option<usize> {
  let rest = body.get(from..)?;
  let at = rest.windows(CRLF.len()).position(|pair| pair == CRLF)?;
  from.checked_add(at)?.checked_add(CRLF.len())
}
